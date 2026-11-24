// SPDX-License-Identifier: AGPL-3.0-only
//! GGUF v3 reader: zero-copy, no allocation, no float, no panics.
//!
//! Reads the file format llama.cpp writes (header, metadata key/values, tensor table, aligned data) over a
//! borrowed byte slice: on heqk the admitted model region, on the build host a file read into memory. It
//! never interprets floating-point values; binary32 metadata comes back as bits.
//!
//! [`Gguf::open`] walks the whole header once and checks every length, count, type, dimension and offset
//! against the slice, with checked arithmetic: tensors must be aligned, inside the data section, in
//! increasing order and non-overlapping, names and keys unique. After that, lookups cannot go out of
//! bounds. [`qwen3`] binds a Qwen3 GGUF to the integer decoder in `neuro_lm::qwen3`.
#![no_std]
#![forbid(unsafe_code)]
#![deny(clippy::indexing_slicing, clippy::unwrap_used, clippy::expect_used, clippy::panic)]

pub mod qwen3;

pub const MAGIC: [u8; 4] = *b"GGUF";
/// Bounds that keep validation cheap and arithmetic far from overflow.
pub const MAX_TENSORS: u64 = 1 << 16;
pub const MAX_KV: u64 = 1 << 16;
pub const MAX_ARRAY: u64 = 1 << 24;
pub const MAX_STRING: u64 = 1 << 16;
pub const MAX_DIMS: usize = 4;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GgufError {
    Magic,
    /// Only version 3 is read.
    Version,
    /// A length, count or offset does not fit the file or the bounds above.
    Bounds,
    /// An unknown metadata value type or tensor type.
    Type,
    /// A duplicate key or tensor name.
    Duplicate,
    /// A tensor is misaligned, overlaps another or lies outside the data section.
    Layout,
    /// Text that is not UTF-8.
    Utf8,
}

/// Metadata value types (GGUF spec).
pub mod vt {
    pub const U8: u32 = 0;
    pub const I8: u32 = 1;
    pub const U16: u32 = 2;
    pub const I16: u32 = 3;
    pub const U32: u32 = 4;
    pub const I32: u32 = 5;
    pub const F32: u32 = 6;
    pub const BOOL: u32 = 7;
    pub const STRING: u32 = 8;
    pub const ARRAY: u32 = 9;
    pub const U64: u32 = 10;
    pub const I64: u32 = 11;
    pub const F64: u32 = 12;
}

/// Tensor types (ggml) with their block size in elements and in bytes.
pub mod tt {
    pub const F32: u32 = 0;
    pub const F16: u32 = 1;
    pub const Q4_0: u32 = 2;
    pub const Q4_1: u32 = 3;
    pub const Q5_0: u32 = 6;
    pub const Q5_1: u32 = 7;
    pub const Q8_0: u32 = 8;
    pub const Q8_1: u32 = 9;
    pub const Q2_K: u32 = 10;
    pub const Q3_K: u32 = 11;
    pub const Q4_K: u32 = 12;
    pub const Q5_K: u32 = 13;
    pub const Q6_K: u32 = 14;
    pub const Q8_K: u32 = 15;
    pub const BF16: u32 = 30;

    /// (elements per block, bytes per block), or None for a type this reader does not size.
    pub fn block(t: u32) -> Option<(u64, u64)> {
        Some(match t {
            F32 => (1, 4),
            F16 | BF16 => (1, 2),
            Q4_0 => (32, 18),
            Q4_1 => (32, 20),
            Q5_0 => (32, 22),
            Q5_1 => (32, 24),
            Q8_0 => (32, 34),
            Q8_1 => (32, 36),
            Q2_K => (256, 84),
            Q3_K => (256, 110),
            Q4_K => (256, 144),
            Q5_K => (256, 176),
            Q6_K => (256, 210),
            Q8_K => (256, 292),
            _ => return None,
        })
    }
}

#[derive(Clone, Copy, Debug)]
struct Cur<'a> {
    b: &'a [u8],
    at: usize,
}

impl<'a> Cur<'a> {
    fn take(&mut self, n: u64) -> Result<&'a [u8], GgufError> {
        let n = usize::try_from(n).map_err(|_| GgufError::Bounds)?;
        let end = self.at.checked_add(n).ok_or(GgufError::Bounds)?;
        let s = self.b.get(self.at..end).ok_or(GgufError::Bounds)?;
        self.at = end;
        Ok(s)
    }
    fn u32(&mut self) -> Result<u32, GgufError> {
        let s = self.take(4)?;
        Ok(u32::from_le_bytes([s.first().copied().unwrap_or(0), s.get(1).copied().unwrap_or(0), s.get(2).copied().unwrap_or(0), s.get(3).copied().unwrap_or(0)]))
    }
    fn u64(&mut self) -> Result<u64, GgufError> {
        let lo = u64::from(self.u32()?);
        let hi = u64::from(self.u32()?);
        Ok(lo | hi << 32)
    }
    fn string(&mut self) -> Result<&'a [u8], GgufError> {
        let n = self.u64()?;
        if n > MAX_STRING {
            return Err(GgufError::Bounds);
        }
        let s = self.take(n)?;
        core::str::from_utf8(s).map_err(|_| GgufError::Utf8)?;
        Ok(s)
    }
}

fn scalar_size(t: u32) -> Option<u64> {
    Some(match t {
        vt::U8 | vt::I8 | vt::BOOL => 1,
        vt::U16 | vt::I16 => 2,
        vt::U32 | vt::I32 | vt::F32 => 4,
        vt::U64 | vt::I64 | vt::F64 => 8,
        _ => return None,
    })
}

/// Skip one value of type `t`; arrays may not nest.
fn skip_value(c: &mut Cur, t: u32, nested: bool) -> Result<(), GgufError> {
    if let Some(n) = scalar_size(t) {
        c.take(n)?;
        return Ok(());
    }
    match t {
        vt::STRING => {
            c.string()?;
        }
        vt::ARRAY if !nested => {
            let et = c.u32()?;
            let n = c.u64()?;
            if n > MAX_ARRAY {
                return Err(GgufError::Bounds);
            }
            if let Some(s) = scalar_size(et) {
                c.take(n.checked_mul(s).ok_or(GgufError::Bounds)?)?;
            } else if et == vt::STRING {
                for _ in 0..n {
                    c.string()?;
                }
            } else {
                return Err(GgufError::Type);
            }
        }
        _ => return Err(GgufError::Type),
    }
    Ok(())
}

/// A metadata value. Scalars are widened; binary32/binary64 come back as bits.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Value<'a> {
    Uint(u64),
    Int(i64),
    /// binary32 bits.
    Single(u32),
    /// binary64 bits.
    Double(u64),
    Bool(bool),
    Str(&'a [u8]),
    Array(Array<'a>),
}

/// An array value: element type, count, and the raw bytes of the elements.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Array<'a> {
    pub elem: u32,
    pub len: u64,
    raw: &'a [u8],
}

impl<'a> Array<'a> {
    /// Iterate a string array.
    pub fn strings(&self) -> Strings<'a> {
        Strings { c: Cur { b: self.raw, at: 0 }, left: if self.elem == vt::STRING { self.len } else { 0 } }
    }
    /// Element `i` of an integer array, widened.
    pub fn int(&self, i: u64) -> Option<i64> {
        let s = scalar_size(self.elem)?;
        let i = usize::try_from(i.checked_mul(s)?).ok()?;
        let b = self.raw.get(i..i + s as usize)?;
        let mut w = [0u8; 8];
        w.get_mut(..b.len())?.copy_from_slice(b);
        let u = u64::from_le_bytes(w);
        Some(match self.elem {
            vt::U8 | vt::U16 | vt::U32 | vt::U64 | vt::BOOL => u as i64,
            vt::I8 => i64::from(u as u8 as i8),
            vt::I16 => i64::from(u as u16 as i16),
            vt::I32 => i64::from(u as u32 as i32),
            vt::I64 => u as i64,
            _ => return None,
        })
    }
}

/// Iterator over a string array (already validated, so it yields exactly `len` items).
pub struct Strings<'a> {
    c: Cur<'a>,
    left: u64,
}

impl<'a> Iterator for Strings<'a> {
    type Item = &'a [u8];
    fn next(&mut self) -> Option<&'a [u8]> {
        if self.left == 0 {
            return None;
        }
        self.left -= 1;
        self.c.string().ok()
    }
}

fn read_value<'a>(c: &mut Cur<'a>, t: u32) -> Result<Value<'a>, GgufError> {
    Ok(match t {
        vt::U8 | vt::U16 | vt::U32 | vt::U64 => {
            let n = scalar_size(t).unwrap_or(0);
            let b = c.take(n)?;
            let mut w = [0u8; 8];
            w.get_mut(..b.len()).ok_or(GgufError::Bounds)?.copy_from_slice(b);
            Value::Uint(u64::from_le_bytes(w))
        }
        vt::I8 => Value::Int(i64::from(c.take(1)?.first().copied().unwrap_or(0) as i8)),
        vt::I16 => {
            let b = c.take(2)?;
            Value::Int(i64::from(i16::from_le_bytes([b.first().copied().unwrap_or(0), b.get(1).copied().unwrap_or(0)])))
        }
        vt::I32 => Value::Int(i64::from(c.u32()? as i32)),
        vt::I64 => Value::Int(c.u64()? as i64),
        vt::F32 => Value::Single(c.u32()?),
        vt::F64 => Value::Double(c.u64()?),
        vt::BOOL => Value::Bool(c.take(1)?.first().copied().unwrap_or(0) != 0),
        vt::STRING => Value::Str(c.string()?),
        vt::ARRAY => {
            let start = c.at;
            let elem = c.u32()?;
            let len = c.u64()?;
            let data = c.at;
            let mut probe = Cur { b: c.b, at: start };
            skip_value(&mut probe, vt::ARRAY, false)?;
            let raw = c.b.get(data..probe.at).ok_or(GgufError::Bounds)?;
            c.at = probe.at;
            Value::Array(Array { elem, len, raw })
        }
        _ => return Err(GgufError::Type),
    })
}

/// A tensor: type, dimensions (`dims[0]` is the fastest-varying, i.e. the row length), and its bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Tensor<'a> {
    pub name: &'a [u8],
    pub ty: u32,
    pub n_dims: usize,
    pub dims: [u64; MAX_DIMS],
    pub data: &'a [u8],
}

impl Tensor<'_> {
    pub fn elements(&self) -> u64 {
        self.dims.iter().take(self.n_dims).product()
    }
    /// (rows, cols) of a 2-D tensor.
    pub fn matrix(&self) -> Option<(usize, usize)> {
        if self.n_dims != 2 {
            return None;
        }
        Some((usize::try_from(*self.dims.get(1)?).ok()?, usize::try_from(*self.dims.first()?).ok()?))
    }
}

#[derive(Clone, Copy, Debug)]
pub struct Gguf<'a> {
    bytes: &'a [u8],
    n_tensors: u64,
    n_kv: u64,
    kv_at: usize,
    ti_at: usize,
    data_at: usize,
    pub alignment: u64,
}

/// (name, type, n_dims, dims, offset)
type TensorInfo<'a> = (&'a [u8], u32, usize, [u64; MAX_DIMS], u64);

fn read_tensor_info<'a>(c: &mut Cur<'a>) -> Result<TensorInfo<'a>, GgufError> {
    let name = c.string()?;
    let n_dims = c.u32()? as usize;
    if n_dims == 0 || n_dims > MAX_DIMS {
        return Err(GgufError::Bounds);
    }
    let mut dims = [1u64; MAX_DIMS];
    for d in dims.iter_mut().take(n_dims) {
        *d = c.u64()?;
        if *d == 0 || *d > (1 << 32) {
            return Err(GgufError::Bounds);
        }
    }
    let ty = c.u32()?;
    let off = c.u64()?;
    Ok((name, ty, n_dims, dims, off))
}

fn tensor_bytes(ty: u32, n_dims: usize, dims: &[u64; MAX_DIMS]) -> Result<u64, GgufError> {
    let (be, bb) = tt::block(ty).ok_or(GgufError::Type)?;
    let row = *dims.first().ok_or(GgufError::Bounds)?;
    if row % be != 0 {
        return Err(GgufError::Layout);
    }
    let mut n = (row / be).checked_mul(bb).ok_or(GgufError::Bounds)?;
    for d in dims.iter().take(n_dims).skip(1) {
        n = n.checked_mul(*d).ok_or(GgufError::Bounds)?;
    }
    Ok(n)
}

impl<'a> Gguf<'a> {
    /// Parse and validate. O(header size + number of tensors²) for the name-uniqueness check.
    pub fn open(bytes: &'a [u8]) -> Result<Self, GgufError> {
        let mut c = Cur { b: bytes, at: 0 };
        if c.take(4)? != MAGIC {
            return Err(GgufError::Magic);
        }
        if c.u32()? != 3 {
            return Err(GgufError::Version);
        }
        let n_tensors = c.u64()?;
        let n_kv = c.u64()?;
        if n_tensors > MAX_TENSORS || n_kv > MAX_KV {
            return Err(GgufError::Bounds);
        }
        let kv_at = c.at;
        let mut alignment = 32u64;
        for _ in 0..n_kv {
            let key = c.string()?;
            let t = c.u32()?;
            if key == b"general.alignment" {
                match read_value(&mut c, t)? {
                    Value::Uint(a) if t == vt::U32 && a.is_power_of_two() && (8..=65536).contains(&a) => alignment = a,
                    _ => return Err(GgufError::Layout),
                }
            } else {
                skip_value(&mut c, t, false)?;
            }
        }
        let ti_at = c.at;
        for _ in 0..n_tensors {
            read_tensor_info(&mut c)?;
        }
        let data_at = usize::try_from(u64::try_from(c.at).map_err(|_| GgufError::Bounds)?.div_ceil(alignment) * alignment).map_err(|_| GgufError::Bounds)?;
        if data_at > bytes.len() {
            return Err(GgufError::Bounds);
        }
        let g = Self { bytes, n_tensors, n_kv, kv_at, ti_at, data_at, alignment };
        // Tensors: aligned, inside the data, increasing and non-overlapping; names unique.
        let data_len = (bytes.len() - data_at) as u64;
        let mut end_prev = 0u64;
        let mut t = Cur { b: bytes, at: ti_at };
        for i in 0..n_tensors {
            let (name, ty, n_dims, dims, off) = read_tensor_info(&mut t)?;
            let size = tensor_bytes(ty, n_dims, &dims)?;
            let end = off.checked_add(size).ok_or(GgufError::Bounds)?;
            if off % alignment != 0 || off < end_prev || end > data_len {
                return Err(GgufError::Layout);
            }
            end_prev = end;
            let mut u = Cur { b: bytes, at: ti_at };
            for _ in 0..i {
                if read_tensor_info(&mut u)?.0 == name {
                    return Err(GgufError::Duplicate);
                }
            }
        }
        // Keys unique.
        let mut k = Cur { b: bytes, at: kv_at };
        for i in 0..n_kv {
            let key = k.string()?;
            let ty = k.u32()?;
            skip_value(&mut k, ty, false)?;
            let mut u = Cur { b: bytes, at: kv_at };
            for _ in 0..i {
                let other = u.string()?;
                let t2 = u.u32()?;
                skip_value(&mut u, t2, false)?;
                if other == key {
                    return Err(GgufError::Duplicate);
                }
            }
        }
        Ok(g)
    }

    pub fn tensor_count(&self) -> u64 {
        self.n_tensors
    }
    pub fn kv_count(&self) -> u64 {
        self.n_kv
    }

    /// Visit every metadata entry.
    pub fn for_each_kv(&self, mut f: impl FnMut(&'a [u8], Value<'a>)) {
        let mut c = Cur { b: self.bytes, at: self.kv_at };
        for _ in 0..self.n_kv {
            let (Ok(key), Ok(t)) = (c.string(), c.u32()) else { return };
            match read_value(&mut c, t) {
                Ok(v) => f(key, v),
                Err(_) => return,
            }
        }
    }

    /// Look up one metadata value.
    pub fn get(&self, key: &[u8]) -> Option<Value<'a>> {
        let mut found = None;
        self.for_each_kv(|k, v| {
            if k == key && found.is_none() {
                found = Some(v);
            }
        });
        found
    }

    pub fn get_uint(&self, key: &[u8]) -> Option<u64> {
        match self.get(key)? {
            Value::Uint(v) => Some(v),
            Value::Int(v) => u64::try_from(v).ok(),
            _ => None,
        }
    }
    pub fn get_single(&self, key: &[u8]) -> Option<u32> {
        match self.get(key)? {
            Value::Single(b) => Some(b),
            _ => None,
        }
    }
    pub fn get_str(&self, key: &[u8]) -> Option<&'a [u8]> {
        match self.get(key)? {
            Value::Str(s) => Some(s),
            _ => None,
        }
    }
    pub fn get_array(&self, key: &[u8]) -> Option<Array<'a>> {
        match self.get(key)? {
            Value::Array(a) => Some(a),
            _ => None,
        }
    }

    /// Visit every tensor in file order.
    pub fn for_each_tensor(&self, mut f: impl FnMut(Tensor<'a>)) {
        let mut c = Cur { b: self.bytes, at: self.ti_at };
        for _ in 0..self.n_tensors {
            let Ok((name, ty, n_dims, dims, off)) = read_tensor_info(&mut c) else { return };
            let Ok(size) = tensor_bytes(ty, n_dims, &dims) else { return };
            let start = self.data_at.saturating_add(off as usize);
            let Some(data) = self.bytes.get(start..start.saturating_add(size as usize)) else { return };
            f(Tensor { name, ty, n_dims, dims, data });
        }
    }

    pub fn tensor(&self, name: &[u8]) -> Option<Tensor<'a>> {
        let mut found = None;
        self.for_each_tensor(|t| {
            if t.name == name && found.is_none() {
                found = Some(t);
            }
        });
        found
    }
}
