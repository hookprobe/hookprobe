// SPDX-License-Identifier: AGPL-3.0-only
//! neuro-engine N0: an integer specialist engine.
//!
//! A model package is data: a header, a memory plan (slots = byte ranges of one arena), an execution plan
//! (steps = kernel id + slots + weight references + parameters) and the weights, closed by a SHA-256 root.
//! [`Model::admit`] checks EVERYTHING once: structure, bounds, kernel ids, shapes, slot overlap, and a
//! worst-case bound proving no accumulator can overflow for any input. After admission, running a model
//! cannot fail, allocates nothing, and takes a fixed, known amount of work ([`Model::macs`]).
//!
//! The plan is interruptible: [`Model::step`] runs one step and returns, so an EL0 server can yield between
//! steps and keep the packet path's latency bound (Neuro `12` R7 b).
//!
//! Signature verification is NOT here: the kernel verifies a package before the engine sees it (R5). The
//! SHA-256 root only detects a damaged or mis-loaded package.
#![no_std]
#![forbid(unsafe_code)]
#![deny(
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation
)]

use sha2::{Digest, Sha256};

pub const MAGIC: [u8; 4] = *b"HNX0";
pub const VERSION: u16 = 0;
pub const ARCH_SPECIALIST: u8 = 1;
pub const TARGET_GENERIC_INT: u8 = 0;

pub const HEADER_LEN: usize = 32;
pub const SLOT_LEN: usize = 8;
pub const STEP_LEN: usize = 28;
pub const ROOT_LEN: usize = 32;
pub const MAX_SLOTS: usize = 16;
pub const MAX_STEPS: usize = 32;
pub const MAX_ARENA: usize = 64 * 1024;
pub const MAX_PACKAGE: usize = 1024 * 1024;

/// The closed kernel table. A package can only name these; new kernels are an engine update.
pub mod kernel {
    /// u8 inputs × i16 weights + i32 bias → i32 (little-endian) per row. The S1 specialist's shape.
    pub const AFFINE_U8_I16: u8 = 1;
    /// i8 inputs × i8 weights + i32 bias → requantised i8: clamp(round(acc·mult / 2^shift) + zero).
    pub const DENSE_I8: u8 = 2;
    /// max(x, 0) on i8, in place or to another slot of the same length.
    pub const RELU_I8: u8 = 3;
    /// Index of the first maximum of an i8 vector → one u8.
    pub const ARGMAX_I8: u8 = 4;
    /// One i32 compared with a threshold → one u8 (1 if greater).
    pub const GT_I32: u8 = 5;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refusal {
    Length,
    Magic,
    Version,
    Arch,
    Target,
    Counts,
    Root,
    Reserved,
    SlotOutOfArena,
    BadSlotIndex,
    UnknownKernel,
    Shape,
    WeightsOutOfBounds,
    SlotsOverlap,
    /// Some input could overflow the accumulator: refused, never wrapped.
    AccumulatorBound,
    Params,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct Slot {
    off: usize,
    len: usize,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct Step {
    kernel: u8,
    shift: u8,
    input: Slot,
    output: Slot,
    rows: usize,
    cols: usize,
    /// Absolute byte ranges inside the package, validated at admission.
    w: Slot,
    b: Slot,
    mult: i32,
    zero: i32,
}

/// An admitted model: the package plus its validated plan.
#[derive(Clone, Copy, Debug)]
pub struct Model<'p> {
    pkg: &'p [u8],
    steps: [Step; MAX_STEPS],
    n_steps: usize,
    arena_bytes: usize,
    input: Slot,
    output: Slot,
    macs: u64,
    root: [u8; 32],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RunError {
    ArenaTooSmall,
    InputLength,
    OutputLength,
    /// `step` called with a cursor past the end.
    Finished,
}

struct Rd<'a> {
    b: &'a [u8],
    i: usize,
}

impl<'a> Rd<'a> {
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let end = self.i.checked_add(n)?;
        let s = self.b.get(self.i..end)?;
        self.i = end;
        Some(s)
    }
    fn u8(&mut self) -> Option<u8> {
        self.take(1)?.first().copied()
    }
    fn u16(&mut self) -> Option<u16> {
        Some(u16::from_le_bytes(self.take(2)?.try_into().ok()?))
    }
    fn u32(&mut self) -> Option<u32> {
        Some(u32::from_le_bytes(self.take(4)?.try_into().ok()?))
    }
    fn i32(&mut self) -> Option<i32> {
        Some(i32::from_le_bytes(self.take(4)?.try_into().ok()?))
    }
}

fn overlaps(a: Slot, b: Slot) -> bool {
    let (ae, be) = (a.off.saturating_add(a.len), b.off.saturating_add(b.len));
    a.off < be && b.off < ae
}

fn i16_at(b: &[u8], i: usize) -> i64 {
    let o = i.saturating_mul(2);
    match b.get(o..o.saturating_add(2)) {
        Some(&[x, y]) => i64::from(i16::from_le_bytes([x, y])),
        _ => 0,
    }
}

fn i32_at(b: &[u8], i: usize) -> i64 {
    let o = i.saturating_mul(4);
    match b.get(o..o.saturating_add(4)) {
        Some(&[a, c, d, e]) => i64::from(i32::from_le_bytes([a, c, d, e])),
        _ => 0,
    }
}

impl<'p> Model<'p> {
    /// Validate a package completely. Nothing is trusted before this returns `Ok`.
    pub fn admit(pkg: &'p [u8]) -> Result<Self, Refusal> {
        use Refusal as R;
        if pkg.len() < HEADER_LEN.saturating_add(ROOT_LEN) || pkg.len() > MAX_PACKAGE {
            return Err(R::Length);
        }
        let body_len = pkg.len().saturating_sub(ROOT_LEN);
        let (body, root_bytes) = pkg.split_at(body_len);
        let mut r = Rd { b: body, i: 0 };
        let l = R::Length;
        if r.take(4).ok_or(l)? != MAGIC {
            return Err(R::Magic);
        }
        if r.u16().ok_or(l)? != VERSION {
            return Err(R::Version);
        }
        if r.u8().ok_or(l)? != ARCH_SPECIALIST {
            return Err(R::Arch);
        }
        if r.u8().ok_or(l)? != TARGET_GENERIC_INT {
            return Err(R::Target);
        }
        let n_slots = usize::from(r.u16().ok_or(l)?);
        let n_steps = usize::from(r.u16().ok_or(l)?);
        let arena_bytes = usize::try_from(r.u32().ok_or(l)?).map_err(|_| l)?;
        let weights_len = usize::try_from(r.u32().ok_or(l)?).map_err(|_| l)?;
        let in_slot = usize::from(r.u16().ok_or(l)?);
        let out_slot = usize::from(r.u16().ok_or(l)?);
        if r.take(8).ok_or(l)?.iter().any(|&x| x != 0) {
            return Err(R::Reserved);
        }
        if n_slots == 0 || n_slots > MAX_SLOTS || n_steps == 0 || n_steps > MAX_STEPS || arena_bytes == 0 || arena_bytes > MAX_ARENA {
            return Err(R::Counts);
        }
        // Exact length: header + slots + steps + weights + root, nothing else.
        let expect = HEADER_LEN
            .checked_add(n_slots.checked_mul(SLOT_LEN).ok_or(l)?)
            .and_then(|v| v.checked_add(n_steps.checked_mul(STEP_LEN)?))
            .and_then(|v| v.checked_add(weights_len))
            .ok_or(l)?;
        if expect != body_len {
            return Err(R::Length);
        }
        // Integrity before any further parsing.
        let digest: [u8; 32] = Sha256::digest(body).into();
        if root_bytes != digest {
            return Err(R::Root);
        }
        let mut slots = [Slot::default(); MAX_SLOTS];
        for s in slots.iter_mut().take(n_slots) {
            let off = usize::try_from(r.u32().ok_or(l)?).map_err(|_| l)?;
            let len = usize::try_from(r.u32().ok_or(l)?).map_err(|_| l)?;
            let end = off.checked_add(len).ok_or(R::SlotOutOfArena)?;
            if len == 0 || end > arena_bytes {
                return Err(R::SlotOutOfArena);
            }
            *s = Slot { off, len };
        }
        let slot = |i: usize| -> Result<Slot, Refusal> {
            if i >= n_slots {
                return Err(R::BadSlotIndex);
            }
            slots.get(i).copied().ok_or(R::BadSlotIndex)
        };
        let weights_base = HEADER_LEN.saturating_add(n_slots.saturating_mul(SLOT_LEN)).saturating_add(n_steps.saturating_mul(STEP_LEN));
        let wrange = |off: u32, len: usize| -> Result<Slot, Refusal> {
            let off = usize::try_from(off).map_err(|_| R::WeightsOutOfBounds)?;
            let end = off.checked_add(len).ok_or(R::WeightsOutOfBounds)?;
            if end > weights_len {
                return Err(R::WeightsOutOfBounds);
            }
            Ok(Slot { off: weights_base.saturating_add(off), len })
        };
        let mut steps = [Step::default(); MAX_STEPS];
        let mut macs: u64 = 0;
        for st in steps.iter_mut().take(n_steps) {
            let k = r.u8().ok_or(l)?;
            let shift = r.u8().ok_or(l)?;
            let input = slot(usize::from(r.u16().ok_or(l)?))?;
            let output = slot(usize::from(r.u16().ok_or(l)?))?;
            let rows = usize::from(r.u16().ok_or(l)?);
            let cols = usize::from(r.u16().ok_or(l)?);
            if r.u16().ok_or(l)? != 0 {
                return Err(R::Reserved);
            }
            let w_off = r.u32().ok_or(l)?;
            let b_off = r.u32().ok_or(l)?;
            let mult = r.i32().ok_or(l)?;
            let zero = r.i32().ok_or(l)?;
            let cells = rows.checked_mul(cols).ok_or(R::Shape)?;
            let none = Slot::default();
            let (w, b) = match k {
                kernel::AFFINE_U8_I16 => {
                    if rows == 0 || cols == 0 || input.len != cols || Some(output.len) != rows.checked_mul(4) || shift != 0 || mult != 0 || zero != 0 {
                        return Err(R::Shape);
                    }
                    (wrange(w_off, cells.checked_mul(2).ok_or(R::Shape)?)?, wrange(b_off, rows.checked_mul(4).ok_or(R::Shape)?)?)
                }
                kernel::DENSE_I8 => {
                    if rows == 0 || cols == 0 || input.len != cols || output.len != rows {
                        return Err(R::Shape);
                    }
                    if shift > 31 || mult < 0 || !(-128..=127).contains(&zero) {
                        return Err(R::Params);
                    }
                    (wrange(w_off, cells)?, wrange(b_off, rows.checked_mul(4).ok_or(R::Shape)?)?)
                }
                kernel::RELU_I8 => {
                    if input.len != output.len || rows != 0 || cols != 0 || shift != 0 || mult != 0 || zero != 0 || w_off != 0 || b_off != 0 {
                        return Err(R::Shape);
                    }
                    (none, none)
                }
                kernel::ARGMAX_I8 => {
                    if output.len != 1 || input.len > 256 || rows != 0 || cols != 0 || shift != 0 || mult != 0 || zero != 0 || w_off != 0 || b_off != 0 {
                        return Err(R::Shape);
                    }
                    (none, none)
                }
                kernel::GT_I32 => {
                    if input.len != 4 || output.len != 1 || rows != 0 || cols != 0 || shift != 0 || mult != 0 || w_off != 0 || b_off != 0 {
                        return Err(R::Shape);
                    }
                    (none, none)
                }
                _ => return Err(R::UnknownKernel),
            };
            // In place is allowed only for RELU on the identical slot.
            let same = input == output;
            if overlaps(input, output) && !(k == kernel::RELU_I8 && same) {
                return Err(R::SlotsOverlap);
            }
            // Worst-case accumulator: |bias| + Σ|w|·max|x| must fit an i32, for every row.
            if k == kernel::AFFINE_U8_I16 || k == kernel::DENSE_I8 {
                let (wb, bb) = (pkg.get(w.off..w.off.saturating_add(w.len)).ok_or(R::WeightsOutOfBounds)?, pkg.get(b.off..b.off.saturating_add(b.len)).ok_or(R::WeightsOutOfBounds)?);
                let xmax: i64 = if k == kernel::AFFINE_U8_I16 { 255 } else { 128 };
                for row in 0..rows {
                    let mut bound = i32_at(bb, row).abs();
                    for col in 0..cols {
                        let idx = row.saturating_mul(cols).saturating_add(col);
                        let wv = if k == kernel::AFFINE_U8_I16 { i16_at(wb, idx) } else { i64::from(wb.get(idx).copied().unwrap_or(0) as i8) };
                        bound = bound.saturating_add(wv.abs().saturating_mul(xmax));
                    }
                    if bound > i64::from(i32::MAX) {
                        return Err(R::AccumulatorBound);
                    }
                }
                macs = macs.saturating_add(u64::try_from(cells).unwrap_or(u64::MAX));
            }
            *st = Step { kernel: k, shift, input, output, rows, cols, w, b, mult, zero };
        }
        let mut root = [0u8; 32];
        root.copy_from_slice(root_bytes);
        Ok(Self { pkg, steps, n_steps, arena_bytes, input: slot(in_slot)?, output: slot(out_slot)?, macs, root })
    }

    /// Bytes of scratch memory a run needs (the admission grant; nothing else is ever touched).
    pub fn arena_bytes(&self) -> usize {
        self.arena_bytes
    }
    pub fn input_len(&self) -> usize {
        self.input.len
    }
    pub fn output_len(&self) -> usize {
        self.output.len
    }
    pub fn steps(&self) -> usize {
        self.n_steps
    }
    /// Multiply-accumulates per run: the model's fixed work, known before it runs.
    pub fn macs(&self) -> u64 {
        self.macs
    }
    /// The package root hash (what an evidence record names as "the model that produced this").
    pub fn root(&self) -> &[u8; 32] {
        &self.root
    }

    /// Copy the input into its slot. Then call [`Model::step`] until it returns `Ok(false)`.
    pub fn begin(&self, arena: &mut [u8], input: &[u8]) -> Result<usize, RunError> {
        if arena.len() < self.arena_bytes {
            return Err(RunError::ArenaTooSmall);
        }
        if input.len() != self.input.len {
            return Err(RunError::InputLength);
        }
        let end = self.input.off.saturating_add(self.input.len);
        arena.get_mut(self.input.off..end).ok_or(RunError::ArenaTooSmall)?.copy_from_slice(input);
        Ok(0)
    }

    /// Run one step. Returns `Ok(true)` while steps remain. Safe to interleave with anything else.
    pub fn step(&self, arena: &mut [u8], cursor: &mut usize) -> Result<bool, RunError> {
        if arena.len() < self.arena_bytes {
            return Err(RunError::ArenaTooSmall);
        }
        let st = self.steps.get(*cursor).filter(|_| *cursor < self.n_steps).ok_or(RunError::Finished)?;
        exec(self.pkg, st, arena);
        *cursor = cursor.saturating_add(1);
        Ok(*cursor < self.n_steps)
    }

    pub fn finish(&self, arena: &[u8], output: &mut [u8]) -> Result<(), RunError> {
        if output.len() != self.output.len {
            return Err(RunError::OutputLength);
        }
        let end = self.output.off.saturating_add(self.output.len);
        output.copy_from_slice(arena.get(self.output.off..end).ok_or(RunError::ArenaTooSmall)?);
        Ok(())
    }

    /// Run the whole plan.
    pub fn run(&self, arena: &mut [u8], input: &[u8], output: &mut [u8]) -> Result<(), RunError> {
        let mut c = self.begin(arena, input)?;
        while self.step(arena, &mut c)? {}
        self.finish(arena, output)
    }
}

/// Execute one validated step. Every range was checked at admission; `get` keeps this panic-free anyway.
fn exec(pkg: &[u8], st: &Step, arena: &mut [u8]) {
    let w = pkg.get(st.w.off..st.w.off.saturating_add(st.w.len)).unwrap_or(&[]);
    let b = pkg.get(st.b.off..st.b.off.saturating_add(st.b.len)).unwrap_or(&[]);
    let (i0, i1) = (st.input.off, st.input.off.saturating_add(st.input.len));
    let (o0, o1) = (st.output.off, st.output.off.saturating_add(st.output.len));
    match st.kernel {
        kernel::RELU_I8 if st.input == st.output => {
            for v in arena.get_mut(i0..i1).unwrap_or(&mut []) {
                if (*v as i8) < 0 {
                    *v = 0;
                }
            }
        }
        _ => {
            // Input and output never overlap here (admission), so split the arena around them.
            let (lo, hi, in_first) = if i0 < o0 { (i1, o0, true) } else { (o1, i0, false) };
            let (head, tail) = arena.split_at_mut(hi);
            let (input, output): (&[u8], &mut [u8]) = if in_first {
                (head.get(i0..lo).unwrap_or(&[]), tail.get_mut(..st.output.len).unwrap_or(&mut []))
            } else {
                (tail.get(..st.input.len).unwrap_or(&[]), head.get_mut(o0..lo).unwrap_or(&mut []))
            };
            match st.kernel {
                kernel::AFFINE_U8_I16 => {
                    for (row, out) in output.as_chunks_mut::<4>().0.iter_mut().enumerate() {
                        let mut acc = i32_at(b, row);
                        let base = row.saturating_mul(st.cols);
                        for (col, &x) in input.iter().enumerate() {
                            // Cannot overflow: admission bounded |bias| + Σ|w|·255 by i32::MAX.
                            acc = acc.saturating_add(i16_at(w, base.saturating_add(col)).saturating_mul(i64::from(x)));
                        }
                        *out = i32::try_from(acc).unwrap_or(0).to_le_bytes();
                    }
                }
                kernel::DENSE_I8 => {
                    let round: i64 = if st.shift == 0 { 0 } else { 1i64 << (st.shift.saturating_sub(1)) };
                    for (row, out) in output.iter_mut().enumerate() {
                        let mut acc = i32_at(b, row);
                        let base = row.saturating_mul(st.cols);
                        for (col, &x) in input.iter().enumerate() {
                            let wv = i64::from(w.get(base.saturating_add(col)).copied().unwrap_or(0) as i8);
                            acc = acc.saturating_add(wv.saturating_mul(i64::from(x as i8)));
                        }
                        let y = (acc.saturating_mul(i64::from(st.mult)).saturating_add(round) >> st.shift).saturating_add(i64::from(st.zero));
                        *out = i8::try_from(y.clamp(-128, 127)).unwrap_or(0).to_le_bytes()[0];
                    }
                }
                kernel::RELU_I8 => {
                    for (o, &x) in output.iter_mut().zip(input) {
                        *o = if (x as i8) < 0 { 0 } else { x };
                    }
                }
                kernel::ARGMAX_I8 => {
                    let mut best = (0usize, i8::MIN);
                    for (i, &x) in input.iter().enumerate() {
                        if (x as i8) > best.1 || i == 0 {
                            best = (i, x as i8);
                        }
                    }
                    if let Some(o) = output.first_mut() {
                        *o = u8::try_from(best.0).unwrap_or(u8::MAX);
                    }
                }
                kernel::GT_I32 => {
                    let v = i32_at(input, 0);
                    if let Some(o) = output.first_mut() {
                        *o = u8::from(v > i64::from(st.zero));
                    }
                }
                _ => {}
            }
        }
    }
}

/// Build-side helpers (the first piece of `hnx-compile`). `no_std`, writes into the caller's buffer.
pub mod pack {
    use super::*;

    #[derive(Clone, Copy, Debug, Default)]
    pub struct StepDef {
        pub kernel: u8,
        pub shift: u8,
        pub input: u16,
        pub output: u16,
        pub rows: u16,
        pub cols: u16,
        pub w_off: u32,
        pub b_off: u32,
        pub mult: i32,
        pub zero: i32,
    }

    struct W<'a> {
        b: &'a mut [u8],
        n: usize,
    }
    impl W<'_> {
        fn put(&mut self, s: &[u8]) -> Option<()> {
            let end = self.n.checked_add(s.len())?;
            self.b.get_mut(self.n..end)?.copy_from_slice(s);
            self.n = end;
            Some(())
        }
    }

    /// Lay out a package and seal it with its SHA-256 root. Returns its length.
    pub fn package(out: &mut [u8], slots: &[(u32, u32)], steps: &[StepDef], weights: &[u8], arena: u32, in_slot: u16, out_slot: u16) -> Option<usize> {
        let mut w = W { b: out, n: 0 };
        w.put(&MAGIC)?;
        w.put(&VERSION.to_le_bytes())?;
        w.put(&[ARCH_SPECIALIST, TARGET_GENERIC_INT])?;
        w.put(&u16::try_from(slots.len()).ok()?.to_le_bytes())?;
        w.put(&u16::try_from(steps.len()).ok()?.to_le_bytes())?;
        w.put(&arena.to_le_bytes())?;
        w.put(&u32::try_from(weights.len()).ok()?.to_le_bytes())?;
        w.put(&in_slot.to_le_bytes())?;
        w.put(&out_slot.to_le_bytes())?;
        w.put(&[0; 8])?;
        for (o, l) in slots {
            w.put(&o.to_le_bytes())?;
            w.put(&l.to_le_bytes())?;
        }
        for s in steps {
            w.put(&[s.kernel, s.shift])?;
            for v in [s.input, s.output, s.rows, s.cols, 0] {
                w.put(&v.to_le_bytes())?;
            }
            w.put(&s.w_off.to_le_bytes())?;
            w.put(&s.b_off.to_le_bytes())?;
            w.put(&s.mult.to_le_bytes())?;
            w.put(&s.zero.to_le_bytes())?;
        }
        w.put(weights)?;
        let n = w.n;
        let d: [u8; 32] = Sha256::digest(w.b.get(..n)?).into();
        w.put(&d)?;
        Some(w.n)
    }

    /// A one-row linear specialist (u8 features × i16 weights + bias, then a threshold): the S1 shape.
    /// Output: score (i32 LE) followed by the alert byte.
    pub fn linear_specialist(out: &mut [u8], weights_i16: &[i16], bias: i32, threshold: i32) -> Option<usize> {
        let n = weights_i16.len();
        let mut wb = [0u8; 2 * 256 + 4];
        if n == 0 || n > 256 {
            return None;
        }
        for (i, v) in weights_i16.iter().enumerate() {
            wb.get_mut(i.checked_mul(2)?..i.checked_mul(2)?.checked_add(2)?)?.copy_from_slice(&v.to_le_bytes());
        }
        let b_off = n.checked_mul(2)?;
        wb.get_mut(b_off..b_off.checked_add(4)?)?.copy_from_slice(&bias.to_le_bytes());
        let nn = u32::try_from(n).ok()?;
        let slots = [(0, nn), (nn, 4), (nn.checked_add(4)?, 1), (nn, 5)];
        let steps = [
            StepDef { kernel: kernel::AFFINE_U8_I16, input: 0, output: 1, rows: 1, cols: u16::try_from(n).ok()?, w_off: 0, b_off: u32::try_from(b_off).ok()?, ..StepDef::default() },
            StepDef { kernel: kernel::GT_I32, input: 1, output: 2, zero: threshold, ..StepDef::default() },
        ];
        package(out, &slots, &steps, wb.get(..b_off.checked_add(4)?)?, nn.checked_add(5)?, 0, 3)
    }
}
