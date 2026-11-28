// SPDX-License-Identifier: AGPL-3.0-only
//! A language-model bundle: everything the device needs to run the model, in one signed payload.
//!
//! A GGUF file alone is not enough on a device with no float and no build tools: the tokenizer needs its
//! Unicode and merge tables, and the decoder needs the RoPE rotation table, which is computed with
//! trigonometry. Both are made on the build host. The bundle carries them beside the model, under the same
//! signature, so the device derives nothing.
//!
//! ```text
//! "HLMB" | version u16 = 1 | n u16 | 0 u64                       16 bytes
//! n × { kind u32 | 0 u32 | offset u64 | len u64 }                24 bytes each
//! sections, in table order, each starting on a 64-byte boundary; zero padding between; nothing after
//! ```
//! Version 1 has exactly three sections, in this order: [`GGUF`], [`TOKENIZER`], [`ROPE`]. Offsets are from the
//! start of the bundle. A 64-byte boundary keeps GGUF's own 32-byte tensor alignment and puts every section on
//! a cache line. Everything is little-endian. Any other shape is refused.
//!
//! The tables are covered by the signature, not re-derived: the device cannot compute a cosine. What admission
//! does check is that they fit the model (`crate::hnx::admit`): the RoPE table has exactly the rows the
//! context and head size need, and the tokenizer tables parse and have the model's vocabulary size.

/// The model: a GGUF file, as it is.
pub const GGUF: u32 = 1;
/// The tokenizer blob `neuro_lm::tok::Tokenizer` reads.
pub const TOKENIZER: u32 = 2;
/// RoPE `(cos, sin)` pairs, two `i32` each, `positions × head_dim / 2` of them, position-major.
pub const ROPE: u32 = 3;

pub const MAGIC: [u8; 4] = *b"HLMB";
pub const VERSION: u16 = 1;
pub const SECTIONS: usize = 3;
pub const ALIGN: usize = 64;
const HEAD: usize = 16;
const ENTRY: usize = 24;
/// Bytes before the first section, padded to the alignment.
pub const PREAMBLE: usize = (HEAD + SECTIONS * ENTRY).div_ceil(ALIGN) * ALIGN;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BundleError {
    Length,
    Magic,
    Version,
    /// Not exactly the three sections, in order, aligned, padded with zeros, with nothing after.
    Layout,
}

#[derive(Clone, Copy, Debug)]
pub struct Bundle<'a> {
    pub gguf: &'a [u8],
    pub tokenizer: &'a [u8],
    rope: &'a [u8],
}

fn u64_at(b: &[u8], at: usize) -> Option<u64> {
    Some(u64::from_le_bytes(b.get(at..at.checked_add(8)?)?.try_into().ok()?))
}

fn u32_at(b: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_le_bytes(b.get(at..at.checked_add(4)?)?.try_into().ok()?))
}

/// Where the three sections go for these lengths, and the bundle's total length.
pub fn layout(lens: [usize; SECTIONS]) -> Option<([usize; SECTIONS], usize)> {
    let mut offs = [0usize; SECTIONS];
    let mut at = PREAMBLE;
    for (o, len) in offs.iter_mut().zip(lens) {
        *o = at;
        at = at.checked_add(len)?.checked_next_multiple_of(ALIGN)?;
    }
    // Nothing after the last section: the total is its end, not the next boundary.
    let last = SECTIONS.checked_sub(1)?;
    let total = offs.get(last)?.checked_add(*lens.get(last)?)?;
    Some((offs, total))
}

/// Build side: write the preamble for sections of these lengths into `out` (at least [`PREAMBLE`] bytes).
pub fn write_preamble(lens: [usize; SECTIONS], out: &mut [u8]) -> Option<()> {
    let (offs, _) = layout(lens)?;
    let out = out.get_mut(..PREAMBLE)?;
    out.fill(0);
    out.get_mut(..4)?.copy_from_slice(&MAGIC);
    out.get_mut(4..6)?.copy_from_slice(&VERSION.to_le_bytes());
    out.get_mut(6..8)?.copy_from_slice(&u16::try_from(SECTIONS).ok()?.to_le_bytes());
    for (i, kind) in [GGUF, TOKENIZER, ROPE].into_iter().enumerate() {
        let at = HEAD.checked_add(i.checked_mul(ENTRY)?)?;
        out.get_mut(at..at.checked_add(4)?)?.copy_from_slice(&kind.to_le_bytes());
        out.get_mut(at.checked_add(8)?..at.checked_add(16)?)?.copy_from_slice(&u64::try_from(*offs.get(i)?).ok()?.to_le_bytes());
        out.get_mut(at.checked_add(16)?..at.checked_add(24)?)?.copy_from_slice(&u64::try_from(*lens.get(i)?).ok()?.to_le_bytes());
    }
    Some(())
}

impl<'a> Bundle<'a> {
    pub fn open(b: &'a [u8]) -> Result<Self, BundleError> {
        let head = b.get(..PREAMBLE).ok_or(BundleError::Length)?;
        if head.get(..4) != Some(&MAGIC[..]) {
            return Err(BundleError::Magic);
        }
        if head.get(4..6) != Some(&VERSION.to_le_bytes()[..]) {
            return Err(BundleError::Version);
        }
        let l = BundleError::Layout;
        if head.get(6..8) != Some(&[3, 0][..]) {
            return Err(l);
        }
        let mut lens = [0usize; SECTIONS];
        for (i, kind) in [GGUF, TOKENIZER, ROPE].into_iter().enumerate() {
            let at = HEAD.saturating_add(i.saturating_mul(ENTRY));
            if u32_at(head, at) != Some(kind) {
                return Err(l);
            }
            let len = u64_at(head, at.saturating_add(16)).and_then(|v| usize::try_from(v).ok()).ok_or(l)?;
            *lens.get_mut(i).ok_or(l)? = len;
        }
        // The preamble must be the one these lengths give: canonical offsets, zero in every other field.
        let (offs, total) = layout(lens).ok_or(l)?;
        let mut want = [0u8; PREAMBLE];
        write_preamble(lens, &mut want).ok_or(l)?;
        if head != want || b.len() != total {
            return Err(l);
        }
        let sec = |i: usize| -> Result<&'a [u8], BundleError> {
            let (o, n) = (*offs.get(i).ok_or(l)?, *lens.get(i).ok_or(l)?);
            b.get(o..o.saturating_add(n)).ok_or(l)
        };
        // Padding between sections is zero, so no byte of the payload is unaccounted for.
        for i in 0..SECTIONS.saturating_sub(1) {
            let end = offs.get(i).ok_or(l)?.saturating_add(*lens.get(i).ok_or(l)?);
            let next = *offs.get(i.saturating_add(1)).ok_or(l)?;
            if b.get(end..next).ok_or(l)?.iter().any(|x| *x != 0) {
                return Err(l);
            }
        }
        let rope = sec(2)?;
        if !rope.len().is_multiple_of(8) {
            return Err(l);
        }
        Ok(Self { gguf: sec(0)?, tokenizer: sec(1)?, rope })
    }

    /// `(cos, sin)` pairs in the RoPE table.
    pub fn rope_pairs(&self) -> usize {
        self.rope.len() / 8
    }

    /// Copy the RoPE table into the server's arena (admission counts it there). `out` must be exactly
    /// [`Bundle::rope_pairs`] long.
    pub fn rope_into(&self, out: &mut [(i32, i32)]) -> Option<()> {
        if out.len() != self.rope_pairs() {
            return None;
        }
        for (o, c) in out.iter_mut().zip(self.rope.as_chunks::<8>().0) {
            let [c0, c1, c2, c3, s0, s1, s2, s3] = *c;
            *o = (i32::from_le_bytes([c0, c1, c2, c3]), i32::from_le_bytes([s0, s1, s2, s3]));
        }
        Some(())
    }
}
