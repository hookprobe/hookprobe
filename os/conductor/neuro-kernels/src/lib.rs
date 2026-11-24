// SPDX-License-Identifier: AGPL-3.0-only
//! Tensor kernels for neuro-engine.
//!
//! # Q4 GEMV, 4-row interleaved layout
//!
//! Weights are signed 4-bit values in −8..=7, two per byte: the LOW nibble is the even column, the HIGH
//! nibble the odd column. Rows are processed four at a time and stored interleaved, so that one pass over
//! the input serves four rows and the weight stream is read strictly forward (Neuro docs 02 §3 and 03 §4:
//! "layout is part of the model, not the runtime"):
//!
//! ```text
//! group (4 rows) = chunk 0 | chunk 1 | …        chunk (32 columns) = row0[16 B] row1[16 B] row2[16 B] row3[16 B]
//! ```
//!
//! Columns are padded to a multiple of 32 and rows to a multiple of 4 by the packer (zero weights).
//! Accumulation is int32 across the whole row with one integer rescale per row afterwards: no per-block
//! float scale (the "hidden tax" of doc 02 §3), so the inner loop is loads, nibble split and SDOT only.
#![no_std]
#![deny(clippy::indexing_slicing, clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::chunks_exact_to_as_chunks, clippy::manual_is_multiple_of)]

pub mod hp;
pub mod lm;
pub mod q8;

/// View int8 activations as the bytes the GEMV kernels read (same size and alignment; sound).
pub fn i8_bytes(x: &[i8]) -> &[u8] {
    // SAFETY: i8 and u8 have identical size and alignment and every bit pattern is valid for both.
    unsafe { core::slice::from_raw_parts(x.as_ptr().cast::<u8>(), x.len()) }
}

/// Columns per chunk and bytes per row per chunk.
pub const CHUNK_COLS: usize = 32;
pub const CHUNK_ROW_BYTES: usize = 16;
pub const GROUP_ROWS: usize = 4;

/// Bytes of packed weights for one 4-row group over `cols` columns (`cols` a multiple of 32).
pub const fn group_bytes(cols: usize) -> usize {
    cols / CHUNK_COLS * GROUP_ROWS * CHUNK_ROW_BYTES
}

/// Which implementation may run. `Scalar` is always available and is the reference.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Simd(Kind);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Kind {
    Scalar,
    #[cfg(all(target_arch = "aarch64", target_feature = "neon"))]
    NeonDot,
}

impl Simd {
    pub const SCALAR: Simd = Simd(Kind::Scalar);

    /// NEON + DotProd. Exists only in hard-float AArch64 builds (`aarch64-unknown-none`); the softfloat
    /// build used by every heqk server today has no SIMD path at all.
    ///
    /// # Safety
    /// The caller promises that this CPU implements AdvSIMD and DotProd (`ID_AA64ISAR0_EL1.DP`), and that
    /// FP/SIMD is enabled for the current context for as long as the token is used (on heqk: the server
    /// holds the KR-1 `FpSimd` grant).
    #[cfg(all(target_arch = "aarch64", target_feature = "neon"))]
    pub const unsafe fn neon_dot() -> Simd {
        Simd(Kind::NeonDot)
    }

    /// True for the NEON path (always false in builds without NEON).
    pub fn is_neon(self) -> bool {
        self.0 != Kind::Scalar
    }

    pub fn name(self) -> &'static str {
        match self.0 {
            Kind::Scalar => "scalar",
            #[cfg(all(target_arch = "aarch64", target_feature = "neon"))]
            Kind::NeonDot => "neon+dotprod",
        }
    }
}

#[inline]
fn nib(v: u8) -> i32 {
    // two's-complement 4-bit: 0..7 → 0..7, 8..15 → −8..−1
    (i32::from(v & 0x0f) ^ 8) - 8
}

/// Reference implementation. `acc[r] += Σ_c w[r][c] · x[c]` for the four rows of one group.
/// `x` holds int8 activations as bytes (the engine's arena is bytes).
/// Returns false (and changes nothing) if the lengths do not fit the layout.
pub fn gemv_q4_group_scalar(w: &[u8], x: &[u8], acc: &mut [i32; 4]) -> bool {
    if x.len() % CHUNK_COLS != 0 || w.len() != group_bytes(x.len()) {
        return false;
    }
    for (wc, xc) in w.chunks_exact(GROUP_ROWS * CHUNK_ROW_BYTES).zip(x.chunks_exact(CHUNK_COLS)) {
        for (a, row) in acc.iter_mut().zip(wc.chunks_exact(CHUNK_ROW_BYTES)) {
            let mut s: i32 = 0;
            for (b, xp) in row.iter().zip(xc.chunks_exact(2)) {
                if let [x0, x1] = *xp {
                    // |term| ≤ 8·128; a chunk sums to ≤ 32,768: no overflow inside a chunk.
                    s += nib(*b) * i32::from(x0 as i8) + nib(*b >> 4) * i32::from(x1 as i8);
                }
            }
            // The caller (engine admission) bounds the whole-row accumulator within i32.
            *a = a.wrapping_add(s);
        }
    }
    true
}

/// One 4-row group with the selected implementation. Same contract as the scalar reference.
pub fn gemv_q4_group(simd: Simd, w: &[u8], x: &[u8], acc: &mut [i32; 4]) -> bool {
    match simd.0 {
        Kind::Scalar => gemv_q4_group_scalar(w, x, acc),
        #[cfg(all(target_arch = "aarch64", target_feature = "neon"))]
        Kind::NeonDot => {
            if x.len() % CHUNK_COLS != 0 || w.len() != group_bytes(x.len()) {
                return false;
            }
            // SAFETY: lengths checked just above; the `Simd` token carries the CPU-feature promise.
            unsafe { neon::gemv_q4_group(w, x, acc) };
            true
        }
    }
}

#[cfg(all(target_arch = "aarch64", target_feature = "neon"))]
mod neon {
    use core::arch::aarch64::*;

    /// # Safety
    /// `x.len()` is a multiple of 32, `w.len() == x.len() / 32 * 64`, and the CPU has NEON + DotProd with
    /// FP/SIMD enabled.
    #[target_feature(enable = "neon,dotprod")]
    pub unsafe fn gemv_q4_group(w: &[u8], x: &[u8], acc: &mut [i32; 4]) {
        let chunks = x.len() / 32;
        let (mut wp, mut xp) = (w.as_ptr(), x.as_ptr());
        let m4 = vdupq_n_u8(0x0f);
        let eight = vdupq_n_u8(8);
        let mut a = [vdupq_n_s32(0); 4];
        for _ in 0..chunks {
            // De-interleave the 32 activations once; reuse for the four rows.
            let x0 = vreinterpretq_s8_u8(vld1q_u8(xp));
            let x1 = vreinterpretq_s8_u8(vld1q_u8(xp.add(16)));
            let xe = vuzp1q_s8(x0, x1); // even columns
            let xo = vuzp2q_s8(x0, x1); // odd columns
            for (r, ar) in a.iter_mut().enumerate() {
                let v = vld1q_u8(wp.add(16 * r));
                // nibble → signed: (n ^ 8) − 8
                let lo = vreinterpretq_s8_u8(vsubq_u8(veorq_u8(vandq_u8(v, m4), eight), eight));
                let hi = vreinterpretq_s8_u8(vsubq_u8(veorq_u8(vshrq_n_u8::<4>(v), eight), eight));
                *ar = vdotq_s32(*ar, lo, xe);
                *ar = vdotq_s32(*ar, hi, xo);
            }
            wp = wp.add(64);
            xp = xp.add(32);
        }
        for (o, v) in acc.iter_mut().zip(a) {
            *o = o.wrapping_add(vaddvq_s32(v));
        }
    }
}

/// Pack one group: `rows[r][c]` are weights in −8..=7 for four rows over `cols` columns (multiple of 32).
/// Build-side helper; returns false if a length or a value is out of range.
pub fn pack_group(rows: [&[i8]; 4], out: &mut [u8]) -> bool {
    let cols = rows[0].len();
    if cols % CHUNK_COLS != 0 || rows.iter().any(|r| r.len() != cols) || out.len() != group_bytes(cols) {
        return false;
    }
    if rows.iter().any(|r| r.iter().any(|v| !(-8..=7).contains(v))) {
        return false;
    }
    for (c, chunk) in out.chunks_exact_mut(GROUP_ROWS * CHUNK_ROW_BYTES).enumerate() {
        for (r, dst) in chunk.chunks_exact_mut(CHUNK_ROW_BYTES).enumerate() {
            let src = rows.get(r).and_then(|row| row.get(c * CHUNK_COLS..(c + 1) * CHUNK_COLS));
            let Some(src) = src else { return false };
            for (d, p) in dst.iter_mut().zip(src.chunks_exact(2)) {
                if let [lo, hi] = *p {
                    *d = (lo as u8 & 0x0f) | ((hi as u8 & 0x0f) << 4);
                }
            }
        }
    }
    true
}
