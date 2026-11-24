// SPDX-License-Identifier: AGPL-3.0-only
//! 8-bit weights in the GGUF `Q8_0` layout, run with integers only.
//!
//! A `Q8_0` block is 34 bytes: a binary16 scale `d` (little-endian bits) followed by 32 signed bytes `q`;
//! the weight is `d · q`. Rows are consecutive blocks, exactly as llama.cpp stores them, so the bytes the
//! device runs are the bytes of the GGUF file that Neuro validated (a converter copies them; it does not
//! re-quantise).
//!
//! Activations are quantised the way llama.cpp's CPU path does for `Q8_0` weights: per block of 32, scale
//! `amax / 127`, `q = round(x / scale)`. Here `x` is a 64-bit fixed-point value with 16 fraction bits
//! ([`hp`](crate::hp)), and the activation scale is kept as an integer mantissa (about 15 bits) and a
//! power-of-two exponent. The binary16 weight scale is decoded with integer operations only.
//!
//! One output row: `Σ_b dot_b · d_b · s_b`, where `dot_b` is the int32 dot product of block `b`
//! (SDOT on NEON), accumulated in i128 at 2^-24 of the output unit. Overflow is impossible for any input:
//! `|dot · mantissa_w · mantissa_x| < 2^46`, the block exponent is at most 70, and rows have at most 1,024
//! blocks (32,768 columns), so `|sum| < 2^126`.

/// Columns per block and bytes per block.
pub const QK: usize = 32;
pub const BLOCK_BYTES: usize = 34;
/// Largest supported row length (columns).
pub const MAX_COLS: usize = 32 * 1024;
/// Fraction bits of the accumulator, below the output unit.
const ACC_FRAC: u32 = 24;

/// Bytes of one row of `cols` columns.
pub const fn row_bytes(cols: usize) -> usize {
    cols / QK * BLOCK_BYTES
}

/// binary16 bits → `(mantissa, shift)` with value = mantissa · 2^-shift. Infinity and NaN decode to 0
/// (admission refuses them; see [`scales_finite`]).
#[inline]
pub fn half_parts(bits: u16) -> (i32, i32) {
    let e = i32::from((bits >> 10) & 0x1f);
    let f = i32::from(bits & 0x3ff);
    let (m, s) = match e {
        0 => (f, 24),
        31 => (0, 0),
        _ => (1024 + f, 25 - e),
    };
    (if bits & 0x8000 != 0 { -m } else { m }, s)
}

/// True if every block scale in `w` is finite (no infinity or NaN). An admission-time check.
pub fn scales_finite(w: &[u8]) -> bool {
    w.chunks_exact(BLOCK_BYTES).all(|b| match b {
        [lo, hi, ..] => (u16::from_le_bytes([*lo, *hi]) >> 10) & 0x1f != 31,
        _ => false,
    })
}

/// Round-half-away-from-zero division of an i128 by 2^s (s ≤ 126).
#[inline]
fn rshift_round_128(v: i128, s: u32) -> i128 {
    if s == 0 {
        return v;
    }
    let half = 1i128 << (s - 1);
    if v >= 0 {
        (v + half) >> s
    } else {
        -((-v + half) >> s)
    }
}

/// Activations quantised per block: `x ≈ q · m · 2^e` (in the fixed-point unit of the input).
#[derive(Clone, Copy, Debug)]
pub struct Act<'a> {
    pub q: &'a [i8],
    pub scale: &'a [(i32, i32)],
}

/// Quantise `x` (any fixed-point unit, here 2^-16) per block of 32. `q.len() == x.len()`,
/// `scale.len() == x.len() / 32`. Returns false (changing nothing) on a length mismatch.
pub fn quantize(x: &[i64], q: &mut [i8], scale: &mut [(i32, i32)]) -> bool {
    if x.len() % QK != 0 || x.len() > MAX_COLS || q.len() != x.len() || scale.len() != x.len() / QK {
        return false;
    }
    for ((xb, qb), sc) in x.chunks_exact(QK).zip(q.chunks_exact_mut(QK)).zip(scale.iter_mut()) {
        let amax = xb.iter().map(|v| v.unsigned_abs()).max().unwrap_or(0);
        if amax == 0 {
            qb.fill(0);
            *sc = (0, 0);
            continue;
        }
        let a = i128::from(amax);
        for (o, &v) in qb.iter_mut().zip(xb) {
            // round(v · 127 / amax), |result| ≤ 127
            let num = i128::from(v) * 127;
            let r = if num >= 0 { (num + a / 2) / a } else { -((-num + a / 2) / a) };
            *o = r.clamp(-127, 127) as i8;
        }
        // scale = amax / 127 = m · 2^e with m ≈ 2^14..2^15.
        let b = 64 - amax.leading_zeros() as i32; // bit length, 1..=64
        let t = 22 - b; // amax · 2^t / 127 lands in [2^14, 2^16)
        let m = if t >= 0 {
            let num = a << t;
            (num + 63) / 127
        } else {
            let den = 127i128 << (-t);
            (a + den / 2) / den
        };
        *sc = (m as i32, -t);
    }
    true
}

#[inline(always)]
fn combine(acc: &mut i128, dot: i32, wbits: u16, xs: (i32, i32)) {
    let (mw, sw) = half_parts(wbits);
    // |dot| < 2^19, |mw| < 2^11, 0 ≤ m < 2^16: |term| < 2^46, so the wrapping ops below never wrap; they only
    // drop the overflow checks the release profile keeps elsewhere (this is the innermost loop).
    let term = i64::from(dot).wrapping_mul(i64::from(mw)).wrapping_mul(i64::from(xs.0));
    let e = xs.1 - sw + ACC_FRAC as i32;
    // Fast path, same value: |term| < 2^46, so for 0 ≤ e ≤ 16 the shifted term fits an i64 and only the add
    // is 128-bit. Real models land here almost always (activation and weight scales near 1).
    let t = if (0..=16).contains(&e) {
        i128::from(term.wrapping_shl(e as u32))
    } else if e >= 0 {
        i128::from(term).wrapping_shl(e.min(100) as u32)
    } else {
        rshift_round_128(i128::from(term), (-e).min(126) as u32)
    };
    // |sum| < 2^126 for any input (module documentation), so this add never wraps.
    *acc = acc.wrapping_add(t);
}

#[inline(always)]
fn finish(acc: i128) -> i64 {
    rshift_round_128(acc, ACC_FRAC).clamp(i128::from(i64::MIN), i128::from(i64::MAX)) as i64
}

fn ok(w: &[u8], x: &Act) -> bool {
    let n = x.q.len();
    n % QK == 0 && n <= MAX_COLS && x.scale.len() == n / QK && w.len() == row_bytes(n)
}

/// Reference: one row of a `Q8_0` matrix times quantised activations, in the activations' unit.
pub fn row_scalar(w: &[u8], x: &Act) -> Option<i64> {
    if !ok(w, x) {
        return None;
    }
    let mut acc: i128 = 0;
    for ((blk, xq), &xs) in w.chunks_exact(BLOCK_BYTES).zip(x.q.chunks_exact(QK)).zip(x.scale) {
        if let [lo, hi, qs @ ..] = blk {
            let dot: i32 = qs.iter().zip(xq).map(|(&a, &b)| i32::from(a as i8) * i32::from(b)).sum();
            combine(&mut acc, dot, u16::from_le_bytes([*lo, *hi]), xs);
        }
    }
    Some(finish(acc))
}

/// One row with the selected implementation. Same contract and bit-identical result as [`row_scalar`].
pub fn row(simd: crate::Simd, w: &[u8], x: &Act) -> Option<i64> {
    if simd.is_neon() {
        #[cfg(all(target_arch = "aarch64", target_feature = "neon"))]
        {
            if !ok(w, x) {
                return None;
            }
            // SAFETY: lengths checked just above; the `Simd` token carries the CPU-feature promise.
            return Some(unsafe { neon::row(w, x) });
        }
    }
    row_scalar(w, x)
}

/// Reference for four consecutive rows (`w` holds 4 rows): the 1-row reference four times.
pub fn rows4_scalar(w: &[u8], x: &Act, out: &mut [i64; 4]) -> bool {
    let rb = row_bytes(x.q.len());
    if rb == 0 || w.len() != 4 * rb || !ok(w.get(..rb).unwrap_or(&[]), x) {
        return false;
    }
    for (o, wr) in out.iter_mut().zip(w.chunks_exact(rb)) {
        *o = row_scalar(wr, x).unwrap_or(0);
    }
    true
}

/// Four consecutive rows with the selected implementation; bit-identical to [`rows4_scalar`]. On NEON each
/// activation block is loaded once for the four rows and the four dot products are reduced together.
pub fn rows4(simd: crate::Simd, w: &[u8], x: &Act, out: &mut [i64; 4]) -> bool {
    if simd.is_neon() {
        #[cfg(all(target_arch = "aarch64", target_feature = "neon"))]
        {
            let rb = row_bytes(x.q.len());
            if rb == 0 || w.len() != 4 * rb || !ok(w.get(..rb).unwrap_or(&[]), x) {
                return false;
            }
            // SAFETY: lengths checked just above; the `Simd` token carries the CPU-feature promise.
            unsafe { neon::rows4(w, rb, x, out) };
            return true;
        }
    }
    rows4_scalar(w, x, out)
}

/// A whole matrix (`rows` consecutive rows of `cols` columns): `sink(row, value)` for each row, four rows at
/// a time, then the remainder one by one. Returns false (calling nothing) if the lengths do not fit.
pub fn matvec(simd: crate::Simd, w: &[u8], rows: usize, x: &Act, mut sink: impl FnMut(usize, i64)) -> bool {
    let rb = row_bytes(x.q.len());
    if rb == 0 || rows.checked_mul(rb) != Some(w.len()) || !ok(w.get(..rb).unwrap_or(&[]), x) {
        return false;
    }
    let mut groups = w.chunks_exact(4 * rb);
    let mut r = 0usize;
    for g in groups.by_ref() {
        let mut o = [0i64; 4];
        rows4(simd, g, x, &mut o);
        for v in o {
            sink(r, v);
            r += 1;
        }
    }
    for wr in groups.remainder().chunks_exact(rb) {
        sink(r, row(simd, wr, x).unwrap_or(0));
        r += 1;
    }
    true
}

/// Dequantise one row into fixed point with `frac` fraction bits (embedding lookup).
pub fn dequant_row(w: &[u8], frac: u32, out: &mut [i64]) -> bool {
    if out.len() % QK != 0 || w.len() != row_bytes(out.len()) || frac > 40 {
        return false;
    }
    for (blk, ob) in w.chunks_exact(BLOCK_BYTES).zip(out.chunks_exact_mut(QK)) {
        if let [lo, hi, qs @ ..] = blk {
            let (m, s) = half_parts(u16::from_le_bytes([*lo, *hi]));
            let e = frac as i32 - s;
            for (o, &q) in ob.iter_mut().zip(qs) {
                let v = i128::from(m) * i128::from(q as i8);
                *o = (if e >= 0 { v << e } else { rshift_round_128(v, (-e) as u32) }) as i64;
            }
        }
    }
    true
}

#[cfg(all(target_arch = "aarch64", target_feature = "neon"))]
mod neon {
    use super::*;
    use core::arch::aarch64::*;

    /// # Safety
    /// `ok(w, x)` holds, and the CPU has NEON + DotProd with FP/SIMD enabled.
    #[target_feature(enable = "neon,dotprod")]
    pub unsafe fn row(w: &[u8], x: &Act) -> i64 {
        let blocks = x.q.len() / QK;
        let (mut wp, mut xp) = (w.as_ptr(), x.q.as_ptr());
        let mut acc: i128 = 0;
        for b in 0..blocks {
            let bits = u16::from_le_bytes([*wp, *wp.add(1)]);
            let w0 = vld1q_s8(wp.add(2).cast::<i8>());
            let w1 = vld1q_s8(wp.add(18).cast::<i8>());
            let x0 = vld1q_s8(xp);
            let x1 = vld1q_s8(xp.add(16));
            let d = vdotq_s32(vdotq_s32(vdupq_n_s32(0), w0, x0), w1, x1);
            combine(&mut acc, vaddvq_s32(d), bits, *x.scale.get_unchecked(b));
            wp = wp.add(BLOCK_BYTES);
            xp = xp.add(QK);
        }
        finish(acc)
    }

    /// Four rows at `w`, `w + rb`, `w + 2rb`, `w + 3rb`.
    ///
    /// # Safety
    /// `w.len() == 4 * rb`, `ok(row, x)` holds for each row, and the CPU has NEON + DotProd with FP/SIMD enabled.
    #[target_feature(enable = "neon,dotprod")]
    pub unsafe fn rows4(w: &[u8], rb: usize, x: &Act, out: &mut [i64; 4]) {
        let blocks = x.q.len() / QK;
        let base = w.as_ptr();
        let mut xp = x.q.as_ptr();
        let mut acc = [0i128; 4];
        let zero = vdupq_n_s32(0);
        for b in 0..blocks {
            let x0 = vld1q_s8(xp);
            let x1 = vld1q_s8(xp.add(16));
            let p = base.add(b * BLOCK_BYTES);
            let (p0, p1, p2, p3) = (p, p.add(rb), p.add(2 * rb), p.add(3 * rb));
            let d0 = vdotq_s32(vdotq_s32(zero, vld1q_s8(p0.add(2).cast()), x0), vld1q_s8(p0.add(18).cast()), x1);
            let d1 = vdotq_s32(vdotq_s32(zero, vld1q_s8(p1.add(2).cast()), x0), vld1q_s8(p1.add(18).cast()), x1);
            let d2 = vdotq_s32(vdotq_s32(zero, vld1q_s8(p2.add(2).cast()), x0), vld1q_s8(p2.add(18).cast()), x1);
            let d3 = vdotq_s32(vdotq_s32(zero, vld1q_s8(p3.add(2).cast()), x0), vld1q_s8(p3.add(18).cast()), x1);
            // [Σd0, Σd1, Σd2, Σd3] with two pairwise adds instead of four horizontal sums.
            let s = vpaddq_s32(vpaddq_s32(d0, d1), vpaddq_s32(d2, d3));
            let xs = *x.scale.get_unchecked(b);
            let bits = |q: *const u8| u16::from_le_bytes([*q, *q.add(1)]);
            combine(&mut acc[0], vgetq_lane_s32::<0>(s), bits(p0), xs);
            combine(&mut acc[1], vgetq_lane_s32::<1>(s), bits(p1), xs);
            combine(&mut acc[2], vgetq_lane_s32::<2>(s), bits(p2), xs);
            combine(&mut acc[3], vgetq_lane_s32::<3>(s), bits(p3), xs);
            xp = xp.add(QK);
        }
        for (o, a) in out.iter_mut().zip(acc) {
            *o = finish(a);
        }
    }
}
