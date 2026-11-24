// SPDX-License-Identifier: AGPL-3.0-only
//! High-precision fixed point for real pretrained models (Qwen3 and alike), integer only.
//!
//! Every hidden value is an `i64` with 16 fraction bits ("Q16"): range ±2^47, resolution 2^-16. Real
//! models have activation outliers in the thousands; Q16 holds them without clipping, which the 8-bit Q5
//! scheme of [`lm`](crate::lm) cannot. Norm gains and the attention scale arrive as IEEE binary32 bits
//! (as stored in GGUF) and are decoded with integer operations only. KV cache entries are `i16` with a
//! per-vector power-of-two shift (15 significant bits per vector; binary16 has 11).
//!
//! | Quantity | Type | Meaning |
//! |---|---|---|
//! | hidden values, residual, logits | `i64` | value × 2^16 |
//! | RoPE cos/sin | `i32` | value × 2^30 (table built on the build host) |
//! | exp, sigmoid, unnormalised probabilities | `i64` | value × 2^30 |
//! | KV cache | `i16` + `u8` shift | value × 2^16 = q · 2^shift |

pub const FRAC: u32 = 16;
pub const ONE: i64 = 1 << FRAC;
pub const ROT_FRAC: u32 = 30;
pub const EXP_FRAC: u32 = 30;

/// Round-half-away-from-zero division of an i128 by 2^s.
#[inline]
pub fn rsr(v: i128, s: u32) -> i128 {
    if s == 0 {
        return v;
    }
    let s = s.min(126);
    let half = 1i128 << (s - 1);
    if v >= 0 {
        (v + half) >> s
    } else {
        -((-v + half) >> s)
    }
}

/// v · 2^s, saturating at the i128 range.
#[inline]
pub fn shl_sat(v: i128, s: u32) -> i128 {
    if v == 0 {
        0
    } else if s >= v.unsigned_abs().leading_zeros().saturating_sub(1) {
        if v > 0 { i128::MAX } else { i128::MIN }
    } else {
        v << s
    }
}

#[inline]
fn sat(v: i128) -> i64 {
    v.clamp(i128::from(i64::MIN), i128::from(i64::MAX)) as i64
}

/// binary32 bits → `(mantissa, shift)` with value = mantissa · 2^-shift (mantissa < 2^24 in magnitude).
/// Infinity and NaN decode to 0; admission refuses them ([`single_finite`]).
pub fn single_parts(bits: u32) -> (i64, i32) {
    let e = ((bits >> 23) & 0xff) as i32;
    let f = i64::from(bits & 0x7f_ffff);
    let (m, s) = match e {
        0 => (f, 149),
        255 => (0, 0),
        _ => (f | 0x80_0000, 150 - e),
    };
    (if bits & 0x8000_0000 != 0 { -m } else { m }, s)
}

pub fn single_finite(bits: u32) -> bool {
    (bits >> 23) & 0xff != 255
}

/// Read binary32 bits from a little-endian byte slice.
pub fn single_at(b: &[u8], i: usize) -> u32 {
    match b.get(4 * i..4 * i + 4) {
        Some([a, c, d, e]) => u32::from_le_bytes([*a, *c, *d, *e]),
        _ => 0,
    }
}

/// `x · g` where `g` is decoded binary32 parts; same unit as `x`, rounded.
#[inline]
pub fn mul_parts(x: i64, g: (i64, i32)) -> i64 {
    let v = i128::from(x) * i128::from(g.0);
    sat(if g.1 >= 0 { rsr(v, g.1 as u32) } else { shl_sat(v, (-g.1) as u32) })
}

/// Integer square root of a u128 (floor).
pub fn isqrt128(v: u128) -> u128 {
    if v < 2 {
        return v;
    }
    let mut x = 1u128 << (128 - v.leading_zeros()).div_ceil(2);
    loop {
        let y = (x + v / x) / 2;
        if y >= x {
            return x;
        }
        x = y;
    }
}

/// RMSNorm in place: `x ← x / sqrt(mean(x²) + eps) · g`. `gains` holds `x.len()` binary32 values
/// (little-endian bytes); `eps` is binary32 bits. Returns false (changing nothing) on a length mismatch.
pub fn rmsnorm(x: &mut [i64], gains: &[u8], eps: u32) -> bool {
    let n = x.len();
    if n == 0 || gains.len() != 4 * n {
        return false;
    }
    // Sum of squares in Q32 (saturating; |x| < 2^47 in practice, so it never saturates).
    let mut ss: u128 = 0;
    for &v in x.iter() {
        let a = u128::from(v.unsigned_abs());
        ss = ss.saturating_add(a * a);
    }
    // Mean + eps at the highest precision that fits, Q(32 + 2h), so the square root gives rms in Q(16 + h)
    // even for tiny vectors (where eps dominates and a Q32 eps would be truncated).
    let h = (ss.leading_zeros().saturating_sub(2) / 2).min(32);
    let (em, es) = single_parts(eps);
    let sh = 32 + 2 * h as i32 - es;
    let eps_s: u128 = if em <= 0 { 0 } else if sh >= 0 { (em as u128) << sh.min(100) as u32 } else { rsr(i128::from(em), (-sh) as u32) as u128 };
    let ms = ((ss << (2 * h)) / n as u128).saturating_add(eps_s);
    let rms = isqrt128(ms).max(1 << h);
    // inv = 2^(62+h) / rms ≤ 2^62; y = x · inv / 2^46 in Q16.
    let inv = (1u128 << (62 + h)) / rms;
    for (i, v) in x.iter_mut().enumerate() {
        // x / rms in Q32 (16 guard bits), then one rounding after the gain.
        let y = rsr(i128::from(*v) * inv as i128, 30);
        let (gm, gs) = single_parts(single_at(gains, i));
        let p = y.saturating_mul(i128::from(gm));
        *v = sat(if gs + 16 >= 0 { rsr(p, (gs + 16) as u32) } else { shl_sat(p, (-(gs + 16)) as u32) });
    }
    true
}

/// NEOX ("rotate half") RoPE on one head in place: pairs `(x[i], x[i + d/2])`, as Qwen2/Qwen3 use.
/// `table` holds `(cos, sin)` in Q30 for `i = 0..d/2` at this position.
pub fn rope_neox(x: &mut [i64], table: &[(i32, i32)]) -> bool {
    let h = x.len() / 2;
    if x.len() % 2 != 0 || table.len() != h {
        return false;
    }
    let (a, b) = x.split_at_mut(h);
    for ((p, q), &(c, s)) in a.iter_mut().zip(b.iter_mut()).zip(table) {
        let (x0, x1, c, s) = (i128::from(*p), i128::from(*q), i128::from(c), i128::from(s));
        *p = sat(rsr(x0 * c - x1 * s, ROT_FRAC));
        *q = sat(rsr(x0 * s + x1 * c, ROT_FRAC));
    }
    true
}

/// `2^(k/256)` in Q30 for k = 0..=256, computed at compile time with integers (repeated square roots).
pub const POW2_TABLE: [u32; 257] = pow2_table();

const fn isqrt_const(v: u128) -> u128 {
    if v < 2 {
        return v;
    }
    let mut x = 1u128 << (128 - v.leading_zeros()).div_ceil(2);
    loop {
        let y = (x + v / x) / 2;
        if y >= x {
            return x;
        }
        x = y;
    }
}

// Evaluated at compile time: an out-of-range index is a build error, not a panic.
#[allow(clippy::indexing_slicing)]
const fn pow2_table() -> [u32; 257] {
    // r = 2^(1/256) in Q62 by eight square roots of 2.
    let mut r: u128 = 2u128 << 62;
    let mut i = 0;
    while i < 8 {
        r = isqrt_const(r << 62);
        i += 1;
    }
    let mut t = [0u32; 257];
    let mut acc: u128 = 1u128 << 62;
    let mut k = 0;
    while k <= 256 {
        t[k] = ((acc + (1u128 << 31)) >> 32) as u32;
        acc = (acc * r + (1u128 << 61)) >> 62;
        k += 1;
    }
    t
}

/// log2(e) in Q40.
pub const LOG2E_Q40: i64 = 1_586_259_972_792;

/// `exp(x)` for `x ≤ 0` in Q16 → Q30: relative error < 2^-17 for results above 2^-12, absolute error
/// < 2^-29 below (table of 2^(k/256) + linear interpolation).
/// Positive inputs are treated as 0 (result 2^30).
pub fn exp_neg(x: i64) -> i64 {
    if x >= 0 {
        return 1 << EXP_FRAC;
    }
    // y = -x · log2(e) in Q24.
    let y = rsr(i128::from(x.unsigned_abs().min(1 << 40)) * i128::from(LOG2E_Q40), 32);
    let n = (y >> 24) as u32; // integer part
    if n >= 31 {
        return 0;
    }
    let frac = (y & 0xff_ffff) as u32;
    // 2^-y = 2^-n · 2^-frac = 2^-(n+1) · 2^(1-frac)
    let g = (1u32 << 24) - frac; // 1 - frac in Q24, in (0, 2^24]
    let k = (g >> 16) as usize;
    let rem = i64::from(g & 0xffff);
    let lo = i64::from(POW2_TABLE.get(k).copied().unwrap_or(0));
    let hi = i64::from(POW2_TABLE.get(k + 1).copied().unwrap_or(1 << 31));
    let v = lo + (((hi - lo) * rem + (1 << 15)) >> 16); // 2^(1-frac) in Q30, in [2^30, 2^31]
    (v + (1i64 << n)) >> (n + 1)
}

/// SiLU gate: `g ← g · sigmoid(g) · u` (SwiGLU), Q16 in and out.
pub fn swiglu(g: &mut [i64], u: &[i64]) -> bool {
    if g.len() != u.len() {
        return false;
    }
    let one = 1i64 << EXP_FRAC;
    for (a, &b) in g.iter_mut().zip(u) {
        let e = exp_neg(-(a.unsigned_abs().min(i64::MAX as u64) as i64)); // e^-|a|
        // sigmoid(a) = 1/(1+e^-a) for a ≥ 0, e^a/(1+e^a) for a < 0; Q30.
        let sig = if *a >= 0 { (one << EXP_FRAC) / (one + e) } else { ((e << EXP_FRAC) + (one + e) / 2) / (one + e) };
        // One rounding: a(Q16) · sig(Q30) · b(Q16) → Q16. |a|, |b| ≤ 2^63 and sig ≤ 2^30: |prod| ≤ 2^126.
        let prod = i128::from(*a) * i128::from(sig) * i128::from(b);
        *a = sat(rsr(prod, EXP_FRAC + FRAC));
    }
    true
}

/// Quantise one vector for the KV cache: `x ≈ q · 2^shift`, 15 significant bits.
pub fn kv_quant(x: &[i64], q: &mut [i16]) -> Option<u8> {
    if q.len() != x.len() {
        return None;
    }
    let amax = x.iter().map(|v| v.unsigned_abs()).max().unwrap_or(0);
    let bits = 64 - amax.leading_zeros();
    let s = bits.saturating_sub(15);
    for (o, &v) in q.iter_mut().zip(x) {
        *o = rsr(i128::from(v), s).clamp(-32767, 32767) as i16;
    }
    u8::try_from(s).ok()
}

/// Quantise the query to 31 significant bits: `x ≈ q · 2^shift`.
fn q_quant(x: &[i64], q: &mut [i32]) -> Option<u8> {
    if q.len() != x.len() {
        return None;
    }
    let amax = x.iter().map(|v| v.unsigned_abs()).max().unwrap_or(0);
    let s = (64 - amax.leading_zeros()).saturating_sub(31);
    for (o, &v) in q.iter_mut().zip(x) {
        *o = rsr(i128::from(v), s).clamp(-(i32::MAX as i128), i32::MAX as i128) as i32;
    }
    u8::try_from(s).ok()
}

/// Decode-time attention for one query head over `t` cached positions.
///
/// `q`: head_dim values (Q16). `k`, `v`: `t × head_dim` cached entries with per-position shifts `ks`, `vs`.
/// `scale`: binary32 bits of the score scale (1/sqrt(head_dim)). `qq`: scratch of head_dim (the query at 31
/// bits; `|q · k| < 2^46` per term, head_dim ≤ 4,096 keeps the dot product within i64); `w`: scratch
/// of length ≥ t. Output: head_dim values (Q16).
#[allow(clippy::too_many_arguments)]
pub fn attend(q: &[i64], k: &[i16], ks: &[u8], v: &[i16], vs: &[u8], t: usize, scale: u32, qq: &mut [i32], w: &mut [i64], out: &mut [i64]) -> bool {
    let d = q.len();
    let Some(cells) = t.checked_mul(d) else { return false };
    if d == 0 || d > 4096 || t == 0 || k.len() < cells || v.len() < cells || ks.len() < t || vs.len() < t || qq.len() != d || w.len() < t || out.len() != d {
        return false;
    }
    let Some(qs) = q_quant(q, qq) else { return false };
    let sc = single_parts(scale);
    let Some(w) = w.get_mut(..t) else { return false };
    // Scores in Q16: Σ qq·kq · 2^(qs + ks_j) is the dot product in Q32.
    let mut max = i64::MIN;
    for (j, s) in w.iter_mut().enumerate() {
        let kj = k.get(j * d..(j + 1) * d).unwrap_or(&[]);
        let dot: i64 = qq.iter().zip(kj).map(|(&a, &b)| i64::from(a) * i64::from(b)).sum();
        let sh = i32::from(qs) + i32::from(ks.get(j).copied().unwrap_or(0)) - FRAC as i32;
        let dq16 = if sh >= 0 { shl_sat(i128::from(dot), sh as u32) } else { rsr(i128::from(dot), (-sh) as u32) };
        *s = mul_parts(sat(dq16), sc);
        max = max.max(*s);
    }
    // Unnormalised probabilities (Q30), each folded with its V shift relative to the largest shift.
    let vmax = vs.get(..t).and_then(|s| s.iter().copied().max()).unwrap_or(0);
    let mut sum: i64 = 0;
    for (j, s) in w.iter_mut().enumerate() {
        let e = exp_neg(s.saturating_sub(max));
        sum += e;
        let drop = u32::from(vmax - vs.get(j).copied().unwrap_or(0));
        *s = if drop >= 63 { 0 } else { rsr(i128::from(e), drop) as i64 };
    }
    // out_c = Σ_j w_j · vq_jc · 2^vmax / sum      (|w| ≤ 2^30, |vq| < 2^15, t ≤ 2^17: fits i64)
    for (c, o) in out.iter_mut().enumerate() {
        let mut acc: i64 = 0;
        for (j, &wj) in w.iter().enumerate() {
            acc += wj * i64::from(v.get(j * d + c).copied().unwrap_or(0));
        }
        let num = shl_sat(i128::from(acc), u32::from(vmax));
        let den = i128::from(sum.max(1));
        *o = sat(if num >= 0 { (num + den / 2) / den } else { -((-num + den / 2) / den) });
    }
    true
}

/// Index of the first maximum.
pub fn argmax(x: &[i64]) -> Option<usize> {
    let mut best: Option<(usize, i64)> = None;
    for (i, &v) in x.iter().enumerate() {
        if best.is_none_or(|(_, b)| v > b) {
            best = Some((i, v));
        }
    }
    best.map(|b| b.0)
}
