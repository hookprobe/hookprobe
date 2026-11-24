// SPDX-License-Identifier: AGPL-3.0-only
//! Language-model kernels, integer only (Neuro doc 13 §6 "N2"). Scalar; the GEMV is the only kernel with a
//! NEON path (it is where the bytes are). No float, no allocation, no panics: every function checks its
//! lengths and returns `false` (changing nothing it has not checked) when they do not fit.
//!
//! Fixed-point scheme (one scheme, so the pieces compose):
//!
//! | Quantity | Type | Meaning |
//! |---|---|---|
//! | residual stream | `i32` | value × 2^8 (Q8) |
//! | activations | `i8` | value × 2^5 (Q5, range ±3.97) |
//! | norm gains | `i16` | value × 2^12 (Q12) |
//! | rotations (RoPE) | `i16` | cos/sin × 2^15 (Q15) |
//! | probabilities | `u16` | p × 2^15 (Q15) |
//! | softmax input | `i32` | logit × 2^4 (1/16 nat steps) |

pub const ACT_SHIFT: u32 = 5;
pub const RES_SHIFT: u32 = 8;
pub const GAIN_SHIFT: u32 = 12;
pub const ROT_SHIFT: u32 = 15;
pub const PROB_ONE: u32 = 1 << 15;
/// Softmax works in 1/16-nat steps; differences beyond the table are probability 0.
pub const SM_STEPS_PER_NAT: i64 = 16;
pub const EXP_TABLE_LEN: usize = 256;

fn clamp_i8(v: i64) -> i8 {
    i8::try_from(v.clamp(-128, 127)).unwrap_or(0)
}

/// Round-half-away-from-zero division by 2^s.
fn rshift_round(v: i64, s: u32) -> i64 {
    if s == 0 {
        return v;
    }
    let half = 1i64 << (s - 1);
    if v >= 0 {
        (v + half) >> s
    } else {
        -((-v + half) >> s)
    }
}

/// Integer square root (floor).
pub fn isqrt(v: u64) -> u64 {
    if v < 2 {
        return v;
    }
    let mut x = 1u64 << ((64 - v.leading_zeros()).div_ceil(2));
    loop {
        let y = (x + v / x) / 2;
        if y >= x {
            return x;
        }
        x = y;
    }
}

/// RMSNorm: residual (Q8) → activations (Q5): `y = x / rms(x) · gain`. `rms` has a floor of 1/256 so an
/// all-zero vector gives zeros, never a division by zero.
pub fn rmsnorm(x: &[i32], gain_q12: &[i16], out: &mut [i8]) -> bool {
    let n = x.len();
    if n == 0 || gain_q12.len() != n || out.len() != n {
        return false;
    }
    let ss: u128 = x.iter().map(|&v| (i128::from(v) * i128::from(v)) as u128).sum();
    // mean of squares in Q16, then rms in Q8.
    let mean = (ss / n as u128).min(u128::from(u64::MAX)) as u64;
    let rms = isqrt(mean).max(1);
    for ((o, &v), &g) in out.iter_mut().zip(x).zip(gain_q12) {
        // value·gain/rms in Q5:  v(Q8)·g(Q12)·2^5 / (rms(Q8)·2^12)
        let num = i128::from(v) * i128::from(g) * (1i128 << ACT_SHIFT);
        let den = i128::from(rms) << GAIN_SHIFT;
        let q = if num >= 0 { (num + den / 2) / den } else { -((-num + den / 2) / den) };
        *o = clamp_i8(q.clamp(-128, 127) as i64);
    }
    true
}

/// Rotary position embedding on one head, in place: pairs (x[2i], x[2i+1]) rotated by the angle for
/// `pos` and `i`, read from a table built offline (`cos_sin[pos][i] = (cos, sin)` in Q15).
pub fn rope(x: &mut [i8], table_row: &[(i16, i16)]) -> bool {
    if x.len() % 2 != 0 || table_row.len() != x.len() / 2 {
        return false;
    }
    for (pair, &(c, s)) in x.chunks_exact_mut(2).zip(table_row) {
        if let [a, b] = pair {
            let (a0, b0) = (i64::from(*a), i64::from(*b));
            let (c, s) = (i64::from(c), i64::from(s));
            *a = clamp_i8(rshift_round(a0 * c - b0 * s, ROT_SHIFT));
            *b = clamp_i8(rshift_round(a0 * s + b0 * c, ROT_SHIFT));
        }
    }
    true
}

/// `exp(-k/16)` in Q15 for k = 0..256, built offline (no float on the device).
pub type ExpTable = [u16; EXP_TABLE_LEN];

/// Softmax over scores in 1/16-nat steps → probabilities in Q15 that sum to 2^15 (± rounding).
pub fn softmax(scores: &[i32], exp: &ExpTable, out: &mut [u16]) -> bool {
    if scores.is_empty() || out.len() != scores.len() {
        return false;
    }
    let max = scores.iter().copied().max().unwrap_or(0);
    let mut sum: u64 = 0;
    for (o, &s) in out.iter_mut().zip(scores) {
        let k = usize::try_from(i64::from(max) - i64::from(s)).unwrap_or(usize::MAX);
        *o = exp.get(k).copied().unwrap_or(0);
        sum += u64::from(*o);
    }
    // The maximum contributes exp(0) = 2^15, so sum ≥ 2^15 > 0.
    for o in out.iter_mut() {
        *o = ((u64::from(*o) * u64::from(PROB_ONE) + sum / 2) / sum) as u16;
    }
    true
}

/// Decode-time attention for ONE query head over `t` cached positions.
///
/// `q`: head_dim activations (Q5). `k`, `v`: the cache for this head's KV group, `t × head_dim` (Q5).
/// `score_mult`, `score_shift`: integer form of `16 / (2^10 · sqrt(head_dim))`, mapping a Q10 dot product
/// to softmax steps. `scores`, `probs`: scratch of length ≥ t. Output: head_dim activations (Q5).
#[allow(clippy::too_many_arguments)]
pub fn attend(q: &[i8], k: &[i8], v: &[i8], t: usize, score_mult: i32, score_shift: u32, exp: &ExpTable, scores: &mut [i32], probs: &mut [u16], out: &mut [i8]) -> bool {
    let d = q.len();
    let Some(cells) = t.checked_mul(d) else { return false };
    if d == 0 || t == 0 || k.len() < cells || v.len() < cells || out.len() != d || scores.len() < t || probs.len() < t || score_shift > 40 {
        return false;
    }
    let (Some(scores), Some(probs)) = (scores.get_mut(..t), probs.get_mut(..t)) else { return false };
    for (j, s) in scores.iter_mut().enumerate() {
        let kj = k.get(j * d..(j + 1) * d).unwrap_or(&[]);
        let dot: i64 = q.iter().zip(kj).map(|(&a, &b)| i64::from(a) * i64::from(b)).sum();
        *s = i32::try_from(rshift_round(dot * i64::from(score_mult), score_shift)).unwrap_or(0);
    }
    if !softmax(scores, exp, probs) {
        return false;
    }
    for (c, o) in out.iter_mut().enumerate() {
        let acc: i64 = probs.iter().enumerate().map(|(j, &p)| i64::from(p) * i64::from(v.get(j * d + c).copied().unwrap_or(0))).sum();
        *o = clamp_i8(rshift_round(acc, ROT_SHIFT));
    }
    true
}

/// Elementwise activation through a 256-entry table built offline (SiLU, GELU, ReLU², …): exact, and any
/// function, for one table lookup per element.
pub fn lut(x: &mut [i8], table: &[i8; 256]) {
    for v in x.iter_mut() {
        *v = table.get(usize::from(*v as u8)).copied().unwrap_or(0);
    }
}

/// a ← a · b (Q5 · Q5 → Q5), the SwiGLU gate product.
pub fn mul(a: &mut [i8], b: &[i8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    for (x, &y) in a.iter_mut().zip(b) {
        *x = clamp_i8(rshift_round(i64::from(*x) * i64::from(y), ACT_SHIFT));
    }
    true
}

/// Requantise a GEMV accumulator row-wise to activations (Q5) or to residual (Q8) values.
pub fn requant_i8(acc: i32, mult: i32, shift: u32) -> i8 {
    clamp_i8(rshift_round(i64::from(acc) * i64::from(mult), shift))
}
pub fn requant_i32(acc: i32, mult: i32, shift: u32) -> i32 {
    i32::try_from(rshift_round(i64::from(acc) * i64::from(mult), shift).clamp(i64::from(i32::MIN), i64::from(i32::MAX))).unwrap_or(0)
}

/// Index of the first maximum (deterministic greedy decoding).
pub fn argmax(x: &[i32]) -> Option<usize> {
    let mut best: Option<(usize, i32)> = None;
    for (i, &v) in x.iter().enumerate() {
        if best.is_none_or(|(_, b)| v > b) {
            best = Some((i, v));
        }
    }
    best.map(|b| b.0)
}
