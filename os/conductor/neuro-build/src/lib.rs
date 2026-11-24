// SPDX-License-Identifier: AGPL-3.0-only
//! Build-host table generators for `neuro_kernels::lm`: floating point is allowed here and only here.
use neuro_kernels::lm::*;


pub fn exp_table() -> ExpTable {
    let mut t = [0u16; EXP_TABLE_LEN];
    for (k, v) in t.iter_mut().enumerate() {
        *v = ((-(k as f64) / SM_STEPS_PER_NAT as f64).exp() * PROB_ONE as f64).round() as u16;
    }
    t
}

/// SiLU on Q5 inputs → Q5 outputs.
pub fn silu_table() -> [i8; 256] {
    let mut t = [0i8; 256];
    for (i, v) in t.iter_mut().enumerate() {
        let x = (i as u8 as i8) as f64 / 32.0;
        *v = (x / (1.0 + (-x).exp()) * 32.0).round().clamp(-128.0, 127.0) as i8;
    }
    t
}

/// RoPE table for `positions × (head_dim/2)` with the usual base.
pub fn rope_table(positions: usize, head_dim: usize, base: f64) -> Vec<(i16, i16)> {
    let mut t = Vec::with_capacity(positions * head_dim / 2);
    for p in 0..positions {
        for i in 0..head_dim / 2 {
            let theta = p as f64 / base.powf(2.0 * i as f64 / head_dim as f64);
            let q = |v: f64| (v * 32768.0).round().clamp(-32767.0, 32767.0) as i16;
            t.push((q(theta.cos()), q(theta.sin())));
        }
    }
    t
}

/// (mult, shift) with mult/2^shift ≈ v, mult < 2^30.
pub fn fixed(v: f64) -> (i32, u32) {
    let mut shift = 0u32;
    while v * ((1u64 << (shift + 1)) as f64) < (1u64 << 30) as f64 && shift < 40 {
        shift += 1;
    }
    ((v * (1u64 << shift) as f64).round() as i32, shift)
}

/// NEOX RoPE table for `neuro_kernels::hp::rope_neox`: `positions × head_dim/2` of `(cos, sin)` in Q30,
/// angle `pos · base^(-2i/head_dim)` for the pair `(i, i + head_dim/2)`.
pub fn rope_neox_table(positions: usize, head_dim: usize, base: f64) -> Vec<(i32, i32)> {
    let one = (1u64 << neuro_kernels::hp::ROT_FRAC) as f64;
    let mut t = Vec::with_capacity(positions * head_dim / 2);
    for p in 0..positions {
        for i in 0..head_dim / 2 {
            let theta = p as f64 * base.powf(-2.0 * i as f64 / head_dim as f64);
            t.push(((theta.cos() * one).round() as i32, (theta.sin() * one).round() as i32));
        }
    }
    t
}

/// Round a value to IEEE binary16 bits (round to nearest even; normal and subnormal range; saturates
/// to the largest finite value). For building test models and checking the decoder.
pub fn to_half(x: f64) -> u16 {
    let sign = if x.is_sign_negative() { 0x8000u16 } else { 0 };
    let a = x.abs();
    if a == 0.0 {
        return sign;
    }
    if a >= 65504.0 {
        return sign | 0x7bff;
    }
    let mut e = a.log2().floor() as i32;
    if a < 2f64.powi(e) {
        e -= 1;
    }
    if e < -14 {
        // subnormal: units of 2^-24
        let m = (a * 2f64.powi(24)).round_ties_even() as u16;
        return sign | m;
    }
    let mut m = ((a / 2f64.powi(e) - 1.0) * 1024.0).round_ties_even() as u32;
    if m == 1024 {
        m = 0;
        e += 1;
    }
    if e > 15 {
        return sign | 0x7bff;
    }
    sign | (((e + 15) as u16) << 10) | m as u16
}

/// binary16 bits → value (reference decoder, independent of the integer one).
pub fn from_half(b: u16) -> f64 {
    let s = if b & 0x8000 != 0 { -1.0 } else { 1.0 };
    let e = ((b >> 10) & 0x1f) as i32;
    let f = (b & 0x3ff) as f64;
    match e {
        0 => s * f * 2f64.powi(-24),
        31 => f64::NAN,
        _ => s * (1.0 + f / 1024.0) * 2f64.powi(e - 15),
    }
}
