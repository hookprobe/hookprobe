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
