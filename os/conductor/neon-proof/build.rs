// SPDX-License-Identifier: AGPL-3.0-only
//! Generates the integer tables (exp, SiLU, RoPE, score scale) on the build host, so the bare-metal binary
//! contains no floating-point code for them.
use neuro_build as build;
use std::fmt::Write;

fn main() {
    let dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();
    println!("cargo:rustc-link-arg=-T{dir}/link.ld");
    println!("cargo:rerun-if-changed=link.ld");
    let mut s = String::new();
    writeln!(s, "pub const EXP: [u16; 256] = {:?};", build::exp_table()).unwrap();
    writeln!(s, "pub const SILU: [i8; 256] = {:?};", build::silu_table()).unwrap();
    let rope = build::rope_table(48, 16, 10000.0);
    writeln!(s, "pub const ROPE: [(i16, i16); {}] = {:?};", rope.len(), rope).unwrap();
    let (m, sh) = build::fixed(16.0 / (1024.0 * 4.0));
    writeln!(s, "pub const SCORE_MULT: i32 = {m};\npub const SCORE_SHIFT: u32 = {sh};").unwrap();
    // Per-row rescale for random weights (std of a uniform -8..7 weight ≈ 4.6; activations ≈ 0.7).
    let mult = |target: f64, residual: bool, cols: f64| ((target * if residual { 8.0 } else { 1.0 } / (4.6 * 0.7 * cols.sqrt())) * (1u64 << 24) as f64).round() as i32;
    writeln!(s, "pub const M_ACT_64: i32 = {};", mult(0.7, false, 64.0)).unwrap();
    writeln!(s, "pub const M_RES_64: i32 = {};", mult(0.4, true, 64.0)).unwrap();
    writeln!(s, "pub const M_RES_128: i32 = {};", mult(0.4, true, 128.0)).unwrap();
    writeln!(s, "pub const M_HEAD_64: i32 = {};", mult(3.0, true, 64.0)).unwrap();
    let rope = build::rope_neox_table(32, 32, 1e6);
    writeln!(s, "pub const ROPE_NEOX: [(i32, i32); {}] = {:?};", rope.len(), rope).unwrap();
    writeln!(s, "pub const EPS_BITS: u32 = {:#x};", 1e-6f32.to_bits()).unwrap();
    writeln!(s, "pub const KQ_SCALE_BITS: u32 = {:#x};", (1.0f32 / 32f32.sqrt()).to_bits()).unwrap();
    std::fs::write(format!("{}/tables.rs", std::env::var("OUT_DIR").unwrap()), s).unwrap();
}
