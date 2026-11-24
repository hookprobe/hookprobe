// SPDX-License-Identifier: AGPL-3.0-only
//! The 8-bit path and Qwen3, verified on the build host against independent f64 implementations:
//! - binary16 / binary32 decoding exhaustively (every binary16 value);
//! - Q8_0 activation quantisation and GEMV against f64 with the same quantised operands;
//! - exp, SwiGLU, RMSNorm, NEOX RoPE, KV quantisation and attention against f64;
//! - a whole Qwen3-shaped model (GQA, QK-norm, NEOX RoPE θ = 1e6, SwiGLU, tied head, outlier channels)
//!   against an f64 model that dequantises the SAME Q8_0 weights and keeps every activation in f64 —
//!   i.e. the integer engine is compared with what a floating-point runtime computes from the same GGUF.
use neuro_build as build;
use neuro_kernels::q8::{self, Act};
use neuro_kernels::{hp, Simd};
use neuro_lm::qwen3::*;
use neuro_lm::Dims;

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn unit(&mut self) -> f64 {
        (self.next() >> 11) as f64 / (1u64 << 53) as f64
    }
    fn normal(&mut self) -> f64 {
        let (u, v) = (self.unit().max(1e-12), self.unit());
        (-2.0 * u.ln()).sqrt() * (2.0 * std::f64::consts::PI * v).cos()
    }
}

const Q16: f64 = 65536.0;

fn q16(x: f64) -> i64 {
    (x * Q16).round() as i64
}

/// Quantise f64 weights to GGUF Q8_0 bytes the way llama.cpp does (d = amax/127 stored as binary16).
fn quant_q8_0(w: &[f64]) -> Vec<u8> {
    let mut out = vec![];
    for b in w.chunks(32) {
        let amax = b.iter().fold(0f64, |m, v| m.max(v.abs()));
        let d = amax / 127.0;
        let id = if d > 0.0 { 1.0 / d } else { 0.0 };
        out.extend_from_slice(&build::to_half(d).to_le_bytes());
        out.extend(b.iter().map(|v| (v * id).round().clamp(-127.0, 127.0) as i8 as u8));
    }
    out
}

fn dequant(w: &[u8]) -> Vec<f64> {
    w.chunks(34).flat_map(|b| {
        let d = build::from_half(u16::from_le_bytes([b[0], b[1]]));
        b[2..].iter().map(move |&q| d * q as i8 as f64)
    }).collect()
}

fn singles(v: &[f64]) -> Vec<u8> {
    v.iter().flat_map(|&x| (x as f32).to_bits().to_le_bytes()).collect()
}

fn single_vals(b: &[u8]) -> Vec<f64> {
    b.chunks(4).map(|c| f32::from_le_bytes([c[0], c[1], c[2], c[3]]) as f64).collect()
}

// ------------------------------------------------------------------ number formats

#[test]
fn binary16_and_binary32_decode_exactly() {
    for bits in 0..=u16::MAX {
        let want = build::from_half(bits);
        let (m, s) = q8::half_parts(bits);
        if want.is_nan() {
            assert_eq!(m, 0, "non-finite decodes to 0");
            let mut blk = [0u8; 34];
            blk[..2].copy_from_slice(&bits.to_le_bytes());
            assert!(!q8::scales_finite(&blk));
            continue;
        }
        assert_eq!(m as f64 * 2f64.powi(-s), want, "binary16 {bits:#06x}");
        // and the encoder round-trips every finite value
        if bits & 0x7fff != 0 {
            assert_eq!(build::to_half(want), bits, "to_half({want})");
        }
    }
    let mut r = Rng(5);
    for _ in 0..200_000 {
        let bits = r.next() as u32;
        let v = f32::from_bits(bits);
        let (m, s) = hp::single_parts(bits);
        if !v.is_finite() {
            assert!(!hp::single_finite(bits) && m == 0);
            continue;
        }
        assert_eq!(m as f64 * 2f64.powi(-s), v as f64, "binary32 {bits:#010x}");
    }
    println!("number formats: all 65,536 binary16 values and 200,000 binary32 values decode exactly");
}

// ------------------------------------------------------------------ Q8_0 GEMV

#[test]
fn q8_gemv_matches_f64_on_the_same_quantised_operands() {
    let mut r = Rng(11);
    let mut worst_rel_act = 0f64;
    let mut worst_grid = 0f64;
    for case in 0..3000 {
        let cols = 32 * (1 + (r.next() % 64) as usize);
        let mag = [1e-3, 0.5, 30.0, 3000.0][case % 4];
        // Activations with an outlier channel, as real models have.
        let mut x: Vec<i64> = (0..cols).map(|_| q16(r.normal() * mag)).collect();
        if case % 3 == 0 {
            x[(r.next() as usize) % cols] = q16(mag * 200.0 * if r.next() % 2 == 0 { 1.0 } else { -1.0 });
        }
        let w: Vec<f64> = (0..cols).map(|_| r.normal() * 0.04).collect();
        let wb = quant_q8_0(&w);
        let (mut xq, mut xs) = (vec![0i8; cols], vec![(0, 0); cols / 32]);
        assert!(q8::quantize(&x, &mut xq, &mut xs));
        // Activation quantisation: each value within half a step of its block scale (amax/127).
        for (b, blk) in x.chunks(32).enumerate() {
            let amax = blk.iter().map(|v| v.unsigned_abs()).max().unwrap() as f64;
            let (m, e) = xs[b];
            let scale = m as f64 * 2f64.powi(e);
            if amax > 0.0 {
                worst_rel_act = worst_rel_act.max((scale - amax / 127.0).abs() / (amax / 127.0));
            }
            for (i, &v) in blk.iter().enumerate() {
                assert!((xq[b * 32 + i] as f64 * scale - v as f64).abs() <= (0.5 + 127.0 / 16384.0) * scale + 1e-9, "v {v} q {} amax {amax} scale {scale} m {m} e {e}", xq[b * 32 + i]);
            }
        }
        // The integer row equals the f64 sum over the same quantised operands, to rounding.
        let act = Act { q: &xq, scale: &xs };
        let wexp = q8::wexp_gguf(&wb);
        let got = q8::row_scalar(&wb, &act, wexp).unwrap();
        let wq = dequant(&wb);
        let want: f64 = (0..cols).map(|c| wq[c] * xq[c] as f64 * xs[c / 32].0 as f64 * 2f64.powi(xs[c / 32].1)).sum();
        // Stated bound: half a grid step per block plus the final rounding (grid = 2^-K output units), plus
        // f64 rounding of the reference sum.
        let k = q8::grid(&act, wexp);
        let tol = (cols / 32) as f64 * 0.5 * 2f64.powi(-k) + 0.5 + want.abs() * 1e-12;
        assert!((got as f64 - want).abs() <= tol, "cols {cols}: {got} vs {want} (K {k})");
        let mag: f64 = (0..cols).map(|c| (wq[c] * xq[c] as f64 * xs[c / 32].0 as f64 * 2f64.powi(xs[c / 32].1)).abs()).sum();
        let _ = mag;
        worst_grid = worst_grid.max((got as f64 - want).abs());
        assert_eq!(q8::row(Simd::SCALAR, &wb, &act, wexp), Some(got));
    }
    assert!(worst_rel_act < 1.0 / 16384.0, "activation scale error {worst_rel_act}");
    // Errors: wrong lengths are refused; matvec calls nothing.
    let x = vec![1i64; 64];
    let (mut xq, mut xs) = (vec![0i8; 64], vec![(0, 0); 2]);
    assert!(!q8::quantize(&x, &mut xq[..63], &mut xs));
    assert!(q8::quantize(&x, &mut xq, &mut xs));
    let act = Act { q: &xq, scale: &xs };
    assert_eq!(q8::row_scalar(&[0u8; 67], &act, 0), None);
    let mut called = false;
    assert!(!q8::matvec(Simd::SCALAR, &[0u8; 68 * 3 - 1], 3, &act, 0, |_, _| called = true));
    assert!(!called);
    // Infinity / NaN scales are refused at admission.
    assert!(q8::scales_finite(&[0, 0x3c, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]));
    assert!(!q8::scales_finite(&[0, 0x7c, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]));
    println!("q8 gemv: 3,000 rows within the stated grid bound of f64 on the same operands (worst error {worst_grid:.3} output LSB, i.e. 2^-16 of the unit); activation scale within {worst_rel_act:.1e}");
}

// ------------------------------------------------------------------ fixed-point functions

#[test]
fn hp_functions_track_f64() {
    // POW2 table and LOG2E constant.
    for (k, &v) in hp::POW2_TABLE.iter().enumerate() {
        assert!((v as f64 - 2f64.powf(k as f64 / 256.0) * 2f64.powi(30)).abs() <= 1.0, "pow2[{k}]");
    }
    assert!((hp::LOG2E_Q40 as f64 - std::f64::consts::LOG2_E * 2f64.powi(40)).abs() <= 1.0);
    // exp: relative error < 2^-17 above 2^-12; below that, absolute error < 2^-29 (the Q30 resolution).
    let mut worst = 0f64;
    for i in 0..400_000i64 {
        let x = -i * 7; // 0 .. -42.7
        let want = (x as f64 / Q16).exp();
        let got = hp::exp_neg(x) as f64 / 2f64.powi(30);
        if want > 2f64.powi(-12) {
            worst = worst.max((got - want).abs() / want);
        } else {
            assert!((got - want).abs() < 2f64.powi(-29), "exp abs error at {x}");
        }
    }
    assert!(worst < 2f64.powi(-17), "exp relative error {worst}");
    println!("exp: worst relative error {worst:.2e}");
    let mut r = Rng(23);
    // SwiGLU: within 1e-5 relative + 2 LSB.
    for _ in 0..100_000 {
        let (a, b) = (r.normal() * [0.1, 3.0, 40.0][(r.next() % 3) as usize], r.normal() * 5.0);
        let mut g = [q16(a)];
        assert!(hp::swiglu(&mut g, &[q16(b)]));
        let (aq, bq) = (q16(a) as f64 / Q16, q16(b) as f64 / Q16);
        let want = aq / (1.0 + (-aq).exp()) * bq * Q16;
        assert!((g[0] as f64 - want).abs() <= 2.0 + want.abs() * 1e-5, "swiglu({a},{b}) {} vs {want}", g[0]);
    }
    // RMSNorm (with eps and binary32 gains): within 1e-6 relative + 1 LSB, across magnitudes.
    let eps = 1e-6f32.to_bits();
    for case in 0..3000 {
        let n = [16, 128, 1024][case % 3];
        let mag = [1e-2, 1.0, 50.0, 5000.0][case % 4];
        let x: Vec<i64> = (0..n).map(|_| q16(r.normal() * mag)).collect();
        let g: Vec<f64> = (0..n).map(|_| 1.0 + 0.3 * r.normal()).collect();
        let gb = singles(&g);
        let mut y = x.clone();
        assert!(hp::rmsnorm(&mut y, &gb, eps));
        let gv = single_vals(&gb);
        let xf: Vec<f64> = x.iter().map(|&v| v as f64 / Q16).collect();
        let rms = (xf.iter().map(|v| v * v).sum::<f64>() / n as f64 + 1e-6f32 as f64).sqrt();
        for i in 0..n {
            let want = xf[i] / rms * gv[i] * Q16;
            assert!((y[i] as f64 - want).abs() <= 1.5 + want.abs() * 1e-6, "rmsnorm {} vs {want}", y[i]);
        }
    }
    // NEOX RoPE at θ = 1e6: within 1 LSB + 2^-28 relative.
    let table = build::rope_neox_table(512, 128, 1e6);
    for _ in 0..2000 {
        let pos = (r.next() % 512) as usize;
        let x: Vec<i64> = (0..128).map(|_| q16(r.normal() * 3.0)).collect();
        let mut y = x.clone();
        assert!(hp::rope_neox(&mut y, &table[pos * 64..(pos + 1) * 64]));
        for i in 0..64 {
            let th = pos as f64 * 1e6f64.powf(-2.0 * i as f64 / 128.0);
            let (a, b) = (x[i] as f64, x[i + 64] as f64);
            assert!((y[i] as f64 - (a * th.cos() - b * th.sin())).abs() <= 1.0 + a.abs().max(b.abs()) * 1e-8);
            assert!((y[i + 64] as f64 - (a * th.sin() + b * th.cos())).abs() <= 1.0 + a.abs().max(b.abs()) * 1e-8);
        }
    }
    // KV quantisation keeps 15 significant bits per vector.
    for _ in 0..2000 {
        let mag = [1e-3, 1.0, 300.0][(r.next() % 3) as usize];
        let x: Vec<i64> = (0..64).map(|_| q16(r.normal() * mag)).collect();
        let mut q = vec![0i16; 64];
        let s = hp::kv_quant(&x, &mut q).unwrap();
        let amax = x.iter().map(|v| v.unsigned_abs()).max().unwrap() as f64;
        for i in 0..64 {
            assert!(((q[i] as f64) * 2f64.powi(s as i32) - x[i] as f64).abs() <= (2f64.powi(s as i32) / 2.0).max(0.0) + 1e-9);
        }
        assert!(amax < 2f64.powi(15 + s as i32), "shift too small");
    }
    // Attention against f64 over the same cached (quantised) K and V.
    let scale = (1.0f32 / 128f32.sqrt()).to_bits();
    let mut worst_att = 0f64;
    for _ in 0..300 {
        let (d, t) = (128usize, 1 + (r.next() % 200) as usize);
        let mag = [0.5, 4.0, 20.0][(r.next() % 3) as usize];
        let q: Vec<i64> = (0..d).map(|_| q16(r.normal() * mag)).collect();
        let (mut k, mut v, mut ks, mut vs) = (vec![0i16; t * d], vec![0i16; t * d], vec![0u8; t], vec![0u8; t]);
        for j in 0..t {
            let kv: Vec<i64> = (0..d).map(|_| q16(r.normal() * mag)).collect();
            let vv: Vec<i64> = (0..d).map(|_| q16(r.normal() * mag * (1.0 + j as f64 / 50.0))).collect();
            ks[j] = hp::kv_quant(&kv, &mut k[j * d..(j + 1) * d]).unwrap();
            vs[j] = hp::kv_quant(&vv, &mut v[j * d..(j + 1) * d]).unwrap();
        }
        let (mut qq, mut w, mut out) = (vec![0i32; d], vec![0i64; t], vec![0i64; d]);
        assert!(hp::attend(&q, &k, &ks, &v, &vs, t, scale, &mut qq, &mut w, &mut out));
        let kf = |j: usize, c: usize| k[j * d + c] as f64 * 2f64.powi(ks[j] as i32) / Q16;
        let vf = |j: usize, c: usize| v[j * d + c] as f64 * 2f64.powi(vs[j] as i32) / Q16;
        let qf: Vec<f64> = q.iter().map(|&x| x as f64 / Q16).collect();
        let sc: Vec<f64> = (0..t).map(|j| (0..d).map(|c| qf[c] * kf(j, c)).sum::<f64>() / 128f64.sqrt()).collect();
        let m = sc.iter().cloned().fold(f64::MIN, f64::max);
        let z: f64 = sc.iter().map(|s| (s - m).exp()).sum();
        let vmax = (0..t).flat_map(|j| (0..d).map(move |c| (j, c))).map(|(j, c)| vf(j, c).abs()).fold(0.0, f64::max);
        for c in 0..d {
            let want: f64 = (0..t).map(|j| (sc[j] - m).exp() / z * vf(j, c)).sum();
            let err = (out[c] as f64 / Q16 - want).abs() / vmax;
            worst_att = worst_att.max(err);
        }
    }
    assert!(worst_att < 1e-3, "attention error {worst_att}");
    println!("attention: worst error {worst_att:.1e} of the largest |V|");
}

// ------------------------------------------------------------------ whole model

struct F64Layer {
    attn_norm: Vec<f64>,
    wq: Vec<f64>,
    wk: Vec<f64>,
    wv: Vec<f64>,
    wo: Vec<f64>,
    q_norm: Vec<f64>,
    k_norm: Vec<f64>,
    ffn_norm: Vec<f64>,
    gate: Vec<f64>,
    up: Vec<f64>,
    down: Vec<f64>,
}

struct Bytes {
    layers: Vec<[Vec<u8>; 11]>,
    embed: Vec<u8>,
    final_norm: Vec<u8>,
}

const D: Dims = Dims { vocab: 384, d_model: 128, n_layers: 3, n_heads: 4, n_kv_heads: 2, head_dim: 64, ffn: 384, max_ctx: 48 };
const THETA: f64 = 1e6;

fn build_model(seed: u64) -> Bytes {
    let mut r = Rng(seed);
    let (dm, qd, kvd) = (D.d_model, D.n_heads * D.head_dim, D.n_kv_heads * D.head_dim);
    let mut mat = |rows: usize, cols: usize, s: f64| quant_q8_0(&(0..rows * cols).map(|_| r.normal() * s / (cols as f64).sqrt()).collect::<Vec<_>>());
    let mut layers = vec![];
    for _ in 0..D.n_layers {
        let m = [mat(qd, dm, 1.0), mat(kvd, dm, 1.0), mat(kvd, dm, 1.0), mat(dm, qd, 1.0), mat(D.ffn, dm, 1.0), mat(D.ffn, dm, 1.0), mat(dm, D.ffn, 1.0)];
        let [wq, wk, wv, wo, g, u, dn] = m;
        layers.push([vec![], wq, wk, wv, wo, vec![], vec![], vec![], g, u, dn]);
    }
    let mut r2 = Rng(seed ^ 0x55);
    for l in layers.iter_mut() {
        l[0] = singles(&(0..dm).map(|_| 1.0 + 0.2 * r2.normal()).collect::<Vec<_>>());
        l[5] = singles(&(0..D.head_dim).map(|_| 1.0 + 0.2 * r2.normal()).collect::<Vec<_>>());
        l[6] = singles(&(0..D.head_dim).map(|_| 1.0 + 0.2 * r2.normal()).collect::<Vec<_>>());
        l[7] = singles(&(0..dm).map(|_| 1.0 + 0.2 * r2.normal()).collect::<Vec<_>>());
    }
    // Embedding with two outlier channels (massive activations, as in real models).
    let emb: Vec<f64> = (0..D.vocab * dm).map(|i| r2.normal() * if i % dm == 5 { 40.0 } else if i % dm == 77 { -15.0 } else { 0.5 }).collect();
    Bytes { layers, embed: quant_q8_0(&emb), final_norm: singles(&(0..dm).map(|_| 1.0 + 0.2 * r2.normal()).collect::<Vec<_>>()) }
}

struct RefModel {
    layers: Vec<F64Layer>,
    embed: Vec<f64>,
    final_norm: Vec<f64>,
    kc: Vec<Vec<Vec<f64>>>, // [layer][pos] -> kvd
    vc: Vec<Vec<Vec<f64>>>,
}

impl RefModel {
    fn new(b: &Bytes) -> Self {
        let layers = b.layers.iter().map(|l| F64Layer {
            attn_norm: single_vals(&l[0]),
            wq: dequant(&l[1]),
            wk: dequant(&l[2]),
            wv: dequant(&l[3]),
            wo: dequant(&l[4]),
            q_norm: single_vals(&l[5]),
            k_norm: single_vals(&l[6]),
            ffn_norm: single_vals(&l[7]),
            gate: dequant(&l[8]),
            up: dequant(&l[9]),
            down: dequant(&l[10]),
        }).collect();
        RefModel { layers, embed: dequant(&b.embed), final_norm: single_vals(&b.final_norm), kc: vec![vec![]; D.n_layers], vc: vec![vec![]; D.n_layers] }
    }
    fn step(&mut self, tok: usize, pos: usize) -> Vec<f64> {
        let (dm, hd) = (D.d_model, D.head_dim);
        let eps = 1e-6f32 as f64;
        let norm = |x: &[f64], g: &[f64]| {
            let rms = (x.iter().map(|v| v * v).sum::<f64>() / x.len() as f64 + eps).sqrt();
            x.iter().zip(g).map(|(v, g)| v / rms * g).collect::<Vec<f64>>()
        };
        let mv = |w: &[f64], x: &[f64]| w.chunks(x.len()).map(|r| r.iter().zip(x).map(|(a, b)| a * b).sum()).collect::<Vec<f64>>();
        let rope = |x: &mut [f64]| {
            let h = x.len() / 2;
            for i in 0..h {
                let th = pos as f64 * THETA.powf(-2.0 * i as f64 / hd as f64);
                let (a, b) = (x[i], x[i + h]);
                x[i] = a * th.cos() - b * th.sin();
                x[i + h] = a * th.sin() + b * th.cos();
            }
        };
        let mut h: Vec<f64> = self.embed[tok * dm..(tok + 1) * dm].to_vec();
        for (li, l) in self.layers.iter().enumerate() {
            let x = norm(&h, &l.attn_norm);
            let mut q = mv(&l.wq, &x);
            let mut k = mv(&l.wk, &x);
            let v = mv(&l.wv, &x);
            for qh in q.chunks_mut(hd) {
                let n = norm(qh, &l.q_norm);
                qh.copy_from_slice(&n);
                rope(qh);
            }
            for kh in k.chunks_mut(hd) {
                let n = norm(kh, &l.k_norm);
                kh.copy_from_slice(&n);
                rope(kh);
            }
            self.kc[li].push(k);
            self.vc[li].push(v);
            let mut att = vec![0.0; D.n_heads * hd];
            let group = D.n_heads / D.n_kv_heads;
            for hh in 0..D.n_heads {
                let g = hh / group;
                let qh = &q[hh * hd..(hh + 1) * hd];
                let s: Vec<f64> = (0..=pos).map(|j| (0..hd).map(|c| qh[c] * self.kc[li][j][g * hd + c]).sum::<f64>() / (hd as f64).sqrt()).collect();
                let m = s.iter().cloned().fold(f64::MIN, f64::max);
                let z: f64 = s.iter().map(|v| (v - m).exp()).sum();
                for c in 0..hd {
                    att[hh * hd + c] = (0..=pos).map(|j| (s[j] - m).exp() / z * self.vc[li][j][g * hd + c]).sum();
                }
            }
            for (a, b) in h.iter_mut().zip(mv(&l.wo, &att)) {
                *a += b;
            }
            let x = norm(&h, &l.ffn_norm);
            let g = mv(&l.gate, &x);
            let u = mv(&l.up, &x);
            let act: Vec<f64> = g.iter().zip(&u).map(|(a, b)| a / (1.0 + (-a).exp()) * b).collect();
            for (a, b) in h.iter_mut().zip(mv(&l.down, &act)) {
                *a += b;
            }
        }
        let x = norm(&h, &self.final_norm);
        mv(&self.embed, &x)
    }
}

fn argmax(v: &[f64]) -> usize {
    v.iter().enumerate().fold((0, f64::MIN), |b, (i, &x)| if x > b.1 { (i, x) } else { b }).0
}

#[test]
fn qwen3_integer_engine_tracks_f64_runtime_on_the_same_weights() {
    let (mut cos_sum, mut cos_min, mut agree, mut steps, mut top_gap_misses) = (0f64, 1f64, 0usize, 0usize, 0usize);
    let rope = build::rope_neox_table(D.max_ctx, D.head_dim, THETA);
    for seed in [3u64, 41, 977] {
        let b = build_model(seed);
        let layers: Vec<Layer> = b.layers.iter().map(|l| Layer {
            attn_norm: &l[0],
            wq: Mat::gguf(D.n_heads * D.head_dim, D.d_model, &l[1]),
            wk: Mat::gguf(D.n_kv_heads * D.head_dim, D.d_model, &l[2]),
            wv: Mat::gguf(D.n_kv_heads * D.head_dim, D.d_model, &l[3]),
            wo: Mat::gguf(D.d_model, D.n_heads * D.head_dim, &l[4]),
            q_norm: &l[5],
            k_norm: &l[6],
            ffn_norm: &l[7],
            w_gate: Mat::gguf(D.ffn, D.d_model, &l[8]),
            w_up: Mat::gguf(D.ffn, D.d_model, &l[9]),
            w_down: Mat::gguf(D.d_model, D.ffn, &l[10]),
        }).collect();
        let model = Model {
            dims: D,
            embed: Mat::gguf(D.vocab, D.d_model, &b.embed),
            layers: &layers,
            final_norm: &b.final_norm,
            head: None,
            rope: &rope,
            eps: 1e-6f32.to_bits(),
            kq_scale: (1.0f32 / (D.head_dim as f32).sqrt()).to_bits(),
        };
        model.check().unwrap();
        let (kvn, kvs) = D.kv_len();
        let (mut vals, mut shifts) = (vec![0i16; kvn], vec![0u8; kvs]);
        let (a, i8n, scn, i16n) = Work::lens(&D, 1);
        let (mut ba, mut bb, mut bc, mut bd) = (vec![0i64; a], vec![0i8; i8n], vec![(0, 0); scn], vec![0i32; i16n]);
        let mut work = Work::new(&D, 1, &mut ba, &mut bb, &mut bc, &mut bd).unwrap();
        let mut kv = Kv { vals: &mut vals, shifts: &mut shifts };
        let mut reference = RefModel::new(&b);
        let mut tok = (seed as usize * 7) % D.vocab;
        for pos in 0..D.max_ctx {
            let got = model.step(Simd::SCALAR, tok, pos, &mut kv, &mut work).unwrap();
            let want = reference.step(tok, pos);
            let gl: Vec<f64> = work.logits.iter().map(|&v| v as f64 / Q16).collect();
            let dot: f64 = gl.iter().zip(&want).map(|(a, b)| a * b).sum();
            let cos = dot / (gl.iter().map(|v| v * v).sum::<f64>().sqrt() * want.iter().map(|v| v * v).sum::<f64>().sqrt());
            cos_sum += cos;
            cos_min = cos_min.min(cos);
            let wbest = argmax(&want);
            if got == wbest {
                agree += 1;
            } else {
                // A disagreement is only acceptable where the f64 top two are nearly tied.
                let mut s = want.clone();
                s.sort_by(|a, b| b.partial_cmp(a).unwrap());
                assert!(s[0] - s[1] < 0.05, "greedy token differs with a clear f64 margin {}", s[0] - s[1]);
                top_gap_misses += 1;
            }
            steps += 1;
            tok = wbest; // teacher-force the f64 choice so both see the same sequence
        }
    }
    let mean = cos_sum / steps as f64;
    println!("qwen3 vs f64 runtime (same Q8_0 weights): {steps} steps, logit 1-cosine mean {:.1e} worst {:.1e}, greedy agreement {agree}/{steps} ({top_gap_misses} near-ties)", 1.0 - mean, 1.0 - cos_min);
    assert!(mean > 0.9999 && cos_min > 0.999, "cosine mean {mean} min {cos_min}");
    assert!(agree * 100 >= steps * 97);
}

#[test]
fn qwen3_rejects_bad_models_and_inputs() {
    let b = build_model(8);
    let rope = build::rope_neox_table(D.max_ctx, D.head_dim, THETA);
    let mk = |l: &[Vec<u8>; 11]| Layer {
        attn_norm: &l[0].clone().leak()[..],
        wq: Mat::gguf(256, 128, l[1].clone().leak()),
        wk: Mat::gguf(128, 128, l[2].clone().leak()),
        wv: Mat::gguf(128, 128, l[3].clone().leak()),
        wo: Mat::gguf(128, 256, l[4].clone().leak()),
        q_norm: l[5].clone().leak(),
        k_norm: l[6].clone().leak(),
        ffn_norm: l[7].clone().leak(),
        w_gate: Mat::gguf(384, 128, l[8].clone().leak()),
        w_up: Mat::gguf(384, 128, l[9].clone().leak()),
        w_down: Mat::gguf(128, 384, l[10].clone().leak()),
    };
    let layers: Vec<Layer> = b.layers.iter().map(mk).collect();
    let good = Model { dims: D, embed: Mat::gguf(384, 128, &b.embed), layers: &layers, final_norm: &b.final_norm, head: None, rope: &rope, eps: 1e-6f32.to_bits(), kq_scale: 0.125f32.to_bits() };
    good.check().unwrap();
    // A NaN gain, an infinite weight scale, a short matrix, a wrong rope table: all refused.
    let mut nan_norm = b.final_norm.clone();
    nan_norm[4..8].copy_from_slice(&f32::NAN.to_bits().to_le_bytes());
    assert!(Model { final_norm: &nan_norm, ..good }.check().is_err());
    let mut inf_emb = b.embed.clone();
    inf_emb[34 * 9..34 * 9 + 2].copy_from_slice(&0x7c00u16.to_le_bytes());
    assert!(Model { embed: Mat { w: &inf_emb, ..good.embed }, ..good }.check().is_err());
    assert!(Model { embed: Mat { w: &b.embed[..b.embed.len() - 1], ..good.embed }, ..good }.check().is_err());
    // A wrong weight exponent (too small would let a block term outgrow the overflow proof) is refused.
    assert!(Model { embed: Mat { wexp: good.embed.wexp - 1, ..good.embed }, ..good }.check().is_err());
    assert!(Model { embed: Mat { wexp: good.embed.wexp + 1, ..good.embed }, ..good }.check().is_err());
    // The packed model gives the same logits, bit for bit.
    let packed: Vec<Vec<u8>> = layers.iter().flat_map(|l| [l.wq, l.wk, l.wv, l.wo, l.w_gate, l.w_up, l.w_down]).chain([good.embed]).map(|m| vec![0u8; q8::packed_bytes(m.rows, m.cols)]).collect();
    let mut packed = packed.into_iter();
    let mut pk = |m: &Mat| -> Mat<'static> { m.pack_into(packed.next().unwrap().leak()).unwrap() };
    let players: Vec<Layer> = layers.iter().map(|l| Layer { wq: pk(&l.wq), wk: pk(&l.wk), wv: pk(&l.wv), wo: pk(&l.wo), w_gate: pk(&l.w_gate), w_up: pk(&l.w_up), w_down: pk(&l.w_down), ..*l }).collect();
    let pmodel = Model { embed: pk(&good.embed), layers: &players, ..good };
    pmodel.check().unwrap();
    {
        let (kvn, kvs) = D.kv_len();
        let (a, i8n, scn, i32n) = Work::lens(&D, 1);
        let mut run = |m: &Model| -> Vec<i64> {
            let (mut vals, mut shifts) = (vec![0i16; kvn], vec![0u8; kvs]);
            let (mut ba, mut bb, mut bc, mut bd) = (vec![0i64; a], vec![0i8; i8n], vec![(0, 0); scn], vec![0i32; i32n]);
            let mut w = Work::new(&D, 1, &mut ba, &mut bb, &mut bc, &mut bd).unwrap();
            let mut kv = Kv { vals: &mut vals, shifts: &mut shifts };
            let mut all = vec![];
            let mut t = 7usize;
            for pos in 0..D.max_ctx {
                t = m.step(Simd::SCALAR, t, pos, &mut kv, &mut w).unwrap();
                all.extend_from_slice(w.logits);
            }
            all
        };
        assert_eq!(run(&good), run(&pmodel), "packed model logits differ");
    }
    assert!(Model { rope: &rope[1..], ..good }.check().is_err());
    assert!(Model { eps: f32::INFINITY.to_bits(), ..good }.check().is_err());
    // Bad token, full context, wrong cache size.
    let (kvn, kvs) = D.kv_len();
    let (mut vals, mut shifts) = (vec![0i16; kvn], vec![0u8; kvs]);
    let (a, i8n, scn, i16n) = Work::lens(&D, 1);
    let (mut ba, mut bb, mut bc, mut bd) = (vec![0i64; a], vec![0i8; i8n], vec![(0, 0); scn], vec![0i32; i16n]);
    assert!(Work::new(&D, 1, &mut ba[..a - 1], &mut bb, &mut bc, &mut bd).is_none());
    let mut work = Work::new(&D, 1, &mut ba, &mut bb, &mut bc, &mut bd).unwrap();
    let mut kv = Kv { vals: &mut vals, shifts: &mut shifts };
    assert_eq!(good.step(Simd::SCALAR, 384, 0, &mut kv, &mut work), Err(neuro_lm::LmError::Token));
    assert_eq!(good.step(Simd::SCALAR, 1, D.max_ctx, &mut kv, &mut work), Err(neuro_lm::LmError::Context));
    let mut short = vec![0i16; kvn - 1];
    let mut kv2 = Kv { vals: &mut short, shifts: &mut vec![0u8; kvs] };
    assert_eq!(good.step(Simd::SCALAR, 1, 0, &mut kv2, &mut work), Err(neuro_lm::LmError::Work));
    // generate: stops at a stop token or a full context, deterministic across runs.
    let mut out1 = [0u32; 64];
    let n1 = good.generate(Simd::SCALAR, &[5, 9, 200], &[], &mut kv, &mut work, &mut out1).unwrap();
    let mut out2 = [0u32; 64];
    let n2 = good.generate(Simd::SCALAR, &[5, 9, 200], &[], &mut kv, &mut work, &mut out2).unwrap();
    assert_eq!((n1, &out1[..n1]), (n2, &out2[..n2]));
    assert_eq!(n1, D.max_ctx - 3 + 1);
    let n3 = good.generate(Simd::SCALAR, &[5, 9, 200], &[out1[2]], &mut kv, &mut work, &mut out2).unwrap();
    assert!(n3 <= 3 && out2[n3 - 1] == out1[2]);
}

// ------------------------------------------------------------------ packed layout

#[test]
fn packed_layout_is_lossless_and_bit_identical() {
    let mut r = Rng(31);
    // Every binary16 scale that can occur (finite, both signs, subnormals, ±0) round-trips exactly.
    let all: Vec<u16> = (0..=u16::MAX).filter(|b| (b >> 10) & 0x1f != 31).collect();
    let cols = 64usize;
    let rows = all.len().div_ceil(2);
    let mut gguf = vec![0u8; rows * q8::row_bytes(cols)];
    for (i, blk) in gguf.chunks_exact_mut(34).enumerate() {
        blk[..2].copy_from_slice(&all.get(i).copied().unwrap_or(0).to_le_bytes());
        for q in blk[2..].iter_mut() {
            *q = r.next() as u8;
        }
    }
    let mut packed = vec![0u8; q8::packed_bytes(rows, cols)];
    assert!(q8::pack(&gguf, rows, cols, &mut packed));
    assert!(q8::packed_valid(&packed, rows, cols));
    let mut back = vec![0u8; q8::row_bytes(cols)];
    for row in 0..rows {
        assert!(q8::unpack_row(&packed, rows, cols, row, &mut back));
        assert_eq!(back, gguf[row * back.len()..(row + 1) * back.len()], "row {row}");
    }
    // Packed and GGUF matvec are bit-identical, for odd row counts (padding) and every activation scale range.
    let mut same = 0usize;
    for case in 0..400 {
        let cols = 32 * (1 + (r.next() % 48) as usize);
        let rows = 1 + (r.next() % 13) as usize;
        let w: Vec<f64> = (0..rows * cols).map(|_| r.normal() * [0.001, 0.05, 3.0][case % 3]).collect();
        let gguf = quant_q8_0(&w);
        let mut packed = vec![0u8; q8::packed_bytes(rows, cols)];
        assert!(q8::pack(&gguf, rows, cols, &mut packed));
        let x: Vec<i64> = (0..cols).map(|_| q16(r.normal() * [1e-3, 1.0, 50.0, 4000.0][case % 4])).collect();
        let (mut xq, mut xs) = (vec![0i8; cols], vec![(0, 0); cols / 32]);
        assert!(q8::quantize(&x, &mut xq, &mut xs));
        let act = Act { q: &xq, scale: &xs };
        let (mut a, mut b) = (vec![0i64; rows], vec![1i64; rows]);
        let wexp = q8::wexp_gguf(&gguf);
        assert_eq!(wexp, q8::wexp_packed(&packed));
        assert!(q8::matvec(Simd::SCALAR, &gguf, rows, &act, wexp, |i, v| a[i] = v));
        assert!(q8::matvec_packed(Simd::SCALAR, &packed, rows, &act, wexp, |i, v| b[i] = v));
        assert_eq!(a, b, "case {case}");
        for (i, v) in a.iter().enumerate() {
            assert_eq!(Some(*v), q8::row_scalar(&gguf[i * q8::row_bytes(cols)..(i + 1) * q8::row_bytes(cols)], &act, wexp));
        }
        // Embedding lookups agree too.
        let (mut e1, mut e2) = (vec![0i64; cols], vec![0i64; cols]);
        let rr = (r.next() as usize) % rows;
        assert!(q8::dequant_row(&gguf[rr * q8::row_bytes(cols)..(rr + 1) * q8::row_bytes(cols)], 16, &mut e1));
        assert!(q8::packed_dequant_row(&packed, rows, rr, 16, &mut e2));
        assert_eq!(e1, e2);
        same += rows;
    }
    // Refusals: infinite scale, non-canonical packed scales, wrong lengths.
    let mut bad = gguf_one_row(0x7c00);
    assert!(!q8::pack(&bad, 1, 32, &mut vec![0u8; 144]));
    bad = gguf_one_row(0x3c00);
    let mut p = vec![0u8; 144];
    assert!(q8::pack(&bad, 1, 32, &mut p));
    for (mw, nsw) in [(2048i16, -10i16), (500, -10), (1500, 6), (1500, -25), (0, -3)] {
        let mut x = p.clone();
        x[128..130].copy_from_slice(&mw.to_le_bytes());
        x[136..138].copy_from_slice(&nsw.to_le_bytes());
        assert!(!q8::packed_valid(&x, 1, 32), "({mw}, {nsw}) accepted");
        assert!(!q8::unpack_row(&x, 1, 32, 0, &mut vec![0u8; 34]));
    }
    assert!(!q8::packed_valid(&p[..143], 1, 32));
    println!("packed layout: all 63,488 finite binary16 scales round-trip byte-exact; {same} rows bit-identical to the GGUF layout");
}

fn gguf_one_row(bits: u16) -> Vec<u8> {
    let mut v = bits.to_le_bytes().to_vec();
    v.extend_from_slice(&[3u8; 32]);
    v
}
