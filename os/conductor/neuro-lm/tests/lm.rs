// SPDX-License-Identifier: AGPL-3.0-only
//! Language-model pieces, verified on the build host:
//! - every kernel against an f64 reference, with stated error bounds;
//! - the tokenizer against a naive reference implementation, plus round trips;
//! - a whole decoder against an independent f64 model with the SAME (dequantised) weights;
//! - KV-cache correctness: incremental decoding equals recomputation from scratch.
use neuro_build as build;
use neuro_kernels::lm;
use neuro_kernels::{group_bytes, pack_group, Simd};
use neuro_lm::bpe::{Bpe, BpeError};
use neuro_lm::*;

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

// ------------------------------------------------------------------ kernels vs f64

#[test]
fn kernels_track_f64_within_stated_bounds() {
    let mut r = Rng(17);
    let exp = build::exp_table();
    // RMSNorm: ≤ 1 LSB (1/32) from the exact value, before clamping.
    for _ in 0..2000 {
        let n = 32 * (1 + (r.next() % 8) as usize);
        let x: Vec<i32> = (0..n).map(|_| (r.normal() * 300.0) as i32).collect();
        let g: Vec<i16> = (0..n).map(|_| (4096.0 * (1.0 + 0.2 * r.normal())) as i16).collect();
        let mut out = vec![0i8; n];
        assert!(lm::rmsnorm(&x, &g, &mut out));
        let rms = (x.iter().map(|&v| (v as f64 / 256.0).powi(2)).sum::<f64>() / n as f64).sqrt().max(1.0 / 256.0);
        for i in 0..n {
            let want = (x[i] as f64 / 256.0) / rms * (g[i] as f64 / 4096.0) * 32.0;
            if want.abs() < 127.0 {
                assert!((out[i] as f64 - want).abs() <= 1.0, "rmsnorm {} vs {want}", out[i]);
            }
        }
    }
    // RoPE: ≤ 1 LSB per element.
    let table = build::rope_table(64, 16, 10000.0);
    for _ in 0..2000 {
        let pos = (r.next() % 64) as usize;
        let x: Vec<i8> = (0..16).map(|_| (r.normal() * 30.0).clamp(-90.0, 90.0) as i8).collect();
        let mut y = x.clone();
        assert!(lm::rope(&mut y, &table[pos * 8..(pos + 1) * 8]));
        for i in 0..8 {
            let th = pos as f64 / 10000f64.powf(2.0 * i as f64 / 16.0);
            let (a, b) = (x[2 * i] as f64, x[2 * i + 1] as f64);
            assert!((y[2 * i] as f64 - (a * th.cos() - b * th.sin())).abs() <= 1.0);
            assert!((y[2 * i + 1] as f64 - (a * th.sin() + b * th.cos())).abs() <= 1.0);
        }
    }
    // Softmax: probabilities within 2^-9 of the exact softmax of the same 1/16-nat inputs.
    let mut worst = 0.0f64;
    for _ in 0..2000 {
        let n = 1 + (r.next() % 64) as usize;
        let s: Vec<i32> = (0..n).map(|_| (r.normal() * 40.0) as i32).collect();
        let mut p = vec![0u16; n];
        assert!(lm::softmax(&s, &exp, &mut p));
        let m = *s.iter().max().unwrap() as f64;
        let z: f64 = s.iter().map(|&v| ((v as f64 - m) / 16.0).exp()).sum();
        for i in 0..n {
            let e = (p[i] as f64 / 32768.0 - ((s[i] as f64 - m) / 16.0).exp() / z).abs();
            worst = worst.max(e);
        }
    }
    assert!(worst < 1.0 / 512.0, "softmax worst error {worst}");
    println!("softmax worst |error|: {worst:.2e}");
    // SiLU table: exact by construction; spot-check against f64 to 1 LSB.
    let silu = build::silu_table();
    for i in -128i32..128 {
        let x = i as f64 / 32.0;
        assert!((silu[(i as i8) as u8 as usize] as f64 - x / (1.0 + (-x).exp()) * 32.0).abs() <= 0.5 + 1e-9);
    }
    // Attention: within 2 LSB of f64 attention over the same int8 q, k, v.
    let (sm, ss) = build::fixed(16.0 / (1024.0 * 4.0)); // head_dim 16
    for _ in 0..2000 {
        let t = 1 + (r.next() % 32) as usize;
        let q: Vec<i8> = (0..16).map(|_| (r.normal() * 32.0).clamp(-127.0, 127.0) as i8).collect();
        let k: Vec<i8> = (0..16 * t).map(|_| (r.normal() * 32.0).clamp(-127.0, 127.0) as i8).collect();
        let v: Vec<i8> = (0..16 * t).map(|_| (r.normal() * 32.0).clamp(-127.0, 127.0) as i8).collect();
        let (mut sc, mut pr, mut out) = (vec![0i32; t], vec![0u16; t], vec![0i8; 16]);
        assert!(lm::attend(&q, &k, &v, t, sm, ss, &exp, &mut sc, &mut pr, &mut out));
        let scores: Vec<f64> = (0..t).map(|j| (0..16).map(|c| q[c] as f64 / 32.0 * k[j * 16 + c] as f64 / 32.0).sum::<f64>() / 4.0).collect();
        let m = scores.iter().cloned().fold(f64::MIN, f64::max);
        let z: f64 = scores.iter().map(|s| (s - m).exp()).sum();
        for c in 0..16 {
            let want = (0..t).map(|j| (scores[j] - m).exp() / z * v[j * 16 + c] as f64).sum::<f64>();
            assert!((out[c] as f64 - want).abs() <= 2.0, "attend {} vs {want:.2}", out[c]);
        }
    }
    // Length errors change nothing.
    let mut o = [5i8; 4];
    assert!(!lm::rmsnorm(&[1, 2, 3], &[1, 2, 3, 4], &mut o) && o == [5; 4]);
    assert!(!lm::attend(&[1; 4], &[1; 4], &[1; 4], 2, 1, 1, &exp, &mut [0; 2], &mut [0; 2], &mut o));
    assert_eq!(lm::argmax(&[3, 9, 9, 1]), Some(1));
    assert_eq!(lm::argmax(&[]), None);
}

// ------------------------------------------------------------------ tokenizer

/// Build-side trainer: the most frequent adjacent pair becomes the next merge (classic BPE training).
fn train(corpus: &[u8], merges: usize) -> (Vec<(u16, u16)>, Vec<(u16, u16, u16)>) {
    let mut seq: Vec<u16> = corpus.iter().map(|&b| b as u16).collect();
    let mut out = vec![];
    for i in 0..merges {
        let mut counts = std::collections::BTreeMap::new();
        for w in seq.windows(2) {
            *counts.entry((w[0], w[1])).or_insert(0usize) += 1;
        }
        let Some((&pair, _)) = counts.iter().max_by_key(|(p, c)| (**c, std::cmp::Reverse(**p))) else { break };
        let new = 256 + i as u16;
        let mut next = vec![];
        let mut j = 0;
        while j < seq.len() {
            if j + 1 < seq.len() && (seq[j], seq[j + 1]) == pair {
                next.push(new);
                j += 2;
            } else {
                next.push(seq[j]);
                j += 1;
            }
        }
        seq = next;
        out.push(pair);
    }
    let mut index: Vec<(u16, u16, u16)> = out.iter().enumerate().map(|(r, &(a, b))| (a, b, r as u16)).collect();
    index.sort();
    (out, index)
}

/// Naive reference encoder: same rule, written independently with std collections.
fn naive_encode(merges: &[(u16, u16)], text: &[u8]) -> Vec<u16> {
    let rank: std::collections::HashMap<(u16, u16), usize> = merges.iter().enumerate().map(|(i, &p)| (p, i)).collect();
    let mut s: Vec<u16> = text.iter().map(|&b| b as u16).collect();
    loop {
        let best = s.windows(2).filter_map(|w| rank.get(&(w[0], w[1]))).min().copied();
        let Some(r) = best else { return s };
        let (pair, new) = (merges[r], 256 + r as u16);
        let mut out = vec![];
        let mut i = 0;
        while i < s.len() {
            if i + 1 < s.len() && (s[i], s[i + 1]) == pair {
                out.push(new);
                i += 2;
            } else {
                out.push(s[i]);
                i += 1;
            }
        }
        s = out;
    }
}

#[test]
fn tokenizer_matches_reference_and_round_trips() {
    let corpus = b"Behaviour deviation on device slot 3: new peers on tcp/443. The device contacted peers it had not used before. \
        Port scan from 198.51.100.7 blocked. DNS queries for a newly registered domain. Not enough evidence to conclude.";
    let (merges, index) = train(corpus, 120);
    let bpe = Bpe::new(&merges, &index).unwrap();
    assert_eq!(bpe.vocab(), 376);
    let mut r = Rng(99);
    let mut toks = vec![0u16; 4096];
    let mut back = vec![0u8; 4096];
    let mut texts: Vec<Vec<u8>> = vec![corpus.to_vec(), b"".to_vec(), "Ünïcödé — bytes \u{202e} too".as_bytes().to_vec()];
    for _ in 0..500 {
        let n = (r.next() % 300) as usize;
        texts.push(if r.next() % 2 == 0 {
            (0..n).map(|_| r.next() as u8).collect()
        } else {
            let s = (r.next() as usize) % corpus.len();
            corpus[s..(s + n).min(corpus.len())].to_vec()
        });
    }
    let mut compressed = 0usize;
    for t in &texts {
        let n = bpe.encode(t, &mut toks).unwrap();
        assert_eq!(&toks[..n], &naive_encode(&merges, t)[..], "encoder disagrees with the reference");
        let m = bpe.decode(&toks[..n], &mut back).unwrap();
        assert_eq!(&back[..m], &t[..], "round trip");
        compressed += n;
    }
    let n = bpe.encode(corpus, &mut toks).unwrap();
    println!("tokenizer: corpus {} bytes -> {} tokens; 503 texts round-trip and match the reference", corpus.len(), n);
    assert!(n < corpus.len() / 2);
    let _ = compressed;
    // Errors: too small an output, an unknown token, inconsistent tables.
    assert_eq!(bpe.encode(b"abc", &mut [0u16; 2]), Err(BpeError::Space));
    assert_eq!(bpe.decode(&[9999], &mut back), Err(BpeError::Token));
    assert_eq!(bpe.decode(&[300], &mut [0u8; 1]), Err(BpeError::Space));
    assert_eq!(Bpe::new(&[(300, 1)], &[(300, 1, 0)]).err(), Some(BpeError::Table), "a merge naming a later token");
    let mut unsorted = index.clone();
    unsorted.swap(0, 1);
    assert_eq!(Bpe::new(&merges, &unsorted).err(), Some(BpeError::Table));
    let mut wrong_rank = index.clone();
    wrong_rank[0].2 = wrong_rank[1].2;
    assert_eq!(Bpe::new(&merges, &wrong_rank).err(), Some(BpeError::Table));
}

// ------------------------------------------------------------------ a whole decoder vs f64

const VOCAB: usize = 100;
const DM: usize = 64;
const LAYERS: usize = 2;
const HEADS: usize = 4;
const KV_HEADS: usize = 2;
const HD: usize = 16;
const FFN: usize = 128;
const CTX: usize = 48;

/// One quantised matrix: packed bytes + per-row mult, and its f64 dequantisation (`scale` maps the
/// integer output to real units: 1 for activation outputs, 1/8 for residual and logit outputs).
struct Mat {
    w: Vec<u8>,
    mult: Vec<i32>,
    f: Vec<Vec<f64>>,
}
const SHIFT: u32 = 24;

fn mat(r: &mut Rng, rows: usize, cols: usize, target_std: f64, residual: bool) -> Mat {
    let raw: Vec<Vec<i8>> = (0..rows).map(|_| (0..cols).map(|_| (r.next() % 16) as i8 - 8).collect()).collect();
    let base = target_std * if residual { 8.0 } else { 1.0 } / (4.6 * 0.7 * (cols as f64).sqrt());
    let mult: Vec<i32> = (0..rows).map(|_| (base * (1.0 + 0.2 * (r.unit() - 0.5)) * (1u64 << SHIFT) as f64).round() as i32).collect();
    let mut w = vec![];
    for g in raw.chunks(4) {
        let mut out = vec![0u8; group_bytes(cols)];
        assert!(pack_group([&g[0], &g[1], &g[2], &g[3]], &mut out));
        w.extend(out);
    }
    let f = raw
        .iter()
        .zip(&mult)
        .map(|(row, &m)| row.iter().map(|&v| v as f64 * m as f64 / (1u64 << SHIFT) as f64 / if residual { 8.0 } else { 1.0 }).collect())
        .collect();
    Mat { w, mult, f }
}

struct Built {
    embed: Vec<i8>,
    norms: Vec<Vec<i16>>, // attn, ffn per layer, then final
    mats: Vec<Mat>,       // per layer: q k v o gate up down; then head
    rope: Vec<(i16, i16)>,
}

fn build_model(seed: u64) -> Built {
    let mut r = Rng(seed);
    let embed: Vec<i8> = (0..VOCAB * DM).map(|_| (r.normal() * 24.0).clamp(-100.0, 100.0) as i8).collect();
    let mut norms = vec![];
    let mut mats = vec![];
    for _ in 0..LAYERS {
        norms.push((0..DM).map(|_| (4096.0 * (1.0 + 0.1 * r.normal())) as i16).collect());
        norms.push((0..DM).map(|_| (4096.0 * (1.0 + 0.1 * r.normal())) as i16).collect());
        mats.push(mat(&mut r, HEADS * HD, DM, 0.7, false));
        mats.push(mat(&mut r, KV_HEADS * HD, DM, 0.7, false));
        mats.push(mat(&mut r, KV_HEADS * HD, DM, 0.7, false));
        mats.push(mat(&mut r, DM, HEADS * HD, 0.4, true));
        mats.push(mat(&mut r, FFN, DM, 0.7, false));
        mats.push(mat(&mut r, FFN, DM, 0.7, false));
        mats.push(mat(&mut r, DM, FFN, 0.4, true));
    }
    norms.push((0..DM).map(|_| (4096.0 * (1.0 + 0.1 * r.normal())) as i16).collect());
    mats.push(mat(&mut r, VOCAB, DM, 3.0, true));
    Built { embed, norms, mats, rope: build::rope_table(CTX, HD, 10000.0) }
}

/// Independent f64 forward pass over the dequantised weights; returns logits for every position.
fn f64_logits(b: &Built, tokens: &[usize]) -> Vec<Vec<f64>> {
    let rms = |x: &[f64], g: &[i16]| -> Vec<f64> {
        let s = (x.iter().map(|v| v * v).sum::<f64>() / x.len() as f64).sqrt().max(1.0 / 256.0);
        x.iter().zip(g).map(|(v, &gg)| v / s * gg as f64 / 4096.0).collect()
    };
    let mv = |m: &Mat, x: &[f64]| -> Vec<f64> { m.f.iter().map(|row| row.iter().zip(x).map(|(a, b)| a * b).sum()).collect() };
    let rope = |x: &mut [f64], pos: usize| {
        for i in 0..HD / 2 {
            let th = pos as f64 / 10000f64.powf(2.0 * i as f64 / HD as f64);
            let (a, c) = (x[2 * i], x[2 * i + 1]);
            x[2 * i] = a * th.cos() - c * th.sin();
            x[2 * i + 1] = a * th.sin() + c * th.cos();
        }
    };
    let mut kc = vec![vec![vec![]; KV_HEADS]; LAYERS];
    let mut vc = vec![vec![vec![]; KV_HEADS]; LAYERS];
    let mut all = vec![];
    for (pos, &t) in tokens.iter().enumerate() {
        let mut x: Vec<f64> = b.embed[t * DM..(t + 1) * DM].iter().map(|&e| e as f64 / 32.0).collect();
        for l in 0..LAYERS {
            let m = &b.mats[l * 7..l * 7 + 7];
            let xn = rms(&x, &b.norms[2 * l]);
            let mut q = mv(&m[0], &xn);
            let mut k = mv(&m[1], &xn);
            let v = mv(&m[2], &xn);
            for h in 0..HEADS {
                rope(&mut q[h * HD..(h + 1) * HD], pos);
            }
            for g in 0..KV_HEADS {
                rope(&mut k[g * HD..(g + 1) * HD], pos);
                kc[l][g].push(k[g * HD..(g + 1) * HD].to_vec());
                vc[l][g].push(v[g * HD..(g + 1) * HD].to_vec());
            }
            let mut att = vec![0.0; HEADS * HD];
            for h in 0..HEADS {
                let g = h / (HEADS / KV_HEADS);
                let s: Vec<f64> = kc[l][g].iter().map(|kk| kk.iter().zip(&q[h * HD..(h + 1) * HD]).map(|(a, b)| a * b).sum::<f64>() / (HD as f64).sqrt()).collect();
                let mx = s.iter().cloned().fold(f64::MIN, f64::max);
                let z: f64 = s.iter().map(|v| (v - mx).exp()).sum();
                for c in 0..HD {
                    att[h * HD + c] = s.iter().zip(&vc[l][g]).map(|(sv, vv)| (sv - mx).exp() / z * vv[c]).sum();
                }
            }
            for (xi, o) in x.iter_mut().zip(mv(&m[3], &att)) {
                *xi += o;
            }
            let xn = rms(&x, &b.norms[2 * l + 1]);
            let gate = mv(&m[4], &xn);
            let up = mv(&m[5], &xn);
            let h: Vec<f64> = gate.iter().zip(&up).map(|(g, u)| g / (1.0 + (-g).exp()) * u).collect();
            for (xi, o) in x.iter_mut().zip(mv(&m[6], &h)) {
                *xi += o;
            }
        }
        let xn = rms(&x, &b.norms[2 * LAYERS]);
        all.push(mv(&b.mats[LAYERS * 7], &xn));
    }
    all
}

macro_rules! with_model {
    ($b:expr, $exp:expr, $silu:expr, $m:ident, $body:block) => {{
        let q = |i: usize, rows: usize, cols: usize| Q4 { rows, cols, w: &$b.mats[i].w, mult: &$b.mats[i].mult, shift: SHIFT };
        let layers: Vec<Layer> = (0..LAYERS)
            .map(|l| Layer {
                attn_norm: &$b.norms[2 * l],
                wq: q(l * 7, HEADS * HD, DM),
                wk: q(l * 7 + 1, KV_HEADS * HD, DM),
                wv: q(l * 7 + 2, KV_HEADS * HD, DM),
                wo: q(l * 7 + 3, DM, HEADS * HD),
                ffn_norm: &$b.norms[2 * l + 1],
                w_gate: q(l * 7 + 4, FFN, DM),
                w_up: q(l * 7 + 5, FFN, DM),
                w_down: q(l * 7 + 6, DM, FFN),
            })
            .collect();
        let (sm, ss) = build::fixed(16.0 / (1024.0 * (HD as f64).sqrt()));
        let $m = Model {
            dims: Dims { vocab: VOCAB, d_model: DM, n_layers: LAYERS, n_heads: HEADS, n_kv_heads: KV_HEADS, head_dim: HD, ffn: FFN, max_ctx: CTX },
            embed: &$b.embed,
            layers: &layers,
            final_norm: &$b.norms[2 * LAYERS],
            head: q(LAYERS * 7, VOCAB, DM),
            rope: &$b.rope,
            exp: &$exp,
            silu: &$silu,
            score_mult: sm,
            score_shift: ss,
        };
        $body
    }};
}

type W = Work<64, 128, 48, 100>;

#[test]
fn integer_decoder_tracks_the_f64_model() {
    let exp = build::exp_table();
    let silu = build::silu_table();
    let (mut cos_min, mut cos_sum, mut agree, mut decisive, mut steps) = (1.0f64, 0.0, 0, 0, 0);
    for seed in 1..=8u64 {
        let b = build_model(seed);
        with_model!(b, exp, silu, m, {
            m.check().unwrap();
            let mut kv = vec![0i8; m.dims.kv_bytes()];
            let mut w: Box<W> = Box::new(Work::new());
            let mut r = Rng(seed * 1000 + 7);
            let tokens: Vec<usize> = (0..32).map(|_| (r.next() % VOCAB as u64) as usize).collect();
            let fl = f64_logits(&b, &tokens);
            for (pos, &t) in tokens.iter().enumerate() {
                let next = m.step(Simd::SCALAR, t, pos, &mut kv, &mut w).unwrap();
                let il: Vec<f64> = w.logits[..VOCAB].iter().map(|&v| v as f64 / 256.0).collect();
                let f = &fl[pos];
                let dot: f64 = il.iter().zip(f).map(|(a, b)| a * b).sum();
                let cos = dot / (il.iter().map(|a| a * a).sum::<f64>().sqrt() * f.iter().map(|a| a * a).sum::<f64>().sqrt());
                cos_min = cos_min.min(cos);
                cos_sum += cos;
                steps += 1;
                let mut sorted = f.clone();
                sorted.sort_by(|a, b| b.partial_cmp(a).unwrap());
                let fbest = f.iter().position(|&v| v == sorted[0]).unwrap();
                // Count agreement where the f64 model itself is decisive (top-2 gap ≥ 0.25 logit).
                if sorted[0] - sorted[1] >= 0.25 {
                    decisive += 1;
                    if fbest == next {
                        agree += 1;
                    }
                }
            }
        });
    }
    println!(
        "integer vs f64 decoder over {steps} steps: logit cosine mean {:.4}, min {:.4}; greedy token agreement {agree}/{decisive} where f64 is decisive",
        cos_sum / steps as f64,
        cos_min
    );
    assert!(cos_min > 0.97, "logits drifted from the f64 model");
    assert!(agree * 100 >= decisive * 95, "greedy choice disagrees too often");
}

#[test]
fn kv_cache_decoding_equals_recomputation_and_bounds_hold() {
    let exp = build::exp_table();
    let silu = build::silu_table();
    let b = build_model(42);
    with_model!(b, exp, silu, m, {
        let mut r = Rng(5);
        let tokens: Vec<usize> = (0..CTX).map(|_| (r.next() % VOCAB as u64) as usize).collect();
        let mut kv = vec![0i8; m.dims.kv_bytes()];
        let mut w: Box<W> = Box::new(Work::new());
        let mut inc = vec![];
        for (pos, &t) in tokens.iter().enumerate() {
            m.step(Simd::SCALAR, t, pos, &mut kv, &mut w).unwrap();
            inc.push(w.logits[..VOCAB].to_vec());
        }
        // From scratch: a fresh cache (poisoned with garbage) for every prefix length.
        for end in [1usize, 2, 7, 23, CTX] {
            let mut kv2 = vec![0x5Ai8; m.dims.kv_bytes()];
            let mut w2: Box<W> = Box::new(Work::new());
            for (pos, &t) in tokens[..end].iter().enumerate() {
                m.step(Simd::SCALAR, t, pos, &mut kv2, &mut w2).unwrap();
            }
            assert_eq!(&w2.logits[..VOCAB], &inc[end - 1][..], "prefix {end}");
        }
        // Bounds: a full context, an unknown token, a wrong cache size are errors, never a panic.
        assert_eq!(m.step(Simd::SCALAR, 1, CTX, &mut kv, &mut w), Err(LmError::Context));
        assert_eq!(m.step(Simd::SCALAR, VOCAB, 0, &mut kv, &mut w), Err(LmError::Token));
        assert_eq!(m.step(Simd::SCALAR, 1, 0, &mut kv[..10], &mut w), Err(LmError::Work));
        let mut small: Box<Work<32, 128, 48, 100>> = Box::new(Work::new());
        assert_eq!(m.step(Simd::SCALAR, 1, 0, &mut kv, &mut small), Err(LmError::Work));
        // Greedy generation is deterministic and stops at the context limit.
        let mut out1 = [0u16; 64];
        let mut out2 = [0u16; 64];
        let n1 = m.generate(Simd::SCALAR, &[3, 14, 15], None, &mut kv, &mut w, &mut out1).unwrap();
        let n2 = m.generate(Simd::SCALAR, &[3, 14, 15], None, &mut vec![0i8; m.dims.kv_bytes()], &mut w, &mut out2).unwrap();
        assert_eq!((n1, &out1[..n1]), (n2, &out2[..n2]));
        assert_eq!(n1, CTX - 3 + 1, "generates until the context is full");
        // A shape error is caught by check() before anything runs.
        let mut bad = m;
        bad.final_norm = &b.norms[0][..10];
        assert_eq!(bad.check(), Err(LmError::Shape));
    });
}
