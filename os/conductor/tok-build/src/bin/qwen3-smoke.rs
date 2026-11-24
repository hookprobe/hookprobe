// SPDX-License-Identifier: AGPL-3.0-only
//! Converter smoke test on the build host (NOT a model track; Neuro owns models and evaluation):
//! a real Qwen3 GGUF is opened with `neuro_gguf`, bound to the integer decoder, tokenised with the device
//! tokenizer built from the same file, and run greedily. Every step is compared with an independent f64
//! runtime that dequantises the same `Q8_0` bytes and keeps every activation in f64.
//!
//! usage: qwen3-smoke FILE.gguf [max_new_tokens] [prompt]
use neuro_gguf::{qwen3 as bind, Gguf};
use neuro_kernels::{hp, Simd};
use neuro_lm::qwen3::{Kv, Work};
use neuro_lm::tok::Tokenizer;
use std::time::Instant;

const CTX: usize = 256;

/// How the f64 reference treats GEMV inputs: kept in f64, quantised as llama.cpp's CPU path does, or
/// quantised by the engine's own quantiser (isolating every other part of the engine's arithmetic).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Mode {
    Float,
    Llama,
    Engine,
}

/// f64 reference, streaming over the GGUF bytes (nothing pre-dequantised; ~13 GB would not fit as f64).
struct Ref<'a> {
    g: &'a Gguf<'a>,
    h: bind::Hparams,
    mode: Mode,
    k: Vec<Vec<Vec<f64>>>,
    v: Vec<Vec<Vec<f64>>>,
}

fn half(b: u16) -> f64 {
    neuro_build::from_half(b)
}

/// y = W x for a Q8_0 matrix, rows split across threads. With `REF_ACTQ=1` the input is first quantised
/// per block of 32 exactly as llama.cpp's CPU path does for Q8_0 (`d = amax/127`, `q = round(x/d)`, the
/// scale stored as binary16), to separate that effect from the integer engine's own arithmetic.
fn mv(w: &[u8], rows: usize, x: &[f64], mode: Mode) -> Vec<f64> {
    let quantised: Vec<f64>;
    let x = if mode == Mode::Engine {
        let xi: Vec<i64> = x.iter().map(|v| (v * hp::ONE as f64).round() as i64).collect();
        let (mut q, mut s) = (vec![0i8; x.len()], vec![(0, 0); x.len() / 32]);
        assert!(neuro_kernels::q8::quantize(&xi, &mut q, &mut s));
        quantised = q.iter().enumerate().map(|(i, &v)| v as f64 * s[i / 32].0 as f64 * 2f64.powi(s[i / 32].1) / hp::ONE as f64).collect();
        &quantised[..]
    } else if mode == Mode::Llama {
        quantised = x.chunks(32).flat_map(|b| {
            let amax = b.iter().fold(0f64, |m, v| m.max(v.abs())) as f32;
            let d = amax / 127.0;
            let id = if d != 0.0 { 1.0 / d } else { 0.0 };
            let dh = half(neuro_build::to_half(d as f64));
            b.iter().map(move |&v| ((v as f32) * id).round() as f64 * dh).collect::<Vec<f64>>()
        }).collect();
        &quantised[..]
    } else {
        x
    };
    let cols = x.len();
    let rb = cols / 32 * 34;
    let mut y = vec![0.0; rows];
    let threads = std::thread::available_parallelism().map_or(4, |n| n.get());
    let per = rows.div_ceil(threads);
    std::thread::scope(|s| {
        for (ci, chunk) in y.chunks_mut(per).enumerate() {
            s.spawn(move || {
                for (j, o) in chunk.iter_mut().enumerate() {
                    let r = ci * per + j;
                    let row = &w[r * rb..(r + 1) * rb];
                    let mut acc = 0.0;
                    for (b, blk) in row.chunks_exact(34).enumerate() {
                        let d = half(u16::from_le_bytes([blk[0], blk[1]]));
                        let mut s = 0.0;
                        for (q, xv) in blk[2..].iter().zip(&x[b * 32..b * 32 + 32]) {
                            s += (*q as i8) as f64 * xv;
                        }
                        acc += d * s;
                    }
                    *o = acc;
                }
            });
        }
    });
    y
}

fn singles(b: &[u8]) -> Vec<f64> {
    b.chunks_exact(4).map(|c| f32::from_le_bytes([c[0], c[1], c[2], c[3]]) as f64).collect()
}

impl<'a> Ref<'a> {
    fn t(&self, name: &str) -> neuro_gguf::Tensor<'a> {
        self.g.tensor(name.as_bytes()).unwrap_or_else(|| panic!("{name}"))
    }
    fn step(&mut self, tok: usize, pos: usize) -> Vec<f64> {
        let d = self.h.dims;
        let (dm, hd) = (d.d_model, d.head_dim);
        let eps = f32::from_bits(self.h.eps) as f64;
        let base = f32::from_bits(self.h.rope_base) as f64;
        let norm = |x: &[f64], g: &[f64]| {
            let rms = (x.iter().map(|v| v * v).sum::<f64>() / x.len() as f64 + eps).sqrt();
            x.iter().zip(g).map(|(v, g)| v / rms * g).collect::<Vec<f64>>()
        };
        let rope = |x: &mut [f64]| {
            let h = x.len() / 2;
            for i in 0..h {
                let th = pos as f64 * base.powf(-2.0 * i as f64 / hd as f64);
                let (a, b) = (x[i], x[i + h]);
                x[i] = a * th.cos() - b * th.sin();
                x[i + h] = a * th.sin() + b * th.cos();
            }
        };
        let emb = self.t("token_embd.weight");
        let rb = dm / 32 * 34;
        let mut h: Vec<f64> = emb.data[tok * rb..(tok + 1) * rb].chunks_exact(34).flat_map(|blk| {
            let s = half(u16::from_le_bytes([blk[0], blk[1]]));
            blk[2..].iter().map(move |&q| s * (q as i8) as f64)
        }).collect();
        for l in 0..d.n_layers {
            let gg = self.g;
            let w = |n: &str| gg.tensor(format!("blk.{l}.{n}").as_bytes()).unwrap_or_else(|| panic!("blk.{l}.{n}"));
            let x = norm(&h, &singles(w("attn_norm.weight").data));
            let mut q = mv(w("attn_q.weight").data, d.n_heads * hd, &x, self.mode);
            let mut k = mv(w("attn_k.weight").data, d.n_kv_heads * hd, &x, self.mode);
            let v = mv(w("attn_v.weight").data, d.n_kv_heads * hd, &x, self.mode);
            let (qn, kn) = (singles(w("attn_q_norm.weight").data), singles(w("attn_k_norm.weight").data));
            for qh in q.chunks_mut(hd) {
                let n = norm(qh, &qn);
                qh.copy_from_slice(&n);
                rope(qh);
            }
            for kh in k.chunks_mut(hd) {
                let n = norm(kh, &kn);
                kh.copy_from_slice(&n);
                rope(kh);
            }
            self.k[l].push(k);
            self.v[l].push(v);
            let mut att = vec![0.0; d.n_heads * hd];
            let group = d.n_heads / d.n_kv_heads;
            for hh in 0..d.n_heads {
                let g = hh / group;
                let qh = &q[hh * hd..(hh + 1) * hd];
                let s: Vec<f64> = (0..=pos).map(|j| (0..hd).map(|c| qh[c] * self.k[l][j][g * hd + c]).sum::<f64>() / (hd as f64).sqrt()).collect();
                let m = s.iter().cloned().fold(f64::MIN, f64::max);
                let z: f64 = s.iter().map(|v| (v - m).exp()).sum();
                for c in 0..hd {
                    att[hh * hd + c] = (0..=pos).map(|j| (s[j] - m).exp() / z * self.v[l][j][g * hd + c]).sum();
                }
            }
            for (a, b) in h.iter_mut().zip(mv(w("attn_output.weight").data, dm, &att, self.mode)) {
                *a += b;
            }
            let x = norm(&h, &singles(w("ffn_norm.weight").data));
            let gt = mv(w("ffn_gate.weight").data, d.ffn, &x, self.mode);
            let up = mv(w("ffn_up.weight").data, d.ffn, &x, self.mode);
            let act: Vec<f64> = gt.iter().zip(&up).map(|(a, b)| a / (1.0 + (-a).exp()) * b).collect();
            for (a, b) in h.iter_mut().zip(mv(w("ffn_down.weight").data, dm, &act, self.mode)) {
                *a += b;
            }
        }
        let x = norm(&h, &singles(self.t("output_norm.weight").data));
        let head = self.g.tensor(b"output.weight").unwrap_or(emb);
        mv(head.data, d.vocab, &x, self.mode)
    }
}

fn cosine(a: &[f64], b: &[f64]) -> f64 {
    let dot: f64 = a.iter().zip(b).map(|(x, y)| x * y).sum();
    dot / (a.iter().map(|v| v * v).sum::<f64>().sqrt() * b.iter().map(|v| v * v).sum::<f64>().sqrt())
}

fn argmax(v: &[f64]) -> usize {
    v.iter().enumerate().fold((0, f64::MIN), |b, (i, &x)| if x > b.1 { (i, x) } else { b }).0
}

fn main() {
    let mut args = std::env::args().skip(1);
    let path = args.next().expect("usage: qwen3-smoke FILE.gguf [max_new_tokens] [prompt]");
    let max_new: usize = args.next().map_or(12, |s| s.parse().expect("max_new_tokens"));
    let question = args.next().unwrap_or_else(|| "What is the capital of France? Answer in one word.".into());

    let t0 = Instant::now();
    // Leaked: the model borrows it for the rest of this one-shot program.
    let bytes: &'static [u8] = std::fs::read(&path).expect("read").leak();
    let g = Gguf::open(bytes).expect("open GGUF");
    let h = bind::hparams(&g, CTX).expect("hparams");
    println!("opened {path} in {:?}: {:?}", t0.elapsed(), h.dims);
    println!("kq_scale bits {:#x} (f32 1/sqrt(128) = {:#x})", h.kq_scale, (1.0f32 / (h.dims.head_dim as f32).sqrt()).to_bits());
    let layers: Vec<_> = (0..h.dims.n_layers).map(|i| bind::layer(&g, &h, i).expect("layer")).collect();
    let rope = neuro_build::rope_neox_table(CTX, h.dims.head_dim, f32::from_bits(h.rope_base) as f64);
    let model = bind::model(&g, &h, &layers, &rope).expect("bind model");

    // PACKED=1: pack every matrix (the device's load-time step), prove each unpacks to the exact GGUF bytes,
    // and run the packed model beside the GGUF one: every logit must be equal.
    let packed_mode = std::env::var("PACKED").is_ok_and(|v| v == "1");
    let pmodel = if packed_mode {
        let t = Instant::now();
        let mut bytes_in = 0usize;
        let mut bytes_out = 0usize;
        let mut pk = |m: &neuro_lm::qwen3::Mat| -> neuro_lm::qwen3::Mat<'static> {
            let buf: &'static mut [u8] = vec![0u8; neuro_kernels::q8::packed_bytes(m.rows, m.cols)].leak();
            let p = m.pack_into(buf).expect("pack");
            let mut row = vec![0u8; neuro_kernels::q8::row_bytes(m.cols)];
            for r in 0..m.rows {
                assert!(neuro_kernels::q8::unpack_row(p.w, m.rows, m.cols, r, &mut row));
                assert_eq!(&row[..], &m.w[r * row.len()..(r + 1) * row.len()], "unpacked row differs from the GGUF bytes");
            }
            bytes_in += m.w.len();
            bytes_out += p.w.len();
            p
        };
        let players: Vec<_> = layers.iter().map(|l| neuro_lm::qwen3::Layer { wq: pk(&l.wq), wk: pk(&l.wk), wv: pk(&l.wv), wo: pk(&l.wo), w_gate: pk(&l.w_gate), w_up: pk(&l.w_up), w_down: pk(&l.w_down), ..*l }).collect();
        let players: &'static [neuro_lm::qwen3::Layer] = players.leak();
        let pm = neuro_lm::qwen3::Model { embed: pk(&model.embed), layers: players, head: model.head.as_ref().map(&mut pk), ..model };
        pm.check().expect("packed model check");
        println!("packed {bytes_in} GGUF bytes into {bytes_out} ({:+.1} %) in {:?}; every row unpacks to the exact GGUF bytes", (bytes_out as f64 / bytes_in as f64 - 1.0) * 100.0, t.elapsed());
        Some(pm)
    } else {
        None
    };

    let tok_blob = tok_build::blob(&tok_build::from_gguf(&g).expect("tokenizer"), &tok_build::unicode_ranges(), &tok_build::nfc_tables()).expect("blob");
    let tok = Tokenizer::new(&tok_blob).expect("tokenizer blob");
    // Qwen3 chat template, non-thinking mode (empty think block), as the template renders it.
    let prompt = format!("<|im_start|>user\n{question}<|im_end|>\n<|im_start|>assistant\n<think>\n\n</think>\n\n");
    let mut ids = vec![0u32; 4096];
    let (mut cps, mut buf) = (vec![0u32; 1 << 16], vec![0u8; 1 << 16]);
    let n = tok.encode_nfc(prompt.as_bytes(), &mut ids, &mut cps, &mut buf).expect("encode");
    ids.truncate(n);
    println!("prompt: {n} tokens: {ids:?}");
    let im_end = tok.added_id(b"<|im_end|>").expect("<|im_end|>");

    let d = h.dims;
    let (kvn, kvs) = d.kv_len();
    let (mut vals, mut shifts) = (vec![0i16; kvn], vec![0u8; kvs]);
    let (a, i8n, scn, i32n) = Work::lens(&d, 1);
    let (mut ba, mut bb, mut bc, mut bd) = (vec![0i64; a], vec![0i8; i8n], vec![(0, 0); scn], vec![0i32; i32n]);
    let mut work = Work::new(&d, 1, &mut ba, &mut bb, &mut bc, &mut bd).expect("work");
    let mut kv = Kv { vals: &mut vals, shifts: &mut shifts };
    let (mut vals2, mut shifts2) = (vec![0i16; kvn], vec![0u8; kvs]);
    let (mut ba2, mut bb2, mut bc2, mut bd2) = (vec![0i64; a], vec![0i8; i8n], vec![(0, 0); scn], vec![0i32; i32n]);
    let mut work2 = Work::new(&d, 1, &mut ba2, &mut bb2, &mut bc2, &mut bd2).expect("work");
    let mut kv2 = Kv { vals: &mut vals2, shifts: &mut shifts2 };
    let mut packed_equal = 0usize;
    let mut reference = Ref { g: &g, h, mode: Mode::Float, k: vec![vec![]; d.n_layers], v: vec![vec![]; d.n_layers] };
    // Diagnostics (REF_DIAG=1): the same f64 runtime with llama.cpp-CPU and with engine activation quantisation.
    let diag = std::env::var("REF_DIAG").is_ok_and(|v| v == "1");
    let mut ref_llama = Ref { g: &g, h, mode: Mode::Llama, k: vec![vec![]; d.n_layers], v: vec![vec![]; d.n_layers] };
    let mut ref_engine = Ref { g: &g, h, mode: Mode::Engine, k: vec![vec![]; d.n_layers], v: vec![vec![]; d.n_layers] };
    let (mut d_llama, mut d_engine) = (0.0f64, 0.0f64);

    let (mut t_int, mut t_ref) = (0.0f64, 0.0f64);
    let (mut cos_min, mut cos_sum, mut agree, mut steps) = (1.0f64, 0.0f64, 0usize, 0usize);
    let mut generated: Vec<u32> = vec![];
    let mut next = 0usize;
    for pos in 0..n + max_new {
        let tokid = if pos < n { ids[pos] as usize } else { next };
        if pos >= n {
            generated.push(tokid as u32);
            if tokid as u32 == im_end {
                break;
            }
        }
        let s = Instant::now();
        let got = model.step(Simd::SCALAR, tokid, pos, &mut kv, &mut work).expect("step");
        if let Some(pm) = &pmodel {
            let got2 = pm.step(Simd::SCALAR, tokid, pos, &mut kv2, &mut work2).expect("packed step");
            assert!(got2 == got && work2.logits == work.logits, "packed and GGUF logits differ at {pos}");
            packed_equal += 1;
        }
        t_int += s.elapsed().as_secs_f64();
        let s = Instant::now();
        let want = reference.step(tokid, pos);
        t_ref += s.elapsed().as_secs_f64();
        let gl: Vec<f64> = work.logits.iter().map(|&v| v as f64 / hp::ONE as f64).collect();
        let dot: f64 = gl.iter().zip(&want).map(|(a, b)| a * b).sum();
        let cos = dot / (gl.iter().map(|v| v * v).sum::<f64>().sqrt() * want.iter().map(|v| v * v).sum::<f64>().sqrt());
        let maxdiff = gl.iter().zip(&want).map(|(a, b)| (a - b).abs()).fold(0.0, f64::max);
        let wbest = argmax(&want);
        if diag {
            let (wl, we) = (ref_llama.step(tokid, pos), ref_engine.step(tokid, pos));
            let (c1, c2) = (cosine(&wl, &want), cosine(&gl, &we));
            d_llama = d_llama.max(1.0 - c1);
            d_engine = d_engine.max(1.0 - c2);
            println!("  pos {pos}: llama.cpp-CPU quantisation vs float 1-cos {:.1e}; integer engine vs float-with-engine-quantisation 1-cos {:.1e}", 1.0 - c1, 1.0 - c2);
        }
        cos_min = cos_min.min(cos);
        cos_sum += cos;
        steps += 1;
        agree += usize::from(got == wbest);
        if got != wbest {
            println!("pos {pos}: integer -> {got}, f64 -> {wbest}: f64 logits {:.4} vs {:.4} (gap {:.4})", want[wbest], want[got], want[wbest] - want[got]);
        }
        if pos + 1 >= n {
            let mut sorted = want.clone();
            sorted.sort_by(|a, b| b.partial_cmp(a).unwrap());
            println!("pos {pos}: integer -> {got}, f64 -> {wbest} (margin {:.3}), 1-cos {:.1e}, max |dlogit| {maxdiff:.4}", sorted[0] - sorted[1], 1.0 - cos);
        }
        next = got;
    }
    let mut out = vec![0u8; 1 << 16];
    let m = tok.decode(&generated, &mut out).expect("decode");
    println!("\nanswer (integer engine, greedy): {:?}", String::from_utf8_lossy(&out[..m]));
    if packed_mode {
        println!("packed model: every logit equal to the GGUF-layout model at all {packed_equal} steps");
    }
    if diag {
        println!("worst 1-cos: llama.cpp-CPU activation quantisation vs float {d_llama:.1e}; integer engine vs float with the engine's own activation quantisation {d_engine:.1e}");
    }
    println!(
        "{steps} steps: logit 1-cosine mean {:.1e} worst {:.1e}; greedy token equal to the f64 runtime in {agree}/{steps}; integer engine {:.2} s/token (scalar, 1 thread, build host), f64 reference {:.2} s/token ({} threads)",
        1.0 - cos_sum / steps as f64,
        1.0 - cos_min,
        t_int / steps as f64,
        t_ref / steps as f64,
        std::thread::available_parallelism().map_or(4, |n| n.get())
    );
}
