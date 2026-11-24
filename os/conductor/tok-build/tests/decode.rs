// SPDX-License-Identifier: AGPL-3.0-only
//! Evidence-closed decoding on a random Qwen3-shaped model with a small trained BPE vocabulary:
//! - a batched forward pass equals one-token steps, logit for logit, in both weight layouts;
//! - every answer is valid under the contract (parsed by the contract's own parser);
//! - plain, head-pruned and speculative decoding produce identical tokens;
//! - speculation and pruning reduce the work the way the stats claim.
use neuro_contract::{context_ids, parse, Allowed, IdList, Machine};
use neuro_kernels::Simd;
use neuro_lm::decode::{generate_closed, Options, Stats};
use neuro_lm::qwen3::{Head, Kv, Layer, Mat, Model, Work, MAX_BATCH};
use neuro_lm::tok::Tokenizer;
use neuro_lm::Dims;
use tok_build::*;

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn normal(&mut self) -> f64 {
        let u = ((self.next() >> 11) as f64 / (1u64 << 53) as f64).max(1e-12);
        let v = (self.next() >> 11) as f64 / (1u64 << 53) as f64;
        (-2.0 * u.ln()).sqrt() * (2.0 * std::f64::consts::PI * v).cos()
    }
}

const EXAMPLE: &str = r#"{"verdict": "suspicious", "severity": "medium", "summary": "H1 contacted R3 on port 443 (F1) and R4 (F2).", "evidence": ["F1", "F2"], "entities": ["H1", "R3"], "next_step": "investigate", "confidence": 60}"#;

/// A byte-level BPE trained on example answers (classic most-frequent-pair), plus `<|im_end|>`.
fn tokenizer() -> Vec<u8> {
    let corpus: String = [EXAMPLE, r#"{"verdict": "benign", "severity": "info", "summary": "", "evidence": [], "entities": [], "next_step": "observe", "confidence": 5}"#].concat();
    let mut seq: Vec<u32> = corpus.bytes().map(u32::from).collect();
    let mut tokens: Vec<Vec<u8>> = (0..=255u8).map(|b| vec![b]).collect();
    let mut merges = vec![];
    for _ in 0..120 {
        let mut counts = std::collections::BTreeMap::new();
        for w in seq.windows(2) {
            *counts.entry((w[0], w[1])).or_insert(0usize) += 1;
        }
        let Some((&pair, &c)) = counts.iter().max_by_key(|(p, c)| (**c, std::cmp::Reverse(**p))) else { break };
        if c < 2 {
            break;
        }
        let new = tokens.len() as u32;
        let mut t = tokens[pair.0 as usize].clone();
        t.extend_from_slice(&tokens[pair.1 as usize]);
        tokens.push(t);
        merges.push(pair);
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
    }
    let eog = tokens.len() as u32;
    tokens.push(b"<|im_end|>".to_vec());
    blob(&Source { tokens, merges, added: vec![eog] }, &unicode_ranges(), &nfc_tables()).unwrap()
}

fn quant_q8_0(w: &[f64]) -> Vec<u8> {
    let mut out = vec![];
    for b in w.chunks(32) {
        let amax = b.iter().fold(0f64, |m, v| m.max(v.abs()));
        let d = amax / 127.0;
        let id = if d > 0.0 { 1.0 / d } else { 0.0 };
        out.extend_from_slice(&neuro_build::to_half(d).to_le_bytes());
        out.extend(b.iter().map(|v| (v * id).round().clamp(-127.0, 127.0) as i8 as u8));
    }
    out
}

fn singles(n: usize, r: &mut Rng) -> Vec<u8> {
    (0..n).flat_map(|_| ((1.0 + 0.2 * r.normal()) as f32).to_bits().to_le_bytes()).collect()
}

struct Bytes {
    mats: Vec<Vec<u8>>,
    norms: Vec<Vec<u8>>,
    embed: Vec<u8>,
    final_norm: Vec<u8>,
}

fn dims(vocab: usize) -> Dims {
    Dims { vocab, d_model: 64, n_layers: 2, n_heads: 4, n_kv_heads: 2, head_dim: 16, ffn: 128, max_ctx: 1024 }
}

fn build(vocab: usize, seed: u64) -> Bytes {
    let d = dims(vocab);
    let mut r = Rng(seed);
    let mut mat = |rows: usize, cols: usize, r: &mut Rng| quant_q8_0(&(0..rows * cols).map(|_| r.normal() / (cols as f64).sqrt()).collect::<Vec<_>>());
    let (qd, kvd) = (d.n_heads * d.head_dim, d.n_kv_heads * d.head_dim);
    let mut mats = vec![];
    let mut norms = vec![];
    for _ in 0..d.n_layers {
        for (rows, cols) in [(qd, 64), (kvd, 64), (kvd, 64), (64, qd), (d.ffn, 64), (d.ffn, 64), (64, d.ffn)] {
            mats.push(mat(rows, cols, &mut r));
        }
        norms.push(singles(64, &mut r));
        norms.push(singles(d.head_dim, &mut r));
        norms.push(singles(d.head_dim, &mut r));
        norms.push(singles(64, &mut r));
    }
    let embed = quant_q8_0(&(0..vocab * 64).map(|_| r.normal() * 2.0).collect::<Vec<_>>());
    Bytes { mats, norms, embed, final_norm: singles(64, &mut r) }
}

fn model<'a>(b: &'a Bytes, vocab: usize, rope: &'a [(i32, i32)], pack: bool) -> Model<'a> {
    let d = dims(vocab);
    let (qd, kvd) = (d.n_heads * d.head_dim, d.n_kv_heads * d.head_dim);
    let shapes = [(qd, 64), (kvd, 64), (kvd, 64), (64, qd), (d.ffn, 64), (d.ffn, 64), (64, d.ffn)];
    let mut mats: Vec<Mat> = b.mats.iter().enumerate().map(|(i, w)| Mat::gguf(shapes[i % 7].0, shapes[i % 7].1, w)).collect();
    let mut embed = Mat::gguf(vocab, 64, &b.embed);
    if pack {
        // Pack into leaked buffers (test only).
        mats = mats.iter().map(|m| m.pack_into(vec![0u8; neuro_kernels::q8::packed_bytes(m.rows, m.cols)].leak()).unwrap()).collect();
        embed = embed.pack_into(vec![0u8; neuro_kernels::q8::packed_bytes(vocab, 64)].leak()).unwrap();
    }
    let layers: Vec<Layer> = (0..d.n_layers)
        .map(|l| Layer {
            attn_norm: &b.norms[4 * l],
            wq: mats[7 * l],
            wk: mats[7 * l + 1],
            wv: mats[7 * l + 2],
            wo: mats[7 * l + 3],
            q_norm: &b.norms[4 * l + 1],
            k_norm: &b.norms[4 * l + 2],
            ffn_norm: &b.norms[4 * l + 3],
            w_gate: mats[7 * l + 4],
            w_up: mats[7 * l + 5],
            w_down: mats[7 * l + 6],
        })
        .collect();
    let m = Model { dims: d, embed, layers: layers.leak(), final_norm: &b.final_norm, head: None, rope, eps: 1e-6f32.to_bits(), kq_scale: (1.0f32 / 4.0).to_bits() };
    m.check().unwrap();
    m
}

struct Buffers {
    vals: Vec<i16>,
    shifts: Vec<u8>,
    a: Vec<i64>,
    b: Vec<i8>,
    c: Vec<(i32, i32)>,
    e: Vec<i32>,
}

fn buffers(d: &Dims, batch: usize) -> Buffers {
    let (kvn, kvs) = d.kv_len();
    let (a, b, c, e) = Work::lens(d, batch);
    Buffers { vals: vec![0; kvn], shifts: vec![0; kvs], a: vec![0; a], b: vec![0; b], c: vec![(0, 0); c], e: vec![0; e] }
}

#[test]
fn batched_forward_equals_single_steps() {
    let tb = tokenizer();
    let tok = Tokenizer::new(&tb).unwrap();
    let vocab = tok.vocab();
    let bytes = build(vocab, 5);
    let rope = neuro_build::rope_neox_table(1024, 16, 1e6);
    for pack in [false, true] {
        let m = model(&bytes, vocab, &rope, pack);
        let d = m.dims;
        let toks: Vec<usize> = (0..40).map(|i| (i * 37 + 11) % vocab).collect();
        // Sequential.
        let mut s = buffers(&d, 1);
        let mut kv = Kv { vals: &mut s.vals, shifts: &mut s.shifts };
        let mut w = Work::new(&d, 1, &mut s.a, &mut s.b, &mut s.c, &mut s.e).unwrap();
        let mut seq = vec![];
        for (p, &t) in toks.iter().enumerate() {
            m.step(Simd::SCALAR, t, p, &mut kv, &mut w).unwrap();
            seq.push(w.logits_of(0, vocab).to_vec());
        }
        // Batched, in uneven chunks.
        for batch in [3usize, 8, MAX_BATCH] {
            let mut s2 = buffers(&d, batch);
            let mut kv2 = Kv { vals: &mut s2.vals, shifts: &mut s2.shifts };
            let mut w2 = Work::new(&d, batch, &mut s2.a, &mut s2.b, &mut s2.c, &mut s2.e).unwrap();
            let mut p = 0usize;
            while p < toks.len() {
                let n = batch.min(toks.len() - p);
                m.forward(Simd::SCALAR, &toks[p..p + n], p, &mut kv2, &mut w2, Head::All).unwrap();
                for j in 0..n {
                    assert_eq!(w2.logits_of(j, vocab), &seq[p + j][..], "pack {pack} batch {batch} position {}", p + j);
                }
                p += n;
            }
        }
        // A pruned head computes exactly the listed rows.
        let mut s3 = buffers(&d, 1);
        let mut kv3 = Kv { vals: &mut s3.vals, shifts: &mut s3.shifts };
        let mut w3 = Work::new(&d, 1, &mut s3.a, &mut s3.b, &mut s3.c, &mut s3.e).unwrap();
        for (p, &t) in toks.iter().enumerate().take(toks.len() - 1) {
            m.step(Simd::SCALAR, t, p, &mut kv3, &mut w3).unwrap();
        }
        let rows: Vec<u32> = (0..vocab as u32).filter(|r| r % 7 == 3 || *r == 0).collect();
        m.forward(Simd::SCALAR, &[toks[toks.len() - 1]], toks.len() - 1, &mut kv3, &mut w3, Head::Rows(&rows)).unwrap();
        for r in 0..vocab {
            let want = if rows.contains(&(r as u32)) { seq[toks.len() - 1][r] } else { i64::MIN };
            assert_eq!(w3.logits_of(0, vocab)[r], want);
        }
    }
    println!("batched forward == single steps for batch 3, 8, {MAX_BATCH} in both layouts; pruned head == full head on its rows");
}

fn decode(m: &Model, tok: &Tokenizer, prompt: &[u32], ctx: &str, opts: Options, batch: usize) -> (Vec<u32>, Stats) {
    let d = m.dims;
    let (mut f, mut e) = (IdList::new(), IdList::new());
    context_ids(ctx.as_bytes(), &mut f, &mut e).unwrap();
    let eog = [tok.added_id(b"<|im_end|>").unwrap()];
    let mut s = buffers(&d, batch);
    let mut kv = Kv { vals: &mut s.vals, shifts: &mut s.shifts };
    let mut w = Work::new(&d, batch, &mut s.a, &mut s.b, &mut s.c, &mut s.e).unwrap();
    let mut hist = vec![0u32; prompt.len() + opts.max_new];
    let mut list = vec![0u32; 4096];
    let mut out = vec![0u32; opts.max_new];
    let machine = Machine::new(Allowed { facts: &f, entities: &e, closed: true });
    let (n, st) = generate_closed(m, Simd::SCALAR, tok, prompt, &eog, machine, &mut kv, &mut w, &mut hist, &mut list, opts, &mut out).unwrap();
    out.truncate(n);
    (out, st)
}

#[test]
fn constrained_decoding_is_valid_and_exactly_the_same_with_speed_ups() {
    let tb = tokenizer();
    let tok = Tokenizer::new(&tb).unwrap();
    let vocab = tok.vocab();
    let rope = neuro_build::rope_neox_table(1024, 16, 1e6);
    let eog = tok.added_id(b"<|im_end|>").unwrap();
    let (mut sum_plain, mut sum_spec, mut sum_tokens, mut accepted, mut drafted, mut pruned_rows, mut pruned_passes) = (0u32, 0u32, 0u32, 0u32, 0u32, 0u64, 0u32);
    for seed in 0..6u64 {
        let bytes = build(vocab, 100 + seed);
        for pack in [false, true] {
            let m = model(&bytes, vocab, &rope, pack);
            let ctx = "F1 H1 -> R3 tcp/443 n=40\nF2 H1 -> R4 udp/53 n=3\nF3 dns D2 newly registered";
            let prompt_text = format!("CONTEXT (untrusted):\n<<<\n{ctx}\n>>>\n\nQUESTION: why? {EXAMPLE}");
            let mut ptoks = vec![0u32; 4096];
            let np = tok.encode(prompt_text.as_bytes(), &mut ptoks).unwrap();
            let prompt = &ptoks[..np];
            let base = Options { prune_max: 0, draft_max: 0, max_new: 1600 };
            let (plain, st0) = decode(&m, &tok, prompt, ctx, base, 1);
            let (pruned, st1) = decode(&m, &tok, prompt, ctx, Options { prune_max: 4096, ..base }, 1);
            let (spec, st2) = decode(&m, &tok, prompt, ctx, Options { draft_max: 7, ..base }, 8);
            let (both, _) = decode(&m, &tok, prompt, ctx, Options { prune_max: 4096, draft_max: 7, ..base }, 8);
            assert_eq!(plain, pruned, "pruning changed the output (seed {seed}, pack {pack})");
            assert_eq!(plain, spec, "speculation changed the output (seed {seed}, pack {pack})");
            assert_eq!(plain, both);
            // The answer is valid under the contract.
            assert_eq!(*plain.last().unwrap(), eog, "no end of generation");
            let mut text = vec![0u8; 8192];
            let nb = tok.decode(&plain[..plain.len() - 1], &mut text).unwrap();
            let (mut f, mut e) = (IdList::new(), IdList::new());
            context_ids(ctx.as_bytes(), &mut f, &mut e).unwrap();
            let a = parse(&text[..nb], &f, &e).unwrap_or_else(|err| panic!("invalid answer {err:?}: {}", String::from_utf8_lossy(&text[..nb])));
            assert!(a.confidence <= 100);
            sum_plain += st0.passes;
            sum_spec += st2.passes;
            sum_tokens += st0.tokens;
            accepted += st2.accepted;
            drafted += st2.drafted;
            pruned_rows += st1.pruned_rows;
            pruned_passes += st1.pruned_passes;
            if seed == 0 && !pack {
                println!("example answer from a random model under the contract: {}", String::from_utf8_lossy(&text[..nb]));
            }
        }
    }
    println!(
        "12 runs, {sum_tokens} tokens, outputs identical with and without the speed-ups: passes {sum_plain} -> {sum_spec} with speculation ({:.2} -> {:.2} per token; {accepted}/{drafted} drafts accepted); pruned passes {pruned_passes}, {:.0} head rows each of {vocab}",
        sum_plain as f64 / sum_tokens as f64,
        sum_spec as f64 / sum_tokens as f64,
        pruned_rows as f64 / pruned_passes.max(1) as f64
    );
    assert!(sum_spec < sum_plain);
}
