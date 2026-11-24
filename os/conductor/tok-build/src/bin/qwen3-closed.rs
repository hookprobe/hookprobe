// SPDX-License-Identifier: AGPL-3.0-only
//! Evidence-closed decoding on a real Qwen3 GGUF (build host; a converter and engine check, NOT an
//! evaluation: Neuro owns models, sets and quality). The prompt is built only from `neuro_contract`: Neuro's
//! system prompt, the closed-mode schema for this context, the user framing. The answer is generated twice,
//! plainly and with head pruning + verified speculation, and must be identical token for token.
//!
//! usage: qwen3-closed FILE.gguf
use neuro_contract::{context_ids, parse, write_system, write_user, Allowed, IdList, Lang, Machine, Out};
use neuro_gguf::{qwen3 as bind, Gguf};
use neuro_kernels::Simd;
use neuro_lm::decode::{generate_closed, Options};
use neuro_lm::qwen3::{Kv, Work};
use neuro_lm::tok::Tokenizer;
use std::time::Instant;

const CTX: usize = 1024;
/// A synthetic context written for this check (not from any Neuro evaluation set).
const CONTEXT: &str = "F1 flow H1 -> R1 tcp dst ports 22,23,80,443,8080 n=40 in 2 s, all SYN, no replies\nF2 flow H1 -> R2 tcp/443 n=2 established, 4 KB\nF3 S1 score 0.93 on H1 (new peers, port fan-out)\nF4 owner note: H1 is a smart TV";
const QUESTION: &str = "Why was H1 flagged?";

fn main() {
    let path = std::env::args().nth(1).expect("usage: qwen3-closed FILE.gguf");
    let bytes: &'static [u8] = std::fs::read(&path).expect("read").leak();
    let g = Gguf::open(bytes).expect("open");
    let h = bind::hparams(&g, CTX).expect("hparams");
    let layers: Vec<_> = (0..h.dims.n_layers).map(|i| bind::layer(&g, &h, i).expect("layer")).collect();
    let layers: &'static [_] = layers.leak();
    let rope: &'static [(i32, i32)] = neuro_build::rope_neox_table(CTX, h.dims.head_dim, f32::from_bits(h.rope_base) as f64).leak();
    let gm = bind::model(&g, &h, layers, rope).expect("bind");
    // Packed weights (the device's load-time form; bit-identical results).
    let pk = |m: &neuro_lm::qwen3::Mat<'static>| m.pack_into(vec![0u8; neuro_kernels::q8::packed_bytes(m.rows, m.cols)].leak()).expect("pack");
    let pl: Vec<_> = layers.iter().map(|l| neuro_lm::qwen3::Layer { wq: pk(&l.wq), wk: pk(&l.wk), wv: pk(&l.wv), wo: pk(&l.wo), w_gate: pk(&l.w_gate), w_up: pk(&l.w_up), w_down: pk(&l.w_down), ..*l }).collect();
    let model = neuro_lm::qwen3::Model { embed: pk(&gm.embed), layers: pl.leak(), ..gm };
    model.check().expect("check");
    let tb = tok_build::blob(&tok_build::from_gguf(&g).expect("tok"), &tok_build::unicode_ranges(), &tok_build::nfc_tables()).expect("blob");
    let tok = Tokenizer::new(&tb).expect("tokenizer");

    // The prompt, from the contract alone.
    let (mut facts, mut ents) = (IdList::new(), IdList::new());
    context_ids(CONTEXT.as_bytes(), &mut facts, &mut ents).expect("ids");
    let mut sys = vec![0u8; 8192];
    let mut o = Out::new(&mut sys);
    write_system(Lang::En, &facts, &ents, true, &mut o).expect("system");
    let ns = o.n;
    let mut usr = vec![0u8; 4096];
    let mut o = Out::new(&mut usr);
    write_user(CONTEXT.as_bytes(), QUESTION.as_bytes(), &mut o).expect("user");
    let nu = o.n;
    // Qwen3 chat template, non-thinking (as llama-server renders it with reasoning off).
    let text = [b"<|im_start|>system\n".as_slice(), &sys[..ns], b"<|im_end|>\n<|im_start|>user\n", &usr[..nu], b"<|im_end|>\n<|im_start|>assistant\n<think>\n\n</think>\n\n"].concat();
    let mut ids = vec![0u32; 8192];
    let (mut cps, mut buf) = (vec![0u32; 1 << 16], vec![0u8; 1 << 16]);
    let np = tok.encode_nfc(&text, &mut ids, &mut cps, &mut buf).expect("encode");
    let prompt = &ids[..np];
    let eog = [tok.added_id(b"<|im_end|>").expect("im_end"), tok.added_id(b"<|endoftext|>").expect("endoftext")];
    println!("prompt: {np} tokens (system {ns} bytes incl. the closed schema with facts {:?}, entities {:?})", facts.iter().map(|x| String::from_utf8_lossy(x).into_owned()).collect::<Vec<_>>(), ents.iter().map(|x| String::from_utf8_lossy(x).into_owned()).collect::<Vec<_>>());

    let d = model.dims;
    let run = |opts: Options, batch: usize| {
        let (kvn, kvs) = d.kv_len();
        let (mut vals, mut shifts) = (vec![0i16; kvn], vec![0u8; kvs]);
        let (a, b, c, e) = Work::lens(&d, batch);
        let (mut wa, mut wb, mut wc, mut we) = (vec![0i64; a], vec![0i8; b], vec![(0, 0); c], vec![0i32; e]);
        let mut w = Work::new(&d, batch, &mut wa, &mut wb, &mut wc, &mut we).expect("work");
        let mut kv = Kv { vals: &mut vals, shifts: &mut shifts };
        let mut hist = vec![0u32; np + opts.max_new];
        let mut list = vec![0u32; opts.prune_max.max(1)];
        let mut out = vec![0u32; opts.max_new];
        let m = Machine::new(Allowed { facts: &facts, entities: &ents, closed: true });
        let t = Instant::now();
        let (n, st) = generate_closed(&model, Simd::SCALAR, &tok, prompt, &eog, m, &mut kv, &mut w, &mut hist, &mut list, opts, &mut out).expect("generate");
        out.truncate(n);
        (out, st, t.elapsed())
    };
    let base = Options { prune_max: 0, draft_max: 0, max_new: 400 };
    let (a, sa, ta) = run(base, 8);
    let (b, sb, tb2) = run(Options { prune_max: 8192, draft_max: 7, ..base }, 8);
    let mut txt = vec![0u8; 1 << 16];
    let n = tok.decode(&a[..a.len() - usize::from(eog.contains(a.last().unwrap()))], &mut txt).expect("decode");
    println!("\nanswer: {}", String::from_utf8_lossy(&txt[..n]));
    let parsed = parse(&txt[..n], &facts, &ents).expect("answer valid under the contract");
    println!("parsed: verdict {}, confidence {}, evidence {:?}, entities {:?}", parsed.verdict_name(), parsed.confidence, parsed.evidence().iter().map(|&i| String::from_utf8_lossy(facts.get(i as usize).unwrap()).into_owned()).collect::<Vec<_>>(), parsed.entities().iter().map(|&i| String::from_utf8_lossy(ents.get(i as usize).unwrap()).into_owned()).collect::<Vec<_>>());
    assert_eq!(a, b, "speed-ups changed the output");
    println!("\nidentical output with and without the speed-ups ({} tokens)", a.len());
    println!("plain:     {} passes after the prompt ({:.2} per token), prompt {} batched passes, {:?}", sa.passes, sa.passes as f64 / sa.tokens as f64, sa.prefill_passes, ta);
    println!("sped-up:   {} passes ({:.2} per token): {} pruned passes averaging {:.0} head rows of {}; {}/{} drafts accepted; {:?}", sb.passes, sb.passes as f64 / sb.tokens as f64, sb.pruned_passes, sb.pruned_rows as f64 / sb.pruned_passes.max(1) as f64, d.vocab, sb.accepted, sb.drafted, tb2);
}
