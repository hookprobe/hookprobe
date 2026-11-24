// SPDX-License-Identifier: AGPL-3.0-only
//! The investigation prompt through the device's tokenizer, against llama-server's token ids for Neuro's test
//! vectors (`tools/neuro-research/inv_contract.json`: `/tokenize` on the rendered prompt, special tokens parsed,
//! no BOS). Needs the model file the vectors were made with: set `QWEN3_INV_GGUF` to the investigation adapter's
//! GGUF (its SHA-256 is in the contract file). Without it the test is skipped and says so.
use neuro_contract::inv::write_prompt;
use neuro_contract::{Lang, Out, USER_HEAD, USER_MID};
use neuro_lm::tok::Tokenizer;
use serde_json::Value;

#[test]
fn investigation_prompt_token_ids_equal_llama_servers() {
    let Ok(path) = std::env::var("QWEN3_INV_GGUF") else {
        println!("SKIPPED: set QWEN3_INV_GGUF to the investigation adapter's GGUF");
        return;
    };
    let p = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../tools/neuro-research/inv_contract.json");
    let c: Value = serde_json::from_str(&std::fs::read_to_string(&p).expect("inv_contract.json")).expect("json");
    let bytes = std::fs::read(&path).unwrap_or_else(|e| panic!("cannot read {path}: {e}"));
    let g = neuro_gguf::Gguf::open(&bytes).expect("GGUF");
    let blob = tok_build::blob(&tok_build::from_gguf(&g).expect("tokenizer"), &tok_build::unicode_ranges(), &tok_build::nfc_tables()).expect("blob");
    let tok = Tokenizer::new(&blob).expect("tokenizer");
    let vectors = c["test_vectors"]["vectors"].as_array().expect("vectors");
    let (mut text, mut ids, mut cps, mut buf) = (vec![0u8; 1 << 16], vec![0u32; 1 << 14], vec![0u32; 1 << 17], vec![0u8; 1 << 17]);
    let mut total = 0usize;
    for v in vectors {
        let id = v["id"].as_str().expect("id");
        let body: Value = serde_json::from_str(v["request_body"].as_str().expect("request_body")).expect("body");
        let user = body["messages"][1]["content"].as_str().expect("user");
        let (shown, question) = user.strip_prefix(USER_HEAD).and_then(|u| u.rsplit_once(USER_MID)).expect("user framing");
        let mut o = Out::new(&mut text);
        write_prompt(Lang::En, shown.as_bytes(), question.as_bytes(), &mut o).expect("prompt");
        let n = o.n;
        let k = tok.encode_nfc(&text[..n], &mut ids, &mut cps, &mut buf).unwrap_or_else(|e| panic!("{id}: encode: {e:?}"));
        let want: Vec<u32> = v["prompt_token_ids"].as_array().expect("ids").iter().map(|x| x.as_u64().expect("id") as u32).collect();
        assert_eq!(k, v["server_prompt_tokens"].as_u64().expect("count") as usize, "{id}: token count differs from the server's");
        assert_eq!(&ids[..k], want.as_slice(), "{id}: token ids differ from llama-server's");
        total += k;
    }
    println!("investigation prompts: {} vectors, {total} token ids equal llama-server's", vectors.len());
}

fn simd() -> neuro_kernels::Simd {
    #[cfg(all(target_arch = "aarch64", target_feature = "neon"))]
    if std::arch::is_aarch64_feature_detected!("dotprod") {
        // SAFETY: the CPU reports AdvSIMD (compile-time target feature) and DotProd (runtime check above), and
        // FP/SIMD is always enabled for a user process on the host OS.
        return unsafe { neuro_kernels::Simd::neon_dot() };
    }
    neuro_kernels::Simd::SCALAR
}

/// The engine on the investigation adapter, step by step against llama.cpp's CPU backend
/// (`tools/neuro-research/inv_contract_gen.json`: the ids the server generated at temperature 0 under its lazy
/// tool-call grammar, with the raw top-2 log-probabilities of every step). Teacher-forced on the server's
/// tokens: the engine's raw top-1 and its constrained choice must equal the server's, except where the server's
/// own top-2 gap is a near-tie. Then the engine decodes on its own and must produce the same ids.
/// Not an evaluation: three synthetic vectors, one model. Needs `QWEN3_INV_GGUF`; skipped without it.
#[test]
fn investigation_decoding_equals_llama_cpp() {
    use neuro_contract::inv::{ToolMachine, MAX_TOKENS, PRESERVED_TOKENS};
    use neuro_gguf::qwen3 as bind;
    use neuro_lm::decode::{generate_tool, pick_tool};
    use neuro_lm::qwen3::{Head, Kv, Work};
    const CTX: usize = 2048;
    const TIE: f64 = 0.5;
    const Q16: f64 = 65536.0;
    let Ok(path) = std::env::var("QWEN3_INV_GGUF") else {
        println!("SKIPPED: set QWEN3_INV_GGUF to the investigation adapter's GGUF");
        return;
    };
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../tools/neuro-research");
    let read = |f: &str| -> Value { serde_json::from_str(&std::fs::read_to_string(dir.join(f)).unwrap_or_else(|e| panic!("{f}: {e}"))).expect("json") };
    let (contract, gen) = (read("inv_contract.json"), read("inv_contract_gen.json"));
    assert_eq!(gen["model_gguf_sha256"], contract["test_vectors"]["model_gguf_sha256"]);

    let bytes: &'static [u8] = std::fs::read(&path).unwrap_or_else(|e| panic!("cannot read {path}: {e}")).leak();
    let g = neuro_gguf::Gguf::open(bytes).expect("GGUF");
    let h = bind::hparams(&g, CTX).expect("hparams");
    let layers: &'static [_] = (0..h.dims.n_layers).map(|i| bind::layer(&g, &h, i).expect("layer")).collect::<Vec<_>>().leak();
    let rope: &'static [(i32, i32)] = neuro_build::rope_neox_table(CTX, h.dims.head_dim, f32::from_bits(h.rope_base) as f64).leak();
    let model = bind::model(&g, &h, layers, rope).expect("bind");
    model.check().expect("model check");
    let blob = tok_build::blob(&tok_build::from_gguf(&g).expect("tokenizer"), &tok_build::unicode_ranges(), &tok_build::nfc_tables()).expect("blob");
    let tok = Tokenizer::new(&blob).expect("tokenizer");
    let eog = [tok.added_id(b"<|im_end|>").expect("im_end"), tok.added_id(b"<|endoftext|>").expect("endoftext")];
    let preserved: Vec<u32> = PRESERVED_TOKENS.iter().map(|t| tok.added_id(t.as_bytes()).unwrap_or_else(|| panic!("{t} is not an added token"))).collect();
    let want_preserved: Vec<u32> = gen["server_grammar"]["preserved_tokens"].as_array().expect("preserved").iter().map(|x| x.as_u64().unwrap() as u32).collect();
    assert_eq!(preserved, want_preserved, "preserved token ids differ from the server's");
    let sd = simd();
    let d = model.dims;
    let vocab = d.vocab.min(tok.vocab());

    let (kvn, kvs) = d.kv_len();
    let (mut vals, mut shifts) = (vec![0i16; kvn], vec![0u8; kvs]);
    let (a, b, c, e) = Work::lens(&d, 8);
    let (mut wa, mut wb, mut wc, mut we) = (vec![0i64; a], vec![0i8; b], vec![(0, 0); c], vec![0i32; e]);
    let ids_of = |v: &Value| -> Vec<u32> { v.as_array().expect("ids").iter().map(|x| x.as_u64().expect("id") as u32).collect() };
    let top2 = |l: &[i64]| {
        let (mut x, mut y) = ((0u32, i64::MIN), (0u32, i64::MIN));
        for (i, &v) in l.iter().enumerate() {
            if v > x.1 {
                y = x;
                x = (i as u32, v);
            } else if v > y.1 {
                y = (i as u32, v);
            }
        }
        (x, y)
    };
    let (mut steps_total, mut near_ties, mut margin_max, mut margin_sum, mut margin_n) = (0usize, 0usize, 0f64, 0f64, 0usize);
    for v in gen["vectors"].as_array().expect("vectors") {
        let id = v["id"].as_str().expect("id");
        let cv = contract["test_vectors"]["vectors"].as_array().unwrap().iter().find(|c| c["id"] == v["id"]).unwrap_or_else(|| panic!("{id}: not in inv_contract.json"));
        assert_eq!(cv["request_body_sha256"], v["request_body_sha256"], "{id}: the two files describe different requests");
        let prompt = ids_of(&cv["prompt_token_ids"]);
        let want = ids_of(&v["generated_token_ids"]);
        let steps = v["steps"].as_array().expect("steps");
        assert_eq!(steps.len(), want.len());

        // Teacher-forced on the server's tokens.
        let mut w = Work::new(&d, 8, &mut wa, &mut wb, &mut wc, &mut we).expect("work");
        let mut kv = Kv { vals: &mut vals, shifts: &mut shifts };
        model.prefill(sd, &prompt, &mut kv, &mut w).unwrap_or_else(|e| panic!("{id}: prefill: {e:?}"));
        let mut col = (prompt.len() - 1) % 8;
        let mut m = ToolMachine::new();
        for (k, s) in steps.iter().enumerate() {
            let logits = &w.logits_of(col, d.vocab)[..vocab];
            let ((e1, v1), (_, v2)) = top2(logits);
            let t2 = s["top2"].as_array().expect("top2");
            let (r1, r1lp, r2lp) = (t2[0][0].as_u64().unwrap() as u32, t2[0][1].as_f64().unwrap(), t2[1][1].as_f64().unwrap());
            let (ref_gap, eng_gap) = (r1lp - r2lp, (v1 - v2) as f64 / Q16);
            let tie = ref_gap < TIE;
            near_ties += usize::from(tie);
            steps_total += 1;
            let sampled = s["id"].as_u64().unwrap() as u32;
            assert_eq!(sampled, want[k]);
            assert!(e1 == r1 || tie, "{id} step {k}: raw top-1 is {e1}, llama.cpp's is {r1} (its gap {ref_gap:.3} nats, not a near-tie)");
            let p = pick_tool(logits, &m, &tok, &eog, &preserved);
            assert!(p == Some(sampled) || tie, "{id} step {k}: the constrained choice is {p:?}, llama.cpp sampled {sampled} (gap {ref_gap:.3})");
            if e1 == r1 {
                let err = (eng_gap - ref_gap).abs();
                margin_max = margin_max.max(err);
                margin_sum += err;
                margin_n += 1;
            }
            if eog.contains(&sampled) {
                assert!(m.accepting(), "{id}: the server ended where the automaton cannot");
                break;
            }
            assert!(m.feed(tok.bytes(sampled as usize).expect("bytes")), "{id} step {k}: the automaton refuses the server's token {sampled}");
            model.forward(sd, &[sampled as usize], prompt.len() + k, &mut kv, &mut w, Head::All).unwrap_or_else(|e| panic!("{id}: forward: {e:?}"));
            col = 0;
        }

        // On its own.
        let mut w = Work::new(&d, 8, &mut wa, &mut wb, &mut wc, &mut we).expect("work");
        let mut kv = Kv { vals: &mut vals, shifts: &mut shifts };
        let mut out = vec![0u32; MAX_TOKENS as usize];
        let n = generate_tool(&model, sd, &tok, &prompt, &eog, &preserved, &mut kv, &mut w, MAX_TOKENS as usize, &mut out).unwrap_or_else(|e| panic!("{id}: generate: {e:?}"));
        assert_eq!(&out[..n], want.as_slice(), "{id}: the engine's own decoding differs from llama.cpp's");
        let mut txt = vec![0u8; 4096];
        let nt = tok.decode(&out[..n - 1], &mut txt).expect("decode");
        println!("{id}: {} prompt tokens, {n} generated, equal to llama.cpp: {:?}", prompt.len(), String::from_utf8_lossy(&txt[..nt]));
    }
    println!(
        "investigation decoding: {steps_total} teacher-forced steps, raw top-1 and constrained choice equal llama.cpp's on all ({near_ties} near-ties below {TIE} nats); top-2 margin error mean {:.4}, max {:.4} nats; free runs equal",
        margin_sum / margin_n.max(1) as f64,
        margin_max
    );
}
