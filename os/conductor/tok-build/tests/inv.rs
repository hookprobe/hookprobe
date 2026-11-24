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
