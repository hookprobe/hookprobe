// SPDX-License-Identifier: AGPL-3.0-only
//! Fidelity check: the heqk-native integer engine against llama.cpp on the SAME GGUF (Neuro's answers to the
//! Conductor, 2026-11-24, question 2). This is not an evaluation. Neuro owns quality. If the engine agrees with
//! llama.cpp, Neuro's quality results carry over; if it disagrees beyond a near-tie, that is an engine bug.
//!
//! It runs where the models are (the Neuro Mac), against a local llama-server Neuro already uses (`--reasoning
//! off`), and talks only to a loopback address: no model, case or answer leaves the machine.
//!
//! Per case (`triage` and `injection` cases of a SPENT set; other tasks are skipped):
//! 1. **Template.** The prompt is rendered from `neuro_contract` alone. It must equal llama-server's own
//!    rendering of the same messages (`/apply-template`).
//! 2. **Tokenizer.** The engine's token ids must equal llama-server's (`/tokenize`).
//! 3. **Reference.** llama-server decodes the same token ids greedily, under the same closed schema (`json_schema`
//!    = `neuro_contract::write_schema`), returning each chosen id and the raw top-2 log-probabilities
//!    (`post_sampling_probs: false`, so before the grammar).
//! 4. **Engine, teacher-forced on the reference tokens.** At every step:
//!    - the raw top-1 must agree with llama.cpp's unless llama.cpp's own top-2 gap is below `--tie` (a near-tie);
//!    - the engine's constrained choice (`neuro_lm::decode::pick`, the same automaton) must equal llama.cpp's
//!      token unless that step is a near-tie.
//! 5. **Free run** (`--free-run`): the engine decodes on its own (with its exact speed-ups) and must produce
//!    llama.cpp's token sequence, or diverge first at a near-tie.
//!
//! Guards before anything runs:
//! - the model file must match its line in `SHA256SUMS`;
//! - the case set must be one Neuro named as spent: dev v8 or blind v3–v6 (triage), inv-blind v1/v2. A sealed
//!   set is refused by its SHA-256.
//!
//! usage:
//!   fidelity --dir DIR --model FILE.gguf --set CASES.jsonl [--url http://127.0.0.1:8080] [--limit N]
//!            [--tie 0.5] [--free-run] [--packed] [--scalar] [--out REPORT.md]
//!
//! ftL (investigation turns) is not covered yet: its prompt is not in `neuro_contract`. Running it on the
//! triage framing would check only the numerics, so the tool refuses inv-blind sets for now and says so.
use neuro_contract::{context_ids, write_schema, write_system, write_user, Allowed, IdList, Lang, Machine, Out};
use neuro_gguf::{qwen3 as bind, Gguf};
use neuro_kernels::Simd;
use neuro_lm::decode::{generate_closed, pick, Options};
use neuro_lm::qwen3::{Kv, Model, Work};
use neuro_lm::tok::Tokenizer;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::io::{BufRead, Read, Write};
use std::time::Instant;

/// Sets Neuro allows (all spent: conductor-answers-2026-11-24.md, question 2). Anything else is refused.
const SPENT: [(&str, &str); 7] = [
    ("d0edb3538bc5703c2e1fbe899a91cb8c797f2d591eaf8b99d7e64374fc0f2e07", "dev v8 (triage, 320 cases)"),
    ("c30d52d284342c0375a9aa9c4b2033bf66cef624ac8386fdc63597618c543c46", "blind v3 (spent)"),
    ("d5f6011f13b428e67be9e9cbe585627a4a5af2538d9aada2668112eb7d336ca5", "blind v4 (spent)"),
    ("4c79a98f89094fa2c700a5acdeb6a7b1278251c03255e9e83b02c1e40c477ed7", "blind v5 (spent)"),
    ("8988df3aaeedf9b5c2f64cb4f9c0aef00bf9e73272744ed0d9e24f324f119e5a", "blind v6 (spent)"),
    ("c49f06c94f75b74e453d6943d6605ede8cd5b0ae6e79d41317cc156d8cb68ade", "inv-blind v1 (investigation)"),
    ("c61231c589b6744b61321a6bf1628c5977b2387001031403f12edf8ce6707a92", "inv-blind v2 (investigation)"),
];
const CTX: usize = 4096;
const Q16: f64 = 65536.0;
/// Largest llama-server response accepted (a completion with ten candidates per step is well under 1 MiB).
const MAX_RESPONSE: usize = 16 << 20;

struct Args {
    dir: String,
    model: String,
    set: String,
    url: String,
    limit: usize,
    /// `(k, n)`: check only the cases whose index among the triage and injection cases is `k` modulo `n`.
    shard: (usize, usize),
    tie: f64,
    free_run: bool,
    packed: bool,
    scalar: bool,
    out: Option<String>,
    max_tokens: usize,
    /// Check only these case ids, and print every disagreeing step with both sides' candidates.
    cases: Vec<String>,
}

fn args() -> Args {
    let mut a = Args { dir: String::new(), model: String::new(), set: String::new(), url: "http://127.0.0.1:8080".into(), limit: usize::MAX, shard: (0, 1), tie: 0.5, free_run: false, packed: false, scalar: false, out: None, max_tokens: 700, cases: vec![] };
    let mut it = std::env::args().skip(1);
    while let Some(k) = it.next() {
        let mut v = || it.next().unwrap_or_else(|| die(&format!("{k} needs a value")));
        match k.as_str() {
            "--dir" => a.dir = v(),
            "--model" => a.model = v(),
            "--set" => a.set = v(),
            "--url" => a.url = v(),
            "--limit" => a.limit = v().parse().unwrap_or_else(|_| die("--limit: a number")),
            "--shard" => {
                let s = v();
                let p = s.split_once('/').and_then(|(k, n)| Some((k.parse::<usize>().ok()?, n.parse::<usize>().ok()?)));
                a.shard = p.filter(|&(k, n)| n > 0 && k < n).unwrap_or_else(|| die("--shard: K/N with K < N"));
            }
            "--tie" => a.tie = v().parse().unwrap_or_else(|_| die("--tie: a number")),
            "--max-tokens" => a.max_tokens = v().parse().unwrap_or_else(|_| die("--max-tokens: a number")),
            "--out" => a.out = Some(v()),
            "--case" => a.cases.push(v()),
            "--free-run" => a.free_run = true,
            "--packed" => a.packed = true,
            "--scalar" => a.scalar = true,
            _ => die(&format!("unknown argument {k}; see the usage at the top of fidelity.rs")),
        }
    }
    if a.dir.is_empty() || a.model.is_empty() || a.set.is_empty() {
        die("usage: fidelity --dir DIR --model FILE.gguf --set CASES.jsonl [--url http://127.0.0.1:8080] [--limit N] [--shard K/N] [--case ID]... [--tie 0.5] [--free-run] [--packed] [--scalar] [--out REPORT.md]");
    }
    a
}

fn die(m: &str) -> ! {
    eprintln!("fidelity: {m}");
    std::process::exit(2)
}

fn sha256_file(p: &std::path::Path) -> String {
    let mut f = std::fs::File::open(p).unwrap_or_else(|e| die(&format!("open {}: {e}", p.display())));
    let mut h = Sha256::new();
    let mut buf = vec![0u8; 1 << 20];
    loop {
        let n = f.read(&mut buf).unwrap_or_else(|e| die(&format!("read {}: {e}", p.display())));
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
    }
    h.finalize().iter().map(|b| format!("{b:02x}")).collect()
}

// ------------------------------------------------------------------ llama-server over loopback HTTP

struct Server {
    host: String,
    port: u16,
}

impl Server {
    fn new(url: &str) -> Self {
        let rest = url.strip_prefix("http://").unwrap_or_else(|| die("--url must be http://<loopback>:<port>"));
        let hp = rest.split('/').next().unwrap_or("");
        let (host, port) = hp.rsplit_once(':').unwrap_or((hp, "80"));
        let port: u16 = port.parse().unwrap_or_else(|_| die("--url: bad port"));
        // Loopback only: nothing about the cases or the answers may leave this machine.
        let ok = std::net::ToSocketAddrs::to_socket_addrs(&(host, port)).map(|mut a| a.all(|x| x.ip().is_loopback())).unwrap_or(false);
        if !ok {
            die("--url must resolve to a loopback address only (127.0.0.1 / localhost)");
        }
        Self { host: host.to_string(), port }
    }

    fn post(&self, path: &str, body: &Value) -> Value {
        self.post_bytes(path, &serde_json::to_vec(body).expect("json"))
    }

    /// As `post`, with the body already serialised. Used where the byte order of the body matters.
    fn post_bytes(&self, path: &str, b: &[u8]) -> Value {
        let mut s = std::net::TcpStream::connect((self.host.as_str(), self.port)).unwrap_or_else(|e| die(&format!("connect to llama-server: {e}")));
        let head = format!("POST {path} HTTP/1.1\r\nHost: {}:{}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", self.host, self.port, b.len());
        s.write_all(head.as_bytes()).and_then(|_| s.write_all(b)).unwrap_or_else(|e| die(&format!("send {path}: {e}")));
        let mut r = std::io::BufReader::new(s);
        let mut status = String::new();
        r.read_line(&mut status).unwrap_or_else(|e| die(&format!("read {path}: {e}")));
        let (mut len, mut chunked) = (None, false);
        loop {
            let mut l = String::new();
            r.read_line(&mut l).unwrap_or_else(|e| die(&format!("read {path}: {e}")));
            let l = l.trim_end();
            if l.is_empty() {
                break;
            }
            let lower = l.to_ascii_lowercase();
            if let Some(v) = lower.strip_prefix("content-length:") {
                len = v.trim().parse::<usize>().ok();
            }
            if lower.starts_with("transfer-encoding:") && lower.contains("chunked") {
                chunked = true;
            }
        }
        let mut data = vec![];
        if chunked {
            loop {
                let mut l = String::new();
                r.read_line(&mut l).unwrap_or_else(|e| die(&format!("read {path}: {e}")));
                let n = usize::from_str_radix(l.trim().split(';').next().unwrap_or("0"), 16).unwrap_or(0);
                if n == 0 {
                    break;
                }
                if n > MAX_RESPONSE - data.len() {
                    die(&format!("{path}: the response is larger than {MAX_RESPONSE} bytes"));
                }
                let mut c = vec![0u8; n + 2];
                r.read_exact(&mut c).unwrap_or_else(|e| die(&format!("read {path}: {e}")));
                data.extend_from_slice(&c[..n]);
            }
        } else if let Some(n) = len {
            if n > MAX_RESPONSE {
                die(&format!("{path}: the response is larger than {MAX_RESPONSE} bytes"));
            }
            data.resize(n, 0);
            r.read_exact(&mut data).unwrap_or_else(|e| die(&format!("read {path}: {e}")));
        } else {
            r.take(MAX_RESPONSE as u64 + 1).read_to_end(&mut data).unwrap_or_else(|e| die(&format!("read {path}: {e}")));
            if data.len() > MAX_RESPONSE {
                die(&format!("{path}: the response is larger than {MAX_RESPONSE} bytes"));
            }
        }
        if !status.contains(" 200") {
            die(&format!("{path}: {} {}", status.trim(), String::from_utf8_lossy(&data)));
        }
        // The peer is the loopback llama-server this tool was pointed at (`--url` is refused unless it resolves to
        // loopback). Its reply is bounded above and parsed into an untyped `Value` only: no type is built from it,
        // and every field is read through checked accessors.
        let v: Value = serde_json::from_slice(&data).unwrap_or_else(|e| die(&format!("{path}: not JSON: {e}")));
        if !v.is_object() && !v.is_array() {
            die(&format!("{path}: the response is not a JSON object or array"));
        }
        v
    }
}

/// One generated step as llama-server reports it.
struct RefStep {
    id: u32,
    /// Raw (pre-grammar) top-2: (id, logprob).
    top: Vec<(u32, f64)>,
}

fn ref_steps(resp: &Value) -> Vec<RefStep> {
    let probs = resp["completion_probabilities"].as_array().unwrap_or_else(|| die("/completion returned no completion_probabilities; this needs a llama.cpp build with n_probs token ids (Neuro's b12477 has them)"));
    probs
        .iter()
        .map(|p| {
            let id = p["id"].as_u64().unwrap_or_else(|| die("completion_probabilities without token ids: use a newer llama-server")) as u32;
            let top = p["top_logprobs"]
                .as_array()
                .unwrap_or_else(|| die("completion_probabilities without top_logprobs"))
                .iter()
                .map(|t| (t["id"].as_u64().unwrap_or(u64::MAX) as u32, t["logprob"].as_f64().unwrap_or(f64::NAN)))
                .collect();
            RefStep { id, top }
        })
        .collect()
}

// ------------------------------------------------------------------ the engine

fn simd(scalar: bool) -> Simd {
    #[cfg(all(target_arch = "aarch64", target_feature = "neon"))]
    if !scalar && std::arch::is_aarch64_feature_detected!("dotprod") {
        // SAFETY: the CPU reports AdvSIMD (compile-time target feature) and DotProd (runtime check above), and
        // FP/SIMD is always enabled for a user process on the host OS.
        return unsafe { Simd::neon_dot() };
    }
    let _ = scalar;
    Simd::SCALAR
}

/// Top two raw logits: (id, value), (id, value).
fn top2(l: &[i64]) -> ((u32, i64), (u32, i64)) {
    let (mut a, mut b) = ((0u32, i64::MIN), (0u32, i64::MIN));
    for (i, &v) in l.iter().enumerate() {
        if v > a.1 {
            b = a;
            a = (i as u32, v);
        } else if v > b.1 {
            b = (i as u32, v);
        }
    }
    (a, b)
}

#[derive(Default)]
struct Tally {
    cases: usize,
    skipped: usize,
    steps: usize,
    raw_top1_agree: usize,
    raw_top1_tie: usize,
    raw_top1_bug: usize,
    pick_agree: usize,
    pick_tie: usize,
    pick_bug: usize,
    margin_abs_err_sum: f64,
    margin_abs_err_max: f64,
    template_mismatch: usize,
    tokenizer_mismatch: usize,
    free_equal: usize,
    free_tie: usize,
    free_bug: usize,
}

fn main() {
    let a = args();
    let dir = std::path::Path::new(&a.dir);
    let model_path = dir.join(&a.model);

    // Guard 1: the model matches SHA256SUMS.
    let sums = std::fs::read_to_string(dir.join("SHA256SUMS")).unwrap_or_else(|e| die(&format!("{}/SHA256SUMS: {e}", a.dir)));
    let want = sums
        .lines()
        .find_map(|l| {
            let (h, n) = l.split_once(char::is_whitespace)?;
            (n.trim().trim_start_matches('*') == a.model).then(|| h.to_ascii_lowercase())
        })
        .unwrap_or_else(|| die(&format!("{} is not listed in SHA256SUMS", a.model)));
    eprintln!("checking {} against SHA256SUMS ...", a.model);
    let got = sha256_file(&model_path);
    if got != want {
        die(&format!("{}: SHA-256 {got} does not match SHA256SUMS {want}", a.model));
    }
    // Guard 2: a spent set only.
    let set_sha = sha256_file(std::path::Path::new(&a.set));
    let Some((_, set_name)) = SPENT.iter().find(|(h, _)| *h == set_sha) else {
        die(&format!("{}: SHA-256 {set_sha} is not a set Neuro named as spent (dev v8, blind v3–v6, inv-blind v1/v2). Sealed sets are never used.", a.set));
    };
    if set_name.starts_with("inv-blind") {
        die("inv-blind (ftL investigation turns) is not covered yet: the investigation prompt is not in neuro_contract. Use dev v8 with ftFg.");
    }
    let srv = Server::new(&a.url);

    // The engine.
    let t0 = Instant::now();
    let bytes: &'static [u8] = std::fs::read(&model_path).unwrap_or_else(|e| die(&format!("read model: {e}"))).leak();
    let g = Gguf::open(bytes).unwrap_or_else(|e| die(&format!("GGUF: {e:?}")));
    let h = bind::hparams(&g, CTX).unwrap_or_else(|e| die(&format!("hparams: {e:?}")));
    let layers: &'static [_] = (0..h.dims.n_layers).map(|i| bind::layer(&g, &h, i).expect("layer")).collect::<Vec<_>>().leak();
    let rope: &'static [(i32, i32)] = neuro_build::rope_neox_table(CTX, h.dims.head_dim, f32::from_bits(h.rope_base) as f64).leak();
    let gm = bind::model(&g, &h, layers, rope).unwrap_or_else(|e| die(&format!("bind: {e:?}")));
    let model: Model<'static> = if a.packed {
        let pk = |m: &neuro_lm::qwen3::Mat<'static>| m.pack_into(vec![0u8; neuro_kernels::q8::packed_bytes(m.rows, m.cols)].leak()).expect("pack");
        let pl: Vec<_> = layers.iter().map(|l| neuro_lm::qwen3::Layer { wq: pk(&l.wq), wk: pk(&l.wk), wv: pk(&l.wv), wo: pk(&l.wo), w_gate: pk(&l.w_gate), w_up: pk(&l.w_up), w_down: pk(&l.w_down), ..*l }).collect();
        Model { embed: pk(&gm.embed), layers: pl.leak(), ..gm }
    } else {
        gm
    };
    model.check().unwrap_or_else(|e| die(&format!("model check: {e:?}")));
    let tb = tok_build::blob(&tok_build::from_gguf(&g).expect("tokenizer"), &tok_build::unicode_ranges(), &tok_build::nfc_tables()).expect("blob");
    let tok = Tokenizer::new(&tb).expect("tokenizer");
    let eog = [tok.added_id(b"<|im_end|>").expect("im_end"), tok.added_id(b"<|endoftext|>").expect("endoftext")];
    let sd = simd(a.scalar);
    let d = model.dims;
    eprintln!("engine ready in {:?}: {} layers, vocab {}, {} layout, {}", t0.elapsed(), d.n_layers, d.vocab, if a.packed { "packed" } else { "GGUF" }, sd.name());

    let (kvn, kvs) = d.kv_len();
    let (mut vals, mut shifts) = (vec![0i16; kvn], vec![0u8; kvs]);
    let (wa_n, wb_n, wc_n, we_n) = Work::lens(&d, 8);
    let (mut wa, mut wb, mut wc, mut we) = (vec![0i64; wa_n], vec![0i8; wb_n], vec![(0, 0); wc_n], vec![0i32; we_n]);
    let mut t = Tally::default();
    let mut lines_out: Vec<String> = vec![];
    let mut eligible = 0usize;

    let set = std::fs::read_to_string(&a.set).unwrap_or_else(|e| die(&format!("read set: {e}")));
    for line in set.lines().filter(|l| !l.trim().is_empty()) {
        if t.cases >= a.limit {
            break;
        }
        let c: Value = serde_json::from_str(line).unwrap_or_else(|e| die(&format!("set line: {e}")));
        let task = c["task"].as_str().unwrap_or("");
        if task != "triage" && task != "injection" {
            t.skipped += 1;
            continue;
        }
        let nth = eligible;
        eligible += 1;
        if nth % a.shard.1 != a.shard.0 {
            continue;
        }
        if !a.cases.is_empty() && !a.cases.iter().any(|x| Some(x.as_str()) == c["id"].as_str()) {
            continue;
        }
        let id = c["id"].as_str().unwrap_or("?").to_string();
        let lang = if c["lang"].as_str() == Some("ro") { Lang::Ro } else { Lang::En };
        let (ctx, q) = (c["context"].as_str().unwrap_or(""), c["question"].as_str().unwrap_or(""));

        // The prompt from the contract.
        let (mut facts, mut ents) = (IdList::new(), IdList::new());
        context_ids(ctx.as_bytes(), &mut facts, &mut ents).unwrap_or_else(|e| die(&format!("{id}: ids: {e:?}")));
        let mut sys = vec![0u8; 16384];
        let mut o = Out::new(&mut sys);
        write_system(lang, &facts, &ents, true, &mut o).expect("system");
        let ns = o.n;
        let mut usr = vec![0u8; 16384];
        let mut o = Out::new(&mut usr);
        write_user(ctx.as_bytes(), q.as_bytes(), &mut o).expect("user");
        let nu = o.n;
        let mut sch = vec![0u8; 16384];
        let mut o = Out::new(&mut sch);
        write_schema(&facts, &ents, true, &mut o).expect("schema");
        let nsch = o.n;
        let (sys_s, usr_s) = (String::from_utf8_lossy(&sys[..ns]).into_owned(), String::from_utf8_lossy(&usr[..nu]).into_owned());
        let text = format!("<|im_start|>system\n{sys_s}<|im_end|>\n<|im_start|>user\n{usr_s}<|im_end|>\n<|im_start|>assistant\n<think>\n\n</think>\n\n");

        // 1. Template: llama-server's rendering of the same messages.
        let tpl = srv.post("/apply-template", &json!({"messages": [{"role": "system", "content": sys_s}, {"role": "user", "content": usr_s}]}));
        let tpl_ok = tpl["prompt"].as_str() == Some(text.as_str());
        t.template_mismatch += usize::from(!tpl_ok);

        // 2. Tokenizer.
        let mut ids = vec![0u32; 16384];
        let (mut cps, mut buf) = (vec![0u32; 1 << 17], vec![0u8; 1 << 17]);
        let np = tok.encode_nfc(text.as_bytes(), &mut ids, &mut cps, &mut buf).unwrap_or_else(|e| die(&format!("{id}: encode: {e:?}")));
        let prompt: Vec<u32> = ids[..np].to_vec();
        let st = srv.post("/tokenize", &json!({"content": text, "add_special": false, "parse_special": true}));
        let theirs: Vec<u32> = st["tokens"].as_array().map(|v| v.iter().filter_map(|x| x.as_u64().map(|x| x as u32)).collect()).unwrap_or_default();
        let tok_ok = theirs == prompt;
        t.tokenizer_mismatch += usize::from(!tok_ok);

        // 3. Reference: the same ids, the same closed schema, greedy, raw top-2.
        // The schema goes out byte for byte as the contract wrote it. llama-server emits the object's keys in the
        // schema's property order, and a `serde_json::Value` round trip would sort them alphabetically.
        let _: Value = serde_json::from_slice(&sch[..nsch]).unwrap_or_else(|e| die(&format!("{id}: schema JSON: {e}")));
        let mut body = serde_json::to_vec(&json!({"prompt": prompt, "n_predict": a.max_tokens, "temperature": 0.0, "top_k": 1, "n_probs": if a.cases.is_empty() { 2 } else { 10 }, "post_sampling_probs": false, "cache_prompt": false})).expect("json");
        body.pop();
        body.extend_from_slice(b",\"json_schema\":");
        body.extend_from_slice(&sch[..nsch]);
        body.push(b'}');
        let resp = srv.post_bytes("/completion", &body);
        let steps = ref_steps(&resp);

        // 4. Engine, teacher-forced on the reference tokens.
        let mut w = Work::new(&d, 8, &mut wa, &mut wb, &mut wc, &mut we).expect("work");
        let mut kv = Kv { vals: &mut vals, shifts: &mut shifts };
        model.prefill(sd, &prompt, &mut kv, &mut w).unwrap_or_else(|e| die(&format!("{id}: prefill: {e:?}")));
        let mut col = (np - 1) % 8;
        let mut m = Machine::new(Allowed { facts: &facts, entities: &ents, closed: true });
        let (mut first_bug, mut case_bugs) = (None, 0usize);
        for (k, s) in steps.iter().enumerate() {
            let logits = w.logits_of(col, d.vocab);
            let ((e1, v1), (_, v2)) = top2(&logits[..d.vocab.min(tok.vocab())]);
            let (r1, r1lp) = s.top.first().copied().unwrap_or((u32::MAX, f64::NAN));
            let r2lp = s.top.get(1).map_or(f64::NAN, |x| x.1);
            let ref_gap = r1lp - r2lp;
            let eng_gap = (v1 - v2) as f64 / Q16;
            let tie = ref_gap.is_finite() && ref_gap < a.tie;
            t.steps += 1;
            if e1 == r1 {
                t.raw_top1_agree += 1;
                let err = (eng_gap - ref_gap).abs();
                if err.is_finite() {
                    t.margin_abs_err_sum += err;
                    t.margin_abs_err_max = t.margin_abs_err_max.max(err);
                }
            } else if tie {
                t.raw_top1_tie += 1;
            } else {
                t.raw_top1_bug += 1;
                case_bugs += 1;
                first_bug.get_or_insert(k);
            }
            let p = pick(&logits[..d.vocab.min(tok.vocab())], &m, &tok, &eog);
            if p == Some(s.id) {
                t.pick_agree += 1;
            } else if tie {
                t.pick_tie += 1;
            } else {
                t.pick_bug += 1;
                case_bugs += 1;
                first_bug.get_or_insert(k);
            }
            if !a.cases.is_empty() && (e1 != r1 || p != Some(s.id)) {
                let show = |i: u32| format!("{i} {:?}", String::from_utf8_lossy(tok.bytes(i as usize).unwrap_or(&[])));
                let lg = |i: u32| logits.get(i as usize).map_or(f64::NAN, |&x| (x - v1) as f64 / Q16);
                eprintln!("step {k}: {}", if tie { "near-tie" } else { "BEYOND a near-tie" });
                let before: String = steps[k.saturating_sub(8)..k].iter().map(|x| String::from_utf8_lossy(tok.bytes(x.id as usize).unwrap_or(&[])).into_owned()).collect::<Vec<_>>().join("|");
                eprintln!("  after {before:?}");
                eprintln!("  llama.cpp chose {} (engine logit {:+.4} relative to its raw top-1)", show(s.id), lg(s.id));
                match p {
                    Some(p) => eprintln!("  engine chose    {} (engine logit {:+.4})", show(p), lg(p)),
                    None => eprintln!("  engine chose    nothing (no allowed token)"),
                }
                eprintln!("  engine raw top-1 {}; llama.cpp raw candidates (logprob, engine logit relative to its top-1, allowed by the automaton next):", show(e1));
                for &(i, lp) in &s.top {
                    let mut m2 = m;
                    eprintln!("    {:+.4}  {:+.4}  {}  {}", lp, lg(i), if m2.feed(tok.bytes(i as usize).unwrap_or(&[])) { "allowed" } else { "refused" }, show(i));
                }
            }
            if eog.contains(&s.id) || k + 1 == steps.len() {
                break;
            }
            if !m.feed(tok.bytes(s.id as usize).unwrap_or(&[])) {
                die(&format!("{id}: llama.cpp's token {} at step {k} is not allowed by the contract automaton (grammar mismatch)", s.id));
            }
            model.step(sd, s.id as usize, np + k, &mut kv, &mut w).unwrap_or_else(|e| die(&format!("{id}: step: {e:?}")));
            col = 0;
        }

        // 5. Free run.
        let mut free = String::new();
        if a.free_run {
            let mut w = Work::new(&d, 8, &mut wa, &mut wb, &mut wc, &mut we).expect("work");
            let mut kv = Kv { vals: &mut vals, shifts: &mut shifts };
            let opts = Options { prune_max: 8192, draft_max: 7, max_new: a.max_tokens };
            let mut hist = vec![0u32; np + opts.max_new];
            let mut list = vec![0u32; opts.prune_max];
            let mut out = vec![0u32; opts.max_new];
            let m = Machine::new(Allowed { facts: &facts, entities: &ents, closed: true });
            let (n, _) = generate_closed(&model, sd, &tok, &prompt, &eog, m, &mut kv, &mut w, &mut hist, &mut list, opts, &mut out).unwrap_or_else(|e| die(&format!("{id}: generate: {e:?}")));
            let ref_ids: Vec<u32> = steps.iter().map(|s| s.id).collect();
            let div = out[..n].iter().zip(&ref_ids).position(|(x, y)| x != y).or((n != ref_ids.len()).then_some(n.min(ref_ids.len())));
            free = match div {
                None => {
                    t.free_equal += 1;
                    "equal".into()
                }
                Some(k) if steps.get(k).is_some_and(|s| s.top.len() > 1 && s.top[0].1 - s.top[1].1 < a.tie) => {
                    t.free_tie += 1;
                    format!("diverges at step {k} (near-tie)")
                }
                Some(k) => {
                    t.free_bug += 1;
                    format!("DIVERGES at step {k}")
                }
            };
        }
        t.cases += 1;
        let row = format!(
            "| {id} | {np} | {} | {} | {} | {} | {} |",
            steps.len(),
            if tpl_ok { "ok" } else { "MISMATCH" },
            if tok_ok { "ok" } else { "MISMATCH" },
            match first_bug { None => "ok".to_string(), Some(k) => format!("{case_bugs} bug step(s), first at {k}") },
            if free.is_empty() { "-".to_string() } else { free }
        );
        eprintln!("{row}");
        lines_out.push(row);
    }

    let pct = |x: usize, n: usize| 100.0 * x as f64 / n.max(1) as f64;
    let mut rep = String::new();
    rep += "# Fidelity: heqk-native integer engine vs llama.cpp (same GGUF)\n\n";
    rep += &format!("- model: `{}` (SHA-256 `{}`, matches SHA256SUMS)\n- set: {set_name} (`{}…`), {} cases checked, {} skipped (not triage or injection)\n", a.model, got, &set_sha[..8], t.cases, t.skipped);
    rep += &format!("- engine: {} layout, {}; reference: llama-server at {} (greedy, closed schema, raw top-2)\n- near-tie threshold: llama.cpp top-2 log-prob gap < {}\n\n", if a.packed { "packed" } else { "GGUF" }, sd.name(), a.url, a.tie);
    if a.shard.1 > 1 {
        rep += &format!("- shard: {} of {} (cases whose index among the checked task types is {} modulo {})\n\n", a.shard.0 + 1, a.shard.1, a.shard.0, a.shard.1);
    }
    rep += "| Check | Result |\n|---|---|\n";
    rep += &format!("| Chat template equals llama-server's | {} of {} |\n", t.cases - t.template_mismatch, t.cases);
    rep += &format!("| Token ids equal llama-server's | {} of {} |\n", t.cases - t.tokenizer_mismatch, t.cases);
    rep += &format!("| Raw top-1 agrees (teacher-forced) | {:.2}% of {} steps; {} near-ties; **{} disagreements beyond a near-tie** |\n", pct(t.raw_top1_agree, t.steps), t.steps, t.raw_top1_tie, t.raw_top1_bug);
    rep += &format!("| Constrained choice equals llama.cpp's token | {:.2}%; {} near-ties; **{} beyond a near-tie** |\n", pct(t.pick_agree, t.steps), t.pick_tie, t.pick_bug);
    rep += &format!("| Top-2 margin, engine vs llama.cpp (nats), where top-1 agrees | mean abs err {:.4}, max {:.4} |\n", t.margin_abs_err_sum / t.raw_top1_agree.max(1) as f64, t.margin_abs_err_max);
    if a.free_run {
        rep += &format!("| Free run equals llama.cpp's tokens | {} equal, {} diverge at a near-tie, **{} diverge otherwise** |\n", t.free_equal, t.free_tie, t.free_bug);
    }
    let verdict = t.template_mismatch == 0 && t.tokenizer_mismatch == 0 && t.raw_top1_bug == 0 && t.pick_bug == 0 && t.free_bug == 0;
    rep += &format!("\n**Verdict: {}.** Disagreements only at near-ties are expected (8-bit activations differ at the 10⁻³ level between implementations); anything beyond is an engine bug to report.\n\n", if verdict { "FAITHFUL" } else { "NOT FAITHFUL: see the rows marked below" });
    rep += "| Case | Prompt tokens | Steps | Template | Tokenizer | Teacher-forced | Free run |\n|---|---|---|---|---|---|---|\n";
    for l in &lines_out {
        rep += l;
        rep += "\n";
    }
    match &a.out {
        Some(p) => std::fs::write(p, &rep).unwrap_or_else(|e| die(&format!("write {p}: {e}"))),
        None => print!("{rep}"),
    }
    eprintln!("verdict: {}", if verdict { "FAITHFUL" } else { "NOT FAITHFUL" });
    std::process::exit(if verdict { 0 } else { 1 });
}
