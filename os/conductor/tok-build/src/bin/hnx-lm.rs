// SPDX-License-Identifier: AGPL-3.0-only
//! A language model through the device's one load path, on the build host.
//!
//! `pack`: wrap a GGUF file as a signed HNX container with the manifest admission reads. By default the payload is
//!         a bundle (kind `LM_BUNDLE`): the model with its tokenizer tables and RoPE table, made here once, so the
//!         device derives nothing. `--bare` stores the GGUF file alone (kind `GGUF_LM`).
//! `run`:  what a heqk server does with that file: open and verify the header and signature, reserve exactly the
//!         payload, read each segment straight into its place and verify it there, check the manifest against the
//!         file, bind the integer engine, answer one question. No other runtime is involved.
//!
//! Usage:
//!   hnx-lm pack --gguf MODEL.gguf --out MODEL.hnx --key SEED.hex --eval REPORT [--ctx 2048] [--licence Apache-2.0] [--svn 1] [--packed | --bare]
//!         `--packed` stores the matrices in the packed layout (the form a device runs fastest, with no packing at load).
//!   hnx-lm run  --hnx MODEL.hnx --pub PUBKEY.hex --ask "question" [--max-new 64] [--scalar] [--packed] [--batch 16]
//!   hnx-lm triage --hnx MODEL.hnx --pub PUBKEY.hex --context WINDOW.txt [--then WINDOW2.txt]... [--max-new 700] [--drafts] [--no-reuse]
//!
//!   hnx-lm job --hnx MODEL.hnx --pub PUBKEY.hex [--l0 benign|suspicious|malicious] [--fact "TEXT"]... [--jobs 2]
//!
//! `job` is the whole Conductor path around the engine, on this host: the device harness builds the request from
//! the job's evidence, the (mock) kernel signs a capability, the worker (`conductor-worker`) checks it, makes its
//! replay mark durable and runs the engine through `conductor-p0`, signs the result, and the device's verifier
//! judges the answer. The model named by the capability is taken to be the one in the file.
//!
//! `triage` is one explainer job as the device runs it: the window's context (as `neuro_contract::cards` writes it),
//! guard A, Neuro's contract prompt, an answer decoded under the contract one pass at a time, read back and checked.
//!
//! A bundle in the GGUF layout runs as a P0 session (`neuro_gguf::p0`): one forward pass per call, in memory
//! sized by `p0::sizes`, as a worker core would drive it. The time of every pass is reported.
//!
//! `SEED.hex` is a 32-byte Ed25519 seed in hex (a build-host test key here; release signing is an operator step).
//! With a bundle, `run` uses no build-host helper: the tokenizer and the RoPE table come from the verified payload.
//! With a bare GGUF payload they are built here from the file, which a device cannot do.
use neuro_gguf::hnx::{admit, manifest_for, manifest_for_bundle};
use neuro_gguf::qwen3 as bind;
use neuro_hnx::{build_prefix, kind, scheme, target, Header, Loader, Platform, HEADER_LEN, LEAF_LEN, MAX_SIG};
use neuro_kernels::Simd;
use neuro_lm::qwen3::{Kv, Layer, Mat, Model, Work, MAX_BATCH};
use neuro_lm::tok::Tokenizer;
use sha2::{Digest, Sha256};
use std::io::{Read, Write};
use std::time::Instant;

fn die(m: &str) -> ! {
    eprintln!("hnx-lm: {m}");
    std::process::exit(2)
}

fn arg(args: &[String], name: &str) -> Option<String> {
    args.iter().position(|a| a == name).and_then(|i| args.get(i + 1)).cloned()
}

fn need(args: &[String], name: &str) -> String {
    arg(args, name).unwrap_or_else(|| die(&format!("{name} is required; see the usage at the top of hnx-lm.rs")))
}

fn hex32(path: &str) -> [u8; 32] {
    let t = std::fs::read_to_string(path).unwrap_or_else(|e| die(&format!("read {path}: {e}")));
    let t = t.trim();
    if t.len() != 64 {
        die(&format!("{path}: 64 hex characters expected"));
    }
    let mut out = [0u8; 32];
    for (i, b) in out.iter_mut().enumerate() {
        *b = u8::from_str_radix(&t[2 * i..2 * i + 2], 16).unwrap_or_else(|_| die(&format!("{path}: not hex")));
    }
    out
}

fn sha(b: &[u8]) -> [u8; 32] {
    Sha256::digest(b).into()
}

const SEG_LOG2: u8 = 21; // 2 MiB: one AArch64 block mapping per segment

fn pack(args: &[String]) {
    let file = std::fs::read(need(args, "--gguf")).unwrap_or_else(|e| die(&format!("read the model: {e}")));
    let ctx: usize = arg(args, "--ctx").map_or(2048, |v| v.parse().unwrap_or_else(|_| die("--ctx")));
    let seed = hex32(&need(args, "--key"));
    let eval = std::fs::read(need(args, "--eval")).unwrap_or_else(|e| die(&format!("read the evaluation report: {e}")));
    let spdx = arg(args, "--licence").unwrap_or_else(|| "Apache-2.0".into());
    let mut licence = [0u8; 32];
    if spdx.is_empty() || spdx.len() > 32 {
        die("--licence: 1 to 32 bytes");
    }
    licence[..spdx.len()].copy_from_slice(spdx.as_bytes());
    let source = sha(&file);
    // The payload: the file alone, or the bundle with the tables a device cannot derive.
    let bare = args.iter().any(|a| a == "--bare");
    let payload = if bare {
        file.clone()
    } else {
        let g = neuro_gguf::Gguf::open(&file).unwrap_or_else(|e| die(&format!("GGUF: {e:?}")));
        let hp = bind::hparams(&g, ctx).unwrap_or_else(|e| die(&format!("this file is not a model the engine binds: {e:?}")));
        let tok = tok_build::blob(&tok_build::from_gguf(&g).unwrap_or_else(|e| die(&e)), &tok_build::unicode_ranges(), &tok_build::nfc_tables()).unwrap_or_else(|e| die(&format!("tokenizer: {e:?}")));
        let rope: Vec<u8> = neuro_build::rope_neox_table(ctx, hp.dims.head_dim, f32::from_bits(hp.rope_base) as f64).iter().flat_map(|(c, s)| [c.to_le_bytes(), s.to_le_bytes()].concat()).collect();
        // `--packed`: the matrices are stored in the packed layout and the file keeps only metadata and norms.
        let (packed, model_file) = if args.iter().any(|a| a == "--packed") { tok_build::packed_parts(&g, &hp).unwrap_or_else(|e| die(&e)) } else { (vec![], file.clone()) };
        let b = tok_build::bundle([&model_file[..], &tok[..], &rope[..], &packed[..]]).unwrap_or_else(|| die("bundle layout"));
        println!("bundle: model file {} bytes, tokenizer tables {} bytes, RoPE table {} bytes, packed matrices {} bytes", model_file.len(), tok.len(), rope.len(), packed.len());
        b
    };
    let mut model_id = [0u8; 16];
    model_id.copy_from_slice(&source[..16]);
    let mut h = Header {
        target: target::GENERIC_INT,
        scheme: scheme::ED25519,
        engine_abi: 1,
        segment_log2: SEG_LOG2,
        n_segments: 0,
        model_id,
        model_svn: arg(args, "--svn").map_or(1, |v| v.parse().unwrap_or_else(|_| die("--svn"))),
        manifest: if bare { manifest_for(&payload, ctx) } else { manifest_for_bundle(&payload, ctx) }.unwrap_or_else(|e| die(&format!("this file is not a model the engine binds: {e:?}"))),
        licence,
        source_sha256: source,
        eval_sha256: sha(&eval),
        merkle_root: [0; 32],
        payload_kind: if bare { kind::GGUF_LM } else { kind::LM_BUNDLE },
    };
    let mut prefix = vec![0u8; HEADER_LEN + payload.len().div_ceil(1 << SEG_LOG2) * LEAF_LEN + 2 + 64];
    let kp = ed25519_compact::KeyPair::from_seed(ed25519_compact::Seed::new(seed));
    let n = build_prefix(&mut h, &payload, &mut prefix, |d| {
        let mut out = [0u8; MAX_SIG];
        out[..64].copy_from_slice(kp.sk.sign(d, None).as_ref());
        Some((out, 64))
    })
    .unwrap_or_else(|| die("could not build the container"));
    let out_path = need(args, "--out");
    let mut out = std::fs::File::create(&out_path).unwrap_or_else(|e| die(&format!("create {out_path}: {e}")));
    out.write_all(&prefix[..n]).and_then(|()| out.write_all(&payload)).unwrap_or_else(|e| die(&format!("write {out_path}: {e}")));
    let m = h.manifest;
    println!("packed {out_path}: {} segments of 2 MiB, prefix {n} bytes, payload {} bytes", h.n_segments, m.payload_bytes);
    println!("manifest: context {}, KV state {} bytes, arena {} bytes, {} tensor bytes per token at most", m.max_context, m.state_bytes_per_session, m.arena_bytes, m.bytes_per_token);
    println!("public key: {}", kp.pk.iter().map(|b| format!("{b:02x}")).collect::<String>());
}

struct Host {
    pk: ed25519_compact::PublicKey,
    licences: Vec<String>,
}

impl Platform for Host {
    fn target(&self) -> u8 {
        target::GENERIC_INT
    }
    fn features(&self) -> u32 {
        neuro_hnx::feature::ALL
    }
    fn engine_abi(&self) -> u16 {
        1
    }
    fn verify(&self, s: u8, digest: &[u8; 32], sig: &[u8]) -> bool {
        s == scheme::ED25519 && ed25519_compact::Signature::from_slice(sig).is_ok_and(|g| self.pk.verify(digest, &g).is_ok())
    }
    fn licence_allowed(&self, spdx: &[u8]) -> bool {
        self.licences.iter().any(|l| l.as_bytes() == spdx)
    }
    fn min_svn(&self, _: &[u8; 16]) -> u32 {
        0
    }
}

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

/// What a heqk server does before any job: open, verify, read in place, admit.
fn admitted(args: &[String]) -> neuro_gguf::hnx::Admitted<'static> {
    let path = need(args, "--hnx");
    let host = Host { pk: ed25519_compact::PublicKey::from_slice(&hex32(&need(args, "--pub"))).unwrap_or_else(|_| die("--pub")), licences: vec![arg(args, "--allow-licence").unwrap_or_else(|| "Apache-2.0".into())] };
    let mut f = std::fs::File::open(&path).unwrap_or_else(|e| die(&format!("open {path}: {e}")));

    // 1 and 2: the header says how long the prefix is; the loader checks it, the table and the signature.
    let t0 = Instant::now();
    let mut prefix = vec![0u8; HEADER_LEN];
    f.read_exact(&mut prefix).unwrap_or_else(|e| die(&format!("read the header: {e}")));
    let h = Header::decode(&prefix).unwrap_or_else(|e| die(&format!("header refused: {e:?}")));
    let table_and_len = usize::try_from(h.n_segments).unwrap_or(usize::MAX).saturating_mul(LEAF_LEN).saturating_add(2);
    prefix.resize(HEADER_LEN + table_and_len, 0);
    f.read_exact(&mut prefix[HEADER_LEN..]).unwrap_or_else(|e| die(&format!("read the segment table: {e}")));
    let sig_len = usize::from(u16::from_le_bytes([prefix[prefix.len() - 2], prefix[prefix.len() - 1]]));
    let at = prefix.len();
    prefix.resize(at + sig_len.min(MAX_SIG), 0);
    f.read_exact(&mut prefix[at..]).unwrap_or_else(|e| die(&format!("read the signature: {e}")));
    let prefix: &'static [u8] = prefix.leak();
    let mut loader = Loader::open(prefix, &host).unwrap_or_else(|e| die(&format!("container refused: {e:?}")));
    let m = loader.header().manifest;
    println!("opened {path} in {:?}: signature and segment table verified; {} segments, payload {} bytes", t0.elapsed(), h.n_segments, m.payload_bytes);

    // 3 and 4: reserve exactly the payload; each segment is read into its place and verified there.
    let mut region = vec![0u8; usize::try_from(m.payload_bytes).unwrap_or_else(|_| die("payload too large for this host"))];
    let (mut t_read, mut t_verify) = (0.0f64, 0.0f64);
    let size = h.segment_size();
    for i in 0..h.n_segments {
        let len = h.segment_len(i).unwrap_or_else(|| die("segment length"));
        let start = i as usize * size;
        let t = Instant::now();
        f.read_exact(&mut region[start..start + len]).unwrap_or_else(|e| die(&format!("read segment {i}: {e}")));
        t_read += t.elapsed().as_secs_f64();
        let t = Instant::now();
        if let Err(e) = loader.accept_in_place(i, &region) {
            loader.abort(&mut region);
            die(&format!("segment {i} refused ({e:?}); the region was wiped"));
        }
        t_verify += t.elapsed().as_secs_f64();
    }
    let mib = m.payload_bytes as f64 / 1048576.0;
    println!("loaded {mib:.0} MiB with no staging copy: read {t_read:.2} s, verify {t_verify:.2} s ({:.0} MiB/s hashing)", mib / t_verify.max(1e-9));

    // 5: the manifest must be what the file needs; then the engine binds the verified bytes.
    let region: &'static [u8] = region.leak();
    let ad = admit(&loader, region).unwrap_or_else(|e| die(&format!("admission refused: {e:?}")));
    ad
}

fn run(args: &[String]) {
    let question = need(args, "--ask");
    let max_new: usize = arg(args, "--max-new").map_or(64, |v| v.parse().unwrap_or_else(|_| die("--max-new")));
    let ad = admitted(args);
    if ad.bundle.is_some_and(|b| !b.packed.is_empty()) || (ad.bundle.is_some() && !args.iter().any(|a| a == "--packed")) {
        return session(args, &ad, &question, max_new);
    }
    let (g, hp) = (ad.gguf, ad.hparams);
    let d = hp.dims;
    let layers: &'static [_] = (0..d.n_layers).map(|i| bind::layer(&g, &hp, i).unwrap_or_else(|e| die(&format!("layer {i}: {e:?}")))).collect::<Vec<_>>().leak();
    // The tables: from the verified bundle, or (bare GGUF payload) built here as a device could not.
    let (rope, tok_blob): (&'static [(i32, i32)], &'static [u8]) = match ad.bundle {
        Some(b) => {
            let arena: &'static mut [(i32, i32)] = vec![(0, 0); b.rope_pairs()].leak();
            b.rope_into(arena).unwrap_or_else(|| die("RoPE table"));
            println!("tables from the bundle: tokenizer {} bytes read in place, RoPE {} pairs copied to the arena; nothing derived", b.tokenizer.len(), b.rope_pairs());
            (arena, b.tokenizer)
        }
        None => {
            println!("bare GGUF payload: tokenizer and RoPE tables built on this host (a device cannot)");
            let tb = tok_build::blob(&tok_build::from_gguf(&g).unwrap_or_else(|e| die(&e)), &tok_build::unicode_ranges(), &tok_build::nfc_tables()).unwrap_or_else(|e| die(&format!("tokenizer: {e:?}")));
            (neuro_build::rope_neox_table(d.max_ctx, d.head_dim, f32::from_bits(hp.rope_base) as f64).leak(), tb.leak())
        }
    };
    let gm = bind::model(&g, &hp, layers, rope).unwrap_or_else(|e| die(&format!("bind: {e:?}")));
    let packed = args.iter().any(|a| a == "--packed");
    let model: Model<'static> = if packed {
        let pk = |m: &Mat<'static>| m.pack_into(vec![0u8; neuro_kernels::q8::packed_bytes(m.rows, m.cols)].leak()).expect("pack");
        let pl: Vec<_> = layers.iter().map(|l| Layer { wq: pk(&l.wq), wk: pk(&l.wk), wv: pk(&l.wv), wo: pk(&l.wo), w_gate: pk(&l.w_gate), w_up: pk(&l.w_up), w_down: pk(&l.w_down), ..*l }).collect();
        Model { embed: pk(&gm.embed), layers: pl.leak(), ..gm }
    } else {
        gm
    };
    model.check().unwrap_or_else(|e| die(&format!("model check: {e:?}")));
    let tok = Tokenizer::new(tok_blob).unwrap_or_else(|_| die("tokenizer tables"));
    let sd = simd(args.iter().any(|a| a == "--scalar"));
    println!("admitted: {} layers, vocab {}, context {}, {} layout, {}", d.n_layers, d.vocab, d.max_ctx, if packed { "packed" } else { "GGUF" }, sd.name());

    let prompt = format!("<|im_start|>user\n{question}<|im_end|>\n<|im_start|>assistant\n<think>\n\n</think>\n\n");
    let mut ids = vec![0u32; d.max_ctx];
    let (mut cps, mut buf) = (vec![0u32; 1 << 16], vec![0u8; 1 << 16]);
    let n = tok.encode_nfc(prompt.as_bytes(), &mut ids, &mut cps, &mut buf).unwrap_or_else(|_| die("the prompt does not fit the context"));
    ids.truncate(n);
    let stop = [tok.added_id(b"<|im_end|>").unwrap_or_else(|| die("<|im_end|>")), tok.added_id(b"<|endoftext|>").unwrap_or_else(|| die("<|endoftext|>"))];
    let (kvn, kvs) = d.kv_len();
    let (mut vals, mut shifts) = (vec![0i16; kvn], vec![0u8; kvs]);
    let (a, b, c, e) = Work::lens(&d, MAX_BATCH);
    let (mut wa, mut wb, mut wc, mut we) = (vec![0i64; a], vec![0i8; b], vec![(0, 0); c], vec![0i32; e]);
    let mut work = Work::new(&d, MAX_BATCH, &mut wa, &mut wb, &mut wc, &mut we).unwrap_or_else(|| die("work area"));
    let mut kv = Kv { vals: &mut vals, shifts: &mut shifts };
    let mut out = vec![0u32; max_new];
    let t = Instant::now();
    let k = model.generate(sd, &ids, &stop, &mut kv, &mut work, &mut out).unwrap_or_else(|e| die(&format!("generate: {e:?}")));
    let secs = t.elapsed().as_secs_f64();
    let answer: Vec<u32> = out[..k].iter().copied().filter(|t| !stop.contains(t)).collect();
    let mut text = vec![0u8; 1 << 16];
    let tn = tok.decode(&answer, &mut text).unwrap_or_else(|_| die("decode"));
    println!("answer: {:?}", String::from_utf8_lossy(&text[..tn]));
    println!("{n} prompt tokens + {k} generated in {secs:.1} s on the build host ({:.2} s per token overall; not a device number)", secs / (n + k) as f64);
}

/// The device's way: a session advanced one forward pass at a time, in memory assigned up front.
fn session(args: &[String], ad: &neuro_gguf::hnx::Admitted<'static>, question: &str, max_new: usize) {
    use neuro_gguf::p0::{self, Mem, Progress, Session};
    let batch: usize = arg(args, "--batch").map_or(MAX_BATCH, |v| v.parse().unwrap_or_else(|_| die("--batch")));
    let z = p0::sizes(&ad.hparams, batch);
    let mem = Mem {
        layers: vec![Layer::EMPTY; z.layers].leak(),
        rope: vec![(0, 0); z.rope].leak(),
        kv_vals: vec![0; z.kv_vals].leak(),
        kv_shifts: vec![0; z.kv_shifts].leak(),
        work_i64: vec![0; z.work_i64].leak(),
        work_i8: vec![0; z.work_i8].leak(),
        work_pairs: vec![(0, 0); z.work_pairs].leak(),
        work_i32: vec![0; z.work_i32].leak(),
        ids: vec![0; z.ids].leak(),
        prev: vec![0; z.prev].leak(),
        list: &mut [],
        out: &mut [],
    };
    let sd = simd(args.iter().any(|a| a == "--scalar"));
    let mut s = Session::open(ad, sd, batch, mem).unwrap_or_else(|e| die(&format!("session: {e:?}")));
    let d = ad.hparams.dims;
    println!("session: {} layers, vocab {}, context {}, {}, {} layout; memory assigned up front {:.1} MiB (KV {:.1} MiB), nothing derived, nothing allocated after this", d.n_layers, d.vocab, d.max_ctx, sd.name(), if ad.bundle.is_some_and(|b| !b.packed.is_empty()) { "packed" } else { "GGUF" }, z.bytes() as f64 / 1048576.0, (z.kv_vals * 2 + z.kv_shifts) as f64 / 1048576.0);
    let prompt = format!("<|im_start|>user\n{question}<|im_end|>\n<|im_start|>assistant\n<think>\n\n</think>\n\n");
    let (mut cps, mut buf) = (vec![0u32; 1 << 16], vec![0u8; 1 << 16]);
    let n = s.start(prompt.as_bytes(), &mut cps, &mut buf).unwrap_or_else(|e| die(&format!("prompt: {e:?}")));
    let (mut prefill, mut steps): (Vec<f64>, Vec<f64>) = (vec![], vec![]);
    let t_all = Instant::now();
    loop {
        let t = Instant::now();
        let p = s.advance().unwrap_or_else(|e| die(&format!("advance: {e:?}")));
        let ms = t.elapsed().as_secs_f64() * 1000.0;
        match p {
            Progress::Prefill { .. } => prefill.push(ms),
            Progress::Token { last, .. } => {
                steps.push(ms);
                if last || steps.len() >= max_new {
                    break;
                }
            }
            Progress::Tokens { .. } | Progress::Done => break,
        }
    }
    let secs = t_all.elapsed().as_secs_f64();
    let mut text = vec![0u8; 1 << 16];
    let tn = s.answer_text(&mut text).unwrap_or_else(|e| die(&format!("decode: {e:?}")));
    println!("answer: {:?}", String::from_utf8_lossy(&text[..tn]));
    // The last token pass only emits (it chose nothing new), so it is left out of the per-pass figures.
    let mut gen: Vec<f64> = steps.iter().copied().take(steps.len().saturating_sub(1)).collect();
    gen.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let pct = |v: &[f64], p: usize| v.get((v.len().saturating_sub(1)) * p / 100).copied().unwrap_or(0.0);
    println!("{n} prompt tokens in {} passes of up to {batch} ({:.0} ms per pass); {} tokens generated", prefill.len(), prefill.iter().sum::<f64>() / prefill.len().max(1) as f64, steps.len());
    println!("one pass per generated token: median {:.1} ms, p99 {:.1} ms, max {:.1} ms; whole job {secs:.2} s (build host, not a device number)", pct(&gen, 50), pct(&gen, 99), gen.last().copied().unwrap_or(0.0));
}

/// Triage jobs the way the device runs them: for each window's context, Neuro's contract prompt, an answer
/// decoded under the contract from the signed bundle one pass at a time, then read back and checked. Several
/// windows run one after another in one session, as on a device.
fn triage(args: &[String]) {
    use neuro_contract::{context_ids, guard, write_system, Allowed, IdList, Lang, Machine, Out, CHAT_ASSISTANT, CHAT_SYSTEM, CHAT_USER, USER_HEAD, USER_MID};
    use neuro_gguf::p0::{self, Mem, Progress, Session};
    use neuro_lm::decode::Options;
    let mut paths = vec![need(args, "--context")];
    paths.extend(args.iter().enumerate().filter(|(_, a)| *a == "--then").filter_map(|(i, _)| args.get(i + 1).cloned()));
    let question = arg(args, "--ask").unwrap_or_else(|| "Assess this window.".into());
    // Neuro measured answers of up to 700 tokens; a job whose prompt leaves less room is refused.
    let max_new: usize = arg(args, "--max-new").map_or(700, |v| v.parse().unwrap_or_else(|_| die("--max-new")));
    let ad = admitted(args);
    if ad.bundle.is_none() {
        die("this container is a bare GGUF payload; a device needs the bundle");
    }
    let batch: usize = arg(args, "--batch").map_or(MAX_BATCH, |v| v.parse().unwrap_or_else(|_| die("--batch")));
    let z = p0::sizes(&ad.hparams, batch);
    let opts = if args.iter().any(|a| a == "--drafts") { Options { prune_max: 8192, draft_max: 7, max_new } } else { Options { prune_max: 8192, draft_max: 0, max_new } };
    let mem = Mem {
        layers: vec![Layer::EMPTY; z.layers].leak(),
        rope: vec![(0, 0); z.rope].leak(),
        kv_vals: vec![0; z.kv_vals].leak(),
        kv_shifts: vec![0; z.kv_shifts].leak(),
        work_i64: vec![0; z.work_i64].leak(),
        work_i8: vec![0; z.work_i8].leak(),
        work_pairs: vec![(0, 0); z.work_pairs].leak(),
        work_i32: vec![0; z.work_i32].leak(),
        ids: vec![0; z.ids].leak(),
        prev: if args.iter().any(|a| a == "--no-reuse") { &mut [] } else { vec![0; z.prev].leak() },
        list: vec![0; 8192].leak(),
        out: vec![0; max_new].leak(),
    };
    let sd = simd(args.iter().any(|a| a == "--scalar"));
    let mut s = Session::open(&ad, sd, batch, mem).unwrap_or_else(|e| die(&format!("session: {e:?}")));
    println!("session: context {}, {}, {} layout, memory assigned up front {:.1} MiB", ad.hparams.dims.max_ctx, sd.name(), if ad.bundle.is_some_and(|b| !b.packed.is_empty()) { "packed" } else { "GGUF" }, z.bytes() as f64 / 1048576.0);
    let (mut cps, mut buf) = (vec![0u32; 1 << 17], vec![0u8; 1 << 17]);
    for path in &paths {
        let context = String::from_utf8(std::fs::read(path).unwrap_or_else(|e| die(&format!("read {path}: {e}")))).unwrap_or_else(|_| die("the context is not UTF-8"));
        let context = context.trim_end_matches('\n');
        // The prompt: guard A on the context, the ids of what is shown, Neuro's system prompt with the closed schema.
        let mut shown = vec![0u8; context.len() * 4 + 256];
        let mut o = Out::new(&mut shown);
        guard::guard_a(context.as_bytes(), &mut o).unwrap_or_else(|e| die(&format!("guard A: {e:?}")));
        let n_shown = o.n;
        let shown = &shown[..n_shown];
        let (facts, ents): (&'static mut IdList, &'static mut IdList) = (Box::leak(Box::new(IdList::new())), Box::leak(Box::new(IdList::new())));
        context_ids(shown, facts, ents).unwrap_or_else(|e| die(&format!("context ids: {e:?}")));
        if facts.is_empty() {
            println!("\n{path}: no fact card; the device does not ask a model about this window (Refused: NoEvidence)");
            continue;
        }
        let (facts, ents): (&'static IdList, &'static IdList) = (facts, ents);
        let mut pbuf = vec![0u8; 1 << 16];
        let mut p = Out::new(&mut pbuf);
        let put = |p: &mut Out, b: &[u8]| p.put(b).unwrap_or_else(|_| die("the prompt is too large"));
        put(&mut p, CHAT_SYSTEM.as_bytes());
        write_system(Lang::En, facts, ents, true, &mut p).unwrap_or_else(|e| die(&format!("system prompt: {e:?}")));
        put(&mut p, CHAT_USER.as_bytes());
        put(&mut p, USER_HEAD.as_bytes());
        put(&mut p, shown);
        put(&mut p, USER_MID.as_bytes());
        put(&mut p, question.as_bytes());
        put(&mut p, CHAT_ASSISTANT.as_bytes());
        let pn = p.n;
        let machine = Machine::new(Allowed { facts, entities: ents, closed: true });
        let n = match s.start_closed(&pbuf[..pn], &mut cps, &mut buf, machine, opts) {
            Ok(n) => n,
            Err(e) => {
                println!("\n{path}: refused ({e:?}): the prompt and a {max_new}-token answer do not fit the admitted context");
                continue;
            }
        };
        println!("\n{path}: {} bytes, {} facts, {} aliases; prompt {n} tokens, {} already in the KV cache from the job before", context.len(), facts.len(), ents.len(), s.reused());
        let (mut prefill, mut passes): (Vec<f64>, Vec<f64>) = (vec![], vec![]);
        let t_all = Instant::now();
        loop {
            let t = Instant::now();
            let pr = s.advance().unwrap_or_else(|e| die(&format!("advance: {e:?}")));
            let ms = t.elapsed().as_secs_f64() * 1000.0;
            match pr {
                Progress::Prefill { .. } => prefill.push(ms),
                Progress::Tokens { .. } | Progress::Token { .. } => passes.push(ms),
                Progress::Done => break,
            }
        }
        let secs = t_all.elapsed().as_secs_f64();
        let st = s.closed_stats().unwrap_or_default();
        let mut text = vec![0u8; 1 << 16];
        let tn = s.answer_text(&mut text).unwrap_or_else(|e| die(&format!("decode: {e:?}")));
        let answer = &text[..tn];
        println!("answer: {}", String::from_utf8_lossy(answer));
        // Read it back as the verifier does, and run guard E against the context as the device wrote it.
        match neuro_contract::parse(answer, facts, ents) {
            Ok(_) => println!("contract: VALID (every fact id and alias is one of the shown context)"),
            Err(e) => println!("contract: REFUSED ({e:?})"),
        }
        println!("guard E: {}", if guard::echoes(context.as_bytes(), answer) { "the answer repeats carried text; the device would replace the prose" } else { "no carried text repeated" });
        passes.sort_by(|a, b| a.partial_cmp(b).unwrap());
        let pct = |v: &[f64], q: usize| v.get(v.len().saturating_sub(1) * q / 100).copied().unwrap_or(0.0);
        let prompt_s = prefill.iter().sum::<f64>() / 1000.0;
        println!("prompt: {} passes, {prompt_s:.1} s; answer: {} tokens in {} passes ({} with a pruned head, {} of {} drafts accepted)", prefill.len(), st.tokens, st.passes, st.pruned_passes, st.accepted, st.drafted);
        println!("per answer pass: median {:.1} ms, p99 {:.1} ms, max {:.1} ms; whole job {secs:.1} s (build host, not a device number)", pct(&passes, 50), pct(&passes, 99), passes.last().copied().unwrap_or(0.0));
    }
}

/// The Conductor path around the engine: harness, capability, worker, engine, signed result, verifier.
fn job(args: &[String]) {
    use conductor_core::class::{DataClass, Tier};
    use conductor_core::crypto::{public_key, sign};
    use conductor_core::harness::{Harness, Outcome};
    use conductor_core::job::Verdict;
    use conductor_mock::disk::{Disk, Platter};
    use conductor_mock::{env_with, policy_p1, Ev, JobBuilder, Kernel, Remote, DEVICE_SEED, MODEL, WORKER_SEED};
    use conductor_p0::P0Executor;
    use conductor_worker::{Layout, ResultKey, Worker};
    use neuro_gguf::p0::{self, Mem, Session};
    struct Key([u8; 32]);
    impl ResultKey for Key {
        fn public_key(&self) -> [u8; 32] {
            public_key(&self.0)
        }
        fn sign(&self, tag: &[u8], msg: &[u8]) -> Option<[u8; 64]> {
            sign(&self.0, tag, msg)
        }
    }
    type Exec = P0Executor<'static, Box<dyn FnMut() -> u64>>;
    struct Node(Worker<Disk, Key, Exec>);
    impl Remote for Node {
        fn tier(&self) -> Tier {
            Tier::P1
        }
        fn receive(&mut self, tx: &[u8], session: &[u8; 32], now_ms: u64) -> Vec<Vec<u8>> {
            let mut v = vec![];
            self.0.handle(tx, session, now_ms, &mut |f| v.push(f.to_vec()));
            v
        }
    }

    let l0 = match arg(args, "--l0").as_deref() {
        None | Some("suspicious") => Verdict::Suspicious,
        Some("benign") => Verdict::Benign,
        Some("malicious") => Verdict::Malicious,
        _ => die("--l0 benign|suspicious|malicious"),
    };
    let mut facts: Vec<String> = args.iter().enumerate().filter(|(_, a)| *a == "--fact").filter_map(|(i, _)| args.get(i + 1).cloned()).collect();
    if facts.is_empty() {
        facts = vec!["42 connections from one device to 203.0.113.9:443 in 10 min, 5 s apart".into(), "203.0.113.9 has no reverse DNS name and was first seen today".into()];
    }
    let n_jobs: u8 = arg(args, "--jobs").map_or(2, |v| v.parse().unwrap_or_else(|_| die("--jobs")));

    // The node: verify, load, admit, open one session, serve one model.
    let ad: &'static neuro_gguf::hnx::Admitted<'static> = Box::leak(Box::new(admitted(args)));
    if ad.bundle.is_none() {
        die("this container is a bare GGUF payload; a node needs the bundle");
    }
    let z = p0::sizes(&ad.hparams, MAX_BATCH);
    let mem = Mem {
        layers: vec![Layer::EMPTY; z.layers].leak(),
        rope: vec![(0, 0); z.rope].leak(),
        kv_vals: vec![0; z.kv_vals].leak(),
        kv_shifts: vec![0; z.kv_shifts].leak(),
        work_i64: vec![0; z.work_i64].leak(),
        work_i8: vec![0; z.work_i8].leak(),
        work_pairs: vec![(0, 0); z.work_pairs].leak(),
        work_i32: vec![0; z.work_i32].leak(),
        ids: vec![0; z.ids].leak(),
        prev: vec![0; z.prev].leak(),
        list: vec![0; 8192].leak(),
        out: vec![0; conductor_p0::MAX_ANSWER_TOKENS].leak(),
    };
    let sd = simd(args.iter().any(|a| a == "--scalar"));
    let session = Session::open(ad, sd, MAX_BATCH, mem).unwrap_or_else(|e| die(&format!("session: {e:?}")));
    let t0 = Instant::now();
    let clock: Box<dyn FnMut() -> u64> = Box::new(move || t0.elapsed().as_millis() as u64);
    let exec = P0Executor::new(session, MODEL, vec![0u32; 1 << 17].leak(), vec![0u8; 1 << 17].leak(), clock);
    let layout = Layout { high_water_lo: 64, epoch_lo: 66 };
    let mut node = Node(Worker::boot(Disk::new(&Platter::default()), layout, Key(WORKER_SEED), exec, public_key(&DEVICE_SEED), Tier::P1).unwrap_or_else(|| die("the worker's store is unreadable")));
    println!("node: one session, {}, serving one model; worker key and store are this host's test doubles", sd.name());

    // The device: one kernel (its capability counter goes on from job to job), one harness per job.
    let mut k = Kernel::new(policy_p1(), Tier::P1);
    for j in 0..n_jobs {
        let evidence: Vec<Ev> = facts.iter().enumerate().map(|(i, t)| Ev { id: i as u16 + 1, class: DataClass::Public, required: i == 0, text: t.clone() }).collect();
        let b = JobBuilder { job_id: [j + 1; 16], tools: 0, l0: l0 as u8, out_total: 4096, compute_total: 600_000, per_call: 120_000, evidence, ..Default::default() };
        let mut h = Box::new(Harness::new());
        let t = Instant::now();
        let r = k.run(&mut h, &b.encode(), env_with(policy_p1(), public_key(&WORKER_SEED), Tier::P1), &mut node);
        let st = node.0.executor().last_stats();
        println!("\njob {}: {:.1} s; prompt {} bytes; {} prompt tokens not fed again; {} prefill passes, {} answer passes, {} answer tokens", j + 1, t.elapsed().as_secs_f64(), h.prompt().len(), node.0.executor().last_reused(), st.prefill_passes, st.passes, st.tokens);
        match r.outcome {
            Some(Outcome::Verified(v)) => println!("  verifier: {:?}; model verdict {:?}; decided by L0: {}", v.status, v.model_verdict, v.l0_decided),
            other => println!("  outcome: {other:?}"),
        }
        println!("  summary shown: {}", String::from_utf8_lossy(h.summary()));
        println!("  ledger records: {}; leases started/ended: {}/{}; worker high-water mark: {}", r.ledger.len(), r.leases_started, r.leases_ended, node.0.high_water());
    }
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("pack") => pack(&args),
        Some("run") => run(&args),
        Some("triage") => triage(&args),
        Some("job") => job(&args),
        _ => die("usage: hnx-lm pack|run|triage|job …; see the top of hnx-lm.rs"),
    }
}
