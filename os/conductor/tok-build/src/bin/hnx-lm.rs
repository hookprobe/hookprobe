// SPDX-License-Identifier: AGPL-3.0-only
//! A language model through the device's one load path, on the build host.
//!
//! `pack`: wrap a GGUF file as a signed HNX container (kind `GGUF_LM`), with the manifest admission reads.
//! `run`:  what a heqk server does with that file: open and verify the header and signature, reserve exactly the
//!         payload, read each segment straight into its place and verify it there, check the manifest against the
//!         file, bind the integer engine, answer one question. No other runtime is involved.
//!
//! Usage:
//!   hnx-lm pack --gguf MODEL.gguf --out MODEL.hnx --key SEED.hex --eval REPORT [--ctx 4096] [--licence Apache-2.0] [--svn 1]
//!   hnx-lm run  --hnx MODEL.hnx --pub PUBKEY.hex --ask "question" [--max-new 64] [--scalar] [--packed]
//!
//! `SEED.hex` is a 32-byte Ed25519 seed in hex (a build-host test key here; release signing is an operator step).
//! Host-side helpers that a device image would carry precomputed: the tokenizer tables and the RoPE table.
use neuro_gguf::hnx::{admit, manifest_for};
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
    let ctx: usize = arg(args, "--ctx").map_or(4096, |v| v.parse().unwrap_or_else(|_| die("--ctx")));
    let seed = hex32(&need(args, "--key"));
    let eval = std::fs::read(need(args, "--eval")).unwrap_or_else(|e| die(&format!("read the evaluation report: {e}")));
    let spdx = arg(args, "--licence").unwrap_or_else(|| "Apache-2.0".into());
    let mut licence = [0u8; 32];
    if spdx.is_empty() || spdx.len() > 32 {
        die("--licence: 1 to 32 bytes");
    }
    licence[..spdx.len()].copy_from_slice(spdx.as_bytes());
    let source = sha(&file);
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
        manifest: manifest_for(&file, ctx).unwrap_or_else(|e| die(&format!("this file is not a model the engine binds: {e:?}"))),
        licence,
        source_sha256: source,
        eval_sha256: sha(&eval),
        merkle_root: [0; 32],
        payload_kind: kind::GGUF_LM,
    };
    let mut prefix = vec![0u8; HEADER_LEN + file.len().div_ceil(1 << SEG_LOG2) * LEAF_LEN + 2 + 64];
    let kp = ed25519_compact::KeyPair::from_seed(ed25519_compact::Seed::new(seed));
    let n = build_prefix(&mut h, &file, &mut prefix, |d| {
        let mut out = [0u8; MAX_SIG];
        out[..64].copy_from_slice(kp.sk.sign(d, None).as_ref());
        Some((out, 64))
    })
    .unwrap_or_else(|| die("could not build the container"));
    let out_path = need(args, "--out");
    let mut out = std::fs::File::create(&out_path).unwrap_or_else(|e| die(&format!("create {out_path}: {e}")));
    out.write_all(&prefix[..n]).and_then(|()| out.write_all(&file)).unwrap_or_else(|e| die(&format!("write {out_path}: {e}")));
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

fn run(args: &[String]) {
    let path = need(args, "--hnx");
    let question = need(args, "--ask");
    let max_new: usize = arg(args, "--max-new").map_or(64, |v| v.parse().unwrap_or_else(|_| die("--max-new")));
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
    let mut loader = Loader::open(&prefix, &host).unwrap_or_else(|e| die(&format!("container refused: {e:?}")));
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
    let (g, hp) = admit(&loader, region).unwrap_or_else(|e| die(&format!("admission refused: {e:?}")));
    let d = hp.dims;
    let layers: &'static [_] = (0..d.n_layers).map(|i| bind::layer(&g, &hp, i).unwrap_or_else(|e| die(&format!("layer {i}: {e:?}")))).collect::<Vec<_>>().leak();
    let rope: &'static [(i32, i32)] = neuro_build::rope_neox_table(d.max_ctx, d.head_dim, f32::from_bits(hp.rope_base) as f64).leak();
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
    let tb = tok_build::blob(&tok_build::from_gguf(&g).unwrap_or_else(|e| die(&e)), &tok_build::unicode_ranges(), &tok_build::nfc_tables()).unwrap_or_else(|e| die(&format!("tokenizer: {e:?}")));
    let tok = Tokenizer::new(&tb).unwrap_or_else(|_| die("tokenizer tables"));
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

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("pack") => pack(&args),
        Some("run") => run(&args),
        _ => die("usage: hnx-lm pack|run …; see the top of hnx-lm.rs"),
    }
}
