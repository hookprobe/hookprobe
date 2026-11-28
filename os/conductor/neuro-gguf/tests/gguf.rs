// SPDX-License-Identifier: AGPL-3.0-only
//! GGUF reader: a synthetic file with every value type, malformed files refused for the right reason,
//! mutation fuzzing (no panic), the integer 1/sqrt against IEEE, and the Qwen3 binder's refusals.
use neuro_gguf::qwen3::{hparams, inv_sqrt_bits, layer, model, BindError};
use neuro_gguf::{tt, vt, Gguf, GgufError, Value};

struct W {
    kv: Vec<u8>,
    n_kv: u64,
    ti: Vec<u8>,
    n_t: u64,
    data: Vec<u8>,
    align: usize,
}

fn s(v: &mut Vec<u8>, x: &[u8]) {
    v.extend_from_slice(&(x.len() as u64).to_le_bytes());
    v.extend_from_slice(x);
}

impl W {
    fn new() -> Self {
        W { kv: vec![], n_kv: 0, ti: vec![], n_t: 0, data: vec![], align: 32 }
    }
    fn kv(&mut self, key: &str, t: u32, val: &[u8]) -> &mut Self {
        s(&mut self.kv, key.as_bytes());
        self.kv.extend_from_slice(&t.to_le_bytes());
        self.kv.extend_from_slice(val);
        self.n_kv += 1;
        self
    }
    fn kv_str(&mut self, key: &str, val: &str) -> &mut Self {
        let mut v = vec![];
        s(&mut v, val.as_bytes());
        self.kv(key, vt::STRING, &v)
    }
    fn kv_u32(&mut self, key: &str, val: u32) -> &mut Self {
        self.kv(key, vt::U32, &val.to_le_bytes())
    }
    fn tensor(&mut self, name: &str, ty: u32, dims: &[u64], bytes: &[u8]) -> &mut Self {
        while self.data.len() % self.align != 0 {
            self.data.push(0);
        }
        s(&mut self.ti, name.as_bytes());
        self.ti.extend_from_slice(&(dims.len() as u32).to_le_bytes());
        for d in dims {
            self.ti.extend_from_slice(&d.to_le_bytes());
        }
        self.ti.extend_from_slice(&ty.to_le_bytes());
        self.ti.extend_from_slice(&(self.data.len() as u64).to_le_bytes());
        self.data.extend_from_slice(bytes);
        self.n_t += 1;
        self
    }
    fn build(&self) -> Vec<u8> {
        let mut f = b"GGUF".to_vec();
        f.extend_from_slice(&3u32.to_le_bytes());
        f.extend_from_slice(&self.n_t.to_le_bytes());
        f.extend_from_slice(&self.n_kv.to_le_bytes());
        f.extend_from_slice(&self.kv);
        f.extend_from_slice(&self.ti);
        while f.len() % self.align != 0 {
            f.push(0);
        }
        f.extend_from_slice(&self.data);
        f
    }
}

fn sample() -> W {
    let mut w = W::new();
    let mut arr = vt::STRING.to_le_bytes().to_vec();
    arr.extend_from_slice(&3u64.to_le_bytes());
    for x in ["a", "bc", "<|im_end|>"] {
        s(&mut arr, x.as_bytes());
    }
    let mut ints = vt::I32.to_le_bytes().to_vec();
    ints.extend_from_slice(&4u64.to_le_bytes());
    for x in [1i32, -2, 3, i32::MIN] {
        ints.extend_from_slice(&x.to_le_bytes());
    }
    w.kv_str("general.architecture", "test")
        .kv("u8", vt::U8, &[200])
        .kv("i8", vt::I8, &[0xfe])
        .kv("u16", vt::U16, &[1, 2])
        .kv("i16", vt::I16, &(-300i16).to_le_bytes())
        .kv_u32("u32", 70_000)
        .kv("i32", vt::I32, &(-5i32).to_le_bytes())
        .kv("f32", vt::F32, &1.5f32.to_bits().to_le_bytes())
        .kv("bool", vt::BOOL, &[1])
        .kv("u64", vt::U64, &(1u64 << 40).to_le_bytes())
        .kv("i64", vt::I64, &(-7i64).to_le_bytes())
        .kv("f64", vt::F64, &2.5f64.to_bits().to_le_bytes())
        .kv("strings", vt::ARRAY, &arr)
        .kv("ints", vt::ARRAY, &ints)
        .tensor("norm", tt::F32, &[8], &[7u8; 32])
        .tensor("mat", tt::Q8_0, &[64, 3], &[9u8; 68 * 3]);
    w
}

#[test]
fn reads_every_value_type_and_tensor() {
    let f = sample().build();
    let g = Gguf::open(&f).unwrap();
    assert_eq!((g.kv_count(), g.tensor_count()), (14, 2));
    assert_eq!(g.get_str(b"general.architecture"), Some(&b"test"[..]));
    assert_eq!(g.get(b"u8"), Some(Value::Uint(200)));
    assert_eq!(g.get(b"i8"), Some(Value::Int(-2)));
    assert_eq!(g.get(b"u16"), Some(Value::Uint(0x0201)));
    assert_eq!(g.get(b"i16"), Some(Value::Int(-300)));
    assert_eq!(g.get_uint(b"u32"), Some(70_000));
    assert_eq!(g.get(b"i32"), Some(Value::Int(-5)));
    assert_eq!(g.get_single(b"f32"), Some(1.5f32.to_bits()));
    assert_eq!(g.get(b"bool"), Some(Value::Bool(true)));
    assert_eq!(g.get_uint(b"u64"), Some(1 << 40));
    assert_eq!(g.get(b"i64"), Some(Value::Int(-7)));
    assert_eq!(g.get(b"f64"), Some(Value::Double(2.5f64.to_bits())));
    assert_eq!(g.get(b"missing"), None);
    let a = g.get_array(b"strings").unwrap();
    assert_eq!(a.strings().collect::<Vec<_>>(), vec![&b"a"[..], b"bc", b"<|im_end|>"]);
    let i = g.get_array(b"ints").unwrap();
    assert_eq!((0..5).map(|k| i.int(k)).collect::<Vec<_>>(), vec![Some(1), Some(-2), Some(3), Some(i32::MIN as i64), None]);
    let t = g.tensor(b"mat").unwrap();
    assert_eq!((t.ty, t.matrix(), t.data.len()), (tt::Q8_0, Some((3, 64)), 204));
    assert!(t.data.iter().all(|&b| b == 9));
    assert_eq!(g.tensor(b"norm").unwrap().data, &[7u8; 32]);
    assert!(g.tensor(b"nope").is_none());
}

#[test]
fn malformed_files_are_refused_for_the_right_reason() {
    let good = sample().build();
    let mut f = good.clone();
    f[0] = b'X';
    assert_eq!(Gguf::open(&f).err(), Some(GgufError::Magic));
    for v in [1u32, 2, 4] {
        let mut f = good.clone();
        f[4..8].copy_from_slice(&v.to_le_bytes());
        assert_eq!(Gguf::open(&f).err(), Some(GgufError::Version));
    }
    // Truncated anywhere in the header or the tensor data.
    for cut in [3, 10, 30, 100, good.len() - 1] {
        assert!(Gguf::open(&good[..cut]).is_err(), "cut {cut}");
    }
    // Absurd counts.
    let mut f = good.clone();
    f[8..16].copy_from_slice(&u64::MAX.to_le_bytes());
    assert_eq!(Gguf::open(&f).err(), Some(GgufError::Bounds));
    // Unknown value type, nested array, unknown tensor type.
    assert_eq!(Gguf::open(&W::new().kv("x", 13, &[0; 8]).build()).err(), Some(GgufError::Type));
    let mut nested = vt::ARRAY.to_le_bytes().to_vec();
    nested.extend_from_slice(&1u64.to_le_bytes());
    assert_eq!(Gguf::open(&W::new().kv("x", vt::ARRAY, &nested).build()).err(), Some(GgufError::Type));
    assert_eq!(Gguf::open(&W::new().tensor("t", 99, &[32], &[0; 32]).build()).err(), Some(GgufError::Type));
    // Duplicate key, duplicate tensor name.
    assert_eq!(Gguf::open(&W::new().kv_u32("k", 1).kv_u32("k", 2).build()).err(), Some(GgufError::Duplicate));
    assert_eq!(Gguf::open(&W::new().tensor("t", tt::F32, &[8], &[0; 32]).tensor("t", tt::F32, &[8], &[0; 32]).build()).err(), Some(GgufError::Duplicate));
    // Row length not a whole number of blocks; zero or 5 dimensions; non-UTF-8 key.
    assert_eq!(Gguf::open(&W::new().tensor("t", tt::Q8_0, &[48], &[0; 51]).build()).err(), Some(GgufError::Layout));
    assert_eq!(Gguf::open(&W::new().tensor("t", tt::F32, &[], &[]).build()).err(), Some(GgufError::Bounds));
    assert_eq!(Gguf::open(&W::new().tensor("t", tt::F32, &[1, 1, 1, 1, 1], &[0; 4]).build()).err(), Some(GgufError::Bounds));
    let mut f = W::new().kv_u32("key", 1).build();
    f[24 + 8] = 0xff;
    assert_eq!(Gguf::open(&f).err(), Some(GgufError::Utf8));
    // Tensor offsets: misaligned, overlapping, beyond the data.
    let mk = |off2: u64| {
        let mut w = W::new();
        w.tensor("a", tt::F32, &[16], &[0; 64]).tensor("b", tt::F32, &[16], &[0; 64]);
        let mut f = w.build();
        // the second tensor's offset is the last 8 bytes of its info, just before the data padding
        let info_end = 24 + w.ti.len();
        f[info_end - 8..info_end].copy_from_slice(&off2.to_le_bytes());
        f
    };
    assert!(Gguf::open(&mk(64)).is_ok());
    assert_eq!(Gguf::open(&mk(68)).err(), Some(GgufError::Layout));
    assert_eq!(Gguf::open(&mk(32)).err(), Some(GgufError::Layout));
    assert_eq!(Gguf::open(&mk(96)).err(), Some(GgufError::Layout));
    // Alignment must be a power of two in 8..=65536 and a u32.
    for (t, v) in [(vt::U32, 3u64), (vt::U32, 4), (vt::U32, 1 << 20), (vt::U64, 32)] {
        let val = if t == vt::U32 { (v as u32).to_le_bytes().to_vec() } else { v.to_le_bytes().to_vec() };
        assert_eq!(Gguf::open(&W::new().kv("general.alignment", t, &val).build()).err(), Some(GgufError::Layout));
    }
    let mut w = W::new();
    w.align = 64;
    w.kv_u32("general.alignment", 64).tensor("a", tt::F32, &[4], &[0; 16]).tensor("b", tt::F32, &[4], &[1; 16]);
    let f = w.build();
    let g = Gguf::open(&f).unwrap();
    assert_eq!((g.alignment, g.tensor(b"b").unwrap().data), (64, &[1u8; 16][..]));
}

#[test]
fn fuzzed_files_never_panic() {
    let good = sample().build();
    let mut x = 0x9e37_79b9_7f4a_7c15u64;
    let mut rnd = || {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        x
    };
    let mut opened = 0;
    for _ in 0..500_000 {
        let mut f = good.clone();
        for _ in 0..1 + rnd() % 4 {
            let i = (rnd() % f.len() as u64) as usize;
            f[i] = rnd() as u8;
        }
        let cut = if rnd() % 8 == 0 { (rnd() % f.len() as u64) as usize } else { f.len() };
        if let Ok(g) = Gguf::open(&f[..cut]) {
            opened += 1;
            g.for_each_kv(|_, v| {
                if let Value::Array(a) = v {
                    let _ = a.strings().count();
                    let _ = a.int(0);
                }
            });
            g.for_each_tensor(|t| {
                let _ = t.matrix();
            });
            let _ = hparams(&g, 16);
        }
    }
    println!("500,000 mutated files: {opened} still valid (changed values or tensor bytes), no panic");
}

#[test]
fn inv_sqrt_equals_ieee() {
    for n in 1..=65_536u64 {
        assert_eq!(inv_sqrt_bits(n), (1.0f32 / (n as f32).sqrt()).to_bits(), "n = {n}");
    }
}

/// A minimal valid Qwen3 file: 1 layer, d 32, 1 head of 32, ffn 32, vocab 4.
fn qwen3_file(arch: &str, q_ty: u32, ctx: u32) -> Vec<u8> {
    qwen3_file_v(arch, q_ty, ctx, 4)
}

/// The same with a vocabulary of `vocab` one-byte-named tokens.
fn qwen3_file_v(arch: &str, q_ty: u32, ctx: u32, vocab: usize) -> Vec<u8> {
    let q8 = |rows: usize, cols: usize| {
        let mut v = vec![];
        for _ in 0..rows * cols / 32 {
            v.extend_from_slice(&0x2000u16.to_le_bytes());
            v.extend_from_slice(&[1u8; 32]);
        }
        v
    };
    let one = |n: usize| 1.0f32.to_bits().to_le_bytes().repeat(n);
    let mut w = W::new();
    let mut toks = vt::STRING.to_le_bytes().to_vec();
    toks.extend_from_slice(&(vocab as u64).to_le_bytes());
    for t in 0..vocab {
        s(&mut toks, &[b'a' + (t % 26) as u8]);
    }
    w.kv_str("general.architecture", arch)
        .kv_u32("qwen3.block_count", 1)
        .kv_u32("qwen3.context_length", ctx)
        .kv_u32("qwen3.embedding_length", 32)
        .kv_u32("qwen3.feed_forward_length", 32)
        .kv_u32("qwen3.attention.head_count", 1)
        .kv_u32("qwen3.attention.head_count_kv", 1)
        .kv_u32("qwen3.attention.key_length", 32)
        .kv("qwen3.rope.freq_base", vt::F32, &1e6f32.to_bits().to_le_bytes())
        .kv("qwen3.attention.layer_norm_rms_epsilon", vt::F32, &1e-6f32.to_bits().to_le_bytes())
        .kv("tokenizer.ggml.tokens", vt::ARRAY, &toks)
        .tensor("token_embd.weight", tt::Q8_0, &[32, vocab as u64], &q8(vocab, 32))
        .tensor("output_norm.weight", tt::F32, &[32], &one(32))
        .tensor("blk.0.attn_norm.weight", tt::F32, &[32], &one(32))
        .tensor("blk.0.attn_q.weight", q_ty, &[32, 32], &if q_ty == tt::Q4_0 { vec![0u8; 32 * 18] } else { q8(32, 32) })
        .tensor("blk.0.attn_k.weight", tt::Q8_0, &[32, 32], &q8(32, 32))
        .tensor("blk.0.attn_v.weight", tt::Q8_0, &[32, 32], &q8(32, 32))
        .tensor("blk.0.attn_output.weight", tt::Q8_0, &[32, 32], &q8(32, 32))
        .tensor("blk.0.attn_q_norm.weight", tt::F32, &[32], &one(32))
        .tensor("blk.0.attn_k_norm.weight", tt::F32, &[32], &one(32))
        .tensor("blk.0.ffn_norm.weight", tt::F32, &[32], &one(32))
        .tensor("blk.0.ffn_gate.weight", tt::Q8_0, &[32, 32], &q8(32, 32))
        .tensor("blk.0.ffn_up.weight", tt::Q8_0, &[32, 32], &q8(32, 32))
        .tensor("blk.0.ffn_down.weight", tt::Q8_0, &[32, 32], &q8(32, 32));
    w.build()
}

#[test]
fn qwen3_binder_refuses_wrong_files() {
    let build = qwen3_file;
    let rope: Vec<(i32, i32)> = vec![(1 << 30, 0); 8 * 16];
    let f = build("qwen3", tt::Q8_0, 64);
    let g = Gguf::open(&f).unwrap();
    let h = hparams(&g, 8).unwrap();
    assert_eq!((h.dims.vocab, h.dims.head_dim, h.kq_scale), (4, 32, (1.0f32 / 32f32.sqrt()).to_bits()));
    let layers = vec![layer(&g, &h, 0).unwrap()];
    assert!(model(&g, &h, &layers, &rope[..8 * 16]).is_ok());
    assert!(matches!(model(&g, &h, &layers, &rope[..8 * 15]), Err(BindError::Check)));
    assert_eq!(hparams(&g, 65).err(), Some(BindError::Param("max_ctx")));
    assert_eq!(layer(&g, &h, 1).err(), Some(BindError::Missing));
    let f2 = build("llama", tt::Q8_0, 64);
    assert_eq!(hparams(&Gguf::open(&f2).unwrap(), 8).err(), Some(BindError::Arch));
    // A well-formed Q4_0 matrix where Q8_0 is required: the reader accepts the file, the binder refuses
    // the layer (never a silent conversion).
    let f3 = build("qwen3", tt::Q4_0, 64);
    let g3 = Gguf::open(&f3).unwrap();
    let h3 = hparams(&g3, 8).unwrap();
    assert_eq!(layer(&g3, &h3, 0).err(), Some(BindError::Tensor));
}

// ------------------------------------------------------------------------------------------- the signed container

mod container {
    use super::{qwen3_file, qwen3_file_v};
    use neuro_gguf::hnx::{admit, manifest_for, AdmitError};
    use neuro_gguf::qwen3::{layer, model};
    use neuro_gguf::tt;
    use neuro_hnx::{build_prefix, kind, scheme, target, Header, Loader, Platform, Refusal, HEADER_LEN, LEAF_LEN, MAX_SIG};
    use neuro_lm::qwen3::{Kv, Work};
    use neuro_kernels::Simd;

    const SEED: [u8; 32] = [0x51; 32];
    const CTX: usize = 8;

    struct Dev(ed25519_compact::PublicKey);
    impl Platform for Dev {
        fn target(&self) -> u8 {
            target::QEMU_VIRT
        }
        fn features(&self) -> u32 {
            0
        }
        fn engine_abi(&self) -> u16 {
            1
        }
        fn verify(&self, scheme: u8, digest: &[u8; 32], sig: &[u8]) -> bool {
            scheme == scheme::ED25519 && ed25519_compact::Signature::from_slice(sig).is_ok_and(|s| self.0.verify(digest, &s).is_ok())
        }
        fn licence_allowed(&self, spdx: &[u8]) -> bool {
            spdx == b"Apache-2.0"
        }
        fn min_svn(&self, _: &[u8; 16]) -> u32 {
            1
        }
    }

    fn dev() -> Dev {
        Dev(ed25519_compact::KeyPair::from_seed(ed25519_compact::Seed::new(SEED)).pk)
    }

    /// The build side: wrap a GGUF file as a signed language-model container.
    fn pack(file: &[u8], edit: impl FnOnce(&mut Header)) -> Vec<u8> {
        pack_as(file, kind::GGUF_LM, manifest_for(file, CTX).unwrap(), edit)
    }

    fn pack_as(payload: &[u8], payload_kind: u8, manifest: neuro_hnx::Manifest, edit: impl FnOnce(&mut Header)) -> Vec<u8> {
        let mut licence = [0u8; 32];
        licence[..10].copy_from_slice(b"Apache-2.0");
        let mut h = Header {
            target: target::GENERIC_INT,
            scheme: scheme::ED25519,
            engine_abi: 1,
            segment_log2: 12,
            n_segments: 0,
            model_id: [9; 16],
            model_svn: 1,
            manifest,
            licence,
            source_sha256: [1; 32],
            eval_sha256: [2; 32],
            merkle_root: [0; 32],
            payload_kind,
        };
        edit(&mut h);
        let mut prefix = vec![0u8; HEADER_LEN + payload.len().div_ceil(4096) * LEAF_LEN + 2 + 64];
        let n = build_prefix(&mut h, payload, &mut prefix, |d| {
            let sig = ed25519_compact::KeyPair::from_seed(ed25519_compact::Seed::new(SEED)).sk.sign(d, None);
            let mut out = [0u8; MAX_SIG];
            out[..64].copy_from_slice(sig.as_ref());
            Some((out, 64))
        })
        .unwrap();
        prefix.truncate(n);
        prefix
    }

    /// The device side: every segment read into its place and verified there.
    fn load<'p>(prefix: &'p [u8], file: &[u8], region: &mut Vec<u8>) -> Loader<'p> {
        let mut l = Loader::open(prefix, &dev()).unwrap();
        *region = vec![0u8; file.len()];
        for i in 0..l.header().n_segments {
            let (s, e) = (i as usize * 4096, ((i as usize + 1) * 4096).min(file.len()));
            region[s..e].copy_from_slice(&file[s..e]);
            l.accept_in_place(i, region).unwrap();
        }
        l
    }

    fn flat_rope() -> Vec<(i32, i32)> {
        vec![(1 << 30, 0); CTX * 16]
    }

    fn first_tokens(g: &neuro_gguf::Gguf, h: &neuro_gguf::qwen3::Hparams, rope: &[(i32, i32)]) -> Vec<usize> {
        let d = h.dims;
        let layers = vec![layer(g, h, 0).unwrap()];
        let m = model(g, h, &layers, rope).unwrap();
        let (kvn, kvs) = d.kv_len();
        let (mut vals, mut shifts) = (vec![0i16; kvn], vec![0u8; kvs]);
        let (a, b, c, e) = Work::lens(&d, 1);
        let (mut wa, mut wb, mut wc, mut we) = (vec![0i64; a], vec![0i8; b], vec![(0, 0); c], vec![0i32; e]);
        let mut work = Work::new(&d, 1, &mut wa, &mut wb, &mut wc, &mut we).unwrap();
        let mut kv = Kv { vals: &mut vals, shifts: &mut shifts };
        let mut out = vec![];
        let mut tok = 1usize;
        for pos in 0..CTX {
            tok = m.step(Simd::SCALAR, tok, pos, &mut kv, &mut work).unwrap();
            out.push(tok);
        }
        out
    }

    #[test]
    fn a_signed_language_model_loads_and_runs() {
        let file = qwen3_file("qwen3", tt::Q8_0, 64);
        let prefix = pack(&file, |_| {});
        let mut region = vec![];
        let l = load(&prefix, &file, &mut region);
        assert!(l.header().n_segments >= 2, "more than one segment");
        let ad = admit(&l, &region).unwrap();
        assert!(ad.bundle.is_none(), "a bare GGUF payload carries no tables");
        let (g, h) = (ad.gguf, ad.hparams);
        assert_eq!((h.dims.max_ctx, h.dims.vocab), (CTX, 4));
        // The engine runs from the verified region exactly as from the file.
        let direct = neuro_gguf::Gguf::open(&file).unwrap();
        let hd = neuro_gguf::qwen3::hparams(&direct, CTX).unwrap();
        assert_eq!(first_tokens(&g, &h, &flat_rope()), first_tokens(&direct, &hd, &flat_rope()));
        // The specialist path refuses a language model, and the other way round.
        assert_eq!(l.finish(&region).err(), Some(Refusal::Kind));
    }

    #[test]
    fn the_manifest_cannot_lie_and_the_file_cannot_change() {
        let file = qwen3_file("qwen3", tt::Q8_0, 64);
        // Each field admission reserves by, under-declared by the signer: refused when the file is opened.
        let lies: [fn(&mut Header); 4] =
            [|h| h.manifest.arena_bytes -= 1, |h| h.manifest.state_bytes_per_session -= 1, |h| h.manifest.bytes_per_token -= 1, |h| h.manifest.max_sessions = 2];
        for lie in lies {
            let prefix = pack(&file, lie);
            let mut region = vec![];
            let l = load(&prefix, &file, &mut region);
            assert_eq!(admit(&l, &region).err(), Some(AdmitError::ManifestMismatch));
        }
        // A context beyond what the model was trained for, and a payload that is not this architecture.
        let prefix = pack(&file, |h| h.manifest.max_context = 65);
        let mut region = vec![];
        let l = load(&prefix, &file, &mut region);
        assert!(matches!(admit(&l, &region), Err(AdmitError::Bind(_))));
        let other = qwen3_file("llama", tt::Q8_0, 64);
        assert!(matches!(manifest_for(&other, CTX), Err(AdmitError::Bind(_))));

        // Not every segment yet; a changed byte; a container of the other kind.
        let prefix = pack(&file, |_| {});
        let mut l = Loader::open(&prefix, &dev()).unwrap();
        let mut region = file.clone();
        l.accept_in_place(0, &region).unwrap();
        assert_eq!(admit(&l, &region).err(), Some(AdmitError::Container(Refusal::Incomplete)));
        region[4096 + 7] ^= 1;
        assert_eq!(l.accept_in_place(1, &region), Err(Refusal::SegmentHash(1)));
        assert_eq!(admit(&l, &region).err(), Some(AdmitError::Container(Refusal::Failed)));
        l.abort(&mut region);
        assert!(region.iter().all(|b| *b == 0));

        let as_engine = pack(&file, |h| h.payload_kind = kind::ENGINE);
        let mut region = vec![];
        let l = load(&as_engine, &file, &mut region);
        assert_eq!(admit(&l, &region).err(), Some(AdmitError::Container(Refusal::Kind)));
        assert!(matches!(l.finish(&region), Err(Refusal::Engine(_))), "a GGUF file is not an engine package");

        // A wrong key, and an unknown kind byte.
        let mut forged = pack(&file, |_| {});
        let n = forged.len();
        forged[n - 1] ^= 1;
        assert_eq!(Loader::open(&forged, &dev()).err(), Some(Refusal::Signature));
        let mut unknown = pack(&file, |_| {});
        unknown[208] = 7;
        assert_eq!(Loader::open(&unknown, &dev()).err(), Some(Refusal::Kind));
    }

    // ---------------------------------------------------------------------------------------- the bundle

    use neuro_gguf::bundle::{self, Bundle, BundleError};
    use neuro_gguf::hnx::manifest_for_bundle;
    use neuro_lm::tok::Tokenizer;

    fn tok_blob(vocab: usize) -> Vec<u8> {
        // Every byte is a token; beyond 256, merged pairs.
        let mut tokens: Vec<Vec<u8>> = (0..=255u8).map(|b| vec![b]).collect();
        let mut merges = vec![];
        for i in 256..vocab {
            let (l, r) = (b'a' as u32, b'a' as u32 + (i - 255) as u32);
            tokens.push(vec![l as u8, r as u8]);
            merges.push((l, r));
        }
        tok_build::blob(&tok_build::Source { tokens, merges, added: vec![] }, &tok_build::unicode_ranges(), &tok_build::nfc_tables()).unwrap()
    }

    /// A rotation table with distinct values, so a wrong or shifted table changes the output.
    fn turned_rope(rows: usize) -> Vec<(i32, i32)> {
        (0..rows).map(|i| if i % 3 == 0 { (0, 1 << 30) } else { (1 << 30, 0) }).collect()
    }

    fn rope_bytes(t: &[(i32, i32)]) -> Vec<u8> {
        t.iter().flat_map(|(c, s)| [c.to_le_bytes(), s.to_le_bytes()].concat()).collect()
    }

    /// The build side of a bundle whose model file carries the matrices.
    fn bundle_of(file: &[u8], tok: &[u8], rope: &[u8]) -> Vec<u8> {
        tok_build::bundle([file, tok, rope, &[]]).unwrap()
    }

    #[test]
    fn a_signed_bundle_runs_with_nothing_derived_on_the_device() {
        let file = qwen3_file_v("qwen3", tt::Q8_0, 64, 256);
        let rope = turned_rope(CTX * 16);
        let b = bundle_of(&file, &tok_blob(256), &rope_bytes(&rope));
        // Every section starts on a cache line, so GGUF's own tensor alignment survives inside the bundle.
        let (offs, total) = bundle::layout([file.len(), tok_blob(256).len(), rope.len() * 8, 0]).unwrap();
        assert!(offs.iter().all(|o| o % 64 == 0) && total == b.len());

        let prefix = pack_as(&b, kind::LM_BUNDLE, manifest_for_bundle(&b, CTX).unwrap(), |_| {});
        let mut region = vec![];
        let l = load(&prefix, &b, &mut region);
        let ad = admit(&l, &region).unwrap();
        let tables = ad.bundle.expect("a bundle carries its tables");
        // The tokenizer is read where it lies; the rotation table is copied into the server's arena.
        let tok = Tokenizer::new(tables.tokenizer).unwrap();
        assert_eq!((tok.vocab(), tok.bytes(99)), (256, Some(&b"c"[..])));
        let mut arena = vec![(0i32, 0i32); tables.rope_pairs()];
        tables.rope_into(&mut arena).unwrap();
        assert_eq!(arena, rope);
        assert!(tables.rope_into(&mut vec![(0, 0); 3]).is_none());
        // The engine gives the tokens it gives from the plain file with the same table, and other tokens with
        // another table: the bundled table is the one in use.
        let direct = neuro_gguf::Gguf::open(&file).unwrap();
        let hd = neuro_gguf::qwen3::hparams(&direct, CTX).unwrap();
        assert_eq!(first_tokens(&ad.gguf, &ad.hparams, &arena), first_tokens(&direct, &hd, &rope));
        // The specialist path refuses it.
        assert_eq!(l.finish(&region).err(), Some(Refusal::Kind));
    }

    #[test]
    fn bundle_tables_must_fit_the_model_and_the_layout_is_exact() {
        let file = qwen3_file_v("qwen3", tt::Q8_0, 64, 256);
        let rope = rope_bytes(&turned_rope(CTX * 16));
        let admit_err = |b: &[u8]| {
            let prefix = pack_as(b, kind::LM_BUNDLE, manifest_for_bundle(b, CTX).unwrap(), |_| {});
            let mut region = vec![];
            let l = load(&prefix, b, &mut region);
            admit(&l, &region).err()
        };
        // Tables for another context, another vocabulary, or no tokenizer at all.
        assert_eq!(admit_err(&bundle_of(&file, &tok_blob(256), &rope[..rope.len() - 8])), Some(AdmitError::Tables));
        assert_eq!(admit_err(&bundle_of(&file, &tok_blob(257), &rope)), Some(AdmitError::Tables));
        assert_eq!(admit_err(&bundle_of(&file, b"not a tokenizer", &rope)), Some(AdmitError::Tables));
        // The manifest is still recomputed from the model inside.
        let good = bundle_of(&file, &tok_blob(256), &rope);
        let prefix = pack_as(&good, kind::LM_BUNDLE, manifest_for_bundle(&good, CTX).unwrap(), |h| h.manifest.state_bytes_per_session -= 1);
        let mut region = vec![];
        let l = load(&prefix, &good, &mut region);
        assert_eq!(admit(&l, &region).err(), Some(AdmitError::ManifestMismatch));

        // The layout: the offsets are the ones the lengths give, every other field is zero, nothing is left over.
        assert!(Bundle::open(&good).is_ok());
        let pad_at = bundle::PREAMBLE + file.len(); // first padding byte after the model, if any
        let mut cases: Vec<(Vec<u8>, BundleError)> = vec![];
        let mut edit = |f: &dyn Fn(&mut Vec<u8>), e| {
            let mut c = good.clone();
            f(&mut c);
            cases.push((c, e));
        };
        edit(&|c| c[0] = b'G', BundleError::Magic);
        edit(&|c| c[4] = 2, BundleError::Version);
        edit(&|c| c[6] = 3, BundleError::Layout); // three sections
        edit(&|c| c[16] = 2, BundleError::Layout); // first section is not the model
        edit(&|c| c[20] = 1, BundleError::Layout); // a reserved field
        edit(&|c| c[24] += 64, BundleError::Layout); // an offset that is not the canonical one
        edit(&|c| c[33] += 1, BundleError::Layout); // a length the rest does not match (256 bytes more)
        edit(&|c| c.push(0), BundleError::Layout); // something after the last section
        edit(&|c| c.truncate(c.len() - 8), BundleError::Layout);
        edit(&|c| c.truncate(40), BundleError::Length);
        if file.len() % 64 != 0 {
            edit(&|c| c[pad_at] = 1, BundleError::Layout); // padding that is not zero
        }
        for (c, want) in &cases {
            assert_eq!(Bundle::open(c).err(), Some(*want));
        }
        // A rotation table that is not whole pairs.
        assert_eq!(Bundle::open(&bundle_of(&file, &tok_blob(256), &rope[..rope.len() - 3])).err(), Some(BundleError::Layout));

        // The wrong label in either direction is refused when the payload is opened.
        let as_bare = pack_as(&good, kind::GGUF_LM, manifest_for_bundle(&good, CTX).unwrap(), |_| {});
        let mut region = vec![];
        let l = load(&as_bare, &good, &mut region);
        assert!(matches!(admit(&l, &region).err(), Some(AdmitError::Gguf(_))));
        let as_bundle = pack_as(&file, kind::LM_BUNDLE, manifest_for(&file, CTX).unwrap(), |_| {});
        let l = load(&as_bundle, &file, &mut region);
        assert_eq!(admit(&l, &region).err(), Some(AdmitError::Bundle(BundleError::Magic)));
    }

    // ---------------------------------------------------------------------------------------- P0: the session

    use neuro_gguf::p0::{self, Mem, P0Error, Progress, Session};
    use neuro_lm::qwen3::Layer;

    /// Owned memory for one session, sized by `p0::sizes` plus `slack` elements each.
    struct Owned {
        layers: Vec<Layer<'static>>,
        rope: Vec<(i32, i32)>,
        kv_vals: Vec<i16>,
        kv_shifts: Vec<u8>,
        wa: Vec<i64>,
        wb: Vec<i8>,
        wc: Vec<(i32, i32)>,
        we: Vec<i32>,
        ids: Vec<u32>,
        prev: Vec<u32>,
    }

    fn owned(z: &p0::Sizes) -> Owned {
        Owned {
            layers: vec![Layer::EMPTY; z.layers],
            rope: vec![(0, 0); z.rope],
            kv_vals: vec![0; z.kv_vals],
            kv_shifts: vec![0; z.kv_shifts],
            wa: vec![0; z.work_i64],
            wb: vec![0; z.work_i8],
            wc: vec![(0, 0); z.work_pairs],
            we: vec![0; z.work_i32],
            ids: vec![0; z.ids],
            prev: vec![0; z.prev],
        }
    }

    fn mem<'a>(o: &'a mut Owned) -> Mem<'a> {
        Mem { layers: layer_table(o.layers.len()), rope: &mut o.rope, kv_vals: &mut o.kv_vals, kv_shifts: &mut o.kv_shifts, work_i64: &mut o.wa, work_i8: &mut o.wb, work_pairs: &mut o.wc, work_i32: &mut o.we, ids: &mut o.ids, prev: &mut o.prev, list: &mut [], out: &mut [] }
    }

    /// A layer table of the borrow's lifetime. (A `&mut [Layer<'static>]` cannot be lent as `&mut [Layer<'a>]`:
    /// a mutable slice is invariant. A test may leak; a device has one table for its lifetime.)
    fn layer_table<'a>(n: usize) -> &'a mut [Layer<'a>] {
        Box::leak(vec![Layer::EMPTY; n].into_boxed_slice())
    }

    #[test]
    fn a_session_advances_one_pass_at_a_time_and_equals_generate() {
        let file = qwen3_file_v("qwen3", tt::Q8_0, 64, 256);
        let rope = turned_rope(CTX * 16);
        let b = bundle_of(&file, &tok_blob(256), &rope_bytes(&rope));
        let prefix = pack_as(&b, kind::LM_BUNDLE, manifest_for_bundle(&b, CTX).unwrap(), |_| {});
        let mut region = vec![];
        let l = load(&prefix, &b, &mut region);
        let ad = admit(&l, &region).unwrap();
        let prompt: [u32; 5] = [72, 101, 108, 108, 111];

        // The reference: the whole answer in one call.
        let want = {
            let d = ad.hparams.dims;
            let layers = vec![layer(&ad.gguf, &ad.hparams, 0).unwrap()];
            let m = model(&ad.gguf, &ad.hparams, &layers, &rope).unwrap();
            let (kvn, kvs) = d.kv_len();
            let (mut vals, mut shifts) = (vec![0i16; kvn], vec![0u8; kvs]);
            let (a, bb, c, e) = Work::lens(&d, 1);
            let (mut wa, mut wb, mut wc, mut we) = (vec![0i64; a], vec![0i8; bb], vec![(0, 0); c], vec![0i32; e]);
            let mut work = Work::new(&d, 1, &mut wa, &mut wb, &mut wc, &mut we).unwrap();
            let mut out = vec![0u32; CTX - prompt.len()];
            let n = m.generate(Simd::SCALAR, &prompt, &[], &mut Kv { vals: &mut vals, shifts: &mut shifts }, &mut work, &mut out).unwrap();
            out.truncate(n);
            out
        };
        assert_eq!(want.len(), CTX - prompt.len());

        for batch in [1usize, 2, 4, 16] {
            let z = p0::sizes(&ad.hparams, batch);
            let mut o = owned(&z);
            let mut s = Session::open(&ad, Simd::SCALAR, batch, mem(&mut o)).unwrap();
            assert_eq!(s.advance().err(), Some(P0Error::NotStarted));
            assert_eq!(s.start_ids(&prompt), Ok(5));
            // The prompt goes in ceil(5 / batch) passes, then one pass per token.
            let (mut prefills, mut tokens, mut passes) = (0, vec![], 0);
            loop {
                passes += 1;
                match s.advance().unwrap() {
                    Progress::Prefill { fed, total } => {
                        prefills += 1;
                        assert_eq!((total, fed), (5, (prefills * batch).min(5)));
                        assert!(tokens.is_empty());
                    }
                    Progress::Token { id, last } => {
                        tokens.push(id);
                        if last {
                            break;
                        }
                    }
                    Progress::Tokens { .. } => panic!("a contract pass in a plain job"),
                    Progress::Done => panic!("done before a last token"),
                }
            }
            assert_eq!(prefills, 5usize.div_ceil(batch));
            assert_eq!(tokens, want, "batch {batch}");
            assert_eq!(s.answer(), &want[..]);
            assert_eq!(passes, prefills + want.len());
            assert_eq!(s.advance(), Ok(Progress::Done));
            // A second job with the same prompt: the KV cache already holds all of it but the last token, which
            // is fed again for its logits. One prompt pass, and the same answer.
            assert_eq!(s.reused(), 0, "the first job had nothing to reuse");
            s.start_ids(&prompt).unwrap();
            assert_eq!(s.reused(), prompt.len() - 1);
            assert_eq!(s.advance(), Ok(Progress::Prefill { fed: 5, total: 5 }));
            let mut again = vec![];
            while let Progress::Token { id, last } = s.advance().unwrap() {
                again.push(id);
                if last {
                    break;
                }
            }
            assert_eq!(again, want, "batch {batch}");
            // A cancelled job stops and keeps what it produced.
            s.start_ids(&prompt).unwrap();
            s.advance().unwrap();
            s.advance().unwrap();
            s.cancel();
            assert_eq!(s.advance(), Ok(Progress::Done));
            assert_eq!(s.answer(), &want[..1]);
            let mut text = [0u8; 64];
            assert_eq!(s.answer_text(&mut text).unwrap(), 1);
        }
    }

    #[test]
    fn a_shared_prompt_prefix_is_not_fed_twice_and_the_answer_is_the_same() {
        let file = qwen3_file_v("qwen3", tt::Q8_0, 64, 256);
        let rope = turned_rope(CTX * 16);
        let b = bundle_of(&file, &tok_blob(256), &rope_bytes(&rope));
        let prefix = pack_as(&b, kind::LM_BUNDLE, manifest_for_bundle(&b, CTX).unwrap(), |_| {});
        let mut region = vec![];
        let l = load(&prefix, &b, &mut region);
        let ad = admit(&l, &region).unwrap();
        let z = p0::sizes(&ad.hparams, 2);
        let run = |s: &mut Session, prompt: &[u32]| -> (Vec<u32>, usize, usize) {
            s.start_ids(prompt).unwrap();
            let (mut passes, mut out) = (0usize, vec![]);
            loop {
                match s.advance().unwrap() {
                    Progress::Prefill { .. } => passes += 1,
                    Progress::Token { id, last } => {
                        out.push(id);
                        if last {
                            break;
                        }
                    }
                    other => panic!("{other:?}"),
                }
            }
            (out, passes, s.reused())
        };
        // What a fresh session answers to each prompt.
        let prompts: [&[u32]; 5] = [&[10, 20, 30, 40, 50], &[10, 20, 30, 41, 51, 61], &[10, 20, 30, 41], &[99, 20, 30], &[10, 20, 30, 41, 51, 61]];
        let fresh: Vec<Vec<u32>> = prompts
            .iter()
            .map(|p| {
                let mut o = owned(&z);
                let mut s = Session::open(&ad, Simd::SCALAR, 2, mem(&mut o)).unwrap();
                run(&mut s, p).0
            })
            .collect();
        // One session, the jobs one after another: the same answers, with the shared leading tokens reused.
        let mut o = owned(&z);
        let mut s = Session::open(&ad, Simd::SCALAR, 2, mem(&mut o)).unwrap();
        let want_reused = [0usize, 3, 3, 0, 0];
        for (k, p) in prompts.iter().enumerate() {
            let (out, passes, reused) = run(&mut s, p);
            assert_eq!(out, fresh[k], "job {k}");
            assert_eq!(reused, want_reused[k], "job {k}");
            assert_eq!(passes, (p.len() - reused).div_ceil(2), "job {k}: only the tokens that were not reused are fed");
        }
        // The answer of a job is in the cache too: a prompt that continues it reuses those positions.
        let mut longer = prompts[4].to_vec();
        longer.push(fresh[4][0]);
        assert_eq!(longer.len(), 7);
        let (_, _, reused) = run(&mut s, &longer);
        assert_eq!(reused, 6);
        // Without the `prev` slice nothing is reused, and the answers are still the same.
        let mut o = owned(&z);
        let mut m = mem(&mut o);
        m.prev = &mut [];
        let mut s = Session::open(&ad, Simd::SCALAR, 2, m).unwrap();
        for (k, p) in prompts.iter().enumerate() {
            let (out, _, reused) = run(&mut s, p);
            assert_eq!((out, reused), (fresh[k].clone(), 0), "job {k}");
        }
    }

    #[test]
    fn a_session_takes_exactly_the_memory_it_asks_for() {
        let file = qwen3_file_v("qwen3", tt::Q8_0, 64, 256);
        let rope = rope_bytes(&turned_rope(CTX * 16));
        let b = bundle_of(&file, &tok_blob(256), &rope);
        let prefix = pack_as(&b, kind::LM_BUNDLE, manifest_for_bundle(&b, CTX).unwrap(), |_| {});
        let mut region = vec![];
        let l = load(&prefix, &b, &mut region);
        let ad = admit(&l, &region).unwrap();
        let z = p0::sizes(&ad.hparams, 2);
        // What admission reserved covers what the session takes (the manifest counts the largest batch).
        let man = l.header().manifest;
        let state = z.kv_vals * 2 + z.kv_shifts;
        assert_eq!(state as u32, man.state_bytes_per_session);
        assert!(z.rope * 8 + z.work_i64 * 8 + z.work_i8 + z.work_pairs * 8 + z.work_i32 * 4 <= man.arena_bytes as usize);
        assert!(z.bytes() > state);
        // One element short in any slice: refused, nothing half-bound.
        let shrink: [fn(&mut Owned); 9] = [
            |o| o.layers.truncate(o.layers.len() - 1),
            |o| o.rope.truncate(o.rope.len() - 1),
            |o| o.kv_vals.truncate(o.kv_vals.len() - 1),
            |o| o.kv_shifts.truncate(o.kv_shifts.len() - 1),
            |o| o.wa.truncate(o.wa.len() - 1),
            |o| o.wb.truncate(o.wb.len() - 1),
            |o| o.wc.truncate(o.wc.len() - 1),
            |o| o.we.truncate(o.we.len() - 1),
            |o| o.ids.truncate(o.ids.len() - 1),
        ];
        for f in shrink {
            let mut o = owned(&z);
            f(&mut o);
            assert_eq!(Session::open(&ad, Simd::SCALAR, 2, mem(&mut o)).err(), Some(P0Error::Mem));
        }
        for batch in [0usize, 17] {
            let mut o = owned(&p0::sizes(&ad.hparams, 16));
            assert_eq!(Session::open(&ad, Simd::SCALAR, batch, mem(&mut o)).err(), Some(P0Error::Mem));
        }
        // A prompt that is empty, or leaves no room for an answer.
        let mut o = owned(&z);
        let mut s = Session::open(&ad, Simd::SCALAR, 2, mem(&mut o)).unwrap();
        assert_eq!(s.start_ids(&[]).err(), Some(P0Error::Prompt));
        assert_eq!(s.start_ids(&[1; CTX]).err(), Some(P0Error::Prompt));
        assert_eq!(s.start_ids(&[1; CTX - 1]), Ok(CTX - 1));

        // A bare GGUF payload has no tables: the device cannot run it.
        let bare = pack(&file, |_| {});
        let mut region2 = vec![];
        let l2 = load(&bare, &file, &mut region2);
        let ad2 = admit(&l2, &region2).unwrap();
        let mut o = owned(&z);
        assert_eq!(Session::open(&ad2, Simd::SCALAR, 2, mem(&mut o)).err(), Some(P0Error::NoTables));
    }

    #[test]
    fn a_session_under_the_contract_equals_generate_closed() {
        use neuro_contract::{context_ids, Allowed, IdList, Machine};
        use neuro_lm::decode::{generate_closed, Options};
        let file = qwen3_file_v("qwen3", tt::Q8_0, 64, 256);
        let rope = turned_rope(CTX * 16);
        let b = bundle_of(&file, &tok_blob(256), &rope_bytes(&rope));
        let prefix = pack_as(&b, kind::LM_BUNDLE, manifest_for_bundle(&b, CTX).unwrap(), |_| {});
        let mut region = vec![];
        let l = load(&prefix, &b, &mut region);
        let ad = admit(&l, &region).unwrap();
        let (facts, ents): (&'static mut IdList, &'static mut IdList) = (Box::leak(Box::new(IdList::new())), Box::leak(Box::new(IdList::new())));
        context_ids(b"F1 H1->R1:443 n=3", facts, ents).unwrap();
        let (facts, ents): (&'static IdList, &'static IdList) = (facts, ents);
        let machine = || Machine::new(Allowed { facts, entities: ents, closed: true });
        let prompt = b"hi";

        for (opts, batch) in [(Options { prune_max: 0, draft_max: 0, max_new: 6 }, 1usize), (Options { prune_max: 64, draft_max: 0, max_new: 6 }, 2), (Options { prune_max: 64, draft_max: 3, max_new: 5 }, 4)] {
            // The reference: the whole answer in one call, on the model bound by hand.
            let d = ad.hparams.dims;
            let layers = vec![layer(&ad.gguf, &ad.hparams, 0).unwrap()];
            let m = model(&ad.gguf, &ad.hparams, &layers, &rope).unwrap();
            let tb = tok_blob(256);
            let tok = Tokenizer::new(&tb).unwrap();
            let mut ids = [0u32; 8];
            let np = tok.encode(prompt, &mut ids).unwrap();
            let (kvn, kvs) = d.kv_len();
            let (mut vals, mut shifts) = (vec![0i16; kvn], vec![0u8; kvs]);
            let (a, bb, c, e) = Work::lens(&d, batch);
            let (mut wa, mut wb, mut wc, mut we) = (vec![0i64; a], vec![0i8; bb], vec![(0, 0); c], vec![0i32; e]);
            let mut work = Work::new(&d, batch, &mut wa, &mut wb, &mut wc, &mut we).unwrap();
            let (mut hist, mut list, mut out) = (vec![0u32; CTX], vec![0u32; 64], vec![0u32; opts.max_new]);
            let (n, st) = generate_closed(&m, Simd::SCALAR, &tok, &ids[..np], &[], machine(), &mut Kv { vals: &mut vals, shifts: &mut shifts }, &mut work, &mut hist, &mut list, opts, &mut out).unwrap();
            assert_eq!(n, opts.max_new, "no end token in this vocabulary: the answer runs to its bound");

            let z = p0::sizes(&ad.hparams, batch);
            let mut o = owned(&z);
            let (mut slist, mut sout) = (vec![0u32; 64], vec![0u32; opts.max_new]);
            let mut sm = mem(&mut o);
            (sm.list, sm.out) = (&mut slist, &mut sout);
            let mut s = Session::open(&ad, Simd::SCALAR, batch, sm).unwrap();
            let (mut cps, mut buf) = (vec![0u32; 64], vec![0u8; 64]);
            assert_eq!(s.start_closed(prompt, &mut cps, &mut buf, machine(), opts), Ok(np));
            let (mut passes, mut got) = (0u32, 0usize);
            loop {
                match s.advance().unwrap() {
                    Progress::Prefill { .. } => {}
                    Progress::Tokens { count } => got += count,
                    Progress::Token { .. } => panic!("a plain token in a job under the contract"),
                    Progress::Done => break,
                }
                passes += 1;
            }
            assert_eq!(s.answer(), &out[..n], "{opts:?} batch {batch}");
            assert_eq!((got, s.closed_stats()), (n, Some(st)));
            assert!(passes >= st.prefill_passes + st.passes && passes <= st.prefill_passes + st.passes + 1);
        }
        // No room for an answer under the contract without the caller's `out`.
        let z = p0::sizes(&ad.hparams, 1);
        let mut o = owned(&z);
        let mut s = Session::open(&ad, Simd::SCALAR, 1, mem(&mut o)).unwrap();
        let (mut cps, mut buf) = (vec![0u32; 64], vec![0u8; 64]);
        assert_eq!(s.start_closed(prompt, &mut cps, &mut buf, machine(), Options { prune_max: 0, draft_max: 0, max_new: 4 }).err(), Some(P0Error::Mem));
    }

    // ---------------------------------------------------------------------------------------- packed weights

    #[test]
    fn a_packed_bundle_gives_the_same_tokens_and_keeps_no_matrices_in_the_file() {
        let file = qwen3_file_v("qwen3", tt::Q8_0, 64, 256);
        let rope = turned_rope(CTX * 16);
        let g = neuro_gguf::Gguf::open(&file).unwrap();
        let h = neuro_gguf::qwen3::hparams(&g, CTX).unwrap();
        let (packed, skeleton) = tok_build::packed_parts(&g, &h).unwrap();
        assert_eq!(Some(packed.len()), neuro_gguf::qwen3::packed_len(&h));
        // The file that is left has the metadata and the norm vectors, and none of the eight matrices.
        let sk = neuro_gguf::Gguf::open(&skeleton).unwrap();
        assert_eq!(sk.kv_count(), g.kv_count());
        assert_eq!(sk.tensor_count(), g.tensor_count() - 8);
        assert!(sk.tensor(b"token_embd.weight").is_none() && sk.tensor(b"blk.0.ffn_down.weight").is_none() && sk.tensor(b"blk.0.attn_norm.weight").is_some());
        assert!(skeleton.len() < file.len() / 2);

        let prompt: [u32; 5] = [72, 101, 108, 108, 111];
        let answer = |bytes: &[u8]| -> Vec<u32> {
            let prefix = pack_as(bytes, kind::LM_BUNDLE, manifest_for_bundle(bytes, CTX).unwrap(), |_| {});
            let mut region = vec![];
            let l = load(&prefix, bytes, &mut region);
            let ad = admit(&l, &region).unwrap();
            let z = p0::sizes(&ad.hparams, 2);
            let mut o = owned(&z);
            let mut s = Session::open(&ad, Simd::SCALAR, 2, mem(&mut o)).unwrap();
            s.start_ids(&prompt).unwrap();
            while s.advance().unwrap() != Progress::Done {}
            s.answer().to_vec()
        };
        let tok = tok_blob(256);
        let unpacked = bundle_of(&file, &tok, &rope_bytes(&rope));
        let packed_bundle = tok_build::bundle([&skeleton, &tok, &rope_bytes(&rope), &packed]).unwrap();
        let want = answer(&unpacked);
        assert_eq!(want.len(), CTX - prompt.len());
        assert_eq!(answer(&packed_bundle), want, "the packed layout computes the same numbers");
        // The manifest counts what a token reads: here the packed matrices and the norms left in the file.
        let (m_un, m_pk) = (manifest_for_bundle(&unpacked, CTX).unwrap(), manifest_for_bundle(&packed_bundle, CTX).unwrap());
        assert_eq!((m_un.state_bytes_per_session, m_un.arena_bytes), (m_pk.state_bytes_per_session, m_pk.arena_bytes));
        assert!(m_pk.bytes_per_token >= packed.len() as u64);

        // A packed section that is not exactly this model's matrices is refused at admission, and a file with no
        // matrices and no packed section cannot be bound.
        let admit_err = |bytes: &[u8]| {
            let prefix = pack_as(bytes, kind::LM_BUNDLE, manifest_for_bundle(bytes, CTX).unwrap(), |_| {});
            let mut region = vec![];
            let l = load(&prefix, bytes, &mut region);
            admit(&l, &region).err()
        };
        let short = tok_build::bundle([&skeleton, &tok, &rope_bytes(&rope), &packed[..packed.len() - 64]]).unwrap();
        assert_eq!(admit_err(&short), Some(AdmitError::Tables));
        let mut longer = packed.clone();
        longer.extend_from_slice(&[0; 64]);
        assert_eq!(admit_err(&tok_build::bundle([&skeleton, &tok, &rope_bytes(&rope), &longer]).unwrap()), Some(AdmitError::Tables));
        let none = tok_build::bundle([&skeleton, &tok, &rope_bytes(&rope), &[]]).unwrap();
        let prefix = pack_as(&none, kind::LM_BUNDLE, manifest_for_bundle(&none, CTX).unwrap(), |_| {});
        let mut region = vec![];
        let l = load(&prefix, &none, &mut region);
        let ad = admit(&l, &region).unwrap();
        let z = p0::sizes(&ad.hparams, 2);
        let mut o = owned(&z);
        assert!(matches!(Session::open(&ad, Simd::SCALAR, 2, mem(&mut o)).err(), Some(P0Error::Bind(_))));
    }
}
