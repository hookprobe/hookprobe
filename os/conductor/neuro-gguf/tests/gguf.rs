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

#[test]
fn qwen3_binder_refuses_wrong_files() {
    // A minimal valid Qwen3 file: 1 layer, d 32, 1 head of 32, ffn 32, vocab 4.
    let q8 = |rows: usize, cols: usize| {
        let mut v = vec![];
        for _ in 0..rows * cols / 32 {
            v.extend_from_slice(&0x2000u16.to_le_bytes());
            v.extend_from_slice(&[1u8; 32]);
        }
        v
    };
    let one = |n: usize| 1.0f32.to_bits().to_le_bytes().repeat(n);
    let build = |arch: &str, q_ty: u32, ctx: u32| {
        let mut w = W::new();
        let mut toks = vt::STRING.to_le_bytes().to_vec();
        toks.extend_from_slice(&4u64.to_le_bytes());
        for t in ["a", "b", "c", "d"] {
            s(&mut toks, t.as_bytes());
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
            .tensor("token_embd.weight", tt::Q8_0, &[32, 4], &q8(4, 32))
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
    };
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
