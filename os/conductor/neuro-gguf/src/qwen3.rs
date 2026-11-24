// SPDX-License-Identifier: AGPL-3.0-only
//! Bind a Qwen3 GGUF (as llama.cpp writes it) to `neuro_lm::qwen3`.
//!
//! Every matrix must be `Q8_0`, every norm binary32, with exactly the shapes the hyperparameters imply;
//! anything else is refused (this engine runs what Neuro validated, never a silent conversion). The output
//! head is `output.weight` when present, else the token embedding (tied, as in Qwen3-1.7B).
//!
//! Not in the GGUF and supplied by the caller: the RoPE table (built on the build host from
//! `qwen3.rope.freq_base`, shipped in the signed package) and the context length to admit.

use crate::{tt, Gguf, Tensor};
use neuro_lm::qwen3::{Layer, Mat, Model};
use neuro_lm::Dims;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BindError {
    /// `general.architecture` is not `qwen3`.
    Arch,
    /// A required hyperparameter is missing or out of range.
    Param(&'static str),
    /// A required tensor is missing.
    Missing,
    /// A tensor has the wrong type or shape.
    Tensor,
    /// The decoder refused the assembled model.
    Check,
}

/// Hyperparameters read from the GGUF.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Hparams {
    pub dims: Dims,
    /// Context length the model was trained for (`qwen3.context_length`).
    pub train_ctx: usize,
    /// binary32 bits.
    pub rope_base: u32,
    pub eps: u32,
    /// Attention scale `1/sqrt(head_dim)` as binary32 bits, as llama.cpp computes it.
    pub kq_scale: u32,
}

fn param(g: &Gguf, key: &[u8], name: &'static str) -> Result<usize, BindError> {
    let v = g.get_uint(key).ok_or(BindError::Param(name))?;
    usize::try_from(v).ok().filter(|&v| v > 0 && v <= (1 << 24)).ok_or(BindError::Param(name))
}

/// Read and check the hyperparameters. `max_ctx` is the context the device admits (≤ train_ctx).
pub fn hparams(g: &Gguf, max_ctx: usize) -> Result<Hparams, BindError> {
    if g.get_str(b"general.architecture") != Some(b"qwen3") {
        return Err(BindError::Arch);
    }
    let d_model = param(g, b"qwen3.embedding_length", "embedding_length")?;
    let n_heads = param(g, b"qwen3.attention.head_count", "head_count")?;
    let n_kv_heads = param(g, b"qwen3.attention.head_count_kv", "head_count_kv")?;
    let head_dim = match g.get_uint(b"qwen3.attention.key_length") {
        Some(_) => param(g, b"qwen3.attention.key_length", "key_length")?,
        None => d_model / n_heads,
    };
    if let Some(v) = g.get_uint(b"qwen3.attention.value_length") {
        if v as usize != head_dim {
            return Err(BindError::Param("value_length"));
        }
    }
    let train_ctx = param(g, b"qwen3.context_length", "context_length")?;
    let vocab = match g.get_array(b"tokenizer.ggml.tokens") {
        Some(a) => usize::try_from(a.len).map_err(|_| BindError::Param("tokens"))?,
        None => param(g, b"qwen3.vocab_size", "vocab_size")?,
    };
    let dims = Dims {
        vocab,
        d_model,
        n_layers: param(g, b"qwen3.block_count", "block_count")?,
        n_heads,
        n_kv_heads,
        head_dim,
        ffn: param(g, b"qwen3.feed_forward_length", "feed_forward_length")?,
        max_ctx,
    };
    if max_ctx == 0 || max_ctx > train_ctx {
        return Err(BindError::Param("max_ctx"));
    }
    let rope_base = g.get_single(b"qwen3.rope.freq_base").ok_or(BindError::Param("rope.freq_base"))?;
    let eps = g.get_single(b"qwen3.attention.layer_norm_rms_epsilon").ok_or(BindError::Param("layer_norm_rms_epsilon"))?;
    Ok(Hparams { dims, train_ctx, rope_base, eps, kq_scale: inv_sqrt_bits(head_dim as u64) })
}

/// Round `m · 2^e` (m > 0) to the nearest binary32 (ties to even); `sticky` marks discarded nonzero bits
/// below `m`. Normal range only (enough for the values used here).
fn round_single(m: u128, e: i32, sticky: bool) -> u32 {
    let bits = 128 - m.leading_zeros() as i32;
    let shift = bits - 24;
    let (mut mant, mut exp) = if shift > 0 {
        let s = shift as u32;
        let keep = m >> s;
        let rem = m & ((1u128 << s) - 1);
        let half = 1u128 << (s - 1);
        let up = rem > half || (rem == half && (sticky || keep & 1 == 1));
        (keep + u128::from(up), e + shift)
    } else {
        (m << (-shift) as u32, e + shift)
    };
    if mant == 1 << 24 {
        mant >>= 1;
        exp += 1;
    }
    // value = mant · 2^exp with mant in [2^23, 2^24): biased exponent = exp + 23 + 127.
    let be = (exp + 150).clamp(1, 254) as u32;
    (be << 23) | (mant as u32 & 0x7f_ffff)
}

/// binary32 bits of `1.0f / sqrtf((float) n)`, computed exactly as IEEE does (two correctly rounded
/// operations) with integers only.
pub fn inv_sqrt_bits(n: u64) -> u32 {
    if n == 0 {
        return 0x7f80_0000;
    }
    // sqrt(n) correctly rounded: r = isqrt(n · 2^(2k)) with a sticky bit for inexactness.
    let k = 50u32;
    let v = u128::from(n) << (2 * k);
    let mut r = {
        let mut x = 1u128 << (128 - v.leading_zeros()).div_ceil(2);
        loop {
            let y = (x + v / x) / 2;
            if y >= x {
                break x;
            }
            x = y;
        }
    };
    while r * r > v {
        r -= 1;
    }
    let sq = round_single(r, -(k as i32), r * r != v);
    // s = mantissa · 2^exp
    let ms = u128::from((sq & 0x7f_ffff) | 0x80_0000);
    let es = ((sq >> 23) & 0xff) as i32 - 150;
    // 1/s = 2^(100 - es) / (ms · 2^100)
    let q = (1u128 << 100) / ms;
    let rem = (1u128 << 100) % ms;
    round_single(q, -100 - es, rem != 0)
}

fn mat<'a>(t: Option<Tensor<'a>>, rows: usize, cols: usize) -> Result<Mat<'a>, BindError> {
    let t = t.ok_or(BindError::Missing)?;
    if t.ty != tt::Q8_0 || t.matrix() != Some((rows, cols)) {
        return Err(BindError::Tensor);
    }
    Ok(Mat { rows, cols, w: t.data })
}

fn norm<'a>(t: Option<Tensor<'a>>, n: usize) -> Result<&'a [u8], BindError> {
    let t = t.ok_or(BindError::Missing)?;
    if t.ty != tt::F32 || t.n_dims != 1 || t.dims.first() != Some(&(n as u64)) {
        return Err(BindError::Tensor);
    }
    Ok(t.data)
}

/// Tensor name `blk.<i>.<suffix>` without allocation.
fn blk_name<'b>(buf: &'b mut [u8; 64], i: usize, suffix: &[u8]) -> &'b [u8] {
    let mut n = 0usize;
    let mut put = |b: &[u8], buf: &mut [u8; 64]| {
        for &c in b {
            if let Some(x) = buf.get_mut(n) {
                *x = c;
            }
            n += 1;
        }
    };
    put(b"blk.", buf);
    let mut digits = [0u8; 20];
    let (mut v, mut d) = (i, 0usize);
    loop {
        if let Some(x) = digits.get_mut(d) {
            *x = b'0' + (v % 10) as u8;
        }
        d += 1;
        v /= 10;
        if v == 0 {
            break;
        }
    }
    for j in (0..d).rev() {
        put(&[digits.get(j).copied().unwrap_or(b'0')], buf);
    }
    put(b".", buf);
    put(suffix, buf);
    buf.get(..n.min(64)).unwrap_or(&[])
}

/// Bind layer `i`.
pub fn layer<'a>(g: &Gguf<'a>, h: &Hparams, i: usize) -> Result<Layer<'a>, BindError> {
    let d = &h.dims;
    let (dm, qd, kvd) = (d.d_model, d.n_heads * d.head_dim, d.n_kv_heads * d.head_dim);
    let mut b = [0u8; 64];
    let mut t = |s: &[u8]| g.tensor(blk_name(&mut b, i, s));
    Ok(Layer {
        attn_norm: norm(t(b"attn_norm.weight"), dm)?,
        wq: mat(t(b"attn_q.weight"), qd, dm)?,
        wk: mat(t(b"attn_k.weight"), kvd, dm)?,
        wv: mat(t(b"attn_v.weight"), kvd, dm)?,
        wo: mat(t(b"attn_output.weight"), dm, qd)?,
        q_norm: norm(t(b"attn_q_norm.weight"), d.head_dim)?,
        k_norm: norm(t(b"attn_k_norm.weight"), d.head_dim)?,
        ffn_norm: norm(t(b"ffn_norm.weight"), dm)?,
        w_gate: mat(t(b"ffn_gate.weight"), d.ffn, dm)?,
        w_up: mat(t(b"ffn_up.weight"), d.ffn, dm)?,
        w_down: mat(t(b"ffn_down.weight"), dm, d.ffn)?,
    })
}

/// Assemble and check the whole model. `layers` must hold `layer(g, h, i)` for every block, in order.
pub fn model<'a>(g: &Gguf<'a>, h: &Hparams, layers: &'a [Layer<'a>], rope: &'a [(i32, i32)]) -> Result<Model<'a>, BindError> {
    let d = h.dims;
    let embed = mat(g.tensor(b"token_embd.weight"), d.vocab, d.d_model)?;
    let head = match g.tensor(b"output.weight") {
        Some(t) => Some(mat(Some(t), d.vocab, d.d_model)?),
        None => None,
    };
    let m = Model { dims: d, embed, layers, final_norm: norm(g.tensor(b"output_norm.weight"), d.d_model)?, head, rope, eps: h.eps, kq_scale: h.kq_scale };
    m.check().map_err(|_| BindError::Check)?;
    Ok(m)
}
