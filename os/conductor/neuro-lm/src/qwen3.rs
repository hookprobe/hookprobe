// SPDX-License-Identifier: AGPL-3.0-only
//! Qwen3 decoder (the architecture of Neuro's explainer ftFg = Qwen3-1.7B fine-tune), integer only.
//!
//! Weights are borrowed in their GGUF form: matrices as `Q8_0` blocks ([`neuro_kernels::q8`]), norm gains
//! as binary32 bits. Hidden values are Q16 `i64` ([`neuro_kernels::hp`]). Per layer:
//!
//! ```text
//! x = RMSNorm(h) ; q,k,v = Wq x, Wk x, Wv x
//! q_h = RoPE_neox(RMSNorm_q(q_h)) ; k_g = RoPE_neox(RMSNorm_k(k_g))      (per-head QK-norm, Qwen3)
//! h += Wo · Attention(q, K, V)                                              (grouped-query, causal)
//! h += Wdown · (SiLU(Wgate RMSNorm(h)) ⊙ Wup RMSNorm(h))
//! ```
//! then the final RMSNorm and the output head (the token embedding when tied, as in Qwen3-1.7B).
//! No biases (Qwen3 has none). Every matrix input is quantised per block of 32 just before its GEMV,
//! as llama.cpp's CPU path does for `Q8_0`.

use crate::{Dims, LmError};
use neuro_kernels::hp;
use neuro_kernels::q8::{self, Act};
use neuro_kernels::Simd;

/// A `Q8_0` matrix, `rows × cols`: row-major blocks exactly as in GGUF, or the packed layout
/// (`neuro_kernels::q8::pack`, lossless, aligned, faster). Both compute the same numbers bit for bit.
#[derive(Clone, Copy, Debug)]
pub struct Mat<'a> {
    pub rows: usize,
    pub cols: usize,
    pub w: &'a [u8],
    pub packed: bool,
    /// Largest weight exponent (`q8::wexp_gguf` / `q8::wexp_packed`); `check()` verifies it.
    pub wexp: i32,
}

impl<'a> Mat<'a> {
    /// A GGUF-layout matrix (computes `wexp` with one pass over the scales).
    pub fn gguf(rows: usize, cols: usize, w: &'a [u8]) -> Self {
        Mat { rows, cols, w, packed: false, wexp: q8::wexp_gguf(w) }
    }

    fn ok(&self, rows: usize, cols: usize) -> bool {
        let shape = self.rows == rows && self.cols == cols && cols % q8::QK == 0 && cols <= q8::MAX_COLS;
        if self.packed {
            shape && q8::packed_valid(self.w, rows, cols) && self.wexp == q8::wexp_packed(self.w)
        } else {
            shape && rows.checked_mul(q8::row_bytes(cols)) == Some(self.w.len()) && q8::scales_finite(self.w) && self.wexp == q8::wexp_gguf(self.w)
        }
    }

    /// Pack this GGUF-layout matrix into `out` (`q8::packed_bytes(rows, cols)` bytes): the load-time step.
    pub fn pack_into<'b>(&self, out: &'b mut [u8]) -> Option<Mat<'b>> {
        if self.packed || !q8::pack(self.w, self.rows, self.cols, out) {
            return None;
        }
        Some(Mat { rows: self.rows, cols: self.cols, w: out, packed: true, wexp: self.wexp })
    }
}

#[derive(Clone, Copy, Debug)]
pub struct Layer<'a> {
    pub attn_norm: &'a [u8],
    pub wq: Mat<'a>,
    pub wk: Mat<'a>,
    pub wv: Mat<'a>,
    pub wo: Mat<'a>,
    /// head_dim gains, shared by every query head / every key head.
    pub q_norm: &'a [u8],
    pub k_norm: &'a [u8],
    pub ffn_norm: &'a [u8],
    pub w_gate: Mat<'a>,
    pub w_up: Mat<'a>,
    pub w_down: Mat<'a>,
}

#[derive(Clone, Copy, Debug)]
pub struct Model<'a> {
    pub dims: Dims,
    /// vocab × d_model.
    pub embed: Mat<'a>,
    pub layers: &'a [Layer<'a>],
    pub final_norm: &'a [u8],
    /// `None`: tied to the embedding.
    pub head: Option<Mat<'a>>,
    /// max_ctx × head_dim/2 `(cos, sin)` in Q30 (built on the build host from rope θ).
    pub rope: &'a [(i32, i32)],
    /// RMSNorm epsilon, binary32 bits.
    pub eps: u32,
    /// Attention score scale (1/sqrt(head_dim)), binary32 bits.
    pub kq_scale: u32,
}

/// Longest context the attention arithmetic is proven for (no i64 overflow).
pub const MAX_CTX: usize = 1 << 17;

/// The KV cache: values and per-vector shifts.
pub struct Kv<'a> {
    pub vals: &'a mut [i16],
    pub shifts: &'a mut [u8],
}

impl Dims {
    /// `(i16 values, u8 shifts)` the KV cache needs.
    pub fn kv_len(&self) -> (usize, usize) {
        let v = self.n_layers * self.n_kv_heads * 2 * self.max_ctx;
        (v * self.head_dim, v)
    }
}

/// Scratch for one decode step, carved from caller-supplied memory (no allocation).
pub struct Work<'a> {
    res: &'a mut [i64],
    xn: &'a mut [i64],
    q: &'a mut [i64],
    k: &'a mut [i64],
    v: &'a mut [i64],
    att: &'a mut [i64],
    gate: &'a mut [i64],
    up: &'a mut [i64],
    w: &'a mut [i64],
    pub logits: &'a mut [i64],
    xq: &'a mut [i8],
    xs: &'a mut [(i32, i32)],
    qq: &'a mut [i32],
}

fn carve<'a, T>(buf: &mut &'a mut [T], n: usize) -> Option<&'a mut [T]> {
    let b = core::mem::take(buf);
    if b.len() < n {
        return None;
    }
    let (a, rest) = b.split_at_mut(n);
    *buf = rest;
    Some(a)
}

impl<'a> Work<'a> {
    fn widest(d: &Dims) -> usize {
        d.d_model.max(d.n_heads * d.head_dim).max(d.ffn)
    }
    /// `(i64, i8, scale pairs, i32)` lengths [`Work::new`] needs for these dimensions.
    pub fn lens(d: &Dims) -> (usize, usize, usize, usize) {
        let (qd, kvd) = (d.n_heads * d.head_dim, d.n_kv_heads * d.head_dim);
        let vrows = d.vocab;
        (2 * d.d_model + 2 * qd + 2 * kvd + 2 * d.ffn + d.max_ctx + vrows, Self::widest(d), Self::widest(d) / q8::QK, d.head_dim)
    }
    pub fn new(d: &Dims, mut a: &'a mut [i64], mut b: &'a mut [i8], mut c: &'a mut [(i32, i32)], mut e: &'a mut [i32]) -> Option<Self> {
        let (qd, kvd) = (d.n_heads * d.head_dim, d.n_kv_heads * d.head_dim);
        let wide = Self::widest(d);
        Some(Self {
            res: carve(&mut a, d.d_model)?,
            xn: carve(&mut a, d.d_model)?,
            q: carve(&mut a, qd)?,
            att: carve(&mut a, qd)?,
            k: carve(&mut a, kvd)?,
            v: carve(&mut a, kvd)?,
            gate: carve(&mut a, d.ffn)?,
            up: carve(&mut a, d.ffn)?,
            w: carve(&mut a, d.max_ctx)?,
            logits: carve(&mut a, d.vocab)?,
            xq: carve(&mut b, wide)?,
            xs: carve(&mut c, wide / q8::QK)?,
            qq: carve(&mut e, d.head_dim)?,
        })
    }
}

fn gains_ok(g: &[u8], n: usize) -> bool {
    g.len() == 4 * n && (0..n).all(|i| hp::single_finite(hp::single_at(g, i)))
}

/// Quantise `x` into the shared activation buffers and run `m`, handing each row to `sink`.
fn gemv(simd: Simd, m: &Mat, x: &[i64], xq: &mut [i8], xs: &mut [(i32, i32)], sink: impl FnMut(usize, i64)) -> Result<(), LmError> {
    let n = x.len();
    let (q, s) = (xq.get_mut(..n).ok_or(LmError::Work)?, xs.get_mut(..n / q8::QK).ok_or(LmError::Work)?);
    if !q8::quantize(x, q, s) {
        return Err(LmError::Shape);
    }
    let act = Act { q, scale: s };
    let ran = if m.packed { q8::matvec_packed(simd, m.w, m.rows, &act, m.wexp, sink) } else { q8::matvec(simd, m.w, m.rows, &act, m.wexp, sink) };
    if ran {
        Ok(())
    } else {
        Err(LmError::Shape)
    }
}

fn into(out: &mut [i64]) -> impl FnMut(usize, i64) + '_ {
    |r, v| {
        if let Some(o) = out.get_mut(r) {
            *o = v;
        }
    }
}

fn add_into(out: &mut [i64]) -> impl FnMut(usize, i64) + '_ {
    |r, v| {
        if let Some(o) = out.get_mut(r) {
            *o = o.saturating_add(v);
        }
    }
}

impl Model<'_> {
    /// Check every shape, and that no scale or gain is infinite or NaN. O(model size); run once at
    /// admission. After it, [`Model::step`] cannot fail on shapes.
    pub fn check(&self) -> Result<(), LmError> {
        let d = &self.dims;
        let (dm, hd, qd, kvd) = (d.d_model, d.head_dim, d.n_heads * d.head_dim, d.n_kv_heads * d.head_dim);
        let dims_ok = d.vocab > 0
            && d.n_layers > 0
            && d.n_heads > 0
            && d.n_kv_heads > 0
            && d.n_heads % d.n_kv_heads == 0
            && hd > 0
            && hd % 2 == 0
            && dm % 32 == 0
            && qd % 32 == 0
            && d.ffn % 32 == 0
            && d.max_ctx > 0
            && d.max_ctx <= MAX_CTX;
        if !dims_ok {
            return Err(LmError::Shape);
        }
        let mat = |m: &Mat, r, c| m.ok(r, c);
        let layer = |l: &Layer| {
            gains_ok(l.attn_norm, dm)
                && gains_ok(l.ffn_norm, dm)
                && gains_ok(l.q_norm, hd)
                && gains_ok(l.k_norm, hd)
                && mat(&l.wq, qd, dm)
                && mat(&l.wk, kvd, dm)
                && mat(&l.wv, kvd, dm)
                && mat(&l.wo, dm, qd)
                && mat(&l.w_gate, d.ffn, dm)
                && mat(&l.w_up, d.ffn, dm)
                && mat(&l.w_down, dm, d.ffn)
        };
        let ok = self.layers.len() == d.n_layers
            && self.layers.iter().all(layer)
            && mat(&self.embed, d.vocab, dm)
            && self.head.as_ref().is_none_or(|h| mat(h, d.vocab, dm))
            && gains_ok(self.final_norm, dm)
            && self.rope.len() == d.max_ctx * hd / 2
            && hp::single_finite(self.eps)
            && hp::single_finite(self.kq_scale);
        if ok {
            Ok(())
        } else {
            Err(LmError::Shape)
        }
    }

    /// One decode step: feed `token` at `pos`, update the cache, return the greedy next token. Logits
    /// (Q16) are left in `work.logits`.
    pub fn step(&self, simd: Simd, token: usize, pos: usize, kv: &mut Kv, work: &mut Work) -> Result<usize, LmError> {
        let dm = &self.dims;
        let (d, hd, nh, nkv, ctx) = (dm.d_model, dm.head_dim, dm.n_heads, dm.n_kv_heads, dm.max_ctx);
        let (qd, kvd) = (nh * hd, nkv * hd);
        let (kv_vals, kv_shifts) = dm.kv_len();
        if kv.vals.len() != kv_vals || kv.shifts.len() != kv_shifts || work.res.len() != d || work.q.len() != qd || work.k.len() != kvd || work.gate.len() != dm.ffn || work.w.len() < ctx || work.logits.len() != dm.vocab {
            return Err(LmError::Work);
        }
        if token >= dm.vocab {
            return Err(LmError::Token);
        }
        if pos >= ctx {
            return Err(LmError::Context);
        }
        let Work { res, xn, q, k, v, att, gate, up, w, logits, xq, xs, qq } = work;
        let looked_up = if self.embed.packed {
            q8::packed_dequant_row(self.embed.w, self.embed.rows, token, hp::FRAC, res)
        } else {
            let rb = q8::row_bytes(d);
            let erow = self.embed.w.get(token * rb..(token + 1) * rb).ok_or(LmError::Shape)?;
            q8::dequant_row(erow, hp::FRAC, res)
        };
        if !looked_up {
            return Err(LmError::Shape);
        }
        let rope = self.rope.get(pos * hd / 2..(pos + 1) * hd / 2).ok_or(LmError::Shape)?;
        // Per layer: [kv head][K, V][position] vectors of head_dim.
        let per_layer = nkv * 2 * ctx;
        for (li, l) in self.layers.iter().enumerate() {
            xn.copy_from_slice(res);
            hp::rmsnorm(xn, l.attn_norm, self.eps);
            gemv(simd, &l.wq, xn, xq, xs, into(q))?;
            gemv(simd, &l.wk, xn, xq, xs, into(k))?;
            gemv(simd, &l.wv, xn, xq, xs, into(v))?;
            for qh in q.chunks_exact_mut(hd) {
                hp::rmsnorm(qh, l.q_norm, self.eps);
                hp::rope_neox(qh, rope);
            }
            for g in 0..nkv {
                let kh = k.get_mut(g * hd..(g + 1) * hd).ok_or(LmError::Shape)?;
                hp::rmsnorm(kh, l.k_norm, self.eps);
                hp::rope_neox(kh, rope);
                for (which, src) in [(0usize, &*kh), (1, v.get(g * hd..(g + 1) * hd).ok_or(LmError::Shape)?)] {
                    let vec = li * per_layer + (g * 2 + which) * ctx + pos;
                    let dst = kv.vals.get_mut(vec * hd..(vec + 1) * hd).ok_or(LmError::Shape)?;
                    let s = hp::kv_quant(src, dst).ok_or(LmError::Shape)?;
                    *kv.shifts.get_mut(vec).ok_or(LmError::Shape)? = s;
                }
            }
            let group = nh / nkv;
            for h in 0..nh {
                let g = h / group;
                let kvec = li * per_layer + g * 2 * ctx;
                let vvec = kvec + ctx;
                let ok = hp::attend(
                    q.get(h * hd..(h + 1) * hd).ok_or(LmError::Shape)?,
                    kv.vals.get(kvec * hd..(kvec + pos + 1) * hd).ok_or(LmError::Shape)?,
                    kv.shifts.get(kvec..=kvec + pos).ok_or(LmError::Shape)?,
                    kv.vals.get(vvec * hd..(vvec + pos + 1) * hd).ok_or(LmError::Shape)?,
                    kv.shifts.get(vvec..=vvec + pos).ok_or(LmError::Shape)?,
                    pos + 1,
                    self.kq_scale,
                    qq,
                    w,
                    att.get_mut(h * hd..(h + 1) * hd).ok_or(LmError::Shape)?,
                );
                if !ok {
                    return Err(LmError::Shape);
                }
            }
            gemv(simd, &l.wo, att, xq, xs, add_into(res))?;
            xn.copy_from_slice(res);
            hp::rmsnorm(xn, l.ffn_norm, self.eps);
            gemv(simd, &l.w_gate, xn, xq, xs, into(gate))?;
            gemv(simd, &l.w_up, xn, xq, xs, into(up))?;
            hp::swiglu(gate, up);
            gemv(simd, &l.w_down, gate, xq, xs, add_into(res))?;
        }
        xn.copy_from_slice(res);
        hp::rmsnorm(xn, self.final_norm, self.eps);
        gemv(simd, self.head.as_ref().unwrap_or(&self.embed), xn, xq, xs, into(logits))?;
        hp::argmax(logits).ok_or(LmError::Shape)
    }

    /// Greedy generation: feed `prompt`, then generate until `stop`, a full context or `out` is full.
    /// Returns the number of generated tokens written to `out`.
    pub fn generate(&self, simd: Simd, prompt: &[u32], stop: &[u32], kv: &mut Kv, work: &mut Work, out: &mut [u32]) -> Result<usize, LmError> {
        self.check()?;
        let mut next = 0usize;
        let mut pos = 0usize;
        for &t in prompt {
            next = self.step(simd, t as usize, pos, kv, work)?;
            pos += 1;
        }
        if prompt.is_empty() {
            return Ok(0);
        }
        let mut n = 0;
        while n < out.len() {
            let tok = u32::try_from(next).map_err(|_| LmError::Token)?;
            if let Some(slot) = out.get_mut(n) {
                *slot = tok;
            }
            n += 1;
            if stop.contains(&tok) || pos >= self.dims.max_ctx {
                break;
            }
            next = self.step(simd, next, pos, kv, work)?;
            pos += 1;
        }
        Ok(n)
    }
}
