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
    /// No matrix: a placeholder for memory that is filled before use. `check()` refuses it.
    pub const EMPTY: Mat<'static> = Mat { rows: 0, cols: 0, w: &[], packed: false, wexp: 0 };

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

impl Layer<'_> {
    /// No layer: a placeholder for the caller's layer table before the binder fills it.
    pub const EMPTY: Layer<'static> =
        Layer { attn_norm: &[], wq: Mat::EMPTY, wk: Mat::EMPTY, wv: Mat::EMPTY, wo: Mat::EMPTY, q_norm: &[], k_norm: &[], ffn_norm: &[], w_gate: Mat::EMPTY, w_up: Mat::EMPTY, w_down: Mat::EMPTY };
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

/// Tokens one [`Model::forward`] call may process (prefill chunks, speculative verification).
pub const MAX_BATCH: usize = q8::MAX_BATCH;

/// Scratch for one forward pass of up to `batch` tokens, carved from caller-supplied memory (no
/// allocation). Per-token vectors are stored column after column.
pub struct Work<'a> {
    batch: usize,
    res: &'a mut [i64],
    xn: &'a mut [i64],
    q: &'a mut [i64],
    k: &'a mut [i64],
    v: &'a mut [i64],
    att: &'a mut [i64],
    gate: &'a mut [i64],
    up: &'a mut [i64],
    w: &'a mut [i64],
    /// `batch × vocab` logits (Q16), column after column; rows a pruned head did not compute hold `i64::MIN`.
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
    /// `(i64, i8, scale pairs, i32)` lengths [`Work::new`] needs for these dimensions and batch size.
    pub fn lens(d: &Dims, batch: usize) -> (usize, usize, usize, usize) {
        let (qd, kvd) = (d.n_heads * d.head_dim, d.n_kv_heads * d.head_dim);
        let per = 2 * d.d_model + 2 * qd + 2 * kvd + 2 * d.ffn + d.vocab;
        (batch * per + d.max_ctx, batch * Self::widest(d), batch * Self::widest(d) / q8::QK, d.head_dim)
    }
    pub fn new(d: &Dims, batch: usize, mut a: &'a mut [i64], mut b: &'a mut [i8], mut c: &'a mut [(i32, i32)], mut e: &'a mut [i32]) -> Option<Self> {
        if batch == 0 || batch > MAX_BATCH {
            return None;
        }
        let (qd, kvd) = (d.n_heads * d.head_dim, d.n_kv_heads * d.head_dim);
        let wide = Self::widest(d);
        Some(Self {
            batch,
            res: carve(&mut a, batch * d.d_model)?,
            xn: carve(&mut a, batch * d.d_model)?,
            q: carve(&mut a, batch * qd)?,
            att: carve(&mut a, batch * qd)?,
            k: carve(&mut a, batch * kvd)?,
            v: carve(&mut a, batch * kvd)?,
            gate: carve(&mut a, batch * d.ffn)?,
            up: carve(&mut a, batch * d.ffn)?,
            w: carve(&mut a, d.max_ctx)?,
            logits: carve(&mut a, batch * d.vocab)?,
            xq: carve(&mut b, batch * wide)?,
            xs: carve(&mut c, batch * wide / q8::QK)?,
            qq: carve(&mut e, d.head_dim)?,
        })
    }
    pub fn batch(&self) -> usize {
        self.batch
    }
    /// Logits of column `j` of the last forward pass.
    pub fn logits_of(&self, j: usize, vocab: usize) -> &[i64] {
        self.logits.get(j * vocab..(j + 1) * vocab).unwrap_or(&[])
    }
}

/// Which output-head rows a forward pass computes.
#[derive(Clone, Copy, Debug)]
pub enum Head<'b> {
    /// None (prefill chunks whose logits nobody reads).
    Skip,
    /// Every row, for every column.
    All,
    /// Every row, last column only (the end of a prefill).
    Last,
    /// Only these rows (ascending), for a single-column pass: grammar-pruned head.
    Rows(&'b [u32]),
}

fn gains_ok(g: &[u8], n: usize) -> bool {
    g.len() == 4 * n && (0..n).all(|i| hp::single_finite(hp::single_at(g, i)))
}

/// Quantise columns `0..n` of `x` (each `cols` long) into the activation buffers.
fn quantize_cols<'q>(x: &[i64], cols: usize, n: usize, xq: &'q mut [i8], xs: &'q mut [(i32, i32)], acts: &mut [Option<Act<'q>>; MAX_BATCH]) -> Result<(), LmError> {
    let (mut qrest, mut srest) = (xq, xs);
    for (j, slot) in acts.iter_mut().enumerate().take(n) {
        let (q, qr) = core::mem::take(&mut qrest).split_at_mut(cols);
        let (s, sr) = core::mem::take(&mut srest).split_at_mut(cols / q8::QK);
        qrest = qr;
        srest = sr;
        if !q8::quantize(x.get(j * cols..(j + 1) * cols).ok_or(LmError::Work)?, q, s) {
            return Err(LmError::Shape);
        }
        *slot = Some(Act { q, scale: s });
    }
    Ok(())
}

/// `m` against `n` columns of `x`; `sink(column, row, value)`. Every column is bit-identical to a
/// single-column pass; the matrix streams from memory once.
fn gemm(simd: Simd, m: &Mat, x: &[i64], n: usize, xq: &mut [i8], xs: &mut [(i32, i32)], sink: impl FnMut(usize, usize, i64)) -> Result<(), LmError> {
    let cols = m.cols;
    if x.len() < n * cols || xq.len() < n * cols || xs.len() < n * cols / q8::QK {
        return Err(LmError::Work);
    }
    let mut acts: [Option<Act>; MAX_BATCH] = [None; MAX_BATCH];
    quantize_cols(x, cols, n, xq, xs, &mut acts)?;
    let mut list = [Act { q: &[], scale: &[] }; MAX_BATCH];
    for (d, a) in list.iter_mut().zip(acts.iter()).take(n) {
        *d = a.ok_or(LmError::Work)?;
    }
    let xs_ref = list.get(..n).ok_or(LmError::Work)?;
    let ran = if m.packed { q8::matvec_packed_multi(simd, m.w, m.rows, xs_ref, m.wexp, sink) } else { q8::matvec_multi(simd, m.w, m.rows, xs_ref, m.wexp, sink) };
    if ran {
        Ok(())
    } else {
        Err(LmError::Shape)
    }
}

fn into(out: &mut [i64], stride: usize) -> impl FnMut(usize, usize, i64) + '_ {
    move |j, r, v| {
        if let Some(o) = out.get_mut(j * stride + r) {
            *o = v;
        }
    }
}

fn add_into(out: &mut [i64], stride: usize) -> impl FnMut(usize, usize, i64) + '_ {
    move |j, r, v| {
        if let Some(o) = out.get_mut(j * stride + r) {
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

    /// Run `tokens` at positions `pos..pos + tokens.len()`: update the KV cache and compute the head rows
    /// `head` asks for into `work.logits`. Each column computes exactly what a one-token pass at its position
    /// computes (same integer operations); the batch only shares the reads of the weights.
    pub fn forward(&self, simd: Simd, tokens: &[usize], pos: usize, kv: &mut Kv, work: &mut Work, head: Head) -> Result<(), LmError> {
        let dm = &self.dims;
        let (d, hd, nh, nkv, ctx) = (dm.d_model, dm.head_dim, dm.n_heads, dm.n_kv_heads, dm.max_ctx);
        let (qd, kvd, ffn) = (nh * hd, nkv * hd, dm.ffn);
        let n = tokens.len();
        let (kv_vals, kv_shifts) = dm.kv_len();
        if n == 0 || n > work.batch || kv.vals.len() != kv_vals || kv.shifts.len() != kv_shifts || work.res.len() != work.batch * d || work.logits.len() != work.batch * dm.vocab || work.w.len() < ctx {
            return Err(LmError::Work);
        }
        if matches!(head, Head::Rows(_)) && n != 1 {
            return Err(LmError::Work);
        }
        if tokens.iter().any(|&t| t >= dm.vocab) {
            return Err(LmError::Token);
        }
        if pos.checked_add(n).is_none_or(|e| e > ctx) {
            return Err(LmError::Context);
        }
        let Work { res, xn, q, k, v, att, gate, up, w, logits, xq, xs, qq, .. } = work;
        for (j, &t) in tokens.iter().enumerate() {
            let col = res.get_mut(j * d..(j + 1) * d).ok_or(LmError::Work)?;
            let looked_up = if self.embed.packed {
                q8::packed_dequant_row(self.embed.w, self.embed.rows, t, hp::FRAC, col)
            } else {
                let rb = q8::row_bytes(d);
                let erow = self.embed.w.get(t * rb..(t + 1) * rb).ok_or(LmError::Shape)?;
                q8::dequant_row(erow, hp::FRAC, col)
            };
            if !looked_up {
                return Err(LmError::Shape);
            }
        }
        // Per layer: [kv head][K, V][position] vectors of head_dim.
        let per_layer = nkv * 2 * ctx;
        let group = nh / nkv;
        for (li, l) in self.layers.iter().enumerate() {
            let (rs, xs_n) = (res.get(..n * d).ok_or(LmError::Work)?, xn.get_mut(..n * d).ok_or(LmError::Work)?);
            xs_n.copy_from_slice(rs);
            for c in xs_n.chunks_exact_mut(d) {
                hp::rmsnorm(c, l.attn_norm, self.eps);
            }
            gemm(simd, &l.wq, xn, n, xq, xs, into(q, qd))?;
            gemm(simd, &l.wk, xn, n, xq, xs, into(k, kvd))?;
            gemm(simd, &l.wv, xn, n, xq, xs, into(v, kvd))?;
            // Norms, rotary position, cache writes: every column at its own position first, so that
            // column j then attends over exactly what a one-token pass at pos + j would see.
            for j in 0..n {
                let p = pos + j;
                let rope = self.rope.get(p * hd / 2..(p + 1) * hd / 2).ok_or(LmError::Shape)?;
                for qh in q.get_mut(j * qd..(j + 1) * qd).ok_or(LmError::Work)?.chunks_exact_mut(hd) {
                    hp::rmsnorm(qh, l.q_norm, self.eps);
                    hp::rope_neox(qh, rope);
                }
                for g in 0..nkv {
                    let kh = k.get_mut(j * kvd + g * hd..j * kvd + (g + 1) * hd).ok_or(LmError::Shape)?;
                    hp::rmsnorm(kh, l.k_norm, self.eps);
                    hp::rope_neox(kh, rope);
                    for (which, src) in [(0usize, &*kh), (1, v.get(j * kvd + g * hd..j * kvd + (g + 1) * hd).ok_or(LmError::Shape)?)] {
                        let vec = li * per_layer + (g * 2 + which) * ctx + p;
                        let dst = kv.vals.get_mut(vec * hd..(vec + 1) * hd).ok_or(LmError::Shape)?;
                        let s = hp::kv_quant(src, dst).ok_or(LmError::Shape)?;
                        *kv.shifts.get_mut(vec).ok_or(LmError::Shape)? = s;
                    }
                }
            }
            for j in 0..n {
                let p = pos + j;
                for h in 0..nh {
                    let g = h / group;
                    let kvec = li * per_layer + g * 2 * ctx;
                    let vvec = kvec + ctx;
                    let ok = hp::attend(
                        q.get(j * qd + h * hd..j * qd + (h + 1) * hd).ok_or(LmError::Shape)?,
                        kv.vals.get(kvec * hd..(kvec + p + 1) * hd).ok_or(LmError::Shape)?,
                        kv.shifts.get(kvec..=kvec + p).ok_or(LmError::Shape)?,
                        kv.vals.get(vvec * hd..(vvec + p + 1) * hd).ok_or(LmError::Shape)?,
                        kv.shifts.get(vvec..=vvec + p).ok_or(LmError::Shape)?,
                        p + 1,
                        self.kq_scale,
                        qq,
                        w,
                        att.get_mut(j * qd + h * hd..j * qd + (h + 1) * hd).ok_or(LmError::Shape)?,
                    );
                    if !ok {
                        return Err(LmError::Shape);
                    }
                }
            }
            gemm(simd, &l.wo, att, n, xq, xs, add_into(res, d))?;
            let (rs, xs_n) = (res.get(..n * d).ok_or(LmError::Work)?, xn.get_mut(..n * d).ok_or(LmError::Work)?);
            xs_n.copy_from_slice(rs);
            for c in xs_n.chunks_exact_mut(d) {
                hp::rmsnorm(c, l.ffn_norm, self.eps);
            }
            gemm(simd, &l.w_gate, xn, n, xq, xs, into(gate, ffn))?;
            gemm(simd, &l.w_up, xn, n, xq, xs, into(up, ffn))?;
            for (gc, uc) in gate.chunks_exact_mut(ffn).zip(up.chunks_exact(ffn)).take(n) {
                hp::swiglu(gc, uc);
            }
            gemm(simd, &l.w_down, gate, n, xq, xs, add_into(res, d))?;
        }
        let hm = self.head.as_ref().unwrap_or(&self.embed);
        let vocab = dm.vocab;
        // Final norm only for the columns the head reads.
        let first = match head {
            Head::Skip => return Ok(()),
            Head::Last => n - 1,
            _ => 0,
        };
        let m = n - first;
        let (rs, xs_n) = (res.get(first * d..n * d).ok_or(LmError::Work)?, xn.get_mut(..m * d).ok_or(LmError::Work)?);
        xs_n.copy_from_slice(rs);
        for c in xs_n.chunks_exact_mut(d) {
            hp::rmsnorm(c, self.final_norm, self.eps);
        }
        match head {
            Head::Rows(list) => {
                let lg = logits.get_mut(..vocab).ok_or(LmError::Work)?;
                lg.fill(i64::MIN);
                let mut acts: [Option<Act>; MAX_BATCH] = [None; MAX_BATCH];
                quantize_cols(xn, d, 1, xq, xs, &mut acts)?;
                let a = acts.first().copied().flatten().ok_or(LmError::Work)?;
                let sink = |r: usize, val: i64| {
                    if let Some(o) = lg.get_mut(r) {
                        *o = val;
                    }
                };
                let ran = if hm.packed { q8::matvec_packed_rows(simd, hm.w, hm.rows, &a, hm.wexp, list, sink) } else { q8::matvec_rows(simd, hm.w, hm.rows, &a, hm.wexp, list, sink) };
                if !ran {
                    return Err(LmError::Shape);
                }
            }
            _ => {
                // Head::All writes column j at j; Head::Last writes its single column at n - 1.
                let base = first * vocab;
                let out = logits.get_mut(base..base + m * vocab).ok_or(LmError::Work)?;
                gemm(simd, hm, xn, m, xq, xs, into(out, vocab))?;
            }
        }
        Ok(())
    }

    /// One decode step: feed `token` at `pos`, update the cache, return the greedy next token. Logits
    /// (Q16) are left in `work.logits` (column 0).
    pub fn step(&self, simd: Simd, token: usize, pos: usize, kv: &mut Kv, work: &mut Work) -> Result<usize, LmError> {
        self.forward(simd, &[token], pos, kv, work, Head::All)?;
        hp::argmax(work.logits_of(0, self.dims.vocab)).ok_or(LmError::Shape)
    }

    /// Feed a prompt in batches (weights read once per batch); returns the greedy next token after it.
    pub fn prefill(&self, simd: Simd, prompt: &[u32], kv: &mut Kv, work: &mut Work) -> Result<usize, LmError> {
        let b = work.batch;
        let mut toks = [0usize; MAX_BATCH];
        let mut pos = 0usize;
        for chunk in prompt.chunks(b) {
            for (d, &t) in toks.iter_mut().zip(chunk) {
                *d = t as usize;
            }
            let last = pos + chunk.len() == prompt.len();
            self.forward(simd, toks.get(..chunk.len()).ok_or(LmError::Work)?, pos, kv, work, if last { Head::Last } else { Head::Skip })?;
            pos += chunk.len();
        }
        let n = prompt.len().checked_sub(1).ok_or(LmError::Token)? % b;
        hp::argmax(work.logits_of(n, self.dims.vocab)).ok_or(LmError::Shape)
    }

    /// Greedy generation: feed `prompt`, then generate until `stop`, a full context or `out` is full.
    /// Returns the number of generated tokens written to `out`.
    pub fn generate(&self, simd: Simd, prompt: &[u32], stop: &[u32], kv: &mut Kv, work: &mut Work, out: &mut [u32]) -> Result<usize, LmError> {
        self.check()?;
        if prompt.is_empty() {
            return Ok(0);
        }
        let mut next = self.prefill(simd, prompt, kv, work)?;
        let mut pos = prompt.len();
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
