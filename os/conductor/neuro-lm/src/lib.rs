// SPDX-License-Identifier: AGPL-3.0-only
//! A decoder-only transformer, integer only: RMSNorm, grouped-query attention with RoPE over an int8 KV
//! cache, a SwiGLU feed-forward, 4-bit weights, greedy decoding. Plus a byte-level BPE tokenizer ([`bpe`]).
//!
//! Numeric scheme: see `neuro_kernels::lm`. Residual Q8 (`i32`), activations Q5 (`i8`), 4-bit weights with
//! per-row integer rescale. Weights, tables and the cache are borrowed; nothing is allocated.
//!
//! Status: the pieces and their composition, verified on the build host against a floating-point model
//! with the same weights. Running a real pretrained model needs the converter (`hnx-compile`) and, on a
//! device, the kernel requests KR-1 (SIMD) and R3–R6 (model region, loader, admission).
#![no_std]
#![forbid(unsafe_code)]
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::manual_is_multiple_of)]

pub mod bpe;

use neuro_kernels::lm::{self, ExpTable};
use neuro_kernels::{gemv_q4_group, group_bytes, i8_bytes, Simd, GROUP_ROWS};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Dims {
    pub vocab: usize,
    pub d_model: usize,
    pub n_layers: usize,
    pub n_heads: usize,
    pub n_kv_heads: usize,
    pub head_dim: usize,
    pub ffn: usize,
    pub max_ctx: usize,
}

impl Dims {
    /// Bytes of KV cache: layers × kv heads × positions × head_dim × (K and V).
    pub fn kv_bytes(&self) -> usize {
        self.n_layers * self.n_kv_heads * self.max_ctx * self.head_dim * 2
    }
    fn valid(&self) -> bool {
        self.vocab > 0
            && self.d_model % 32 == 0
            && self.ffn % 32 == 0
            && self.n_heads > 0
            && self.n_kv_heads > 0
            && self.n_heads % self.n_kv_heads == 0
            && self.head_dim % 2 == 0
            && self.n_heads * self.head_dim % 32 == 0
            && self.n_layers > 0
            && self.max_ctx > 0
    }
}

/// A 4-bit matrix in the interleaved layout, with a per-row integer rescale `acc · mult[r] >> shift`.
#[derive(Clone, Copy, Debug)]
pub struct Q4<'a> {
    pub rows: usize,
    pub cols: usize,
    pub w: &'a [u8],
    pub mult: &'a [i32],
    pub shift: u32,
}

impl Q4<'_> {
    fn ok(&self, rows: usize, cols: usize) -> bool {
        self.rows == rows
            && self.cols == cols
            && rows % GROUP_ROWS == 0
            && cols % 32 == 0
            && self.w.len() == rows / GROUP_ROWS * group_bytes(cols)
            && self.mult.len() == rows
            && self.shift <= 40
    }

    /// Run the matrix over `x` and hand each row's accumulator to `sink(row, acc)`.
    fn apply(&self, simd: Simd, x: &[i8], mut sink: impl FnMut(usize, i32)) {
        let gb = group_bytes(self.cols);
        for (g, wg) in self.w.chunks_exact(gb.max(1)).enumerate() {
            let mut acc = [0i32; 4];
            gemv_q4_group(simd, wg, i8_bytes(x), &mut acc);
            for (i, a) in acc.into_iter().enumerate() {
                sink(g * GROUP_ROWS + i, a);
            }
        }
    }

    fn to_act(&self, simd: Simd, x: &[i8], out: &mut [i8]) {
        let (m, s) = (self.mult, self.shift);
        self.apply(simd, x, |r, a| {
            if let (Some(o), Some(&mu)) = (out.get_mut(r), m.get(r)) {
                *o = lm::requant_i8(a, mu, s);
            }
        });
    }

    fn add_residual(&self, simd: Simd, x: &[i8], res: &mut [i32]) {
        let (m, s) = (self.mult, self.shift);
        self.apply(simd, x, |r, a| {
            if let (Some(o), Some(&mu)) = (res.get_mut(r), m.get(r)) {
                *o = o.saturating_add(lm::requant_i32(a, mu, s));
            }
        });
    }

    fn to_logits(&self, simd: Simd, x: &[i8], out: &mut [i32]) {
        let (m, s) = (self.mult, self.shift);
        self.apply(simd, x, |r, a| {
            if let (Some(o), Some(&mu)) = (out.get_mut(r), m.get(r)) {
                *o = lm::requant_i32(a, mu, s);
            }
        });
    }
}

#[derive(Clone, Copy, Debug)]
pub struct Layer<'a> {
    pub attn_norm: &'a [i16],
    pub wq: Q4<'a>,
    pub wk: Q4<'a>,
    pub wv: Q4<'a>,
    pub wo: Q4<'a>,
    pub ffn_norm: &'a [i16],
    pub w_gate: Q4<'a>,
    pub w_up: Q4<'a>,
    pub w_down: Q4<'a>,
}

#[derive(Clone, Copy, Debug)]
pub struct Model<'a> {
    pub dims: Dims,
    /// vocab × d_model activations (Q5).
    pub embed: &'a [i8],
    pub layers: &'a [Layer<'a>],
    pub final_norm: &'a [i16],
    pub head: Q4<'a>,
    /// max_ctx × head_dim/2 (cos, sin) in Q15.
    pub rope: &'a [(i16, i16)],
    pub exp: &'a ExpTable,
    pub silu: &'a [i8; 256],
    /// Integer form of 16 / (2^10 · sqrt(head_dim)).
    pub score_mult: i32,
    pub score_shift: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LmError {
    Shape,
    Token,
    /// The context is full (pos ≥ max_ctx).
    Context,
    Work,
}

/// All scratch memory one decode step needs, sized by const parameters at compile time (no allocation):
/// D ≥ d_model and ≥ n_heads·head_dim, F ≥ ffn, C ≥ max_ctx, V ≥ vocab.
pub struct Work<const D: usize, const F: usize, const C: usize, const V: usize> {
    res: [i32; D],
    xn: [i8; D],
    q: [i8; D],
    k: [i8; D],
    v: [i8; D],
    att: [i8; D],
    gate: [i8; F],
    up: [i8; F],
    scores: [i32; C],
    probs: [u16; C],
    pub logits: [i32; V],
}

impl<const D: usize, const F: usize, const C: usize, const V: usize> Work<D, F, C, V> {
    pub const fn new() -> Self {
        Self { res: [0; D], xn: [0; D], q: [0; D], k: [0; D], v: [0; D], att: [0; D], gate: [0; F], up: [0; F], scores: [0; C], probs: [0; C], logits: [0; V] }
    }
}

impl<const D: usize, const F: usize, const C: usize, const V: usize> Default for Work<D, F, C, V> {
    fn default() -> Self {
        Self::new()
    }
}

impl Model<'_> {
    /// Check every shape once; after this, [`Model::step`] cannot fail on shapes.
    pub fn check(&self) -> Result<(), LmError> {
        let d = &self.dims;
        if !d.valid() {
            return Err(LmError::Shape);
        }
        let (dm, qd, kvd) = (d.d_model, d.n_heads * d.head_dim, d.n_kv_heads * d.head_dim);
        let ok_layer = |l: &Layer| {
            l.attn_norm.len() == dm
                && l.ffn_norm.len() == dm
                && l.wq.ok(qd, dm)
                && l.wk.ok(kvd, dm)
                && l.wv.ok(kvd, dm)
                && l.wo.ok(dm, qd)
                && l.w_gate.ok(d.ffn, dm)
                && l.w_up.ok(d.ffn, dm)
                && l.w_down.ok(dm, d.ffn)
        };
        let shapes = self.layers.len() == d.n_layers
            && self.layers.iter().all(ok_layer)
            && self.embed.len() == d.vocab * dm
            && self.final_norm.len() == dm
            && self.head.ok(d.vocab.div_ceil(4) * 4, dm)
            && self.rope.len() == d.max_ctx * d.head_dim / 2
            && self.score_shift <= 40;
        if shapes {
            Ok(())
        } else {
            Err(LmError::Shape)
        }
    }

    /// One decode step: feed `token` at position `pos`, update the KV cache, return the greedy next token.
    /// Logits (Q8) are left in `work.logits[..vocab]`.
    pub fn step<const D: usize, const F: usize, const C: usize, const V: usize>(&self, simd: Simd, token: usize, pos: usize, kv: &mut [i8], work: &mut Work<D, F, C, V>) -> Result<usize, LmError> {
        let dm = &self.dims;
        let (d, hd, nh, nkv) = (dm.d_model, dm.head_dim, dm.n_heads, dm.n_kv_heads);
        let (qd, kvd) = (nh * hd, nkv * hd);
        if D < d || D < qd || F < dm.ffn || C < dm.max_ctx || V < self.head.rows.max(dm.vocab) || kv.len() != dm.kv_bytes() {
            return Err(LmError::Work);
        }
        if token >= dm.vocab {
            return Err(LmError::Token);
        }
        if pos >= dm.max_ctx {
            return Err(LmError::Context);
        }
        let w = work;
        // Embedding (Q5) into the residual stream (Q8).
        let row = self.embed.get(token * d..(token + 1) * d).ok_or(LmError::Shape)?;
        for (r, &e) in w.res.iter_mut().zip(row) {
            *r = i32::from(e) << (lm::RES_SHIFT - lm::ACT_SHIFT);
        }
        let rope_row = self.rope.get(pos * hd / 2..(pos + 1) * hd / 2).ok_or(LmError::Shape)?;
        let per_layer = nkv * dm.max_ctx * hd * 2;
        for (li, l) in self.layers.iter().enumerate() {
            let (xn, res) = (&mut w.xn[..d], &w.res[..d]);
            lm::rmsnorm(res, l.attn_norm, xn);
            l.wq.to_act(simd, &w.xn[..d], &mut w.q[..qd]);
            l.wk.to_act(simd, &w.xn[..d], &mut w.k[..kvd]);
            l.wv.to_act(simd, &w.xn[..d], &mut w.v[..kvd]);
            for h in 0..nh {
                lm::rope(&mut w.q[h * hd..(h + 1) * hd], rope_row);
            }
            for g in 0..nkv {
                lm::rope(&mut w.k[g * hd..(g + 1) * hd], rope_row);
            }
            // Cache layout per layer: [kv head][K or V][position][head_dim].
            let cache = kv.get_mut(li * per_layer..(li + 1) * per_layer).ok_or(LmError::Shape)?;
            for g in 0..nkv {
                let base = g * dm.max_ctx * hd * 2;
                let (kc, vc) = (base + pos * hd, base + dm.max_ctx * hd + pos * hd);
                cache.get_mut(kc..kc + hd).ok_or(LmError::Shape)?.copy_from_slice(&w.k[g * hd..(g + 1) * hd]);
                cache.get_mut(vc..vc + hd).ok_or(LmError::Shape)?.copy_from_slice(&w.v[g * hd..(g + 1) * hd]);
            }
            let group = nh / nkv;
            for h in 0..nh {
                let g = h / group;
                let base = g * dm.max_ctx * hd * 2;
                let kc = cache.get(base..base + (pos + 1) * hd).ok_or(LmError::Shape)?;
                let vc = cache.get(base + dm.max_ctx * hd..base + dm.max_ctx * hd + (pos + 1) * hd).ok_or(LmError::Shape)?;
                lm::attend(&w.q[h * hd..(h + 1) * hd], kc, vc, pos + 1, self.score_mult, self.score_shift, self.exp, &mut w.scores, &mut w.probs, &mut w.att[h * hd..(h + 1) * hd]);
            }
            l.wo.add_residual(simd, &w.att[..qd], &mut w.res[..d]);
            lm::rmsnorm(&w.res[..d], l.ffn_norm, &mut w.xn[..d]);
            l.w_gate.to_act(simd, &w.xn[..d], &mut w.gate[..dm.ffn]);
            l.w_up.to_act(simd, &w.xn[..d], &mut w.up[..dm.ffn]);
            lm::lut(&mut w.gate[..dm.ffn], self.silu);
            lm::mul(&mut w.gate[..dm.ffn], &w.up[..dm.ffn]);
            l.w_down.add_residual(simd, &w.gate[..dm.ffn], &mut w.res[..d]);
        }
        lm::rmsnorm(&w.res[..d], self.final_norm, &mut w.xn[..d]);
        self.head.to_logits(simd, &w.xn[..d], &mut w.logits[..self.head.rows]);
        lm::argmax(&w.logits[..dm.vocab]).ok_or(LmError::Shape)
    }

    /// Greedy generation: feed `prompt`, then generate until `stop`, a full context or `out` is full.
    /// Returns the number of generated tokens written to `out`.
    pub fn generate<const D: usize, const F: usize, const C: usize, const V: usize>(&self, simd: Simd, prompt: &[u16], stop: Option<u16>, kv: &mut [i8], work: &mut Work<D, F, C, V>, out: &mut [u16]) -> Result<usize, LmError> {
        self.check()?;
        let mut next = 0usize;
        let mut pos = 0usize;
        for &t in prompt {
            next = self.step(simd, usize::from(t), pos, kv, work)?;
            pos += 1;
        }
        if prompt.is_empty() {
            return Ok(0);
        }
        let mut n = 0;
        while n < out.len() {
            let tok = u16::try_from(next).map_err(|_| LmError::Token)?;
            if let Some(slot) = out.get_mut(n) {
                *slot = tok;
            }
            n += 1;
            if Some(tok) == stop || pos >= self.dims.max_ctx {
                break;
            }
            next = self.step(simd, next, pos, kv, work)?;
            pos += 1;
        }
        Ok(n)
    }
}
