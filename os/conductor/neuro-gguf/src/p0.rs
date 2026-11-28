// SPDX-License-Identifier: AGPL-3.0-only
//! P0: the language model on the device, as a job that is advanced one forward pass at a time.
//!
//! ADR 0060 (amendment, W3 stage S2) puts the engine on a compute-role worker core: an executive that never
//! allocates, gets its memory from core 0 before it starts, and is driven over rings. This module is the
//! engine in that shape:
//! - [`sizes`] says, from the model's hyperparameters, exactly what memory a session needs;
//! - [`Session::open`] takes that memory ([`Mem`]) and an admitted bundle (`crate::hnx::admit`), binds the
//!   model and reads the tokenizer and the RoPE table from the bundle. Nothing is derived, nothing allocated;
//! - [`Session::advance`] does **one forward pass over the weights** and returns: a prompt batch fed, or one
//!   token generated. The caller decides between calls whether to go on, so a job can be preempted, paced by
//!   the packet path, or cancelled, at a granularity of one pass.
//!
//! Decoding is greedy (temperature 0, as Neuro measured), and gives the tokens `Model::generate` gives.
//! Not here yet: decoding under the answer grammar (`neuro_lm::decode`) one pass at a time.

use crate::hnx::Admitted;
use crate::qwen3::{layer, model, BindError, Hparams};
use neuro_kernels::{hp, Simd};
use neuro_lm::qwen3::{Head, Kv, Layer, Model, Work, MAX_BATCH};
use neuro_lm::tok::Tokenizer;
use neuro_lm::LmError;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum P0Error {
    /// A slice of [`Mem`] is smaller than [`sizes`] says, or the batch is not 1 to 16.
    Mem,
    /// The payload is a bare GGUF file: it has no tokenizer or RoPE table, and the device cannot make them.
    NoTables,
    Bind(BindError),
    Engine(LmError),
    /// The prompt does not tokenize, or does not fit the context.
    Prompt,
    /// `advance` before `start`.
    NotStarted,
}

/// Elements of each slice a session needs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Sizes {
    pub layers: usize,
    pub rope: usize,
    pub kv_vals: usize,
    pub kv_shifts: usize,
    pub work_i64: usize,
    pub work_i8: usize,
    pub work_pairs: usize,
    pub work_i32: usize,
    /// Token ids of the prompt and the answer: the context length.
    pub ids: usize,
}

impl Sizes {
    /// Bytes of all of it (the layer table at `core::mem::size_of::<Layer>()` each).
    pub fn bytes(&self) -> usize {
        self.layers
            .saturating_mul(core::mem::size_of::<Layer>())
            .saturating_add(self.rope.saturating_mul(8))
            .saturating_add(self.kv_vals.saturating_mul(2))
            .saturating_add(self.kv_shifts)
            .saturating_add(self.work_i64.saturating_mul(8))
            .saturating_add(self.work_i8)
            .saturating_add(self.work_pairs.saturating_mul(8))
            .saturating_add(self.work_i32.saturating_mul(4))
            .saturating_add(self.ids.saturating_mul(4))
    }
}

/// What a session of this model needs when it feeds the prompt `batch` tokens per pass.
pub fn sizes(h: &Hparams, batch: usize) -> Sizes {
    let d = &h.dims;
    let (kv_vals, kv_shifts) = d.kv_len();
    let (work_i64, work_i8, work_pairs, work_i32) = Work::lens(d, batch);
    Sizes { layers: d.n_layers, rope: d.max_ctx.saturating_mul(d.head_dim / 2), kv_vals, kv_shifts, work_i64, work_i8, work_pairs, work_i32, ids: d.max_ctx }
}

/// The session's memory, assigned by the caller. Each slice may be longer than needed; none may be shorter.
pub struct Mem<'a> {
    pub layers: &'a mut [Layer<'a>],
    pub rope: &'a mut [(i32, i32)],
    pub kv_vals: &'a mut [i16],
    pub kv_shifts: &'a mut [u8],
    pub work_i64: &'a mut [i64],
    pub work_i8: &'a mut [i8],
    pub work_pairs: &'a mut [(i32, i32)],
    pub work_i32: &'a mut [i32],
    pub ids: &'a mut [u32],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Progress {
    /// A batch of the prompt went through the weights. `fed` of `total` tokens are in.
    Prefill { fed: usize, total: usize },
    /// One token of the answer. `last`: a stop token, or the context is full; the next call returns `Done`.
    Token { id: u32, last: bool },
    Done,
}

pub struct Session<'a> {
    model: Model<'a>,
    tok: Tokenizer<'a>,
    kv: Kv<'a>,
    work: Work<'a>,
    ids: &'a mut [u32],
    simd: Simd,
    batch: usize,
    stop: [Option<u32>; 2],
    /// Tokens of the prompt, tokens in `ids`, tokens fed to the model.
    n_prompt: usize,
    n: usize,
    fed: usize,
    next: Option<usize>,
    done: bool,
}

impl<'a> Session<'a> {
    /// Bind the admitted model into `mem`. `batch` is the number of prompt tokens per pass (1 to 16).
    pub fn open(ad: &Admitted<'a>, simd: Simd, batch: usize, mem: Mem<'a>) -> Result<Self, P0Error> {
        let tables = ad.bundle.ok_or(P0Error::NoTables)?;
        if batch == 0 || batch > MAX_BATCH {
            return Err(P0Error::Mem);
        }
        let (g, h) = (&ad.gguf, &ad.hparams);
        let need = sizes(h, batch);
        let Mem { layers, rope, kv_vals, kv_shifts, work_i64, work_i8, work_pairs, work_i32, ids } = mem;
        let layers = layers.get_mut(..need.layers).ok_or(P0Error::Mem)?;
        for (i, slot) in layers.iter_mut().enumerate() {
            *slot = layer(g, h, i).map_err(P0Error::Bind)?;
        }
        let rope = rope.get_mut(..need.rope).ok_or(P0Error::Mem)?;
        tables.rope_into(rope).ok_or(P0Error::Mem)?;
        let (layers, rope): (&'a [Layer<'a>], &'a [(i32, i32)]) = (layers, rope);
        let model = model(g, h, layers, rope).map_err(P0Error::Bind)?;
        let kv = Kv { vals: kv_vals.get_mut(..need.kv_vals).ok_or(P0Error::Mem)?, shifts: kv_shifts.get_mut(..need.kv_shifts).ok_or(P0Error::Mem)? };
        let work = Work::new(
            &h.dims,
            batch,
            work_i64.get_mut(..need.work_i64).ok_or(P0Error::Mem)?,
            work_i8.get_mut(..need.work_i8).ok_or(P0Error::Mem)?,
            work_pairs.get_mut(..need.work_pairs).ok_or(P0Error::Mem)?,
            work_i32.get_mut(..need.work_i32).ok_or(P0Error::Mem)?,
        )
        .ok_or(P0Error::Mem)?;
        let tok = Tokenizer::new(tables.tokenizer).map_err(|_| P0Error::NoTables)?;
        let stop = [tok.added_id(b"<|im_end|>"), tok.added_id(b"<|endoftext|>")];
        let ids = ids.get_mut(..need.ids).ok_or(P0Error::Mem)?;
        Ok(Self { model, tok, kv, work, ids, simd, batch, stop, n_prompt: 0, n: 0, fed: 0, next: None, done: true })
    }

    pub fn tokenizer(&self) -> &Tokenizer<'a> {
        &self.tok
    }

    pub fn model(&self) -> &Model<'a> {
        &self.model
    }

    /// Begin a job from prompt text. `cps` and `buf` are scratch for normalisation. Returns the prompt's tokens.
    pub fn start(&mut self, prompt: &[u8], cps: &mut [u32], buf: &mut [u8]) -> Result<usize, P0Error> {
        let n = self.tok.encode_nfc(prompt, self.ids, cps, buf).map_err(|_| P0Error::Prompt)?;
        self.begin(n)
    }

    /// Begin a job from token ids.
    pub fn start_ids(&mut self, prompt: &[u32]) -> Result<usize, P0Error> {
        self.ids.get_mut(..prompt.len()).ok_or(P0Error::Prompt)?.copy_from_slice(prompt);
        self.begin(prompt.len())
    }

    fn begin(&mut self, n: usize) -> Result<usize, P0Error> {
        // At least one token, and room for at least one of the answer.
        if n == 0 || n >= self.ids.len() {
            self.done = true;
            return Err(P0Error::Prompt);
        }
        (self.n_prompt, self.n, self.fed, self.next, self.done) = (n, n, 0, None, false);
        Ok(n)
    }

    /// One forward pass over the weights.
    pub fn advance(&mut self) -> Result<Progress, P0Error> {
        if self.done {
            return if self.n_prompt == 0 { Err(P0Error::NotStarted) } else { Ok(Progress::Done) };
        }
        let vocab = self.model.dims.vocab;
        if self.fed < self.n_prompt {
            let end = self.fed.saturating_add(self.batch).min(self.n_prompt);
            let chunk = self.ids.get(self.fed..end).ok_or(P0Error::Mem)?;
            let mut toks = [0usize; MAX_BATCH];
            for (d, t) in toks.iter_mut().zip(chunk) {
                *d = usize::try_from(*t).map_err(|_| P0Error::Prompt)?;
            }
            let m = chunk.len();
            let last = end == self.n_prompt;
            self.model.forward(self.simd, toks.get(..m).ok_or(P0Error::Mem)?, self.fed, &mut self.kv, &mut self.work, if last { Head::Last } else { Head::Skip }).map_err(P0Error::Engine)?;
            self.fed = end;
            if last {
                self.next = Some(hp::argmax(self.work.logits_of(m.saturating_sub(1), vocab)).ok_or(P0Error::Engine(LmError::Shape))?);
            }
            return Ok(Progress::Prefill { fed: end, total: self.n_prompt });
        }
        // Emit the token the last pass chose; unless it ends the answer, run the pass that chooses the next.
        let tok = self.next.ok_or(P0Error::NotStarted)?;
        let id = u32::try_from(tok).map_err(|_| P0Error::Engine(LmError::Token))?;
        *self.ids.get_mut(self.n).ok_or(P0Error::Mem)? = id;
        self.n = self.n.saturating_add(1);
        if self.stop.contains(&Some(id)) || self.n >= self.ids.len() {
            self.done = true;
            return Ok(Progress::Token { id, last: true });
        }
        self.next = Some(self.model.step(self.simd, tok, self.fed, &mut self.kv, &mut self.work).map_err(P0Error::Engine)?);
        self.fed = self.fed.saturating_add(1);
        Ok(Progress::Token { id, last: false })
    }

    /// Stop the job where it is (a preemption that will not resume, a cancellation).
    pub fn cancel(&mut self) {
        self.done = true;
    }

    /// The tokens generated so far.
    pub fn answer(&self) -> &[u32] {
        self.ids.get(self.n_prompt..self.n).unwrap_or(&[])
    }

    /// The answer as text, without a closing stop token.
    pub fn answer_text(&self, out: &mut [u8]) -> Result<usize, P0Error> {
        let a = self.answer();
        let a = match a.split_last() {
            Some((last, head)) if self.stop.contains(&Some(*last)) => head,
            _ => a,
        };
        self.tok.decode(a, out).map_err(|_| P0Error::Prompt)
    }
}
