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
//! Decoding is greedy (temperature 0, as Neuro measured). A job is plain ([`Session::start`]: the tokens
//! `Model::generate` gives) or under the answer contract ([`Session::start_closed`]: the tokens
//! `neuro_lm::decode::generate_closed` gives, with its pruned head and verified drafts).

use crate::hnx::Admitted;
use crate::qwen3::{layer, layer_packed, model, model_packed, BindError, Hparams, Packed};
use neuro_kernels::{hp, Simd};
use neuro_contract::Machine;
use neuro_lm::decode::{ClosedRun, Options, Pass, Stats};
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
    /// The tokens the KV cache was computed from, kept between jobs (see [`Session::reused`]).
    pub prev: usize,
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
            .saturating_add(self.prev.saturating_mul(4))
    }
}

/// What a session of this model needs when it feeds the prompt `batch` tokens per pass.
pub fn sizes(h: &Hparams, batch: usize) -> Sizes {
    let d = &h.dims;
    let (kv_vals, kv_shifts) = d.kv_len();
    let (work_i64, work_i8, work_pairs, work_i32) = Work::lens(d, batch);
    Sizes { layers: d.n_layers, rope: d.max_ctx.saturating_mul(d.head_dim / 2), kv_vals, kv_shifts, work_i64, work_i8, work_pairs, work_i32, ids: d.max_ctx, prev: d.max_ctx }
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
    /// The tokens behind the KV cache, kept between jobs so a job that starts with the same tokens does not
    /// feed them again. May be empty: then every job feeds its whole prompt.
    pub prev: &'a mut [u32],
    /// For jobs under the answer contract: scratch for the allowed-token list (its length bounds head
    /// pruning) and the answer's tokens (its length bounds the answer). Both may be empty for plain jobs.
    pub list: &'a mut [u32],
    pub out: &'a mut [u32],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Progress {
    /// A batch of the prompt went through the weights. `fed` of `total` tokens are in.
    Prefill { fed: usize, total: usize },
    /// One token of the answer. `last`: a stop token, or the context is full; the next call returns `Done`.
    Token { id: u32, last: bool },
    /// A pass of a job under the contract: this many tokens joined the answer (more than one when drafts
    /// were confirmed).
    Tokens { count: usize },
    Done,
}

pub struct Session<'a> {
    model: Model<'a>,
    tok: Tokenizer<'a>,
    kv: Kv<'a>,
    work: Work<'a>,
    ids: &'a mut [u32],
    prev: &'a mut [u32],
    /// `prev[..prev_len]` is what the first `prev_len` positions of the KV cache were computed from.
    prev_len: usize,
    /// `ids` describes the KV cache (a job ran from it); false while `ids` is being rewritten.
    ids_live: bool,
    reused: usize,
    list: &'a mut [u32],
    out: &'a mut [u32],
    closed: Option<ClosedRun<'a>>,
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
        let Mem { layers, rope, kv_vals, kv_shifts, work_i64, work_i8, work_pairs, work_i32, ids, prev, list, out } = mem;
        let layers = layers.get_mut(..need.layers).ok_or(P0Error::Mem)?;
        // The matrices: the packed section if the bundle has one (the stored form for a device), else the file's.
        let mut packed = (!tables.packed.is_empty()).then(|| Packed::new(tables.packed));
        let embed = match packed.as_mut() {
            Some(p) => Some(p.take(h.dims.vocab, h.dims.d_model).map_err(P0Error::Bind)?),
            None => None,
        };
        for (i, slot) in layers.iter_mut().enumerate() {
            *slot = match packed.as_mut() {
                Some(p) => layer_packed(g, h, i, p),
                None => layer(g, h, i),
            }
            .map_err(P0Error::Bind)?;
        }
        if packed.as_ref().is_some_and(|p| !p.done()) {
            return Err(P0Error::Bind(BindError::Tensor));
        }
        let rope = rope.get_mut(..need.rope).ok_or(P0Error::Mem)?;
        tables.rope_into(rope).ok_or(P0Error::Mem)?;
        let (layers, rope): (&'a [Layer<'a>], &'a [(i32, i32)]) = (layers, rope);
        let model = match embed {
            Some(e) => model_packed(g, h, e, layers, rope),
            None => model(g, h, layers, rope),
        }
        .map_err(P0Error::Bind)?;
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
        Ok(Self { model, tok, kv, work, ids, prev, prev_len: 0, ids_live: false, reused: 0, list, out, closed: None, simd, batch, stop, n_prompt: 0, n: 0, fed: 0, next: None, done: true })
    }

    pub fn tokenizer(&self) -> &Tokenizer<'a> {
        &self.tok
    }

    pub fn model(&self) -> &Model<'a> {
        &self.model
    }

    /// Begin a job from prompt text. `cps` and `buf` are scratch for normalisation. Returns the prompt's tokens.
    pub fn start(&mut self, prompt: &[u8], cps: &mut [u32], buf: &mut [u8]) -> Result<usize, P0Error> {
        self.keep_prefix();
        let n = self.tok.encode_nfc(prompt, self.ids, cps, buf).map_err(|_| P0Error::Prompt)?;
        self.begin(n)
    }

    /// Begin a job from token ids.
    pub fn start_ids(&mut self, prompt: &[u32]) -> Result<usize, P0Error> {
        self.keep_prefix();
        self.ids.get_mut(..prompt.len()).ok_or(P0Error::Prompt)?.copy_from_slice(prompt);
        self.begin(prompt.len())
    }

    fn begin(&mut self, n: usize) -> Result<usize, P0Error> {
        // At least one token, and room for at least one of the answer.
        if n == 0 || n >= self.ids.len() {
            self.done = true;
            return Err(P0Error::Prompt);
        }
        // Position i of the KV cache depends only on tokens 0..=i, so the positions an earlier job computed
        // from the same leading tokens stand. The last prompt token is fed again in any case: its logits choose
        // the first token of the answer.
        let same = self.ids.iter().zip(self.prev.get(..self.prev_len).unwrap_or(&[])).take_while(|(a, b)| a == b).count();
        self.reused = same.min(n.saturating_sub(1));
        // From here the cache follows this job: what stays valid of `prev` is the shared prefix.
        self.prev_len = self.prev_len.min(self.reused);
        (self.n_prompt, self.n, self.fed, self.next, self.done) = (n, n, self.reused, None, false);
        self.closed = None;
        self.ids_live = true;
        Ok(n)
    }

    /// Before `ids` is rewritten for a new job: remember which tokens the KV cache holds.
    fn keep_prefix(&mut self) {
        if !self.ids_live {
            return;
        }
        self.ids_live = false;
        let fed = self.closed.as_ref().map_or(self.fed, ClosedRun::fed);
        let n = fed.min(self.prev.len()).min(self.ids.len());
        if let (Some(dst), Some(src)) = (self.prev.get_mut(..n), self.ids.get(..n)) {
            dst.copy_from_slice(src);
            self.prev_len = n;
        } else {
            self.prev_len = 0;
        }
    }

    /// Prompt tokens of the current job that were not fed again, because the KV cache already held them from
    /// an earlier job with the same leading tokens (the system prompt, for instance). Exact: the answer is the
    /// one a fresh session gives.
    pub fn reused(&self) -> usize {
        self.reused
    }

    /// Begin a job whose answer must follow the contract: `machine` is the answer automaton for this request's
    /// facts and aliases. The answer is at most `opts.max_new` tokens; `Mem::out` must hold that many, and the
    /// context must have room for them after the prompt, or the job is refused.
    pub fn start_closed(&mut self, prompt: &[u8], cps: &mut [u32], buf: &mut [u8], machine: Machine<'a>, opts: Options) -> Result<usize, P0Error> {
        let n = self.start(prompt, cps, buf)?;
        // The whole answer must fit: a job whose prompt leaves less room is refused, never cut short
        // (agreed with Neuro: prompt + answer bound within the admitted context, or no job).
        if opts.max_new == 0 || opts.max_new > self.out.len() {
            self.done = true;
            return Err(P0Error::Mem);
        }
        if opts.max_new > self.ids.len().saturating_sub(n) {
            self.done = true;
            return Err(P0Error::Prompt);
        }
        self.closed = Some(ClosedRun::in_place(n, self.reused, machine, opts, self.ids).map_err(P0Error::Engine)?);
        Ok(n)
    }

    /// A whole job under the contract in one call, for a caller that owns its thread of control (a worker
    /// answering one request). `machine` may borrow lists that live only for this call. `between` runs after
    /// every pass with the tokens so far; returning `false` cancels. Returns the answer's tokens and counters;
    /// read the answer with [`Session::answer`] or [`Session::answer_text`].
    pub fn run_closed(&mut self, prompt: &[u8], cps: &mut [u32], buf: &mut [u8], machine: Machine<'_>, opts: Options, mut between: impl FnMut(usize) -> bool) -> Result<(usize, Stats), P0Error> {
        let n = self.start(prompt, cps, buf)?;
        if opts.max_new == 0 || opts.max_new > self.out.len() {
            self.done = true;
            return Err(P0Error::Mem);
        }
        if opts.max_new > self.ids.len().saturating_sub(n) {
            self.done = true;
            return Err(P0Error::Prompt);
        }
        let mut run = ClosedRun::in_place(n, self.reused, machine, opts, self.ids).map_err(P0Error::Engine)?;
        let mut eog = [0u32; 2];
        let mut k = 0usize;
        for id in self.stop.iter().flatten() {
            if let Some(slot) = eog.get_mut(k) {
                *slot = *id;
                k = k.saturating_add(1);
            }
        }
        let eog = eog.get(..k).unwrap_or(&[]);
        loop {
            let pass = run.advance(&self.model, self.simd, &self.tok, eog, &mut self.kv, &mut self.work, self.ids, self.list, self.out);
            // Keep the session's own view in step, so prefix reuse and `answer` work after this call.
            self.fed = run.fed();
            self.n = self.n_prompt.saturating_add(run.tokens());
            match pass.map_err(|e| {
                self.done = true;
                P0Error::Engine(e)
            })? {
                Pass::Done => break,
                _ => {
                    if !between(run.tokens()) {
                        break;
                    }
                }
            }
        }
        self.done = true;
        Ok((run.tokens(), run.stats()))
    }

    /// Passes and tokens of the current job under the contract.
    pub fn closed_stats(&self) -> Option<Stats> {
        self.closed.as_ref().map(ClosedRun::stats)
    }

    /// One forward pass over the weights.
    pub fn advance(&mut self) -> Result<Progress, P0Error> {
        if self.done {
            return if self.n_prompt == 0 { Err(P0Error::NotStarted) } else { Ok(Progress::Done) };
        }
        if let Some(run) = self.closed.as_mut() {
            let mut eog = [0u32; 2];
            let mut k = 0usize;
            for id in self.stop.iter().flatten() {
                if let Some(slot) = eog.get_mut(k) {
                    *slot = *id;
                    k = k.saturating_add(1);
                }
            }
            let pass = run.advance(&self.model, self.simd, &self.tok, eog.get(..k).unwrap_or(&[]), &mut self.kv, &mut self.work, self.ids, self.list, self.out).map_err(P0Error::Engine)?;
            self.n = self.n_prompt.saturating_add(run.tokens());
            return Ok(match pass {
                Pass::Prefill { fed, total } => Progress::Prefill { fed, total },
                Pass::Tokens(count) => Progress::Tokens { count },
                Pass::Done => {
                    self.done = true;
                    Progress::Done
                }
            });
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
