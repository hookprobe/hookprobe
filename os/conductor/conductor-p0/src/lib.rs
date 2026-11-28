// SPDX-License-Identifier: AGPL-3.0-only
//! The worker's compute, bound to the native engine.
//!
//! `conductor_worker::Worker` checks the capability, makes its replay state durable and signs the result; what
//! it runs is an [`Executor`]. This is the executor of a heqk node that serves the explainer: one admitted
//! model in one P0 session (`neuro_gguf::p0`), answering each `infer` request under Neuro's answer contract.
//!
//! The request carries the prompt the device built. The answer must be closed over the facts and aliases of
//! the context in that prompt, so the executor reads them from the prompt itself (the text between the user
//! framing's head and its question) with the same rule the device used, and decodes under that automaton. A
//! prompt it cannot read that way is refused: the worker never decodes without the contract.
//!
//! What decides the contract is the model, not the request: this executor serves one model digest, and that
//! model is the explainer. Another digest is refused.
#![no_std]
#![forbid(unsafe_code)]
#![deny(clippy::indexing_slicing, clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use conductor_core::cap;
use conductor_core::frame::{profile, QuoteRequest};
use conductor_worker::{Executor, Run};
use neuro_contract::{context_ids, Allowed, IdList, Machine, USER_HEAD, USER_MID};
use neuro_gguf::p0::{P0Error, Session};
use neuro_lm::decode::{Options, Stats};

/// Error codes this executor reports to the device (an ERROR frame).
pub mod code {
    /// Not `infer`, or not the model this node serves.
    pub const UNSUPPORTED: u16 = 0x0201;
    /// The prompt is not the explainer's (no context block to close the answer over), or it has no fact.
    pub const PROMPT: u16 = 0x0202;
    /// The prompt and the answer bound do not fit the admitted context.
    pub const CONTEXT: u16 = 0x0203;
    /// The engine failed.
    pub const ENGINE: u16 = 0x0204;
    /// The answer does not fit the output the capability allows.
    pub const OUTPUT: u16 = 0x0205;
    /// The caller stopped the job between two passes. No part of an answer is returned.
    pub const CANCELLED: u16 = 0x0206;
}

pub mod core_job;

/// Neuro's bound on an answer (its evaluations ran with `max_tokens` 700).
pub const MAX_ANSWER_TOKENS: usize = 700;

pub struct P0Executor<'a, C: FnMut() -> u64> {
    session: Session<'a>,
    model: [u8; 32],
    opts: Options,
    /// Scratch for normalising the prompt.
    cps: &'a mut [u32],
    buf: &'a mut [u8],
    /// The node's monotonic clock, in ms.
    clock: C,
    last: Stats,
    /// Predicted time to the first token and per token, for quotes (measured on this node, set by its owner).
    pub quote_ttft_ms: u32,
    pub quote_tpot_ms: u32,
}

impl<'a, C: FnMut() -> u64> P0Executor<'a, C> {
    /// `session` is open on the admitted model whose digest is `model`; its memory must include the contract
    /// buffers (`Mem::list`, `Mem::out` of at least [`MAX_ANSWER_TOKENS`]).
    pub fn new(session: Session<'a>, model: [u8; 32], cps: &'a mut [u32], buf: &'a mut [u8], clock: C) -> Self {
        Self { session, model, opts: Options { prune_max: 8192, draft_max: 0, max_new: MAX_ANSWER_TOKENS }, cps, buf, clock, last: Stats::default(), quote_ttft_ms: 0, quote_tpot_ms: 0 }
    }

    /// Another bound on the answer than Neuro's 700 tokens (a model whose tokens are not the explainer's).
    pub fn with_max_answer(mut self, tokens: usize) -> Self {
        self.opts.max_new = tokens;
        self
    }

    /// Passes and tokens of the last answer.
    pub fn last_stats(&self) -> Stats {
        self.last
    }

    /// Prompt tokens the last job did not feed again (`Session::reused`).
    pub fn last_reused(&self) -> usize {
        self.session.reused()
    }
}

fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len()).position(|w| w == needle)
}

fn rfind(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len()).rposition(|w| w == needle)
}

/// The context block of an explainer prompt: between the framing's head and its last question marker.
pub fn shown_context(prompt: &[u8]) -> Option<&[u8]> {
    let start = find(prompt, USER_HEAD.as_bytes())?.checked_add(USER_HEAD.len())?;
    let rest = prompt.get(start..)?;
    rest.get(..rfind(rest, USER_MID.as_bytes())?)
}

impl<C: FnMut() -> u64> Executor for P0Executor<'_, C> {
    fn run(&mut self, op: u8, model: &[u8; 32], prompt: &[u8], out: &mut [u8]) -> Result<Run, u16> {
        if op != cap::op::INFER || *model != self.model {
            return Err(code::UNSUPPORTED);
        }
        self.infer(prompt, out, &mut |_| true)
    }

    fn quote(&self, q: &QuoteRequest) -> (bool, u32, u32, u8) {
        let meets = (q.slo_ttft_ms == 0 || self.quote_ttft_ms <= q.slo_ttft_ms) && (q.slo_tpot_ms == 0 || self.quote_tpot_ms <= q.slo_tpot_ms);
        (meets, self.quote_ttft_ms, self.quote_tpot_ms, profile::CPU_ONLY)
    }
}

impl<C: FnMut() -> u64> P0Executor<'_, C> {
    /// One answer to `prompt` under the contract. `keep_going` is asked after every pass over the weights, with
    /// the answer tokens so far; `false` stops the job, and nothing of the answer is returned.
    pub fn infer(&mut self, prompt: &[u8], out: &mut [u8], keep_going: &mut dyn FnMut(usize) -> bool) -> Result<Run, u16> {
        // The contract for this request: the ids of the context the device showed.
        let shown = shown_context(prompt).ok_or(code::PROMPT)?;
        let (mut facts, mut ents) = (IdList::new(), IdList::new());
        context_ids(shown, &mut facts, &mut ents).map_err(|_| code::PROMPT)?;
        if facts.is_empty() {
            return Err(code::PROMPT);
        }
        let machine = Machine::new(Allowed { facts: &facts, entities: &ents, closed: true });
        let t0 = (self.clock)();
        let mut first: Option<u64> = None;
        let mut stopped = false;
        let clock = &mut self.clock;
        let (_, stats) = self
            .session
            .run_closed(prompt, self.cps, self.buf, machine, self.opts, |tokens| {
                if tokens > 0 && first.is_none() {
                    first = Some(clock());
                }
                stopped = !keep_going(tokens);
                !stopped
            })
            .map_err(|e| match e {
                P0Error::Prompt => code::CONTEXT,
                _ => code::ENGINE,
            })?;
        let t1 = (self.clock)();
        self.last = stats;
        if stopped {
            return Err(code::CANCELLED);
        }
        let len = self.session.answer_text(out).map_err(|_| code::OUTPUT)?;
        let ms = |a: u64, b: u64| u32::try_from(b.saturating_sub(a)).unwrap_or(u32::MAX);
        Ok(Run { len, compute_ms: ms(t0, t1), ttft_ms: ms(t0, first.unwrap_or(t1)) })
    }
}
