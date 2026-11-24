// SPDX-License-Identifier: AGPL-3.0-only
//! The P1 reference worker (ADR 0071 C2): what a heqk node on the owner's LAN runs to serve the device.
//!
//! It accepts a call only after [`conductor_core::worker::WorkerGate`] has checked the whole capability, the
//! same code the device's tests use. Then it makes the replay state durable **before** it computes:
//! - the high-water mark of the device's counter;
//! - the newest revocation epoch.
//!
//! Both use ADR 0069's record (`conductor_core::durable`), on the node's own block device. A crash between
//! acceptance and computation therefore burns the capability: the device sees a timeout, never a second
//! execution. That is at-most-once execution across power loss.
//!
//! It runs `infer`, `embed` and `classify` through an [`Executor`] (on a heqk node: the native engine). It
//! enforces the capability's output budget itself, and signs every result with a [`ResultKey`] the node's
//! kernel holds. The key never enters this library.
//!
//! Sans-IO: frames in, frames out through a callback. No allocation, no unsafe, no float.
#![no_std]
#![forbid(unsafe_code)]
#![deny(
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation
)]

use conductor_core::cap::{self, HpExec};
use conductor_core::class::Tier;
use conductor_core::crypto::{sha256, TAG_QUOTE, TAG_RESULT};
use conductor_core::durable::{self, BlockDev, MAGIC_WORKER_EPOCH, MAGIC_WORKER_HWM};
use conductor_core::frame::{self, Body, QuoteRequest, Request, Response, Usage};
use conductor_core::limits::{self, units};
use conductor_core::worker::{Refuse, WorkerGate};

/// The worker's signing key for results and quotes. On a heqk node the kernel holds it; this library only asks
/// for signatures.
pub trait ResultKey {
    fn public_key(&self) -> [u8; 32];
    fn sign(&self, tag: &[u8], msg: &[u8]) -> Option<[u8; 64]>;
}

/// What one call computed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Run {
    /// Bytes written to the output buffer.
    pub len: usize,
    pub compute_ms: u32,
    pub ttft_ms: u32,
}

/// The compute. On a heqk node: the native engine (`neuro-engine` / `neuro-lm`). `infer` writes text,
/// `embed` an int8 vector, `classify` a label; the protocol is the same for all three.
pub trait Executor {
    /// Run `op` (exactly one bit of `cap::op`) of model `model` on `prompt`, writing at most `out.len()`
    /// bytes. `Err(code)` is reported to the device as an ERROR frame.
    fn run(&mut self, op: u8, model: &[u8; 32], prompt: &[u8], out: &mut [u8]) -> Result<Run, u16>;
    /// Whether this node can meet the targets now: (can_meet, predicted ttft ms, predicted tpot ms, offload
    /// profile). Called with sizes only, never content.
    fn quote(&self, q: &QuoteRequest) -> (bool, u32, u32, u8);
}

/// Error codes the worker itself sends.
pub mod code {
    /// The executor produced more than the capability allows (bytes or units).
    pub const OVER_BUDGET: u16 = 0x0101;
    /// The executor wrote an impossible length.
    pub const EXECUTOR: u16 = 0x0102;
}

/// What happened to one inbound message.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    /// Executed; frames emitted, ending with a signed FINAL.
    Done { counter: u64 },
    /// Executed, but the result was refused or failed; an ERROR frame was emitted.
    Failed { counter: u64, code: u16 },
    Quoted,
    /// Refused before anything ran. Nothing emitted.
    Refused(Refuse),
    /// The replay state could not be made durable: nothing ran, nothing emitted.
    NotDurable,
    /// Not a frame this worker understands. Nothing emitted.
    Unknown,
    /// The key refused to sign. Nothing (more) emitted.
    KeyFailed,
}

/// Where the worker's state lives on its block device (two sectors each, ADR 0069 record).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Layout {
    pub high_water_lo: u64,
    pub epoch_lo: u64,
}

pub struct Worker<D: BlockDev, K: ResultKey, E: Executor> {
    gate: WorkerGate,
    dev: D,
    layout: Layout,
    key: K,
    exec: E,
    out: [u8; limits::MAX_OUTPUT],
}

impl<D: BlockDev, K: ResultKey, E: Executor> Worker<D, K, E> {
    /// Boot: read the durable replay state. `None` if the device cannot be read at all; the worker must not
    /// serve then, because it would forget which capabilities it already ran.
    pub fn boot(dev: D, layout: Layout, key: K, exec: E, device_pk: [u8; 32], tier: Tier) -> Option<Self> {
        let high_water = durable::load(&dev, MAGIC_WORKER_HWM, layout.high_water_lo).ok()?;
        let min_epoch = u32::try_from(durable::load(&dev, MAGIC_WORKER_EPOCH, layout.epoch_lo).ok()?).ok()?;
        let gate = WorkerGate { my_pk: key.public_key(), device_pk, tier, high_water, min_epoch };
        Some(Self { gate, dev, layout, key, exec, out: [0; limits::MAX_OUTPUT] })
    }

    pub fn high_water(&self) -> u64 {
        self.gate.high_water
    }

    pub fn min_epoch(&self) -> u32 {
        self.gate.min_epoch
    }

    pub fn executor(&self) -> &E {
        &self.exec
    }

    pub fn device(&self) -> &D {
        &self.dev
    }

    /// The device's signed epoch announcement (the kill switch). The new epoch is made durable before it is
    /// acknowledged; `None` if it was refused or could not be persisted (the in-memory epoch still rose, so
    /// this boot refuses old capabilities either way).
    pub fn on_epoch(&mut self, announcement: &[u8]) -> Option<u32> {
        let e = self.gate.apply_epoch(announcement).ok()?;
        durable::raise(&mut self.dev, MAGIC_WORKER_EPOCH, self.layout.epoch_lo, u64::from(e))?;
        Some(e)
    }

    /// One inbound message on the channel bound to `session`: a quote request, or `signed capability ‖
    /// request`. Response frames go to `emit`, in order.
    pub fn handle(&mut self, tx: &[u8], session: &[u8; 32], now_ms: u64, emit: &mut dyn FnMut(&[u8])) -> Outcome {
        if tx.starts_with(&frame::QREQ_MAGIC) {
            return self.quote(tx, emit);
        }
        if tx.len() < cap::SIGNED_LEN {
            return Outcome::Unknown;
        }
        let (signed, request) = tx.split_at(cap::SIGNED_LEN);
        let c = match self.gate.accept(signed, session, request, Some(now_ms)) {
            Ok(c) => c,
            Err(e) => return Outcome::Refused(e),
        };
        // Durable BEFORE compute: once this returns, the capability can never run again on this node.
        if durable::raise(&mut self.dev, MAGIC_WORKER_HWM, self.layout.high_water_lo, c.counter).is_none()
            || durable::raise(&mut self.dev, MAGIC_WORKER_EPOCH, self.layout.epoch_lo, u64::from(c.revocation_epoch)).is_none()
        {
            return Outcome::NotDurable;
        }
        let Some(req) = Request::decode(request) else {
            return Outcome::Unknown; // the gate decoded it already; unreachable in practice
        };
        self.execute(&c, &req, emit)
    }

    fn execute(&mut self, c: &HpExec, req: &Request, emit: &mut dyn FnMut(&[u8])) -> Outcome {
        let counter = c.counter;
        let cap_id = c.capability_id;
        let budget = usize::try_from(c.req.max_response_bytes).unwrap_or(usize::MAX).min(self.out.len());
        let ran = self.exec.run(req.op, &req.model_digest, req.prompt, self.out.get_mut(..budget).unwrap_or(&mut []));
        let fail = |code: u16, emit: &mut dyn FnMut(&[u8])| {
            let mut b = [0u8; frame::RES_MAX];
            if let Some(n) = (Response { capability_id: cap_id, seq: 0, body: Body::Error(code) }).encode(&mut b) {
                emit(b.get(..n).unwrap_or(&[]));
            }
            Outcome::Failed { counter, code }
        };
        let run = match ran {
            Ok(r) => r,
            Err(code) => return fail(code, emit),
        };
        let Some(text) = self.out.get(..run.len).filter(|_| run.len <= budget) else {
            return fail(code::EXECUTOR, emit);
        };
        if units(text.len()) > c.req.max_output_units {
            return fail(code::OVER_BUDGET, emit);
        }
        let mut seq = 0u32;
        let mut b = [0u8; frame::RES_MAX];
        for chunk in text.chunks(limits::MAX_CHUNK) {
            if let Some(n) = (Response { capability_id: cap_id, seq, body: Body::Chunk(chunk) }).encode(&mut b) {
                emit(b.get(..n).unwrap_or(&[]));
            }
            seq = seq.saturating_add(1);
        }
        let usage = Usage { in_units: units(req.prompt.len()), out_units: units(text.len()), compute_ms: run.compute_ms, ttft_ms: run.ttft_ms };
        let output_hash = sha256(&[text]);
        let msg = frame::result_message(&cap_id, &c.req.request_hash, &output_hash, seq, &usage);
        let Some(sig) = self.key.sign(TAG_RESULT, &msg) else {
            return Outcome::KeyFailed;
        };
        if let Some(n) = (Response { capability_id: cap_id, seq, body: Body::Final { usage, output_hash, sig } }).encode(&mut b) {
            emit(b.get(..n).unwrap_or(&[]));
        }
        Outcome::Done { counter }
    }

    fn quote(&mut self, tx: &[u8], emit: &mut dyn FnMut(&[u8])) -> Outcome {
        let Some(q) = QuoteRequest::decode(tx) else {
            return Outcome::Unknown;
        };
        let (can_meet, ttft, tpot, profile) = self.exec.quote(&q);
        let quote = frame::Quote { job_id: q.job_id, nonce: q.nonce, can_meet, predicted_ttft_ms: ttft, predicted_tpot_ms: tpot, offload_profile: profile, valid_ms: 5_000 };
        let mut body = [0u8; frame::QUOTE_BODY_LEN];
        if quote.encode_body(&mut body).is_none() {
            return Outcome::Unknown;
        }
        let Some(sig) = self.key.sign(TAG_QUOTE, &body) else {
            return Outcome::KeyFailed;
        };
        let mut out = [0u8; frame::QUOTE_LEN];
        let (a, s) = out.split_at_mut(frame::QUOTE_BODY_LEN);
        a.copy_from_slice(&body);
        s.copy_from_slice(&sig);
        emit(&out);
        Outcome::Quoted
    }
}
