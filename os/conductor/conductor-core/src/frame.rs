// SPDX-License-Identifier: AGPL-3.0-only
//! Request-level frames. The device sends one REQUEST per call; the worker streams CHUNKs and ends with one
//! FINAL (signed by the worker's pinned key) or one ERROR. Tensors never cross this protocol: a worker may
//! offload inside its own boundary however it likes, but only prompts and tokens move between machines.
//!
//! Exact-length formats; every decoder rejects trailing bytes and out-of-range lengths.

use crate::limits;
use crate::wire::{Reader, Writer};

pub const REQ_MAGIC: [u8; 4] = *b"HQRQ";
pub const RES_MAGIC: [u8; 4] = *b"HQRS";
pub const FRAME_VERSION: u8 = 1;
pub const REQ_HEADER: usize = 4 + 1 + 1 + 32 + 2;
pub const REQ_MAX: usize = REQ_HEADER + limits::MAX_PROMPT;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Request<'a> {
    pub op: u8,
    pub model_digest: [u8; 32],
    pub prompt: &'a [u8],
}

impl<'a> Request<'a> {
    pub fn encode(&self, out: &mut [u8]) -> Option<usize> {
        if self.prompt.len() > limits::MAX_PROMPT {
            return None;
        }
        let mut w = Writer::new(out);
        w.put(&REQ_MAGIC)?;
        w.u8(FRAME_VERSION)?;
        w.u8(self.op)?;
        w.put(&self.model_digest)?;
        w.u16(u16::try_from(self.prompt.len()).ok()?)?;
        w.put(self.prompt)?;
        Some(w.len())
    }
    pub fn decode(b: &'a [u8]) -> Option<Self> {
        let mut r = Reader::new(b);
        if r.arr::<4>()? != REQ_MAGIC || r.u8()? != FRAME_VERSION {
            return None;
        }
        let op = r.u8()?;
        if op.count_ones() != 1 || op & crate::cap::op::ALLOWED == 0 {
            return None;
        }
        let model_digest = r.arr()?;
        let n = usize::from(r.u16()?);
        if n > limits::MAX_PROMPT {
            return None;
        }
        let prompt = r.take(n)?;
        r.done().then_some(Self { op, model_digest, prompt })
    }
}

pub mod kind {
    pub const CHUNK: u8 = 1;
    pub const FINAL: u8 = 2;
    pub const ERROR: u8 = 3;
}

/// The figures a worker reports with its final frame. The device checks each against the capability and
/// against its own measurement.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Usage {
    pub in_units: u32,
    pub out_units: u32,
    pub compute_ms: u32,
    pub ttft_ms: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Body<'a> {
    Chunk(&'a [u8]),
    Final { usage: Usage, output_hash: [u8; 32], sig: [u8; 64] },
    Error(u16),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Response<'a> {
    pub capability_id: [u8; 16],
    pub seq: u32,
    pub body: Body<'a>,
}

pub const RES_HEADER: usize = 4 + 1 + 1 + 16 + 4;
pub const RES_MAX: usize = RES_HEADER + 2 + limits::MAX_CHUNK;

impl<'a> Response<'a> {
    pub fn encode(&self, out: &mut [u8]) -> Option<usize> {
        let mut w = Writer::new(out);
        w.put(&RES_MAGIC)?;
        w.u8(FRAME_VERSION)?;
        let k = match self.body {
            Body::Chunk(_) => kind::CHUNK,
            Body::Final { .. } => kind::FINAL,
            Body::Error(_) => kind::ERROR,
        };
        w.u8(k)?;
        w.put(&self.capability_id)?;
        w.u32(self.seq)?;
        match self.body {
            Body::Chunk(d) => {
                if d.is_empty() || d.len() > limits::MAX_CHUNK {
                    return None;
                }
                w.u16(u16::try_from(d.len()).ok()?)?;
                w.put(d)?;
            }
            Body::Final { usage, output_hash, sig } => {
                w.u32(usage.in_units)?;
                w.u32(usage.out_units)?;
                w.u32(usage.compute_ms)?;
                w.u32(usage.ttft_ms)?;
                w.put(&output_hash)?;
                w.put(&sig)?;
            }
            Body::Error(c) => w.u16(c)?,
        }
        Some(w.len())
    }

    pub fn decode(b: &'a [u8]) -> Option<Self> {
        let mut r = Reader::new(b);
        if r.arr::<4>()? != RES_MAGIC || r.u8()? != FRAME_VERSION {
            return None;
        }
        let k = r.u8()?;
        let capability_id = r.arr()?;
        let seq = r.u32()?;
        let body = match k {
            kind::CHUNK => {
                let n = usize::from(r.u16()?);
                if n == 0 || n > limits::MAX_CHUNK {
                    return None;
                }
                Body::Chunk(r.take(n)?)
            }
            kind::FINAL => Body::Final {
                usage: Usage { in_units: r.u32()?, out_units: r.u32()?, compute_ms: r.u32()?, ttft_ms: r.u32()? },
                output_hash: r.arr()?,
                sig: r.arr()?,
            },
            kind::ERROR => Body::Error(r.u16()?),
            _ => return None,
        };
        r.done().then_some(Self { capability_id, seq, body })
    }
}

/// The message a worker signs over its final result (with `crypto::TAG_RESULT`). It binds the result to the
/// capability, the exact request, the exact output and the reported usage, so the ledger can attribute
/// every result to one worker key, independent of the channel.
pub fn result_message(cap_id: &[u8; 16], request_hash: &[u8; 32], output_hash: &[u8; 32], seq: u32, u: &Usage) -> [u8; 100] {
    let mut m = [0u8; 100];
    let mut w = Writer::new(&mut m);
    // Fixed sizes: 16 + 32 + 32 + 4 + 16 = 100, so these cannot fail.
    let _ = w.put(cap_id);
    let _ = w.put(request_hash);
    let _ = w.put(output_hash);
    let _ = w.u32(seq);
    let _ = w.u32(u.in_units);
    let _ = w.u32(u.out_units);
    let _ = w.u32(u.compute_ms);
    let _ = w.u32(u.ttft_ms);
    m
}

// ------------------------------------------------------------------ SLO admission quotes (Select-N style)
//
// Before any data leaves, the device may ask a worker whether it can meet the job's time targets at its
// current offload configuration (all in VRAM, experts in RAM, NVMe streaming, …). The request carries only
// sizes and targets, never content. The worker's answer is signed by its pinned key and bound to the
// request's fresh nonce, so a quote cannot be replayed into another job or forged by the network. heqk is
// the "upper-level scheduler" Select-N hands a request back to when a worker cannot meet the SLO.

pub const QREQ_MAGIC: [u8; 4] = *b"HQQR";
pub const QUOTE_MAGIC: [u8; 4] = *b"HQQT";
pub const QREQ_LEN: usize = 4 + 1 + 16 + 32 + 4 + 4 + 4 + 4 + 1 + 1 + 16;
pub const QUOTE_BODY_LEN: usize = 4 + 1 + 16 + 16 + 1 + 4 + 4 + 1 + 4;
pub const QUOTE_LEN: usize = QUOTE_BODY_LEN + 64;

/// Offload profile a worker reports (informational; placement only ever changes speed, never correctness).
pub mod profile {
    pub const ALL_IN_VRAM: u8 = 1;
    pub const EXPERTS_IN_RAM: u8 = 2;
    pub const NVME_STREAM: u8 = 3;
    pub const CPU_ONLY: u8 = 4;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct QuoteRequest {
    pub job_id: [u8; 16],
    pub model_digest: [u8; 32],
    pub in_units: u32,
    pub max_out_units: u32,
    pub slo_ttft_ms: u32,
    pub slo_tpot_ms: u32,
    pub offload_hints: u8,
    pub energy_policy: u8,
    pub nonce: [u8; 16],
}

impl QuoteRequest {
    pub fn encode(&self, out: &mut [u8]) -> Option<usize> {
        let mut w = Writer::new(out);
        w.put(&QREQ_MAGIC)?;
        w.u8(FRAME_VERSION)?;
        w.put(&self.job_id)?;
        w.put(&self.model_digest)?;
        w.u32(self.in_units)?;
        w.u32(self.max_out_units)?;
        w.u32(self.slo_ttft_ms)?;
        w.u32(self.slo_tpot_ms)?;
        w.u8(self.offload_hints)?;
        w.u8(self.energy_policy)?;
        w.put(&self.nonce)?;
        Some(w.len())
    }
    pub fn decode(b: &[u8]) -> Option<Self> {
        let r = &mut Reader::new(b);
        if r.arr::<4>()? != QREQ_MAGIC || r.u8()? != FRAME_VERSION {
            return None;
        }
        let q = Self {
            job_id: r.arr()?,
            model_digest: r.arr()?,
            in_units: r.u32()?,
            max_out_units: r.u32()?,
            slo_ttft_ms: r.u32()?,
            slo_tpot_ms: r.u32()?,
            offload_hints: r.u8()?,
            energy_policy: r.u8()?,
            nonce: r.arr()?,
        };
        r.done().then_some(q)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Quote {
    pub job_id: [u8; 16],
    pub nonce: [u8; 16],
    pub can_meet: bool,
    pub predicted_ttft_ms: u32,
    pub predicted_tpot_ms: u32,
    pub offload_profile: u8,
    pub valid_ms: u32,
}

impl Quote {
    pub fn encode_body(&self, out: &mut [u8; QUOTE_BODY_LEN]) -> Option<()> {
        let mut w = Writer::new(out);
        w.put(&QUOTE_MAGIC)?;
        w.u8(FRAME_VERSION)?;
        w.put(&self.job_id)?;
        w.put(&self.nonce)?;
        w.u8(u8::from(self.can_meet))?;
        w.u32(self.predicted_ttft_ms)?;
        w.u32(self.predicted_tpot_ms)?;
        w.u8(self.offload_profile)?;
        w.u32(self.valid_ms)?;
        (w.len() == QUOTE_BODY_LEN).then_some(())
    }
    /// Decode and verify a signed quote with the worker's pinned key.
    pub fn open(b: &[u8], worker_pk: &[u8; 32]) -> Option<Self> {
        if b.len() != QUOTE_LEN {
            return None;
        }
        let (body, sig) = b.split_at(QUOTE_BODY_LEN);
        let mut s = [0u8; 64];
        s.copy_from_slice(sig);
        if !crate::crypto::verify(worker_pk, crate::crypto::TAG_QUOTE, body, &s) {
            return None;
        }
        let r = &mut Reader::new(body);
        if r.arr::<4>()? != QUOTE_MAGIC || r.u8()? != FRAME_VERSION {
            return None;
        }
        let q = Self {
            job_id: r.arr()?,
            nonce: r.arr()?,
            can_meet: match r.u8()? {
                0 => false,
                1 => true,
                _ => return None,
            },
            predicted_ttft_ms: r.u32()?,
            predicted_tpot_ms: r.u32()?,
            offload_profile: r.u8()?,
            valid_ms: r.u32()?,
        };
        r.done().then_some(q)
    }
    /// Does this quote meet the targets? A zero target means "no target".
    pub fn meets(&self, slo_ttft_ms: u32, slo_tpot_ms: u32) -> bool {
        self.can_meet
            && (slo_ttft_ms == 0 || self.predicted_ttft_ms <= slo_ttft_ms)
            && (slo_tpot_ms == 0 || self.predicted_tpot_ms <= slo_tpot_ms)
    }
}
