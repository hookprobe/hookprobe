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
