// SPDX-License-Identifier: AGPL-3.0-only
//! Serving one paired device. The rules, in the order they are applied:
//!
//! 1. The channel only completes for the paired device identity (PQ-hybrid Noise, `chan.rs`).
//! 2. Quote requests are data-free; quotes are signed and bound to the request's nonce.
//! 3. An EXEC runs only if `WorkerGate::accept` passes: device signature, this worker's key and tier, THIS
//!    session, counter above the high-water mark, epoch, time window, exact request hash, op, model, size.
//! 4. The new high-water mark is persisted (fsync) BEFORE the engine sees the prompt.
//! 5. Output is held to the capability's byte, unit and time limits; on any breach the worker sends an
//!    ERROR frame instead of a truncated answer.
//! 6. The final frame is signed over (capability, request hash, output hash, sequence, usage).
//! 7. Nothing about content is logged: only ids, hashes, sizes and timings.

use crate::chan::{kind, Chan};
use crate::engine::{Engine, EngineError, GenRequest};
use crate::files::{Keys, Paired, State};
use crate::quote::{self, IdleProbe, Profile};
use conductor_core::cap::SIGNED_LEN;
use conductor_core::class::Tier;
use conductor_core::crypto::{sha256, sign, TAG_QUOTE, TAG_RESULT};
use conductor_core::frame::{result_message, Body, QuoteRequest, Request, Response, Usage, QUOTE_BODY_LEN};
use conductor_core::limits::{units, MAX_CHUNK};
use conductor_core::worker::{Refuse, WorkerGate};
use std::path::PathBuf;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// REFUSE codes (worker → device) when no capability could be opened, so no ERROR frame can be bound.
pub mod refuse {
    pub const GATE: u16 = 1;
    pub const MALFORMED: u16 = 2;
    pub const PERSIST: u16 = 3;
    pub const EPOCH: u16 = 4;
}

#[derive(Default, Debug, Clone, Copy)]
pub struct Stats {
    pub jobs_ok: u64,
    pub jobs_failed: u64,
    pub refused: u64,
    pub quotes: u64,
}

pub struct Worker<E: Engine> {
    pub dir: PathBuf,
    pub keys: Keys,
    pub paired: Paired,
    pub gate: WorkerGate,
    pub engine: E,
    pub profile: Profile,
    pub idle: IdleProbe,
    /// Trust the system clock for the capability's wall-clock window? (NTP-synced hosts: yes.) The device's
    /// lease ends the job on time either way.
    pub wall_clock: Option<fn() -> u64>,
    pub stats: Stats,
    pub log: fn(&str),
}

pub fn system_ms() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_millis() as u64)
}

pub fn log_stderr(s: &str) {
    eprintln!("[conductor-worker] {s}");
}

impl<E: Engine> Worker<E> {
    pub fn open(dir: PathBuf, engine: E, idle: IdleProbe) -> Result<Self, String> {
        let keys = Keys::load(&dir)?;
        let paired = Paired::load(&dir)?;
        let tier = Tier::from_u8(paired.tier).filter(|t| *t != Tier::P2).ok_or("paired: tier must be 1, 3, 4 or 5")?;
        let state = State::load(&dir)?;
        let gate = WorkerGate { my_pk: keys.result_pk(), device_pk: paired.delegation_pk, tier, high_water: state.high_water, min_epoch: state.min_epoch };
        let profile = Profile::load(&dir);
        Ok(Self { dir, keys, paired, gate, engine, profile, idle, wall_clock: None, stats: Stats::default(), log: log_stderr })
    }

    fn persist(&self) -> Result<(), String> {
        State { high_water: self.gate.high_water, min_epoch: self.gate.min_epoch }.save(&self.dir)
    }

    /// Serve one connection until BYE, error or timeout.
    pub fn serve(&mut self, chan: &mut Chan) {
        let _ = chan.set_timeout(Some(Duration::from_secs(300)));
        while let Ok((k, msg)) = chan.recv() {
            let ok = match k {
                kind::QUOTE_REQ => self.on_quote(chan, &msg),
                kind::EXEC => self.on_exec(chan, &msg),
                kind::EPOCH => self.on_epoch(chan, &msg),
                kind::BYE => return,
                _ => false,
            };
            if !ok {
                return; // any send failure or protocol error ends the connection
            }
        }
    }

    fn on_quote(&mut self, chan: &mut Chan, msg: &[u8]) -> bool {
        let Some(q) = QuoteRequest::decode(msg) else { return chan.send(kind::REFUSE, &refuse::MALFORMED.to_le_bytes()).is_ok() };
        let quote = quote::answer(&q, &self.profile, self.idle.idle());
        let mut body = [0u8; QUOTE_BODY_LEN];
        if quote.encode_body(&mut body).is_none() {
            return false;
        }
        let Some(sig) = sign(&self.keys.result_seed, TAG_QUOTE, &body) else { return false };
        let mut out = body.to_vec();
        out.extend_from_slice(&sig);
        self.stats.quotes += 1;
        (self.log)(&format!("quote job={} can_meet={} ttft={}ms tpot={}ms", crate::files::hex(&q.job_id[..4]), quote.can_meet, quote.predicted_ttft_ms, quote.predicted_tpot_ms));
        chan.send(kind::QUOTE, &out).is_ok()
    }

    fn on_epoch(&mut self, chan: &mut Chan, msg: &[u8]) -> bool {
        match self.gate.apply_epoch(msg) {
            Ok(e) => {
                if self.persist().is_err() {
                    return false;
                }
                (self.log)(&format!("epoch now {e}: older capabilities are revoked"));
                chan.send(kind::EPOCH_OK, &e.to_le_bytes()).is_ok()
            }
            Err(_) => chan.send(kind::REFUSE, &refuse::EPOCH.to_le_bytes()).is_ok(),
        }
    }

    fn on_exec(&mut self, chan: &mut Chan, msg: &[u8]) -> bool {
        if msg.len() <= SIGNED_LEN {
            self.stats.refused += 1;
            return chan.send(kind::REFUSE, &refuse::MALFORMED.to_le_bytes()).is_ok();
        }
        let (signed, request) = msg.split_at(SIGNED_LEN);
        let now = self.wall_clock.map(|f| f());
        let cap = match self.gate.accept(signed, &chan.binding, request, now) {
            Ok(c) => c,
            Err(e) => {
                self.stats.refused += 1;
                (self.log)(&format!("refused: {e:?}"));
                let mut b = refuse::GATE.to_le_bytes().to_vec();
                b.push(refuse_detail(e));
                return chan.send(kind::REFUSE, &b).is_ok();
            }
        };
        // Rule 4: the mark is durable before any work, so a crash cannot re-open this capability.
        if let Err(e) = self.persist() {
            (self.log)(&format!("cannot persist replay state, not executing: {e}"));
            let _ = chan.send(kind::REFUSE, &refuse::PERSIST.to_le_bytes());
            return false;
        }
        let req = match Request::decode(request) {
            Some(r) => r,
            None => return false, // accept() already decoded it; unreachable in practice
        };
        let prompt = String::from_utf8_lossy(req.prompt).into_owned();
        let max_bytes = (cap.req.max_response_bytes as usize).min(conductor_core::limits::MAX_OUTPUT);
        let start = Instant::now();
        let g = GenRequest {
            prompt: &prompt,
            max_out_bytes: max_bytes,
            max_out_units: cap.req.max_output_units,
            deadline: start + Duration::from_millis(u64::from(cap.req.max_compute_ms)),
            cache_scope: cap.req.cache_scope,
            cache_salt: cap.cache_salt,
            offload_hints: cap.req.offload_hints,
        };
        // Stream: coalesce engine pieces into CHUNK frames of up to MAX_CHUNK bytes.
        let mut out: Vec<u8> = Vec::new();
        let mut pending: Vec<u8> = Vec::new();
        let mut seq = 0u32;
        let mut send_ok = true;
        let cap_id = cap.capability_id;
        let flush = |chan: &mut Chan, pending: &mut Vec<u8>, seq: &mut u32| -> bool {
            for piece in pending.chunks(MAX_CHUNK) {
                let mut f = vec![0u8; conductor_core::frame::RES_MAX];
                let Some(n) = (Response { capability_id: cap_id, seq: *seq, body: Body::Chunk(piece) }).encode(&mut f) else { return false };
                if chan.send(kind::RESPONSE, &f[..n]).is_err() {
                    return false;
                }
                *seq += 1;
            }
            pending.clear();
            true
        };
        let result = self.engine.generate(&g, &mut |piece| {
            out.extend_from_slice(piece);
            pending.extend_from_slice(piece);
            if pending.len() >= 256 {
                send_ok = flush(chan, &mut pending, &mut seq);
            }
            send_ok
        });
        let compute_ms = start.elapsed().as_millis().min(u32::MAX as u128) as u32;
        let stats = match result {
            Ok(s) => s,
            Err(e) => {
                self.stats.jobs_failed += 1;
                (self.log)(&format!("job cap={} failed: {e:?}", crate::files::hex(&cap_id[..4])));
                if matches!(e, EngineError::Aborted) {
                    return false;
                }
                let mut f = vec![0u8; 64];
                let Some(n) = (Response { capability_id: cap_id, seq, body: Body::Error(e.code()) }).encode(&mut f) else { return false };
                return chan.send(kind::RESPONSE, &f[..n]).is_ok();
            }
        };
        if !send_ok || !flush(chan, &mut pending, &mut seq) {
            return false;
        }
        let usage = Usage { in_units: units(req.prompt.len()), out_units: units(out.len()), compute_ms, ttft_ms: stats.ttft_ms };
        let output_hash = sha256(&[&out]);
        let msg = result_message(&cap_id, &cap.req.request_hash, &output_hash, seq, &usage);
        let Some(sig) = sign(&self.keys.result_seed, TAG_RESULT, &msg) else { return false };
        let mut f = vec![0u8; 256];
        let Some(n) = (Response { capability_id: cap_id, seq, body: Body::Final { usage, output_hash, sig } }).encode(&mut f) else { return false };
        self.stats.jobs_ok += 1;
        (self.log)(&format!(
            "job cap={} ok in={} out={} ttft={}ms total={}ms out_hash={}",
            crate::files::hex(&cap_id[..4]),
            usage.in_units,
            usage.out_units,
            usage.ttft_ms,
            compute_ms,
            crate::files::hex(&output_hash[..6])
        ));
        chan.send(kind::RESPONSE, &f[..n]).is_ok()
    }
}

fn refuse_detail(e: Refuse) -> u8 {
    match e {
        Refuse::Open(_) => 1,
        Refuse::WrongWorker => 2,
        Refuse::WrongTier => 3,
        Refuse::Session => 4,
        Refuse::Replay => 5,
        Refuse::Revoked => 6,
        Refuse::NotYetValid => 7,
        Refuse::Expired => 8,
        Refuse::RequestHash => 9,
        Refuse::RequestMalformed => 10,
        Refuse::OpNotGranted => 11,
        Refuse::ModelMismatch => 12,
        Refuse::InputTooLarge => 13,
        Refuse::Epoch => 14,
    }
}
