// SPDX-License-Identifier: AGPL-3.0-only
//! The worker's acceptance gate: what a worker MUST check before it runs anything. Shared code, so the
//! reference worker (C2) and the device's tests agree on one definition. Order matters: the device
//! signature is verified before any field of the body is trusted.
//!
//! Replay protection follows ADR 0069: the device's counter is monotonic and sealed; the worker keeps a
//! high-water mark per device and must persist it BEFORE executing an accepted capability.

use crate::cap::{self, HpExec, OpenError};
use crate::class::Tier;
use crate::crypto::{ct_eq, sha256};
use crate::frame::Request;
use crate::limits::units;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refuse {
    Open(OpenError),
    /// The capability names another worker.
    WrongWorker,
    /// The capability is for a tier this worker does not serve.
    WrongTier,
    /// The capability is bound to another channel session.
    Session,
    /// Counter not above the high-water mark: a replay, or a restored old device.
    Replay,
    /// Revocation epoch below the newest the worker has seen.
    Revoked,
    NotYetValid,
    Expired,
    /// The request is not the one the capability was issued for.
    RequestHash,
    RequestMalformed,
    OpNotGranted,
    ModelMismatch,
    InputTooLarge,
    /// An epoch announcement that is malformed or not signed by the paired device.
    Epoch,
}

pub struct WorkerGate {
    pub my_pk: [u8; 32],
    pub device_pk: [u8; 32],
    pub tier: Tier,
    /// Highest counter accepted from this device (persisted by the worker).
    pub high_water: u64,
    /// Newest revocation epoch seen (persisted by the worker).
    pub min_epoch: u32,
}

impl WorkerGate {
    /// Apply a signed epoch announcement from the paired device (the kill switch). Returns the new epoch.
    /// Only ever raises `min_epoch`; the worker persists it like the high-water mark.
    pub fn apply_epoch(&mut self, announcement: &[u8]) -> Result<u32, Refuse> {
        const MSG: usize = 32 + 4 + 8;
        if announcement.len() != MSG + 64 {
            return Err(Refuse::Epoch);
        }
        let (m, s) = announcement.split_at(MSG);
        let mut sig = [0u8; 64];
        sig.copy_from_slice(s);
        if !crate::crypto::verify(&self.device_pk, crate::crypto::TAG_EPOCH, m, &sig) {
            return Err(Refuse::Epoch);
        }
        let r = &mut crate::wire::Reader::new(m);
        let pk: [u8; 32] = r.arr().ok_or(Refuse::Epoch)?;
        let epoch = r.u32().ok_or(Refuse::Epoch)?;
        if !ct_eq(&pk, &self.device_pk) {
            return Err(Refuse::Epoch);
        }
        self.min_epoch = self.min_epoch.max(epoch);
        Ok(self.min_epoch)
    }

    /// `now_ms` is the worker's clock if it trusts it; `None` skips the wall-clock window (the device's
    /// lease still ends the job on time — expiry and revocation hold independently).
    pub fn accept(&mut self, signed: &[u8], session: &[u8; 32], request: &[u8], now_ms: Option<u64>) -> Result<HpExec, Refuse> {
        let c = cap::open(signed, &self.device_pk).map_err(Refuse::Open)?;
        if !ct_eq(&c.req.worker_public_key, &self.my_pk) {
            return Err(Refuse::WrongWorker);
        }
        if c.req.tier != self.tier as u8 {
            return Err(Refuse::WrongTier);
        }
        if !ct_eq(&c.req.session_binding, session) {
            return Err(Refuse::Session);
        }
        if c.revocation_epoch < self.min_epoch {
            return Err(Refuse::Revoked);
        }
        if c.counter <= self.high_water {
            return Err(Refuse::Replay);
        }
        if let Some(now) = now_ms {
            if now < c.not_before_ms {
                return Err(Refuse::NotYetValid);
            }
            if now >= c.expiry_ms {
                return Err(Refuse::Expired);
            }
        }
        if !ct_eq(&sha256(&[request]), &c.req.request_hash) {
            return Err(Refuse::RequestHash);
        }
        let r = Request::decode(request).ok_or(Refuse::RequestMalformed)?;
        if r.op & c.req.operations == 0 {
            return Err(Refuse::OpNotGranted);
        }
        if r.model_digest != c.req.model_digest {
            return Err(Refuse::ModelMismatch);
        }
        if units(r.prompt.len()) > c.req.max_input_units {
            return Err(Refuse::InputTooLarge);
        }
        self.high_water = c.counter;
        self.min_epoch = c.revocation_epoch;
        Ok(c)
    }
}
