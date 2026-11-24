// SPDX-License-Identifier: AGPL-3.0-only
//! HP-EXEC capability v1 (design review v2 §03, plus the v3 offload/cache fields).
//!
//! One worker, one channel session, one request, one use. Canonical fixed-layout encoding: every field is
//! present, little-endian, at a fixed offset; there are no optional encodings, and a decoder accepts only
//! the exact length. The device's delegation key signs `TAG_HP_EXEC ‖ body`.
//!
//! The harness never signs. It fills a [`SignRequest`]; the signer (EL1 in C1, a mock in C0) adds the
//! authority fields (identity, counter, epoch, time window, ids, nonce, cache salt), enforces its own
//! policy and returns the signed blob. The harness then checks that the blob says what it asked for.

use crate::class::{self, Tier};
use crate::limits;
use crate::wire::{Reader, Writer};

pub const VERSION: u16 = 1;
pub const BODY_LEN: usize = 333;
pub const SIG_LEN: usize = 64;
pub const SIGNED_LEN: usize = BODY_LEN + SIG_LEN;

/// Operations (bitmask). C0–C2 allow only these three request-level operations (no remote app execution).
pub mod op {
    pub const INFER: u8 = 1 << 0;
    pub const EMBED: u8 = 1 << 1;
    pub const CLASSIFY: u8 = 1 << 2;
    pub const ALLOWED: u8 = INFER | EMBED | CLASSIFY;
}

/// How the worker may reuse KV / prefix caches. Reuse is only ever within the salt the device chose.
pub mod cache_scope {
    /// No reuse; the worker discards KV at the end of the call.
    pub const NONE: u8 = 0;
    /// Reuse within this job's calls only.
    pub const JOB: u8 = 1;
    /// Reuse within one affinity session (follow-up turns), same data classes, same model.
    pub const SESSION: u8 = 2;
    pub const MAX: u8 = SESSION;
}

/// Where the worker may keep KV after a call. Disk persistence is not allowed before C2's encrypted store.
pub mod kv_persist {
    pub const NONE: u8 = 0;
    pub const RAM: u8 = 1;
    pub const MAX: u8 = RAM;
}

/// Hints a worker uses to pick its offload configuration. Hints change speed, never correctness.
pub mod offload {
    pub const PREFER_THROUGHPUT: u8 = 1 << 0;
    pub const ALLOW_NVME_STREAM: u8 = 1 << 1;
    pub const ALLOW_SPECULATIVE: u8 = 1 << 2;
    pub const ALL: u8 = PREFER_THROUGHPUT | ALLOW_NVME_STREAM | ALLOW_SPECULATIVE;
}

/// Energy policy for owner hardware.
pub mod energy {
    /// Run only when the worker reports its GPU idle (no game, no other user).
    pub const IDLE_ONLY: u8 = 1 << 0;
    pub const ALL: u8 = IDLE_ONLY;
}

/// The fields the harness chooses.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SignRequest {
    pub tier: u8,
    pub worker_public_key: [u8; 32],
    pub session_binding: [u8; 32],
    pub job_id: [u8; 16],
    pub request_hash: [u8; 32],
    pub model_digest: [u8; 32],
    pub operations: u8,
    pub data_classes: u8,
    pub egress_policy_id: [u8; 16],
    pub max_input_units: u32,
    pub max_output_units: u32,
    pub max_compute_ms: u32,
    pub max_response_bytes: u32,
    pub ttl_ms: u64,
    pub slo_ttft_ms: u32,
    pub slo_tpot_ms: u32,
    pub affinity_id: [u8; 16],
    pub cache_scope: u8,
    pub kv_persist: u8,
    pub offload_hints: u8,
    pub energy_policy: u8,
}

impl SignRequest {
    pub const ZERO: Self = Self {
        tier: 0,
        worker_public_key: [0; 32],
        session_binding: [0; 32],
        job_id: [0; 16],
        request_hash: [0; 32],
        model_digest: [0; 32],
        operations: 0,
        data_classes: 0,
        egress_policy_id: [0; 16],
        max_input_units: 0,
        max_output_units: 0,
        max_compute_ms: 0,
        max_response_bytes: 0,
        ttl_ms: 0,
        slo_ttft_ms: 0,
        slo_tpot_ms: 0,
        affinity_id: [0; 16],
        cache_scope: 0,
        kv_persist: 0,
        offload_hints: 0,
        energy_policy: 0,
    };
}

/// The full signed body.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HpExec {
    pub version: u16,
    pub capability_id: [u8; 16],
    pub device_identity: [u8; 32],
    pub req: SignRequest,
    pub counter: u64,
    pub not_before_ms: u64,
    pub expiry_ms: u64,
    pub revocation_epoch: u32,
    pub nonce: [u8; 16],
    /// HMAC(device salt key, data_classes ‖ model_digest ‖ affinity_id ‖ cache_scope): the only cache
    /// namespace the worker may use. A lower-class job can never hit a higher-class prefix.
    pub cache_salt: [u8; 32],
}

impl HpExec {
    pub const ZERO: Self = Self {
        version: 0,
        capability_id: [0; 16],
        device_identity: [0; 32],
        req: SignRequest::ZERO,
        counter: 0,
        not_before_ms: 0,
        expiry_ms: 0,
        revocation_epoch: 0,
        nonce: [0; 16],
        cache_salt: [0; 32],
    };
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CapError {
    Length,
    Version,
    Tier,
    Operations,
    Classes,
    Limits,
    Window,
    Cache,
    Hints,
}

/// Checks every structural rule that does not need a key or state. Used by the signer before signing and
/// by the worker and harness after decoding, so all three agree on what a valid capability is.
pub fn check_request(r: &SignRequest) -> Result<(), CapError> {
    match Tier::from_u8(r.tier) {
        None | Some(Tier::P2) => return Err(CapError::Tier),
        Some(_) => {}
    }
    if r.operations == 0 || r.operations & !op::ALLOWED != 0 {
        return Err(CapError::Operations);
    }
    if r.data_classes & !class::ALL_CLASSES != 0 || r.data_classes & class::NEVER_LEAVES != 0 {
        return Err(CapError::Classes);
    }
    let lim_ok = (1..=limits::MAX_IN_UNITS).contains(&r.max_input_units)
        && (1..=limits::MAX_OUT_UNITS).contains(&r.max_output_units)
        && (1..=limits::MAX_COMPUTE_MS).contains(&r.max_compute_ms)
        && r.max_response_bytes >= 1
        && usize::try_from(r.max_response_bytes).is_ok_and(|b| b <= limits::MAX_OUTPUT);
    if !lim_ok {
        return Err(CapError::Limits);
    }
    if r.ttl_ms == 0 || r.ttl_ms > limits::MAX_TTL_MS {
        return Err(CapError::Window);
    }
    if r.cache_scope > cache_scope::MAX || r.kv_persist > kv_persist::MAX {
        return Err(CapError::Cache);
    }
    // KV kept after the call needs a scope that names who may reuse it.
    if r.kv_persist != kv_persist::NONE && r.cache_scope == cache_scope::NONE {
        return Err(CapError::Cache);
    }
    // Session reuse needs an affinity id; an affinity id without reuse is harmless (routing only).
    if r.cache_scope == cache_scope::SESSION && r.affinity_id == [0; 16] {
        return Err(CapError::Cache);
    }
    if r.offload_hints & !offload::ALL != 0 || r.energy_policy & !energy::ALL != 0 {
        return Err(CapError::Hints);
    }
    Ok(())
}

impl HpExec {
    pub fn encode(&self, out: &mut [u8; BODY_LEN]) -> Option<()> {
        let r = &self.req;
        let mut w = Writer::new(out);
        w.u16(self.version)?;
        w.put(&self.capability_id)?;
        w.put(&self.device_identity)?;
        w.put(&r.worker_public_key)?;
        w.put(&r.session_binding)?;
        w.put(&r.job_id)?;
        w.u64(self.counter)?;
        w.put(&r.request_hash)?;
        w.put(&r.model_digest)?;
        w.u8(r.operations)?;
        w.u8(r.data_classes)?;
        w.u8(r.tier)?;
        w.put(&r.egress_policy_id)?;
        w.u32(r.max_input_units)?;
        w.u32(r.max_output_units)?;
        w.u32(r.max_compute_ms)?;
        w.u32(r.max_response_bytes)?;
        w.u64(self.not_before_ms)?;
        w.u64(self.expiry_ms)?;
        w.u32(self.revocation_epoch)?;
        w.put(&self.nonce)?;
        w.u32(r.slo_ttft_ms)?;
        w.u32(r.slo_tpot_ms)?;
        w.put(&r.affinity_id)?;
        w.u8(r.cache_scope)?;
        w.u8(r.kv_persist)?;
        w.u8(r.offload_hints)?;
        w.u8(r.energy_policy)?;
        w.put(&self.cache_salt)?;
        (w.len() == BODY_LEN).then_some(())
    }

    /// Decode and structurally validate a body. Does NOT verify the signature (see [`open`]).
    pub fn decode(b: &[u8]) -> Result<Self, CapError> {
        if b.len() != BODY_LEN {
            return Err(CapError::Length);
        }
        let mut rd = Reader::new(b);
        let e = CapError::Length;
        let version = rd.u16().ok_or(e)?;
        if version != VERSION {
            return Err(CapError::Version);
        }
        let capability_id = rd.arr().ok_or(e)?;
        let device_identity = rd.arr().ok_or(e)?;
        let worker_public_key = rd.arr().ok_or(e)?;
        let session_binding = rd.arr().ok_or(e)?;
        let job_id = rd.arr().ok_or(e)?;
        let counter = rd.u64().ok_or(e)?;
        let request_hash = rd.arr().ok_or(e)?;
        let model_digest = rd.arr().ok_or(e)?;
        let operations = rd.u8().ok_or(e)?;
        let data_classes = rd.u8().ok_or(e)?;
        let tier = rd.u8().ok_or(e)?;
        let egress_policy_id = rd.arr().ok_or(e)?;
        let max_input_units = rd.u32().ok_or(e)?;
        let max_output_units = rd.u32().ok_or(e)?;
        let max_compute_ms = rd.u32().ok_or(e)?;
        let max_response_bytes = rd.u32().ok_or(e)?;
        let not_before_ms = rd.u64().ok_or(e)?;
        let expiry_ms = rd.u64().ok_or(e)?;
        let revocation_epoch = rd.u32().ok_or(e)?;
        let nonce = rd.arr().ok_or(e)?;
        let slo_ttft_ms = rd.u32().ok_or(e)?;
        let slo_tpot_ms = rd.u32().ok_or(e)?;
        let affinity_id = rd.arr().ok_or(e)?;
        let cache_scope = rd.u8().ok_or(e)?;
        let kv_persist = rd.u8().ok_or(e)?;
        let offload_hints = rd.u8().ok_or(e)?;
        let energy_policy = rd.u8().ok_or(e)?;
        let cache_salt = rd.arr().ok_or(e)?;
        if !rd.done() {
            return Err(CapError::Length);
        }
        let window = expiry_ms.checked_sub(not_before_ms).ok_or(CapError::Window)?;
        let req = SignRequest {
            tier,
            worker_public_key,
            session_binding,
            job_id,
            request_hash,
            model_digest,
            operations,
            data_classes,
            egress_policy_id,
            max_input_units,
            max_output_units,
            max_compute_ms,
            max_response_bytes,
            ttl_ms: window,
            slo_ttft_ms,
            slo_tpot_ms,
            affinity_id,
            cache_scope,
            kv_persist,
            offload_hints,
            energy_policy,
        };
        check_request(&req)?;
        Ok(Self {
            version,
            capability_id,
            device_identity,
            req,
            counter,
            not_before_ms,
            expiry_ms,
            revocation_epoch,
            nonce,
            cache_salt,
        })
    }
}

/// Split a signed blob, verify the device signature FIRST, then decode. Nothing in an unverified body is
/// trusted, not even its length fields.
pub fn open(signed: &[u8], device_pk: &[u8; 32]) -> Result<HpExec, OpenError> {
    if signed.len() != SIGNED_LEN {
        return Err(OpenError::Length);
    }
    let (body, sig) = signed.split_at(BODY_LEN);
    let mut s = [0u8; SIG_LEN];
    s.copy_from_slice(sig);
    if !crate::crypto::verify(device_pk, crate::crypto::TAG_HP_EXEC, body, &s) {
        return Err(OpenError::Signature);
    }
    let cap = HpExec::decode(body).map_err(OpenError::Invalid)?;
    if !crate::crypto::ct_eq(&cap.device_identity, device_pk) {
        return Err(OpenError::Identity);
    }
    Ok(cap)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OpenError {
    Length,
    Signature,
    Identity,
    Invalid(CapError),
}
