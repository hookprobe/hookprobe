// SPDX-License-Identifier: AGPL-3.0-only
//! The delegation signer. In C1 this runs in EL1 (the key never leaves the kernel); in C0 it is used by the
//! host mock. It is written so it can be lifted as is: no allocation, no I/O except the counter store.
//!
//! It does NOT trust the harness. It re-checks every structural rule, signs only for a paired worker with
//! that worker's egress profile, re-checks the data classes against its own copy of the owner policy, adds
//! the authority fields itself and derives the cache salt, so a compromised harness can obtain nothing it
//! could not have obtained honestly.

use crate::cap::{check_request, CapError, HpExec, SignRequest, BODY_LEN, SIGNED_LEN, VERSION};
use crate::class::{mask_allowed, OwnerPolicy, Tier};
use crate::crypto::{hmac_sha256, public_key, sign, TAG_HP_EXEC};
use crate::limits::MAX_TTL_MS;

/// Monotonic counter persisted BEFORE the value is used (ADR 0069: sealed store, one write per use).
pub trait CounterStore {
    fn advance(&mut self) -> Option<u64>;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Pairing {
    pub tier: Tier,
    pub worker_pk: [u8; 32],
    pub egress_policy_id: [u8; 16],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SignRefusal {
    Invalid(CapError),
    NotPaired,
    EgressMismatch,
    ClassesNotAllowed,
    Counter,
    Clock,
    Encode,
}

pub const MAX_PAIRINGS: usize = 8;

pub struct Signer<S: CounterStore> {
    seed: [u8; 32],
    salt_key: [u8; 32],
    pk: [u8; 32],
    pub epoch: u32,
    pub policy: OwnerPolicy,
    pub pairings: [Option<Pairing>; MAX_PAIRINGS],
    store: S,
}

impl<S: CounterStore> Signer<S> {
    /// `seed`: the delegation key (purpose: Conductor delegation only). `salt_key`: the cache-salt key.
    /// Both are distinct from the Noise static key and every other heqk key (key separation, v2 §03).
    pub fn new(seed: [u8; 32], salt_key: [u8; 32], policy: OwnerPolicy, store: S) -> Self {
        Self { pk: public_key(&seed), seed, salt_key, epoch: 1, policy, pairings: [None; MAX_PAIRINGS], store }
    }

    pub fn public_key(&self) -> [u8; 32] {
        self.pk
    }

    /// The owner's kill switch: every capability issued before this is refused by workers that learn the
    /// new epoch, and the data plane ends every lease (the host's job).
    pub fn bump_epoch(&mut self) -> Option<u32> {
        self.epoch = self.epoch.checked_add(1)?;
        Some(self.epoch)
    }

    pub fn sign(&mut self, r: &SignRequest, now_ms: u64, entropy: &mut dyn FnMut(&mut [u8])) -> Result<[u8; SIGNED_LEN], SignRefusal> {
        check_request(r).map_err(SignRefusal::Invalid)?;
        let tier = Tier::from_u8(r.tier).ok_or(SignRefusal::Invalid(CapError::Tier))?;
        let pairing = self
            .pairings
            .iter()
            .flatten()
            .find(|p| p.tier == tier && p.worker_pk == r.worker_public_key)
            .ok_or(SignRefusal::NotPaired)?;
        if pairing.egress_policy_id != r.egress_policy_id {
            return Err(SignRefusal::EgressMismatch);
        }
        if !mask_allowed(r.data_classes, tier, &self.policy) {
            return Err(SignRefusal::ClassesNotAllowed);
        }
        let ttl = r.ttl_ms.min(MAX_TTL_MS);
        let expiry = now_ms.checked_add(ttl).ok_or(SignRefusal::Clock)?;
        let counter = self.store.advance().ok_or(SignRefusal::Counter)?;
        let mut capability_id = [0u8; 16];
        let mut nonce = [0u8; 16];
        entropy(&mut capability_id);
        entropy(&mut nonce);
        let cache_salt = hmac_sha256(
            &self.salt_key,
            &[&[r.data_classes, r.cache_scope, r.tier], &r.model_digest, &r.affinity_id],
        );
        let cap = HpExec {
            version: VERSION,
            capability_id,
            device_identity: self.pk,
            req: SignRequest { ttl_ms: ttl, ..*r },
            counter,
            not_before_ms: now_ms,
            expiry_ms: expiry,
            revocation_epoch: self.epoch,
            nonce,
            cache_salt,
        };
        let mut body = [0u8; BODY_LEN];
        cap.encode(&mut body).ok_or(SignRefusal::Encode)?;
        let sig = sign(&self.seed, TAG_HP_EXEC, &body).ok_or(SignRefusal::Encode)?;
        let mut out = [0u8; SIGNED_LEN];
        let (a, b) = out.split_at_mut(BODY_LEN);
        a.copy_from_slice(&body);
        b.copy_from_slice(&sig);
        Ok(out)
    }
}
