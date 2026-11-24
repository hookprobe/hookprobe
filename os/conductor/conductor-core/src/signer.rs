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
use crate::crypto::{hmac_sha256, public_key, sign, TAG_EPOCH, TAG_HP_EXEC};
use crate::pairing::{open_record, PairingRecord};
use crate::limits::MAX_TTL_MS;

/// Monotonic counter persisted BEFORE the value is used (ADR 0069: sealed store, one write per use).
pub trait CounterStore {
    fn advance(&mut self) -> Option<u64>;
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
    /// The pairing exists but its owner confirmation has lapsed.
    PairingExpired,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PairRefusal {
    /// Not signed by the owner key, or malformed.
    NotOwnerSigned,
    /// Not newer than the record already installed for this worker and tier (no rollback).
    Stale,
    Full,
}

/// Bytes of an epoch announcement: device_pk[32] ‖ epoch u32 ‖ issued_ms u64, then the signature.
pub const EPOCH_MSG_LEN: usize = 32 + 4 + 8;
pub const EPOCH_LEN: usize = EPOCH_MSG_LEN + 64;

pub const MAX_PAIRINGS: usize = 8;

pub struct Signer<S: CounterStore> {
    seed: [u8; 32],
    salt_key: [u8; 32],
    pk: [u8; 32],
    pub epoch: u32,
    pub policy: OwnerPolicy,
    /// Installed only through owner-signed records ([`Signer::install_pairing`]).
    pairings: [Option<PairingRecord>; MAX_PAIRINGS],
    owner_pk: [u8; 32],
    store: S,
}

impl<S: CounterStore> Signer<S> {
    /// `seed`: the delegation key (purpose: Conductor delegation only). `salt_key`: the cache-salt key.
    /// Both are distinct from the Noise static key and every other heqk key (key separation, v2 §03).
    pub fn new(seed: [u8; 32], salt_key: [u8; 32], owner_pk: [u8; 32], policy: OwnerPolicy, store: S) -> Self {
        Self { pk: public_key(&seed), seed, salt_key, epoch: 1, policy, pairings: [None; MAX_PAIRINGS], owner_pk, store }
    }

    /// Install or replace a pairing from an owner-signed record. A record for the same worker and tier
    /// replaces the old one only if its revision is higher; a revocation is a newer revision with
    /// `valid_until_ms = 0`.
    pub fn install_pairing(&mut self, bytes: &[u8], sig: &[u8; 64]) -> Result<(), PairRefusal> {
        let rec = open_record(bytes, sig, &self.owner_pk).ok_or(PairRefusal::NotOwnerSigned)?;
        if let Some(slot) = self.pairings.iter_mut().flatten().find(|p| p.tier == rec.tier && p.worker_pk == rec.worker_pk) {
            if rec.revision <= slot.revision {
                return Err(PairRefusal::Stale);
            }
            *slot = rec;
            return Ok(());
        }
        let free = self.pairings.iter_mut().find(|p| p.is_none()).ok_or(PairRefusal::Full)?;
        *free = Some(rec);
        Ok(())
    }

    pub fn pairing(&self, tier: Tier, worker_pk: &[u8; 32]) -> Option<&PairingRecord> {
        self.pairings.iter().flatten().find(|p| p.tier == tier && &p.worker_pk == worker_pk)
    }

    /// The kill switch, part 2: a signed announcement of the current epoch, which the host broadcasts to
    /// every paired worker. A worker that applies it refuses every older capability, even ones it has not
    /// seen yet.
    pub fn announce_epoch(&self, now_ms: u64) -> Option<[u8; EPOCH_LEN]> {
        let mut m = [0u8; EPOCH_MSG_LEN];
        let mut w = crate::wire::Writer::new(&mut m);
        w.put(&self.pk)?;
        w.u32(self.epoch)?;
        w.u64(now_ms)?;
        let sig = sign(&self.seed, TAG_EPOCH, &m)?;
        let mut out = [0u8; EPOCH_LEN];
        let (a, b) = out.split_at_mut(EPOCH_MSG_LEN);
        a.copy_from_slice(&m);
        b.copy_from_slice(&sig);
        Some(out)
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
        if now_ms >= pairing.valid_until_ms {
            return Err(SignRefusal::PairingExpired);
        }
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
