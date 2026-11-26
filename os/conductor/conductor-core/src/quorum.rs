// SPDX-License-Identifier: AGPL-3.0-only
//! Verified redundancy for fleet compute (ADR 0071 amendment 2026-11-26, A3).
//!
//! The native engine is integer-only and bit-exact (ADR 0071 D8): two honest workers given the same model
//! digest and the same request return the same output bytes. Verification is therefore an exact
//! comparison of signed output hashes, with no tolerance band. Other systems have to buy or approximate
//! this: Verde/RepOps (Gensyn, arXiv 2502.19405) pays roughly 30-60 % on matmul to make floating point
//! reproducible; TOPLOC (arXiv 2501.16007) and DiFR (arXiv 2511.20621) calibrate thresholds because GPU
//! inference is not bitwise reproducible; Proof of Sampling (arXiv 2405.00295) assumes a deterministic
//! function and gets it from fixed-point arithmetic. See
//! `docs/research/heqk-fleet-compute-aggregation-2026-11-26.md`.
//!
//! Two primitives, both allocation-free:
//! * [`Quorum`]: collect worker attestations for one request; `Agreed` once `k` identical signed hashes
//!   arrive, `Conflict` the moment two validly signed hashes differ. A conflict is self-contained evidence:
//!   both votes re-verify against the request hash, so anyone holding the two worker keys can check that
//!   the workers disagreed. Who is wrong is decided against a reference result (the device's own P0 run or
//!   a further worker) with [`Quorum::disagrees_with`].
//! * [`audit_selected`]: keyed sampling of which single-run jobs are re-executed elsewhere. The key is a
//!   device secret, so a worker cannot predict which of its results will be checked.
//!
//! Lessons carried from V1 (`legacy/v1/shared/dnsXai/mesh_intelligence.py`, `.../federated/`): a sender
//! counts once (a replayed vote is refused, not counted), and every vote is signature-checked against the
//! worker key the device pinned, never a self-declared id.
//!
//! The caller is responsible for one binding this module cannot see: every attestation offered to one
//! `Quorum` must come from a capability the device issued for the same model digest and request.

use crate::crypto;
use crate::frame::{self, Usage};

/// Most votes one quorum holds. k-of-n with n up to 8 covers every policy in the amendment (k = 3 for
/// high-stakes jobs).
pub const MAX_VOTES: usize = 8;

/// Domain tag for audit selection.
pub const TAG_AUDIT: &[u8] = b"hookprobe/conductor/audit/v1\0";

/// One worker's signed final result, as received in a `Final` frame.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Vote {
    pub worker_pk: [u8; 32],
    pub cap_id: [u8; 16],
    pub output_hash: [u8; 32],
    pub seq: u32,
    pub usage: Usage,
    pub sig: [u8; 64],
}

impl Vote {
    /// True if the worker's signature binds this vote to `request_hash`.
    pub fn verifies(&self, request_hash: &[u8; 32]) -> bool {
        let m = frame::result_message(&self.cap_id, request_hash, &self.output_hash, self.seq, &self.usage);
        crypto::verify(&self.worker_pk, crypto::TAG_RESULT, &m, &self.sig)
    }
}

/// Two validly signed, contradictory results for one request. With a bit-exact engine at least one of the
/// two workers is faulty or dishonest.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Conflict {
    pub request_hash: [u8; 32],
    pub a: Vote,
    pub b: Vote,
}

impl Conflict {
    /// Re-check the evidence: both signatures valid for the same request, different outputs, different
    /// workers.
    pub fn is_valid_evidence(&self) -> bool {
        self.a.output_hash != self.b.output_hash
            && self.a.worker_pk != self.b.worker_pk
            && self.a.verifies(&self.request_hash)
            && self.b.verifies(&self.request_hash)
    }
}

// The Conflict variant carries the full evidence by value: this crate allocates nothing, so it cannot box it.
#[allow(clippy::large_enum_variant)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    /// Fewer than `k` votes, all identical so far.
    Pending { votes: u8 },
    /// `k` identical signed hashes and no disagreement.
    Agreed { output_hash: [u8; 32] },
    /// Two votes disagree. Sticky: a quorum never turns `Agreed` after a conflict.
    Conflict(Conflict),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reject {
    /// `k` outside `1..=MAX_VOTES`.
    BadK,
    /// The signature does not bind this vote to the quorum's request.
    BadSignature,
    /// This worker key already voted (a replay or a second answer is not a second vote).
    DuplicateWorker,
    /// `MAX_VOTES` already held.
    Full,
}

/// k-of-n agreement on one request.
pub struct Quorum {
    request_hash: [u8; 32],
    k: u8,
    votes: [Option<Vote>; MAX_VOTES],
    conflict: Option<Conflict>,
}

impl Quorum {
    pub fn new(request_hash: [u8; 32], k: u8) -> Result<Self, Reject> {
        if k == 0 || usize::from(k) > MAX_VOTES {
            return Err(Reject::BadK);
        }
        Ok(Self { request_hash, k, votes: [None; MAX_VOTES], conflict: None })
    }

    pub fn request_hash(&self) -> &[u8; 32] {
        &self.request_hash
    }

    fn held(&self) -> impl Iterator<Item = &Vote> {
        self.votes.iter().flatten()
    }

    /// Offer one vote. Signature first, then duplicate check, then agreement.
    pub fn offer(&mut self, v: Vote) -> Result<Outcome, Reject> {
        if !v.verifies(&self.request_hash) {
            return Err(Reject::BadSignature);
        }
        if self.held().any(|h| h.worker_pk == v.worker_pk) {
            return Err(Reject::DuplicateWorker);
        }
        let first_diff = self.held().find(|h| h.output_hash != v.output_hash).copied();
        let Some(slot) = self.votes.iter_mut().find(|s| s.is_none()) else { return Err(Reject::Full) };
        *slot = Some(v);
        if self.conflict.is_none() {
            if let Some(a) = first_diff {
                self.conflict = Some(Conflict { request_hash: self.request_hash, a, b: v });
            }
        }
        Ok(self.outcome())
    }

    pub fn votes(&self) -> u8 {
        // At most MAX_VOTES (8) entries, so the count fits.
        u8::try_from(self.held().count()).unwrap_or(u8::MAX)
    }

    pub fn outcome(&self) -> Outcome {
        if let Some(c) = self.conflict {
            return Outcome::Conflict(c);
        }
        let n = self.votes();
        match self.held().next() {
            Some(first) if n >= self.k => Outcome::Agreed { output_hash: first.output_hash },
            _ => Outcome::Pending { votes: n },
        }
    }

    /// Votes whose output differs from a trusted `reference` (the device's own P0 result, or the hash
    /// a further independent run produced). With a bit-exact engine each of these is a faulty worker.
    pub fn disagrees_with<'a>(&'a self, reference: &'a [u8; 32]) -> impl Iterator<Item = &'a Vote> + 'a {
        self.held().filter(move |v| &v.output_hash != reference)
    }
}

/// Is the single-run job `job_id` selected for re-execution on another node? Selected with probability
/// `rate_ppm` / 1 000 000, keyed by a device secret so workers cannot predict it. Deterministic for a
/// given key and job, so the decision can be recorded in the ledger and re-derived later.
pub fn audit_selected(audit_key: &[u8; 32], job_id: &[u8; 16], rate_ppm: u32) -> bool {
    if rate_ppm >= 1_000_000 {
        return true;
    }
    let h = crypto::hmac_sha256(audit_key, &[TAG_AUDIT, job_id]);
    let Some(x) = h.first_chunk::<4>() else { return true };
    let x = u64::from(u32::from_be_bytes(*x));
    // x / 2^32 < rate / 10^6  <=>  x * 10^6 < rate * 2^32 ; both sides fit in u64.
    x.saturating_mul(1_000_000) < u64::from(rate_ppm) << 32
}
