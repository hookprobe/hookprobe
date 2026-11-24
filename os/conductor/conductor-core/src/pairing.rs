// SPDX-License-Identifier: AGPL-3.0-only
//! Owner pairing of a worker (C2 logic, built and tested now). Defends the one step where a LAN attacker
//! could substitute their own worker key: the first exchange of public keys.
//!
//! Commit-then-reveal numeric comparison (the Bluetooth LE Secure Connections pattern):
//! 1. worker → device: `worker_pk`, `commit = SHA-256(TAG_COMMIT ‖ worker_pk ‖ worker_nonce)`
//! 2. device → worker: `device_pk`, `device_nonce`
//! 3. worker → device: `worker_nonce` (the device checks it against `commit`)
//! 4. both show `sas()`, six digits over both keys and both nonces; the OWNER compares the two screens
//!    and confirms in Mission Control.
//!
//! The commitment stops a man in the middle from choosing its nonce after seeing the device's, so it gets
//! one 1-in-a-million guess per attempt, and every failed attempt is visible to the owner. On
//! confirmation, the owner's key signs a [`PairingRecord`]; the delegation signer installs pairings only
//! from such a record, so a compromised harness cannot pair a worker.

use crate::class::Tier;
use crate::crypto::{ct_eq, sha256, verify};
use crate::wire::{Reader, Writer};

pub const TAG_COMMIT: &[u8] = b"hookprobe/conductor/pair-commit/v1\0";
pub const TAG_SAS: &[u8] = b"hookprobe/conductor/pair-sas/v1\0";
/// Owner signature over a pairing record (an owner-key purpose distinct from every other owner action).
pub const TAG_RECORD: &[u8] = b"hookprobe/conductor/pairing/v1\0";

pub fn commit(worker_pk: &[u8; 32], worker_nonce: &[u8; 16]) -> [u8; 32] {
    sha256(&[TAG_COMMIT, worker_pk, worker_nonce])
}

pub fn check_commit(c: &[u8; 32], worker_pk: &[u8; 32], worker_nonce: &[u8; 16]) -> bool {
    ct_eq(c, &commit(worker_pk, worker_nonce))
}

/// The six-digit comparison value, 000000..=999999.
pub fn sas(device_pk: &[u8; 32], worker_pk: &[u8; 32], device_nonce: &[u8; 16], worker_nonce: &[u8; 16]) -> u32 {
    let h = sha256(&[TAG_SAS, device_pk, worker_pk, device_nonce, worker_nonce]);
    let v = u32::from_le_bytes([h[0], h[1], h[2], h[3]]);
    v % 1_000_000
}

pub const RECORD_LEN: usize = 1 + 32 + 16 + 8 + 4;

/// What the owner approves: this worker key, for this tier, with this data-plane egress profile, until
/// this time. `revision` lets a newer record replace an older one and never the reverse.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PairingRecord {
    pub tier: Tier,
    pub worker_pk: [u8; 32],
    pub egress_policy_id: [u8; 16],
    /// Device monotonic time after which the pairing lapses (owners re-confirm periodically).
    pub valid_until_ms: u64,
    pub revision: u32,
}

impl PairingRecord {
    pub fn encode(&self, out: &mut [u8; RECORD_LEN]) {
        let mut w = Writer::new(out);
        // Fixed sizes summing to RECORD_LEN.
        let _ = w.u8(self.tier as u8);
        let _ = w.put(&self.worker_pk);
        let _ = w.put(&self.egress_policy_id);
        let _ = w.u64(self.valid_until_ms);
        let _ = w.u32(self.revision);
    }
    pub fn decode(b: &[u8]) -> Option<Self> {
        let r = &mut Reader::new(b);
        let tier = Tier::from_u8(r.u8()?)?;
        if tier == Tier::P2 {
            return None; // fleet_mesh is not built
        }
        let rec = Self { tier, worker_pk: r.arr()?, egress_policy_id: r.arr()?, valid_until_ms: r.u64()?, revision: r.u32()? };
        r.done().then_some(rec)
    }
}

/// Verify an owner-signed pairing record.
pub fn open_record(bytes: &[u8], sig: &[u8; 64], owner_pk: &[u8; 32]) -> Option<PairingRecord> {
    if !verify(owner_pk, TAG_RECORD, bytes, sig) {
        return None;
    }
    PairingRecord::decode(bytes)
}
