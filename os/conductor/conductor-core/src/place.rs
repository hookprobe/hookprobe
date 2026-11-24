// SPDX-License-Identifier: AGPL-3.0-only
//! Placement as admission (M5). One deterministic function decides which provider tier a job goes to, or
//! refuses with a reason the operator sees. The data class gates the choice before anything else; then
//! availability and the energy policy. The order of preference is the owner's own hardware first.
//!
//! In C0 there is no local inference, so packet-path pressure does not change the remote choice. Worker
//! quotes (Select-N-style SLO admission by the worker) are specified for C2 and not built here.

use crate::cap::energy;
use crate::class::{mask_allowed, OwnerPolicy, Tier};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct WorkerInfo {
    /// A worker is paired for this tier (a flag, not `Option`, so an empty table is all-zero).
    pub present: bool,
    /// The worker's key, pinned when the owner paired it.
    pub public_key: [u8; 32],
    /// The data-plane lease profile for this worker (compute segment, allowlist). The signer re-checks it.
    pub egress_policy_id: [u8; 16],
    pub available: bool,
    /// The worker reports its accelerator idle (no game, no other user).
    pub idle: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct Env {
    /// The device's delegation PUBLIC key (the harness verifies what the signer returns).
    pub device_pk: [u8; 32],
    pub policy: OwnerPolicy,
    /// Indexed by tier number (1..=5); index 0 unused.
    pub workers: [WorkerInfo; 6],
}

impl Env {
    pub fn worker(&self, t: Tier) -> Option<&WorkerInfo> {
        self.workers.get(usize::from(t as u8)).filter(|w| w.present)
    }
}

impl WorkerInfo {
    pub const EMPTY: Self = Self { present: false, public_key: [0; 32], egress_policy_id: [0; 16], available: false, idle: false };
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u16)]
pub enum PlaceRefusal {
    /// Remote execution is off (the default).
    RemoteDisabled = 1,
    /// No enabled tier may see the job's required data classes.
    NoTierForData = 2,
    /// Tiers allow the data, but no paired worker is available.
    NoWorkerAvailable = 3,
    /// The only suitable worker is busy and the job asked for idle-only.
    WorkerBusy = 4,
}

pub fn place(required_mask: u8, energy_policy: u8, env: &Env) -> Result<Tier, PlaceRefusal> {
    if !env.policy.remote_enabled {
        return Err(PlaceRefusal::RemoteDisabled);
    }
    let mut data_ok = false;
    let mut busy = false;
    for t in Tier::PREFERENCE {
        if !env.policy.tier_enabled(t) || !mask_allowed(required_mask, t, &env.policy) {
            continue;
        }
        data_ok = true;
        let Some(w) = env.worker(t) else { continue };
        if !w.available {
            continue;
        }
        if energy_policy & energy::IDLE_ONLY != 0 && !w.idle {
            busy = true;
            continue;
        }
        return Ok(t);
    }
    Err(if !data_ok {
        PlaceRefusal::NoTierForData
    } else if busy {
        PlaceRefusal::WorkerBusy
    } else {
        PlaceRefusal::NoWorkerAvailable
    })
}
