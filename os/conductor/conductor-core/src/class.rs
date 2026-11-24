// SPDX-License-Identifier: AGPL-3.0-only
//! Data classes, provider tiers and the owner policy that decides which class may reach which tier
//! (design review v2 §06). Raw captures and secrets never leave the device, whatever the policy says.

/// What a piece of data is. Ordered by sensitivity, but policy is a table, not a threshold.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum DataClass {
    /// Public CVE text, public threat intelligence, documentation.
    Public = 0,
    /// Aggregate statistics a person has reviewed for anonymity.
    AggregateReviewed = 1,
    /// Aggregate statistics, not reviewed.
    Aggregate = 2,
    /// Internal device / peer fingerprints (not anonymous: correlation can re-identify).
    Fingerprint = 3,
    /// Internal IP addresses, hostnames, user names.
    Address = 4,
    /// Raw packet captures.
    Raw = 5,
    /// Credentials, keys, tokens.
    Secret = 6,
}

impl DataClass {
    pub fn from_u8(v: u8) -> Option<Self> {
        Some(match v {
            0 => Self::Public,
            1 => Self::AggregateReviewed,
            2 => Self::Aggregate,
            3 => Self::Fingerprint,
            4 => Self::Address,
            5 => Self::Raw,
            6 => Self::Secret,
            _ => return None,
        })
    }
    pub fn bit(self) -> u8 {
        1u8 << (self as u8)
    }
}

/// Bits that may never appear in a capability's data-class mask, on any tier.
pub const NEVER_LEAVES: u8 = (1 << DataClass::Raw as u8) | (1 << DataClass::Secret as u8);
/// All defined class bits.
pub const ALL_CLASSES: u8 = 0x7f;

/// Execution providers (design review v2 §02). P0 (local) is not a remote tier and has no number here.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Tier {
    /// The owner's LAN workstation, paired by the owner, on a confined compute segment.
    P1 = 1,
    /// Other HookProbe devices: needs the `fleet_mesh` capability (ADR 0004), not built. Always refused in C0.
    P2 = 2,
    /// Untrusted cloud worker: public-class data only.
    P3 = 3,
    /// Confidential VM with the full attestation chain (CPU, and GPU where used).
    P4 = 4,
    /// External API under an explicit owner data-sharing policy.
    P5 = 5,
}

impl Tier {
    pub fn from_u8(v: u8) -> Option<Self> {
        Some(match v {
            1 => Self::P1,
            2 => Self::P2,
            3 => Self::P3,
            4 => Self::P4,
            5 => Self::P5,
            _ => return None,
        })
    }
    pub fn bit(self) -> u8 {
        1u8 << (self as u8)
    }
    /// Placement preference: the owner's own hardware first, then attested, then API, then untrusted.
    pub const PREFERENCE: [Tier; 4] = [Tier::P1, Tier::P4, Tier::P5, Tier::P3];
}

/// The owner's choices. The default is the design's default: remote execution OFF, every opt-in false.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct OwnerPolicy {
    /// Master switch. False: every job is refused with `RemoteDisabled`.
    pub remote_enabled: bool,
    /// Bitmask of enabled tiers (`Tier::bit`).
    pub tiers: u8,
    /// Fingerprints may go to the owner's LAN worker (P1) / to an attested P4.
    pub fingerprints_p1: bool,
    pub fingerprints_p4: bool,
    /// Addresses and names may go to P1 / P4.
    pub addresses_p1: bool,
    pub addresses_p4: bool,
    /// Aggregates may go to the external API (P5).
    pub aggregate_p5: bool,
    /// P4 attestation (CPU + GPU) has been demonstrated end to end (gate C3b). Until then P4 is
    /// treated as public-only, whatever the other flags say.
    pub p4_chain_proven: bool,
}

impl OwnerPolicy {
    pub fn tier_enabled(&self, t: Tier) -> bool {
        self.remote_enabled && self.tiers & t.bit() != 0
    }
}

/// May data of `class` be sent to `tier` under `policy`? This is the only place the table lives.
pub fn allowed(class: DataClass, tier: Tier, p: &OwnerPolicy) -> bool {
    if !p.tier_enabled(tier) {
        return false;
    }
    let p4_full = p.p4_chain_proven;
    match (class, tier) {
        // Never, anywhere.
        (DataClass::Raw | DataClass::Secret, _) => false,
        // fleet_mesh is not built.
        (_, Tier::P2) => false,
        (DataClass::Public, _) => true,
        (DataClass::AggregateReviewed, Tier::P1 | Tier::P3) => true,
        (DataClass::AggregateReviewed, Tier::P4) => p4_full,
        (DataClass::AggregateReviewed | DataClass::Aggregate, Tier::P5) => p.aggregate_p5,
        (DataClass::Aggregate, Tier::P1) => true,
        (DataClass::Aggregate, Tier::P4) => p4_full,
        (DataClass::Aggregate, Tier::P3) => false,
        (DataClass::Fingerprint, Tier::P1) => p.fingerprints_p1,
        (DataClass::Fingerprint, Tier::P4) => p4_full && p.fingerprints_p4,
        (DataClass::Address, Tier::P1) => p.addresses_p1,
        (DataClass::Address, Tier::P4) => p4_full && p.addresses_p4,
        (DataClass::Fingerprint | DataClass::Address, Tier::P3 | Tier::P5) => false,
    }
}

/// Every class in `mask` allowed on `tier`? Unknown bits fail closed.
pub fn mask_allowed(mask: u8, tier: Tier, p: &OwnerPolicy) -> bool {
    if mask & !ALL_CLASSES != 0 {
        return false;
    }
    (0u8..7).all(|i| {
        if mask & (1 << i) == 0 {
            return true;
        }
        match DataClass::from_u8(i) {
            Some(c) => allowed(c, tier, p),
            None => false,
        }
    })
}
