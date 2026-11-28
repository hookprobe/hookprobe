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

/// Execution providers (ADR 0071 amendment A1). Every provider is a heqk node. P0 (the engine on this
/// device) is not a remote tier and has no number here. Numbers 4 and 5 were a GPU confidential VM and an
/// external API; both are removed and are refused wherever a tier is decoded.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Tier {
    /// The owner's paired heqk node on the LAN, on a confined compute segment.
    P1 = 1,
    /// HookProbe peers: needs the `fleet_mesh` capability (ADR 0004), not built. Always refused.
    P2 = 2,
    /// A heqk node in the cloud: public-class and reviewed-aggregate data only.
    P3 = 3,
}

impl Tier {
    pub fn from_u8(v: u8) -> Option<Self> {
        Some(match v {
            1 => Self::P1,
            2 => Self::P2,
            3 => Self::P3,
            _ => return None,
        })
    }
    pub fn bit(self) -> u8 {
        1u8 << (self as u8)
    }
    /// Number of slots in a table indexed by tier number (index 0 unused).
    pub const SLOTS: usize = 4;
    /// Bits of the tiers that exist.
    pub const ALL_BITS: u8 = 0b1110;
    /// Placement preference: the owner's own node first, then the cloud node. P2 is not placed until
    /// `fleet_mesh` exists.
    pub const PREFERENCE: [Tier; 2] = [Tier::P1, Tier::P3];
}

/// The owner's choices. The default is the design's default: remote execution OFF, every opt-in false.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct OwnerPolicy {
    /// Master switch. False: every job is refused with `RemoteDisabled`.
    pub remote_enabled: bool,
    /// Bitmask of enabled tiers (`Tier::bit`).
    pub tiers: u8,
    /// Fingerprints may go to the owner's paired LAN node (P1).
    pub fingerprints_p1: bool,
    /// Addresses and names may go to P1.
    pub addresses_p1: bool,
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
    match (class, tier) {
        // Never, anywhere.
        (DataClass::Raw | DataClass::Secret, _) => false,
        // fleet_mesh is not built.
        (_, Tier::P2) => false,
        (DataClass::Public, _) => true,
        (DataClass::AggregateReviewed, Tier::P1 | Tier::P3) => true,
        (DataClass::Aggregate, Tier::P1) => true,
        (DataClass::Aggregate, Tier::P3) => false,
        (DataClass::Fingerprint, Tier::P1) => p.fingerprints_p1,
        (DataClass::Address, Tier::P1) => p.addresses_p1,
        (DataClass::Fingerprint | DataClass::Address, Tier::P3) => false,
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
