//! M-segmentation — the per-device REACH plane: the on-device ACTUATOR the U2b unbuild,
//! L5/L6 NAC onboarding, and A11 quarantine-to-segment all need. heqk's single aggregate
//! inline port + binary verdict cannot switch VLANs/segments, but it CAN enforce a per-device
//! REACH policy — which destination scopes a source device is allowed to reach — which is
//! what "segmentation" reduces to on an inline sensor/gateway.
//!
//! CRITICAL DESIGN (security-auditor CONDITIONAL-GO, 2026-09-08, C1-C8): reach is **SET BY AN
//! AUTHORITY** (the reconciler/NAC/signed manifest — off-device per ADR 0044 D3), **NEVER
//! inferred by heqk**. heqk is a pure ENFORCEMENT engine here — it applies the operator's
//! expressed policy. This is why a reach-drop is defensible where A11's inference-drop was
//! NO-GO (`corroboration.rs:8-23`): enforcement keys on the frame's OWN src, so a spoofed src
//! only applies the victim's reach to the ATTACKER's frames — there is **no victim-framing
//! path** (A11's fatal flaw). The residual spoofing risk is only that an already-hostile
//! attacker escapes his OWN containment — strictly weaker, degrading to no-worse-than-no-
//! segmentation. Modeled on the shipped kill-switch (`edge.rs::egress_allowed`), a policy
//! wire-drop consulted AFTER the threat pipeline PASSes — NOT a `FindingClass` in `decide()`.
//!
//! Conditions honored here:
//! * C1 FAIL-OPEN — Full is the default; unknown/expired/collision → Full (never a dropping
//!   state). Entries are TTL-leased and expire to Full. A standalone/air-gapped box, and any
//!   device the authority never named, is NEVER segmented (deny-list, never allow-list).
//! * C2 INFRA CARVE-OUT — never drop the path to DHCP(255.255.255.255)/link-local/subnet-
//!   broadcast/(authority-supplied gateway+DNS). ARP/ND pass inherently (no IPv4 dst → not
//!   LAN-internal). Without the gateway carve-out InternetOnly cannot reach the internet, so
//!   the gateway/DNS are set by the same authority via `set_infra`.
//! * C3 MGMT FLOOR — an `is_allowlisted` src is never segmented (checked before reach lookup).
//! * C4 KEY ON MAC (`ratelimit::mac_hash`) — survives DHCP churn, aligns with NAC identity.
//!   On-segment spoofing still defeats containment against an ACTIVE spoofer; cryptographic
//!   containment (ingress-port binding) is blocked on the P9 multi-port RX (aggregate port 0).
//! * C5 distinct INFO telemetry (`RULE_SEG_POLICY` = 1000050) — a policy drop, NOT a threat;
//!   must not feed QSecBit / corroboration / the threat score.
//! * C6 a SEPARATE gate after the threat pipeline PASSes (kill-switch pattern).
//! * C7 BUILD-but-DO-NOT-ARM — `REACH_ARMED` defaults false; the gate is a no-op until an
//!   AUTHENTICATED reach channel provisions policy (mirrors the WAN-kill-switch fail-closed
//!   posture). Until then a device set to InternetOnly/Quarantine is still passed.
//! * C8 bounded table with collision-EVICT-toward-Full discipline.

use core::sync::atomic::{AtomicBool, AtomicU64, AtomicU8, Ordering};

/// Per-device reach policy (authority-set). `Full` is the fail-safe default.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Reach {
    /// Full LAN + WAN reach (default; never strand a legit device).
    Full,
    /// Internet only — LAN-internal peers blocked, WAN allowed (via the carved-out gateway).
    /// L6: a stale unclassified device past its onboarding grace.
    InternetOnly,
    /// Lateral containment — LAN-internal peers blocked (WAN per policy allowed here). A11's
    /// quarantine-to-segment.
    Quarantine,
}

const R_FULL: u8 = 0; // the fail-safe default code
const R_INTERNET_ONLY: u8 = 1;
const R_QUARANTINE: u8 = 2;

/// Distinct INFO telemetry id (C5): a segmentation-POLICY drop, never a threat class. Must
/// not feed QSecBit / corroboration / the threat score. heqk rule-ids are `u16`; `1050` is the
/// heqk analog of the Linux ~1000050 policy band, distinct from the detection ids (1-3 / 101-121
/// / 201-204 / 301-302).
pub const RULE_SEG_POLICY: u16 = 1050;

const DEV_SLOTS: usize = 64;
/// Reach-entry lease (C1): an entry older than this expires to Full, so a stale authority
/// state can never durably strand a legit device.
const REACH_TTL_SECS: u64 = 3600;

static DEV_KEY: [AtomicU64; DEV_SLOTS] = [const { AtomicU64::new(0) }; DEV_SLOTS]; // mac_hash (0 = empty)
static DEV_REACH: [AtomicU8; DEV_SLOTS] = [const { AtomicU8::new(0) }; DEV_SLOTS]; // R_* code
static DEV_SET_AT: [AtomicU64; DEV_SLOTS] = [const { AtomicU64::new(0) }; DEV_SLOTS]; // cntpct at set

/// C7 — the gate is DISARMED until an authenticated reach channel provisions policy. While
/// false, `reach_decision` is a no-op (always Allow), so no reach-drop can hit the wire.
static REACH_ARMED: AtomicBool = AtomicBool::new(false);

/// C2 — the authority-supplied LAN gateway + DNS resolver (host-order IPv4, 0 = unset). These
/// are LAN-internal IPs that InternetOnly/Quarantine must NEVER drop (else the device can't
/// reach the internet or resolve). Set by the same authenticated channel that sets reach.
static INFRA_GATEWAY: AtomicU64 = AtomicU64::new(0);
static INFRA_DNS: AtomicU64 = AtomicU64::new(0);

#[inline]
fn cntpct() -> u64 {
    let v: u64;
    unsafe { core::arch::asm!("mrs {}, cntpct_el0", out(reg) v, options(nomem, nostack)) };
    v
}
#[inline]
fn cntfrq() -> u64 {
    let v: u64;
    unsafe { core::arch::asm!("mrs {}, cntfrq_el0", out(reg) v, options(nomem, nostack)) };
    v
}

/// AUTHORITY seam (C7): ARM the reach plane. MUST be called only after an AUTHENTICATED reach
/// channel (signed manifest / attested control link) has provisioned policy. Until armed the
/// enforcement gate is inert.
pub fn arm_reach_channel() {
    REACH_ARMED.store(true, Ordering::Relaxed);
}

/// TEST/GATE hook — disarm again (restores the fail-open no-op state).
pub fn disarm_reach_channel() {
    REACH_ARMED.store(false, Ordering::Relaxed);
}

/// Is the reach plane armed?
pub fn reach_armed() -> bool {
    REACH_ARMED.load(Ordering::Relaxed)
}

/// AUTHORITY seam (C2): register the LAN gateway + DNS resolver (host-order IPv4) so
/// InternetOnly/Quarantine devices are never cut off from them.
pub fn set_infra(gateway: u32, dns: u32) {
    INFRA_GATEWAY.store(gateway as u64, Ordering::Relaxed);
    INFRA_DNS.store(dns as u64, Ordering::Relaxed);
}

/// AUTHORITY seam (C4): set a device's reach, keyed by `mac_hash(eth_src)`. Direct-mapped,
/// collision-EVICT (C8) — a colliding device overwrites the slot (never counts against
/// another's policy). Stamps the set time for the TTL lease (C1).
pub fn set_reach(mac_key: u64, reach: Reach) {
    if mac_key == 0 {
        return;
    }
    let s = (mac_key as usize) % DEV_SLOTS;
    let code = match reach {
        Reach::Full => R_FULL,
        Reach::InternetOnly => R_INTERNET_ONLY,
        Reach::Quarantine => R_QUARANTINE,
    };
    DEV_KEY[s].store(mac_key, Ordering::Relaxed);
    DEV_REACH[s].store(code, Ordering::Relaxed);
    DEV_SET_AT[s].store(cntpct(), Ordering::Relaxed);
}

/// Look up a device's reach (C1 fail-open): unknown key, a collision (slot holds another
/// device), or an expired lease all resolve to `Full`.
pub fn reach_of(mac_key: u64) -> Reach {
    if mac_key == 0 {
        return Reach::Full;
    }
    let s = (mac_key as usize) % DEV_SLOTS;
    if DEV_KEY[s].load(Ordering::Relaxed) != mac_key {
        return Reach::Full; // empty or a colliding (evicted) device
    }
    // TTL lease: an entry older than REACH_TTL_SECS expires to Full (C1).
    let now = cntpct();
    let win = cntfrq().max(1).saturating_mul(REACH_TTL_SECS);
    if now.wrapping_sub(DEV_SET_AT[s].load(Ordering::Relaxed)) >= win {
        return Reach::Full;
    }
    match DEV_REACH[s].load(Ordering::Relaxed) {
        R_INTERNET_ONLY => Reach::InternetOnly,
        R_QUARANTINE => Reach::Quarantine,
        _ => Reach::Full,
    }
}

/// C2 — is `dst` (host-order IPv4) an infra destination InternetOnly/Quarantine must never
/// drop? DHCP broadcast (255.255.255.255), IPv4 link-local (169.254/16), and the authority-
/// supplied gateway + DNS. (ARP/ND carry no IPv4 dst → handled by the not-internal branch.)
#[inline]
fn is_infra_dst(dst: u32) -> bool {
    if dst == 0xFFFF_FFFF {
        return true; // limited broadcast (DHCP DISCOVER/REQUEST)
    }
    if (dst >> 16) == 0xA9FE {
        return true; // 169.254.0.0/16 link-local
    }
    let gw = INFRA_GATEWAY.load(Ordering::Relaxed) as u32;
    let dns = INFRA_DNS.load(Ordering::Relaxed) as u32;
    (gw != 0 && dst == gw) || (dns != 0 && dst == dns)
}

/// The reach-enforcement decision — a POLICY gate (C6), applied AFTER the threat pipeline has
/// PASSed a frame, keyed on the frame's OWN src MAC. Returns `true` to ALLOW, `false` to
/// segmentation-DROP. Fail-open by construction: disarmed (C7), mgmt-floor (C3), infra (C2),
/// non-internal dst, unknown/expired device (C1) all return ALLOW. Only an ARMED plane with an
/// authority-set non-Full device sending to a LAN-internal, non-infra peer is dropped.
///
/// `src_ipv4` = host-order IPv4 src (for the mgmt floor; 0 if none). `mac_key` = `mac_hash`.
/// `dst_ipv4` = host-order IPv4 dst (0 for ARP/ND/none). `dst_internal` = `is_internal(dst)`.
pub fn reach_allow(src_ipv4: u32, mac_key: u64, dst_ipv4: u32, dst_internal: bool) -> bool {
    if !REACH_ARMED.load(Ordering::Relaxed) {
        return true; // C7 — inert until an authenticated channel arms it
    }
    if crate::verdict::is_allowlisted(src_ipv4) {
        return true; // C3 — never segment the mgmt path
    }
    if !dst_internal || is_infra_dst(dst_ipv4) {
        return true; // C2 — WAN/external + infra (gateway/DHCP/DNS/link-local) always reachable
    }
    // LAN-internal, non-infra dst: gate on the device's authority-set reach.
    match reach_of(mac_key) {
        Reach::Full => true,
        Reach::InternetOnly | Reach::Quarantine => false, // lateral containment / InternetOnly
    }
}

/// Prove the reach matrix + every fail-open invariant, then RESTORE the inert (disarmed)
/// state (C7). Pure logic — runs in QEMU and on metal. Returns true iff all hold.
pub fn reach_selftest() -> bool {
    let full: u64 = 0x1111;
    let io: u64 = 0x2222;
    let quar: u64 = 0x3333;
    let lan: u32 = 0x0A00_0005; // 10.0.0.5   (internal)
    let wan: u32 = 0x0808_0808; // 8.8.8.8     (external)
    let gw: u32 = 0x0A00_0001; // 10.0.0.1    (gateway = infra, internal)
    let mgmt: u32 = 0x0AC8_0005; // 10.200.0.5  (mgmt floor)
    set_infra(gw, 0x0A00_0002);
    set_reach(full, Reach::Full);
    set_reach(io, Reach::InternetOnly);
    set_reach(quar, Reach::Quarantine);

    // C7: DISARMED → nothing is ever segmented (even Quarantine → LAN).
    disarm_reach_channel();
    let disarmed = reach_allow(0, quar, lan, true);

    // ARMED: the reach matrix.
    arm_reach_channel();
    let full_lan = reach_allow(0, full, lan, true); // Full → allow
    let io_lan = !reach_allow(0, io, lan, true); // InternetOnly + LAN peer → DENY
    let io_wan = reach_allow(0, io, wan, false); // InternetOnly + WAN → allow
    let io_gw = reach_allow(0, io, gw, true); // C2 infra (gateway) → allow even though internal
    let q_lan = !reach_allow(0, quar, lan, true); // Quarantine + LAN peer → DENY (lateral containment)
    let q_wan = reach_allow(0, quar, wan, false); // Quarantine + WAN → allow
    let mgmt_ok = reach_allow(mgmt, quar, lan, true); // C3 mgmt floor → allow even if Quarantine
    let unknown = reach_allow(0, 0x9999, lan, true); // C1 unknown device → Full → allow

    disarm_reach_channel(); // restore the inert production state (C7)

    disarmed && full_lan && io_lan && io_wan && io_gw && q_lan && q_wan && mgmt_ok && unknown
}
