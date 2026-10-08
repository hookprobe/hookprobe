//! DET-SEP / M2 keystone — the **tri-state enforcement verdict** and the `decide()`
//! seam, porting the operator's hard rule (ADR 0023) onto heqk: *observe by
//! default; a legitimate customer connection must ALWAYS pass; drop ONLY a genuine,
//! high-confidence attack or a resource-reality event.*
//!
//! Before this module heqk's detection plane was **binary**: a signed rule that
//! matched returned `packet::DROP` inline (`rules::run_set`), so *detection == wire
//! drop* — the exact "fire = drop the customer" inversion ADR 0023 forbids. The
//! seam here decouples the two: a rule FIRING is now an **alert** carrying a
//! `FindingClass`; a single `decide()` / `decide_l2()` maps that class to a
//! tri-state `Verdict` whose **default is `Observe` (PASS on the wire)**. Only the
//! four ADR-0023-D2 suspicion-free classes (a truly-malformed frame, an operator
//! signature policy, a real rate/flood, and — later — a confirmed scan) ever reach
//! a wire drop, and the management `Allowlisted` floor can never be enforced against
//! (ADR 0022 D2, "the operator can never self-lock-out").
//!
//! On-wire integers are unchanged (`packet::PASS = 1` / `packet::DROP = 2`) — the
//! net gate (`netq`, `packet::classify`) still consumes a `u16`; it is now DERIVED
//! from the verdict via `Verdict::to_wire()` instead of being the rule's raw result.

use crate::packet;
use core::sync::atomic::{AtomicU8, Ordering};

/// The tri-state verdict, isomorphic to Linux `scan_responder::ReflexVerdict` /
/// `l2_responder::L2Verdict` (ADR 0023 D1). Graduated by confidence, with a
/// management-safety floor that is never enforced.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Verdict {
    /// Management/mgmt-path floor — detected or not, **never enforced** (PASS).
    /// The operator can never self-lock-out (ADR 0022 D2).
    Allowlisted,
    /// Detected, not attributable-to-enforce — **log only, PASS on the wire**.
    /// This is the DEFAULT for any fired detector (observe-by-default).
    Observe,
    /// A real pattern, identity unconfirmed — a bounded, self-reverting cap.
    /// `over_limit` = a measured rate/resource wall was actually crossed *this
    /// window* (only then does it touch the wire). Reflecting a victim's spoofed
    /// IP costs it at most a windowed cap, never a durable block.
    RateLimit { over_limit: bool },
    /// A truly-malformed / structural L2 fact — drop the FRAME (never the identity).
    FrameDrop,
    /// High-confidence, ADR-0018-CONFIRMED identity threat — durable block.
    /// Not yet reachable on heqk (no handshake/conntrack-ESTABLISHED source exists
    /// yet — see the M2 gap-map §2 flow-state row); defined so the seam is complete
    /// and the follow-on port only has to supply `ctx.confirmed`.
    Quarantine,
}

impl Verdict {
    /// Derive the on-wire integer the net gate consumes. Only a structural
    /// `FrameDrop`, a `Quarantine`, or a `RateLimit` whose rate wall was crossed
    /// touches the wire; `Observe` / `Allowlisted` / an under-limit `RateLimit`
    /// PASS. This is the whole point: a legit customer is never on a DROP path.
    #[inline]
    pub fn to_wire(self) -> u16 {
        match self {
            Verdict::FrameDrop | Verdict::Quarantine => packet::DROP,
            Verdict::RateLimit { over_limit: true } => packet::DROP,
            Verdict::Allowlisted | Verdict::Observe | Verdict::RateLimit { over_limit: false } => {
                packet::PASS
            }
        }
    }

    /// True iff this verdict drops the frame on the wire.
    #[inline]
    pub fn is_drop(self) -> bool {
        self.to_wire() == packet::DROP
    }

    /// Stable wire code for the tri-state class, carried on every SOAR event + export record so
    /// the operator sees WHY a frame passed/dropped (Observe vs a self-reverting RateLimit vs a
    /// confirmed Quarantine) — `to_wire()` alone collapses that to PASS/DROP. 0 = unknown.
    /// Codes are append-only (the off-device receiver keys on them).
    #[inline]
    pub fn class_code(self) -> u8 {
        match self {
            Verdict::Allowlisted => CLASS_ALLOWLISTED,
            Verdict::Observe => CLASS_OBSERVE,
            Verdict::RateLimit { over_limit: false } => CLASS_RATELIMIT_UNDER,
            Verdict::RateLimit { over_limit: true } => CLASS_RATELIMIT_OVER,
            Verdict::FrameDrop => CLASS_FRAMEDROP,
            Verdict::Quarantine => CLASS_QUARANTINE,
        }
    }
}

pub const CLASS_UNKNOWN: u8 = 0;
pub const CLASS_ALLOWLISTED: u8 = 1;
pub const CLASS_OBSERVE: u8 = 2;
pub const CLASS_RATELIMIT_UNDER: u8 = 3;
pub const CLASS_RATELIMIT_OVER: u8 = 4;
pub const CLASS_FRAMEDROP: u8 = 5;
pub const CLASS_QUARANTINE: u8 = 6;

/// What a fired signed rule MEANS — the input to `decide()`. Each rule in the
/// corpus (`rules.rs`) carries one; firing the rule proposes this class, and
/// `decide()` chooses the final verdict. Keeps detection (the bytecode) decoupled
/// from enforcement (this policy), exactly as ADR 0023 D1 requires.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum FindingClass {
    /// A structurally-malformed frame (bad ARP shape, VM fault on a truncated
    /// frame). Keyed on WHAT THE FRAME IS, never who sent it → `FrameDrop`.
    MalformedFrame,
    /// An explicit operator destination-port / payload signature policy (block
    /// :4444/:23/:31337, an MQTT probe). Not identity-keyed (a customer never
    /// connects TO the box's backdoor port) → drops.
    Signature,
    /// A stateless anomalous-flag scan SHAPE (TCP NULL/FIN/Xmas/SYN-FIN). A single
    /// crafted packet, no rate context → `RateLimit`-unconfirmed → **Observe on the
    /// wire** today (a per-source scan meter is the M2.2 follow-on).
    ScanShape,
    /// A per-source RATE wall crossed this window (SYN-flood limiter fired). Keyed
    /// on rate reality, self-reverting by the window → `RateLimit { over_limit }`.
    FloodRate,
    /// A real L1/L2 flood (mac-flood / broadcast-storm). Port-role-aware: on an
    /// Access port a genuine flood is `RateLimit` (bounded, self-reverting); on an
    /// Uplink/AP port many distinct client MACs are LEGITIMATE, so it stays `Observe`
    /// — detected, logged, NEVER a wire cap that could drop a legit AP client (D12).
    L2Flood,
    /// A threat-feed / blocklist reputation hit (one IOC). A SINGLE uncorroborated
    /// hit must **never** drop a customer (matrix row L11) → `Observe`. Corroboration
    /// → a higher verdict is the M2 follow-on.
    IdentityReputation,
    /// An ARP identity anomaly (eth-src ≠ sender-mac). A legit gratuitous / proxy /
    /// NAT-rebind ARP presents this shape, and heqk has no cross-packet state to
    /// confirm a real spoof → `Observe` (matrix row L3), never a fabricated drop.
    IdentitySpoof,
    /// An L7 / BEHAVIORAL finding (M2.4): C2 beacon periodicity, east-west lateral fan-out,
    /// bulk outbound exfil, tunneled/DGA DNS. OBSERVE-ONLY BY CONSTRUCTION (ADR 0023 /
    /// matrix A10-detection + L8) — the SOC must SEE these, but none is a suspicion-free
    /// confirmed drop, so this maps UNCONDITIONALLY to `Verdict::Observe` (PASS on the
    /// wire), even for a `confirmed`/non-mgmt source. Zero legit-drop risk: a false positive
    /// only emits a SOAR alert, never a wire action. Mirrors the Linux posture (beacon/
    /// lateral run in the userspace observation stream, never in the tc-bpf drop path).
    Behavioral,
    /// RA-guard (RFC 6105 / matrix rows L4 legit + A9 rogue). An ICMPv6 Router
    /// Advertisement is legitimate ONLY from a designated router/uplink port. This
    /// class is PORT-ROLE-GATED like `L2Flood`, but the Access verdict is a clean
    /// `FrameDrop` (a RA on a client-only port is a definitionally-illegitimate
    /// gateway-hijack — a suspicion-free, port-keyed drop of THAT frame, ADR 0023),
    /// while an Uplink RA is the legit downstream-router advertisement → `Observe`
    /// (accepted + logged). NOTE: the IPv4 mgmt floor does NOT reach this class — an
    /// IPv6 frame carries `src == 0` and a `0` source is never allowlisted, so an IPv6
    /// management floor is a precondition of ever arming the Access drop (A9-6).
    /// FAIL-SAFE: the live aggregate port defaults `Uplink`, so a real RA is never
    /// dropped until a manifest marks a specific access interface. The Access
    /// `FrameDrop` arm is EMBARGOED from arming until the ADR 0023 D16-parity
    /// conditions in `docs/design/heqk-detection-parity.md` §5 are met (security-
    /// auditor ruling 2026-09-11): first-sight source-blind RA drop is the
    /// default-deny posture D16 removed on the Linux tier.
    RaGuard,
}

/// The role of the ingress port — the FP guard that keeps a busy AP/uplink radio's
/// many legitimate client MACs from being mistaken for a mac-flood (ADR 0023 D12).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum PortRole {
    /// A downstream access port — one endpoint expected; a genuine fan-out of many
    /// distinct source MACs is a real mac-flood → `RateLimit`.
    Access,
    /// An uplink / AP-radio / bridge port — MANY distinct client MACs are ordinary
    /// churn; a flood here is detected but stays `Observe`, never a wire cap.
    Uplink,
}

/// PLACEHOLDER — the ingress port's role. On a real deployment this is sourced from
/// the signed Platform Manifest (a per-interface role: `wlan0`=AP=Uplink, a wired
/// access port=Access). heqk has **no manifest port-role source yet** (M2 follow-on).
///
/// The live datapath (`packet::classify`) fuses ALL ingress into a single aggregate
/// port 0. That port carries the box's own built-in Wi-Fi AP + bridged LAN, where
/// MANY distinct client MACs are ordinary churn — a SOHO/office LAN or AP with 20+
/// active devices is completely normal. If the aggregate port defaulted to `Access`,
/// the 21st distinct MAC in a 10s window would trip the mac-flood wire cap and
/// FrameDrop the whole segment — a self-reinflicting outage of LEGITIMATE customer
/// traffic, the exact thing ADR 0023 ("a legitimate connection must ALWAYS pass")
/// and its D12 mac-flood FP guard exist to prevent. So the SAFE default for the
/// aggregate port is `Uplink`: a genuine mac-flood is still DETECTED (→ `Observe`,
/// logged for the operator), but never wire-capped. Only a manifest that resolves a
/// specific wired-access interface may narrow it back to `Access`. Fail-safe toward
/// never dropping legit traffic — honestly a stub, NOT faked as manifest-driven.
pub const DEFAULT_PORT_ROLE: PortRole = PortRole::Uplink;

// ---- M2 A1/A2 — the per-ingress-port ROLE SOURCE (the manifest seam) ----
//
// The gap this closes: `classify()` used to pass the hardcoded `DEFAULT_PORT_ROLE`
// stub, so the Access→`RateLimit` mac-flood path (matrix row A1) could NEVER fire on
// the live device — there was no per-interface role source at all. This table is that
// source. On a real deployment the SIGNED PLATFORM MANIFEST populates it once at boot
// (CLAUDE.md "detect once, query forever": `wlan0`=AP=Uplink, a wired single-endpoint
// access port=Access); heqk's manifest reader is an M-follow-on, so today every port
// starts at the fail-safe default (`Uplink` — a port that legitimately carries many
// client MACs is NEVER wire-capped, ADR 0023 D12) and `set_port_role` is the seam that
// manifest reader (or the Gate-R self-test) writes through. This is honestly a seam
// with a safe default, NOT faked as manifest-driven.
const MAX_PORTS: usize = 8;
const ROLE_UPLINK_U8: u8 = 0; // the fail-safe default (never wire-drop legit many-MAC churn)
const ROLE_ACCESS_U8: u8 = 1;
static PORT_ROLE: [AtomicU8; MAX_PORTS] = [const { AtomicU8::new(ROLE_UPLINK_U8) }; MAX_PORTS];

/// The manifest/Gate-R seam: set the role of ingress `port`. Out-of-range is ignored
/// (fail-safe — an unknown port keeps the `Uplink` default via `port_role_for`).
pub fn set_port_role(port: usize, role: PortRole) {
    if port < MAX_PORTS {
        let code = match role {
            PortRole::Uplink => ROLE_UPLINK_U8,
            PortRole::Access => ROLE_ACCESS_U8,
        };
        PORT_ROLE[port].store(code, Ordering::Relaxed);
    }
}

/// The role `classify()` consults per ingress port. Any port not explicitly set to
/// `Access` (including out-of-range) resolves to `Uplink` — the fail-safe that keeps a
/// busy AP/uplink's many legit client MACs from ever being wire-dropped (ADR 0023 D12).
pub fn port_role_for(port: u64) -> PortRole {
    let p = port as usize;
    if p < MAX_PORTS && PORT_ROLE[p].load(Ordering::Relaxed) == ROLE_ACCESS_U8 {
        PortRole::Access
    } else {
        PortRole::Uplink
    }
}

/// The context `decide()` reads. `allowlisted` = the source is on the management
/// path (the floor). `confirmed` = an ADR-0018 confirmation signal is present
/// (M2.2: a confirmed distinct-dst-port scan — SYN-only to >= CONFIRM ports from one
/// source WITH ZERO establishment — sourced from `ratelimit::scan_confirmed`, so
/// `Quarantine` is now reachable for a confirmed sweep and unreachable for anything a
/// legit busy source can produce). `over_limit` = a per-source RATE/PORT-COUNT wall is
/// actively crossed THIS window (a bounded, self-reverting cap should touch the wire);
/// `false` for a single crafted packet with no rate context. `port_role` = the D12
/// mac-flood FP guard. Everything is a `Copy` scalar — no allocation, `no_std`-clean.
#[derive(Clone, Copy)]
pub struct DecideCtx {
    pub allowlisted: bool,
    pub confirmed: bool,
    pub over_limit: bool,
    pub port_role: PortRole,
}

impl DecideCtx {
    /// Build the context for an IPv4 source (host-order u32; 0 = no attributable
    /// source), with the default port role. M2.2: `confirmed` is now sourced from
    /// flow-state (`ratelimit::scan_confirmed`) instead of the old hardwired `false`, so
    /// a confirmed scanner's findings can reach `Quarantine`. `over_limit` defaults
    /// `false` (a single-packet finding carries no rate context); the stateful port-scan
    /// detector sets it explicitly when the distinct-port wall is crossed.
    #[inline]
    pub fn for_src(src: u32) -> Self {
        DecideCtx {
            allowlisted: is_allowlisted(src),
            confirmed: crate::ratelimit::scan_confirmed(src as u64),
            over_limit: false,
            port_role: DEFAULT_PORT_ROLE,
        }
    }

    /// Build the context for an L2 finding on a specific port role (mac-flood /
    /// broadcast-storm). `src` = the IPv4 source if the frame carries one (for the
    /// mgmt floor + attribution), else 0. L2 findings are not flow-confirmed.
    #[inline]
    pub fn for_l2(src: u32, port_role: PortRole) -> Self {
        DecideCtx {
            allowlisted: is_allowlisted(src),
            confirmed: false,
            over_limit: false,
            port_role,
        }
    }
}

/// The management allowlist (the `Allowlisted` floor). A minimal, self-contained
/// mgmt prefix so the floor is real and testable; in production this is sourced
/// from the signed Platform Manifest / caps, NOT hard-coded — that is the M2
/// follow-on. Host-order `10.200.0.0/24` (the mgmt /24 the fleet uses).
pub const MGMT_NET: u32 = 0x0A_C8_00_00; // 10.200.0.0
pub const MGMT_LEN: u32 = 24;

/// Is `src` (host-order IPv4) on the management path? A `0` source (no IPv4
/// attribution) is never allowlisted — the floor requires a positive identity.
#[inline]
pub fn is_allowlisted(src: u32) -> bool {
    if src == 0 {
        return false;
    }
    let mask = if MGMT_LEN == 0 { 0 } else { u32::MAX << (32 - MGMT_LEN) };
    (src & mask) == (MGMT_NET & mask)
}

/// The core policy: `FindingClass` × `DecideCtx` → `Verdict`. Default is `Observe`.
/// The management floor short-circuits every ENFORCEABLE class to `Allowlisted`
/// (structural/policy drops of the FRAME still apply — a malformed frame or a
/// backdoor-port hit is dropped regardless of source, since that cannot lock the
/// operator out of anything).
fn decide_core(class: FindingClass, ctx: DecideCtx) -> Verdict {
    match class {
        // Keyed on the frame/policy, not identity — the floor does not exempt these
        // (dropping a malformed frame or a :4444 hit never self-locks-out the operator).
        FindingClass::MalformedFrame | FindingClass::Signature => Verdict::FrameDrop,

        // Identity/reputation findings — observe-by-default; a single hit never drops
        // a customer. The floor is moot (already PASS), but honored for clarity.
        // Behavioral (M2.4) is observe-only BY CONSTRUCTION: a beacon/lateral/exfil/DNS
        // finding is never a confirmed suspicion-free drop → always Observe (PASS), even
        // for a `confirmed`/non-mgmt source. Grouped here since the mapping is unconditional.
        FindingClass::IdentityReputation
        | FindingClass::IdentitySpoof
        | FindingClass::Behavioral => Verdict::Observe,

        // A scan SHAPE finding, graduated by flow-state (M2.2). mgmt → floor;
        // CONFIRMED (>= CONFIRM distinct SYN-only ports, zero establishment) → durable
        // Quarantine; else a bounded, self-reverting RateLimit whose `over_limit` is the
        // flow-state signal — `true` once the per-source distinct-port wall is crossed
        // (a real sweep → the cap touches the wire), `false` for a single crafted flag
        // packet with no rate context (→ Observe on the wire, unchanged for the stateless
        // NULL/FIN/Xmas tier). A legit source can reach neither: establishment holds
        // `confirmed` off and it never crosses the distinct-port wall (`over_limit` stays
        // `false`).
        FindingClass::ScanShape => {
            if ctx.allowlisted {
                Verdict::Allowlisted
            } else if ctx.confirmed {
                Verdict::Quarantine
            } else {
                Verdict::RateLimit { over_limit: ctx.over_limit }
            }
        }

        // A per-source RATE wall crossed (SYN-flood limiter) — a bounded, self-
        // reverting drop keyed on rate reality, UNLESS the source is on the mgmt path.
        FindingClass::FloodRate => {
            if ctx.allowlisted {
                Verdict::Allowlisted
            } else {
                Verdict::RateLimit { over_limit: true }
            }
        }

        // A real L1/L2 flood — PORT-ROLE-AWARE (ADR 0023 D12). Access: RateLimit
        // (bounded). Uplink/AP: Observe — a genuine multi-hundred-MAC flood is still
        // DETECTED and logged, but NEVER a wire cap, because that port legitimately
        // carries many client MACs and a cap would drop real AP clients. The mgmt
        // floor still short-circuits either way.
        FindingClass::L2Flood => {
            if ctx.allowlisted {
                Verdict::Allowlisted
            } else {
                match ctx.port_role {
                    PortRole::Access => Verdict::RateLimit { over_limit: true },
                    PortRole::Uplink => Verdict::Observe,
                }
            }
        }

        // RA-guard (RFC 6105). Port-role-gated like L2Flood, but a rogue RA is dropped
        // as a whole illegitimate FRAME (gateway-hijack), not rate-limited: Access →
        // FrameDrop (A9), Uplink → the legit downstream-router RA is Observed (L4). The
        // mgmt floor still short-circuits. Live default (Uplink) never drops a real RA.
        FindingClass::RaGuard => {
            if ctx.allowlisted {
                Verdict::Allowlisted
            } else {
                match ctx.port_role {
                    PortRole::Access => Verdict::FrameDrop,
                    PortRole::Uplink => Verdict::Observe,
                }
            }
        }
    }
}

/// The L3-L4 / flow-tier decision seam (signatures, TCP-scan shapes, SYN-flood,
/// blocklist). Detectors emit an alert + `class`; THIS is the only place an L3/L4
/// verdict is chosen.
#[inline]
pub fn decide(class: FindingClass, ctx: DecideCtx) -> Verdict {
    decide_core(class, ctx)
}

/// The L1-L2 / frame-tier decision seam (malformed-ARP, ARP-spoof, and — later —
/// L2 floods). Isomorphic to Linux `l2_responder::decide_l2`; shares the core
/// mapping with `decide()` since the `FindingClass` already encodes the tier.
#[inline]
pub fn decide_l2(class: FindingClass, ctx: DecideCtx) -> Verdict {
    decide_core(class, ctx)
}
