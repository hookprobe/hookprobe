//! AEGIS reflex response to napse-dpi's L1/L2 defensive detectors (`napse_loader::l2guard`,
//! rule_ids 1_000_030..=1_000_033) — the "heal threat detection" payload ADR 0020's
//! security-auditor threat-model cleared as DEFENSIVE, buildable now (Phase-1a; no
//! offensive/probe code). Hardens `napse`/AEGIS against link-layer attacks: mac-flood, ARP
//! spoofing/poisoning, broadcast/multicast amplification, and malformed/fuzzed frames.
//!
//! ## The anti-spoof discipline this inherits from ADR 0018 (CRITICAL, non-negotiable)
//! L1/L2 source identifiers (MAC/IP) are SPOOFABLE — the exact lesson ADR 0018 hardened for
//! port-scan quarantine (`scan_responder::decide`'s confirmation gate), applied one layer
//! earlier in the stack, where it is even MORE binding: at L1/L2 there is no TCP-handshake-style
//! confirmation possible at all (`confirm::HandshakeTracker` needs a completed 3-way handshake; a
//! mac-flood/ARP/broadcast observation never carries one). So this module:
//!
//!   - **[`L2Verdict`] has EXACTLY three variants — `RateLimit`, `FrameDrop`, and `Observe` — and
//!     NO variant that reaches a durable, identity-keyed enforcement action.** This is a
//!     structural property, not a convention: nothing in this module can ever call
//!     [`crate::scan_responder::reconcile_quarantine`] (the persisted, escalating-hold,
//!     `(IP,MAC)`-confirmed durable block `scan_responder::decide` alone is allowed to reach),
//!     because there is no code path from an [`L2Alert`]/[`L2Verdict`] into that function at all.
//!     (2026-07-07 enforcement-separation audit: [`L2Verdict::Observe`] was added as the THIRD,
//!     even-more-conservative variant — alert/log only, no wire-level claim at all — precisely so
//!     a finding whose real-world confidence doesn't clear the bar for wire enforcement, or for
//!     which no real enforcement mechanism actually exists, is never misreported as `"active"`.
//!     See D12/D15 in this module's fixes below.)
//!   - **A malformed frame is dropped because the FRAME is bad** (a deterministic fact about the
//!     packet — `napse_loader::dpi::frame_anomaly_reason`), never because of who claims to have
//!     sent it — [`L2Verdict::FrameDrop`].
//!   - **A flood/storm is mitigated by a bounded, SELF-REVERTING per-source/per-link rate cap**
//!     ([`L2Verdict::RateLimit`], rendered as an nft `meter` — see [`render_storm_control`]) —
//!     never a permanent blocklist of a (spoofable) source MAC. Reflecting a victim's spoofed MAC
//!     through this path costs that MAC, at most, a few packets/second for ONE rate window —
//!     never a lasting quarantine. This is the exact reflected-DoS trap ADR 0018 killed, closed
//!     here by construction rather than by a runtime check.
//!   - **A finding that cannot honestly claim any wire-level enforcement is `Observe`, never a
//!     verdict that LOOKS enforced but isn't** — see D12 (a mac-flood alert on a busy uplink/AP
//!     port, where the operator's own rule "a legit customer connection must ALWAYS pass" means no
//!     wire-level cap is installed at all) and D15 (an ARP binding-flip-flop, which needs
//!     cross-packet state no stateless per-packet mechanism — nft meter or TC-bpf classifier alike
//!     — can express) below.
//!
//! ## 2026-07-07 enforcement-separation audit fixes (D12/D13/D15) — observe-by-default, drop only
//! genuine high-confidence attacks; a legit customer connection must ALWAYS pass
//!   - **D12 (mac-flood cap was topology-blind)**: [`L2GuardConfig::lan_port_role`] now gates BOTH
//!     the response-record verdict (`decide_l2`: `RateLimit` only on a genuine [`PortRole::Access`]
//!     port; [`L2Verdict::Observe`] on an [`PortRole::UplinkBridge`] port — the device's own actual
//!     default topology, `lan_iface` = `wlan0`, an AP radio serving the whole LAN) AND the static
//!     nft storm-control meter itself (`render_storm_control` no longer installs the per-source
//!     mac-flood drop meter at all on an `UplinkBridge` port — see that function's doc). The
//!     DETECTION threshold is separately made topology-aware in
//!     `napse_loader::l2guard::MacFloodConfig` (thresholds/topology owned there).
//!   - **D13 (broadcast-storm counted legit mDNS/SSDP/LLMNR)**: [`render_storm_control`] now
//!     `accept`s the well-known service-discovery multicast destinations BEFORE the storm-control
//!     meter, so a chatty-but-legitimate device's Bonjour/SSDP/LLMNR traffic never reaches the
//!     drop path at all — mirroring the SAME exemption `napse_loader::l2guard::is_exempt_multicast`
//!     already applies at the detection layer.
//!   - **D15 (flip-flop verdict claimed a drop that doesn't exist)**: an ARP binding flip-flop
//!     needs cross-packet history (the previous claimant of an IP) that neither the nft meter path
//!     nor `modules/napse-l2guard`'s stateless per-packet TC-bpf classifier can express — see
//!     `render_frame_drop_status`'s own honesty note, which already disclosed this gap in prose.
//!     `decide_l2` now reflects it in the STRUCTURED verdict too: `binding_flip_flop` maps to
//!     [`L2Verdict::Observe`], not `FrameDrop` — so `render_l2_response_json`'s `mechanism`/
//!     `status` fields (which the evidence graph and any downstream automation actually consume)
//!     never claim an enforcement action that isn't real.
//!
//! ## Why this is a SEPARATE nft table from `scan_responder`'s quarantine table
//! `scan_responder::render_bootstrap`/`render_element_ops` manage `hookprobe_quarantine` — a
//! PERSISTED, escalating-hold, per-source state machine keyed on a confirmed `(IP, MAC)` pair.
//! Nothing here ever touches that table, by design: [`render_storm_control`] declares its own
//! `hookprobe_l2guard` table using nft `meter`s, which are self-managing dynamic sets with their
//! OWN internal per-key timeout — there is no persisted JSON state file, no `offenses` counter, no
//! escalating TTL for an L2 finding. A source that stops flooding simply ages out of the meter on
//! its own; nothing here ever "remembers" a source across the flood ending. That absence of
//! persisted per-identity state IS the anti-spoof property for the rate-limit path, verified in
//! this module's tests by construction (there is no state-carrying struct here at all, unlike
//! `scan_responder::QuarantineEntry`).
//!
//! ## What's real vs stubbed in this pass (honesty, per the task's explicit allowance)
//! - **RateLimit rendering is REAL**: `nft` genuinely supports per-source-key dynamic rate
//!   limiting via a named `meter` (`limit rate over N/second`), which is exactly "bounded,
//!   self-reverting storm-control" — [`render_storm_control`] emits real, idempotent nft.
//! - **FrameDrop enforcement is now ALSO REAL — via a SEPARATE, non-nft mechanism (2026-07-05).**
//!   nft's static packet matching still cannot express "this frame is malformed"
//!   (byte-level/length/VLAN-nesting validation) or "these two header fields disagree with each
//!   other" (the ARP sender-mac-vs-eth-src mismatch) — that fact hasn't changed, and this crate
//!   still never fabricates an nft rule claiming to do it (see [`render_frame_drop_status`], which
//!   documents the real enforcement point rather than emitting a working-looking-but-inert rule).
//!   The real enforcement point is `modules/napse-l2guard` — a TC-bpf clsact-**ingress** hook
//!   (a sibling of, and deliberately SEPARATE from, `modules/napse-quarantine`'s BPF program: that
//!   one drops a packet because of who — a spoofable claimed identity — a prior decision already
//!   quarantined; this one drops a packet because of WHAT it structurally is, regardless of
//!   source) that re-parses raw frame bytes exactly like `napse_loader::dpi` already does and
//!   returns `TC_ACT_SHOT` for precisely the conditions [`decide_l2`] classifies as
//!   [`L2Verdict::FrameDrop`]. See `modules/napse-l2guard/loader/src/predicates.rs` for the
//!   anti-drift proof that its C logic and this crate's Rust-side detector definitions
//!   (`napse_loader::dpi::frame_anomaly_reason` / `ArpObs::is_malformed` / `ArpObs::eth_mismatch`)
//!   stay in lockstep. **Honesty on verification depth**: that BPF object is compile-proven
//!   (`clang -target bpf`, 0 errors, byte-identical across `arm64`/`x86` targets) and covered by a
//!   16-test Rust-mirror parity suite in this pass, but NOT yet verifier-load/attach-tested on
//!   real hardware (this dev box has no root/CAP_BPF) — the same honest posture
//!   `modules/napse-quarantine` carried before its first live Pi test. [`render_l2_response_json`]
//!   reflects this: `FrameDrop`'s `mechanism` is `"tc-bpf-l2guard"` and `status` is `"active"` —
//!   "a real enforcement mechanism exists and is wired for this verdict", the SAME meaning
//!   `"active"` already carries for `RateLimit` (never a live "verified currently attached on
//!   THIS box" claim, which no static renderer in this crate can make either way).

use crate::multi_wan::GeneratedFile;

// ---------------------------------------------------------------------------
// The L1/L2 alert (exact schema `napse_loader::l2guard::L2Alert::to_json` emits).
// ---------------------------------------------------------------------------

pub const MAC_FLOOD_RULE_ID: i64 = 1_000_030;
pub const ARP_SPOOF_RULE_ID: i64 = 1_000_031;
pub const BROADCAST_STORM_RULE_ID: i64 = 1_000_032;
pub const L2_MALFORMED_RULE_ID: i64 = 1_000_033;

/// One `napse-dpi` L1/L2 alert line from `/var/lib/hookprobe/events`. Matches
/// `napse_loader::l2guard::L2Alert::to_json`'s exact schema:
/// `{"ts":<f64>,"rule_id":<i64>,"rule_msg":"...","mitre":"...","category":"...","severity":<i64>,
/// "confidence":<f64>,"reason":"...","detail":"...","src_mac":"aa:..","claimed_ip":"10.0.0.5"}`.
/// Deliberately carries NO `confirmed` bit (unlike `scan_responder::ScanAlert`) — there is no
/// handshake-style confirmation possible at L1/L2 (see this module's doc); [`decide_l2`] never
/// looks for one.
#[derive(Debug, Clone, PartialEq, serde::Deserialize, serde::Serialize)]
pub struct L2Alert {
    pub ts: f64,
    #[serde(default)]
    pub rule_id: i64,
    #[serde(default)]
    pub rule_msg: String,
    #[serde(default)]
    pub mitre: String,
    #[serde(default)]
    pub category: String,
    #[serde(default)]
    pub severity: i64,
    #[serde(default)]
    pub confidence: f64,
    /// Machine tag distinguishing WHICH anomaly fired within a category — see
    /// `napse_loader::l2guard::L2Alert::reason`'s doc for the full set of values.
    #[serde(default)]
    pub reason: String,
    #[serde(default)]
    pub detail: String,
    #[serde(default)]
    pub src_mac: Option<String>,
    #[serde(default)]
    pub claimed_ip: Option<String>,
}

/// Parse one `events` line; `Some` only for one of the four L1/L2 detections (matched by rule_id
/// OR category, either being definitive — the SAME "accept either" discipline
/// `scan_responder::parse_scan_alert` uses, so a future rule_id rename can't silently stop
/// ingestion). Any other line (a flow, a port-scan alert, a blank/malformed line) is `None`.
pub fn parse_l2_alert(line: &str) -> Option<L2Alert> {
    let trimmed = line.trim();
    if trimmed.is_empty() {
        return None;
    }
    let a: L2Alert = serde_json::from_str(trimmed).ok()?;
    let known_rule_id =
        matches!(a.rule_id, MAC_FLOOD_RULE_ID | ARP_SPOOF_RULE_ID | BROADCAST_STORM_RULE_ID | L2_MALFORMED_RULE_ID);
    let known_category = matches!(a.category.as_str(), "mac_flood" | "arp_spoof" | "broadcast_storm" | "l2_malformed");
    if known_rule_id || known_category {
        Some(a)
    } else {
        None
    }
}

// ---------------------------------------------------------------------------
// TOPOLOGY — D12 fix: the same two-value port-role classification
// `napse_loader::l2guard::PortRole` uses for the DETECTION threshold, mirrored here (its own,
// crate-local type — this crate is a dependency OF napse-loader, not the reverse, so it cannot
// reuse that type directly) for the ENFORCEMENT side: whether the storm-control meter itself gets
// installed, and whether a mac_flood finding may claim RateLimit at all.
// ---------------------------------------------------------------------------

/// See `napse_loader::l2guard::PortRole`'s doc for the full rationale — this is the same concept,
/// derived from the same manifest data (`Network.uplinks`/`Network.wifi_radios`), applied here to
/// gate the nft-level mac-flood storm-control meter instead of the detection threshold.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PortRole {
    /// A single-uplink / single-client-facing port (a WAN uplink, a Wi-Fi station radio). Many
    /// distinct source MACs here is genuinely anomalous — keep the hard per-source rate cap.
    Access,
    /// A port that fans out to many legitimate devices by construction (a Wi-Fi AP radio, a LAN
    /// bridge/switch uplink — this device's own actual default `lan_iface` topology). A static,
    /// low per-source-MAC packet-rate ceiling would eventually cap ANY busy legitimate device on
    /// this port (a bulk LAN transfer routinely exceeds thousands of packets/second) — the
    /// operator's rule ("a legit customer connection must ALWAYS pass") means this port does NOT
    /// get the mac-flood meter at all; see [`render_storm_control`].
    UplinkBridge,
}
impl Default for PortRole {
    /// `UplinkBridge` — matches `L2GuardConfig::lan_iface`'s own default (`wlan0`, an AP radio
    /// serving the whole LAN). See `napse_loader::l2guard::PortRole::default`'s identical rationale.
    fn default() -> Self {
        PortRole::UplinkBridge
    }
}

// ---------------------------------------------------------------------------
// DECIDE — L2Verdict has exactly three variants; see the module doc for why that is still the
// anti-spoof proof (no code path here can reach a durable identity quarantine).
// ---------------------------------------------------------------------------

/// The reflex verdict for one L1/L2 finding. **Structurally incapable of a durable,
/// identity-keyed enforcement action** — there is no fourth variant, and none of the three carries
/// anything [`crate::scan_responder::reconcile_quarantine`] could consume.
#[derive(Debug, Clone, PartialEq)]
pub enum L2Verdict {
    /// Bounded, self-reverting per-source/per-link rate cap (storm-control) — mac-flood on a
    /// genuine access port, broadcast/multicast storms, and a gratuitous-ARP flood all mitigate
    /// this way.
    RateLimit { reason: String },
    /// The observed FRAME is dropped because it is malformed/conflicting — never a claim about
    /// who sent it. Malformed ARP fields, an ARP sender-mac/eth-src mismatch, and a generically
    /// malformed/fuzzed L1-L2 frame all resolve here.
    FrameDrop { reason: String },
    /// **D12/D15 fix (2026-07-07): alert/log only — no wire-level claim at all.** Used exactly
    /// when either (a) no real enforcement mechanism exists for this finding (an ARP
    /// binding-flip-flop needs cross-packet history no stateless mechanism here can express — D15),
    /// or (b) the operator's "a legit customer connection must ALWAYS pass" rule means enforcement
    /// would risk dropping legitimate traffic (a mac-flood finding on a busy uplink/AP port — D12).
    /// The finding is still fully logged/alerted (the evidence graph still records it) — only the
    /// wire-level action is withheld.
    Observe { reason: String },
}

/// Decide the reflex verdict for one L1/L2 alert on a link classified `lan_port_role`. Pure,
/// deterministic, model-free — mirrors `scan_responder::decide`'s "no LLM in this path" discipline.
/// Dispatches on the alert's `category`/`reason` tags (never on free-text `detail` substring
/// matching, which would be fragile) — see `napse_loader::l2guard`'s doc for the full tag
/// vocabulary this must stay in lockstep with.
pub fn decide_l2(alert: &L2Alert, lan_port_role: PortRole) -> L2Verdict {
    match alert.category.as_str() {
        // D12 fix: a mac_flood finding only claims a wire-level rate cap on a genuine ACCESS port.
        // On an UplinkBridge port (this device's own default topology — an AP/LAN-bridge serving
        // many legitimate clients) the finding is real and still logged, but NO enforcement is
        // claimed or installed — see `render_storm_control`'s matching fix and the operator's rule
        // that a legit customer connection must always pass.
        "mac_flood" => match lan_port_role {
            PortRole::Access => L2Verdict::RateLimit {
                reason: format!(
                    "MAC-flood on a single-client access link — per-link source-MAC rate cap engaged, \
                     self-reverting; never a permanent block of any single (spoofable) MAC — {}",
                    alert.detail
                ),
            },
            PortRole::UplinkBridge => L2Verdict::Observe {
                reason: format!(
                    "many distinct source MACs on the LAN/AP uplink — expected on a port serving many \
                     legitimate clients; observed and logged, no wire-level rate cap installed (a legit \
                     customer connection must always pass) — {}",
                    alert.detail
                ),
            },
        },
        "broadcast_storm" => L2Verdict::RateLimit {
            reason: format!(
                "broadcast/multicast storm — per-source rate cap engaged, self-reverting (well-known \
                 service-discovery multicast — mDNS/SSDP/LLMNR — is exempted before this cap ever \
                 applies; see render_storm_control) — {}",
                alert.detail
            ),
        },
        "arp_spoof" => match alert.reason.as_str() {
            // A gratuitous-ARP FLOOD is a rate condition — storm-control (rate-limit), same as
            // mac-flood/broadcast-storm above.
            "gratuitous_flood" => L2Verdict::RateLimit {
                reason: format!("gratuitous-ARP flood — per-source rate cap engaged, self-reverting — {}", alert.detail),
            },
            // D15 fix: a binding flip-flop needs CROSS-PACKET history (the previous claimant of an
            // IP) — neither the nft meter path nor `modules/napse-l2guard`'s stateless per-packet
            // TC-bpf classifier can express that, so this must never claim FrameDrop (which would
            // be a fabricated enforcement claim in `render_l2_response_json`). Still fully alerted.
            "binding_flip_flop" => L2Verdict::Observe {
                reason: format!(
                    "ARP binding flip-flop — a stateful, cross-packet condition with no real wire-level \
                     drop mechanism (see render_frame_drop_status); observed and logged only — {}",
                    alert.detail
                ),
            },
            // Malformed fields or an eth/sender-mac mismatch are single-frame anomalies — the
            // anomalous frame is dropped (RA-Guard-style), never a lasting block of the (spoofable)
            // claimed identity. Real, stateless, per-packet enforcement — see
            // `modules/napse-l2guard`'s TC-bpf classifier.
            other => L2Verdict::FrameDrop {
                reason: format!("malformed/conflicting ARP frame ({other}) — dropped, RA-Guard-style — {}", alert.detail),
            },
        },
        "l2_malformed" => L2Verdict::FrameDrop {
            reason: format!("malformed L1/L2 frame ({}) — dropped deterministically — {}", alert.reason, alert.detail),
        },
        // Fail-safe default for an alert `parse_l2_alert` somehow still let through with an
        // unrecognized category (should not happen — `parse_l2_alert` already filters to the
        // four known categories) — the SAFER of the two verdicts (bounded rate-limit, never a
        // frame-drop that could be exploited to blackhole traffic on an unrecognized condition).
        _ => L2Verdict::RateLimit {
            reason: format!(
                "unrecognized L1/L2 category {:?} — fail-safe bounded rate-limit, never an identity block",
                alert.category
            ),
        },
    }
}

// ---------------------------------------------------------------------------
// ENFORCE (real) — nft `meter`-based storm-control, a SEPARATE table from the persistent
// IP/MAC quarantine table `scan_responder` renders.
// ---------------------------------------------------------------------------

const L2_NFT_TABLE: &str = "hookprobe_l2guard";
const L2_BANNER: &str =
    "# GENERATED by hookprobe l2-responder — deterministic nft storm-control (self-reverting meters).\n\
     # Do NOT edit by hand. This is a SEPARATE table from the port-scan responder's persistent\n\
     # quarantine table — nothing here is a persisted, identity-keyed, escalating-hold block; see\n\
     # the module doc (crates/hookprobe-manifest/src/l2_responder.rs).\n";

/// LAN/WAN interfaces + rate ceilings for the storm-control renderer. Interface defaults match
/// `scan_responder::IfaceConfig`'s live-topology defaults (`wlan0`/`end0`) so an operator
/// configuring one iface set configures both consistently.
#[derive(Debug, Clone)]
pub struct L2GuardConfig {
    pub lan_iface: String,
    pub wan_iface: String,
    /// D12 fix (2026-07-07): the [`PortRole`] of `lan_iface` — derived from the same
    /// manifest/network classification `napse_loader::l2guard::port_role_for_interface` uses.
    /// Gates whether the mac-flood storm-control meter is installed at all (see
    /// [`render_storm_control`]) and whether `decide_l2` may claim `RateLimit` for a mac_flood
    /// finding. Defaults to `UplinkBridge` — matching `lan_iface`'s own default (`wlan0`, an AP
    /// radio serving the whole LAN), the safer out-of-the-box choice.
    pub lan_port_role: PortRole,
    /// Per-source-MAC packets/second ceiling once mac-flood conditions are being observed on a
    /// genuine ACCESS port — the storm-control cap, not the DETECTION threshold
    /// (`l2guard::MacFloodConfig`'s `threshold` is "how many DISTINCT macs trip the alert"; this is
    /// "how fast may any ONE mac send once the link is under a flood"). **Never applied when
    /// `lan_port_role` is `UplinkBridge`** — see [`render_storm_control`]'s doc for why a static
    /// per-mac packet-rate ceiling would eventually cap any busy legitimate device on that kind of
    /// port (a bulk LAN transfer routinely exceeds this by orders of magnitude).
    pub mac_flood_pps: u32,
    /// Per-source-MAC broadcast/multicast packets/second ceiling.
    pub broadcast_pps: u32,
    /// Per-source-MAC ARP packets/second ceiling — a coarser proxy for "gratuitous-ARP flood"
    /// specifically (see the module doc's honesty note: nft cannot compare two packet fields to
    /// each other, so it cannot match "sender==target" on its own; capping the WHOLE ARP stream
    /// from a flooding source is the closest nft-expressible mitigation and is still bounded and
    /// self-reverting — a legitimate host's normal, low-rate ARP traffic is far below this cap).
    pub arp_pps: u32,
    /// How long an idle per-source meter entry survives before nft itself expires it — this IS
    /// the self-revert: no code in this crate ever "un-quarantines" a meter entry, nft's own
    /// dynamic-set timeout does.
    pub meter_timeout_secs: u64,
}
pub const DEFAULT_MAC_FLOOD_PPS: u32 = 50;
pub const DEFAULT_BROADCAST_PPS: u32 = 100;
pub const DEFAULT_ARP_PPS: u32 = 50;
pub const DEFAULT_METER_TIMEOUT_SECS: u64 = 60;
impl Default for L2GuardConfig {
    fn default() -> Self {
        L2GuardConfig {
            lan_iface: "wlan0".to_string(),
            wan_iface: "end0".to_string(),
            lan_port_role: PortRole::default(),
            mac_flood_pps: DEFAULT_MAC_FLOOD_PPS,
            broadcast_pps: DEFAULT_BROADCAST_PPS,
            arp_pps: DEFAULT_ARP_PPS,
            meter_timeout_secs: DEFAULT_METER_TIMEOUT_SECS,
        }
    }
}

/// Render the storm-control bootstrap — table + chain + THREE `meter`-backed rate-limit rules,
/// scoped to the LAN ingress iface (the plane these link-layer attacks target). Each meter is a
/// per-source-MAC (`ether saddr`) dynamic set nft manages itself: an entry is created lazily the
/// first time a source exceeds the declared rate, ages out after `meter_timeout_secs` of the
/// source going quiet, and NOTHING in this crate ever adds/removes an element from it — there is
/// no per-alert diff loop the way `scan_responder::render_element_ops` has, because a meter
/// doesn't need one; this is the concrete difference between "bounded, self-reverting rate cap"
/// and "persisted, escalating-hold identity block".
///
/// 2026-07-05 threat-model fix (H1): a `meter NAME { ... }` declared inline inside `add rule`
/// creates an IMPLICIT, table-scoped named set (`NAME`) that OUTLIVES `flush chain` — `flush
/// chain` only empties the chain's RULE list, never a table-level object like a meter/set. Before
/// this fix, re-applying this exact script a SECOND time (e.g. `nft -f` on a reconcile) tried to
/// declare each meter fresh via `add rule … meter napse_..._meter { … }` while the FIRST apply's
/// meter of the identical name was still alive underneath — nft rejects that as `File exists;
/// meter 'NAME' overlaps an existing set 'NAME'` (reproduced empirically: `nft -f` on this exact
/// rendered content, applied twice, exits 1 on the second apply with exactly that error for all
/// three meters), which aborts the WHOLE batch — L2 storm-control silently stops being enforced
/// after the first reconcile. Fix: unconditionally `delete table inet hookprobe_l2guard` FIRST
/// (dropping the table — and every meter/set/chain scoped to it — outright), THEN `add table` to
/// recreate it from nothing every cycle; the three meters are therefore always declared into a
/// table that provably does not already contain one of that name. On the very first-ever apply
/// (table doesn't exist yet) the `delete table` line itself errors — by design, this is harmless
/// PROVIDED each line is applied as its OWN independent `nft` invocation (word-split + exec one
/// argv at a time — the ONLY in-tree consumer today, `supervisor`'s `apply_or_print`, does exactly
/// this: it execs each non-comment line as a separate `Command::new("nft")` and logs-but-continues
/// past a single line's failure, never aborting the whole reconcile over it) — empirically verified
/// (line-by-line, in an isolated network namespace) to succeed on both the very first apply
/// (`delete table` fails harmlessly, everything after it succeeds) AND every subsequent re-apply
/// (`delete table` now succeeds, and the meters are declared fresh each time, so `add rule …
/// meter …` never collides). **Caveat, stated honestly**: if a FUTURE consumer ever switches to
/// batching this whole file through a single `nft -f` transaction (all-or-nothing), a `delete
/// table` on a table that doesn't exist yet would abort that ENTIRE transaction on first boot —
/// this fix assumes the current, only, in-tree per-line application model; a batch-mode consumer
/// would need a separate first-boot-safe variant (e.g. its own `add table` pre-step run once,
/// outside the batch). See `render_storm_control_apply_twice_succeeds_line_by_line` below for the
/// real-`nft` proof (network-namespace-gated, skips cleanly where unavailable).
///
/// ## D12 fix (2026-07-07): the mac-flood meter is NEVER installed on an `UplinkBridge` port
/// A static per-source-MAC packet-RATE ceiling (the mac-flood meter, historically 50pps) is the
/// right defense on a genuine [`PortRole::Access`] port (one expected client — any sustained rate
/// that high from it is already suspicious), but is simply the wrong tool on a
/// [`PortRole::UplinkBridge`] port (this device's own default `lan_iface` topology — an AP radio or
/// LAN-bridge/switch uplink serving MANY legitimate devices at once): ordinary bulk LAN traffic
/// (a NAS backup, a big file copy, 4K streaming) routinely exceeds any static per-mac pps ceiling
/// low enough to still matter as a "flood" cap, by one to three orders of magnitude. Rather than
/// pick an arbitrary "sharply higher" number that is still an eventual false positive waiting to
/// happen, this renderer does not install the mac-flood meter at all when `lan_port_role` is
/// `UplinkBridge` — the operator's rule ("a legit customer connection must ALWAYS pass") wins;
/// the finding is still fully observed via `decide_l2`'s matching `Observe` verdict on that role
/// (see the module doc's D12 entry). The broadcast and ARP meters are UNCHANGED by this — they
/// mitigate a different, genuinely rare-in-legitimate-traffic condition (see their own doc lines).
///
/// ## D13 fix (2026-07-07): well-known service-discovery multicast is exempted BEFORE the meter
/// mDNS/SSDP/LLMNR are accepted outright (an unconditional `accept`, evaluated before the
/// broadcast/multicast storm-control meter in the same chain) so a chatty-but-legitimate
/// smart-TV/printer/HomeKit accessory's routine Bonjour/UPnP/LLMNR traffic can never be counted
/// toward, or capped by, the storm-control meter — mirroring the identical exemption
/// `napse_loader::l2guard::is_exempt_multicast` already applies at the detection layer. A raw
/// `ff:ff:ff:ff:ff:ff` broadcast or any NON-exempt multicast group still falls through to the meter
/// unchanged.
pub fn render_storm_control(cfg: &L2GuardConfig) -> GeneratedFile {
    let lan = cfg.lan_iface.as_str();
    let t = cfg.meter_timeout_secs;
    let mut s = String::from(L2_BANNER);
    s.push_str(&format!(
        "# storm-control on {lan} (port_role={:?}): mac-flood {}, broadcast/multicast {}pps, arp {}pps per source mac, \
         meter idle-timeout {t}s.\n",
        cfg.lan_port_role,
        match cfg.lan_port_role {
            PortRole::Access => format!("{}pps", cfg.mac_flood_pps),
            PortRole::UplinkBridge => "OBSERVE-ONLY (no meter installed — D12 fix)".to_string(),
        },
        cfg.broadcast_pps, cfg.arp_pps
    ));
    // H1 fix: delete-then-recreate the table every cycle so a meter declared inline in `add rule`
    // never collides with a same-named meter surviving from a prior apply (meters are NOT cleared
    // by `flush chain` — only a table drop removes them). Ignore-if-absent on a first-ever apply
    // is provided by the caller's per-line, continue-on-failure execution model (see doc above).
    // 2026-07-07 first-boot fix (found on the arm64 VM's very first boot): a bare `delete table`
    // of a NOT-YET-EXISTING table aborts the WHOLE `nft -f` transaction (exit 1 — "No such file or
    // directory"), so on first boot the entire l2guard ruleset failed to install. The fully-idempotent
    // idiom is `add` (no-op if present) → `delete` (now always succeeds, dropping the meters' implicit
    // set-state a prior apply left) → `add` fresh. Works standalone AND batched through one transaction.
    s.push_str(&format!("add table inet {L2_NFT_TABLE}\n"));
    s.push_str(&format!("delete table inet {L2_NFT_TABLE}\n"));
    s.push_str(&format!("add table inet {L2_NFT_TABLE}\n"));
    s.push_str(&format!("add chain inet {L2_NFT_TABLE} forward {{ type filter hook forward priority -6; policy accept; }}\n"));
    s.push_str(&format!("flush chain inet {L2_NFT_TABLE} forward\n"));
    // mac-flood storm-control — D12 fix: ONLY on a genuine ACCESS port (one expected client — any
    // sustained high rate from it is already suspicious). On an UplinkBridge port (serving many
    // legitimate devices) this meter is NOT rendered at all — see the doc above.
    match cfg.lan_port_role {
        PortRole::Access => {
            s.push_str(&format!(
                "add rule inet {L2_NFT_TABLE} forward iifname \"{lan}\" meter napse_macflood_meter {{ ether saddr timeout {t}s limit rate over {}/second }} counter drop comment \"hookprobe-l2guard-storm-control-macflood\"\n",
                cfg.mac_flood_pps
            ));
        }
        PortRole::UplinkBridge => {
            s.push_str(&format!(
                "# D12 fix: {lan} is classified UplinkBridge (serves many legitimate clients) — the mac-flood \
                 per-source packet-rate meter is intentionally NOT installed here (a static pps ceiling low \
                 enough to matter as a flood cap would eventually drop legitimate bulk LAN traffic). The \
                 mac_flood finding is still fully observed/logged — see decide_l2's Observe verdict for this role.\n"
            ));
        }
    }
    // D13 fix: well-known service-discovery multicast is ACCEPTED before the storm-control meter
    // below ever evaluates it — mDNS (224.0.0.251 / ff02::fb), SSDP (239.255.255.250 / ff02::c),
    // LLMNR (224.0.0.252 / ff02::1:3), and the IPv6 all-nodes/all-routers groups (ff02::1/::2) a
    // HomeKit/Thread accessory's normal RIO chatter can also touch. A raw broadcast or any
    // non-exempt multicast group is NOT in this set and still falls through to the meter.
    s.push_str(&format!(
        "add rule inet {L2_NFT_TABLE} forward iifname \"{lan}\" ip daddr {{ 224.0.0.251, 239.255.255.250, 224.0.0.252 }} accept comment \"hookprobe-l2guard-exempt-multicast-v4\"\n"
    ));
    s.push_str(&format!(
        "add rule inet {L2_NFT_TABLE} forward iifname \"{lan}\" ip6 daddr {{ ff02::fb, ff02::c, ff02::1:3, ff02::1, ff02::2 }} accept comment \"hookprobe-l2guard-exempt-multicast-v6\"\n"
    ));
    // broadcast/multicast storm-control — `meta pkttype` is a native nft meta match (broadcast |
    // multicast | unicast | ...); no set/database needed to classify a destination this way.
    s.push_str(&format!(
        "add rule inet {L2_NFT_TABLE} forward iifname \"{lan}\" meta pkttype {{ broadcast, multicast }} meter napse_bcast_meter {{ ether saddr timeout {t}s limit rate over {}/second }} counter drop comment \"hookprobe-l2guard-storm-control-broadcast\"\n",
        cfg.broadcast_pps
    ));
    // ARP storm-control (coarser proxy for gratuitous-ARP flood specifically — see the module
    // doc's honesty note on why nft cannot match the semantically-precise condition itself).
    s.push_str(&format!(
        "add rule inet {L2_NFT_TABLE} forward iifname \"{lan}\" ether type arp meter napse_arp_meter {{ ether saddr timeout {t}s limit rate over {}/second }} counter drop comment \"hookprobe-l2guard-storm-control-arp\"\n",
        cfg.arp_pps
    ));
    GeneratedFile { path: "l2guard/00-storm-control.nft".to_string(), content: s }
}

/// **REAL enforcement now exists (2026-07-05) — SEE ALSO, not TODO.** Deterministic
/// malformed-frame / conflicting-ARP-frame DROP is enforced by `modules/napse-l2guard`, a TC-bpf
/// clsact-**ingress** hook that re-parses raw frame bytes exactly like `napse_loader::dpi` does
/// and returns `TC_ACT_SHOT` for exactly the conditions [`decide_l2`] classifies as
/// [`L2Verdict::FrameDrop`]. This function's job is unchanged in KIND (it still never fabricates
/// an nft rule for a condition nft cannot express — that fact about nft hasn't changed), but its
/// CONTENT is no longer a "not yet built" TODO: it documents where the real enforcement lives and
/// the honest verification-depth caveat (compile-proven; attach-on-metal validation pending — see
/// `modules/napse-l2guard/README.md`'s "honest constraints" section for the exact reproduction:
/// `clang -target bpf` compiles clean, `bpftool prog load` fails with `Operation not permitted`
/// on this dev box, which has no root/CAP_BPF).
pub fn render_frame_drop_status() -> GeneratedFile {
    let content = "ENFORCED (2026-07-05, ADR 0020 Phase-1a defensive) — via modules/napse-l2guard, \
NOT via nft.\n\
\n\
napse-dpi's L1/L2 detectors (napse_loader::l2guard::{frame_anomaly_reason via MalformedFrameGate, \
ArpGuard}) run on the tc-mirred MIRROR sink (hp-mirror) — out-of-band, read-only observation, per \
that binary's own module doc; they cannot themselves drop a frame on the wire. Real inline \
enforcement is a SEPARATE Ring-0 program: modules/napse-l2guard's TC-bpf clsact-ingress hook \
(l2guard_ingress, bpf/l2guard.bpf.c), attached on the REAL interface — a sibling of, and \
deliberately separate from, modules/napse-quarantine's identity-quarantine BPF program (that one \
drops a packet because of WHO a prior decision quarantined; this one drops a packet because of \
WHAT it structurally is, regardless of source).\n\
\n\
It re-parses the raw frame bytes exactly like napse_loader::dpi does, and returns TC_ACT_SHOT for \
the conditions this crate's decide_l2() classifies as L2Verdict::FrameDrop:\n\
  - a malformed/oversized/runt/double-VLAN-tagged L1-L2 frame (l2_malformed)\n\
  - a malformed ARP header (arp_spoof / malformed_fields)\n\
  - an ARP sender-mac vs Ethernet-src mismatch (arp_spoof / eth_mismatch)\n\
\n\
NOT covered by that BPF program (stateful, out of scope, documented there rather than silently \
gapped): an ARP binding flip-flop (arp_spoof / binding_flip_flop) remains alert-only; a \
gratuitous-ARP flood is separately rate-limited (real nft enforcement) by render_storm_control \
above, not by this frame-level program.\n\
\n\
nft still cannot express byte-level frame validation or one packet field disagreeing with \
another — that has not changed, and this crate still never emits an nft rule claiming to do it.\n\
\n\
Verification depth (honest, do not round up): modules/napse-l2guard's bpf/l2guard.bpf.c compiles \
clean with clang -target bpf (0 errors), byte-identical across arm64/x86 targets, and its \
predicates are proven to agree exactly with napse_loader::dpi's real detector functions via a \
16-test Rust-mirror parity suite (modules/napse-l2guard/loader/src/predicates.rs). It has NOT yet \
been verifier-load-tested or attach-tested on real hardware in this pass (no root/CAP_BPF on the \
dev box that built it) — see modules/napse-l2guard/README.md's honest-constraints section for the \
exact reproduction and the next validation step.\n"
        .to_string();
    GeneratedFile { path: "l2guard/STATUS-frame-drop-enforcement.txt".to_string(), content }
}

// ---------------------------------------------------------------------------
// DOCUMENT — response events for `hookprobe-evidence --responses` to ingest.
// ---------------------------------------------------------------------------

/// One response-event JSON line for an L1/L2 finding — mirrors
/// `scan_responder::render_response_json`'s shape so both responders' output lands in the SAME
/// evidence-graph response schema.
pub fn render_l2_response_json(alert: &L2Alert, verdict: &L2Verdict, now: f64) -> String {
    // "active" means the SAME thing for both enforcing arms: a real enforcement mechanism exists
    // and is wired for this verdict — never a live "verified currently attached on THIS box right
    // now" claim, which no static renderer in this crate can make either way (see the module doc's
    // "what's real vs stubbed" section for the honest verification-depth caveat on `tc-bpf-l2guard`
    // specifically: compile-proven, attach-on-metal-pending). D12/D15 fix: `Observe` NEVER reports
    // "active" — it exists precisely for findings with no real wire-level enforcement to claim.
    let (action, mechanism, detail, status) = match verdict {
        L2Verdict::RateLimit { reason } => ("rate_limit", "nft-meter", reason.clone(), "active"),
        L2Verdict::FrameDrop { reason } => ("frame_drop", "tc-bpf-l2guard", reason.clone(), "active"),
        L2Verdict::Observe { reason } => ("observe", "alert-only", reason.clone(), "alert-only"),
    };
    serde_json::json!({
        "ts": now,
        "rule_id": alert.rule_id,
        "category": alert.category,
        "reason": alert.reason,
        "src_mac": alert.src_mac,
        "claimed_ip": alert.claimed_ip,
        "action": action,
        "mechanism": mechanism,
        "detail": detail,
        "status": status,
    })
    .to_string()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn alert(category: &str, reason: &str, rule_id: i64, detail: &str, src_mac: Option<&str>, claimed_ip: Option<&str>) -> L2Alert {
        L2Alert {
            ts: 1000.0,
            rule_id,
            rule_msg: "test".to_string(),
            mitre: "T0000".to_string(),
            category: category.to_string(),
            severity: 2,
            confidence: 0.9,
            reason: reason.to_string(),
            detail: detail.to_string(),
            src_mac: src_mac.map(String::from),
            claimed_ip: claimed_ip.map(String::from),
        }
    }

    // ---- parse_l2_alert ---------------------------------------------------------------------

    const MAC_FLOOD_LINE: &str = r#"{"ts":1000.5,"rule_id":1000030,"rule_msg":"NAPSE MAC-Flood / MAC-Table Exhaustion Detected","mitre":"T1498.001","category":"mac_flood","severity":2,"confidence":0.9,"reason":"fanout","detail":"25 distinct source MACs"}"#;

    #[test]
    fn parses_the_exact_napse_l2_schema() {
        let a = parse_l2_alert(MAC_FLOOD_LINE).expect("must parse the exact schema");
        assert_eq!(a.rule_id, MAC_FLOOD_RULE_ID);
        assert_eq!(a.category, "mac_flood");
        assert_eq!(a.mitre, "T1498.001");
    }

    #[test]
    fn ignores_non_l2_lines() {
        let flow = r#"{"type":"conn","ts":1.0}"#;
        assert!(parse_l2_alert(flow).is_none());
        // a port-scan alert (scan_responder's own schema) must not be mistaken for an L2 finding
        let scan = r#"{"ts":1.0,"src_ip":"1.2.3.4","src_port":1,"dst_ip":"5.6.7.8","dst_port":22,"proto":"tcp","severity":2,"rule_id":1000003,"rule_msg":"x","mitre":"T1046","category":"port_scan","confidence":0.9}"#;
        assert!(parse_l2_alert(scan).is_none());
        assert!(parse_l2_alert("").is_none());
        assert!(parse_l2_alert("not json").is_none());
    }

    #[test]
    fn accepts_category_even_with_a_different_rule_id() {
        let line = r#"{"ts":1.0,"rule_id":9999999,"category":"arp_spoof","reason":"eth_mismatch"}"#;
        assert!(parse_l2_alert(line).is_some(), "future-proofing: category alone still matches");
    }

    // ---- decide_l2 — the categories route correctly ------------------------------------------

    #[test]
    fn broadcast_storm_always_decides_to_rate_limit_regardless_of_port_role() {
        let bs = alert("broadcast_storm", "storm", BROADCAST_STORM_RULE_ID, "200 frames", Some("aa:bb:cc:dd:ee:ff"), None);
        assert!(matches!(decide_l2(&bs, PortRole::Access), L2Verdict::RateLimit { .. }));
        assert!(matches!(decide_l2(&bs, PortRole::UplinkBridge), L2Verdict::RateLimit { .. }));
    }

    /// D12 fix — THE legit-passes / attack-still-caught pair: the SAME mac_flood alert decides
    /// differently depending on port role. On a genuine ACCESS port it still claims RateLimit (a
    /// real access-port mac-flood must still enforce); on an UplinkBridge port (this device's own
    /// default topology) it decides Observe — logged, but no wire-level claim.
    #[test]
    fn mac_flood_decides_rate_limit_on_access_but_observe_on_uplink_bridge() {
        let mf = alert("mac_flood", "fanout", MAC_FLOOD_RULE_ID, "25 macs", None, None);
        assert!(matches!(decide_l2(&mf, PortRole::Access), L2Verdict::RateLimit { .. }), "a real access-port mac-flood must still enforce");
        assert!(
            matches!(decide_l2(&mf, PortRole::UplinkBridge), L2Verdict::Observe { .. }),
            "a busy uplink/AP port's mac-flood finding must be observe-only, never a wire-level claim"
        );
    }

    #[test]
    fn arp_gratuitous_flood_decides_to_rate_limit_but_single_frame_anomalies_decide_to_frame_drop() {
        let grat = alert("arp_spoof", "gratuitous_flood", ARP_SPOOF_RULE_ID, "flood", Some("aa:bb:cc:dd:ee:ff"), Some("10.0.0.5"));
        assert!(
            matches!(decide_l2(&grat, PortRole::Access), L2Verdict::RateLimit { .. }),
            "a FLOOD is a rate condition, not a single bad frame"
        );

        for reason in ["eth_mismatch", "malformed_fields"] {
            let a = alert("arp_spoof", reason, ARP_SPOOF_RULE_ID, "x", Some("aa:bb:cc:dd:ee:ff"), Some("10.0.0.5"));
            assert!(
                matches!(decide_l2(&a, PortRole::Access), L2Verdict::FrameDrop { .. }),
                "a single-frame ARP anomaly ({reason}) must drop the frame, never rate-limit an identity"
            );
        }
    }

    /// D15 fix: a binding flip-flop is a STATEFUL, cross-packet condition no real mechanism here
    /// enforces (see `render_frame_drop_status`'s honesty note) — it must decide `Observe`, never
    /// the dishonest `FrameDrop` claim the pre-fix code emitted.
    #[test]
    fn arp_binding_flip_flop_decides_to_observe_not_frame_drop() {
        let a = alert("arp_spoof", "binding_flip_flop", ARP_SPOOF_RULE_ID, "3 macs claimed this ip", Some("aa:bb:cc:dd:ee:ff"), Some("10.0.0.5"));
        let v = decide_l2(&a, PortRole::Access);
        assert!(matches!(v, L2Verdict::Observe { .. }), "binding_flip_flop must decide Observe — no real stateful drop exists");
        assert!(!matches!(v, L2Verdict::FrameDrop { .. }), "must never claim FrameDrop for a condition with no real enforcement");
    }

    #[test]
    fn l2_malformed_decides_to_frame_drop() {
        let a = alert("l2_malformed", "malformed_frame", L2_MALFORMED_RULE_ID, "runt frame", Some("aa:bb:cc:dd:ee:ff"), None);
        assert!(matches!(decide_l2(&a, PortRole::Access), L2Verdict::FrameDrop { .. }));
    }

    #[test]
    fn an_unrecognized_category_fails_safe_to_rate_limit_never_frame_drop() {
        let a = alert("something_new", "x", 424242, "detail", None, None);
        assert!(matches!(decide_l2(&a, PortRole::Access), L2Verdict::RateLimit { .. }));
    }

    // ---- THE CORE anti-spoof property proof --------------------------------------------------
    // A spoofed-source-MAC flood (or any other L1/L2 finding) must NEVER produce a verdict that
    // could reach a durable, identity-keyed quarantine — by construction, L2Verdict has only three
    // variants and NONE is consumed by `scan_responder::reconcile_quarantine`. This match is
    // EXHAUSTIVE (no wildcard arm): if a future edit ever added an `L2Verdict::Quarantine`
    // variant, this test would fail to COMPILE until a human consciously updated it.
    #[test]
    fn no_l2_finding_ever_produces_a_verdict_capable_of_a_durable_identity_quarantine() {
        let victim_mac = "aa:bb:cc:dd:ee:ff"; // pretend this is a real victim's spoofed mac
        let cases = vec![
            alert("mac_flood", "fanout", MAC_FLOOD_RULE_ID, "50 distinct macs incl. a spoofed victim", None, None),
            alert("broadcast_storm", "storm", BROADCAST_STORM_RULE_ID, "storm", Some(victim_mac), None),
            alert("arp_spoof", "gratuitous_flood", ARP_SPOOF_RULE_ID, "flood", Some(victim_mac), Some("10.0.0.5")),
            alert("arp_spoof", "eth_mismatch", ARP_SPOOF_RULE_ID, "mismatch", Some(victim_mac), Some("10.0.0.5")),
            alert("arp_spoof", "binding_flip_flop", ARP_SPOOF_RULE_ID, "flip-flop", Some(victim_mac), Some("10.0.0.5")),
            alert("arp_spoof", "malformed_fields", ARP_SPOOF_RULE_ID, "malformed", Some(victim_mac), None),
            alert("l2_malformed", "malformed_frame", L2_MALFORMED_RULE_ID, "runt", Some(victim_mac), None),
        ];
        for a in cases {
            for role in [PortRole::Access, PortRole::UplinkBridge] {
                match decide_l2(&a, role) {
                    // Exhaustive over the ENTIRE enum — all three arms are structurally incapable
                    // of a durable identity block (see the module doc). No `_ =>` arm exists on
                    // purpose.
                    L2Verdict::RateLimit { .. } | L2Verdict::FrameDrop { .. } | L2Verdict::Observe { .. } => {}
                }
            }
        }
    }

    #[test]
    fn a_mac_flood_alert_never_carries_a_single_attributable_victim_identity() {
        // mac_flood is, by construction (see napse_loader::l2guard::MacFloodTracker), never
        // emitted with a single src_mac — reinforcing the anti-spoof property one level earlier:
        // there is no identity for `decide_l2` to even consider blocking.
        let mf = alert("mac_flood", "fanout", MAC_FLOOD_RULE_ID, "50 distinct macs", None, None);
        assert!(mf.src_mac.is_none());
        assert!(matches!(decide_l2(&mf, PortRole::Access), L2Verdict::RateLimit { .. }));
    }

    // ---- render_storm_control — real nft, a SEPARATE table from scan_responder's quarantine --

    #[test]
    fn render_storm_control_emits_a_separate_table_from_the_persistent_quarantine_table() {
        let g = render_storm_control(&L2GuardConfig::default());
        assert!(g.content.contains("hookprobe_l2guard"));
        assert!(!g.content.contains("hookprobe_quarantine"), "must never touch scan_responder's persistent table");
        assert!(!g.content.contains("quarantine_lan_macs"));
        assert!(!g.content.contains("quarantine_wan_ips"));
    }

    #[test]
    fn render_storm_control_uses_self_reverting_meters_not_persisted_elements() {
        // D12 fix: `L2GuardConfig::default()` is now `UplinkBridge` (the device's own default
        // topology), which intentionally omits the mac-flood meter — exercise `Access` here so
        // this test still covers all THREE meters' shape.
        let cfg = L2GuardConfig { lan_port_role: PortRole::Access, ..Default::default() };
        let g = render_storm_control(&cfg);
        assert!(g.content.contains("meter napse_macflood_meter"));
        assert!(g.content.contains("meter napse_bcast_meter"));
        assert!(g.content.contains("meter napse_arp_meter"));
        // no "add element"/"delete element" anywhere — a meter is self-managing, unlike
        // scan_responder::render_element_ops's per-cycle add/remove diff.
        assert!(!g.content.contains("add element"));
        assert!(!g.content.contains("delete element"));
    }

    #[test]
    fn render_storm_control_scopes_rules_to_the_configured_lan_iface() {
        let cfg = L2GuardConfig { lan_iface: "br-lan".to_string(), ..Default::default() };
        let g = render_storm_control(&cfg);
        assert!(g.content.contains("iifname \"br-lan\""));
    }

    #[test]
    fn render_storm_control_is_idempotent_shaped() {
        // 2026-07-07 first-boot fix: the fully-idempotent idiom is `add table` (no-op if present) →
        // `delete table` (now ALWAYS succeeds — a bare delete-first aborts a single `nft -f`
        // transaction when the table doesn't exist yet, which broke the arm64 VM's first boot) →
        // `add table` fresh (dropping any meter implicit-set state a prior apply left), THEN the
        // chain/flush/meter rules.
        let g = render_storm_control(&L2GuardConfig::default());
        let first_add = g.content.find("add table inet hookprobe_l2guard").expect("must guard-add table first");
        let delete_at = g.content.find("delete table inet hookprobe_l2guard").expect("must delete table");
        let last_add = g.content.rfind("add table inet hookprobe_l2guard").expect("must re-add table fresh");
        assert!(first_add < delete_at, "a guard `add table` must precede `delete table` (first-boot-safe)");
        assert!(delete_at < last_add, "`delete table` must be followed by a fresh `add table`");
        assert!(g.content.contains("flush chain inet hookprobe_l2guard forward"));
    }

    /// H1 real-`nft` proof: render the storm-control bootstrap and apply it TWICE via the real
    /// `nft` binary, line-by-line (mirroring `supervisor::apply_or_print`'s actual execution model:
    /// each non-comment line is its own `nft <argv>` invocation, continuing past a single line's
    /// failure rather than aborting the whole reconcile) — inside an unprivileged network namespace
    /// (`unshare --net --map-root-user`) so this proof needs no root/CAP_NET_ADMIN on the CI/dev
    /// box and touches no real interface. BEFORE this fix, the second apply's THREE `add rule …
    /// meter napse_..._meter { … }` lines each failed with nft's real `File exists; meter '…'
    /// overlaps an existing set '…'` error (reproduced manually while diagnosing H1) and the
    /// meters were silently gone from the live ruleset after a second reconcile. Skips cleanly
    /// (does not fail the suite) if this sandbox has neither `nft` nor unprivileged user
    /// namespaces available — this is a real-environment integration proof, not a substitute for
    /// the pure content-shape test above, which always runs.
    #[test]
    fn render_storm_control_apply_twice_succeeds_line_by_line() {
        use std::process::Command;

        // Environment probe: skip (not fail) if this sandbox can't grant an unprivileged netns.
        let probe = Command::new("unshare").args(["--net", "--map-root-user", "--", "true"]).status();
        if !matches!(probe, Ok(st) if st.success()) {
            eprintln!("skipping render_storm_control_apply_twice_succeeds_line_by_line: no unprivileged netns available");
            return;
        }
        if Command::new("nft").arg("--version").status().is_err() {
            eprintln!("skipping render_storm_control_apply_twice_succeeds_line_by_line: nft not installed");
            return;
        }

        let content = render_storm_control(&L2GuardConfig::default()).content;
        // One shell function applying the rendered content line-by-line exactly like
        // `apply_or_print`: word-split each non-comment line, exec `nft` with those args, log
        // (never abort) on failure. Run the WHOLE two-apply sequence inside ONE `unshare` so both
        // applies share the same (freshly created) netns / nft kernel state.
        let script = format!(
            "apply() {{ echo \"$1\" | while IFS= read -r line; do \
               case \"$line\" in ''|'#'*) continue;; esac; \
               nft $line >/tmp/l2guard_apply_err.$$ 2>&1 || {{ cat /tmp/l2guard_apply_err.$$; exit 1; }}; \
               rm -f /tmp/l2guard_apply_err.$$; \
             done; }}\n\
             CONTENT='{}'\n\
             echo \"=== apply #1 (first-ever; delete-table is EXPECTED to no-op/fail harmlessly) ===\"\n\
             echo \"$CONTENT\" | while IFS= read -r line; do case \"$line\" in ''|'#'*) continue;; esac; nft $line >/dev/null 2>&1; done\n\
             echo \"=== apply #2 (reconcile; this is what H1 broke) ===\"\n\
             apply \"$CONTENT\"\n\
             echo ALL_GOOD",
            content.replace('\'', "'\\''")
        );
        let out = Command::new("unshare")
            .args(["--net", "--map-root-user", "--", "sh", "-c", &script])
            .output()
            .expect("exec unshare+sh");
        let stdout = String::from_utf8_lossy(&out.stdout);
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(
            out.status.success() && stdout.contains("ALL_GOOD"),
            "second apply of render_storm_control's output must succeed with the real nft binary \
             (H1's exact failure mode was a meter-overlap error on re-apply) — stdout:\n{stdout}\nstderr:\n{stderr}"
        );
        assert!(!stdout.to_lowercase().contains("overlaps an existing set"), "H1 regressed: meter overlap on re-apply");
    }

    // ---- render_frame_drop_status — real enforcement exists now, never a fabricated nft rule ---

    #[test]
    fn render_frame_drop_status_names_the_real_enforcement_point_never_a_fabricated_nft_rule() {
        let g = render_frame_drop_status();
        assert!(g.content.contains("ENFORCED"), "must no longer read as an unfulfilled TODO");
        assert!(g.content.contains("napse-l2guard"), "must name the real module that enforces this");
        assert!(g.content.contains("TC-bpf") || g.content.contains("TC_ACT_SHOT"), "must name the real enforcement mechanism");
        // nft STILL cannot express this — the crate must never emit a rule that LOOKS like real
        // nft-based enforcement for a condition nft cannot express.
        assert!(!g.content.contains("add rule"), "must never emit a fabricated nft rule");
        assert!(!g.content.contains("add table"));
    }

    #[test]
    fn render_frame_drop_status_is_honest_about_verification_depth() {
        let g = render_frame_drop_status();
        assert!(g.content.contains("compile") || g.content.contains("clang"), "must disclose compile-proven status");
        assert!(
            g.content.contains("root/CAP_BPF") || g.content.contains("attach-on-metal") || g.content.contains("hardware"),
            "must disclose the attach-on-metal-pending caveat, not silently claim full verification"
        );
    }

    #[test]
    fn render_frame_drop_status_discloses_the_binding_flip_flop_scope_gap_honestly() {
        let g = render_frame_drop_status();
        assert!(g.content.contains("binding_flip_flop"), "must name what the BPF program does NOT cover");
        assert!(g.content.contains("alert-only"), "must say the uncovered condition stays alert-only");
    }

    // ---- render_l2_response_json ---------------------------------------------------------------

    #[test]
    fn response_json_for_rate_limit_and_frame_drop_are_both_marked_active_with_distinct_mechanisms() {
        // Both verdicts now have REAL enforcement (2026-07-05: modules/napse-l2guard closed the
        // FrameDrop gap) — distinguished by `mechanism`, not by a stale "alert_only" status.
        // A real access-port mac_flood still claims RateLimit — see the D12 test above for the
        // UplinkBridge-decides-Observe counterpart.
        let rl_alert = alert("mac_flood", "fanout", MAC_FLOOD_RULE_ID, "flood", None, None);
        let rl_verdict = decide_l2(&rl_alert, PortRole::Access);
        let rl_json = render_l2_response_json(&rl_alert, &rl_verdict, 2000.0);
        let v: serde_json::Value = serde_json::from_str(&rl_json).expect("valid json");
        assert_eq!(v["action"], "rate_limit");
        assert_eq!(v["mechanism"], "nft-meter");
        assert_eq!(v["status"], "active");

        let fd_alert = alert("l2_malformed", "malformed_frame", L2_MALFORMED_RULE_ID, "runt", Some("aa:bb:cc:dd:ee:ff"), None);
        let fd_verdict = decide_l2(&fd_alert, PortRole::Access);
        let fd_json = render_l2_response_json(&fd_alert, &fd_verdict, 2000.0);
        let v2: serde_json::Value = serde_json::from_str(&fd_json).expect("valid json");
        assert_eq!(v2["action"], "frame_drop");
        assert_eq!(v2["mechanism"], "tc-bpf-l2guard", "the real, separate Ring-0 program — see render_frame_drop_status");
        assert_eq!(v2["status"], "active");
    }

    /// D15 fix, response-record honesty: `binding_flip_flop` must render as `observe`/`alert-only`
    /// — never a fabricated `active` claim for a mechanism that doesn't exist.
    #[test]
    fn response_json_for_binding_flip_flop_is_honestly_observe_alert_only_never_active() {
        let a = alert("arp_spoof", "binding_flip_flop", ARP_SPOOF_RULE_ID, "flip-flop", Some("aa:bb:cc:dd:ee:ff"), Some("10.0.0.5"));
        let verdict = decide_l2(&a, PortRole::Access);
        let json = render_l2_response_json(&a, &verdict, 2000.0);
        let v: serde_json::Value = serde_json::from_str(&json).expect("valid json");
        assert_eq!(v["action"], "observe");
        assert_eq!(v["mechanism"], "alert-only");
        assert_eq!(v["status"], "alert-only", "must never claim active enforcement for a condition with none");
    }

    /// D12 fix, response-record honesty: a mac_flood finding on an UplinkBridge port must likewise
    /// render `observe`/`alert-only`, never `active` — no meter was installed for it.
    #[test]
    fn response_json_for_mac_flood_on_uplink_bridge_is_honestly_observe_alert_only() {
        let a = alert("mac_flood", "fanout", MAC_FLOOD_RULE_ID, "40 distinct macs", None, None);
        let verdict = decide_l2(&a, PortRole::UplinkBridge);
        let json = render_l2_response_json(&a, &verdict, 2000.0);
        let v: serde_json::Value = serde_json::from_str(&json).expect("valid json");
        assert_eq!(v["action"], "observe");
        assert_eq!(v["status"], "alert-only");
    }

    // ---- D12/D13 render_storm_control — topology-aware mac-flood meter + multicast exemption ----

    /// THE legit-passes proof: on an UplinkBridge port (the device's own default topology), the
    /// mac-flood meter is NOT rendered at all — only the broadcast/ARP meters remain.
    #[test]
    fn render_storm_control_omits_the_macflood_meter_on_uplink_bridge_ports() {
        let cfg = L2GuardConfig { lan_port_role: PortRole::UplinkBridge, ..Default::default() };
        let g = render_storm_control(&cfg);
        assert!(!g.content.contains("napse_macflood_meter"), "no mac-flood meter on an UplinkBridge port");
        assert!(g.content.contains("napse_bcast_meter"), "broadcast meter is unaffected by port role");
        assert!(g.content.contains("napse_arp_meter"), "ARP meter is unaffected by port role");
        assert!(g.content.to_lowercase().contains("observe"), "must document why the meter is absent");
    }

    /// THE attack-still-caught proof: on a genuine ACCESS port, the mac-flood meter is still
    /// rendered exactly as before.
    #[test]
    fn render_storm_control_still_renders_the_macflood_meter_on_access_ports() {
        let cfg = L2GuardConfig { lan_port_role: PortRole::Access, ..Default::default() };
        let g = render_storm_control(&cfg);
        assert!(g.content.contains("napse_macflood_meter"), "a genuine access port keeps the real mac-flood cap");
    }

    /// D13 legit-passes proof at the enforcement layer: the exempt service-discovery multicast
    /// groups are accepted BEFORE the broadcast-storm meter, for both port roles.
    #[test]
    fn render_storm_control_exempts_wellknown_multicast_before_the_broadcast_meter() {
        let g = render_storm_control(&L2GuardConfig::default());
        let accept_v4_at = g.content.find("hookprobe-l2guard-exempt-multicast-v4").expect("v4 exemption present");
        let accept_v6_at = g.content.find("hookprobe-l2guard-exempt-multicast-v6").expect("v6 exemption present");
        let meter_at = g.content.find("napse_bcast_meter").expect("broadcast meter present");
        assert!(accept_v4_at < meter_at && accept_v6_at < meter_at, "exemptions must precede the storm-control meter");
        assert!(g.content.contains("224.0.0.251") && g.content.contains("239.255.255.250") && g.content.contains("224.0.0.252"));
        assert!(g.content.contains("ff02::fb") && g.content.contains("ff02::c") && g.content.contains("ff02::1:3"));
    }
}
