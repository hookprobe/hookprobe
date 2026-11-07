//! Packet-layer SYN fan-out (port-scan) detector — the deep layer's answer to a gap validated live
//! on a real Pi 4: a fast host scan's closed-port SYNs get RST'd instantly, so conntrack (polled by
//! `senzorium-flow` every 5 s) never accumulates enough concurrent entries to see it (measured: max
//! 5 concurrent ports in conntrack even watching at 4 Hz during a live scan). NAPSE's wasm engine
//! HAS a port-scan rule (1000003, ≥50 unique dst ports) but it is fed by the conntrack flow file and
//! so never sees the ports. The raw SYNs ARE visible here, on the mirror sink — this module tracks
//! them directly: a per-source-IP sliding window of distinct destination ports reached by PURE
//! connection-attempt SYNs (`dpi::parse_tcp_syn` already filters out SYN-ACK replies and
//! established/ACK traffic — see that module for the wire-level classification).
//!
//! Deliberately mirrors NAPSE wasm rule 1000003 exactly (rule_id, message, category, MITRE
//! technique, severity, and confidence formula) so the same scan renders identically in the
//! evidence graph whichever sensor caught it (flow-based wasm engine or this packet-layer tracker).
//!
//! Pure, no I/O — `PortScanTracker::observe` is fed `(ts, src_ip, src_port, dst_ip, dst_port,
//! syn_only, src_mac)` tuples by the AF_PACKET recv loop in `bin/napse-dpi.rs` and returns
//! `Some(alert)` exactly once per scan (edge-triggered: fires the instant the distinct-dport count
//! first reaches the threshold, then suppressed for `cooldown_secs` so one scan yields one alert,
//! not a flood).
//!
//! 2026-07-05 threat-model fix (CRITICAL #1/#2): crossing this fan-out threshold is NO LONGER, by
//! itself, sufficient to enforce against a source — a single-packet, spoofable claimed source IP
//! must never populate the enforced quarantine map. `bin/napse-dpi.rs` additionally runs
//! `crate::confirm::HandshakeTracker` over the SAME packet stream and stamps the alert's
//! `confirmed` bit (rendered by `PortScanAlert::to_json`) from that independent, validated signal
//! — this module itself does not decide confirmation, only fan-out. It DOES now carry the
//! OBSERVED L2 source MAC (`src_mac`, captured at detection time, never resolved from the claimed
//! IP afterward) so the responder never needs an ARP/`ip neigh` lookup keyed on attacker-controlled
//! input.

use std::collections::{HashMap, HashSet, VecDeque};
use std::net::Ipv4Addr;

/// Rule 1000003 identity — MUST match `modules/napse/src/lib.rs` exactly, so a scan looks identical
/// in the evidence graph regardless of which sensor (flow-based wasm engine or this packet-layer
/// tracker) fired it.
pub const RULE_ID: u32 = 1_000_003;
pub const RULE_MSG: &str = "NAPSE Port Scan Detected";
pub const CATEGORY: &str = "port_scan";
pub const MITRE: &str = "T1046";
/// Suricata convention: 1=CRITICAL 2=HIGH 3=MEDIUM 4=LOW 5=INFO. Rule 1000003 is MEDIUM in the wasm
/// engine (`SEV_MEDIUM`, see `modules/napse/src/lib.rs`) — kept identical here for a CONFIRMED scan.
pub const SEVERITY: u8 = 3;
/// 2026-07-05 threat-model fix (CRITICAL #1): an UNCONFIRMED SYN-only fan-out (no source seen to
/// complete a real TCP handshake — see `crate::confirm::HandshakeTracker`) is downgraded to LOW.
/// It is still emitted (detection is never suppressed) but the responder must never enforce on
/// it alone — see `hookprobe_manifest::scan_responder::decide`'s `confirmed` gate.
pub const SEVERITY_UNCONFIRMED: u8 = 4;

pub const DEFAULT_THRESHOLD: usize = 50;
pub const DEFAULT_WINDOW_SECS: f64 = 10.0;
pub const DEFAULT_COOLDOWN_SECS: f64 = 30.0;
pub const DEFAULT_MAX_SOURCES: usize = 4096;

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct PortScanConfig {
    /// Distinct destination ports within `window_secs` that trigger a scan alert.
    pub threshold: usize,
    /// Sliding-window size, seconds.
    pub window_secs: f64,
    /// After firing, suppress re-firing for this source for this many seconds (one scan = one
    /// alert).
    pub cooldown_secs: f64,
    /// Cap on distinct tracked source IPs — bounds memory against an unbounded-source attack
    /// (e.g. spoofed-source SYN flood). Oldest-inserted source is evicted first once at capacity.
    pub max_sources: usize,
}

impl Default for PortScanConfig {
    fn default() -> Self {
        PortScanConfig {
            threshold: DEFAULT_THRESHOLD,
            window_secs: DEFAULT_WINDOW_SECS,
            cooldown_secs: DEFAULT_COOLDOWN_SECS,
            max_sources: DEFAULT_MAX_SOURCES,
        }
    }
}

/// One emitted port-scan alert, ready to render as a NAPSE event-stream JSON line.
#[derive(Debug, Clone, PartialEq)]
pub struct PortScanAlert {
    pub ts: f64,
    pub src_ip: Ipv4Addr,
    /// The scanning source's TCP source port on the triggering packet (last seen).
    pub src_port: u16,
    /// The target IP of the triggering packet (last-probed target — this tracker counts distinct
    /// PORTS per source, not per (target,port) pair, matching the wasm engine's rule 1000003).
    pub dst_ip: Ipv4Addr,
    /// The destination port that completed the threshold crossing (last-probed port).
    pub dst_port: u16,
    pub distinct_ports: usize,
    /// The OBSERVED Ethernet source MAC on the triggering packet (never an ARP/`ip neigh`
    /// resolution of the claimed `src_ip` — see `hookprobe_manifest::scan_responder::resolve_mac`'s
    /// doc comment for why that lookup is the vulnerability this field's plumbing fixes).
    /// `None` only if every packet in this scan somehow failed MAC extraction (never happens for a
    /// well-formed Ethernet frame; kept `Option` for robustness, not because it's expected).
    pub src_mac: Option<[u8; 6]>,
}

impl PortScanAlert {
    /// Confidence formula mirrors the wasm engine's rule 1000003 exactly: 0.50 base + 0.005 per
    /// distinct port observed, capped at 0.95.
    fn confidence(&self) -> f64 {
        (0.50 + self.distinct_ports as f64 * 0.005).min(0.95)
    }

    fn mac_str(&self) -> Option<String> {
        self.src_mac.map(|m| {
            format!("{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}", m[0], m[1], m[2], m[3], m[4], m[5])
        })
    }

    /// Render as one NAPSE event-stream JSON line. Field set matches what
    /// `hookprobe-evidence::ingest_detection` reads (ts, src_ip, src_port, dst_ip, dst_port, proto,
    /// severity, rule_id, rule_msg, mitre, category, confidence) plus the 2026-07-05 fix's two new
    /// fields the responder gates enforcement on: `confirmed` (handshake-validated, never a
    /// self-reported claim the responder blindly trusts — see `scan_responder::decide`) and
    /// `src_mac` (the observed L2 address to bind LAN quarantine to). `confirmed=false` renders
    /// `SEVERITY_UNCONFIRMED` (LOW) instead of `SEVERITY` (MEDIUM) — detection is never suppressed,
    /// only its enforcement weight is downgraded.
    pub fn to_json(&self, confirmed: bool) -> String {
        let sev = if confirmed { SEVERITY } else { SEVERITY_UNCONFIRMED };
        let mac_field = match self.mac_str() {
            Some(m) => format!(r#","src_mac":"{m}""#),
            None => String::new(),
        };
        format!(
            concat!(
                r#"{{"ts":{ts:.3},"src_ip":"{src}","src_port":{sp},"#,
                r#""dst_ip":"{dst}","dst_port":{dp},"proto":"tcp","#,
                r#""severity":{sev},"rule_id":{rid},"rule_msg":"{msg}","#,
                r#""mitre":"{mitre}","category":"{cat}","confidence":{conf:.4},"#,
                r#""confirmed":{confirmed}{mac_field}}}"#,
            ),
            ts = self.ts,
            src = self.src_ip,
            sp = self.src_port,
            dst = self.dst_ip,
            dp = self.dst_port,
            sev = sev,
            rid = RULE_ID,
            msg = RULE_MSG,
            mitre = MITRE,
            cat = CATEGORY,
            conf = self.confidence(),
            confirmed = confirmed,
            mac_field = mac_field,
        )
    }
}

struct SourceState {
    /// (ts, dst_port) of every SYN-only packet still inside the window.
    window: VecDeque<(f64, u16)>,
    last_alert_ts: Option<f64>,
    last_src_port: u16,
    last_dst_ip: Ipv4Addr,
    /// The observed L2 source MAC on the most recent SYN — captured at detection time, never
    /// resolved from the claimed IP afterward.
    last_src_mac: [u8; 6],
}

/// Bounded per-source-IP sliding-window SYN fan-out tracker.
pub struct PortScanTracker {
    cfg: PortScanConfig,
    sources: HashMap<Ipv4Addr, SourceState>,
    /// Insertion-order FIFO of tracked source IPs, for O(1) oldest-eviction. Kept exactly in sync
    /// with `sources`'s key set: a source is pushed once (on first sighting) and popped once (on
    /// eviction), so it never holds a stale entry.
    order: VecDeque<Ipv4Addr>,
}

impl PortScanTracker {
    pub fn new(cfg: PortScanConfig) -> Self {
        PortScanTracker { cfg, sources: HashMap::new(), order: VecDeque::new() }
    }

    /// Feed one packet observation. `syn_only` must be true only for a pure connection-attempt SYN
    /// (SYN set, ACK clear) — `dpi::parse_tcp_syn` makes this distinction; SYN-ACK replies and
    /// established/ACK traffic must be passed with `syn_only=false` (or not passed at all) and never
    /// count toward a scan.
    ///
    /// Returns `Some(alert)` the instant `src_ip`'s distinct-dport count within the window first
    /// reaches `threshold`, then suppresses re-firing for that source until `cooldown_secs` has
    /// elapsed (so one scan yields one alert).
    #[allow(clippy::too_many_arguments)]
    pub fn observe(
        &mut self,
        now: f64,
        src_ip: Ipv4Addr,
        src_port: u16,
        dst_ip: Ipv4Addr,
        dst_port: u16,
        syn_only: bool,
        src_mac: [u8; 6],
    ) -> Option<PortScanAlert> {
        if !syn_only {
            return None;
        }

        if !self.sources.contains_key(&src_ip) {
            self.evict_if_full();
            self.order.push_back(src_ip);
            self.sources.insert(
                src_ip,
                SourceState {
                    window: VecDeque::new(),
                    last_alert_ts: None,
                    last_src_port: src_port,
                    last_dst_ip: dst_ip,
                    last_src_mac: src_mac,
                },
            );
        }
        let state = self.sources.get_mut(&src_ip).expect("just inserted above");
        state.window.push_back((now, dst_port));
        state.last_src_port = src_port;
        state.last_dst_ip = dst_ip;
        state.last_src_mac = src_mac;

        // Evict window entries older than `window_secs`.
        let cutoff = now - self.cfg.window_secs;
        while state.window.front().is_some_and(|&(ts, _)| ts < cutoff) {
            state.window.pop_front();
        }

        let distinct: HashSet<u16> = state.window.iter().map(|&(_, p)| p).collect();
        if distinct.len() < self.cfg.threshold {
            return None;
        }
        if let Some(last) = state.last_alert_ts {
            if now - last < self.cfg.cooldown_secs {
                return None; // one scan = one alert; still cooling down
            }
        }
        state.last_alert_ts = Some(now);
        Some(PortScanAlert {
            ts: now,
            src_ip,
            src_port: state.last_src_port,
            dst_ip: state.last_dst_ip,
            dst_port,
            distinct_ports: distinct.len(),
            src_mac: Some(state.last_src_mac),
        })
    }

    /// Bound tracked sources: evict the oldest-inserted source(s) before adding a new one once at
    /// capacity. Guards against unbounded memory growth from a spoofed-source flood.
    fn evict_if_full(&mut self) {
        let cap = self.cfg.max_sources.max(1);
        while self.sources.len() >= cap {
            match self.order.pop_front() {
                Some(old) => {
                    self.sources.remove(&old);
                }
                None => break, // queue and map both empty — nothing to evict
            }
        }
    }
}

// ---------------------------------------------------------------------------------------------
// 2026-07-05 fan-out coverage fix (EDR #2) — UDP port-fanout + ICMP host-sweep trackers. Neither
// protocol has a SYN/handshake concept, so both reuse the SAME sliding-window/threshold/cooldown
// machinery `PortScanTracker` established, over a different observation shape each:
//   - UDP has no handshake at all — EVERY datagram to a new destination port from one source is
//     itself the probe signal (`dpi::UdpObs`, fed by `dpi::parse_udp_obs`).
//   - ICMP has no ports at all — a host-discovery sweep is "one source pinging many DISTINCT
//     destination IPs", not "many ports on one destination" (`dpi::IcmpObs`, `dpi::parse_icmp_obs`,
//     filtered to `ICMP_ECHO_REQUEST` — replies/unreachables/etc. are irrelevant to a sweep).
// Both are DETECTIONS ONLY in this pass (rule_ids in the SAME 1_000_0xx band `portscan::RULE_ID`
// already occupies, checked against every rule_id in the workspace — see each `RULE_ID` constant's
// doc below): they emit an alert line exactly like `PortScanAlert`, but do NOT carry a `confirmed`
// bit or wire into `scan_responder`'s quarantine path — the SYN-handshake confirmation discipline
// (ADR 0018/CRITICAL #1) has no UDP/ICMP equivalent yet (no 3-way handshake to validate), so
// enforcement wiring for these two is intentionally left as a documented follow-up rather than
// inventing a confirmation signal that doesn't exist. Both new trackers are pure, dependency-free
// library code — ready for `bin/napse-dpi.rs`'s capture loop to feed (that wiring, and the
// existing `syn_only` boolean it computes inline instead of calling `dpi::TcpObs::scan_probe_kind`,
// are a follow-up in that binary, which is outside this pass's file ownership).
// ---------------------------------------------------------------------------------------------

/// Rule id for the UDP destination-port fan-out (UDP scan) detector.
// 2026-07-07 COLLISION FIX: this was originally assigned `1_000_010`, on the (incorrect, at the
// time unchecked-against-the-wasm-engine) assumption that only 1_000_001/2/3/4/5/7/8/9 were taken.
// `modules/napse::run_signatures` rule 1000010 is "NAPSE Path Traversal Attempt" (T1083) — a
// REAL, already-shipped collision: a UDP scan and a path-traversal hit would have rendered under
// the identical `rule_id` in the evidence graph / responder natural-key match, from two different
// sensors, with no way to tell them apart downstream. Moved to `1_000_014` (free — checked against
// every `RULE_ID`/rule_id constant in the workspace: `modules/napse` 1_000_001..=1_000_025 —
// including 1_000_010 "Path Traversal" and 1_000_011 "DNS Non-Standard Port", both of which the
// ORIGINAL 2026-07-05 check missed — `napse-capture::portscan` itself 1_000_003/1_000_012/1_000_013,
// `napse-capture::l2guard` 1_000_030..=1_000_033, host-EDR 1_000_100..=1_000_118, this file's new
// `beacon`/`lateral` additions 1_000_040/1_000_041).
pub const UDP_SCAN_RULE_ID: u32 = 1_000_014;
pub const UDP_SCAN_MSG: &str = "NAPSE UDP Port Scan Detected";
pub const UDP_SCAN_CATEGORY: &str = "udp_scan";
/// Same MITRE technique as the TCP port scan (`portscan::MITRE`) — both are Network Service
/// Discovery (T1046), just over a different transport.
pub const UDP_SCAN_MITRE: &str = "T1046";

/// Rule id for the ICMP host-discovery sweep detector.
// 2026-07-07: moved 1_000_011 → 1_000_013 to resolve a rule_id COLLISION — the wasm engine's
// canonical rule 1000011 is "DNS Query to Non-Standard Port" (T1071.004, modules/napse/src/lib.rs),
// which predates and owns 1000011. Two detections sharing a rule_id would conflate in the evidence
// graph / responder natural-key match. 1_000_013 is free (1_000_012 = slow-scan).
pub const ICMP_SWEEP_RULE_ID: u32 = 1_000_013;
pub const ICMP_SWEEP_MSG: &str = "NAPSE ICMP Host Sweep Detected";
pub const ICMP_SWEEP_CATEGORY: &str = "icmp_sweep";
/// Remote System Discovery — finding which HOSTS are alive, distinct from T1046 (which service
/// PORTS are open on one host).
pub const ICMP_SWEEP_MITRE: &str = "T1018";

pub const DEFAULT_UDP_SCAN_THRESHOLD: usize = 50;
pub const DEFAULT_UDP_SCAN_WINDOW_SECS: f64 = 10.0;
pub const DEFAULT_UDP_SCAN_COOLDOWN_SECS: f64 = 30.0;
pub const DEFAULT_UDP_SCAN_MAX_SOURCES: usize = 4096;

pub const DEFAULT_ICMP_SWEEP_THRESHOLD: usize = 20;
pub const DEFAULT_ICMP_SWEEP_WINDOW_SECS: f64 = 10.0;
pub const DEFAULT_ICMP_SWEEP_COOLDOWN_SECS: f64 = 30.0;
pub const DEFAULT_ICMP_SWEEP_MAX_SOURCES: usize = 4096;

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct UdpScanConfig {
    pub threshold: usize,
    pub window_secs: f64,
    pub cooldown_secs: f64,
    pub max_sources: usize,
}
impl Default for UdpScanConfig {
    fn default() -> Self {
        UdpScanConfig {
            threshold: DEFAULT_UDP_SCAN_THRESHOLD,
            window_secs: DEFAULT_UDP_SCAN_WINDOW_SECS,
            cooldown_secs: DEFAULT_UDP_SCAN_COOLDOWN_SECS,
            max_sources: DEFAULT_UDP_SCAN_MAX_SOURCES,
        }
    }
}

/// One emitted UDP-scan alert — same shape/field-naming convention as [`PortScanAlert`], minus the
/// `confirmed` bit (no handshake concept for UDP to confirm against — see this section's doc).
#[derive(Debug, Clone, PartialEq)]
pub struct UdpScanAlert {
    pub ts: f64,
    pub src_ip: Ipv4Addr,
    pub src_port: u16,
    pub dst_ip: Ipv4Addr,
    pub dst_port: u16,
    pub distinct_ports: usize,
    pub src_mac: Option<[u8; 6]>,
}
impl UdpScanAlert {
    fn confidence(&self) -> f64 {
        (0.50 + self.distinct_ports as f64 * 0.005).min(0.95)
    }
    fn mac_str(&self) -> Option<String> {
        self.src_mac.map(|m| format!("{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}", m[0], m[1], m[2], m[3], m[4], m[5]))
    }
    pub fn to_json(&self) -> String {
        let mac_field = match self.mac_str() {
            Some(m) => format!(r#","src_mac":"{m}""#),
            None => String::new(),
        };
        format!(
            concat!(
                r#"{{"ts":{ts:.3},"src_ip":"{src}","src_port":{sp},"#,
                r#""dst_ip":"{dst}","dst_port":{dp},"proto":"udp","#,
                r#""severity":{sev},"rule_id":{rid},"rule_msg":"{msg}","#,
                r#""mitre":"{mitre}","category":"{cat}","confidence":{conf:.4}{mac_field}}}"#,
            ),
            ts = self.ts,
            src = self.src_ip,
            sp = self.src_port,
            dst = self.dst_ip,
            dp = self.dst_port,
            sev = SEVERITY,
            rid = UDP_SCAN_RULE_ID,
            msg = UDP_SCAN_MSG,
            mitre = UDP_SCAN_MITRE,
            cat = UDP_SCAN_CATEGORY,
            conf = self.confidence(),
            mac_field = mac_field,
        )
    }
}

struct UdpSourceState {
    window: VecDeque<(f64, u16)>,
    last_alert_ts: Option<f64>,
    last_src_port: u16,
    last_dst_ip: Ipv4Addr,
    last_src_mac: [u8; 6],
}

/// Bounded per-source-IP sliding-window UDP destination-port fan-out tracker. Every UDP datagram
/// counts (there's no SYN/handshake gate to filter on) — mirrors [`PortScanTracker`]'s sliding
/// window exactly, just fed `dpi::UdpObs` tuples instead of TCP SYN observations.
pub struct UdpScanTracker {
    cfg: UdpScanConfig,
    sources: HashMap<Ipv4Addr, UdpSourceState>,
    order: VecDeque<Ipv4Addr>,
}
impl UdpScanTracker {
    pub fn new(cfg: UdpScanConfig) -> Self {
        UdpScanTracker { cfg, sources: HashMap::new(), order: VecDeque::new() }
    }

    fn evict_if_full(&mut self) {
        let cap = self.cfg.max_sources.max(1);
        while self.sources.len() >= cap {
            match self.order.pop_front() {
                Some(old) => {
                    self.sources.remove(&old);
                }
                None => break,
            }
        }
    }

    /// Feed one UDP datagram observation. Returns `Some(alert)` the instant `src_ip`'s distinct
    /// dst-port count within the window first reaches `threshold`, then suppresses re-firing for
    /// `cooldown_secs` (one scan = one alert), exactly like [`PortScanTracker::observe`].
    #[allow(clippy::too_many_arguments)]
    pub fn observe(
        &mut self,
        now: f64,
        src_ip: Ipv4Addr,
        src_port: u16,
        dst_ip: Ipv4Addr,
        dst_port: u16,
        src_mac: [u8; 6],
    ) -> Option<UdpScanAlert> {
        if !self.sources.contains_key(&src_ip) {
            self.evict_if_full();
            self.order.push_back(src_ip);
            self.sources.insert(
                src_ip,
                UdpSourceState { window: VecDeque::new(), last_alert_ts: None, last_src_port: src_port, last_dst_ip: dst_ip, last_src_mac: src_mac },
            );
        }
        let state = self.sources.get_mut(&src_ip).expect("just inserted above");
        state.window.push_back((now, dst_port));
        state.last_src_port = src_port;
        state.last_dst_ip = dst_ip;
        state.last_src_mac = src_mac;

        let cutoff = now - self.cfg.window_secs;
        while state.window.front().is_some_and(|&(ts, _)| ts < cutoff) {
            state.window.pop_front();
        }

        let distinct: HashSet<u16> = state.window.iter().map(|&(_, p)| p).collect();
        if distinct.len() < self.cfg.threshold {
            return None;
        }
        if let Some(last) = state.last_alert_ts {
            if now - last < self.cfg.cooldown_secs {
                return None;
            }
        }
        state.last_alert_ts = Some(now);
        Some(UdpScanAlert {
            ts: now,
            src_ip,
            src_port: state.last_src_port,
            dst_ip: state.last_dst_ip,
            dst_port,
            distinct_ports: distinct.len(),
            src_mac: Some(state.last_src_mac),
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct IcmpSweepConfig {
    /// Distinct destination IPs pinged within `window_secs` that trigger a sweep alert.
    pub threshold: usize,
    pub window_secs: f64,
    pub cooldown_secs: f64,
    pub max_sources: usize,
}
impl Default for IcmpSweepConfig {
    fn default() -> Self {
        IcmpSweepConfig {
            threshold: DEFAULT_ICMP_SWEEP_THRESHOLD,
            window_secs: DEFAULT_ICMP_SWEEP_WINDOW_SECS,
            cooldown_secs: DEFAULT_ICMP_SWEEP_COOLDOWN_SECS,
            max_sources: DEFAULT_ICMP_SWEEP_MAX_SOURCES,
        }
    }
}

/// One emitted ICMP-sweep alert. `dst_ip` is the LAST host probed that completed the threshold
/// crossing (mirrors `PortScanAlert::dst_port`'s "last-probed" convention) — the full set of swept
/// hosts is a distinct-destination count, not enumerated in the alert itself (matches how a port
/// scan alert reports `distinct_ports` as a count, not the full port list).
#[derive(Debug, Clone, PartialEq)]
pub struct IcmpSweepAlert {
    pub ts: f64,
    pub src_ip: Ipv4Addr,
    pub dst_ip: Ipv4Addr,
    pub distinct_hosts: usize,
    pub src_mac: Option<[u8; 6]>,
}
impl IcmpSweepAlert {
    fn confidence(&self) -> f64 {
        (0.50 + self.distinct_hosts as f64 * 0.01).min(0.95)
    }
    fn mac_str(&self) -> Option<String> {
        self.src_mac.map(|m| format!("{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}", m[0], m[1], m[2], m[3], m[4], m[5]))
    }
    pub fn to_json(&self) -> String {
        let mac_field = match self.mac_str() {
            Some(m) => format!(r#","src_mac":"{m}""#),
            None => String::new(),
        };
        format!(
            concat!(
                r#"{{"ts":{ts:.3},"src_ip":"{src}","dst_ip":"{dst}","proto":"icmp","#,
                r#""severity":{sev},"rule_id":{rid},"rule_msg":"{msg}","#,
                r#""mitre":"{mitre}","category":"{cat}","confidence":{conf:.4}{mac_field}}}"#,
            ),
            ts = self.ts,
            src = self.src_ip,
            dst = self.dst_ip,
            sev = SEVERITY,
            rid = ICMP_SWEEP_RULE_ID,
            msg = ICMP_SWEEP_MSG,
            mitre = ICMP_SWEEP_MITRE,
            cat = ICMP_SWEEP_CATEGORY,
            conf = self.confidence(),
            mac_field = mac_field,
        )
    }
}

struct IcmpSourceState {
    /// (ts, dst_ip) of every ICMP echo-request still inside the window.
    window: VecDeque<(f64, Ipv4Addr)>,
    last_alert_ts: Option<f64>,
    last_dst_ip: Ipv4Addr,
    last_src_mac: [u8; 6],
}

/// Bounded per-source-IP sliding-window ICMP echo-request host-sweep tracker: counts DISTINCT
/// destination IPs (not ports — ICMP has none) one source has pinged within the window.
pub struct IcmpSweepTracker {
    cfg: IcmpSweepConfig,
    sources: HashMap<Ipv4Addr, IcmpSourceState>,
    order: VecDeque<Ipv4Addr>,
}
impl IcmpSweepTracker {
    pub fn new(cfg: IcmpSweepConfig) -> Self {
        IcmpSweepTracker { cfg, sources: HashMap::new(), order: VecDeque::new() }
    }

    fn evict_if_full(&mut self) {
        let cap = self.cfg.max_sources.max(1);
        while self.sources.len() >= cap {
            match self.order.pop_front() {
                Some(old) => {
                    self.sources.remove(&old);
                }
                None => break,
            }
        }
    }

    /// Feed one ICMP observation. `is_echo_request` must be true only for `icmp_type ==
    /// dpi::ICMP_ECHO_REQUEST` (the caller filters — mirrors `PortScanTracker::observe`'s
    /// `syn_only` caller-filters convention) — echo REPLIES and every other ICMP type must never
    /// count toward a sweep. Returns `Some(alert)` the instant `src_ip`'s distinct-dst-host count
    /// within the window first reaches `threshold`, then suppresses re-firing for `cooldown_secs`.
    pub fn observe(
        &mut self,
        now: f64,
        src_ip: Ipv4Addr,
        dst_ip: Ipv4Addr,
        is_echo_request: bool,
        src_mac: [u8; 6],
    ) -> Option<IcmpSweepAlert> {
        if !is_echo_request {
            return None;
        }
        if !self.sources.contains_key(&src_ip) {
            self.evict_if_full();
            self.order.push_back(src_ip);
            self.sources.insert(
                src_ip,
                IcmpSourceState { window: VecDeque::new(), last_alert_ts: None, last_dst_ip: dst_ip, last_src_mac: src_mac },
            );
        }
        let state = self.sources.get_mut(&src_ip).expect("just inserted above");
        state.window.push_back((now, dst_ip));
        state.last_dst_ip = dst_ip;
        state.last_src_mac = src_mac;

        let cutoff = now - self.cfg.window_secs;
        while state.window.front().is_some_and(|&(ts, _)| ts < cutoff) {
            state.window.pop_front();
        }

        let distinct: HashSet<Ipv4Addr> = state.window.iter().map(|&(_, ip)| ip).collect();
        if distinct.len() < self.cfg.threshold {
            return None;
        }
        if let Some(last) = state.last_alert_ts {
            if now - last < self.cfg.cooldown_secs {
                return None;
            }
        }
        state.last_alert_ts = Some(now);
        Some(IcmpSweepAlert {
            ts: now,
            src_ip,
            dst_ip: state.last_dst_ip,
            distinct_hosts: distinct.len(),
            src_mac: Some(state.last_src_mac),
        })
    }
}

// ---------------------------------------------------------------------------------------------
// 2026-07-07 low-and-slow coverage fix (ADR 0022 §Consequences names this the model's weakness):
// `PortScanTracker` above has a SHORT window (default 10s) + 50-distinct-port threshold. A
// scanner probing a few ports every 10s window over several MINUTES never crosses 50-in-10s and
// so completely evades it (confirmed live: `NAPSE_PORTSCAN_THRESHOLD=50,
// NAPSE_PORTSCAN_WINDOW_SECS=10, NAPSE_PORTSCAN_COOLDOWN_SECS=30`). `SlowScanTracker` closes this
// with a LONG sliding window (default 300s, `SLOWSCAN_WINDOW_SECS`) over the SAME distinct-dport
// accumulation the fast tracker gates on — catching exactly the trickle a 10s window misses.
//
// FP analysis (a 300s window is 30x longer than the fast tracker's and invites 30x the
// opportunity to accidentally accumulate unrelated ports — two guards, both load-bearing):
//
//   1. **Per-target scoping.** Distinct ports are counted PER (src_ip, dst_ip) — never globally
//      per source the way it might naively be done. Without this, a source that is simply a busy
//      client of the network (a NAT gateway, a laptop with many browser tabs, a monitoring
//      agent polling dozens of hosts) legitimately touches many DIFFERENT destination ports over
//      5 minutes purely because it talks to many DIFFERENT hosts (mail on 993, a web app on
//      8443, ssh-checks on 22, ...) — none of which is a scan. Scoping the count to "distinct
//      ports reached on ONE target host" means only a source that hammers a SINGLE host across
//      >=50 different ports over 5 minutes fires — which is the actual definition of a (slow)
//      port scan, and something no legitimate multi-host client does. `PortScanTargetState`
//      below is that per-(source,target) window; `PortScanSourceState`'s `targets` map holds one
//      per destination host this source has touched, itself bounded (`max_targets_per_source`,
//      same FIFO-eviction discipline `PortScanTracker::evict_if_full` already established) so a
//      source that legitimately talks to hundreds of hosts can't grow this source's memory
//      unboundedly either.
//   2. **Fast-scan dedup.** A source that already tripped the FAST tracker's rule 1000003 has
//      already been reported — 1000012 exists for the sources the fast tracker MISSES, not to
//      double-report the ones it catches (that would just be noise: every ordinary fast scan
//      also, trivially, crosses the slow tracker's lower bar within the same window). Wired via
//      `suppress_fast_scan`, called by `bin/napse-dpi.rs` every time `PortScanTracker::observe`
//      returns `Some` — see that binary's wiring for the exact call site.
//
// Same anti-spoof discipline as the fast tracker: carries the OBSERVED `src_mac` so a CONFIRMED
// slow-scanner (validated by the independent `confirm::HandshakeTracker`, exactly as the fast
// tracker's `confirmed` bit is decided) can be quarantined, while an unconfirmed one is Observed
// only — `bin/napse-dpi.rs` stamps `confirmed` at emission time, never this tracker itself.
// ---------------------------------------------------------------------------------------------

pub const SLOWSCAN_RULE_ID: u32 = 1_000_012;
pub const SLOWSCAN_RULE_MSG: &str = "NAPSE Slow Port Scan Detected";
pub const SLOWSCAN_CATEGORY: &str = "slow_port_scan";
/// Same technique as the fast tracker (`portscan::MITRE`) — Network Service Discovery — just
/// accumulated over a much longer window.
pub const SLOWSCAN_MITRE: &str = "T1046";

pub const DEFAULT_SLOWSCAN_THRESHOLD: usize = 50;
pub const DEFAULT_SLOWSCAN_WINDOW_SECS: f64 = 300.0;
pub const DEFAULT_SLOWSCAN_COOLDOWN_SECS: f64 = 300.0;
pub const DEFAULT_SLOWSCAN_MAX_SOURCES: usize = 4096;
/// Per-source cap on the number of distinct TARGET hosts tracked — bounds memory against a
/// source that legitimately (or maliciously, via an IP sweep) talks to very many hosts; oldest
/// target is evicted first, same discipline as source eviction.
pub const DEFAULT_SLOWSCAN_MAX_TARGETS_PER_SOURCE: usize = 256;

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct SlowScanConfig {
    /// Distinct destination ports reached on ONE target host within `window_secs` that trigger a
    /// slow-scan alert — see this section's FP analysis for why this is scoped per-target, not
    /// per-source globally.
    pub threshold: usize,
    /// Sliding-window size, seconds. Long by design (default 300s) — this is precisely what lets
    /// it catch the trickle the fast tracker's short window misses.
    pub window_secs: f64,
    pub cooldown_secs: f64,
    pub max_sources: usize,
    pub max_targets_per_source: usize,
}

impl Default for SlowScanConfig {
    fn default() -> Self {
        SlowScanConfig {
            threshold: DEFAULT_SLOWSCAN_THRESHOLD,
            window_secs: DEFAULT_SLOWSCAN_WINDOW_SECS,
            cooldown_secs: DEFAULT_SLOWSCAN_COOLDOWN_SECS,
            max_sources: DEFAULT_SLOWSCAN_MAX_SOURCES,
            max_targets_per_source: DEFAULT_SLOWSCAN_MAX_TARGETS_PER_SOURCE,
        }
    }
}

/// One emitted slow-scan alert — same shape/rendering convention as [`PortScanAlert`] (including
/// the `confirmed`-gated severity downgrade), plus a `proto` field since this tracker is fed by
/// both the TCP scan-probe path and (optionally) the UDP fan-out path in `bin/napse-dpi.rs`.
#[derive(Debug, Clone, PartialEq)]
pub struct SlowScanAlert {
    pub ts: f64,
    pub src_ip: Ipv4Addr,
    pub src_port: u16,
    /// The ONE target host this alert fired against (per-target scoping — see module doc).
    pub dst_ip: Ipv4Addr,
    pub dst_port: u16,
    pub distinct_ports: usize,
    pub src_mac: Option<[u8; 6]>,
    pub proto: &'static str,
}

impl SlowScanAlert {
    /// Same confidence formula as [`PortScanAlert::confidence`] — kept identical so a slow scan
    /// and a fast scan of the same size render comparably in the evidence graph.
    fn confidence(&self) -> f64 {
        (0.50 + self.distinct_ports as f64 * 0.005).min(0.95)
    }

    fn mac_str(&self) -> Option<String> {
        self.src_mac.map(|m| {
            format!("{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}", m[0], m[1], m[2], m[3], m[4], m[5])
        })
    }

    /// Render as one NAPSE event-stream JSON line — same field set/discipline as
    /// [`PortScanAlert::to_json`] (see its doc comment): `confirmed=false` renders
    /// `SEVERITY_UNCONFIRMED` (LOW) instead of `SEVERITY` (MEDIUM); detection is never suppressed,
    /// only its enforcement weight is.
    pub fn to_json(&self, confirmed: bool) -> String {
        let sev = if confirmed { SEVERITY } else { SEVERITY_UNCONFIRMED };
        let mac_field = match self.mac_str() {
            Some(m) => format!(r#","src_mac":"{m}""#),
            None => String::new(),
        };
        format!(
            concat!(
                r#"{{"ts":{ts:.3},"src_ip":"{src}","src_port":{sp},"#,
                r#""dst_ip":"{dst}","dst_port":{dp},"proto":"{proto}","#,
                r#""severity":{sev},"rule_id":{rid},"rule_msg":"{msg}","#,
                r#""mitre":"{mitre}","category":"{cat}","confidence":{conf:.4},"#,
                r#""confirmed":{confirmed}{mac_field}}}"#,
            ),
            ts = self.ts,
            src = self.src_ip,
            sp = self.src_port,
            dst = self.dst_ip,
            dp = self.dst_port,
            proto = self.proto,
            sev = sev,
            rid = SLOWSCAN_RULE_ID,
            msg = SLOWSCAN_RULE_MSG,
            mitre = SLOWSCAN_MITRE,
            cat = SLOWSCAN_CATEGORY,
            conf = self.confidence(),
            confirmed = confirmed,
            mac_field = mac_field,
        )
    }
}

/// Per-(source,target) sliding window of (ts, dst_port) pairs — the FP-guard scoping unit: a
/// source's distinct-port count is evaluated PER TARGET, never globally (see module doc).
struct SlowScanTargetState {
    window: VecDeque<(f64, u16)>,
}

struct SlowScanSourceState {
    /// One window per distinct target host this source has probed, bounded by
    /// `max_targets_per_source` (FIFO-evicted via `target_order`, same discipline as source
    /// eviction).
    targets: HashMap<Ipv4Addr, SlowScanTargetState>,
    target_order: VecDeque<Ipv4Addr>,
    last_alert_ts: Option<f64>,
    last_src_port: u16,
    last_src_mac: [u8; 6],
    /// Set by `suppress_fast_scan` when the FAST tracker (rule 1000003) has already fired for
    /// this source — while `Some(t)` with `t > now`, this source's slow-scan firing is
    /// suppressed (dedup: the fast alert already reported this scan).
    fast_suppressed_until: Option<f64>,
}

impl SlowScanSourceState {
    fn new(src_port: u16, src_mac: [u8; 6]) -> Self {
        SlowScanSourceState {
            targets: HashMap::new(),
            target_order: VecDeque::new(),
            last_alert_ts: None,
            last_src_port: src_port,
            last_src_mac: src_mac,
            fast_suppressed_until: None,
        }
    }
}

/// Bounded per-source, per-target-scoped, LONG-window port-fanout tracker — see this section's
/// module doc for the full rationale (evasion gap it closes + the two FP guards it applies).
pub struct SlowScanTracker {
    cfg: SlowScanConfig,
    sources: HashMap<Ipv4Addr, SlowScanSourceState>,
    order: VecDeque<Ipv4Addr>,
}

impl SlowScanTracker {
    pub fn new(cfg: SlowScanConfig) -> Self {
        SlowScanTracker { cfg, sources: HashMap::new(), order: VecDeque::new() }
    }

    fn evict_if_full(&mut self) {
        let cap = self.cfg.max_sources.max(1);
        while self.sources.len() >= cap {
            match self.order.pop_front() {
                Some(old) => {
                    self.sources.remove(&old);
                }
                None => break,
            }
        }
    }

    fn ensure_source(&mut self, src_ip: Ipv4Addr, src_port: u16, src_mac: [u8; 6]) {
        if !self.sources.contains_key(&src_ip) {
            self.evict_if_full();
            self.order.push_back(src_ip);
            self.sources.insert(src_ip, SlowScanSourceState::new(src_port, src_mac));
        }
    }

    /// Mark `src_ip` as already covered by the FAST tracker's rule 1000003 as of `now` —
    /// suppresses 1000012 for this source for `window_secs` (the long tracker exists for what the
    /// fast one MISSES, not to double-report what it already caught). `bin/napse-dpi.rs` calls
    /// this every time `PortScanTracker::observe` returns `Some`.
    pub fn suppress_fast_scan(&mut self, src_ip: Ipv4Addr, now: f64) {
        self.ensure_source(src_ip, 0, [0u8; 6]);
        let window_secs = self.cfg.window_secs;
        if let Some(state) = self.sources.get_mut(&src_ip) {
            state.fast_suppressed_until = Some(now + window_secs);
        }
    }

    /// Feed one scan-probe observation. `is_probe` must be true only for a TCP SYN/FIN/NULL/XMAS
    /// scan-probe shape (`dpi::TcpObs::scan_probe_kind`) or (per-datagram, since UDP has no
    /// handshake concept) a UDP observation — `proto` is cosmetic (rendered in the alert JSON)
    /// and does not affect scoring. Returns `Some(alert)` the instant `src_ip`'s distinct-dport
    /// count reached on THIS ONE `dst_ip`, within the window, first crosses `threshold`, then
    /// suppresses re-firing for that (source) for `cooldown_secs`.
    #[allow(clippy::too_many_arguments)]
    pub fn observe(
        &mut self,
        now: f64,
        src_ip: Ipv4Addr,
        src_port: u16,
        dst_ip: Ipv4Addr,
        dst_port: u16,
        is_probe: bool,
        src_mac: [u8; 6],
        proto: &'static str,
    ) -> Option<SlowScanAlert> {
        if !is_probe {
            return None;
        }
        self.ensure_source(src_ip, src_port, src_mac);
        let cfg = self.cfg;
        let state = self.sources.get_mut(&src_ip).expect("just ensured above");
        state.last_src_port = src_port;
        state.last_src_mac = src_mac;

        let suppressed = state.fast_suppressed_until.is_some_and(|until| now < until);

        // ---- record into the per-(source,target) window (FP guard #1 — see module doc) --------
        if !state.targets.contains_key(&dst_ip) {
            let cap = cfg.max_targets_per_source.max(1);
            while state.targets.len() >= cap {
                match state.target_order.pop_front() {
                    Some(old) => {
                        state.targets.remove(&old);
                    }
                    None => break,
                }
            }
            state.target_order.push_back(dst_ip);
            state.targets.insert(dst_ip, SlowScanTargetState { window: VecDeque::new() });
        }
        let target = state.targets.get_mut(&dst_ip).expect("just inserted above");
        target.window.push_back((now, dst_port));
        let cutoff = now - cfg.window_secs;
        while target.window.front().is_some_and(|&(ts, _)| ts < cutoff) {
            target.window.pop_front();
        }
        let distinct: HashSet<u16> = target.window.iter().map(|&(_, p)| p).collect();
        let distinct_count = distinct.len();

        // FP guard #2 (dedup — see module doc): still RECORD while suppressed (so the window
        // stays warm for once suppression lapses), but never FIRE while suppressed.
        if suppressed || distinct_count < cfg.threshold {
            return None;
        }
        if let Some(last) = state.last_alert_ts {
            if now - last < cfg.cooldown_secs {
                return None;
            }
        }
        state.last_alert_ts = Some(now);
        Some(SlowScanAlert {
            ts: now,
            src_ip,
            src_port: state.last_src_port,
            dst_ip,
            dst_port,
            distinct_ports: distinct_count,
            src_mac: Some(state.last_src_mac),
            proto,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(threshold: usize, window_secs: f64, cooldown_secs: f64) -> PortScanConfig {
        PortScanConfig { threshold, window_secs, cooldown_secs, max_sources: 4096 }
    }

    const MAC: [u8; 6] = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];

    // (a) 60 distinct SYN dports from one src within the window → fires exactly once.
    #[test]
    fn fires_exactly_once_on_sixty_distinct_ports() {
        let mut t = PortScanTracker::new(cfg(50, 10.0, 30.0));
        let src = Ipv4Addr::new(10, 0, 0, 50);
        let dst = Ipv4Addr::new(10, 0, 0, 1);
        let mut fires = 0;
        for i in 0..60u16 {
            if t.observe(100.0 + i as f64 * 0.01, src, 40000, dst, 1000 + i, true, MAC).is_some() {
                fires += 1;
            }
        }
        assert_eq!(fires, 1, "one scan of 60 distinct ports must yield exactly one alert");
    }

    // (b) established/ACK traffic (syn_only=false) never counts, however many ports.
    #[test]
    fn non_syn_only_traffic_never_counts() {
        let mut t = PortScanTracker::new(cfg(50, 10.0, 30.0));
        let src = Ipv4Addr::new(10, 0, 0, 51);
        let dst = Ipv4Addr::new(10, 0, 0, 1);
        for i in 0..200u16 {
            assert!(t.observe(100.0 + i as f64 * 0.001, src, 40000, dst, 1000 + i, false, MAC).is_none());
        }
    }

    // (c) fewer than threshold distinct ports → no fire.
    #[test]
    fn below_threshold_never_fires() {
        let mut t = PortScanTracker::new(cfg(50, 10.0, 30.0));
        let src = Ipv4Addr::new(10, 0, 0, 52);
        let dst = Ipv4Addr::new(10, 0, 0, 1);
        for i in 0..49u16 {
            assert!(t.observe(100.0 + i as f64 * 0.01, src, 40000, dst, 1000 + i, true, MAC).is_none());
        }
    }

    // (d) same src re-scanning after the cooldown → fires again (but not during cooldown).
    #[test]
    fn refires_after_cooldown_but_not_during_it() {
        let mut t = PortScanTracker::new(cfg(50, 10.0, 5.0));
        let src = Ipv4Addr::new(10, 0, 0, 53);
        let dst = Ipv4Addr::new(10, 0, 0, 1);

        let mut first_fire = false;
        for i in 0..50u16 {
            if t.observe(100.0 + i as f64 * 0.01, src, 40000, dst, 2000 + i, true, MAC).is_some() {
                first_fire = true;
            }
        }
        assert!(first_fire, "first scan must fire");

        // Still inside the 5s cooldown — must not refire even while continuing to scan new ports.
        let mut refired_in_cooldown = false;
        for i in 0..50u16 {
            if t.observe(100.51 + i as f64 * 0.01, src, 40000, dst, 3000 + i, true, MAC).is_some() {
                refired_in_cooldown = true;
            }
        }
        assert!(!refired_in_cooldown, "must not refire inside the cooldown window");

        // 20s later: cooldown elapsed AND the old window (10s) has aged out — a fresh scan fires.
        let mut second_fire = false;
        for i in 0..50u16 {
            if t.observe(120.0 + i as f64 * 0.01, src, 40000, dst, 4000 + i, true, MAC).is_some() {
                second_fire = true;
            }
        }
        assert!(second_fire, "re-scan after the cooldown must fire again");
    }

    // (e) window eviction: ports spread beyond WINDOW_SECS don't accumulate into one scan.
    #[test]
    fn window_eviction_prevents_accumulation_across_gaps() {
        let mut t = PortScanTracker::new(cfg(50, 5.0, 30.0));
        let src = Ipv4Addr::new(10, 0, 0, 54);
        let dst = Ipv4Addr::new(10, 0, 0, 1);

        // 30 distinct ports at t=0..0.29
        for i in 0..30u16 {
            assert!(t.observe(i as f64 * 0.01, src, 40000, dst, 5000 + i, true, MAC).is_none());
        }
        // 30 MORE distinct ports far beyond the 5s window — the first 30 must have aged out, so
        // this batch alone (30 < 50) must not fire even though 60 were seen "ever".
        let mut fired = false;
        for i in 0..30u16 {
            if t.observe(100.0 + i as f64 * 0.01, src, 40000, dst, 6000 + i, true, MAC).is_some() {
                fired = true;
            }
        }
        assert!(!fired, "ports spread across a gap larger than the window must not accumulate");
    }

    #[test]
    fn max_sources_bounds_memory() {
        let mut t = PortScanTracker::new(PortScanConfig {
            threshold: 50,
            window_secs: 10.0,
            cooldown_secs: 30.0,
            max_sources: 4,
        });
        let dst = Ipv4Addr::new(10, 0, 0, 1);
        for i in 0..100u8 {
            t.observe(1000.0 + i as f64, Ipv4Addr::new(192, 168, 1, i), 1, dst, 22, true, MAC);
        }
        assert!(t.sources.len() <= 4, "tracked sources must stay bounded at max_sources");
    }

    #[test]
    fn observe_captures_the_last_observed_src_mac() {
        let mut t = PortScanTracker::new(cfg(3, 10.0, 30.0));
        let src = Ipv4Addr::new(10, 0, 0, 60);
        let dst = Ipv4Addr::new(10, 0, 0, 1);
        let other_mac = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66];
        t.observe(100.0, src, 1, dst, 1000, true, MAC);
        t.observe(100.1, src, 1, dst, 1001, true, other_mac);
        let alert = t.observe(100.2, src, 1, dst, 1002, true, other_mac).expect("threshold=3 crossed");
        assert_eq!(alert.src_mac, Some(other_mac), "alert carries the MOST RECENTLY observed mac");
    }

    #[test]
    fn alert_json_matches_rule_1000003_schema_when_confirmed() {
        let a = PortScanAlert {
            ts: 1782900000.123,
            src_ip: Ipv4Addr::new(10, 66, 0, 20),
            src_port: 51000,
            dst_ip: Ipv4Addr::new(10, 66, 0, 1),
            dst_port: 1049,
            distinct_ports: 50,
            src_mac: Some(MAC),
        };
        let j = a.to_json(true);
        assert!(j.contains(r#""rule_id":1000003"#));
        assert!(j.contains(r#""rule_msg":"NAPSE Port Scan Detected""#));
        assert!(j.contains(r#""category":"port_scan""#));
        assert!(j.contains(r#""mitre":"T1046""#));
        assert!(j.contains(r#""proto":"tcp""#));
        assert!(j.contains(r#""severity":3"#), "a CONFIRMED scan renders MEDIUM severity");
        assert!(j.contains(r#""confidence":0.7500"#));
        assert!(j.contains(r#""src_ip":"10.66.0.20""#));
        assert!(j.contains(r#""src_port":51000"#));
        assert!(j.contains(r#""dst_ip":"10.66.0.1""#));
        assert!(j.contains(r#""dst_port":1049"#));
        assert!(j.contains(r#""confirmed":true"#));
        assert!(j.contains(r#""src_mac":"aa:bb:cc:dd:ee:ff""#));
        // must be a single valid JSON line — round-trip through serde_json to be sure.
        let v: serde_json::Value = serde_json::from_str(&j).expect("valid json");
        assert_eq!(v["rule_id"], 1000003);
    }

    // The 2026-07-05 fix's core rendering proof: an UNCONFIRMED alert downgrades to LOW severity
    // and self-reports `confirmed:false` — detection is kept, enforcement weight is not.
    #[test]
    fn alert_json_downgrades_severity_when_unconfirmed() {
        let a = PortScanAlert {
            ts: 1000.0,
            src_ip: Ipv4Addr::new(203, 0, 113, 7),
            src_port: 51000,
            dst_ip: Ipv4Addr::new(10, 66, 0, 1),
            dst_port: 22,
            distinct_ports: 50,
            src_mac: Some(MAC),
        };
        let j = a.to_json(false);
        assert!(j.contains(r#""severity":4"#), "an UNCONFIRMED scan renders LOW severity, not MEDIUM");
        assert!(j.contains(r#""confirmed":false"#));
        assert!(j.contains(r#""rule_id":1000003"#), "still the SAME rule — detection is never suppressed");
        let v: serde_json::Value = serde_json::from_str(&j).expect("valid json");
        assert_eq!(v["confirmed"], false);
    }

    #[test]
    fn alert_json_omits_mac_field_when_none() {
        let a = PortScanAlert {
            ts: 1000.0,
            src_ip: Ipv4Addr::new(203, 0, 113, 7),
            src_port: 1,
            dst_ip: Ipv4Addr::new(10, 66, 0, 1),
            dst_port: 22,
            distinct_ports: 50,
            src_mac: None,
        };
        let j = a.to_json(true);
        assert!(!j.contains("src_mac"));
        let _: serde_json::Value = serde_json::from_str(&j).expect("still valid json without the mac field");
    }

    // ---- 2026-07-05 fan-out coverage fix (EDR #2): UdpScanTracker ------------------------------

    fn udp_cfg(threshold: usize, window_secs: f64, cooldown_secs: f64) -> UdpScanConfig {
        UdpScanConfig { threshold, window_secs, cooldown_secs, max_sources: 4096 }
    }

    #[test]
    fn udp_scan_fires_on_distinct_dst_port_fanout() {
        let mut t = UdpScanTracker::new(udp_cfg(50, 10.0, 30.0));
        let src = Ipv4Addr::new(10, 0, 0, 70);
        let dst = Ipv4Addr::new(10, 0, 0, 1);
        let mut fires = 0;
        for i in 0..60u16 {
            if t.observe(100.0 + i as f64 * 0.01, src, 40000, dst, 1000 + i, MAC).is_some() {
                fires += 1;
            }
        }
        assert_eq!(fires, 1, "one UDP scan of 60 distinct ports must yield exactly one alert");
    }

    #[test]
    fn udp_scan_below_threshold_never_fires() {
        let mut t = UdpScanTracker::new(udp_cfg(50, 10.0, 30.0));
        let src = Ipv4Addr::new(10, 0, 0, 71);
        let dst = Ipv4Addr::new(10, 0, 0, 1);
        for i in 0..30u16 {
            assert!(t.observe(100.0 + i as f64 * 0.01, src, 40000, dst, 2000 + i, MAC).is_none());
        }
    }

    #[test]
    fn udp_scan_respects_cooldown() {
        let mut t = UdpScanTracker::new(udp_cfg(5, 10.0, 100.0));
        let src = Ipv4Addr::new(10, 0, 0, 72);
        let dst = Ipv4Addr::new(10, 0, 0, 1);
        let mut fires = 0;
        for i in 0..20u16 {
            if t.observe(100.0 + i as f64 * 0.01, src, 40000, dst, 3000 + i, MAC).is_some() {
                fires += 1;
            }
        }
        assert_eq!(fires, 1, "one burst yields one alert while cooling down");
    }

    #[test]
    fn udp_scan_alert_json_matches_the_new_rule_id_and_category() {
        let a = UdpScanAlert {
            ts: 1000.0,
            src_ip: Ipv4Addr::new(203, 0, 113, 7),
            src_port: 40000,
            dst_ip: Ipv4Addr::new(10, 66, 0, 1),
            dst_port: 33434,
            distinct_ports: 50,
            src_mac: Some(MAC),
        };
        let j = a.to_json();
        let v: serde_json::Value = serde_json::from_str(&j).expect("valid json");
        assert_eq!(v["rule_id"], 1_000_014); // moved from 1_000_010 (collided with wasm Path Traversal)
        assert_eq!(v["category"], "udp_scan");
        assert_eq!(v["proto"], "udp");
        assert_eq!(v["mitre"], "T1046");
        assert_eq!(v["src_mac"], "aa:bb:cc:dd:ee:ff");
    }

    #[test]
    fn udp_scan_max_sources_bounds_memory() {
        let mut t = UdpScanTracker::new(UdpScanConfig { threshold: 50, window_secs: 10.0, cooldown_secs: 30.0, max_sources: 4 });
        let dst = Ipv4Addr::new(10, 0, 0, 1);
        for i in 0..100u8 {
            t.observe(1000.0 + i as f64, Ipv4Addr::new(192, 168, 2, i), 1, dst, 53, MAC);
        }
        assert!(t.sources.len() <= 4, "tracked sources must stay bounded at max_sources");
    }

    // ---- 2026-07-05 fan-out coverage fix (EDR #2): IcmpSweepTracker ----------------------------

    fn icmp_cfg(threshold: usize, window_secs: f64, cooldown_secs: f64) -> IcmpSweepConfig {
        IcmpSweepConfig { threshold, window_secs, cooldown_secs, max_sources: 4096 }
    }

    #[test]
    fn icmp_sweep_fires_on_distinct_host_fanout() {
        let mut t = IcmpSweepTracker::new(icmp_cfg(20, 10.0, 30.0));
        let src = Ipv4Addr::new(10, 0, 0, 80);
        let mut fires = 0;
        for i in 0..30u8 {
            let dst = Ipv4Addr::new(10, 0, 0, i);
            if t.observe(100.0 + i as f64 * 0.01, src, dst, true, MAC).is_some() {
                fires += 1;
            }
        }
        assert_eq!(fires, 1, "one sweep of 30 distinct hosts must yield exactly one alert");
    }

    #[test]
    fn icmp_sweep_ignores_non_echo_request_traffic() {
        // Echo REPLIES (is_echo_request=false) must never count, however many distinct hosts.
        let mut t = IcmpSweepTracker::new(icmp_cfg(5, 10.0, 30.0));
        let src = Ipv4Addr::new(10, 0, 0, 81);
        for i in 0..50u8 {
            let dst = Ipv4Addr::new(10, 0, 0, i);
            assert!(t.observe(100.0 + i as f64 * 0.01, src, dst, false, MAC).is_none());
        }
    }

    #[test]
    fn icmp_sweep_below_threshold_never_fires() {
        let mut t = IcmpSweepTracker::new(icmp_cfg(20, 10.0, 30.0));
        let src = Ipv4Addr::new(10, 0, 0, 82);
        for i in 0..15u8 {
            let dst = Ipv4Addr::new(10, 0, 0, i);
            assert!(t.observe(100.0 + i as f64 * 0.01, src, dst, true, MAC).is_none());
        }
    }

    #[test]
    fn icmp_sweep_alert_json_matches_the_new_rule_id_and_category() {
        let a = IcmpSweepAlert {
            ts: 1000.0,
            src_ip: Ipv4Addr::new(203, 0, 113, 8),
            dst_ip: Ipv4Addr::new(10, 66, 0, 20),
            distinct_hosts: 25,
            src_mac: Some(MAC),
        };
        let j = a.to_json();
        let v: serde_json::Value = serde_json::from_str(&j).expect("valid json");
        assert_eq!(v["rule_id"], 1_000_013); // moved from 1_000_011 (collided with wasm DNS-non-standard-port)
        assert_eq!(v["category"], "icmp_sweep");
        assert_eq!(v["proto"], "icmp");
        assert_eq!(v["mitre"], "T1018");
    }

    #[test]
    fn icmp_sweep_max_sources_bounds_memory() {
        let mut t = IcmpSweepTracker::new(IcmpSweepConfig { threshold: 20, window_secs: 10.0, cooldown_secs: 30.0, max_sources: 4 });
        for i in 0..100u8 {
            let src = Ipv4Addr::new(192, 168, 3, i);
            let dst = Ipv4Addr::new(10, 0, 0, 1);
            t.observe(1000.0 + i as f64, src, dst, true, MAC);
        }
        assert!(t.sources.len() <= 4, "tracked sources must stay bounded at max_sources");
    }

    // ---- rule_id collision guard: the new bands must not collide with the existing one ----------

    #[test]
    fn new_rule_ids_do_not_collide_with_existing_ones_in_this_module() {
        assert_ne!(UDP_SCAN_RULE_ID, RULE_ID);
        assert_ne!(ICMP_SWEEP_RULE_ID, RULE_ID);
        assert_ne!(UDP_SCAN_RULE_ID, ICMP_SWEEP_RULE_ID);
        assert_ne!(SLOWSCAN_RULE_ID, RULE_ID);
        assert_ne!(SLOWSCAN_RULE_ID, UDP_SCAN_RULE_ID);
        assert_ne!(SLOWSCAN_RULE_ID, ICMP_SWEEP_RULE_ID);
    }

    // 2026-07-07: cross-checked against the wasm engine's OWN rule catalogue (`modules/napse`
    // 1_000_001..=1_000_025, including 1_000_010 "Path Traversal" and 1_000_011 "DNS Non-Standard
    // Port") — this module's collision guard above only checked itself, which is exactly how
    // `UDP_SCAN_RULE_ID = 1_000_010` collided with the wasm engine undetected. Pin the full known
    // inventory here so a future addition anywhere in this file trips this test instead of
    // shipping a silent collision again. `RULE_ID` (1_000_003) is EXCLUDED deliberately — see this
    // module's top-level doc comment: it's not a collision, it's an intentional mirror (the same
    // scan must render under the SAME rule_id whichever sensor, packet-layer or wasm, caught it).
    #[test]
    fn rule_ids_do_not_collide_with_the_wasm_engines_catalogue() {
        const WASM_ENGINE_RULE_IDS: &[u32] = &[
            1_000_001, 1_000_002, 1_000_004, 1_000_005, 1_000_007, 1_000_008, 1_000_009,
            1_000_010, 1_000_011, 1_000_021, 1_000_025,
        ];
        let this_module_rule_ids = [UDP_SCAN_RULE_ID, ICMP_SWEEP_RULE_ID, SLOWSCAN_RULE_ID];
        for mine in this_module_rule_ids {
            assert!(
                !WASM_ENGINE_RULE_IDS.contains(&mine),
                "rule_id {mine} collides with the wasm engine's catalogue (modules/napse)"
            );
        }
    }

    // ---- 2026-07-07 low-and-slow coverage fix: SlowScanTracker ----------------------------------

    fn slow_cfg(threshold: usize, window_secs: f64, cooldown_secs: f64) -> SlowScanConfig {
        SlowScanConfig { threshold, window_secs, cooldown_secs, max_sources: 4096, max_targets_per_source: 256 }
    }

    /// The core gap-fix proof: a scanner probing a NEW distinct port roughly every 3.4s (60 ports
    /// over ~200s) never crosses the FAST tracker's 50-in-10s bar (at most ~3 distinct ports land
    /// in any rolling 10s slice) — completely evading `PortScanTracker` — but the SAME sequence,
    /// fed to `SlowScanTracker`'s 300s window, accumulates past its 50-distinct-port threshold and
    /// fires 1000012.
    #[test]
    fn slow_scanner_evades_fast_tracker_but_fires_slowscan() {
        let mut fast = PortScanTracker::new(cfg(50, 10.0, 30.0));
        let mut slow = SlowScanTracker::new(slow_cfg(50, 300.0, 300.0));
        let src = Ipv4Addr::new(198, 51, 100, 10);
        let dst = Ipv4Addr::new(10, 0, 0, 1);

        let mut fast_fired = false;
        let mut slow_fired = false;
        for i in 0..60u16 {
            let ts = i as f64 * 3.4; // spans ~0..200.6s, one distinct port every 3.4s
            let port = 1000 + i;
            if fast.observe(ts, src, 40000, dst, port, true, MAC).is_some() {
                fast_fired = true;
                slow.suppress_fast_scan(src, ts);
            }
            if slow.observe(ts, src, 40000, dst, port, true, MAC, "tcp").is_some() {
                slow_fired = true;
            }
        }
        assert!(!fast_fired, "a trickle of ~1 new port/3.4s must never cross the fast tracker's 50-in-10s bar");
        assert!(slow_fired, "the same trickle, accumulated over the long window, must cross the slow tracker's bar");
    }

    /// The dedup guard: a FAST scan (which also, trivially, crosses the slow tracker's lower bar
    /// within the same window) must fire 1000003 exactly once and must NOT also spam 1000012 for
    /// the same source — 1000012 exists for what the fast tracker misses, not to double-report
    /// what it already caught.
    #[test]
    fn fast_scanner_fires_1000003_and_is_suppressed_from_slowscan() {
        let mut fast = PortScanTracker::new(cfg(50, 10.0, 30.0));
        let mut slow = SlowScanTracker::new(slow_cfg(50, 300.0, 300.0));
        let src = Ipv4Addr::new(198, 51, 100, 11);
        let dst = Ipv4Addr::new(10, 0, 0, 1);

        let mut fast_fired = false;
        let mut slow_fired = false;
        for i in 0..60u16 {
            let ts = 100.0 + i as f64 * 0.01; // a fast burst, well within one 10s window
            let port = 2000 + i;
            if fast.observe(ts, src, 40000, dst, port, true, MAC).is_some() {
                fast_fired = true;
                slow.suppress_fast_scan(src, ts);
            }
            if slow.observe(ts, src, 40000, dst, port, true, MAC, "tcp").is_some() {
                slow_fired = true;
            }
        }
        assert!(fast_fired, "the fast burst must still fire 1000003");
        assert!(!slow_fired, "a source already caught by the fast tracker must not also fire 1000012");
    }

    /// FP guard (a): a legit client making many REPEAT connections to one service, on only a
    /// handful of distinct ports, must never fire however long it keeps talking.
    #[test]
    fn legit_client_few_ports_on_one_host_never_fires_slowscan() {
        let mut slow = SlowScanTracker::new(slow_cfg(50, 300.0, 300.0));
        let src = Ipv4Addr::new(10, 0, 0, 200);
        let dst = Ipv4Addr::new(10, 0, 0, 1);
        // 200 connections over 250s, but only ever to 3 distinct ports (a real client's repeat
        // traffic pattern to one multi-port service).
        for i in 0..200u16 {
            let ts = i as f64 * 1.25;
            let port = 443 + (i % 3); // only 443/444/445 ever used
            assert!(slow.observe(ts, src, 40000, dst, port, true, MAC, "tcp").is_none());
        }
    }

    /// FP guard (b) — the harder, load-bearing case: a source that legitimately talks to MANY
    /// DIFFERENT hosts (a NAT gateway, a busy client, a monitoring agent), each on only a
    /// handful of ports, must NOT accumulate into a false slow-scan just because the GLOBAL
    /// distinct-port count across all those hosts happens to exceed the threshold. This is
    /// exactly why counting is scoped per (source, target) rather than globally per source.
    #[test]
    fn legit_client_touching_many_hosts_with_few_ports_each_never_fires_slowscan() {
        let mut slow = SlowScanTracker::new(slow_cfg(50, 300.0, 300.0));
        let src = Ipv4Addr::new(10, 0, 0, 201);
        // 100 different destination hosts, each hit on the SAME 3 ports (80/443/22) — 100*3 = 300
        // distinct (host,port) pairs and 3 GLOBAL distinct ports, but NEVER more than 3 distinct
        // ports against any ONE host.
        for h in 0..100u8 {
            let dst = Ipv4Addr::new(10, 1, 0, h);
            for (i, port) in [80u16, 443, 22].into_iter().enumerate() {
                let ts = (h as f64) * 2.0 + (i as f64) * 0.1;
                assert!(slow.observe(ts, src, 40000, dst, port, true, MAC, "tcp").is_none());
            }
        }
    }

    /// LRU eviction bounds memory on the SOURCE dimension exactly like `PortScanTracker`'s.
    #[test]
    fn slowscan_max_sources_bounds_memory() {
        let mut slow = SlowScanTracker::new(SlowScanConfig {
            threshold: 50,
            window_secs: 300.0,
            cooldown_secs: 300.0,
            max_sources: 4,
            max_targets_per_source: 256,
        });
        let dst = Ipv4Addr::new(10, 0, 0, 1);
        for i in 0..100u8 {
            slow.observe(1000.0 + i as f64, Ipv4Addr::new(192, 168, 4, i), 1, dst, 22, true, MAC, "tcp");
        }
        assert!(slow.sources.len() <= 4, "tracked sources must stay bounded at max_sources");
    }

    /// LRU eviction ALSO bounds memory on the per-source TARGET dimension — a source that
    /// legitimately (or via an IP sweep) touches very many hosts must not grow unboundedly.
    #[test]
    fn slowscan_max_targets_per_source_bounds_memory() {
        let mut slow = SlowScanTracker::new(SlowScanConfig {
            threshold: 50,
            window_secs: 300.0,
            cooldown_secs: 300.0,
            max_sources: 4096,
            max_targets_per_source: 4,
        });
        let src = Ipv4Addr::new(10, 0, 0, 210);
        for h in 0..100u8 {
            let dst = Ipv4Addr::new(10, 2, 0, h);
            slow.observe(1000.0 + h as f64, src, 1, dst, 22, true, MAC, "tcp");
        }
        let state = slow.sources.get(&src).expect("source tracked");
        assert!(state.targets.len() <= 4, "tracked targets-per-source must stay bounded at max_targets_per_source");
    }

    /// Confirmed-vs-unconfirmed carried through exactly like the fast tracker: a CONFIRMED
    /// slow-scan renders MEDIUM severity, an UNCONFIRMED one renders LOW — detection is never
    /// suppressed, only the enforcement weight.
    #[test]
    fn slowscan_alert_json_downgrades_severity_when_unconfirmed_and_carries_mac() {
        let a = SlowScanAlert {
            ts: 1782900000.0,
            src_ip: Ipv4Addr::new(203, 0, 113, 20),
            src_port: 51000,
            dst_ip: Ipv4Addr::new(10, 66, 0, 1),
            dst_port: 1049,
            distinct_ports: 55,
            src_mac: Some(MAC),
            proto: "tcp",
        };
        let confirmed = a.to_json(true);
        let unconfirmed = a.to_json(false);

        let vc: serde_json::Value = serde_json::from_str(&confirmed).expect("valid json");
        assert_eq!(vc["rule_id"], 1_000_012);
        assert_eq!(vc["category"], "slow_port_scan");
        assert_eq!(vc["mitre"], "T1046");
        assert_eq!(vc["proto"], "tcp");
        assert_eq!(vc["severity"], 3, "confirmed slow scan renders MEDIUM severity");
        assert_eq!(vc["confirmed"], true);
        assert_eq!(vc["src_mac"], "aa:bb:cc:dd:ee:ff");

        let vu: serde_json::Value = serde_json::from_str(&unconfirmed).expect("valid json");
        assert_eq!(vu["severity"], 4, "unconfirmed slow scan renders LOW severity");
        assert_eq!(vu["confirmed"], false);
        assert_eq!(vu["rule_id"], 1_000_012, "still the same rule — detection is never suppressed");
    }
}
