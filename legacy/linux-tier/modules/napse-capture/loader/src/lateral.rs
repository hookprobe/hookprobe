//! East-west lateral-movement detector (T1021 — Remote Services). The reserved-but-unused `T1021`
//! comment in `crates/hookprobe-evidence/src/host_edr.rs` names this as an explicit, acknowledged
//! gap: host-EDR sees exec/file events on ONE machine and cannot see cross-device movement at all;
//! the network layer's `T1021`/`lateral_movement` signal is host_edr's documented substitute — this
//! module is that signal.
//!
//! Once inside a network, an attacker (or self-propagating malware — a worm, ransomware pivoting
//! before encrypting) moves host-to-host over administrative protocols: SMB (445, PsExec/lateral
//! file-copy), RDP (3389), WinRM (5985/5986, PowerShell remoting), SSH (22), VNC (5900). The tell
//! is not any ONE of these connections (a normal client legitimately reaches ITS one file server
//! or jump host over exactly one of these ports all day) but a SINGLE internal source reaching MANY
//! DISTINCT internal peers over these ports in a short window — a sweep, not routine use.
//!
//! `LateralMovementTracker` counts, per source, the distinct INTERNAL destination IPs reached on
//! any tracked lateral-movement port within a (short — sweeps are fast) sliding window.
//!
//! ## FP guards
//!
//! 1. **INTERNAL → INTERNAL only.** Both `src_ip` and `dst_ip` must be RFC1918. A source's SSH
//!    session out to a public jump host, or a public client RDP-ing into one internal host, are
//!    outside this detector's scope entirely (checked first, before any state is touched) — this
//!    is deliberately an EAST-WEST-only signal, not "any SSH/RDP/SMB traffic".
//! 2. **Distinct-PEER threshold, not distinct-CONNECTION threshold.** A normal client reaching its
//!    ONE file server or ONE jump host — however many times, however many sessions — touches
//!    exactly one distinct peer and can never cross `threshold` (default
//!    [`DEFAULT_LATERAL_THRESHOLD`] = 5 distinct internal peers). Only a source that fans out
//!    across multiple DIFFERENT internal machines on these ports fires.
//! 3. **Short window** (default [`DEFAULT_LATERAL_WINDOW_SECS`] = 300s) — a real lateral-movement
//!    sweep (automated or manual, during an active intrusion) happens over minutes, not days; a
//!    short window means a host that legitimately touches many peers spread out over a long period
//!    (e.g. an IT admin doing routine maintenance across the week) does not accumulate into a false
//!    positive the way an unbounded/very-long window would.
//! 4. Self-connections (`src_ip == dst_ip`, e.g. a loopback-routed test) never count.
//!
//! Same anti-spoof discipline as every other tracker in this crate: carries the OBSERVED `src_mac`
//! so a CONFIRMED lateral-mover (validated by the independent `confirm::HandshakeTracker` — real
//! lateral movement establishes real, completed sessions, so confirmation is the expected case) can
//! be composed into enforcement, while an unconfirmed one renders at lower severity.
//!
//! Fed from the TCP SYN-only ("real new connection attempt") observation stream in
//! `bin/napse-dpi.rs` — bounded LRU memory exactly like every other tracker in this crate.

use std::collections::{HashMap, HashSet, VecDeque};
use std::net::Ipv4Addr;

/// Fresh rule_id — see `beacon::BEACON_RULE_ID`'s doc comment for the full workspace-wide
/// collision check; this module takes the adjacent `1_000_041`.
pub const LATERAL_RULE_ID: u32 = 1_000_041;
pub const LATERAL_RULE_MSG: &str = "NAPSE Lateral Movement Detected";
/// Matches the category name `crates/hookprobe-evidence/src/host_edr.rs`'s doc comment and the
/// evidence-graph ingest tests already use for this exact concept (`"lateral_movement"`,
/// `"mitre":"T1021"`) — so this detector's alerts correlate under the SAME category/technique the
/// rest of the workspace already expects for lateral movement, not a newly invented name.
pub const LATERAL_CATEGORY: &str = "lateral_movement";
pub const LATERAL_MITRE: &str = "T1021";

/// Suricata severity convention (matches every other rule_id band in this workspace):
/// 1=CRITICAL 2=HIGH 3=MEDIUM 4=LOW 5=INFO. Fanning out across multiple internal admin-port peers
/// is a strong, late-kill-chain signal — HIGH when confirmed, MEDIUM when not (never suppressed,
/// only downgraded).
pub const LATERAL_SEVERITY_CONFIRMED: u8 = 2;
pub const LATERAL_SEVERITY_UNCONFIRMED: u8 = 3;

/// Administrative / remote-access ports lateral movement rides — SMB, RDP, WinRM (both the HTTP
/// and HTTPS listener ports), SSH, VNC.
pub const LATERAL_PORTS: &[u16] = &[22, 445, 3389, 5900, 5985, 5986];

pub const DEFAULT_LATERAL_THRESHOLD: usize = 5;
pub const DEFAULT_LATERAL_WINDOW_SECS: f64 = 300.0;
pub const DEFAULT_LATERAL_COOLDOWN_SECS: f64 = 300.0;
pub const DEFAULT_LATERAL_MAX_SOURCES: usize = 4096;

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct LateralConfig {
    /// Distinct internal peers reached (on any tracked port) within `window_secs` that trigger an
    /// alert.
    pub threshold: usize,
    pub window_secs: f64,
    pub cooldown_secs: f64,
    pub max_sources: usize,
}

impl Default for LateralConfig {
    fn default() -> Self {
        LateralConfig {
            threshold: DEFAULT_LATERAL_THRESHOLD,
            window_secs: DEFAULT_LATERAL_WINDOW_SECS,
            cooldown_secs: DEFAULT_LATERAL_COOLDOWN_SECS,
            max_sources: DEFAULT_LATERAL_MAX_SOURCES,
        }
    }
}

/// Check if an IPv4 address is RFC1918 private space (10/8, 172.16/12, 192.168/16) — mirrors
/// `napse::is_private_ip`'s semantics (including treating 127/8 as private) but operates directly
/// on an [`Ipv4Addr`], avoiding this crate's packet-layer trackers having to round-trip through a
/// string the way the wasm engine's flow-record-based version does.
pub fn is_private_ipv4(ip: Ipv4Addr) -> bool {
    let o = ip.octets();
    match o[0] {
        10 | 127 => true,
        172 => (16..=31).contains(&o[1]),
        192 => o[1] == 168,
        _ => false,
    }
}

/// One emitted lateral-movement alert.
#[derive(Debug, Clone, PartialEq)]
pub struct LateralAlert {
    pub ts: f64,
    pub src_ip: Ipv4Addr,
    /// The LAST internal peer probed that completed the threshold crossing (mirrors
    /// `portscan::PortScanAlert::dst_port`'s "last-probed" convention — the full peer set is a
    /// count, not enumerated in the alert itself).
    pub dst_ip: Ipv4Addr,
    pub dst_port: u16,
    pub distinct_peers: usize,
    pub src_mac: Option<[u8; 6]>,
}

impl LateralAlert {
    fn confidence(&self) -> f64 {
        (0.55 + self.distinct_peers as f64 * 0.05).min(0.95)
    }

    fn mac_str(&self) -> Option<String> {
        self.src_mac.map(|m| {
            format!("{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}", m[0], m[1], m[2], m[3], m[4], m[5])
        })
    }

    /// Render as one NAPSE event-stream JSON line — same field-naming/confirmed-severity
    /// discipline as every other tracker in this crate.
    pub fn to_json(&self, confirmed: bool) -> String {
        let sev = if confirmed { LATERAL_SEVERITY_CONFIRMED } else { LATERAL_SEVERITY_UNCONFIRMED };
        let mac_field = match self.mac_str() {
            Some(m) => format!(r#","src_mac":"{m}""#),
            None => String::new(),
        };
        format!(
            concat!(
                r#"{{"ts":{ts:.3},"src_ip":"{src}","dst_ip":"{dst}","dst_port":{dp},"proto":"tcp","#,
                r#""severity":{sev},"rule_id":{rid},"rule_msg":"{msg}","#,
                r#""mitre":"{mitre}","category":"{cat}","confidence":{conf:.4},"#,
                r#""distinct_peers":{dpeers},"confirmed":{confirmed}{mac_field}}}"#,
            ),
            ts = self.ts,
            src = self.src_ip,
            dst = self.dst_ip,
            dp = self.dst_port,
            sev = sev,
            rid = LATERAL_RULE_ID,
            msg = LATERAL_RULE_MSG,
            mitre = LATERAL_MITRE,
            cat = LATERAL_CATEGORY,
            conf = self.confidence(),
            dpeers = self.distinct_peers,
            confirmed = confirmed,
            mac_field = mac_field,
        )
    }
}

struct SourceState {
    /// (ts, dst_ip) of every lateral-port connection attempt still inside the window.
    window: VecDeque<(f64, Ipv4Addr)>,
    last_alert_ts: Option<f64>,
    last_dst_port: u16,
    last_src_mac: [u8; 6],
}

/// Bounded per-source-IP sliding-window distinct-internal-peer tracker — see the module doc for
/// the full detection rationale and FP-guard analysis.
pub struct LateralMovementTracker {
    cfg: LateralConfig,
    sources: HashMap<Ipv4Addr, SourceState>,
    order: VecDeque<Ipv4Addr>,
}

impl LateralMovementTracker {
    pub fn new(cfg: LateralConfig) -> Self {
        LateralMovementTracker { cfg, sources: HashMap::new(), order: VecDeque::new() }
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

    /// Feed one real connection-attempt observation (SYN set, ACK clear — the caller filters
    /// exactly like every other tracker's `syn_only`/`is_probe` convention in this crate). Returns
    /// `None` immediately (no state touched) unless `dst_port` is one of [`LATERAL_PORTS`] AND both
    /// `src_ip` and `dst_ip` are RFC1918 internal AND they differ — see FP guards #1/#4 in the
    /// module doc. Otherwise returns `Some(alert)` the instant this source's distinct-internal-peer
    /// count within the window first reaches `threshold`, then suppresses re-firing for
    /// `cooldown_secs`.
    pub fn observe(
        &mut self,
        now: f64,
        src_ip: Ipv4Addr,
        dst_ip: Ipv4Addr,
        dst_port: u16,
        src_mac: [u8; 6],
    ) -> Option<LateralAlert> {
        if !LATERAL_PORTS.contains(&dst_port) {
            return None;
        }
        if src_ip == dst_ip {
            return None;
        }
        if !is_private_ipv4(src_ip) || !is_private_ipv4(dst_ip) {
            return None; // FP guard #1 — east-west only, never north-south
        }

        if !self.sources.contains_key(&src_ip) {
            self.evict_if_full();
            self.order.push_back(src_ip);
            self.sources.insert(
                src_ip,
                SourceState { window: VecDeque::new(), last_alert_ts: None, last_dst_port: dst_port, last_src_mac: src_mac },
            );
        }
        let state = self.sources.get_mut(&src_ip).expect("just inserted above");
        state.window.push_back((now, dst_ip));
        state.last_dst_port = dst_port;
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
                return None; // one sweep = one alert; still cooling down
            }
        }
        state.last_alert_ts = Some(now);
        Some(LateralAlert {
            ts: now,
            src_ip,
            dst_ip,
            dst_port: state.last_dst_port,
            distinct_peers: distinct.len(),
            src_mac: Some(state.last_src_mac),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MAC: [u8; 6] = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66];

    fn cfg() -> LateralConfig {
        LateralConfig { threshold: 5, window_secs: 300.0, cooldown_secs: 300.0, max_sources: 4096 }
    }

    // (a) Positive: one internal source hitting 5 distinct internal peers on lateral ports fires.
    #[test]
    fn east_west_sweep_fires() {
        let mut t = LateralMovementTracker::new(cfg());
        let src = Ipv4Addr::new(10, 0, 0, 50);
        let ports = [445u16, 3389, 22, 5985, 5900];
        let mut fired = false;
        for (i, &port) in ports.iter().enumerate() {
            let dst = Ipv4Addr::new(10, 0, 1, i as u8);
            if t.observe(100.0 + i as f64, src, dst, port, MAC).is_some() {
                fired = true;
            }
        }
        assert!(fired, "5 distinct internal peers on lateral ports must fire");
    }

    #[test]
    fn alert_json_matches_schema_and_category() {
        let mut t = LateralMovementTracker::new(cfg());
        let src = Ipv4Addr::new(10, 0, 0, 51);
        let mut alert = None;
        for i in 0..6u8 {
            let dst = Ipv4Addr::new(10, 0, 2, i);
            if let Some(a) = t.observe(200.0 + i as f64, src, dst, 445, MAC) {
                alert = Some(a);
            }
        }
        let a = alert.expect("6 distinct peers on SMB must fire");
        let j = a.to_json(true);
        let v: serde_json::Value = serde_json::from_str(&j).expect("valid json");
        assert_eq!(v["rule_id"], 1_000_041);
        assert_eq!(v["category"], "lateral_movement");
        assert_eq!(v["mitre"], "T1021");
        assert_eq!(v["severity"], 2, "confirmed lateral movement renders HIGH severity");
        assert_eq!(v["confirmed"], true);
        assert_eq!(v["src_mac"], "11:22:33:44:55:66");

        let ju = a.to_json(false);
        let vu: serde_json::Value = serde_json::from_str(&ju).expect("valid json");
        assert_eq!(vu["severity"], 3, "unconfirmed lateral movement renders MEDIUM, never suppressed");
    }

    // (b) FP guard: a normal client reaching ONE internal server repeatedly never fires, however
    // many connections it makes.
    #[test]
    fn single_peer_never_fires_however_many_connections() {
        let mut t = LateralMovementTracker::new(cfg());
        let src = Ipv4Addr::new(10, 0, 0, 52);
        let dst = Ipv4Addr::new(10, 0, 3, 1);
        for i in 0..100u32 {
            assert!(t.observe(i as f64, src, dst, 445, MAC).is_none());
        }
    }

    // (c) FP guard: below the distinct-peer threshold never fires.
    #[test]
    fn below_threshold_never_fires() {
        let mut t = LateralMovementTracker::new(cfg());
        let src = Ipv4Addr::new(10, 0, 0, 53);
        for i in 0..4u8 {
            let dst = Ipv4Addr::new(10, 0, 4, i);
            assert!(t.observe(100.0 + i as f64, src, dst, 22, MAC).is_none());
        }
    }

    // (d) FP guard: north-south (internal → EXTERNAL) traffic on the same ports never fires — a
    // client SSH-ing out to many public hosts is not lateral movement.
    #[test]
    fn external_destinations_never_fire() {
        let mut t = LateralMovementTracker::new(cfg());
        let src = Ipv4Addr::new(10, 0, 0, 54);
        for i in 0..20u8 {
            let dst = Ipv4Addr::new(203, 0, 113, i);
            assert!(t.observe(100.0 + i as f64, src, dst, 22, MAC).is_none());
        }
    }

    // (e) FP guard: north-south the OTHER direction (EXTERNAL source into one internal host) never
    // fires either — this detector is strictly internal-source-scoped.
    #[test]
    fn external_source_never_fires() {
        let mut t = LateralMovementTracker::new(cfg());
        let src = Ipv4Addr::new(198, 51, 100, 7);
        for i in 0..20u8 {
            let dst = Ipv4Addr::new(10, 0, 5, i);
            assert!(t.observe(100.0 + i as f64, src, dst, 3389, MAC).is_none());
        }
    }

    // (f) FP guard: non-lateral ports never count toward the fan-out, however many distinct peers.
    #[test]
    fn non_lateral_ports_never_count() {
        let mut t = LateralMovementTracker::new(cfg());
        let src = Ipv4Addr::new(10, 0, 0, 55);
        for i in 0..20u8 {
            let dst = Ipv4Addr::new(10, 0, 6, i);
            assert!(t.observe(100.0 + i as f64, src, dst, 443, MAC).is_none(), "HTTPS is not a lateral-movement port");
        }
    }

    #[test]
    fn cooldown_suppresses_immediate_refire() {
        let mut t = LateralMovementTracker::new(cfg());
        let src = Ipv4Addr::new(10, 0, 0, 56);
        let mut fires = 0;
        for i in 0..50u8 {
            let dst = Ipv4Addr::new(10, 0, 7, i);
            if t.observe(100.0 + i as f64, src, dst, 445, MAC).is_some() {
                fires += 1;
            }
        }
        assert_eq!(fires, 1, "one sweep must yield exactly one alert while cooling down");
    }

    #[test]
    fn max_sources_bounds_memory() {
        let mut cfg = cfg();
        cfg.max_sources = 4;
        let mut t = LateralMovementTracker::new(cfg);
        let dst = Ipv4Addr::new(10, 0, 8, 1);
        for i in 0..100u8 {
            t.observe(1000.0 + i as f64, Ipv4Addr::new(10, 9, 0, i), dst, 445, MAC);
        }
        assert!(t.sources.len() <= 4, "tracked sources must stay bounded at max_sources");
    }

    #[test]
    fn is_private_ipv4_matches_rfc1918_and_loopback() {
        assert!(is_private_ipv4(Ipv4Addr::new(10, 1, 2, 3)));
        assert!(is_private_ipv4(Ipv4Addr::new(172, 16, 0, 1)));
        assert!(is_private_ipv4(Ipv4Addr::new(172, 31, 255, 255)));
        assert!(!is_private_ipv4(Ipv4Addr::new(172, 32, 0, 1)));
        assert!(is_private_ipv4(Ipv4Addr::new(192, 168, 1, 1)));
        assert!(!is_private_ipv4(Ipv4Addr::new(192, 169, 1, 1)));
        assert!(is_private_ipv4(Ipv4Addr::new(127, 0, 0, 1)));
        assert!(!is_private_ipv4(Ipv4Addr::new(8, 8, 8, 8)));
    }

    #[test]
    fn rule_id_does_not_collide_with_other_trackers_in_this_crate() {
        use crate::beacon::BEACON_RULE_ID;
        use crate::portscan::{ICMP_SWEEP_RULE_ID, RULE_ID, SLOWSCAN_RULE_ID, UDP_SCAN_RULE_ID};
        assert_ne!(LATERAL_RULE_ID, RULE_ID);
        assert_ne!(LATERAL_RULE_ID, UDP_SCAN_RULE_ID);
        assert_ne!(LATERAL_RULE_ID, ICMP_SWEEP_RULE_ID);
        assert_ne!(LATERAL_RULE_ID, SLOWSCAN_RULE_ID);
        assert_ne!(LATERAL_RULE_ID, BEACON_RULE_ID);
    }
}
