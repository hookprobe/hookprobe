//! C2 beacon / periodicity detector — the gap-analysis HIGHEST-value miss: none of the existing
//! packet-layer trackers (`portscan`) or the conntrack-fed wasm engine (`modules/napse`) look at
//! the TIME STRUCTURE of a connection sequence — only its fan-out (how many distinct ports/hosts)
//! or its content (signatures, entropy). A C2 implant that "checks in" to its controller on a
//! fixed sleep interval (Cobalt Strike, Metasploit, Empire, most commodity RATs — T1071.001
//! Application Layer Protocol; often riding a "legitimate-looking" web service, T1102) produces
//! near-zero port/host fan-out (it talks to ONE controller, on ONE port) and often innocuous
//! content (HTTPS to a plausible domain) — it is invisible to every detector above. What it CANNOT
//! hide without breaking its own scheduling logic is the metronomic INTERVAL between check-ins.
//!
//! `BeaconTracker` tracks, per `(src_ip, dst_ip, dst_port)`, the timestamps of connection attempts
//! over a LONG sliding window and fires when the inter-arrival intervals are both NUMEROUS (≥
//! `min_connections`, so a couple of coincidental reconnects can't trip it) and REGULAR (coefficient
//! of variation — stddev/mean of the intervals — below `max_cv`; a human-driven or bursty workload
//! has high variance, a `sleep(N) + jitter%` C2 loop has low variance almost by definition).
//!
//! ## FP guards (the reason this detector doesn't just fire on every keep-alive/health-check)
//!
//! 1. **Per-destination scoping.** Counted per `(src_ip, dst_ip, dst_port)`, never globally per
//!    source — mirrors `portscan::SlowScanTracker`'s per-target scoping rationale exactly: a
//!    source that talks to MANY different periodic services (an NTP client, a backup agent, a
//!    monitoring exporter, and a real C2 implant all running on the same host) must not have those
//!    independent periodic patterns conflated into one another; each destination's own regularity
//!    is judged on its own.
//! 2. **Minimum connection count** (`min_connections`, default
//!    [`DEFAULT_BEACON_MIN_CONNECTIONS`]) — a couple of retries landing at a similar spacing by
//!    chance is not a pattern; real beacon detection needs a run long enough to be statistically
//!    meaningful.
//! 3. **Minimum mean interval** (`min_mean_interval_secs`) — without this, a RAPID, low-jitter
//!    retry burst (e.g. a client hammering a down service every 200ms with a consistent backoff)
//!    would also read as "low CV, many connections" and false-fire. Real C2 sleep intervals are
//!    seconds-to-minutes-or-hours; a sub-several-second mean interval is far more likely a retry
//!    loop or a legitimate fast-poll client than a beacon, so it's excluded by construction.
//! 4. **Allowlist** (`allowlist_ports`, `allowlist_ips`) — legitimate periodic traffic is common
//!    and this is explicitly named as the critical risk in the gap analysis this closes: NTP
//!    (UDP/123) is exempted by default; the operator can additionally allowlist their own
//!    update/telemetry endpoints via env (`NAPSE_BEACON_ALLOWLIST_IPS`, wired in
//!    `bin/napse-dpi.rs`) so a device's own legitimate phone-home traffic never fires. Checked
//!    FIRST in `observe`, before any state is even touched, so an allowlisted destination costs
//!    this tracker nothing.
//!
//! Same anti-spoof discipline as every other tracker in this crate: carries the OBSERVED `src_mac`
//! so a CONFIRMED beacon (validated by the independent `confirm::HandshakeTracker` — a beacon's
//! connections are real, repeated, successful TCP sessions, so confirmation is the common case,
//! unlike a single spoofable SYN burst) can be composed into enforcement, while an unconfirmed one
//! renders at lower severity. Fed from BOTH the TCP SYN-only ("real new connection attempt", never
//! a FIN/NULL/XMAS scan-probe shape) and UDP-datagram observation streams in `bin/napse-dpi.rs` —
//! `proto` is carried through into the rendered alert for operator context, not used in scoring.
//!
//! Bounded LRU memory exactly like [`crate::portscan::PortScanTracker`]: oldest-inserted
//! `(src_ip, dst_ip, dst_port)` tuple is evicted first once `max_tracked` is reached.

use std::collections::{HashMap, HashSet, VecDeque};
use std::net::Ipv4Addr;

/// Fresh rule_id band (checked 2026-07-07 against every `RULE_ID`/rule_id constant in the
/// workspace: `modules/napse` 1_000_001..=1_000_025, `napse-capture::portscan`
/// 1_000_003/1_000_012/1_000_013/1_000_014, `napse-capture::l2guard` 1_000_030..=1_000_033,
/// host-EDR 1_000_100..=1_000_118 — `1_000_040` is free; `lateral::LATERAL_RULE_ID` takes the
/// adjacent `1_000_041` for the same gap-analysis pass).
pub const BEACON_RULE_ID: u32 = 1_000_040;
pub const BEACON_RULE_MSG: &str = "NAPSE C2 Beaconing Detected";
pub const BEACON_CATEGORY: &str = "c2_beacon";
/// Application Layer Protocol beaconing — same technique tag the wasm engine's existing JA3/content
/// C2 rule (1000004) uses, so a JA3-matched beacon and a pure-timing-matched beacon correlate under
/// the same MITRE technique in the evidence graph. T1102 (Web Service) is the closely-related
/// technique when the beacon rides a legitimate web platform (a dead-drop resolver, a paste site) —
/// worth noting in any operator-facing explanation, but not carried as a second `mitre` field (the
/// schema is one MITRE id per alert, matching every other rule in this workspace).
pub const BEACON_MITRE: &str = "T1071.001";

/// Suricata severity convention (matches every other rule_id band in this workspace):
/// 1=CRITICAL 2=HIGH 3=MEDIUM 4=LOW 5=INFO. A confirmed beacon is a HIGHER-confidence finding than
/// an unconfirmed port/host fan-out (it takes real, repeated, successful sessions to establish a
/// timing pattern at all — a single spoofed packet can never fake a whole regular sequence) — HIGH
/// when confirmed, MEDIUM when not (never suppressed, only downgraded — same discipline as
/// `portscan`'s confirmed-gated severity).
pub const BEACON_SEVERITY_CONFIRMED: u8 = 2;
pub const BEACON_SEVERITY_UNCONFIRMED: u8 = 3;

pub const DEFAULT_BEACON_MIN_CONNECTIONS: usize = 6;
/// Long by design — a beacon's periodicity only becomes statistically visible over many cycles;
/// the default sleep interval commodity C2 frameworks use (30s-300s) needs a window measured in
/// tens of minutes to an hour to accumulate `min_connections` samples at all.
pub const DEFAULT_BEACON_WINDOW_SECS: f64 = 3600.0;
/// Coefficient of variation (stddev/mean of inter-arrival intervals) below which a sequence is
/// judged "regular enough" to be a beacon. 0.15 = intervals cluster within roughly ±15% of the
/// mean — comfortably catches a `sleep(N) + jitter%` C2 loop (typical implant jitter is 10-30% of
/// the sleep, which after averaging several cycles reads well under this bar) while staying well
/// above the variance any human-driven or bursty workload produces.
pub const DEFAULT_BEACON_MAX_CV: f64 = 0.15;
/// See FP guard #3 in the module doc — excludes rapid retry-storm patterns from ever being read as
/// a beacon regardless of how low their jitter is.
pub const DEFAULT_BEACON_MIN_MEAN_INTERVAL_SECS: f64 = 8.0;
pub const DEFAULT_BEACON_COOLDOWN_SECS: f64 = 900.0;
pub const DEFAULT_BEACON_MAX_TRACKED: usize = 8192;

/// NTP is exempted by default regardless of operator configuration — see FP guard #4.
pub const DEFAULT_BEACON_ALLOWLIST_PORTS: &[u16] = &[123];

#[derive(Debug, Clone)]
pub struct BeaconConfig {
    pub min_connections: usize,
    pub window_secs: f64,
    pub max_cv: f64,
    pub min_mean_interval_secs: f64,
    pub cooldown_secs: f64,
    pub max_tracked: usize,
    /// Destination ports exempt from tracking entirely (NTP by default — see
    /// [`DEFAULT_BEACON_ALLOWLIST_PORTS`]).
    pub allowlist_ports: HashSet<u16>,
    /// Destination IPs exempt from tracking entirely — the operator's own configured
    /// update/telemetry endpoints, populated from env by `bin/napse-dpi.rs`.
    pub allowlist_ips: HashSet<Ipv4Addr>,
}

impl Default for BeaconConfig {
    fn default() -> Self {
        BeaconConfig {
            min_connections: DEFAULT_BEACON_MIN_CONNECTIONS,
            window_secs: DEFAULT_BEACON_WINDOW_SECS,
            max_cv: DEFAULT_BEACON_MAX_CV,
            min_mean_interval_secs: DEFAULT_BEACON_MIN_MEAN_INTERVAL_SECS,
            cooldown_secs: DEFAULT_BEACON_COOLDOWN_SECS,
            max_tracked: DEFAULT_BEACON_MAX_TRACKED,
            allowlist_ports: DEFAULT_BEACON_ALLOWLIST_PORTS.iter().copied().collect(),
            allowlist_ips: HashSet::new(),
        }
    }
}

/// One emitted beacon alert.
#[derive(Debug, Clone, PartialEq)]
pub struct BeaconAlert {
    pub ts: f64,
    pub src_ip: Ipv4Addr,
    pub dst_ip: Ipv4Addr,
    pub dst_port: u16,
    /// How many connection attempts within the window fed the computation that fired this alert.
    pub connection_count: usize,
    /// Mean inter-arrival interval, seconds — the beacon's apparent "sleep time".
    pub mean_interval_secs: f64,
    /// Coefficient of variation of the intervals — the "jitter" figure; lower = more regular.
    pub jitter_cv: f64,
    pub src_mac: Option<[u8; 6]>,
    pub proto: &'static str,
}

impl BeaconAlert {
    /// Confidence rises with how many connections corroborate the pattern — a longer, more
    /// sustained regular sequence is a stronger signal than one that just crossed the minimum.
    fn confidence(&self) -> f64 {
        (0.55 + self.connection_count as f64 * 0.03).min(0.95)
    }

    fn mac_str(&self) -> Option<String> {
        self.src_mac.map(|m| {
            format!("{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}", m[0], m[1], m[2], m[3], m[4], m[5])
        })
    }

    /// Render as one NAPSE event-stream JSON line — same field-naming/confirmed-severity discipline
    /// as [`crate::portscan::PortScanAlert::to_json`], plus the two beacon-specific measurements
    /// (`mean_interval_secs`, `jitter_cv`) an operator/AI-copilot explanation needs to justify "why".
    pub fn to_json(&self, confirmed: bool) -> String {
        let sev = if confirmed { BEACON_SEVERITY_CONFIRMED } else { BEACON_SEVERITY_UNCONFIRMED };
        let mac_field = match self.mac_str() {
            Some(m) => format!(r#","src_mac":"{m}""#),
            None => String::new(),
        };
        format!(
            concat!(
                r#"{{"ts":{ts:.3},"src_ip":"{src}","dst_ip":"{dst}","dst_port":{dp},"#,
                r#""proto":"{proto}","severity":{sev},"rule_id":{rid},"rule_msg":"{msg}","#,
                r#""mitre":"{mitre}","category":"{cat}","confidence":{conf:.4},"#,
                r#""connection_count":{cc},"mean_interval_secs":{mi:.3},"jitter_cv":{jc:.4},"#,
                r#""confirmed":{confirmed}{mac_field}}}"#,
            ),
            ts = self.ts,
            src = self.src_ip,
            dst = self.dst_ip,
            dp = self.dst_port,
            proto = self.proto,
            sev = sev,
            rid = BEACON_RULE_ID,
            msg = BEACON_RULE_MSG,
            mitre = BEACON_MITRE,
            cat = BEACON_CATEGORY,
            conf = self.confidence(),
            cc = self.connection_count,
            mi = self.mean_interval_secs,
            jc = self.jitter_cv,
            confirmed = confirmed,
            mac_field = mac_field,
        )
    }
}

struct DestState {
    /// Connection-attempt timestamps still inside the window, in arrival order (every tracker in
    /// this crate assumes its caller feeds observations in non-decreasing `now` order, exactly like
    /// `portscan::PortScanTracker`'s own window).
    window: VecDeque<f64>,
    last_alert_ts: Option<f64>,
    last_src_mac: [u8; 6],
}

/// Bounded per-`(src_ip, dst_ip, dst_port)` sliding-window connection-timing tracker — see the
/// module doc for the full detection rationale and FP-guard analysis.
pub struct BeaconTracker {
    cfg: BeaconConfig,
    dests: HashMap<(Ipv4Addr, Ipv4Addr, u16), DestState>,
    order: VecDeque<(Ipv4Addr, Ipv4Addr, u16)>,
}

impl BeaconTracker {
    pub fn new(cfg: BeaconConfig) -> Self {
        BeaconTracker { cfg, dests: HashMap::new(), order: VecDeque::new() }
    }

    fn evict_if_full(&mut self) {
        let cap = self.cfg.max_tracked.max(1);
        while self.dests.len() >= cap {
            match self.order.pop_front() {
                Some(old) => {
                    self.dests.remove(&old);
                }
                None => break,
            }
        }
    }

    /// Feed one connection-attempt observation (a real new TCP session — SYN set, ACK clear — or a
    /// UDP datagram to this destination; `proto` is cosmetic, rendered but not scored). Returns
    /// `Some(alert)` the instant this `(src_ip, dst_ip, dst_port)`'s interval sequence first reads
    /// as regular-enough beaconing, then suppresses re-firing for `cooldown_secs`.
    pub fn observe(
        &mut self,
        now: f64,
        src_ip: Ipv4Addr,
        dst_ip: Ipv4Addr,
        dst_port: u16,
        src_mac: [u8; 6],
        proto: &'static str,
    ) -> Option<BeaconAlert> {
        // FP guard #4 — checked FIRST, before any state is touched (see module doc).
        if self.cfg.allowlist_ports.contains(&dst_port) || self.cfg.allowlist_ips.contains(&dst_ip) {
            return None;
        }

        let key = (src_ip, dst_ip, dst_port);
        if !self.dests.contains_key(&key) {
            self.evict_if_full();
            self.order.push_back(key);
            self.dests.insert(key, DestState { window: VecDeque::new(), last_alert_ts: None, last_src_mac: src_mac });
        }
        let state = self.dests.get_mut(&key).expect("just inserted above");
        state.window.push_back(now);
        state.last_src_mac = src_mac;

        let cutoff = now - self.cfg.window_secs;
        while state.window.front().is_some_and(|&t| t < cutoff) {
            state.window.pop_front();
        }

        // FP guard #2 — need enough samples for the statistics to mean anything.
        if state.window.len() < self.cfg.min_connections {
            return None;
        }

        // Inter-arrival intervals over the (time-ordered) window.
        let intervals: Vec<f64> =
            state.window.iter().zip(state.window.iter().skip(1)).map(|(a, b)| b - a).collect();
        let n = intervals.len() as f64;
        let mean = intervals.iter().sum::<f64>() / n;

        // FP guard #3 — exclude rapid retry-storm patterns regardless of their jitter.
        if mean < self.cfg.min_mean_interval_secs {
            return None;
        }

        let variance = intervals.iter().map(|&x| (x - mean).powi(2)).sum::<f64>() / n;
        let stddev = variance.sqrt();
        let cv = if mean > 0.0 { stddev / mean } else { f64::MAX };

        if cv > self.cfg.max_cv {
            return None;
        }
        if let Some(last) = state.last_alert_ts {
            if now - last < self.cfg.cooldown_secs {
                return None; // one detected pattern = one alert; still cooling down
            }
        }
        state.last_alert_ts = Some(now);
        Some(BeaconAlert {
            ts: now,
            src_ip,
            dst_ip,
            dst_port,
            connection_count: state.window.len(),
            mean_interval_secs: mean,
            jitter_cv: cv,
            src_mac: Some(state.last_src_mac),
            proto,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MAC: [u8; 6] = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];

    fn cfg() -> BeaconConfig {
        BeaconConfig {
            min_connections: 6,
            window_secs: 3600.0,
            max_cv: 0.15,
            min_mean_interval_secs: 8.0,
            cooldown_secs: 900.0,
            max_tracked: 8192,
            allowlist_ports: [123u16].into_iter().collect(),
            allowlist_ips: HashSet::new(),
        }
    }

    // (a) Positive: a regular 60s-interval beacon (small jitter) fires.
    #[test]
    fn regular_interval_beacon_fires() {
        let mut t = BeaconTracker::new(cfg());
        let src = Ipv4Addr::new(10, 0, 0, 5);
        let dst = Ipv4Addr::new(203, 0, 113, 50);
        let mut fired = false;
        // 10 check-ins at ~60s +/- 2s jitter — well within a real implant's jitter budget.
        let jitters = [0.0, 1.0, -1.0, 2.0, -2.0, 1.5, -1.5, 0.5, -0.5, 0.0];
        for (i, j) in jitters.iter().enumerate() {
            let ts = i as f64 * 60.0 + j;
            if t.observe(ts, src, dst, 443, MAC, "tcp").is_some() {
                fired = true;
            }
        }
        assert!(fired, "a low-jitter 60s-interval sequence must fire the beacon rule");
    }

    #[test]
    fn alert_fields_and_json_are_well_formed() {
        let mut t = BeaconTracker::new(cfg());
        let src = Ipv4Addr::new(10, 0, 0, 6);
        let dst = Ipv4Addr::new(203, 0, 113, 60);
        let mut alert = None;
        for i in 0..10u32 {
            let ts = i as f64 * 45.0;
            if let Some(a) = t.observe(ts, src, dst, 8443, MAC, "tcp") {
                alert = Some(a);
            }
        }
        let a = alert.expect("regular 45s sequence must fire");
        assert_eq!(a.src_ip, src);
        assert_eq!(a.dst_ip, dst);
        assert_eq!(a.dst_port, 8443);
        assert!(a.jitter_cv < 0.15);
        assert!(a.connection_count >= 6);

        let j = a.to_json(true);
        let v: serde_json::Value = serde_json::from_str(&j).expect("valid json");
        assert_eq!(v["rule_id"], 1_000_040);
        assert_eq!(v["category"], "c2_beacon");
        assert_eq!(v["mitre"], "T1071.001");
        assert_eq!(v["severity"], 2, "confirmed beacon renders HIGH severity");
        assert_eq!(v["confirmed"], true);
        assert_eq!(v["src_mac"], "aa:bb:cc:dd:ee:ff");

        let ju = a.to_json(false);
        let vu: serde_json::Value = serde_json::from_str(&ju).expect("valid json");
        assert_eq!(vu["severity"], 3, "unconfirmed beacon renders MEDIUM, never suppressed");
        assert_eq!(vu["rule_id"], 1_000_040);
    }

    // (b) FP guard: fewer than min_connections never fires, however regular.
    #[test]
    fn below_min_connections_never_fires() {
        let mut t = BeaconTracker::new(cfg());
        let src = Ipv4Addr::new(10, 0, 0, 7);
        let dst = Ipv4Addr::new(203, 0, 113, 70);
        for i in 0..5u32 {
            let ts = i as f64 * 60.0;
            assert!(t.observe(ts, src, dst, 443, MAC, "tcp").is_none());
        }
    }

    // (c) FP guard: high-jitter (human/bursty) traffic never fires even with many connections.
    #[test]
    fn irregular_intervals_never_fire() {
        let mut t = BeaconTracker::new(cfg());
        let src = Ipv4Addr::new(10, 0, 0, 8);
        let dst = Ipv4Addr::new(203, 0, 113, 80);
        // Wildly varying intervals: 10s, 300s, 45s, 900s, 20s, 600s, 5s, 400s ... — high CV.
        let gaps = [10.0, 300.0, 45.0, 900.0, 20.0, 600.0, 5.0, 400.0, 15.0, 700.0];
        let mut ts = 0.0;
        for g in gaps {
            assert!(t.observe(ts, src, dst, 443, MAC, "tcp").is_none());
            ts += g;
        }
    }

    // (d) FP guard: a rapid, low-jitter retry storm (mean interval below min_mean_interval_secs)
    // never fires, however regular — see FP guard #3.
    #[test]
    fn rapid_low_jitter_retry_storm_never_fires() {
        let mut t = BeaconTracker::new(cfg());
        let src = Ipv4Addr::new(10, 0, 0, 9);
        let dst = Ipv4Addr::new(203, 0, 113, 90);
        for i in 0..20u32 {
            let ts = i as f64 * 0.5; // every 500ms, essentially zero jitter
            assert!(t.observe(ts, src, dst, 443, MAC, "tcp").is_none());
        }
    }

    // (e) FP guard: NTP (UDP/123) is exempt by default regardless of pattern regularity.
    #[test]
    fn ntp_destination_port_is_exempt_by_default() {
        let mut t = BeaconTracker::new(BeaconConfig::default());
        let src = Ipv4Addr::new(10, 0, 0, 10);
        let dst = Ipv4Addr::new(203, 0, 113, 123);
        for i in 0..20u32 {
            let ts = i as f64 * 64.0;
            assert!(t.observe(ts, src, dst, 123, MAC, "udp").is_none(), "NTP must never fire");
        }
    }

    // (f) FP guard: an operator-configured allowlisted IP (e.g. the device's own update/telemetry
    // endpoint) never fires however regularly it's polled.
    #[test]
    fn operator_allowlisted_destination_never_fires() {
        let mut cfg = cfg();
        let update_host = Ipv4Addr::new(198, 51, 100, 200);
        cfg.allowlist_ips.insert(update_host);
        let mut t = BeaconTracker::new(cfg);
        let src = Ipv4Addr::new(10, 0, 0, 11);
        for i in 0..20u32 {
            let ts = i as f64 * 3600.0; // hourly update check, textbook "beacon" shape
            assert!(t.observe(ts, src, update_host, 443, MAC, "tcp").is_none());
        }
    }

    // (g) FP guard: per-destination scoping — a busy client alternating between two DIFFERENT
    // periodic destinations must not have their timestamps conflated into one false pattern.
    #[test]
    fn per_destination_scoping_prevents_cross_destination_conflation() {
        let mut t = BeaconTracker::new(cfg());
        let src = Ipv4Addr::new(10, 0, 0, 12);
        let dst_a = Ipv4Addr::new(203, 0, 113, 10);
        let dst_b = Ipv4Addr::new(203, 0, 113, 11);
        // dst_a every 60s, dst_b every 41s — interleaved, each independently regular, but
        // interleaving them would NOT read as "one" regular pattern if conflated.
        let mut fired_a = false;
        let mut fired_b = false;
        for i in 0..10u32 {
            if t.observe(i as f64 * 60.0, src, dst_a, 443, MAC, "tcp").is_some() {
                fired_a = true;
            }
            if t.observe(i as f64 * 41.0, src, dst_b, 8080, MAC, "tcp").is_some() {
                fired_b = true;
            }
        }
        assert!(fired_a, "dst_a's own regular pattern must still be detected independently");
        assert!(fired_b, "dst_b's own regular pattern must still be detected independently");
    }

    #[test]
    fn cooldown_suppresses_immediate_refire() {
        let mut t = BeaconTracker::new(cfg());
        let src = Ipv4Addr::new(10, 0, 0, 13);
        let dst = Ipv4Addr::new(203, 0, 113, 13);
        let mut fires = 0;
        // 12 check-ins at 60s spacing span 660s — comfortably inside the 900s cooldown, so the
        // pattern (first detectable at the 6th connection, t=300s) must fire exactly once.
        for i in 0..12u32 {
            if t.observe(i as f64 * 60.0, src, dst, 443, MAC, "tcp").is_some() {
                fires += 1;
            }
        }
        assert_eq!(fires, 1, "one detected pattern must yield exactly one alert within the 900s cooldown");
    }

    #[test]
    fn refires_after_cooldown_lapses() {
        let mut t = BeaconTracker::new(cfg());
        let src = Ipv4Addr::new(10, 0, 0, 15);
        let dst = Ipv4Addr::new(203, 0, 113, 15);
        // 30 check-ins at 60s spacing span 1740s, well past the 900s cooldown — the SAME ongoing
        // beacon must be re-reported once the cooldown lapses (an operator should not lose
        // visibility into a beacon that is still active just because it fired once earlier).
        let mut fires = 0;
        for i in 0..30u32 {
            if t.observe(i as f64 * 60.0, src, dst, 443, MAC, "tcp").is_some() {
                fires += 1;
            }
        }
        assert!(fires >= 2, "an ongoing beacon must re-fire after the cooldown lapses, got {fires}");
    }

    #[test]
    fn max_tracked_bounds_memory() {
        let mut cfg = cfg();
        cfg.max_tracked = 4;
        let mut t = BeaconTracker::new(cfg);
        let src = Ipv4Addr::new(10, 0, 0, 14);
        for i in 0..100u8 {
            let dst = Ipv4Addr::new(203, 0, 113, i);
            t.observe(1000.0 + i as f64, src, dst, 443, MAC, "tcp");
        }
        assert!(t.dests.len() <= 4, "tracked destinations must stay bounded at max_tracked");
    }

    #[test]
    fn rule_id_does_not_collide_with_other_trackers_in_this_crate() {
        use crate::portscan::{ICMP_SWEEP_RULE_ID, RULE_ID, SLOWSCAN_RULE_ID, UDP_SCAN_RULE_ID};
        assert_ne!(BEACON_RULE_ID, RULE_ID);
        assert_ne!(BEACON_RULE_ID, UDP_SCAN_RULE_ID);
        assert_ne!(BEACON_RULE_ID, ICMP_SWEEP_RULE_ID);
        assert_ne!(BEACON_RULE_ID, SLOWSCAN_RULE_ID);
        assert_ne!(BEACON_RULE_ID, crate::lateral::LATERAL_RULE_ID);
    }
}
