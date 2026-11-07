//! L1/L2 link-layer defensive detectors (ADR 0020 Phase-1a — DEFENSIVE, no offensive/probe code;
//! the security-auditor threat-model cleared this half to build immediately, see ADR 0020
//! "Threat-model sign-off"). Hardens `napse`/AEGIS against link-layer attacks: MAC-table
//! exhaustion (mac-flood), ARP spoofing/poisoning, broadcast/multicast amplification, and
//! malformed/fuzzed L1-L2 frames. Mirrors `portscan.rs`'s sliding-window/threshold + emit-to-events
//! pattern exactly, fed by the SAME mirror-sink AF_PACKET stream (`bin/napse-dpi.rs`).
//!
//! ## The anti-spoof discipline this inherits from ADR 0018 (CRITICAL, non-negotiable)
//! L1/L2 source identifiers (MAC/IP) are SPOOFABLE. This module therefore only ever reports the
//! OBSERVABLE frame anomaly + rate — never a claim keyed on a spoofable identity that could be
//! escalated into a durable block:
//!   - A **malformed frame** ([`l2_malformed`]) is flagged because the FRAME is bad (deterministic,
//!     evaluated by `dpi::frame_anomaly_reason`), never because of who claims to have sent it.
//!   - A **flood/storm** ([`mac_flood`]/[`broadcast_storm`]) is a RATE observation over a sliding
//!     window — the mitigation this feeds (`hookprobe_manifest::l2_responder`) is a bounded,
//!     self-reverting per-source/per-link rate cap, never a permanent blocklist of a (spoofable)
//!     source MAC.
//!   - **ARP anomalies** ([`ArpGuard`]) never resolve or trust a claimed identity as ground truth —
//!     they compare OBSERVED fields against each other (the ARP payload's own `sender_mac` vs the
//!     Ethernet frame's `src_mac`; an IP's most-recently-observed binding vs its new claim) and
//!     flag the disagreement itself as the evidence.
//!
//! This module makes ZERO enforcement decisions — it only detects and emits alerts (rule_ids
//! 1_000_030..=1_000_033, a fresh, unused range — see the module doc for the existing 1_000_00x
//! band this repo's wasm NAPSE engine and `portscan.rs`'s 1_000_003 already occupy, and the
//! 9_1xx_xxx/9_2xx_xxx supply-chain bands `module_sig.rs`/`resource_budget.rs` use). The verdict
//! (rate-limit vs frame-drop, never identity-quarantine) is `hookprobe_manifest::l2_responder`'s
//! job, exactly as `scan_responder::decide` owns the port-scan verdict.

use crate::dpi::ArpObs;
use std::collections::{HashMap, HashSet, VecDeque};
use std::net::Ipv4Addr;

/// Suricata severity convention (matches `portscan.rs`): 1=CRITICAL 2=HIGH 3=MEDIUM 4=LOW 5=INFO.
pub const SEV_HIGH: u8 = 2;
pub const SEV_MEDIUM: u8 = 3;

/// Rule ids for the four L1/L2 detectors this module adds. A FRESH, unused range: the napse wasm
/// engine (`modules/napse/src/lib.rs`) and this crate's own packet-layer port-scan tracker
/// (`portscan::RULE_ID`) occupy `1_000_001..=1_000_025`; the supply-chain bands
/// (`module_sig::ARTIFACT_TAMPER_RULE_ID`, `resource_budget::RESOURCE_BUDGET_RULE_ID`) occupy
/// `9_1xx_xxx`/`9_2xx_xxx`. `1_000_030..=1_000_033` collides with none of the above (checked
/// 2026-07-05 against every `rule_id`/`RULE_ID` constant in the workspace).
pub const MAC_FLOOD_RULE_ID: u32 = 1_000_030;
pub const ARP_SPOOF_RULE_ID: u32 = 1_000_031;
pub const BROADCAST_STORM_RULE_ID: u32 = 1_000_032;
pub const L2_MALFORMED_RULE_ID: u32 = 1_000_033;

pub const MAC_FLOOD_MSG: &str = "NAPSE MAC-Flood / MAC-Table Exhaustion Detected";
pub const ARP_SPOOF_MSG: &str = "NAPSE ARP Anomaly Detected";
pub const BROADCAST_STORM_MSG: &str = "NAPSE Broadcast/Multicast Storm Detected";
pub const L2_MALFORMED_MSG: &str = "NAPSE Malformed L1/L2 Frame Detected";

fn mac_str(m: [u8; 6]) -> String {
    format!("{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}", m[0], m[1], m[2], m[3], m[4], m[5])
}

/// One L1/L2 alert, ready to render as a NAPSE event-stream JSON line and be picked up by
/// `hookprobe_manifest::l2_responder::parse_l2_alert`. Deliberately carries NO `confirmed` bit
/// (unlike `portscan::PortScanAlert`) — there is no handshake-style confirmation possible at
/// L1/L2 (see this module's doc), so the responder must never be tempted to gate enforcement on
/// one; instead the RESPONSE itself (rate-limit / frame-drop) is structurally incapable of a
/// durable identity block — see `l2_responder::L2Verdict`.
#[derive(Debug, Clone, PartialEq)]
pub struct L2Alert {
    pub ts: f64,
    pub category: &'static str,
    pub rule_id: u32,
    pub rule_msg: &'static str,
    pub mitre: &'static str,
    pub severity: u8,
    pub confidence: f64,
    /// A short, stable machine tag distinguishing WHICH anomaly fired within a category (e.g.
    /// `arp_spoof` has four: `gratuitous_flood`/`binding_flip_flop`/`eth_mismatch`/
    /// `malformed_fields`). `l2_responder::decide_l2` dispatches on this, never on `detail`
    /// (free text) or fragile substring matching.
    pub reason: &'static str,
    /// The observed source MAC, when this alert is attributable to ONE frame's source (ARP
    /// anomalies, malformed frames). `None` for a link-wide finding (mac-flood: the whole point
    /// is that MANY distinct claimed sources were observed, so no single mac is "the" offender).
    pub src_mac: Option<[u8; 6]>,
    /// The IP address in dispute, for ARP anomalies only (the claimed sender IP whose binding
    /// flip-flopped, or that appeared in a gratuitous ARP). `None` otherwise.
    pub claimed_ip: Option<Ipv4Addr>,
    pub detail: String,
}

impl L2Alert {
    /// Render as one NAPSE event-stream JSON line — same field-naming convention as
    /// `portscan::PortScanAlert::to_json` (ts/rule_id/rule_msg/mitre/category/severity/confidence),
    /// plus this module's own `reason`/`src_mac`/`claimed_ip`/`detail`.
    pub fn to_json(&self) -> String {
        let mac_field = match self.src_mac {
            Some(m) => format!(r#","src_mac":"{}""#, mac_str(m)),
            None => String::new(),
        };
        let ip_field = match self.claimed_ip {
            Some(ip) => format!(r#","claimed_ip":"{ip}""#),
            None => String::new(),
        };
        format!(
            concat!(
                r#"{{"ts":{ts:.3},"rule_id":{rid},"rule_msg":"{msg}","mitre":"{mitre}","#,
                r#""category":"{cat}","severity":{sev},"confidence":{conf:.4},"reason":"{reason}","#,
                r#""detail":"{detail}"{mac_field}{ip_field}}}"#,
            ),
            ts = self.ts,
            rid = self.rule_id,
            msg = self.rule_msg,
            mitre = self.mitre,
            cat = self.category,
            sev = self.severity,
            conf = self.confidence,
            reason = self.reason,
            detail = jesc(&self.detail),
            mac_field = mac_field,
            ip_field = ip_field,
        )
    }
}

fn jesc(s: &str) -> String {
    s.chars().filter(|c| !c.is_control()).map(|c| if c == '"' || c == '\\' { ' ' } else { c }).collect()
}

// ---------------------------------------------------------------------------------------------
// 1. MAC-flood / MAC-table exhaustion — distinct source MACs on the ingress link per window.
// ---------------------------------------------------------------------------------------------

/// D12 (2026-07-07 enforcement-separation audit) topology classification for the link a
/// [`MacFloodTracker`] watches. "Many distinct source MACs in a short window" is the textbook
/// mac-flood/MAC-table-exhaustion signal on a **single-client access port** — but it is the
/// EXPECTED, benign shape of an **uplink/bridge/AP port** that fans traffic out to (or in from) a
/// whole LAN/office/café: a switch uplink or a Wi-Fi AP radio sees a new distinct MAC every time
/// ANY of its many legitimate clients (re)associates, roams, or a DHCP lease turns over — nothing
/// hostile is implied. Before this fix `MacFloodTracker` used ONE threshold for every link, so the
/// device's own default LAN-facing interface (`l2_responder::L2GuardConfig::lan_iface` defaults to
/// `wlan0`, an AP radio serving the whole LAN) tripped `mac_flood` on completely ordinary usage.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PortRole {
    /// A single-uplink / single-client-facing port that should see only ONE (or a small handful
    /// of) source MAC — e.g. a WAN uplink (the one upstream ISP router/modem) or a Wi-Fi
    /// **station** radio (the one AP it associates to). Many distinct MACs here IS anomalous —
    /// keep the sensitive default threshold.
    Access,
    /// A port that fans out to MANY legitimate devices by construction — a Wi-Fi **AP** radio or
    /// a genuine LAN bridge/switch uplink. Many distinct source MACs is the NORMAL, expected shape
    /// of this port; only a sharply higher volume is a credible flood.
    UplinkBridge,
}
impl Default for PortRole {
    /// `UplinkBridge` — matches the device's own actual default topology (`lan_iface` = `wlan0`,
    /// the AP radio serving the whole LAN; see the SASE portable-edge default). This is the safer
    /// default: it avoids the out-of-the-box false positive on ordinary LAN/AP usage, while a
    /// genuinely dedicated access port opts IN to the stricter threshold explicitly.
    fn default() -> Self {
        PortRole::UplinkBridge
    }
}

/// Derive a [`PortRole`] for `iface` from the SAME interface classification the reconciler already
/// keys off — never a fresh hardware re-probe (`hookprobe_manifest::types::ManifestUplink` for WAN
/// candidates, `hookprobe_manifest::types::WifiRadio` for the Wi-Fi station-vs-AP role assigned at
/// build time; see `net_roles::assign_wifi_roles`). Order of evidence, most specific first:
///   1. A WAN uplink candidate (`network.uplinks`) — the ONE upstream router/modem; `Access`.
///   2. A Wi-Fi radio (`network.wifi_radios`) — `"station"` associates to exactly one AP
///      (`Access`); anything else (in practice `"ap"`) fans out to many clients (`UplinkBridge`).
///   3. Anything else (an Ethernet interface that is neither a WAN candidate nor a known radio) —
///      defaults to `UplinkBridge`, the safer choice: an untagged Ethernet port on this device is,
///      in practice, the LAN/bridge side (a switch uplink carrying many legitimate clients), and
///      treating it as `Access` would reintroduce exactly the false-positive this fix closes.
pub fn port_role_for_interface(
    iface: &str,
    uplinks: &[hookprobe_manifest::types::ManifestUplink],
    wifi_radios: &[hookprobe_manifest::types::WifiRadio],
) -> PortRole {
    if uplinks.iter().any(|u| u.name == iface) {
        return PortRole::Access;
    }
    if let Some(radio) = wifi_radios.iter().find(|w| w.name == iface) {
        return if radio.role == "station" { PortRole::Access } else { PortRole::UplinkBridge };
    }
    PortRole::UplinkBridge
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct MacFloodConfig {
    /// Distinct source MACs within `window_secs` that trigger the alert on an [`PortRole::Access`]
    /// link (a genuine single-client port — keeps the original, sensitive bar).
    pub threshold: usize,
    /// Distinct source MACs within `window_secs` that trigger the alert on a
    /// [`PortRole::UplinkBridge`] link — sharply higher, because seeing many distinct MACs there
    /// is the NORMAL shape of a busy LAN/AP, not a flood signal. Only a genuinely high-volume
    /// event (an actual attacker driving hundreds of spoofed MACs) crosses this bar.
    pub uplink_threshold: usize,
    /// Which of the two thresholds above applies — derived once from the manifest/network config
    /// via [`port_role_for_interface`], never re-probed per packet.
    pub port_role: PortRole,
    pub window_secs: f64,
    pub cooldown_secs: f64,
    /// Bound on tracked (ts, mac) observations in the window — caps memory against an
    /// unbounded-rate attack regardless of the distinct-mac math above.
    pub max_tracked: usize,
}
pub const DEFAULT_MAC_FLOOD_THRESHOLD: usize = 20;
/// D12 fix: 15x the access-port bar — sharply higher, so a busy office/café LAN's ordinary churn
/// (dozens of legitimate clients (re)associating/DHCP-renewing within the window) never trips it,
/// while an actual mac-flood attempt (typically hundreds-to-thousands of spoofed MACs, the whole
/// point being to overflow a switch's few-thousand-entry CAM table) still does.
pub const DEFAULT_MAC_FLOOD_UPLINK_THRESHOLD: usize = 300;
pub const DEFAULT_MAC_FLOOD_WINDOW_SECS: f64 = 10.0;
pub const DEFAULT_MAC_FLOOD_COOLDOWN_SECS: f64 = 30.0;
pub const DEFAULT_MAC_FLOOD_MAX_TRACKED: usize = 8192;
impl Default for MacFloodConfig {
    fn default() -> Self {
        MacFloodConfig {
            threshold: DEFAULT_MAC_FLOOD_THRESHOLD,
            uplink_threshold: DEFAULT_MAC_FLOOD_UPLINK_THRESHOLD,
            port_role: PortRole::default(),
            window_secs: DEFAULT_MAC_FLOOD_WINDOW_SECS,
            cooldown_secs: DEFAULT_MAC_FLOOD_COOLDOWN_SECS,
            max_tracked: DEFAULT_MAC_FLOOD_MAX_TRACKED,
        }
    }
}

/// Link-wide sliding-window tracker: how many DISTINCT source MACs has this link's mirror seen
/// recently. A real switch's CAM table holds a few thousand entries at most; a burst of
/// (typically spoofed) distinct source MACs is the classic MAC-flood attack that forces a switch
/// to fail open into hub-like flooding (enabling passive sniffing) — this tracker sees the same
/// signal on the mirror without needing switch-side telemetry.
pub struct MacFloodTracker {
    cfg: MacFloodConfig,
    window: VecDeque<(f64, [u8; 6])>,
    last_alert_ts: Option<f64>,
}
impl MacFloodTracker {
    pub fn new(cfg: MacFloodConfig) -> Self {
        MacFloodTracker { cfg, window: VecDeque::new(), last_alert_ts: None }
    }

    pub fn observe(&mut self, now: f64, src_mac: [u8; 6]) -> Option<L2Alert> {
        self.window.push_back((now, src_mac));
        let cutoff = now - self.cfg.window_secs;
        while self.window.front().is_some_and(|&(ts, _)| ts < cutoff) {
            self.window.pop_front();
        }
        while self.window.len() > self.cfg.max_tracked.max(1) {
            self.window.pop_front();
        }
        let distinct: HashSet<[u8; 6]> = self.window.iter().map(|&(_, m)| m).collect();
        // D12 fix: the bar is topology-aware — a genuine access port keeps the sensitive default;
        // an uplink/bridge/AP port (this device's own actual default topology) uses the sharply
        // higher bar, since seeing many distinct MACs there is normal, not a flood signal.
        let effective_threshold = match self.cfg.port_role {
            PortRole::Access => self.cfg.threshold,
            PortRole::UplinkBridge => self.cfg.uplink_threshold,
        };
        if distinct.len() < effective_threshold {
            return None;
        }
        if let Some(last) = self.last_alert_ts {
            if now - last < self.cfg.cooldown_secs {
                return None;
            }
        }
        self.last_alert_ts = Some(now);
        Some(L2Alert {
            ts: now,
            category: "mac_flood",
            rule_id: MAC_FLOOD_RULE_ID,
            rule_msg: MAC_FLOOD_MSG,
            mitre: "T1498.001",
            severity: SEV_HIGH,
            confidence: (0.60 + distinct.len() as f64 * 0.01).min(0.95),
            reason: "fanout",
            src_mac: None, // link-wide finding — no single attributable source, see doc comment
            claimed_ip: None,
            detail: format!(
                "{} distinct source MACs observed on the ingress link within {:.0}s (>= threshold {}, port_role={:?})",
                distinct.len(),
                self.cfg.window_secs,
                effective_threshold,
                self.cfg.port_role,
            ),
        })
    }
}

// ---------------------------------------------------------------------------------------------
// 2. Broadcast/multicast amplification — rate of broadcast/multicast frames per source MAC.
// ---------------------------------------------------------------------------------------------

/// True if `dst` is a broadcast or multicast destination — covers the plain broadcast
/// (ff:ff:ff:ff:ff:ff), IPv4 multicast (01:00:5e:*), LLDP (01:80:c2:*), and CDP (01:00:0c:*)
/// address ranges the task calls out: all of them set the multicast/group bit (LSB of the first
/// octet), which IEEE 802.3 reserves exactly for this purpose — one cheap, universal check.
pub fn is_broadcast_or_multicast(dst: [u8; 6]) -> bool {
    dst[0] & 0x01 != 0
}

/// D13 (2026-07-07 enforcement-separation audit) fix: well-known **link-local service-discovery**
/// multicast destinations a chatty-but-entirely-legitimate device (a smart-TV/printer/HomeKit
/// accessory doing mDNS/Bonjour, SSDP/UPnP, or LLMNR) sends routinely and can burst well past the
/// storm threshold — these are never amplification vectors (bounded to the local link, one hop,
/// no forwarding) and must NEVER count toward [`BroadcastStormTracker`]'s rate. Address → the
/// IEEE-mapped destination MAC ("01:00:5e:xx:xx:xx" for IPv4 multicast — low 23 bits of the group
/// address; "33:33:xx:xx:xx:xx" for IPv6 multicast — low 32 bits of the group address):
///   - mDNS:    224.0.0.251   → 01:00:5e:00:00:fb   |  ff02::fb    → 33:33:00:00:00:fb
///   - SSDP:    239.255.255.250 → 01:00:5e:7f:ff:fa |  ff02::c     → 33:33:00:00:00:0c
///   - LLMNR:   224.0.0.252   → 01:00:5e:00:00:fc   |  ff02::1:3   → 33:33:00:01:00:03
///   - all-nodes/all-routers (IPv6 only, no IPv4 equivalent): ff02::1 → 33:33:00:00:00:01,
///     ff02::2 → 33:33:00:00:00:02
///
/// A RAW broadcast (`ff:ff:ff:ff:ff:ff`) or any NON-exempt multicast group is NOT covered here and
/// still counts — this is a narrow, named allowlist of specific well-known service-discovery
/// groups, never a blanket "all multicast is fine" carve-out (which would hand an attacker a free
/// amplification channel).
pub fn is_exempt_multicast(dst: [u8; 6]) -> bool {
    const EXEMPT: [[u8; 6]; 8] = [
        [0x01, 0x00, 0x5e, 0x00, 0x00, 0xfb], // mDNS v4 (224.0.0.251)
        [0x33, 0x33, 0x00, 0x00, 0x00, 0xfb], // mDNS v6 (ff02::fb)
        [0x01, 0x00, 0x5e, 0x7f, 0xff, 0xfa], // SSDP v4 (239.255.255.250)
        [0x33, 0x33, 0x00, 0x00, 0x00, 0x0c], // SSDP v6 (ff02::c)
        [0x01, 0x00, 0x5e, 0x00, 0x00, 0xfc], // LLMNR v4 (224.0.0.252)
        [0x33, 0x33, 0x00, 0x01, 0x00, 0x03], // LLMNR v6 (ff02::1:3)
        [0x33, 0x33, 0x00, 0x00, 0x00, 0x01], // IPv6 all-nodes (ff02::1)
        [0x33, 0x33, 0x00, 0x00, 0x00, 0x02], // IPv6 all-routers (ff02::2)
    ];
    EXEMPT.contains(&dst)
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct BroadcastStormConfig {
    pub threshold: usize,
    pub window_secs: f64,
    pub cooldown_secs: f64,
    pub max_sources: usize,
}
pub const DEFAULT_BROADCAST_THRESHOLD: usize = 100;
pub const DEFAULT_BROADCAST_WINDOW_SECS: f64 = 5.0;
pub const DEFAULT_BROADCAST_COOLDOWN_SECS: f64 = 30.0;
pub const DEFAULT_BROADCAST_MAX_SOURCES: usize = 4096;
impl Default for BroadcastStormConfig {
    fn default() -> Self {
        BroadcastStormConfig {
            threshold: DEFAULT_BROADCAST_THRESHOLD,
            window_secs: DEFAULT_BROADCAST_WINDOW_SECS,
            cooldown_secs: DEFAULT_BROADCAST_COOLDOWN_SECS,
            max_sources: DEFAULT_BROADCAST_MAX_SOURCES,
        }
    }
}

struct BcastSourceState {
    window: VecDeque<f64>,
    last_alert_ts: Option<f64>,
}

/// Per-source-MAC sliding-window counter of broadcast/multicast frames. Bounded (FIFO-evicted,
/// same discipline as `portscan::PortScanTracker::evict_if_full`) so an attacker cannot grow this
/// tracker's own memory unbounded by rotating source MACs (that pattern is exactly what
/// [`MacFloodTracker`] catches separately).
pub struct BroadcastStormTracker {
    cfg: BroadcastStormConfig,
    sources: HashMap<[u8; 6], BcastSourceState>,
    order: VecDeque<[u8; 6]>,
}
impl BroadcastStormTracker {
    pub fn new(cfg: BroadcastStormConfig) -> Self {
        BroadcastStormTracker { cfg, sources: HashMap::new(), order: VecDeque::new() }
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

    /// Feed one observed frame. Returns `None` immediately for a non-broadcast/multicast `dst` —
    /// only the flood signal matters here, not general traffic volume. D13 fix: a well-known
    /// service-discovery multicast group ([`is_exempt_multicast`] — mDNS/SSDP/LLMNR/all-nodes/
    /// all-routers) is likewise never counted — a chatty-but-legitimate smart-TV/printer doing
    /// routine Bonjour/UPnP announcements must never look like a broadcast storm. A raw
    /// `ff:ff:ff:ff:ff:ff` broadcast or any NON-exempt multicast group still counts in full.
    pub fn observe(&mut self, now: f64, src_mac: [u8; 6], dst_mac: [u8; 6]) -> Option<L2Alert> {
        if !is_broadcast_or_multicast(dst_mac) || is_exempt_multicast(dst_mac) {
            return None;
        }
        if !self.sources.contains_key(&src_mac) {
            self.evict_if_full();
            self.order.push_back(src_mac);
            self.sources.insert(src_mac, BcastSourceState { window: VecDeque::new(), last_alert_ts: None });
        }
        let state = self.sources.get_mut(&src_mac).expect("just inserted above");
        state.window.push_back(now);
        let cutoff = now - self.cfg.window_secs;
        while state.window.front().is_some_and(|&ts| ts < cutoff) {
            state.window.pop_front();
        }
        if state.window.len() < self.cfg.threshold {
            return None;
        }
        if let Some(last) = state.last_alert_ts {
            if now - last < self.cfg.cooldown_secs {
                return None;
            }
        }
        state.last_alert_ts = Some(now);
        let count = state.window.len();
        Some(L2Alert {
            ts: now,
            category: "broadcast_storm",
            rule_id: BROADCAST_STORM_RULE_ID,
            rule_msg: BROADCAST_STORM_MSG,
            mitre: "T1498.001",
            severity: SEV_MEDIUM,
            confidence: (0.50 + count as f64 * 0.005).min(0.95),
            reason: "storm",
            src_mac: Some(src_mac),
            claimed_ip: None,
            detail: format!(
                "{} broadcast/multicast frames from this source within {:.0}s (>= threshold {})",
                count, self.cfg.window_secs, self.cfg.threshold
            ),
        })
    }
}

// ---------------------------------------------------------------------------------------------
// 3. ARP anomaly / asymmetric poisoning — binding flip-flop, gratuitous flood, mismatch, malformed.
// ---------------------------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct ArpGuardConfig {
    /// Distinct-MAC claims for the SAME IP within `flip_flop_window_secs` that flag a
    /// binding-flip-flop (RA-Guard-style poisoning signal).
    pub flip_flop_threshold: usize,
    pub flip_flop_window_secs: f64,
    /// Gratuitous ARPs from the SAME source MAC within `gratuitous_window_secs` that flag a flood.
    pub gratuitous_threshold: usize,
    pub gratuitous_window_secs: f64,
    pub cooldown_secs: f64,
    pub max_bindings: usize,
}
pub const DEFAULT_FLIP_FLOP_THRESHOLD: usize = 3;
pub const DEFAULT_FLIP_FLOP_WINDOW_SECS: f64 = 30.0;
pub const DEFAULT_GRATUITOUS_THRESHOLD: usize = 10;
pub const DEFAULT_GRATUITOUS_WINDOW_SECS: f64 = 10.0;
pub const DEFAULT_ARP_COOLDOWN_SECS: f64 = 30.0;
pub const DEFAULT_MAX_BINDINGS: usize = 4096;
impl Default for ArpGuardConfig {
    fn default() -> Self {
        ArpGuardConfig {
            flip_flop_threshold: DEFAULT_FLIP_FLOP_THRESHOLD,
            flip_flop_window_secs: DEFAULT_FLIP_FLOP_WINDOW_SECS,
            gratuitous_threshold: DEFAULT_GRATUITOUS_THRESHOLD,
            gratuitous_window_secs: DEFAULT_GRATUITOUS_WINDOW_SECS,
            cooldown_secs: DEFAULT_ARP_COOLDOWN_SECS,
            max_bindings: DEFAULT_MAX_BINDINGS,
        }
    }
}

struct Binding {
    mac: [u8; 6],
    flips: VecDeque<f64>,
}

/// Bounded, pure ARP-anomaly detector. Tracks the most-recently-observed `(ip -> mac)` binding
/// per claimed sender IP (never resolved from anywhere else — the binding IS the observation) to
/// catch a rapid re-claim of the same IP from a DIFFERENT mac (poisoning), and a per-source-MAC
/// gratuitous-ARP rate to catch a gratuitous-ARP flood. Malformed-field and sender/eth-mac
/// mismatch anomalies are stateless (evaluated directly from one `ArpObs`).
pub struct ArpGuard {
    cfg: ArpGuardConfig,
    bindings: HashMap<Ipv4Addr, Binding>,
    binding_order: VecDeque<Ipv4Addr>,
    gratuitous_window: HashMap<[u8; 6], VecDeque<f64>>,
    gratuitous_order: VecDeque<[u8; 6]>,
    last_malformed_alert: Option<f64>,
    last_mismatch_alert: Option<f64>,
    last_flip_flop_alert: Option<f64>,
    last_gratuitous_alert: Option<f64>,
}
impl ArpGuard {
    pub fn new(cfg: ArpGuardConfig) -> Self {
        ArpGuard {
            cfg,
            bindings: HashMap::new(),
            binding_order: VecDeque::new(),
            gratuitous_window: HashMap::new(),
            gratuitous_order: VecDeque::new(),
            last_malformed_alert: None,
            last_mismatch_alert: None,
            last_flip_flop_alert: None,
            last_gratuitous_alert: None,
        }
    }

    fn cooled_down(last: &mut Option<f64>, now: f64, cooldown: f64) -> bool {
        if let Some(t) = *last {
            if now - t < cooldown {
                return false;
            }
        }
        *last = Some(now);
        true
    }

    fn evict_bindings_if_full(&mut self) {
        let cap = self.cfg.max_bindings.max(1);
        while self.bindings.len() >= cap {
            match self.binding_order.pop_front() {
                Some(old) => {
                    self.bindings.remove(&old);
                }
                None => break,
            }
        }
    }

    fn evict_gratuitous_if_full(&mut self) {
        let cap = self.cfg.max_bindings.max(1);
        while self.gratuitous_window.len() >= cap {
            match self.gratuitous_order.pop_front() {
                Some(old) => {
                    self.gratuitous_window.remove(&old);
                }
                None => break,
            }
        }
    }

    /// Feed one parsed ARP observation. Returns at most one alert per call, in priority order:
    /// malformed fields (the packet itself is invalid — cannot trust anything else in it) →
    /// sender/eth-mac mismatch (a single-frame tell, independent of history) → binding flip-flop
    /// (needs the per-IP history this call also updates) → gratuitous-ARP flood (needs the
    /// per-source-mac history this call also updates).
    pub fn observe(&mut self, now: f64, obs: &ArpObs) -> Option<L2Alert> {
        if obs.is_malformed() {
            if !Self::cooled_down(&mut self.last_malformed_alert, now, self.cfg.cooldown_secs) {
                return None;
            }
            return Some(L2Alert {
                ts: now,
                category: "arp_spoof",
                rule_id: ARP_SPOOF_RULE_ID,
                rule_msg: ARP_SPOOF_MSG,
                mitre: "T1557.002",
                severity: SEV_HIGH,
                confidence: 0.90,
                reason: "malformed_fields",
                src_mac: Some(obs.eth_src_mac),
                claimed_ip: None,
                detail: format!(
                    "malformed ARP header (htype={}, ptype=0x{:04x}, hlen={}, plen={}) — not a valid \
                     Ethernet/IPv4 address-resolution packet",
                    obs.htype, obs.ptype, obs.hlen, obs.plen
                ),
            });
        }

        // Still falls through to record the binding below even when the mismatch alert itself is
        // cooling down — the flip-flop/gratuitous trackers must not silently miss activity during
        // a cooldown just because we chose not to emit a SECOND alert for the same window.
        if obs.eth_mismatch() && Self::cooled_down(&mut self.last_mismatch_alert, now, self.cfg.cooldown_secs) {
            return Some(L2Alert {
                ts: now,
                category: "arp_spoof",
                rule_id: ARP_SPOOF_RULE_ID,
                rule_msg: ARP_SPOOF_MSG,
                mitre: "T1557.002",
                severity: SEV_HIGH,
                confidence: 0.95,
                reason: "eth_mismatch",
                src_mac: Some(obs.eth_src_mac),
                claimed_ip: Some(obs.sender_ip),
                detail: format!(
                    "ARP sender-mac {} disagrees with the Ethernet frame's own source mac {} for claimed ip {}",
                    mac_str(obs.sender_mac),
                    mac_str(obs.eth_src_mac),
                    obs.sender_ip
                ),
            });
        }

        if let Some(alert) = self.check_flip_flop(now, obs) {
            return Some(alert);
        }

        if obs.is_gratuitous() {
            if let Some(alert) = self.check_gratuitous_flood(now, obs) {
                return Some(alert);
            }
        }

        None
    }

    fn check_flip_flop(&mut self, now: f64, obs: &ArpObs) -> Option<L2Alert> {
        let cutoff = now - self.cfg.flip_flop_window_secs;
        match self.bindings.get_mut(&obs.sender_ip) {
            Some(b) if b.mac != obs.sender_mac => {
                b.flips.push_back(now);
                while b.flips.front().is_some_and(|&t| t < cutoff) {
                    b.flips.pop_front();
                }
                let old_mac = b.mac;
                b.mac = obs.sender_mac;
                let flip_count = b.flips.len();
                if flip_count < self.cfg.flip_flop_threshold {
                    return None;
                }
                if !Self::cooled_down(&mut self.last_flip_flop_alert, now, self.cfg.cooldown_secs) {
                    return None;
                }
                Some(L2Alert {
                    ts: now,
                    category: "arp_spoof",
                    rule_id: ARP_SPOOF_RULE_ID,
                    rule_msg: ARP_SPOOF_MSG,
                    mitre: "T1557.002",
                    severity: SEV_HIGH,
                    confidence: (0.60 + flip_count as f64 * 0.05).min(0.95),
                    reason: "binding_flip_flop",
                    src_mac: Some(obs.eth_src_mac),
                    claimed_ip: Some(obs.sender_ip),
                    detail: format!(
                        "{} claimed by {} distinct MACs within {:.0}s (last: {} -> {}) — binding flip-flop / poisoning",
                        obs.sender_ip,
                        flip_count,
                        self.cfg.flip_flop_window_secs,
                        mac_str(old_mac),
                        mac_str(obs.sender_mac)
                    ),
                })
            }
            Some(_) => None, // same mac re-observed — nothing new
            None => {
                self.evict_bindings_if_full();
                self.binding_order.push_back(obs.sender_ip);
                self.bindings.insert(obs.sender_ip, Binding { mac: obs.sender_mac, flips: VecDeque::new() });
                None
            }
        }
    }

    fn check_gratuitous_flood(&mut self, now: f64, obs: &ArpObs) -> Option<L2Alert> {
        if !self.gratuitous_window.contains_key(&obs.sender_mac) {
            self.evict_gratuitous_if_full();
            self.gratuitous_order.push_back(obs.sender_mac);
            self.gratuitous_window.insert(obs.sender_mac, VecDeque::new());
        }
        let win = self.gratuitous_window.get_mut(&obs.sender_mac).expect("just inserted above");
        win.push_back(now);
        let cutoff = now - self.cfg.gratuitous_window_secs;
        while win.front().is_some_and(|&t| t < cutoff) {
            win.pop_front();
        }
        let count = win.len();
        if count < self.cfg.gratuitous_threshold {
            return None;
        }
        if !Self::cooled_down(&mut self.last_gratuitous_alert, now, self.cfg.cooldown_secs) {
            return None;
        }
        Some(L2Alert {
            ts: now,
            category: "arp_spoof",
            rule_id: ARP_SPOOF_RULE_ID,
            rule_msg: ARP_SPOOF_MSG,
            mitre: "T1557.002",
            severity: SEV_MEDIUM,
            confidence: (0.55 + count as f64 * 0.01).min(0.90),
            reason: "gratuitous_flood",
            src_mac: Some(obs.sender_mac),
            claimed_ip: Some(obs.sender_ip),
            detail: format!(
                "{} gratuitous ARPs from this source within {:.0}s (>= threshold {})",
                count, self.cfg.gratuitous_window_secs, self.cfg.gratuitous_threshold
            ),
        })
    }
}

// ---------------------------------------------------------------------------------------------
// 4. Malformed frame / L1-L2 fuzzing — deterministic, stateless (see `dpi::frame_anomaly_reason`).
// ---------------------------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct MalformedFrameConfig {
    pub min_len: usize,
    pub max_len: usize,
    /// A fuzzer can send malformed frames far faster than a human operator wants events for —
    /// bound the alert rate itself (the underlying nft/BPF drop, once real — see `l2_responder`
    /// — has no such rate limit; this is purely about not flooding the events file).
    pub cooldown_secs: f64,
}
impl Default for MalformedFrameConfig {
    fn default() -> Self {
        MalformedFrameConfig {
            min_len: crate::dpi::DEFAULT_MIN_FRAME_LEN,
            max_len: crate::dpi::DEFAULT_MAX_FRAME_LEN,
            cooldown_secs: 10.0,
        }
    }
}

/// Stateless-detection + rate-limited-alerting wrapper around `dpi::frame_anomaly_reason`.
pub struct MalformedFrameGate {
    cfg: MalformedFrameConfig,
    last_alert_ts: Option<f64>,
    /// F6: this host's own interface MAC(s). Locally-originated GSO/TSO super-frames sourced from
    /// these are exempt from the oversize check (see `with_local_macs`). Empty = no exemption
    /// (the pre-F6 behavior), so existing `new(cfg)` callers are unchanged.
    local_macs: Vec<[u8; 6]>,
}
impl MalformedFrameGate {
    pub fn new(cfg: MalformedFrameConfig) -> Self {
        MalformedFrameGate { cfg, last_alert_ts: None, local_macs: Vec::new() }
    }

    /// F6: register this host's own interface MAC(s) so locally-originated GSO/TSO super-frames
    /// (which legitimately exceed MTU pre-segmentation on the egress mirror) aren't mis-flagged as
    /// oversized malformed frames. A remote/attacker MAC is never trusted — the exemption requires
    /// BOTH the local-MAC source AND a well-formed IPv4 TCP/UDP shape (see
    /// `dpi::frame_anomaly_reason_local`), so a spoofed local MAC on a genuinely malformed frame
    /// still fires.
    pub fn with_local_macs(mut self, local_macs: Vec<[u8; 6]>) -> Self {
        self.local_macs = local_macs;
        self
    }

    /// `frame` is the RAW captured bytes (any ethertype, any length). Returns `Some(alert)` iff
    /// `dpi::frame_anomaly_reason` flags it AND the alert-rate cooldown has elapsed (detection
    /// itself is never suppressed by the cooldown — only how often we log it is).
    pub fn observe(&mut self, now: f64, frame: &[u8]) -> Option<L2Alert> {
        let reason = crate::dpi::frame_anomaly_reason_local(
            frame,
            self.cfg.min_len,
            self.cfg.max_len,
            &self.local_macs,
        )?;
        if let Some(last) = self.last_alert_ts {
            if now - last < self.cfg.cooldown_secs {
                return None;
            }
        }
        self.last_alert_ts = Some(now);
        let src_mac = crate::dpi::eth_addrs(frame).map(|(_, src)| src);
        Some(L2Alert {
            ts: now,
            category: "l2_malformed",
            rule_id: L2_MALFORMED_RULE_ID,
            rule_msg: L2_MALFORMED_MSG,
            mitre: "T1499.004",
            severity: SEV_MEDIUM,
            confidence: 0.90,
            reason: "malformed_frame",
            src_mac,
            claimed_ip: None,
            detail: reason.to_string(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MAC_A: [u8; 6] = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];
    const MAC_B: [u8; 6] = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
    const BCAST: [u8; 6] = [0xff, 0xff, 0xff, 0xff, 0xff, 0xff];

    fn rand_mac(i: u8) -> [u8; 6] {
        [0x02, 0x00, 0x00, 0x00, 0x00, i] // locally-administered, distinct per i
    }

    // ---- MacFloodTracker ------------------------------------------------------------------

    #[test]
    fn mac_flood_fires_when_distinct_macs_cross_threshold() {
        let mut t = MacFloodTracker::new(MacFloodConfig {
            threshold: 20,
            window_secs: 10.0,
            cooldown_secs: 30.0,
            max_tracked: 4096,
            port_role: PortRole::Access,
            ..Default::default()
        });
        let mut fired = false;
        for i in 0..30u8 {
            if t.observe(100.0 + i as f64 * 0.01, rand_mac(i)).is_some() {
                fired = true;
            }
        }
        assert!(fired, "20+ distinct source MACs on a genuine ACCESS port must still trip mac_flood");
    }

    #[test]
    fn mac_flood_never_fires_on_benign_baseline_traffic() {
        // A handful of normal, stable hosts chattering — well under the threshold.
        let mut t = MacFloodTracker::new(MacFloodConfig::default());
        for i in 0..1000u32 {
            let mac = rand_mac((i % 5) as u8); // only 5 distinct macs, ever
            assert!(t.observe(100.0 + i as f64 * 0.01, mac).is_none(), "benign traffic (5 stable hosts) must never alert");
        }
    }

    #[test]
    fn mac_flood_alert_carries_no_single_attributable_source() {
        let mut t = MacFloodTracker::new(MacFloodConfig {
            threshold: 5,
            window_secs: 10.0,
            cooldown_secs: 30.0,
            max_tracked: 4096,
            port_role: PortRole::Access,
            ..Default::default()
        });
        let mut alert = None;
        for i in 0..10u8 {
            if let Some(a) = t.observe(100.0 + i as f64 * 0.01, rand_mac(i)) {
                alert = Some(a);
            }
        }
        let a = alert.expect("must fire");
        assert!(a.src_mac.is_none(), "a link-wide flood must never name one attributable source mac");
        assert_eq!(a.rule_id, MAC_FLOOD_RULE_ID);
    }

    #[test]
    fn mac_flood_respects_cooldown() {
        let mut t = MacFloodTracker::new(MacFloodConfig {
            threshold: 5,
            window_secs: 10.0,
            cooldown_secs: 100.0,
            max_tracked: 4096,
            port_role: PortRole::Access,
            ..Default::default()
        });
        let mut fires = 0;
        for i in 0..20u8 {
            if t.observe(100.0 + i as f64 * 0.01, rand_mac(i)).is_some() {
                fires += 1;
            }
        }
        assert_eq!(fires, 1, "one flood burst yields one alert while cooling down");
    }

    // ---- D12 fix: topology-aware mac-flood (the busy-uplink/AP false-positive) ---------------

    /// THE legit-passes proof: a busy office/café LAN's ordinary churn (40 distinct client MACs
    /// seen on the AP/uplink within one window — completely normal for a shared radio/switch
    /// uplink) must NEVER fire mac_flood once the link is correctly classified `UplinkBridge`.
    #[test]
    fn mac_flood_never_fires_on_a_busy_uplink_with_many_legit_macs() {
        let mut t = MacFloodTracker::new(MacFloodConfig { port_role: PortRole::UplinkBridge, ..Default::default() });
        let mut fired = false;
        for i in 0..40u8 {
            if t.observe(100.0 + i as f64 * 0.01, rand_mac(i)).is_some() {
                fired = true;
            }
        }
        assert!(!fired, "40 distinct legit client MACs on an uplink/AP port must never look like a flood");
    }

    /// The SAME 40-distinct-MAC pattern on a genuine ACCESS port (a single-client port that should
    /// never see more than a handful of MACs) still correctly fires — the fix narrows WHERE the
    /// alert applies, it does not weaken detection on a real access port.
    #[test]
    fn mac_flood_still_fires_on_an_access_port_with_the_same_mac_count() {
        let mut t = MacFloodTracker::new(MacFloodConfig { port_role: PortRole::Access, ..Default::default() });
        let mut fired = false;
        for i in 0..40u8 {
            if t.observe(100.0 + i as f64 * 0.01, rand_mac(i)).is_some() {
                fired = true;
            }
        }
        assert!(fired, "40 distinct MACs on a genuine single-client access port is still a real mac-flood signal");
    }

    /// THE attack-still-caught proof: a genuinely high-volume mac-flood (hundreds of spoofed MACs
    /// — the actual attack the detector exists for) still fires even on an `UplinkBridge` port,
    /// because it clears the sharply-higher-but-still-finite uplink bar.
    #[test]
    fn mac_flood_still_fires_on_an_uplink_when_the_volume_is_genuinely_a_flood() {
        let mut t = MacFloodTracker::new(MacFloodConfig { port_role: PortRole::UplinkBridge, window_secs: 10.0, max_tracked: 8192, ..Default::default() });
        let mut fired = false;
        // rand_mac only covers u8 (256 values); vary a second byte too for a genuinely large burst.
        'outer: for hi in 0..3u8 {
            for lo in 0..=255u8 {
                let mac = [0x02, 0x00, 0x00, 0x00, hi, lo];
                if t.observe(100.0, mac).is_some() {
                    fired = true;
                    break 'outer;
                }
            }
        }
        assert!(fired, "an actual multi-hundred-MAC flood must still trip mac_flood even on an uplink/AP port");
    }

    // ---- port_role_for_interface — derives role from the SAME manifest data the reconciler uses --

    #[test]
    fn port_role_classifies_a_wan_uplink_as_access() {
        let uplinks = vec![hookprobe_manifest::types::ManifestUplink { name: "end0".into(), kind: "wired".into(), priority: 10 }];
        assert_eq!(port_role_for_interface("end0", &uplinks, &[]), PortRole::Access);
    }

    #[test]
    fn port_role_classifies_a_wifi_station_radio_as_access_and_ap_radio_as_uplink_bridge() {
        let radios = vec![
            hookprobe_manifest::types::WifiRadio { name: "wlan_sta0".into(), role: "station".into(), band: None },
            hookprobe_manifest::types::WifiRadio { name: "wlan0".into(), role: "ap".into(), band: None },
        ];
        assert_eq!(port_role_for_interface("wlan_sta0", &[], &radios), PortRole::Access);
        assert_eq!(port_role_for_interface("wlan0", &[], &radios), PortRole::UplinkBridge);
    }

    #[test]
    fn port_role_defaults_an_unlisted_interface_to_uplink_bridge() {
        // An Ethernet port that is neither a declared WAN uplink nor a known radio is, in practice,
        // the LAN/bridge side on this device — defaulting it to Access would reopen D12.
        assert_eq!(port_role_for_interface("hp-br0", &[], &[]), PortRole::UplinkBridge);
    }

    // ---- BroadcastStormTracker --------------------------------------------------------------

    #[test]
    fn broadcast_storm_fires_on_high_rate_from_one_source() {
        let mut t = BroadcastStormTracker::new(BroadcastStormConfig { threshold: 50, window_secs: 5.0, cooldown_secs: 30.0, max_sources: 4096 });
        let mut fired = false;
        for i in 0..60u16 {
            if t.observe(100.0 + i as f64 * 0.01, MAC_A, BCAST).is_some() {
                fired = true;
            }
        }
        assert!(fired);
    }

    #[test]
    fn broadcast_storm_ignores_unicast_traffic() {
        let mut t = BroadcastStormTracker::new(BroadcastStormConfig { threshold: 5, window_secs: 5.0, cooldown_secs: 30.0, max_sources: 4096 });
        for i in 0..100u16 {
            assert!(t.observe(100.0 + i as f64 * 0.01, MAC_A, MAC_B).is_none(), "unicast dst must never count toward a storm");
        }
    }

    #[test]
    fn broadcast_storm_benign_baseline_does_not_fire() {
        // A normal amount of ARP/DHCP broadcast chatter — well under threshold.
        let mut t = BroadcastStormTracker::new(BroadcastStormConfig::default());
        for i in 0..10u16 {
            assert!(t.observe(100.0 + i as f64, MAC_A, BCAST).is_none());
        }
    }

    #[test]
    fn is_broadcast_or_multicast_recognizes_lldp_cdp_and_plain_broadcast() {
        assert!(is_broadcast_or_multicast(BCAST));
        assert!(is_broadcast_or_multicast([0x01, 0x80, 0xc2, 0x00, 0x00, 0x0e]), "LLDP");
        assert!(is_broadcast_or_multicast([0x01, 0x00, 0x0c, 0xcc, 0xcc, 0xcc]), "CDP");
        assert!(is_broadcast_or_multicast([0x01, 0x00, 0x5e, 0x00, 0x00, 0x01]), "IPv4 multicast");
        assert!(!is_broadcast_or_multicast(MAC_A), "a normal unicast address must not count");
    }

    // ---- D13 fix: exempt well-known service-discovery multicast (the mDNS/Bonjour false-positive) --

    const MDNS_V4: [u8; 6] = [0x01, 0x00, 0x5e, 0x00, 0x00, 0xfb];
    const MDNS_V6: [u8; 6] = [0x33, 0x33, 0x00, 0x00, 0x00, 0xfb];
    const SSDP_V4: [u8; 6] = [0x01, 0x00, 0x5e, 0x7f, 0xff, 0xfa];
    const LLMNR_V4: [u8; 6] = [0x01, 0x00, 0x5e, 0x00, 0x00, 0xfc];

    /// THE legit-passes proof: a chatty-but-legitimate smart-TV/printer doing an mDNS/Bonjour burst
    /// well past what would otherwise be a "storm" threshold must never fire broadcast_storm.
    #[test]
    fn broadcast_storm_never_fires_on_an_mdns_burst() {
        let mut t = BroadcastStormTracker::new(BroadcastStormConfig { threshold: 50, window_secs: 5.0, cooldown_secs: 30.0, max_sources: 4096 });
        for i in 0..200u16 {
            assert!(t.observe(100.0 + i as f64 * 0.01, MAC_A, MDNS_V4).is_none(), "mDNS v4 must never count toward a storm");
        }
    }

    #[test]
    fn broadcast_storm_exempts_ssdp_llmnr_and_ipv6_mdns_too() {
        let mut t = BroadcastStormTracker::new(BroadcastStormConfig { threshold: 20, window_secs: 5.0, cooldown_secs: 30.0, max_sources: 4096 });
        for (name, group) in [("SSDP v4", SSDP_V4), ("LLMNR v4", LLMNR_V4), ("mDNS v6", MDNS_V6)] {
            for i in 0..50u16 {
                assert!(t.observe(100.0 + i as f64 * 0.01, MAC_A, group).is_none(), "{name} must never count toward a storm");
            }
        }
    }

    /// THE attack-still-caught proof: a RAW broadcast flood (not a named service-discovery group)
    /// still counts and still fires — the exemption is narrow, not a blanket multicast carve-out.
    #[test]
    fn broadcast_storm_still_fires_on_a_raw_broadcast_flood() {
        let mut t = BroadcastStormTracker::new(BroadcastStormConfig { threshold: 50, window_secs: 5.0, cooldown_secs: 30.0, max_sources: 4096 });
        let mut fired = false;
        for i in 0..60u16 {
            if t.observe(100.0 + i as f64 * 0.01, MAC_A, BCAST).is_some() {
                fired = true;
            }
        }
        assert!(fired, "a raw ff:ff:ff:ff:ff:ff broadcast flood must still trip the storm detector");
    }

    /// A non-exempt multicast group (not one of the named service-discovery addresses) also still
    /// counts in full — only the specific named groups are carved out.
    #[test]
    fn broadcast_storm_still_fires_on_a_non_exempt_multicast_flood() {
        let non_exempt_group = [0x01, 0x00, 0x5e, 0x12, 0x34, 0x56]; // an arbitrary, unlisted IPv4 mcast group
        let mut t = BroadcastStormTracker::new(BroadcastStormConfig { threshold: 50, window_secs: 5.0, cooldown_secs: 30.0, max_sources: 4096 });
        let mut fired = false;
        for i in 0..60u16 {
            if t.observe(100.0 + i as f64 * 0.01, MAC_A, non_exempt_group).is_some() {
                fired = true;
            }
        }
        assert!(fired, "a flood of a NON-exempt multicast group must still trip the storm detector");
    }

    #[test]
    fn is_exempt_multicast_covers_the_named_groups_and_nothing_else() {
        for g in [MDNS_V4, MDNS_V6, SSDP_V4, LLMNR_V4, [0x33, 0x33, 0x00, 0x01, 0x00, 0x03], [0x33, 0x33, 0x00, 0x00, 0x00, 0x01], [0x33, 0x33, 0x00, 0x00, 0x00, 0x02], [0x33, 0x33, 0x00, 0x00, 0x00, 0x0c]] {
            assert!(is_exempt_multicast(g), "{g:?} must be exempt");
        }
        assert!(!is_exempt_multicast(BCAST), "raw broadcast must never be exempt");
        assert!(!is_exempt_multicast([0x01, 0x00, 0x5e, 0x12, 0x34, 0x56]), "an arbitrary multicast group must never be exempt");
    }

    // ---- ArpGuard ---------------------------------------------------------------------------

    fn arp(sender_mac: [u8; 6], sender_ip: [u8; 4], target_ip: [u8; 4], eth_src: [u8; 6]) -> ArpObs {
        ArpObs {
            eth_src_mac: eth_src,
            htype: 1,
            ptype: 0x0800,
            hlen: 6,
            plen: 4,
            opcode: 1,
            sender_mac,
            sender_ip: Ipv4Addr::new(sender_ip[0], sender_ip[1], sender_ip[2], sender_ip[3]),
            target_mac: [0; 6],
            target_ip: Ipv4Addr::new(target_ip[0], target_ip[1], target_ip[2], target_ip[3]),
        }
    }

    #[test]
    fn arp_guard_benign_traffic_never_fires() {
        let mut g = ArpGuard::new(ArpGuardConfig::default());
        for i in 0..20u8 {
            let obs = arp(MAC_A, [10, 0, 0, 5], [10, 0, 0, 1], MAC_A);
            assert!(g.observe(100.0 + i as f64, &obs).is_none(), "a stable, consistent binding must never alert");
        }
    }

    #[test]
    fn arp_guard_flags_binding_flip_flop() {
        let mut g = ArpGuard::new(ArpGuardConfig { flip_flop_threshold: 3, flip_flop_window_secs: 30.0, ..Default::default() });
        let victim_ip = [10, 0, 0, 9];
        let mut fired = false;
        // The real owner, then repeated attempts by a DIFFERENT mac claiming the same IP.
        g.observe(100.0, &arp(MAC_A, victim_ip, [10, 0, 0, 1], MAC_A));
        for (i, m) in [MAC_B, MAC_A, MAC_B].into_iter().enumerate() {
            let obs = arp(m, victim_ip, [10, 0, 0, 1], m);
            if g.observe(101.0 + i as f64, &obs).is_some() {
                fired = true;
            }
        }
        assert!(fired, "an IP claimed by several distinct MACs in a short window must flag a flip-flop");
    }

    #[test]
    fn arp_guard_flags_eth_mismatch() {
        let mut g = ArpGuard::new(ArpGuardConfig::default());
        // ARP payload claims MAC_A but the Ethernet frame's OWN source is MAC_B.
        let obs = arp(MAC_A, [10, 0, 0, 5], [10, 0, 0, 1], MAC_B);
        let a = g.observe(100.0, &obs).expect("mismatch must fire immediately, no history needed");
        assert_eq!(a.reason, "eth_mismatch");
        assert_eq!(a.rule_id, ARP_SPOOF_RULE_ID);
    }

    #[test]
    fn arp_guard_flags_malformed_fields() {
        let mut g = ArpGuard::new(ArpGuardConfig::default());
        let mut obs = arp(MAC_A, [10, 0, 0, 5], [10, 0, 0, 1], MAC_A);
        obs.hlen = 8; // invalid
        let a = g.observe(100.0, &obs).expect("malformed ARP must fire");
        assert_eq!(a.reason, "malformed_fields");
    }

    #[test]
    fn arp_guard_flags_gratuitous_flood() {
        let mut g = ArpGuard::new(ArpGuardConfig { gratuitous_threshold: 5, gratuitous_window_secs: 10.0, ..Default::default() });
        let mut fired = false;
        for i in 0..10u8 {
            // sender == target: gratuitous
            let obs = arp(MAC_A, [10, 0, 0, 5], [10, 0, 0, 5], MAC_A);
            if g.observe(100.0 + i as f64 * 0.1, &obs).is_some() {
                fired = true;
            }
        }
        assert!(fired, "a rapid gratuitous-ARP burst from one source must flag a flood");
    }

    #[test]
    fn arp_guard_low_rate_gratuitous_is_benign() {
        let mut g = ArpGuard::new(ArpGuardConfig::default());
        // One gratuitous ARP every 60s — normal IP-conflict/failover behavior, not a flood.
        for i in 0..3u32 {
            let obs = arp(MAC_A, [10, 0, 0, 5], [10, 0, 0, 5], MAC_A);
            assert!(g.observe(100.0 + i as f64 * 60.0, &obs).is_none());
        }
    }

    // ---- MalformedFrameGate -------------------------------------------------------------------

    #[test]
    fn malformed_frame_gate_fires_on_a_runt_frame() {
        let mut g = MalformedFrameGate::new(MalformedFrameConfig::default());
        let runt = vec![0u8; 20];
        let a = g.observe(100.0, &runt).expect("runt frame must fire");
        assert_eq!(a.rule_id, L2_MALFORMED_RULE_ID);
        assert_eq!(a.category, "l2_malformed");
    }

    #[test]
    fn malformed_frame_gate_silent_on_benign_frame() {
        let mut g = MalformedFrameGate::new(MalformedFrameConfig::default());
        let mut benign = vec![0u8; 64];
        benign[0..6].copy_from_slice(&[1, 2, 3, 4, 5, 6]);
        benign[6..12].copy_from_slice(&MAC_A);
        benign[12..14].copy_from_slice(&0x0800u16.to_be_bytes());
        assert!(g.observe(100.0, &benign).is_none());
    }

    /// 2026-07-05 false-positive fix (EDR #7): a bare 54-byte TCP control segment (what every
    /// SYN/SYN-ACK/ACK/RST/FIN handshake or teardown packet looks like with no hardware wire
    /// padding on a mirror-sink capture) must NOT fire `l2_malformed` — before the fix, this
    /// tripped rule_id 1000033 ("runt frame") on literally every TCP connection, polluting the
    /// events stream on entirely benign traffic (see `dpi::frame_anomaly_reason`'s doc for the
    /// full rationale this gate now relies on).
    #[test]
    fn malformed_frame_gate_does_not_fire_on_a_bare_54_byte_tcp_handshake_segment() {
        let mut g = MalformedFrameGate::new(MalformedFrameConfig::default());
        // 14 eth + 20 ipv4 (no options) + 20 tcp (no options), no payload = 54 bytes exactly.
        let mut f = vec![0u8; 14];
        f[0..6].copy_from_slice(&MAC_A);
        f[6..12].copy_from_slice(&MAC_B);
        f[12..14].copy_from_slice(&0x0800u16.to_be_bytes());
        let mut ip = vec![0u8; 20];
        ip[0] = 0x45; // v4, ihl 5
        ip[9] = 6; // tcp
        ip[12..16].copy_from_slice(&[10, 66, 0, 20]);
        ip[16..20].copy_from_slice(&[1, 1, 1, 1]);
        f.extend_from_slice(&ip);
        let mut tcp = vec![0u8; 20];
        tcp[0..2].copy_from_slice(&51000u16.to_be_bytes());
        tcp[2..4].copy_from_slice(&443u16.to_be_bytes());
        tcp[12] = 5 << 4; // data offset 5 (no options)
        tcp[13] = 0x10; // ACK
        f.extend_from_slice(&tcp);
        assert_eq!(f.len(), 54);
        assert!(g.observe(100.0, &f).is_none(), "a well-formed bare-ACK 54-byte control segment must never be l2_malformed");
    }

    #[test]
    fn malformed_frame_gate_respects_cooldown() {
        let mut g = MalformedFrameGate::new(MalformedFrameConfig { min_len: 60, max_len: 1522, cooldown_secs: 100.0 });
        let runt = vec![0u8; 20];
        assert!(g.observe(100.0, &runt).is_some());
        assert!(g.observe(100.5, &runt).is_none(), "must not flood the events file during cooldown");
        assert!(g.observe(300.0, &runt).is_some(), "must fire again after cooldown elapses");
    }

    #[test]
    fn l2_alert_json_round_trips_and_carries_expected_fields() {
        let a = L2Alert {
            ts: 1782900000.0,
            category: "arp_spoof",
            rule_id: ARP_SPOOF_RULE_ID,
            rule_msg: ARP_SPOOF_MSG,
            mitre: "T1557.002",
            severity: SEV_HIGH,
            confidence: 0.95,
            reason: "eth_mismatch",
            src_mac: Some(MAC_A),
            claimed_ip: Some(Ipv4Addr::new(10, 0, 0, 5)),
            detail: "test detail".to_string(),
        };
        let j = a.to_json();
        let v: serde_json::Value = serde_json::from_str(&j).expect("valid json");
        assert_eq!(v["rule_id"], 1_000_031);
        assert_eq!(v["category"], "arp_spoof");
        assert_eq!(v["reason"], "eth_mismatch");
        assert_eq!(v["src_mac"], "aa:bb:cc:dd:ee:ff");
        assert_eq!(v["claimed_ip"], "10.0.0.5");
    }
}
