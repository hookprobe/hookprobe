//! napse-dpi — deep-packet sensor on the mirror sink. Opens an AF_PACKET raw socket bound to the
//! mirror interface (`hp-mirror`, fed by the `tc-mirred` mirror of every NIC), parses each frame for
//! DNS/TLS/HTTP signals, and appends NAPSE flow records to `/var/lib/hookprobe/flows`. Out-of-band,
//! read-only on the wire; needs CAP_NET_RAW. The parsing is the tested `napse_loader::dpi` core.
//!
//! Also runs the packet-layer SYN port-scan detector (`napse_loader::portscan`): every TCP SYN on
//! the mirror is fed to a per-source-IP fan-out tracker; when a source crosses
//! `NAPSE_PORTSCAN_THRESHOLD` distinct destination ports within `NAPSE_PORTSCAN_WINDOW_SECS`, one
//! alert (rule 1000003, identical to the wasm engine's conntrack-fed rule) is appended to the
//! EVENTS stream — NOT the flows stream — so the evidence-graph ingester picks it up as a
//! detection. This closes the gap where a fast scan's closed-port SYNs get RST'd before conntrack
//! (polled every 5s by senzorium-flow) ever accumulates them.
//!
//! 2026-07-05 threat-model fix (CRITICAL #1): EVERY TCP packet on the mirror (both directions,
//! not just SYNs) also feeds `napse_loader::confirm::HandshakeTracker` — a claimed source IP is
//! only `confirmed` once it completes a real, validated 3-way handshake as seen on the wire (an
//! off-path spoofer can never do this — see `confirm.rs`'s module doc). The port-scan alert's
//! `confirmed` bit is stamped from that independent tracker at emission time, and the
//! AEGIS responder (`hookprobe_manifest::scan_responder::decide`) refuses to enforce on anything
//! that isn't confirmed — this is what stops a spoofed-source SYN burst from quarantining an
//! innocent (possibly load-bearing, e.g. the device's own gateway/resolver) victim.

use anyhow::{bail, Context, Result};
use napse_loader::beacon;
use napse_loader::beacon::{BeaconConfig, BeaconTracker};
use napse_loader::capture::{self, CaptureConfig, FrameCapture};
use napse_loader::confirm::{HandshakeConfig, HandshakeTracker};
use napse_loader::dpi;
use napse_loader::l2guard;
use napse_loader::l2guard::{
    ArpGuard, ArpGuardConfig, BroadcastStormConfig, BroadcastStormTracker, MacFloodConfig, MacFloodTracker,
    MalformedFrameConfig, MalformedFrameGate,
};
use napse_loader::lateral;
use napse_loader::lateral::{LateralConfig, LateralMovementTracker};
use napse_loader::portscan;
use napse_loader::portscan::{
    IcmpSweepConfig, IcmpSweepTracker, PortScanConfig, PortScanTracker, SlowScanConfig, SlowScanTracker,
    UdpScanConfig, UdpScanTracker,
};
use std::collections::HashSet;
use std::fs::OpenOptions;
use std::io::Write;
use std::net::Ipv4Addr;
use std::os::fd::{FromRawFd, OwnedFd};
use std::time::{SystemTime, UNIX_EPOCH};

fn env_or(k: &str, d: &str) -> String {
    std::env::var(k).unwrap_or_else(|_| d.to_string())
}

/// Self-gate (arch F5 fix): this binary previously claimed capability-gating in its
/// module.yaml (`requires.capabilities: [capture]`) but never actually checked it — it
/// only implicitly depended on the mirror interface's *existence* (a bind() failure if
/// `hp-mirror` is absent), which is a proxy for "does the mirror exist", not "is capture
/// granted". Reads the signed Platform Manifest at startup and returns whether `cap` is
/// `capabilities.<cap>.state == "granted"` — mirrors `modules/ovs/config/ovs-bringup`'s
/// bash `granted() { [[ "$(jq ...)" == "granted" ]]; }` and napse-quarantine's loader.
/// A missing/unparseable manifest is treated as NOT granted (fail closed).
fn granted(cap: &str) -> bool {
    let path = env_or("MANIFEST", "/var/lib/hookprobe/manifest.json");
    let text = match std::fs::read_to_string(&path) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("napse-dpi: cannot read manifest {path} ({e}) — treating '{cap}' as not granted");
            return false;
        }
    };
    let m: hookprobe_manifest::Manifest = match serde_json::from_str(&text) {
        Ok(m) => m,
        Err(e) => {
            eprintln!("napse-dpi: cannot parse manifest {path} ({e}) — treating '{cap}' as not granted");
            return false;
        }
    };
    m.capabilities
        .get(cap)
        .map(|c| c.state == hookprobe_manifest::types::CapabilityState::Granted)
        .unwrap_or(false)
}

/// Parse an env var as the given numeric type; fall back to `d` (and warn) if unset or unparseable
/// so a typo'd knob degrades to the documented default instead of crashing the sensor.
fn env_num<T: std::str::FromStr>(k: &str, d: T) -> T {
    match std::env::var(k) {
        Ok(v) => v.parse().unwrap_or_else(|_| {
            eprintln!("napse-dpi: {k}={v:?} is not a valid number, using default");
            d
        }),
        Err(_) => d,
    }
}

fn portscan_config_from_env() -> PortScanConfig {
    PortScanConfig {
        threshold: env_num("NAPSE_PORTSCAN_THRESHOLD", portscan::DEFAULT_THRESHOLD),
        window_secs: env_num("NAPSE_PORTSCAN_WINDOW_SECS", portscan::DEFAULT_WINDOW_SECS),
        cooldown_secs: env_num("NAPSE_PORTSCAN_COOLDOWN_SECS", portscan::DEFAULT_COOLDOWN_SECS),
        max_sources: portscan::DEFAULT_MAX_SOURCES,
    }
}

/// 2026-07-07 low-and-slow coverage fix: the LONG-window counterpart to `portscan_config_from_env`
/// — see `portscan::SlowScanTracker`'s module doc for the evasion gap this closes (a scanner
/// probing a few ports per 10s window over several minutes never crosses the fast tracker's
/// 50-in-10s bar) and its two FP guards (per-target scoping, fast-scan dedup).
fn slowscan_config_from_env() -> SlowScanConfig {
    SlowScanConfig {
        threshold: env_num("SLOWSCAN_THRESHOLD", portscan::DEFAULT_SLOWSCAN_THRESHOLD),
        window_secs: env_num("SLOWSCAN_WINDOW_SECS", portscan::DEFAULT_SLOWSCAN_WINDOW_SECS),
        cooldown_secs: env_num("SLOWSCAN_COOLDOWN_SECS", portscan::DEFAULT_SLOWSCAN_COOLDOWN_SECS),
        max_sources: portscan::DEFAULT_SLOWSCAN_MAX_SOURCES,
        max_targets_per_source: portscan::DEFAULT_SLOWSCAN_MAX_TARGETS_PER_SOURCE,
    }
}

// ADR 0020 Phase-1a defensive: L1/L2 detector configs, same env-knob discipline as the port-scan
// and handshake-confirmation configs above (a typo'd env var degrades to the documented default,
// never crashes the sensor).

/// Parse a comma-separated list of IPv4 addresses from an env var (empty/unset → empty set).
/// Malformed entries are skipped with a warning rather than crashing the sensor — same
/// typo-degrades-to-default discipline as `env_num`.
fn env_ipv4_set(k: &str) -> HashSet<Ipv4Addr> {
    let raw = match std::env::var(k) {
        Ok(v) => v,
        Err(_) => return HashSet::new(),
    };
    raw.split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .filter_map(|s| match s.parse::<Ipv4Addr>() {
            Ok(ip) => Some(ip),
            Err(_) => {
                eprintln!("napse-dpi: {k} entry {s:?} is not a valid IPv4 address, skipping");
                None
            }
        })
        .collect()
}

/// Parse a comma-separated list of u16 ports from an env var, seeded with `defaults` (NTP/123 for
/// the beacon allowlist — see `beacon::DEFAULT_BEACON_ALLOWLIST_PORTS`).
fn env_port_set(k: &str, defaults: &[u16]) -> HashSet<u16> {
    let mut set: HashSet<u16> = defaults.iter().copied().collect();
    if let Ok(raw) = std::env::var(k) {
        for s in raw.split(',').map(str::trim).filter(|s| !s.is_empty()) {
            match s.parse::<u16>() {
                Ok(p) => {
                    set.insert(p);
                }
                Err(_) => eprintln!("napse-dpi: {k} entry {s:?} is not a valid port, skipping"),
            }
        }
    }
    set
}

/// C2 beacon / periodicity detector (rule 1000040, T1071.001/T1102 — see `beacon` module doc for
/// the full detection rationale + FP-guard analysis). `NAPSE_BEACON_ALLOWLIST_IPS` is the
/// operator's own configured update/telemetry endpoints (comma-separated IPv4); NTP (port 123) is
/// exempted unconditionally by default, extendable via `NAPSE_BEACON_ALLOWLIST_PORTS`.
fn beacon_config_from_env() -> BeaconConfig {
    BeaconConfig {
        min_connections: env_num("NAPSE_BEACON_MIN_CONNECTIONS", beacon::DEFAULT_BEACON_MIN_CONNECTIONS),
        window_secs: env_num("NAPSE_BEACON_WINDOW_SECS", beacon::DEFAULT_BEACON_WINDOW_SECS),
        max_cv: env_num("NAPSE_BEACON_MAX_CV", beacon::DEFAULT_BEACON_MAX_CV),
        min_mean_interval_secs: env_num(
            "NAPSE_BEACON_MIN_MEAN_INTERVAL_SECS",
            beacon::DEFAULT_BEACON_MIN_MEAN_INTERVAL_SECS,
        ),
        cooldown_secs: env_num("NAPSE_BEACON_COOLDOWN_SECS", beacon::DEFAULT_BEACON_COOLDOWN_SECS),
        max_tracked: env_num("NAPSE_BEACON_MAX_TRACKED", beacon::DEFAULT_BEACON_MAX_TRACKED),
        allowlist_ports: env_port_set("NAPSE_BEACON_ALLOWLIST_PORTS", beacon::DEFAULT_BEACON_ALLOWLIST_PORTS),
        allowlist_ips: env_ipv4_set("NAPSE_BEACON_ALLOWLIST_IPS"),
    }
}

/// East-west lateral-movement detector (rule 1000041, T1021 — see `lateral` module doc).
fn lateral_config_from_env() -> LateralConfig {
    LateralConfig {
        threshold: env_num("NAPSE_LATERAL_THRESHOLD", lateral::DEFAULT_LATERAL_THRESHOLD),
        window_secs: env_num("NAPSE_LATERAL_WINDOW_SECS", lateral::DEFAULT_LATERAL_WINDOW_SECS),
        cooldown_secs: env_num("NAPSE_LATERAL_COOLDOWN_SECS", lateral::DEFAULT_LATERAL_COOLDOWN_SECS),
        max_sources: env_num("NAPSE_LATERAL_MAX_SOURCES", lateral::DEFAULT_LATERAL_MAX_SOURCES),
    }
}

/// D12 fix: which [`l2guard::PortRole`] the monitored LAN-facing interface is — read from the
/// signed Platform Manifest's `network.uplinks`/`network.wifi_radios` (the SAME classification the
/// reconciler already keys off — see `l2guard::port_role_for_interface`'s doc), never a fresh
/// hardware re-probe. `NAPSE_MACFLOOD_PORT_ROLE=access|uplink` overrides it explicitly for a
/// deployment this heuristic gets wrong; unset uses the manifest-derived value. A missing/
/// unparseable manifest falls back to `PortRole::default()` (`UplinkBridge` — the safer default;
/// see that type's doc), matching `granted()`'s fail-safe-but-not-fail-open discipline for reading
/// the same file.
fn mac_flood_port_role() -> l2guard::PortRole {
    if let Ok(v) = std::env::var("NAPSE_MACFLOOD_PORT_ROLE") {
        match v.to_ascii_lowercase().as_str() {
            "access" => return l2guard::PortRole::Access,
            "uplink" | "uplink_bridge" | "uplink-bridge" => return l2guard::PortRole::UplinkBridge,
            _ => eprintln!("napse-dpi: NAPSE_MACFLOOD_PORT_ROLE={v:?} not recognized, deriving from the manifest instead"),
        }
    }
    let iface = env_or("NAPSE_MACFLOOD_LAN_IFACE", "wlan0");
    let path = env_or("MANIFEST", "/var/lib/hookprobe/manifest.json");
    let manifest: hookprobe_manifest::Manifest = match std::fs::read_to_string(&path).ok().and_then(|t| serde_json::from_str(&t).ok()) {
        Some(m) => m,
        None => {
            eprintln!("napse-dpi: cannot read/parse manifest {path} — defaulting mac-flood port role to {:?}", l2guard::PortRole::default());
            return l2guard::PortRole::default();
        }
    };
    l2guard::port_role_for_interface(&iface, &manifest.network.uplinks, &manifest.network.wifi_radios)
}

fn mac_flood_config_from_env() -> MacFloodConfig {
    MacFloodConfig {
        threshold: env_num("NAPSE_MACFLOOD_THRESHOLD", l2guard::DEFAULT_MAC_FLOOD_THRESHOLD),
        uplink_threshold: env_num("NAPSE_MACFLOOD_UPLINK_THRESHOLD", l2guard::DEFAULT_MAC_FLOOD_UPLINK_THRESHOLD),
        port_role: mac_flood_port_role(),
        window_secs: env_num("NAPSE_MACFLOOD_WINDOW_SECS", l2guard::DEFAULT_MAC_FLOOD_WINDOW_SECS),
        cooldown_secs: env_num("NAPSE_MACFLOOD_COOLDOWN_SECS", l2guard::DEFAULT_MAC_FLOOD_COOLDOWN_SECS),
        max_tracked: l2guard::DEFAULT_MAC_FLOOD_MAX_TRACKED,
    }
}

fn broadcast_storm_config_from_env() -> BroadcastStormConfig {
    BroadcastStormConfig {
        threshold: env_num("NAPSE_BROADCAST_THRESHOLD", l2guard::DEFAULT_BROADCAST_THRESHOLD),
        window_secs: env_num("NAPSE_BROADCAST_WINDOW_SECS", l2guard::DEFAULT_BROADCAST_WINDOW_SECS),
        cooldown_secs: env_num("NAPSE_BROADCAST_COOLDOWN_SECS", l2guard::DEFAULT_BROADCAST_COOLDOWN_SECS),
        max_sources: l2guard::DEFAULT_BROADCAST_MAX_SOURCES,
    }
}

fn arp_guard_config_from_env() -> ArpGuardConfig {
    ArpGuardConfig {
        flip_flop_threshold: env_num("NAPSE_ARP_FLIPFLOP_THRESHOLD", l2guard::DEFAULT_FLIP_FLOP_THRESHOLD),
        flip_flop_window_secs: env_num("NAPSE_ARP_FLIPFLOP_WINDOW_SECS", l2guard::DEFAULT_FLIP_FLOP_WINDOW_SECS),
        gratuitous_threshold: env_num("NAPSE_ARP_GRATUITOUS_THRESHOLD", l2guard::DEFAULT_GRATUITOUS_THRESHOLD),
        gratuitous_window_secs: env_num("NAPSE_ARP_GRATUITOUS_WINDOW_SECS", l2guard::DEFAULT_GRATUITOUS_WINDOW_SECS),
        cooldown_secs: env_num("NAPSE_ARP_COOLDOWN_SECS", l2guard::DEFAULT_ARP_COOLDOWN_SECS),
        max_bindings: l2guard::DEFAULT_MAX_BINDINGS,
    }
}

fn malformed_frame_config_from_env() -> MalformedFrameConfig {
    MalformedFrameConfig {
        min_len: env_num("NAPSE_L2_MIN_FRAME_LEN", dpi::DEFAULT_MIN_FRAME_LEN),
        max_len: env_num("NAPSE_L2_MAX_FRAME_LEN", dpi::DEFAULT_MAX_FRAME_LEN),
        cooldown_secs: env_num("NAPSE_L2_MALFORMED_COOLDOWN_SECS", 10.0),
    }
}

fn handshake_config_from_env() -> HandshakeConfig {
    use napse_loader::confirm::{
        DEFAULT_CONFIRMED_TTL_SECS, DEFAULT_HALF_OPEN_TTL_SECS, DEFAULT_MAX_CONFIRMED, DEFAULT_MAX_FLOWS,
    };
    HandshakeConfig {
        max_flows: env_num("NAPSE_CONFIRM_MAX_FLOWS", DEFAULT_MAX_FLOWS),
        half_open_ttl_secs: env_num("NAPSE_CONFIRM_HALF_OPEN_TTL_SECS", DEFAULT_HALF_OPEN_TTL_SECS),
        max_confirmed: env_num("NAPSE_CONFIRM_MAX_CONFIRMED", DEFAULT_MAX_CONFIRMED),
        // 2026-07-05 Q6 fix: confirmation is recent evidence, not a permanent vouch — see
        // `confirm::HandshakeTracker::is_confirmed`'s doc comment.
        confirmed_ttl_secs: env_num("NAPSE_CONFIRM_TTL_SECS", DEFAULT_CONFIRMED_TTL_SECS),
    }
}

/// Trigger-to-evidence pcap capture (roadmap D) knobs — same `env_num`/`env_or` typo-degrades-to-
/// default discipline as every other config in this file. `capture::CaptureConfig::default()`
/// documents each field's default value/rationale; only the three operator-facing knobs
/// (`hookprobe_manifest::inspect::InspectIntent`'s `capture`/`capture_window_secs`/
/// `capture_cap_mb`) are exposed here — the finer per-source/global/pending bounds stay
/// hardcoded, sensible-default internals (not something an operator needs to hand-tune).
fn capture_config_from_env() -> CaptureConfig {
    let d = CaptureConfig::default();
    CaptureConfig {
        enabled: match std::env::var("NAPSE_CAPTURE_ENABLED") {
            Ok(v) => v != "0" && !v.eq_ignore_ascii_case("false"),
            Err(_) => d.enabled,
        },
        window_secs: env_num("NAPSE_CAPTURE_WINDOW_SECS", d.window_secs),
        global_max_bytes: env_num::<usize>("NAPSE_CAPTURE_CAP_MB", capture::DEFAULT_CAPTURE_CAP_MB) * 1024 * 1024,
        ..d
    }
}

/// Append `line` to the events stream immediately (UNCHANGED timing vs. before this pass — see
/// `capture`'s module doc "Alert-emission timing" for why `hookprobe_manifest::scan_responder`'s
/// enforcement latency must never regress), then — capture permitting — schedule a bounded
/// trigger-to-evidence pcap keyed on `key` (the alert's own `src_ip`/`src_mac`). `key: None` (an
/// alert with no single attributable source — `mac_flood`'s link-wide finding is the one case in
/// this file) skips capture honestly rather than inventing a source to ring on.
fn emit_and_maybe_capture(
    events: &str,
    capture: &mut FrameCapture,
    now: f64,
    key: Option<&str>,
    rule_id: u32,
    line: &str,
) {
    append_line(events, line);
    if let Some(k) = key {
        capture.trigger(now, k, rule_id, line);
    }
}

fn wall_secs() -> f64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs_f64()).unwrap_or(0.0)
}

/// F6: parse a `aa:bb:cc:dd:ee:ff` MAC string into 6 bytes. `None` on any malformed field.
fn parse_mac(s: &str) -> Option<[u8; 6]> {
    let mut out = [0u8; 6];
    let mut parts = s.split(':');
    for b in out.iter_mut() {
        *b = u8::from_str_radix(parts.next()?, 16).ok()?;
    }
    if parts.next().is_some() {
        return None; // more than 6 octets → not a MAC
    }
    Some(out)
}

/// F6: read every local interface's MAC from `/sys/class/net/*/address` (skipping `lo` and the
/// all-zero placeholder) so the malformed-frame gate can exempt this host's OWN GSO/TSO super-frames
/// on the egress mirror. Best-effort: an unreadable sysfs yields an empty set → no exemption (the
/// pre-F6 behavior), never a crash.
fn read_local_macs() -> Vec<[u8; 6]> {
    let mut macs = Vec::new();
    let Ok(entries) = std::fs::read_dir("/sys/class/net") else {
        return macs;
    };
    for e in entries.flatten() {
        if e.file_name() == "lo" {
            continue;
        }
        if let Ok(s) = std::fs::read_to_string(e.path().join("address")) {
            if let Some(mac) = parse_mac(s.trim()) {
                if mac != [0u8; 6] {
                    macs.push(mac);
                }
            }
        }
    }
    macs
}

/// Append one line to `path`, creating it if needed. Re-opens per write (not held open) so we keep
/// writing to the current inode across senzorium's log rotation; one `write_all` under O_APPEND is
/// atomic for lines under PIPE_BUF, so concurrent appenders never interleave mid-line.
fn append_line(path: &str, line: &str) {
    if let Ok(mut f) = OpenOptions::new().create(true).append(true).open(path) {
        let _ = f.write_all(line.as_bytes());
        let _ = f.write_all(b"\n");
        let _ = f.flush();
    }
}

/// Open an AF_PACKET/SOCK_RAW socket capturing ALL ethertypes, bound to `iface`.
fn open_afpacket(iface: &str) -> Result<OwnedFd> {
    // SAFETY: raw libc socket setup; each call is checked. ETH_P_ALL = 0x0003 in network order.
    let eth_p_all = (libc::ETH_P_ALL as u16).to_be() as i32;
    let fd = unsafe { libc::socket(libc::AF_PACKET, libc::SOCK_RAW, eth_p_all) };
    if fd < 0 {
        bail!("socket(AF_PACKET) failed (need CAP_NET_RAW): {}", std::io::Error::last_os_error());
    }
    let sock = unsafe { OwnedFd::from_raw_fd(fd) };
    let ifindex = std::fs::read_to_string(format!("/sys/class/net/{iface}/ifindex"))
        .with_context(|| format!("ifindex for {iface}"))?
        .trim()
        .parse::<i32>()?;
    // bind to the interface via sockaddr_ll
    let mut sll: libc::sockaddr_ll = unsafe { std::mem::zeroed() };
    sll.sll_family = libc::AF_PACKET as u16;
    sll.sll_protocol = eth_p_all as u16;
    sll.sll_ifindex = ifindex;
    let rc = unsafe {
        libc::bind(
            fd,
            &sll as *const _ as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_ll>() as u32,
        )
    };
    if rc < 0 {
        bail!("bind({iface}) failed: {}", std::io::Error::last_os_error());
    }
    Ok(sock)
}

fn main() -> Result<()> {
    if !granted("capture") {
        eprintln!(
            "napse-dpi: capability 'capture' not granted on this platform (module.yaml \
             requires.capabilities) — nothing to capture here, exiting cleanly."
        );
        return Ok(());
    }
    let iface = env_or("MIRROR_IFACE", "hp-mirror");
    let flows = env_or("FLOWS", "/var/lib/hookprobe/flows");
    let events = env_or("EVENTS", "/var/lib/hookprobe/events");
    let ps_cfg = portscan_config_from_env();
    let mut scanner = PortScanTracker::new(ps_cfg);
    // EDR #2 coverage: non-SYN TCP scans (FIN/NULL/XMAS) feed `scanner` via the broadened
    // `scan_probe_kind()` gate below; UDP fan-out and ICMP host-sweeps get their own trackers.
    let mut udp_scan = UdpScanTracker::new(UdpScanConfig::default());
    // 2026-07-07 low-and-slow coverage fix: rule 1000012, the long-window counterpart to `scanner`
    // — see `portscan::SlowScanTracker`'s module doc.
    let ss_cfg = slowscan_config_from_env();
    let mut slow_scanner = SlowScanTracker::new(ss_cfg);
    let mut icmp_sweep = IcmpSweepTracker::new(IcmpSweepConfig::default());
    // Gap-analysis pass (2026-07-07): C2 beacon/periodicity (rule 1000040) + east-west lateral
    // movement (rule 1000041) — see `beacon`/`lateral` module docs for the full rationale.
    let beacon_cfg = beacon_config_from_env();
    let mut beaconing = BeaconTracker::new(beacon_cfg.clone());
    let lateral_cfg = lateral_config_from_env();
    let mut lateral_movement = LateralMovementTracker::new(lateral_cfg);
    let hs_cfg = handshake_config_from_env();
    let mut handshakes = HandshakeTracker::new(hs_cfg);
    // ADR 0020 Phase-1a defensive: L1/L2 mitigations hardening napse/AEGIS against link-layer
    // attacks — mac-flood, ARP spoofing/poisoning, broadcast/multicast amplification, and
    // malformed/fuzzed frames. Detection only (this sensor is a read-only mirror tap — see the
    // module doc); the verdict/enforcement plumbing lives in
    // `hookprobe_manifest::l2_responder` (rate-limit / frame-drop, never an identity quarantine).
    let mut mac_flood = MacFloodTracker::new(mac_flood_config_from_env());
    let mut broadcast_storm = BroadcastStormTracker::new(broadcast_storm_config_from_env());
    let mut arp_guard = ArpGuard::new(arp_guard_config_from_env());
    // F6: exempt this host's own GSO/TSO super-frames (locally-originated, exceed MTU by design)
    // from the oversize/malformed check — the egress mirror carries them and they are not attacks.
    let mut malformed_gate =
        MalformedFrameGate::new(malformed_frame_config_from_env()).with_local_macs(read_local_macs());
    // Trigger-to-evidence pcap capture (roadmap D) — see `napse_loader::capture`'s module doc for
    // the full design (bounded per-source ring + bounded post-trigger tail + global byte ceiling).
    let cap_cfg = capture_config_from_env();
    let (cap_window_secs, cap_cap_mb) = (cap_cfg.window_secs, cap_cfg.global_max_bytes / (1024 * 1024));
    let pcap_dir = env_or("PCAP_DIR", "/var/lib/hookprobe/pcap");
    if cap_cfg.enabled {
        let _ = std::fs::create_dir_all(&pcap_dir);
    }
    let mut capture = FrameCapture::new(cap_cfg, pcap_dir.clone());
    let sock = open_afpacket(&iface)?;
    let fd = std::os::fd::AsRawFd::as_raw_fd(&sock);
    // sd_notify watchdog (backend-audit gap 2 — Architecture.md §4.4): READY=1 now that the
    // mirror socket is bound and open (successful startup); WATCHDOG=1 is pinged from inside the
    // recv() loop below, rate-limited (WatchdogPinger), ONLY after a real frame is received AND
    // this pass through the loop completes — a genuine "the capture loop is alive and processing
    // the wire" proof, never a background timer that would keep pinging while `recv()` (or
    // anything downstream of it) is truly wedged. Honest tradeoff, same as the wasm streaming
    // loop's: if the mirror interface goes completely silent (no traffic of ANY kind — no ARP, no
    // broadcast/multicast noise) for longer than `napse-dpi.service`'s `WatchdogSec=`, this
    // process will NOT ping and gets restarted — this is actually a FEATURE here, not just a
    // tolerated false-positive: a dead mirror feed (the exact "F1 dead-ingress-mirror" class of
    // bug this codebase has hit before) makes napse-dpi look "alive" while silently producing
    // zero detections forever, and the watchdog now bounds how long that can go undetected between
    // 15-minute selftest passes.
    hookprobe_manifest::sd_notify::notify_ready();
    let mut watchdog = hookprobe_manifest::sd_notify::WatchdogPinger::new(std::time::Duration::from_secs(20));
    eprintln!(
        "napse-dpi: capturing on {iface} → {flows} (DNS/TLS/HTTP); \
         port-scan detector → {events} (threshold={}, window={}s, cooldown={}s); \
         slow-scan detector (rule 1000012) → {events} (threshold={}, window={}s, cooldown={}s); \
         beacon detector (rule 1000040) → {events} (min_connections={}, window={}s, max_cv={}, \
         min_mean_interval={}s, allowlisted_ports={:?}); \
         lateral-movement detector (rule 1000041) → {events} (threshold={} peers, window={}s); \
         confirmation gate (max_flows={}, half_open_ttl={}s) — see ADR 0018; \
         trigger-to-evidence pcap capture (roadmap D) → {} (enabled={}, window={}s, cap_mb={})",
        ps_cfg.threshold, ps_cfg.window_secs, ps_cfg.cooldown_secs,
        ss_cfg.threshold, ss_cfg.window_secs, ss_cfg.cooldown_secs,
        beacon_cfg.min_connections, beacon_cfg.window_secs, beacon_cfg.max_cv,
        beacon_cfg.min_mean_interval_secs, beacon_cfg.allowlist_ports,
        lateral_cfg.threshold, lateral_cfg.window_secs,
        hs_cfg.max_flows, hs_cfg.half_open_ttl_secs,
        pcap_dir, capture.enabled(), cap_window_secs, cap_cap_mb,
    );

    let mut buf = vec![0u8; 65536];
    loop {
        let n = unsafe { libc::recv(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len(), 0) };
        if n <= 0 {
            if n < 0 {
                let e = std::io::Error::last_os_error();
                if e.kind() == std::io::ErrorKind::Interrupted {
                    continue;
                }
                bail!("recv failed: {e}");
            }
            continue;
        }
        // A real frame arrived and passed the n>0 check above — the capture loop is alive and
        // about to process it (see the sd_notify watchdog note above `notify_ready()`).
        watchdog.tick();
        let frame = &buf[..n as usize];
        let now = wall_secs();
        // Trigger-to-evidence pcap capture (roadmap D): record EVERY frame into its source's
        // bounded ring before any detector below decides whether it's a trigger — see
        // `capture`'s module doc for the cost discipline (no I/O here, bounded work only).
        let cap_key = capture::capture_key(frame);
        if let Some(k) = &cap_key {
            capture.observe(now, k, frame);
        }

        // ADR 0020 Phase-1a defensive L1/L2 mitigations — run on EVERY captured frame, before any
        // L3/L4-specific parsing. A malformed/fuzzed frame's other fields can't be trusted, so a
        // malformed hit short-circuits the rest of THIS frame's L2 detectors below (the existing
        // dns/tls/http/tcp parsers further down already bounds-check independently and simply
        // return `None` on genuinely malformed input regardless, so nothing downstream is at risk
        // either way — this is purely about not wasting cycles classifying a frame we already
        // know is garbage).
        if let Some(alert) = malformed_gate.observe(now, frame) {
            let rid = alert.rule_id;
            emit_and_maybe_capture(&events, &mut capture, now, cap_key.as_deref(), rid, &alert.to_json());
        } else {
            if let Some((dst_mac, src_mac)) = dpi::eth_addrs(frame) {
                if let Some(alert) = mac_flood.observe(now, src_mac) {
                    // Deliberately NOT captured — `mac_flood` is a link-wide finding with no single
                    // attributable source (see `l2guard::L2Alert`'s own doc + `capture`'s module
                    // doc "What this is NOT" section) — there is no honest per-source key to ring
                    // on, so this alert is emitted exactly as before this pass.
                    append_line(&events, &alert.to_json());
                }
                if let Some(alert) = broadcast_storm.observe(now, src_mac, dst_mac) {
                    let rid = alert.rule_id;
                    emit_and_maybe_capture(&events, &mut capture, now, cap_key.as_deref(), rid, &alert.to_json());
                }
            }
            if let Some(obs) = dpi::parse_arp_obs(frame) {
                if let Some(alert) = arp_guard.observe(now, &obs) {
                    let rid = alert.rule_id;
                    emit_and_maybe_capture(&events, &mut capture, now, cap_key.as_deref(), rid, &alert.to_json());
                }
            }
        }

        if let Some(rec) = dpi::parse_frame(frame, now) {
            // ONE write_all of the whole line (< PIPE_BUF) is atomic under O_APPEND, so concurrent
            // appenders (napse-loader ringbuf + senzorium) never interleave mid-line. Re-open per
            // record keeps us writing to the current inode across senzorium's log rotation.
            if let Ok(mut f) = OpenOptions::new().create(true).append(true).open(&flows) {
                let _ = f.write_all(format!("{rec}\n").as_bytes());
            }
        }

        // Independent of the dns/tls/http gate above: every TCP packet feeds BOTH the SYN fan-out
        // tracker (a port scan probes arbitrary ports, not just 53/80/443) AND the confirmation
        // gate (ANY direction — a handshake needs to see the SYN, the SYN-ACK, and the final ACK,
        // which arrive as three separate packets, only one of which is itself a SYN).
        if let Some(obs) = dpi::parse_tcp_obs(frame) {
            // 2026-07-05 Q2 fix: the handshake tracker is fed the OBSERVED frame src_mac for
            // EVERY direction, not just the SYN — confirmation is keyed on (ip, mac), never IP
            // alone (see `confirm::HandshakeTracker`'s doc comment for why IP-alone keying let a
            // victim's own innocent traffic vouch for an attacker spoofing its IP).
            handshakes.observe(
                now, obs.src, obs.sport, obs.dst, obs.dport, obs.syn, obs.ack, obs.seq, obs.ack_num, obs.src_mac,
            );

            // EDR #2: count SYN *and* FIN/NULL/XMAS scan-probe shapes toward the fan-out, not just
            // SYN-only. Confirmation still needs a real handshake, so these non-SYN scans (which
            // never handshake) surface as detections but stay unconfirmed → Observed, not blocked.
            let is_scan_probe = obs.scan_probe_kind().is_some();
            if let Some(alert) =
                scanner.observe(now, obs.src, obs.sport, obs.dst, obs.dport, is_scan_probe, obs.src_mac)
            {
                // Stamp confirmation from the INDEPENDENT handshake tracker — never trust a field
                // an attacker could set; this is the ONLY place `confirmed` is decided. Keyed on
                // the SCANNING packets' own observed mac (`alert.src_mac`) — a missing mac (never
                // happens for a well-formed frame; kept `Option` for robustness) fails CLOSED
                // toward "not confirmed", never toward trusting the bare IP.
                let confirmed = alert
                    .src_mac
                    .map(|mac| handshakes.is_confirmed(&alert.src_ip, &mac, now))
                    .unwrap_or(false);
                eprintln!(
                    "napse-dpi: port scan detected — src={} dst_port={} distinct_ports={} confirmed={confirmed}",
                    alert.src_ip, alert.dst_port, alert.distinct_ports
                );
                let key = alert.src_ip.to_string();
                emit_and_maybe_capture(&events, &mut capture, now, Some(&key), portscan::RULE_ID, &alert.to_json(confirmed));
                // Low-and-slow dedup (2026-07-07): this source is already reported via 1000003 —
                // suppress 1000012 for it so the slow tracker doesn't double-report the same scan
                // (see `SlowScanTracker::suppress_fast_scan`'s doc).
                slow_scanner.suppress_fast_scan(alert.src_ip, now);
            }

            // 2026-07-07 low-and-slow coverage fix: every scan-probe packet ALSO feeds the
            // long-window tracker, independent of whether the fast one fired above (the dedup call
            // just above handles the case where it did). This is what catches the trickle a fast
            // scanner never crosses — see `portscan::SlowScanTracker`'s module doc.
            if let Some(alert) = slow_scanner.observe(
                now, obs.src, obs.sport, obs.dst, obs.dport, is_scan_probe, obs.src_mac, "tcp",
            ) {
                let confirmed = alert
                    .src_mac
                    .map(|mac| handshakes.is_confirmed(&alert.src_ip, &mac, now))
                    .unwrap_or(false);
                eprintln!(
                    "napse-dpi: SLOW port scan detected — src={} dst_ip={} distinct_ports={} confirmed={confirmed}",
                    alert.src_ip, alert.dst_ip, alert.distinct_ports
                );
                let key = alert.src_ip.to_string();
                emit_and_maybe_capture(&events, &mut capture, now, Some(&key), portscan::SLOWSCAN_RULE_ID, &alert.to_json(confirmed));
            }

            // 2026-07-07 gap-analysis pass: a genuine NEW connection attempt (SYN set, ACK clear —
            // deliberately excludes the FIN/NULL/XMAS scan-probe shapes `is_scan_probe` above also
            // counts; those are never real sessions and would only pollute the beacon/lateral
            // timing signal) feeds BOTH the C2 beacon tracker and the lateral-movement tracker.
            // Independent of whatever `scanner`/`slow_scanner` decided above — a source can be
            // scanning AND beaconing AND moving laterally; each detector judges its own signal.
            if obs.syn && !obs.ack {
                if let Some(alert) = beaconing.observe(now, obs.src, obs.dst, obs.dport, obs.src_mac, "tcp") {
                    let confirmed = alert
                        .src_mac
                        .map(|mac| handshakes.is_confirmed(&alert.src_ip, &mac, now))
                        .unwrap_or(false);
                    eprintln!(
                        "napse-dpi: C2 beacon detected — src={} dst={}:{} mean_interval={:.1}s jitter_cv={:.3} confirmed={confirmed}",
                        alert.src_ip, alert.dst_ip, alert.dst_port, alert.mean_interval_secs, alert.jitter_cv
                    );
                    let key = alert.src_ip.to_string();
                    emit_and_maybe_capture(&events, &mut capture, now, Some(&key), beacon::BEACON_RULE_ID, &alert.to_json(confirmed));
                }
                if let Some(alert) = lateral_movement.observe(now, obs.src, obs.dst, obs.dport, obs.src_mac) {
                    let confirmed = alert
                        .src_mac
                        .map(|mac| handshakes.is_confirmed(&alert.src_ip, &mac, now))
                        .unwrap_or(false);
                    eprintln!(
                        "napse-dpi: lateral movement detected — src={} distinct_peers={} last_dst={}:{} confirmed={confirmed}",
                        alert.src_ip, alert.distinct_peers, alert.dst_ip, alert.dst_port
                    );
                    let key = alert.src_ip.to_string();
                    emit_and_maybe_capture(&events, &mut capture, now, Some(&key), lateral::LATERAL_RULE_ID, &alert.to_json(confirmed));
                }
            }
        }

        // EDR #2: UDP fan-out + ICMP host-sweep — no handshake/port concept, so every UDP datagram
        // to a new dst port / every ICMP echo-request to a new host IS the probe signal itself.
        if let Some(u) = dpi::parse_udp_obs(frame) {
            if let Some(alert) = udp_scan.observe(now, u.src, u.sport, u.dst, u.dport, u.src_mac) {
                let key = alert.src_ip.to_string();
                emit_and_maybe_capture(&events, &mut capture, now, Some(&key), portscan::UDP_SCAN_RULE_ID, &alert.to_json());
            }
            // 2026-07-07: every UDP datagram to a new destination also feeds the beacon tracker —
            // a UDP-based C2 channel (or a UDP-riding periodic beacon) is otherwise invisible to
            // the TCP-SYN-fed path above. NTP (port 123) is exempted by default (see
            // `beacon::DEFAULT_BEACON_ALLOWLIST_PORTS`); UDP has no handshake to confirm against,
            // so a UDP-fed beacon always renders unconfirmed (Observed only, never enforced) —
            // same honest-scope note as the UDP scan tracker.
            if let Some(alert) = beaconing.observe(now, u.src, u.dst, u.dport, u.src_mac, "udp") {
                eprintln!(
                    "napse-dpi: UDP C2 beacon detected — src={} dst={}:{} mean_interval={:.1}s jitter_cv={:.3}",
                    alert.src_ip, alert.dst_ip, alert.dst_port, alert.mean_interval_secs, alert.jitter_cv
                );
                let key = alert.src_ip.to_string();
                emit_and_maybe_capture(&events, &mut capture, now, Some(&key), beacon::BEACON_RULE_ID, &alert.to_json(false));
            }
            // 2026-07-07: UDP has no handshake to confirm against (same honest-scope note as the
            // fast UDP tracker above), so a UDP-fed slow-scan alert always renders unconfirmed —
            // Observed only, never enforced. Still real coverage: a low-and-slow UDP prober (e.g.
            // a slow SNMP/DNS/NTP service sweep) accumulates here exactly like the TCP path.
            if let Some(alert) =
                slow_scanner.observe(now, u.src, u.sport, u.dst, u.dport, true, u.src_mac, "udp")
            {
                eprintln!(
                    "napse-dpi: SLOW UDP port scan detected — src={} dst_ip={} distinct_ports={}",
                    alert.src_ip, alert.dst_ip, alert.distinct_ports
                );
                let key = alert.src_ip.to_string();
                emit_and_maybe_capture(&events, &mut capture, now, Some(&key), portscan::SLOWSCAN_RULE_ID, &alert.to_json(false));
            }
        }
        if let Some(ic) = dpi::parse_icmp_obs(frame) {
            if let Some(alert) =
                icmp_sweep.observe(now, ic.src, ic.dst, ic.icmp_type == dpi::ICMP_ECHO_REQUEST, ic.src_mac)
            {
                let key = alert.src_ip.to_string();
                emit_and_maybe_capture(&events, &mut capture, now, Some(&key), portscan::ICMP_SWEEP_RULE_ID, &alert.to_json());
            }
        }

        // Trigger-to-evidence pcap capture (roadmap D): finish any capture whose bounded
        // post-trigger tail has elapsed and append its annotated follow-up events-stream line.
        // Cheap: `poll_finalize` is an early-return no-op whenever nothing is pending (the common
        // case — triggers are cooldown-rate-limited upstream, see `capture`'s module doc).
        for fc in capture.poll_finalize(now) {
            append_line(&events, &fc.json_line);
        }
    }
}
