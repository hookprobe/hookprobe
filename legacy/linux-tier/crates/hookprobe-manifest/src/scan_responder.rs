//! AEGIS reflex response to a NAPSE port-scan detection (rule_id 1000003, `napse-dpi` /
//! `modules/napse-capture`) — ENRICH (passive intel, always safe), DROP (deterministic nft
//! quarantine, TTL auto-revert, mgmt-path allowlisted, idempotent), DOCUMENT (a response record
//! `hookprobe-evidence --responses` links to the detection it responded to). Handles BOTH a
//! LAN-side scanner and a WAN-side (public internet) scanner — see [`classify_source`].
//!
//! ## Why nft, not the OVS override `trust.rs` renders
//! `trust.rs`'s `render_quarantine_flows`/`render_reconcile` re-segment a device by moving its
//! `dl_src` OpenFlow binding to a quarantine VLAN — that needs a live OVS bridge. This Pi 4 has
//! none (`hp-br0` down; the AP is plain `wlan0` + nft masquerade), so quarantine here is rendered
//! as **nft set membership**, scoped per source kind (see [`render_bootstrap`]):
//!   - LAN scanner — `quarantine_lan_ips` + `quarantine_lan_macs`, dropped on the LAN iface's
//!     forward AND input chains (a LAN client has both an IP and an L2 MAC to bind).
//!   - WAN scanner — `quarantine_wan_ips` only, dropped on the WAN iface's input chain (shields
//!     this box's own exposed services) and forward (defense-in-depth) — a routed WAN source
//!     has no L2 MAC.
//!
//! The nft `timeout` flag gives kernel-level auto-expiry as defense-in-depth; this module's own
//! `reconcile_quarantine`/`sweep_quarantine` are the AUTHORITATIVE revert path (a persisted state
//! file, evaluated every cycle — mirrors `trust::reconcile`'s newly-quarantined/recovered diff,
//! just keyed on elapsed time since last offense instead of "still in this cycle's posture").
//!
//! ## Reusing the existing trust path (no new decision engine)
//! [`decide`] builds a [`trust::PostureSignal`] (`threat = Malicious`, the T1046 verdict is
//! definitional for a port scan) and runs it through the EXISTING `trust::evaluate` — the same
//! deterministic reconciler `trust-reconcile.sh` drives for continuous-trust quarantine. A port
//! scan always evaluates to `TrustAction::Quarantine`; the only thing this module adds on top is
//! the fail-safe management-path allowlist (never quarantine the admin subnet / gateway / WAN —
//! self-lockout is worse than a missed detection) and the nft rendering (vs. the OVS VLAN move).
//! No LLM anywhere in this path — model-free, same as `aegis-guard`'s Deny-is-final guard.

use crate::fingerprint::{self, DeviceObservation};
use crate::multi_wan::GeneratedFile;
use crate::trust::{self, PostureSignal, ThreatLevel, TrustAction, TrustPolicy};
use std::collections::BTreeSet;

// `SourceKind`/`classify_source` and the mgmt-allowlist safety valve (`ProtectPolicy`,
// `protect_reason`) now live in the dependency-free `hookprobe-mgmt-guard` crate — SHARED with
// `aegis-guard`'s reflex engine (2026-07 audit fix) so the scan-responder's quarantine path and
// the reflex's DISCONNECT/`block_ip` path can never diverge on what counts as "never enforce
// against this address". Re-exported here so every existing `scan_responder::{...}` call site
// in this crate (and callers like `supervisor`) keeps working unchanged.
pub use hookprobe_mgmt_guard::{classify_source, protect_reason, ProtectPolicy, SourceKind};

// ---------------------------------------------------------------------------
// The NAPSE port-scan alert (exact schema napse-dpi/rule 1000003 emits).
// ---------------------------------------------------------------------------

/// One NAPSE alert line from `/var/lib/hookprobe/events`. Matches the exact schema:
/// `{"ts":<f64>,"src_ip":"<scanner>","src_port":<u16>,"dst_ip":"<target>","dst_port":<u16>,
/// "proto":"tcp","severity":2,"rule_id":1000003,"rule_msg":"NAPSE Port Scan Detected",
/// "mitre":"T1046","category":"port_scan","confidence":0.9,"confirmed":true,"src_mac":"aa:.."}`.
#[derive(Debug, Clone, PartialEq, serde::Deserialize, serde::Serialize)]
pub struct ScanAlert {
    pub ts: f64,
    pub src_ip: String,
    pub src_port: u16,
    pub dst_ip: String,
    pub dst_port: u16,
    #[serde(default)]
    pub proto: String,
    #[serde(default)]
    pub severity: i64,
    #[serde(default)]
    pub rule_id: i64,
    #[serde(default)]
    pub rule_msg: String,
    #[serde(default)]
    pub mitre: String,
    #[serde(default)]
    pub category: String,
    #[serde(default)]
    pub confidence: f64,
    /// 2026-07-05 threat-model fix (CRITICAL #1): `true` only if the emitting sensor
    /// (`napse_loader::confirm::HandshakeTracker`) observed a REAL, validated TCP handshake from
    /// this source — never a self-reported claim this crate trusts blindly; [`decide`] is the
    /// single place that turns this into an enforcement decision. **Defaults to `false`** on a
    /// missing/older-schema field — fail CLOSED toward "don't enforce", never fail-open toward
    /// "trust an alert that predates this fix".
    ///
    /// 2026-07-06 fix (F4): this is ONE of two independent confirmation sources now — see
    /// [`is_confirmed_any`], which ALSO trusts a conntrack-ESTABLISHED flow for this source
    /// (this device's own kernel, not the mirror). Callers should feed `decide`'s `confirmed`
    /// parameter from `is_confirmed_any(alert.confirmed, flows_jsonl, &alert.src_ip)`, not this
    /// field alone, so a mirror-pipeline outage can never single-handedly disable enforcement.
    #[serde(default)]
    pub confirmed: bool,
    /// The OBSERVED Ethernet source MAC at detection time (never an ARP/`ip neigh` resolution of
    /// `src_ip` — see [`resolve_mac`]'s doc comment for why that lookup is the vulnerability this
    /// field's plumbing replaces). `None`/absent for a WAN-classified source (no L2 MAC to bind).
    #[serde(default)]
    pub src_mac: Option<String>,
}

/// The rule id napse-dpi and the wasm NAPSE engine both use for a SYN port scan (ADR 0005).
pub const PORT_SCAN_RULE_ID: i64 = 1_000_003;

/// Parse one `events` line; `Some` only for a port-scan detection (rule_id 1000003 OR
/// category `"port_scan"` — either is definitive; NAPSE emits both, and accepting either keeps
/// this reflex working if one is ever renamed without the other). Any other line (a flow, a
/// different alert, a blank/malformed line) is `None` — not an error, just "not for us".
pub fn parse_scan_alert(line: &str) -> Option<ScanAlert> {
    let trimmed = line.trim();
    if trimmed.is_empty() {
        return None;
    }
    let a: ScanAlert = serde_json::from_str(trimmed).ok()?;
    if a.rule_id == PORT_SCAN_RULE_ID || a.category == "port_scan" {
        Some(a)
    } else {
        None
    }
}

// ---------------------------------------------------------------------------
// SOURCE CLASSIFICATION — LAN vs WAN (a key requirement: the reflex must handle BOTH).
// A port scan is handled identically end-to-end EXCEPT for this fork: a LAN-side scanner
// gets device fingerprinting + an ip+mac drop on the LAN iface; a WAN-side (public
// internet) scanner gets network intel (PTR/coarse grouping/reputation/bogon) + an
// ip-only drop on the WAN iface (a routed WAN source has no L2 MAC to bind).
//
// `SourceKind`/`classify_source` are re-exported above from `hookprobe_mgmt_guard` (shared with
// `aegis-guard`); `ipv4_octets` below stays LOCAL — it's a trivial dotted-quad parser reused by
// several unrelated checks in this file (`is_bogon_v4`, subnet math, ...), not part of the
// shared mgmt-allowlist predicate itself.
// ---------------------------------------------------------------------------

/// Parse a dotted-quad IPv4 address into its 4 octets, or `None` for anything else (IPv6,
/// hostnames, garbage) — shared by every IPv4-only check in this module.
fn ipv4_octets(ip: &str) -> Option<[u8; 4]> {
    let parts: Vec<u8> = ip.split('.').map(|p| p.parse().ok()).collect::<Option<Vec<u8>>>()?;
    if parts.len() != 4 {
        return None;
    }
    Some([parts[0], parts[1], parts[2], parts[3]])
}

// ---------------------------------------------------------------------------
// ENRICH — resolve scanner IP → MAC, then MAC-independent identity (fingerprint reuse).
// ---------------------------------------------------------------------------

/// Parse `ip neigh show` output and return the MAC for `ip`, if a `lladdr` entry exists.
/// Lines look like: `10.66.0.23 dev wlan0 lladdr aa:bb:cc:dd:ee:ff REACHABLE`. A `FAILED`/
/// incomplete entry (no `lladdr` token) correctly yields `None`.
pub fn parse_ip_neigh(text: &str, ip: &str) -> Option<String> {
    for line in text.lines() {
        let mut it = line.split_whitespace();
        let Some(first) = it.next() else { continue };
        if first != ip {
            continue;
        }
        let rest: Vec<&str> = it.collect();
        if let Some(pos) = rest.iter().position(|t| *t == "lladdr") {
            return rest.get(pos + 1).map(|s| s.to_ascii_lowercase());
        }
    }
    None
}

/// Parse `/proc/net/arp` (`IP address  HW type  Flags  HW address  Mask  Device`, header line
/// first) and return the MAC for `ip`. An all-zero MAC (incomplete ARP entry) is not a match.
pub fn parse_proc_net_arp(text: &str, ip: &str) -> Option<String> {
    for line in text.lines().skip(1) {
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.len() < 4 || f[0] != ip {
            continue;
        }
        let mac = f[3];
        if mac != "00:00:00:00:00:00" && !mac.is_empty() {
            return Some(mac.to_ascii_lowercase());
        }
    }
    None
}

/// Resolve a MAC for `ip` from `ip neigh`/`/proc/net/arp`, preferring the former.
///
/// # SECURITY — do NOT use this to key quarantine enforcement (2026-07-05 threat-model fix)
/// This resolves the ARP/neighbor-table entry for the CLAIMED `ip`, which is exactly as spoofable
/// as `ip` itself: a WAN attacker forging `src_ip` = this device's own gateway or DNS resolver
/// makes this function faithfully return the REAL gateway/resolver's MAC — which, if bound into
/// the LAN quarantine set, poisons enforcement against a legitimate, load-bearing address the
/// attacker never even touched. The quarantine responder (`decide`/`reconcile_quarantine`) MUST
/// key LAN enforcement on the OBSERVED frame source MAC captured at detection time
/// (`ScanAlert::src_mac`, populated by `napse_loader::portscan::PortScanTracker`), never on this
/// function's output. This helper remains for informational/enrichment use only (e.g. displaying
/// a "last known MAC" in host intel) where being wrong has no enforcement consequence.
pub fn resolve_mac(neigh_text: Option<&str>, arp_text: Option<&str>, ip: &str) -> Option<String> {
    neigh_text
        .and_then(|t| parse_ip_neigh(t, ip))
        .or_else(|| arp_text.and_then(|t| parse_proc_net_arp(t, ip)))
}

/// The scanner's enriched host record — the ENRICH step's output. Written to
/// `/var/lib/hookprobe/host-intel/<mac-or-ip>.json` and folded into the evidence-graph device
/// node via the response event (see `render_response_json`). Always safe/passive: nothing here
/// touches the wire or blocks traffic.
#[derive(Debug, Clone, Default, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct HostIntel {
    pub ip: String,
    #[serde(default)]
    pub mac: Option<String>,
    /// True if the MAC is locally-administered (randomized) — identity is the fingerprint, not
    /// the MAC (mirrors `fingerprint::DeviceProfile::mac_randomized`).
    #[serde(default)]
    pub mac_randomized: bool,
    /// OUI vendor label — `None` for a randomized MAC or an unrecognized universal OUI.
    #[serde(default)]
    pub oui_vendor: Option<String>,
    #[serde(default)]
    pub hostname: Option<String>,
    #[serde(default)]
    pub vendor_class: Option<String>,
    #[serde(default)]
    pub dhcp_opt55: Option<String>,
    #[serde(default)]
    pub mdns_services: Vec<String>,
    #[serde(default)]
    pub models: Vec<String>,
    #[serde(default)]
    pub device_class: String,
    #[serde(default)]
    pub confidence: String,
    pub first_seen: f64,
    pub last_seen: f64,
    /// Distinct targets this scanner has probed (usually one; a multi-host recon sweep grows it).
    #[serde(default)]
    pub scan_targets: Vec<String>,
    /// Distinct destination ports probed across every alert line seen for this scanner.
    #[serde(default)]
    pub scan_ports: Vec<u16>,
    /// Number of NAPSE alert lines folded into this record (scan attempts observed).
    #[serde(default)]
    pub scan_count: u64,
}

/// The observed signals for one enrichment call — bundled so `enrich_host` takes one struct
/// instead of a long positional-argument list (every field is optional; use whatever the
/// caller actually resolved this cycle).
#[derive(Debug, Clone, Copy, Default)]
pub struct EnrichSignals<'a> {
    pub mac: Option<&'a str>,
    pub hostname: Option<&'a str>,
    pub vendor_class: Option<&'a str>,
    pub dhcp_opt55: Option<&'a str>,
    pub mdns: Option<&'a fingerprint::MdnsHost>,
}

/// Build/merge the enriched host record for one scan alert. `prev` is the record already on
/// disk for this scanner (if any) — its `scan_ports`/`scan_targets`/`scan_count`/`first_seen`
/// are folded forward so the record ACCUMULATES facts across multiple alert lines instead of
/// being overwritten each call (NAPSE emits one alert per probed port, not one per whole scan).
/// Reuses `fingerprint::classify` (MAC-independent identity) and `fingerprint::oui_vendor` —
/// extended only with the latter, which the classifier didn't expose.
pub fn enrich_host(prev: Option<&HostIntel>, alert: &ScanAlert, sig: EnrichSignals, now: f64) -> HostIntel {
    let empty_mdns = fingerprint::MdnsHost::default();
    let mdns = sig.mdns.unwrap_or(&empty_mdns);
    let obs = DeviceObservation {
        mac: sig.mac.unwrap_or("").to_string(),
        ip: Some(alert.src_ip.clone()),
        hostname: sig.hostname.map(String::from),
        vendor_class: sig.vendor_class.map(String::from),
        dhcp_opt55: sig.dhcp_opt55.map(String::from),
        mdns_services: mdns.services.clone(),
        models: mdns.models.clone(),
    };
    let profile = fingerprint::classify(&obs);

    let mut ports: BTreeSet<u16> = prev.map(|p| p.scan_ports.iter().copied().collect()).unwrap_or_default();
    ports.insert(alert.dst_port);
    let mut targets: BTreeSet<String> = prev.map(|p| p.scan_targets.iter().cloned().collect()).unwrap_or_default();
    targets.insert(alert.dst_ip.clone());
    let scan_count = prev.map(|p| p.scan_count).unwrap_or(0) + 1;
    let first_seen = prev.map(|p| p.first_seen).unwrap_or(now);

    HostIntel {
        ip: alert.src_ip.clone(),
        mac: sig.mac.map(String::from),
        mac_randomized: profile.mac_randomized,
        oui_vendor: sig.mac.and_then(fingerprint::oui_vendor).map(String::from),
        hostname: sig.hostname.map(String::from),
        vendor_class: sig.vendor_class.map(String::from),
        dhcp_opt55: sig.dhcp_opt55.map(String::from),
        mdns_services: obs.mdns_services,
        models: obs.models,
        device_class: profile.class.as_str().to_string(),
        confidence: profile.confidence.as_str().to_string(),
        first_seen,
        last_seen: now,
        scan_targets: targets.into_iter().collect(),
        scan_ports: ports.into_iter().collect(),
        scan_count,
    }
}

// ---------------------------------------------------------------------------
// ENRICH (WAN) — network intel for a public-internet scanner: no DHCP/mDNS is possible
// off-link, so identity here is PTR + coarse network grouping + a bogon flag + reputation
// against HYDRA's already-fetched threat-intel feeds — the real seam, never fabricated.
// ---------------------------------------------------------------------------

/// The scanner's WAN-side network intel — the ENRICH step's output for a `Wan`-classified
/// source. Mirrors `HostIntel`'s scan-fact fields; identity fields are network-only (no
/// MAC/hostname/mDNS is possible for an off-link source).
#[derive(Debug, Clone, Default, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct WanIntel {
    pub ip: String,
    /// Reverse-DNS (PTR) hostname, when resolvable. `None` is reported honestly — never guessed.
    #[serde(default)]
    pub ptr: Option<String>,
    /// The coarse `/24` grouping. A real ASN/GeoIP lookup needs a database this OS doesn't
    /// bundle yet; this is the honest, dependency-free stand-in — wiring a real ASN/GeoIP feed
    /// is a documented seam, not this field's job.
    pub network_group: String,
    /// True if `ip` falls in a reserved/documentation/multicast range that must never be a
    /// real internet source (0.0.0.0/8, IETF/TEST-NET ranges, multicast, reserved, broadcast)
    /// — flags a spoofed or misrouted private-leak source arriving on the WAN path.
    #[serde(default)]
    pub is_bogon: bool,
    /// Threat-feed match against HYDRA's already-fetched CIDR feeds (`/var/lib/hookprobe/feeds`
    /// — the SAME files `hydra-feedsync` parses into the BPF blocklist, ADR 0005), e.g.
    /// `Some("spamhaus-drop")`. `None` = "unknown, needs feed" — NOT fabricated as clean.
    #[serde(default)]
    pub reputation: Option<String>,
    pub first_seen: f64,
    pub last_seen: f64,
    #[serde(default)]
    pub scan_targets: Vec<String>,
    #[serde(default)]
    pub scan_ports: Vec<u16>,
    #[serde(default)]
    pub scan_count: u64,
}

/// The `/24` a WAN address belongs to — a dependency-free stand-in for a real ASN lookup (no
/// GeoIP/ASN database ships with this OS yet). Callers only invoke this for `Wan`-classified
/// addresses, but malformed input still renders `"unknown"` rather than panicking.
pub fn wan_network_group(ip: &str) -> String {
    match ipv4_octets(ip) {
        Some(o) => format!("{}.{}.{}.0/24", o[0], o[1], o[2]),
        None => "unknown".to_string(),
    }
}

/// Reserved/documentation/multicast ranges that must never be a real internet source IP —
/// seeing one on the WAN path flags a spoofed or misrouted private-leak source.
const BOGON_RANGES: &[([u8; 4], u8)] = &[
    ([0, 0, 0, 0], 8),           // "this network"
    ([192, 0, 0, 0], 24),        // IETF protocol assignments
    ([192, 0, 2, 0], 24),        // TEST-NET-1
    ([198, 51, 100, 0], 24),     // TEST-NET-2
    ([203, 0, 113, 0], 24),      // TEST-NET-3
    ([224, 0, 0, 0], 4),         // multicast
    ([240, 0, 0, 0], 4),         // reserved
    ([255, 255, 255, 255], 32),  // limited broadcast
];

fn v4_in_prefix(ip: [u8; 4], net: [u8; 4], prefixlen: u8) -> bool {
    let ip_n = u32::from_be_bytes(ip);
    let net_n = u32::from_be_bytes(net);
    let mask: u32 = if prefixlen == 0 { 0 } else { u32::MAX << (32 - prefixlen) };
    (ip_n & mask) == (net_n & mask)
}

/// True if `ip` is a bogon/reserved address (see [`BOGON_RANGES`]); `false` for unparseable
/// input (fail toward "not flagged" — the caller's own allowlist/classification is authoritative).
pub fn is_bogon_v4(ip: &str) -> bool {
    let Some(o) = ipv4_octets(ip) else { return false };
    BOGON_RANGES.iter().any(|&(net, plen)| v4_in_prefix(o, net, plen))
}

/// Parse one threat-intel feed line → an IPv4 CIDR prefix, or `None` for a comment/blank/IPv6/
/// garbage line. A minimal, INDEPENDENT re-implementation of the exact tolerant format
/// `napse_loader::feed::parse_line` already parses (Spamhaus DROP/EDROP, FireHOL, Emerging
/// Threats, Feodo, SSLBL) — duplicated, not depended on: `napse-loader` depends on THIS crate
/// (`hookprobe-manifest`), so a dependency back would cycle. Reads the SAME on-disk feed files
/// HYDRA already fetches, without touching `modules/napse-capture/loader`.
fn parse_feed_prefix(line: &str) -> Option<([u8; 4], u8)> {
    let head = line.split(&[';', '#'][..]).next().unwrap_or("").trim();
    if head.is_empty() {
        return None;
    }
    let tok = head.split_whitespace().next()?;
    if tok.contains(':') {
        return None; // IPv6 — not handled here
    }
    let (addr_s, plen) = match tok.split_once('/') {
        Some((a, p)) => (a, p.parse::<u8>().ok()?),
        None => (tok, 32),
    };
    if plen > 32 {
        return None;
    }
    let octs = ipv4_octets(addr_s)?;
    Some((octs, plen))
}

/// Check `ip` against already-fetched HYDRA threat-intel feed bodies (`(name, text)` pairs —
/// e.g. every `/var/lib/hookprobe/feeds/*.txt`, the SAME files `hydra-feedsync` parses into the
/// BPF blocklist, ADR 0005). Returns the first matching feed's name. `None` is the honest
/// default ("unknown, needs feed") — never fabricated as either clean or malicious.
pub fn wan_reputation(ip: &str, feeds: &[(&str, &str)]) -> Option<String> {
    let ip_octets = ipv4_octets(ip)?;
    for (name, body) in feeds {
        for line in body.lines() {
            if let Some((net, plen)) = parse_feed_prefix(line) {
                if v4_in_prefix(ip_octets, net, plen) {
                    return Some((*name).to_string());
                }
            }
        }
    }
    None
}

// ---------------------------------------------------------------------------
// 2026-07-05 threat-model fix (HIGH #4) — resolving THIS DEVICE's own live upstream, so it can be
// folded into `ProtectPolicy::ips`. Pure parsers only; the caller (supervisor's scan-respond
// startup, once, never per-alert) does the actual `ip route`/`/etc/resolv.conf` I/O.
// ---------------------------------------------------------------------------

/// Parse `ip route show default` output → the gateway address after `via`, or `None` if there is
/// no default route / the output doesn't parse. Multiple default routes (multi-WAN) are handled
/// by returning the FIRST one listed — good enough for a fail-safe protect-list entry; missing a
/// secondary gateway costs one fewer protected address, not a security regression.
pub fn parse_default_gateway(text: &str) -> Option<String> {
    text.lines().find_map(|line| {
        let mut it = line.split_whitespace();
        while let Some(tok) = it.next() {
            if tok == "via" {
                return it.next().map(String::from);
            }
        }
        None
    })
}

/// Parse `/etc/resolv.conf` → every configured `nameserver` address (zero, one, or more).
pub fn parse_resolv_conf_nameservers(text: &str) -> Vec<String> {
    text.lines()
        .filter_map(|l| l.trim().strip_prefix("nameserver"))
        .filter_map(|rest| rest.split_whitespace().next())
        .map(String::from)
        .collect()
}

/// 2026-07-05 VERIFY-pass re-audit (Q5 fix): parse `ip -4 -o addr show dev <wan-iface>` output →
/// every configured IPv4 address on that interface (prefix length stripped) — this device's OWN
/// WAN-side address(es), for [`is_wan_ingress_martian`]'s `wan_self_ips` parameter ONLY.
/// Deliberately a SEPARATE parser/list from `ProtectPolicy::ips` (the mgmt/gateway/resolver
/// allowlist) — conflating the two let a LAN attacker scanning the gateway itself get
/// misclassified as an "impossible WAN ingress" and evade enforcement (see `decide`'s doc comment
/// and ADR 0018's Q5 correction). Each `-o` (one-line-per-address) output line looks like:
/// `2: end0    inet 198.51.100.44/24 brd 198.51.100.255 scope global end0\       valid_lft ...`;
/// this also tolerates the multi-line (`ip addr show`, no `-o`) form since it just scans for the
/// first `"inet "` token per line. Multiple lines (multi-WAN) all contribute.
pub fn parse_wan_self_ips(text: &str) -> Vec<String> {
    text.lines()
        .filter_map(|line| {
            let idx = line.find("inet ")?;
            let rest = line[idx + "inet ".len()..].trim_start();
            let tok = rest.split_whitespace().next()?;
            let (addr, _prefixlen) = tok.split_once('/').unwrap_or((tok, "32"));
            if ipv4_octets(addr).is_some() {
                Some(addr.to_string())
            } else {
                None
            }
        })
        .collect()
}

/// Parse `getent hosts <ip>` output (`"<ip>  <hostname> [aliases...]"`) → the PTR hostname, or
/// `None` if it didn't resolve (NXDOMAIN / empty output / no PTR record) — reported honestly,
/// never guessed.
pub fn parse_getent_hosts(text: &str) -> Option<String> {
    let line = text.lines().next()?.trim();
    if line.is_empty() {
        return None;
    }
    let mut it = line.split_whitespace();
    it.next()?; // the ip column
    it.next().map(|h| h.trim_end_matches('.').to_string())
}

/// Build/merge the WAN network-intel record for one scan alert — the `Wan`-classified
/// counterpart of `enrich_host`. `prev` is folded forward the same way (scan facts accumulate
/// across alert lines instead of being overwritten each call).
pub fn enrich_wan(prev: Option<&WanIntel>, alert: &ScanAlert, ptr: Option<&str>, reputation: Option<&str>, now: f64) -> WanIntel {
    let mut ports: BTreeSet<u16> = prev.map(|p| p.scan_ports.iter().copied().collect()).unwrap_or_default();
    ports.insert(alert.dst_port);
    let mut targets: BTreeSet<String> = prev.map(|p| p.scan_targets.iter().cloned().collect()).unwrap_or_default();
    targets.insert(alert.dst_ip.clone());
    let scan_count = prev.map(|p| p.scan_count).unwrap_or(0) + 1;
    let first_seen = prev.map(|p| p.first_seen).unwrap_or(now);
    WanIntel {
        ip: alert.src_ip.clone(),
        ptr: ptr.map(String::from).or_else(|| prev.and_then(|p| p.ptr.clone())),
        network_group: wan_network_group(&alert.src_ip),
        is_bogon: is_bogon_v4(&alert.src_ip),
        reputation: reputation.map(String::from).or_else(|| prev.and_then(|p| p.reputation.clone())),
        first_seen,
        last_seen: now,
        scan_targets: targets.into_iter().collect(),
        scan_ports: ports.into_iter().collect(),
        scan_count,
    }
}

// ---------------------------------------------------------------------------
// Safety valve — NEVER quarantine the management path / gateway / WAN / self.
//
// `ProtectPolicy`/`protect_reason` now live in the shared `hookprobe_mgmt_guard` crate
// (re-exported at the top of this file) — see that crate's docs for the 2026-07-05 threat-model
// fixes (HIGH #4/#5) this predicate encodes, and the 2026-07 audit fix that made `aegis-guard`'s
// reflex engine share it too.
// ---------------------------------------------------------------------------

/// 2026-07-05 threat-model fix (HIGH #4): true if `(src_ip, dst_ip)` is a WAN-ingress martian —
/// the alert's TARGET (`dst_ip`) is one of this device's own WAN-side addresses (`wan_self_ips`,
/// e.g. the live WAN IP), which means the packet necessarily arrived via the WAN interface,
/// yet the claimed SOURCE is a private/reserved/loopback/CGNAT address that could never
/// legitimately route across the public internet to reach it. This is a STRONGER, ingress-fact-
/// based check than `classify_source(src_ip)` alone: that function (correctly, for LAN/WAN
/// enforcement-plane purposes) calls an RFC1918 address "Lan" wherever it appears; this check
/// asks the orthogonal question "is this specific (src, dst) pair even physically possible" —
/// seeing a private-looking source arrive at this device's OWN public WAN address is definitive
/// proof of spoofing or gross misrouting, never a real scanner. Fails toward `false` (not
/// flagged) on unparseable input, matching `is_bogon_v4`'s convention.
pub fn is_wan_ingress_martian(src_ip: &str, dst_ip: &str, wan_self_ips: &[String]) -> bool {
    if !wan_self_ips.iter().any(|w| w == dst_ip) {
        return false;
    }
    classify_source(src_ip) == SourceKind::Lan || is_bogon_v4(src_ip)
}

// ---------------------------------------------------------------------------
// CONFIRMATION, SOURCE #2 — conntrack ESTABLISHED (2026-07-06 fix, F4, live Pi pentest).
//
// `ScanAlert::confirmed` (napse_loader::confirm::HandshakeTracker, fed by the tc-mirred packet
// copy) was, before the companion 2026-07-06 F1 fix
// (modules/napse-quarantine/bpf/quarantine.bpf.c / modules/napse-l2guard/bpf/l2guard.bpf.c), the
// ONLY confirmation source `decide` ever saw — and the tc ingress guards' `TC_ACT_OK` pass-path
// bug meant the mirror NEVER delivered inbound traffic to napse-dpi on real hardware, so
// `confirmed` was structurally stuck at `false` for every alert: `decide` never durably
// quarantined anything, no matter how real the attack (F1's doc comment has the full mechanism).
// F1 fixes the root cause, but a mirror is still ONE pipeline that can fail again in a different
// way (a bad NIC offload, a future filter-priority regression, a driver bug) — `is_confirmed_any`
// below makes confirmation robust to that by ALSO trusting this device's OWN conntrack table,
// entirely independent of the tc-mirred copy: `/var/lib/hookprobe/flows` (rendered by
// `napse_loader::event::NapseEvent::to_flow_json` and `senzorium-flow-export.sh`) already carries
// a Zeek-style `conn_state` per `"type":"conn"` record, and a record showing `"SF"` (this
// pipeline's rendering of a raw kernel conntrack `ESTABLISHED`+ state — see both renderers' state
// tables) for a flow naming this IP is proof this device's OWN kernel completed a real 3-way
// handshake to/from it. An off-path spoofer cannot forge that any more than it can forge the
// mirror-observed final ACK `HandshakeTracker` requires (same ISN-blindness argument, see
// `napse_loader::confirm`'s module doc comment) — the kernel only advances a conntrack entry to
// ESTABLISHED once ITS OWN stack has seen a validly-acknowledging final ACK, so this is a
// genuinely independent, equally spoof-resistant signal, not a weaker stand-in.
//
// ANTI-SPOOF INVARIANT PRESERVED: this ONLY broadens how a LEGITIMATE source becomes confirmed.
// A source with neither a validated mirror handshake NOR a conntrack ESTABLISHED entry is
// UNCHANGED — still never reaches `ReflexVerdict::Quarantine` (see `decide`'s unconfirmed ->
// `RateLimit` gate, untouched below). Deliberately IP-only (no MAC pairing, unlike
// `HandshakeTracker`'s `(ip, mac)` key): conntrack is an L3 concept with no L2 visibility, so this
// signal is strictly IP-scoped — it is an OR with the MAC-keyed handshake signal, never a
// replacement for it.
// ---------------------------------------------------------------------------

/// `conn_state` values (as rendered on-disk by `napse_loader::event::NapseEvent::to_flow_json` and
/// `senzorium-flow-export.sh`) that represent a validated TCP handshake this device's OWN kernel
/// completed. `"SF"` is the Zeek-style code both renderers use for a raw conntrack `ESTABLISHED`
/// (and later steady, e.g. `TIME_WAIT`/`CLOSE_WAIT`) state; `"ESTABLISHED"` itself is accepted too
/// so this function also works if ever fed raw `conntrack -L`-style text instead of the rendered
/// JSONL (defensive, costs nothing — the rendered stream never emits that literal string today).
const CONNTRACK_ESTABLISHED_CONN_STATES: &[&str] = &["SF", "ESTABLISHED"];

/// `true` iff `flows_jsonl` (the `/var/lib/hookprobe/flows` stream — one JSON object per line)
/// contains at least one `"type":"conn"` record whose `src_ip` OR `dst_ip` equals `ip` and whose
/// `conn_state` is one of [`CONNTRACK_ESTABLISHED_CONN_STATES`]. Matches either direction because
/// `ip` may be the flow's initiator (its own outbound handshake) or responder (an inbound
/// handshake this device completed as the server) — either way, this device's kernel reached
/// ESTABLISHED for a real 3-way handshake naming `ip`. Malformed/non-JSON lines are skipped, never
/// treated as an error (this reads a live, appended-to log; a partially-written last line is
/// expected, not exceptional) — fails toward `false` (not established) on anything it cannot
/// parse, the same fail-CLOSED-toward-"not confirmed" convention `ScanAlert::confirmed`'s
/// `#[serde(default)]` already documents.
pub fn conntrack_established(flows_jsonl: &str, ip: &str) -> bool {
    for line in flows_jsonl.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let Ok(v) = serde_json::from_str::<serde_json::Value>(line) else {
            continue;
        };
        if v.get("type").and_then(|t| t.as_str()) != Some("conn") {
            continue;
        }
        let established = v
            .get("conn_state")
            .and_then(|s| s.as_str())
            .is_some_and(|s| CONNTRACK_ESTABLISHED_CONN_STATES.contains(&s));
        if !established {
            continue;
        }
        let src_matches = v.get("src_ip").and_then(|s| s.as_str()) == Some(ip);
        let dst_matches = v.get("dst_ip").and_then(|s| s.as_str()) == Some(ip);
        if src_matches || dst_matches {
            return true;
        }
    }
    false
}

/// The broadened confirmation gate `decide`'s caller should use in place of the bare
/// `ScanAlert::confirmed` bit (2026-07-06 fix, F4): `true` if EITHER the mirror-fed
/// `HandshakeTracker` already confirmed this (ip, mac) pair (`alert_confirmed`, i.e. the alert's
/// own `confirmed` field) OR this device's conntrack table independently shows an ESTABLISHED
/// flow naming `ip` ([`conntrack_established`]). See this section's module-level doc comment for
/// the full rationale and the preserved anti-spoof invariant. `flows_jsonl` is expected to be the
/// current contents (or a recent tail) of `/var/lib/hookprobe/flows`; an empty/unreadable stream
/// degrades gracefully to `alert_confirmed` alone (never panics, never confirms on its own).
pub fn is_confirmed_any(alert_confirmed: bool, flows_jsonl: &str, ip: &str) -> bool {
    alert_confirmed || conntrack_established(flows_jsonl, ip)
}

// ---------------------------------------------------------------------------
// DROP — the reflex verdict (reuses trust::evaluate; deterministic, model-free).
// ---------------------------------------------------------------------------

/// The reflex verdict for one scanner.
#[derive(Debug, Clone, PartialEq)]
pub enum ReflexVerdict {
    /// Enforce via nft (subject to the TTL/idempotency reconcile below).
    Quarantine { reason: String },
    /// Never enforced — the management-path fail-safe fired.
    Allowlisted { reason: String },
    /// 2026-07-05 threat-model fix (EDR #3 — the "external SYN-scanner detected-but-not-enforced"
    /// gap): an UNCONFIRMED source (no validated 3-way handshake — see [`ReflexVerdict::Observed`]'s
    /// doc for why that alone must never reach [`ReflexVerdict::Quarantine`]) is NOT left entirely
    /// unenforced anymore. `decide` already only reaches this arm once `portscan::PortScanTracker`
    /// (or the wasm engine's rule 1000003) has ALREADY crossed its own distinct-dst-port fan-out
    /// threshold — i.e. a real fan-out is an established fact by the time this verdict fires, only
    /// HANDSHAKE confirmation of the claimed identity is missing (the overwhelmingly common case
    /// for an external SYN/stealth scanner: it never completes a handshake by design). Mirrors
    /// `l2_responder::L2Verdict::RateLimit`'s EXACT anti-spoof discipline one layer up the stack —
    /// see [`render_syn_fanout_rate_limit`]: a bounded, SELF-REVERTING per-source-IP SYN-rate cap
    /// (an nft `meter`, kernel-timeout-expired, never a persisted state file), never a durable,
    /// identity-keyed block — reflecting a victim's spoofed IP through this path costs it, at most,
    /// a few SYN packets/second for ONE rate window, the same bounded blast-radius property
    /// `L2Verdict::RateLimit` documents. This is a THROTTLE on the FLOW, not a claim about WHO sent
    /// it — the frame/flow itself (a SYN fan-out already crossed a real threshold) is the evidence.
    RateLimit { reason: String },
    /// 2026-07-05 threat-model fix (CRITICAL #1 / HIGH #4): detected and logged, but NEVER
    /// enforced (not even rate-limited) — the source is a WAN-ingress martian
    /// (`is_wan_ingress_martian`): a private/reserved/bogon address that could never have
    /// physically routed here, so ANY enforcement keyed on it (durable OR rate-limited) can only
    /// ever cost a real, uninvolved victim address something, never the actual attacker. This is
    /// the verdict that closes the reflected-DoS: a single-packet, spoofable claimed source can
    /// reach this verdict, but it can NEVER reach `Quarantine` — no code path in `decide` lets it.
    Observed { reason: String },
}

/// Decide the reflex verdict for a scanner.
///
/// Order of gates (2026-07-05 threat-model fix — CRITICAL #1, HIGH #4/#5; VERIFY-pass re-audit
/// Q5 correction; EDR #3 rate-limit fix):
///   1. WAN-ingress martian (`is_wan_ingress_martian`) → `Observed`, unconditionally — a source
///      that cannot physically be who it claims is never enforced (not even rate-limited),
///      confirmed or not.
///   2. Management-path allowlist (`protect_reason`, now MAC-bound for LAN — HIGH #5) →
///      `Allowlisted`. Checked BEFORE the confirmed/unconfirmed split (EDR #3 fix) so an
///      unconfirmed "scan" from the gateway/mgmt subnet/this device's own WAN address is JUST AS
///      un-rate-limited as a confirmed one would be un-quarantined — self-lockout is worse than a
///      missed detection either way.
///   3. Unconfirmed (`!confirmed`) → `RateLimit` (EDR #3 fix, was unconditionally `Observed` with
///      zero enforcement before this pass) — a bounded, self-reverting per-source SYN-rate cap
///      (see [`render_syn_fanout_rate_limit`]), never a durable identity block. The fan-out alert
///      is still detected/logged either way (`napse_loader::portscan` never suppresses emission).
///   4. Otherwise → `Quarantine`, via the EXISTING `trust::evaluate` reconciler (`threat =
///      Malicious` — a port scan, T1046, is definitionally malicious; no risk-score judgment call
///      needed), the same deterministic path continuous-trust quarantine uses.
///
/// # Q5 correction — `wan_self_ips` is a SEPARATE, dedicated parameter (never `policy.ips`)
/// `policy.ips` is the ALLOWLIST (mgmt subnet, LAN gateway, DNS resolvers — addresses this device
/// must never quarantine). `wan_self_ips` is an entirely different concept: the device's OWN
/// WAN-interface address(es), used ONLY to detect a physically-impossible ingress (a private/
/// reserved source claiming to have routed across the public internet to reach THIS device's own
/// WAN address). The original implementation passed `policy.ips` for both, which meant a
/// LAN-side scanner targeting the LAN gateway or a DNS resolver (both legitimately in
/// `policy.ips`) got misclassified as `is_wan_ingress_martian` — flagged `Observed` and NEVER
/// enforced, letting a LAN attacker evade detection by aiming at exactly the addresses this
/// reflex most needs to protect. Callers MUST build `wan_self_ips` from the live WAN interface
/// address only (see `parse_wan_self_ips`), never from the protect/allowlist set.
///
/// # `confirmed` (2026-07-06 fix, F4) — pass [`is_confirmed_any`]'s result, not the bare alert bit
/// Callers SHOULD compute this parameter as `is_confirmed_any(alert.confirmed, flows_jsonl,
/// ip)` rather than `alert.confirmed` alone, so a mirror-pipeline outage (the tc ingress bug the
/// companion 2026-07-06 F1 fix addresses, or any future regression like it) cannot single-
/// -handedly hold every alert at `confirmed = false` forever — see this module's "CONFIRMATION,
/// SOURCE #2" section above for the full rationale. `decide` itself is unchanged: it still simply
/// trusts whatever `confirmed` it is handed, keeping the martian/allowlist/rate-limit gates below
/// exactly as strict either way.
#[allow(clippy::too_many_arguments)]
pub fn decide(
    ip: &str,
    dst_ip: &str,
    distinct_ports: usize,
    confirmed: bool,
    observed_mac: Option<&str>,
    policy: &ProtectPolicy,
    wan_self_ips: &[String],
) -> ReflexVerdict {
    if is_wan_ingress_martian(ip, dst_ip, wan_self_ips) {
        return ReflexVerdict::Observed {
            reason: format!(
                "{ip} is a private/reserved address claiming to reach this device's own WAN address {dst_ip} — \
                 impossible over the public internet (spoofed or misrouted); scan logged, NOT quarantined"
            ),
        };
    }
    // EDR #3 fix: the management-path fail-safe now gates BOTH enforcement arms below (previously
    // only ever reached from the confirmed/Quarantine path — see this function's doc comment).
    if let Some(reason) = protect_reason(ip, observed_mac, policy) {
        return ReflexVerdict::Allowlisted { reason };
    }
    if !confirmed {
        return ReflexVerdict::RateLimit {
            reason: format!(
                "{ip}'s SYN fan-out ({distinct_ports} distinct port(s) probed) has NOT completed a validated \
                 TCP handshake — a single-packet, spoofable claimed source alone must never be durably \
                 quarantined; a bounded, self-reverting per-source SYN-rate cap is applied instead (nft \
                 meter, kernel-timeout auto-revert — never an identity block)"
            ),
        };
    }

    let signal = PostureSignal {
        mac: ip.to_string(),
        current_segment: "unknown".to_string(),
        risk: 95.0,
        threat: ThreatLevel::Malicious,
        reasons: vec![format!("NAPSE port scan: {distinct_ports} distinct port(s) probed (MITRE T1046)")],
        // A completed-handshake port scan is a DIRECTLY-confirmed attack (this arm is only reached
        // once `confirmed` is true), so it keeps `Direct` provenance and quarantines unconditionally
        // — the Finding-1 intel-only corroboration gate does not apply to it.
        provenance: trust::SignalProvenance::Direct,
        corroborated: false,
    };
    let decision = trust::evaluate(&signal, &TrustPolicy::default());
    debug_assert_eq!(
        decision.action,
        TrustAction::Quarantine,
        "a Malicious threat verdict always quarantines in trust::evaluate"
    );
    ReflexVerdict::Quarantine { reason: decision.reason }
}

// ---------------------------------------------------------------------------
// EDR #3 fix — bounded, self-reverting per-source SYN-fanout rate-limit (nft meter), the SAME
// anti-spoof discipline `l2_responder::render_storm_control` establishes one layer down the stack,
// reapplied here for [`ReflexVerdict::RateLimit`]. A SEPARATE table from BOTH `hookprobe_quarantine`
// (this file's persisted, identity-keyed durable block) and `hookprobe_l2guard` (the L1/L2 storm
// control) — nothing here is a persisted state file; a source that stops SYN-scanning simply ages
// out of the meter on its own, exactly like `l2_responder`'s meters do.
// ---------------------------------------------------------------------------

const SYN_RATELIMIT_NFT_TABLE: &str = "hookprobe_scan_ratelimit";
const SYN_RATELIMIT_BANNER: &str =
    "# GENERATED by hookprobe scan-responder — deterministic nft SYN-fanout rate-limit (self-reverting meter).\n\
     # Do NOT edit by hand. Bounded/self-reverting (EDR #3) — a SEPARATE table from BOTH this file's\n\
     # persistent quarantine table and the L1/L2 responder's storm-control table.\n";

/// Config for [`render_syn_fanout_rate_limit`]. Interface defaults match [`IfaceConfig::default`]
/// so one operator-configured interface set configures every responder in this crate consistently.
#[derive(Debug, Clone)]
pub struct SynRateLimitConfig {
    pub lan_iface: String,
    pub wan_iface: String,
    /// Per-source-IP new-SYN packets/second ceiling once an unconfirmed fan-out has already been
    /// OBSERVED for that source (see [`ReflexVerdict::RateLimit`]'s doc — this is the mitigation
    /// cap, not the detection threshold, exactly the same "detection threshold vs enforcement cap"
    /// split `l2_responder::L2GuardConfig`'s fields document). Deliberately much lower than a real
    /// client's normal SYN rate — a legitimate host opening a handful of connections/second is far
    /// below this cap; a scanner probing dozens of ports/second is far above it.
    pub syn_pps: u32,
    /// How long an idle per-source meter entry survives before nft itself expires it — the
    /// self-revert (no code in this crate ever un-limits a meter entry; nft's own dynamic-set
    /// timeout does, identical discipline to `l2_responder::L2GuardConfig::meter_timeout_secs`).
    pub meter_timeout_secs: u64,
}
pub const DEFAULT_SYN_RATELIMIT_PPS: u32 = 10;
pub const DEFAULT_SYN_RATELIMIT_METER_TIMEOUT_SECS: u64 = 60;
impl Default for SynRateLimitConfig {
    fn default() -> Self {
        SynRateLimitConfig {
            lan_iface: "wlan0".to_string(),
            wan_iface: "end0".to_string(),
            syn_pps: DEFAULT_SYN_RATELIMIT_PPS,
            meter_timeout_secs: DEFAULT_SYN_RATELIMIT_METER_TIMEOUT_SECS,
        }
    }
}

/// Render the SYN-fanout rate-limit bootstrap — table + forward/input chains + TWO `meter`-backed
/// rate-limit rules (one per chain; nft rejects the SAME meter name referenced from two different
/// rules as "overlaps an existing set", reproduced empirically while building this — hence two
/// distinctly-named meters, not one reused across both chains), matching new (SYN, no ACK) TCP
/// packets by source IP on EITHER the LAN or WAN ingress (an unconfirmed scanner can originate from
/// either side — see `classify_source`).
///
/// **Idempotent by construction (learns H1's lesson up front — see `l2_responder::render_storm_control`'s
/// doc comment for the exact failure mode this avoids):** a `meter NAME { ... }` declared inline in
/// `add rule` creates an IMPLICIT, table-scoped named set that OUTLIVES `flush chain` — re-applying
/// this script without first dropping the table would hit nft's real "File exists; meter '…'
/// overlaps an existing set '…'" error on the SECOND apply (reproduced manually for this exact
/// pattern while diagnosing H1). This renderer therefore ALSO `delete table`s first, unconditionally,
/// exactly like `l2_responder::render_storm_control` does — safe under the SAME per-line,
/// continue-on-failure application model (`supervisor::apply_or_print`) this crate's other
/// renderers already assume; see that function's doc for the documented `nft -f` batch-mode caveat.
pub fn render_syn_fanout_rate_limit(cfg: &SynRateLimitConfig) -> GeneratedFile {
    let (lan, wan) = (cfg.lan_iface.as_str(), cfg.wan_iface.as_str());
    let t = cfg.meter_timeout_secs;
    let mut s = String::from(SYN_RATELIMIT_BANNER);
    s.push_str(&format!(
        "# SYN-fanout rate-limit on {lan}/{wan}: {}pps per source ip, meter idle-timeout {t}s.\n",
        cfg.syn_pps
    ));
    s.push_str(&format!("delete table inet {SYN_RATELIMIT_NFT_TABLE}\n"));
    s.push_str(&format!("add table inet {SYN_RATELIMIT_NFT_TABLE}\n"));
    s.push_str(&format!(
        "add chain inet {SYN_RATELIMIT_NFT_TABLE} forward {{ type filter hook forward priority -4; policy accept; }}\n"
    ));
    s.push_str(&format!(
        "add chain inet {SYN_RATELIMIT_NFT_TABLE} input {{ type filter hook input priority -4; policy accept; }}\n"
    ));
    s.push_str(&format!("flush chain inet {SYN_RATELIMIT_NFT_TABLE} forward\n"));
    s.push_str(&format!("flush chain inet {SYN_RATELIMIT_NFT_TABLE} input\n"));
    for iface in [lan, wan] {
        s.push_str(&format!(
            "add rule inet {SYN_RATELIMIT_NFT_TABLE} forward iifname \"{iface}\" tcp flags syn / syn,ack meter napse_synfanout_fwd_{iface}_meter {{ ip saddr timeout {t}s limit rate over {}/second }} counter drop comment \"hookprobe-scan-ratelimit-fwd-{iface}\"\n",
            cfg.syn_pps
        ));
        s.push_str(&format!(
            "add rule inet {SYN_RATELIMIT_NFT_TABLE} input iifname \"{iface}\" tcp flags syn / syn,ack meter napse_synfanout_in_{iface}_meter {{ ip saddr timeout {t}s limit rate over {}/second }} counter drop comment \"hookprobe-scan-ratelimit-in-{iface}\"\n",
            cfg.syn_pps
        ));
    }
    GeneratedFile { path: "quarantine/02-syn-ratelimit.nft".to_string(), content: s }
}

// ---------------------------------------------------------------------------
// TTL / idempotency — the persisted quarantine state + reconcile diff.
// ---------------------------------------------------------------------------

/// One quarantined scanner's TTL bookkeeping (persisted JSON, `--quarantine-state-file`).
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct QuarantineEntry {
    pub ip: String,
    #[serde(default)]
    pub mac: Option<String>,
    pub first_seen: f64,
    pub last_seen: f64,
    /// 2026-07-05 threat-model fix (MEDIUM #6 — escalating hold): number of times this entry has
    /// been (re-)observed while ALREADY quarantined. Every call into `reconcile_quarantine` for a
    /// given `ip` only ever happens for a CONFIRMED (validated-handshake) or allowlisted source —
    /// `decide`'s `Observed` verdict never reaches this function — so this can only grow on real
    /// repeat offenses, never on a spoofed/unconfirmed replay. Defaults to `1` for a fresh/older
    /// entry (never `0` — an entry always represents at least one offense).
    #[serde(default = "one")]
    pub offenses: u32,
}
fn one() -> u32 {
    1
}

/// 2026-07-05 threat-model fix (MEDIUM #6): the effective hold time for an entry, growing with
/// repeat CONFIRMED offenses (an attacker can't reset this by merely pausing — offenses persist
/// across TTL windows via `reconcile_quarantine`'s refresh path) but capped at
/// `ESCALATION_CAP`× the base TTL so a hold can never grow unbounded.
const ESCALATION_CAP: u32 = 6;
pub fn effective_ttl_secs(base_ttl_secs: u64, offenses: u32) -> u64 {
    base_ttl_secs.saturating_mul(offenses.clamp(1, ESCALATION_CAP) as u64)
}

/// What one reconcile cycle must DO to the live nft sets, and the full state to persist next.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct QuarantineDiff {
    /// Newly-quarantined this cycle (nft `add element`).
    pub to_add: Vec<QuarantineEntry>,
    /// TTL-expired or force-released this cycle (nft `delete element`).
    pub to_remove: Vec<QuarantineEntry>,
    /// The full surviving set — persist this as next cycle's state.
    pub state: Vec<QuarantineEntry>,
}

/// TTL sweep shared by both the per-alert reconcile and the standalone sweep cycle: an entry
/// whose `last_seen` is more than its OWN escalated TTL old (see [`effective_ttl_secs`]) is
/// expired and removed; everything else is kept.
fn ttl_sweep(state: Vec<QuarantineEntry>, now: f64, ttl_secs: u64) -> (Vec<QuarantineEntry>, Vec<QuarantineEntry>) {
    state.into_iter().partition(|e| now - e.last_seen <= effective_ttl_secs(ttl_secs, e.offenses) as f64)
}

/// 2026-07-05 threat-model fix (MEDIUM #7): bound on the persisted/enforced quarantine set —
/// caps how large `scan-quarantine.json` (and therefore the nft sets / BPF maps mirroring it) can
/// grow. Every entry here is already CONFIRMED (validated handshake) by construction (`decide`'s
/// `Observed` verdict never reaches `reconcile_quarantine`), so eviction simply prefers the
/// LEAST-RECENTLY-active entry (oldest `last_seen`) — the entry least likely to still be an
/// active, ongoing offense.
pub const DEFAULT_MAX_QUARANTINE_ENTRIES: usize = 4096;

/// Evict the oldest-`last_seen` entries down to `max_entries`, returning `(kept, evicted)`.
fn cap_entries(mut state: Vec<QuarantineEntry>, max_entries: usize) -> (Vec<QuarantineEntry>, Vec<QuarantineEntry>) {
    if state.len() <= max_entries {
        return (state, Vec::new());
    }
    state.sort_by(|a, b| a.last_seen.partial_cmp(&b.last_seen).unwrap_or(std::cmp::Ordering::Equal));
    let evict_count = state.len() - max_entries;
    // `split_off(at)` returns [at, len) and leaves [0, at) in `state` — since `state` is sorted
    // ascending by `last_seen`, the returned tail is the NEWEST `max_entries` (kept) and what
    // remains in `state` is the OLDEST `evict_count` (evicted).
    let kept = state.split_off(evict_count);
    (kept, state)
}

/// Reconcile one scanner observation into the persisted quarantine state.
///
/// - **New scanner** (not `allowlisted`) → added to state, `to_add` gets one entry (`offenses=1`).
/// - **Already-quarantined scanner re-observed within the TTL window** → `last_seen` is
///   refreshed and `offenses` incremented (escalating hold, MEDIUM #6) but NO `add` is re-emitted
///   — this is what makes re-applying the same quarantine a no-op (idempotent): the nft element
///   is already there.
/// - **Allowlisted (mgmt-path) scanner** → if it was somehow already in state (the allowlist
///   changed under us, or a race), it is force-removed immediately — a management-path false
///   positive must self-correct as fast as possible, not wait out the TTL.
/// - **Every cycle**, regardless of the above, the TTL sweep runs — any entry quiet for more
///   than its (possibly escalated) TTL is released (`to_remove`). This is the auto-revert.
/// - **The set is capped** at `max_entries` (MEDIUM #7) — the caller passes
///   [`DEFAULT_MAX_QUARANTINE_ENTRIES`] unless it has a reason not to.
pub fn reconcile_quarantine(
    mut state: Vec<QuarantineEntry>,
    ip: &str,
    mac: Option<&str>,
    now: f64,
    ttl_secs: u64,
    allowlisted: bool,
    max_entries: usize,
) -> QuarantineDiff {
    let mut diff = QuarantineDiff::default();
    let existing = state.iter().position(|e| e.ip == ip);

    if allowlisted {
        if let Some(idx) = existing {
            diff.to_remove.push(state.remove(idx));
        }
    } else {
        match existing {
            Some(idx) => {
                state[idx].last_seen = now;
                state[idx].offenses = state[idx].offenses.saturating_add(1);
            }
            None => {
                let e = QuarantineEntry {
                    ip: ip.to_string(),
                    mac: mac.map(String::from),
                    first_seen: now,
                    last_seen: now,
                    offenses: 1,
                };
                state.push(e.clone());
                diff.to_add.push(e);
            }
        }
    }

    let (keep, expired) = ttl_sweep(state, now, ttl_secs);
    diff.to_remove.extend(expired);
    let (keep, evicted) = cap_entries(keep, max_entries.max(1));
    diff.to_remove.extend(evicted);
    diff.state = keep;
    diff
}

/// Sweep-only reconcile (the `--scan-respond-sweep` timer path, independent of any new alert):
/// expire anything quiet for more than its (possibly escalated) TTL. Delegates to the SAME
/// `ttl_sweep` helper the per-alert path uses, so the two entry points can never define "expired"
/// differently.
pub fn sweep_quarantine(state: Vec<QuarantineEntry>, now: f64, ttl_secs: u64) -> QuarantineDiff {
    let (keep, expired) = ttl_sweep(state, now, ttl_secs);
    QuarantineDiff { to_add: Vec::new(), to_remove: expired, state: keep }
}

// ---------------------------------------------------------------------------
// nft rendering — declarative, idempotent-safe artifacts (mirrors the `GeneratedFile` pattern
// `trust.rs`/`fabric.rs`/`microseg.rs` already use for reconciler output).
// ---------------------------------------------------------------------------

const NFT_TABLE: &str = "hookprobe_quarantine";
const BANNER: &str =
    "# GENERATED by hookprobe scan-responder — deterministic nft quarantine (TTL auto-revert).\n\
     # Do NOT edit by hand.\n";

/// Interfaces the quarantine enforcement binds to: the LAN/AP side (ip+mac drop) and the WAN
/// uplink (ip-only drop — a routed WAN source has no L2 MAC to bind). NEVER the real reconcile
/// path's source of truth — that is `aegis::reconcile_network`'s `ifaces.env` (derived from THIS
/// SAME manifest's classified WAN uplink + bridge/routed-AP LAN side, plumbed to
/// `scan-responder.sh`/`hookprobe-supervisor --scan-respond` via
/// `EnvironmentFile=-/var/lib/hookprobe/ifaces.env` → `--lan-iface`/`--wan-iface`). `Default`
/// below is only reached if a caller builds an `IfaceConfig` without resolving anything (the CLI
/// path in `supervisor/src/main.rs` never does) — kept as the historical Pi 4 topology
/// (`docs/architecture/network-segmentation.md`; `aegis.rs`'s routed-AP plane: the onboard AP radio, no bridge
/// since brcmfmac can't bridge AP unicast, + the wired uplink) so an un-configured invocation
/// still does something sane on the reference platform, never silently nothing.
#[derive(Debug, Clone)]
pub struct IfaceConfig {
    pub lan: String,
    pub wan: String,
}
impl Default for IfaceConfig {
    fn default() -> Self {
        IfaceConfig { lan: "wlan0".to_string(), wan: "end0".to_string() }
    }
}
impl IfaceConfig {
    /// The interface a given source kind is enforced on (for response-event detail strings).
    pub fn for_kind(&self, kind: SourceKind) -> &str {
        match kind {
            SourceKind::Lan => &self.lan,
            SourceKind::Wan => &self.wan,
        }
    }
}

/// LAST-RESORT fallback for the Ring-0 BPF loaders (`napse-quarantine`/`napse-l2guard`): if their
/// CONFIGURED interface (from `ifaces.env`/CLI/env) isn't present in sysfs at startup — e.g.
/// `ifaces.env` hasn't been generated yet on a device that never ran
/// `hookprobe-network-reconcile.service` — read the SIGNED manifest directly and derive a
/// best-effort candidate from facts alone (no intent document needed, unlike the full
/// `aegis::reconcile_network` pass): the WAN uplink is the manifest's own already-priority-ordered
/// `network.uplinks[0]`; the LAN candidate is the first AP-role Wi-Fi radio, else the SECOND
/// uplink (a second wired port, best-effort — the reconciler's own bridge-vs-routed distinction
/// isn't reproduced here on purpose: this is a fallback of last resort, not a second copy of the
/// fabric planner). Returns `(wan, lan)`; either side may be `None` on a manifest with nothing to
/// offer, in which case the caller keeps its originally-configured name (fail-open — the per-iface
/// attach loop already tolerates one bad interface without stopping the other).
pub fn manifest_iface_fallback(manifest: &crate::types::Manifest) -> (Option<String>, Option<String>) {
    let wan = manifest.network.uplinks.first().map(|u| u.name.clone());
    let lan = manifest
        .network
        .wifi_radios
        .iter()
        .find(|w| w.role == "ap")
        .map(|w| w.name.clone())
        .or_else(|| manifest.network.uplinks.get(1).map(|u| u.name.clone()));
    (wan, lan)
}

/// The static bootstrap: table + THREE TIMEOUT-flagged sets (kernel-level auto-expiry, belt-
/// and-braces alongside the Rust-side TTL sweep, which is authoritative) + forward/input DROP
/// rules scoped to the RIGHT interface for each source kind — the LAN/WAN branch, rendered:
///   - LAN (`ifaces.lan`) — ip AND mac sets/rules are declared, but (2026-07-05 Q2 half 2 fix)
///     [`render_element_ops`] NEVER populates `quarantine_lan_ips` — LAN enforcement is MAC-only
///     in practice. The ip set/rule are kept declared for forward compatibility (e.g. a future,
///     explicitly-operator-confirmed IP binding) and because an always-empty nft set is inert,
///     not a liability.
///   - WAN (`ifaces.wan`) — ip-only set, enforced on INPUT (shields this box's own exposed
///     services) and forward (defense-in-depth for anything port-forwarded through it).
///
/// Safe to re-apply: `add table`/`add set`/`add chain` are no-ops when the object already
/// exists with the same spec, and `flush chain` before `add rule` means re-running this whole
/// script never accumulates duplicate rules — only the named SETS carry state, untouched by
/// `flush chain`.
pub fn render_bootstrap(ttl_secs: u64, ifaces: &IfaceConfig) -> GeneratedFile {
    let (lan, wan) = (ifaces.lan.as_str(), ifaces.wan.as_str());
    let mut s = String::from(BANNER);
    s.push_str(&format!(
        "# default element timeout {ttl_secs}s; LAN quarantine on {lan} (ip+mac), WAN quarantine on {wan} (ip only).\n\
         # --scan-respond-sweep's state-file TTL sweep is the authoritative revert path.\n"
    ));
    s.push_str(&format!("add table inet {NFT_TABLE}\n"));
    s.push_str(&format!("add set inet {NFT_TABLE} quarantine_lan_ips {{ type ipv4_addr; flags timeout; }}\n"));
    s.push_str(&format!("add set inet {NFT_TABLE} quarantine_lan_macs {{ type ether_addr; flags timeout; }}\n"));
    s.push_str(&format!("add set inet {NFT_TABLE} quarantine_wan_ips {{ type ipv4_addr; flags timeout; }}\n"));
    s.push_str(&format!("add chain inet {NFT_TABLE} forward {{ type filter hook forward priority -5; policy accept; }}\n"));
    s.push_str(&format!("add chain inet {NFT_TABLE} input {{ type filter hook input priority -5; policy accept; }}\n"));
    s.push_str(&format!("flush chain inet {NFT_TABLE} forward\n"));
    s.push_str(&format!("flush chain inet {NFT_TABLE} input\n"));
    // 2026-07-06 fix (proven on real hardware): a quarantined source must be dropped on WHICHEVER
    // ingress interface it actually arrives on — NOT only the interface matching its IP-based
    // LAN/WAN class. On-metal, a confirmed private-IP (so LAN-classified → mac-keyed) scanner that
    // arrived on the WAN uplink `end0` was quarantined into `quarantine_lan_macs` but NEVER dropped,
    // because the mac-drop rule was scoped to the LAN iface alone (this happens for real with
    // CGNAT/double-NAT WANs, `100.64/10` uplinks, or a directly-attached private-addressed WAN
    // segment). So every drop rule now fires on the UNION of the {lan, wan} ingress interfaces, on
    // both the `forward` (transit / port-forward) and `input` (this box's own services) hooks. Both
    // the mac-keyed drop (L2-adjacent source, the anti-spoof identity) and the ip-keyed drops apply
    // on every ingress iface: the sets only ever hold CONFIRMED-quarantined identities, so widening
    // the interface scope can never introduce a false drop, only close the "arrived on the wrong
    // iface → not enforced" gap.
    let ifset = if lan == wan { format!("\"{lan}\"") } else { format!("{{ \"{lan}\", \"{wan}\" }}") };
    for hook in ["forward", "input"] {
        s.push_str(&format!("add rule inet {NFT_TABLE} {hook} iifname {ifset} ether saddr @quarantine_lan_macs drop comment \"hookprobe-scan-quarantine-lan\"\n"));
        s.push_str(&format!("add rule inet {NFT_TABLE} {hook} iifname {ifset} ip saddr @quarantine_lan_ips drop comment \"hookprobe-scan-quarantine-lan\"\n"));
        s.push_str(&format!("add rule inet {NFT_TABLE} {hook} iifname {ifset} ip saddr @quarantine_wan_ips drop comment \"hookprobe-scan-quarantine-wan\"\n"));
    }
    GeneratedFile { path: "quarantine/00-bootstrap.nft".to_string(), content: s }
}

/// Per-cycle element add/remove — the ONLY commands that change scanner-by-scanner. Routes
/// each entry to its LAN (MAC-only) or WAN (ip-only) set via [`classify_source`] — the SAME
/// classification the bootstrap's iface-scoped rules already key on, so an entry can never
/// land in a set its rules don't drop. Each non-comment line is a single, fully-formed `nft`
/// argv (no shell metacharacters), so a caller can word-split and `exec` it directly — mirrors
/// `trust-reconcile.sh`'s never-`eval` discipline.
///
/// 2026-07-05 VERIFY-pass re-audit (Q2 half 2, CRITICAL): a LAN-classified entry's `ip` is
/// EXACTLY as spoofable as the alert that produced it (`decide`'s `confirmed` gate proves a real
/// handshake happened for SOME `(ip, mac)` pair — see `confirm::HandshakeTracker` — never that
/// `ip` alone is trustworthy in isolation). This function therefore NEVER emits a
/// `quarantine_lan_ips` element for a LAN entry — enforcement is rendered ONLY via the OBSERVED
/// `mac` (`quarantine_lan_macs`), which an off-path attacker cannot forge. An entry that somehow
/// reached this point with no resolved mac is NOT enforced at all on the LAN plane (a comment is
/// emitted so the plan is never silently empty) — it must never fall back to the spoofable IP.
/// `render_bootstrap` still declares the `quarantine_lan_ips` set/rules (kept for forward
/// compatibility, e.g. a future explicitly-operator-confirmed IP binding) but this function is the
/// only writer of quarantine element state, and it never populates that set.
pub fn render_element_ops(diff: &QuarantineDiff, ttl_secs: u64) -> GeneratedFile {
    let mut s = String::from(BANNER);
    if diff.to_add.is_empty() && diff.to_remove.is_empty() {
        s.push_str("# (no change this cycle)\n");
    }
    for e in &diff.to_add {
        // MEDIUM #6: escalating hold — a repeat CONFIRMED offender's nft timeout grows with its
        // `offenses` count (see `effective_ttl_secs`), capped at ESCALATION_CAP× the base TTL.
        let ttl = effective_ttl_secs(ttl_secs, e.offenses);
        match classify_source(&e.ip) {
            SourceKind::Lan => match &e.mac {
                Some(mac) => {
                    s.push_str(&format!("add element inet {NFT_TABLE} quarantine_lan_macs {{ {mac} timeout {ttl}s }}\n"));
                }
                None => {
                    s.push_str(&format!(
                        "# WARNING: LAN quarantine entry for {} has no observed mac — NOT enforced \
                         (never falls back to the spoofable ip)\n",
                        e.ip
                    ));
                }
            },
            SourceKind::Wan => {
                s.push_str(&format!("add element inet {NFT_TABLE} quarantine_wan_ips {{ {} timeout {ttl}s }}\n", e.ip));
            }
        }
    }
    for e in &diff.to_remove {
        match classify_source(&e.ip) {
            SourceKind::Lan => {
                if let Some(mac) = &e.mac {
                    s.push_str(&format!("delete element inet {NFT_TABLE} quarantine_lan_macs {{ {mac} }}\n"));
                }
            }
            SourceKind::Wan => {
                s.push_str(&format!("delete element inet {NFT_TABLE} quarantine_wan_ips {{ {} }}\n", e.ip));
            }
        }
    }
    GeneratedFile { path: "quarantine/01-elements.nft".to_string(), content: s }
}

// ---------------------------------------------------------------------------
// DOCUMENT — response events for `hookprobe-evidence --responses` to ingest.
// ---------------------------------------------------------------------------

/// One response-event JSON line. `hookprobe-evidence` links it to the detection(s) it responded
/// to by natural key (rule_id/src_ip/dst_ip/dst_port, within a time window) — the SAME pattern
/// `ingest_detection` already uses to link a detection to its triggering flows, so no id-sharing
/// code is needed between the supervisor and the evidence-graph binaries.
pub fn render_response_json(alert: &ScanAlert, verdict: &ReflexVerdict, ttl_secs: u64, now: f64, iface: &str) -> String {
    let (action, target, detail, status) = match verdict {
        ReflexVerdict::Quarantine { reason } => (
            "quarantine",
            alert.src_ip.clone(),
            format!("quarantined via nft on {iface}, TTL {ttl_secs}s, auto-revert — {reason}"),
            "active",
        ),
        ReflexVerdict::Allowlisted { reason } => (
            "log_only",
            alert.src_ip.clone(),
            format!("NOT quarantined — {reason}"),
            "skipped",
        ),
        // EDR #3 fix: distinct from `Observed` — this verdict DOES enforce (a bounded,
        // self-reverting nft-meter SYN-rate cap), just never a durable identity block.
        ReflexVerdict::RateLimit { reason } => (
            "rate_limit",
            alert.src_ip.clone(),
            format!("NOT durably quarantined (unconfirmed) — bounded self-reverting SYN-rate cap applied — {reason}"),
            "active",
        ),
        ReflexVerdict::Observed { reason } => (
            "observe_only",
            alert.src_ip.clone(),
            format!("NOT quarantined (martian) — {reason}"),
            "unconfirmed",
        ),
    };
    serde_json::json!({
        "ts": now,
        "rule_id": alert.rule_id,
        "src_ip": alert.src_ip,
        "dst_ip": alert.dst_ip,
        "dst_port": alert.dst_port,
        "action": action,
        "mechanism": "nft",
        "target": target,
        "detail": detail,
        "ttl_secs": ttl_secs,
        "status": status,
    })
    .to_string()
}

/// A REVERT response event (emitted when the TTL sweep releases a quarantine).
pub fn render_revert_json(entry: &QuarantineEntry, ttl_secs: u64, now: f64, iface: &str) -> String {
    serde_json::json!({
        "ts": now,
        "rule_id": PORT_SCAN_RULE_ID,
        "src_ip": entry.ip,
        "dst_ip": "",
        "dst_port": 0,
        "action": "revert",
        "mechanism": "nft",
        "target": entry.ip,
        "detail": format!("released from nft on {iface} — quiet for {ttl_secs}s (TTL auto-revert)"),
        "ttl_secs": ttl_secs,
        "status": "reverted",
    })
    .to_string()
}

// =============================================================================================
// RESOURCE-REALITY ENFORCEMENT (2026-07-07) — the ONE enforcement class the SOC was missing.
// =============================================================================================
//
// Everything above this banner enforces on IDENTITY/SIGNATURE — a confirmed port scan
// (`decide`/`reconcile_quarantine`), an unconfirmed SYN fan-out (`render_syn_fanout_rate_limit`),
// or (in `l2_responder.rs`) an L1/L2 flood/malformed-frame pattern. An adversarial audit found
// the one thing missing from that picture: a genuine VOLUMETRIC DDoS that never trips any of
// those signature detectors (no port-scan shape, no L2 storm shape, just raw connection/packet
// VOLUME saturating this box's own CPU/RAM/conntrack table) is DETECTED (QSECBIT/telemetry can
// see the load) but never SHED. This section closes that gap — and ONLY that gap.
//
// ## Status update (base-tier-build-ticket.md Phase 2, ADR 0031 §E) — DEMOTED to fallback
// On devices where `resource_shed_v2` is granted, an eBPF fast loop
// (`modules/napse-capture/bpf/napse_detect.bpf.c`'s `shed_admit()`, driven by `hookprobe-psid`'s
// PSI-tier writes into the pinned `shed_ctrl` map) is now the PRIMARY shed mechanism for exactly
// the SAME invariant this nft table enforces — same trigger facts (PSI CPU/mem pressure), same
// self-reverting no-persisted-state property, same "never identity" discipline — but reacting in
// ~1s at TC/XDP cost instead of this table's 10s reconciler cadence at nft cost. **Everything
// below in this file is UNCHANGED and stays LIVE regardless**: Layer 1's blanket per-source cap
// (`render_conn_rate_cap`) and Layer 2's conntrack-saturation guard
// (`evaluate_resource_reality`) are explicitly kept as defence-in-depth (ADR 0031 §E) — they now
// also serve as the SOFTWARE-FLOOR fallback on any platform where `resource_shed_v2` is NOT
// granted (no PSI/pinned-map path), and as a second line even where it IS granted (e.g. the
// window between boot and `hookprobe-psid`'s first tier write, or a device whose `hookprobe-psid`
// has died and is mid-restart). Nothing in this section was gated on `resource_shed_v2` — that
// would reintroduce exactly the reaction-latency gap shed-v2 exists to close on the platforms
// that DO have it, for zero benefit (this table's own cost is negligible compared to the flood
// it's shedding either way).
//
// ## The one rule this section is built around (non-negotiable, proven by construction below)
// **Every function here keys on a RESOURCE-REALITY SIGNAL — packets/connections-per-second, the
// conntrack table's OWN fill level, or `/proc/pressure`'s kernel-computed stall fraction — NEVER
// on who a source claims to be.** There is no MAC/IP allowlist bypass to defeat here because there
// is no identity judgment being made at all: a source is capped because of a MEASURED RATE or
// because the BOX ITSELF is provably failing, never because of a prior "this is malicious"
// verdict. Concretely:
//   - Layer 1 ([`render_conn_rate_cap`]) is a BLANKET, always-on nft `meter` — it doesn't even
//     have a concept of "source reputation"; every source, however trusted, is capped at the same
//     generous per-source new-connection ceiling. A legitimate source never approaches it (see the
//     threshold rationale below); only a source opening connections far faster than any real
//     client (a connect-flood) ever does.
//   - Layers 2/3 ([`evaluate_resource_reality`]) only ever act once a REAL resource wall is
//     already crossed (conntrack >= [`DEFAULT_CONNTRACK_SATURATION_PCT`] full, or sustained PSI
//     stall >= threshold) — and even then the "highest-volume source" they cap is picked by
//     MEASURED CONCURRENT-FLOW COUNT ([`top_talkers`]), not by any detection/reputation verdict.
//
// ## Self-reverting is a STRUCTURAL property, not a promise
// Nothing in this section ever writes an entry with no expiry, and nothing ever refreshes an
// entry's TTL just because it still exists — an entry survives ONLY while it keeps being
// re-observed as a top-talker DURING an active resource-pressure window (see
// [`reconcile_resource_shed`]); the moment the pressure clears (or the source's own share of the
// table/PSI signal drops out of `evaluate_resource_reality`'s output), it is not re-added, and the
// TTL sweep releases it a few reconcile cycles later. There is no escalating hold, no offense
// counter, no persisted "known bad" list — unlike [`QuarantineEntry`] (this file's OTHER,
// deliberately different state machine), a [`ShedEntry`] carries no history across pressure
// windows: the same source that tripped this yesterday starts from zero today.
//
// ## Why this is a SEPARATE nft table from EVERYTHING above (own table, own set, own meter names)
// `hookprobe_resource_shed` never touches `hookprobe_quarantine` (`decide`/`reconcile_quarantine`),
// `hookprobe_scan_ratelimit` (`render_syn_fanout_rate_limit`), or `hookprobe_l2guard`
// (`l2_responder::render_storm_control`) — same discipline those three already established
// pairwise. A source can be simultaneously present in the quarantine table (a confirmed scanner)
// AND the resource-shed table (also a top conntrack talker) — the two mechanisms are orthogonal
// and neither one's revert affects the other.
//
// ## Layers 2 and 3 share ONE mechanism (`shed_ips`), tagged by `signal`
// The spec describes three layers, but layers 2 (conntrack-saturation) and 3 (PSI) both resolve to
// the exact same action once triggered — "apply a temporary per-source new-connection cap to the
// highest-volume source, self-reverting" — so they share one dynamic nft set (`shed_ips`) and one
// reconcile/element-ops pipeline ([`ShedEntry`]/[`reconcile_resource_shed`]/
// [`render_shed_element_ops`]); only the TRIGGER (which real-world fact fired) and the `signal`
// string threaded into the response record differ. This is not a shortcut — it is the honest
// reflection that both layers ultimately answer the same question ("is this box's own resource
// reality failing, and if so who is using the most of the resource that's failing") with the same
// remedy (throttle that source's NEW connections, self-revert). Layer 1's blanket per-source cap
// remains fully independent (a static nft meter, no source list, no state file — see its own doc).
//
// ## Honesty on Layer 1's response-record coverage (does NOT emit one, by design)
// [`render_conn_rate_cap`]'s meter is, like `l2_responder::render_storm_control`'s storm-control
// meters, a purely kernel-side dynamic set with no per-hit event this crate is ever notified of
// (nft does not push an event when a meter entry starts dropping — reading that back out would
// need `nft -j list meter`, a live-state POLL this crate doesn't perform anywhere else either).
// Layers 2/3, by contrast, are RECONCILER DECISIONS with an identified source and a concrete
// trigger fact in hand at decide-time — so THOSE emit a first-class response record
// ([`render_shed_response_json`]/[`render_shed_revert_json`]) into the same responses stream
// `hookprobe-evidence --responses` already ingests `scan_responder`'s/`l2_responder`'s records
// from. This is the same "don't fabricate visibility the code doesn't have" discipline
// `l2_responder::render_frame_drop_status` documents for its own gap.

use std::collections::HashMap;

/// One `/proc/pressure/{cpu,memory,io}` stall-fraction snapshot (one of the `some`/`full` lines).
/// Fields are percentages already (the kernel emits `avgN=0.00`..`100.00`), NOT fractions.
#[derive(Debug, Clone, Copy, PartialEq, Default)]
pub struct PsiSnapshot {
    pub avg10: f64,
    pub avg60: f64,
    pub avg300: f64,
    pub total: u64,
}

/// Parse one `/proc/pressure/*` line, e.g. `"some avg10=6.43 avg60=6.09 avg300=7.02
/// total=28965010545"` -> `("some", PsiSnapshot{avg10:6.43,...})`. `None` for anything that isn't
/// exactly this shape (fails toward "no signal", never toward a fabricated snapshot).
pub fn parse_psi_line(line: &str) -> Option<(String, PsiSnapshot)> {
    let mut it = line.split_whitespace();
    let kind = it.next()?;
    if kind != "some" && kind != "full" {
        return None;
    }
    let mut snap = PsiSnapshot::default();
    for tok in it {
        let (k, v) = tok.split_once('=')?;
        match k {
            "avg10" => snap.avg10 = v.parse().ok()?,
            "avg60" => snap.avg60 = v.parse().ok()?,
            "avg300" => snap.avg300 = v.parse().ok()?,
            "total" => snap.total = v.parse().ok()?,
            _ => {}
        }
    }
    Some((kind.to_string(), snap))
}

/// Both lines of one `/proc/pressure/{cpu,memory}` file. `cpu` never has a `full` line (a single
/// task can't be "fully" stalled on a resource with nothing else runnable in a way distinct from
/// `some` — the kernel simply never emits it for `cpu`); `memory`/`io` do. Either field is `None`
/// if that line was absent/unparseable — never fabricated.
#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct PsiPressure {
    pub some: Option<PsiSnapshot>,
    pub full: Option<PsiSnapshot>,
}

/// Parse a whole `/proc/pressure/{cpu,memory}` file's text into its `some`/`full` snapshots.
pub fn parse_psi_file(text: &str) -> PsiPressure {
    let mut p = PsiPressure::default();
    for line in text.lines() {
        match parse_psi_line(line) {
            Some((k, s)) if k == "some" => p.some = Some(s),
            Some((k, s)) if k == "full" => p.full = Some(s),
            _ => {}
        }
    }
    p
}

/// Thresholds for [`psi_under_sustained_pressure`]. Deliberately keyed on `avg60` (the 60-SECOND
/// rolling average), never `avg10` — `avg10` alone is exactly the kind of transient spike a
/// perfectly healthy box produces under a normal burst (a cron job, a big detection-rule
/// recompile, a burst of legitimate connections) and would make this backstop trigger-happy; only
/// a stall fraction SUSTAINED across a full minute is "the box is genuinely, currently failing",
/// which is the only condition the operator asked this layer to react to.
#[derive(Debug, Clone, Copy)]
pub struct PsiThresholds {
    /// `cpu`'s `some avg60` percentage (0..100) above which this device is sustainedly CPU-stalled
    /// enough to justify shedding load. `cpu` has no `full` line (see [`PsiPressure`]'s doc), so
    /// `some` — "at least one runnable task stalled" — is the only signal available; a 40% sixty-
    /// second average means, on AVERAGE across the whole minute, something was waiting on CPU
    /// nearly half the time on a multi-service SOC box (NAPSE+AEGIS+HYDRA+wasm engines all
    /// scheduling concurrently) — well past "busy", into "genuinely contended".
    pub cpu_some_avg60_pct: f64,
    /// `memory`'s `full avg60` percentage above which this device is sustainedly, fully memory-
    /// stalled ("maxing out RAM" in the operator's own words). Deliberately `full`, not `some`:
    /// `some` memory stall (at least one task waiting on a page) is close to background-normal
    /// under real load; `full` (EVERY runnable task simultaneously stalled on memory) only happens
    /// when the box is thrashing/near-OOM — a MUCH stricter, rarer condition, so its threshold is
    /// set lower (rarer events matter more once they start) than the cpu `some` one.
    pub mem_full_avg60_pct: f64,
}
pub const DEFAULT_CPU_SOME_AVG60_PCT: f64 = 40.0;
pub const DEFAULT_MEM_FULL_AVG60_PCT: f64 = 15.0;
impl Default for PsiThresholds {
    fn default() -> Self {
        PsiThresholds { cpu_some_avg60_pct: DEFAULT_CPU_SOME_AVG60_PCT, mem_full_avg60_pct: DEFAULT_MEM_FULL_AVG60_PCT }
    }
}

/// `Some(reason)` iff this device is GENUINELY, SUSTAINEDLY under resource pressure right now
/// (the operator's literal "maxing out RAM/CPU") — `None` otherwise, including when either PSI
/// file simply wasn't readable (fail toward "not under pressure", never toward shedding on a
/// missing/unreadable signal).
pub fn psi_under_sustained_pressure(cpu: &PsiPressure, mem: &PsiPressure, cfg: &PsiThresholds) -> Option<String> {
    if let Some(s) = cpu.some {
        if s.avg60 >= cfg.cpu_some_avg60_pct {
            return Some(format!(
                "sustained CPU pressure: /proc/pressure/cpu 'some avg60'={:.1}% >= {:.1}% threshold",
                s.avg60, cfg.cpu_some_avg60_pct
            ));
        }
    }
    if let Some(f) = mem.full {
        if f.avg60 >= cfg.mem_full_avg60_pct {
            return Some(format!(
                "sustained MEMORY pressure: /proc/pressure/memory 'full avg60'={:.1}% >= {:.1}% threshold",
                f.avg60, cfg.mem_full_avg60_pct
            ));
        }
    }
    None
}

/// `true` iff the trigger [`psi_under_sustained_pressure`] found was the CPU one (used only to
/// pick the `signal` tag for the response record — the caller already has the reason string).
pub fn psi_signal_name(cpu: &PsiPressure, cfg: &PsiThresholds) -> &'static str {
    if cpu.some.is_some_and(|s| s.avg60 >= cfg.cpu_some_avg60_pct) {
        "psi_cpu"
    } else {
        "psi_memory"
    }
}

// ---------------------------------------------------------------------------
// Conntrack — table fill level + per-source concurrent-flow counts (top-talker identification).
// ---------------------------------------------------------------------------

/// Parse `/proc/sys/net/netfilter/nf_conntrack_count` (or `nf_conntrack_max`) — a single bare
/// integer, possibly with trailing whitespace/newline. `None` for anything else.
pub fn parse_conntrack_scalar(text: &str) -> Option<u64> {
    text.trim().parse().ok()
}

/// The conntrack table's current fill percentage (0.0..~100.0, can exceed 100 only if the kernel
/// itself is over budget, which we report honestly rather than clamp). `0.0` if `max` is `0`
/// (never divide by zero, never fabricate saturation on a degenerate reading).
pub fn conntrack_fill_pct(count: u64, max: u64) -> f64 {
    if max == 0 {
        return 0.0;
    }
    (count as f64 / max as f64) * 100.0
}

/// Extract the originating source IP from one `conntrack -L` / `/proc/net/nf_conntrack`-style
/// line — the FIRST `src=` token (the original-direction tuple's source; conntrack lines carry a
/// second `src=`/`dst=` pair for the reply direction, which we deliberately ignore here: for a
/// connection-flood the ORIGINATING side is the one whose volume we want to attribute). `None` for
/// a line with no `src=` token at all (a header/blank/malformed line).
pub fn parse_conntrack_line_src(line: &str) -> Option<String> {
    line.split_whitespace().find_map(|tok| tok.strip_prefix("src=")).map(String::from)
}

/// Every originating source IP across a conntrack table dump — one entry per table row (a source
/// with N concurrent flows appears N times), which is exactly what [`top_talkers`] wants to count.
pub fn parse_conntrack_src_ips(dump_text: &str) -> Vec<String> {
    dump_text.lines().filter_map(parse_conntrack_line_src).collect()
}

/// The `top_n` sources by CONCURRENT conntrack-table-entry count, descending, `(ip, count)`.
/// Ties broken by first-seen order (stable) — good enough for "who to throttle", not a ranking
/// that needs to be perfectly deterministic under ties.
pub fn top_talkers(src_ips: &[String], top_n: usize) -> Vec<(String, u64)> {
    let mut counts: HashMap<&str, u64> = HashMap::new();
    let mut order: Vec<&str> = Vec::new();
    for ip in src_ips {
        let e = counts.entry(ip.as_str()).or_insert_with(|| {
            order.push(ip.as_str());
            0
        });
        *e += 1;
    }
    let mut ranked: Vec<(String, u64)> = order.into_iter().map(|ip| (ip.to_string(), counts[ip])).collect();
    ranked.sort_by_key(|(_, count)| std::cmp::Reverse(*count));
    ranked.truncate(top_n);
    ranked
}

// ---------------------------------------------------------------------------
// LAYER 1 — blanket, always-on, per-source new-connection-rate cap (nft meter, self-reverting).
// A SEPARATE table/chain from EVERYTHING else in this crate (see the section-level doc above).
// ---------------------------------------------------------------------------

pub const RESOURCE_SHED_NFT_TABLE: &str = "hookprobe_resource_shed";
const RESOURCE_SHED_BANNER: &str =
    "# GENERATED by hookprobe resource-shed responder — RESOURCE-REALITY enforcement (pps / \
     conntrack-fill / PSI), never identity. Do NOT edit by hand.\n\
     # A SEPARATE table from the port-scan quarantine, the SYN-fanout rate-limit, and the L1/L2 \
     storm-control tables. Self-reverting by construction: LAYER 1 is a bare nft meter timeout \
     (no persisted state at all); LAYER 2/3's `shed_ips` set entries carry their own element \
     timeout AND are only ever refreshed while the reconciler keeps re-observing genuine pressure.\n\
     # base-tier-build-ticket.md Phase 2: where `resource_shed_v2` is granted, an eBPF fast loop \
     (napse_detect.bpf.c + hookprobe-psid) is the PRIMARY shed path (~1s reaction); this nft table \
     is now the SOFTWARE-FLOOR FALLBACK + defence-in-depth, unchanged, still always applied.\n";

/// Config for [`render_conn_rate_cap`] (Layer 1). Interface defaults match every other
/// responder's live-topology defaults (`wlan0`/`end0`) for the same reason they all do.
#[derive(Debug, Clone)]
pub struct ConnRateCapConfig {
    pub lan_iface: String,
    pub wan_iface: String,
    /// Per-source-IP NEW-connection ceiling, packets/second, matching `ct state new` across EVERY
    /// protocol (not just TCP SYN, unlike [`render_syn_fanout_rate_limit`] — a connection-flood can
    /// just as easily be UDP or ICMP). See [`DEFAULT_NEW_CONN_PPS`] for the rationale.
    pub new_conn_pps: u32,
    /// How long an idle per-source meter entry survives before nft itself expires it — the
    /// self-revert (identical discipline to every other meter-backed responder in this crate).
    pub meter_timeout_secs: u64,
    /// Layers 2/3's stricter per-source cap, applied ONLY to members of the dynamic `shed_ips`
    /// set (never the whole population, unlike `new_conn_pps` above) — see
    /// [`DEFAULT_SHED_CAP_PPS`] for the rationale. Declared here (not a separate config struct) so
    /// [`render_conn_rate_cap`] can render the WHOLE resource-shed table — Layer 1's blanket meter
    /// AND Layer 2/3's `shed_ips` set + cap rule — in one idempotent bootstrap artifact.
    pub shed_cap_pps: u32,
    /// Management-safety allowlist CIDRs (the mgmt subnet) — a first-match `accept` prepended to the
    /// resource-shed chains so the operator's own segment is NEVER shed. Trusted infrastructure, not
    /// a spoofable customer claim (LAN-side spoofers are caught by MAC-binding at the quarantine
    /// layer; resource-shed is a throttle, not a block). Empty = no floor (legacy behaviour).
    pub protect_cidrs: Vec<String>,
    /// Management-safety allowlist exact IPs (gateway, DNS resolvers, WAN self) — same first-match
    /// `accept` as `protect_cidrs`. The LAN gateway (e.g. `10.66.0.1`) MUST be here or a
    /// connection-flood window could throttle the very NAT/gateway path every LAN customer needs.
    pub protect_ips: Vec<String>,
    /// Per-source CONCURRENT-conntrack ceiling. The 2026-07-09 on-metal finding: a port/conn scan
    /// from ONE source fills the GLOBAL conntrack table faster than the timer-driven shed reflex can
    /// react, and a full table makes the KERNEL drop EVERY new connection — legit customers (a LAN
    /// phone) and the operator's mgmt SSH included. Capping each source's own conntrack footprint
    /// (`meter { ip saddr ct count over N }`) bounds the blast radius to the offending source: the
    /// table can never be exhausted by one talker, so every OTHER customer always keeps a slot. Keys
    /// on the source's OWN resource consumption (resource-reality), never identity. A legit client
    /// sits in the low hundreds of concurrent conns; a scanner blows past N. 0 = disabled.
    pub max_conns_per_src: u32,
    /// Input-exposed MANAGEMENT TCP ports (e.g. sshd's 22) that get an ALWAYS-ON, per-source
    /// NEW-connection rate cap on the WAN input chain — the 2026-07-10 Finding-2 fix. A TCP-connect
    /// flood to the box's OWN management service (sshd) saturated it (hit `MaxStartups` → new SSH
    /// refused for ~88s) BEFORE the 10s timer-driven Layer 2/3 shed could react. This static cap is
    /// present the moment the bootstrap is applied (no pressure signal, no dynamic set), so it has no
    /// such window. Empty = no mgmt-port cap. See [`DEFAULT_MGMT_PORTS`]; keyed on a measured
    /// per-source new-connection RATE (resource-reality), never on identity — it applies to EVERY
    /// source (mgmt-allowlisted or not), because it is a rate cap, not a block: an already-
    /// ESTABLISHED/authenticated SSH session is accepted before it and never torn down.
    pub mgmt_ports: Vec<u16>,
    /// Per-source NEW-connection/second ceiling for [`mgmt_ports`]. See [`DEFAULT_MGMT_CONN_PPS`].
    /// 0 = disabled.
    pub mgmt_conn_pps: u32,
}
/// Several hundred new connections/second from a SINGLE source, sustained. Rationale (err toward
/// NOT dropping, per the task's explicit instruction): a genuinely busy legitimate client — a
/// browser loading a heavy page (loads dozens of sub-resources, each often its own connection on
/// HTTP/1.1-only origins), a video call renegotiating several media/data channels, a phone with a
/// dozen apps syncing at once — opens at most a few TENS of new connections per second even in a
/// worst-case burst. 400/s is roughly an order of magnitude above that worst-case, so only a real
/// connect-flood (a SYN flood, a botnet fan-in, a misbehaving scanner far past
/// `render_syn_fanout_rate_limit`'s own narrower TCP-SYN-only cap) will ever cross it — this is the
/// FIRST, always-on line of defense the operator asked for ("a single source opening connections
/// faster than any real client"). Env-overridable, like every other `DEFAULT_*_PPS` in this crate.
pub const DEFAULT_NEW_CONN_PPS: u32 = 400;
pub const DEFAULT_CONN_RATE_METER_TIMEOUT_SECS: u64 = 30;
/// The Layer-2/3 shed cap itself — deliberately STRICTER than Layer 1's blanket
/// [`DEFAULT_NEW_CONN_PPS`] (this only ever applies to a source ALREADY identified as a top
/// contributor to a REAL, already-crossed resource wall — a tighter cap here is still far above
/// any single legitimate flow's own new-connection needs, since a "flow" doesn't open sub-
/// connections at this rate; it just protects the box from that ONE source compounding the
/// problem while everyone else drains normally).
pub const DEFAULT_SHED_CAP_PPS: u32 = 50;
/// Per-source concurrent-conntrack ceiling (see [`ConnRateCapConfig::max_conns_per_src`]). 2048 is
/// ~an order of magnitude above any single legitimate client's concurrent-connection needs (a busy
/// browser/phone sits in the low hundreds), yet far below the default 65536-entry table — so one
/// scanner is capped at 1/32 of the table and can NEVER exhaust it, while no real customer is ever
/// near the ceiling. Env-overridable like every other `DEFAULT_*` here.
pub const DEFAULT_MAX_CONNS_PER_SRC: u32 = 2048;
/// The input-exposed MANAGEMENT TCP ports that get the always-on per-source new-connection cap
/// ([`ConnRateCapConfig::mgmt_ports`]). Default = SSH (22) ONLY: it is the sole management service
/// bound to a routable interface (a release image ships no sshd at all — ADR 0016 — so on a release
/// image this rule matches nothing; it is correct defense-in-depth regardless, and protects any
/// future input-exposed mgmt service). The hookprobe-api (127.0.0.1:8420, loopback-only) never
/// traverses a WAN/LAN input chain, so it is deliberately EXCLUDED — scoped conservatively to what
/// is actually exposed. An operator who exposes another management service adds its port via
/// `RESOURCE_SHED_MGMT_PORTS`. Env/config-overridable, never a hardcoded literal at the rule site.
pub const DEFAULT_MGMT_PORTS: &[u16] = &[22];
/// Per-source NEW-connection/second ceiling for [`DEFAULT_MGMT_PORTS`] (the always-on management-
/// plane flood cap). Deliberately an ORDER OF MAGNITUDE below Layer 1's blanket
/// [`DEFAULT_NEW_CONN_PPS`] (400): a human operator or an automation runner opens at most a handful
/// of NEW SSH connections/second to the box's OWN sshd even in a worst case (a parallel Ansible/rsync
/// fan-out is a few tens of *forwarded* sessions, not tens of new connections/second to :22); a
/// connect-flood aiming to exhaust `sshd`'s `MaxStartups` opens hundreds/second. 20/s sits safely
/// between the two — a real operator never approaches it, a flood is capped well below the rate that
/// saturates sshd. Env-overridable, like every other `DEFAULT_*_PPS` in this crate.
pub const DEFAULT_MGMT_CONN_PPS: u32 = 20;
impl Default for ConnRateCapConfig {
    fn default() -> Self {
        ConnRateCapConfig {
            lan_iface: "wlan0".to_string(),
            wan_iface: "end0".to_string(),
            new_conn_pps: DEFAULT_NEW_CONN_PPS,
            meter_timeout_secs: DEFAULT_CONN_RATE_METER_TIMEOUT_SECS,
            shed_cap_pps: DEFAULT_SHED_CAP_PPS,
            protect_cidrs: Vec::new(),
            protect_ips: Vec::new(),
            max_conns_per_src: DEFAULT_MAX_CONNS_PER_SRC,
            mgmt_ports: DEFAULT_MGMT_PORTS.to_vec(),
            mgmt_conn_pps: DEFAULT_MGMT_CONN_PPS,
        }
    }
}

/// Render the WHOLE resource-shed table's static bootstrap in one idempotent artifact: table +
/// forward/input chains + Layer 1's blanket per-source `ct state new` meter (BOTH lan/wan ingress
/// — a connection flood can originate from either plane) + the `shed_ips` set Layers 2/3 populate
/// dynamically + a STRICTER cap rule matching ONLY `ip saddr @shed_ips` (so a source must first be
/// added to that set by [`render_shed_element_ops`] — driven by [`evaluate_resource_reality`] — to
/// ever hit the tighter `shed_cap_pps` ceiling; every other source only ever sees the generous
/// blanket `new_conn_pps` meter above). Idempotent via the same `add table` -> `delete table` ->
/// `add table` idiom `l2_responder::render_storm_control`'s 2026-07-07 first-boot fix established
/// (a meter/set declared inline in `add rule`/`add set` outlives `flush chain`, so the table itself
/// must be dropped-and-recreated each cycle to avoid a "File exists" error on re-apply; the leading
/// guard `add table` additionally makes the very first-ever apply's `delete table` a safe
/// no-op-if-missing rather than an aborting error under a batched `nft -f` transaction). Safe to
/// re-apply every reconcile cycle (this crate's other renderers already assume line-by-line,
/// continue-on-failure application — see `supervisor::apply_or_print`).
pub fn render_conn_rate_cap(cfg: &ConnRateCapConfig) -> GeneratedFile {
    let (lan, wan) = (cfg.lan_iface.as_str(), cfg.wan_iface.as_str());
    let t = cfg.meter_timeout_secs;
    let mut s = String::from(RESOURCE_SHED_BANNER);
    s.push_str(&format!(
        "# Layer 1 — blanket per-source new-connection-rate cap on {lan}/{wan}: {}pps/source (any \
         protocol, ct state new), meter idle-timeout {t}s. Applies to EVERY source, trusted or not \
         — a resource-reality signal, never an identity check. Layer 2/3 shed cap: {}pps/source, \
         applied ONLY to members of the dynamic shed_ips set (see render_shed_element_ops).\n",
        cfg.new_conn_pps, cfg.shed_cap_pps
    ));
    s.push_str(&format!("add table inet {RESOURCE_SHED_NFT_TABLE}\n"));
    s.push_str(&format!("delete table inet {RESOURCE_SHED_NFT_TABLE}\n"));
    s.push_str(&format!("add table inet {RESOURCE_SHED_NFT_TABLE}\n"));
    s.push_str(&format!(
        "add chain inet {RESOURCE_SHED_NFT_TABLE} forward {{ type filter hook forward priority -3; policy accept; }}\n"
    ));
    s.push_str(&format!(
        "add chain inet {RESOURCE_SHED_NFT_TABLE} input {{ type filter hook input priority -3; policy accept; }}\n"
    ));
    s.push_str(&format!("flush chain inet {RESOURCE_SHED_NFT_TABLE} forward\n"));
    s.push_str(&format!("flush chain inet {RESOURCE_SHED_NFT_TABLE} input\n"));
    // Layers 2/3's dynamic set — populated ONLY by `render_shed_element_ops`, driven by
    // `evaluate_resource_reality`'s real-signal decision. Declaring it here (before any rule
    // references `@shed_ips`) is required nft ordering.
    s.push_str(&format!("add set inet {RESOURCE_SHED_NFT_TABLE} shed_ips {{ type ipv4_addr; flags timeout; }}\n"));

    // ---- CUSTOMER-SEPARATION FLOOR (2026-07-09 on-metal finding) --------------------------------
    // The invariant is "a legitimate customer connection must ALWAYS pass." Three guards, FIRST in
    // both chains (nft is first-match within a chain), before ANY shed drop below:
    //   (a) never break an already-ESTABLISHED/related flow — shedding only ever targets ct-new, so
    //       an ongoing customer session (a phone mid-download, the operator's live SSH) is untouched
    //       even while the box is under a real flood;
    //   (b) a management-safety accept for the operator's own segment / gateway / resolvers — trusted
    //       infrastructure, so the operator never loses access and the LAN's own NAT/DNS path is
    //       never throttled (identity here is a NARROW infra allowlist, not a spoofable claim);
    //   (c) a per-source CONCURRENT-conntrack cap so ONE talker can't exhaust the global table and
    //       make the kernel drop every OTHER customer's new connections (the exact collateral seen on
    //       metal). (c) is pure resource-reality — it keys on the source's OWN footprint, not identity.
    for dir in ["forward", "input"] {
        s.push_str(&format!(
            "add rule inet {RESOURCE_SHED_NFT_TABLE} {dir} ct state established,related counter accept comment \"hookprobe-resource-shed-established-accept\"\n"
        ));
    }

    // ---- MANAGEMENT-PLANE FLOOD CAP (always-on; Finding-2, 2026-07-10 metal pentest) ------------
    // An always-on, per-source NEW-connection rate cap on the box's OWN input-exposed management
    // service(s) (sshd :22) on the WAN input chain — the ONE rule in this whole table that is NOT
    // waiting on a resource wall or a 10s timer: it is present from the first bootstrap apply. It
    // closes the gap where a TCP-connect flood to :22 saturates sshd (`MaxStartups` → new SSH
    // refused) in the ~10s window before the timer-driven Layer 2/3 shed reacts. Two invariants make
    // it safe:
    //   - Placed AFTER the `ct state established,related accept` above → an ONGOING operator SSH
    //     session (or any authenticated flow) is accepted first and NEVER torn down; only the flood
    //     of NEW connection attempts is capped (`ct state new`).
    //   - Placed DELIBERATELY BEFORE the mgmt-allowlist accept below → it applies to ALL sources,
    //     including the mgmt subnet. This is a RATE CAP keyed on a measured per-source
    //     new-connection rate (resource-reality), never an identity block, and no legitimate operator
    //     or automation ever opens `mgmt_conn_pps` NEW connections/second to the box's own sshd — so
    //     capping even a trusted source's flood is correct, while its established session is untouched.
    // Input-chain only (management services live on THIS box, not the forward/customer path — the
    // forward plane is never touched). Own meter name (self-cleaning, per-source, not identity),
    // distinct from every other meter in this table.
    if cfg.mgmt_conn_pps > 0 && !cfg.mgmt_ports.is_empty() {
        let ports = cfg.mgmt_ports.iter().map(|p| p.to_string()).collect::<Vec<_>>().join(", ");
        s.push_str(&format!(
            "# Management-plane flood cap: {}pps/source new conns to mgmt port(s) {{ {ports} }} on {wan} input (self-reverting meter, timeout {t}s).\n",
            cfg.mgmt_conn_pps
        ));
        s.push_str(&format!(
            "add rule inet {RESOURCE_SHED_NFT_TABLE} input iifname \"{wan}\" tcp dport {{ {ports} }} ct state new meter napse_mgmtport_in_{wan}_meter {{ ip saddr timeout {t}s limit rate over {}/second }} counter drop comment \"hookprobe-resource-shed-mgmtport-in-{wan}\"\n",
            cfg.mgmt_conn_pps
        ));
    }

    if !cfg.protect_cidrs.is_empty() || !cfg.protect_ips.is_empty() {
        let mut elems: Vec<String> = Vec::new();
        elems.extend(cfg.protect_cidrs.iter().cloned());
        elems.extend(cfg.protect_ips.iter().cloned());
        let set = elems.join(", ");
        for dir in ["forward", "input"] {
            s.push_str(&format!(
                "add rule inet {RESOURCE_SHED_NFT_TABLE} {dir} ip saddr {{ {set} }} counter accept comment \"hookprobe-resource-shed-mgmt-allowlist\"\n"
            ));
        }
    }

    for iface in [lan, wan] {
        // Layer 0 — per-source concurrent-conntrack footprint cap (guard (c) above): bounds the
        // conntrack blast radius of any ONE source so the global table can't be exhausted. Runs
        // BEFORE the rate meters so a table-filling scanner is capped even below the pps ceiling.
        if cfg.max_conns_per_src > 0 {
            s.push_str(&format!(
                "add rule inet {RESOURCE_SHED_NFT_TABLE} forward iifname \"{iface}\" ct state new meter napse_conncount_fwd_{iface}_meter {{ ip saddr ct count over {} }} counter drop comment \"hookprobe-resource-shed-conncount-fwd-{iface}\"\n",
                cfg.max_conns_per_src
            ));
            s.push_str(&format!(
                "add rule inet {RESOURCE_SHED_NFT_TABLE} input iifname \"{iface}\" ct state new meter napse_conncount_in_{iface}_meter {{ ip saddr ct count over {} }} counter drop comment \"hookprobe-resource-shed-conncount-in-{iface}\"\n",
                cfg.max_conns_per_src
            ));
        }
        // Layer 1 — blanket, always-on, every source.
        s.push_str(&format!(
            "add rule inet {RESOURCE_SHED_NFT_TABLE} forward iifname \"{iface}\" ct state new meter napse_connrate_fwd_{iface}_meter {{ ip saddr timeout {t}s limit rate over {}/second }} counter drop comment \"hookprobe-resource-shed-connrate-fwd-{iface}\"\n",
            cfg.new_conn_pps
        ));
        s.push_str(&format!(
            "add rule inet {RESOURCE_SHED_NFT_TABLE} input iifname \"{iface}\" ct state new meter napse_connrate_in_{iface}_meter {{ ip saddr timeout {t}s limit rate over {}/second }} counter drop comment \"hookprobe-resource-shed-connrate-in-{iface}\"\n",
            cfg.new_conn_pps
        ));
        // Layers 2/3 — stricter cap, ONLY for members of shed_ips (a plain set-membership match,
        // no second meter needed: `shed_ips`'s own per-element timeout already IS the self-revert
        // for THESE entries; the rate figure below simply throttles a member's new connections
        // rather than dropping every packet from it outright — still a THROTTLE, never a full
        // block, matching the "never durably harm a legit customer" invariant even for a source
        // that legitimately-but-heavily contributed to a real resource wall).
        s.push_str(&format!(
            "add rule inet {RESOURCE_SHED_NFT_TABLE} forward iifname \"{iface}\" ip saddr @shed_ips ct state new limit rate over {}/second counter drop comment \"hookprobe-resource-shed-cap-fwd-{iface}\"\n",
            cfg.shed_cap_pps
        ));
        s.push_str(&format!(
            "add rule inet {RESOURCE_SHED_NFT_TABLE} input iifname \"{iface}\" ip saddr @shed_ips ct state new limit rate over {}/second counter drop comment \"hookprobe-resource-shed-cap-in-{iface}\"\n",
            cfg.shed_cap_pps
        ));
    }
    GeneratedFile { path: "resource-shed/00-bootstrap.nft".to_string(), content: s }
}

// ---------------------------------------------------------------------------
// LAYERS 2 + 3 — shared dynamic per-source shed set (`shed_ips`), triggered by conntrack-
// saturation OR sustained PSI pressure. Self-reverting via TTL, never an identity blocklist.
// ---------------------------------------------------------------------------

/// One source currently capped by Layer 2/3 — deliberately CARRIES NO OFFENSE HISTORY (contrast
/// with [`QuarantineEntry`]'s `offenses`/escalating hold): a fresh pressure window starts every
/// source at zero, by design (this is a resource-reality throttle, never a punishment record).
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct ShedEntry {
    pub ip: String,
    pub first_seen: f64,
    pub last_seen: f64,
    /// Which resource-reality signal is currently justifying this cap: `"conntrack_saturation"`,
    /// `"psi_cpu"`, or `"psi_memory"`. Refreshed to the LATEST triggering signal each cycle (a
    /// source can move between causes across cycles without losing its `first_seen`).
    pub signal: String,
    /// Human-readable detail for the evidence-graph response record (fill pct / PSI avg60 / flow
    /// count) — never fabricated, always the exact fact that justified this cycle's decision.
    pub detail: String,
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct ShedDiff {
    pub to_add: Vec<ShedEntry>,
    pub to_remove: Vec<ShedEntry>,
    pub state: Vec<ShedEntry>,
}

/// Bound on the persisted/enforced shed set — mirrors [`DEFAULT_MAX_QUARANTINE_ENTRIES`]'s
/// rationale at a smaller scale (this only ever holds the CURRENT cycle's top-`N` talkers, so a
/// small cap is generous headroom, not a real limit in practice).
pub const DEFAULT_MAX_SHED_ENTRIES: usize = 64;

/// One resource-reality trigger — an (ip, signal, detail) [`evaluate_resource_reality`] decided
/// deserves a temporary cap this cycle.
#[derive(Debug, Clone, PartialEq)]
pub struct ShedTrigger {
    pub ip: String,
    pub signal: String,
    pub detail: String,
}

/// Reconcile this cycle's [`ShedTrigger`]s into the persisted shed state — mirrors
/// `reconcile_quarantine`'s add/refresh/TTL-sweep/cap shape, WITHOUT escalation (see
/// [`ShedEntry`]'s doc: no offense history, ever).
///
/// - **New trigger** -> added, `to_add` gets one entry.
/// - **Already-shedding source, re-triggered this cycle** -> `last_seen`/`signal`/`detail`
///   refreshed, NO re-add (idempotent, matches every other responder's re-apply discipline).
/// - **Every cycle, regardless**: a TTL sweep releases anything not re-triggered for
///   `ttl_secs` — this is the WHOLE self-revert mechanism: once `evaluate_resource_reality` stops
///   naming a source (because the table drained / PSI dropped below threshold), that source's
///   `last_seen` simply stops advancing and it ages out on its own, exactly like
///   [`sweep_quarantine`]'s TTL sweep, just with no escalation term.
/// - **Capped** at `max_entries` ([`DEFAULT_MAX_SHED_ENTRIES`]), oldest-`last_seen` evicted first.
pub fn reconcile_resource_shed(
    mut state: Vec<ShedEntry>,
    triggers: &[ShedTrigger],
    now: f64,
    ttl_secs: u64,
    max_entries: usize,
) -> ShedDiff {
    let mut diff = ShedDiff::default();
    for t in triggers {
        match state.iter().position(|e| e.ip == t.ip) {
            Some(idx) => {
                state[idx].last_seen = now;
                state[idx].signal = t.signal.clone();
                state[idx].detail = t.detail.clone();
            }
            None => {
                let e = ShedEntry {
                    ip: t.ip.clone(),
                    first_seen: now,
                    last_seen: now,
                    signal: t.signal.clone(),
                    detail: t.detail.clone(),
                };
                state.push(e.clone());
                diff.to_add.push(e);
            }
        }
    }
    let (mut keep, expired): (Vec<ShedEntry>, Vec<ShedEntry>) =
        state.into_iter().partition(|e| now - e.last_seen <= ttl_secs as f64);
    diff.to_remove.extend(expired);
    let cap = max_entries.max(1);
    if keep.len() > cap {
        // Ascending by `last_seen` -> `split_off(evict_count)` returns the NEWEST `cap` entries
        // (kept) and leaves the OLDEST `evict_count` behind in `keep` (evicted) — same idiom as
        // `cap_entries` above, just for `ShedEntry`.
        keep.sort_by(|a, b| a.last_seen.partial_cmp(&b.last_seen).unwrap_or(std::cmp::Ordering::Equal));
        let evict_count = keep.len() - cap;
        let survivors = keep.split_off(evict_count);
        diff.to_remove.extend(keep);
        keep = survivors;
    }
    diff.state = keep;
    diff
}

/// Per-cycle `shed_ips` element add/remove for Layers 2/3 — mirrors
/// [`render_element_ops`]'s shape exactly (own comment banner, own set, no cross-talk with the
/// quarantine table it mirrors the STRUCTURE of, never the STATE of).
pub fn render_shed_element_ops(diff: &ShedDiff, ttl_secs: u64) -> GeneratedFile {
    let mut s = String::from(RESOURCE_SHED_BANNER);
    if diff.to_add.is_empty() && diff.to_remove.is_empty() {
        s.push_str("# (no change this cycle)\n");
    }
    for e in &diff.to_add {
        s.push_str(&format!(
            "add element inet {RESOURCE_SHED_NFT_TABLE} shed_ips {{ {} timeout {ttl_secs}s }} comment \"{}\"\n",
            e.ip, e.signal
        ));
    }
    for e in &diff.to_remove {
        s.push_str(&format!("delete element inet {RESOURCE_SHED_NFT_TABLE} shed_ips {{ {} }}\n", e.ip));
    }
    GeneratedFile { path: "resource-shed/01-shed-elements.nft".to_string(), content: s }
}

/// The rule id this crate reserves for resource-reality shed response records (mirrors
/// [`PORT_SCAN_RULE_ID`]'s role — a stable id `hookprobe-evidence` can key on) — NOT a NAPSE
/// detection rule (there is no "alert" here, only a reconciler decision against a live resource
/// fact), but reserved in the SAME numbering space so the evidence graph has one place to look.
pub const RESOURCE_SHED_RULE_ID: i64 = 1_000_050;

/// A first-class response record for one Layer-2/3 shed action (added or refreshed this cycle) —
/// `hookprobe-evidence --responses` ingests this exactly like `render_response_json`'s output.
/// Honest by construction: `signal`/`detail` are always the literal fact that triggered THIS
/// decision (conntrack fill pct, PSI avg60, concurrent-flow count) — never a guess.
pub fn render_shed_response_json(entry: &ShedEntry, cap_pps: u32, ttl_secs: u64, now: f64, iface: &str) -> String {
    serde_json::json!({
        "ts": now,
        "rule_id": RESOURCE_SHED_RULE_ID,
        "src_ip": entry.ip,
        "action": "resource_shed",
        "mechanism": "nft",
        "target": entry.ip,
        "signal": entry.signal,
        "cap_new_conns_per_sec": cap_pps,
        "detail": format!(
            "temporary per-source new-connection cap ({cap_pps}/s) on {iface} — {} — {}, TTL {ttl_secs}s, self-reverting (never a durable/identity block)",
            entry.signal, entry.detail
        ),
        "ttl_secs": ttl_secs,
        "status": "active",
    })
    .to_string()
}

/// The REVERT counterpart (mirrors [`render_revert_json`]'s role) — emitted when
/// [`reconcile_resource_shed`]'s TTL sweep releases a shed source (the pressure cleared / the
/// source stopped being a top-talker).
pub fn render_shed_revert_json(entry: &ShedEntry, ttl_secs: u64, now: f64, iface: &str) -> String {
    serde_json::json!({
        "ts": now,
        "rule_id": RESOURCE_SHED_RULE_ID,
        "src_ip": entry.ip,
        "action": "resource_shed_revert",
        "mechanism": "nft",
        "target": entry.ip,
        "signal": entry.signal,
        "detail": format!("released from resource-shed on {iface} — quiet/no-longer-a-top-talker for {ttl_secs}s (TTL auto-revert)"),
        "ttl_secs": ttl_secs,
        "status": "reverted",
    })
    .to_string()
}

// ---------------------------------------------------------------------------
// ORCHESTRATION — the pure decision function the CLI wires real /proc + conntrack reads into.
// ---------------------------------------------------------------------------

/// Everything [`evaluate_resource_reality`] needs, pre-read by the caller (pure-function
/// discipline, same as `decide`'s `flows_jsonl`/`wan_self_ips` parameters — no I/O in this crate).
#[derive(Debug, Clone, Default)]
pub struct ResourceRealityInputs {
    pub conntrack_count: Option<u64>,
    pub conntrack_max: Option<u64>,
    /// Every source IP in the CURRENT conntrack table dump (one entry per concurrent flow) — used
    /// for [`top_talkers`], for EITHER the conntrack-saturation trigger or (as a proxy for "the
    /// highest-volume source") the PSI trigger.
    pub conntrack_src_ips: Vec<String>,
    pub psi_cpu: PsiPressure,
    pub psi_mem: PsiPressure,
}

/// Config for [`evaluate_resource_reality`] — every threshold in one place, all with a
/// `DEFAULT_*` constant and an honest rationale on that constant's own doc.
#[derive(Debug, Clone)]
pub struct ResourceRealityConfig {
    pub conntrack_saturation_pct: f64,
    /// A source needs at least this many CONCURRENT conntrack entries to be considered a
    /// top-talker candidate during saturation — guards against capping a source that merely
    /// happens to rank #1 among many roughly-equal, individually-tiny flows (the table can be
    /// "full" from thousands of legitimate low-volume IoT devices; ranking #1 there is not
    /// evidence of a flood). See [`DEFAULT_TOP_TALKER_MIN_ENTRIES`].
    pub top_talker_min_entries: u64,
    /// How many top talkers to cap simultaneously once triggered (generous — see
    /// [`DEFAULT_SHED_TOP_N`]).
    pub top_n: usize,
    pub psi: PsiThresholds,
}
/// Conntrack table crossing 80% full is a REAL resource wall (the kernel starts dropping new
/// connections outright once `nf_conntrack_max` is hit) — 80%, not 100%, gives the shed a chance
/// to act BEFORE the table is actually exhausted (matches the task's explicit "~80%" spec).
pub const DEFAULT_CONNTRACK_SATURATION_PCT: f64 = 80.0;
/// A legitimate top talker (e.g. a busy internal server, a NAS, a media box) rarely holds more
/// than a few dozen concurrent flows; a source with 200+ CONCURRENT conntrack entries while the
/// table is already 80%+ full is contributing meaningfully to the exhaustion, not just "the
/// biggest of many small fish".
pub const DEFAULT_TOP_TALKER_MIN_ENTRIES: u64 = 200;
pub const DEFAULT_SHED_TOP_N: usize = 3;
/// The Layer-2/3 self-revert window for [`ShedEntry`]/[`reconcile_resource_shed`] — see
/// [`DEFAULT_CONN_RATE_METER_TIMEOUT_SECS`]'s sibling rationale: short enough that a source stops
/// being throttled within a minute of the pressure actually clearing, long enough to avoid
/// flapping the nft set on/off every single reconcile tick.
pub const DEFAULT_SHED_TTL_SECS: u64 = 60;
impl Default for ResourceRealityConfig {
    fn default() -> Self {
        ResourceRealityConfig {
            conntrack_saturation_pct: DEFAULT_CONNTRACK_SATURATION_PCT,
            top_talker_min_entries: DEFAULT_TOP_TALKER_MIN_ENTRIES,
            top_n: DEFAULT_SHED_TOP_N,
            psi: PsiThresholds::default(),
        }
    }
}

/// Decide this cycle's Layer-2/3 shed triggers — pure, deterministic, no LLM, same discipline as
/// `decide`/`decide_l2`. Two independent gates, either (or both) may fire:
///   1. **Conntrack saturation** — table fill `>= conntrack_saturation_pct` AND at least one
///      source has `>= top_talker_min_entries` concurrent flows -> those top-`N` sources trigger
///      with `signal = "conntrack_saturation"`.
///   2. **Sustained PSI pressure** — [`psi_under_sustained_pressure`] fires -> the single highest-
///      volume source (by the SAME conntrack-derived [`top_talkers`], `top_n = 1` — the box itself
///      is failing, so only the biggest single contributor is targeted, not a whole list) triggers
///      with `signal = "psi_cpu"`/`"psi_memory"`. If there is no conntrack visibility at all in
///      this cycle (empty `conntrack_src_ips`), PSI pressure is still reported (for the caller to
///      log/alert on) but produces NO trigger — this backstop must never cap an UNIDENTIFIED
///      source; "genuinely under pressure but we don't know who's using it" is a real, honest
///      state this function reports as "no action", never a guess.
///
/// A source appearing in BOTH gates is de-duplicated (conntrack-saturation's reason wins — it is
/// the more specific fact) rather than emitted twice.
pub fn evaluate_resource_reality(inputs: &ResourceRealityInputs, cfg: &ResourceRealityConfig) -> Vec<ShedTrigger> {
    let mut triggers: Vec<ShedTrigger> = Vec::new();
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();

    if let (Some(count), Some(max)) = (inputs.conntrack_count, inputs.conntrack_max) {
        let pct = conntrack_fill_pct(count, max);
        if pct >= cfg.conntrack_saturation_pct {
            for (ip, n) in top_talkers(&inputs.conntrack_src_ips, cfg.top_n) {
                if n >= cfg.top_talker_min_entries && seen.insert(ip.clone()) {
                    triggers.push(ShedTrigger {
                        ip,
                        signal: "conntrack_saturation".to_string(),
                        detail: format!(
                            "conntrack table {pct:.1}% full ({count}/{max}) >= {:.1}% threshold; source has {n} \
                             concurrent flows (>= {} floor)",
                            cfg.conntrack_saturation_pct, cfg.top_talker_min_entries
                        ),
                    });
                }
            }
        }
    }

    if let Some(reason) = psi_under_sustained_pressure(&inputs.psi_cpu, &inputs.psi_mem, &cfg.psi) {
        if let Some((ip, n)) = top_talkers(&inputs.conntrack_src_ips, 1).into_iter().next() {
            if seen.insert(ip.clone()) {
                triggers.push(ShedTrigger {
                    ip,
                    signal: psi_signal_name(&inputs.psi_cpu, &cfg.psi).to_string(),
                    detail: format!("{reason}; highest-volume source has {n} concurrent conntrack flows"),
                });
            }
            // else: already triggered by conntrack-saturation this cycle — one trigger per source
            // per cycle, the more specific (conntrack) reason already recorded.
        }
        // else: pressure is real but there is no conntrack visibility to attribute it to a source
        // this cycle — reported by the caller (PSI reason is still available to log), no trigger.
    }

    triggers
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    const EXACT_SCHEMA: &str = r#"{"ts":1000.5,"src_ip":"203.0.113.7","src_port":54321,"dst_ip":"192.168.1.10","dst_port":22,"proto":"tcp","severity":2,"rule_id":1000003,"rule_msg":"NAPSE Port Scan Detected","mitre":"T1046","category":"port_scan","confidence":0.9}"#;

    // ---- parse_scan_alert ------------------------------------------------------------------

    #[test]
    fn parses_the_exact_napse_schema() {
        let a = parse_scan_alert(EXACT_SCHEMA).expect("must parse the exact schema");
        assert_eq!(a.src_ip, "203.0.113.7");
        assert_eq!(a.src_port, 54321);
        assert_eq!(a.dst_ip, "192.168.1.10");
        assert_eq!(a.dst_port, 22);
        assert_eq!(a.rule_id, 1000003);
        assert_eq!(a.mitre, "T1046");
        assert!((a.confidence - 0.9).abs() < 1e-9);
    }

    #[test]
    fn ignores_non_scan_lines() {
        // a flow line (no rule_id/category at all)
        let flow = r#"{"type":"conn","ts":1.0,"src_ip":"1.2.3.4","src_port":1,"dst_ip":"5.6.7.8","dst_port":2,"proto":"tcp"}"#;
        assert!(parse_scan_alert(flow).is_none());
        // a DIFFERENT NAPSE alert (brute force, not a scan)
        let bf = r#"{"ts":1.0,"src_ip":"1.2.3.4","src_port":1,"dst_ip":"5.6.7.8","dst_port":22,"proto":"tcp","severity":2,"rule_id":1000001,"rule_msg":"x","mitre":"T1110","category":"brute_force","confidence":0.7}"#;
        assert!(parse_scan_alert(bf).is_none());
        assert!(parse_scan_alert("").is_none());
        assert!(parse_scan_alert("not json").is_none());
    }

    #[test]
    fn accepts_category_port_scan_even_with_a_different_rule_id() {
        // future-proofing: if rule_id is ever renumbered, category alone still matches.
        let line = r#"{"ts":1.0,"src_ip":"1.2.3.4","src_port":1,"dst_ip":"5.6.7.8","dst_port":22,"proto":"tcp","severity":2,"rule_id":9999999,"rule_msg":"x","mitre":"T1046","category":"port_scan","confidence":0.9}"#;
        assert!(parse_scan_alert(line).is_some());
    }

    // ---- neighbor resolution ----------------------------------------------------------------

    #[test]
    fn parses_ip_neigh_show() {
        let text = "10.66.0.23 dev wlan0 lladdr aa:bb:cc:dd:ee:ff REACHABLE\n10.66.0.9 dev wlan0 FAILED\n";
        assert_eq!(parse_ip_neigh(text, "10.66.0.23"), Some("aa:bb:cc:dd:ee:ff".to_string()));
        assert_eq!(parse_ip_neigh(text, "10.66.0.9"), None, "no lladdr on a FAILED entry");
        assert_eq!(parse_ip_neigh(text, "10.66.0.99"), None, "not present at all");
    }

    #[test]
    fn parses_proc_net_arp() {
        let text = "IP address       HW type     Flags       HW address            Mask     Device\n\
                    10.66.0.23       0x1         0x2         AA:BB:CC:DD:EE:FF     *        wlan0\n\
                    10.66.0.50       0x1         0x0         00:00:00:00:00:00     *        wlan0\n";
        assert_eq!(parse_proc_net_arp(text, "10.66.0.23"), Some("aa:bb:cc:dd:ee:ff".to_string()));
        assert_eq!(parse_proc_net_arp(text, "10.66.0.50"), None, "incomplete (all-zero) entry");
    }

    #[test]
    fn resolve_mac_prefers_neigh_then_falls_back_to_arp() {
        let neigh = "10.0.0.5 dev wlan0 lladdr 11:11:11:11:11:11 REACHABLE\n";
        let arp = "hdr\n10.0.0.5 0x1 0x2 22:22:22:22:22:22 * wlan0\n10.0.0.6 0x1 0x2 33:33:33:33:33:33 * wlan0\n";
        assert_eq!(resolve_mac(Some(neigh), Some(arp), "10.0.0.5"), Some("11:11:11:11:11:11".to_string()), "neigh wins");
        assert_eq!(resolve_mac(Some(neigh), Some(arp), "10.0.0.6"), Some("33:33:33:33:33:33".to_string()), "falls back to arp");
        assert_eq!(resolve_mac(Some(neigh), Some(arp), "10.0.0.99"), None);
        assert_eq!(resolve_mac(None, None, "10.0.0.5"), None);
    }

    // ---- enrichment (fingerprint reuse) -------------------------------------------------------

    fn alert(src_ip: &str, dst_port: u16) -> ScanAlert {
        ScanAlert {
            ts: 1000.0, src_ip: src_ip.to_string(), src_port: 12345, dst_ip: "192.168.1.10".to_string(),
            dst_port, proto: "tcp".to_string(), severity: 2, rule_id: PORT_SCAN_RULE_ID,
            rule_msg: "NAPSE Port Scan Detected".to_string(), mitre: "T1046".to_string(),
            category: "port_scan".to_string(), confidence: 0.9,
            confirmed: true, src_mac: None,
        }
    }

    #[test]
    fn enrich_host_classifies_via_fingerprint_and_reports_oui() {
        let a = alert("203.0.113.7", 22);
        let sig = EnrichSignals { mac: Some("dc:a6:32:aa:bb:cc"), hostname: Some("guardian"), ..Default::default() };
        let intel = enrich_host(None, &a, sig, 1000.0);
        assert_eq!(intel.device_class, "sbc", "Raspberry Pi OUI + 'guardian' hostname → SBC");
        assert!(!intel.mac_randomized);
        assert_eq!(intel.oui_vendor.as_deref(), Some("Raspberry Pi"));
        assert_eq!(intel.scan_ports, vec![22]);
        assert_eq!(intel.scan_count, 1);
        assert_eq!(intel.first_seen, 1000.0);
    }

    #[test]
    fn enrich_host_flags_randomized_mac_and_no_oui_guess() {
        let a = alert("203.0.113.8", 80);
        let sig = EnrichSignals { mac: Some("c2:01:b1:72:4d:dc"), hostname: Some("iPhone"), ..Default::default() };
        let intel = enrich_host(None, &a, sig, 1000.0);
        assert!(intel.mac_randomized);
        assert_eq!(intel.oui_vendor, None, "randomized MAC must never get a guessed OUI vendor");
        assert_eq!(intel.device_class, "phone");
    }

    #[test]
    fn enrich_host_accumulates_ports_targets_and_count_across_calls() {
        let a1 = alert("203.0.113.9", 22);
        let r1 = enrich_host(None, &a1, EnrichSignals::default(), 1000.0);
        assert_eq!(r1.scan_ports, vec![22]);
        assert_eq!(r1.scan_count, 1);

        let a2 = alert("203.0.113.9", 443);
        let r2 = enrich_host(Some(&r1), &a2, EnrichSignals::default(), 1005.0);
        assert_eq!(r2.scan_ports, vec![22, 443], "ports accumulate, sorted+deduped");
        assert_eq!(r2.scan_count, 2);
        assert_eq!(r2.first_seen, 1000.0, "first_seen carried forward from prev");
        assert_eq!(r2.last_seen, 1005.0);

        // re-observing the SAME port must not duplicate it.
        let a3 = alert("203.0.113.9", 443);
        let r3 = enrich_host(Some(&r2), &a3, EnrichSignals::default(), 1010.0);
        assert_eq!(r3.scan_ports, vec![22, 443], "no duplicate port");
        assert_eq!(r3.scan_count, 3);
    }

    // ---- protect_reason / allowlist --------------------------------------------------------

    #[test]
    fn protects_management_subnet_and_gateway() {
        let p = ProtectPolicy::default();
        assert!(protect_reason("10.200.0.5", None, &p).is_some(), "mgmt subnet /28 must be protected");
        assert!(protect_reason("10.200.0.15", None, &p).is_some(), "still inside /28 (last host)");
        assert!(protect_reason("10.200.0.16", None, &p).is_none(), "just OUTSIDE the /28");
        assert!(protect_reason("10.66.0.1", None, &p).is_some(), "gateway is protected");
        assert!(protect_reason("203.0.113.7", None, &p).is_none(), "a normal external scanner is NOT protected");
    }

    #[test]
    fn protects_operator_supplied_wan_ip() {
        let p = ProtectPolicy {
            cidrs: vec!["10.200.0.0/28".into()],
            ips: vec!["10.66.0.1".into(), "198.51.100.44".into()],
            lan_macs: Vec::new(),
        };
        assert!(protect_reason("198.51.100.44", None, &p).is_some(), "the live WAN IP, once supplied, is protected");
    }

    // `cidr_match_is_conservative_on_malformed_input` (the private `ipv4_in_cidr` helper) moved
    // to `hookprobe-mgmt-guard`'s own test suite along with the function itself.

    // 2026-07-05 threat-model fix (HIGH #5): once `lan_macs` is configured, a LAN-classified
    // protected IP claimed from the WRONG mac is NOT exempted — an on-link impostor spoofing the
    // gateway's IP does not inherit the gateway's allowlist entry.
    #[test]
    fn protect_reason_requires_the_bound_mac_once_lan_macs_is_configured() {
        let p = ProtectPolicy {
            cidrs: vec![],
            ips: vec!["10.66.0.1".into()],
            lan_macs: vec!["aa:bb:cc:dd:ee:ff".into()],
        };
        assert!(protect_reason("10.66.0.1", Some("aa:bb:cc:dd:ee:ff"), &p).is_some(), "the REAL gateway mac is exempted");
        assert!(
            protect_reason("10.66.0.1", Some("11:22:33:44:55:66"), &p).is_none(),
            "an impostor claiming the gateway's IP from a DIFFERENT mac must NOT be exempted"
        );
        assert!(protect_reason("10.66.0.1", None, &p).is_none(), "no observed mac at all must NOT be exempted either");
    }

    #[test]
    fn protect_reason_stays_ip_only_when_lan_macs_is_not_configured() {
        // backward compatibility: an operator who hasn't set --protect-mac yet keeps today's
        // IP-only behavior (never a regression for existing deployments).
        let p = ProtectPolicy::default();
        assert!(protect_reason("10.66.0.1", Some("11:22:33:44:55:66"), &p).is_some());
        assert!(protect_reason("10.66.0.1", None, &p).is_some());
    }

    #[test]
    fn protect_reason_never_mac_binds_a_wan_source() {
        // a WAN source has no L2 mac to bind — matching stays IP/CIDR-only regardless of
        // `lan_macs` (that field only constrains the LAN plane).
        let p = ProtectPolicy {
            cidrs: vec![],
            ips: vec!["198.51.100.44".into()],
            lan_macs: vec!["aa:bb:cc:dd:ee:ff".into()],
        };
        assert!(protect_reason("198.51.100.44", None, &p).is_some());
    }

    // ---- is_wan_ingress_martian — HIGH #4 -----------------------------------------------------

    #[test]
    fn wan_ingress_martian_flags_a_private_source_reaching_this_devices_own_wan_ip() {
        let wan_self = vec!["198.51.100.44".to_string()];
        assert!(
            is_wan_ingress_martian("10.0.0.1", "198.51.100.44", &wan_self),
            "an RFC1918 source claiming to reach the device's OWN public WAN ip is impossible"
        );
        assert!(is_wan_ingress_martian("203.0.113.7", "198.51.100.44", &wan_self), "TEST-NET-3 is also a bogon");
    }

    #[test]
    fn wan_ingress_martian_is_false_for_a_real_public_source_or_a_non_self_target() {
        let wan_self = vec!["198.51.100.44".to_string()];
        assert!(!is_wan_ingress_martian("8.8.8.8", "198.51.100.44", &wan_self), "a real public source is fine");
        assert!(
            !is_wan_ingress_martian("10.0.0.1", "192.168.1.10", &wan_self),
            "the target isn't this device's own WAN address — not flagged"
        );
    }

    // ---- conntrack_established / is_confirmed_any — 2026-07-06 fix (F4) -----------------------

    #[test]
    fn conntrack_established_finds_a_matching_conn_record_as_src() {
        let flows = "{\"type\":\"conn\",\"src_ip\":\"203.0.113.7\",\"dst_ip\":\"10.66.0.5\",\"conn_state\":\"SF\"}\n";
        assert!(conntrack_established(flows, "203.0.113.7"), "an SF conn record naming this ip as src confirms it");
    }

    #[test]
    fn conntrack_established_finds_a_matching_conn_record_as_dst() {
        // This device was the RESPONDER (e.g. an inbound connection it accepted) — still proof of
        // a real completed handshake naming this ip, just on the other side of the tuple.
        let flows = "{\"type\":\"conn\",\"src_ip\":\"10.66.0.5\",\"dst_ip\":\"203.0.113.7\",\"conn_state\":\"SF\"}\n";
        assert!(conntrack_established(flows, "203.0.113.7"));
    }

    #[test]
    fn conntrack_established_is_false_for_a_new_flow_not_yet_established() {
        // conn_state "S0" (NAPSE's R_NEW_FLOW rendering) is only a SYN observed, not a completed
        // handshake — must NOT count as confirmation (would reopen the exact spoof window
        // HandshakeTracker's own "bare SYN never confirms" proof closes).
        let flows = "{\"type\":\"conn\",\"src_ip\":\"203.0.113.7\",\"dst_ip\":\"10.66.0.5\",\"conn_state\":\"S0\"}\n";
        assert!(!conntrack_established(flows, "203.0.113.7"));
    }

    #[test]
    fn conntrack_established_is_false_for_a_different_ip() {
        let flows = "{\"type\":\"conn\",\"src_ip\":\"198.51.100.9\",\"dst_ip\":\"10.66.0.5\",\"conn_state\":\"SF\"}\n";
        assert!(!conntrack_established(flows, "203.0.113.7"), "an established flow for a DIFFERENT ip must not confirm");
    }

    #[test]
    fn conntrack_established_ignores_alert_type_records() {
        // An "alert" record (a DROP, e.g. a blocklist hit) is not proof of a completed handshake
        // even if it happens to name the right ip/state-looking field — only "conn" counts.
        let flows = "{\"type\":\"alert\",\"src_ip\":\"203.0.113.7\",\"dst_ip\":\"10.66.0.5\",\"conn_state\":\"SF\"}\n";
        assert!(!conntrack_established(flows, "203.0.113.7"));
    }

    #[test]
    fn conntrack_established_skips_malformed_lines_without_panicking() {
        let flows = "not json at all\n\n{\"type\":\"conn\",\"src_ip\":\"203.0.113.7\",\"dst_ip\":\"10.66.0.5\",\"conn_state\":\"SF\"}\n{truncated";
        assert!(conntrack_established(flows, "203.0.113.7"), "the one valid line among garbage still confirms");
    }

    #[test]
    fn conntrack_established_accepts_raw_conntrack_style_established_literal() {
        // Defensive: if ever fed raw `conntrack -L`-derived text using the literal kernel state
        // name instead of the rendered "SF", it still works.
        let flows = "{\"type\":\"conn\",\"src_ip\":\"203.0.113.7\",\"dst_ip\":\"10.66.0.5\",\"conn_state\":\"ESTABLISHED\"}\n";
        assert!(conntrack_established(flows, "203.0.113.7"));
    }

    #[test]
    fn conntrack_established_is_false_on_an_empty_or_unreadable_stream() {
        assert!(!conntrack_established("", "203.0.113.7"), "no flows data at all must never confirm");
    }

    #[test]
    fn is_confirmed_any_true_when_the_alert_bit_alone_is_true() {
        assert!(is_confirmed_any(true, "", "203.0.113.7"), "the mirror-fed handshake signal alone is sufficient");
    }

    #[test]
    fn is_confirmed_any_true_when_only_conntrack_confirms_the_mirror_missed_it() {
        // THE CORE F4 PROOF: alert.confirmed = false (e.g. the mirror pipeline is down/broken —
        // the exact live-Pi symptom the F1 fix addresses) but conntrack independently shows this
        // device completed a real handshake with this source — must still confirm.
        let flows = "{\"type\":\"conn\",\"src_ip\":\"203.0.113.7\",\"dst_ip\":\"10.66.0.5\",\"conn_state\":\"SF\"}\n";
        assert!(
            is_confirmed_any(false, flows, "203.0.113.7"),
            "a conntrack-ESTABLISHED source must confirm even when the mirror-fed alert bit is false"
        );
    }

    #[test]
    fn is_confirmed_any_stays_false_when_neither_signal_confirms() {
        // THE ANTI-SPOOF PROOF: an unconfirmed source with no conntrack evidence either must NOT
        // become confirmed — the invariant `decide`'s unconfirmed -> RateLimit gate depends on.
        assert!(!is_confirmed_any(false, "", "203.0.113.7"));
        let unrelated_flows = "{\"type\":\"conn\",\"src_ip\":\"198.51.100.9\",\"dst_ip\":\"10.66.0.5\",\"conn_state\":\"SF\"}\n";
        assert!(!is_confirmed_any(false, unrelated_flows, "203.0.113.7"), "an established flow for a different ip must not leak confirmation");
    }

    // End-to-end proof: `decide` durably quarantines a source once `is_confirmed_any` broadens
    // confirmation via conntrack alone (the alert's own `confirmed` bit is false throughout,
    // simulating a dead mirror) — this is the exact behavior change F4 fixes.
    #[test]
    fn decide_quarantines_via_conntrack_confirmation_even_when_the_mirror_alert_bit_is_false() {
        let flows = "{\"type\":\"conn\",\"src_ip\":\"203.0.113.7\",\"dst_ip\":\"10.66.0.5\",\"conn_state\":\"SF\"}\n";
        let confirmed = is_confirmed_any(false, flows, "203.0.113.7");
        assert!(confirmed);
        let v = decide("203.0.113.7", dst(), 60, confirmed, None, &ProtectPolicy::default(), &no_wan_self());
        assert!(matches!(v, ReflexVerdict::Quarantine { .. }), "conntrack confirmation must be enough to durably quarantine; got {v:?}");
    }

    // ---- decide() — the reflex verdict -----------------------------------------------------

    fn dst() -> &'static str {
        "192.168.1.10"
    }

    /// No WAN self address configured — the common case for tests that aren't specifically
    /// exercising `is_wan_ingress_martian`/Q5.
    fn no_wan_self() -> Vec<String> {
        Vec::new()
    }

    #[test]
    fn decide_quarantines_a_normal_confirmed_scanner() {
        let v = decide("203.0.113.7", dst(), 12, true, None, &ProtectPolicy::default(), &no_wan_self());
        assert!(matches!(v, ReflexVerdict::Quarantine { .. }));
    }

    // (a)/(b) — the core CRITICAL #1 proof: unconfirmed never DURABLY quarantines, confirmed does.
    // EDR #3 fix: unconfirmed is no longer "Observed" (zero enforcement) — it's `RateLimit`
    // (bounded, self-reverting), but it must NEVER be `Quarantine` (durable, identity-keyed).
    #[test]
    fn decide_never_durably_quarantines_an_unconfirmed_scanner() {
        let v = decide("203.0.113.7", dst(), 60, false, None, &ProtectPolicy::default(), &no_wan_self());
        assert!(matches!(v, ReflexVerdict::RateLimit { .. }), "unconfirmed must rate-limit, never durably Quarantine");
    }

    #[test]
    fn decide_quarantines_once_confirmed() {
        let v = decide("203.0.113.7", dst(), 60, true, None, &ProtectPolicy::default(), &no_wan_self());
        assert!(matches!(v, ReflexVerdict::Quarantine { .. }), "a CONFIRMED scan must still be enforceable");
    }

    #[test]
    fn decide_allowlists_a_management_subnet_scanner_never_quarantine() {
        let v = decide("10.200.0.5", dst(), 5, true, None, &ProtectPolicy::default(), &no_wan_self());
        match v {
            ReflexVerdict::Allowlisted { reason } => assert!(reason.contains("NOT quarantined")),
            other => panic!("mgmt-subnet scanner must be Allowlisted, got {other:?}"),
        }
    }

    #[test]
    fn decide_allowlists_the_gateway() {
        let v = decide("10.66.0.1", dst(), 5, true, None, &ProtectPolicy::default(), &no_wan_self());
        assert!(matches!(v, ReflexVerdict::Allowlisted { .. }), "gateway scanning itself/others must never self-lock");
    }

    // EDR #3 fix proof: the management-path fail-safe now gates the RateLimit arm too — an
    // UNCONFIRMED "scan" from the gateway/mgmt subnet must be Allowlisted (no enforcement AT ALL),
    // never RateLimit'd. Before this fix's reordering, `protect_reason` was only ever checked
    // AFTER the confirmed branch, so an unconfirmed mgmt-path "scanner" would have incorrectly
    // reached the (then-`Observed`, now-`RateLimit`) arm instead of `Allowlisted`.
    #[test]
    fn decide_allowlists_an_unconfirmed_management_subnet_scanner_never_rate_limits_it() {
        let v = decide("10.200.0.5", dst(), 60, false, None, &ProtectPolicy::default(), &no_wan_self());
        assert!(matches!(v, ReflexVerdict::Allowlisted { .. }), "mgmt subnet must never be rate-limited either, confirmed or not; got {v:?}");
    }

    #[test]
    fn decide_allowlists_an_unconfirmed_gateway_scanner_never_rate_limits_it() {
        let v = decide("10.66.0.1", dst(), 60, false, None, &ProtectPolicy::default(), &no_wan_self());
        assert!(matches!(v, ReflexVerdict::Allowlisted { .. }), "gateway must never be rate-limited either, confirmed or not; got {v:?}");
    }

    // (c) — mgmt-src spoof does NOT evade: a spoofed gateway IP from the WRONG mac is neither
    // Allowlisted NOR Quarantined blindly — it correctly falls through to Quarantine ONLY once
    // confirmed (proving the allowlist doesn't rubber-stamp it), and rate-limits (never durably
    // quarantines) if unconfirmed.
    #[test]
    fn decide_mgmt_spoof_from_wrong_mac_does_not_evade_enforcement_once_confirmed() {
        let p = ProtectPolicy {
            cidrs: vec![],
            ips: vec!["10.66.0.1".into()],
            lan_macs: vec!["aa:bb:cc:dd:ee:ff".into()],
        };
        // impostor confirmed a real handshake (so it passes gate #2) but comes from the WRONG mac.
        let v = decide("10.66.0.1", dst(), 60, true, Some("11:22:33:44:55:66"), &p, &no_wan_self());
        assert!(matches!(v, ReflexVerdict::Quarantine { .. }), "an impostor of the gateway's IP is NOT exempted and IS enforceable");
    }

    // (c) — a WAN-side RFC1918-src is dropped as martian (never reaches Quarantine OR Allowlisted).
    // Note: `wan_self_ips` is now a DEDICATED list (Q5 fix), never `p.ips` — `p.ips` here holds an
    // unrelated mgmt address to prove the two lists are no longer conflated.
    #[test]
    fn decide_drops_a_wan_side_rfc1918_source_as_martian() {
        let p = ProtectPolicy { cidrs: vec![], ips: vec!["10.66.0.1".into()], lan_macs: vec![] };
        let wan_self = vec!["198.51.100.44".to_string()];
        let v = decide("10.0.0.7", "198.51.100.44", 60, true, None, &p, &wan_self);
        match v {
            ReflexVerdict::Observed { reason } => assert!(reason.contains("impossible")),
            other => panic!("a WAN-ingress martian must be Observed, got {other:?}"),
        }
    }

    // (d) — Q5 re-audit proof: a LAN attacker scanning the device's own gateway/resolver (both
    // legitimately in `policy.ips`, the ALLOWLIST) must NOT be misclassified as a "WAN-ingress
    // martian" and must NOT evade enforcement. Before the fix, `decide` passed `policy.ips`
    // itself as `wan_self_ips`, so `dst_ip` (the gateway) being IN that list plus `src` being LAN
    // satisfied `is_wan_ingress_martian` and routed straight to `Observed` — a free evasion for
    // anyone willing to target the gateway/resolver instead of a random LAN host. With a
    // DEDICATED `wan_self_ips` (here: the device's real, distinct external address, never the
    // gateway), scanning the gateway is evaluated normally and reaches `Quarantine`.
    #[test]
    fn decide_lan_attacker_scanning_the_gateway_is_no_longer_evasively_marked_martian() {
        let p = ProtectPolicy { cidrs: vec![], ips: vec!["10.66.0.1".into()], lan_macs: vec![] };
        let wan_self = vec!["198.51.100.44".to_string()]; // the device's OWN, distinct WAN ip
        let attacker_ip = "10.66.0.50"; // a LAN attacker, NOT itself on the allowlist
        let v = decide(attacker_ip, "10.66.0.1", 60, true, None, &p, &wan_self);
        assert!(
            matches!(v, ReflexVerdict::Quarantine { .. }),
            "scanning the gateway must be enforced like any other LAN target, not waved through as martian; got {v:?}"
        );
    }

    // A resolver address that is legitimately in `policy.ips` (the allowlist) must NOT be treated
    // as this device's own WAN address just because it's protected — confirms the two lists are
    // independent inputs, never derived from one another (the Q5 bug's root cause).
    #[test]
    fn decide_lan_attacker_scanning_a_protected_resolver_is_also_no_longer_evasively_martian() {
        let p = ProtectPolicy { cidrs: vec![], ips: vec!["10.66.0.1".into(), "1.1.1.1".into()], lan_macs: vec![] };
        let wan_self = vec!["198.51.100.44".to_string()]; // the real, distinct WAN address
        let v = decide("10.66.0.50", "1.1.1.1", 60, true, None, &p, &wan_self);
        assert!(
            matches!(v, ReflexVerdict::Quarantine { .. }),
            "scanning a protected resolver from the LAN must be enforced, not waved through as martian; got {v:?}"
        );
    }

    // ---- reconcile_quarantine — TTL + idempotency ------------------------------------------

    const MAX: usize = DEFAULT_MAX_QUARANTINE_ENTRIES;

    #[test]
    fn reconcile_adds_a_new_scanner() {
        let diff = reconcile_quarantine(vec![], "203.0.113.7", Some("aa:bb:cc:dd:ee:ff"), 1000.0, 300, false, MAX);
        assert_eq!(diff.to_add.len(), 1);
        assert_eq!(diff.to_add[0].ip, "203.0.113.7");
        assert_eq!(diff.to_add[0].offenses, 1);
        assert!(diff.to_remove.is_empty());
        assert_eq!(diff.state.len(), 1);
    }

    #[test]
    fn reconcile_is_idempotent_on_replay_within_ttl() {
        let state = vec![QuarantineEntry { ip: "203.0.113.7".into(), mac: None, first_seen: 1000.0, last_seen: 1000.0, offenses: 1 }];
        // same scanner, 30s later, well within a 300s TTL — refresh, but NO re-add, NO re-remove.
        let diff = reconcile_quarantine(state, "203.0.113.7", None, 1030.0, 300, false, MAX);
        assert!(diff.to_add.is_empty(), "re-applying the same quarantine must be a no-op (no re-add)");
        assert!(diff.to_remove.is_empty());
        assert_eq!(diff.state[0].last_seen, 1030.0, "last_seen refreshed (extends the TTL window)");
        assert_eq!(diff.state[0].first_seen, 1000.0, "first_seen preserved");
    }

    // (f) — an UNCONFIRMED re-observation never even reaches reconcile_quarantine (main.rs only
    // calls it for Quarantine/Allowlisted verdicts; RateLimit is reconciled by the SEPARATE,
    // stateless nft-meter path — `render_syn_fanout_rate_limit` — never this persisted state
    // file), so it structurally cannot refresh the DURABLE-quarantine TTL. Proven here at the
    // unit boundary: reconcile_quarantine simply never receives one for an unconfirmed verdict.
    #[test]
    fn reconcile_quarantine_is_never_invoked_for_an_unconfirmed_verdict() {
        let v = decide("203.0.113.7", dst(), 60, false, None, &ProtectPolicy::default(), &no_wan_self());
        assert!(matches!(v, ReflexVerdict::RateLimit { .. }), "unconfirmed rate-limits, never feeds the durable quarantine state file");
        // the ONLY verdicts that legitimately drive a `reconcile_quarantine` call:
        let v2 = decide("203.0.113.7", dst(), 60, true, None, &ProtectPolicy::default(), &no_wan_self());
        assert!(matches!(v2, ReflexVerdict::Quarantine { .. } | ReflexVerdict::Allowlisted { .. }));
    }

    #[test]
    fn reconcile_ttl_expires_a_quiet_scanner() {
        let state = vec![QuarantineEntry {
            ip: "203.0.113.7".into(),
            mac: Some("aa:bb:cc:dd:ee:ff".into()),
            first_seen: 1000.0,
            last_seen: 1000.0,
            offenses: 1,
        }];
        // a DIFFERENT scanner shows up 400s later; the old one (300s TTL) must expire.
        let diff = reconcile_quarantine(state, "198.51.100.9", None, 1400.0, 300, false, MAX);
        assert_eq!(diff.to_add.len(), 1, "the new scanner is added");
        assert_eq!(diff.to_remove.len(), 1, "the quiet scanner is released");
        assert_eq!(diff.to_remove[0].ip, "203.0.113.7");
        assert_eq!(diff.state.len(), 1);
        assert_eq!(diff.state[0].ip, "198.51.100.9");
    }

    #[test]
    fn reconcile_force_releases_an_allowlisted_entry_immediately() {
        // simulate: this ip was quarantined, then an operator added it to the allowlist.
        let state = vec![QuarantineEntry { ip: "10.66.0.1".into(), mac: None, first_seen: 1000.0, last_seen: 1000.0, offenses: 1 }];
        let diff = reconcile_quarantine(state, "10.66.0.1", None, 1005.0, 300, true, MAX);
        assert_eq!(diff.to_remove.len(), 1, "must release immediately, not wait out the TTL");
        assert!(diff.state.is_empty());
    }

    #[test]
    fn reconcile_allowlisted_never_adds() {
        let diff = reconcile_quarantine(vec![], "10.200.0.5", None, 1000.0, 300, true, MAX);
        assert!(diff.to_add.is_empty());
        assert!(diff.state.is_empty());
    }

    // MEDIUM #6 — escalating hold: a repeat CONFIRMED offense grows the effective TTL, so it
    // survives past the base window while a first-timer would already have expired.
    #[test]
    fn reconcile_escalates_ttl_on_repeat_offenses() {
        let mut state = vec![];
        let diff1 = reconcile_quarantine(state, "203.0.113.7", None, 1000.0, 100, false, MAX);
        state = diff1.state;
        assert_eq!(state[0].offenses, 1);
        // re-offend 3 more times, each within the (escalating) TTL window.
        for i in 1..4u32 {
            let diff = reconcile_quarantine(state, "203.0.113.7", None, 1000.0 + i as f64 * 50.0, 100, false, MAX);
            state = diff.state;
        }
        assert_eq!(state[0].offenses, 4);
        // base ttl=100s, offenses=4 → effective ttl=400s. 150s after the last refresh (1150+150=1300)
        // is well within 400s but would be WAY past a flat 100s TTL — proves escalation is applied.
        let diff = sweep_quarantine(state, 1150.0 + 150.0, 100);
        assert!(diff.to_remove.is_empty(), "an escalated-TTL entry must survive past the base window");
    }

    #[test]
    fn effective_ttl_secs_grows_with_offenses_and_caps() {
        assert_eq!(effective_ttl_secs(100, 1), 100);
        assert_eq!(effective_ttl_secs(100, 3), 300);
        assert_eq!(effective_ttl_secs(100, 6), 600);
        assert_eq!(effective_ttl_secs(100, 999), 600, "capped at ESCALATION_CAP (6x)");
    }

    // MEDIUM #7 — the enforced set is bounded; oldest-`last_seen` entries are evicted first.
    #[test]
    fn reconcile_quarantine_caps_the_enforced_set_evicting_the_oldest() {
        let mut state: Vec<QuarantineEntry> = (0..5)
            .map(|i| QuarantineEntry {
                ip: format!("203.0.113.{i}"),
                mac: None,
                first_seen: i as f64,
                last_seen: i as f64,
                offenses: 1,
            })
            .collect();
        state.push(QuarantineEntry { ip: "9.9.9.9".into(), mac: None, first_seen: 0.0, last_seen: 0.0, offenses: 1 });
        // 6 entries in, cap of 5 — a fresh new one arrives too, must evict the globally oldest.
        let diff = reconcile_quarantine(state, "203.0.113.100", None, 1000.0, 10_000, false, 5);
        assert_eq!(diff.state.len(), 5, "capped at max_entries");
        assert!(diff.state.iter().any(|e| e.ip == "203.0.113.100"), "the newest observation is always kept");
        assert!(diff.to_remove.iter().any(|e| e.ip == "9.9.9.9" || e.ip == "203.0.113.0"), "the oldest entries are evicted first");
    }

    #[test]
    fn sweep_quarantine_matches_reconcile_ttl_semantics() {
        let state = vec![
            QuarantineEntry { ip: "1.1.1.1".into(), mac: None, first_seen: 0.0, last_seen: 90.0, offenses: 1 },
            QuarantineEntry { ip: "2.2.2.2".into(), mac: None, first_seen: 0.0, last_seen: 390.0, offenses: 1 },
        ];
        let diff = sweep_quarantine(state, 400.0, 300);
        assert_eq!(diff.to_remove.len(), 1, "only the 300s-quiet entry expires");
        assert_eq!(diff.to_remove[0].ip, "1.1.1.1");
        assert_eq!(diff.state.len(), 1);
        assert_eq!(diff.state[0].ip, "2.2.2.2");
    }

    // ---- classify_source — LAN vs WAN (the key requirement) --------------------------------

    #[test]
    fn classifies_rfc1918_link_local_cgnat_and_loopback_as_lan() {
        assert_eq!(classify_source("10.66.0.20"), SourceKind::Lan, "RFC1918 10/8");
        assert_eq!(classify_source("10.200.0.4"), SourceKind::Lan, "the mgmt subnet, also 10/8");
        assert_eq!(classify_source("172.16.0.5"), SourceKind::Lan, "RFC1918 172.16/12");
        assert_eq!(classify_source("172.31.255.254"), SourceKind::Lan, "top of 172.16/12");
        assert_eq!(classify_source("172.32.0.1"), SourceKind::Wan, "just OUTSIDE 172.16/12");
        assert_eq!(classify_source("192.168.1.50"), SourceKind::Lan, "RFC1918 192.168/16");
        assert_eq!(classify_source("169.254.1.1"), SourceKind::Lan, "link-local");
        assert_eq!(classify_source("100.64.0.1"), SourceKind::Lan, "CGNAT-shared 100.64/10");
        assert_eq!(classify_source("100.127.255.255"), SourceKind::Lan, "top of 100.64/10");
        assert_eq!(classify_source("100.128.0.1"), SourceKind::Wan, "just OUTSIDE 100.64/10");
        assert_eq!(classify_source("127.0.0.1"), SourceKind::Lan, "loopback");
    }

    #[test]
    fn classifies_public_addresses_as_wan() {
        assert_eq!(classify_source("203.0.113.7"), SourceKind::Wan);
        assert_eq!(classify_source("8.8.8.8"), SourceKind::Wan);
        assert_eq!(classify_source("198.51.100.9"), SourceKind::Wan);
    }

    #[test]
    fn classify_source_defaults_unparseable_input_to_wan() {
        assert_eq!(classify_source("not-an-ip"), SourceKind::Wan);
        assert_eq!(classify_source("2001:db8::1"), SourceKind::Wan, "IPv6 not handled — safe default");
    }

    // ---- WAN enrichment: network group / bogon / reputation / PTR -------------------------

    #[test]
    fn wan_network_group_is_the_containing_slash24() {
        assert_eq!(wan_network_group("203.0.113.7"), "203.0.113.0/24");
        assert_eq!(wan_network_group("not-an-ip"), "unknown");
    }

    #[test]
    fn is_bogon_flags_reserved_ranges_not_real_public_addresses() {
        assert!(is_bogon_v4("203.0.113.7"), "TEST-NET-3 is reserved/documentation, never real");
        assert!(is_bogon_v4("198.51.100.9"), "TEST-NET-2");
        assert!(is_bogon_v4("0.5.5.5"), "0.0.0.0/8");
        assert!(is_bogon_v4("240.1.2.3"), "reserved 240/4");
        assert!(!is_bogon_v4("8.8.8.8"), "a real public address must NOT be flagged");
        assert!(!is_bogon_v4("not-an-ip"), "malformed input fails toward not-flagged");
    }

    #[test]
    fn wan_reputation_matches_a_hydra_feed_and_reports_unknown_otherwise() {
        let spamhaus = "1.2.3.0/24 ; SBL12345\n";
        let firehol = "203.0.113.0/24\n";
        let feeds = [("spamhaus-drop", spamhaus), ("firehol-level1", firehol)];
        assert_eq!(wan_reputation("203.0.113.7", &feeds), Some("firehol-level1".to_string()));
        assert_eq!(wan_reputation("9.9.9.9", &feeds), None, "not listed → honest 'unknown, needs feed'");
    }

    #[test]
    fn parses_getent_hosts_ptr_output() {
        assert_eq!(parse_getent_hosts("203.0.113.7    example.com.\n"), Some("example.com".to_string()));
        assert_eq!(parse_getent_hosts(""), None, "no PTR record / NXDOMAIN");
    }

    // ---- parse_default_gateway / parse_resolv_conf_nameservers — HIGH #4 -------------------

    #[test]
    fn parses_default_gateway_from_ip_route_output() {
        let text = "default via 198.51.100.1 dev end0 proto dhcp metric 100 \n";
        assert_eq!(parse_default_gateway(text), Some("198.51.100.1".to_string()));
    }

    #[test]
    fn parses_first_default_gateway_when_multiple_routes_present() {
        let text = "default via 198.51.100.1 dev end0 proto dhcp metric 100\ndefault via 10.0.0.1 dev wwan1 metric 200\n";
        assert_eq!(parse_default_gateway(text), Some("198.51.100.1".to_string()));
    }

    #[test]
    fn parse_default_gateway_is_none_when_absent() {
        assert_eq!(parse_default_gateway(""), None);
        assert_eq!(parse_default_gateway("10.66.0.0/24 dev wlan0 proto kernel scope link\n"), None);
    }

    #[test]
    fn parses_resolv_conf_nameservers() {
        let text = "search example.com\nnameserver 1.1.1.1\nnameserver 9.9.9.9\noptions edns0\n";
        assert_eq!(parse_resolv_conf_nameservers(text), vec!["1.1.1.1".to_string(), "9.9.9.9".to_string()]);
        assert!(parse_resolv_conf_nameservers("").is_empty());
    }

    // ---- parse_wan_self_ips — Q5 fix (the dedicated wan-self list) -------------------------

    #[test]
    fn parses_wan_self_ips_from_ip_dash_o_addr_show_output() {
        let text = "2: end0    inet 198.51.100.44/24 brd 198.51.100.255 scope global end0\\       valid_lft forever preferred_lft forever\n";
        assert_eq!(parse_wan_self_ips(text), vec!["198.51.100.44".to_string()]);
    }

    #[test]
    fn parses_wan_self_ips_from_multiline_ip_addr_show_output() {
        let text = "2: end0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500\n    inet 198.51.100.44/24 brd 198.51.100.255 scope global end0\n       valid_lft forever preferred_lft forever\n";
        assert_eq!(parse_wan_self_ips(text), vec!["198.51.100.44".to_string()]);
    }

    #[test]
    fn parse_wan_self_ips_ignores_inet6_and_malformed_lines() {
        let text = "2: end0    inet6 fe80::1/64 scope link\n2: end0    inet 203.0.113.9/32 scope global end0\n";
        assert_eq!(parse_wan_self_ips(text), vec!["203.0.113.9".to_string()], "inet6 lines must never be picked up as an inet address");
        assert!(parse_wan_self_ips("").is_empty());
        assert!(parse_wan_self_ips("no inet token here at all\n").is_empty());
    }

    #[test]
    fn parses_multiple_wan_self_addresses_multi_wan() {
        let text = "2: end0    inet 198.51.100.44/24 scope global end0\n3: wwan1    inet 203.0.113.5/32 scope global wwan1\n";
        assert_eq!(parse_wan_self_ips(text), vec!["198.51.100.44".to_string(), "203.0.113.5".to_string()]);
    }

    #[test]
    fn enrich_wan_reports_network_intel_and_accumulates_scan_facts() {
        let a1 = alert("203.0.113.7", 22);
        let r1 = enrich_wan(None, &a1, Some("example.com"), Some("firehol-level1"), 1000.0);
        assert_eq!(r1.network_group, "203.0.113.0/24");
        assert!(r1.is_bogon, "TEST-NET-3 flagged bogon");
        assert_eq!(r1.reputation.as_deref(), Some("firehol-level1"));
        assert_eq!(r1.ptr.as_deref(), Some("example.com"));
        assert_eq!(r1.scan_ports, vec![22]);

        // a later alert with no fresh PTR/reputation carries the prior facts forward (honest —
        // not re-fabricated), and accumulates the new port.
        let a2 = alert("203.0.113.7", 443);
        let r2 = enrich_wan(Some(&r1), &a2, None, None, 1005.0);
        assert_eq!(r2.ptr.as_deref(), Some("example.com"), "PTR carried forward");
        assert_eq!(r2.reputation.as_deref(), Some("firehol-level1"), "reputation carried forward");
        assert_eq!(r2.scan_ports, vec![22, 443]);
        assert_eq!(r2.scan_count, 2);
        assert_eq!(r2.first_seen, 1000.0);
    }

    #[test]
    fn enrich_wan_is_honest_about_unresolved_ptr_and_reputation() {
        let a = alert("198.51.100.9", 22);
        let r = enrich_wan(None, &a, None, None, 1000.0);
        assert_eq!(r.ptr, None, "no PTR — reported as None, not guessed");
        assert_eq!(r.reputation, None, "not on any feed — 'unknown, needs feed', not fabricated clean");
    }

    // ---- nft rendering — LAN vs WAN branching (the key requirement) ------------------------

    #[test]
    fn bootstrap_nft_renders_both_lan_and_wan_iface_scoped_rules() {
        let f = render_bootstrap(300, &IfaceConfig::default());
        assert!(f.content.contains("add table inet hookprobe_quarantine"));
        assert!(f.content.contains("add set inet hookprobe_quarantine quarantine_lan_ips { type ipv4_addr; flags timeout; }"));
        assert!(f.content.contains("add set inet hookprobe_quarantine quarantine_lan_macs { type ether_addr; flags timeout; }"));
        assert!(f.content.contains("add set inet hookprobe_quarantine quarantine_wan_ips { type ipv4_addr; flags timeout; }"));
        assert!(f.content.contains("flush chain inet hookprobe_quarantine forward"));
        // 2026-07-06: every drop fires on the UNION of the {lan, wan} ingress interfaces (default
        // wlan0+end0), on BOTH forward AND input — a quarantined source is dropped on whichever
        // interface it actually arrives on, closing the on-metal "private-IP scanner on the WAN
        // uplink was quarantined into quarantine_lan_macs but never dropped" gap.
        for hook in ["forward", "input"] {
            assert!(
                f.content.contains(&format!("{hook} iifname {{ \"wlan0\", \"end0\" }} ether saddr @quarantine_lan_macs drop")),
                "mac-keyed drop must fire on BOTH ifaces on {hook} (the gap fix)"
            );
            assert!(
                f.content.contains(&format!("{hook} iifname {{ \"wlan0\", \"end0\" }} ip saddr @quarantine_wan_ips drop")),
                "wan-ip drop on both ifaces, {hook}"
            );
            assert!(
                f.content.contains(&format!("{hook} iifname {{ \"wlan0\", \"end0\" }} ip saddr @quarantine_lan_ips drop")),
                "lan-ip drop on both ifaces, {hook}"
            );
        }
        assert!(!f.content.contains("quarantine_wan_macs"), "no MAC set for WAN — a routed source has none");
    }

    #[test]
    fn bootstrap_nft_honors_custom_iface_names() {
        let f = render_bootstrap(300, &IfaceConfig { lan: "hp-br0".to_string(), wan: "eth2".to_string() });
        // The union iface set carries BOTH custom names; the defaults never leak in.
        assert!(f.content.contains("iifname { \"hp-br0\", \"eth2\" }"), "bridged LAN plane + custom WAN in the drop-rule union");
        assert!(!f.content.contains("wlan0") && !f.content.contains("end0"));
    }

    #[test]
    fn bootstrap_nft_collapses_the_iface_set_when_lan_equals_wan() {
        // Single-interface deployments (lan == wan) must render a bare `iifname "eth0"`, never a
        // degenerate `{ "eth0", "eth0" }` set.
        let f = render_bootstrap(300, &IfaceConfig { lan: "eth0".to_string(), wan: "eth0".to_string() });
        assert!(f.content.contains("iifname \"eth0\" ether saddr @quarantine_lan_macs drop"));
        assert!(!f.content.contains("{ \"eth0\", \"eth0\" }"));
    }

    /// REGRESSION — the cross-platform bug confirmed live on an amd64 VM: with the RESOLVED
    /// (non-Pi) interface set from that box (`enp0s2`/`enp0s3`), the nft quarantine must scope its
    /// drop rules to THOSE names, never fall back to `wlan0`/`end0`.
    #[test]
    fn bootstrap_nft_uses_resolved_non_pi_ifaces_not_hardcoded_defaults() {
        let ifaces = IfaceConfig { lan: "enp0s3".to_string(), wan: "enp0s2".to_string() };
        let f = render_bootstrap(300, &ifaces);
        assert!(f.content.contains("iifname { \"enp0s3\", \"enp0s2\" }"), "got: {}", f.content);
        assert!(!f.content.contains("wlan0") && !f.content.contains("end0"), "must never leak the Pi defaults: {}", f.content);
    }

    /// `manifest_iface_fallback` is a pure, no-I/O read of the SIGNED manifest's own already-
    /// resolved uplinks/wifi_radios — the BPF loaders' last-resort fallback when their configured
    /// iface is absent from sysfs. A wired-only (no Wi-Fi) manifest falls back to the manifest's
    /// own enp* names, never wlan0/end0.
    #[test]
    fn manifest_iface_fallback_resolves_enp_names_from_uplinks() {
        use crate::types::{ManifestUplink, Network};
        let mut manifest = crate::builder::build_manifest(
            &crate::scan::HardwareScan {
                device_tree_compatible: vec![],
                dmi: None,
                arch: crate::types::Arch::Amd64,
                cpu: crate::scan::ScanCpu { model: String::new(), cores: 2 },
                memory_mb: 2048,
                kernel_release: None,
                storage: vec![],
                tpm: crate::types::Tpm { present: false, version: None, kind: crate::types::TpmKind::None },
                secure_boot: crate::types::SecureBoot { supported: false, enabled: false },
                npu: crate::types::Npu { present: false, driver_ready: false, vendor: None, model: None },
                virt: "kvm".to_string(),
                interfaces: vec![],
                wifi: crate::types::Wifi { present: false, max_standard: None },
                lte: crate::types::Lte { present: false, model: None },
                unbound: vec![],
            },
            {
                let platforms = crate::load_platforms(std::path::Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/../../platforms"))).expect("platforms");
                // classify() borrows `platforms`; leak it for this test's simple lifetime needs.
                Box::leak(Box::new(platforms)).iter().find(|p| p.profile == "cloud").expect("cloud platform")
            },
            &crate::types::MatchInfo { method: crate::types::MatchMethod::Virt, key: "kvm".to_string() },
            "2026-01-01T00:00:00Z",
            "img",
            "sha256:0",
        )
        .expect("manifest");
        // Override network facts directly (this test is about the fallback fn, not classification).
        manifest.network = Network {
            uplinks: vec![
                ManifestUplink { name: "enp0s2".to_string(), kind: "wired".to_string(), priority: 10 },
                ManifestUplink { name: "enp0s3".to_string(), kind: "wired".to_string(), priority: 10 },
            ],
            ..manifest.network
        };
        let (wan, lan) = manifest_iface_fallback(&manifest);
        assert_eq!(wan.as_deref(), Some("enp0s2"));
        assert_eq!(lan.as_deref(), Some("enp0s3"), "no AP radio → falls back to the second uplink, not wlan0");
    }

    // ---- EDR #3 fix: render_syn_fanout_rate_limit — separate table, distinct meter names,
    // delete-table-first idempotent from the start (learns H1's lesson up front) ----------------

    #[test]
    fn syn_ratelimit_renders_a_separate_table_from_quarantine_and_l2guard() {
        let f = render_syn_fanout_rate_limit(&SynRateLimitConfig::default());
        assert!(f.content.contains("hookprobe_scan_ratelimit"));
        assert!(!f.content.contains("hookprobe_quarantine"), "must never touch the durable quarantine table");
        assert!(!f.content.contains("hookprobe_l2guard"), "must never touch the L1/L2 storm-control table");
    }

    #[test]
    fn syn_ratelimit_uses_two_distinctly_named_meters_never_the_same_name_twice() {
        // nft rejects the SAME meter name referenced from two different rules ("overlaps an
        // existing set") — reproduced empirically while building this. forward and input MUST use
        // distinct meter names.
        let f = render_syn_fanout_rate_limit(&SynRateLimitConfig::default());
        assert!(f.content.contains("napse_synfanout_fwd_wlan0_meter"));
        assert!(f.content.contains("napse_synfanout_in_wlan0_meter"));
        assert!(f.content.contains("napse_synfanout_fwd_end0_meter"));
        assert!(f.content.contains("napse_synfanout_in_end0_meter"));
        assert_ne!("napse_synfanout_fwd_wlan0_meter", "napse_synfanout_in_wlan0_meter");
    }

    #[test]
    fn syn_ratelimit_matches_new_syn_only_not_established_traffic() {
        let f = render_syn_fanout_rate_limit(&SynRateLimitConfig::default());
        assert!(f.content.contains("tcp flags syn / syn,ack"), "must match SYN-only, not SYN-ACK/established");
    }

    #[test]
    fn syn_ratelimit_is_idempotent_shaped_delete_before_add() {
        let f = render_syn_fanout_rate_limit(&SynRateLimitConfig::default());
        let delete_at = f.content.find("delete table inet hookprobe_scan_ratelimit").expect("must delete-first");
        let add_at = f.content.find("add table inet hookprobe_scan_ratelimit").expect("must add table");
        assert!(delete_at < add_at, "delete table must precede add table (H1's lesson, applied from the start)");
    }

    /// Real-`nft` proof (mirrors `l2_responder`'s equivalent test): apply the rendered rate-limit
    /// bootstrap TWICE, line-by-line, inside an unprivileged network namespace. Skips cleanly if
    /// this sandbox has neither `nft` nor unprivileged user namespaces.
    #[test]
    fn syn_ratelimit_apply_twice_succeeds_line_by_line() {
        use std::process::Command;
        let probe = Command::new("unshare").args(["--net", "--map-root-user", "--", "true"]).status();
        if !matches!(probe, Ok(st) if st.success()) {
            eprintln!("skipping syn_ratelimit_apply_twice_succeeds_line_by_line: no unprivileged netns available");
            return;
        }
        if Command::new("nft").arg("--version").status().is_err() {
            eprintln!("skipping syn_ratelimit_apply_twice_succeeds_line_by_line: nft not installed");
            return;
        }
        let content = render_syn_fanout_rate_limit(&SynRateLimitConfig::default()).content;
        let script = format!(
            "apply() {{ echo \"$1\" | while IFS= read -r line; do \
               case \"$line\" in ''|'#'*) continue;; esac; \
               nft $line >/tmp/synrl_apply_err.$$ 2>&1 || {{ cat /tmp/synrl_apply_err.$$; exit 1; }}; \
               rm -f /tmp/synrl_apply_err.$$; \
             done; }}\n\
             CONTENT='{}'\n\
             echo \"$CONTENT\" | while IFS= read -r line; do case \"$line\" in ''|'#'*) continue;; esac; nft $line >/dev/null 2>&1; done\n\
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
            "second apply of render_syn_fanout_rate_limit's output must succeed with the real nft binary — \
             stdout:\n{stdout}\nstderr:\n{stderr}"
        );
        assert!(!stdout.to_lowercase().contains("overlaps an existing set"));
    }

    #[test]
    fn response_json_for_rate_limit_verdict_is_active_and_distinct_from_observed() {
        let a = ScanAlert {
            ts: 1000.0,
            src_ip: "203.0.113.7".to_string(),
            src_port: 51000,
            dst_ip: "10.66.0.1".to_string(),
            dst_port: 22,
            proto: "tcp".to_string(),
            severity: 4,
            rule_id: PORT_SCAN_RULE_ID,
            rule_msg: "NAPSE Port Scan Detected".to_string(),
            mitre: "T1046".to_string(),
            category: "port_scan".to_string(),
            confidence: 0.75,
            confirmed: false,
            src_mac: None,
        };
        let verdict = ReflexVerdict::RateLimit { reason: "test unconfirmed fan-out".to_string() };
        let j = render_response_json(&a, &verdict, 300, 2000.0, "end0");
        let v: serde_json::Value = serde_json::from_str(&j).expect("valid json");
        assert_eq!(v["action"], "rate_limit");
        assert_eq!(v["status"], "active", "RateLimit DOES enforce, unlike Observed");

        let observed = ReflexVerdict::Observed { reason: "martian".to_string() };
        let j2 = render_response_json(&a, &observed, 300, 2000.0, "end0");
        let v2: serde_json::Value = serde_json::from_str(&j2).expect("valid json");
        assert_eq!(v2["action"], "observe_only");
        assert_eq!(v2["status"], "unconfirmed", "Observed truly enforces nothing, unlike RateLimit");
    }

    // (c) — the CORE Q2-half-2 re-audit proof: a LAN entry must enforce via its OBSERVED MAC
    // ONLY — it must NEVER populate `quarantine_lan_ips` with the (spoofable-capable) claimed IP.
    // Before this fix, an attacker who somehow drove a LAN entry for a victim's IP would still
    // have that IP dropped at the nft layer regardless of MAC; after this fix, only the
    // attacker's own hardware (the MAC that actually completed the handshake — see
    // `confirm::HandshakeTracker`) can ever be dropped.
    #[test]
    fn element_ops_routes_lan_entry_to_mac_only_never_the_spoofable_ip() {
        let diff = QuarantineDiff {
            to_add: vec![QuarantineEntry {
                ip: "10.66.0.20".into(),
                mac: Some("aa:bb:cc:dd:ee:ff".into()),
                first_seen: 0.0,
                last_seen: 0.0,
                offenses: 1,
            }],
            to_remove: vec![],
            state: vec![],
        };
        let f = render_element_ops(&diff, 300);
        assert!(
            f.content.contains("add element inet hookprobe_quarantine quarantine_lan_macs { aa:bb:cc:dd:ee:ff timeout 300s }"),
            "the observed mac IS enforced"
        );
        assert!(
            !f.content.contains("quarantine_lan_ips"),
            "Q2 fix: a LAN entry must NEVER populate the spoofable ip set, not even as a comment target"
        );
        assert!(!f.content.contains("quarantine_wan_ips"), "a LAN entry must never land in the WAN set");
    }

    // A LAN entry that (for whatever reason) has no resolved mac must NOT be enforced at all on
    // the LAN plane — it must never silently fall back to the spoofable ip.
    #[test]
    fn element_ops_lan_entry_without_a_mac_is_not_enforced_on_either_set() {
        let diff = QuarantineDiff {
            to_add: vec![QuarantineEntry { ip: "10.66.0.21".into(), mac: None, first_seen: 0.0, last_seen: 0.0, offenses: 1 }],
            to_remove: vec![],
            state: vec![],
        };
        let f = render_element_ops(&diff, 300);
        assert!(!f.content.contains("add element"), "no mac to enforce with — nothing is added, only a warning comment");
        assert!(f.content.contains("NOT enforced"), "the gap is documented in the plan, not silently dropped");
    }

    // The `delete` (revert) side must mirror the `add` side: a LAN removal deletes the mac
    // element only, never touches quarantine_lan_ips (which the add side never populated either).
    #[test]
    fn element_ops_lan_removal_deletes_the_mac_element_only() {
        let diff = QuarantineDiff {
            to_add: vec![],
            to_remove: vec![QuarantineEntry {
                ip: "10.66.0.20".into(),
                mac: Some("aa:bb:cc:dd:ee:ff".into()),
                first_seen: 0.0,
                last_seen: 0.0,
                offenses: 1,
            }],
            state: vec![],
        };
        let f = render_element_ops(&diff, 300);
        assert!(f.content.contains("delete element inet hookprobe_quarantine quarantine_lan_macs { aa:bb:cc:dd:ee:ff }"));
        assert!(!f.content.contains("quarantine_lan_ips"));
    }

    #[test]
    fn element_ops_routes_wan_entry_to_ip_only_set() {
        let diff = QuarantineDiff {
            to_add: vec![QuarantineEntry { ip: "203.0.113.7".into(), mac: None, first_seen: 0.0, last_seen: 0.0, offenses: 1 }],
            to_remove: vec![QuarantineEntry { ip: "198.51.100.9".into(), mac: None, first_seen: 0.0, last_seen: 0.0, offenses: 1 }],
            state: vec![],
        };
        let f = render_element_ops(&diff, 300);
        assert!(f.content.contains("add element inet hookprobe_quarantine quarantine_wan_ips { 203.0.113.7 timeout 300s }"));
        assert!(f.content.contains("delete element inet hookprobe_quarantine quarantine_wan_ips { 198.51.100.9 }"));
        assert!(!f.content.contains("quarantine_lan_ips"), "a WAN entry must never land in the LAN set");
        assert!(!f.content.contains("quarantine_lan_macs"), "no MAC element for a WAN entry");
    }

    #[test]
    fn element_ops_empty_diff_is_a_no_op_plan() {
        let f = render_element_ops(&QuarantineDiff::default(), 300);
        assert!(f.content.contains("no change this cycle"));
    }

    // ---- response JSON ------------------------------------------------------------------------

    #[test]
    fn response_json_for_lan_quarantine_names_the_lan_iface() {
        let a = alert("10.66.0.20", 22);
        let v = ReflexVerdict::Quarantine { reason: "test reason".to_string() };
        let json = render_response_json(&a, &v, 300, 1000.0, "wlan0");
        let parsed: serde_json::Value = serde_json::from_str(&json).expect("must be valid JSON");
        assert_eq!(parsed["action"], "quarantine");
        assert_eq!(parsed["status"], "active");
        assert_eq!(parsed["src_ip"], "10.66.0.20");
        assert_eq!(parsed["rule_id"], 1000003);
        assert_eq!(parsed["ttl_secs"], 300);
        assert_eq!(parsed["detail"], "quarantined via nft on wlan0, TTL 300s, auto-revert — test reason");
    }

    #[test]
    fn response_json_for_wan_quarantine_names_the_wan_iface() {
        let a = alert("203.0.113.7", 22);
        let v = ReflexVerdict::Quarantine { reason: "test reason".to_string() };
        let json = render_response_json(&a, &v, 300, 1000.0, "end0");
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["detail"], "quarantined via nft on end0, TTL 300s, auto-revert — test reason");
    }

    #[test]
    fn response_json_for_allowlisted_is_log_only() {
        let a = alert("10.200.0.5", 22);
        let v = ReflexVerdict::Allowlisted { reason: "mgmt subnet".to_string() };
        let json = render_response_json(&a, &v, 300, 1000.0, "wlan0");
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["action"], "log_only");
        assert_eq!(parsed["status"], "skipped");
    }

    #[test]
    fn response_json_for_observed_is_observe_only_and_never_active() {
        let a = alert("203.0.113.7", 22);
        let v = ReflexVerdict::Observed { reason: "unconfirmed SYN fan-out".to_string() };
        let json = render_response_json(&a, &v, 300, 1000.0, "end0");
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["action"], "observe_only");
        assert_eq!(parsed["status"], "unconfirmed");
        assert_ne!(parsed["status"], "active", "an Observed verdict must never render as an active enforcement");
    }

    #[test]
    fn revert_json_is_valid_and_marks_reverted() {
        let e = QuarantineEntry { ip: "203.0.113.7".into(), mac: Some("aa:bb:cc:dd:ee:ff".into()), first_seen: 1000.0, last_seen: 1000.0, offenses: 1 };
        let json = render_revert_json(&e, 300, 1400.0, "end0");
        let parsed: serde_json::Value = serde_json::from_str(&json).expect("must be valid JSON");
        assert_eq!(parsed["action"], "revert");
        assert_eq!(parsed["status"], "reverted");
        assert_eq!(parsed["target"], "203.0.113.7");
        assert!(parsed["detail"].as_str().unwrap().contains("nft on end0"));
    }

    // ---- injection safety (mirrors hookprobe-evidence's own injection test) -----------------

    #[test]
    fn response_json_survives_hostile_reason_text() {
        let a = alert("203.0.113.7", 22);
        let nasty = "reason\" ,\"injected\":\"x\n2nd\\line".to_string();
        let v = ReflexVerdict::Quarantine { reason: nasty.clone() };
        let json = render_response_json(&a, &v, 300, 1000.0, "end0");
        let parsed: serde_json::Value = serde_json::from_str(&json).expect("serde_json must always produce valid JSON");
        assert!(parsed["detail"].as_str().unwrap().contains(&nasty));
    }
}

// =============================================================================================
// RESOURCE-REALITY ENFORCEMENT — tests (deliberately a SEPARATE `mod` from `tests` above, so
// this addition never touches an existing test — see this file's task-scoping requirement).
// =============================================================================================
#[cfg(test)]
mod resource_shed_tests {
    use super::*;

    // ---- PSI parsing -------------------------------------------------------------------------

    #[test]
    fn parses_a_real_proc_pressure_line() {
        let (kind, snap) = parse_psi_line("some avg10=6.43 avg60=6.09 avg300=7.02 total=28965010545").unwrap();
        assert_eq!(kind, "some");
        assert!((snap.avg10 - 6.43).abs() < 1e-9);
        assert!((snap.avg60 - 6.09).abs() < 1e-9);
        assert!((snap.avg300 - 7.02).abs() < 1e-9);
        assert_eq!(snap.total, 28965010545);
    }

    #[test]
    fn parses_a_whole_psi_file_with_some_and_full() {
        let text = "some avg10=0.00 avg60=0.00 avg300=0.00 total=51802787\nfull avg10=1.00 avg60=2.00 avg300=3.00 total=38847083\n";
        let p = parse_psi_file(text);
        assert_eq!(p.some.unwrap().avg10, 0.0);
        assert_eq!(p.full.unwrap().avg60, 2.0);
    }

    #[test]
    fn psi_line_rejects_garbage_without_panicking() {
        assert!(parse_psi_line("").is_none());
        assert!(parse_psi_line("not a psi line").is_none());
        assert!(parse_psi_line("some avg10=notanumber").is_none());
    }

    #[test]
    fn cpu_has_no_full_line_in_practice_but_parser_tolerates_its_absence() {
        // real /proc/pressure/cpu carries only a `some` line — PsiPressure::full stays None,
        // never fabricated.
        let p = parse_psi_file("some avg10=6.43 avg60=6.09 avg300=7.02 total=1\n");
        assert!(p.full.is_none());
    }

    // ---- psi_under_sustained_pressure — keyed on avg60, never avg10 -------------------------

    #[test]
    fn a_transient_avg10_spike_alone_never_triggers_sustained_pressure() {
        let cpu = PsiPressure { some: Some(PsiSnapshot { avg10: 99.0, avg60: 2.0, avg300: 1.0, total: 1 }), full: None };
        let mem = PsiPressure::default();
        assert!(
            psi_under_sustained_pressure(&cpu, &mem, &PsiThresholds::default()).is_none(),
            "a spiky avg10 with a low avg60 must NOT read as sustained pressure"
        );
    }

    #[test]
    fn sustained_cpu_some_avg60_triggers() {
        let cpu = PsiPressure { some: Some(PsiSnapshot { avg10: 45.0, avg60: 45.0, avg300: 40.0, total: 1 }), full: None };
        let mem = PsiPressure::default();
        let r = psi_under_sustained_pressure(&cpu, &mem, &PsiThresholds::default());
        assert!(r.is_some());
        assert!(r.unwrap().contains("CPU"));
    }

    #[test]
    fn sustained_memory_full_avg60_triggers_and_some_alone_does_not() {
        // memory `some` well above the cpu-style threshold must NOT trigger — only `full` counts.
        let mem_some_only =
            PsiPressure { some: Some(PsiSnapshot { avg10: 90.0, avg60: 90.0, avg300: 90.0, total: 1 }), full: None };
        assert!(psi_under_sustained_pressure(&PsiPressure::default(), &mem_some_only, &PsiThresholds::default()).is_none());

        let mem_full = PsiPressure { some: None, full: Some(PsiSnapshot { avg10: 20.0, avg60: 20.0, avg300: 20.0, total: 1 }) };
        let r = psi_under_sustained_pressure(&PsiPressure::default(), &mem_full, &PsiThresholds::default());
        assert!(r.is_some());
        assert!(r.unwrap().contains("MEMORY"));
    }

    #[test]
    fn no_psi_data_at_all_never_triggers() {
        assert!(psi_under_sustained_pressure(&PsiPressure::default(), &PsiPressure::default(), &PsiThresholds::default())
            .is_none());
    }

    // ---- conntrack fill + top-talkers ----------------------------------------------------------

    #[test]
    fn conntrack_fill_pct_computes_correctly_and_never_divides_by_zero() {
        assert!((conntrack_fill_pct(80, 100) - 80.0).abs() < 1e-9);
        assert_eq!(conntrack_fill_pct(1, 0), 0.0, "must never divide by zero");
    }

    #[test]
    fn parse_conntrack_scalar_parses_a_bare_integer() {
        assert_eq!(parse_conntrack_scalar("1096\n"), Some(1096));
        assert_eq!(parse_conntrack_scalar("not a number"), None);
    }

    const CONNTRACK_DUMP: &str = "\
tcp 6 431999 ESTABLISHED src=203.0.113.9 dst=10.66.0.5 sport=51001 dport=443 src=10.66.0.5 dst=203.0.113.9 sport=443 dport=51001 [ASSURED] mark=0 use=1\n\
tcp 6 431999 ESTABLISHED src=203.0.113.9 dst=10.66.0.5 sport=51002 dport=443 src=10.66.0.5 dst=203.0.113.9 sport=443 dport=51002 [ASSURED] mark=0 use=1\n\
tcp 6 431999 ESTABLISHED src=203.0.113.9 dst=10.66.0.5 sport=51003 dport=443 src=10.66.0.5 dst=203.0.113.9 sport=443 dport=51003 [ASSURED] mark=0 use=1\n\
tcp 6 431999 ESTABLISHED src=198.51.100.4 dst=10.66.0.5 sport=51010 dport=443 src=10.66.0.5 dst=198.51.100.4 sport=443 dport=51010 [ASSURED] mark=0 use=1\n";

    #[test]
    fn parse_conntrack_line_src_takes_the_first_src_token_only() {
        let line = "tcp 6 431999 ESTABLISHED src=203.0.113.9 dst=10.66.0.5 sport=1 dport=2 src=10.66.0.5 dst=203.0.113.9 sport=2 dport=1 [ASSURED] mark=0 use=1";
        assert_eq!(parse_conntrack_line_src(line), Some("203.0.113.9".to_string()));
    }

    #[test]
    fn parse_conntrack_src_ips_counts_one_entry_per_row() {
        let ips = parse_conntrack_src_ips(CONNTRACK_DUMP);
        assert_eq!(ips.len(), 4);
        assert_eq!(ips.iter().filter(|ip| *ip == "203.0.113.9").count(), 3);
    }

    #[test]
    fn top_talkers_ranks_by_concurrent_flow_count_descending() {
        let ips = parse_conntrack_src_ips(CONNTRACK_DUMP);
        let ranked = top_talkers(&ips, 2);
        assert_eq!(ranked[0], ("203.0.113.9".to_string(), 3));
        assert_eq!(ranked[1], ("198.51.100.4".to_string(), 1));
    }

    // ---- THE CORE REQUIREMENT: a flood-rate source is capped; a legit source is NOT -----------

    #[test]
    fn evaluate_resource_reality_caps_a_genuine_flood_source_during_conntrack_saturation() {
        // Build a table that is 85% full (over the 80% wall) with ONE source responsible for a
        // clear majority of entries — the shape of a real connection-flood.
        let mut flood_ips: Vec<String> = Vec::new();
        for _ in 0..500 {
            flood_ips.push("203.0.113.9".to_string()); // the flood source: 500 concurrent flows
        }
        for i in 0..10 {
            flood_ips.push(format!("192.168.1.{}", i)); // ten ordinary LAN clients, a few flows each
        }
        let inputs = ResourceRealityInputs {
            conntrack_count: Some(85_000),
            conntrack_max: Some(100_000),
            conntrack_src_ips: flood_ips,
            psi_cpu: PsiPressure::default(),
            psi_mem: PsiPressure::default(),
        };
        let triggers = evaluate_resource_reality(&inputs, &ResourceRealityConfig::default());
        assert_eq!(triggers.len(), 1, "only the genuine flood source should trigger, got {triggers:?}");
        assert_eq!(triggers[0].ip, "203.0.113.9");
        assert_eq!(triggers[0].signal, "conntrack_saturation");
    }

    #[test]
    fn evaluate_resource_reality_never_caps_a_legit_high_but_normal_source() {
        // Table is comfortably below the saturation wall (30% full) — even though one source
        // happens to have more flows than the rest (a legitimate busy NAS/media box), nothing
        // should trigger, because the RESOURCE WALL itself was never crossed.
        let mut ips: Vec<String> = Vec::new();
        for _ in 0..40 {
            ips.push("192.168.1.50".to_string()); // the busiest legit LAN host: 40 concurrent flows
        }
        for i in 0..10 {
            ips.push(format!("192.168.1.{}", i));
        }
        let inputs = ResourceRealityInputs {
            conntrack_count: Some(30_000),
            conntrack_max: Some(100_000),
            conntrack_src_ips: ips,
            psi_cpu: PsiPressure::default(),
            psi_mem: PsiPressure::default(),
        };
        let triggers = evaluate_resource_reality(&inputs, &ResourceRealityConfig::default());
        assert!(triggers.is_empty(), "table nowhere near saturated — must never shed anyone; got {triggers:?}");
    }

    #[test]
    fn evaluate_resource_reality_never_caps_when_table_full_but_no_single_top_talker_floor_met() {
        // The table IS 90% full, but from thousands of small, roughly-equal legitimate flows (the
        // "many small fish" case this crate's `top_talker_min_entries` floor exists for) — nobody
        // individually crosses the floor, so nobody is capped (erring toward not dropping).
        let mut ips: Vec<String> = Vec::new();
        for i in 0..50 {
            ips.push(format!("192.168.1.{}", i)); // 50 hosts, 2 flows each = 100 total, all small
            ips.push(format!("192.168.1.{}", i));
        }
        let inputs = ResourceRealityInputs {
            conntrack_count: Some(90_000),
            conntrack_max: Some(100_000),
            conntrack_src_ips: ips,
            psi_cpu: PsiPressure::default(),
            psi_mem: PsiPressure::default(),
        };
        let triggers = evaluate_resource_reality(&inputs, &ResourceRealityConfig::default());
        assert!(triggers.is_empty(), "no single source meets the top-talker floor — must not shed; got {triggers:?}");
    }

    #[test]
    fn evaluate_resource_reality_psi_pressure_caps_the_highest_volume_source() {
        let mut ips: Vec<String> = Vec::new();
        for _ in 0..20 {
            ips.push("203.0.113.9".to_string());
        }
        ips.push("192.168.1.5".to_string());
        let inputs = ResourceRealityInputs {
            conntrack_count: None, // no conntrack-saturation signal this cycle at all
            conntrack_max: None,
            conntrack_src_ips: ips,
            psi_cpu: PsiPressure { some: Some(PsiSnapshot { avg10: 50.0, avg60: 50.0, avg300: 45.0, total: 1 }), full: None },
            psi_mem: PsiPressure::default(),
        };
        let triggers = evaluate_resource_reality(&inputs, &ResourceRealityConfig::default());
        assert_eq!(triggers.len(), 1);
        assert_eq!(triggers[0].ip, "203.0.113.9", "the highest-volume source (by conntrack count) is capped");
        assert_eq!(triggers[0].signal, "psi_cpu");
    }

    #[test]
    fn evaluate_resource_reality_psi_pressure_with_no_conntrack_visibility_never_guesses_a_source() {
        let inputs = ResourceRealityInputs {
            conntrack_count: None,
            conntrack_max: None,
            conntrack_src_ips: Vec::new(), // no visibility into who is using the resource
            psi_cpu: PsiPressure { some: Some(PsiSnapshot { avg10: 90.0, avg60: 90.0, avg300: 90.0, total: 1 }), full: None },
            psi_mem: PsiPressure::default(),
        };
        let triggers = evaluate_resource_reality(&inputs, &ResourceRealityConfig::default());
        assert!(triggers.is_empty(), "genuinely under pressure but no attributable source — must never guess/cap blindly");
    }

    #[test]
    fn evaluate_resource_reality_dedupes_a_source_triggered_by_both_gates() {
        let mut ips: Vec<String> = Vec::new();
        for _ in 0..500 {
            ips.push("203.0.113.9".to_string());
        }
        let inputs = ResourceRealityInputs {
            conntrack_count: Some(85_000),
            conntrack_max: Some(100_000),
            conntrack_src_ips: ips,
            psi_cpu: PsiPressure { some: Some(PsiSnapshot { avg10: 50.0, avg60: 50.0, avg300: 45.0, total: 1 }), full: None },
            psi_mem: PsiPressure::default(),
        };
        let triggers = evaluate_resource_reality(&inputs, &ResourceRealityConfig::default());
        assert_eq!(triggers.len(), 1, "the SAME source tripping both gates must produce ONE trigger, not two");
        assert_eq!(triggers[0].signal, "conntrack_saturation", "the more specific reason wins over PSI's coarser one");
    }

    // ---- reconcile_resource_shed — self-reverting, no escalation ------------------------------

    #[test]
    fn reconcile_adds_a_new_shed_source() {
        let triggers = vec![ShedTrigger { ip: "203.0.113.9".into(), signal: "conntrack_saturation".into(), detail: "x".into() }];
        let diff = reconcile_resource_shed(vec![], &triggers, 1000.0, 60, DEFAULT_MAX_SHED_ENTRIES);
        assert_eq!(diff.to_add.len(), 1);
        assert_eq!(diff.to_add[0].ip, "203.0.113.9");
        assert_eq!(diff.state.len(), 1);
    }

    #[test]
    fn reconcile_refreshes_without_readding_while_still_triggering() {
        let state = vec![ShedEntry {
            ip: "203.0.113.9".into(),
            first_seen: 1000.0,
            last_seen: 1000.0,
            signal: "conntrack_saturation".into(),
            detail: "x".into(),
        }];
        let triggers = vec![ShedTrigger { ip: "203.0.113.9".into(), signal: "conntrack_saturation".into(), detail: "y".into() }];
        let diff = reconcile_resource_shed(state, &triggers, 1020.0, 60, DEFAULT_MAX_SHED_ENTRIES);
        assert!(diff.to_add.is_empty(), "still-triggering source must refresh, not re-add");
        assert!(diff.to_remove.is_empty());
        assert_eq!(diff.state[0].last_seen, 1020.0);
        assert_eq!(diff.state[0].first_seen, 1000.0, "first_seen preserved across refreshes");
        assert_eq!(diff.state[0].detail, "y", "detail updates to the latest triggering fact");
    }

    // THE CORE SELF-REVERT PROOF: once a source stops being re-triggered (the pressure cleared),
    // it is NOT refreshed, and ages out via the TTL sweep exactly like the quarantine table does —
    // never a durable/identity block.
    #[test]
    fn reconcile_self_reverts_once_no_longer_triggered_and_ttl_elapses() {
        let state = vec![ShedEntry {
            ip: "203.0.113.9".into(),
            first_seen: 1000.0,
            last_seen: 1000.0,
            signal: "conntrack_saturation".into(),
            detail: "x".into(),
        }];
        // No triggers this cycle (pressure cleared) — 61s later (past a 60s TTL).
        let diff = reconcile_resource_shed(state, &[], 1061.0, 60, DEFAULT_MAX_SHED_ENTRIES);
        assert_eq!(diff.to_remove.len(), 1, "must self-revert once TTL elapses with no re-trigger");
        assert_eq!(diff.to_remove[0].ip, "203.0.113.9");
        assert!(diff.state.is_empty());
    }

    #[test]
    fn reconcile_does_not_revert_early_within_the_ttl_window() {
        let state = vec![ShedEntry {
            ip: "203.0.113.9".into(),
            first_seen: 1000.0,
            last_seen: 1000.0,
            signal: "conntrack_saturation".into(),
            detail: "x".into(),
        }];
        // Only 10s later, well within a 60s TTL, still no new trigger — must NOT revert yet.
        let diff = reconcile_resource_shed(state, &[], 1010.0, 60, DEFAULT_MAX_SHED_ENTRIES);
        assert!(diff.to_remove.is_empty());
        assert_eq!(diff.state.len(), 1);
    }

    #[test]
    fn reconcile_shed_never_escalates_across_windows_unlike_quarantine() {
        // A source shed today, released, then shed again tomorrow starts completely fresh — no
        // offense counter exists on ShedEntry at all (contrast with QuarantineEntry::offenses).
        let e = ShedEntry { ip: "203.0.113.9".into(), first_seen: 1000.0, last_seen: 1000.0, signal: "psi_cpu".into(), detail: "x".into() };
        // (compile-time proof: constructing a ShedEntry needs no `offenses` field at all.)
        assert_eq!(e.ip, "203.0.113.9");
    }

    #[test]
    fn reconcile_caps_the_shed_set_evicting_the_oldest() {
        let mut state: Vec<ShedEntry> = (0..5)
            .map(|i| ShedEntry {
                ip: format!("203.0.113.{i}"),
                first_seen: i as f64,
                last_seen: i as f64,
                signal: "conntrack_saturation".into(),
                detail: "x".into(),
            })
            .collect();
        state.push(ShedEntry { ip: "9.9.9.9".into(), first_seen: 0.0, last_seen: 0.0, signal: "psi_cpu".into(), detail: "x".into() });
        let triggers = vec![ShedTrigger { ip: "203.0.113.100".into(), signal: "conntrack_saturation".into(), detail: "x".into() }];
        let diff = reconcile_resource_shed(state, &triggers, 1000.0, 10_000, 5);
        assert_eq!(diff.state.len(), 5, "capped at max_entries");
        assert!(diff.state.iter().any(|e| e.ip == "203.0.113.100"), "the newest observation is always kept");
        assert!(diff.to_remove.iter().any(|e| e.ip == "9.9.9.9" || e.ip == "203.0.113.0"), "oldest entries evicted first");
    }

    // ---- nft rendering — real syntax proof + separateness from every other table --------------

    #[test]
    fn render_conn_rate_cap_is_a_separate_table_from_every_other_responder() {
        let g = render_conn_rate_cap(&ConnRateCapConfig::default());
        assert!(g.content.contains("hookprobe_resource_shed"));
        assert!(!g.content.contains("hookprobe_quarantine"), "must never touch the port-scan quarantine table");
        assert!(!g.content.contains("hookprobe_scan_ratelimit"), "must never touch the SYN-fanout rate-limit table");
        assert!(!g.content.contains("hookprobe_l2guard"), "must never touch the L1/L2 storm-control table");
    }

    #[test]
    fn render_conn_rate_cap_uses_ct_state_new_never_a_syn_only_match() {
        // Layer 1 must cap ANY protocol's new-connection rate (a flood need not be TCP), unlike
        // render_syn_fanout_rate_limit's deliberately TCP-SYN-only match.
        let g = render_conn_rate_cap(&ConnRateCapConfig::default());
        assert!(g.content.contains("ct state new"));
    }

    #[test]
    fn render_conn_rate_cap_declares_shed_ips_before_referencing_it() {
        let g = render_conn_rate_cap(&ConnRateCapConfig::default());
        let set_decl = g.content.find("add set inet hookprobe_resource_shed shed_ips").expect("must declare the set");
        let first_use = g.content.find("ip saddr @shed_ips").expect("must reference the set");
        assert!(set_decl < first_use, "the set must be declared before any rule references it");
    }

    #[test]
    fn render_conn_rate_cap_is_idempotent_shaped() {
        let g = render_conn_rate_cap(&ConnRateCapConfig::default());
        let first_add = g.content.find("add table inet hookprobe_resource_shed").expect("guard add-table first");
        let delete_at = g.content.find("delete table inet hookprobe_resource_shed").expect("must delete table");
        let last_add = g.content.rfind("add table inet hookprobe_resource_shed").expect("must re-add table fresh");
        assert!(first_add < delete_at);
        assert!(delete_at < last_add);
    }

    // ---- Finding-2: always-on management-plane flood cap (mgmt-port new-conn rate cap) ----------

    /// The rendered ruleset carries the mgmt-port NEW-conn rate cap on the WAN INPUT chain with the
    /// policy pps (default 20/s to sshd :22), and it is INPUT-only (the forward/customer plane is
    /// never touched).
    #[test]
    fn render_conn_rate_cap_has_always_on_mgmt_port_cap_on_wan_input() {
        let g = render_conn_rate_cap(&ConnRateCapConfig::default());
        // Exact rule shape: WAN input, tcp dport { 22 }, ct state new, per-source meter, drop.
        assert!(
            g.content.contains(
                "add rule inet hookprobe_resource_shed input iifname \"end0\" tcp dport { 22 } ct state new meter napse_mgmtport_in_end0_meter { ip saddr timeout 30s limit rate over 20/second } counter drop"
            ),
            "must render the always-on mgmt-port new-conn cap on the WAN input chain; got:\n{}",
            g.content
        );
        // INPUT-only: there is no mgmt-port cap on the forward chain (customer/forward plane untouched).
        assert!(
            !g.content.contains("add rule inet hookprobe_resource_shed forward iifname \"end0\" tcp dport"),
            "the mgmt-port cap must never appear on the forward chain"
        );
    }

    /// The mgmt-port cap matches ONLY `ct state new` + the mgmt dport(s) — never established, and
    /// never all-ports. Established/authenticated SSH sessions are accepted before it (the
    /// `established,related accept` precedes it in the input chain) and are never torn down.
    #[test]
    fn mgmt_port_cap_matches_ct_new_and_mgmt_dport_only_never_established() {
        let g = render_conn_rate_cap(&ConnRateCapConfig::default());
        let mgmt_line = g
            .content
            .lines()
            .find(|l| l.contains("hookprobe-resource-shed-mgmtport-in-end0"))
            .expect("the mgmt-port cap rule must exist");
        assert!(mgmt_line.contains("ct state new"), "must key on ct state new");
        assert!(mgmt_line.contains("tcp dport { 22 }"), "must match only the mgmt dport");
        assert!(!mgmt_line.contains("established"), "the mgmt-port cap line must never match established");
        // Ordering: established,related accept precedes the mgmt cap, which precedes the shed drops —
        // so an ongoing session is accepted before the cap can ever see it.
        let est = g.content.find("ct state established,related counter accept").expect("established accept must exist");
        let mgmt = g.content.find("hookprobe-resource-shed-mgmtport-in-end0").expect("mgmt cap must exist");
        let blanket = g.content.find("hookprobe-resource-shed-connrate-in-end0").expect("layer-1 blanket must exist");
        assert!(est < mgmt, "established,related accept must precede the mgmt-port cap");
        assert!(mgmt < blanket, "the mgmt-port cap must precede the layer-1 blanket drop");
    }

    /// The cap applies to ALL sources: it is rendered BEFORE the mgmt-allowlist `accept`, so even a
    /// mgmt-subnet source's NEW-conn flood is rate-capped (it is a rate cap, not a block — its
    /// established session was already accepted above).
    #[test]
    fn mgmt_port_cap_precedes_the_mgmt_allowlist_accept_so_it_applies_to_all_sources() {
        let cfg = ConnRateCapConfig { protect_cidrs: vec!["10.200.0.0/28".into()], ..Default::default() };
        let g = render_conn_rate_cap(&cfg);
        let mgmt = g.content.find("hookprobe-resource-shed-mgmtport-in-end0").expect("mgmt cap must exist");
        let allow = g.content.find("hookprobe-resource-shed-mgmt-allowlist").expect("mgmt-allowlist accept must exist");
        assert!(mgmt < allow, "the mgmt-port cap must precede the mgmt-allowlist accept so it applies to ALL sources");
    }

    /// The mgmt port list and pps are POLICY, not magic literals: a custom list renders a multi-port
    /// set at the custom rate.
    #[test]
    fn mgmt_port_cap_is_policy_tunable_ports_and_rate() {
        let cfg = ConnRateCapConfig { mgmt_ports: vec![22, 2222], mgmt_conn_pps: 15, ..Default::default() };
        let g = render_conn_rate_cap(&cfg);
        assert!(g.content.contains("tcp dport { 22, 2222 } ct state new"), "custom mgmt ports must render");
        assert!(g.content.contains("limit rate over 15/second"), "custom mgmt pps must render");
    }

    /// Disabled cleanly: an empty port list OR a zero pps renders NO mgmt-port cap rule at all (and
    /// the rest of the resource-shed table is unaffected).
    #[test]
    fn mgmt_port_cap_disables_on_empty_ports_or_zero_pps() {
        for cfg in [
            ConnRateCapConfig { mgmt_ports: vec![], ..Default::default() },
            ConnRateCapConfig { mgmt_conn_pps: 0, ..Default::default() },
        ] {
            let g = render_conn_rate_cap(&cfg);
            assert!(!g.content.contains("mgmtport"), "no mgmt-port cap rule when disabled");
            // The rest of the table is still rendered (Layer 1 blanket cap still present).
            assert!(g.content.contains("hookprobe-resource-shed-connrate-in-end0"));
        }
    }

    /// Real-`nft` proof (network-namespace-gated, mirrors
    /// `l2_responder::render_storm_control_apply_twice_succeeds_line_by_line`): applying this
    /// exact rendered content TWICE, line-by-line, must never hit nft's "File exists ... overlaps
    /// an existing set" error — the concrete failure mode the add/delete/add idiom exists to avoid.
    /// This ALSO exercises the mgmt-port cap rule through the real `nft` parser (default cfg enables
    /// it), so a malformed mgmt rule would fail this test.
    #[test]
    fn render_conn_rate_cap_apply_twice_succeeds_line_by_line() {
        use std::process::Command;
        let probe = Command::new("unshare").args(["--net", "--map-root-user", "--", "true"]).status();
        if !matches!(probe, Ok(st) if st.success()) {
            eprintln!("skipping render_conn_rate_cap_apply_twice_succeeds_line_by_line: no unprivileged netns available");
            return;
        }
        if Command::new("nft").arg("--version").status().is_err() {
            eprintln!("skipping render_conn_rate_cap_apply_twice_succeeds_line_by_line: nft not installed");
            return;
        }
        let content = render_conn_rate_cap(&ConnRateCapConfig::default()).content;
        let script = format!(
            "apply() {{ echo \"$1\" | while IFS= read -r line; do \
               case \"$line\" in ''|'#'*) continue;; esac; \
               nft $line >/tmp/rshed_apply_err.$$ 2>&1 || {{ cat /tmp/rshed_apply_err.$$; exit 1; }}; \
               rm -f /tmp/rshed_apply_err.$$; \
             done; }}\n\
             CONTENT='{}'\n\
             echo \"$CONTENT\" | while IFS= read -r line; do case \"$line\" in ''|'#'*) continue;; esac; nft $line >/dev/null 2>&1; done\n\
             apply \"$CONTENT\"\n\
             echo ALL_GOOD",
            content.replace('\'', "'\\''")
        );
        let out = Command::new("unshare").args(["--net", "--map-root-user", "--", "sh", "-c", &script]).output().expect("exec unshare+sh");
        let stdout = String::from_utf8_lossy(&out.stdout);
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(
            out.status.success() && stdout.contains("ALL_GOOD"),
            "second apply must succeed with the real nft binary — stdout:\n{stdout}\nstderr:\n{stderr}"
        );
        assert!(!stdout.to_lowercase().contains("overlaps an existing set"));
    }

    #[test]
    fn render_shed_element_ops_adds_and_removes_from_the_shed_ips_set_only() {
        let diff = ShedDiff {
            to_add: vec![ShedEntry { ip: "203.0.113.9".into(), first_seen: 1.0, last_seen: 1.0, signal: "conntrack_saturation".into(), detail: "x".into() }],
            to_remove: vec![ShedEntry { ip: "198.51.100.4".into(), first_seen: 1.0, last_seen: 1.0, signal: "psi_cpu".into(), detail: "x".into() }],
            state: vec![],
        };
        let g = render_shed_element_ops(&diff, 60);
        assert!(g.content.contains("add element inet hookprobe_resource_shed shed_ips { 203.0.113.9 timeout 60s }"));
        assert!(g.content.contains("delete element inet hookprobe_resource_shed shed_ips { 198.51.100.4 }"));
        assert!(!g.content.contains("quarantine_lan_ips"), "must never touch the quarantine sets");
        assert!(!g.content.contains("quarantine_wan_ips"), "must never touch the quarantine sets");
    }

    #[test]
    fn render_shed_element_ops_is_a_noop_comment_when_nothing_changed() {
        let g = render_shed_element_ops(&ShedDiff::default(), 60);
        assert!(g.content.contains("no change"));
    }

    // ---- response record — proof it exists, is honest, and is distinct from every other action -

    #[test]
    fn render_shed_response_json_emits_a_first_class_evidence_record() {
        let e = ShedEntry {
            ip: "203.0.113.9".into(),
            first_seen: 1000.0,
            last_seen: 1000.0,
            signal: "conntrack_saturation".into(),
            detail: "conntrack table 85.0% full (85000/100000) >= 80.0% threshold; source has 500 concurrent flows (>= 200 floor)".into(),
        };
        let json = render_shed_response_json(&e, 50, 60, 1000.0, "end0");
        let v: serde_json::Value = serde_json::from_str(&json).expect("must be valid json");
        assert_eq!(v["action"], "resource_shed");
        assert_eq!(v["mechanism"], "nft");
        assert_eq!(v["src_ip"], "203.0.113.9");
        assert_eq!(v["signal"], "conntrack_saturation");
        assert_eq!(v["status"], "active");
        assert_eq!(v["ttl_secs"], 60);
        assert!(v["detail"].as_str().unwrap().contains("self-reverting"));
        assert!(v["detail"].as_str().unwrap().contains("never a durable/identity block"));
    }

    #[test]
    fn render_shed_revert_json_emits_the_revert_counterpart() {
        let e = ShedEntry { ip: "203.0.113.9".into(), first_seen: 1000.0, last_seen: 1000.0, signal: "psi_memory".into(), detail: "x".into() };
        let json = render_shed_revert_json(&e, 60, 2000.0, "end0");
        let v: serde_json::Value = serde_json::from_str(&json).expect("must be valid json");
        assert_eq!(v["action"], "resource_shed_revert");
        assert_eq!(v["status"], "reverted");
        assert_eq!(v["src_ip"], "203.0.113.9");
    }

    #[test]
    fn shed_response_records_never_carry_an_ip_or_mac_allowlist_bypass_concept() {
        // Anti-identity proof: nothing about ShedTrigger/ShedEntry/the response renderers ever
        // consults `ProtectPolicy`/`classify_source`/a MAC — the ONLY inputs are resource facts
        // (conntrack fill, PSI avg60, concurrent-flow counts). Compile-time-checked by construction
        // (these types have no such fields); this test documents the property at the value level.
        let e = ShedEntry {
            ip: "10.200.0.5".into(), // even the MANAGEMENT SUBNET — normally always-allowlisted —
            first_seen: 1.0,
            last_seen: 1.0,
            signal: "conntrack_saturation".into(),
            detail: "x".into(),
        };
        // is capped exactly the same way if it genuinely floods the table — no identity carve-out
        // exists anywhere in this section (contrast with `decide`'s explicit `protect_reason` gate).
        let json = render_shed_response_json(&e, 50, 60, 1.0, "end0");
        assert!(json.contains("10.200.0.5"));
    }
}
