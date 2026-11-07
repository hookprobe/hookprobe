//! Multi-WAN failover reconciler — turns the signed manifest's `network.uplinks`
//! (+ optional operator intent) into a GENERATED routing artifact. This is the
//! AEGIS pattern in miniature: the operator declares *what* they want (which
//! uplinks, in what order); the reconciler renders the config. Config is an
//! artifact, never the interface — the generated drop-ins carry a "do not edit"
//! banner and are reproduced from the manifest on every run.
//!
//! Mechanism: each uplink's DHCP/RA default route gets a distinct kernel **metric**
//! (lower = preferred). The kernel uses the lowest-metric reachable default route;
//! when a link drops, its route is withdrawn and traffic falls through to the next.
//! No daemon in the steady-state path — pure kernel routing.

use crate::types::ManifestUplink;

/// Operator intent over the WAN uplinks. Everything is optional — an empty intent
/// uses the manifest's default failover order verbatim.
#[derive(Debug, Clone, Default, serde::Deserialize)]
#[serde(default)]
pub struct WanIntent {
    /// Uplink names OR kinds the operator has disabled — e.g. `"cellular"` to keep
    /// a metered modem out of the rotation, or `"wlan_24ghz"` to pin one radio to AP.
    pub disable: Vec<String>,
    /// Explicit priority overrides keyed by uplink name (lower = preferred). Use to
    /// promote a normally-last uplink, e.g. make `wwan0` primary on a cellular site.
    pub prefer: Vec<PreferOverride>,
}

/// One `name: priority` override inside [`WanIntent::prefer`].
#[derive(Debug, Clone, serde::Deserialize)]
pub struct PreferOverride {
    pub name: String,
    pub priority: u32,
}

// ---------------------------------------------------------------------------
// Dual-stack WAN model — "be ready for ANY uplink type and ANY address family."
//
// MODULAR + EXTENSIBLE by design: `WanMode` is the addressing method (add variants for future
// dynamic-routing modes — BGP/ASN/RT/RD/MPLS/prefix-lists/route-maps — without touching the
// failover core); `WanIp` is the dual-stack v4/v6 config (DHCP, static, RA, DHCPv6, PREFIX
// DELEGATION, DUID pinning). The renderer matches `WanMode` exhaustively. Today we render the
// dhcp/static paths fully; pppoe/cellular are recognized modes that render a typed stub +
// hand-off note (pppd / ModemManager own those). The base is here for everything else to grow on.
// ---------------------------------------------------------------------------

/// How a WAN uplink obtains its address. Extensible — new transports/routing methods are new
/// variants; nothing else in the failover plan changes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum WanMode {
    /// DHCPv4 + IPv6 (RA + DHCPv6, incl. prefix delegation). Covers wired, Wi-Fi-station and
    /// modem-presented-as-IP links — the common case.
    #[default]
    Dhcp,
    /// Operator-set static v4 and/or v6 addresses + gateway.
    Static,
    /// PPPoE (fibre ISPs, e.g. Digi) — driven by `pppd`; rendered as a typed hand-off note.
    Pppoe,
    /// Cellular (wwan) — owned by ModemManager via `hookprobe-cellular.service`.
    Cellular,
}

/// Dual-stack IP configuration for one WAN uplink. Defaults are "ready for anything": DHCPv4 +
/// accept the ISP's IPv6 RA + request a DHCPv6 **prefix delegation** for the LAN. An ISP that
/// doesn't offer one of these simply leaves it unused — nothing breaks.
#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize)]
#[serde(default)]
pub struct WanIp {
    pub ipv4: bool,            // request/keep IPv4
    pub ipv6: bool,            // enable IPv6
    pub accept_ra: bool,       // accept the ISP Router Advertisement on the WAN
    pub dhcpv6_pd: bool,       // request a DHCPv6 prefix delegation (for the LAN)
    pub pd_hint: Option<u8>,   // requested PD length, e.g. 56 (→ /56 delegation)
    pub duid: Option<String>,  // DUID-LLT hex to pin (ISP re-issues the SAME prefix on reinstall)
    pub static_v4: Option<String>,  // static mode: CIDR (e.g. 203.0.113.2/24)
    pub gateway_v4: Option<String>,
    pub static_v6: Option<String>,  // static mode: CIDR (e.g. 2001:db8::2/64)
    pub gateway_v6: Option<String>,
}
impl Default for WanIp {
    fn default() -> Self {
        // Dual-stack, PD-requesting — the safe "ready for any ISP" baseline.
        WanIp {
            ipv4: true, ipv6: true, accept_ra: true, dhcpv6_pd: true,
            pd_hint: None, duid: None,
            static_v4: None, gateway_v4: None, static_v6: None, gateway_v6: None,
        }
    }
}

impl WanIntent {
    pub fn parse(yaml: &str) -> anyhow::Result<WanIntent> {
        Ok(serde_yaml::from_str(yaml)?)
    }
    fn is_disabled(&self, u: &ManifestUplink) -> bool {
        self.disable.iter().any(|d| d == &u.name || d == &u.kind)
    }
    fn override_for(&self, name: &str) -> Option<u32> {
        self.prefer.iter().find(|p| p.name == name).map(|p| p.priority)
    }
}

/// One default-route entry in the rendered plan (preferred first).
#[derive(Debug, Clone, PartialEq)]
pub struct WanRoute {
    pub iface: String,
    pub kind: String,
    /// The kernel route metric written to the generated config. Strictly increasing
    /// across the plan — no two uplinks share a metric (the kernel needs them unique).
    pub metric: u32,
}

/// The ordered failover plan derived from the manifest + intent.
#[derive(Debug, Clone, PartialEq)]
pub struct WanPlan {
    pub routes: Vec<WanRoute>,
}

impl WanPlan {
    /// The preferred (lowest-metric) uplink, if any survives the intent.
    pub fn primary(&self) -> Option<&WanRoute> {
        self.routes.first()
    }
    /// One human-readable line: `enp1s0(wired) > wlan_24ghz(wifi-station) > wwan0(cellular)`.
    pub fn summary(&self) -> String {
        if self.routes.is_empty() {
            return "no uplinks — device is OFFLINE (no WAN candidate)".to_string();
        }
        self.routes
            .iter()
            .map(|r| format!("{}({})", r.iface, r.kind))
            .collect::<Vec<_>>()
            .join(" > ")
    }
}

/// Build the failover plan: filter out disabled uplinks, apply priority overrides,
/// order by effective priority, then assign STRICTLY INCREASING unique metrics so
/// the kernel can hold every default route at once and fail through deterministically.
pub fn plan(uplinks: &[ManifestUplink], intent: &WanIntent) -> WanPlan {
    let mut routes: Vec<WanRoute> = uplinks
        .iter()
        .filter(|u| !intent.is_disabled(u))
        .map(|u| WanRoute {
            iface: u.name.clone(),
            kind: u.kind.clone(),
            metric: intent.override_for(&u.name).unwrap_or(u.priority),
        })
        .collect();

    // Deterministic order: by effective metric, then by name to break ties stably.
    routes.sort_by(|a, b| a.metric.cmp(&b.metric).then_with(|| a.iface.cmp(&b.iface)));

    // De-collide: the kernel rejects two default routes with the same metric, so
    // bump any non-increasing metric to one past its predecessor. Bands are kept
    // (10/20/30) while within-band siblings spread to 10,11,12,… deterministically.
    let mut last: Option<u32> = None;
    for r in &mut routes {
        if let Some(prev) = last {
            if r.metric <= prev {
                r.metric = prev + 1;
            }
        }
        last = Some(r.metric);
    }
    WanPlan { routes }
}

/// A generated config file: a path (relative to the networkd drop-in root) and its
/// full contents. The reconciler writes these; they are never hand-edited.
#[derive(Debug, Clone, PartialEq)]
pub struct GeneratedFile {
    pub path: String,
    pub content: String,
}

const BANNER: &str = "# GENERATED by hookprobe multi-WAN reconciler from the signed manifest.\n# Do NOT edit — changes are overwritten. Declare intent instead (wan-intent.yaml).\n";

/// 2026-07-07 LLMNR/mDNS hardening fix: `resolved.conf.d/60-hookprobe-hardening.conf` sets the
/// GLOBAL `LLMNR=no`/`MulticastDNS=no`, but `systemd.network(5)`'s own `LLMNR=`/`MulticastDNS=`
/// keys default to `yes`/`no` respectively PER LINK when a `.network` file doesn't set them — and
/// a per-link setting from networkd always takes precedence over resolved's global default for
/// that link (confirmed: `resolvectl status` showed `+LLMNR` per-interface despite the global
/// `-LLMNR`). Every WAN uplink `.network` unit this reconciler generates must therefore set both
/// explicitly, or the WAN uplink stays a live LLMNR responder regardless of the global hardening
/// drop-in. See `lan.rs`'s identical fix for the LAN-side `.network` unit.
const LLMNR_OFF: &str = "LLMNR=no\nMulticastDNS=no\n";

/// ADR 0034 D11 (W1): the WAN uplink is the interface `network-online.target` should actually
/// wait on — `systemd-networkd-wait-online` must gate boot readiness on a routable WAN, not the
/// AP/LAN-gateway radio (see `lan.rs`'s `RequiredForOnline=no` on that side). Explicit `routable`
/// (rather than leaving the per-link default, which networkd derives from whether any [Network]
/// address/DHCP directive is present and can vary by unit shape) makes the WAN-online re-resolve
/// oneshot (`hookprobe-regdomain-reresolve.service`, `After=network-online.target`) reliably fire
/// only once THIS uplink is actually up.
///
/// BUG-N1 (2026-07-17, live CM5 metal): this key is a **[Link]**-section option
/// (systemd.network(5)). It used to be emitted inside [Network], where networkd logged
/// `Unknown key 'RequiredForOnline' in section [Network], ignoring` and DROPPED it — so neither
/// this `routable` intent nor `lan.rs`'s `no` ever applied. It is now emitted as its own [Link]
/// section (see `LINK_SECTION_ROUTABLE`).
/// The complete `[Link]` section carrying `RequiredForOnline=routable`, placed between `[Match]`
/// and `[Network]` (systemd parses sections in any order; this reads naturally). ONE source of
/// truth — the key must never be emitted anywhere else, least of all inside `[Network]`.
const LINK_SECTION_ROUTABLE: &str = "[Link]\nRequiredForOnline=routable\n\n";

/// Render the plan as self-contained systemd-networkd `.network` units — one per uplink,
/// pinning the DHCP/RA default-route metric. A complete `[Match]`+`[Network]` unit (NOT a
/// `.network.d/` drop-in, which would be orphaned with no base unit to attach to). Path:
/// `50-hookprobe-wan-<iface>.network`. Note `RouteMetric` lives under `[DHCPv4]` and
/// `[IPv6AcceptRA]` only — there is no `[DHCPv6] RouteMetric` key in networkd.
///
/// Cellular (wwan) is owned by ModemManager (`hookprobe-cellular.service`), so we emit a
/// commented note for it rather than a conflicting DHCP unit; its failover metric is set
/// on the ModemManager/pppd side.
pub fn render_networkd(plan: &WanPlan) -> Vec<GeneratedFile> {
    // Default mode per uplink: cellular → Cellular (ModemManager owns it), everything else →
    // dhcp dual-stack with the "ready for anything" WanIp default (v4 + accept-RA + request PD).
    plan.routes
        .iter()
        .map(|r| {
            let mode = if r.kind == "cellular" { WanMode::Cellular } else { WanMode::Dhcp };
            let content = render_wan_unit(&r.iface, &r.kind, r.metric, mode, &WanIp::default());
            GeneratedFile { path: format!("50-hookprobe-wan-{}.network", r.iface), content }
        })
        .collect()
}

/// Render ONE WAN uplink's networkd unit for the given mode + dual-stack IP config. This is the
/// modular core: each `WanMode` renders its own shape; future modes add an arm here.
pub fn render_wan_unit(iface: &str, kind: &str, metric: u32, mode: WanMode, ip: &WanIp) -> String {
    match mode {
        WanMode::Cellular => format!(
            "{BANNER}# uplink: {iface} (cellular) — failover metric {metric} (lower = preferred).\n\
             # Managed by ModemManager via hookprobe-cellular.service; not a networkd unit.\n\
             # Set the cellular route metric to {metric} in cellular.yaml / the connection profile.\n"
        ),
        WanMode::Pppoe => format!(
            "{BANNER}# uplink: {iface} (pppoe, {kind}) — failover metric {metric}.\n\
             # PPPoE is driven by pppd (rp-pppoe), NOT networkd: hookprobe-pppoe@{iface}.service\n\
             # brings up ppp0 (public IPv4 + IPv6); DHCPv6-PD requests the LAN prefix. Creds live in\n\
             # /etc/hookprobe/wan-pppoe.conf (never in the image). See docs/wan-dualstack.md.\n"
        ),
        WanMode::Static => {
            let mut s = format!(
                "{BANNER}# uplink: {iface} ({kind}) — STATIC, failover metric {metric}\n\
                 [Match]\nName={iface}\n\n{LINK_SECTION_ROUTABLE}[Network]\n{LLMNR_OFF}"
            );
            if ip.ipv4 {
                if let Some(a) = &ip.static_v4 { s.push_str(&format!("Address={a}\n")); }
                if let Some(g) = &ip.gateway_v4 { s.push_str(&format!("Gateway={g}\n")); }
            }
            if ip.ipv6 {
                if let Some(a) = &ip.static_v6 { s.push_str(&format!("Address={a}\n")); }
                if let Some(g) = &ip.gateway_v6 { s.push_str(&format!("Gateway={g}\n")); }
                s.push_str(&format!("IPv6AcceptRA={}\n", yn(ip.accept_ra)));
            }
            s.push_str(&format!("\n[Route]\nGateway={}\nMetric={metric}\n",
                ip.gateway_v4.as_deref().unwrap_or("_dhcp4")));
            s
        }
        WanMode::Dhcp => {
            // Dual-stack DHCP: v4 + IPv6 (accept ISP RA) + optional DHCPv6 prefix delegation.
            let mut s = format!(
                "{BANNER}# uplink: {iface} ({kind}) — WAN failover metric {metric} (lower = preferred)\n\
                 [Match]\nName={iface}\n\n{LINK_SECTION_ROUTABLE}[Network]\n{LLMNR_OFF}"
            );
            // DHCP= selects families: ipv4 / ipv6 / yes (both) / no.
            let dhcp = match (ip.ipv4, ip.ipv6) { (true, true) => "yes", (true, false) => "ipv4", (false, true) => "ipv6", _ => "no" };
            s.push_str(&format!("DHCP={dhcp}\n"));
            if ip.ipv6 { s.push_str(&format!("IPv6AcceptRA={}\n", yn(ip.accept_ra))); }
            if ip.ipv4 {
                // ClientIdentifier=mac: present the interface MAC (DHCP option 61) as the client-id
                // instead of systemd's default RFC4361 DUID — which regenerates on every fresh flash
                // (new /etc/machine-id) and makes the DHCP server treat each reflash as a NEW client,
                // burning a fresh lease each time until a small pool (e.g. a /28) is exhausted →
                // "no address available" → the device gets IPv6 (SLAAC, poolless) but no IPv4. The MAC
                // is stable across reflashes, so the server reuses ONE lease for the life of the device.
                s.push_str(&format!("\n[DHCPv4]\nRouteMetric={metric}\nUseDNS=yes\nClientIdentifier=mac\n"));
            }
            if ip.ipv6 {
                if ip.dhcpv6_pd {
                    // Solicit DHCPv6 even when the RA's Managed flag is unset (many ISPs do
                    // PD-only) so we always request a delegation; the LAN unit claims a /64.
                    s.push_str("\n[DHCPv6]\nWithoutRA=solicit\nUseDelegatedPrefix=yes\n");
                    if let Some(h) = ip.pd_hint { s.push_str(&format!("PrefixDelegationHint=::/{h}\n")); }
                    if let Some(d) = &ip.duid { s.push_str(&format!("# DUID pinned for stable PD across reinstall\nDUIDType=link-layer\nDUIDRawData={d}\n")); }
                }
                s.push_str(&format!("\n[IPv6AcceptRA]\nRouteMetric={metric}\n"));
            }
            s
        }
    }
}

// NOTE: LAN-side IPv6 (ULA gateway + RA + DHCPv6-PD claim + advertised prefix) is rendered by the
// LAN reconciler (`lan::plan`) MERGED into the single `50-hookprobe-lan-<iface>.network`. It must not
// be a separate `55-*.network` matching the same interface — systemd-networkd applies only the first
// matching .network file per link, so a second file is silently ignored (LAN clients then get no IPv6).

fn yn(b: bool) -> &'static str { if b { "yes" } else { "no" } }

/// D16 fix (2026-07-07 enforcement-separation audit) log prefix shared by every RA-Guard renderer
/// below — a rogue (non-allowlisted, non-confirmed-rogue) RA is LOGGED, never silently dropped.
const RA_GUARD_LOG_PREFIX: &str = "hookprobe-rogue-ra: ";
const REDIRECT_GUARD_LOG_PREFIX: &str = "hookprobe-rogue-redirect: ";

/// Curated default OUI (24-bit vendor prefix) allowlist (S5, 2026-07-08). The Router Advertisements
/// of well-known consumer ROUTER / HomeKit-hub / Thread-border-router vendors are legitimate
/// downstream infrastructure. A source whose MAC OUI is on this list is auto-RECOGNIZED — accepted
/// WITHOUT the rogue-RA log, so an operator's own eero / UniFi / Apple TV / Nest / Netgear gear
/// doesn't generate false-positive rogue-RA noise. This is DISTINCT from:
///   - an UNKNOWN source → observe-first (logged + accepted, never dropped on first sight — D16), and
///   - a `confirmed_rogue` source → hard-dropped, which OUTRANKS this list (a confirmed-rogue device
///     is dropped even if its vendor OUI is allowlisted — the confirmed-rogue rules are emitted at a
///     higher priority / earlier in the chain than these recognized-OUI accepts).
///
/// Being on this list ONLY suppresses a LOG; it never grants an exemption from the confirmed-rogue
/// drop, and it never turns an observe posture into a drop. Data-driven + documented: extend by
/// adding a row (an operator can also pin a specific full MAC via `hub_allowlist`). OUIs are the
/// IEEE 24-bit assignment (first three octets), lowercase-hyphen-free colon form.
pub const DEFAULT_ROUTER_OUI_ALLOWLIST: &[(&str, &str)] = &[
    // Apple — HomePod / Apple TV act as HomeKit hubs + Thread border routers.
    ("a4:83:e7", "Apple"), ("f0:18:98", "Apple"), ("dc:a9:04", "Apple"), ("3c:22:fb", "Apple"),
    // Google / Nest — Nest Wifi / Nest Hub are Thread border routers.
    ("f4:f5:d8", "Google"), ("f4:f5:e8", "Google"), ("d8:6c:63", "Google"), ("1c:f2:9a", "Google"),
    // Amazon eero mesh routers / Amazon Echo (Thread border router).
    ("f8:bb:bf", "eero"), ("fc:65:de", "Amazon"), ("44:65:0d", "Amazon"),
    // Ubiquiti — UniFi / Dream Machine routers.
    ("24:a4:3c", "Ubiquiti"), ("fc:ec:da", "Ubiquiti"), ("68:d7:9a", "Ubiquiti"), ("78:8a:20", "Ubiquiti"),
    // Netgear routers.
    ("00:14:6c", "Netgear"), ("a0:40:a0", "Netgear"), ("9c:3d:cf", "Netgear"),
    // TP-Link routers.
    ("50:c7:bf", "TP-Link"), ("ac:84:c6", "TP-Link"), ("14:cc:20", "TP-Link"),
    // ASUS routers.
    ("2c:56:dc", "ASUSTek"), ("38:d5:47", "ASUSTek"),
];

/// Expand a stored 3-octet OUI (`"a4:83:e7"`) to nftables' masked-ether prefix form
/// (`"a4:83:e7:00:00:00/24"`) — a 24-bit prefix match on the source MAC.
fn oui_nft(oui: &str) -> String {
    format!("{oui}:00:00:00/24")
}

/// Expand a stored 3-octet OUI to OVS' masked-ether form (`"a4:83:e7:00:00:00/ff:ff:ff:00:00:00"`).
fn oui_ovs(oui: &str) -> String {
    format!("{oui}:00:00:00/ff:ff:ff:00:00:00")
}

/// Render RA-Guard for a genuinely BRIDGED LAN — the edge is the ONE legitimate IPv6 router.
/// SMARTER than a blanket drop, in TWO ways now:
///   - `hub_allowlist` MACs (known HomeKit/Thread-hub or downstream-router MACs — populated from
///     the SAME device-classifier `nac.rs`'s `default_policy` already tags `"router"` — see that
///     module) are permitted to send RAs outright, so their Thread-mesh Route Information Options
///     (or a customer's own downstream router) keep working.
///   - **D16 fix**: everyone else is NOT hard-dropped on first sight anymore. A non-allowlisted RA
///     is observed: LOGGED (so the operator/evidence-graph sees it and can promote a legitimate
///     hub into `hub_allowlist`, or confirm a rogue one) and ACCEPTED — a customer's own unlisted
///     downstream router or a HomeKit/Thread border router the operator hasn't yet classified must
///     never have its IPv6 silently cut on first sight. The HARD drop is reserved for
///     `confirmed_rogue` — MACs the operator (or a future stateful detector) has actually confirmed
///     hostile against the known-edge set — never a default-deny-everyone-else posture. RFC 6105.
///
/// # `bridge`-family requirement (2026-07 audit fix)
/// `bridge`-family nft hooks (`prerouting`/`input`/`forward`/…) only fire for frames actually
/// traversing an L2 bridge device — `bridge` here MUST be a genuine bridge (Linux `bridge`/OVS
/// port fabric), never a routed L3 interface. On a routed AP (e.g. the Pi's onboard `brcmfmac`
/// radio, which can never join a bridge — see `fabric::is_bridgeable`), these rules load, pass
/// `nft -c`, and sit inertly in the ruleset because bridge hooks are never invoked for routed
/// traffic — a silent RA-guard bypass. Callers MUST use [`render_ra_guard_netdev`] instead for a
/// routed interface; see `lan::LanIntent::bridged` for the selection.
///
/// `bridge` is the L2 LAN bridge name; `hub_allowlist` is the known-good HomeKit-hub/router MACs;
/// `confirmed_rogue` is MACs actually confirmed hostile (hard-dropped) — empty by default.
pub fn render_ra_guard_nft(bridge: &str, hub_allowlist: &[String], confirmed_rogue: &[String]) -> GeneratedFile {
    let mut s = String::from(BANNER);
    s.push_str(&format!(
        "# RA-Guard on {bridge} (bridge family — {bridge} is a genuine L2 bridge): the edge + allowlisted \
         hubs/routers may emit RAs; a NON-allowlisted RA is observed (logged + accepted) unless its \
         source is in confirmed_rogue, which is hard-dropped. Never a silent first-sight drop (D16).\n"
    ));
    s.push_str("nft add table bridge hookprobe_raguard 2>/dev/null || true\n");
    s.push_str(
        "nft 'add chain bridge hookprobe_raguard ingress { type filter hook prerouting priority -300; policy accept; }' 2>/dev/null || true\n"
    );
    // Allowlisted HomeKit-hub/router RAs (Thread border-router RIO, or a customer's own known
    // downstream router) pass outright — preserves Matter-over-Thread / nested routing.
    for mac in hub_allowlist {
        s.push_str(&format!(
            "nft add rule bridge hookprobe_raguard ingress iifname \"{bridge}\" ether saddr {mac} icmpv6 type 134 accept  # allowlisted hub/router RIO\n"
        ));
    }
    // D16 fix: hard-drop ONLY a source actually confirmed rogue — never every non-allowlisted MAC.
    for mac in confirmed_rogue {
        s.push_str(&format!(
            "nft add rule bridge hookprobe_raguard ingress iifname \"{bridge}\" ether saddr {mac} icmpv6 type 134 drop  # CONFIRMED rogue RA source\n"
        ));
        s.push_str(&format!(
            "nft add rule bridge hookprobe_raguard ingress iifname \"{bridge}\" ether saddr {mac} icmpv6 type 137 drop  # CONFIRMED rogue redirect source\n"
        ));
    }
    // S5: recognized default-OUI routers/hubs (eero/UniFi/Apple/Nest/…) are accepted WITHOUT the
    // rogue-RA log — no false-positive noise for the operator's own gear. Emitted AFTER the
    // confirmed_rogue drops above (so a confirmed-rogue device is dropped even if its OUI is
    // recognized) and BEFORE the observe-first log rule below (so a recognized source never reaches
    // the log). An UNKNOWN OUI falls through to observe-first.
    for (oui, vendor) in DEFAULT_ROUTER_OUI_ALLOWLIST {
        s.push_str(&format!(
            "nft add rule bridge hookprobe_raguard ingress iifname \"{bridge}\" ether saddr {} icmpv6 type 134 accept  # recognized {vendor} router/hub OUI (S5)\n",
            oui_nft(oui)
        ));
        s.push_str(&format!(
            "nft add rule bridge hookprobe_raguard ingress iifname \"{bridge}\" ether saddr {} icmpv6 type 137 accept  # recognized {vendor} router/hub OUI (S5)\n",
            oui_nft(oui)
        ));
    }
    // D16 fix: everyone else — observe, don't silently sever. Logged (evidence-graph-visible) and
    // ACCEPTED, never a hard drop on first sight (a legit downstream router/HomeKit hub the
    // operator hasn't yet classified must keep working).
    s.push_str(&format!(
        "nft add rule bridge hookprobe_raguard ingress iifname \"{bridge}\" icmpv6 type 134 log prefix \"{RA_GUARD_LOG_PREFIX}\" accept  # observe-first grace (D16) — not a confirmed-rogue source\n"
    ));
    s.push_str(&format!(
        "nft add rule bridge hookprobe_raguard ingress iifname \"{bridge}\" icmpv6 type 137 log prefix \"{REDIRECT_GUARD_LOG_PREFIX}\" accept  # observe-first grace (D16)\n"
    ));
    // Per-interface path (not a single static name) — a routed-AP RA-Guard file (see
    // `render_ra_guard_netdev`) can coexist with a bridged one (N100: wired bridge + separate AP
    // radio) without one silently clobbering the other on disk.
    GeneratedFile { path: format!("fabric/64-ra-guard.{bridge}.nft"), content: s }
}

/// Render RA-Guard for a ROUTED AP interface — the Pi-class shape where the AP radio (e.g.
/// `wlan0`) is an L3-routed interface carrying the gateway IP directly (never a bridge member;
/// `brcmfmac` cannot bridge AP unicast — see `fabric::is_bridgeable`). `bridge`-family nft hooks
/// never fire for routed traffic, so [`render_ra_guard_nft`]'s bridge-family rules would load,
/// pass `nft -c`, and never match a single packet on this topology (the 2026-07 on-metal audit
/// finding). This renders the SAME observe-first / confirmed-rogue-only-drop policy (D16) in the
/// **netdev** family, attached directly to the radio's `ingress` hook — the earliest point a frame
/// is seen on that device, firing regardless of any later L3 routing decision. RFC 6105.
///
/// `iface` is the routed AP/LAN interface (radio or single-port L3 LAN); `hub_allowlist` is the
/// known-good HomeKit-hub/router MACs permitted to emit RAs outright; `confirmed_rogue` is MACs
/// actually confirmed hostile (hard-dropped) — empty by default.
pub fn render_ra_guard_netdev(iface: &str, hub_allowlist: &[String], confirmed_rogue: &[String]) -> GeneratedFile {
    let mut s = String::from(BANNER);
    s.push_str(&format!(
        "# RA-Guard on {iface} (netdev family — {iface} is a ROUTED L3 interface, not a bridge port):\n\
         # bridge-family hooks never fire for routed traffic, so this attaches to the netdev ingress\n\
         # hook directly on the radio/interface instead. The edge + allowlisted hubs/routers may emit\n\
         # RAs outright; a NON-allowlisted RA is observed (logged + accepted) unless confirmed rogue\n\
         # (hard-dropped) — never a silent first-sight drop (D16).\n"
    ));
    s.push_str("nft add table netdev hookprobe_raguard 2>/dev/null || true\n");
    s.push_str(&format!(
        "nft 'add chain netdev hookprobe_raguard ingress {{ type filter hook ingress device \"{iface}\" priority -500; policy accept; }}' 2>/dev/null || true\n"
    ));
    // Allowlisted HomeKit-hub/router RAs (Thread border-router RIO) pass — preserves Matter-over-Thread.
    for mac in hub_allowlist {
        s.push_str(&format!(
            "nft add rule netdev hookprobe_raguard ingress ether saddr {mac} icmpv6 type 134 accept  # allowlisted hub/router RIO\n"
        ));
    }
    // D16 fix: hard-drop ONLY a source actually confirmed rogue.
    for mac in confirmed_rogue {
        s.push_str(&format!(
            "nft add rule netdev hookprobe_raguard ingress ether saddr {mac} icmpv6 type 134 drop  # CONFIRMED rogue RA source\n"
        ));
        s.push_str(&format!(
            "nft add rule netdev hookprobe_raguard ingress ether saddr {mac} icmpv6 type 137 drop  # CONFIRMED rogue redirect source\n"
        ));
    }
    // S5: recognized default-OUI routers/hubs accepted WITHOUT the rogue-RA log (no FP noise for
    // the operator's own gear). AFTER the confirmed_rogue drops (rogue outranks OUI) and BEFORE the
    // observe-first log rule (recognized never reaches the log). Unknown OUI → observe-first.
    for (oui, vendor) in DEFAULT_ROUTER_OUI_ALLOWLIST {
        s.push_str(&format!(
            "nft add rule netdev hookprobe_raguard ingress ether saddr {} icmpv6 type 134 accept  # recognized {vendor} router/hub OUI (S5)\n",
            oui_nft(oui)
        ));
        s.push_str(&format!(
            "nft add rule netdev hookprobe_raguard ingress ether saddr {} icmpv6 type 137 accept  # recognized {vendor} router/hub OUI (S5)\n",
            oui_nft(oui)
        ));
    }
    // D16 fix: everyone else — observe (log + accept), never a silent first-sight drop. No
    // iifname match needed — the chain is already device-scoped by the `ingress` hook's `device`.
    s.push_str(&format!(
        "nft add rule netdev hookprobe_raguard ingress icmpv6 type 134 log prefix \"{RA_GUARD_LOG_PREFIX}\" accept  # observe-first grace (D16)\n"
    ));
    s.push_str(&format!(
        "nft add rule netdev hookprobe_raguard ingress icmpv6 type 137 log prefix \"{REDIRECT_GUARD_LOG_PREFIX}\" accept  # observe-first grace (D16)\n"
    ));
    GeneratedFile { path: format!("fabric/64-ra-guard.{iface}.netdev.nft"), content: s }
}

/// Render RA-Guard as OVS OpenFlow (when the LAN runs on an OVS bridge) — the V1 approach, and the
/// SASE portable-edge DEFAULT plane (`lan::LanIntent::ovs` defaults `true`). Edge (bridge LOCAL
/// port) + allowlisted hub/router MACs may send RAs outright; a source actually `confirmed_rogue`
/// is hard-dropped; everyone else is observed — forwarded (`NORMAL`), never dropped on first sight
/// (D16). Honest note: `ovs-ofctl`'s flow-rule primitive has no per-packet `log` action equivalent
/// to nft's `log` statement without wiring a controller — observability for the OVS plane is each
/// flow's own hit counter (`ovs-ofctl dump-flows`) plus the SAME napse-dpi/l2guard alert pipeline
/// the nft renderers rely on for the structured finding; this renderer's job is solely to make sure
/// the PACKET action is never a silent first-sight drop.
pub fn render_ra_guard_ovs(bridge: &str, hub_allowlist: &[String], confirmed_rogue: &[String]) -> GeneratedFile {
    let mut s = String::from(BANNER);
    s.push_str(&format!(
        "# RA-Guard (OpenFlow) on {bridge} — the edge + allowlisted hubs/routers may send RAs outright; \
         a confirmed-rogue source is dropped; everyone else is observed (forwarded), never dropped on \
         first sight (D16).\n"
    ));
    s.push_str(&format!("ovs-ofctl add-flow {bridge} priority=900,icmp6,icmpv6_type=134,in_port=LOCAL,actions=NORMAL\n"));
    for (i, mac) in hub_allowlist.iter().enumerate() {
        s.push_str(&format!("ovs-ofctl add-flow {bridge} priority={},icmp6,icmpv6_type=134,dl_src={mac},actions=NORMAL\n", 901 + i));
    }
    // D16 fix: hard-drop ONLY a source actually confirmed rogue (highest priority — evaluated
    // before the observe-and-forward catch-all below).
    for (i, mac) in confirmed_rogue.iter().enumerate() {
        s.push_str(&format!("ovs-ofctl add-flow {bridge} priority={},icmp6,icmpv6_type=134,dl_src={mac},actions=drop\n", 950 + i));
        s.push_str(&format!("ovs-ofctl add-flow {bridge} priority={},icmp6,icmpv6_type=137,dl_src={mac},actions=drop\n", 950 + i));
    }
    // S5: recognized default-OUI routers/hubs forwarded as NORMAL at a priority ABOVE the
    // observe-first catch-all (899) but BELOW the confirmed_rogue drops (950) — so a confirmed-rogue
    // device is still dropped even if its OUI is recognized. (The OVS plane has no per-flow `log`
    // action; "recognized vs observe-first" here is expressed as distinct, higher-priority accept
    // flows — the structured finding still comes from the napse-dpi/l2guard pipeline.)
    for (oui, _vendor) in DEFAULT_ROUTER_OUI_ALLOWLIST {
        s.push_str(&format!("ovs-ofctl add-flow {bridge} priority=910,icmp6,icmpv6_type=134,dl_src={},actions=NORMAL\n", oui_ovs(oui)));
        s.push_str(&format!("ovs-ofctl add-flow {bridge} priority=910,icmp6,icmpv6_type=137,dl_src={},actions=NORMAL\n", oui_ovs(oui)));
    }
    // D16 fix: everyone else — observe (forward as NORMAL, never drop on first sight). A future
    // stateful detector promotes a source into confirmed_rogue once actually confirmed hostile.
    s.push_str(&format!("ovs-ofctl add-flow {bridge} priority=899,icmp6,icmpv6_type=134,actions=NORMAL\n"));
    s.push_str(&format!("ovs-ofctl add-flow {bridge} priority=899,icmp6,icmpv6_type=137,actions=NORMAL\n"));
    GeneratedFile { path: format!("fabric/64-ra-guard.{bridge}.of"), content: s }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn up(name: &str, kind: &str, priority: u32) -> ManifestUplink {
        ManifestUplink { name: name.into(), kind: kind.into(), priority }
    }

    /// The N100 shape: 4 wired + wifi-station + cellular. Default intent preserves
    /// failover order, wired primary, and assigns unique strictly-increasing metrics.
    #[test]
    fn plan_preserves_failover_order_with_unique_metrics() {
        let uplinks = vec![
            up("enp1s0", "wired", 10),
            up("enp2s0", "wired", 10),
            up("enp3s0", "wired", 10),
            up("enp4s0", "wired", 10),
            up("wlan_24ghz", "wifi-station", 20),
            up("wwan0", "cellular", 30),
        ];
        let p = plan(&uplinks, &WanIntent::default());
        assert_eq!(p.primary().unwrap().iface, "enp1s0");
        assert_eq!(p.routes.last().unwrap().kind, "cellular");
        // Metrics strictly increasing (no kernel collision) ...
        let metrics: Vec<u32> = p.routes.iter().map(|r| r.metric).collect();
        assert!(metrics.windows(2).all(|w| w[0] < w[1]), "metrics must be strictly increasing: {metrics:?}");
        // ... and bands preserved: the four wired collapse to 10,11,12,13.
        assert_eq!(&metrics[..4], &[10, 11, 12, 13]);
    }

    /// Intent `disable: [cellular]` keeps the metered modem out of the rotation.
    #[test]
    fn intent_disables_a_kind() {
        let uplinks = vec![up("enp1s0", "wired", 10), up("wwan0", "cellular", 30)];
        let intent = WanIntent { disable: vec!["cellular".into()], prefer: vec![] };
        let p = plan(&uplinks, &intent);
        assert_eq!(p.routes.len(), 1);
        assert_eq!(p.routes[0].iface, "enp1s0");
    }

    /// Intent `prefer: {wwan0: 5}` promotes the modem to primary on a cellular site.
    #[test]
    fn intent_prefers_an_uplink() {
        let uplinks = vec![up("enp1s0", "wired", 10), up("wwan0", "cellular", 30)];
        let intent = WanIntent {
            disable: vec![],
            prefer: vec![PreferOverride { name: "wwan0".into(), priority: 5 }],
        };
        let p = plan(&uplinks, &intent);
        assert_eq!(p.primary().unwrap().iface, "wwan0", "override must make wwan0 primary");
    }

    /// The generated drop-in is a real networkd metric override carrying the banner.
    #[test]
    fn render_emits_networkd_metric_dropins() {
        let p = plan(&[up("enp1s0", "wired", 10)], &WanIntent::default());
        let files = render_networkd(&p);
        assert_eq!(files.len(), 1);
        assert_eq!(files[0].path, "50-hookprobe-wan-enp1s0.network");
        assert!(files[0].content.contains("[Match]\nName=enp1s0"), "self-contained base unit, not an orphan drop-in");
        assert!(files[0].content.contains("[DHCPv4]\nRouteMetric=10"));
        // MAC as the DHCPv4 client-id — a stable identity across reflashes so a small ISP pool isn't
        // exhausted by a new DUID each fresh install (which strands the device on IPv6-only).
        assert!(files[0].content.contains("ClientIdentifier=mac"), "stable DHCPv4 client-id across reflashes");
        assert!(!files[0].content.contains("[DHCPv6]\nRouteMetric"), "no [DHCPv6] RouteMetric key in networkd");
        assert!(files[0].content.contains("Do NOT edit"), "must carry the generated banner");
    }

    /// No survivors → an explicit OFFLINE summary, never a silent empty plan.
    #[test]
    fn empty_plan_is_explicit_offline() {
        let uplinks = vec![up("wwan0", "cellular", 30)];
        let intent = WanIntent { disable: vec!["cellular".into()], prefer: vec![] };
        let p = plan(&uplinks, &intent);
        assert!(p.primary().is_none());
        assert!(p.summary().contains("OFFLINE"));
    }

    // ---- dual-stack WAN ----

    /// Default DHCP uplink is fully dual-stack + requests a prefix delegation for the LAN.
    #[test]
    fn dhcp_uplink_is_dualstack_with_pd() {
        let c = render_wan_unit("end0", "wired", 10, WanMode::Dhcp, &WanIp::default());
        assert!(c.contains("DHCP=yes"), "both families");
        assert!(c.contains("IPv6AcceptRA=yes"), "accept the ISP RA");
        assert!(c.contains("[DHCPv6]") && c.contains("WithoutRA=solicit"), "request DHCPv6/PD even on PD-only ISPs");
        assert!(c.contains("[DHCPv4]\nRouteMetric=10"));
    }

    /// IPv4-only and a pinned DUID both render correctly.
    #[test]
    fn dhcp_v4only_and_duid_pin() {
        let ip = WanIp { ipv6: false, ..WanIp::default() };
        assert!(render_wan_unit("e", "wired", 5, WanMode::Dhcp, &ip).contains("DHCP=ipv4"));
        let ip = WanIp { duid: Some("00:03:00:01:de:ad".into()), pd_hint: Some(56), ..WanIp::default() };
        let c = render_wan_unit("e", "wired", 5, WanMode::Dhcp, &ip);
        assert!(c.contains("PrefixDelegationHint=::/56") && c.contains("DUIDRawData=00:03:00:01:de:ad"));
    }

    /// PPPoE renders a typed hand-off note (pppd owns it), not a conflicting DHCP unit.
    #[test]
    fn pppoe_mode_is_handoff_note() {
        let c = render_wan_unit("enp1s0", "wired", 10, WanMode::Pppoe, &WanIp::default());
        assert!(c.contains("PPPoE") && c.contains("pppd") && !c.contains("DHCP=yes"));
    }

    /// Static mode renders the operator's addresses/gateways for both families.
    #[test]
    fn static_mode_renders_addresses() {
        let ip = WanIp {
            static_v4: Some("203.0.113.2/24".into()), gateway_v4: Some("203.0.113.1".into()),
            static_v6: Some("2001:db8::2/64".into()), gateway_v6: Some("2001:db8::1".into()),
            ..WanIp::default()
        };
        let c = render_wan_unit("end0", "wired", 10, WanMode::Static, &ip);
        assert!(c.contains("Address=203.0.113.2/24") && c.contains("Address=2001:db8::2/64"));
    }

    /// LLMNR/mDNS hardening fix: EVERY networkd-rendered WAN unit (both DHCP and Static — the
    /// only two modes with a `[Network]` section networkd actually reads) must explicitly turn
    /// LLMNR/MulticastDNS off, since `systemd.network(5)`'s own per-link default (`LLMNR=yes`)
    /// otherwise overrides `resolved.conf.d`'s global `-LLMNR` for that link — the WAN uplink is
    /// exactly the interface that must never be a live LLMNR responder.
    #[test]
    fn wan_units_explicitly_disable_llmnr_and_mdns_per_link() {
        let dhcp = render_wan_unit("end0", "wired", 10, WanMode::Dhcp, &WanIp::default());
        assert!(dhcp.contains("LLMNR=no") && dhcp.contains("MulticastDNS=no"), "got: {dhcp}");
        let ip = WanIp {
            static_v4: Some("203.0.113.2/24".into()), gateway_v4: Some("203.0.113.1".into()),
            ..WanIp::default()
        };
        let stat = render_wan_unit("end0", "wired", 10, WanMode::Static, &ip);
        assert!(stat.contains("LLMNR=no") && stat.contains("MulticastDNS=no"), "got: {stat}");
    }

    /// ADR 0034 D11 (W1): every real WAN `.network` unit (DHCP and Static — the two modes with a
    /// `[Network]` section) must carry `RequiredForOnline=routable`, so
    /// `systemd-networkd-wait-online` gates `network-online.target` on the WAN actually being up,
    /// not on the AP/LAN-gateway radio (which explicitly opts OUT — see `lan.rs`). This is what
    /// lets `hookprobe-regdomain-reresolve.service` (`After=network-online.target`) fire reliably.
    #[test]
    fn wan_units_require_online_routable_not_the_ap_radio() {
        let dhcp = render_wan_unit("end0", "wired", 10, WanMode::Dhcp, &WanIp::default());
        assert!(dhcp.contains("RequiredForOnline=routable"), "got: {dhcp}");
        let ip = WanIp {
            static_v4: Some("203.0.113.2/24".into()), gateway_v4: Some("203.0.113.1".into()),
            ..WanIp::default()
        };
        let stat = render_wan_unit("end0", "wired", 10, WanMode::Static, &ip);
        assert!(stat.contains("RequiredForOnline=routable"), "got: {stat}");
    }

    /// Return the INI section name a given key is emitted under, or None. Deliberately dumb: walks
    /// `[Section]` headers exactly the way systemd's own parser does.
    fn section_of_key(unit: &str, key: &str) -> Option<String> {
        let mut cur = String::new();
        for line in unit.lines() {
            let l = line.trim();
            if l.starts_with('[') && l.ends_with(']') {
                cur = l.trim_matches(['[', ']']).to_string();
            } else if l.split('=').next().map(str::trim) == Some(key) {
                return Some(cur.clone());
            }
        }
        None
    }

    /// BUG-N1 REGRESSION GUARD (2026-07-17, found on live CM5 metal). `RequiredForOnline=` is a
    /// **[Link]**-section key. Emitting it under [Network] made systemd-networkd log
    /// `Unknown key 'RequiredForOnline' in section [Network], ignoring` and silently DROP it — so
    /// the WAN never gated `network-online.target` and (worse, via `lan.rs`) the AP radio never
    /// stopped gating it: `wait-online` blocked on `wlan0: configuring`, timed out, FAILED, the
    /// target never activated, every boot came up `degraded`, and `After=network-online.target`
    /// units (e.g. `hookprobe-regdomain-reresolve.service`) never fired.
    ///
    /// The PRE-FIX tests asserted only `.contains("RequiredForOnline=routable")` — which is true
    /// from ANY section, so they passed against the broken output for months. THIS test asserts the
    /// SECTION, which is the property systemd actually cares about.
    #[test]
    fn required_for_online_is_in_the_link_section_not_network() {
        for (name, unit) in [
            ("dhcp", render_wan_unit("end0", "wired", 10, WanMode::Dhcp, &WanIp::default())),
            ("static", render_wan_unit("end0", "wired", 10, WanMode::Static, &WanIp {
                static_v4: Some("203.0.113.2/24".into()), gateway_v4: Some("203.0.113.1".into()),
                ..WanIp::default()
            })),
        ] {
            assert_eq!(
                section_of_key(&unit, "RequiredForOnline").as_deref(),
                Some("Link"),
                "{name} WAN unit must carry RequiredForOnline in [Link] (systemd ignores it in \
                 [Network] — BUG-N1). got:\n{unit}"
            );
        }
    }

    // LAN-side IPv6 is now rendered (merged into the single LAN .network) + tested by `lan::plan`
    // (see lan.rs `default_lan_is_a_full_router`). render_lan_ipv6 was removed — a separate
    // 55-*.network for the same interface is silently ignored by systemd-networkd.

    /// RA-Guard allowlists a known hub/router MAC outright; D16 fix: everyone ELSE (not
    /// allowlisted, not confirmed rogue) is observed — logged + ACCEPTED, never dropped.
    #[test]
    fn ra_guard_allows_hub_and_observes_everyone_else_never_drops_on_first_sight() {
        let hub = vec!["40:ed:cf:82:62:6b".to_string()];
        let nf = render_ra_guard_nft("hp-br0", &hub, &[]);
        assert!(nf.content.contains("ether saddr 40:ed:cf:82:62:6b icmpv6 type 134 accept"), "hub RIO allowlisted");
        assert!(!nf.content.contains("icmpv6 type 134 drop"), "D16: a non-allowlisted, non-confirmed-rogue RA must never be hard-dropped");
        assert!(!nf.content.contains("icmpv6 type 137 drop"), "D16: same for redirects");
        assert!(nf.content.contains("icmpv6 type 134 log prefix") && nf.content.contains("accept"), "observed (logged) and accepted");

        let of = render_ra_guard_ovs("hp-br0", &hub, &[]);
        assert!(of.content.contains("icmpv6_type=134,in_port=LOCAL,actions=NORMAL"), "edge RA allowed");
        assert!(of.content.contains("dl_src=40:ed:cf:82:62:6b") && of.content.contains("actions=NORMAL"), "hub allowlisted, forwarded");
        assert!(!of.content.contains("actions=drop"), "D16: OVS plane must not drop anyone by default either");
    }

    /// THE attack-still-caught proof: a source actually placed in `confirmed_rogue` IS hard-dropped
    /// — the HARD drop is reserved for a confirmed-hostile source, never the default for everyone.
    #[test]
    fn ra_guard_hard_drops_only_a_confirmed_rogue_source() {
        let rogue = vec!["de:ad:be:ef:00:99".to_string()];
        let nf = render_ra_guard_nft("hp-br0", &[], &rogue);
        assert!(nf.content.contains("ether saddr de:ad:be:ef:00:99 icmpv6 type 134 drop"), "confirmed-rogue RA source is dropped");
        assert!(nf.content.contains("ether saddr de:ad:be:ef:00:99 icmpv6 type 137 drop"), "confirmed-rogue redirect source is dropped");
        // The observe-everyone-else catch-all is still present and still accepts (never a global drop).
        assert!(nf.content.contains("log prefix") && nf.content.contains("accept"));

        let of = render_ra_guard_ovs("hp-br0", &[], &rogue);
        assert!(of.content.contains("dl_src=de:ad:be:ef:00:99") && of.content.contains("actions=drop"), "OVS plane also drops the confirmed-rogue source");
    }

    // --- S5: curated default OUI allowlist ----------------------------------------------------

    /// A legit downstream router whose MAC OUI is on the curated default list (here eero's
    /// `f8:bb:bf`) is auto-RECOGNIZED — accepted WITHOUT the rogue-RA log, no false-positive noise —
    /// across the bridge, netdev, and OVS planes. An UNKNOWN source still falls through to the
    /// observe-first log rule (which remains present for it).
    #[test]
    fn recognized_default_oui_router_is_accepted_without_a_rogue_ra_log() {
        // bridge nft
        let nf = render_ra_guard_nft("hp-br0", &[], &[]);
        assert!(
            nf.content.contains("ether saddr f8:bb:bf:00:00:00/24 icmpv6 type 134 accept")
                && nf.content.contains("recognized eero router/hub OUI (S5)"),
            "a recognized eero OUI must be accepted (no log): {}", nf.content
        );
        // the recognized accept for this OUI must come BEFORE the observe-first log catch-all, so a
        // recognized source never reaches the log line.
        let oui_at = nf.content.find("f8:bb:bf:00:00:00/24 icmpv6 type 134 accept").unwrap();
        let log_at = nf.content.find("type 134 log prefix").unwrap();
        assert!(oui_at < log_at, "recognized-OUI accept must precede the observe-first log rule");
        // unknown sources still have the observe-first log rule available.
        assert!(nf.content.contains("type 134 log prefix"), "observe-first still present for unknown OUIs");

        // netdev
        let nd = render_ra_guard_netdev("wlan0", &[], &[]);
        assert!(nd.content.contains("ether saddr a4:83:e7:00:00:00/24 icmpv6 type 134 accept"), "Apple OUI recognized on netdev");

        // OVS — recognized OUI forwarded NORMAL at priority ABOVE observe-first (899), BELOW rogue (950).
        let of = render_ra_guard_ovs("hp-br0", &[], &[]);
        assert!(of.content.contains("priority=910,icmp6,icmpv6_type=134,dl_src=f8:bb:bf:00:00:00/ff:ff:ff:00:00:00,actions=NORMAL"), "recognized OUI forwarded on OVS: {}", of.content);
        assert!(!of.content.contains("actions=drop"), "no confirmed rogue → no drop anywhere");
    }

    /// THE attack-still-caught proof for S5: a device whose OUI IS on the recognized list but whose
    /// FULL MAC is `confirmed_rogue` is STILL hard-dropped — the confirmed-rogue drop OUTRANKS the
    /// recognized-OUI accept (emitted earlier in the chain / at higher OVS priority). Recognition
    /// only suppresses a log; it never exempts a confirmed-hostile source from the drop.
    #[test]
    fn confirmed_rogue_outranks_a_recognized_oui() {
        // f8:bb:bf is eero's recognized OUI, but THIS specific device is confirmed rogue.
        let rogue = vec!["f8:bb:bf:de:ad:01".to_string()];
        let nf = render_ra_guard_nft("hp-br0", &[], &rogue);
        let drop_at = nf.content.find("ether saddr f8:bb:bf:de:ad:01 icmpv6 type 134 drop")
            .expect("confirmed-rogue drop must be present even though its OUI is recognized");
        let oui_accept_at = nf.content.find("f8:bb:bf:00:00:00/24 icmpv6 type 134 accept")
            .expect("the recognized-OUI accept is still emitted");
        assert!(drop_at < oui_accept_at, "the confirmed-rogue drop must be evaluated BEFORE the recognized-OUI accept");

        // OVS: rogue drop priority (950) must outrank recognized-OUI accept (910).
        let of = render_ra_guard_ovs("hp-br0", &[], &rogue);
        assert!(of.content.contains("priority=950,icmp6,icmpv6_type=134,dl_src=f8:bb:bf:de:ad:01,actions=drop"), "OVS rogue drop at 950");
        assert!(of.content.contains("priority=910,"), "recognized-OUI accept at 910 (below the 950 rogue drop)");
    }

    /// The bridge-family path must never be static — two RA-Guard files (one bridged, one
    /// routed-AP) can coexist without clobbering each other on disk (the latent collision the
    /// 2026-07 audit also flagged: both used to write the same `fabric/64-ra-guard.nft`).
    #[test]
    fn nft_bridge_path_is_per_bridge() {
        let nf = render_ra_guard_nft("hp-br0", &[], &[]);
        assert_eq!(nf.path, "fabric/64-ra-guard.hp-br0.nft");
    }

    /// Routed-AP RA-Guard (2026-07 on-metal audit fix): `bridge`-family nft hooks never fire for
    /// an L3-routed radio, so the routed path MUST render in the `netdev` family, attached to the
    /// interface's own `ingress` hook — never `table bridge`. D16: still observe-first here too.
    #[test]
    fn ra_guard_netdev_targets_routed_interface_not_bridge_family() {
        let hub = vec!["40:ed:cf:82:62:6b".to_string()];
        let nf = render_ra_guard_netdev("wlan0", &hub, &[]);
        assert!(nf.content.contains("table netdev hookprobe_raguard"), "must be netdev family, not bridge");
        assert!(!nf.content.contains("table bridge"), "must NOT use the inert bridge family for a routed iface");
        assert!(nf.content.contains("hook ingress device \"wlan0\""), "attached to the radio's own ingress hook");
        assert!(nf.content.contains("ether saddr 40:ed:cf:82:62:6b icmpv6 type 134 accept"), "hub RIO allowlisted");
        assert!(!nf.content.contains("icmpv6 type 134 drop"), "D16: no first-sight drop on the routed-AP path either");
        assert!(nf.content.contains("log prefix") && nf.content.contains("accept"));
        assert_eq!(nf.path, "fabric/64-ra-guard.wlan0.netdev.nft");
    }

    /// A downstream router / HomeKit-Thread border router the operator has NOT yet allowlisted
    /// must still get its RAs through (D16's core legit-passes requirement) — on both nft planes.
    #[test]
    fn ra_guard_never_cuts_ipv6_for_an_unlisted_legit_downstream_router() {
        let unlisted_but_legit = "aa:bb:cc:11:22:33";
        for content in [
            render_ra_guard_nft("hp-br0", &[], &[]).content,
            render_ra_guard_netdev("wlan0", &[], &[]).content,
        ] {
            // Nothing in the generated ruleset can match-and-drop this MAC specifically (it's in
            // neither hub_allowlist nor confirmed_rogue) — the only icmpv6-type-134/137 verdict
            // reachable for it is the observe-and-accept catch-all.
            assert!(!content.contains(&format!("ether saddr {unlisted_but_legit}")), "must not appear in any per-mac rule");
            assert!(content.contains("accept"), "the catch-all must still end in accept, not drop");
        }
    }
}
