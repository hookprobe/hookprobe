//! Network-fabric reconciler — the modular L2/L3 data-plane model that scales from a
//! 4-port edge LAN (the N100) to a cloud WAN of segmented VRFs. Same intent→artifact
//! loop as [`crate::multi_wan`] / [`crate::wifi_cfg`]: the operator declares segments
//! and policy; this renders the bring-up plan. The shell oneshot becomes a thin executor.
//!
//! ## Two COMPLEMENTARY planes (not either/or)
//!
//! - **L2 switching (OVS)** — only meaningful with **≥2 LAN carriers** (ports/AP radios
//!   to switch *between*). One OVS bridge (`hp-br0`): LAN ports + AP radios as members,
//!   the WAN uplink left OFF the bridge, per-segment VLAN internal ports, MAC→segment
//!   binding as OpenFlow `mod_vlan_vid` flows, out-of-band IDS mirror. Mirrors V1's
//!   `FTS` bridge + `fortress` OpenFlow rules + `tc mirred` taps. Where OVS isn't a
//!   granted capability, falls back to a **kernel Linux bridge** (the V1 `FTS` pattern).
//! - **L3 routing separation (VRF)** — separates routes from the global table into a
//!   VRF + table per segment (public / mssp / ids), cross-segment dropped by nftables.
//!   Useful even on a **single NIC** (the cloud / super-PoP "firewall for a separate
//!   vnet"). Mirrors V1 `setup-vrf.sh`.
//!
//! A device can run BOTH at once (**hybrid**): switch its LAN at L2 *and* separate
//! routing domains at L3. The plane(s) are chosen from **topology + capability**, with
//! intent as the override — `kind: auto` is the default and does the right thing per box.
//!
//! MAC binding (V1 `mac_vlan.json` + OUI classifier → OVS flow): a device's MAC is
//! pinned to a segment by a single `priority=200,dl_src=<mac>,actions=mod_vlan_vid:<vlan>`
//! flow — static lookup, one flow per device, no per-packet re-classification.

use crate::multi_wan::GeneratedFile;
use crate::types::{InterfaceRole, InterfaceType, ManifestInterface};

/// Which fabric plane(s) to render. `Auto` (default) derives them from topology +
/// capability; the others force a choice.
#[derive(Debug, Clone, Copy, PartialEq, serde::Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub enum FabricKind {
    /// Topology-driven: ≥2 LAN carriers → L2 switching; else, with segments → L3 VRF.
    #[default]
    Auto,
    /// Force the L2 switching plane (OVS, or Linux-bridge fallback).
    OvsBridge,
    /// Force the L3 routing-separation plane (VRF + nftables).
    VrfSegmented,
    /// Both planes at once — switch the LAN AND separate routing domains.
    Hybrid,
}

/// One segment: a VLAN (L2 switching) and/or a VRF routing domain (L3 separation).
#[derive(Debug, Clone, serde::Deserialize)]
pub struct Segment {
    pub name: String,
    /// VLAN id (L2) — also derives the VRF routing-table id (L3, `100 + vlan`).
    pub vlan: u32,
    /// "fail-open" (default) | "fail-closed" (drops unknown traffic when control is
    /// down → OVS `fail_mode=secure` / a default-drop flow / no-egress VRF rule).
    #[serde(default)]
    pub fail: Option<String>,
}
impl Segment {
    fn fail_closed(&self) -> bool {
        self.fail.as_deref() == Some("fail-closed")
    }
}

/// Static device→segment binding. `via` selects the mechanism:
///   - `mac` (default): an OpenFlow `dl_src` flow. **Only reliable for stable-OUI IoT**
///     (cameras, bulbs). Randomizing clients (phones/laptops) defeat it — see below.
///   - `dot1x`: 802.1X identity → VLAN via RADIUS `Tunnel-Private-Group-Id`. The DURABLE
///     path — survives MAC randomization because the identity is a credential, not a MAC.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct MacBinding {
    pub mac: String,
    pub segment: String,
    #[serde(default)]
    pub via: Option<String>,
}
impl MacBinding {
    fn is_dot1x(&self) -> bool {
        self.via.as_deref() == Some("dot1x")
    }
}

/// MAC address class. The **locally-administered** bit (0x02 in the first octet) is set
/// by MAC randomization — such a MAC is NOT a stable identity and has no real OUI, so
/// binding a segment to it is unstable (it churns every time the client rotates its MAC).
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum MacClass {
    /// Universally-administered (burned-in OUI) — stable; OUI classification is valid.
    Universal,
    /// Locally-administered (randomized / spoofed) — ephemeral; treat as not-identity.
    LocallyAdministered,
}

/// Classify a MAC by its locally-administered bit. Unparseable → assume randomized
/// (the safe default: don't trust it as identity).
pub fn mac_class(mac: &str) -> MacClass {
    match mac.split([':', '-']).next().and_then(|h| u8::from_str_radix(h, 16).ok()) {
        Some(b) if b & 0x02 != 0 => MacClass::LocallyAdministered,
        Some(_) => MacClass::Universal,
        None => MacClass::LocallyAdministered,
    }
}

/// Operator fabric intent. Everything optional → safe defaults (auto plane, one
/// `hp-br0`, fail-open, no segments) so an un-configured edge still bridges its LAN.
#[derive(Debug, Clone, Default, serde::Deserialize)]
#[serde(default)]
pub struct FabricIntent {
    pub kind: FabricKind,
    pub bridge: Option<String>,
    pub segments: Vec<Segment>,
    pub mac_bindings: Vec<MacBinding>,
    /// Mirror out-of-band traffic to an IDS tap (e.g. `dummy-mirror`) — the NAPSE
    /// capture path. `None` = no mirror.
    pub mirror_to: Option<String>,
    /// Where un-bound / randomized-MAC devices land — an onboarding/guest segment,
    /// NOT silent quarantine. The catch-all instead of dumping unknowns to drop.
    pub unknown_segment: Option<String>,
}
impl FabricIntent {
    pub fn parse(yaml: &str) -> anyhow::Result<FabricIntent> {
        Ok(serde_yaml::from_str(yaml)?)
    }
    fn bridge(&self) -> &str {
        self.bridge.as_deref().unwrap_or("hp-br0")
    }
}

/// What an interface becomes in the L2 plane.
#[derive(Debug, Clone, PartialEq)]
pub enum PortAction {
    BridgeMember,
    WanUplink,
    MirrorOnly,
}

#[derive(Debug, Clone, PartialEq)]
pub struct FabricPort {
    pub iface: String,
    pub action: PortAction,
}

/// Read-only topology summary the plane selection is derived from.
#[derive(Debug, Clone, PartialEq)]
pub struct FabricTopology {
    /// LAN L2 carriers (ethernet + AP radios) EXCLUDING the WAN uplink.
    pub lan_carriers: Vec<String>,
    /// True when there are ≥2 LAN carriers — i.e. there is something to *switch*.
    pub can_switch: bool,
}

/// Inspect the manifest interfaces to decide whether L2 switching is even meaningful.
pub fn analyze(interfaces: &[ManifestInterface], wan_uplink: Option<&str>) -> FabricTopology {
    let lan_carriers: Vec<String> = interfaces
        .iter()
        .filter(|i| is_bridgeable(i))
        .filter(|i| Some(i.name.as_str()) != wan_uplink)
        .map(|i| i.name.clone())
        .collect();
    FabricTopology { can_switch: lan_carriers.len() >= 2, lan_carriers }
}

/// The L2 backend actually used.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum L2Backend {
    /// Open vSwitch — full OpenFlow (MAC binding, mirrors). Needs the `openvswitch` cap.
    Ovs,
    /// Kernel Linux bridge fallback (the V1 `FTS` pattern) when OVS isn't granted —
    /// switches + VLAN-filters, but no OpenFlow MAC-binding flows.
    LinuxBridge,
}

/// The L2 switching plane.
#[derive(Debug, Clone)]
pub struct L2Plane {
    pub backend: L2Backend,
    pub bridge: String,
    pub ports: Vec<FabricPort>,
    pub segments: Vec<Segment>,
    pub mac_bindings: Vec<MacBinding>,
    pub mirror_to: Option<String>,
    pub unknown_segment: Option<String>,
    pub any_fail_closed: bool,
}

/// The L3 routing-separation plane.
#[derive(Debug, Clone)]
pub struct VrfPlane {
    pub segments: Vec<Segment>,
}

/// The resolved fabric plan — zero, one, or both planes, plus why they were chosen.
#[derive(Debug, Clone)]
pub struct FabricPlan {
    pub resolved: String,
    pub why: String,
    pub topology: FabricTopology,
    pub l2: Option<L2Plane>,
    pub vrf: Option<VrfPlane>,
}

impl FabricPlan {
    pub fn summary(&self) -> String {
        let mut parts = Vec::new();
        if let Some(l2) = &self.l2 {
            let members = l2.ports.iter().filter(|p| p.action == PortAction::BridgeMember).count();
            let backend = match l2.backend {
                L2Backend::Ovs => "OVS",
                L2Backend::LinuxBridge => "Linux-bridge",
            };
            parts.push(format!(
                "L2 {backend} {} · {members} member(s) · {} segment(s){}",
                l2.bridge, l2.segments.len(),
                if l2.any_fail_closed { " · fail-closed" } else { "" }
            ));
        }
        if let Some(vrf) = &self.vrf {
            parts.push(format!("L3 VRF · {} routing domain(s)", vrf.segments.len()));
        }
        if parts.is_empty() {
            return "no fabric (no LAN to switch, no routing segments declared)".to_string();
        }
        parts.join("  +  ")
    }
}

/// Resolve the plan from interfaces + the WAN uplink + intent + the `openvswitch`
/// capability grant. `wan_uplink` is kept OFF the L2 bridge (the route out).
pub fn plan(
    interfaces: &[ManifestInterface],
    wan_uplink: Option<&str>,
    intent: &FabricIntent,
    ovs_granted: bool,
) -> FabricPlan {
    let topo = analyze(interfaces, wan_uplink);
    let has_segments = !intent.segments.is_empty();

    // Decide which plane(s) apply.
    let (use_l2, use_vrf, why): (bool, bool, String) = match intent.kind {
        FabricKind::OvsBridge => (true, false, "forced L2 switching".into()),
        FabricKind::VrfSegmented => (false, true, "forced L3 routing separation".into()),
        FabricKind::Hybrid => (true, true, "forced hybrid (switch + route-separate)".into()),
        FabricKind::Auto => {
            let has_wifi = interfaces.iter().any(|i| matches!(i.iface_type, InterfaceType::Wifi));
            if topo.lan_carriers.is_empty() && has_wifi {
                // Wi-Fi-only edge (Pi 4): no bridgeable wired LAN, but there IS an AP radio, which
                // lan.rs ROUTES (gateway on the radio + nft NAC). Emit NO VRF here: its forward chain
                // is `policy drop`, which would black-hole the routed AP's egress (wlanN→WAN is in no
                // VRF segment). (A NIC-only box with 0 carriers — e.g. a cloud VM — still VRFs below,
                // for logical tenant separation, since it has no routed AP to strand.)
                //
                // NOTE (2026-07-10 CM5 fix): this zero-carrier guard does NOT fire when the box has a
                // SECOND wired LAN port (CM5: `end0` WAN + `enP1p1s0` LAN carrier + onboard `wlan0`
                // AP): `lan_carriers` is then non-empty, so with segments this falls through to the
                // `single carrier + segments → VRF` branch below — the VRF is emitted AND the routed
                // AP still runs. That coexistence is LEGITIMATE (L3 microseg for the wired segments +
                // a routed Wi-Fi bubble), so the black-hole is fixed NOT by suppressing the VRF but by
                // `render_vrf_north_south` (wired in aegis::reconcile_network), which grants the
                // routed AP/LAN device explicit north-south egress through the global forward hook.
                (false, false, "no bridgeable LAN carriers + Wi-Fi AP → routed (lan.rs)".into())
            } else if topo.can_switch {
                (true, false, format!("{} LAN carriers → L2 switching", topo.lan_carriers.len()))
            } else if has_segments {
                (false, true, "single carrier + segments → L3 VRF routing separation".into())
            } else {
                // One carrier, no segments: still bridge it (so AP radios/one LAN port
                // attach), but there is nothing to switch between.
                (true, false, "single carrier → flat bridge (nothing to switch yet)".into())
            }
        }
    };

    let l2 = use_l2.then(|| {
        let backend = if ovs_granted { L2Backend::Ovs } else { L2Backend::LinuxBridge };
        L2Plane {
            backend,
            bridge: intent.bridge().to_string(),
            ports: interfaces.iter().filter_map(|i| classify_port(i, wan_uplink)).collect(),
            segments: intent.segments.clone(),
            mac_bindings: intent.mac_bindings.clone(),
            mirror_to: intent.mirror_to.clone(),
            unknown_segment: intent.unknown_segment.clone(),
            any_fail_closed: intent.segments.iter().any(|s| s.fail_closed()),
        }
    });
    let vrf = use_vrf.then(|| VrfPlane { segments: intent.segments.clone() });

    let resolved = match (&l2, &vrf) {
        (Some(l2), Some(_)) => format!("hybrid ({}+vrf)", l2_backend_str(l2.backend)),
        (Some(l2), None) => l2_backend_str(l2.backend).to_string(),
        (None, Some(_)) => "vrf-segmented".to_string(),
        (None, None) => "none".to_string(),
    };
    FabricPlan { resolved, why, topology: topo, l2, vrf }
}

fn l2_backend_str(b: L2Backend) -> &'static str {
    match b {
        L2Backend::Ovs => "ovs-bridge",
        L2Backend::LinuxBridge => "linux-bridge",
    }
}

/// An interface can be an OVS BRIDGE member iff it's a wired port. Wi-Fi is always ROUTED, never
/// bridged: the Pi's onboard `brcmfmac` literally cannot bridge AP unicast (driver limitation), and
/// we can't yet prove from the manifest that a given radio is a bridgeable fixed AP vs a USB station
/// — so `lan.rs` routes AP radios and stations stay uplinks. (Bridging PCIe `ath` radios for
/// dual-band single-SSID band-steering is a future optimization, gated on driver/bus in the
/// manifest.) Cellular is never an L2 member either.
pub fn is_bridgeable(i: &ManifestInterface) -> bool {
    matches!(i.iface_type, InterfaceType::Ethernet)
}

/// The WAN uplink stays off the bridge; LAN ethernet ports become members; out-of-band ifaces are
/// mirror-only. Wi-Fi (routed AP / station uplink) + cellular are never L2 members.
fn classify_port(i: &ManifestInterface, wan_uplink: Option<&str>) -> Option<FabricPort> {
    if !is_bridgeable(i) {
        return None;
    }
    if Some(i.name.as_str()) == wan_uplink {
        return Some(FabricPort { iface: i.name.clone(), action: PortAction::WanUplink });
    }
    let action = if i.role == InterfaceRole::OutOfBand {
        PortAction::MirrorOnly
    } else {
        PortAction::BridgeMember
    };
    Some(FabricPort { iface: i.name.clone(), action })
}

const BANNER: &str = "# GENERATED by hookprobe fabric reconciler from the signed manifest.\n# Do NOT edit — changes are overwritten. Declare intent instead (fabric-intent.yaml).\n";

/// Render the bring-up artifact(s) for whichever plane(s) the plan resolved to.
pub fn render(plan: &FabricPlan) -> Vec<GeneratedFile> {
    let mut out = Vec::new();
    if let Some(l2) = &plan.l2 {
        match l2.backend {
            L2Backend::Ovs => {
                out.push(render_ovs(l2));
                out.push(render_flows(l2));
                if let Some(radius) = render_radius(l2) {
                    out.push(radius);
                }
            }
            L2Backend::LinuxBridge => out.push(render_linux_bridge(l2)),
        }
    }
    if let Some(vrf) = &plan.vrf {
        out.push(render_vrf(vrf));
    }
    out
}

fn render_ovs(l2: &L2Plane) -> GeneratedFile {
    let br = &l2.bridge;
    let mut s = String::from(BANNER);
    s.push_str(&format!("# L2 OVS switching: bridge {br}\n"));
    s.push_str(&format!("ovs-vsctl --may-exist add-br {br}\n"));
    let fm = if l2.any_fail_closed { "secure" } else { "standalone" };
    s.push_str(&format!("ovs-vsctl set bridge {br} fail_mode={fm}\n"));
    for p in &l2.ports {
        match p.action {
            PortAction::BridgeMember => s.push_str(&format!("ovs-vsctl --may-exist add-port {br} {}\n", p.iface)),
            PortAction::WanUplink => s.push_str(&format!("# {} = WAN uplink — left OFF the bridge (route to internet)\n", p.iface)),
            PortAction::MirrorOnly => s.push_str(&mirror_lines(&p.iface, l2.mirror_to.as_deref())),
        }
    }
    for seg in &l2.segments {
        s.push_str(&format!(
            "ovs-vsctl --may-exist add-port {br} seg-{name} -- set interface seg-{name} type=internal -- set port seg-{name} tag={vlan}\n",
            name = seg.name, vlan = seg.vlan
        ));
    }
    GeneratedFile { path: format!("fabric/60-{br}.ovs.plan"), content: s }
}

fn render_flows(l2: &L2Plane) -> GeneratedFile {
    let br = &l2.bridge;
    let seg_vlan = |name: &str| l2.segments.iter().find(|s| s.name == name).map(|s| s.vlan);
    let mut s = String::from(BANNER);
    s.push_str(&format!("# OpenFlow flows for {br} (apply: ovs-ofctl add-flows {br} -)\n"));
    s.push_str("# Pipeline: table 0 = classify + MAC→VLAN bind, then RESUBMIT to table 1 (the\n");
    s.push_str("# policy pipeline) so EVERY device — bound or not — traverses microsegmentation\n");
    s.push_str("# (a binding no longer terminates with `normal` and skip ct). table 1 default is\n");
    s.push_str("# allow-through; the microseg artifact, when applied, overrides it with a conntrack\n");
    s.push_str("# dispatch at higher priority.\n");
    s.push_str("table=0,priority=100,arp,actions=normal\n");
    // MAC-based bindings — ONLY for `via: mac` (802.1X bindings are RADIUS, see .radius).
    // Set the VLAN, then fall into the policy pipeline instead of forwarding directly.
    for b in l2.mac_bindings.iter().filter(|b| !b.is_dot1x()) {
        match seg_vlan(&b.segment) {
            None => s.push_str(&format!("# WARNING: mac {} → unknown segment '{}' (no flow)\n", b.mac, b.segment)),
            Some(vlan) => {
                if mac_class(&b.mac) == MacClass::LocallyAdministered {
                    s.push_str(&format!(
                        "# UNSTABLE: {} is locally-administered (randomized) — this dl_src flow\n\
                         #   will go stale when the client rotates its MAC. Use via:dot1x for durable identity.\n",
                        b.mac
                    ));
                }
                s.push_str(&format!("table=0,priority=200,dl_src={mac},actions=mod_vlan_vid:{vlan},resubmit(,1)\n", mac = b.mac));
            }
        }
    }
    // Default classification for everything else (the catch-all). Un-bound devices are
    // assigned the onboarding VLAN (if configured) then enter the policy pipeline.
    match l2.unknown_segment.as_deref() {
        Some(name) if seg_vlan(name).is_some() => s.push_str(&format!(
            "table=0,priority=50,ip,actions=mod_vlan_vid:{},resubmit(,1)  # unbound → onboarding '{name}'\n",
            seg_vlan(name).unwrap()
        )),
        Some(name) => {
            s.push_str(&format!(
                "# WARNING: unknown_segment '{name}' is not a declared segment — unbound devices keep their VLAN (check the spelling).\n"
            ));
            s.push_str("table=0,priority=50,ip,actions=resubmit(,1)\n");
        }
        None => s.push_str("table=0,priority=50,ip,actions=resubmit(,1)\n"),
    }
    // Table 1 default policy: allow. The microseg conntrack program (when applied) installs
    // a higher-priority ip→ct dispatch here, so isolation applies to bound devices too.
    s.push_str("table=1,priority=0,actions=normal\n");
    GeneratedFile { path: format!("fabric/61-{br}.flows.of"), content: s }
}

/// Emit the durable identity path: 802.1X bindings → RADIUS `Tunnel-Private-Group-Id`
/// (the V1 FreeRADIUS pattern). Identity is a credential, so it survives MAC rotation.
/// Returns `None` when no `via: dot1x` bindings exist.
fn render_radius(l2: &L2Plane) -> Option<GeneratedFile> {
    let dot1x: Vec<&MacBinding> = l2.mac_bindings.iter().filter(|b| b.is_dot1x()).collect();
    if dot1x.is_empty() {
        return None;
    }
    let mut s = String::from(BANNER);
    s.push_str("# 802.1X identity → VLAN (FreeRADIUS authorize). DURABLE: keyed on the\n");
    s.push_str("# authenticated identity, not the MAC — survives MAC randomization.\n");
    for b in dot1x {
        match l2.segments.iter().find(|s| s.name == b.segment) {
            Some(seg) => s.push_str(&format!(
                "{id} Cleartext-Password := \"<provision-per-device>\"\n    \
                 Tunnel-Type = VLAN,\n    Tunnel-Medium-Type = IEEE-802,\n    \
                 Tunnel-Private-Group-Id = {vlan}\n\n",
                id = b.mac, vlan = seg.vlan
            )),
            None => s.push_str(&format!("# WARNING: identity {} → unknown segment '{}'\n", b.mac, b.segment)),
        }
    }
    Some(GeneratedFile { path: format!("fabric/62-{}.radius", l2.bridge), content: s })
}

fn render_linux_bridge(l2: &L2Plane) -> GeneratedFile {
    let br = &l2.bridge;
    let mut s = String::from(BANNER);
    s.push_str(&format!("# L2 Linux-bridge switching (OVS capability NOT granted): {br}\n"));
    s.push_str(&format!("ip link add name {br} type bridge 2>/dev/null || true\n"));
    if !l2.segments.is_empty() {
        s.push_str(&format!("ip link set {br} type bridge vlan_filtering 1\n"));
    }
    s.push_str(&format!("ip link set {br} up\n"));
    for p in &l2.ports {
        match p.action {
            PortAction::BridgeMember => s.push_str(&format!("ip link set {} master {br} && ip link set {} up\n", p.iface, p.iface)),
            PortAction::WanUplink => s.push_str(&format!("# {} = WAN uplink — left OFF the bridge (route to internet)\n", p.iface)),
            PortAction::MirrorOnly => s.push_str(&mirror_lines(&p.iface, l2.mirror_to.as_deref())),
        }
    }
    if !l2.mac_bindings.is_empty() {
        s.push_str("# NOTE: MAC→segment binding needs OpenFlow (OVS) — not enforced on a Linux bridge.\n");
        s.push_str("#       Grant the 'openvswitch' capability for per-MAC VLAN flows.\n");
    }
    GeneratedFile { path: format!("fabric/60-{br}.linux-bridge.plan"), content: s }
}

/// VRF master interface name for a segment, clamped to the kernel's IFNAMSIZ (15 chars).
/// `vrf-hp-` is 7 chars, leaving 8 for the segment; longer names are truncated so
/// `ip link add` cannot fail with "numerical result out of range".
fn vrf_ifname(seg: &str) -> String {
    let max_seg = 15 - "vrf-hp-".len(); // 8
    let s: String = seg.chars().take(max_seg).collect();
    format!("vrf-hp-{s}")
}

fn render_vrf(vrf: &VrfPlane) -> GeneratedFile {
    let mut s = String::from(BANNER);
    s.push_str("# L3 routing separation: one kernel VRF + table per segment. The forward chain\n");
    s.push_str("# default-DROPs, then ACCEPTs same-segment + established + north-south egress;\n");
    s.push_str("# cross-segment (vrf-A → vrf-B) has no accept rule, so it is dropped + logged.\n");
    s.push_str("nft add table inet hookprobe_vrf 2>/dev/null || true\n");
    s.push_str("nft 'add chain inet hookprobe_vrf forward { type filter hook forward priority 0; policy drop; }' 2>/dev/null || true\n");
    // Return traffic always passes (stateful), so fail-open segments actually forward.
    s.push_str("nft add rule inet hookprobe_vrf forward ct state established,related accept\n");
    for seg in &vrf.segments {
        let table = 100 + seg.vlan;
        let dev = vrf_ifname(&seg.name);
        s.push_str(&format!(
            "ip link add {dev} type vrf table {table} 2>/dev/null || true\nip link set {dev} up\n"
        ));
        if seg.fail_closed() {
            // No egress at all (e.g. the IDS capture VRF): drop everything from it.
            s.push_str(&format!("nft add rule inet hookprobe_vrf forward iifname \"{dev}\" drop  # fail-closed: no egress\n"));
        } else {
            // Fail-open: allow NEW egress to anywhere EXCEPT other hookprobe VRFs (so the
            // segment reaches the internet but cannot route laterally into another segment).
            s.push_str(&format!("nft add rule inet hookprobe_vrf forward iifname \"{dev}\" oifname != \"vrf-hp-*\" accept  # north-south egress (not cross-segment)\n"));
            // Log + drop explicit cross-segment attempts for visibility.
            // 2026-07-07 fix (arm64 VM first boot): this `.plan` is EXECUTED LINE-BY-LINE AS SHELL
            // (`runsh` evals each `nft …`), so the shell strips the nft-level quotes around the log
            // prefix — a prefix containing `[`/`]` then reaches nft's own lexer UNQUOTED as a bare
            // `[` → "syntax error, unexpected '['" → the whole rule fails to load, silently DROPPING
            // the cross-segment east-west DROP enforcement. Use a bracket-free, space-free prefix
            // token (`vrf-xseg-<seg>`) that survives shell-word-splitting and nft's bare-string lexer.
            s.push_str(&format!("nft add rule inet hookprobe_vrf forward iifname \"{dev}\" oifname \"vrf-hp-*\" log prefix \"vrf-xseg-{} \" drop\n", seg.name));
        }
    }
    GeneratedFile { path: "fabric/60-vrf.plan".to_string(), content: s }
}

/// Grant routed (non-VRF) LAN/AP interfaces north-south egress through the GLOBAL
/// `inet hookprobe_vrf forward` hook — which is `policy drop` for the WHOLE forward path,
/// not merely the `vrf-hp-*` devices. Confirmed live on a CM5 (2026-07-10): a phone
/// associates to the routed onboard AP (`wlan0`, gateway 10.66.0.1/24), gets a lease, but
/// has NO internet — its NEW `iifname wlan0 oifname <wan>` packet is not a `vrf-hp-*`
/// interface, matches none of [`render_vrf`]'s per-segment accepts, and hits `policy drop`.
/// (Return traffic already passes via the chain's `ct state established,related accept`, so
/// only the NEW outbound direction is stranded — which is exactly why a lease is handed out
/// but nothing routes.)
///
/// This is emitted whenever the VRF plane coexists with a routed AP / bridged LAN (the
/// hybrid edge: L3 microsegmentation for the wired segments AND a routed Wi-Fi bubble). It
/// idempotently (re-)asserts the table + chain + the stateful-return accept, so it is correct
/// whether applied before OR after the VRF plane's own `60-vrf.plan` (both use
/// `add … 2>/dev/null || true` / append-only `add rule`, so re-assertion is a no-op).
///
/// Dual-stack by construction: it is `table inet` and matches ONLY on `iifname`/`oifname`
/// (no `ip`/`ip6 saddr`), so ONE rule per device grants BOTH the IPv4 LAN (10.66.0.0/24) and
/// the IPv6 ULA (`fd00:6606:1::/64`) north-south egress. Cross-segment isolation is NOT
/// weakened: the accept is scoped to `oifname "<wan>"`, so a routed device still cannot route
/// laterally INTO a `vrf-hp-*` segment (that path has no accept rule and stays dropped +
/// logged by [`render_vrf`]'s per-segment `oifname "vrf-hp-*" … drop`). When the WAN is not
/// yet resolved (offline first boot), it falls back to `oifname != "vrf-hp-*"` — reach
/// anything except another segment — so the routed AP is never black-holed by boot timing.
pub fn render_vrf_north_south(devs: &[String], wan: Option<&str>) -> GeneratedFile {
    let mut s = String::from(BANNER);
    s.push_str(
        "# Routed north-south egress grant: the `inet hookprobe_vrf forward` hook is a GLOBAL\n\
         # `policy drop` (see 60-vrf.plan), so a routed AP/LAN device (NOT a vrf-hp-* interface)\n\
         # would be black-holed on its NEW wlanN/br0 -> WAN packet. Grant it explicitly here.\n\
         # inet family + iifname/oifname-only match = ONE rule covers BOTH IPv4 and IPv6.\n",
    );
    // Idempotently (re-)assert the table + chain + stateful return, so this file is self-contained
    // and order-independent vs 60-vrf.plan (a duplicate append is harmless).
    s.push_str("nft add table inet hookprobe_vrf 2>/dev/null || true\n");
    s.push_str("nft 'add chain inet hookprobe_vrf forward { type filter hook forward priority 0; policy drop; }' 2>/dev/null || true\n");
    s.push_str("nft add rule inet hookprobe_vrf forward ct state established,related accept\n");
    for dev in devs {
        match wan {
            Some(wan) => s.push_str(&format!(
                "nft add rule inet hookprobe_vrf forward iifname \"{dev}\" oifname \"{wan}\" accept  # routed AP/LAN north-south egress (not cross-segment)\n"
            )),
            None => s.push_str(&format!(
                "nft add rule inet hookprobe_vrf forward iifname \"{dev}\" oifname != \"vrf-hp-*\" accept  # routed AP/LAN north-south egress (WAN unresolved — not cross-segment)\n"
            )),
        }
    }
    GeneratedFile { path: "fabric/63-vrf-north-south.plan".to_string(), content: s }
}

fn mirror_lines(iface: &str, dst: Option<&str>) -> String {
    match dst {
        Some(dst) => format!(
            "# {iface} out-of-band → tc mirred tap to {dst} (no inline forwarding)\n\
             tc qdisc add dev {iface} clsact 2>/dev/null || true\n\
             tc filter add dev {iface} ingress matchall action mirred egress mirror dev {dst}\n\
             tc filter add dev {iface} egress  matchall action mirred egress mirror dev {dst}\n"
        ),
        None => format!("# {iface} out-of-band → mirror (no IDS tap configured)\n"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn iface(name: &str, ty: InterfaceType, role: InterfaceRole) -> ManifestInterface {
        ManifestInterface {
            name: name.into(), mac: None, iface_type: ty, supported_modes: vec![],
            role, fail_mode: None, state: "up".into(), xdp_native: false,
        }
    }
    fn eth(name: &str) -> ManifestInterface { iface(name, InterfaceType::Ethernet, InterfaceRole::Unassigned) }
    /// A Wi-Fi radio — always ROUTED (never an OVS bridge member), whatever its role.
    fn ap(name: &str) -> ManifestInterface { iface(name, InterfaceType::Wifi, InterfaceRole::Unassigned) }
    fn n100() -> Vec<ManifestInterface> {
        vec![
            eth("enp1s0"), eth("enp2s0"), eth("enp3s0"), eth("enp4s0"),
            ap("wlan_24ghz"), ap("wlan_5ghz"),
            iface("wwan0", InterfaceType::Lte, InterfaceRole::Unassigned),
        ]
    }

    /// AUTO on the N100 (≥2 LAN carriers) → L2 OVS switching; WAN uplink off-bridge;
    /// AP radios bridged; cellular excluded.
    #[test]
    fn auto_selects_ovs_on_multiport_lan() {
        let p = plan(&n100(), Some("enp1s0"), &FabricIntent::default(), /* ovs_granted */ true);
        assert_eq!(p.resolved, "ovs-bridge");
        assert!(p.topology.can_switch);
        let l2 = p.l2.as_ref().unwrap();
        assert_eq!(l2.backend, L2Backend::Ovs);
        let act = |n: &str| l2.ports.iter().find(|x| x.iface == n).map(|x| x.action.clone());
        assert_eq!(act("enp1s0"), Some(PortAction::WanUplink));
        assert_eq!(act("enp2s0"), Some(PortAction::BridgeMember)); // wired LAN port bridges
        assert_eq!(act("wlan_5ghz"), None); // Wi-Fi is ROUTED, never a bridge member
        assert_eq!(act("wwan0"), None);
        assert!(p.vrf.is_none());
    }

    /// AUTO on a single-NIC cloud VM WITH segments → L3 VRF routing separation, no L2.
    #[test]
    fn auto_selects_vrf_on_single_nic_with_segments() {
        let intent = FabricIntent {
            segments: vec![
                Segment { name: "public".into(), vlan: 1, fail: None },
                Segment { name: "ids".into(), vlan: 3, fail: Some("fail-closed".into()) },
            ],
            ..Default::default()
        };
        let p = plan(&[eth("enp0s6")], Some("enp0s6"), &intent, true);
        assert_eq!(p.resolved, "vrf-segmented");
        assert!(!p.topology.can_switch);
        assert!(p.l2.is_none() && p.vrf.is_some());
        let vrf = render(&p).into_iter().next().unwrap();
        assert!(vrf.content.contains("vrf-hp-public type vrf table 101"));
        assert!(vrf.content.contains("vrf-hp-ids\" drop"));
    }

    /// HYBRID: switch the LAN at L2 AND separate routing domains at L3 — both planes
    /// render (a multi-port edge that is also a multi-tenant router).
    #[test]
    fn hybrid_renders_both_planes() {
        let intent = FabricIntent {
            kind: FabricKind::Hybrid,
            segments: vec![Segment { name: "tenantA".into(), vlan: 10, fail: None }],
            ..Default::default()
        };
        let p = plan(&n100(), Some("enp1s0"), &intent, true);
        assert_eq!(p.resolved, "hybrid (ovs-bridge+vrf)");
        assert!(p.l2.is_some() && p.vrf.is_some());
        let files = render(&p);
        assert!(files.iter().any(|f| f.path.contains(".ovs.plan")));
        assert!(files.iter().any(|f| f.path.contains("vrf.plan")));
    }

    /// Capability fallback: OVS not granted but the LAN can switch → kernel Linux
    /// bridge (V1 FTS pattern). MAC binding is flagged as unavailable without OpenFlow.
    #[test]
    fn linux_bridge_fallback_when_ovs_not_granted() {
        let intent = FabricIntent {
            segments: vec![Segment { name: "iot".into(), vlan: 20, fail: None }],
            mac_bindings: vec![MacBinding { mac: "9c:8e:cd:dd:ee:ff".into(), segment: "iot".into(), via: None }],
            ..Default::default()
        };
        let p = plan(&n100(), Some("enp1s0"), &intent, /* ovs_granted */ false);
        assert_eq!(p.resolved, "linux-bridge");
        let lb = render(&p).into_iter().find(|f| f.path.contains("linux-bridge")).unwrap();
        assert!(lb.content.contains("type bridge"));
        assert!(lb.content.contains("ip link set enp2s0 master hp-br0"));
        assert!(lb.content.contains("vlan_filtering 1"));
        assert!(lb.content.contains("MAC→segment binding needs OpenFlow"), "honest about the limitation");
    }

    /// MAC binding → a single OpenFlow flow; fail-closed → secure + default drop.
    #[test]
    fn mac_binding_and_fail_closed_flows() {
        let intent = FabricIntent {
            kind: FabricKind::OvsBridge,
            segments: vec![Segment { name: "cameras".into(), vlan: 30, fail: Some("fail-closed".into()) }],
            mac_bindings: vec![MacBinding { mac: "9c:8e:cd:11:22:33".into(), segment: "cameras".into(), via: None }],
            ..Default::default()
        };
        let p = plan(&n100(), Some("enp1s0"), &intent, true);
        let files = render(&p);
        let ovs = files.iter().find(|f| f.path.contains(".ovs.plan")).unwrap();
        assert!(ovs.content.contains("fail_mode=secure"));
        assert!(ovs.content.contains("seg-cameras") && ovs.content.contains("tag=30"));
        let flows = files.iter().find(|f| f.path.contains(".flows.of")).unwrap();
        // The binding sets the VLAN then RESUBMITS into the policy pipeline (table 1) — it no
        // longer terminates with `normal`, so a bound device still traverses microseg.
        assert!(flows.content.contains("dl_src=9c:8e:cd:11:22:33,actions=mod_vlan_vid:30,resubmit(,1)"));
        assert!(flows.content.contains("table=1,priority=0,actions=normal"), "table-1 default policy");
        // fail_mode=secure (set on the bridge in the .ovs.plan) is the fail-closed control now.
        assert!(ovs.content.contains("fail_mode=secure"));
    }

    /// MAC randomization is detected: a locally-administered MAC binding is FLAGGED as
    /// unstable (it churns), and the durable path (dot1x) is recommended.
    #[test]
    fn randomized_mac_binding_is_flagged_unstable() {
        // 0x02 in the first octet = locally-administered (randomized).
        assert_eq!(mac_class("02:11:22:33:44:55"), MacClass::LocallyAdministered);
        assert_eq!(mac_class("9c:8e:cd:11:22:33"), MacClass::Universal);
        let intent = FabricIntent {
            kind: FabricKind::OvsBridge,
            segments: vec![Segment { name: "guest".into(), vlan: 50, fail: None }],
            mac_bindings: vec![MacBinding { mac: "02:11:22:33:44:55".into(), segment: "guest".into(), via: None }],
            ..Default::default()
        };
        let flows = render(&plan(&n100(), Some("enp1s0"), &intent, true))
            .into_iter().find(|f| f.path.contains(".flows.of")).unwrap();
        assert!(flows.content.contains("UNSTABLE") && flows.content.contains("via:dot1x"));
    }

    /// 802.1X binding → RADIUS Tunnel-Private-Group-Id (durable), NOT an OpenFlow flow.
    #[test]
    fn dot1x_binding_emits_radius_not_flow() {
        let intent = FabricIntent {
            kind: FabricKind::OvsBridge,
            segments: vec![Segment { name: "corp".into(), vlan: 100, fail: None }],
            mac_bindings: vec![MacBinding { mac: "alice@corp".into(), segment: "corp".into(), via: Some("dot1x".into()) }],
            ..Default::default()
        };
        let files = render(&plan(&n100(), Some("enp1s0"), &intent, true));
        let radius = files.iter().find(|f| f.path.contains(".radius")).expect("radius artifact");
        assert!(radius.content.contains("Tunnel-Private-Group-Id = 100"));
        // The identity must NOT appear as a brittle dl_src flow.
        let flows = files.iter().find(|f| f.path.contains(".flows.of")).unwrap();
        assert!(!flows.content.contains("alice@corp"), "802.1X identity is RADIUS, not a flow");
    }

    /// Unknown / randomized devices land in an onboarding segment (catch-all), never a
    /// silent drop — even when a fail-closed segment exists elsewhere.
    #[test]
    fn unknown_devices_land_in_onboarding_segment() {
        let intent = FabricIntent {
            kind: FabricKind::OvsBridge,
            segments: vec![
                Segment { name: "onboarding".into(), vlan: 99, fail: None },
                Segment { name: "secure".into(), vlan: 5, fail: Some("fail-closed".into()) },
            ],
            unknown_segment: Some("onboarding".into()),
            ..Default::default()
        };
        let flows = render(&plan(&n100(), Some("enp1s0"), &intent, true))
            .into_iter().find(|f| f.path.contains(".flows.of")).unwrap();
        // Unbound devices are assigned the onboarding VLAN by the default table-0 classifier
        // (which actually fires now — it used to be shadowed), then enter the policy pipeline.
        assert!(flows.content.contains("priority=50,ip,actions=mod_vlan_vid:99,resubmit(,1)"));
        assert!(!flows.content.contains("actions=drop"), "unknowns onboard, never dropped");
    }

    /// The CM5 fix: a routed AP/LAN device gets an explicit north-south egress accept in the VRF
    /// forward chain (dual-stack via inet + iifname/oifname-only), while the per-segment
    /// cross-segment DROP is untouched. Scoped to `oifname "<wan>"` so it is NOT a lateral grant.
    #[test]
    fn vrf_north_south_grants_routed_egress_without_weakening_isolation() {
        let f = render_vrf_north_south(&["wlan0".to_string()], Some("end0"));
        assert_eq!(f.path, "fabric/63-vrf-north-south.plan");
        // The exact rule the operator proved live on the CM5.
        assert!(
            f.content.contains("iifname \"wlan0\" oifname \"end0\" accept"),
            "routed AP wlan0→WAN end0 north-south egress must be granted: {}", f.content
        );
        // Self-contained: idempotent table/chain (re-)assertion + stateful return, so it is safe
        // regardless of apply order vs 60-vrf.plan.
        assert!(f.content.contains("add table inet hookprobe_vrf"));
        assert!(f.content.contains("hook forward priority 0; policy drop"));
        assert!(f.content.contains("ct state established,related accept"));
        // It must NOT open a lateral cross-segment path (no accept toward another vrf-hp-*).
        assert!(!f.content.contains("oifname \"vrf-hp-"), "north-south grant must never target a vrf-hp-* oif");
    }

    /// Offline first boot (WAN unresolved): the routed AP is STILL not stranded — it may reach
    /// anything except another segment (`oifname != "vrf-hp-*"`), never a black-hole by boot timing.
    #[test]
    fn vrf_north_south_falls_back_to_non_segment_egress_when_wan_unresolved() {
        let f = render_vrf_north_south(&["wlan0".to_string()], None);
        assert!(f.content.contains("iifname \"wlan0\" oifname != \"vrf-hp-*\" accept"), "got: {}", f.content);
    }

    /// Integration: the VRF plan + the north-south grant PARSE and APPLY with the real `nft` binary
    /// (in an unprivileged netns), and the resulting ruleset shows BOTH the routed-AP egress accept
    /// AND the cross-segment DROP still enforced. Skips cleanly where no netns/nft is available.
    #[test]
    fn vrf_plan_plus_north_south_apply_with_real_nft_and_preserve_isolation() {
        use std::process::Command;
        if !matches!(
            Command::new("unshare").args(["--net", "--map-root-user", "--", "true"]).status(),
            Ok(st) if st.success()
        ) {
            eprintln!("skipping vrf_plan_plus_north_south_apply_with_real_nft: no unprivileged netns");
            return;
        }
        if Command::new("nft").arg("--version").status().is_err() {
            eprintln!("skipping vrf_plan_plus_north_south_apply_with_real_nft: nft not installed");
            return;
        }
        // A single-carrier-with-segments VRF plane + the routed-AP north-south grant.
        let vrf = render_vrf(&VrfPlane {
            segments: vec![
                Segment { name: "trusted".into(), vlan: 10, fail: None },
                Segment { name: "cameras".into(), vlan: 30, fail: Some("fail-closed".into()) },
            ],
        });
        let ns = render_vrf_north_south(&["wlan0".to_string()], Some("end0"));
        // Apply ONLY the `nft …` lines (skip `ip link …` — vrf devices need the kernel module; nft
        // matches iifname/oifname by NAME so the devices need not exist to parse/apply). Each line is
        // eval'd via `sh -c` so the quoted `add chain … { … }` and `|| true` survive, exactly like
        // the runsh executor. Then dump the ruleset for assertions.
        let mut script = String::from("set -e\n");
        for line in vrf.content.lines().chain(ns.content.lines()) {
            let l = line.trim();
            if l.starts_with("nft ") {
                script.push_str(l);
                script.push('\n');
            }
        }
        script.push_str("nft list ruleset\n");
        let out = Command::new("unshare")
            .args(["--net", "--map-root-user", "--", "sh", "-c", &script])
            .output()
            .expect("exec unshare+sh");
        let stdout = String::from_utf8_lossy(&out.stdout);
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(out.status.success(), "vrf + north-south nft must apply cleanly — stderr:\n{stderr}");
        // (a) routed AP egress present.
        assert!(
            stdout.contains("iifname \"wlan0\" oifname \"end0\" accept"),
            "routed AP north-south egress missing from live ruleset:\n{stdout}"
        );
        // (b) cross-segment DROP still enforced for the real segment.
        assert!(
            stdout.contains("iifname \"vrf-hp-trusted\" oifname \"vrf-hp-*\"") && stdout.contains("drop"),
            "cross-segment drop must remain in the live ruleset:\n{stdout}"
        );
    }

    /// Out-of-band port is mirrored (tc mirred), never bridged.
    #[test]
    fn out_of_band_port_is_mirrored() {
        let mut ifs = vec![eth("enp1s0"), eth("enp2s0"), eth("enp3s0")];
        ifs[2].role = InterfaceRole::OutOfBand;
        let intent = FabricIntent { mirror_to: Some("dummy-mirror".into()), ..Default::default() };
        let p = plan(&ifs, Some("enp1s0"), &intent, true);
        let l2 = p.l2.as_ref().unwrap();
        assert_eq!(l2.ports.iter().find(|x| x.iface == "enp3s0").unwrap().action, PortAction::MirrorOnly);
        let ovs = render(&p).into_iter().find(|f| f.path.contains(".ovs.plan")).unwrap();
        assert!(ovs.content.contains("mirred egress mirror dev dummy-mirror"));
        assert!(!ovs.content.contains("add-port hp-br0 enp3s0"));
    }
}
