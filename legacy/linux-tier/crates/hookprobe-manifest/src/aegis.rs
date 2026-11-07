//! AEGIS network reconciler — the project's "operated by intent, not configured" core.
//!
//! One declarative intent document (`network:` in `hookprobe.yaml`) is reconciled in a
//! SINGLE pass into every generated artifact: the multi-WAN failover plan, the Wi-Fi
//! AP/station config, the L2/L3 fabric (OVS/Linux-bridge/VRF), and the microsegmentation
//! flows. The operator declares *what they want*; AEGIS produces the config — which is an
//! artifact, never the interface. The result carries a **plan-as-diff** the caller shows
//! and a flat list of artifacts the caller writes/verifies. Everything is derived from
//! the SIGNED manifest (interfaces, uplinks, wifi radios, capabilities) + this intent.
//!
//! Continuous trust is intentionally NOT part of this static apply — it is posture-driven
//! and runs on its own timer (`hookprobe-trust-reconcile`); its policy is echoed here.

use crate::multi_wan::GeneratedFile;
use crate::{fabric, inspect, lan, microseg, multi_wan, nac, trust, wifi_cfg, Manifest};

/// The `network:` section of `hookprobe.yaml` — each sub-intent is optional and defaults
/// to the reconciler's own safe default (auto fabric, idle Wi-Fi, manifest WAN order, …).
#[derive(Debug, Clone, Default, serde::Deserialize)]
#[serde(default)]
pub struct NetworkIntent {
    pub wan: Option<multi_wan::WanIntent>,
    pub wifi: Option<wifi_cfg::WifiIntent>,
    pub fabric: Option<fabric::FabricIntent>,
    pub microseg: Option<microseg::MicrosegIntent>,
    pub trust: Option<trust::TrustPolicy>,
    /// Per-device NAC — declared devices (auto-classified from fingerprints, admin-tunable).
    pub nac: Option<nac::NacIntent>,
    pub inspect: Option<inspect::InspectIntent>,
}

/// Top-level intent document (so the file reads `network: { … }`).
#[derive(Debug, Clone, Default, serde::Deserialize)]
#[serde(default)]
pub struct HookprobeIntent {
    pub network: NetworkIntent,
}
impl HookprobeIntent {
    pub fn parse(yaml: &str) -> anyhow::Result<HookprobeIntent> {
        Ok(serde_yaml::from_str(yaml)?)
    }
}

/// The outcome of one reconcile pass: a human plan-as-diff, the artifacts to write, and
/// any warnings (unresolved references, missing capabilities, …).
#[derive(Debug, Clone, Default)]
pub struct ReconcileResult {
    pub plan: Vec<String>,
    pub artifacts: Vec<GeneratedFile>,
    pub warnings: Vec<String>,
}

/// Reconcile the whole network intent against the signed manifest in one pass.
pub fn reconcile_network(manifest: &Manifest, intent: &NetworkIntent, ovs_granted: bool) -> ReconcileResult {
    let mut r = ReconcileResult::default();

    // 1. Multi-WAN failover — from the manifest's uplinks + operator overrides.
    let wan_intent = intent.wan.clone().unwrap_or_default();
    let wan = multi_wan::plan(&manifest.network.uplinks, &wan_intent);
    r.plan.push(format!("WAN      · {}", wan.summary()));
    r.artifacts.extend(multi_wan::render_networkd(&wan));
    // The wired port kept OFF the LAN bridge is the WIRED WAN uplink AS CHOSEN BY THE WAN
    // PLAN (which already applied disable/prefer). Sourcing it from the plan — not the raw
    // manifest — means a `disable: [<iface>]` or `prefer:` override can't leave the active
    // WAN port enslaved to the bridge.
    let wan_uplink = wan
        .routes
        .iter()
        .find(|route| route.kind == "wired")
        .map(|route| route.iface.clone());

    // 2. Wi-Fi radios — station/AP config from the baked-in roles + intent.
    let wifi_intent = intent.wifi.clone().unwrap_or_default();
    // `identity.device_id` is this device's stable, signed-manifest identity (a hardware-
    // fingerprint hash — see `identity::puf_seed` / `builder::build_manifest`) — the seed for
    // the AP's per-device default SSID when the operator's intent doesn't declare one. Same
    // device → same SSID every reconcile; two devices sharing one image → different SSIDs.
    let wifi_files = wifi_cfg::render(&manifest.network.wifi_radios, &wifi_intent, &manifest.identity.device_id);
    let wp = wifi_cfg::plan(&manifest.network.wifi_radios, &wifi_intent, &manifest.identity.device_id);
    r.plan.push(format!("Wi-Fi    · {} ({} config file(s))", wp.summary(), wifi_files.len()));
    r.artifacts.extend(wifi_files);

    // 3. Fabric — L2 switching (OVS / Linux-bridge) and/or L3 VRF, topology-driven.
    let fabric_intent = intent.fabric.clone().unwrap_or_default();
    let fab = fabric::plan(&manifest.network.interfaces, wan_uplink.as_deref(), &fabric_intent, ovs_granted);
    r.plan.push(format!("Fabric   · {} — {}", fab.resolved, fab.summary()));
    if !ovs_granted && fab.l2.is_some() {
        r.warnings.push("openvswitch capability not granted → Linux-bridge fallback (no OpenFlow MAC binding/microseg)".to_string());
    }
    r.artifacts.extend(fabric::render(&fab));

    // 3b. Routed north-south egress through the VRF forward hook — THE CM5 fix (2026-07-10).
    // When the L3 VRF plane is present, its `forward` chain is a GLOBAL `inet … hook forward
    // priority 0; policy drop` (see `fabric::render_vrf`). That drop covers EVERY forwarded packet,
    // not just the `vrf-hp-*` devices — so a box that runs the VRF microseg AND a routed AP/LAN
    // (the CM5: `end0` WAN + `enP1p1s0` LAN carrier → single-carrier-with-segments VRF, + onboard
    // `wlan0` routed AP gateway 10.66.0.1/24, rendered unconditionally in 4c below) black-holes the
    // routed clients' NEW wlanN→WAN traffic: confirmed live (phone associates + gets a lease, but no
    // internet). This coexistence is legitimate, so we DON'T suppress the VRF — we grant the routed
    // AP/LAN device(s) explicit north-south egress into the same forward chain, in this same pass.
    if fab.vrf.is_some() {
        let mut north_south: Vec<String> = Vec::new();
        // Hybrid: an L2 bridge LAN with a real member also forwards through the global hook.
        if let Some(l2) = &fab.l2 {
            if l2.ports.iter().any(|p| p.action == fabric::PortAction::BridgeMember) {
                north_south.push(l2.bridge.clone());
            }
        }
        // The routed AP radio (Pi/CM5 onboard brcmfmac gateway) — the confirmed CM5 case. Matches
        // the SAME radio lan.rs (4c) routes the gateway onto.
        if let Some(ap) = wp.assignments.iter().find(|a| a.role == "ap") {
            if !north_south.contains(&ap.iface) {
                north_south.push(ap.iface.clone());
            }
        }
        if !north_south.is_empty() {
            r.plan.push(format!(
                "VRF-NS   · north-south egress {north_south:?} → WAN {} (routed AP/LAN not stranded by the VRF policy-drop forward chain)",
                wan_uplink.as_deref().unwrap_or("<unresolved>")
            ));
            r.artifacts.push(fabric::render_vrf_north_south(&north_south, wan_uplink.as_deref()));
        }
    }

    // 4. Microsegmentation — east-west isolation over the fabric's segments.
    let ms_intent = intent.microseg.clone().unwrap_or_default();
    if !fabric_intent.segments.is_empty() {
        let msp = microseg::plan(&fabric_intent.segments, &ms_intent);
        for u in &msp.unresolved {
            r.warnings.push(format!("microseg: unresolved segment reference '{u}'"));
        }
        r.plan.push(format!("Microseg · {}", msp.summary()));
        // Emit the microseg enforcement that MATCHES the fabric plane, never both:
        //   - OVS bridge present → OpenFlow conntrack microseg on the bridge;
        //   - VRF or Linux-bridge (no OVS bridge) → nft microseg.
        // Emitting the OVS flows in VRF mode left them orphaned (targeting a non-existent
        // `hp-br0`), which hard-failed network-apply (`ovs-ofctl: no bridge`). This fixes that drift.
        let has_ovs_bridge = match &fab.l2 {
            Some(l2) => matches!(l2.backend, fabric::L2Backend::Ovs),
            None => false,
        };
        if has_ovs_bridge {
            r.artifacts.push(microseg::render_ovs_conntrack(&msp));
        } else {
            r.artifacts.push(microseg::render_nft(&msp));
        }
    }

    // 4c. LAN gateway — bring the LAN online as a ROUTER (gateway IP + DHCP + NAT out the WAN +
    // dual-stack IPv6 + RA-Guard). TWO planes, hardware-picked (capabilities, not branches):
    //   (i)  BRIDGED — a bridgeable L2 plane exists (wired ports / PCIe `ath` radios) → gateway on
    //        the OVS bridge, OpenFlow enforcement (the N100/Fortress shape).
    //   (ii) ROUTED — an ONBOARD `brcmfmac` AP radio can't bridge → gateway on the radio itself,
    //        nft enforcement (the Pi 4 shape). The NAC block below renders nft for this plane.
    let wan_for_lan = wan_uplink.clone().unwrap_or_else(|| "end0".to_string());
    if let Some(l2) = &fab.l2 {
        let lan_intent = lan::LanIntent {
            bridge: l2.bridge.clone(),
            wan: wan_for_lan.clone(),
            ovs: matches!(l2.backend, fabric::L2Backend::Ovs),
            // `l2.bridge` is always a genuine L2 bridge (OVS or Linux-bridge) here — `fabric::plan`
            // only populates `fab.l2` for a real bridge device. RA-Guard can safely use bridge- or
            // OVS-family enforcement (bridge-family hooks fire for its traffic).
            bridged: true,
            ..Default::default()
        };
        let lp = lan::plan(&lan_intent);
        r.plan.push(format!("LAN      · {}", lp.summary));
        r.artifacts.extend(lp.artifacts);
    }
    // Routed AP: a Wi-Fi AP radio can't join the OVS bridge (brcmfmac can't bridge AP unicast), so
    // put the gateway directly ON the radio (routed), nft enforcement. Route the first AP radio.
    if let Some(ap_iface) = wp
        .assignments
        .iter()
        .find(|a| a.role == "ap")
        .map(|a| a.iface.clone())
    {
        let lan_intent = lan::LanIntent {
            bridge: ap_iface.clone(), // routed: the gateway lives on the AP radio itself
            wan: wan_for_lan.clone(),
            ovs: false, // routed → nft RA-Guard, not OpenFlow
            // 2026-07 on-metal audit fix: `ap_iface` is an L3-ROUTED radio, never a bridge member
            // (brcmfmac and equivalents can't bridge AP unicast — see `fabric::is_bridgeable`).
            // Bridge-family nft hooks never fire for routed traffic, so this MUST select the
            // netdev-family RA-Guard (`render_ra_guard_netdev`), not the bridge-family one — the
            // bridge-family rules would load, pass `nft -c`, and silently never match a packet.
            bridged: false,
            ..Default::default()
        };
        let lp = lan::plan(&lan_intent);
        r.plan.push(format!("LAN(routed {ap_iface}) · {}", lp.summary));
        r.artifacts.extend(lp.artifacts);
    }

    // 4d. Per-device NAC (north-south LAN/internet access) — V2's durable-identity improvement of
    // V1's MAC-set NAC. Resolves declared devices (fingerprint-classified default + admin override)
    // into nft sets (always) + OVS conntrack flows (when on an OVS bridge). Complements microseg
    // (east-west). The MAC is just the current enforcement binding; the policy keys on identity.
    if let Some(nac_intent) = &intent.nac {
        if !nac_intent.devices.is_empty() {
            let wan = wan_uplink.clone().unwrap_or_else(|| "end0".to_string());
            let np = nac::resolve(&nac_intent.devices, "10.66.0.0/24", &wan);
            r.plan.push(format!("NAC      · {}", np.summary()));
            r.artifacts.push(nac::render_nft(&np));
            if let Some(l2) = &fab.l2 {
                if matches!(l2.backend, fabric::L2Backend::Ovs) {
                    r.artifacts.push(nac::render_ovs(&np, &l2.bridge, &wan));
                }
            }
        }
    }

    // 4e. Inspection substrate — "everything is rogue": mirror every forwarding NIC to the SOC sink
    // (tc-mirred, XDP-free → works on brcmfmac) + record the per-NIC fast-path mode (XDP where the
    // driver supports it, software floor otherwise). Deep DPI reads the mirror sink; the software
    // flow floor (senzorium-flow) runs regardless. XDP capability probing plugs into xdp_caps_for.
    //
    // `.unwrap_or_default()` — NOT `if let Some(..)` — matching every sibling section above
    // (wan/wifi/fabric/microseg all default when the operator OMITS the block). CRITICAL FIX
    // (2026-07-05, live Pi4 hunt): this used to be `if let Some(insp) = &intent.inspect`, so an
    // `/etc/hookprobe/network.yaml` that simply doesn't carry an `inspect:` key (hand-trimmed by
    // an operator, or written before this stanza existed and never touched again — /etc on an
    // already-provisioned device is NOT re-templated by an OS update) silently produced ZERO
    // mirror artifacts: `hp-mirror` existed (created once, historically) but nothing fed it, so
    // napse-dpi/portscan(rule 1000003)/l2guard saw NO packets — confirmed live: two nmap SYN
    // scans (300+600 ports) from fortress → Pi produced zero portscan alerts. `InspectIntent`'s
    // `Default` IS the zero-trust posture (`mirror: true`), so defaulting here — like every other
    // domain — restores network.example.yaml's own documented contract ("every section is
    // OPTIONAL... omit one and its reconciler uses safe defaults") for the ONE section where
    // omission previously meant "go blind" instead of "stay safe by default".
    let insp = intent.inspect.clone().unwrap_or_default();
    {
        // Self-selecting ladder: per-NIC native-XDP + host bpf-stateful are FACTS bootstrap probed
        // into the manifest (`xdp::driver_supports_native_xdp` / `kernel_bpf_stateful`). No branching
        // on hardware — the mode follows capability (ADR 0005).
        let ifaces = &manifest.network.interfaces;
        // ALL uplinks (primary + failover + cellular) are WAN-side — the whole failover set gets the
        // ingress-threat ruleset, not just the primary wired uplink.
        let uplink_names: Vec<&str> = manifest.network.uplinks.iter().map(|u| u.name.as_str()).collect();
        let ip = inspect::plan(
            ifaces,
            &uplink_names,
            &insp,
            |name| inspect::XdpCaps {
                native: ifaces.iter().find(|i| i.name == name).map(|i| i.xdp_native).unwrap_or(false),
            },
            manifest.network.bpf_stateful,
        );
        if !ip.ifaces.is_empty() {
            r.plan.push(format!("Inspect  · {}", ip.summary));
            r.artifacts.extend(ip.artifacts);
        }
    }

    // 4f. Ring-0 enforcement interfaces — the FIX for the cross-platform bug confirmed live on the
    // amd64 VM (interfaces enp0s2/enp0s3): `napse-quarantine`/`napse-l2guard` (TC-bpf) and
    // `scan-responder.sh`'s nft quarantine used to have `wlan0`/`end0` (the Pi's names) baked into
    // their systemd units/scripts, so on any OTHER platform the BPF loader failed
    // (`read ifindex for wlan0: No such file or directory`) and the nft drop rules matched an
    // interface that never carried traffic — enforcement was silently a no-op everywhere except
    // the Pi. AEGIS already classifies the real LAN/WAN interfaces in THIS SAME reconcile pass
    // (the WAN plan above, `fab`'s bridge/routed-AP LAN side) — this resolves the SAME two
    // devices `lan::plan` (4c) already gated the gateway on, so enforcement always binds to
    // whatever this device's fabric actually is, never a hardcoded platform name:
    //   - WAN = the wired uplink the WAN plan chose (`wan_uplink`; falls back to the LAN side, then
    //     to `end0` only if literally nothing resolved — a manifest with zero interfaces).
    //   - LAN = the bridge device (bridged plane — OVS or Linux-bridge, matching `lan::plan`'s
    //     `bridge:` for that plane) IF it actually has a real (non-WAN, non-mirror-only) member,
    //     else the routed AP radio (matching `lan::plan`'s routed plane), else the WAN side, else
    //     `wlan0`. The "has a real member" guard matters: a single-NIC device still gets an empty
    //     `fab.l2` (bridge with only the WAN port classified, kept OFF it — see `fabric::plan`'s
    //     "single carrier → flat bridge" branch) which would otherwise resolve to a bridge that
    //     carries no LAN traffic at all.
    let lan_bridge_has_real_member = fab
        .l2
        .as_ref()
        .is_some_and(|l2| l2.ports.iter().any(|p| p.action == fabric::PortAction::BridgeMember));
    let lan_enforcement_iface = if lan_bridge_has_real_member {
        fab.l2.as_ref().map(|l2| l2.bridge.clone())
    } else {
        None
    }
    .or_else(|| wp.assignments.iter().find(|a| a.role == "ap").map(|a| a.iface.clone()));
    let resolved_wan = wan_uplink
        .clone()
        .or_else(|| lan_enforcement_iface.clone())
        .unwrap_or_else(|| "end0".to_string());
    let resolved_lan = lan_enforcement_iface
        .or_else(|| wan_uplink.clone())
        .unwrap_or_else(|| "wlan0".to_string());
    r.plan.push(format!(
        "Enforce  · napse-quarantine/l2guard (TC-bpf) + scan-responder (nft) bind LAN={resolved_lan} WAN={resolved_wan}"
    ));
    r.artifacts.push(render_ifaces_env(&resolved_lan, &resolved_wan, &insp.mirror_sink));

    // 5. Continuous trust — policy echoed; enforcement runs on its own timer.
    if let Some(tp) = &intent.trust {
        r.plan.push(format!(
            "Trust    · quarantine→{} (vlan {}) at risk≥{:.0} (applied by hookprobe-trust-reconcile.timer)",
            tp.quarantine_segment, tp.quarantine_vlan, tp.risk_threshold
        ));
    }

    r.plan.push(format!("→ {} artifact(s) generated from one signed manifest + intent", r.artifacts.len()));
    r
}

/// GENERATED interface bindings for Ring-0 enforcement (`napse-quarantine`, `napse-l2guard`) and
/// the scan-responder's nft quarantine — the ONE place that turns "the reconciler already
/// classified these interfaces" into something those out-of-process consumers can load via
/// `EnvironmentFile=-/var/lib/hookprobe/ifaces.env`, without re-probing hardware or hardcoding the
/// Pi's `wlan0`/`end0`. Both the generic names (`LAN_IFACE`/`WAN_IFACE`, read by
/// `scan-responder.sh`/`scan-responder-sweep.sh` and `hookprobe-supervisor --scan-respond`'s CLI
/// fallback) and each BPF loader's own namespaced names are emitted, because systemd's
/// `Environment=`/`EnvironmentFile=` do NOT expand `$VAR` references between assignments (see
/// `systemd.exec(5)`: "variable expansion is not performed inside the strings") — one flat file
/// carrying every name a consumer might read is simpler and more robust than relying on shell-style
/// indirection systemd doesn't support.
fn render_ifaces_env(lan: &str, wan: &str, mirror: &str) -> GeneratedFile {
    let mut s = String::from(
        "# GENERATED by hookprobe-supervisor --reconcile-network (aegis::reconcile_network).\n\
         # Do NOT edit by hand — declare intent instead (network.yaml). Re-derived on every\n\
         # reconcile from the SAME classified interfaces the rest of the network fabric uses\n\
         # (fabric::plan's bridge / lan.rs's routed-AP radio / multi_wan's chosen WAN uplink) —\n\
         # never a hardcoded platform-specific interface name baked into a systemd unit.\n",
    );
    s.push_str(&format!("LAN_IFACE={lan}\n"));
    s.push_str(&format!("WAN_IFACE={wan}\n"));
    s.push_str(&format!("MIRROR_IFACE={mirror}\n"));
    s.push_str(&format!("NAPSE_QUARANTINE_LAN_IFACE={lan}\n"));
    s.push_str(&format!("NAPSE_QUARANTINE_WAN_IFACE={wan}\n"));
    s.push_str(&format!("NAPSE_L2GUARD_LAN_IFACE={lan}\n"));
    s.push_str(&format!("NAPSE_L2GUARD_WAN_IFACE={wan}\n"));
    GeneratedFile { path: "ifaces.env".to_string(), content: s }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::builder::build_manifest;
    use crate::scan::ScanProfile;

    // The Pi4 fixture has BOTH ethernet and Wi-Fi radios, so it exercises every domain
    // (the n100 fixture predates Wi-Fi capture). Roles/uplinks are platform-agnostic.
    const EDGE_FIXTURE: &str = include_str!("../../../manifest/fixtures/rpi4-live.profile.json");

    const N100_FIXTURE: &str = include_str!("../../../manifest/fixtures/n100.profile.json");

    fn manifest_from(fixture: &str) -> Manifest {
        let scan = serde_json::from_str::<ScanProfile>(fixture).expect("fixture").scan;
        let platforms = crate::load_platforms(std::path::Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/../../platforms"))).expect("platforms");
        let (platform, mi) = crate::classify(&scan, &platforms).expect("classify");
        build_manifest(&scan, platform, &mi, "2026-01-01T00:00:00Z", "img", "sha256:0").expect("manifest")
    }
    /// Pi 4 (rpi4-live): onboard `brcmfmac` AP + USB station + one wired WAN → ROUTED AP, no bridge.
    fn edge_manifest() -> Manifest { manifest_from(EDGE_FIXTURE) }
    /// N100: four wired ports → OVS L2 bridge (the bridged/OpenFlow plane).
    fn n100_manifest() -> Manifest { manifest_from(N100_FIXTURE) }

    const INTENT: &str = r#"
network:
  fabric:
    kind: auto
    segments:
      - { name: trusted, vlan: 10 }
      - { name: cameras, vlan: 30 }
    mac_bindings:
      - { mac: "9c:8e:cd:11:22:33", segment: cameras }
  wifi:
    ap: { ssid: HookProbe, passphrase: secret12345 }
    country: GB
  microseg:
    gateway: 10.200.0.1
  trust:
    quarantine_segment: quarantine
    quarantine_vlan: 666
"#;

    /// One intent → all domains reconciled in a single pass. On the Pi 4 the onboard AP is ROUTED:
    /// WAN + hostapd + LAN(routed on the AP radio) + nft microseg — no OVS bridge, no OpenFlow.
    #[test]
    fn one_intent_reconciles_all_domains() {
        let m = edge_manifest();
        let intent = HookprobeIntent::parse(INTENT).expect("parse intent").network;
        let r = reconcile_network(&m, &intent, /* ovs_granted */ true);
        // Plan mentions every domain, incl. the routed LAN.
        let plan = r.plan.join("\n");
        assert!(plan.contains("WAN") && plan.contains("Wi-Fi") && plan.contains("Fabric") && plan.contains("Microseg") && plan.contains("Trust"));
        assert!(plan.contains("LAN(routed"), "routed LAN gateway on the onboard AP radio");
        // Artifacts span the routed reconcilers (networkd WAN + hostapd + routed LAN gateway + nft).
        let paths: Vec<&str> = r.artifacts.iter().map(|a| a.path.as_str()).collect();
        assert!(paths.iter().any(|p| p.contains("hookprobe-wan-")), "WAN drop-ins");
        assert!(paths.iter().any(|p| p.starts_with("hostapd-")), "hostapd config");
        assert!(paths.iter().any(|p| p.contains("hookprobe-lan-")), "routed LAN gateway .network");
        assert!(paths.iter().any(|p| p.contains("microseg")), "nft microseg");
        // A routed AP must NOT emit OVS/OpenFlow artifacts (brcmfmac can't bridge), NOR a VRF —
        // the VRF forward chain is `policy drop` and would black-hole the routed AP's wlanN→WAN egress.
        assert!(!paths.iter().any(|p| p.contains(".ovs.plan") || p.contains(".flows.of")), "no OVS on routed AP");
        assert!(!paths.iter().any(|p| p.contains("60-vrf.plan")), "no VRF drop-chain on routed AP (would strand egress)");
        // 2026-07 on-metal audit fix: the routed AP's RA-Guard MUST be netdev-family (bridge-family
        // hooks never fire for its L3-routed traffic — see `lan::LanIntent::bridged`).
        let rg = r.artifacts.iter().find(|a| a.path.contains("64-ra-guard")).expect("RA-Guard artifact");
        assert!(rg.path.ends_with(".netdev.nft"), "routed AP RA-Guard must be the netdev-family file, got {}", rg.path);
        assert!(rg.content.contains("table netdev hookprobe_raguard") && !rg.content.contains("table bridge"));
    }

    /// A multi-port wired box (N100) DOES bridge: OVS L2 plane + OpenFlow, and the camera MAC
    /// binding lands as a VLAN-tagging flow on the bridge. This is the bridged counterpart plane.
    #[test]
    fn wired_lan_bridges_with_ovs_flows() {
        let m = n100_manifest();
        let intent = HookprobeIntent::parse(INTENT).expect("parse intent").network;
        let r = reconcile_network(&m, &intent, /* ovs_granted */ true);
        let paths: Vec<&str> = r.artifacts.iter().map(|a| a.path.as_str()).collect();
        assert!(paths.iter().any(|p| p.contains(".ovs.plan")), "fabric OVS plan");
        assert!(paths.iter().any(|p| p.contains(".flows.of")), "fabric flows");
        let flows = r.artifacts.iter().find(|a| a.path.contains(".flows.of")).unwrap();
        assert!(flows.content.contains("dl_src=9c:8e:cd:11:22:33,actions=mod_vlan_vid:30"));
    }

    /// The SHIPPED default intent (installed as /etc/hookprobe/network.yaml) must parse with all
    /// sections — incl. `nac` + `fabric.kind: auto` — so the edge boots its AP/LAN on either plane.
    #[test]
    fn shipped_network_example_parses() {
        let yaml = include_str!("../../../base/config/network.example.yaml");
        let doc = HookprobeIntent::parse(yaml).expect("network.example.yaml must parse");
        assert!(doc.network.nac.is_some(), "nac section present");
        assert!(doc.network.fabric.is_some() && doc.network.wifi.is_some());
    }

    /// A NAC intent flows through the reconcile: the classifier assigns the camera lan_only and
    /// the per-device nft NAC artifact is emitted (+ LAN gateway when on an OVS bridge).
    #[test]
    fn nac_intent_produces_per_device_artifacts() {
        let m = edge_manifest();
        let mut intent = HookprobeIntent::parse(INTENT).expect("parse").network;
        intent.nac = Some(nac::NacIntent {
            devices: vec![nac::DeviceNacDecl {
                identity: "hik-cam".into(),
                mac: Some("00:0c:b5:00:00:09".into()),
                class: Some("iot-camera".into()),
                policy: None,
                allow: vec![],
                first_seen: None,
            }],
            onboarding_grace_secs: None,
        });
        let r = reconcile_network(&m, &intent, /* ovs_granted */ true);
        assert!(r.plan.iter().any(|l| l.contains("NAC")), "NAC appears in the plan-as-diff");
        let nf = r.artifacts.iter().find(|a| a.path.contains("66-nac.nft")).expect("NAC nft artifact");
        // classifier put the camera in lan_only; the current MAC is bound into that set.
        assert!(nf.content.contains("lan_only_macs { 00:0c:b5:00:00:09 }"), "camera → lan_only");
        // and the LAN gateway (router) came up on the OVS bridge.
        assert!(r.plan.iter().any(|l| l.contains("LAN")), "LAN gateway in the plan");
    }

    /// An empty intent still reconciles safely (auto fabric, default WAN order, no Wi-Fi).
    #[test]
    fn empty_intent_is_safe() {
        let m = edge_manifest();
        let r = reconcile_network(&m, &NetworkIntent::default(), true);
        assert!(!r.artifacts.is_empty(), "auto fabric + WAN still produce artifacts");
        assert!(r.plan.iter().any(|l| l.contains("Fabric")));
    }

    /// REGRESSION (live Pi4 hunt, 2026-07-05): omitting `inspect:` from `network.yaml` entirely
    /// (an already-provisioned device's on-disk file predating this stanza, or a hand-trimmed
    /// config) must NOT blind the packet-layer detectors. `NetworkIntent::default()` has
    /// `inspect: None` — the reconciler must still wire the zero-trust mirror (`hp-mirror` sink +
    /// tc-mirred on every forwarding NIC) exactly as if `inspect: {}` had been written explicitly.
    /// This is the wiring gap that let a real device ship with an active `hp-mirror` dummy sink
    /// that nothing fed: two live nmap SYN scans (300+600 ports) produced zero portscan alerts.
    #[test]
    fn inspect_mirror_applies_even_when_network_yaml_omits_the_section() {
        let m = edge_manifest();
        // No `inspect:` key at all — the exact on-disk shape of a config written before this
        // section existed, or trimmed by an operator for an unrelated edit.
        let r = reconcile_network(&m, &NetworkIntent::default(), true);
        let inspect_line = r.plan.iter().find(|l| l.contains("Inspect")).expect("Inspect must appear in the plan even with an omitted `inspect:` section");
        assert!(inspect_line.contains("+mirror"), "the mirror must be ON by default: {inspect_line}");
        let mirror = r
            .artifacts
            .iter()
            .find(|a| a.path.contains("70-mirror.plan"))
            .expect("the tc-mirred mirror artifact must be generated even with an omitted `inspect:` section");
        // Both the WAN uplink and the LAN/AP radio must be mirrored to hp-mirror — this is the
        // Pi4's real topology (eth0 WAN + wlan1 onboard AP) from the live fixture.
        assert!(mirror.content.contains("mirred egress mirror dev hp-mirror"), "sink present: {}", mirror.content);
    }

    /// The inspection ladder SELF-SELECTS per NIC from real driver facts in the manifest (ADR 0005):
    /// the Pi's bcmgenet/brcmfmac have no native XDP → tc-bpf; the N100's igc does → xdp-native. No
    /// hardware branching — the mode follows capability. Covers WAN + LAN sides.
    #[test]
    fn inspect_ladder_self_selects_from_driver_facts() {
        let mut intent = HookprobeIntent::parse(INTENT).expect("parse").network;
        intent.inspect = Some(inspect::InspectIntent::default());
        // Pi 4: kernel 6.1 (bpf_stateful) + non-native drivers → every NIC on the tc-bpf tier.
        let rpi = reconcile_network(&edge_manifest(), &intent, true);
        let pi = rpi.plan.iter().find(|l| l.contains("Inspect")).expect("inspect plan");
        assert!(pi.contains("tc-bpf") && !pi.contains("xdp-native"), "Pi → tc-bpf: {pi}");
        assert!(pi.contains("/wan") && pi.contains("/lan"), "cover all round (WAN+LAN): {pi}");
        // N100: igc has native XDP → the ladder picks xdp-native automatically.
        let n100 = reconcile_network(&n100_manifest(), &intent, true);
        let n = n100.plan.iter().find(|l| l.contains("Inspect")).expect("inspect plan");
        assert!(n.contains("xdp-native"), "N100 igc → xdp-native: {n}");
    }

    /// No OVS capability on a box that WOULD bridge (N100, wired LAN) → Linux-bridge fallback warns.
    #[test]
    fn missing_ovs_capability_warns() {
        let m = n100_manifest();
        let intent = HookprobeIntent::parse(INTENT).expect("parse").network;
        let r = reconcile_network(&m, &intent, /* ovs_granted */ false);
        assert!(r.warnings.iter().any(|w| w.contains("Linux-bridge fallback")));
    }

    // -----------------------------------------------------------------------------------------
    // Ring-0 enforcement interfaces (`ifaces.env`) — the cross-platform fix. Confirmed LIVE on an
    // amd64 VM (interfaces enp0s2/enp0s3): napse-quarantine/napse-l2guard had wlan0/end0 (the Pi's
    // names) hardcoded in their systemd units, so the BPF loader failed
    // (`read ifindex for wlan0: No such file or directory`) and enforcement was a silent no-op on
    // every non-Pi platform. These tests build synthetic manifests via `HardwareScan` directly
    // (not the checked-in JSON fixtures, whose interface names — `eth0`/`wlan1` in rpi4-live.
    // profile.json — predate the real device's `end0`/`wlan0` naming) so the exact platform shapes
    // named in the bug report are covered.
    // -----------------------------------------------------------------------------------------

    use crate::scan::{HardwareScan, ScanCpu, ScanInterface};
    use crate::types::{Arch, InterfaceRole, InterfaceType, Lte, Npu, SecureBoot, Tpm, TpmKind, Wifi};

    fn iface(name: &str, ty: InterfaceType, bus: Option<&str>, onboard: bool) -> ScanInterface {
        ScanInterface {
            name: name.to_string(),
            mac: None,
            iface_type: ty,
            driver: Some("test-driver".to_string()),
            supported_modes: vec![],
            role: InterfaceRole::Unassigned,
            fail_mode: None,
            state: "up".to_string(),
            bus: bus.map(str::to_string),
            onboard,
            band: None,
            hw_timestamping: false,
        }
    }

    /// Minimal-but-valid scan (mirrors `classify.rs`'s own test helper) — only the fields the
    /// classifier + `build_manifest` read for THIS test's purposes are meaningful.
    fn scan_with(interfaces: Vec<ScanInterface>, virt: &str, arch: Arch) -> HardwareScan {
        HardwareScan {
            device_tree_compatible: vec![],
            dmi: None,
            arch,
            cpu: ScanCpu { model: String::new(), cores: 4 },
            memory_mb: 4096,
            kernel_release: None,
            storage: vec![],
            tpm: Tpm { present: false, version: None, kind: TpmKind::None },
            secure_boot: SecureBoot { supported: false, enabled: false },
            npu: Npu { present: false, driver_ready: false, vendor: None, model: None },
            virt: virt.to_string(),
            interfaces,
            wifi: Wifi { present: false, max_standard: None },
            lte: Lte { present: false, model: None },
            unbound: vec![],
        }
    }

    fn manifest_from_scan(scan: &HardwareScan) -> Manifest {
        let platforms = crate::load_platforms(std::path::Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/../../platforms"))).expect("platforms");
        let (platform, mi) = crate::classify(scan, &platforms).expect("classify");
        build_manifest(scan, platform, &mi, "2026-01-01T00:00:00Z", "img", "sha256:0").expect("manifest")
    }

    /// THE bug-report shape: an amd64 VM with two wired NICs, no Wi-Fi at all — the case that was
    /// silently unenforced. `enp0s2` classifies first as the WAN uplink (both are wired, same
    /// priority — WAN-plan selection is stable on manifest order); `enp0s3` is the sole remaining
    /// LAN carrier, so `fabric::plan` bridges it (`hp-br0`, "single carrier → flat bridge"). The
    /// resolved `ifaces.env` must carry the REAL enp* names (or the bridge fronting the LAN NIC),
    /// never `wlan0`/`end0`.
    #[test]
    fn amd64_vm_two_wired_nics_resolves_to_real_iface_names_not_pi_defaults() {
        let scan = scan_with(
            vec![
                iface("enp0s2", InterfaceType::Ethernet, Some("pci"), false),
                iface("enp0s3", InterfaceType::Ethernet, Some("pci"), false),
            ],
            "kvm",
            Arch::Amd64,
        );
        let m = manifest_from_scan(&scan);
        let r = reconcile_network(&m, &NetworkIntent::default(), /* ovs_granted */ true);
        let ifaces_env = r.artifacts.iter().find(|a| a.path == "ifaces.env").expect("ifaces.env must be generated");
        assert!(ifaces_env.content.contains("WAN_IFACE=enp0s2"), "got: {}", ifaces_env.content);
        assert!(ifaces_env.content.contains("LAN_IFACE=hp-br0"), "the sole remaining LAN NIC is bridged: {}", ifaces_env.content);
        assert!(!ifaces_env.content.contains("wlan0") && !ifaces_env.content.contains("end0"), "must never leak Pi defaults: {}", ifaces_env.content);
        // Every module-namespaced name mirrors the generic one (no systemd $VAR expansion to rely on).
        assert!(ifaces_env.content.contains("NAPSE_QUARANTINE_WAN_IFACE=enp0s2"));
        assert!(ifaces_env.content.contains("NAPSE_QUARANTINE_LAN_IFACE=hp-br0"));
        assert!(ifaces_env.content.contains("NAPSE_L2GUARD_WAN_IFACE=enp0s2"));
        assert!(ifaces_env.content.contains("NAPSE_L2GUARD_LAN_IFACE=hp-br0"));
    }

    /// A genuinely single-NIC box (e.g. a 1-NIC cloud VM): the lone interface is the WAN uplink,
    /// `fabric::plan` still emits an (empty-of-real-members) bridge, and the "real member" guard
    /// must skip it — LAN degenerately collapses to the same interface as WAN, never an inert
    /// bridge name and never a Pi default.
    #[test]
    fn single_nic_cloud_vm_lan_collapses_to_wan_not_an_empty_bridge() {
        let scan = scan_with(vec![iface("enp0s6", InterfaceType::Ethernet, Some("pci"), false)], "kvm", Arch::Amd64);
        let m = manifest_from_scan(&scan);
        let r = reconcile_network(&m, &NetworkIntent::default(), true);
        let ifaces_env = r.artifacts.iter().find(|a| a.path == "ifaces.env").expect("ifaces.env must be generated");
        assert!(ifaces_env.content.contains("WAN_IFACE=enp0s6"), "got: {}", ifaces_env.content);
        assert!(ifaces_env.content.contains("LAN_IFACE=enp0s6"), "single NIC ⇒ LAN==WAN, not an empty hp-br0: {}", ifaces_env.content);
    }

    /// THE CM5 bug (confirmed live on real silicon, 2026-07-10): a CM5 with TWO wired ports
    /// (`end0` = onboard RP1 main port → WAN, `enP1p1s0` = PCIe 2nd port → a single LAN carrier) +
    /// the onboard `wlan0` AP, run with the shipped 6-segment microseg intent. The single LAN
    /// carrier + segments makes `fabric::plan` pick the L3 VRF plane (there's nothing to L2-switch),
    /// while `wlan0` is ALSO routed as an AP gateway (10.66.0.1/24) — the two planes coexist. The
    /// VRF `forward` chain is a GLOBAL `policy drop`, so without the north-south grant the routed AP
    /// clients' NEW wlanN→WAN packets are black-holed (phone associates + leases, but no internet).
    /// The fix must: (a) still emit the VRF (the microseg feature is real), (b) grant the routed AP
    /// device explicit `iifname wlan0 oifname end0 accept` egress, (c) keep cross-segment isolation.
    #[test]
    fn cm5_routed_ap_plus_vrf_microseg_grants_north_south_egress() {
        let scan = scan_with(
            vec![
                iface("end0", InterfaceType::Ethernet, Some("platform"), true), // onboard main → WAN
                iface("enP1p1s0", InterfaceType::Ethernet, Some("pci"), false), // PCIe 2nd → LAN carrier
                iface("wlan0", InterfaceType::Wifi, Some("sdio"), true),        // onboard → routed AP
            ],
            "none",
            Arch::Arm64,
        );
        let m = manifest_from_scan(&scan);
        // The shipped-config shape: auto fabric + the 6 microseg segments + a real AP.
        let intent = HookprobeIntent::parse(
            r#"
network:
  wifi:
    ap: { ssid: HookProbe, passphrase: secret12345 }
    country: GB
  fabric:
    kind: auto
    segments:
      - { name: onboarding, vlan: 99 }
      - { name: trusted,    vlan: 10 }
      - { name: byod,       vlan: 60 }
      - { name: iot,        vlan: 20 }
      - { name: cameras,    vlan: 30, fail: fail-closed }
      - { name: quarantine, vlan: 666, fail: fail-closed }
"#,
        )
        .expect("parse")
        .network;
        let r = reconcile_network(&m, &intent, /* ovs_granted */ true);
        let paths: Vec<&str> = r.artifacts.iter().map(|a| a.path.as_str()).collect();
        // (a) The VRF plane IS emitted (single LAN carrier + segments) — the microseg feature is real.
        assert!(paths.iter().any(|p| p.contains("60-vrf.plan")), "VRF plane must be emitted on the CM5 (single LAN carrier + segments): {paths:?}");
        // (a') …AND the routed AP LAN gateway still comes up on the radio.
        assert!(r.plan.iter().any(|l| l.contains("LAN(routed")), "routed AP gateway on wlan0 must still run");
        // (b) THE FIX: the routed AP device is granted explicit north-south egress in the VRF chain.
        let ns = r.artifacts.iter().find(|a| a.path.contains("63-vrf-north-south.plan")).expect("north-south grant artifact must be emitted when VRF coexists with a routed AP");
        assert!(ns.content.contains("iifname \"wlan0\" oifname \"end0\" accept"), "routed AP wlan0→WAN end0 egress must be granted: {}", ns.content);
        assert!(r.plan.iter().any(|l| l.contains("VRF-NS")), "the plan-as-diff must surface the north-south grant");
        // (c) Cross-segment isolation is untouched: the per-segment cross-segment DROP remains.
        let vrf = r.artifacts.iter().find(|a| a.path.contains("60-vrf.plan")).unwrap();
        assert!(vrf.content.contains("oifname \"vrf-hp-*\"") && vrf.content.contains("drop"), "cross-segment vrf-A→vrf-B drop must remain enforced");
        // …and the grant itself never opens a lateral path.
        assert!(!ns.content.contains("oifname \"vrf-hp-"), "the north-south grant must not target another segment");
    }

    /// The Pi reference platform, using the REAL production device's interface names (the live
    /// Pi4 at 10.200.0.4: onboard `brcmfmac` AP `wlan0`, wired uplink `end0` — no USB dongle). This
    /// is the "must not regress" case: same names the units/scripts always hardcoded, now arrived
    /// at via classification instead of a hardcoded default.
    #[test]
    fn pi_reference_platform_still_yields_end0_wlan0() {
        let scan = scan_with(
            vec![
                iface("end0", InterfaceType::Ethernet, Some("platform"), false),
                iface("wlan0", InterfaceType::Wifi, Some("sdio"), true),
            ],
            "none",
            Arch::Arm64,
        );
        let m = manifest_from_scan(&scan);
        let r = reconcile_network(&m, &NetworkIntent::default(), true);
        let ifaces_env = r.artifacts.iter().find(|a| a.path == "ifaces.env").expect("ifaces.env must be generated");
        assert!(ifaces_env.content.contains("WAN_IFACE=end0"), "got: {}", ifaces_env.content);
        assert!(ifaces_env.content.contains("LAN_IFACE=wlan0"), "onboard AP radio, routed (brcmfmac can't bridge): {}", ifaces_env.content);
    }
}
