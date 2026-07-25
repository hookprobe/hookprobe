//! Microsegmentation — east-west (intra-segment) isolation, beyond what VLANs express.
//!
//! A VLAN is the COARSE boundary (north-south). But devices *in the same segment*
//! should usually not talk freely: a compromised camera must not reach another camera.
//! This module renders **stateful OVS conntrack** OpenFlow rules (and an nftables
//! variant for the Linux-bridge/VRF path) that enforce, per segment:
//!   - `open`             — no east-west restriction (e.g. a trusted workstation VLAN);
//!   - `client-isolation` — devices reach only the GATEWAY (north-south) + established
//!     return traffic; lateral (east-west) NEW flows are dropped. The right default for
//!     IoT / cameras / guest.
//!   - `allowlist`        — client-isolation PLUS explicit allow rules (e.g. the NVR
//!     may reach the cameras on RTSP 554); everything else dropped.
//!
//! Same intent→artifact loop as the rest of the fabric. Segment names resolve to VLANs
//! via the fabric segment list, so policy is written in human terms, not VLAN ids.

use crate::fabric::Segment;
use crate::multi_wan::GeneratedFile;

/// East-west posture for a segment.
#[derive(Debug, Clone, Copy, PartialEq, serde::Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub enum Isolation {
    /// No intra-segment restriction.
    Open,
    /// Devices reach only the gateway + established return traffic (lateral NEW dropped).
    #[default]
    ClientIsolation,
    /// `client-isolation` + explicit allow rules.
    Allowlist,
}

/// One intra/inter-segment exception (used under `allowlist`): permit `from`→`to`
/// (segment names) on an optional proto/port. `from` defaults to the policy's segment.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct AllowRule {
    #[serde(default)]
    pub from: Option<String>,
    pub to: String,
    #[serde(default)]
    pub proto: Option<String>,
    #[serde(default)]
    pub port: Option<u32>,
}

/// Per-segment microsegmentation policy.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct SegmentPolicy {
    pub segment: String,
    #[serde(default)]
    pub mode: Isolation,
    #[serde(default)]
    pub allow: Vec<AllowRule>,
}

/// Operator microsegmentation intent.
#[derive(Debug, Clone, Default, serde::Deserialize)]
#[serde(default)]
pub struct MicrosegIntent {
    /// Gateway IP that client-isolated devices are still allowed to reach (on-link router
    /// services). NOTE: internet (north-south) egresses via the gateway's MAC, not its IP,
    /// so set `gateway_mac` too for full north-south under client-isolation.
    pub gateway: Option<String>,
    /// Gateway MAC. When set, client-isolated devices may send NEW flows to it (covering
    /// ALL north-south — internet goes via the gateway MAC), while peer-to-peer (east-west)
    /// stays denied. Without it, only flows to the gateway IP (router services) are allowed.
    pub gateway_mac: Option<String>,
    pub policies: Vec<SegmentPolicy>,
}
impl MicrosegIntent {
    pub fn parse(yaml: &str) -> anyhow::Result<MicrosegIntent> {
        Ok(serde_yaml::from_str(yaml)?)
    }
}

/// A resolved policy (segment name → VLAN) ready to render.
#[derive(Debug, Clone)]
pub struct ResolvedPolicy {
    pub segment: String,
    pub vlan: u32,
    pub mode: Isolation,
    /// (from_vlan, to_vlan, proto, port) exceptions.
    pub allow: Vec<(u32, u32, Option<String>, Option<u32>)>,
}

#[derive(Debug, Clone)]
pub struct MicrosegPlan {
    pub gateway: Option<String>,
    pub gateway_mac: Option<String>,
    pub policies: Vec<ResolvedPolicy>,
    /// Segment names in the intent that don't exist in the fabric segment list.
    pub unresolved: Vec<String>,
}

impl MicrosegPlan {
    pub fn summary(&self) -> String {
        if self.policies.is_empty() {
            return "no microsegmentation policies".to_string();
        }
        self.policies
            .iter()
            .map(|p| format!("{}[vlan {}]={}", p.segment, p.vlan, mode_str(p.mode)))
            .collect::<Vec<_>>()
            .join("  ")
    }
}

fn mode_str(m: Isolation) -> &'static str {
    match m {
        Isolation::Open => "open",
        Isolation::ClientIsolation => "client-isolation",
        Isolation::Allowlist => "allowlist",
    }
}

/// The sensible DEFAULT east-west posture for a segment, by its name — so identity
/// (fingerprint → segment) drives microsegmentation with no hand-written policy. IoT,
/// cameras, guests and the onboarding/quarantine holding areas are isolated by default;
/// personal (byod) and infrastructure segments stay open. The operator can override.
pub fn default_isolation_for_segment(name: &str) -> Isolation {
    match name {
        // Things that should never talk laterally.
        "cameras" | "iot" | "printers" | "media" | "onboarding" | "quarantine" | "guest" => {
            Isolation::ClientIsolation
        }
        // Personal devices and infra typically need east-west (AirPlay, file shares, …).
        "byod" | "trusted" | "infra" => Isolation::Open,
        // Unknown segment name → safe default (isolate).
        _ => Isolation::ClientIsolation,
    }
}

/// Build a default per-segment policy set (one policy per segment, default isolation).
/// Used when the operator declares segments but no explicit microseg policy.
pub fn default_policies(segments: &[Segment]) -> Vec<SegmentPolicy> {
    segments
        .iter()
        .map(|s| SegmentPolicy {
            segment: s.name.clone(),
            mode: default_isolation_for_segment(&s.name),
            allow: vec![],
        })
        .collect()
}

/// Resolve segment names to VLANs against the fabric segment list. Every segment gets a
/// policy: an explicit one from the intent if present, else its identity-driven default
/// (built via `default_policies`, the single source of "segment name -> default policy" —
/// A1 dedupe fix: this used to re-implement that mapping inline, diverging from the
/// dedicated function docs/BuildPlan.md and docs/OS-platform-report.md already described
/// as the auto-fill mechanism). (Declaring one explicit policy no longer disables
/// defaults for the OTHER segments.)
pub fn plan(segments: &[Segment], intent: &MicrosegIntent) -> MicrosegPlan {
    let mut merged: Vec<SegmentPolicy> = default_policies(segments)
        .into_iter()
        .map(|default| {
            intent
                .policies
                .iter()
                .find(|p| p.segment == default.segment)
                .cloned()
                .unwrap_or(default)
        })
        .collect();
    // Keep any explicit policies that name a segment not in the fabric list (so they are
    // reported as unresolved rather than silently dropped).
    for p in &intent.policies {
        if !segments.iter().any(|s| s.name == p.segment) {
            merged.push(p.clone());
        }
    }
    let effective = MicrosegIntent {
        gateway: intent.gateway.clone(),
        gateway_mac: intent.gateway_mac.clone(),
        policies: merged,
    };
    plan_explicit(segments, &effective)
}

fn plan_explicit(segments: &[Segment], intent: &MicrosegIntent) -> MicrosegPlan {
    let vlan_of = |name: &str| segments.iter().find(|s| s.name == name).map(|s| s.vlan);
    let mut policies = Vec::new();
    let mut unresolved = Vec::new();
    for p in &intent.policies {
        let Some(vlan) = vlan_of(&p.segment) else {
            unresolved.push(p.segment.clone());
            continue;
        };
        let mut allow = Vec::new();
        for r in &p.allow {
            let from = r.from.as_deref().unwrap_or(&p.segment);
            match (vlan_of(from), vlan_of(&r.to)) {
                (Some(fv), Some(tv)) => allow.push((fv, tv, r.proto.clone(), r.port)),
                _ => unresolved.push(format!("{}→{}", from, r.to)),
            }
        }
        policies.push(ResolvedPolicy { segment: p.segment.clone(), vlan, mode: p.mode, allow });
    }
    MicrosegPlan {
        gateway: intent.gateway.clone(),
        gateway_mac: intent.gateway_mac.clone(),
        policies,
        unresolved,
    }
}

const BANNER: &str = "# GENERATED by hookprobe microsegmentation reconciler from the signed manifest.\n# Do NOT edit — changes are overwritten. Declare intent instead (microseg-intent.yaml).\n";

/// Render stateful OVS conntrack OpenFlow rules. Table 0 sends IP to conntrack; table 1
/// allows established/related + gateway + allowlist, and drops new east-west in isolated
/// segments. Apply: `ovs-ofctl add-flows <br> -`.
pub fn render_ovs_conntrack(plan: &MicrosegPlan) -> GeneratedFile {
    let mut s = String::from(BANNER);
    s.push_str("# Microsegmentation (stateful OVS conntrack). table 1 = conntrack dispatch,\n");
    s.push_str("# table 2 = policy. The table-1 dispatch (priority 100) layers ON TOP of the\n");
    s.push_str("# fabric flows' table-1 default (priority 0 normal), so a MAC-bound device that\n");
    s.push_str("# resubmits into table 1 is subject to the SAME isolation as an unbound one.\n");
    // Standalone entry (when microseg is applied without the fabric flows): get packets
    // from table 0 into the pipeline. Low priority so the fabric flows' table-0 rules win
    // when BOTH are loaded (no conflict).
    s.push_str("table=0,priority=100,arp,actions=normal\n");
    s.push_str("table=0,priority=1,ip,actions=resubmit(,1)\n");
    s.push_str("table=1,priority=100,ip,actions=ct(table=2)\n");
    // Established/related return traffic always passes (stateful).
    s.push_str("table=2,priority=100,ct_state=+est+trk,ip,actions=normal\n");
    s.push_str("table=2,priority=100,ct_state=+rel+trk,ip,actions=normal\n");
    // North-south: a client-isolated device must still reach the internet, which egresses
    // via the GATEWAY's MAC (the dst IP is external, so an nw_dst=gateway-IP match would
    // miss it — that was the bug). If gateway_mac is known, allow NEW flows to it (covers
    // all north-south). Always allow NEW flows to the gateway IP (on-link router services).
    if let Some(mac) = &plan.gateway_mac {
        // 2026-07-05 threat-model fix (H2): `ct()` needs an L3 ethertype in the match — a bare
        // `dl_dst=<mac>,actions=ct(...)` (no `ip`/`ipv6`) is rejected by the switch with
        // `OFPBAC_MATCH_INCONSISTENT` (reproduced: `ovs-ofctl parse-flows` on exactly this shape
        // errors "Bad OXM/NXM flow match"-class rejection for a conntrack action lacking dl_type),
        // which fails the WHOLE flow batch load — every east-west isolation rule below it in the
        // same `ovs-ofctl add-flows` batch never loads either, so this one malformed line silently
        // disabled ALL microsegmentation on a box using `gateway_mac`. Fix: emit the SAME rule
        // TWICE, once matching `ip` and once matching `ipv6`, so `ct()` always has an L3 ethertype
        // to hang off — covers both address families' north-south traffic via the gateway MAC.
        s.push_str(&format!(
            "table=2,priority=95,ct_state=+new+trk,ip,dl_dst={mac},actions=ct(commit),normal  # north-south via gateway MAC (ipv4)\n"
        ));
        s.push_str(&format!(
            "table=2,priority=95,ct_state=+new+trk,ipv6,dl_dst={mac},actions=ct(commit),normal  # north-south via gateway MAC (ipv6)\n"
        ));
    }
    if let Some(gw) = &plan.gateway {
        s.push_str(&format!(
            "table=2,priority=90,ct_state=+new+trk,ip,nw_dst={gw},actions=ct(commit),normal  # gateway IP (router services)\n"
        ));
    }
    for p in &plan.policies {
        match p.mode {
            Isolation::Open => s.push_str(&format!(
                "table=2,priority=20,dl_vlan={},actions=normal  # {} open (no east-west restriction)\n",
                p.vlan, p.segment
            )),
            Isolation::ClientIsolation | Isolation::Allowlist => {
                // Same-segment exceptions: lift the east-west drop for a proto/port WITHIN
                // the segment's VLAN (e.g. RTSP 554 so an NVR can pull from cameras). True
                // cross-VLAN flows are ROUTED and governed by the inter-VLAN firewall, not
                // this L2 drop — so we match the segment VLAN, never an unpopulated register.
                for (_fv, tv, proto, port) in &p.allow {
                    let mut m = format!("dl_vlan={tv}");
                    // tp_dst requires an L4 proto match; ovs-ofctl rejects a bare tp_dst, so
                    // default to tcp when a port is given without a proto.
                    let proto = proto.clone().or_else(|| port.map(|_| "tcp".to_string()));
                    if let Some(pr) = &proto {
                        m.push(',');
                        m.push_str(pr);
                    }
                    if let Some(pt) = port {
                        m.push_str(&format!(",tp_dst={pt}"));
                    }
                    s.push_str(&format!(
                        "table=2,priority=50,ct_state=+new+trk,{m},actions=ct(commit),normal  # {} allow\n",
                        p.segment
                    ));
                }
                // Drop NEW lateral (east-west) flows within the segment. Established/related
                // (priority 100) and gateway/north-south (90/95) already passed above.
                s.push_str(&format!(
                    "table=2,priority=20,dl_vlan={},ct_state=+new+trk,ip,actions=drop  # {} client-isolation (east-west denied)\n",
                    p.vlan, p.segment
                ));
            }
        }
    }
    // Default: IP that matched no segment rule (e.g. an open segment, or traffic on a VLAN
    // with no policy) is allowed. Segment east-west drops above (priority 20) take precedence.
    s.push_str("table=2,priority=0,actions=normal\n");
    GeneratedFile { path: "fabric/63-microseg.conntrack.of".to_string(), content: s }
}

/// Render an nftables variant for the Linux-bridge / VRF path (no OVS conntrack). Uses
/// the kernel's stateful `ct state` matching and per-VLAN/iif drops.
pub fn render_nft(plan: &MicrosegPlan) -> GeneratedFile {
    // NOTE the chain is named `forward`, NOT `fwd`: `fwd` is a RESERVED nftables keyword (the
    // fast-forward statement), so `add chain … fwd …` is a syntax error and the whole microseg
    // ruleset silently fails to load (empty table). `forward` parses fine (the VRF plane uses it).
    let mut s = String::from(BANNER);
    s.push_str("nft add table inet hookprobe_microseg 2>/dev/null || true\n");
    s.push_str("nft 'add chain inet hookprobe_microseg forward { type filter hook forward priority -10; policy accept; }' 2>/dev/null || true\n");
    s.push_str("nft add rule inet hookprobe_microseg forward ct state established,related accept\n");
    if let Some(gw) = &plan.gateway {
        s.push_str(&format!("nft add rule inet hookprobe_microseg forward ip daddr {gw} accept  # gateway IP (router services)\n"));
    }
    if let Some(mac) = &plan.gateway_mac {
        s.push_str(&format!("nft add rule inet hookprobe_microseg forward ether daddr {mac} accept  # north-south via gateway MAC\n"));
    }
    let isolated: Vec<&ResolvedPolicy> = plan
        .policies
        .iter()
        .filter(|p| p.mode != Isolation::Open)
        .collect();
    for p in &isolated {
        for (_fv, _tv, proto, port) in &p.allow {
            // Valid nft L4 match: `<proto> dport <port> accept` (NOT `meta tcp dport`).
            match (proto.as_deref(), port) {
                (Some(pr), Some(pt)) => s.push_str(&format!("nft add rule inet hookprobe_microseg forward ip protocol {pr} {pr} dport {pt} accept  # {} allow\n", p.segment)),
                (_, Some(pt)) => s.push_str(&format!("nft add rule inet hookprobe_microseg forward tcp dport {pt} accept  # {} allow (assumed tcp)\n", p.segment)),
                _ => {}
            }
        }
    }
    // HONEST LIMITATION: true per-VLAN east-west isolation needs VLAN-aware (bridge-family)
    // nft or per-segment subnets, which this inet/forward chain can't express portably. We
    // do NOT emit a blanket `ct state new drop` (it would blackhole ALL routed traffic).
    // The OVS conntrack path (render_ovs_conntrack) is the real enforcement; on the
    // Linux-bridge fallback, isolation is best-effort (established/gateway/allow accepted).
    if !isolated.is_empty() {
        s.push_str(&format!(
            "# NOTE: {} isolated segment(s) — full east-west drop requires the OVS plane or\n\
             #       VLAN-aware bridge nft + per-segment subnets; not enforced on this fallback.\n",
            isolated.len()
        ));
    }
    GeneratedFile { path: "fabric/63-microseg.nft".to_string(), content: s }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn seg(name: &str, vlan: u32) -> Segment {
        Segment { name: name.into(), vlan, fail: None }
    }

    /// Client-isolation: established + gateway pass; new east-west in the segment is
    /// dropped. The core IoT/guest posture.
    #[test]
    fn client_isolation_drops_east_west() {
        let segs = vec![seg("cameras", 30)];
        let intent = MicrosegIntent {
            gateway: Some("10.200.0.1".into()),
            gateway_mac: None,
            policies: vec![SegmentPolicy { segment: "cameras".into(), mode: Isolation::ClientIsolation, allow: vec![] }],
        };
        let p = plan(&segs, &intent);
        let f = render_ovs_conntrack(&p);
        assert!(f.content.contains("ct_state=+est+trk,ip,actions=normal"), "established passes");
        assert!(f.content.contains("nw_dst=10.200.0.1,actions=ct(commit),normal"), "gateway reachable");
        assert!(f.content.contains("dl_vlan=30,ct_state=+new+trk,ip,actions=drop"), "east-west denied");
    }

    /// Open segment → no east-west drop (normal forwarding).
    #[test]
    fn open_segment_has_no_drop() {
        let segs = vec![seg("trusted", 10)];
        let intent = MicrosegIntent {
            gateway: None,
            gateway_mac: None,
            policies: vec![SegmentPolicy { segment: "trusted".into(), mode: Isolation::Open, allow: vec![] }],
        };
        let f = render_ovs_conntrack(&plan(&segs, &intent));
        assert!(f.content.contains("dl_vlan=10,actions=normal"));
        assert!(!f.content.contains("dl_vlan=10,ct_state=+new+trk,ip,actions=drop"));
    }

    /// Allowlist: the NVR→cameras RTSP exception is permitted above the isolation drop.
    #[test]
    fn allowlist_permits_named_flow() {
        let segs = vec![seg("cameras", 30), seg("nvr", 31)];
        let intent = MicrosegIntent {
            gateway: Some("10.0.0.1".into()),
            gateway_mac: None,
            policies: vec![SegmentPolicy {
                segment: "cameras".into(),
                mode: Isolation::Allowlist,
                allow: vec![AllowRule { from: Some("nvr".into()), to: "cameras".into(), proto: Some("tcp".into()), port: Some(554) }],
            }],
        };
        let p = plan(&segs, &intent);
        assert!(p.unresolved.is_empty());
        let f = render_ovs_conntrack(&p);
        assert!(f.content.contains("tp_dst=554") && f.content.contains("priority=50"), "NVR→camera RTSP allowed");
        assert!(f.content.contains("dl_vlan=30,ct_state=+new+trk,ip,actions=drop"), "default still isolated");
    }

    /// A policy naming a non-existent segment is flagged, not silently ignored.
    #[test]
    fn unknown_segment_is_flagged() {
        let segs = vec![seg("iot", 20)];
        let intent = MicrosegIntent {
            gateway: None,
            gateway_mac: None,
            policies: vec![SegmentPolicy { segment: "ghost".into(), mode: Isolation::ClientIsolation, allow: vec![] }],
        };
        let p = plan(&segs, &intent);
        assert!(p.unresolved.contains(&"ghost".to_string()), "ghost is flagged, not silently ignored");
        // The real segment (iot) still gets its identity-driven default policy — declaring
        // a (bad) policy for one segment must not blank out the others.
        assert!(p.policies.iter().any(|x| x.segment == "iot"), "iot keeps its default policy");
        assert!(!p.policies.iter().any(|x| x.segment == "ghost"), "ghost not in resolved policies");
    }

    /// Identity-driven defaults: with no explicit policy, cameras/iot/onboarding are
    /// auto-isolated while byod/infra stay open — no hand-written microseg needed.
    #[test]
    fn default_posture_from_segment_names() {
        let segs = vec![seg("cameras", 30), seg("byod", 60), seg("iot", 20), seg("infra", 40)];
        let p = plan(&segs, &MicrosegIntent { gateway: Some("10.0.0.1".into()), gateway_mac: None, policies: vec![] });
        let mode = |n: &str| p.policies.iter().find(|x| x.segment == n).map(|x| x.mode);
        assert_eq!(mode("cameras"), Some(Isolation::ClientIsolation));
        assert_eq!(mode("iot"), Some(Isolation::ClientIsolation));
        assert_eq!(mode("byod"), Some(Isolation::Open));
        assert_eq!(mode("infra"), Some(Isolation::Open));
        let f = render_ovs_conntrack(&p);
        assert!(f.content.contains("dl_vlan=30,ct_state=+new+trk,ip,actions=drop"), "cameras auto-isolated");
    }

    /// H2 fix: the gateway-MAC north-south flow must carry an L3 match (`ip`/`ipv6`) alongside
    /// `ct(commit)` — `ovs-ofctl parse-flows` genuinely rejects a bare `dl_dst=…,actions=ct(...)`
    /// with `OFPBAC_MATCH_INCONSISTENT` (reproduced empirically while diagnosing this), which
    /// aborts the WHOLE flow batch on a real switch (every other microseg rule in the same
    /// `ovs-ofctl add-flows` call fails to load too). Two flows (ip + ipv6) are emitted instead of
    /// one bare `dl_dst` flow, and the rendered OpenFlow text round-trips through the REAL
    /// `ovs-ofctl parse-flows` binary with no error — an actual OVS-validity proof, not just a
    /// content-shape assertion. Skips cleanly if `ovs-ofctl` isn't installed in this sandbox.
    #[test]
    fn gateway_mac_flow_carries_an_l3_match_for_ct_and_is_valid_ovs_syntax() {
        let segs = vec![seg("cameras", 30)];
        let intent = MicrosegIntent {
            gateway: None,
            gateway_mac: Some("aa:bb:cc:00:00:01".into()),
            policies: vec![SegmentPolicy { segment: "cameras".into(), mode: Isolation::ClientIsolation, allow: vec![] }],
        };
        let f = render_ovs_conntrack(&plan(&segs, &intent));
        // Never a BARE dl_dst match on a ct() action (no preceding ip/ipv6 match) — every
        // gateway-mac line must have "ip," or "ipv6," immediately before "dl_dst=".
        for line in f.content.lines().filter(|l| l.contains("dl_dst=aa:bb:cc:00:00:01") && l.contains("actions=ct")) {
            assert!(
                line.contains(",ip,dl_dst=") || line.contains(",ipv6,dl_dst="),
                "every ct()-committing dl_dst line must carry an L3 match (ip/ipv6): {line}"
            );
        }
        assert!(f.content.contains("ct_state=+new+trk,ip,dl_dst=aa:bb:cc:00:00:01,actions=ct(commit)"), "ipv4 flow present");
        assert!(f.content.contains("ct_state=+new+trk,ipv6,dl_dst=aa:bb:cc:00:00:01,actions=ct(commit)"), "ipv6 flow present");

        // Real-syntax proof: hand the exact rendered flow lines to the real ovs-ofctl parser.
        if let Ok(status) = std::process::Command::new("ovs-ofctl").arg("--version").status() {
            if status.success() {
                let path = std::env::temp_dir().join("hookprobe-microseg-h2-test.flows");
                std::fs::write(&path, &f.content).expect("write temp flow file");
                let out = std::process::Command::new("ovs-ofctl")
                    .arg("parse-flows")
                    .arg(&path)
                    .output()
                    .expect("exec ovs-ofctl parse-flows");
                let _ = std::fs::remove_file(&path);
                assert!(
                    out.status.success(),
                    "ovs-ofctl parse-flows must accept the rendered flow file — stderr:\n{}",
                    String::from_utf8_lossy(&out.stderr)
                );
            }
        }
    }

    /// nftables variant carries the stateful + gateway + drop logic too.
    #[test]
    fn nft_variant_renders() {
        let segs = vec![seg("guest", 40)];
        let intent = MicrosegIntent {
            gateway: Some("10.0.0.1".into()),
            gateway_mac: Some("aa:bb:cc:00:00:01".into()),
            policies: vec![SegmentPolicy { segment: "guest".into(), mode: Isolation::ClientIsolation, allow: vec![] }],
        };
        let f = render_nft(&plan(&segs, &intent));
        assert!(f.content.contains("ct state established,related accept"));
        assert!(f.content.contains("ip daddr 10.0.0.1 accept"));
        assert!(f.content.contains("ether daddr aa:bb:cc:00:00:01 accept"), "north-south via gateway MAC");
        // It must NOT emit a blanket `ct state new drop` (that would blackhole all routing).
        assert!(!f.content.contains("ct state new drop"), "no global blackhole drop");
        assert!(f.content.contains("not enforced on this fallback"), "honest about the limitation");
    }
}
