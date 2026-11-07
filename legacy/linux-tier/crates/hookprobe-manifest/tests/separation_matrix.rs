//! THE ENFORCEMENT-SEPARATION VALIDATION MATRIX (2026-07-07, operator step-3 requirement).
//!
//! A permanent, deterministic gate: "the SOC breaks a legit device" bug class must never ship
//! again undetected. Every assertion below calls a REAL, public enforcement-decision function —
//! never a reimplementation of one — with representative LEGIT and ATTACKER inputs, and asserts
//! the exact verdict. Pass condition: **zero false-drops on legit traffic** (every LEGIT row must
//! render as FORWARD/OBSERVE — never a wire-drop, never a durable block).
//!
//! Companion file: `modules/napse-capture/loader/tests/separation_matrix_frames.rs` owns the
//! RAW-FRAME predicates (`napse_loader::dpi::frame_anomaly_reason_local`/`parse_arp_obs`/
//! `classify_scan_probe`) — this file owns everything from the packet-layer TRACKERS (mac-flood,
//! broadcast-storm, port-scan, beacon, lateral-movement — all defined in `napse-loader`, pulled in
//! here as a dev-dependency so the REAL detector -> REAL responder pipeline is exercised end to
//! end, never a hand-built alert) up through the responder decision functions this crate owns
//! (`scan_responder::decide`, `l2_responder::decide_l2`, `nac::{default_policy,resolve}`,
//! `multi_wan::render_ra_guard_*`, `scan_responder::evaluate_resource_reality`).
//!
//! Every test function is named/labeled so a failure names the exact scenario. Grouped into two
//! `mod`s below: `legit` (must never drop/block) and `attacker` (must reach the CORRECT tri-state
//! action — RateLimit / FrameDrop-or-Quarantine / Observe — per the anti-spoof discipline ADR
//! 0018/0020 already established).

use hookprobe_manifest::l2_responder::{self, decide_l2, L2Verdict, PortRole as MPortRole};
use hookprobe_manifest::multi_wan::{render_ra_guard_netdev, render_ra_guard_nft};
use hookprobe_manifest::nac::{self, DeviceNacDecl, NacPolicy};
use hookprobe_manifest::scan_responder::{
    decide, evaluate_resource_reality, render_conn_rate_cap, ConnRateCapConfig, ProtectPolicy,
    PsiPressure, PsiSnapshot, ReflexVerdict, ResourceRealityConfig, ResourceRealityInputs, DEFAULT_NEW_CONN_PPS,
};

use napse_loader::beacon::{BeaconConfig, BeaconTracker};
use napse_loader::l2guard::{
    BroadcastStormConfig, BroadcastStormTracker, MacFloodConfig, MacFloodTracker, PortRole as LPortRole,
};
use napse_loader::lateral::{LateralConfig, LateralMovementTracker};
use napse_loader::portscan::{PortScanConfig, PortScanTracker};

// A2 / ADR 0027 (IOC → quarantine bridge): the real trust-reconciler decision surface, so the
// separation matrix covers "a customer touching one IOC is never dropped, but a corroborated
// active-IOC threat IS enforced" with the SAME public functions the device runs.
use hookprobe_manifest::trust::{
    build_posture, evaluate_all, intel_signals_from_hydra, ArpEntry, HydraDeviceVerdict, ThreatLevel,
    TrustAction, TrustPolicy,
};

use std::net::Ipv4Addr;

fn mac_str(m: [u8; 6]) -> String {
    format!("{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}", m[0], m[1], m[2], m[3], m[4], m[5])
}

fn rand_mac(i: u8) -> [u8; 6] {
    [0x02, 0x00, 0x00, 0x00, 0x00, i]
}

// =================================================================================================
// LEGIT — must FORWARD / OBSERVE. NEVER a wire-drop, NEVER a durable block.
// =================================================================================================
mod legit {
    use super::*;

    /// ROW: mDNS/SSDP/LLMNR burst (224.0.0.251 / ff02::fb / 239.255.255.250-mapped multicast MACs).
    /// Real function: `napse_loader::l2guard::BroadcastStormTracker::observe` — the exemption lives
    /// HERE (before any alert is even generated), not in `decide_l2` (which has no knowledge of
    /// destination groups at all — it only classifies whatever alert category it's handed). A
    /// burst well past what would otherwise be a storm threshold must produce NO alert at all,
    /// which structurally means it can never reach `L2Verdict::RateLimit`/`FrameDrop`.
    #[test]
    fn mdns_ssdp_llmnr_burst_never_produces_a_broadcast_storm_alert() {
        let mdns_v4: [u8; 6] = [0x01, 0x00, 0x5e, 0x00, 0x00, 0xfb];
        let ssdp_v4: [u8; 6] = [0x01, 0x00, 0x5e, 0x7f, 0xff, 0xfa];
        let llmnr_v4: [u8; 6] = [0x01, 0x00, 0x5e, 0x00, 0x00, 0xfc];
        let src = rand_mac(1);
        for group in [mdns_v4, ssdp_v4, llmnr_v4] {
            let mut t = BroadcastStormTracker::new(BroadcastStormConfig {
                threshold: 20,
                window_secs: 5.0,
                cooldown_secs: 30.0,
                max_sources: 4096,
            });
            for i in 0..200u32 {
                let alert = t.observe(100.0 + i as f64 * 0.01, src, group);
                assert!(
                    alert.is_none(),
                    "a well-known service-discovery multicast burst ({group:02x?}) must never even generate a \
                     broadcast_storm alert — no alert means no path to RateLimit/FrameDrop at all"
                );
            }
        }
    }

    /// ROW: a busy uplink/AP port sees 40 distinct source MACs (completely ordinary churn for a
    /// shared radio/switch uplink). Real function: `napse_loader::l2guard::MacFloodTracker::observe`
    /// (must not even fire on `UplinkBridge`) AND `l2_responder::decide_l2` (must classify
    /// `Observe`, never `RateLimit`, if it somehow did fire).
    #[test]
    fn busy_uplink_forty_distinct_macs_never_rate_limits() {
        let mut t = MacFloodTracker::new(MacFloodConfig { port_role: LPortRole::UplinkBridge, ..Default::default() });
        let mut alert = None;
        for i in 0..40u8 {
            if let Some(a) = t.observe(100.0 + i as f64 * 0.01, rand_mac(i)) {
                alert = Some(a);
            }
        }
        assert!(alert.is_none(), "40 distinct legit client MACs on an uplink/AP port must never even alert");

        // Even if a mac_flood alert HAD fired on this port role, decide_l2 must still never claim
        // a wire-level RateLimit for it — Observe only.
        let manifest_alert = l2_responder::L2Alert {
            ts: 100.0,
            rule_id: l2_responder::MAC_FLOOD_RULE_ID,
            rule_msg: "NAPSE MAC-Flood / MAC-Table Exhaustion Detected".to_string(),
            mitre: "T1498.001".to_string(),
            category: "mac_flood".to_string(),
            severity: 2,
            confidence: 0.9,
            reason: "fanout".to_string(),
            detail: "40 distinct source MACs".to_string(),
            src_mac: None,
            claimed_ip: None,
        };
        let verdict = decide_l2(&manifest_alert, MPortRole::UplinkBridge);
        assert!(
            matches!(verdict, L2Verdict::Observe { .. }),
            "a mac_flood finding on a busy uplink/AP port must decide Observe, never RateLimit: {verdict:?}"
        );
    }

    /// ROW: ARP binding flip-flop. Real function: `l2_responder::decide_l2` — must decide
    /// `Observe` (honest, alert-only; no real stateless wire-level drop mechanism exists for a
    /// cross-packet condition), never `FrameDrop` (which would be a fabricated enforcement claim).
    #[test]
    fn arp_binding_flip_flop_decides_observe_never_frame_drop() {
        let alert = l2_responder::L2Alert {
            ts: 100.0,
            rule_id: l2_responder::ARP_SPOOF_RULE_ID,
            rule_msg: "NAPSE ARP Anomaly Detected".to_string(),
            mitre: "T1557.002".to_string(),
            category: "arp_spoof".to_string(),
            severity: 2,
            confidence: 0.8,
            reason: "binding_flip_flop".to_string(),
            detail: "10.0.0.9 claimed by 3 distinct MACs within 30s".to_string(),
            src_mac: Some("aa:bb:cc:dd:ee:ff".to_string()),
            claimed_ip: Some("10.0.0.9".to_string()),
        };
        let verdict = decide_l2(&alert, MPortRole::Access);
        assert!(matches!(verdict, L2Verdict::Observe { .. }), "binding_flip_flop must decide Observe: {verdict:?}");
        assert!(!matches!(verdict, L2Verdict::FrameDrop { .. }), "must never claim a FrameDrop that doesn't exist");
    }

    /// ROW: an unlisted downstream-router / HomeKit-hub RA (ICMPv6 type 134). Real function:
    /// `multi_wan::render_ra_guard_netdev`/`render_ra_guard_nft` (D16) — an unclassified source
    /// must be observed (logged + accepted), NEVER dropped; the hard drop is reserved for
    /// `confirmed_rogue` only.
    #[test]
    fn unlisted_ra_source_is_observed_accepted_never_dropped() {
        let unlisted_hub_mac = "aa:bb:cc:00:11:22";
        // An actual nft DROP rule (an "add rule ... drop" line) — as opposed to the prose banner
        // comment, which legitimately discusses "hard-dropped"/"first-sight drop" as PROSE
        // explaining the D16 policy, never as a rendered action. This asserts on the real
        // enforcement primitive (an emitted `nft add rule` line), not on comment text.
        fn has_drop_rule_line(content: &str) -> bool {
            content.lines().any(|l| l.trim_start().starts_with("nft add rule") && l.contains(" drop"))
        }

        // Routed AP shape (this device's own default topology).
        let netdev = render_ra_guard_netdev("wlan0", &[], &[]); // no hubs, no confirmed_rogue
        assert!(
            !netdev.content.to_lowercase().contains(&format!("{unlisted_hub_mac} icmpv6 type 134 drop")),
            "an unlisted RA source must never appear on a drop line"
        );
        assert!(netdev.content.contains("icmpv6 type 134 log prefix"), "must observe/log a non-allowlisted RA");
        assert!(netdev.content.contains("accept"), "must accept a non-confirmed-rogue RA (D16 observe-first grace)");
        assert!(!has_drop_rule_line(&netdev.content), "with confirmed_rogue empty, no drop RULE should be rendered at all");

        // Bridged-LAN shape — same D16 policy in the bridge-family renderer.
        let nft = render_ra_guard_nft("hp-br0", &[], &[]);
        assert!(nft.content.contains("icmpv6 type 134 log prefix"));
        assert!(!has_drop_rule_line(&nft.content), "bridged RA-Guard must also never drop an unclassified source");
    }

    /// ROW: a brand-new, not-yet-classified device. Real functions:
    /// `nac::default_policy`/`nac::resolve` (D17) — must resolve to `OnboardingGrace` (full LAN+WAN,
    /// observed/logged), never the old `InternetOnly` stranding-from-LAN default.
    #[test]
    fn brand_new_unclassified_device_gets_onboarding_grace_not_internet_only() {
        assert_eq!(nac::default_policy("totally-unrecognized-class"), NacPolicy::OnboardingGrace);

        let decls = vec![DeviceNacDecl {
            identity: "new-phone".to_string(),
            mac: Some("aa:bb:cc:00:11:22".to_string()),
            class: None, // fingerprinting hasn't classified it yet at all
            policy: None,
            allow: vec![],
            first_seen: None, // just joined — within grace, observe-not-strand (S4)
        }];
        let plan = nac::resolve(&decls, "10.66.0.0/24", "end0");
        let d = plan.devices.iter().find(|d| d.identity == "new-phone").unwrap();
        assert_eq!(d.policy, NacPolicy::OnboardingGrace, "a brand-new unclassified device must get full LAN+WAN reach");
    }

    /// S4: a device that sat unclassified PAST the onboarding grace window reverts to the stricter
    /// InternetOnly default — the separation matrix's "legit new device passes" row is bounded, not
    /// a permanent free pass. (Deterministic `resolve_at` with a pinned clock.)
    #[test]
    fn stale_unclassified_onboarding_device_reverts_to_internet_only_after_grace() {
        let now = 2_000_000.0;
        let decls = vec![DeviceNacDecl {
            identity: "stale-phone".to_string(),
            mac: Some("aa:bb:cc:00:11:33".to_string()),
            class: None,
            policy: None,
            allow: vec![],
            first_seen: Some(now - 25.0 * 3_600.0), // joined 25h ago; 24h grace → expired
        }];
        let plan = nac::resolve_at(&decls, "10.66.0.0/24", "end0", now, nac::DEFAULT_ONBOARDING_GRACE_SECS);
        let d = plan.devices.iter().find(|d| d.identity == "stale-phone").unwrap();
        assert_eq!(d.policy, NacPolicy::InternetOnly, "past grace + still unclassified = revert to the stricter default");
        assert!(d.reason.contains("EXPIRED"), "the reversion must be observable in the reason: {}", d.reason);
    }

    /// ROW: 100 connections all to :443 (CDN fan-out — many DIFFERENT destination IPs, ONE
    /// destination port). Real function: `napse_loader::portscan::PortScanTracker::observe` — keys
    /// strictly on DISTINCT DESTINATION PORTS per source, never distinct destinations, so this
    /// must never produce a port-scan alert.
    #[test]
    fn cdn_fanout_to_port_443_never_trips_the_port_scan_tracker() {
        let mut t = PortScanTracker::new(PortScanConfig::default()); // threshold 50
        let src = Ipv4Addr::new(10, 66, 0, 42);
        let src_mac = rand_mac(9);
        let mut alert = None;
        for i in 0..120u32 {
            // A different CDN edge IP per connection, but always the SAME destination port (443).
            let dst = Ipv4Addr::new(203, 0, 113, (i % 256) as u8);
            if let Some(a) = t.observe(100.0 + i as f64 * 0.01, src, 51000 + (i as u16 % 1000), dst, 443, true, src_mac) {
                alert = Some(a);
            }
        }
        assert!(
            alert.is_none(),
            "100+ connections to many different hosts, all on port 443, must never look like a port scan \
             (the tracker counts distinct DESTINATION PORTS, not destinations)"
        );
    }

    /// ROW: NTP periodic traffic (destination port 123) at a textbook beacon-shaped regular
    /// interval. Real function: `napse_loader::beacon::BeaconTracker::observe` — NTP is
    /// allowlisted by default (FP guard #4) and must never fire, however regular the interval.
    #[test]
    fn ntp_periodic_traffic_is_allowlisted_and_never_fires_the_beacon_detector() {
        let mut t = BeaconTracker::new(BeaconConfig::default());
        let src = Ipv4Addr::new(10, 66, 0, 5);
        let dst = Ipv4Addr::new(132, 163, 96, 1); // pool.ntp.org-shaped
        let src_mac = rand_mac(3);
        for i in 0..20u32 {
            // A textbook-regular 64s interval — exactly the shape that WOULD trip the detector on
            // any non-allowlisted port.
            let alert = t.observe(i as f64 * 64.0, src, dst, 123, src_mac, "udp");
            assert!(alert.is_none(), "NTP (port 123) must be allowlisted and never fire the beacon detector");
        }
    }

    /// ROW: a legit high-but-normal source — 150 concurrent conntrack flows in a table that is
    /// only 40% full, AND CPU/memory PSI comfortably below the sustained-pressure thresholds.
    /// Real function: `scan_responder::evaluate_resource_reality` — must trigger NO shed at all
    /// (the RESOURCE WALL itself was never crossed, regardless of any one source's relative share).
    #[test]
    fn legit_high_but_normal_source_never_triggers_a_resource_shed() {
        let mut ips: Vec<String> = Vec::new();
        for _ in 0..150 {
            ips.push("192.168.1.50".to_string()); // a legit busy NAS/media box: 150 concurrent flows
        }
        for i in 0..10 {
            ips.push(format!("192.168.1.{i}"));
        }
        let inputs = ResourceRealityInputs {
            conntrack_count: Some(40_000), // 40% full — comfortably below the 80% wall
            conntrack_max: Some(100_000),
            conntrack_src_ips: ips,
            psi_cpu: PsiPressure { some: Some(PsiSnapshot { avg10: 20.0, avg60: 18.0, avg300: 15.0, total: 1 }), full: None },
            psi_mem: PsiPressure::default(),
        };
        let triggers = evaluate_resource_reality(&inputs, &ResourceRealityConfig::default());
        assert!(
            triggers.is_empty(),
            "a busy-but-legit source in a table nowhere near saturated, with PSI well below threshold, must never shed; got {triggers:?}"
        );
    }

    /// ROW: a legit source opening ~100 new connections/second (a heavy web page load, a phone
    /// syncing a dozen apps). Real function: `scan_responder::render_conn_rate_cap` (Layer 1's
    /// BLANKET, always-on per-source new-connection ceiling) — the rendered ceiling
    /// (`DEFAULT_NEW_CONN_PPS` = 400/s) must sit comfortably above any such legitimate burst.
    #[test]
    fn legit_hundred_conns_per_second_sits_well_under_the_blanket_conn_rate_cap() {
        let legit_conns_per_sec: u32 = std::hint::black_box(100);
        assert!(
            legit_conns_per_sec < DEFAULT_NEW_CONN_PPS,
            "a legitimate ~100 new-conns/sec burst must sit under the blanket cap ({DEFAULT_NEW_CONN_PPS}/s)"
        );
        let rendered = render_conn_rate_cap(&ConnRateCapConfig::default());
        assert!(
            rendered.content.contains(&format!("limit rate over {DEFAULT_NEW_CONN_PPS}/second")),
            "the real renderer must install the generous blanket ceiling, not a tighter one that would \
             catch a legit 100/s burst"
        );
    }

    /// ROW (A2 / ADR 0027 — IOC → quarantine SEPARATION): a legit CUSTOMER device whose traffic
    /// touches exactly ONE bundled threat-intel IOC (e.g. a shared-hosting/CDN IP that also appears
    /// in a feed) raises a single UNCORROBORATED IntelOnly posture signal. It must NEVER quarantine
    /// — the operator's hard rule is that one intel hit on a customer flow can't drop the customer.
    /// Runs the SAME public reconciler surface the device runs (`intel_signals_from_hydra` →
    /// `build_posture` → `evaluate_all`), placing the invariant in the release-blocking gate (it was
    /// already unit-proven in trust.rs; this is the canonical-matrix coverage the audit found missing).
    #[test]
    fn customer_touching_one_ioc_is_never_quarantined() {
        let arp = vec![ArpEntry { mac: "de:ad:00:00:0a:01".into(), ip: Some("10.66.0.60".into()), online: true }];
        let verdicts = vec![HydraDeviceVerdict {
            device_ip: "10.66.0.60".into(),
            threat: ThreatLevel::Suspicious,
            risk: 40.0,
            enforce: false, // HYDRA's own gate: one signal, not corroborated
            reasons: vec!["IOC 50.16.16.211 (ip)".into()],
        }];
        let intel = intel_signals_from_hydra(&verdicts, &arp, &[], "byod");
        let posture = build_posture(&arp, &[], &intel, &[], "byod");
        let decisions = evaluate_all(&posture, &TrustPolicy::default());
        assert_ne!(
            decisions[0].action, TrustAction::Quarantine,
            "a single/uncorroborated IOC hit must never quarantine a customer"
        );
        assert_eq!(decisions[0].to_segment, "byod", "customer stays in-segment — traffic still passes");
    }
}

// =================================================================================================
// ATTACKER — must get the CORRECT tri-state action (RateLimit / FrameDrop-or-Quarantine / Observe).
// =================================================================================================
mod attacker {
    use super::*;

    /// ROW: access-port mac-flood (`PortRole::Access`, >=20 distinct MACs). Real functions:
    /// `napse_loader::l2guard::MacFloodTracker::observe` (must fire) + `l2_responder::decide_l2`
    /// (must decide `RateLimit` on a genuine access port).
    #[test]
    fn access_port_mac_flood_fires_and_rate_limits() {
        let mut t = MacFloodTracker::new(MacFloodConfig { port_role: LPortRole::Access, ..Default::default() });
        let mut fired_json = None;
        for i in 0..40u8 {
            if let Some(a) = t.observe(100.0 + i as f64 * 0.01, rand_mac(i)) {
                fired_json = Some(a.to_json());
            }
        }
        let json = fired_json.expect("40 distinct MACs on a genuine ACCESS port must fire mac_flood");
        let manifest_alert = l2_responder::parse_l2_alert(&json).expect("must parse the real emitted schema");
        let verdict = decide_l2(&manifest_alert, MPortRole::Access);
        assert!(matches!(verdict, L2Verdict::RateLimit { .. }), "an access-port mac-flood must RateLimit: {verdict:?}");
    }

    /// ROW: a multi-HUNDRED-MAC flood, even on an `UplinkBridge` port (the sharply-higher uplink
    /// bar), must still be DETECTED (never silently swallowed). Real function:
    /// `MacFloodTracker::observe` — fires at the uplink threshold (300). Per this codebase's
    /// deliberate D12 design (an operator rule: "a legit customer connection must ALWAYS pass" on a
    /// fan-out port), `decide_l2` still renders `Observe` — not a wire-level `RateLimit` — for
    /// this port role; the CORRECT action here is "detected, logged, no risk of dropping a
    /// legitimate AP client", which is exactly what `Observe` means. Labeled explicitly so this
    /// nuance is never mistaken for a miss.
    #[test]
    fn multi_hundred_mac_flood_on_uplink_bridge_still_fires_the_detector_and_is_observed() {
        let mut t = MacFloodTracker::new(MacFloodConfig { port_role: LPortRole::UplinkBridge, ..Default::default() });
        let mut fired_json = None;
        'outer: for hi in 0..3u8 {
            for lo in 0..=255u8 {
                if let Some(a) = t.observe(100.0, [0x02, 0x00, 0x00, 0x00, hi, lo]) {
                    fired_json = Some(a.to_json());
                    break 'outer;
                }
            }
        }
        let json = fired_json.expect("a genuine multi-hundred-MAC flood must still fire even on an uplink/AP port");
        let manifest_alert = l2_responder::parse_l2_alert(&json).expect("must parse");
        let verdict = decide_l2(&manifest_alert, MPortRole::UplinkBridge);
        assert!(
            matches!(verdict, L2Verdict::Observe { .. }),
            "by design (D12), an UplinkBridge port's mac-flood is Observe — detected/logged, never a \
             wire-level cap that could drop legitimate AP clients: {verdict:?}"
        );
    }

    /// ROW: a non-exempt broadcast/multicast flood (a raw `ff:ff:ff:ff:ff:ff` storm — NOT one of
    /// the named service-discovery groups). Real functions: `BroadcastStormTracker::observe` (must
    /// fire) + `l2_responder::decide_l2` (must decide `RateLimit`).
    #[test]
    fn non_exempt_broadcast_flood_fires_and_rate_limits() {
        let bcast = [0xff, 0xff, 0xff, 0xff, 0xff, 0xff];
        let mut t = BroadcastStormTracker::new(BroadcastStormConfig { threshold: 50, window_secs: 5.0, cooldown_secs: 30.0, max_sources: 4096 });
        let mut fired_json = None;
        for i in 0..60u32 {
            if let Some(a) = t.observe(100.0 + i as f64 * 0.01, rand_mac(7), bcast) {
                fired_json = Some(a.to_json());
            }
        }
        let json = fired_json.expect("a raw broadcast flood must fire broadcast_storm");
        let manifest_alert = l2_responder::parse_l2_alert(&json).expect("must parse");
        let verdict = decide_l2(&manifest_alert, MPortRole::Access);
        assert!(matches!(verdict, L2Verdict::RateLimit { .. }), "a non-exempt broadcast flood must RateLimit: {verdict:?}");
    }

    /// ROW: a SYN scan, unconfirmed (no validated 3-way handshake), at least 50 distinct ports.
    /// Real functions: `napse_loader::portscan::PortScanTracker::observe` (must fire, at least 50
    /// distinct ports) and `scan_responder::decide` (must decide `RateLimit` — a bounded,
    /// self-reverting cap, never a durable identity `Quarantine`, per ADR 0018's anti-spoof
    /// discipline).
    #[test]
    fn unconfirmed_syn_scan_over_fifty_ports_rate_limits_never_quarantines() {
        let mut t = PortScanTracker::new(PortScanConfig::default());
        let src = Ipv4Addr::new(203, 0, 113, 9);
        let src_mac = rand_mac(4);
        let mut alert = None;
        for port in 1..=60u16 {
            if let Some(a) = t.observe(100.0 + port as f64 * 0.01, src, 51000, Ipv4Addr::new(198, 51, 100, 5), port, true, src_mac) {
                alert = Some(a);
            }
        }
        let alert = alert.expect("60 distinct SYN-only ports must trip the >=50 threshold");
        assert!(alert.distinct_ports >= 50);

        let policy = ProtectPolicy::default();
        let verdict = decide(&src.to_string(), "198.51.100.5", alert.distinct_ports, false, Some(&mac_str(src_mac)), &policy, &[]);
        assert!(
            matches!(verdict, ReflexVerdict::RateLimit { .. }),
            "an unconfirmed SYN fan-out must RateLimit (bounded, self-reverting), never Quarantine (durable): {verdict:?}"
        );
    }

    /// ROW: the SAME fan-out, but this time CONFIRMED (a validated 3-way handshake — either the
    /// mirror-fed `HandshakeTracker` or an independent conntrack-ESTABLISHED signal). Real
    /// function: `scan_responder::decide` — must decide `Quarantine` (durable, via the existing
    /// `trust::evaluate` reconciler).
    #[test]
    fn confirmed_syn_scan_over_fifty_ports_quarantines() {
        let mut t = PortScanTracker::new(PortScanConfig::default());
        let src = Ipv4Addr::new(203, 0, 113, 10);
        let src_mac = rand_mac(5);
        let mut alert = None;
        for port in 1..=60u16 {
            if let Some(a) = t.observe(100.0 + port as f64 * 0.01, src, 51000, Ipv4Addr::new(198, 51, 100, 5), port, true, src_mac) {
                alert = Some(a);
            }
        }
        let alert = alert.expect("60 distinct SYN-only ports must trip the threshold");

        let policy = ProtectPolicy::default();
        let verdict = decide(&src.to_string(), "198.51.100.5", alert.distinct_ports, true, Some(&mac_str(src_mac)), &policy, &[]);
        assert!(matches!(verdict, ReflexVerdict::Quarantine { .. }), "a CONFIRMED >=50-port scan must Quarantine: {verdict:?}");
    }

    /// ROW: FIN/NULL/XMAS stealth scan shapes — these never complete a real TCP handshake by
    /// construction (an open port silently ignores them; a closed one RSTs), so
    /// `confirm::HandshakeTracker` structurally can never confirm one. Real functions:
    /// `napse_loader::dpi::classify_scan_probe` (proven in the frame-level companion file to
    /// recognize all three shapes) + `scan_responder::decide` with `confirmed=false` — must decide
    /// `RateLimit`, the same bounded cap an unconfirmed SYN scan gets.
    #[test]
    fn fin_null_xmas_scan_never_confirmed_and_rate_limits() {
        let policy = ProtectPolicy::default();
        let verdict = decide("203.0.113.11", "198.51.100.5", 60, false, Some("aa:bb:cc:dd:ee:ff"), &policy, &[]);
        assert!(
            matches!(verdict, ReflexVerdict::RateLimit { .. }),
            "FIN/NULL/XMAS probes never complete a handshake, so this must RateLimit like any unconfirmed scan: {verdict:?}"
        );
    }

    /// ROW: connection-flood / conntrack saturation — table 85% full, ONE source responsible for
    /// 500 concurrent flows. Real function: `scan_responder::evaluate_resource_reality` — must
    /// shed/cap exactly that source.
    #[test]
    fn conntrack_saturation_from_a_single_flood_source_triggers_a_shed() {
        let mut ips: Vec<String> = Vec::new();
        for _ in 0..500 {
            ips.push("203.0.113.9".to_string());
        }
        for i in 0..10 {
            ips.push(format!("192.168.1.{i}"));
        }
        let inputs = ResourceRealityInputs {
            conntrack_count: Some(85_000), // 85% full — over the 80% wall
            conntrack_max: Some(100_000),
            conntrack_src_ips: ips,
            psi_cpu: PsiPressure::default(),
            psi_mem: PsiPressure::default(),
        };
        let triggers = evaluate_resource_reality(&inputs, &ResourceRealityConfig::default());
        assert_eq!(triggers.len(), 1, "only the genuine flood source should trigger: {triggers:?}");
        assert_eq!(triggers[0].ip, "203.0.113.9");
        assert_eq!(triggers[0].signal, "conntrack_saturation");
    }

    /// ROW: sustained PSI pressure (CPU `some avg60` >= 40%) with an attributable top-talker. Real
    /// function: `scan_responder::evaluate_resource_reality` — must shed the highest-volume source.
    #[test]
    fn sustained_psi_pressure_with_an_attributable_top_talker_triggers_a_shed() {
        let mut ips: Vec<String> = Vec::new();
        for _ in 0..20 {
            ips.push("203.0.113.20".to_string());
        }
        ips.push("192.168.1.7".to_string());
        let inputs = ResourceRealityInputs {
            conntrack_count: None,
            conntrack_max: None,
            conntrack_src_ips: ips,
            psi_cpu: PsiPressure { some: Some(PsiSnapshot { avg10: 45.0, avg60: 45.0, avg300: 40.0, total: 1 }), full: None },
            psi_mem: PsiPressure::default(),
        };
        let triggers = evaluate_resource_reality(&inputs, &ResourceRealityConfig::default());
        assert_eq!(triggers.len(), 1);
        assert_eq!(triggers[0].ip, "203.0.113.20", "the highest-volume source must be capped");
        assert_eq!(triggers[0].signal, "psi_cpu");
    }

    /// ROW: a confirmed-rogue RA source. Real function: `multi_wan::render_ra_guard_netdev`/
    /// `render_ra_guard_nft` — must hard-drop (unlike the unlisted-source LEGIT row above).
    #[test]
    fn confirmed_rogue_ra_source_is_dropped() {
        let rogue_mac = "de:ad:be:ef:00:13".to_string();
        let netdev = render_ra_guard_netdev("wlan0", &[], std::slice::from_ref(&rogue_mac));
        assert!(
            netdev.content.contains(&format!("ether saddr {rogue_mac} icmpv6 type 134 drop")),
            "a CONFIRMED rogue RA source must be hard-dropped"
        );
        let nft = render_ra_guard_nft("hp-br0", &[], std::slice::from_ref(&rogue_mac));
        assert!(nft.content.contains(&format!("ether saddr {rogue_mac} icmpv6 type 134 drop")));
    }

    /// ROW: a lateral-movement / C2-beaconing shaped alert must remain alert-only — there is no
    /// enforcement consumer for either `BeaconAlert` or `LateralAlert` anywhere in this crate's
    /// responder surface (`scan_responder::decide`, `l2_responder::decide_l2`,
    /// `nac::{default_policy,resolve}` — the only three enforcement-decision functions this crate
    /// exposes — none accept a beacon/lateral alert type at all; Rust's type system makes it a
    /// compile error to even attempt it). This test positively proves BOTH detectors genuinely
    /// fire on their textbook-shaped patterns (so "alert-only" is a deliberate design, not a
    /// detection gap) and documents, rather than fakes, the "no enforcement consumer" half — see
    /// this test's own doc for why that half is a structural/source-audit fact, not something a
    /// single runtime assertion can exercise (an ABSENCE of a code path cannot be invoked).
    #[test]
    fn lateral_movement_and_c2_beacon_findings_are_detected_but_never_reach_an_enforcement_function() {
        // --- C2 beacon: a metronomic 64s check-in to one internal-looking "C2" destination/port.
        let mut bt = BeaconTracker::new(BeaconConfig::default());
        let mut beacon_fired = false;
        for i in 0..12u32 {
            if bt
                .observe(i as f64 * 64.0, Ipv4Addr::new(10, 66, 0, 40), Ipv4Addr::new(198, 51, 100, 77), 8443, rand_mac(8), "tcp")
                .is_some()
            {
                beacon_fired = true;
            }
        }
        assert!(beacon_fired, "a textbook metronomic beacon pattern must fire (proves this isn't a detection gap)");

        // --- Lateral movement: one internal source fanning out across 6 distinct internal peers
        // on admin ports within the short window.
        let mut lt = LateralMovementTracker::new(LateralConfig::default());
        let mut lateral_fired = false;
        for i in 0..6u8 {
            let dst = Ipv4Addr::new(10, 66, 0, 100 + i);
            if lt.observe(100.0 + i as f64, Ipv4Addr::new(10, 66, 0, 9), dst, 445, rand_mac(10)).is_some() {
                lateral_fired = true;
            }
        }
        assert!(lateral_fired, "a textbook lateral-movement sweep pattern must fire (proves this isn't a detection gap)");

        // "No enforcement consumer" (the alert-only half): verified by SOURCE AUDIT, not a runtime
        // call — `grep -rln "BeaconAlert\|LateralAlert" --include=*.rs` across this workspace
        // (checked 2026-07-07) shows the ONLY consumer of either type is
        // `modules/napse-capture/loader/src/bin/napse-dpi.rs` (which serializes them straight to
        // the events stream) — neither `scan_responder.rs`, `l2_responder.rs`, nor `nac.rs`
        // reference either type at all. This is flagged explicitly, per this matrix's own
        // instructions, rather than faked as a callable-function assertion.
    }

    /// ROW (A2 / ADR 0027 — IOC → quarantine SEPARATION, attacker half): a device with a genuinely
    /// ACTIVE IOC hit PLUS corroboration — HYDRA's own gate already set `enforce=true` because it
    /// crossed `min_distinct_signals` AND the quarantine score (e.g. IOC IP + C2-beacon rule
    /// 1000040) — MUST be enforceable: quarantined into the isolation segment. This is the other
    /// half of the customer/attacker pair in `mod legit`: "never drop a customer on one hit" is NOT
    /// "never drop" — a confirmed, corroborated, active threat still gets moved. Same public surface
    /// (`intel_signals_from_hydra` → `build_posture` → `evaluate_all`) the device runs.
    #[test]
    fn corroborated_active_ioc_threat_is_quarantined() {
        let arp = vec![ArpEntry { mac: "de:ad:00:00:0a:02".into(), ip: Some("10.66.0.61".into()), online: true }];
        let verdicts = vec![HydraDeviceVerdict {
            device_ip: "10.66.0.61".into(),
            threat: ThreatLevel::Malicious,
            risk: 82.0,
            enforce: true, // HYDRA gate: active IOC hit + C2-beacon corroboration crossed the bar
            reasons: vec!["IOC 50.16.16.211 (ip)".into(), "corroboration: C2 beaconing".into()],
        }];
        let intel = intel_signals_from_hydra(&verdicts, &arp, &[], "byod");
        let posture = build_posture(&arp, &[], &intel, &[], "byod");
        let decisions = evaluate_all(&posture, &TrustPolicy::default());
        assert_eq!(
            decisions[0].action, TrustAction::Quarantine,
            "a corroborated, genuinely-active IOC threat must remain enforceable"
        );
        assert_eq!(decisions[0].to_segment, "quarantine");
    }
}
