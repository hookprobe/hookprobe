//! `hookprobe-manifest` — shared library for the HookProbe OS bootstrap and supervisor.
//!
//! Contains:
//! - Schema-2 manifest serde types (ADR 0003)
//! - Platform YAML + module.yaml types
//! - Classifier, capability mapper, resource allocator, retention computer
//! - Manifest builder
//! - Supervisor reconciler

pub mod aegis;
pub mod builder;
pub mod capabilities;
pub mod claim;
pub mod classify;
pub mod crypto;
pub mod fabric;
pub mod fingerprint;
pub mod fleet;
pub mod health;
pub mod identity;
pub mod inspect;
pub mod l2_responder;
pub mod lan;
pub mod module_def;
pub mod md5;
pub mod microseg;
pub mod module_sig;
pub mod multi_wan;
pub mod nac;
pub mod net_roles;
pub mod platform;
pub mod resource_budget;
pub mod resources;
pub mod scan;
pub mod scan_responder;
pub mod sd_notify;
pub mod storage;
pub mod supervisor;
pub mod trust;
pub mod types;
pub mod wifi_calibrate;
pub mod wifi_cfg;
pub mod xdp;

// Re-export the most commonly used public surface.
pub use builder::build_manifest;
pub use classify::{classify, load_platforms};
pub use supervisor::reconcile;
pub use types::Manifest;

// ---------------------------------------------------------------------------
// Tests — lock the behavior of all three fixture platforms.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use crate::builder::build_manifest;
    use crate::capabilities::map_capabilities;
    use crate::module_def::ModuleDef;
    use crate::scan::{ScanInterface, ScanProfile};
    use crate::supervisor::reconcile;
    use crate::types::{CapabilityState, CpuMem, InterfaceRole, InterfaceType, Manifest};

    // Fixture JSON (probert scanner output).
    const RK3588_FIXTURE: &str =
        include_str!("../../../manifest/fixtures/rk3588.profile.json");
    const N100_FIXTURE: &str =
        include_str!("../../../manifest/fixtures/n100.profile.json");
    const UNKNOWN_FIXTURE: &str =
        include_str!("../../../manifest/fixtures/unknown.profile.json");

    // Platform YAML specs.
    const RK3588_PLATFORM: &str = include_str!("../../../platforms/rk3588.yaml");
    const N100_PLATFORM: &str = include_str!("../../../platforms/n100.yaml");
    const GENERIC_PLATFORM: &str = include_str!("../../../platforms/generic.yaml");
    const RPI4_PLATFORM: &str = include_str!("../../../platforms/rpi4.yaml");
    const RPI5_PLATFORM: &str = include_str!("../../../platforms/rpi5.yaml");
    const CLOUD_PLATFORM: &str = include_str!("../../../platforms/cloud.yaml");

    // Module definitions.
    const NAPSE_MODULE: &str = include_str!("../../../modules/napse/module.yaml");
    const HYDRA_MODULE: &str = include_str!("../../../modules/hydra/module.yaml");
    const EDGE_AI_MODULE: &str = include_str!("../../../modules/edge-ai-detector/module.yaml");
    const INLINE_GUARD_MODULE: &str = include_str!("../../../modules/inline-guard/module.yaml");

    // Helpers ----------------------------------------------------------------

    fn parse_scan(fixture_json: &str) -> crate::scan::HardwareScan {
        let profile: ScanProfile = serde_json::from_str(fixture_json).expect("parse fixture");
        profile.scan
    }

    fn parse_platform(yaml: &str) -> crate::platform::PlatformSpec {
        serde_yaml::from_str(yaml).expect("parse platform yaml")
    }

    fn parse_module(yaml: &str) -> ModuleDef {
        serde_yaml::from_str(yaml).expect("parse module yaml")
    }

    fn all_modules() -> Vec<ModuleDef> {
        // The real supervisor performs cosign-style verification and records the verdict in
        // `sig_verified` BEFORE calling reconcile(); these tests exercise reconcile directly,
        // so mark the modules verified (the dedicated `unverified_required_module_is_refused`
        // test sets Some(false) to cover the fail-closed path).
        [NAPSE_MODULE, HYDRA_MODULE, EDGE_AI_MODULE, INLINE_GUARD_MODULE]
            .iter()
            .map(|m| {
                let mut d = parse_module(m);
                d.sig_verified = Some(true);
                d
            })
            .collect()
    }

    // -----------------------------------------------------------------------
    // Capability mapping tests
    // -----------------------------------------------------------------------

    /// rk3588: inline_ips must be present_unsafe (stmmac not in known_good list).
    #[test]
    fn rk3588_inline_ips_present_unsafe() {
        let scan = parse_scan(RK3588_FIXTURE);
        let platform = parse_platform(RK3588_PLATFORM);
        let caps = map_capabilities(&scan, &platform);
        let cap = caps.get("inline_ips").expect("inline_ips present");
        assert_eq!(
            cap.state,
            CapabilityState::PresentUnsafe,
            "rk3588 inline_ips should be present_unsafe (stmmac not known-good), got {:?}",
            cap
        );
    }

    /// n100: inline_ips must be granted (igc is on the known_good list).
    #[test]
    fn n100_inline_ips_granted() {
        let scan = parse_scan(N100_FIXTURE);
        let platform = parse_platform(N100_PLATFORM);
        let caps = map_capabilities(&scan, &platform);
        let cap = caps.get("inline_ips").expect("inline_ips present");
        assert_eq!(
            cap.state,
            CapabilityState::Granted,
            "n100 inline_ips should be granted (igc known-good), got {:?}",
            cap
        );
    }

    /// n100: edge_ai must be absent (no NPU present).
    #[test]
    fn n100_edge_ai_absent() {
        let scan = parse_scan(N100_FIXTURE);
        let platform = parse_platform(N100_PLATFORM);
        let caps = map_capabilities(&scan, &platform);
        let cap = caps.get("edge_ai").expect("edge_ai present");
        assert_eq!(
            cap.state,
            CapabilityState::Absent,
            "n100 edge_ai should be absent (no NPU), got {:?}",
            cap
        );
    }

    /// generic class: the SOFTWARE-only SOC baseline is granted (soc, ids, host_telemetry,
    /// dns_filtering, threat_intel — so an unrecognized box still runs a full local SOC);
    /// every HARDWARE / DATA-PATH-gated capability stays withheld until a real profile
    /// validates the silicon.
    #[test]
    fn generic_grants_software_soc_baseline_and_withholds_hardware_features() {
        let scan = parse_scan(UNKNOWN_FIXTURE);
        let platform = parse_platform(GENERIC_PLATFORM);
        let caps = map_capabilities(&scan, &platform);

        // The exact software SOC baseline that MUST be granted on unknown hardware.
        const SOFTWARE_BASELINE: &[&str] = &["soc", "ids", "host_telemetry", "dns_filtering", "threat_intel"];

        let granted: Vec<&str> = caps
            .iter()
            .filter(|(_, c)| c.state == CapabilityState::Granted)
            .map(|(k, _)| k.as_str())
            .collect();

        for want in SOFTWARE_BASELINE {
            assert!(
                granted.contains(want),
                "generic must grant software-SOC capability '{want}', got granted={granted:?}"
            );
        }
        // Nothing OUTSIDE the software baseline may be granted (no hardware/datapath auto-grant).
        for cap in &granted {
            assert!(
                SOFTWARE_BASELINE.contains(cap),
                "generic class granted a non-baseline (hardware/datapath) capability: {cap}"
            );
        }
        // Spot-check the honest withholds: XDP capture + edge_ai must NOT be granted.
        assert_ne!(caps["capture"].state, CapabilityState::Granted, "generic must withhold XDP capture");
        assert_ne!(caps["edge_ai"].state, CapabilityState::Granted, "generic must withhold edge_ai");
    }

    /// HONESTY: on a platform WITH NPU silicon but NO loaded driver, edge_ai is withheld
    /// with an accurate reason ("NPU present but its driver is not loaded"), NEVER the
    /// fabricated "no NPU present". Locks the no-fabricated-capabilities discipline.
    #[test]
    fn edge_ai_reason_distinguishes_missing_driver_from_missing_silicon() {
        // rk3588 profile + a scan where the NPU is present but the driver is NOT ready.
        let mut scan = parse_scan(RK3588_FIXTURE);
        scan.npu.present = true;
        scan.npu.driver_ready = false;
        let platform = parse_platform(RK3588_PLATFORM);
        let caps = map_capabilities(&scan, &platform);
        let cap = caps.get("edge_ai").expect("edge_ai present");
        assert_eq!(cap.state, CapabilityState::Absent, "no driver ⇒ edge_ai absent");
        let reason = cap.reason.as_deref().unwrap_or("");
        assert!(
            reason.contains("driver is not loaded"),
            "reason must name the missing driver, got: {reason:?}"
        );
        assert!(
            !reason.contains("no NPU"),
            "must NOT fabricate 'no NPU present' when silicon IS present, got: {reason:?}"
        );

        // And the truly-empty case still reports honestly.
        scan.npu.present = false;
        let caps2 = map_capabilities(&scan, &platform);
        assert_eq!(
            caps2["edge_ai"].reason.as_deref(),
            Some("no NPU/accelerator present"),
            "no silicon ⇒ 'no NPU/accelerator present'"
        );
    }

    /// Helper: a minimal-but-valid ethernet `ScanInterface` with `hw_timestamping` set,
    /// for the `ptp_hw` end-to-end reachability tests below.
    fn eth_iface(name: &str, hw_timestamping: bool) -> ScanInterface {
        ScanInterface {
            name: name.to_string(),
            mac: None,
            iface_type: InterfaceType::Ethernet,
            driver: Some("macb".to_string()),
            supported_modes: vec![],
            role: InterfaceRole::Unassigned,
            fail_mode: None,
            state: "up".to_string(),
            bus: None,
            onboard: true,
            band: None,
            hw_timestamping,
        }
    }

    /// End-to-end (base-tier-build-ticket.md Phase 3, ADR 0031 §B): `ptp_hw` GRANTS once the
    /// scan carries a real per-interface `hw_timestamping=true` fact (what
    /// `bootstrap::probe::ethtool_hw_timestamping` writes on a real device that passes the
    /// Phase-0 §5 metal gate) — no longer the hardcoded `present_unsafe` stub.
    #[test]
    fn rpi5_ptp_hw_granted_when_hw_timestamping_fact_true() {
        let mut scan = parse_scan(RK3588_FIXTURE);
        scan.interfaces = vec![eth_iface("end0", true)];
        let platform = parse_platform(RPI5_PLATFORM);
        let caps = map_capabilities(&scan, &platform);
        let cap = caps.get("ptp_hw").expect("ptp_hw present");
        assert_eq!(
            cap.state,
            CapabilityState::Granted,
            "ptp_hw should be granted when ethtool -T confirms hw rx/tx timestamping + PHC, got {:?}",
            cap
        );
        assert!(
            cap.evidence.iter().any(|e| e.contains("end0")),
            "evidence should name the confirmed interface, got {:?}",
            cap.evidence
        );
    }

    /// HONESTY (mirrors `edge_ai_reason_distinguishes_missing_driver_from_missing_silicon`):
    /// with an ethernet interface scanned but `hw_timestamping=false` (ethtool ran and found
    /// no hardware rx/tx timestamping / no bound PHC), `ptp_hw` stays withheld — `Absent`,
    /// never a fabricated `Granted` — with a reason naming the ethtool finding.
    #[test]
    fn rpi5_ptp_hw_absent_when_hw_timestamping_fact_false() {
        let mut scan = parse_scan(RK3588_FIXTURE);
        scan.interfaces = vec![eth_iface("end0", false)];
        let platform = parse_platform(RPI5_PLATFORM);
        let caps = map_capabilities(&scan, &platform);
        let cap = caps.get("ptp_hw").expect("ptp_hw present");
        assert_eq!(
            cap.state,
            CapabilityState::Absent,
            "ptp_hw must stay withheld (conservative default) when the scan fact is false, got {:?}",
            cap
        );
        let reason = cap.reason.as_deref().unwrap_or("");
        assert!(
            reason.contains("hardware rx/tx timestamping"),
            "reason should name the ethtool finding, got {:?}",
            reason
        );
    }

    /// HONESTY: the withheld reason distinguishes "no wired ethernet interface at all" from
    /// "ethernet scanned but none confirmed hw timestamping" — same discriminating-reason
    /// discipline as `edge_ai`'s "no NPU" vs "NPU present but driver not loaded".
    #[test]
    fn rpi5_ptp_hw_reason_distinguishes_no_ethernet_from_unconfirmed_hw_timestamping() {
        let platform = parse_platform(RPI5_PLATFORM);

        let mut scan_no_eth = parse_scan(RK3588_FIXTURE);
        scan_no_eth.interfaces = vec![];
        let caps_no_eth = map_capabilities(&scan_no_eth, &platform);
        assert_eq!(caps_no_eth["ptp_hw"].state, CapabilityState::Absent);
        assert!(
            caps_no_eth["ptp_hw"]
                .reason
                .as_deref()
                .unwrap_or("")
                .contains("no wired ethernet interface"),
            "got {:?}",
            caps_no_eth["ptp_hw"].reason
        );

        let mut scan_unconfirmed = parse_scan(RK3588_FIXTURE);
        scan_unconfirmed.interfaces = vec![eth_iface("end0", false)];
        let caps_unconfirmed = map_capabilities(&scan_unconfirmed, &platform);
        assert_eq!(caps_unconfirmed["ptp_hw"].state, CapabilityState::Absent);
        assert!(
            !caps_unconfirmed["ptp_hw"]
                .reason
                .as_deref()
                .unwrap_or("")
                .contains("no wired ethernet interface"),
            "must NOT fabricate 'no wired ethernet' when an ethernet iface WAS scanned, got {:?}",
            caps_unconfirmed["ptp_hw"].reason
        );
    }

    // -----------------------------------------------------------------------
    // Retirement audit #8 (2026-07-08): `hardware_validated`/`validation_note` honesty
    // marker tests — only `rpi4` has a real on-silicon boot+selftest gate record
    // (docs/roadmap/BuildPlan.md); every other shipping profile is classification-tested only
    // and must say so, never imply parity it hasn't earned.
    // -----------------------------------------------------------------------

    /// rpi4 is the ONLY profile with a real on-silicon boot-gate record — must be `true`.
    #[test]
    fn rpi4_is_the_only_profile_marked_hardware_validated() {
        let rpi4 = parse_platform(RPI4_PLATFORM);
        assert!(rpi4.hardware_validated, "rpi4 has a real Pi4 boot-gate record — must be true");
        assert!(
            rpi4.validation_note.as_deref().unwrap_or("").to_lowercase().contains("silicon")
                || rpi4.validation_note.as_deref().unwrap_or("").to_lowercase().contains("pi4"),
            "rpi4's validation_note should name the real boot-gate evidence, got {:?}",
            rpi4.validation_note
        );
    }

    /// Every other shipping profile is classification-tested only — must default/say `false`
    /// with an honest note, never claim a boot-gate record it does not have.
    #[test]
    fn every_other_shipping_profile_is_honestly_marked_not_hardware_validated() {
        for (name, yaml) in [
            ("rpi5", RPI5_PLATFORM),
            ("rk3588", RK3588_PLATFORM),
            ("n100", N100_PLATFORM),
            ("cloud", CLOUD_PLATFORM),
            ("generic", GENERIC_PLATFORM),
        ] {
            let spec = parse_platform(yaml);
            assert!(
                !spec.hardware_validated,
                "{name} has no on-silicon boot-gate record and must not claim hardware_validated=true"
            );
            let note = spec.validation_note.as_deref().unwrap_or("");
            assert!(
                !note.is_empty(),
                "{name} should carry a validation_note explaining the false verdict"
            );
        }
    }

    /// Schema-compatibility / backward-honesty: a platform YAML written BEFORE this field
    /// existed (no `hardware_validated`/`validation_note` keys at all) must still parse, and
    /// must default to the honest `false` — never silently claim validation it never declared.
    #[test]
    fn hardware_validated_defaults_to_false_when_absent_from_yaml() {
        let minimal = r#"
profile: pre-existing
class: generic
sku: null
match:
  method: fallback
crypto_suite: hookprobe-pqc-hybrid-2026
"#;
        let spec: crate::platform::PlatformSpec =
            serde_yaml::from_str(minimal).expect("must still parse without the new field");
        assert!(!spec.hardware_validated, "absent field must default to false, not fabricate true");
        assert!(spec.validation_note.is_none());
    }

    // -----------------------------------------------------------------------
    // Reconciler tests
    // -----------------------------------------------------------------------

    /// Build a minimal manifest from a fixture + platform and run the supervisor.
    fn manifest_for(fixture: &str, platform_yaml: &str) -> Manifest {
        let scan = parse_scan(fixture);
        let platform = parse_platform(platform_yaml);
        build_manifest(
            &scan,
            &platform,
            &crate::types::MatchInfo {
                method: crate::types::MatchMethod::Fallback,
                key: "test".to_string(),
            },
            "2026-01-01T00:00:00Z",
            "ghcr.io/hookprobe/os:test",
            &format!("sha256:{}", "0".repeat(64)),
        )
        .expect("build_manifest")
    }

    /// The signed manifest carries the "Get Online" uplink list, in failover order,
    /// wired first. This is what the console + multi-WAN reconciler read.
    #[test]
    fn manifest_carries_uplinks_in_failover_order() {
        let m = manifest_for(N100_FIXTURE, N100_PLATFORM);
        assert!(!m.network.uplinks.is_empty(), "N100 must surface uplinks");
        // Priorities are non-decreasing (already sorted) and the first is wired.
        let prios: Vec<u32> = m.network.uplinks.iter().map(|u| u.priority).collect();
        let mut sorted = prios.clone();
        sorted.sort();
        assert_eq!(prios, sorted, "uplinks must be in failover (priority) order");
        assert_eq!(m.network.uplinks[0].kind, "wired", "wired is the preferred uplink");
    }

    /// Idempotency: running reconcile a second time (with already-running modules
    /// in manifest.modules[]) produces only "already running (no-op)" outcomes —
    /// nothing is newly loaded.
    #[test]
    fn reconcile_is_idempotent() {
        let mut manifest = manifest_for(N100_FIXTURE, N100_PLATFORM);
        let modules = all_modules();

        // First reconcile: loads some modules.
        let report1 = reconcile(&mut manifest, &modules);
        let loaded_count = report1.iter().filter(|r| r.state == crate::supervisor::OutcomeState::Running).count();
        assert!(loaded_count > 0, "first reconcile should load at least one module");

        // Second reconcile: must be a no-op (all running = "already running").
        let report2 = reconcile(&mut manifest, &modules);
        for outcome in &report2 {
            if outcome.state == crate::supervisor::OutcomeState::Running {
                assert_eq!(
                    outcome.detail, "already running (no-op)",
                    "second reconcile: module '{}' should be no-op, got: {}",
                    outcome.id, outcome.detail
                );
            }
        }
    }

    /// An over-budget module must be refused.
    ///
    /// We set allocatable cpu_pct=1, memory_mb=1 so that all modules with
    /// real resource requirements are refused for budget reasons.
    #[test]
    fn over_budget_module_is_refused() {
        let mut manifest = manifest_for(N100_FIXTURE, N100_PLATFORM);
        // Crush the allocatable budget so nothing can fit.
        manifest.resources.allocatable = CpuMem { cpu_pct: 1, memory_mb: 1 };

        let modules = all_modules();
        let report = reconcile(&mut manifest, &modules);

        // Every module that passes capability checks must be refused for budget.
        let refused: Vec<_> = report
            .iter()
            .filter(|r| r.state == crate::supervisor::OutcomeState::Refused)
            .collect();
        assert!(
            !refused.is_empty(),
            "expected at least one budget refusal, got report: {:?}",
            report.iter().map(|r| (&r.id, &r.detail)).collect::<Vec<_>>()
        );
        // napse (requires soc+ids, both granted on n100) must be refused for budget.
        let napse_outcome = report.iter().find(|r| r.id == "napse").expect("napse in report");
        assert_eq!(
            napse_outcome.state,
            crate::supervisor::OutcomeState::Refused,
            "napse should be refused when budget is 1/1, got: {}",
            napse_outcome.detail
        );
    }

    // -----------------------------------------------------------------------
    // Full pipeline tests: build manifest + run reconciler, check expected gates.
    // -----------------------------------------------------------------------

    /// rk3588: napse, hydra, edge-ai-detector load; inline-guard is refused (inline_ips=present_unsafe).
    #[test]
    fn rk3588_supervisor_gates() {
        let mut manifest = manifest_for(RK3588_FIXTURE, RK3588_PLATFORM);
        let modules = all_modules();
        let report = reconcile(&mut manifest, &modules);

        let outcome = |id: &str| report.iter().find(|r| r.id == id).expect(id);

        assert_eq!(outcome("napse").state, crate::supervisor::OutcomeState::Running, "napse should run on rk3588");
        assert_eq!(outcome("hydra").state, crate::supervisor::OutcomeState::Running, "hydra should run on rk3588");
        assert_eq!(outcome("edge-ai-detector").state, crate::supervisor::OutcomeState::Running, "edge-ai should run on rk3588 (NPU present+driver-ready)");
        assert_eq!(
            outcome("inline-guard").state,
            crate::supervisor::OutcomeState::Refused,
            "inline-guard must be refused on rk3588 (inline_ips=present_unsafe), got: {}",
            outcome("inline-guard").detail
        );
    }

    /// n100: napse, hydra, inline-guard load; edge-ai-detector is refused (no NPU).
    #[test]
    fn n100_supervisor_gates() {
        let mut manifest = manifest_for(N100_FIXTURE, N100_PLATFORM);
        let modules = all_modules();
        let report = reconcile(&mut manifest, &modules);

        let outcome = |id: &str| report.iter().find(|r| r.id == id).expect(id);

        assert_eq!(outcome("napse").state, crate::supervisor::OutcomeState::Running, "napse should run on n100");
        assert_eq!(outcome("hydra").state, crate::supervisor::OutcomeState::Running, "hydra should run on n100");
        assert_eq!(outcome("inline-guard").state, crate::supervisor::OutcomeState::Running, "inline-guard should run on n100 (igc known-good)");
        assert_eq!(
            outcome("edge-ai-detector").state,
            crate::supervisor::OutcomeState::Refused,
            "edge-ai must be refused on n100 (no NPU), got: {}",
            outcome("edge-ai-detector").detail
        );
    }

    /// generic / unknown: only napse and hydra load (soc+ids granted, nothing else).
    #[test]
    fn generic_supervisor_gates() {
        let mut manifest = manifest_for(UNKNOWN_FIXTURE, GENERIC_PLATFORM);
        let modules = all_modules();
        let report = reconcile(&mut manifest, &modules);

        let outcome = |id: &str| report.iter().find(|r| r.id == id).expect(id);

        assert_eq!(outcome("napse").state, crate::supervisor::OutcomeState::Running, "napse should run on generic");
        assert_eq!(outcome("hydra").state, crate::supervisor::OutcomeState::Running, "hydra should run on generic");
        assert_ne!(
            outcome("edge-ai-detector").state,
            crate::supervisor::OutcomeState::Running,
            "edge-ai must not run on generic"
        );
        assert_ne!(
            outcome("inline-guard").state,
            crate::supervisor::OutcomeState::Running,
            "inline-guard must not run on generic"
        );
    }

    /// Software-PUF identity: sign a manifest, verify it, and confirm tampering is caught.
    #[test]
    fn sign_and_verify_roundtrip() {
        let mut m = manifest_for(N100_FIXTURE, N100_PLATFORM);
        let id = crate::identity::DeviceIdentity::derive(false);
        id.sign_manifest(&mut m);
        assert_eq!(
            crate::identity::verify_manifest(&m).expect("verify"),
            crate::identity::Verify::Valid,
            "freshly-signed manifest must verify"
        );
        // Tamper: flip a hardware fact; the signature must now FAIL.
        m.hardware.memory_mb += 1;
        assert!(
            crate::identity::verify_manifest(&m).is_err(),
            "tampered manifest must fail verification"
        );
    }

    // --- health: self-test → heal → shed; commit-confirmed for data-plane ---
    use crate::health::{run_health, HealthPolicy, HealthProbe, HealthState};
    use std::collections::HashSet;

    struct MockProbe {
        fail: HashSet<String>,
        flaky: HashSet<String>,
        cut_net: HashSet<String>,
        seen: std::collections::HashMap<String, u32>,
    }
    impl MockProbe {
        fn new() -> Self {
            MockProbe {
                fail: HashSet::new(),
                flaky: HashSet::new(),
                cut_net: HashSet::new(),
                seen: std::collections::HashMap::new(),
            }
        }
    }
    impl HealthProbe for MockProbe {
        fn self_test(&mut self, id: &str, _rt: &crate::types::Runtime) -> Result<(), String> {
            let n = self.seen.entry(id.to_string()).or_insert(0);
            *n += 1;
            if self.fail.contains(id) {
                return Err("persistent fail".into());
            }
            if self.flaky.contains(id) && *n == 1 {
                return Err("transient fail".into());
            }
            Ok(())
        }
        fn verify_connectivity(&mut self, after_id: &str) -> Result<(), String> {
            if self.cut_net.contains(after_id) {
                Err("mgmt path unreachable".into())
            } else {
                Ok(())
            }
        }
    }

    /// A transient self-test failure is HEALED (passes on retry); the module survives.
    #[test]
    fn health_heals_transient() {
        let mut m = manifest_for(N100_FIXTURE, N100_PLATFORM);
        reconcile(&mut m, &all_modules());
        let before = m.modules.len();
        let mut probe = MockProbe::new();
        probe.flaky.insert("napse".to_string());
        let out = run_health(&mut m, &all_modules(), HealthPolicy::default(), &mut probe, None);
        let napse = out.iter().find(|o| o.id == "napse").expect("napse outcome");
        assert_eq!(napse.state, HealthState::Healed, "napse should heal, got {napse:?}");
        assert_eq!(m.modules.len(), before, "healed module must remain running");
    }

    /// A persistent self-test failure is SHED; the rest of the box stays up.
    #[test]
    fn health_sheds_persistent() {
        let mut m = manifest_for(N100_FIXTURE, N100_PLATFORM);
        reconcile(&mut m, &all_modules());
        assert!(m.modules.iter().any(|e| e.id == "napse"));
        let mut probe = MockProbe::new();
        probe.fail.insert("napse".to_string());
        let out = run_health(&mut m, &all_modules(), HealthPolicy::default(), &mut probe, None);
        assert_eq!(out.iter().find(|o| o.id == "napse").unwrap().state, HealthState::Failed);
        assert!(!m.modules.iter().any(|e| e.id == "napse"), "failed module must be shed");
        assert!(m.modules.iter().any(|e| e.id == "hydra"), "other modules must survive");
    }

    /// A data-plane module that loses the management path is auto-REVERTED.
    #[test]
    fn health_reverts_dataplane_on_connectivity_loss() {
        let mut m = manifest_for(N100_FIXTURE, N100_PLATFORM);
        reconcile(&mut m, &all_modules());
        m.modules.push(crate::types::ModuleEntry {
            id: "net-capture".to_string(),
            version: "0".to_string(),
            runtime: crate::types::Runtime::Sysext, // data-plane by runtime
            state: crate::types::ModuleState::Running,
            budget: crate::types::Budget::default(),
            signature: crate::types::SignatureStatus::Verified,
        });
        let mut probe = MockProbe::new();
        probe.cut_net.insert("net-capture".to_string());
        let out = run_health(&mut m, &all_modules(), HealthPolicy::default(), &mut probe, None);
        assert_eq!(
            out.iter().find(|o| o.id == "net-capture").unwrap().state,
            HealthState::Reverted,
            "data-plane module must revert on connectivity loss"
        );
        assert!(!m.modules.iter().any(|e| e.id == "net-capture"), "reverted module must be shed");
        assert!(m.modules.iter().any(|e| e.id == "napse"), "non-data-plane modules unaffected");
    }

    /// Module supply-chain: sign a module dir, verify it, and confirm tampering is caught.
    #[test]
    fn module_sig_roundtrip() {
        let tmp = std::env::temp_dir().join(format!("hp-modsig-{}", std::process::id()));
        let mdir = tmp.join("mod");
        std::fs::create_dir_all(&mdir).unwrap();
        std::fs::write(mdir.join("module.yaml"), b"id: testmod\nversion: '1'\nruntime: wasm\n").unwrap();
        let trust = tmp.join(".trust");
        let key = tmp.join("release.key");
        let n = crate::module_sig::dev_sign_all(std::slice::from_ref(&mdir), &key, &trust).unwrap();
        assert_eq!(n, 1);
        let keys = crate::module_sig::load_trust(&trust);
        assert!(!keys.is_empty(), "trust store must hold the release pubkey");
        assert_eq!(
            crate::module_sig::verify_module(&mdir, &keys),
            crate::module_sig::SigState::Verified
        );
        // Tamper the artifact → the signature must no longer verify.
        std::fs::write(mdir.join("module.yaml"), b"id: testmod\nversion: '2'\nruntime: wasm\n").unwrap();
        assert_eq!(
            crate::module_sig::verify_module(&mdir, &keys),
            crate::module_sig::SigState::Invalid
        );
        let _ = std::fs::remove_dir_all(&tmp);
    }

    /// Fleet GitOps: a desired state diffs against the live device to drift items.
    #[test]
    fn fleet_diff_detects_drift() {
        let y = "channel: stable\nmodules:\n  enable: [napse, foo]\n  disable: [edge-ai-detector]\n";
        let d = crate::fleet::DesiredState::parse(y).unwrap();
        let running = vec!["napse".to_string(), "edge-ai-detector".to_string()];
        let drift = crate::fleet::diff(&d, &running, "edge"); // have 'edge' != desired 'stable'
        use crate::fleet::Drift;
        assert!(drift.contains(&Drift::ChannelMismatch { want: "stable".into(), have: "edge".into() }));
        assert!(drift.contains(&Drift::ModuleShouldStart("foo".into())));
        assert!(drift.contains(&Drift::ModuleShouldStop("edge-ai-detector".into())));
        assert!(
            !drift.iter().any(|x| matches!(x, Drift::ModuleShouldStart(m) if m == "napse")),
            "napse already running → no start drift"
        );
    }

    /// First-boot claim (local, no account) then optional enroll (additive).
    #[test]
    fn claim_then_enroll() {
        let mut m = manifest_for(N100_FIXTURE, N100_PLATFORM);
        assert_eq!(m.identity.claim_state, crate::types::ClaimState::Unclaimed);
        let rec = crate::claim::claim(&mut m, "hunter2", crate::claim::Mode::Standalone, "2026-01-01T00:00:00Z");
        assert_eq!(m.identity.claim_state, crate::types::ClaimState::Claimed);
        assert!(rec.admin_hash.starts_with("sha256:"));
        assert_eq!(rec.mode, "standalone");
        assert!(m.identity.tenant.is_none(), "standalone claim has no tenant");
        // Enroll is additive: Claimed → Enrolled, sets the tenant.
        crate::claim::enroll(&mut m, "acme-corp", "tok-xyz");
        assert_eq!(m.identity.claim_state, crate::types::ClaimState::Enrolled);
        assert_eq!(m.identity.tenant.as_deref(), Some("acme-corp"));
    }

    /// Device fingerprint is STABLE when only the /dev name reorders — the disk
    /// serial drives identity, so sda↔nvme↔mmcblk shuffles don't change device_id.
    #[test]
    fn fingerprint_stable_across_dev_reorder() {
        let mut scan = parse_scan(N100_FIXTURE);
        scan.storage[0].serial = Some("SERIAL-XYZ".to_string());
        let platform = parse_platform(N100_PLATFORM);
        let mi = crate::types::MatchInfo {
            method: crate::types::MatchMethod::Fallback,
            key: "t".to_string(),
        };
        let mk = |s: &crate::scan::HardwareScan| {
            build_manifest(s, &platform, &mi, "2026-01-01T00:00:00Z", "img", "sha256:0")
                .unwrap()
                .hardware
                .fingerprint
        };
        let fp1 = mk(&scan);
        scan.storage[0].dev = "sdz9".to_string(); // /dev reorder; serial unchanged
        let fp2 = mk(&scan);
        assert_eq!(fp1, fp2, "fingerprint must be stable across /dev reorder (serial drives identity)");
    }

    /// A `signature: required` module that fails verification is REFUSED by reconcile.
    #[test]
    fn unverified_required_module_is_refused() {
        let mut m = manifest_for(N100_FIXTURE, N100_PLATFORM);
        let mut def = parse_module(NAPSE_MODULE);
        def.signature = "required".to_string();
        def.sig_verified = Some(false); // cosign-style verify failed
        let report = reconcile(&mut m, &[def]);
        let napse = report.iter().find(|r| r.id == "napse").expect("napse outcome");
        assert_eq!(napse.state, crate::supervisor::OutcomeState::Refused);
        assert!(
            napse.detail.contains("signature"),
            "refusal reason should mention signature: {}",
            napse.detail
        );
    }
}
