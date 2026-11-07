//! Classifier — maps raw scan facts to a platform spec (Architecture.md C5).
//!
//! Priority: device-tree (ARM) -> dmi-tuple (x86) -> fallback (generic).
//! Mirrors `classify()` in `bootstrap/reference/generate_manifest.py`.

use anyhow::{anyhow, Result};

use crate::platform::{PlatformMatch, PlatformSpec};
use crate::scan::{DmiInfo, HardwareScan};
use crate::types::{MatchInfo, MatchMethod};

/// DMI field values that indicate "no meaningful value".
const BLANK_DMI: &[&str] = &[
    "",
    "default string",
    "to be filled by o.e.m.",
    "system manufacturer",
    "system product name",
];

/// Return the DMI field value if it is non-blank, else None.
fn dmi_field(dmi: Option<&DmiInfo>, key: &str) -> Option<String> {
    let info = dmi?;
    let v = match key {
        "sys_vendor" => info.sys_vendor.as_deref(),
        "product_name" => info.product_name.as_deref(),
        "board_name" => info.board_name.as_deref(),
        _ => None,
    }?;
    let trimmed = v.trim();
    if BLANK_DMI.contains(&trimmed.to_lowercase().as_str()) {
        None
    } else {
        Some(trimmed.to_string())
    }
}

/// Load all platform specs from `platforms/*.yaml` in a directory.
///
/// Files without a `profile` key are silently skipped (matches Python behaviour).
pub fn load_platforms(platforms_dir: &std::path::Path) -> Result<Vec<PlatformSpec>> {
    let mut out = Vec::new();
    let mut entries: Vec<_> = std::fs::read_dir(platforms_dir)?
        .filter_map(|e| e.ok())
        .filter(|e| e.path().extension().map(|x| x == "yaml").unwrap_or(false))
        .collect();
    entries.sort_by_key(|e| e.path());

    for entry in entries {
        let text = std::fs::read_to_string(entry.path())?;
        let spec: serde_yaml::Value = serde_yaml::from_str(&text)?;
        if spec.get("profile").is_none() {
            continue;
        }
        let spec: PlatformSpec = serde_yaml::from_str(&text)?;
        out.push(spec);
    }
    Ok(out)
}

/// Classify scan facts against the platform list.
///
/// Returns `(platform_spec, match_info)`.  Priority:
/// 1. device-tree `compatible` tokens (ARM)
/// 2. DMI tuple with fnmatch wildcards (x86)
/// 3. fallback (generic)
pub fn classify<'a>(
    scan: &HardwareScan,
    platforms: &'a [PlatformSpec],
) -> Result<(&'a PlatformSpec, MatchInfo)> {
    // --- 1. device-tree ---
    let dt_tokens = &scan.device_tree_compatible;
    for spec in platforms.iter().filter(|s| matches!(s.match_rule, PlatformMatch::DeviceTree { .. })) {
        if let PlatformMatch::DeviceTree { device_tree_compatible } = &spec.match_rule {
            for token in device_tree_compatible {
                if dt_tokens.contains(token) {
                    return Ok((
                        spec,
                        MatchInfo {
                            method: MatchMethod::DeviceTree,
                            key: token.clone(),
                        },
                    ));
                }
            }
        }
    }

    // --- 2. dmi-tuple ---
    let vendor = dmi_field(scan.dmi.as_ref(), "sys_vendor");
    let product = dmi_field(scan.dmi.as_ref(), "product_name");
    let board = dmi_field(scan.dmi.as_ref(), "board_name");

    if vendor.is_some() || product.is_some() || board.is_some() {
        for spec in platforms.iter().filter(|s| matches!(s.match_rule, PlatformMatch::DmiTuple { .. })) {
            if let PlatformMatch::DmiTuple { dmi_tuples } = &spec.match_rule {
                for tup in dmi_tuples {
                    if fnmatch(vendor.as_deref().unwrap_or(""), &tup.sys_vendor)
                        && fnmatch(product.as_deref().unwrap_or(""), &tup.product_name)
                        && fnmatch(board.as_deref().unwrap_or(""), &tup.board_name)
                    {
                        // Format key the same way as Python: "{vendor};{product};{board}"
                        // Python uses `f"{vendor};{product};{board}"` where None -> "None".
                        let key = format!(
                            "{};{};{}",
                            vendor.as_deref().unwrap_or("None"),
                            product.as_deref().unwrap_or("None"),
                            board.as_deref().unwrap_or("None"),
                        );
                        return Ok((
                            spec,
                            MatchInfo {
                                method: MatchMethod::DmiTuple,
                                key,
                            },
                        ));
                    }
                }
            }
        }
    }

    // --- 3. cpu-model (x86 whitebox / blank-DMI, e.g. N100 with "Default string" DMI) ---
    let cpu_model = scan.cpu.model.trim();
    if !cpu_model.is_empty() {
        for spec in platforms
            .iter()
            .filter(|s| matches!(s.match_rule, PlatformMatch::CpuModel { .. }))
        {
            if let PlatformMatch::CpuModel { cpu_models } = &spec.match_rule {
                for pat in cpu_models {
                    if fnmatch(cpu_model, pat) {
                        return Ok((
                            spec,
                            MatchInfo {
                                method: MatchMethod::CpuModel,
                                key: cpu_model.to_string(),
                            },
                        ));
                    }
                }
            }
        }
    }

    // --- 4. virt (cloud / VM, e.g. QEMU/KVM) ---
    let virt = scan.virt.trim().to_lowercase();
    if !virt.is_empty() && virt != "none" {
        for spec in platforms
            .iter()
            .filter(|s| matches!(s.match_rule, PlatformMatch::Virt { .. }))
        {
            if let PlatformMatch::Virt { virt: virts } = &spec.match_rule {
                if virts.iter().any(|v| v.to_lowercase() == virt) {
                    return Ok((
                        spec,
                        MatchInfo {
                            method: MatchMethod::Virt,
                            key: virt.clone(),
                        },
                    ));
                }
            }
        }
    }

    // --- 5. fallback ---
    if let Some(spec) = platforms
        .iter()
        .find(|s| matches!(s.match_rule, PlatformMatch::Fallback))
    {
        return Ok((
            spec,
            MatchInfo {
                method: MatchMethod::Fallback,
                key: "unknown".to_string(),
            },
        ));
    }

    Err(anyhow!(
        "No fallback profile found in platforms/ directory (generic.yaml missing)."
    ))
}

// ---------------------------------------------------------------------------
// fnmatch — shell-style wildcard matching (*, ?)
// ---------------------------------------------------------------------------

/// Shell-style wildcard match.  Supports `*` (any sequence) and `?` (any char).
/// Case-sensitive (Unix semantics, matching Python's `fnmatch` on Linux).
pub fn fnmatch(name: &str, pattern: &str) -> bool {
    fnmatch_inner(name.as_bytes(), pattern.as_bytes())
}

fn fnmatch_inner(s: &[u8], p: &[u8]) -> bool {
    match (s, p) {
        (_, []) => s.is_empty(),
        (_, [b'*', rest @ ..]) => {
            // * matches zero or more bytes
            for i in 0..=s.len() {
                if fnmatch_inner(&s[i..], rest) {
                    return true;
                }
            }
            false
        }
        ([], _) => false,
        ([_sc, s_rest @ ..], [b'?', p_rest @ ..]) => fnmatch_inner(s_rest, p_rest),
        ([sc, s_rest @ ..], [pc, p_rest @ ..]) => sc == pc && fnmatch_inner(s_rest, p_rest),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fnmatch_star_matches_anything() {
        assert!(fnmatch("anything", "*"));
        assert!(fnmatch("", "*"));
    }

    #[test]
    fn fnmatch_exact() {
        assert!(fnmatch("AAEON", "AAEON"));
        assert!(!fnmatch("aaeon", "AAEON"));
    }

    #[test]
    fn fnmatch_trailing_star() {
        assert!(fnmatch("N100-A10", "N100*"));
        assert!(!fnmatch("M100", "N100*"));
    }

    #[test]
    fn blank_dmi_returns_none() {
        let dmi = DmiInfo {
            sys_vendor: Some("Default string".to_string()),
            product_name: Some("".to_string()),
            board_name: None,
        };
        assert!(dmi_field(Some(&dmi), "sys_vendor").is_none());
        assert!(dmi_field(Some(&dmi), "product_name").is_none());
        assert!(dmi_field(Some(&dmi), "board_name").is_none());
    }

    // -----------------------------------------------------------------------
    // Classification: every real platform must classify to ITS profile, never
    // fall through to `generic` and silently lose capabilities.
    // -----------------------------------------------------------------------

    use crate::scan::{ScanCpu, HardwareScan};
    use crate::types::{Arch, Lte, Npu, SecureBoot, Tpm, TpmKind, Wifi};

    // The six shipping platform profiles, parsed from the real checked-in YAML.
    const RPI4_PLATFORM: &str = include_str!("../../../platforms/rpi4.yaml");
    const RPI5_PLATFORM: &str = include_str!("../../../platforms/rpi5.yaml");
    const RK3588_PLATFORM: &str = include_str!("../../../platforms/rk3588.yaml");
    const N100_PLATFORM: &str = include_str!("../../../platforms/n100.yaml");
    const CLOUD_PLATFORM: &str = include_str!("../../../platforms/cloud.yaml");
    const GENERIC_PLATFORM: &str = include_str!("../../../platforms/generic.yaml");

    fn all_platforms() -> Vec<PlatformSpec> {
        [
            RPI4_PLATFORM, RPI5_PLATFORM, RK3588_PLATFORM,
            N100_PLATFORM, CLOUD_PLATFORM, GENERIC_PLATFORM,
        ]
        .iter()
        .map(|y| serde_yaml::from_str(y).expect("parse platform yaml"))
        .collect()
    }

    /// Minimal-but-valid scan; only the fields the classifier reads are meaningful.
    fn scan_with(dt: &[&str], cpu_model: &str, virt: &str, dmi: Option<DmiInfo>) -> HardwareScan {
        HardwareScan {
            device_tree_compatible: dt.iter().map(|s| s.to_string()).collect(),
            dmi,
            arch: Arch::Arm64,
            cpu: ScanCpu { model: cpu_model.to_string(), cores: 4 },
            memory_mb: 4096,
            kernel_release: None,
            storage: vec![],
            tpm: Tpm { present: false, version: None, kind: TpmKind::None },
            secure_boot: SecureBoot { supported: false, enabled: false },
            npu: Npu { present: false, driver_ready: false, vendor: None, model: None },
            virt: virt.to_string(),
            interfaces: vec![],
            wifi: Wifi { present: false, max_standard: None },
            lte: Lte { present: false, model: None },
            unbound: vec![],
        }
    }

    fn classify_profile(scan: &HardwareScan) -> (String, MatchMethod) {
        let platforms = all_platforms();
        let (spec, mi) = classify(scan, &platforms).expect("classify");
        (spec.profile.clone(), mi.method)
    }

    #[test]
    fn rpi4_classifies_by_device_tree() {
        let s = scan_with(&["raspberrypi,4-model-b", "brcm,bcm2711"], "", "none", None);
        assert_eq!(classify_profile(&s), ("rpi4".into(), MatchMethod::DeviceTree));
    }

    #[test]
    fn rpi5_classifies_by_device_tree() {
        let s = scan_with(&["raspberrypi,5-model-b", "brcm,bcm2712"], "", "none", None);
        assert_eq!(classify_profile(&s), ("rpi5".into(), MatchMethod::DeviceTree));
    }

    /// Compute Module 5 (CM5) — release-engineer CM5 platform pass (2026-07-08). CM5 is
    /// BCM2712/Cortex-A76, same silicon family as the Pi 5 Model B, and its device tree
    /// (`bcm2712-rpi-cm5.dtsi` / `bcm2712-rpi-cm5-cm5io.dts`, raspberrypi/linux) carries the
    /// EXACT SAME `compatible` chain as the Pi 5 board — `model = "Raspberry Pi Compute
    /// Module 5"`, `compatible = "raspberrypi,5-compute-module", "brcm,bcm2712"` (verified
    /// against raspberrypi/linux upstream source, not assumed). `platforms/rpi5.yaml` already
    /// lists `raspberrypi,5-compute-module` as a match token (its header has said "Raspberry
    /// Pi 5 AND Compute Module 5" since it was written) — CM5 needs NO separate
    /// `platforms/cm5.yaml`; a second file claiming the same device-tree token would only
    /// create an ambiguous dual-claim (classify()'s first-file-wins-by-filename-sort rule),
    /// not a cleaner one. This test locks in "adding CM5 required zero platform-classification
    /// code" as an asserted regression, not a hopeful assumption.
    #[test]
    fn cm5_classifies_by_device_tree_as_rpi5_profile() {
        let s = scan_with(&["raspberrypi,5-compute-module", "brcm,bcm2712"], "", "none", None);
        assert_eq!(classify_profile(&s), ("rpi5".into(), MatchMethod::DeviceTree));
    }

    #[test]
    fn rk3588_classifies_by_device_tree() {
        let s = scan_with(&["radxa,rock-5b", "rockchip,rk3588"], "", "none", None);
        assert_eq!(classify_profile(&s), ("rk3588".into(), MatchMethod::DeviceTree));
    }

    /// An rk3588j-only device-tree (industrial variant) must NOT fall through to generic.
    #[test]
    fn rk3588j_only_still_classifies_rk3588_not_generic() {
        let s = scan_with(&["vendor,industrial-board", "rockchip,rk3588j"], "", "none", None);
        assert_eq!(classify_profile(&s), ("rk3588".into(), MatchMethod::DeviceTree));
    }

    #[test]
    fn n100_classifies_by_cpu_model_even_with_blank_dmi() {
        // Blank DMI ("Default string") must not defeat the CPU-model path.
        let dmi = DmiInfo {
            sys_vendor: Some("Default string".into()),
            product_name: Some("Default string".into()),
            board_name: None,
        };
        let s = scan_with(&[], "Intel(R) N100", "none", Some(dmi));
        assert_eq!(classify_profile(&s), ("n100".into(), MatchMethod::CpuModel));
    }

    #[test]
    fn cloud_vm_classifies_by_virt() {
        // arm64 KVM VM: dummy device-tree, no matching board tokens ⇒ falls to virt ⇒ cloud.
        let s = scan_with(&["linux,dummy-virt"], "", "kvm", None);
        assert_eq!(classify_profile(&s), ("cloud".into(), MatchMethod::Virt));
    }

    #[test]
    fn unrecognized_hardware_falls_back_to_generic() {
        let s = scan_with(&["some,unknown-soc"], "Weird CPU", "none", None);
        assert_eq!(classify_profile(&s), ("generic".into(), MatchMethod::Fallback));
    }

    // -----------------------------------------------------------------------
    // base-tier-build-ticket.md Phase 2 — `tc_bpf` / `resource_shed_v2` capability grants.
    // Regression-locks against the REAL checked-in platforms/{rpi5,rk3588}.yaml (not a synthetic
    // fixture): `tc_bpf` was documented in ADR 0003's token table but never actually added to
    // either file's `capabilities:` map before this pass (so `dataplane-tune-apply.sh`'s existing
    // `capability_state tc_bpf` gate always silently resolved `absent`); `resource_shed_v2` is
    // this phase's new token, chained on `tc_bpf`. Both must resolve `granted` on a plausible
    // real scan (device-tree matched, `soc`'s `cpu`/`memory_mb` facts always present).
    // -----------------------------------------------------------------------

    use crate::capabilities::map_capabilities;
    use crate::types::CapabilityState;

    #[test]
    fn rpi5_grants_tc_bpf_and_resource_shed_v2() {
        let platforms = all_platforms();
        let s = scan_with(&["raspberrypi,5-model-b", "brcm,bcm2712"], "", "none", None);
        let (spec, _) = classify(&s, &platforms).expect("classify rpi5");
        let caps = map_capabilities(&s, spec);
        assert_eq!(
            caps.get("tc_bpf").map(|c| &c.state),
            Some(&CapabilityState::Granted),
            "tc_bpf must be granted on rpi5 — dataplane-tune-apply.sh's whole Phase-1 tuning \
             recipe silently no-ops forever if this ever regresses to absent"
        );
        assert_eq!(caps.get("resource_shed_v2").map(|c| &c.state), Some(&CapabilityState::Granted));
    }

    #[test]
    fn rk3588_grants_tc_bpf_and_resource_shed_v2() {
        let platforms = all_platforms();
        let s = scan_with(&["radxa,rock-5b", "rockchip,rk3588"], "", "none", None);
        let (spec, _) = classify(&s, &platforms).expect("classify rk3588");
        let caps = map_capabilities(&s, spec);
        assert_eq!(caps.get("tc_bpf").map(|c| &c.state), Some(&CapabilityState::Granted));
        assert_eq!(caps.get("resource_shed_v2").map(|c| &c.state), Some(&CapabilityState::Granted));
    }

    /// `resource_shed_v2` must never be modelled as independently grantable of `tc_bpf` — the
    /// dependency chain (`resource_shed_v2 requires tc_bpf requires capture requires soc`) is
    /// the whole point (shed-v2 rides on the SAME BPF+BTF floor `tc_bpf` names); this is a
    /// structural assertion against the parsed YAML, not just the resolved grant above.
    #[test]
    fn resource_shed_v2_requires_tc_bpf_in_both_platform_files() {
        for (name, yaml) in [("rpi5", RPI5_PLATFORM), ("rk3588", RK3588_PLATFORM)] {
            let spec: PlatformSpec = serde_yaml::from_str(yaml).expect("parse");
            let pol = spec.capabilities.get("resource_shed_v2").unwrap_or_else(|| panic!("{name}: resource_shed_v2 must be declared"));
            assert!(
                pol.requires.iter().any(|r| r == "tc_bpf"),
                "{name}: resource_shed_v2 must require tc_bpf, got {:?}",
                pol.requires
            );
        }
    }
}
