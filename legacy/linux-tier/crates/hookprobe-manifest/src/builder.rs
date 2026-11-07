//! Manifest builder — assembles a signed Platform Manifest from scan + platform.
//!
//! Mirrors `build_manifest()` in `bootstrap/reference/generate_manifest.py`.
//! The STUB signature section emits "UNSIGNED-REFERENCE-BUILD"; the shipping
//! binary performs real cosign signing + TPM sealing.
//!
//! TODO: cosign + TPM seal in the shipping impl.

use anyhow::Result;
use sha2::{Digest, Sha256};

use crate::capabilities::map_capabilities;
use crate::crypto::crypto_suite;
use crate::platform::PlatformSpec;
use crate::resources::{allocate_resources, compute_retention};
use crate::scan::HardwareScan;
use crate::types::{
    ClaimState, Hardware, IDevId, IDevIdType, Identity, Manifest, ManifestInterface,
    ManifestPlatform, MatchInfo, Network, Provenance, SignatureBlock,
};

/// The version of the platform classification/capability-mapping RULES this build of
/// `hookprobe-bootstrap` implements (`classify` + `map_capabilities` + `platforms/*.yaml`
/// semantics) — NOT the manifest JSON `schema_version` (which is the on-disk SHAPE of the
/// document, unrelated). Bump this whenever a classification or capability-mapping fix
/// changes what an ALREADY-PROBED device would be granted (e.g. a `platforms/*.yaml`
/// matcher fix, a `map_capabilities` bug fix) — `hookprobe-bootstrap --check-rules-version`
/// (2026-07-05, backend-audit P1 #5) reads this constant to decide whether a frozen,
/// already-provisioned device's manifest is stale enough to re-probe. Never bump this for
/// a change that doesn't affect classification/capability outcomes (e.g. a comment-only
/// edit) — an unnecessary bump costs every fielded device one extra re-probe on next boot.
// v2 (2026-07-07, per-platform capability-model audit): classification + capability-mapping
// changes that alter grants on an already-probed device, so fielded manifests must re-probe once:
//   - classifier: rk3588 now matches `rockchip,rk3588j` (industrial variant no longer → generic).
//   - generic profile: host_telemetry / dns_filtering / threat_intel now granted (software SOC
//     baseline), so an unrecognized box runs a full local SOC and the report matches reality.
//   - edge_ai withheld-reason is now honest ("NPU present but driver not loaded" vs "no NPU").
// v3 (2026-07-08, ADR 0017/0021 A76 AOT loader selection): the manifest now carries
// `hardware.cpu.tier` (from `platforms/<profile>.yaml`'s `cpu_tier`) so the Wasm loader can pick
// the `cortex-a76`-tier AOT blob on rpi5/rk3588. An already-probed rpi5/rk3588 whose frozen
// manifest predates this field would run the A72-safe baseline forever; bumping forces a one-time
// re-probe so the tier is populated and the faster blob is selected. Baseline devices (no
// `cpu_tier` in their platform YAML) re-probe to an unchanged (absent) tier — a no-op grant-wise.
pub const PLATFORM_RULES_VERSION: u32 = 3;

/// SHA256 tag — mirrors Python `_sha256_tag`: `"SHA256:" + sha256(json).hexdigest()`.
///
/// Uses compact JSON serialization (no spaces). The exact bytes differ from
/// Python's `json.dumps(sort_keys=True)` (which uses `, ` / `: ` separators),
/// but the format is valid: `"SHA256:" + 64 hex chars`.
///
/// `serde_json` without the `preserve_order` feature uses `BTreeMap` internally,
/// so object keys are always emitted in sorted (alphabetical) order.
pub fn sha256_tag(obj: &serde_json::Value) -> String {
    let json_bytes = serde_json::to_vec(obj).expect("infallible JSON serialization");
    let hash = Sha256::digest(&json_bytes);
    format!("SHA256:{}", hex::encode(hash))
}

/// Assemble a complete Platform Manifest from scan facts + platform spec.
pub fn build_manifest(
    scan: &HardwareScan,
    platform: &PlatformSpec,
    match_info: &MatchInfo,
    now_iso: &str,
    image_ref: &str,
    image_digest: &str,
) -> Result<Manifest> {
    // Fingerprint: SHA256 of stable hardware identity facts (sorted keys via BTreeMap).
    // Storage identity by STABLE serial (fallback to the /dev name) so `device_id`
    // doesn't change when /dev names reorder (sda↔nvme↔mmcblk across reboots).
    let mut storage_ids: Vec<String> = scan
        .storage
        .iter()
        .map(|s| s.serial.clone().unwrap_or_else(|| s.dev.clone()))
        .collect();
    storage_ids.sort();
    // NOTE: memory_mb (MemTotal) is deliberately EXCLUDED — it shifts with kernel/firmware
    // reserved-memory changes, so including it would make device_id unstable across upgrades.
    let fp_obj = serde_json::json!({
        "arch": format!("{:?}", scan.arch).to_lowercase(),
        "cpu": { "cores": scan.cpu.cores, "model": scan.cpu.model },
        "match": { "key": match_info.key, "method": format!("{:?}", match_info.method).to_lowercase() },
        "storage": storage_ids,
    });
    let fingerprint = sha256_tag(&fp_obj);

    let has_tpm = scan.tpm.present;

    // IDevID pubkey fingerprint.
    let idevid_fpr = sha256_tag(&serde_json::json!({
        "id": fingerprint,
        "kind": "idevid",
    }));

    let device_id = format!("hp-{}", &fingerprint[7..39]); // "SHA256:" prefix is 7 chars

    // Network: convert scan interfaces to manifest interfaces (strip `driver`).
    let interfaces: Vec<ManifestInterface> = scan
        .interfaces
        .iter()
        .map(|i| {
            let fail_mode = if i.role == crate::types::InterfaceRole::Inline {
                Some(i.fail_mode.clone().unwrap_or_else(|| "fail-open".to_string()))
            } else {
                None
            };
            ManifestInterface {
                name: i.name.clone(),
                mac: i.mac.clone(),
                iface_type: i.iface_type.clone(),
                supported_modes: i.supported_modes.clone(),
                role: i.role.clone(),
                fail_mode,
                state: i.state.clone(),
                // Derive native-XDP support from the driver name (fact, detect-once). Absent/unknown
                // driver ⇒ false ⇒ the inspect ladder uses TC-bpf. See ADR 0005.
                xdp_native: crate::xdp::driver_supports_native_xdp(i.driver.as_deref().unwrap_or("")),
            }
        })
        .collect();

    let capabilities = map_capabilities(scan, platform);
    let resources = allocate_resources(scan, platform);
    let crypto = crypto_suite(&platform.crypto_suite)?;
    let retention = compute_retention(scan, platform, now_iso);

    Ok(Manifest {
        schema_version: 2,
        identity: Identity {
            device_id,
            serial: None, // real serial probe in shipping impl
            idevid: IDevId {
                kind: if has_tpm { IDevIdType::Tpm } else { IDevIdType::Software },
                pubkey_fpr: idevid_fpr,
                sealed: has_tpm,
            },
            claim_state: ClaimState::Unclaimed,
            tenant: None,
        },
        platform: ManifestPlatform {
            class: parse_class(&platform.class),
            profile: platform.profile.clone(),
            sku: platform.sku.clone(),
            match_info: match_info.clone(),
            platform_rules_version: PLATFORM_RULES_VERSION,
        },
        hardware: Hardware {
            arch: scan.arch.clone(),
            cpu: crate::types::Cpu {
                model: scan.cpu.model.clone(),
                cores: scan.cpu.cores,
                // ADR 0017/0021: freeze the platform's declared CPU microarch tier (data-driven,
                // from `platforms/<profile>.yaml`'s `cpu_tier`) into the signed manifest so the
                // Wasm loader can select the right AOT blob (`cortex-a76` → `<id>.a76.cwasm`)
                // without ever re-probing the CPU. `None` = the arch's safe baseline.
                tier: platform.cpu_tier.clone(),
            },
            memory_mb: scan.memory_mb,
            storage: scan.storage.clone(),
            tpm: scan.tpm.clone(),
            secure_boot: scan.secure_boot.clone(),
            npu: scan.npu.clone(),
            virt: scan.virt.clone(),
            fingerprint,
        },
        network: Network {
            interfaces,
            wifi: scan.wifi.clone(),
            lte: scan.lte.clone(),
            bpf_stateful: scan
                .kernel_release
                .as_deref()
                .map(crate::xdp::kernel_bpf_stateful)
                .unwrap_or(false),
            uplinks: crate::net_roles::enumerate_uplinks(&scan.interfaces, scan.lte.present)
                .into_iter()
                .map(|u| crate::types::ManifestUplink {
                    name: u.name,
                    kind: u.kind.as_str().to_string(),
                    priority: u.priority,
                })
                .collect(),
            wifi_radios: {
                let has_nonwifi =
                    crate::net_roles::has_nonwifi_uplink(&scan.interfaces, scan.lte.present);
                crate::net_roles::assign_wifi_roles(&scan.interfaces, has_nonwifi)
                    .into_iter()
                    .map(|(name, role)| {
                        // Carry the radio's detected band (stable phy capability) through.
                        let band = scan
                            .interfaces
                            .iter()
                            .find(|i| i.name == name)
                            .and_then(|i| i.band.clone());
                        crate::types::WifiRadio { name, role: role.as_str().to_string(), band }
                    })
                    .collect()
            },
        },
        capabilities,
        resources,
        crypto,
        retention,
        modules: vec![],
        provenance: Provenance {
            image_ref: image_ref.to_string(),
            image_digest: image_digest.to_string(),
            generated_at: now_iso.to_string(),
            generator: "bootstrap/0.1.0".to_string(),
            schema_version: 2,
        },
        // STUB: the shipping (Rust) bootstrap performs real cosign signing + TPM sealing.
        // TODO: cosign + TPM seal.
        signature: SignatureBlock {
            method: "cosign".to_string(),
            sig: "UNSIGNED-REFERENCE-BUILD".to_string(),
            cert: "UNSIGNED-REFERENCE-BUILD".to_string(),
            tpm_sealed: false,
            pcr_policy: None,
        },
    })
}

fn parse_class(class: &str) -> crate::types::PlatformClass {
    match class {
        "edge-lite" => crate::types::PlatformClass::EdgeLite,
        "edge-pro" => crate::types::PlatformClass::EdgePro,
        "cloud" => crate::types::PlatformClass::Cloud,
        "virtual" => crate::types::PlatformClass::Virtual,
        "dev" => crate::types::PlatformClass::Dev,
        _ => crate::types::PlatformClass::Generic,
    }
}
