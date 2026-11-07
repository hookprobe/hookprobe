//! Capability + mode envelope for `/api/manifest` — the read-API's half of "capability-gated
//! rendering" (MissionControl.md §Cross-cutting: "A control is rendered, greyed-with-reason, or
//! hidden purely from the manifest — never a broken or no-op button"). The UI never hardware-
//! branches; it renders off exactly this shape.
//!
//! Reads the two on-disk artifacts the OS invariants already define — never re-probes hardware,
//! never invents data:
//! - the signed Platform Manifest (`/var/lib/hookprobe/manifest.json`, schema 2): capabilities +
//!   identity (`hookprobe_manifest::types::Manifest`).
//! - the claim record (`/var/lib/hookprobe/claim.json`): the explicit deployment-mode string set at
//!   claim time (`hookprobe_manifest::claim::{claim, ClaimRecord}`).
//!
//! NEVER errors and NEVER 500s: a dev box or a device that hasn't first-booted yet has neither
//! file, and the only honest response is "standalone, no grants" (`manifest_present: false`) — the
//! UI must be able to render *something* (safe, ungated-nothing) before hardware has ever been
//! probed, exactly like every other capability-gated surface in this OS.
use serde_json::{json, Value};
use std::path::Path;

pub fn manifest_view_json(manifest_path: &Path, claim_path: &Path) -> String {
    let manifest: Option<hookprobe_manifest::Manifest> = std::fs::read_to_string(manifest_path)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok());

    let claim_mode: Option<String> = std::fs::read_to_string(claim_path)
        .ok()
        .and_then(|s| serde_json::from_str::<Value>(&s).ok())
        .and_then(|v| v.get("mode").and_then(|m| m.as_str()).map(|s| s.to_string()));

    let Some(m) = manifest else {
        return json!({
            "manifest_present": false,
            "mode": claim_mode.unwrap_or_else(|| "standalone".to_string()),
            "device_id": Value::Null,
            "claim_state": "unclaimed",
            "tenant": Value::Null,
            "capabilities": {},
        })
        .to_string();
    };

    use hookprobe_manifest::types::{CapabilityState, ClaimState};

    let capabilities: serde_json::Map<String, Value> = m
        .capabilities
        .iter()
        .map(|(name, cap)| {
            let (granted, state_str) = match cap.state {
                CapabilityState::Granted => (true, "granted"),
                CapabilityState::PresentUnsafe => (false, "present_unsafe"),
                CapabilityState::PolicyDenied => (false, "policy_denied"),
                CapabilityState::Absent => (false, "absent"),
            };
            (
                name.clone(),
                json!({"granted": granted, "state": state_str, "reason": cap.reason}),
            )
        })
        .collect();

    let claim_state = match m.identity.claim_state {
        ClaimState::Unclaimed => "unclaimed",
        ClaimState::Claimed => "claimed",
        ClaimState::Enrolled => "enrolled",
    };

    // Mode precedence: claim.json's explicit string (set at claim time by `claim::claim`/`enroll`)
    // wins when present; otherwise fall back to a coarse derivation from claim_state alone (the
    // manifest itself never distinguishes cloud-linked from self-hosted — that's claim.json's job).
    let mode = claim_mode.unwrap_or_else(|| {
        if matches!(m.identity.claim_state, ClaimState::Enrolled) {
            "cloud-linked".to_string()
        } else {
            "standalone".to_string()
        }
    });

    json!({
        "manifest_present": true,
        "mode": mode,
        "device_id": m.identity.device_id,
        "claim_state": claim_state,
        "tenant": m.identity.tenant,
        "capabilities": capabilities,
    })
    .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A REAL manifest fixture (not hand-typed) — the same `generic.manifest.json` example the
    /// `manifest/` tooling ships (`manifest/examples/generic.manifest.json`), so this test exercises
    /// the exact schema-2 shape the bootstrap scanner produces, not a hand-rolled approximation of it.
    const GENERIC_MANIFEST: &str = include_str!("../../../manifest/examples/generic.manifest.json");

    #[test]
    fn missing_files_yield_a_safe_standalone_default_never_an_error() {
        let missing = Path::new("/nonexistent/hookprobe-api-test/manifest.json");
        let missing_claim = Path::new("/nonexistent/hookprobe-api-test/claim.json");
        let out = manifest_view_json(missing, missing_claim);
        let v: Value = serde_json::from_str(&out).unwrap();
        assert_eq!(v["manifest_present"], false);
        assert_eq!(v["mode"], "standalone");
        assert_eq!(v["claim_state"], "unclaimed");
        assert_eq!(v["capabilities"], json!({}));
    }

    #[test]
    fn present_manifest_surfaces_real_capabilities_unclaimed_defaults_to_standalone() {
        let dir = std::env::temp_dir().join(format!("hp-api-manifest-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let manifest_path = dir.join("manifest.json");
        let claim_path = dir.join("claim.json"); // deliberately absent — device never claimed
        std::fs::write(&manifest_path, GENERIC_MANIFEST).unwrap();

        let out = manifest_view_json(&manifest_path, &claim_path);
        let v: Value = serde_json::from_str(&out)
            .unwrap_or_else(|e| panic!("manifest_view_json did not return valid JSON ({e}): {out}"));
        assert_eq!(v["manifest_present"], true);
        assert_eq!(v["mode"], "standalone", "no claim.json + claim_state=unclaimed -> standalone default");
        assert_eq!(v["device_id"], "hp-9fe2a9b1e40decf1bbeefd05a56986d4");
        assert_eq!(v["claim_state"], "unclaimed");
        assert_eq!(v["tenant"], Value::Null);
        // real capabilities from the fixture: "ids" granted, "openvswitch" absent-with-reason.
        assert_eq!(v["capabilities"]["ids"]["granted"], true);
        assert_eq!(v["capabilities"]["ids"]["state"], "granted");
        assert_eq!(v["capabilities"]["openvswitch"]["granted"], false);
        assert_eq!(v["capabilities"]["openvswitch"]["state"], "absent");
        assert_eq!(v["capabilities"]["openvswitch"]["reason"], "requires >=2 network interfaces; 1 present");
    }

    #[test]
    fn claim_json_explicit_mode_wins_over_the_claim_state_derivation() {
        let dir = std::env::temp_dir().join(format!("hp-api-manifest-test2-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let manifest_path = dir.join("manifest.json");
        let claim_path = dir.join("claim.json");

        // Same real fixture, but mutated to Enrolled + tenanted (mirrors `claim::enroll`'s effect).
        let mut m: Value = serde_json::from_str(GENERIC_MANIFEST).unwrap();
        m["identity"]["claim_state"] = json!("enrolled");
        m["identity"]["tenant"] = json!("acme-mssp");
        std::fs::write(&manifest_path, m.to_string()).unwrap();
        std::fs::write(
            &claim_path,
            json!({"mode": "self-hosted", "admin_hash": "x", "tenant": "acme-mssp", "claimed_at": "2026-01-01T00:00:00Z"})
                .to_string(),
        )
        .unwrap();

        let out = manifest_view_json(&manifest_path, &claim_path);
        let v: Value = serde_json::from_str(&out).unwrap();
        assert_eq!(v["mode"], "self-hosted", "claim.json's explicit mode string wins over the coarse enrolled->cloud-linked derivation");
        assert_eq!(v["claim_state"], "enrolled");
        assert_eq!(v["tenant"], "acme-mssp");

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn enrolled_without_a_claim_json_falls_back_to_the_coarse_cloud_linked_derivation() {
        let mut m: Value = serde_json::from_str(GENERIC_MANIFEST).unwrap();
        m["identity"]["claim_state"] = json!("enrolled");
        let dir = std::env::temp_dir().join(format!("hp-api-manifest-test3-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let manifest_path = dir.join("manifest.json");
        std::fs::write(&manifest_path, m.to_string()).unwrap();
        let missing_claim = dir.join("claim.json");

        let out = manifest_view_json(&manifest_path, &missing_claim);
        let v: Value = serde_json::from_str(&out).unwrap();
        assert_eq!(v["mode"], "cloud-linked");
        std::fs::remove_dir_all(&dir).ok();
    }
}
