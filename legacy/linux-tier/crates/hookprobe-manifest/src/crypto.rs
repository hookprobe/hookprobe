//! Crypto suite registry (ADR 0002).
//!
//! In the shipping build, the active suite is resolved per device from
//! `security/`. Here we ship the one named suite referenced by all three
//! platform profiles.
//!
//! HONESTY (F5 audit fix, 2026-07-05): this registry is POLICY, cross-checked against reality by
//! `security/cbom/gen-cbom.py`'s `IMPLEMENTED_ALGOS` map (the load-bearing "what actually ships"
//! source) — see `security/cbom/suites/hookprobe-pqc-hybrid-2026.yaml`'s per-domain comments for
//! the current implemented/roadmap verdict. `image_signing` here is `["ecdsa-p256"]`: the REAL
//! mechanism is cosign KEYLESS signing (`.github/workflows/build-os.yml`'s `cosign sign --yes`,
//! Fulcio-issued ECDSA-P256 cert) — NOT ml-dsa, which this suite previously (and wrongly) claimed.

use anyhow::{anyhow, Result};

use crate::types::Crypto;

/// Return the named crypto suite, or an error if unknown.
///
/// Mirrors the `CRYPTO_SUITES` dict in `bootstrap/reference/generate_manifest.py`.
pub fn crypto_suite(suite_id: &str) -> Result<Crypto> {
    match suite_id {
        "hookprobe-pqc-hybrid-2026" => Ok(Crypto {
            agility: true,
            suite_id: "hookprobe-pqc-hybrid-2026".to_string(),
            image_signing: vec!["ecdsa-p256".to_string()],
            module_signing: vec!["ml-dsa-65".to_string(), "ed25519".to_string()],
            boot_signing: "lms".to_string(),
            tls_kex: vec!["ml-kem-768+x25519".to_string()],
            tls_auth: vec!["ml-dsa-65".to_string(), "ecdsa-p256".to_string()],
            data_at_rest: "aes-256-gcm".to_string(),
            hash: vec![
                "sha-256".to_string(),
                "sha-384".to_string(),
                "sha3-256".to_string(),
            ],
            device_identity: vec!["ml-dsa-65".to_string(), "ed25519".to_string()],
            cbom: "/usr/share/hookprobe/cbom.json".to_string(),
        }),
        // A named CLASSICAL-ONLY suite — proves the ADR 0002 agility mechanism is real (a device/
        // operator can select this suite and module verification genuinely becomes Ed25519-only,
        // no ML-DSA leg required or even consulted; see `module_sig::verify_module_for_suite`).
        // Intended for a regulated/FIPS-pinned deployment ahead of a FIPS-validated PQC provider,
        // or simply a device that has not yet rolled onto the hybrid suite — a policy choice, not
        // a lesser code path. NOT the default; `hookprobe-pqc-hybrid-2026` remains the active suite.
        "hookprobe-ed25519-only-legacy" => Ok(Crypto {
            agility: true,
            suite_id: "hookprobe-ed25519-only-legacy".to_string(),
            image_signing: vec!["ecdsa-p256".to_string()], // same real cosign-keyless mechanism regardless of module-signing suite
            module_signing: vec!["ed25519".to_string()],
            boot_signing: "none".to_string(),
            tls_kex: vec!["x25519".to_string()],
            tls_auth: vec!["ecdsa-p256".to_string()],
            data_at_rest: "aes-256-gcm".to_string(),
            hash: vec![
                "sha-256".to_string(),
                "sha-384".to_string(),
                "sha3-256".to_string(),
            ],
            device_identity: vec!["ed25519".to_string()],
            cbom: "/usr/share/hookprobe/cbom.json".to_string(),
        }),
        other => Err(anyhow!("Unknown crypto suite: '{other}'")),
    }
}
