//! First-boot claim + enrollment — the device's transition from "detected" to
//! "owned", honouring the local-first invariant.
//!
//! - **Claim** (always local, no account): set a local admin credential + pick a
//!   deployment mode, transition `Unclaimed → Claimed`. A standalone device is
//!   fully operational here — no cloud, no account.
//! - **Enroll** (additive, optional): link to a tenant on `mssp.hookprobe.com`
//!   (cloud-linked) or a self-hosted control plane, `Claimed → Enrolled`. Never a
//!   precondition for the device working.
//!
//! Identity already exists before claim (the bootstrap derives + signs it). Claim
//! mutates `identity.claim_state`/`tenant`, so the caller MUST re-sign the manifest.

use serde::{Deserialize, Serialize};

use crate::identity::puf_seed;
use crate::types::{ClaimState, Manifest};

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Mode {
    Standalone,
    CloudLinked,
    SelfHosted,
}
impl Mode {
    pub fn as_str(&self) -> &'static str {
        match self {
            Mode::Standalone => "standalone",
            Mode::CloudLinked => "cloud-linked",
            Mode::SelfHosted => "self-hosted",
        }
    }
    pub fn parse(s: &str) -> Option<Mode> {
        match s {
            "standalone" => Some(Mode::Standalone),
            "cloud-linked" => Some(Mode::CloudLinked),
            "self-hosted" => Some(Mode::SelfHosted),
            _ => None,
        }
    }
}

/// Persisted to the data partition (`/var/lib/hookprobe/claim.json`), NOT the
/// immutable rootfs — survives `bootc upgrade`/`rollback`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClaimRecord {
    pub mode: String,
    /// `sha256(device_seed || password)` — REFERENCE only; production uses argon2id.
    pub admin_hash: String,
    pub tenant: Option<String>,
    pub claimed_at: String,
}

/// Claim a device: set the local admin credential + mode; `Unclaimed → Claimed`.
pub fn claim(manifest: &mut Manifest, admin_password: &str, mode: Mode, now: &str) -> ClaimRecord {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(b"hookprobe-admin-v1");
    h.update(puf_seed()); // device-unique salt
    h.update(admin_password.as_bytes());
    let admin_hash = format!("sha256:{}", hex::encode(h.finalize()));

    manifest.identity.claim_state = ClaimState::Claimed;
    ClaimRecord {
        mode: mode.as_str().to_string(),
        admin_hash,
        tenant: manifest.identity.tenant.clone(),
        claimed_at: now.to_string(),
    }
}

/// Enroll into a tenant (cloud-linked / self-hosted): `Claimed → Enrolled`.
/// Additive — a device can run forever standalone without ever enrolling.
pub fn enroll(manifest: &mut Manifest, tenant: &str, _token: &str) {
    manifest.identity.tenant = Some(tenant.to_string());
    manifest.identity.claim_state = ClaimState::Enrolled;
}
