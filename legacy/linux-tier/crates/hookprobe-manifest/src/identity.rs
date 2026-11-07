//! Device identity + manifest signing — the SOFTWARE root of trust (no TPM needed).
//!
//! Not every device has a (discrete) TPM. This gives a software-PUF identity that
//! works on bare metal everywhere:
//!   - derive a device-unique, reproducible seed from hardware fingerprints that
//!     are NOT published in the manifest (board/SoC serial, storage serial, MACs);
//!   - derive a deterministic Ed25519 keypair from that seed (re-derived each boot,
//!     never stored — survives a data wipe, unique per device);
//!   - sign the Platform Manifest with it; verify the signature on load.
//!
//! Strength ladder (`idevid.type`): TPM-sealed (discrete or firmware/fTPM) >
//! DICE/OTP-fuse > THIS software-PUF. cosign VERIFICATION of images/modules needs
//! only public keys and is independent of this (works without any TPM).
//!
//! Honest threat model: a software-PUF has NO hardware tamper-resistance — an
//! attacker with root on the device can re-derive the key. It provides integrity
//! and a stable hardware-bound identity, not a hardware vault.
//! TODO: seal to TPM (fTPM on the N100) / DICE (OTP fuses) where available.

use anyhow::{anyhow, Context, Result};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::Path;

use crate::types::{IDevId, IDevIdType, Manifest, SignatureBlock};

const SIG_METHOD: &str = "ed25519-puf";

fn read_trim<P: AsRef<Path>>(p: P) -> Option<String> {
    fs::read_to_string(p)
        .ok()
        .map(|s| {
            s.trim_matches(|c: char| c == '\0' || c.is_whitespace())
                .to_string()
        })
        .filter(|s| !s.is_empty())
}

/// Sorted MACs of physical NICs (those with a `/sys` device symlink).
fn primary_macs() -> Vec<String> {
    let mut macs = Vec::new();
    if let Ok(entries) = fs::read_dir("/sys/class/net") {
        for e in entries.flatten() {
            let base = e.path();
            if !base.join("device").exists() {
                continue;
            }
            if let Some(m) = read_trim(base.join("address")) {
                if m != "00:00:00:00:00:00" {
                    macs.push(m);
                }
            }
        }
    }
    macs.sort();
    macs
}

/// Storage device serials (NVMe serial + MMC CID), read-only.
fn storage_serials() -> Vec<String> {
    let mut out = Vec::new();
    if let Ok(entries) = fs::read_dir("/sys/class/nvme") {
        for e in entries.flatten() {
            if let Some(s) = read_trim(e.path().join("serial")) {
                out.push(s);
            }
        }
    }
    if let Ok(entries) = fs::read_dir("/sys/block") {
        for e in entries.flatten() {
            if e.file_name().to_string_lossy().starts_with("mmcblk") {
                if let Some(s) = read_trim(e.path().join("device/cid")) {
                    out.push(s);
                }
            }
        }
    }
    out.sort();
    out
}

/// Read-only PUF material from hardware sources (NOT published in the manifest).
fn puf_material() -> Vec<u8> {
    let mut parts: Vec<String> = Vec::new();
    // ARM board/SoC serial (hardware-unique, reimage-stable).
    if let Some(s) = read_trim("/proc/device-tree/serial-number") {
        parts.push(format!("dt:{s}"));
    }
    // machine-id adds entropy (note: regenerated on reimage).
    if let Some(s) = read_trim("/etc/machine-id") {
        parts.push(format!("mid:{s}"));
    }
    for s in storage_serials() {
        parts.push(format!("stor:{s}"));
    }
    for m in primary_macs() {
        parts.push(format!("mac:{m}"));
    }
    parts.join("|").into_bytes()
}

/// Device-unique 32-byte seed (domain-separated SHA-256 of the PUF material).
pub fn puf_seed() -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"hookprobe-device-puf-v1");
    h.update(puf_material());
    h.finalize().into()
}

/// True when there is NO device-unique PUF material (no board serial, machine-id, storage
/// serial or MAC). Such a device would derive an IDENTICAL, publicly-reproducible key —
/// the seed is not secret. Callers MUST surface this (and a real deployment must add a
/// persistent random nonce or a hardware root). systemd normally guarantees /etc/machine-id,
/// so this is rare, but it must never be silent.
pub fn weak_entropy() -> bool {
    puf_material().is_empty()
}

/// A device's software identity (deterministic Ed25519 from the PUF seed).
pub struct DeviceIdentity {
    sk: SigningKey,
    /// Whether a TPM is present (informational: marks the available upgrade tier).
    pub tpm_available: bool,
}

impl DeviceIdentity {
    /// Derive the identity from this machine's hardware (read-only, no storage).
    pub fn derive(tpm_available: bool) -> Self {
        DeviceIdentity {
            sk: SigningKey::from_bytes(&puf_seed()),
            tpm_available,
        }
    }

    pub fn pubkey_hex(&self) -> String {
        hex::encode(self.sk.verifying_key().to_bytes())
    }

    pub fn pubkey_fpr(&self) -> String {
        format!(
            "SHA256:{}",
            hex::encode(Sha256::digest(self.sk.verifying_key().to_bytes()))
        )
    }

    /// Sign `manifest` in place — sets `identity.idevid` + the `signature` block.
    pub fn sign_manifest(&self, manifest: &mut Manifest) {
        // idevid is part of the signed payload — set it before computing the digest.
        manifest.identity.idevid = IDevId {
            kind: IDevIdType::Software, // software-PUF tier; TPM/DICE sealing upgrades this
            pubkey_fpr: self.pubkey_fpr(),
            sealed: false,
        };
        let tbs = to_be_signed(manifest);
        let sig: Signature = self.sk.sign(&tbs);
        manifest.signature = SignatureBlock {
            method: SIG_METHOD.to_string(),
            sig: hex::encode(sig.to_bytes()),
            cert: self.pubkey_hex(),
            tpm_sealed: false,
            pcr_policy: None,
        };
    }
}

/// Canonical to-be-signed bytes: the manifest with an EMPTY signature block, so
/// signing and verification operate on identical bytes.
fn to_be_signed(manifest: &Manifest) -> Vec<u8> {
    let mut clone = manifest.clone();
    clone.signature = SignatureBlock {
        method: String::new(),
        sig: String::new(),
        cert: String::new(),
        tpm_sealed: false,
        pcr_policy: None,
    };
    // CANONICAL bytes: route through serde_json::Value so every object key — including
    // the `capabilities` map — is emitted in sorted order. Serializing the struct
    // directly would iterate its HashMap in per-process-random order, so the signer
    // and the verifier (different processes) would hash different bytes. serde_json's
    // Value uses a BTreeMap (no `preserve_order` feature), giving stable sorted keys.
    let value = serde_json::to_value(&clone).unwrap_or(serde_json::Value::Null);
    serde_json::to_vec(&value).unwrap_or_default()
}

/// Best available key-sealing tier for a device. Real TPM/DICE sealing is a future
/// drop-in (TPM needs `tss-esapi` + root; DICE needs OTP/eFuse access). Until then
/// ALL tiers use the software-PUF key, so the manifest honestly reports
/// `idevid.type = software` / `sealed = false`; this just names the upgrade target.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum SealTier {
    TpmSealed,
    DiceSealed,
    SoftwarePuf,
}
impl SealTier {
    pub fn as_str(&self) -> &'static str {
        match self {
            SealTier::TpmSealed => "tpm-sealed",
            SealTier::DiceSealed => "dice-sealed",
            SealTier::SoftwarePuf => "software-puf",
        }
    }
}

/// The strongest sealing tier this device could use (highest → lowest).
pub fn recommended_tier(tpm_present: bool, dice_available: bool) -> SealTier {
    if tpm_present {
        SealTier::TpmSealed
    } else if dice_available {
        SealTier::DiceSealed
    } else {
        SealTier::SoftwarePuf
    }
}

/// Verification outcome for a loaded manifest.
#[derive(Debug, PartialEq)]
pub enum Verify {
    /// Signed and the signature is valid.
    Valid,
    /// No real signature (reference/unsigned build) — the caller decides policy.
    Unsigned,
}

/// Verify a manifest's self-signature using its embedded public key.
/// Returns `Err` only if a signature is present but INVALID (tampered).
pub fn verify_manifest(manifest: &Manifest) -> Result<Verify> {
    let s = &manifest.signature;
    if s.method != SIG_METHOD || s.sig.is_empty() || s.sig == "UNSIGNED-REFERENCE-BUILD" {
        return Ok(Verify::Unsigned);
    }
    let pk_bytes: [u8; 32] = hex::decode(&s.cert)
        .context("decode public key")?
        .try_into()
        .map_err(|_| anyhow!("public key must be 32 bytes"))?;
    let vk = VerifyingKey::from_bytes(&pk_bytes).context("parse public key")?;
    let sig_bytes: [u8; 64] = hex::decode(&s.sig)
        .context("decode signature")?
        .try_into()
        .map_err(|_| anyhow!("signature must be 64 bytes"))?;
    let sig = Signature::from_bytes(&sig_bytes);
    vk.verify_strict(&to_be_signed(manifest), &sig)
        .map_err(|e| anyhow!("manifest signature INVALID (tampered?): {e}"))?;
    Ok(Verify::Valid)
}
