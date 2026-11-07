//! Module supply-chain verification ("trust nothing unsigned") — cosign-style.
//!
//! Before the supervisor loads a module it verifies a detached signature over the
//! module's content digest against a **baked-in trusted public key**. Signing keys
//! live OFF-device (the release HSM, ADR 0002); the device only VERIFIES, holding
//! public keys in a trust store.
//!
//! This reference signs the digest of the module's `module.yaml` with an Ed25519
//! release key and verifies with `verify_strict`. Production swaps in full
//! sigstore/cosign over the OCI artifact (.wasm / container image) — the trust
//! MECHANISM (sign-the-digest, verify-with-a-trusted-key, refuse-on-mismatch) is
//! identical and is what this implements + tests.

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{anyhow, bail, Context, Result};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use ml_dsa::{
    EncodedSignature as MlDsaEncodedSignature, EncodedVerifyingKey as MlDsaEncodedVerifyingKey,
    Keypair as MlDsaKeypairTrait, MlDsa65, Signature as MlDsaSignature, Signer as MlDsaSignerTrait,
    SigningKey as MlDsaSigningKey, Verifier as MlDsaVerifierTrait, VerifyingKey as MlDsaVerifyingKey,
};
use sha2::{Digest, Sha256, Sha384};
use sha3::Sha3_256;

use crate::module_def::{ArtifactRole, ModuleDef};

// Type aliases: this build ships exactly ONE ML-DSA parameter set (ML-DSA-65, FIPS 204 security
// category 3 — the suite's `module_signing: ["ml-dsa-65", ...]` name). `ml_dsa::MlDsa65` is a
// zero-sized marker type; the alias is purely for readability at call sites below.
type MlDsaSk = MlDsaSigningKey<MlDsa65>;
type MlDsaVk = MlDsaVerifyingKey<MlDsa65>;
type MlDsaSig = MlDsaSignature<MlDsa65>;

/// SHA-256 over the module's signed artifact (here: `module.yaml` bytes).
pub fn module_digest(module_dir: &Path) -> Result<[u8; 32]> {
    let yaml = module_dir.join("module.yaml");
    let bytes = fs::read(&yaml).with_context(|| format!("reading {yaml:?}"))?;
    Ok(Sha256::digest(&bytes).into())
}

#[derive(Debug, PartialEq)]
pub enum SigState {
    Verified,
    Unsigned,
    Invalid,
}
impl SigState {
    pub fn as_str(&self) -> &'static str {
        match self {
            SigState::Verified => "verified",
            SigState::Unsigned => "unsigned",
            SigState::Invalid => "INVALID",
        }
    }
}

/// Verify `<module_dir>/module.sig` against any key in the trust store.
pub fn verify_module(module_dir: &Path, trust: &[VerifyingKey]) -> SigState {
    let Ok(sig_hex) = fs::read_to_string(module_dir.join("module.sig")) else {
        return SigState::Unsigned;
    };
    let Ok(sig_bytes) = hex::decode(sig_hex.trim()) else {
        return SigState::Invalid;
    };
    let Ok(sig_arr) = <[u8; 64]>::try_from(sig_bytes) else {
        return SigState::Invalid;
    };
    let sig = Signature::from_bytes(&sig_arr);
    let Ok(digest) = module_digest(module_dir) else {
        return SigState::Invalid;
    };
    if trust.iter().any(|vk| vk.verify_strict(&digest, &sig).is_ok()) {
        SigState::Verified
    } else {
        SigState::Invalid
    }
}

/// Map a raw signature-verification outcome to the `ModuleDef.sig_verified` tri-state the
/// reconciler/loader consumes, given the module's declared policy (`signature: required|unsigned`).
/// Shared by the reconcile path AND the `--run-wasm` production streaming path so both apply the
/// EXACT same fail-closed rule (see `supervisor::verify_signature`'s doc for the full rationale):
/// `Verified` -> trusted; `Unsigned` -> trusted only if the module doesn't require a signature;
/// `Invalid` (tampered/wrong key) -> never trusted, regardless of policy.
pub fn resolve_sig_verified(state: &SigState, signature_policy: &str) -> Option<bool> {
    match state {
        SigState::Verified => Some(true),
        SigState::Unsigned => {
            if signature_policy == "required" {
                Some(false)
            } else {
                None
            }
        }
        SigState::Invalid => Some(false),
    }
}

/// Load trusted public keys (hex Ed25519, one per `*.pub` file) from a trust dir.
///
/// Deliberately EXCLUDES `*-mldsa.pub` files (see [`load_trust_mldsa`]) — the two legs live in
/// separate namespaces in the SAME trust dir so a hybrid-suite device carries both without either
/// glob picking up the other key type by accident.
pub fn load_trust(trust_dir: &Path) -> Vec<VerifyingKey> {
    let mut keys = Vec::new();
    let Ok(entries) = fs::read_dir(trust_dir) else {
        return keys;
    };
    for e in entries.flatten() {
        let name = e.file_name();
        let name = name.to_string_lossy();
        if name.ends_with(".pub") && !name.ends_with("-mldsa.pub") {
            if let Ok(h) = fs::read_to_string(e.path()) {
                if let Ok(b) = hex::decode(h.trim()) {
                    if let Ok(arr) = <[u8; 32]>::try_from(b) {
                        if let Ok(vk) = VerifyingKey::from_bytes(&arr) {
                            keys.push(vk);
                        }
                    }
                }
            }
        }
    }
    keys
}

// =================================================================================================
// Part A — hybrid ML-DSA-65 module signing (ADR 0002 §3, FIPS 204).
// =================================================================================================
//
// A SECOND, independent detached signature over the EXACT SAME digest `module_digest()` computes
// for the Ed25519 leg — `<module_dir>/module.mldsa.sig` — verified against `*-mldsa.pub` keys in
// the SAME trust store. Pure-Rust RustCrypto `ml-dsa` (FIPS 204, no liboqs/C, `no_std`-capable).
//
// This is a LEG, not a replacement: `verify_module`/`SigState`/`resolve_sig_verified` above are
// completely unchanged and still the Ed25519 half. What makes the hybrid posture REAL is
// `verify_module_for_suite` below, which requires BOTH legs the active crypto suite names —
// fail-closed on a MISSING or INVALID ML-DSA signature, never a silent downgrade to Ed25519-only.

/// Load trusted ML-DSA-65 public keys (hex-encoded `EncodedVerifyingKey<MlDsa65>`, one per
/// `*-mldsa.pub` file) from a trust dir. Malformed entries (wrong length, bad hex) are skipped,
/// not fatal — mirrors `load_trust`'s own tolerance for a partially-populated trust store.
pub fn load_trust_mldsa(trust_dir: &Path) -> Vec<MlDsaVk> {
    let mut keys = Vec::new();
    let Ok(entries) = fs::read_dir(trust_dir) else {
        return keys;
    };
    for e in entries.flatten() {
        let name = e.file_name();
        if !name.to_string_lossy().ends_with("-mldsa.pub") {
            continue;
        }
        let Ok(h) = fs::read_to_string(e.path()) else { continue };
        let Ok(b) = hex::decode(h.trim()) else { continue };
        let Ok(enc) = MlDsaEncodedVerifyingKey::<MlDsa65>::try_from(b.as_slice()) else { continue };
        keys.push(MlDsaVk::decode(&enc));
    }
    keys
}

/// Verify `<module_dir>/module.mldsa.sig` (hex `EncodedSignature<MlDsa65>`) against any trusted
/// ML-DSA-65 key, over the SAME digest [`module_digest`] computes for the Ed25519 leg. Same
/// tri-state contract as [`verify_module`]: `Unsigned` (file absent) / `Invalid` (malformed hex,
/// undecodable signature, or no trusted key verifies it) / `Verified`.
pub fn verify_module_mldsa(module_dir: &Path, trust: &[MlDsaVk]) -> SigState {
    let Ok(sig_hex) = fs::read_to_string(module_dir.join("module.mldsa.sig")) else {
        return SigState::Unsigned;
    };
    let Ok(sig_bytes) = hex::decode(sig_hex.trim()) else {
        return SigState::Invalid;
    };
    let Ok(enc) = MlDsaEncodedSignature::<MlDsa65>::try_from(sig_bytes.as_slice()) else {
        return SigState::Invalid;
    };
    let Some(sig) = MlDsaSig::decode(&enc) else {
        return SigState::Invalid;
    };
    let Ok(digest) = module_digest(module_dir) else {
        return SigState::Invalid;
    };
    if trust.iter().any(|vk| vk.verify(&digest, &sig).is_ok()) {
        SigState::Verified
    } else {
        SigState::Invalid
    }
}

/// Normalize a `crypto.module_signing` leg name (manifest/suite convention is lowercase-hyphen,
/// e.g. `"ml-dsa-65"`/`"ed25519"`) for case-insensitive matching in [`verify_module_for_suite`].
fn normalize_leg(s: &str) -> String {
    s.trim().to_ascii_lowercase()
}

/// The ADR 0002 crypto-agility DISPATCH for module signing — the fix for "`module_signing` is a
/// `Vec<String>` no call site reads": this is the ONE call site, and it is what makes the CBOM's
/// `module_signing: implemented (hybrid)` claim true instead of aspirational.
///
/// For every leg the ACTIVE suite names (`manifest.crypto.module_signing` on-device, or the named
/// suite's `module_signing` off the registry for a manifest-less caller), verify that leg
/// independently and AND the results:
///   - every leg present and verifying → [`SigState::Verified`]
///   - any leg INVALID (tampered/wrong key) → [`SigState::Invalid`] — refused regardless of policy
///     (matches `resolve_sig_verified`'s existing Invalid rule).
///   - otherwise, if any REQUIRED leg is simply ABSENT → [`SigState::Unsigned`] — under a
///     `signature: required` module this still refuses via `resolve_sig_verified` (fail-closed);
///     under a non-required module it is accepted exactly as an absent Ed25519 signature is today.
///
/// This is the critical ANTI-DOWNGRADE property: a hybrid suite (`["ml-dsa-65", "ed25519"]`)
/// stripped of its `module.mldsa.sig` does NOT fall back to Ed25519-only — it reads as `Unsigned`,
/// which a `signature: required` module refuses outright. An Ed25519-only suite (`["ed25519"]`)
/// never even looks for an ML-DSA leg, so it is unaffected (the agility promise: swapping the
/// suite is a policy edit, never a code change).
///
/// An unrecognized leg name (a suite typo, or an algorithm this build does not implement) is
/// treated as unverifiable — [`SigState::Invalid`] — rather than silently skipped; ADR 0002 policy
/// is not hardcoded, but an unknown name must never be treated as an automatic pass.
pub fn verify_module_for_suite(module_dir: &Path, trust_dir: &Path, module_signing_legs: &[String]) -> SigState {
    if module_signing_legs.is_empty() {
        // No policy at all for this domain: nothing verifies, so nothing is trusted (the same
        // fail-closed posture `resolve_sig_verified` already applies to a plain `Unsigned` state).
        return SigState::Unsigned;
    }

    let needs_ed25519 = module_signing_legs.iter().any(|l| normalize_leg(l) == "ed25519");
    let needs_mldsa = module_signing_legs.iter().any(|l| normalize_leg(l) == "ml-dsa-65");
    let ed_trust = if needs_ed25519 { load_trust(trust_dir) } else { Vec::new() };
    let mldsa_trust = if needs_mldsa { load_trust_mldsa(trust_dir) } else { Vec::new() };

    let mut any_invalid = false;
    let mut any_missing = false;
    for leg in module_signing_legs {
        let state = match normalize_leg(leg).as_str() {
            "ed25519" => verify_module(module_dir, &ed_trust),
            "ml-dsa-65" => verify_module_mldsa(module_dir, &mldsa_trust),
            other => {
                eprintln!(
                    "warning: crypto suite names unsupported module-signing leg '{other}' for \
                     {module_dir:?} -- treating as unverifiable (fail-closed, ADR 0002 agility dispatch)"
                );
                SigState::Invalid
            }
        };
        match state {
            SigState::Invalid => any_invalid = true,
            SigState::Unsigned => any_missing = true,
            SigState::Verified => {}
        }
    }

    if any_invalid {
        SigState::Invalid
    } else if any_missing {
        SigState::Unsigned
    } else {
        SigState::Verified
    }
}

// --- DEV release-signing simulation (production signs OFF-device in the HSM) ---

fn sign_module(module_dir: &Path, key: &SigningKey) -> Result<()> {
    let digest = module_digest(module_dir)?;
    let sig = key.sign(&digest);
    fs::write(module_dir.join("module.sig"), hex::encode(sig.to_bytes()))
        .with_context(|| format!("writing {:?}/module.sig", module_dir))?;
    Ok(())
}

fn load_or_create_release_key(path: &Path) -> Result<SigningKey> {
    if let Ok(h) = fs::read_to_string(path) {
        let b = hex::decode(h.trim()).context("decode release key")?;
        let arr = <[u8; 32]>::try_from(b).map_err(|_| anyhow!("release key must be 32 bytes"))?;
        return Ok(SigningKey::from_bytes(&arr));
    }
    // Deterministic DEV key (clearly NOT for production — that uses an HSM).
    let seed: [u8; 32] = Sha256::digest(b"hookprobe-dev-release-key-v1").into();
    if let Some(parent) = path.parent() {
        let _ = fs::create_dir_all(parent);
    }
    let _ = fs::write(path, hex::encode(seed));
    Ok(SigningKey::from_bytes(&seed))
}

// --- Part A sign side: the ML-DSA-65 leg alongside the Ed25519 one ------------------------------

/// `<keyfile>.mldsa` — the ML-DSA-65 seed lives beside the Ed25519 release key, same directory,
/// same "hex of a 32-byte seed" file shape, never colliding with it (distinct filename).
fn mldsa_keyfile_path(keyfile: &Path) -> PathBuf {
    let mut s = keyfile.as_os_str().to_os_string();
    s.push(".mldsa");
    PathBuf::from(s)
}

fn sign_module_mldsa(module_dir: &Path, key: &MlDsaSk) -> Result<()> {
    let digest = module_digest(module_dir)?;
    let sig: MlDsaSig = key.sign(&digest);
    fs::write(module_dir.join("module.mldsa.sig"), hex::encode(sig.encode().as_slice()))
        .with_context(|| format!("writing {:?}/module.mldsa.sig", module_dir))?;
    Ok(())
}

/// Mirrors `load_or_create_release_key` exactly, for the ML-DSA-65 leg: a 32-byte seed (ML-DSA-65
/// seeds are 32 bytes across all FIPS 204 parameter sets, same as Ed25519's) stored as hex; a
/// deterministic DEV seed if the file doesn't exist yet. Production supplies a REAL seed the same
/// way it supplies the Ed25519 one — off-device, in the release HSM (ADR 0002 §5).
fn load_or_create_release_key_mldsa(path: &Path) -> Result<MlDsaSk> {
    if let Ok(h) = fs::read_to_string(path) {
        let b = hex::decode(h.trim()).context("decode ML-DSA release key seed")?;
        let seed = ml_dsa::Seed::try_from(b.as_slice())
            .map_err(|_| anyhow!("ML-DSA release key seed must be 32 bytes"))?;
        return Ok(MlDsaSk::from_seed(&seed));
    }
    // Deterministic DEV seed (clearly NOT for production — that uses an HSM), domain-separated
    // from the Ed25519 dev seed so the two legs never accidentally derive the same key material.
    let seed_bytes: [u8; 32] = Sha256::digest(b"hookprobe-dev-release-key-mldsa-v1").into();
    if let Some(parent) = path.parent() {
        let _ = fs::create_dir_all(parent);
    }
    let _ = fs::write(path, hex::encode(seed_bytes));
    let seed = ml_dsa::Seed::try_from(seed_bytes.as_slice()).map_err(|_| anyhow!("bad ML-DSA seed length"))?;
    Ok(MlDsaSk::from_seed(&seed))
}

/// DEV ONLY: simulate the off-device release-signing step. Loads/creates a release key at
/// `keyfile`, writes its public key to `<trust_dir>/release.pub`, signs every module dir with it
/// (Ed25519 leg) — AND (Part A) does the SAME for a second ML-DSA-65 release key
/// (`<keyfile>.mldsa` → `<trust_dir>/release-mldsa.pub` → `module.mldsa.sig`). Every module this
/// dev tool signs gets BOTH legs, so an on-device hybrid-suite verify (`verify_module_for_suite`)
/// always has both to check. Returns the number of modules signed.
pub fn dev_sign_all(module_dirs: &[PathBuf], keyfile: &Path, trust_dir: &Path) -> Result<usize> {
    let key = load_or_create_release_key(keyfile)?;
    let mldsa_key = load_or_create_release_key_mldsa(&mldsa_keyfile_path(keyfile))?;
    fs::create_dir_all(trust_dir)?;
    fs::write(
        trust_dir.join("release.pub"),
        hex::encode(key.verifying_key().to_bytes()),
    )?;
    fs::write(
        trust_dir.join("release-mldsa.pub"),
        hex::encode(mldsa_key.verifying_key().encode().as_slice()),
    )?;
    for d in module_dirs {
        sign_module(d, &key)?;
        sign_module_mldsa(d, &mldsa_key)?;
    }
    Ok(module_dirs.len())
}

// =================================================================================================
// Generic hybrid signing over an ARBITRARY artifact file (VEX / SBOM / CBOM / any signed
// supply-chain document) — ADR 0024. Reuses EXACTLY the module-signing seam: same dev release
// keys, same trust store, same hybrid ML-DSA-65 + Ed25519 legs, same fail-closed anti-downgrade
// verify contract. The only difference from `dev_sign_all` is the signed payload: SHA-256 over the
// artifact FILE's bytes (not `module.yaml`), with sidecars `<path>.sig` (Ed25519) and
// `<path>.mldsa.sig` (ML-DSA-65) alongside the artifact. This is the "the VEX output is a signed
// artifact like SBOM/CBOM" invariant, implemented once so the exploitability pipeline never rolls
// its own crypto.
// =================================================================================================

/// SHA-256 over an artifact file's bytes — the digest the generic hybrid signers/verifiers below
/// sign. (Distinct from [`module_digest`], which hashes `module.yaml`.)
pub fn artifact_file_digest(artifact: &Path) -> Result<[u8; 32]> {
    let bytes = fs::read(artifact).with_context(|| format!("reading {artifact:?} for signing"))?;
    Ok(Sha256::digest(&bytes).into())
}

/// Append a sidecar extension to an artifact path (`vex.json` → `vex.json.sig`), never replacing
/// the artifact's own extension — the signature lives BESIDE the document.
fn sidecar(artifact: &Path, ext: &str) -> PathBuf {
    let mut s = artifact.as_os_str().to_os_string();
    s.push(".");
    s.push(ext);
    PathBuf::from(s)
}

/// DEV ONLY: hybrid-sign an arbitrary artifact file with BOTH release legs (Ed25519 +
/// ML-DSA-65), publishing the public keys into `trust_dir` exactly as [`dev_sign_all`] does (so a
/// device that already trusts the module-signing release keys trusts these signatures too, no new
/// key distribution). Writes `<artifact>.sig` and `<artifact>.mldsa.sig`. Production signs the
/// same two digests OFF-device in the release HSM (ADR 0002 §5).
pub fn dev_sign_artifact_hybrid(artifact: &Path, keyfile: &Path, trust_dir: &Path) -> Result<()> {
    let key = load_or_create_release_key(keyfile)?;
    let mldsa_key = load_or_create_release_key_mldsa(&mldsa_keyfile_path(keyfile))?;
    fs::create_dir_all(trust_dir)?;
    fs::write(
        trust_dir.join("release.pub"),
        hex::encode(key.verifying_key().to_bytes()),
    )?;
    fs::write(
        trust_dir.join("release-mldsa.pub"),
        hex::encode(mldsa_key.verifying_key().encode().as_slice()),
    )?;
    let digest = artifact_file_digest(artifact)?;
    let sig = key.sign(&digest);
    fs::write(sidecar(artifact, "sig"), hex::encode(sig.to_bytes()))
        .with_context(|| format!("writing {:?}.sig", artifact))?;
    let msig: MlDsaSig = mldsa_key.sign(&digest);
    fs::write(sidecar(artifact, "mldsa.sig"), hex::encode(msig.encode().as_slice()))
        .with_context(|| format!("writing {:?}.mldsa.sig", artifact))?;
    Ok(())
}

/// Verify an artifact file's hybrid signatures against the trust store, for the legs the active
/// crypto suite names (`manifest.crypto.module_signing`). SAME fail-closed, anti-downgrade
/// contract as [`verify_module_for_suite`]: every named leg must be present AND verify; a stripped
/// ML-DSA leg reads `Unsigned` (not a silent Ed25519-only fallback); any tampered leg reads
/// `Invalid`.
pub fn verify_artifact_hybrid(artifact: &Path, trust_dir: &Path, module_signing_legs: &[String]) -> SigState {
    if module_signing_legs.is_empty() {
        return SigState::Unsigned;
    }
    let Ok(digest) = artifact_file_digest(artifact) else {
        return SigState::Invalid;
    };
    let needs_ed25519 = module_signing_legs.iter().any(|l| normalize_leg(l) == "ed25519");
    let needs_mldsa = module_signing_legs.iter().any(|l| normalize_leg(l) == "ml-dsa-65");
    let ed_trust = if needs_ed25519 { load_trust(trust_dir) } else { Vec::new() };
    let mldsa_trust = if needs_mldsa { load_trust_mldsa(trust_dir) } else { Vec::new() };

    let mut any_invalid = false;
    let mut any_missing = false;
    for leg in module_signing_legs {
        let state = match normalize_leg(leg).as_str() {
            "ed25519" => verify_artifact_ed25519(artifact, &digest, &ed_trust),
            "ml-dsa-65" => verify_artifact_mldsa(artifact, &digest, &mldsa_trust),
            other => {
                eprintln!(
                    "warning: crypto suite names unsupported artifact-signing leg '{other}' for \
                     {artifact:?} -- treating as unverifiable (fail-closed, ADR 0002/0024 dispatch)"
                );
                SigState::Invalid
            }
        };
        match state {
            SigState::Invalid => any_invalid = true,
            SigState::Unsigned => any_missing = true,
            SigState::Verified => {}
        }
    }
    if any_invalid {
        SigState::Invalid
    } else if any_missing {
        SigState::Unsigned
    } else {
        SigState::Verified
    }
}

fn verify_artifact_ed25519(artifact: &Path, digest: &[u8; 32], trust: &[VerifyingKey]) -> SigState {
    let Ok(sig_hex) = fs::read_to_string(sidecar(artifact, "sig")) else {
        return SigState::Unsigned;
    };
    let Ok(sig_bytes) = hex::decode(sig_hex.trim()) else { return SigState::Invalid };
    let Ok(sig_arr) = <[u8; 64]>::try_from(sig_bytes) else { return SigState::Invalid };
    let sig = Signature::from_bytes(&sig_arr);
    if trust.iter().any(|vk| vk.verify_strict(digest, &sig).is_ok()) {
        SigState::Verified
    } else {
        SigState::Invalid
    }
}

fn verify_artifact_mldsa(artifact: &Path, digest: &[u8; 32], trust: &[MlDsaVk]) -> SigState {
    let Ok(sig_hex) = fs::read_to_string(sidecar(artifact, "mldsa.sig")) else {
        return SigState::Unsigned;
    };
    let Ok(sig_bytes) = hex::decode(sig_hex.trim()) else { return SigState::Invalid };
    let Ok(enc) = MlDsaEncodedSignature::<MlDsa65>::try_from(sig_bytes.as_slice()) else {
        return SigState::Invalid;
    };
    let Some(sig) = MlDsaSig::decode(&enc) else { return SigState::Invalid };
    if trust.iter().any(|vk| vk.verify(digest, &sig).is_ok()) {
        SigState::Verified
    } else {
        SigState::Invalid
    }
}

// =================================================================================================
// ADR 0016 — artifact-hash signing: the signature must cover the PAYLOAD, not just `module.yaml`.
// =================================================================================================
//
// `module_digest()`/`verify_module()` above prove `module.yaml` (and therefore its `artifacts:`
// block) is authentic. That is necessary but NOT sufficient: a module.yaml can be byte-identical
// and still point at a swapped `.wasm`/loader-ELF/`.bpf.o` on disk, because the signature never
// hashed the payload. `verify_artifact_digests` closes that gap: it recomputes each declared
// artifact's digest from the bytes ACTUALLY on disk and fail-closed-refuses on any mismatch — the
// SAME function reused by both the `--run-wasm` production path and the reconcile load path
// (`supervisor/src/main.rs`), so the two run paths can never diverge (the same discipline ADR 0009
// established for the plain signature gate).

/// Rule-id band for artifact-tamper evidence events (ADR 0016) — a payload swap is a security
/// incident, not a config warning, so it becomes a first-class `detections`-shape evidence-graph
/// node (`hookprobe-evidence::ingest_detection` already parses this exact shape: rule_id/rule_msg/
/// category/severity/mitre/src_ip/dst_ip/dst_port/confidence — no new ingest path needed).
/// Deliberately outside NAPSE's `1_000_0xx` detection-rule band and ADR 0014's reserved `9_000_0xx`
/// ML-tier band.
pub const ARTIFACT_TAMPER_RULE_ID: i64 = 9_100_001;

/// Resolve an artifact's declared `path` against a module's install dir: an ABSOLUTE path (the
/// sysext/host-integral convention, e.g. `/usr/lib/hookprobe/bin/napse-quarantine`) is used as-is;
/// a RELATIVE path (the co-located `.wasm` convention, e.g. `napse.wasm`) resolves under
/// `install_dir` — which callers pass as wherever the payload actually lives (the module's own
/// directory for a plain module.yaml-adjacent file, or the resolved executable's parent dir for the
/// wasm run paths, so this binds to the EXACT file about to execute regardless of which of
/// `wasm_loader::locate_wasm`'s candidate layouts a given run picked).
pub fn resolve_artifact_path(path: &str, install_dir: &Path) -> PathBuf {
    let p = Path::new(path);
    if p.is_absolute() {
        p.to_path_buf()
    } else {
        install_dir.join(p)
    }
}

// =================================================================================================
// ADR 0016/0017 sysext/native-module artifact-digest gap fix — `--write-artifact-digests`/
// `--check-artifact-digests` need to resolve a module's payload the SAME way the STAGING pipeline
// does, not just the co-located `.wasm` convention `resolve_artifact_path` alone assumes.
// =================================================================================================
//
// A `runtime: wasm` module's `artifacts[].path` names a file co-located with its OWN
// `module.yaml` (the `resolve_artifact_path` convention above). A `runtime: sysext`/native-loader
// module (`host-telemetry`, `napse-quarantine`, …) instead pins the on-device **dest** the
// staging pipeline installs to (e.g. `/usr/lib/hookprobe/bin/napse-quarantine`) — there IS no
// file at that absolute path in THIS repo checkout; the actual bytes live at whatever
// `staging.artifacts[].src` in the SAME module.yaml names (a build-tree path, `gen-staging.sh`/
// `stage-apply.sh`'s `{repo}`/`{wasm}`/`{bin}`/`{gnu_bin}` placeholder convention). Before this
// fix, `--write-artifact-digests` only ever tried `resolve_artifact_path` — which for an absolute
// `dest` path just returns it as-is — so it silently found nothing for every sysext module
// (`modules/napse-quarantine/module.yaml`'s own comment documents the resulting hand-`sha256sum`
// workaround). `resolve_artifact_source` below closes that gap by consulting the module's own
// `staging.artifacts[].src -> dest` mapping FIRST, falling back to the unchanged co-located
// convention when no staging entry matches (wasm modules: identical behavior to before).

/// Recognized "not yet populated" sentinel values for an artifact digest — ONE canonical
/// definition (`builder/verify-staging.sh` and `builder/release-pass.sh`'s own checks already
/// used this exact token set independently; this is the single Rust source of truth other
/// checks should match, not a new convention). A module author writes one of these by hand when
/// declaring an `artifacts:` entry whose real bytes cannot be produced in the CURRENT build
/// environment (e.g. a cross-arch native binary with no cross-toolchain on this box) — the
/// REAL per-arch release build is expected to overwrite it via `--write-artifact-digests` before
/// `--sign-modules` runs (ADR 0016 D5 rollout: no shipped image may carry one of these).
pub fn is_placeholder_digest(value: &str) -> bool {
    matches!(
        value.trim().to_ascii_uppercase().as_str(),
        "" | "PENDING" | "TODO" | "DEADBEEF"
    )
}

/// Map an arch token (`arm64`/`amd64`/`riscv64` — [`running_arch`]'s vocabulary) to the Rust
/// target triple `builder/stage-apply.sh`'s `TRIPLE=` case statement derives it from. Kept in
/// exact lockstep with that script — if its triples change, this must change too (one
/// convention, enforced in two languages, not two conventions).
fn arch_triple(arch: &str) -> Result<&'static str> {
    Ok(match arch {
        "arm64" => "aarch64",
        "amd64" => "x86_64",
        "riscv64" => "riscv64gc",
        other => bail!(
            "resolve_staging_src: unknown arch '{other}' (expected arm64|amd64|riscv64 — \
             builder/stage-apply.sh's vocabulary)"
        ),
    })
}

/// Resolve a `staging.artifacts[].src` value (`module.yaml`, ADR 0015 D1) to a real filesystem
/// path, using EXACTLY the placeholder convention `builder/stage-apply.sh::resolve()` and
/// `builder/gen-staging.sh::resolve_src()` already define for the staging pipeline — this
/// function is not a second convention, it re-derives the SAME one in Rust, so the digest tool
/// hashes the identical bytes the staging pipeline would install.
///
/// Placeholders: `{repo}` (repo root), `{wasm}` (`target/wasm32-wasip1/release`), `{bin}`
/// (`target/<triple>-unknown-linux-musl/release`), `{gnu_bin}` (`target/<triple>-unknown-linux-gnu/release`).
/// A bare (non-`{`-prefixed) `src` is repo-relative — `gen-staging.sh::resolve_src()`'s rule for
/// a bare `staging.artifacts[].src` in `module.yaml` (it prefixes `{repo}/` before this convention
/// ever sees it; a raw `module.yaml` read, as this function's callers do, still needs the same
/// prefixing applied here). `WASM`/`BIN`/`GNU_BIN` env vars override the default derived dirs,
/// mirroring `stage-apply.sh`'s own overridable env, so a CI run that customizes those resolves
/// identically here.
pub fn resolve_staging_src(src: &str, repo_root: &Path, arch: &str) -> Result<PathBuf> {
    fn env_or(var: &str, default: PathBuf) -> PathBuf {
        std::env::var(var).map(PathBuf::from).unwrap_or(default)
    }

    let resolved = if let Some(rest) = src.strip_prefix("{repo}/") {
        repo_root.join(rest)
    } else if let Some(rest) = src.strip_prefix("{wasm}/") {
        env_or("WASM", repo_root.join("target/wasm32-wasip1/release")).join(rest)
    } else if let Some(rest) = src.strip_prefix("{bin}/") {
        let triple = arch_triple(arch)?;
        env_or("BIN", repo_root.join(format!("target/{triple}-unknown-linux-musl/release"))).join(rest)
    } else if let Some(rest) = src.strip_prefix("{gnu_bin}/") {
        let triple = arch_triple(arch)?;
        env_or("GNU_BIN", repo_root.join(format!("target/{triple}-unknown-linux-gnu/release"))).join(rest)
    } else if src.starts_with('{') {
        bail!(
            "resolve_staging_src: unsupported placeholder in src '{src}' (builder/stage-apply.sh \
             defines only {{repo}}/{{wasm}}/{{bin}}/{{gnu_bin}} — must not invent a new one)"
        );
    } else {
        // Bare repo-relative path: `gen-staging.sh::resolve_src()`'s convention for a bare
        // `staging.artifacts[].src` value.
        repo_root.join(src)
    };
    Ok(resolved)
}

/// The ADR 0016/0017 sysext/native-loader gap fix: resolve an artifact's digest-check bytes by
/// preferring the module's OWN `staging.artifacts[].src -> dest` mapping (the build-tree source
/// path `gen-staging.sh`/`stage-apply.sh` stage it FROM) whenever it names the exact on-device
/// `dest` a declared `artifacts[]` entry's `path` pins. This is the honest source of truth for a
/// module whose payload is declared by staged/on-device path (`runtime: sysext`/native-loader
/// convention), not by the module's own directory (the co-located `.wasm` convention
/// `resolve_artifact_path` alone assumes). Falls back to the plain `resolve_artifact_path`
/// unchanged when no staging entry matches — every co-located wasm module behaves exactly as
/// before this function existed.
pub fn resolve_artifact_source(
    def: &ModuleDef,
    artifact_path: &str,
    module_dir: &Path,
    repo_root: &Path,
    arch: &str,
) -> Result<PathBuf> {
    if let Some(staging) = &def.staging {
        if let Some(sa) = staging.artifacts.iter().find(|a| a.dest == artifact_path) {
            return resolve_staging_src(&sa.src, repo_root, arch);
        }
    }
    Ok(resolve_artifact_path(artifact_path, module_dir))
}

/// Hex digest of `bytes` under a NAMED algorithm — crypto-agile per ADR 0002, never a hardcoded
/// choice. Rejects (fail-closed) any algorithm this build does not implement, rather than treating
/// an unrecognized name as an automatic pass.
pub fn digest_hex(alg: &str, bytes: &[u8]) -> Result<String> {
    Ok(match alg {
        "sha256" => hex::encode(Sha256::digest(bytes)),
        "sha384" => hex::encode(Sha384::digest(bytes)),
        "sha3-256" => hex::encode(Sha3_256::digest(bytes)),
        other => bail!("unsupported digest alg '{other}' (ADR 0002 policy — not hardcoded, but this build implements sha256/sha384/sha3-256 only)"),
    })
}

fn now_ts() -> f64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0)
}

/// Render one JSON-lines evidence event for a payload-digest mismatch, in the SAME `detections`
/// shape `hookprobe-evidence::ingest_detection` already parses. `src_ip`/`dst_ip`/`dst_port` are
/// empty/zero (this is a supply-chain event, not a network one) — `ingest_detection` does not
/// require them non-empty, so the event still ingests as a first-class node.
pub fn artifact_tamper_event(module_id: &str, artifact_path: &str, expected: &str, actual: &str, ts: f64) -> String {
    serde_json::json!({
        "ts": ts,
        "rule_id": ARTIFACT_TAMPER_RULE_ID,
        "rule_msg": format!("ArtifactTamper: {module_id} artifact '{artifact_path}' failed its ADR 0016 digest check"),
        "category": "supply_chain_tamper",
        "severity": 3,
        "mitre": "T1195",
        "src_ip": "",
        "dst_ip": "",
        "dst_port": 0,
        "confidence": 1.0,
        "module": module_id,
        "path": artifact_path,
        "expected": expected,
        "actual": actual,
    })
    .to_string()
}

/// Append one `artifact_tamper_event` line to the events file (best-effort — O_APPEND, atomic for
/// one `write_all` under `PIPE_BUF`, same convention `napse-dpi` uses for the same file). A write
/// failure here must never mask the underlying digest-mismatch error the caller is already
/// fail-closing on: this function never returns an error, it only logs one on stderr.
pub fn emit_artifact_tamper(events_path: &Path, module_id: &str, artifact_path: &str, expected: &str, actual: &str) {
    let line = artifact_tamper_event(module_id, artifact_path, expected, actual, now_ts());
    match fs::OpenOptions::new().create(true).append(true).open(events_path) {
        Ok(mut f) => {
            use std::io::Write as _;
            if let Err(e) = writeln!(f, "{line}") {
                eprintln!("warning: could not append ArtifactTamper event to {events_path:?}: {e}");
            }
        }
        Err(e) => eprintln!("warning: could not open events file {events_path:?} for ArtifactTamper event: {e}"),
    }
}

/// ADR 0021 (multi-arch native artifacts, extending ADR 0016/0017) — true iff `def` declares at
/// least one artifact of `role` that APPLIES to `running`: either arch-less (arch-independent —
/// today's single-arch-canonical convention, unchanged) or explicitly `arch:`-qualified to
/// `running` itself. Used to detect the dangerous "this module DOES pin `role` digests, but only
/// for OTHER arches" condition — for a native (non-wasm) role (`executable`/`loader`/
/// `bpf-object`) there is no JIT-fallback floor the way `role: aot` has, so that condition must be
/// treated exactly like "no digest pinned at all" (D5), not silently ignored.
fn has_arch_applicable_artifact(def: &ModuleDef, role: ArtifactRole, running: &str) -> bool {
    def.artifacts.iter().any(|a| {
        a.role == role
            && a.arch
                .as_deref()
                .map(|ar| ar.eq_ignore_ascii_case(running))
                .unwrap_or(true)
    })
}

/// ADR 0021: true iff `def` declares role `role` at all (for ANY arch) but NONE of those entries
/// apply to `running` — i.e. every declared entry for this role is arch-qualified to some OTHER
/// arch. This is the multi-arch analogue of "missing digest": on THIS build's arch, the role is
/// exactly as unprotected as if it had never been declared.
fn role_declared_but_not_for_this_arch(def: &ModuleDef, role: ArtifactRole, running: &str) -> bool {
    let declared_any = def.artifacts.iter().any(|a| a.role == role);
    declared_any && !has_arch_applicable_artifact(def, role, running)
}

/// The ADR 0016 D2/D5 gate (extended by ADR 0021 for multi-arch native artifacts):
/// recompute-and-match every artifact digest a module declares FOR THIS BUILD'S ARCH,
/// fail-closed.
///
/// Rules:
///   1. (D5) A `signature: required` module with an EMPTY `artifacts:` block is an unprotected
///      payload — a HARD FAIL in a release build (`#[cfg(not(debug_assertions))]`), a loud warning
///      in dev/debug (so `cargo run -- --run-wasm <id>` against unsigned local builds still works
///      during development). No grandfathering flag: an image either pins every payload or fails
///      its release pass (ADR 0016 D5).
///   2. (ADR 0021) The SAME hard-fail/dev-warn gate fires when a native role
///      (`executable`/`loader`/`bpf-object`) IS declared, but only for OTHER arches than this
///      build's own (`running_arch()`) — a module shipped on an arch it never pinned a digest for
///      is exactly as unprotected, on THAT arch, as a module with an empty `artifacts:` block.
///   3. Every DECLARED artifact APPLICABLE to this build's arch (arch-less, i.e. arch-independent,
///      OR `arch:`-qualified to `running_arch()`) has its digest recomputed from the bytes on disk
///      and compared; a missing file, an unreadable file, an unsupported algorithm, or a mismatch
///      is a fail-closed refusal — REGARDLESS of build profile. This is affirmative evidence of
///      tampering (or a broken release), never merely "unsigned", so `--allow-unsigned` must NOT
///      (and does not) exempt it — that flag is wired to signature-absence only in
///      `supervisor::verify_signature`, never plumbed into this function at all. An entry
///      `arch:`-qualified to a DIFFERENT arch is skipped entirely — inert signed metadata for
///      another platform's image build, never opened, never a reason to fail (mirrors
///      `verify_aot_binding`'s own arch selection for `role: aot`, generalized to every role).
///
/// `events_path`, when given, gets one `ArtifactTamper` evidence-graph line appended per mismatch
/// (best-effort — see `emit_artifact_tamper`); `None` is the right choice for tests / any caller
/// with no on-disk evidence stream to append to.
pub fn verify_artifact_digests(def: &ModuleDef, install_dir: &Path, events_path: Option<&Path>) -> Result<()> {
    let running = running_arch();
    let unprotected_for_this_arch = [ArtifactRole::Executable, ArtifactRole::Loader, ArtifactRole::BpfObject]
        .into_iter()
        .any(|r| role_declared_but_not_for_this_arch(def, r, running));

    if def.signature == "required" && (def.artifacts.is_empty() || unprotected_for_this_arch) {
        let msg = if unprotected_for_this_arch {
            format!(
                "{}: signature: required but every native (executable/loader/bpf-object) artifact \
                 digest is pinned for a DIFFERENT arch than this build's own ({running}) — payload is \
                 UNPROTECTED here (ADR 0016/0021). Run this arch's own build through \
                 `hookprobe-supervisor --write-artifact-digests {}` then re-sign with builder/sign-release.sh.",
                def.id, def.id
            )
        } else {
            format!(
                "{}: signature: required but module.yaml pins no artifact digest — payload is \
                 UNPROTECTED (ADR 0016). Populate it with `hookprobe-supervisor --write-artifact-digests {}` \
                 then re-sign with builder/sign-release.sh.",
                def.id, def.id
            )
        };
        #[cfg(not(debug_assertions))]
        bail!("refusing to load: {msg}");
        #[cfg(debug_assertions)]
        eprintln!("warning: {msg} (dev/debug build only — this is a HARD FAIL in a release build, ADR 0016 D5)");
    }

    for a in &def.artifacts {
        // ADR 0017: `role: aot` entries are exempt from this blanket sweep for the same reason
        // `verify_executable_binding` exempts them — an absent/stale AOT blob must fall back to
        // JIT, never hard-fail a module's load. (This function only runs for `signature:
        // unsigned` modules in `load_module_gated` today, but keeping the rule identical in both
        // sweeps avoids a footgun if it's ever reused elsewhere.)
        if a.role == ArtifactRole::Aot {
            continue;
        }
        // ADR 0021: an entry `arch:`-qualified to a DIFFERENT arch than this running build is
        // inert signed metadata for another platform's image — never attempted, never opened,
        // never a reason to fail. An arch-less entry (`None`) stays arch-independent, exactly the
        // pre-ADR-0021 behavior.
        if let Some(a_arch) = a.arch.as_deref() {
            if !a_arch.eq_ignore_ascii_case(running) {
                continue;
            }
        }
        let file = resolve_artifact_path(&a.path, install_dir);
        let bytes = fs::read(&file).with_context(|| {
            format!(
                "{}: artifact '{}' not found for its ADR 0016 digest check (resolved: {file:?})",
                def.id, a.path
            )
        })?;
        let actual = digest_hex(&a.digest.alg, &bytes).with_context(|| format!("{}: artifact '{}'", def.id, a.path))?;
        if !actual.eq_ignore_ascii_case(a.digest.value.trim()) {
            if let Some(ep) = events_path {
                emit_artifact_tamper(ep, &def.id, &a.path, &a.digest.value, &actual);
            }
            bail!(
                "refusing {}: artifact '{}' digest MISMATCH — payload tampered (expected {}, got {}). \
                 ADR 0016 fail-closed.",
                def.id, a.path, a.digest.value, actual
            );
        }
    }
    Ok(())
}

// =================================================================================================
// ADR 0016 Findings 1 & 3 — the CRITICAL fix: hash the bytes about to EXECUTE, and bind them to
// a declared artifact, not just a digest match on whatever happens to be at a path.
// =================================================================================================
//
// `verify_artifact_digests` above has two gaps a 2026-07-04/05 audit found:
//
//   Finding 1 (CRITICAL): every caller re-opened the artifact path to hash it, then SEPARATELY
//   let the loader open (a possibly different!) file to actually run. On a device with a
//   writable-partition AOT cache (`.cwasm`), an attacker who can write there swaps in a
//   malicious `.cwasm` + a sidecar claiming the (untouched, real) `.wasm`'s hash — the digest
//   check above passes (it hashes the real, unmodified `.wasm`), but Wasmtime then
//   `deserialize_file`s the EVIL `.cwasm`. No key is forged; the check just never looked at the
//   bytes that actually ran.
//
//   Finding 3: `verify_artifact_digests` iterates whatever `artifacts:` DECLARES, but never
//   confirms the file about to execute is actually one of those declared entries. A manifest
//   whose `artifacts:` block names only a `role: data` file (digest matches) passes cleanly
//   while the real, unpinned `.wasm` executes unchecked.
//
// `verify_executable_binding` below closes BOTH: the caller reads the file that is about to run
// EXACTLY ONCE and hands those bytes in — this function never re-opens that path — AND requires
// the resolved, canonicalized path to match a declared `role: executable`/`role: loader` entry.

/// Resolve `resolved` for the ADR 0016 Finding-3 execute-time binding check: refuses (fail-closed)
/// if `declared_path` (the artifact's `path:` field as written in the signed `module.yaml`)
/// contains a literal `..` path-traversal component, or if `resolved` is itself a symlink.
/// Returns the canonical (symlink-free, absolute) path on success. NOTE: this only inspects the
/// FINAL path component for a symlink — a symlinked ANCESTOR directory is not separately detected
/// beyond whatever `fs::canonicalize` folds in; that is an accepted, documented residual (the
/// payloads this binds are shipped on the immutable rootfs under a build-controlled tree, not an
/// attacker-writable one — see ADR 0016 Fix B).
fn reject_traversal_or_symlink(declared_path: &str, resolved: &Path) -> Result<PathBuf> {
    if declared_path.split(['/', '\\']).any(|c| c == "..") {
        bail!(
            "refusing artifact path '{declared_path}': contains '..' path traversal \
             (ADR 0016 Finding 3 path-binding check)"
        );
    }
    no_symlink_canonical(resolved)
}

/// Like `reject_traversal_or_symlink`, but for a path that is not itself a *declared* artifact
/// string (e.g. the resolved executable path `locate_executable` handed back) — no `..`-in-source
/// check applies (that check is about a signed manifest's own `path:` field), only the
/// no-symlink + canonicalize half.
fn no_symlink_canonical(resolved: &Path) -> Result<PathBuf> {
    let meta = fs::symlink_metadata(resolved).with_context(|| {
        format!("stat {resolved:?} for the ADR 0016 Finding-3 path-binding check")
    })?;
    if meta.file_type().is_symlink() {
        bail!(
            "refusing {resolved:?}: symlink is not permitted at the ADR 0016 Finding-3 \
             execute-time path-binding check"
        );
    }
    fs::canonicalize(resolved)
        .with_context(|| format!("canonicalize {resolved:?} for the ADR 0016 path-binding check"))
}

/// The ADR 0016 Findings 1+3 fail-closed gate — the ONE check a loader calls immediately before
/// compiling/executing a specific file it has ALREADY READ INTO MEMORY as `exec_bytes`.
///
/// Two things must both hold:
///
///  1. **Path-binding (Finding 3).** `exec_path` (canonicalized; symlinked/`..` rejected) MUST
///     equal the canonicalized path of some artifact this module declares with
///     `role: executable` (the wasm convention) or `role: loader` (the sysext/native-loader
///     convention — there is no "executable" role to bind to for those). A manifest whose
///     `artifacts:` block pins only an unrelated `role: data`/`role: bpf-object` entry, leaving
///     the real payload unchecked, is refused here instead of silently passing.
///  2. **Digest, on the bytes actually about to run (Finding 1).** The artifact that binds to
///     `exec_path` is verified against `exec_bytes` — the caller's own in-memory read — NEVER by
///     re-opening `exec_path` again. This is what closes the `.cwasm`-swap TOCTOU: whatever the
///     loader is about to hand to the compiler is EXACTLY what got hashed and compared, with no
///     window in between for a writable-partition artifact to change out from under the check.
///     Every OTHER artifact this module declares (e.g. a sibling `data`/`bpf-object` file) is
///     still verified by reading it fresh from disk, exactly as `verify_artifact_digests` does.
///
/// D5 (an empty `artifacts:` on a `signature: required` module is a release-build hard fail,
/// a loud dev/debug warning otherwise) applies identically to `verify_artifact_digests`, extended
/// (ADR 0021) to "every `role: executable`/`role: loader` entry is pinned for a DIFFERENT arch
/// than this build's own `running_arch()`" — treated exactly like an empty block, since an
/// arch-mismatched entry never binds (skipped below) and so can never satisfy Finding 3's
/// "the executing file matched a declared entry" requirement either way; the two code paths
/// (the early D5-style message here, and the generic "no artifact bound" refusal at the end of
/// this function) both fire fail-closed for this condition — belt and suspenders, not redundant
/// dead code, since either could independently be reached depending on what else is declared.
pub fn verify_executable_binding(
    def: &ModuleDef,
    install_dir: &Path,
    exec_path: &Path,
    exec_bytes: &[u8],
    events_path: Option<&Path>,
) -> Result<()> {
    let running = running_arch();
    let unprotected_for_this_arch = [ArtifactRole::Executable, ArtifactRole::Loader]
        .into_iter()
        .any(|r| role_declared_but_not_for_this_arch(def, r, running));

    if def.signature == "required" && (def.artifacts.is_empty() || unprotected_for_this_arch) {
        let msg = if unprotected_for_this_arch {
            format!(
                "{}: signature: required but every executable/loader artifact digest is pinned for \
                 a DIFFERENT arch than this build's own ({running}) — payload is UNPROTECTED here \
                 (ADR 0016/0021). Run this arch's own build through \
                 `hookprobe-supervisor --write-artifact-digests {}` then re-sign with builder/sign-release.sh.",
                def.id, def.id
            )
        } else {
            format!(
                "{}: signature: required but module.yaml pins no artifact digest — payload is \
                 UNPROTECTED (ADR 0016). Populate it with `hookprobe-supervisor --write-artifact-digests {}` \
                 then re-sign with builder/sign-release.sh.",
                def.id, def.id
            )
        };
        #[cfg(not(debug_assertions))]
        bail!("refusing to load: {msg}");
        #[cfg(debug_assertions)]
        eprintln!("warning: {msg} (dev/debug build only — this is a HARD FAIL in a release build, ADR 0016 D5)");
    }

    let exec_canon = no_symlink_canonical(exec_path).with_context(|| {
        format!(
            "{}: resolving the file about to execute ({exec_path:?}) for the ADR 0016 \
             Finding-3 binding check",
            def.id
        )
    })?;

    let mut bound = false;
    for a in &def.artifacts {
        // ADR 0017: `role: aot` entries are NEVER part of this sweep. They are checked
        // separately and MORE LENIENTLY by `verify_aot_binding` (absent/wrong-arch/mismatched ->
        // fall back to verified JIT, never a hard failure of the whole load) -- folding them into
        // THIS function's blanket "every declared artifact must digest-match or the load fails"
        // rule would turn a merely-unavailable AOT fast path (normal, safe, D2) into a hard
        // refusal to load the module at all, which is exactly the load-bearing safety property
        // ADR 0017 D2 says must NOT happen ("any doubt -> verified JIT, never a hard failure").
        if a.role == ArtifactRole::Aot {
            continue;
        }
        // ADR 0021: an entry `arch:`-qualified to a DIFFERENT arch than this running build is
        // inert signed metadata for another platform's image — never attempted, never opened,
        // never allowed to bind (and, if it happens to share a `path` with THIS arch's own entry,
        // never confused with it — path equality alone is no longer sufficient to bind, arch must
        // match too). An arch-less entry (`None`) stays arch-independent, exactly the pre-ADR-0021
        // single-arch-canonical behavior.
        if let Some(a_arch) = a.arch.as_deref() {
            if !a_arch.eq_ignore_ascii_case(running) {
                continue;
            }
        }
        let file = resolve_artifact_path(&a.path, install_dir);
        let is_executing_role = matches!(a.role, ArtifactRole::Executable | ArtifactRole::Loader);

        // Does THIS declared artifact resolve to the exact file about to execute? If so, verify
        // it against the caller's pre-read bytes (Finding 1) instead of touching the path again.
        let pinned_match = is_executing_role
            && reject_traversal_or_symlink(&a.path, &file)
                .map(|c| c == exec_canon)
                .unwrap_or(false);

        let actual = if pinned_match {
            bound = true;
            digest_hex(&a.digest.alg, exec_bytes).with_context(|| format!("{}: artifact '{}'", def.id, a.path))?
        } else {
            let bytes = fs::read(&file).with_context(|| {
                format!(
                    "{}: artifact '{}' not found for its ADR 0016 digest check (resolved: {file:?})",
                    def.id, a.path
                )
            })?;
            digest_hex(&a.digest.alg, &bytes).with_context(|| format!("{}: artifact '{}'", def.id, a.path))?
        };

        if !actual.eq_ignore_ascii_case(a.digest.value.trim()) {
            if let Some(ep) = events_path {
                emit_artifact_tamper(ep, &def.id, &a.path, &a.digest.value, &actual);
            }
            bail!(
                "refusing {}: artifact '{}' digest MISMATCH — payload tampered (expected {}, got {}). \
                 ADR 0016 fail-closed.",
                def.id, a.path, a.digest.value, actual
            );
        }
    }

    // Finding 3: an artifacts: block that never actually named the file about to execute is
    // exactly as dangerous as a missing block — refuse, don't silently trust path equality by
    // coincidence. Only enforced when the module actually declares artifacts (an empty block on
    // a non-`required` module is D5's concern, already handled above; nothing to bind to here).
    if !def.artifacts.is_empty() && !bound {
        bail!(
            "refusing {}: the file about to execute ({exec_path:?}) does not match any declared \
             `role: executable`/`role: loader` artifact digest — an artifacts: block that pins \
             only an unrelated artifact (e.g. role: data/bpf-object) must not pass \
             (ADR 0016 Finding 3 path-binding check).",
            def.id
        );
    }

    Ok(())
}

// =================================================================================================
// ADR 0017 — authenticated AOT cache: move the `.cwasm` INSIDE the trust boundary. Build-time
// precompile per arch -> ship in the RO rootfs -> digest pinned in the SAME signed `module.yaml`
// (a `role: aot`, arch-qualified `ArtifactDigest`) -> the supervisor verifies the exact `.cwasm`
// bytes about to be `Module::deserialize`d against that entry BEFORE deserializing, and falls back
// to the ADR 0016 Fix A verified-JIT floor on ANY doubt. Extends ADR 0016, never replaces it: the
// `.wasm` digest/path-binding/signature mechanism above is completely unchanged.
// =================================================================================================

/// The architecture token (`arm64` | `amd64` | `riscv64` | `unknown`) THIS compiled binary
/// targets. A bootc image is arch-specific and its `build` stage runs AS the target arch (ADR
/// 0017 context — QEMU-emulated `--platform linux/${TARGETARCH}` in CI produces a `.cwasm` native
/// to that arch, deserialize-compatible with the identically-arched device that later loads it).
/// So the arch this very process was compiled for IS the one arch whose `role: aot` entry could
/// ever be true for a `.cwasm` shipped alongside it — this needs no Platform Manifest lookup, and
/// so works even on the `--run-wasm` streaming entry point, which never requires one.
pub fn running_arch() -> &'static str {
    if cfg!(target_arch = "aarch64") {
        "arm64"
    } else if cfg!(target_arch = "x86_64") {
        "amd64"
    } else if cfg!(target_arch = "riscv64") {
        "riscv64"
    } else {
        "unknown"
    }
}

/// The ADR 0017 D2 authenticated-AOT gate: verify an ALREADY-READ-INTO-MEMORY `.cwasm`'s bytes
/// against the ONE `role: aot` artifact entry matching (`arch`, `cpu`), path-bound to `path` (canonicalized,
/// symlink-free, non-traversal — the same Finding-3 discipline `verify_executable_binding` applies
/// to the `.wasm`), fail-closed. `bytes` MUST be the exact bytes the caller is about to
/// `Module::deserialize` — this function NEVER re-opens `path` (closes the identical TOCTOU class
/// Fix A closed for the `.wasm`: whatever gets hashed is exactly what gets loaded, no window for a
/// swap in between).
///
/// Two distinct "not ok" outcomes, DELIBERATELY different (ADR 0017 D2 "digest-mismatch is an
/// incident, not a warning"):
///   - **Absent for this arch** (no `role: aot` entry declares `arch`, or none of the ones that do
///     resolve to `path`) — a plain `Err`, NO `ArtifactTamper` event. This is the NORMAL, safe,
///     WARN-only condition D3 describes ("a module that ships no AOT for the built arch" falls
///     back to verified JIT) — absence is not evidence of tampering.
///   - **Digest MISMATCH** on a blob that IS present and IS declared for `arch` — `Err` +
///     `ArtifactTamper` evidence event (same shape/rule-band as ADR 0016's). A swapped RO-rootfs
///     `.cwasm` is affirmative tamper evidence, surfaced in Detect/Investigate.
///
/// Callers MUST treat every `Err` from this function identically: fall back to the ADR 0016 Fix A
/// floor (`Module::from_binary` on the already-verified `.wasm` bytes). There is no code path from
/// an `Err` here to `Module::deserialize`-ing `bytes` anyway — enforced by the caller
/// (`wasm_loader::load_module_gated`), not by this function refusing to return.
/// `cpu` (ADR 0021 A76 selection): the CPU-microarch tier the caller resolved this blob FOR — the
/// signed Platform Manifest's `hardware.cpu.tier`. `None` binds ONLY a baseline `role: aot` entry
/// (one with no `cpu:` field — loadable on the arch's oldest CPU); `Some("cortex-a76")` binds ONLY
/// an entry carrying `cpu: cortex-a76`. The two never substitute for each other: a baseline request
/// never accepts an A76 blob (it would trap on an illegal LSE instruction on an A72), and an A76
/// request never silently accepts the baseline entry here — the CALLER (`load_module_gated`) does
/// the baseline fallback explicitly, as a SEPARATE `cpu: None` verify pass, so each pass proves the
/// exact (arch, cpu) blob it selected.
pub fn verify_aot_binding(
    def: &ModuleDef,
    install_dir: &Path,
    arch: &str,
    cpu: Option<&str>,
    path: &Path,
    bytes: &[u8],
    events_path: Option<&Path>,
) -> Result<()> {
    let path_canon = no_symlink_canonical(path).with_context(|| {
        format!("{}: resolving the AOT blob ({path:?}) for the ADR 0017 binding check", def.id)
    })?;

    for a in &def.artifacts {
        if a.role != ArtifactRole::Aot {
            continue;
        }
        let Some(a_arch) = a.arch.as_deref() else {
            continue; // an `aot` entry with no `arch` is malformed (D1 requires it) -- skip, not trust
        };
        if !a_arch.eq_ignore_ascii_case(arch) {
            continue; // another arch's entry -- inert signed metadata, never consulted (ADR 0017 D1)
        }
        // ADR 0021 CPU-tier selection: the entry's `cpu:` must EXACTLY match the requested tier.
        // `None`(request) binds `None`(entry) — the baseline; `Some(tier)` binds only the entry
        // declaring that same tier. Never cross-bind (an A76 blob for a baseline request would
        // crash on an A72; a baseline blob is not what an A76 request selected). Belt-and-suspenders
        // with `locate_rootfs_aot`, which already picked the (arch,cpu) entry's `path` — this
        // re-derives the same match so the digest is checked against the RIGHT declared entry.
        let cpu_matches = match (cpu, a.cpu.as_deref()) {
            (None, None) => true,
            (Some(want), Some(have)) => want.eq_ignore_ascii_case(have),
            _ => false,
        };
        if !cpu_matches {
            continue;
        }
        let candidate = resolve_artifact_path(&a.path, install_dir);
        let candidate_canon = match reject_traversal_or_symlink(&a.path, &candidate) {
            Ok(c) => c,
            Err(_) => continue, // a malformed declared path never binds; keep looking for another
        };
        if candidate_canon != path_canon {
            continue; // declared for THIS arch, but not the file the caller resolved -- no bind
        }

        // Bound: this is THE entry for (path, arch, cpu). Verify the CALLER'S bytes (Finding-1
        // discipline) -- never re-read `path`.
        let actual = digest_hex(&a.digest.alg, bytes)
            .with_context(|| format!("{}: AOT artifact '{}' (arch {arch}, cpu {})", def.id, a.path, cpu.unwrap_or("baseline")))?;
        if !actual.eq_ignore_ascii_case(a.digest.value.trim()) {
            if let Some(ep) = events_path {
                emit_artifact_tamper(ep, &def.id, &a.path, &a.digest.value, &actual);
            }
            bail!(
                "refusing {}: AOT artifact '{}' (arch {arch}, cpu {}) digest MISMATCH — RO-rootfs .cwasm \
                 tampered (expected {}, got {}). ADR 0017 fail-closed — falling back to verified JIT.",
                def.id, a.path, cpu.unwrap_or("baseline"), a.digest.value, actual
            );
        }
        return Ok(());
    }

    bail!(
        "{}: no `role: aot` artifact declared for arch '{arch}' cpu '{}' binding to {path:?} — falling \
         back to verified JIT (ADR 0017/0021: absent/wrong-arch/wrong-cpu AOT is a normal, safe \
         condition, not tampering).",
        def.id, cpu.unwrap_or("baseline")
    );
}

/// Replace the `value: "..."` line of a matching `artifacts[]` entry with `new_hex` — a surgical
/// text edit that preserves every comment and everything else in `module.yaml` untouched (a full
/// parse+reserialize through `serde_yaml` would silently drop the hand-written documentation
/// every `module.yaml` in this repo carries). Used by the `--write-artifact-digests` builder step
/// (ADR 0016 D3 / ADR 0017 D3): the module author declares `path`+`role`(+`arch`) once by hand;
/// this tool only ever refreshes `value`.
///
/// `want_arch: None` matches the FIRST entry whose `path:` equals `artifact_path` — the original
/// ADR 0016 behavior, correct for every role except `aot` (a `path` disambiguated by role alone).
/// `want_arch: Some(a)` additionally requires an `arch: a` line inside that SAME entry block
/// before the next entry starts — required for `role: aot`, whose entries legitimately REPEAT the
/// same `path` once per built arch (ADR 0017 D1) and are disambiguated only by `arch`.
pub fn write_digest_value_matching(
    text: &str,
    artifact_path: &str,
    want_arch: Option<&str>,
    new_hex: &str,
) -> Result<String> {
    fn entry_path(trimmed: &str) -> Option<&str> {
        let rest = trimmed.strip_prefix("- path:").or_else(|| trimmed.strip_prefix("path:"))?;
        Some(rest.split('#').next().unwrap_or("").trim().trim_matches('"'))
    }
    fn entry_arch(trimmed: &str) -> Option<&str> {
        let rest = trimmed.strip_prefix("arch:")?;
        Some(rest.split('#').next().unwrap_or("").trim().trim_matches('"'))
    }

    let lines: Vec<&str> = text.lines().collect();

    // Block boundaries: every line index that starts a new artifact entry.
    let starts: Vec<usize> = (0..lines.len())
        .filter(|&i| entry_path(lines[i].trim_start()).is_some())
        .collect();
    if starts.is_empty() {
        bail!("no artifact entries found while looking for path '{artifact_path}'");
    }

    let mut target: Option<usize> = None; // index INTO `starts`
    for (bi, &s) in starts.iter().enumerate() {
        if entry_path(lines[s].trim_start()) != Some(artifact_path) {
            continue;
        }
        if let Some(want) = want_arch {
            let end = starts.get(bi + 1).copied().unwrap_or(lines.len());
            let arch_here = lines[s..end].iter().find_map(|l| entry_arch(l.trim_start()));
            if arch_here != Some(want) {
                continue; // right path, wrong (or absent) arch -- keep looking (ADR 0017 D1)
            }
        }
        target = Some(bi);
        break;
    }

    let Some(bi) = target else {
        bail!(
            "no matching artifact entry found for path '{artifact_path}'{} in module.yaml \
             (malformed artifacts: block, or the arch-qualified entry was never declared?)",
            want_arch.map(|a| format!(" arch '{a}'")).unwrap_or_default()
        );
    };
    let block_start = starts[bi];
    let block_end = starts.get(bi + 1).copied().unwrap_or(lines.len());

    let mut out: Vec<String> = Vec::with_capacity(lines.len());
    out.extend(lines[..block_start].iter().map(|s| s.to_string()));
    let mut found_value = false;
    for &l in &lines[block_start..block_end] {
        let lt = l.trim_start();
        if let Some(vt) = lt.strip_prefix("value:") {
            let indent = &l[..l.len() - lt.len()];
            let comment = vt.split_once('#').map(|(_, c)| c.trim());
            let new_line = match comment {
                Some(c) if !c.is_empty() => format!("{indent}value: \"{new_hex}\"  # {c}"),
                _ => format!("{indent}value: \"{new_hex}\""),
            };
            out.push(new_line);
            found_value = true;
        } else {
            out.push(l.to_string());
        }
    }
    out.extend(lines[block_end..].iter().map(|s| s.to_string()));

    if !found_value {
        bail!("no `value:` line found for artifact path '{artifact_path}' in module.yaml (malformed artifacts: block?)");
    }
    let mut joined = out.join("\n");
    joined.push('\n');
    Ok(joined)
}

/// Back-compat entry point (ADR 0016 D3): matches by `path` alone, ignoring `arch`. Correct for
/// every role except `aot`, whose repeated-`path` entries need
/// [`write_digest_value_matching`]`(text, path, Some(arch), new_hex)` instead.
pub fn write_digest_value(text: &str, artifact_path: &str, new_hex: &str) -> Result<String> {
    write_digest_value_matching(text, artifact_path, None, new_hex)
}

// =================================================================================================
// Part A regression tests — hybrid ML-DSA-65 + Ed25519 module signing, and the ADR 0002 agility
// dispatch (`verify_module_for_suite`). These are the F5 audit's five required proofs:
//   (a) a hybrid-suite module with a VALID ML-DSA + valid Ed25519 sig loads
//   (b) a module MISSING module.mldsa.sig under the hybrid suite is REFUSED (anti-downgrade)
//   (c) a module with a BAD ML-DSA sig but good Ed25519 is REFUSED
//   (d) an Ed25519-only suite still works Ed25519-only (agility dispatch)
//   (e) is proven in gen-cbom.py's own output, not here (see security/cbom/gen-cbom.py).
// =================================================================================================
#[cfg(test)]
mod hybrid_signing_tests {
    use super::*;

    fn tmp_dir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("hp-hybrid-sig-{tag}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(&d).unwrap();
        d
    }

    fn make_module(dir: &Path, contents: &[u8]) -> PathBuf {
        let mdir = dir.join("mod");
        fs::create_dir_all(&mdir).unwrap();
        fs::write(mdir.join("module.yaml"), contents).unwrap();
        mdir
    }

    const HYBRID: &[&str] = &["ml-dsa-65", "ed25519"];
    fn hybrid_legs() -> Vec<String> {
        HYBRID.iter().map(|s| s.to_string()).collect()
    }
    fn ed25519_only_legs() -> Vec<String> {
        vec!["ed25519".to_string()]
    }

    /// (a) A hybrid-suite module signed with BOTH a valid ML-DSA-65 sig and a valid Ed25519 sig
    /// verifies -- the happy path the whole mechanism exists to allow.
    #[test]
    fn hybrid_suite_valid_both_legs_verifies() {
        let dir = tmp_dir("both-valid");
        let mdir = make_module(&dir, b"id: hy\nversion: '1'\nruntime: wasm\n");
        let trust = dir.join(".trust");
        let key = dir.join("release.key");
        let n = dev_sign_all(std::slice::from_ref(&mdir), &key, &trust).unwrap();
        assert_eq!(n, 1);
        assert!(trust.join("release.pub").exists(), "Ed25519 trust key must be written");
        assert!(trust.join("release-mldsa.pub").exists(), "ML-DSA-65 trust key must be written (Part A)");
        assert!(mdir.join("module.sig").exists());
        assert!(mdir.join("module.mldsa.sig").exists(), "module.mldsa.sig must be produced alongside module.sig");

        let state = verify_module_for_suite(&mdir, &trust, &hybrid_legs());
        assert_eq!(state, SigState::Verified, "both legs valid -> Verified");
        // The tri-state -> bool mapping a `signature: required` module actually gets:
        assert_eq!(resolve_sig_verified(&state, "required"), Some(true));
    }

    /// (b) THE ANTI-DOWNGRADE KEY TEST: a module with a valid Ed25519 signature but NO
    /// `module.mldsa.sig` at all, verified under the HYBRID suite, must be REFUSED -- never
    /// silently accepted as "Ed25519 was enough". An attacker who strips the ML-DSA sidecar must
    /// not be able to downgrade a hybrid-suite module to classical-only trust.
    #[test]
    fn hybrid_suite_missing_mldsa_sig_is_refused_not_downgraded() {
        let dir = tmp_dir("missing-mldsa");
        let mdir = make_module(&dir, b"id: hy\nversion: '1'\nruntime: wasm\n");
        let trust = dir.join(".trust");
        let key = dir.join("release.key");
        dev_sign_all(std::slice::from_ref(&mdir), &key, &trust).unwrap();

        // Strip the ML-DSA leg only -- the Ed25519 signature is still perfectly valid.
        fs::remove_file(mdir.join("module.mldsa.sig")).unwrap();
        assert_eq!(
            verify_module(&mdir, &load_trust(&trust)),
            SigState::Verified,
            "sanity: the Ed25519 leg alone still verifies fine"
        );

        let state = verify_module_for_suite(&mdir, &trust, &hybrid_legs());
        assert_eq!(
            state,
            SigState::Unsigned,
            "a missing ML-DSA leg under the hybrid suite must NOT read as fully Verified"
        );
        // The property that actually matters: a `signature: required` module is REFUSED, not
        // silently downgraded to trusting the Ed25519 leg alone.
        assert_eq!(
            resolve_sig_verified(&state, "required"),
            Some(false),
            "signature: required + missing ML-DSA leg under hybrid suite -> REFUSED (anti-downgrade)"
        );
    }

    /// (c) A module with a BAD (tampered/wrong-key) ML-DSA-65 signature but a perfectly good
    /// Ed25519 signature must be REFUSED under the hybrid suite -- an INVALID leg always wins over
    /// a valid one; never averaged, never "best of two".
    #[test]
    fn hybrid_suite_bad_mldsa_sig_is_refused_even_with_good_ed25519() {
        let dir = tmp_dir("bad-mldsa");
        let mdir = make_module(&dir, b"id: hy\nversion: '1'\nruntime: wasm\n");
        let trust = dir.join(".trust");
        let key = dir.join("release.key");
        dev_sign_all(std::slice::from_ref(&mdir), &key, &trust).unwrap();

        // Corrupt the ML-DSA signature bytes (still valid hex, wrong signature).
        let bad_sig = hex::encode([0xAAu8; 3309]);
        fs::write(mdir.join("module.mldsa.sig"), &bad_sig).unwrap();
        assert_eq!(
            verify_module(&mdir, &load_trust(&trust)),
            SigState::Verified,
            "sanity: Ed25519 leg is untouched and still verifies"
        );

        let state = verify_module_for_suite(&mdir, &trust, &hybrid_legs());
        assert_eq!(state, SigState::Invalid, "a bad ML-DSA leg must refuse regardless of the Ed25519 leg");
        assert_eq!(
            resolve_sig_verified(&state, "required"),
            Some(false),
            "Invalid always refuses, independent of module policy"
        );
    }

    /// (d) THE AGILITY PROOF: an Ed25519-ONLY suite (no ML-DSA leg named at all) must still verify
    /// a module that carries ONLY an Ed25519 signature -- the suite string genuinely drives which
    /// signatures are required, not a hardcoded hybrid-always rule. This also proves an absent
    /// `module.mldsa.sig` is NOT held against a module when the active suite never asked for one.
    #[test]
    fn ed25519_only_suite_verifies_ed25519_only_module() {
        let dir = tmp_dir("classical-only");
        let mdir = make_module(&dir, b"id: classic\nversion: '1'\nruntime: wasm\n");
        let trust = dir.join(".trust");
        let key = dir.join("release.key");
        // dev_sign_all always produces both legs (the release pipeline signs whatever the
        // strongest suite might need); an Ed25519-only-suite VERIFY must simply never consult
        // the ML-DSA leg, even though one happens to be present.
        dev_sign_all(std::slice::from_ref(&mdir), &key, &trust).unwrap();
        assert_eq!(verify_module_for_suite(&mdir, &trust, &ed25519_only_legs()), SigState::Verified);

        // Now delete the ML-DSA leg entirely -- the ed25519-only suite must be UNAFFECTED (proves
        // it never even looks for it).
        fs::remove_file(mdir.join("module.mldsa.sig")).unwrap();
        assert_eq!(
            verify_module_for_suite(&mdir, &trust, &ed25519_only_legs()),
            SigState::Verified,
            "an ed25519-only suite must not require (or even check for) an ML-DSA leg"
        );
    }

    /// Suite registry agility: `crypto_suite()` for the hybrid suite names both legs; for a
    /// classical suite it names only Ed25519 -- proving the dispatch really is driven by the
    /// named suite's `module_signing` list, not a hardcoded assumption in this crate.
    #[test]
    fn crypto_suite_registry_drives_distinct_leg_sets() {
        let hybrid = crate::crypto::crypto_suite("hookprobe-pqc-hybrid-2026").unwrap();
        assert_eq!(hybrid.module_signing, vec!["ml-dsa-65".to_string(), "ed25519".to_string()]);

        let classical = crate::crypto::crypto_suite("hookprobe-ed25519-only-legacy").unwrap();
        assert_eq!(classical.module_signing, vec!["ed25519".to_string()]);
    }

    /// An empty `module_signing` policy verifies nothing -- fail-closed as `Unsigned`, never as an
    /// automatic pass (a misconfigured/empty suite must not silently grant trust).
    #[test]
    fn empty_suite_policy_is_unsigned_fail_closed() {
        let dir = tmp_dir("empty-policy");
        let mdir = make_module(&dir, b"id: x\nversion: '1'\nruntime: wasm\n");
        let trust = dir.join(".trust");
        assert_eq!(verify_module_for_suite(&mdir, &trust, &[]), SigState::Unsigned);
    }

    /// An unrecognized leg name in the suite policy is treated as unverifiable (Invalid), not
    /// silently skipped -- an unknown algorithm name must never be an automatic pass.
    #[test]
    fn unknown_leg_name_is_invalid_fail_closed() {
        let dir = tmp_dir("unknown-leg");
        let mdir = make_module(&dir, b"id: x\nversion: '1'\nruntime: wasm\n");
        let trust = dir.join(".trust");
        let key = dir.join("release.key");
        dev_sign_all(std::slice::from_ref(&mdir), &key, &trust).unwrap();
        let legs = vec!["ed25519".to_string(), "slh-dsa-999".to_string()];
        assert_eq!(
            verify_module_for_suite(&mdir, &trust, &legs),
            SigState::Invalid,
            "an unimplemented/unknown leg name must fail closed, not be silently ignored"
        );
    }
}

#[cfg(test)]
mod artifact_digest_tests {
    use super::*;
    use crate::module_def::{ArtifactDigest, ArtifactRole, Digest, ModuleDef};
    use crate::types::Runtime;

    fn tmp_dir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("hp-artifact-{tag}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(&d).unwrap();
        d
    }

    fn def_with_artifacts(signature: &str, artifacts: Vec<ArtifactDigest>) -> ModuleDef {
        ModuleDef {
            id: "testmod".to_string(),
            version: "1".to_string(),
            runtime: Runtime::Wasm,
            requires: Default::default(),
            provides: Default::default(),
            resources: None,
            signature: signature.to_string(),
            grants: Vec::new(),
            artifact: None,
            status: None,
            staging: None,
            artifacts,
            sig_verified: None,
        }
    }

    fn sha256_artifact(path: &str, bytes: &[u8]) -> ArtifactDigest {
        ArtifactDigest {
            path: path.to_string(),
            role: ArtifactRole::Executable,
            arch: None,
            cpu: None,
            digest: Digest { alg: "sha256".to_string(), value: digest_hex("sha256", bytes).unwrap() },
        }
    }

    // --- digest_hex: crypto-agile alg switch -----------------------------------------------

    #[test]
    fn digest_hex_supports_every_named_alg() {
        let bytes = b"hookprobe";
        assert_eq!(digest_hex("sha256", bytes).unwrap().len(), 64);
        assert_eq!(digest_hex("sha384", bytes).unwrap().len(), 96);
        assert_eq!(digest_hex("sha3-256", bytes).unwrap().len(), 64);
        // Same alg, same bytes -> same digest (determinism).
        assert_eq!(digest_hex("sha256", bytes).unwrap(), digest_hex("sha256", bytes).unwrap());
        // Different algs on the same bytes must NOT collide.
        assert_ne!(digest_hex("sha256", bytes).unwrap(), digest_hex("sha3-256", bytes).unwrap());
    }

    #[test]
    fn digest_hex_rejects_unknown_alg_fail_closed() {
        let err = digest_hex("md5", b"x").unwrap_err();
        assert!(err.to_string().contains("unsupported digest alg"), "got: {err}");
    }

    // --- verify_artifact_digests: ACCEPT (digest match) ------------------------------------

    #[test]
    fn accepts_a_matching_artifact_digest() {
        let dir = tmp_dir("accept");
        let payload = b"#!/bin/true\n-- pretend .wasm bytes --";
        fs::write(dir.join("napse.wasm"), payload).unwrap();
        let def = def_with_artifacts("required", vec![sha256_artifact("napse.wasm", payload)]);
        assert!(
            verify_artifact_digests(&def, &dir, None).is_ok(),
            "a matching digest must be accepted"
        );
    }

    // --- verify_artifact_digests: REJECT (digest mismatch — fail-closed) -------------------

    #[test]
    fn rejects_a_tampered_artifact_fail_closed() {
        let dir = tmp_dir("tamper");
        let original = b"the real payload bytes";
        let tampered = b"a malicious payload swap!";
        // Digest pins the ORIGINAL bytes...
        let def = def_with_artifacts("required", vec![sha256_artifact("napse.wasm", original)]);
        // ...but the file on disk has been SWAPPED (flip-a-byte-class attack, ADR 0016 context).
        fs::write(dir.join("napse.wasm"), tampered).unwrap();
        let err = verify_artifact_digests(&def, &dir, None).unwrap_err();
        assert!(err.to_string().contains("MISMATCH"), "got: {err}");
        assert!(err.to_string().contains("fail-closed") || err.to_string().to_lowercase().contains("tampered"), "got: {err}");
    }

    #[test]
    fn rejects_a_tampered_artifact_and_emits_an_evidence_event() {
        let dir = tmp_dir("tamper-evidence");
        let original = b"the real payload bytes";
        let def = def_with_artifacts("required", vec![sha256_artifact("napse.wasm", original)]);
        fs::write(dir.join("napse.wasm"), b"swapped bytes").unwrap();
        let events = dir.join("events");
        let err = verify_artifact_digests(&def, &dir, Some(&events)).unwrap_err();
        assert!(err.to_string().contains("MISMATCH"));
        let contents = fs::read_to_string(&events).expect("ArtifactTamper event must be appended");
        let v: serde_json::Value = serde_json::from_str(contents.trim()).expect("valid JSON line");
        assert_eq!(v["rule_id"], ARTIFACT_TAMPER_RULE_ID);
        assert_eq!(v["category"], "supply_chain_tamper");
        assert_eq!(v["module"], "testmod");
        assert_eq!(v["path"], "napse.wasm");
    }

    #[test]
    fn rejects_a_missing_artifact_file_fail_closed() {
        let dir = tmp_dir("missing-file");
        // Digest declared, but the file was never written — a missing payload is exactly as
        // dangerous as a tampered one (ADR 0016 D2: "missing file... fail-closed refusal").
        let def = def_with_artifacts(
            "required",
            vec![ArtifactDigest {
                path: "napse.wasm".to_string(),
                role: ArtifactRole::Executable,
                arch: None,
                cpu: None,
                digest: Digest { alg: "sha256".to_string(), value: "deadbeef".to_string() },
            }],
        );
        assert!(verify_artifact_digests(&def, &dir, None).is_err());
    }

    // --- D5: missing artifacts: block on a signature:required module --------------------------

    #[test]
    fn missing_digest_block_gate_matches_build_profile() {
        // signature:required, artifacts EMPTY -- the exact "signed manifest, unprotected payload"
        // condition ADR 0016 D5 calls the dangerous silent state. The verdict is intentionally
        // build-profile-dependent (D5): `cargo test` (debug) WARNS and proceeds so dev/local runs
        // against not-yet-migrated fixtures still work; `cargo test --release` HARD FAILS, closing
        // the "shipped a signed-but-unprotected module" hole. Both branches are asserted here (via
        // `cfg`) so this test is meaningful — and passes — under either profile, proving the gate
        // actually flips rather than merely existing in source.
        let def = def_with_artifacts("required", vec![]);
        let dir = tmp_dir("no-artifacts");
        let result = verify_artifact_digests(&def, &dir, None);
        #[cfg(debug_assertions)]
        assert!(result.is_ok(), "debug build: missing artifacts: block WARNS, does not hard-fail");
        #[cfg(not(debug_assertions))]
        assert!(result.is_err(), "release build: missing artifacts: block on signature:required MUST hard-fail (ADR 0016 D5)");
    }

    #[test]
    fn unsigned_module_with_no_artifacts_is_never_gated() {
        // signature: unsigned (not required) + no artifacts: this module never claimed payload
        // protection in the first place -- D5's gate is specific to `signature: required`.
        let def = def_with_artifacts("unsigned", vec![]);
        let dir = tmp_dir("unsigned-no-artifacts");
        assert!(verify_artifact_digests(&def, &dir, None).is_ok());
    }

    // --- resolve_artifact_path: relative vs absolute ------------------------------------------

    #[test]
    fn resolves_relative_path_under_install_dir() {
        let dir = PathBuf::from("/opt/hookprobe/modules/napse");
        assert_eq!(resolve_artifact_path("napse.wasm", &dir), dir.join("napse.wasm"));
    }

    #[test]
    fn resolves_absolute_path_as_is() {
        let dir = PathBuf::from("/opt/hookprobe/modules/napse-quarantine");
        let abs = "/usr/lib/hookprobe/bin/napse-quarantine";
        assert_eq!(resolve_artifact_path(abs, &dir), PathBuf::from(abs));
    }

    // --- manifest (de)serialization of the artifacts: block -----------------------------------

    #[test]
    fn artifacts_block_deserializes_from_yaml() {
        let yaml = r#"
id: napse
version: 2.4.1
runtime: wasm
signature: required
artifacts:
  - path: napse.wasm
    role: executable
    digest:
      alg: sha256
      value: "3f6bdeadbeefa91c"
"#;
        let def: ModuleDef = serde_yaml::from_str(yaml).expect("parses");
        assert_eq!(def.artifacts.len(), 1);
        assert_eq!(def.artifacts[0].path, "napse.wasm");
        assert_eq!(def.artifacts[0].role, ArtifactRole::Executable);
        assert_eq!(def.artifacts[0].digest.alg, "sha256");
        assert_eq!(def.artifacts[0].digest.value, "3f6bdeadbeefa91c");
    }

    #[test]
    fn artifacts_block_defaults_to_empty_when_absent() {
        // Every module.yaml written before this ADR landed has NO artifacts: key at all -- must
        // default to empty, not fail to parse (ADR 0016 D5's "rollout" migration path).
        let yaml = "id: legacy\nversion: '1'\nruntime: wasm\n";
        let def: ModuleDef = serde_yaml::from_str(yaml).expect("parses with no artifacts: key");
        assert!(def.artifacts.is_empty());
    }

    #[test]
    fn artifact_role_defaults_to_executable_when_absent() {
        let yaml = r#"
id: m
version: "1"
runtime: wasm
artifacts:
  - path: m.wasm
    digest: { alg: sha256, value: "abc123" }
"#;
        let def: ModuleDef = serde_yaml::from_str(yaml).expect("parses");
        assert_eq!(def.artifacts[0].role, ArtifactRole::Executable);
    }

    #[test]
    fn artifact_digest_serialize_deserialize_roundtrip() {
        let original = ArtifactDigest {
            path: "quarantine.bpf.o".to_string(),
            role: ArtifactRole::BpfObject,
            arch: None,
            cpu: None,
            digest: Digest { alg: "sha3-256".to_string(), value: "abcd1234".to_string() },
        };
        let json = serde_json::to_string(&original).unwrap();
        let back: ArtifactDigest = serde_json::from_str(&json).unwrap();
        assert_eq!(back, original);
        // role serializes kebab-case (matches the ADR's YAML: `role: bpf-object`).
        assert!(json.contains("bpf-object"), "got: {json}");
    }

    /// ADR 0017 D1: `role: aot` serializes kebab-case (`"aot"`), and `arch` round-trips.
    #[test]
    fn aot_role_and_arch_serialize_deserialize_roundtrip() {
        let original = ArtifactDigest {
            path: "napse.cwasm".to_string(),
            role: ArtifactRole::Aot,
            arch: Some("arm64".to_string()),
            cpu: None,
            digest: Digest { alg: "sha256".to_string(), value: "abcd1234".to_string() },
        };
        let json = serde_json::to_string(&original).unwrap();
        assert!(json.contains("\"aot\""), "got: {json}");
        assert!(json.contains("\"arm64\""), "got: {json}");
        let back: ArtifactDigest = serde_json::from_str(&json).unwrap();
        assert_eq!(back, original);
    }

    /// ADR 0017 D1: two `role: aot` entries may legitimately share the SAME `path` (one per
    /// built arch) -- `arch` disambiguates, not `path`. Deserializing the ADR's own worked
    /// example must produce both entries distinctly.
    #[test]
    fn two_aot_entries_same_path_different_arch_both_deserialize() {
        let yaml = r#"
id: napse
version: 2.4.1
runtime: wasm
signature: required
artifacts:
  - path: napse.wasm
    role: executable
    digest: { alg: sha256, value: "0788deadbeef2544" }
  - path: napse.cwasm
    role: aot
    arch: arm64
    digest: { alg: sha256, value: "aaaa" }
  - path: napse.cwasm
    role: aot
    arch: amd64
    digest: { alg: sha256, value: "bbbb" }
"#;
        let def: ModuleDef = serde_yaml::from_str(yaml).expect("parses");
        assert_eq!(def.artifacts.len(), 3);
        let aot: Vec<_> = def.artifacts.iter().filter(|a| a.role == ArtifactRole::Aot).collect();
        assert_eq!(aot.len(), 2);
        assert_eq!(aot[0].path, "napse.cwasm");
        assert_eq!(aot[1].path, "napse.cwasm");
        assert_eq!(aot[0].arch.as_deref(), Some("arm64"));
        assert_eq!(aot[1].arch.as_deref(), Some("amd64"));
        assert_ne!(aot[0].digest.value, aot[1].digest.value);
    }

    #[test]
    fn multiple_artifacts_all_role_kinds_roundtrip_via_yaml() {
        let yaml = r#"
id: napse-quarantine
version: 0.1.0
runtime: sysext
artifacts:
  - path: /usr/lib/hookprobe/bin/napse-quarantine
    role: loader
    digest: { alg: sha256, value: "aaaa" }
  - path: /usr/lib/hookprobe/bpf/quarantine.bpf.o
    role: bpf-object
    digest: { alg: sha256, value: "bbbb" }
signature: required
"#;
        let def: ModuleDef = serde_yaml::from_str(yaml).expect("parses");
        assert_eq!(def.artifacts.len(), 2);
        assert_eq!(def.artifacts[0].role, ArtifactRole::Loader);
        assert_eq!(def.artifacts[1].role, ArtifactRole::BpfObject);
    }

    // --- write_digest_value: surgical in-place edit, comments preserved -----------------------

    #[test]
    fn write_digest_value_updates_only_the_target_value_preserving_comments() {
        let before = r#"id: napse
version: 2.4.1
runtime: wasm

# Payload digests -- the signature over this module.yaml transitively covers these
# files (ADR 0016).
artifacts:
  - path: napse.wasm            # resolved relative to the module's install dir
    role: executable
    digest:
      alg: sha256
      value: "OLDVALUE"

signature: required             # the .sig now protects code, not just metadata
"#;
        let after = write_digest_value(before, "napse.wasm", "newhex1234").unwrap();
        assert!(after.contains(r#"value: "newhex1234""#), "got:\n{after}");
        assert!(!after.contains("OLDVALUE"));
        // Every comment survives -- this is the whole point of a text edit over a full reparse.
        assert!(after.contains("# Payload digests"));
        assert!(after.contains("# resolved relative to the module's install dir"));
        assert!(after.contains("# the .sig now protects code, not just metadata"));
    }

    #[test]
    fn write_digest_value_targets_the_right_entry_among_several() {
        let before = r#"artifacts:
  - path: /usr/lib/hookprobe/bin/napse-quarantine
    role: loader
    digest: { alg: sha256, value: "aaaa" }
"#;
        // inline-map form (`digest: { alg: ..., value: ... }`) has no standalone `value:` LINE,
        // so this is exercised with the block form used consistently across this repo's
        // module.yaml files instead:
        let before_block = r#"artifacts:
  - path: napse.wasm
    role: executable
    digest:
      alg: sha256
      value: "first"
  - path: extra.wasm
    role: data
    digest:
      alg: sha256
      value: "second"
"#;
        let after = write_digest_value(before_block, "extra.wasm", "SECONDNEW").unwrap();
        assert!(after.contains(r#"value: "first""#), "the OTHER entry must be untouched:\n{after}");
        assert!(after.contains(r#"value: "SECONDNEW""#));
        let _ = before; // inline-map form documented above, not exercised by this repo's convention
    }

    #[test]
    fn write_digest_value_errors_when_path_not_found() {
        let text = "artifacts:\n  - path: napse.wasm\n    digest:\n      alg: sha256\n      value: \"x\"\n";
        assert!(write_digest_value(text, "does-not-exist.wasm", "hex").is_err());
    }

    // =============================================================================================
    // ADR 0021 — multi-arch native artifacts: arch-selective `verify_artifact_digests` (the native
    // start path this repo owns end-to-end — `napse-quarantine`'s own self-verification calls this
    // exact function, never `verify_executable_binding`, per its own doc comment).
    // =============================================================================================

    fn other_arch() -> &'static str {
        if running_arch() == "amd64" { "arm64" } else { "amd64" }
    }

    fn loader_artifact_arch(path: &str, arch: &str, bytes: &[u8]) -> ArtifactDigest {
        ArtifactDigest {
            path: path.to_string(),
            role: ArtifactRole::Loader,
            arch: Some(arch.to_string()),
            cpu: None,
            digest: Digest { alg: "sha256".to_string(), value: digest_hex("sha256", bytes).unwrap() },
        }
    }

    /// The napse-quarantine driving case, end to end: TWO `role: loader` entries share the same
    /// `path` (arch-disambiguated); the on-disk file is THIS build's arch. Must PASS.
    #[test]
    fn right_arch_digest_verifies_when_two_arches_share_the_same_path() {
        let dir = tmp_dir("multiarch-loader-right");
        let this_arch = running_arch();
        let this_bytes = b"-- this arch's real loader bytes --";
        let other_bytes = b"-- a completely different other-arch build --";
        fs::write(dir.join("napse-quarantine"), this_bytes).unwrap();
        let def = def_with_artifacts(
            "required",
            vec![
                loader_artifact_arch("napse-quarantine", this_arch, this_bytes),
                loader_artifact_arch("napse-quarantine", other_arch(), other_bytes),
            ],
        );
        assert!(
            verify_artifact_digests(&def, &dir, None).is_ok(),
            "the arch-matching entry must verify even with an other-arch sibling sharing the path"
        );
    }

    /// The other arch's entry, sharing the same `path`, must be SKIPPED entirely — its
    /// deliberately-wrong digest (relative to the on-disk file) must never cause a failure.
    #[test]
    fn wrong_arch_entry_is_skipped_even_sharing_the_same_path() {
        let dir = tmp_dir("multiarch-loader-skip");
        let this_arch = running_arch();
        let this_bytes = b"the correct bytes for this build's own arch";
        fs::write(dir.join("napse-quarantine"), this_bytes).unwrap();
        let def = def_with_artifacts(
            "required",
            vec![
                loader_artifact_arch("napse-quarantine", this_arch, this_bytes),
                ArtifactDigest {
                    path: "napse-quarantine".to_string(),
                    role: ArtifactRole::Loader,
                    arch: Some(other_arch().to_string()),
                    cpu: None,
                    digest: Digest { alg: "sha256".to_string(), value: "deliberately-wrong-hex".to_string() },
                },
            ],
        );
        assert!(verify_artifact_digests(&def, &dir, None).is_ok());
    }

    /// Fail-closed: a `signature: required` module whose ONLY `role: loader` entry is pinned for
    /// a DIFFERENT arch must be refused on this arch (no JIT fallback exists for a native binary
    /// unlike `role: aot` — this is exactly as unprotected as an empty `artifacts:` block, ADR
    /// 0021 extends D5).
    #[test]
    fn no_matching_arch_digest_fails_closed_like_an_empty_artifacts_block() {
        let dir = tmp_dir("multiarch-loader-nomatch");
        let bytes = b"a real binary; only the wrong arch's digest is pinned";
        fs::write(dir.join("napse-quarantine"), bytes).unwrap();
        let def = def_with_artifacts("required", vec![loader_artifact_arch("napse-quarantine", other_arch(), bytes)]);
        let result = verify_artifact_digests(&def, &dir, None);
        #[cfg(debug_assertions)]
        assert!(result.is_ok(), "debug build: arch-mismatched-only artifacts WARN, do not hard-fail");
        #[cfg(not(debug_assertions))]
        assert!(
            result.is_err(),
            "release build: a module pinned ONLY for another arch MUST hard-fail on this arch (ADR 0021)"
        );
    }

    /// An arch-less entry (no `arch:` at all, every pre-ADR-0021 module.yaml) is unaffected: it
    /// stays arch-independent and verifies regardless of `running_arch()` — zero regression.
    #[test]
    fn arch_less_entry_still_verifies_regardless_of_running_arch() {
        let dir = tmp_dir("multiarch-archless-digest-unaffected");
        let payload = b"the same bytes on every arch";
        fs::write(dir.join("napse.wasm"), payload).unwrap();
        let def = def_with_artifacts("required", vec![sha256_artifact("napse.wasm", payload)]);
        assert!(verify_artifact_digests(&def, &dir, None).is_ok());
    }

    /// The bpf-object role is covered by the same arch-selection rule as loader/executable.
    #[test]
    fn bpf_object_role_is_also_arch_selective() {
        let dir = tmp_dir("multiarch-bpf-object");
        let this_arch = running_arch();
        let this_bytes = b"the CO-RE .bpf.o bytes built for this arch's register layout";
        let other_bytes = b"a different arch's CO-RE .bpf.o bytes";
        fs::write(dir.join("quarantine.bpf.o"), this_bytes).unwrap();
        let def = def_with_artifacts(
            "required",
            vec![
                // an executable/loader entry is still required so D5's own gate doesn't fire
                // independently of the thing this test targets:
                loader_artifact_arch("loader-bin", this_arch, b"loader bytes"),
                ArtifactDigest {
                    path: "quarantine.bpf.o".to_string(),
                    role: ArtifactRole::BpfObject,
                    arch: Some(this_arch.to_string()),
                    cpu: None,
                    digest: Digest { alg: "sha256".to_string(), value: digest_hex("sha256", this_bytes).unwrap() },
                },
                ArtifactDigest {
                    path: "quarantine.bpf.o".to_string(),
                    role: ArtifactRole::BpfObject,
                    arch: Some(other_arch().to_string()),
                    cpu: None,
                    digest: Digest { alg: "sha256".to_string(), value: digest_hex("sha256", other_bytes).unwrap() },
                },
            ],
        );
        fs::write(dir.join("loader-bin"), b"loader bytes").unwrap();
        assert!(verify_artifact_digests(&def, &dir, None).is_ok());
    }
}

// =================================================================================================
// ADR 0016 Findings 1 & 3 regression tests — `verify_executable_binding`.
// =================================================================================================
#[cfg(test)]
mod executable_binding_tests {
    use super::*;
    use crate::module_def::{ArtifactDigest, ArtifactRole, Digest, ModuleDef};
    use crate::types::Runtime;

    fn tmp_dir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("hp-exec-binding-{tag}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(&d).unwrap();
        d
    }

    fn def_with_artifacts(signature: &str, artifacts: Vec<ArtifactDigest>) -> ModuleDef {
        ModuleDef {
            id: "testmod".to_string(),
            version: "1".to_string(),
            runtime: Runtime::Wasm,
            requires: Default::default(),
            provides: Default::default(),
            resources: None,
            signature: signature.to_string(),
            grants: Vec::new(),
            artifact: None,
            status: None,
            staging: None,
            artifacts,
            sig_verified: None,
        }
    }

    fn exec_artifact(path: &str, bytes: &[u8]) -> ArtifactDigest {
        ArtifactDigest {
            path: path.to_string(),
            role: ArtifactRole::Executable,
            arch: None,
            cpu: None,
            digest: Digest { alg: "sha256".to_string(), value: digest_hex("sha256", bytes).unwrap() },
        }
    }

    // --- Finding 1: the .cwasm-swap attack must fail, using PINNED bytes ------------------------

    /// The literal attack from the audit: the digest declared in `module.yaml` matches the REAL
    /// `.wasm` on disk (untouched) — but the bytes ACTUALLY about to execute (what a `.cwasm`
    /// AOT-cache swap would hand the compiler) are different. `verify_artifact_digests` (the OLD,
    /// re-open-the-path check) would pass here, because it never looks at what really executes.
    /// `verify_executable_binding`, given the REAL exec bytes, must catch the mismatch.
    #[test]
    fn cwasm_swap_attack_is_rejected_when_verifying_the_bytes_that_actually_execute() {
        let dir = tmp_dir("cwasm-swap");
        let real_wasm = b"-- the real, signed .wasm bytes --";
        let evil_bytes = b"-- attacker's native/evil payload bytes, disguised as a .cwasm --";

        // module.yaml pins the digest of the REAL bytes (as `--write-artifact-digests` would).
        fs::write(dir.join("napse.wasm"), real_wasm).unwrap();
        let def = def_with_artifacts("required", vec![exec_artifact("napse.wasm", real_wasm)]);

        // The OLD check (re-opens the path) is fooled: the file on disk is untouched.
        assert!(
            verify_artifact_digests(&def, &dir, None).is_ok(),
            "sanity: the pre-Fix-A check passes because the .wasm on disk is untouched"
        );

        // The NEW check is handed the bytes a compromised `.cwasm` fast path would actually
        // compile/run (simulating the attack: sidecar hash matches the real .wasm, but the
        // bytes about to execute are the evil ones) -- it MUST refuse.
        let exec_path = dir.join("napse.wasm");
        let err = verify_executable_binding(&def, &dir, &exec_path, evil_bytes, None).unwrap_err();
        assert!(err.to_string().contains("MISMATCH"), "got: {err}");
    }

    /// The safe path: verifying against the SAME bytes that were hashed into the digest (i.e.
    /// no swap happened) must succeed -- proves the fix doesn't just fail everything.
    #[test]
    fn matching_pinned_bytes_are_accepted() {
        let dir = tmp_dir("cwasm-match");
        let wasm = b"-- real .wasm bytes, unmodified --";
        fs::write(dir.join("napse.wasm"), wasm).unwrap();
        let def = def_with_artifacts("required", vec![exec_artifact("napse.wasm", wasm)]);
        let exec_path = dir.join("napse.wasm");
        assert!(verify_executable_binding(&def, &dir, &exec_path, wasm, None).is_ok());
    }

    // --- Finding 3: path-binding cross-check -----------------------------------------------------

    /// A manifest whose `artifacts:` block pins ONLY a `role: data` entry (digest matches that
    /// unrelated file) must NOT let an unlisted `.wasm` execute unchecked -- the whole point of
    /// requiring the resolved executable to match a declared `role: executable`/`loader` entry.
    #[test]
    fn data_only_artifacts_block_refuses_the_unlisted_executable() {
        let dir = tmp_dir("data-only");
        let real_wasm = b"the actual code that would run";
        let sidecar_data = b"some unrelated config blob";
        fs::write(dir.join("napse.wasm"), real_wasm).unwrap();
        fs::write(dir.join("config.json"), sidecar_data).unwrap();

        // ONLY a data-role artifact is declared -- and its digest is perfectly correct.
        let def = def_with_artifacts(
            "required",
            vec![ArtifactDigest {
                path: "config.json".to_string(),
                role: ArtifactRole::Data,
                arch: None,
                cpu: None,
                digest: Digest { alg: "sha256".to_string(), value: digest_hex("sha256", sidecar_data).unwrap() },
            }],
        );

        let exec_path = dir.join("napse.wasm");
        let err = verify_executable_binding(&def, &dir, &exec_path, real_wasm, None).unwrap_err();
        assert!(
            err.to_string().contains("Finding 3") || err.to_string().contains("does not match any declared"),
            "got: {err}"
        );
    }

    /// The positive case: a `role: executable` entry that DOES bind to the resolved path, plus
    /// an extra unrelated `data` artifact, must still pass (binding is "at least one match", not
    /// "every artifact is the executable").
    #[test]
    fn executable_role_artifact_binds_and_passes_alongside_a_data_artifact() {
        let dir = tmp_dir("exec-plus-data");
        let wasm = b"the real code";
        let cfg = b"a config sidecar";
        fs::write(dir.join("napse.wasm"), wasm).unwrap();
        fs::write(dir.join("config.json"), cfg).unwrap();
        let def = def_with_artifacts(
            "required",
            vec![
                exec_artifact("napse.wasm", wasm),
                ArtifactDigest {
                    path: "config.json".to_string(),
                    role: ArtifactRole::Data,
                    arch: None,
                    cpu: None,
                    digest: Digest { alg: "sha256".to_string(), value: digest_hex("sha256", cfg).unwrap() },
                },
            ],
        );
        let exec_path = dir.join("napse.wasm");
        assert!(verify_executable_binding(&def, &dir, &exec_path, wasm, None).is_ok());
    }

    /// A `role: loader` entry (the sysext/native-loader convention) also satisfies the binding —
    /// not just `role: executable`.
    #[test]
    fn loader_role_artifact_also_satisfies_the_binding() {
        let dir = tmp_dir("loader-role");
        let bin = b"a native loader ELF (pretend bytes)";
        fs::write(dir.join("napse-quarantine"), bin).unwrap();
        let def = def_with_artifacts(
            "required",
            vec![ArtifactDigest {
                path: "napse-quarantine".to_string(),
                role: ArtifactRole::Loader,
                arch: None,
                cpu: None,
                digest: Digest { alg: "sha256".to_string(), value: digest_hex("sha256", bin).unwrap() },
            }],
        );
        let exec_path = dir.join("napse-quarantine");
        assert!(verify_executable_binding(&def, &dir, &exec_path, bin, None).is_ok());
    }

    // --- `..` traversal / symlink rejection ------------------------------------------------------

    #[test]
    fn rejects_declared_artifact_path_containing_dotdot_traversal() {
        let dir = tmp_dir("traversal");
        // The artifact's OWN declared path tries to escape install_dir.
        let outside = std::env::temp_dir().join(format!("hp-exec-binding-outside-{}", std::process::id()));
        fs::write(&outside, b"escaped file").unwrap();
        let traversal_path = "../hp-exec-binding-outside-PLACEHOLDER";
        let traversal_path = traversal_path.replace("PLACEHOLDER", &std::process::id().to_string());
        let def = def_with_artifacts(
            "required",
            vec![ArtifactDigest {
                path: traversal_path.clone(),
                role: ArtifactRole::Executable,
                arch: None,
                cpu: None,
                digest: Digest { alg: "sha256".to_string(), value: "deadbeef".to_string() },
            }],
        );
        let exec_path = dir.join("napse.wasm"); // does not even need to exist -- traversal check
                                                 // on the DECLARED path fires before any file IO.
        let err = verify_executable_binding(&def, &dir, &exec_path, b"x", None);
        // The traversal artifact never binds (rejected before comparison) and there IS no other
        // artifact to satisfy the binding requirement -- so this must be an Err either from the
        // per-artifact digest-read (missing/mismatched) or the "no artifact bound" refusal. What
        // matters: it must NEVER silently succeed.
        assert!(err.is_err(), "a `..`-traversal artifact path must never silently pass");
        let _ = fs::remove_file(&outside);
    }

    #[test]
    fn rejects_a_symlinked_executable_path() {
        use std::os::unix::fs::symlink;
        let dir = tmp_dir("symlink");
        let real = dir.join("real.wasm");
        fs::write(&real, b"real bytes").unwrap();
        let link = dir.join("napse.wasm");
        symlink(&real, &link).unwrap();

        let def = def_with_artifacts("required", vec![exec_artifact("napse.wasm", b"real bytes")]);
        // exec_path IS the symlink -- must be refused regardless of digest correctness.
        let err = verify_executable_binding(&def, &dir, &link, b"real bytes", None).unwrap_err();
        assert!(err.to_string().to_lowercase().contains("symlink"), "got: {err}");
    }

    // --- ADR 0017: `role: aot` entries are exempt from THIS function's blanket digest sweep -------

    /// A `role: aot` sibling with a WRONG digest (simulating a tampered/stale RO-rootfs `.cwasm`)
    /// must NOT fail `verify_executable_binding` — that would turn "no AOT fast path available"
    /// (safe, ADR 0017 D2) into "the module cannot load at all" (a real regression). The
    /// `.wasm`/`role: executable` binding must still pass on its own merits.
    #[test]
    fn aot_sibling_with_wrong_digest_does_not_fail_the_executable_binding_check() {
        let dir = tmp_dir("aot-sibling-wrong-digest");
        let wasm = b"the real, correctly-pinned .wasm bytes";
        fs::write(dir.join("napse.wasm"), wasm).unwrap();
        // The .cwasm sibling's CONTENT doesn't even need to exist on disk for this check --
        // verify_executable_binding must never open it at all once it sees role: aot.
        let def = def_with_artifacts(
            "required",
            vec![
                exec_artifact("napse.wasm", wasm),
                ArtifactDigest {
                    path: "napse.cwasm".to_string(),
                    role: ArtifactRole::Aot,
                    arch: Some("amd64".to_string()),
                    cpu: None,
                    digest: Digest { alg: "sha256".to_string(), value: "deliberately-wrong-hex".to_string() },
                },
            ],
        );
        let exec_path = dir.join("napse.wasm");
        assert!(
            verify_executable_binding(&def, &dir, &exec_path, wasm, None).is_ok(),
            "an aot sibling's digest/presence must never gate the executable binding check"
        );
    }

    // --- D5 still applies through this entry point -----------------------------------------------

    #[test]
    fn empty_artifacts_on_required_module_matches_build_profile() {
        let dir = tmp_dir("d5-empty");
        let exec_path = dir.join("napse.wasm");
        fs::write(&exec_path, b"whatever").unwrap();
        let def = def_with_artifacts("required", vec![]);
        let result = verify_executable_binding(&def, &dir, &exec_path, b"whatever", None);
        #[cfg(debug_assertions)]
        assert!(result.is_ok(), "debug build: empty artifacts: WARNS, does not hard-fail");
        #[cfg(not(debug_assertions))]
        assert!(result.is_err(), "release build: empty artifacts: on signature:required MUST hard-fail");
    }

    // =============================================================================================
    // ADR 0021 — multi-arch native artifacts: arch-selective `verify_executable_binding`. Mirrors
    // `aot_binding_tests`' own arch-selection proofs, generalized to `role: executable`/`loader`.
    // =============================================================================================

    fn other_arch() -> &'static str {
        if running_arch() == "amd64" { "arm64" } else { "amd64" }
    }

    fn exec_artifact_arch(path: &str, arch: &str, bytes: &[u8]) -> ArtifactDigest {
        ArtifactDigest {
            path: path.to_string(),
            role: ArtifactRole::Loader,
            arch: Some(arch.to_string()),
            cpu: None,
            digest: Digest { alg: "sha256".to_string(), value: digest_hex("sha256", bytes).unwrap() },
        }
    }

    /// The napse-quarantine driving case: TWO `role: loader` entries share the SAME `path` (one
    /// per built arch, exactly the `role: aot` convention generalized), and the on-disk file at
    /// that path is THIS build's own arch's binary. The entry `arch:`-qualified to `running_arch()`
    /// must be the one that binds and verifies — proving arch selection, not just "first path
    /// match wins".
    #[test]
    fn right_arch_entry_verifies_when_two_arches_share_the_same_path() {
        let dir = tmp_dir("multiarch-right-arch");
        let this_arch = running_arch();
        let this_bytes = b"-- THIS arch's real loader bytes --";
        let other_bytes = b"-- the OTHER arch's completely different loader bytes --";
        fs::write(dir.join("napse-quarantine"), this_bytes).unwrap();
        let def = def_with_artifacts(
            "required",
            vec![
                exec_artifact_arch("napse-quarantine", this_arch, this_bytes),
                exec_artifact_arch("napse-quarantine", other_arch(), other_bytes),
            ],
        );
        let exec_path = dir.join("napse-quarantine");
        assert!(
            verify_executable_binding(&def, &dir, &exec_path, this_bytes, None).is_ok(),
            "the entry arch-qualified to THIS build's own arch must bind and verify"
        );
    }

    /// The other arch's entry must be INERT: even though it shares the exact same declared
    /// `path`, its (deliberately wrong-for-this-file) digest must never be consulted, and its
    /// mere presence must never cause a failure.
    #[test]
    fn wrong_arch_entry_is_never_consulted_even_sharing_the_same_path() {
        let dir = tmp_dir("multiarch-wrong-arch-inert");
        let this_arch = running_arch();
        let this_bytes = b"the correct bytes for this build's arch";
        fs::write(dir.join("napse-quarantine"), this_bytes).unwrap();
        let def = def_with_artifacts(
            "required",
            vec![
                exec_artifact_arch("napse-quarantine", this_arch, this_bytes),
                // Deliberately WRONG digest for the other arch -- if this were ever consulted
                // against the on-disk file it would fail; it must simply never be looked at.
                ArtifactDigest {
                    path: "napse-quarantine".to_string(),
                    role: ArtifactRole::Loader,
                    arch: Some(other_arch().to_string()),
                    cpu: None,
                    digest: Digest { alg: "sha256".to_string(), value: "deliberately-wrong-hex".to_string() },
                },
            ],
        );
        let exec_path = dir.join("napse-quarantine");
        assert!(verify_executable_binding(&def, &dir, &exec_path, this_bytes, None).is_ok());
    }

    /// Fail-closed, in EVERY build profile: a `signature: required` module whose ONLY
    /// `role: loader`/`executable` entries are pinned for a DIFFERENT arch than this build's own
    /// must be refused. Unlike `verify_artifact_digests`'s D5 gate (debug-warn/release-hard-fail),
    /// this refusal is unconditional here — a non-empty `artifacts:` block that never binds the
    /// file about to execute already hits the pre-existing Finding-3 "no artifact bound" check
    /// (unconditional in every profile) BEFORE the ADR 0021 D5-style message would otherwise only
    /// warn in debug; both are fail-closed, this one simply fires first/always.
    #[test]
    fn no_matching_arch_entry_fails_closed_in_every_build_profile() {
        let dir = tmp_dir("multiarch-no-match");
        let bytes = b"a real binary, but only the WRONG arch's digest is pinned for it";
        fs::write(dir.join("napse-quarantine"), bytes).unwrap();
        let def = def_with_artifacts(
            "required",
            vec![exec_artifact_arch("napse-quarantine", other_arch(), bytes)],
        );
        let exec_path = dir.join("napse-quarantine");
        let err = verify_executable_binding(&def, &dir, &exec_path, bytes, None).unwrap_err();
        assert!(
            err.to_string().contains("does not match any declared") || err.to_string().contains("UNPROTECTED"),
            "got: {err}"
        );
    }

    /// An arch-LESS entry (no `arch:` field at all — every pre-ADR-0021 `module.yaml`) is
    /// unaffected by arch selection: it stays arch-independent and binds regardless of
    /// `running_arch()`, proving zero regression for the single-arch-canonical convention.
    #[test]
    fn arch_less_entry_still_binds_regardless_of_running_arch() {
        let dir = tmp_dir("multiarch-archless-unaffected");
        let bytes = b"the same bytes on every arch (source-convention artifact)";
        fs::write(dir.join("napse.wasm"), bytes).unwrap();
        let def = def_with_artifacts("required", vec![exec_artifact("napse.wasm", bytes)]);
        let exec_path = dir.join("napse.wasm");
        assert!(verify_executable_binding(&def, &dir, &exec_path, bytes, None).is_ok());
    }
}

// =================================================================================================
// ADR 0017 regression tests — `verify_aot_binding`, `running_arch`, and the arch-aware
// `write_digest_value_matching`.
// =================================================================================================
#[cfg(test)]
mod aot_binding_tests {
    use super::*;
    use crate::module_def::{ArtifactDigest, ArtifactRole, Digest, ModuleDef};
    use crate::types::Runtime;

    fn tmp_dir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("hp-aot-binding-{tag}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(&d).unwrap();
        d
    }

    fn def_with_artifacts(signature: &str, artifacts: Vec<ArtifactDigest>) -> ModuleDef {
        ModuleDef {
            id: "testmod".to_string(),
            version: "1".to_string(),
            runtime: Runtime::Wasm,
            requires: Default::default(),
            provides: Default::default(),
            resources: None,
            signature: signature.to_string(),
            grants: Vec::new(),
            artifact: None,
            status: None,
            staging: None,
            artifacts,
            sig_verified: None,
        }
    }

    fn aot_entry(path: &str, arch: &str, bytes: &[u8]) -> ArtifactDigest {
        ArtifactDigest {
            path: path.to_string(),
            role: ArtifactRole::Aot,
            arch: Some(arch.to_string()),
            cpu: None,
            digest: Digest { alg: "sha256".to_string(), value: digest_hex("sha256", bytes).unwrap() },
        }
    }

    fn aot_entry_cpu(path: &str, arch: &str, cpu: &str, bytes: &[u8]) -> ArtifactDigest {
        ArtifactDigest {
            path: path.to_string(),
            role: ArtifactRole::Aot,
            arch: Some(arch.to_string()),
            cpu: Some(cpu.to_string()),
            digest: Digest { alg: "sha256".to_string(), value: digest_hex("sha256", bytes).unwrap() },
        }
    }

    #[test]
    fn running_arch_is_one_of_the_three_named_targets() {
        // Whatever this build is, it must resolve to one of the ADR 0017 D1 tokens -- never
        // silently "unknown" on any arch this repo actually ships (arm64/amd64/riscv64).
        let a = running_arch();
        assert!(["arm64", "amd64", "riscv64"].contains(&a), "got: {a}");
    }

    // --- ADR 0021 CPU-TIER SELECTION: (arch, cpu) must BOTH match ------------------------------

    /// An A76 request (`cpu: Some("cortex-a76")`) binds ONLY the `cpu: cortex-a76` entry, verifying
    /// the A76 blob's own bytes — the whole point of the per-microarch tier.
    #[test]
    fn a76_request_binds_the_cortex_a76_entry() {
        let dir = tmp_dir("a76-accept");
        let baseline_bytes = b"-- A72-safe baseline .cwasm --";
        let a76_bytes = b"-- A76 (LSE) .cwasm, DIFFERENT bytes --";
        let path = dir.join("napse.a76.cwasm");
        fs::write(&path, a76_bytes).unwrap();
        let def = def_with_artifacts(
            "required",
            vec![
                aot_entry("napse.cwasm", "arm64", baseline_bytes),
                aot_entry_cpu("napse.a76.cwasm", "arm64", "cortex-a76", a76_bytes),
            ],
        );
        assert!(verify_aot_binding(&def, &dir, "arm64", Some("cortex-a76"), &path, a76_bytes, None).is_ok());
    }

    /// A BASELINE request (`cpu: None`) binds ONLY the baseline (no-`cpu`) entry, NEVER the A76
    /// one — loading an A76 blob on an A72 would trap on an illegal LSE instruction. Proven by
    /// verifying the A76 file's path AS baseline: no baseline entry pins that path → absence.
    #[test]
    fn baseline_request_never_binds_the_a76_entry() {
        let dir = tmp_dir("baseline-not-a76");
        let a76_bytes = b"-- A76 .cwasm --";
        let a76_path = dir.join("napse.a76.cwasm");
        fs::write(&a76_path, a76_bytes).unwrap();
        // Only an A76 entry exists for this path; there is NO baseline entry pinning napse.a76.cwasm.
        let def = def_with_artifacts(
            "required",
            vec![aot_entry_cpu("napse.a76.cwasm", "arm64", "cortex-a76", a76_bytes)],
        );
        // Requesting baseline (cpu: None) against the A76 file must NOT bind (cpu mismatch) —
        // an absence, never a mismatch, never a silent cross-tier substitution.
        let err = verify_aot_binding(&def, &dir, "arm64", None, &a76_path, a76_bytes, None).unwrap_err();
        assert!(!err.to_string().contains("MISMATCH"), "cross-tier must read as absence, not tamper: {err}");
    }

    /// An A76 request on an image that ships ONLY the baseline blob finds nothing bound for the
    /// A76 tier — a safe absence (the caller then falls back to the baseline tier). Proven by
    /// verifying the baseline file AS cortex-a76: the baseline entry has no `cpu`, so no bind.
    #[test]
    fn a76_request_with_only_baseline_entry_is_a_safe_absence() {
        let dir = tmp_dir("a76-absent");
        let baseline_bytes = b"-- only the baseline was shipped --";
        let path = dir.join("napse.cwasm");
        fs::write(&path, baseline_bytes).unwrap();
        let def = def_with_artifacts("required", vec![aot_entry("napse.cwasm", "arm64", baseline_bytes)]);
        let events = dir.join("events");
        let err = verify_aot_binding(&def, &dir, "arm64", Some("cortex-a76"), &path, baseline_bytes, Some(&events)).unwrap_err();
        assert!(!err.to_string().contains("MISMATCH"), "absence must not read as a mismatch: {err}");
        assert!(!events.exists(), "an absent A76 tier must NOT emit an ArtifactTamper event");
    }

    /// A tampered A76 blob (present, declared for cortex-a76, wrong bytes) is a fail-closed refusal
    /// + ArtifactTamper — same incident discipline as the arch-only case, now on the cpu tier.
    #[test]
    fn tampered_a76_blob_is_refused_with_tamper_event() {
        let dir = tmp_dir("a76-tamper");
        let real_bytes = b"the real signed A76 .cwasm";
        let evil_bytes = b"a swapped A76 blob!";
        let path = dir.join("napse.a76.cwasm");
        fs::write(&path, evil_bytes).unwrap();
        let def = def_with_artifacts(
            "required",
            vec![aot_entry_cpu("napse.a76.cwasm", "arm64", "cortex-a76", real_bytes)],
        );
        let events = dir.join("events");
        let err = verify_aot_binding(&def, &dir, "arm64", Some("cortex-a76"), &path, evil_bytes, Some(&events)).unwrap_err();
        assert!(err.to_string().contains("MISMATCH"), "got: {err}");
        let contents = fs::read_to_string(&events).expect("ArtifactTamper event must be appended");
        assert!(contents.contains("napse.a76.cwasm"), "event must name the A76 blob: {contents}");
    }

    // --- ACCEPT: matching bytes, matching arch, path-bound -------------------------------------

    #[test]
    fn accepts_a_matching_aot_blob_for_this_arch() {
        let dir = tmp_dir("accept");
        let cwasm_bytes = b"-- pretend .cwasm bytes --";
        let path = dir.join("napse.cwasm");
        fs::write(&path, cwasm_bytes).unwrap();
        let def = def_with_artifacts("required", vec![aot_entry("napse.cwasm", "amd64", cwasm_bytes)]);
        assert!(verify_aot_binding(&def, &dir, "amd64", None, &path, cwasm_bytes, None).is_ok());
    }

    // --- ARCH-SELECTIVE: only the entry matching `arch` is ever consulted ----------------------

    #[test]
    fn only_the_entry_for_the_running_arch_is_consulted() {
        let dir = tmp_dir("arch-select");
        let arm64_bytes = b"-- arm64 native code --";
        let amd64_bytes = b"-- amd64 native code, DIFFERENT bytes --";
        let path = dir.join("napse.cwasm");
        // The file ON DISK is the amd64 build...
        fs::write(&path, amd64_bytes).unwrap();
        let def = def_with_artifacts(
            "required",
            vec![aot_entry("napse.cwasm", "arm64", arm64_bytes), aot_entry("napse.cwasm", "amd64", amd64_bytes)],
        );
        // ...and verifying it AS amd64 (matching bytes) succeeds...
        assert!(verify_aot_binding(&def, &dir, "amd64", None, &path, amd64_bytes, None).is_ok());
        // ...while verifying the SAME on-disk bytes AS arm64 must fail (wrong entry: the arm64
        // digest pins DIFFERENT bytes) -- proving the arm64 entry is never silently substituted.
        let err = verify_aot_binding(&def, &dir, "arm64", None, &path, amd64_bytes, None).unwrap_err();
        assert!(err.to_string().contains("MISMATCH"), "got: {err}");
    }

    #[test]
    fn other_arch_entries_are_inert_when_this_arch_has_none() {
        // A module ships ONLY an arm64 aot entry; running "as amd64" must find nothing bound --
        // an absence, not a mismatch (D2: absence is safe/normal, never ArtifactTamper).
        let dir = tmp_dir("other-arch-only");
        let bytes = b"arm64 only";
        let path = dir.join("napse.cwasm");
        fs::write(&path, bytes).unwrap();
        let def = def_with_artifacts("required", vec![aot_entry("napse.cwasm", "arm64", bytes)]);
        let err = verify_aot_binding(&def, &dir, "amd64", None, &path, bytes, None).unwrap_err();
        assert!(!err.to_string().contains("MISMATCH"), "absence must not read as a mismatch: {err}");
    }

    // --- REJECT: digest mismatch -- fail-closed + ArtifactTamper -------------------------------

    #[test]
    fn rejects_a_tampered_aot_blob_and_emits_artifact_tamper() {
        let dir = tmp_dir("tamper");
        let real_bytes = b"the real, signed .cwasm bytes";
        let evil_bytes = b"a completely different, attacker-swapped native blob!";
        let path = dir.join("napse.cwasm");
        fs::write(&path, evil_bytes).unwrap(); // the RO-rootfs file has been swapped
        let def = def_with_artifacts("required", vec![aot_entry("napse.cwasm", "amd64", real_bytes)]);
        let events = dir.join("events");
        // Caller reads the (swapped) bytes ONCE and hands them here -- exactly what
        // load_module_gated does; never a second open of `path`.
        let err = verify_aot_binding(&def, &dir, "amd64", None, &path, evil_bytes, Some(&events)).unwrap_err();
        assert!(err.to_string().contains("MISMATCH"), "got: {err}");
        let contents = fs::read_to_string(&events).expect("ArtifactTamper event must be appended");
        let v: serde_json::Value = serde_json::from_str(contents.trim()).unwrap();
        assert_eq!(v["rule_id"], ARTIFACT_TAMPER_RULE_ID);
        assert_eq!(v["category"], "supply_chain_tamper");
        assert_eq!(v["path"], "napse.cwasm");
    }

    // --- ABSENT: no aot entry at all for this module -- safe, no event -------------------------

    #[test]
    fn absent_aot_entry_is_a_plain_err_with_no_tamper_event() {
        let dir = tmp_dir("absent");
        let path = dir.join("napse.cwasm");
        fs::write(&path, b"whatever bytes happen to be here").unwrap();
        // module.yaml declares NO `role: aot` entries at all (only the wasm executable one).
        let def = def_with_artifacts(
            "required",
            vec![ArtifactDigest {
                path: "napse.wasm".to_string(),
                role: ArtifactRole::Executable,
                arch: None,
                cpu: None,
                digest: Digest { alg: "sha256".to_string(), value: "deadbeef".to_string() },
            }],
        );
        let events = dir.join("events");
        let err = verify_aot_binding(&def, &dir, "amd64", None, &path, b"whatever bytes happen to be here", Some(&events)).unwrap_err();
        assert!(!err.to_string().contains("MISMATCH"), "got: {err}");
        assert!(!events.exists(), "absence must NOT emit an ArtifactTamper event");
    }

    // --- write_digest_value_matching: arch disambiguates repeated `path:` (ADR 0017 D1) --------

    #[test]
    fn write_digest_value_matching_updates_only_the_arch_qualified_entry() {
        let before = r#"artifacts:
  - path: napse.wasm
    role: executable
    digest:
      alg: sha256
      value: "wasmhash"
  - path: napse.cwasm
    role: aot
    arch: arm64
    digest:
      alg: sha256
      value: "OLD_ARM64"
  - path: napse.cwasm
    role: aot
    arch: amd64
    digest:
      alg: sha256
      value: "OLD_AMD64"
"#;
        let after = write_digest_value_matching(before, "napse.cwasm", Some("amd64"), "NEW_AMD64").unwrap();
        assert!(after.contains(r#"value: "NEW_AMD64""#), "got:\n{after}");
        assert!(after.contains(r#"value: "OLD_ARM64""#), "the OTHER arch entry must be untouched:\n{after}");
        assert!(after.contains(r#"value: "wasmhash""#), "the unrelated executable entry must be untouched:\n{after}");

        // And the reverse: targeting arm64 leaves amd64 (now updated) alone.
        let after2 = write_digest_value_matching(&after, "napse.cwasm", Some("arm64"), "NEW_ARM64").unwrap();
        assert!(after2.contains(r#"value: "NEW_ARM64""#));
        assert!(after2.contains(r#"value: "NEW_AMD64""#), "got:\n{after2}");
    }

    #[test]
    fn write_digest_value_matching_errors_when_arch_never_declared() {
        let text = "artifacts:\n  - path: napse.cwasm\n    role: aot\n    arch: arm64\n    digest:\n      alg: sha256\n      value: \"x\"\n";
        let err = write_digest_value_matching(text, "napse.cwasm", Some("riscv64"), "hex").unwrap_err();
        assert!(err.to_string().contains("no matching artifact entry"), "got: {err}");
    }
}

// =================================================================================================
// ADR 0016/0017 sysext-artifact-digest gap fix tests — `resolve_staging_src`/`resolve_artifact_source`
// (the `host-telemetry` driving case: `staging.artifacts[].src -> dest` resolution, the SAME
// convention `builder/gen-staging.sh`/`builder/stage-apply.sh` already interpret) and the
// `is_placeholder_digest` sentinel the three-case release-gate check relies on.
// =================================================================================================
#[cfg(test)]
mod sysext_staging_resolution_tests {
    use super::*;
    use crate::module_def::{ArtifactDigest, ArtifactRole, ModuleStaging, StagingArtifact};
    use crate::types::Runtime;

    fn def_sysext(staging: Option<ModuleStaging>, artifacts: Vec<ArtifactDigest>) -> ModuleDef {
        ModuleDef {
            id: "host-telemetry".to_string(),
            version: "0.1.0".to_string(),
            runtime: Runtime::Sysext,
            requires: Default::default(),
            provides: Default::default(),
            resources: None,
            signature: "required".to_string(),
            grants: Vec::new(),
            artifact: None,
            status: None,
            staging,
            artifacts,
            sig_verified: None,
        }
    }

    // --- is_placeholder_digest: the canonical sentinel set (shared by the shell three-case gate) --

    #[test]
    fn is_placeholder_digest_recognizes_every_sentinel_case_insensitively() {
        for v in ["", "PENDING", "pending", "Pending", "TODO", "todo", "DEADBEEF", "deadbeef", "  pending  "] {
            assert!(is_placeholder_digest(v), "expected placeholder: {v:?}");
        }
    }

    #[test]
    fn is_placeholder_digest_rejects_a_real_looking_hex_value() {
        assert!(!is_placeholder_digest("976ca44e878a7f7f572938561a8816cd3ae4373fca7e0838cd3dd8fe505d5d95"));
        assert!(!is_placeholder_digest("deadbeefcafedeadbeefcafedeadbeefcafedeadbeefcafedeadbeefcafedead"));
    }

    // --- resolve_staging_src: mirrors builder/stage-apply.sh's placeholder convention exactly ----

    #[test]
    fn resolve_staging_src_repo_placeholder() {
        let repo = PathBuf::from("/repo");
        let p = resolve_staging_src("{repo}/modules/host-telemetry/module.yaml", &repo, "arm64").unwrap();
        assert_eq!(p, repo.join("modules/host-telemetry/module.yaml"));
    }

    #[test]
    fn resolve_staging_src_bare_path_is_repo_relative() {
        // gen-staging.sh's resolve_src() convention: a bare (non-`{`) src is repo-relative — the
        // EXACT shape host-telemetry's checked-in .bpf.o source uses in module.yaml.
        let repo = PathBuf::from("/repo");
        let p = resolve_staging_src(
            "modules/host-telemetry/sysext/usr/lib/hookprobe/bpf/execsnoop.bpf.o",
            &repo,
            "arm64",
        )
        .unwrap();
        assert_eq!(p, repo.join("modules/host-telemetry/sysext/usr/lib/hookprobe/bpf/execsnoop.bpf.o"));
    }

    #[test]
    fn resolve_staging_src_bin_placeholder_uses_musl_triple_for_arch() {
        let repo = PathBuf::from("/repo");
        let p = resolve_staging_src("{bin}/hookprobe-execsnoop", &repo, "arm64").unwrap();
        assert_eq!(p, repo.join("target/aarch64-unknown-linux-musl/release/hookprobe-execsnoop"));

        let p = resolve_staging_src("{bin}/hookprobe-execsnoop", &repo, "amd64").unwrap();
        assert_eq!(p, repo.join("target/x86_64-unknown-linux-musl/release/hookprobe-execsnoop"));
    }

    #[test]
    fn resolve_staging_src_gnu_bin_placeholder_uses_gnu_triple_for_arch() {
        // napse-quarantine's own worked example: `{gnu_bin}/napse-quarantine`.
        let repo = PathBuf::from("/repo");
        let p = resolve_staging_src("{gnu_bin}/napse-quarantine", &repo, "arm64").unwrap();
        assert_eq!(p, repo.join("target/aarch64-unknown-linux-gnu/release/napse-quarantine"));
    }

    #[test]
    fn resolve_staging_src_wasm_placeholder_is_arch_independent() {
        let repo = PathBuf::from("/repo");
        let p = resolve_staging_src("{wasm}/napse.wasm", &repo, "riscv64").unwrap();
        assert_eq!(p, repo.join("target/wasm32-wasip1/release/napse.wasm"));
    }

    #[test]
    fn resolve_staging_src_rejects_unknown_arch_for_a_triple_dependent_placeholder() {
        let repo = PathBuf::from("/repo");
        let err = resolve_staging_src("{bin}/x", &repo, "unknown").unwrap_err();
        assert!(err.to_string().contains("unknown arch"), "got: {err}");
    }

    #[test]
    fn resolve_staging_src_rejects_an_unsupported_placeholder() {
        let repo = PathBuf::from("/repo");
        let err = resolve_staging_src("{nope}/x", &repo, "arm64").unwrap_err();
        assert!(err.to_string().contains("unsupported placeholder"), "got: {err}");
    }

    // --- resolve_artifact_source: the actual gap fix (dest -> src, THEN placeholder-resolve) -----

    #[test]
    fn resolve_artifact_source_prefers_staging_src_over_dest_for_a_matching_entry() {
        // The host-telemetry shape: artifacts[].path is the on-device DEST (absolute); the real
        // bytes live at staging.artifacts[].src (a build-tree path) for the SAME dest.
        let repo = PathBuf::from("/repo");
        let module_dir = PathBuf::from("/repo/modules/host-telemetry");
        let staging = ModuleStaging {
            artifacts: vec![
                StagingArtifact {
                    src: "{bin}/hookprobe-execsnoop".to_string(),
                    dest: "/usr/lib/hookprobe/hookprobe-execsnoop".to_string(),
                    mode: None,
                },
                StagingArtifact {
                    src: "modules/host-telemetry/sysext/usr/lib/hookprobe/bpf/execsnoop.bpf.o".to_string(),
                    dest: "/usr/lib/hookprobe/bpf/execsnoop.bpf.o".to_string(),
                    mode: None,
                },
            ],
        };
        let def = def_sysext(Some(staging), vec![]);

        let loader = resolve_artifact_source(
            &def,
            "/usr/lib/hookprobe/hookprobe-execsnoop",
            &module_dir,
            &repo,
            "amd64",
        )
        .unwrap();
        assert_eq!(loader, repo.join("target/x86_64-unknown-linux-musl/release/hookprobe-execsnoop"));

        let bpf_obj = resolve_artifact_source(
            &def,
            "/usr/lib/hookprobe/bpf/execsnoop.bpf.o",
            &module_dir,
            &repo,
            "amd64",
        )
        .unwrap();
        assert_eq!(bpf_obj, repo.join("modules/host-telemetry/sysext/usr/lib/hookprobe/bpf/execsnoop.bpf.o"));

        // NOT the naive (pre-fix) resolution, which would have returned the absolute dest as-is
        // (a path that never exists in this checkout) — the whole point of the gap fix.
        assert_ne!(loader, PathBuf::from("/usr/lib/hookprobe/hookprobe-execsnoop"));
    }

    #[test]
    fn resolve_artifact_source_falls_back_to_resolve_artifact_path_when_no_staging_entry_matches() {
        // A co-located wasm module (no `staging:` block at all) must behave EXACTLY as before this
        // fix existed.
        let repo = PathBuf::from("/repo");
        let module_dir = PathBuf::from("/repo/modules/napse");
        let def = def_sysext(None, vec![]);
        let p = resolve_artifact_source(&def, "napse.wasm", &module_dir, &repo, "amd64").unwrap();
        assert_eq!(p, module_dir.join("napse.wasm"));
    }

    #[test]
    fn resolve_artifact_source_falls_back_when_staging_present_but_dest_unmatched() {
        // A module WITH a staging: block, but this particular artifact's `path` doesn't match any
        // staging.artifacts[].dest (e.g. a stray co-located file alongside a sysext module) — must
        // still fall back to the co-located convention, not error.
        let repo = PathBuf::from("/repo");
        let module_dir = PathBuf::from("/repo/modules/host-telemetry");
        let staging = ModuleStaging {
            artifacts: vec![StagingArtifact {
                src: "{bin}/hookprobe-execsnoop".to_string(),
                dest: "/usr/lib/hookprobe/hookprobe-execsnoop".to_string(),
                mode: None,
            }],
        };
        let def = def_sysext(Some(staging), vec![]);
        let p = resolve_artifact_source(&def, "some-other-file.txt", &module_dir, &repo, "amd64").unwrap();
        assert_eq!(p, module_dir.join("some-other-file.txt"));
    }

    // --- end-to-end: the REAL host-telemetry shape, hashed against the REAL checked-in .bpf.o ----

    #[test]
    fn resolve_artifact_source_resolves_the_real_checked_in_host_telemetry_bpf_object() {
        // Uses the actual repo tree (this crate lives at <repo>/crates/hookprobe-manifest) so this
        // is a REAL end-to-end proof, not just a path-shape assertion: resolve host-telemetry's
        // `role: bpf-object` artifact through its own `staging.artifacts[].src`, read the bytes,
        // and confirm they hash to the exact digest `modules/host-telemetry/module.yaml` pins.
        let repo_root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
        let module_dir = repo_root.join("modules/host-telemetry");
        let yaml_path = module_dir.join("module.yaml");
        let Ok(text) = fs::read_to_string(&yaml_path) else {
            eprintln!("skipping: {yaml_path:?} not found in this checkout");
            return;
        };
        let def: ModuleDef = serde_yaml::from_str(&text).expect("parses host-telemetry/module.yaml");
        let bpf_artifact = def
            .artifacts
            .iter()
            .find(|a| a.role == ArtifactRole::BpfObject)
            .expect("host-telemetry declares a role: bpf-object artifact");

        let resolved = resolve_artifact_source(&def, &bpf_artifact.path, &module_dir, &repo_root, "amd64")
            .expect("resolves via staging.artifacts[].src");
        let bytes = fs::read(&resolved).unwrap_or_else(|e| panic!("reading {resolved:?}: {e}"));
        let actual = digest_hex(&bpf_artifact.digest.alg, &bytes).unwrap();
        assert!(
            actual.eq_ignore_ascii_case(bpf_artifact.digest.value.trim()),
            "resolved {resolved:?} digest {actual} does not match module.yaml's pinned {}",
            bpf_artifact.digest.value
        );
        assert!(!is_placeholder_digest(&bpf_artifact.digest.value), "bpf-object digest must be REAL, not a placeholder");
    }
}
