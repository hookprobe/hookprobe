//! P15 — sealing blob format (`HQKSEAL1`) + seal/unseal (Encrypt-then-MAC).
//!
//! DICE-style, TPM-free: every per-policy key is derived from a sealing root key
//! (SRK) bound to the boot measurement. A layer that is not the measured one
//! derives a DIFFERENT key and simply cannot authenticate the blob — refusal is
//! automatic, with no policy-evaluation engine to bypass.
//!
//!   PRK  = HKDF-Extract(salt = policy_digest, ikm = SRK)
//!   k_enc = HKDF-Expand(PRK, "HQKSEAL1-enc")   (CTR keystream key)
//!   k_mac = HKDF-Expand(PRK, "HQKSEAL1-mac")   (HMAC tag key)
//!   ct   = CTR(k_enc, plaintext)
//!   tag  = HMAC(k_mac, header[0..96] || ct)     (Encrypt-then-MAC)
//!
//! Blob = 128-byte header (incl. the tag) followed by the ciphertext.
//!
//! SECURITY LIMIT (SEALED_STORAGE.md): the measurement binding is only REAL once
//! HBoot derives the SRK from the OTP secret with EL1 unable to read OTP (audit
//! finding V3). Until then the kernel uses a SYNTHETIC SRK and the caller MUST
//! print that measurement enforcement is not yet real. The crypto below is
//! correct either way — only the *provenance* of the SRK is provisional.

use boot_abi::kdf;
use boot_abi::sha256::Hasher;
use boot_abi::NUM_PCR;

pub const SEAL_MAGIC: &[u8; 8] = b"HQKSEAL1";
pub const SEAL_VERSION: u32 = 1;
pub const SEAL_HDR_LEN: usize = 128;
/// Max plaintext so a blob fits in 8 sectors (128 + 3968 = 4096 = 8 * 512).
pub const SEAL_MAX_PT: usize = 3968;
pub const SEAL_MAX_BLOB: usize = SEAL_HDR_LEN + SEAL_MAX_PT;

// Header field offsets (little-endian scalars).
const O_MAGIC: usize = 0; //  8 bytes
const O_VERSION: usize = 8; //  u32
const O_MASK: usize = 12; //  u32
const O_DEVID: usize = 16; //  u64
const O_FLOOR: usize = 24; //  u64
const O_PDIGEST: usize = 32; // 32 bytes
const O_PTLEN: usize = 64; //  u32
const O_CTLEN: usize = 68; //  u32
// 72..96 reserved (zero)
const O_TAG: usize = 96; //  32 bytes
const TAG_COVER: usize = 96; // header bytes the tag authenticates (before the tag)

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SealErr {
    BadMagic,
    BadVersion,
    /// Plaintext longer than SEAL_MAX_PT, or the output buffer is too small.
    TooLong,
    /// Blob shorter than the header, or the declared ct length doesn't fit.
    ShortBlob,
    /// The blob's bound device_id doesn't match the current device.
    DeviceMismatch,
    /// The current measurement/policy differs from the sealed one.
    PolicyMismatch,
    /// The authentication tag failed (tampered ciphertext/header, or wrong key).
    Tag,
}

/// The measured environment a blob is bound to. `mask` selects which PCRs bind;
/// `device_id` and `svn_floor` always bind (identity + anti-rollback).
#[derive(Clone, Copy)]
pub struct Policy {
    pub mask: u32,
    pub device_id: u64,
    pub svn_floor: u64,
    pub pcr: [[u8; 32]; NUM_PCR],
}

impl Policy {
    /// `policy = SHA256("tag" || mask || device_id || svn_floor || selected PCRs)`.
    /// Order-fixed and domain-separated so two policies never collide.
    pub fn digest(&self) -> [u8; 32] {
        let mut h = Hasher::new();
        h.update(b"HEQK-SEAL-POLICY-v1");
        h.update(&self.mask.to_le_bytes());
        h.update(&self.device_id.to_le_bytes());
        h.update(&self.svn_floor.to_le_bytes());
        for i in 0..NUM_PCR {
            if self.mask & (1 << i) != 0 {
                h.update(&self.pcr[i]);
            }
        }
        h.finish()
    }
}

/// A pair of derived subkeys, zeroized on drop (no key material lingers in RAM).
pub struct SealKey {
    k_enc: [u8; 32],
    k_mac: [u8; 32],
}

impl SealKey {
    /// Bind the policy into the extract salt so a different measurement/policy
    /// yields different subkeys — the DICE "cannot decrypt" property.
    fn derive(srk: &[u8; 32], policy_digest: &[u8; 32]) -> SealKey {
        let prk = kdf::hkdf_extract(policy_digest, srk);
        SealKey {
            k_enc: kdf::hkdf_expand32(&prk, b"HQKSEAL1-enc"),
            k_mac: kdf::hkdf_expand32(&prk, b"HQKSEAL1-mac"),
        }
    }
}

impl Drop for SealKey {
    fn drop(&mut self) {
        // Volatile zeroing so the scrub is not optimized away.
        for b in self.k_enc.iter_mut() {
            unsafe { core::ptr::write_volatile(b, 0) };
        }
        for b in self.k_mac.iter_mut() {
            unsafe { core::ptr::write_volatile(b, 0) };
        }
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    }
}

/// A fixed-capacity sealed blob (avoids heap in the crypto path).
pub struct SealBlob {
    pub bytes: [u8; SEAL_MAX_BLOB],
    pub len: usize,
}

impl SealBlob {
    pub fn new() -> Self {
        SealBlob {
            bytes: [0u8; SEAL_MAX_BLOB],
            len: 0,
        }
    }
    pub fn as_slice(&self) -> &[u8] {
        &self.bytes[..self.len]
    }
}

impl Default for SealBlob {
    fn default() -> Self {
        Self::new()
    }
}

#[inline]
fn put_u32(buf: &mut [u8], off: usize, v: u32) {
    buf[off..off + 4].copy_from_slice(&v.to_le_bytes());
}
#[inline]
fn put_u64(buf: &mut [u8], off: usize, v: u64) {
    buf[off..off + 8].copy_from_slice(&v.to_le_bytes());
}
#[inline]
fn get_u32(buf: &[u8], off: usize) -> u32 {
    u32::from_le_bytes([buf[off], buf[off + 1], buf[off + 2], buf[off + 3]])
}

/// Seal `plaintext` under `policy` using `srk`, writing the blob into `out`.
pub fn seal(
    srk: &[u8; 32],
    policy: &Policy,
    plaintext: &[u8],
    out: &mut SealBlob,
) -> Result<(), SealErr> {
    if plaintext.len() > SEAL_MAX_PT {
        return Err(SealErr::TooLong);
    }
    let pd = policy.digest();
    let key = SealKey::derive(srk, &pd);

    let b = &mut out.bytes;
    // Zero the header (reserved bytes stay 0).
    for x in b[..SEAL_HDR_LEN].iter_mut() {
        *x = 0;
    }
    b[O_MAGIC..O_MAGIC + 8].copy_from_slice(SEAL_MAGIC);
    put_u32(b, O_VERSION, SEAL_VERSION);
    put_u32(b, O_MASK, policy.mask);
    put_u64(b, O_DEVID, policy.device_id);
    put_u64(b, O_FLOOR, policy.svn_floor);
    b[O_PDIGEST..O_PDIGEST + 32].copy_from_slice(&pd);
    put_u32(b, O_PTLEN, plaintext.len() as u32);
    put_u32(b, O_CTLEN, plaintext.len() as u32);

    // Ciphertext = CTR(plaintext).
    b[SEAL_HDR_LEN..SEAL_HDR_LEN + plaintext.len()].copy_from_slice(plaintext);
    kdf::ctr_xor(
        &key.k_enc,
        &mut b[SEAL_HDR_LEN..SEAL_HDR_LEN + plaintext.len()],
    );

    // Tag = HMAC(k_mac, header[0..96] || ct) — Encrypt-then-MAC.
    let (head, rest) = b.split_at(SEAL_HDR_LEN);
    let tag = kdf::hmac_sha256_2(&key.k_mac, &head[..TAG_COVER], &rest[..plaintext.len()]);
    b[O_TAG..O_TAG + 32].copy_from_slice(&tag);

    out.len = SEAL_HDR_LEN + plaintext.len();
    Ok(())
}

/// Unseal `blob` against the CURRENT `cur` measurement, writing plaintext into
/// `out` and returning its length. Encrypt-then-MAC: the tag is verified BEFORE
/// any decryption, and NO plaintext is written on any failure path. All
/// identity/policy/tag comparisons are constant-time.
pub fn unseal(
    srk: &[u8; 32],
    cur: &Policy,
    blob: &[u8],
    out: &mut [u8],
) -> Result<usize, SealErr> {
    if blob.len() < SEAL_HDR_LEN {
        return Err(SealErr::ShortBlob);
    }
    if &blob[O_MAGIC..O_MAGIC + 8] != SEAL_MAGIC {
        return Err(SealErr::BadMagic);
    }
    if get_u32(blob, O_VERSION) != SEAL_VERSION {
        return Err(SealErr::BadVersion);
    }
    let mask = get_u32(blob, O_MASK);
    let ct_len = get_u32(blob, O_CTLEN) as usize;
    let pt_len = get_u32(blob, O_PTLEN) as usize;
    if ct_len != pt_len
        || ct_len > SEAL_MAX_PT
        || SEAL_HDR_LEN + ct_len > blob.len()
    {
        return Err(SealErr::ShortBlob);
    }
    if out.len() < ct_len {
        return Err(SealErr::TooLong);
    }

    // Recompute the policy the CURRENT device/state would produce under the
    // blob's declared PCR mask — current device_id + floor + PCRs, sealed mask.
    let pol = Policy {
        mask,
        device_id: cur.device_id,
        svn_floor: cur.svn_floor,
        pcr: cur.pcr,
    };

    // Explicit, constant-time identity gate (clean error; also authenticated).
    if !kdf::ct_eq(&blob[O_DEVID..O_DEVID + 8], &cur.device_id.to_le_bytes()) {
        return Err(SealErr::DeviceMismatch);
    }
    // Explicit, constant-time policy gate: sealed digest vs current digest.
    let pd_now = pol.digest();
    if !kdf::ct_eq(&blob[O_PDIGEST..O_PDIGEST + 32], &pd_now) {
        return Err(SealErr::PolicyMismatch);
    }

    // Cryptographic gate: recompute the tag over header[0..96] || ct.
    let key = SealKey::derive(srk, &pd_now);
    let tag = kdf::hmac_sha256_2(
        &key.k_mac,
        &blob[..TAG_COVER],
        &blob[SEAL_HDR_LEN..SEAL_HDR_LEN + ct_len],
    );
    if !kdf::ct_eq(&blob[O_TAG..O_TAG + 32], &tag) {
        return Err(SealErr::Tag); // authentication failed — reveal NO plaintext
    }

    // Authenticated: decrypt into the caller's buffer.
    out[..ct_len].copy_from_slice(&blob[SEAL_HDR_LEN..SEAL_HDR_LEN + ct_len]);
    kdf::ctr_xor(&key.k_enc, &mut out[..ct_len]);
    Ok(ct_len)
}
