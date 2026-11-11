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
//!   ct   = CTR(k_enc, nonce, plaintext)         (fresh per-seal nonce, AUD-STO-1)
//!   tag  = HMAC(k_mac, header[0..96] || ct)     (Encrypt-then-MAC; nonce in header)
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
const O_NONCE: usize = 72; // 16 bytes — per-seal CTR nonce (AUD-STO-1); MAC-covered
const NONCE_LEN: usize = 16;
// 88..96 reserved (zero)
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

/// Per-seal CTR nonce (AUD-STO-1). MUST be unique per (key, seal) or the keystream
/// repeats. Within a boot: a strictly-monotonic counter + the cycle counter, through SHA-256.
/// ACROSS boots (2026-11-09, BOI review A6.6): the counter restarts at 0 and the cycle counter
/// restarts too, so a snapshot sealed at the same point after two boots could reuse a nonce under
/// the same SRK-derived key — CTR keystream reuse. Every nonce now also absorbs a per-boot 32-byte
/// salt drawn once from the hardware TRNG (BCM2712 RNG200, strict/health-checked). If the TRNG is
/// unavailable the draw is retried on the next seal (the nonce is still unique within the boot).
/// QEMU has no TRNG: there the old within-boot guarantee is what holds.
fn boot_salt() -> Option<[u8; 32]> {
    use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
    static SET: AtomicBool = AtomicBool::new(false);
    static W: [AtomicU64; 4] = [const { AtomicU64::new(0) }; 4];
    if !SET.load(Ordering::Acquire) {
        #[cfg(feature = "cm5")]
        {
            let mut w = [0u64; 4];
            for x in w.iter_mut() {
                *x = arch_aarch64::rng200::next_word_strict()?;
            }
            for (a, v) in W.iter().zip(w) {
                a.store(v, Ordering::Relaxed);
            }
            SET.store(true, Ordering::Release);
        }
        #[cfg(not(feature = "cm5"))]
        return None;
    }
    let mut s = [0u8; 32];
    for (i, a) in W.iter().enumerate() {
        s[i * 8..i * 8 + 8].copy_from_slice(&a.load(Ordering::Relaxed).to_le_bytes());
    }
    Some(s)
}

fn gen_nonce() -> [u8; NONCE_LEN] {
    use core::sync::atomic::{AtomicU64, Ordering};
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let seq = SEQ.fetch_add(1, Ordering::Relaxed);
    let t: u64;
    unsafe {
        core::arch::asm!("mrs {}, cntpct_el0", out(reg) t, options(nomem, nostack));
    }
    let mut h = Hasher::new();
    h.update(b"HQKSEAL1-nonce");
    if let Some(salt) = boot_salt() {
        h.update(&salt);
    }
    h.update(&seq.to_le_bytes());
    h.update(&t.to_le_bytes());
    let d = h.finish();
    let mut n = [0u8; NONCE_LEN];
    n.copy_from_slice(&d[..NONCE_LEN]);
    n
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

    // AUD-STO-1: fresh per-seal nonce, written into the MAC-covered header so it is
    // authenticated and available to unseal. Binds the CTR keystream to this seal.
    let nonce = gen_nonce();
    b[O_NONCE..O_NONCE + NONCE_LEN].copy_from_slice(&nonce);

    // Ciphertext = CTR(k_enc, nonce, plaintext).
    b[SEAL_HDR_LEN..SEAL_HDR_LEN + plaintext.len()].copy_from_slice(plaintext);
    kdf::ctr_xor_nonce(
        &key.k_enc,
        &nonce,
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

    // Authenticated: decrypt into the caller's buffer. The nonce lives in the
    // MAC-covered header, so the tag check above already authenticated it.
    out[..ct_len].copy_from_slice(&blob[SEAL_HDR_LEN..SEAL_HDR_LEN + ct_len]);
    kdf::ctr_xor_nonce(&key.k_enc, &blob[O_NONCE..O_NONCE + NONCE_LEN], &mut out[..ct_len]);
    Ok(ct_len)
}

// ---- configuration sealed at rest (design the repo-root design doc heqk-sealed-config-live-apply, step 1) ---------------------
// In-place variants for the A/B configuration store: a 16 KiB HQCFG1 bundle does not fit SEAL_MAX_PT. Same HQKSEAL1
// header and the same Encrypt-then-MAC; the reserved MAC-covered bytes 88..96 carry the configuration GENERATION so
// the store's fallback can read it without decrypting (and a swapped generation fails the tag).

/// Largest plaintext sealed in place (a bundle 16 KiB + its signature sector).
pub const SEAL_INPLACE_MAX_PT: usize = 16 * 1024 + 512;
const O_GEN: usize = 88;

/// The per-type configuration key: `HKDF(SRK, "HQ-cfg-at-rest-v1" ‖ ty)` — a sealed WAN slot copied into the Wi-Fi
/// slot fails the tag. Used as the `srk` argument of the in-place functions.
pub fn cfg_key(srk: &[u8; 32], ty: u8) -> [u8; 32] {
    let prk = kdf::hkdf_extract(b"HQ-cfg-at-rest-v1", srk);
    kdf::hkdf_expand32(&prk, &[b'c', b'f', b'g', ty])
}

/// The config seal policy: device-bound, not measurement- or SVN-bound (the configuration must survive OTA updates).
pub fn cfg_policy(device_id: u64) -> Policy {
    Policy { mask: 0, device_id, svn_floor: 0, pcr: [[0u8; 32]; NUM_PCR] }
}

/// Seal in place: `buf[SEAL_HDR_LEN..SEAL_HDR_LEN + pt_len]` holds the plaintext on entry; on return `buf[..len]` is
/// the blob (header + ciphertext). Ok(blob length).
pub fn seal_in_place(key: &[u8; 32], policy: &Policy, buf: &mut [u8], pt_len: usize, gen: u64) -> Result<usize, SealErr> {
    if pt_len > SEAL_INPLACE_MAX_PT || buf.len() < SEAL_HDR_LEN + pt_len {
        return Err(SealErr::TooLong);
    }
    let pd = policy.digest();
    let k = SealKey::derive(key, &pd);
    buf[..SEAL_HDR_LEN].fill(0);
    buf[O_MAGIC..O_MAGIC + 8].copy_from_slice(SEAL_MAGIC);
    put_u32(buf, O_VERSION, SEAL_VERSION);
    put_u32(buf, O_MASK, policy.mask);
    put_u64(buf, O_DEVID, policy.device_id);
    put_u64(buf, O_FLOOR, policy.svn_floor);
    buf[O_PDIGEST..O_PDIGEST + 32].copy_from_slice(&pd);
    put_u32(buf, O_PTLEN, pt_len as u32);
    put_u32(buf, O_CTLEN, pt_len as u32);
    let nonce = gen_nonce();
    buf[O_NONCE..O_NONCE + NONCE_LEN].copy_from_slice(&nonce);
    put_u64(buf, O_GEN, gen);
    kdf::ctr_xor_nonce(&k.k_enc, &nonce, &mut buf[SEAL_HDR_LEN..SEAL_HDR_LEN + pt_len]);
    let (head, rest) = buf.split_at_mut(SEAL_HDR_LEN);
    let tag = kdf::hmac_sha256_2(&k.k_mac, &head[..TAG_COVER], &rest[..pt_len]);
    head[O_TAG..O_TAG + 32].copy_from_slice(&tag);
    Ok(SEAL_HDR_LEN + pt_len)
}

/// The generation recorded in a sealed blob's (MAC-covered) header, without decrypting. Only trust it after unseal.
pub fn sealed_gen(blob: &[u8]) -> Option<u64> {
    (blob.len() >= SEAL_HDR_LEN && &blob[O_MAGIC..O_MAGIC + 8] == SEAL_MAGIC)
        .then(|| u64::from_le_bytes(blob[O_GEN..O_GEN + 8].try_into().unwrap()))
}

/// Unseal in place: the tag is verified over the header + ciphertext BEFORE anything is decrypted (nothing is
/// decrypted on failure); then `buf[SEAL_HDR_LEN..SEAL_HDR_LEN + len]` becomes the plaintext. Ok((len, generation)).
pub fn unseal_in_place(key: &[u8; 32], cur: &Policy, buf: &mut [u8]) -> Result<(usize, u64), SealErr> {
    if buf.len() < SEAL_HDR_LEN {
        return Err(SealErr::ShortBlob);
    }
    if &buf[O_MAGIC..O_MAGIC + 8] != SEAL_MAGIC {
        return Err(SealErr::BadMagic);
    }
    if get_u32(buf, O_VERSION) != SEAL_VERSION {
        return Err(SealErr::BadVersion);
    }
    let ct_len = get_u32(buf, O_CTLEN) as usize;
    if ct_len != get_u32(buf, O_PTLEN) as usize || ct_len > SEAL_INPLACE_MAX_PT || SEAL_HDR_LEN + ct_len > buf.len() {
        return Err(SealErr::ShortBlob);
    }
    let pol = Policy { mask: get_u32(buf, O_MASK), device_id: cur.device_id, svn_floor: cur.svn_floor, pcr: cur.pcr };
    if !kdf::ct_eq(&buf[O_DEVID..O_DEVID + 8], &cur.device_id.to_le_bytes()) {
        return Err(SealErr::DeviceMismatch);
    }
    let pd = pol.digest();
    if !kdf::ct_eq(&buf[O_PDIGEST..O_PDIGEST + 32], &pd) {
        return Err(SealErr::PolicyMismatch);
    }
    let k = SealKey::derive(key, &pd);
    let tag = kdf::hmac_sha256_2(&k.k_mac, &buf[..TAG_COVER], &buf[SEAL_HDR_LEN..SEAL_HDR_LEN + ct_len]);
    if !kdf::ct_eq(&buf[O_TAG..O_TAG + 32], &tag) {
        return Err(SealErr::Tag);
    }
    let gen = u64::from_le_bytes(buf[O_GEN..O_GEN + 8].try_into().unwrap());
    let nonce: [u8; NONCE_LEN] = buf[O_NONCE..O_NONCE + NONCE_LEN].try_into().unwrap();
    kdf::ctr_xor_nonce(&k.k_enc, &nonce, &mut buf[SEAL_HDR_LEN..SEAL_HDR_LEN + ct_len]);
    Ok((ct_len, gen))
}

/// `[P-sealcfg]` (step 1): a 16.6 KiB in-place round trip; the plaintext is gone from the blob; a flipped ciphertext,
/// header or generation byte is refused (nothing decrypted); another type's key and another device are refused.
pub fn inplace_selftest() -> bool {
    static mut B: [u8; SEAL_HDR_LEN + SEAL_INPLACE_MAX_PT] = [0; SEAL_HDR_LEN + SEAL_INPLACE_MAX_PT];
    let buf = unsafe { &mut *core::ptr::addr_of_mut!(B) };
    let srk = [0x5au8; 32];
    let (kw, kf) = (cfg_key(&srk, 6), cfg_key(&srk, 7));
    let pol = cfg_policy(0x1234);
    let n = SEAL_INPLACE_MAX_PT;
    let fill = |b: &mut [u8]| {
        for (i, x) in b[SEAL_HDR_LEN..SEAL_HDR_LEN + n].iter_mut().enumerate() {
            *x = (i % 251) as u8;
        }
        b[SEAL_HDR_LEN..SEAL_HDR_LEN + 15].copy_from_slice(b"pppoe_pass=s3cr");
    };
    fill(buf);
    let sealed = seal_in_place(&kw, &pol, buf, n, 42).ok() == Some(SEAL_HDR_LEN + n);
    let hidden = !buf.windows(15).any(|w| w == b"pppoe_pass=s3cr") && sealed_gen(buf) == Some(42);
    let mut ok_rt = false;
    let refuse = |b: &mut [u8], at: usize, k: &[u8; 32], p: &Policy| -> bool {
        b[at] ^= 1;
        let r = unseal_in_place(k, p, b).is_err();
        b[at] ^= 1;
        r
    };
    let flips = refuse(buf, SEAL_HDR_LEN + 1000, &kw, &pol) && refuse(buf, 88, &kw, &pol) && refuse(buf, 75, &kw, &pol);
    let other_type = unseal_in_place(&kf, &pol, buf).is_err();
    let other_dev = unseal_in_place(&kw, &cfg_policy(0x9999), buf).is_err();
    if let Ok((len, gen)) = unseal_in_place(&kw, &pol, buf) {
        ok_rt = len == n && gen == 42 && &buf[SEAL_HDR_LEN..SEAL_HDR_LEN + 15] == b"pppoe_pass=s3cr"
            && buf[SEAL_HDR_LEN + 15..SEAL_HDR_LEN + n].iter().enumerate().all(|(i, &x)| x == ((i + 15) % 251) as u8);
    }
    let pass = sealed && hidden && flips && other_type && other_dev && ok_rt;
    arch_aarch64::_print(format_args!(" [P-sealcfg] {} — config sealed at rest, step 1: 16.6 KiB in-place seal/unseal round trip={} the secret and the plaintext are gone from the blob, generation readable={} a flipped ciphertext / generation / nonce byte refused={} another type's key refused={} another device refused={}\n",
        if pass { "PASS" } else { "FAIL" }, ok_rt, hidden, flips, other_type, other_dev));
    pass
}
