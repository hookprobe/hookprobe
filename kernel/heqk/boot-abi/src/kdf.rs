//! P15 sealing primitives — HMAC / HKDF / CTR / constant-time compare, all built
//! over the `boot-abi` SHA-256 (`sha256`). Kept minimal on purpose: rather than
//! pull a RustCrypto AEAD into the boot TCB for a <=4 KiB blob, the whole
//! construction is ~120 lines of well-understood primitives over one hash.
//!
//! Shared by HBoot (SRK derivation, when V3 is closed) and the kernel seal store,
//! so it lives in the arch-agnostic boot ABI and is fully QEMU-testable.
//!
//! NOTE: the underlying SHA-256 is not constant-time (data-independent control
//! flow but table-free); `ct_eq` below is the constant-time tag/policy/id compare
//! the seal layer relies on. Secrets are 256-bit uniform keys, not low-entropy.

use crate::sha256::{self, Hasher};

const BLOCK: usize = 64; // SHA-256 block size

/// HMAC-SHA256 over a single message slice. Standard RFC 2104 construction.
pub fn hmac_sha256(key: &[u8], msg: &[u8]) -> [u8; 32] {
    hmac_sha256_2(key, msg, &[])
}

/// HMAC-SHA256 over the concatenation `msg1 || msg2`, without allocating the
/// concatenation (the seal tag covers `header || ciphertext`, two slices, with a
/// ciphertext that can be multiple KiB — streamed through the incremental hasher).
pub fn hmac_sha256_2(key: &[u8], msg1: &[u8], msg2: &[u8]) -> [u8; 32] {
    // K0: key padded/hashed to the block size.
    let mut k0 = [0u8; BLOCK];
    if key.len() > BLOCK {
        let kh = sha256::digest(key);
        k0[..32].copy_from_slice(&kh);
    } else {
        k0[..key.len()].copy_from_slice(key);
    }
    let mut ipad = [0u8; BLOCK];
    let mut opad = [0u8; BLOCK];
    for i in 0..BLOCK {
        ipad[i] = k0[i] ^ 0x36;
        opad[i] = k0[i] ^ 0x5c;
    }
    // inner = H(ipad || msg1 || msg2)
    let mut inner = Hasher::new();
    inner.update(&ipad);
    inner.update(msg1);
    inner.update(msg2);
    let ih = inner.finish();
    // outer = H(opad || inner)
    let mut outer = Hasher::new();
    outer.update(&opad);
    outer.update(&ih);
    outer.finish()
}

/// HKDF-Extract (RFC 5869): `PRK = HMAC(salt, IKM)`.
pub fn hkdf_extract(salt: &[u8], ikm: &[u8]) -> [u8; 32] {
    hmac_sha256(salt, ikm)
}

/// HKDF-Expand for a single 32-byte output block (L = 32, so one T(1) round):
/// `HMAC(PRK, info || 0x01)`. `info` is streamed so no concatenation buffer is
/// needed.
pub fn hkdf_expand32(prk: &[u8; 32], info: &[u8]) -> [u8; 32] {
    hmac_sha256_2(prk, info, &[0x01])
}

/// Stream-cipher XOR in place: keystream block `i` = `SHA256(key || LE64(i))`,
/// 32 bytes each, counter incrementing from 0. Encrypt == decrypt.
pub fn ctr_xor(key: &[u8; 32], data: &mut [u8]) {
    let mut counter: u64 = 0;
    let mut off = 0usize;
    let mut blk = [0u8; 40];
    blk[..32].copy_from_slice(key);
    while off < data.len() {
        blk[32..40].copy_from_slice(&counter.to_le_bytes());
        let ks = sha256::digest(&blk);
        let n = (data.len() - off).min(32);
        for j in 0..n {
            data[off + j] ^= ks[j];
        }
        off += n;
        counter = counter.wrapping_add(1);
    }
}

/// Constant-time equality: fold every byte difference; no early exit. Returns
/// false immediately on a length mismatch (length is not secret).
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for i in 0..a.len() {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}
