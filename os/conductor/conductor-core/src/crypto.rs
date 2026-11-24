// SPDX-License-Identifier: AGPL-3.0-only
//! The two primitives Conductor uses, both already in heqk: SHA-256 and Ed25519 (verify here; signing only
//! behind the `signer` feature). Every signature is over a domain tag followed by the message, so a
//! signature made for one purpose can never be accepted for another (design review v2 §03, key separation).

use sha2::{Digest, Sha256};

/// HP-EXEC capability, signed by the device's delegation key (only that key, only this purpose).
pub const TAG_HP_EXEC: &[u8] = b"hookprobe/conductor/hp-exec/v1\0";
/// A worker's signature over its final result.
pub const TAG_RESULT: &[u8] = b"hookprobe/conductor/result/v1\0";

pub fn sha256(parts: &[&[u8]]) -> [u8; 32] {
    let mut h = Sha256::new();
    for p in parts {
        h.update(p);
    }
    h.finalize().into()
}

/// Largest message any Conductor signature covers (tag + HP-EXEC body), so verification needs no allocation.
const MSG_MAX: usize = 512;

fn join<'a>(buf: &'a mut [u8; MSG_MAX], tag: &[u8], msg: &[u8]) -> Option<&'a [u8]> {
    let n = tag.len().checked_add(msg.len())?;
    buf.get_mut(..tag.len())?.copy_from_slice(tag);
    buf.get_mut(tag.len()..n)?.copy_from_slice(msg);
    buf.get(..n)
}

/// Verify an Ed25519 signature over `tag ‖ msg`. Any malformed input is simply `false`.
pub fn verify(pk: &[u8; 32], tag: &[u8], msg: &[u8], sig: &[u8; 64]) -> bool {
    let mut buf = [0u8; MSG_MAX];
    let Some(m) = join(&mut buf, tag, msg) else { return false };
    let pk = ed25519_compact::PublicKey::new(*pk);
    let sig = ed25519_compact::Signature::new(*sig);
    pk.verify(m, &sig).is_ok()
}

/// Sign `tag ‖ msg` (deterministic Ed25519). Only for the delegation signer and the mock worker.
#[cfg(feature = "signer")]
pub fn sign(seed: &[u8; 32], tag: &[u8], msg: &[u8]) -> Option<[u8; 64]> {
    let mut buf = [0u8; MSG_MAX];
    let m = join(&mut buf, tag, msg)?;
    let kp = ed25519_compact::KeyPair::from_seed(ed25519_compact::Seed::new(*seed));
    Some(*kp.sk.sign(m, None))
}

/// The public key for a 32-byte seed.
#[cfg(feature = "signer")]
pub fn public_key(seed: &[u8; 32]) -> [u8; 32] {
    let kp = ed25519_compact::KeyPair::from_seed(ed25519_compact::Seed::new(*seed));
    *kp.pk
}

/// HMAC-SHA256 (RFC 2104), used by the signer to derive per-class cache salts the worker cannot choose.
pub fn hmac_sha256(key: &[u8; 32], parts: &[&[u8]]) -> [u8; 32] {
    let mut ipad = [0x36u8; 64];
    let mut opad = [0x5cu8; 64];
    for (i, k) in key.iter().enumerate() {
        if let (Some(a), Some(b)) = (ipad.get_mut(i), opad.get_mut(i)) {
            *a ^= k;
            *b ^= k;
        }
    }
    let mut h = Sha256::new();
    h.update(ipad);
    for p in parts {
        h.update(p);
    }
    let inner: [u8; 32] = h.finalize().into();
    sha256(&[&opad, &inner])
}

/// Constant-time equality for secrets-adjacent comparisons (hashes, ids).
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut d = 0u8;
    for (x, y) in a.iter().zip(b) {
        d |= x ^ y;
    }
    d == 0
}
