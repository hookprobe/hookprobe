// SPDX-License-Identifier: AGPL-3.0-only
//! Release or debug stub (ADR 0070 D3.3)? The stub carries the trust root of `boot_abi::verify`. If either key is a
//! development key — its SHA-256 is in `os/build/heqk-dev-key-fingerprints.txt`, the block-list
//! `heqk-boot-key-check.sh` enforces on every release build — the stub is a DEBUG build: INFO reports `release=0`
//! and the page refuses it unless "Accept a DEBUG stub" is ticked. Derived from the compiled-in keys themselves, so
//! the flag cannot disagree with what the verifier will accept.

use boot_abi::sha256;
use boot_abi::verify::{TRUSTED_ED25519_PUBKEY, TRUSTED_SLHDSA_PUBKEY};

include!(concat!(env!("OUT_DIR"), "/dev_key_fps.rs"));

/// True when none of `keys` has its fingerprint in `dev_fps`.
pub fn none_listed(keys: &[&[u8]], dev_fps: &[[u8; 32]]) -> bool {
    keys.iter().all(|k| !dev_fps.contains(&sha256::digest(k)))
}

/// The stub's own trust root is a release key pair (neither key on the development block-list).
pub fn trust_root_is_release() -> bool {
    none_listed(&[&TRUSTED_ED25519_PUBKEY, &TRUSTED_SLHDSA_PUBKEY], DEV_KEY_FPS)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_listed_key_makes_a_debug_stub() {
        let fp = sha256::digest(b"some key");
        assert!(!none_listed(&[b"other", b"some key"], &[fp]));
        assert!(none_listed(&[b"other"], &[fp]));
        assert!(!DEV_KEY_FPS.is_empty());
    }

    #[test]
    fn the_registry_is_the_one_heqk_boot_key_check_reads() {
        // The ED25519 dev key the block-list names first (dev keygen 2026-07-21).
        let first = DEV_KEY_FPS[0];
        assert_eq!(first[..4], [0x12, 0xe2, 0x11, 0x16]);
    }
}
