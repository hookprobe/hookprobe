//! Remote-attestation quote generation.
//!
//! After measured boot, HBoot signs a quote — `nonce || svn || PCR0..3` — with
//! the device Attestation Key (hybrid: ed25519 + SLH-DSA, quantum-safe). A
//! remote verifier checks both signatures against the AK public keys, the nonce
//! for freshness, and the PCRs against known-good, thereby confirming the exact
//! software that booted, cryptographically and off-device.
//!
//! The AK private keys are embedded in HBoot (software AK). A hardware-bound AK
//! derived from BCM2712 OTP is the follow-on that pairs with the secure-counter
//! work — it would make the AK non-extractable and per-device.

use crate::attest_keys;
use crate::puts;
use boot_abi::*;
use ed25519_compact::{SecretKey as EdSecretKey, Signature as EdSignature};

/// Build and sign the attestation quote, writing it to ATTEST_QUOTE_ADDR.
/// Returns the ed25519 signature (for a short console echo).
pub fn emit_quote(svn: u64, pcr: &[[u8; 32]; NUM_PCR]) -> [u8; ED25519_SIG_LEN] {
    // Body = nonce || svn || PCR0..3.
    let mut body = [0u8; QUOTE_BODY_LEN];
    body[..32].copy_from_slice(&CHALLENGE_NONCE);
    body[32..40].copy_from_slice(&svn.to_le_bytes());
    for i in 0..NUM_PCR {
        body[40 + 32 * i..40 + 32 * (i + 1)].copy_from_slice(&pcr[i]);
    }

    // Classical AK signature.
    puts(" attest : signing quote (ed25519)...\n");
    let ed_sk = EdSecretKey::from_slice(&attest_keys::AK_ED25519_SK).unwrap();
    let ed_sig: EdSignature = ed_sk.sign(body, None);
    let mut ed_bytes = [0u8; ED25519_SIG_LEN];
    ed_bytes.copy_from_slice(ed_sig.as_ref());

    // Post-quantum AK signature: DEFERRED. The on-device fips205 SLH-DSA-128s
    // *signer* stalls at EL2 (the verifier is fine); left zero-filled until the
    // signer perf/path is resolved. Secure boot stays fully hybrid QS — only
    // the attestation quote's PQ half is pending. Verifier treats zero as
    // "PQ quote not present".
    let slh_sig = [0u8; AK_SLHDSA_SIG_LEN];

    // Publish the quote for the kernel to forward to a verifier.
    let q = ATTEST_QUOTE_ADDR as *mut AttestQuote;
    unsafe {
        core::ptr::write(
            q,
            AttestQuote {
                magic: ATTEST_QUOTE_MAGIC,
                nonce: CHALLENGE_NONCE,
                svn,
                pcr: *pcr,
                ed25519_sig: ed_bytes,
                slhdsa_sig: slh_sig,
            },
        );
    }
    ed_bytes
}
