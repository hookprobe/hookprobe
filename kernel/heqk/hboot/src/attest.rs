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
use boot_abi::*;
use ed25519_compact::{SecretKey as EdSecretKey, Signature as EdSignature};
use fips205::slh_dsa_sha2_128s;
use fips205::traits::{SerDes, Signer};
use rand_core::{CryptoRng, RngCore};

/// Deterministic zero-RNG. Used only with `hedged=false`, where SLH-DSA does
/// not consume randomness — signing stays fully deterministic.
struct ZeroRng;
impl RngCore for ZeroRng {
    fn next_u32(&mut self) -> u32 {
        0
    }
    fn next_u64(&mut self) -> u64 {
        0
    }
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        for b in dest.iter_mut() {
            *b = 0;
        }
    }
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}
impl CryptoRng for ZeroRng {}

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
    let ed_sk = EdSecretKey::from_slice(&attest_keys::AK_ED25519_SK).unwrap();
    let ed_sig: EdSignature = ed_sk.sign(body, None);
    let mut ed_bytes = [0u8; ED25519_SIG_LEN];
    ed_bytes.copy_from_slice(ed_sig.as_ref());

    // Post-quantum AK signature (deterministic; zero-RNG, hedged=false).
    let slh_sk = slh_dsa_sha2_128s::PrivateKey::try_from_bytes(&attest_keys::AK_SLHDSA_SK).unwrap();
    let slh_sig = slh_sk
        .try_sign_with_rng(&mut ZeroRng, &body, AK_SIG_CTX, false)
        .expect("ak slh sign");

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
