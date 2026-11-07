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
use crate::puthex;
use crate::puts;
use crate::rng;
use boot_abi::*;
use ed25519_compact::{SecretKey as EdSecretKey, Signature as EdSignature};
use fips205::slh_dsa_sha2_128f;
use fips205::traits::{SerDes, Signer};
use rand_core::{CryptoRng, RngCore};

/// Deterministic zero-RNG (used with hedged=false — not consumed for entropy).
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
pub fn emit_quote(
    svn: u64,
    pcr: &[[u8; 32]; NUM_PCR],
    ak: &crate::ak_derive::DerivedAk,
) -> [u8; ED25519_SIG_LEN] {
    // Fresh per-boot nonce from the BCM2712 hardware TRNG — replaces the
    // compile-time-constant CHALLENGE_NONCE that made quotes replayable (B-2).
    let (nonce, trng_words) = rng::hw_nonce();
    puts(" attest : nonce (hw-trng words=");
    puthex(trng_words as u64);
    puts(", ");
    puthex(u32::from_le_bytes([nonce[0], nonce[1], nonce[2], nonce[3]]) as u64);
    puts("...)\n");

    // Body = nonce || svn || PCR0..3.
    let mut body = [0u8; QUOTE_BODY_LEN];
    body[..32].copy_from_slice(&nonce);
    body[32..40].copy_from_slice(&svn.to_le_bytes());
    for i in 0..NUM_PCR {
        body[40 + 32 * i..40 + 32 * (i + 1)].copy_from_slice(&pcr[i]);
    }

    // Classical AK signature.
    puts(" attest : signing quote (ed25519)...\n");
    let ed_sk = EdSecretKey::from_slice(&ak.ed_sk).unwrap();
    let ed_sig: EdSignature = ed_sk.sign(body, None);
    let mut ed_bytes = [0u8; ED25519_SIG_LEN];
    ed_bytes.copy_from_slice(ed_sig.as_ref());

    // Post-quantum AK signature: SLH-DSA-SHA2-128f (fast-sign, quantum-safe).
    // The 'f' variant signs in seconds even with software SHA-256 on bare metal
    // (128s was minutes). Deterministic: zero-RNG + hedged=false.
    puts(" attest : signing quote (SLH-DSA-128f, quantum-safe)...\n");
    let slh_sk = slh_dsa_sha2_128f::PrivateKey::try_from_bytes(&ak.slh_sk).unwrap();
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
                nonce,
                svn,
                pcr: *pcr,
                ed25519_sig: ed_bytes,
                slhdsa_sig: slh_sig,
            },
        );
    }
    ed_bytes
}

/// B-2 runtime attestation: mint a per-boot EPHEMERAL ed25519 key (seeded from
/// the hardware TRNG), hybrid-sign a certificate binding it to (svn, PCRs) with
/// the device AK, and publish both at ATTEST_EPH_ADDR. The kernel then signs
/// verifier-supplied challenge nonces with the ephemeral key (per-request
/// freshness) while the AK stays in HBoot and is scrubbed after this. Call
/// AFTER `emit_quote` and BEFORE `attest_keys::scrub()`.
pub fn emit_ephemeral_cert(
    svn: u64,
    device_id: u64,
    otp_provisioned: u64,
    pcr: &[[u8; 32]; NUM_PCR],
    ak: &crate::ak_derive::DerivedAk,
) {
    use ed25519_compact::{KeyPair, Seed};

    // Per-boot ephemeral keypair from TRNG entropy (distinct from the AK).
    let mut seed = [0u8; 32];
    let live = rng::fill(&mut seed); // count of LIVE hardware-RNG words (8 = fully live)
    // SEC-7/V9: the ephemeral attestation private key MUST be unpredictable. If the
    // TRNG was not fully live, `seed` is a cntpct-folded (guessable) value — an
    // attacker could precompute this key and answer live challenge nonces, defeating
    // per-request freshness. Fail CLOSED: publish NO runtime-attestation key (zero the
    // handoff so its magic is invalid). Attestation-unavailable is safe; a predictable
    // attestation key is not.
    if live < 8 {
        puts(" attest : TRNG not fully live -> REFUSING to publish ephemeral key (attestation unavailable)\n");
        unsafe {
            core::ptr::write_bytes(
                ATTEST_EPH_ADDR as *mut u8,
                0,
                core::mem::size_of::<AttestEphemeral>(),
            );
        }
        return;
    }
    let kp = KeyPair::from_seed(Seed::new(seed));
    let mut eph_pk = [0u8; 32];
    let mut eph_sk = [0u8; 64];
    eph_pk.copy_from_slice(kp.pk.as_ref());
    eph_sk.copy_from_slice(kp.sk.as_ref());

    // Cert body = eph_pk || svn || device_id || PCR0..3 (the verifier + the
    // kernel reconstruct this exact layout). device_id binds the per-device
    // identity so a cert can't be replayed device-to-device (B-1 anonymity half).
    let mut body = [0u8; EPH_CERT_BODY_LEN];
    body[..32].copy_from_slice(&eph_pk);
    body[32..40].copy_from_slice(&svn.to_le_bytes());
    body[40..48].copy_from_slice(&device_id.to_le_bytes());
    for i in 0..NUM_PCR {
        body[48 + 32 * i..48 + 32 * (i + 1)].copy_from_slice(&pcr[i]);
    }

    // AK ed25519 cert sig over EPH_CERT_CTX || body (domain-separated from the quote).
    puts(" attest : certifying ephemeral key (AK ed25519)...\n");
    let clen = EPH_CERT_CTX.len();
    let mut ed_msg = [0u8; 32 + EPH_CERT_BODY_LEN]; // ctx(15) + body(168) fits
    ed_msg[..clen].copy_from_slice(EPH_CERT_CTX);
    ed_msg[clen..clen + EPH_CERT_BODY_LEN].copy_from_slice(&body);
    let ed_sk = EdSecretKey::from_slice(&ak.ed_sk).unwrap();
    let ed_sig: EdSignature = ed_sk.sign(&ed_msg[..clen + EPH_CERT_BODY_LEN], None);
    let mut cert_ed_sig = [0u8; ED25519_SIG_LEN];
    cert_ed_sig.copy_from_slice(ed_sig.as_ref());

    // AK SLH-DSA cert sig over body with ctx=EPH_CERT_CTX (quantum-safe).
    puts(" attest : certifying ephemeral key (AK SLH-DSA, quantum-safe)...\n");
    let slh_sk = slh_dsa_sha2_128f::PrivateKey::try_from_bytes(&ak.slh_sk).unwrap();
    let cert_slh_sig = slh_sk
        .try_sign_with_rng(&mut ZeroRng, &body, EPH_CERT_CTX, false)
        .expect("eph cert slh sign");

    let e = ATTEST_EPH_ADDR as *mut AttestEphemeral;
    unsafe {
        core::ptr::write(
            e,
            AttestEphemeral {
                magic: ATTEST_EPH_MAGIC,
                eph_ed_pk: eph_pk,
                eph_ed_sk: eph_sk,
                cert_ed_sig,
                cert_slh_sig,
                svn,
                device_id,
                otp_provisioned,
                ak_ed_pk: ak.ed_pk,
                ak_slh_pk: ak.slh_pk,
                ak_hw_bound: u64::from(ak.hw_bound),
                pcr: *pcr,
            },
        );
    }
    puts(" attest : ephemeral key certified + published @ ");
    puthex(ATTEST_EPH_ADDR as u64);
    puts(" (AK then scrubbed)\n");
}
