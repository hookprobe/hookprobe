//! Runtime attestation service — verifier-supplied per-request freshness (B-2).
//!
//! Measured boot proves WHAT booted, once, at boot time. Audit B-2's gap was
//! that a verifier could never demand a FRESH proof afterwards: the nonce was a
//! compile-time constant, so a captured quote replayed forever. P7d-a made the
//! boot nonce hardware-random per boot; this service closes the rest — it signs
//! a *verifier-supplied* nonce on demand, so every challenge yields a response
//! no earlier capture can satisfy.
//!
//! Two-tier key model (keeps the device AK out of the kernel):
//!   - HBoot mints a per-boot EPHEMERAL ed25519 key (seeded from the hardware
//!     TRNG) and hybrid-signs a certificate `AK_sign(eph_pk||svn||PCRs)`
//!     (ed25519 + SLH-DSA — quantum-safe, binds the key to this device + boot
//!     state), then SCRUBS the AK private key. The AK never persists in RAM.
//!   - The kernel holds ONLY the ephemeral key and signs verifier challenges
//!     with it (ed25519 — fast, small; no SLH-DSA in the kernel). A leaked
//!     ephemeral key compromises only the current boot.
//!
//! A verifier checks: (1) the hybrid cert chains AK→eph_pk and the PCRs match
//! known-good; (2) the response is eph_pk's signature over the nonce IT chose.
//! Freshness follows from the verifier owning the nonce.

use ed25519_compact::{KeyPair, PublicKey, SecretKey, Seed, Signature};

/// Longest challenge message we build on-stack: CHALLENGE_CTX || nonce.
const MSG_MAX: usize = 96;

/// Build the domain-separated message that a challenge response signs:
/// `CHALLENGE_CTX || nonce`. Returns the filled prefix of `out`.
fn challenge_msg<'a>(nonce: &[u8], out: &'a mut [u8; MSG_MAX]) -> &'a [u8] {
    let c = boot_abi::CHALLENGE_CTX;
    let n = core::cmp::min(nonce.len(), MSG_MAX - c.len());
    out[..c.len()].copy_from_slice(c);
    out[c.len()..c.len() + n].copy_from_slice(&nonce[..n]);
    &out[..c.len() + n]
}

/// The kernel's per-boot attestor: holds only the EPHEMERAL ed25519 key.
pub struct Attestor {
    sk: SecretKey,
    pub pk: PublicKey,
}

impl Attestor {
    /// Build from a 32-byte seed (HBoot derives it from the hardware TRNG; on
    /// QEMU a fixed test seed stands in for the HBoot-provided key).
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        let kp = KeyPair::from_seed(Seed::new(*seed));
        Attestor { sk: kp.sk, pk: kp.pk }
    }

    /// Build from the 64-byte ephemeral secret key HBoot handed down.
    pub fn from_sk(sk_bytes: &[u8; 64]) -> Option<Self> {
        let sk = SecretKey::from_slice(sk_bytes).ok()?;
        let pk = sk.public_key();
        Some(Attestor { sk, pk })
    }

    /// Sign a verifier-supplied challenge nonce.
    pub fn respond(&self, nonce: &[u8]) -> Signature {
        let mut buf = [0u8; MSG_MAX];
        let m = challenge_msg(nonce, &mut buf);
        self.sk.sign(m, None)
    }
}

/// The device AK ed25519 PUBLIC key (public — safe to embed). Used for the
/// on-device half of the cert-chain check; the remote verifier additionally
/// checks the SLH-DSA half (quantum-safe). Matches ~/heqk-sign/keys/ak_ed.pk.
pub const AK_ED_PK: [u8; 32] = [
    0x42, 0xa2, 0x00, 0x58, 0x55, 0xd2, 0x93, 0xc6, 0xfe, 0xec, 0x3d, 0xfd, 0xb7, 0xbc, 0xcf, 0x26,
    0x94, 0x9e, 0x0c, 0xd5, 0xa4, 0xdd, 0xe5, 0x7e, 0x56, 0x2f, 0x44, 0x77, 0x67, 0x2e, 0x42, 0xaf,
];

/// Verify the AK's ed25519 signature over the ephemeral-key certificate
/// (`EPH_CERT_CTX || eph_pk || svn || PCRs`) against the device AK public key —
/// the on-device half of the chain (AK certifies this boot's ephemeral key).
/// The verifier checks the SLH-DSA half off-device for the full quantum-safe
/// chain. Returns true iff the ephemeral key is genuinely AK-certified.
pub fn verify_cert_ed(ak_ed_pk: &[u8; 32], e: &boot_abi::AttestEphemeral) -> bool {
    let pk = match PublicKey::from_slice(ak_ed_pk) {
        Ok(p) => p,
        Err(_) => return false,
    };
    let sig = match Signature::from_slice(&e.cert_ed_sig) {
        Ok(s) => s,
        Err(_) => return false,
    };
    // Reconstruct EPH_CERT_CTX || (eph_pk || svn || PCRs).
    let c = boot_abi::EPH_CERT_CTX;
    let clen = c.len();
    let mut msg = [0u8; 32 + boot_abi::EPH_CERT_BODY_LEN];
    msg[..clen].copy_from_slice(c);
    let b = &mut msg[clen..clen + boot_abi::EPH_CERT_BODY_LEN];
    b[..32].copy_from_slice(&e.eph_ed_pk);
    b[32..40].copy_from_slice(&e.svn.to_le_bytes());
    b[40..48].copy_from_slice(&e.device_id.to_le_bytes());
    for i in 0..boot_abi::NUM_PCR {
        b[48 + 32 * i..48 + 32 * (i + 1)].copy_from_slice(&e.pcr[i]);
    }
    pk.verify(&msg[..clen + boot_abi::EPH_CERT_BODY_LEN], &sig).is_ok()
}

/// Verify a challenge response against an ephemeral public key (what a remote
/// verifier does after checking the AK cert chains to `pk`).
pub fn verify_response(pk: &PublicKey, nonce: &[u8], sig: &Signature) -> bool {
    let mut buf = [0u8; MSG_MAX];
    let m = challenge_msg(nonce, &mut buf);
    pk.verify(m, sig).is_ok()
}

/// Demonstrate the runtime freshness mechanism: distinct verifier nonces yield
/// distinct valid responses, and a response to one nonce does NOT satisfy
/// another (replay rejected). Returns true on PASS. `label` seeds the console.
pub fn self_test(att: &Attestor) -> bool {
    // Two DISTINCT nonces, as a remote verifier would send on two requests.
    let n1 = [0x11u8; 32];
    let n2 = [0x22u8; 32];
    let s1 = att.respond(&n1);
    let s2 = att.respond(&n2);

    let ok1 = verify_response(&att.pk, &n1, &s1); // valid answer to n1
    let ok2 = verify_response(&att.pk, &n2, &s2); // valid answer to n2
    let distinct = s1.as_ref() != s2.as_ref(); // fresh nonce -> fresh signature
    let replay_rejected = !verify_response(&att.pk, &n1, &s2); // s2 can't answer n1

    ok1 && ok2 && distinct && replay_rejected
}
