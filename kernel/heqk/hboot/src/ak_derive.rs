//! Per-device hardware-bound Attestation Key (B-1 extractability half).
//!
//! Closes the last B-1 gap: the AK is no longer a software constant baked into
//! the world-readable image. Instead HBoot burns a 256-bit secret — generated
//! ON-DEVICE from the hardware TRNG, so it never exists off-device — into
//! customer OTP (block 1) ONCE, then derives the per-device AK (ed25519 +
//! SLH-DSA) from what it reads back. The AK secret now lives only in the
//! device's fuses, not the image; every device is cryptographically unique at
//! the root, and extraction requires code execution on THAT board (not merely
//! the public firmware). Honest limit: OTP is readable by on-device supervisor
//! code (a documented Pi platform property), so this is not HSM-grade secrecy —
//! it closes B-1 as written (not-in-image, per-device), not more.
//!
//! Safety of the irreversible burn: the write is constrained to block 1 (the
//! customer region — it cannot touch the serial/bootloader/device-key rows), is
//! skipped if the region is already provisioned (idempotent), and the AK is
//! ALWAYS derived from the read-back OTP contents (ground truth), never from
//! what we intended to write. If the burn does not take, we fall back to the
//! software AK and touch nothing further.

use crate::attest_keys;
use crate::mailbox;
use crate::puthex;
use crate::puts;
use crate::rng;
use fips205::slh_dsa_sha2_128f;
use fips205::traits::SerDes;
use rand_core::{CryptoRng, RngCore};

/// The Attestation Key HBoot signs with + publishes (per-device or software).
pub struct DerivedAk {
    pub ed_sk: [u8; 64],
    pub ed_pk: [u8; 32],
    pub slh_sk: [u8; 64],
    pub slh_pk: [u8; 32],
    pub hw_bound: bool, // true => derived from OTP (non-extractable from image)
}

impl DerivedAk {
    /// Zero the private key material after signing (defense in depth).
    pub fn zeroize(&mut self) {
        self.ed_sk = [0u8; 64];
        self.slh_sk = [0u8; 64];
        unsafe { core::arch::asm!("dsb sy") };
    }
}

/// Deterministic SHA-256 DRBG: reproduces the same keystream from a 32-byte
/// seed so per-device SLH-DSA keygen yields the same keypair every boot.
struct SeedRng {
    state: [u8; 32],
    ctr: u64,
    buf: [u8; 32],
    have: usize,
}
impl SeedRng {
    fn new(seed: &[u8; 32]) -> Self {
        SeedRng { state: *seed, ctr: 0, buf: [0; 32], have: 0 }
    }
    fn refill(&mut self) {
        let mut inp = [0u8; 40];
        inp[..32].copy_from_slice(&self.state);
        inp[32..40].copy_from_slice(&self.ctr.to_le_bytes());
        self.buf = boot_abi::sha256::digest(&inp);
        self.ctr = self.ctr.wrapping_add(1);
        self.have = 32;
    }
}
impl RngCore for SeedRng {
    fn next_u32(&mut self) -> u32 {
        let mut b = [0u8; 4];
        self.fill_bytes(&mut b);
        u32::from_le_bytes(b)
    }
    fn next_u64(&mut self) -> u64 {
        let mut b = [0u8; 8];
        self.fill_bytes(&mut b);
        u64::from_le_bytes(b)
    }
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        for d in dest.iter_mut() {
            if self.have == 0 {
                self.refill();
            }
            *d = self.buf[32 - self.have];
            self.have -= 1;
        }
    }
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}
impl CryptoRng for SeedRng {}

/// Domain-separated 32-byte derivation from the OTP secret (uniform 256-bit
/// input, so a tagged SHA-256 is a sound KDF here).
fn derive32(tag: &[u8], secret: &[u8; 32]) -> [u8; 32] {
    let mut inp = [0u8; 96];
    let t = core::cmp::min(tag.len(), 64);
    inp[..t].copy_from_slice(&tag[..t]);
    inp[t..t + 32].copy_from_slice(secret);
    boot_abi::sha256::digest(&inp[..t + 32])
}

/// The software AK, wrapped as a DerivedAk fallback (hw_bound = false).
fn software_ak() -> DerivedAk {
    let mut ed_sk = [0u8; 64];
    ed_sk.copy_from_slice(attest_keys::ak_ed_sk());
    let mut slh_sk = [0u8; 64];
    slh_sk.copy_from_slice(attest_keys::ak_slh_sk());
    DerivedAk {
        ed_sk,
        ed_pk: attest_keys::ak_ed_pk(),
        slh_sk,
        slh_pk: attest_keys::AK_SLHDSA_PK,
        hw_bound: false,
    }
}

/// Derive the per-device AK from a 256-bit OTP secret (already read back).
fn derive_from_secret(secret_words: &[u32; 8]) -> DerivedAk {
    let mut secret = [0u8; 32];
    for i in 0..8 {
        secret[i * 4..i * 4 + 4].copy_from_slice(&secret_words[i].to_le_bytes());
    }
    let ed_seed = derive32(b"HEQK-AK-ed25519-v1", &secret);
    let slh_seed = derive32(b"HEQK-AK-slhdsa-v1", &secret);

    // ed25519 keypair from the derived seed.
    let kp = ed25519_compact::KeyPair::from_seed(ed25519_compact::Seed::new(ed_seed));
    let mut ed_sk = [0u8; 64];
    let mut ed_pk = [0u8; 32];
    ed_sk.copy_from_slice(kp.sk.as_ref());
    ed_pk.copy_from_slice(kp.pk.as_ref());

    // Deterministic per-device SLH-DSA-128f keypair (keygen is cheap for 128f).
    let mut drng = SeedRng::new(&slh_seed);
    let (pk, sk) = slh_dsa_sha2_128f::try_keygen_with_rng(&mut drng).expect("per-device slh keygen");
    let slh_sk = sk.into_bytes();
    let slh_pk = pk.into_bytes();

    DerivedAk { ed_sk, ed_pk, slh_sk, slh_pk, hw_bound: true }
}

/// Provision (once) + derive the AK. Reads customer OTP; if blank, burns a
/// TRNG secret (IRREVERSIBLE), reads back, and derives from the actual OTP
/// contents; if already provisioned, derives from the existing secret; if the
/// mailbox/burn does not deliver a secret, falls back to the software AK.
pub fn provision_and_derive() -> DerivedAk {
    let existing = mailbox::get_customer_otp();
    let secret = match existing {
        Some(w) if w.iter().any(|&x| x != 0) => {
            puts(" ak     : customer OTP already provisioned -> deriving per-device AK\n");
            w
        }
        Some(_) => {
            // Blank region -> burn a fresh on-device TRNG secret, ONCE.
            puts(" ak     : customer OTP blank -> burning per-device secret (IRREVERSIBLE)...\n");
            let mut w = [0u32; 8];
            for x in w.iter_mut() {
                let mut b = [0u8; 4];
                let _ = rng::fill(&mut b);
                *x = u32::from_le_bytes(b);
            }
            let reported = mailbox::set_customer_otp(&w);
            // Ground truth: read back and derive from what is ACTUALLY in OTP.
            match mailbox::get_customer_otp() {
                Some(rb) if rb.iter().any(|&x| x != 0) => {
                    puts(if reported {
                        " ak     : OTP burn OK (firmware ack + read-back non-blank)\n"
                    } else {
                        " ak     : OTP read-back non-blank (deriving from actual contents)\n"
                    });
                    rb
                }
                _ => {
                    puts(" ak     : OTP burn did NOT take (still blank) -> software AK fallback\n");
                    return software_ak();
                }
            }
        }
        None => {
            puts(" ak     : customer OTP unreadable (mailbox) -> software AK fallback\n");
            return software_ak();
        }
    };
    let ak = derive_from_secret(&secret);
    puts(" ak     : per-device AK derived (hw-bound). ak_ed_pk=");
    puthex(u32::from_le_bytes([ak.ed_pk[0], ak.ed_pk[1], ak.ed_pk[2], ak.ed_pk[3]]) as u64);
    puts("...\n");
    ak
}
