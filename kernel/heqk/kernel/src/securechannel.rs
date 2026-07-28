//! M4.2a — PQC secure-channel crypto PRIMITIVES + Known-Answer Tests (KATs).
//!
//! This module adds the four cryptographic building blocks a hybrid post-quantum
//! secure channel needs, and GATES each with a deterministic KAT. It is
//! **FRAMING-AGNOSTIC on purpose**: the ADR-0002 rustls-hybrid path and the
//! ADR-0004 Noise path need the *identical* KEX + AEAD, so they are brought in
//! ONCE here. The handshake state machine + the rustls-vs-Noise framing decision
//! + the crypto review are **M4.2b**, NOT this phase (docs/design/heqk-control-plane.md
//! §2.3). Nothing here opens a socket or drives smoltcp — these are pure primitives.
//!
//! What lands (all `no_std`, behind the `securechannel` feature, OFF by default so
//! the base kernel TCB pulls in none of it):
//!   1. **ML-KEM-768 (FIPS 203)** — RustCrypto `ml-kem`, the PQ key-encapsulation leg.
//!   2. **X25519 (RFC 7748)** — `x25519-dalek`, the classical ECDH leg.
//!   3. **ChaCha20-Poly1305 (RFC 8439)** — `chacha20poly1305`, the record AEAD
//!      (no AES-NI dependence — correct for a softfloat edge target).
//!   4. **Hybrid KEX combiner** — HKDF-combines the ML-KEM shared secret WITH the
//!      X25519 shared secret into ONE hybrid secret, reusing the EXISTING
//!      `boot_abi::kdf` (the same HKDF the P15 seal layer trusts). This is the
//!      pattern both rustls-hybrid (X25519MLKEM768) and Noise-PQ use.
//!
//! ENTROPY / HONESTY (Track-C, matches the M3.3 VEK entropy note):
//!   * Every KAT here is **DETERMINISTIC** — fixed seeds / fixed scalars / fixed
//!     key+nonce, **no RNG**. That is what makes them QEMU/host-reproducible.
//!   * REAL keygen on a live device draws its `(d, z, m)` / ephemeral scalars from
//!     the **hardware TRNG**, which is **metal (Gate R)** — not exercised here.
//!     In QEMU we use a TEST SEED. A shared secret is only as strong as that
//!     entropy; the deterministic KAT proves the *math*, the TRNG proves the
//!     *secrecy*, and the two are validated in different gates on purpose.

#![cfg(feature = "securechannel")]

use boot_abi::kdf;
use boot_abi::sha256;
use chacha20poly1305::{AeadInPlace, ChaCha20Poly1305, Key, KeyInit, Nonce, Tag};
use kem::Decapsulate;
use ml_kem::array::Array;
use ml_kem::{EncapsulateDeterministic, KemCore, MlKem768, B32};
use x25519_dalek::{x25519, PublicKey, StaticSecret};

/// Local console print (the `kprint!` macro lives in main.rs and isn't exported;
/// every module reaches the early console through the same arch seam).
macro_rules! kprint {
    ($($t:tt)*) => { arch_aarch64::_print(format_args!($($t)*)) };
}

// ===========================================================================
// 1. ML-KEM-768 (FIPS 203) — the post-quantum KEX leg.
// ===========================================================================

/// A ML-KEM-768 encaps/decaps round-trip, run DETERMINISTICALLY from fixed seeds
/// so it is a reproducible Known-Answer Test with no RNG.
///
///   keygen_deterministic(d, z) -> (dk, ek)
///   encaps_deterministic(ek, m) -> (ct, ss_sender)   [what "Alice" sends + holds]
///   decaps(dk, ct)              ->  ss_receiver        [what "Bob" recovers]
///
/// Returns the two shared secrets. FIPS 203 guarantees `ss_sender == ss_receiver`;
/// the caller asserts that (functional KAT) AND pins `ss_sender` to a fixed value
/// (regression/determinism lock — see `MLKEM768_KAT_SS`).
fn mlkem768_roundtrip(d: &[u8; 32], z: &[u8; 32], m: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
    let d: B32 = Array(*d);
    let z: B32 = Array(*z);
    let m: B32 = Array(*m);

    let (dk, ek) = MlKem768::generate_deterministic(&d, &z);
    // Sender: encapsulate a shared secret to `ek`, deterministically from `m`.
    let (ct, ss_sender) = ek
        .encapsulate_deterministic(&m)
        .expect("ml-kem encaps is infallible");
    // Receiver: decapsulate with the matching decapsulation key.
    let ss_receiver = dk.decapsulate(&ct).expect("ml-kem decaps is infallible");

    let mut a = [0u8; 32];
    let mut b = [0u8; 32];
    a.copy_from_slice(ss_sender.as_slice());
    b.copy_from_slice(ss_receiver.as_slice());
    (a, b)
}

/// The three 32-byte seeds for the ML-KEM-768 KAT. Fixed, distinct, domain-labelled
/// (bytes derived from a label hash so they are not all-zero degenerate inputs).
fn mlkem_kat_seeds() -> ([u8; 32], [u8; 32], [u8; 32]) {
    let d = sha256::digest(b"HEQK-M4.2a-MLKEM768-KAT-d");
    let z = sha256::digest(b"HEQK-M4.2a-MLKEM768-KAT-z");
    let m = sha256::digest(b"HEQK-M4.2a-MLKEM768-KAT-m");
    (d, z, m)
}

/// Pinned expected ML-KEM-768 shared secret for `mlkem_kat_seeds()`.
///
/// PROVENANCE (honest): this is a DETERMINISTIC self-consistent vector — the seeds
/// are fixed above and this is the shared secret the RustCrypto `ml-kem` 0.2.3
/// implementation (itself validated upstream against NIST ACVP) produces for them.
/// It is a determinism/regression LOCK, not a transcribed NIST .rsp line: any change
/// to the crate, the seeds, or the math changes this value and fails the gate. It is
/// cross-checkable against any FIPS-203 reference by feeding the same (d, z, m).
const MLKEM768_KAT_SS: [u8; 32] = [
    0xec, 0x16, 0x1c, 0xc8, 0xe0, 0x3e, 0x8e, 0x6d, 0xea, 0xef, 0x91, 0x69, 0x7b, 0x00, 0xb8, 0x6e,
    0xa1, 0x22, 0x14, 0x31, 0x19, 0x66, 0xf1, 0x7f, 0x00, 0x51, 0x93, 0x98, 0xf8, 0x26, 0x32, 0xe3,
];

// ===========================================================================
// 2. X25519 (RFC 7748) — the classical KEX leg.
// ===========================================================================

/// RFC 7748 §5.2 X25519 Known-Answer Test (the single-computation vector).
/// input scalar and u-coordinate -> expected output. This exercises the bare
/// `x25519()` function (which clamps the scalar exactly as the RFC vector expects).
const X25519_RFC7748_SCALAR: [u8; 32] = [
    0xa5, 0x46, 0xe3, 0x6b, 0xf0, 0x52, 0x7c, 0x9d, 0x3b, 0x16, 0x15, 0x4b, 0x82, 0x46, 0x5e, 0xdd,
    0x62, 0x14, 0x4c, 0x0a, 0xc1, 0xfc, 0x5a, 0x18, 0x50, 0x6a, 0x22, 0x44, 0xba, 0x44, 0x9a, 0xc4,
];
const X25519_RFC7748_U: [u8; 32] = [
    0xe6, 0xdb, 0x68, 0x67, 0x58, 0x30, 0x30, 0xdb, 0x35, 0x94, 0xc1, 0xa4, 0x24, 0xb1, 0x5f, 0x7c,
    0x72, 0x66, 0x24, 0xec, 0x26, 0xb3, 0x35, 0x3b, 0x10, 0xa9, 0x03, 0xa6, 0xd0, 0xab, 0x1c, 0x4c,
];
const X25519_RFC7748_OUT: [u8; 32] = [
    0xc3, 0xda, 0x55, 0x37, 0x9d, 0xe9, 0xc6, 0x90, 0x8e, 0x94, 0xea, 0x4d, 0xf2, 0x8d, 0x08, 0x4f,
    0x32, 0xec, 0xcf, 0x03, 0x49, 0x1c, 0x71, 0xf7, 0x54, 0xb4, 0x07, 0x55, 0x77, 0xa2, 0x85, 0x52,
];

// ===========================================================================
// 3. ChaCha20-Poly1305 (RFC 8439) — the record-protection AEAD.
// ===========================================================================

/// RFC 8439 §2.8.2 AEAD Known-Answer Test.
const CHACHA_KEY: [u8; 32] = [
    0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f,
    0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f,
];
const CHACHA_NONCE: [u8; 12] = [
    0x07, 0x00, 0x00, 0x00, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
];
const CHACHA_AAD: [u8; 12] = [
    0x50, 0x51, 0x52, 0x53, 0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7,
];
const CHACHA_PLAINTEXT: &[u8] =
    b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
const CHACHA_CIPHERTEXT: [u8; 114] = [
    0xd3, 0x1a, 0x8d, 0x34, 0x64, 0x8e, 0x60, 0xdb, 0x7b, 0x86, 0xaf, 0xbc, 0x53, 0xef, 0x7e, 0xc2,
    0xa4, 0xad, 0xed, 0x51, 0x29, 0x6e, 0x08, 0xfe, 0xa9, 0xe2, 0xb5, 0xa7, 0x36, 0xee, 0x62, 0xd6,
    0x3d, 0xbe, 0xa4, 0x5e, 0x8c, 0xa9, 0x67, 0x12, 0x82, 0xfa, 0xfb, 0x69, 0xda, 0x92, 0x72, 0x8b,
    0x1a, 0x71, 0xde, 0x0a, 0x9e, 0x06, 0x0b, 0x29, 0x05, 0xd6, 0xa5, 0xb6, 0x7e, 0xcd, 0x3b, 0x36,
    0x92, 0xdd, 0xbd, 0x7f, 0x2d, 0x77, 0x8b, 0x8c, 0x98, 0x03, 0xae, 0xe3, 0x28, 0x09, 0x1b, 0x58,
    0xfa, 0xb3, 0x24, 0xe4, 0xfa, 0xd6, 0x75, 0x94, 0x55, 0x85, 0x80, 0x8b, 0x48, 0x31, 0xd7, 0xbc,
    0x3f, 0xf4, 0xde, 0xf0, 0x8e, 0x4b, 0x7a, 0x9d, 0xe5, 0x76, 0xd2, 0x65, 0x86, 0xce, 0xc6, 0x4b,
    0x61, 0x16,
];
const CHACHA_TAG: [u8; 16] = [
    0x1a, 0xe1, 0x0b, 0x59, 0x4f, 0x09, 0xe2, 0x6a, 0x7e, 0x90, 0x2e, 0xcb, 0xd0, 0x60, 0x06, 0x91,
];

/// RFC 8439 KAT: seal the vector plaintext, check ct+tag byte-for-byte, then open
/// it back and check the plaintext round-trips (and that a flipped tag is rejected).
/// Uses the detached in-place AEAD API — no heap, matching the kernel's no-alloc
/// crypto discipline. Returns true on full match.
fn chacha20poly1305_kat() -> bool {
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&CHACHA_KEY));
    let nonce = Nonce::from_slice(&CHACHA_NONCE);

    // ---- encrypt ----
    let mut buf = [0u8; 114];
    buf.copy_from_slice(CHACHA_PLAINTEXT);
    let tag = match cipher.encrypt_in_place_detached(nonce, &CHACHA_AAD, &mut buf) {
        Ok(t) => t,
        Err(_) => return false,
    };
    if !kdf::ct_eq(&buf, &CHACHA_CIPHERTEXT) {
        return false;
    }
    if !kdf::ct_eq(tag.as_slice(), &CHACHA_TAG) {
        return false;
    }

    // ---- decrypt (authenticated) round-trip ----
    let good_tag = Tag::from_slice(&CHACHA_TAG);
    if cipher
        .decrypt_in_place_detached(nonce, &CHACHA_AAD, &mut buf, good_tag)
        .is_err()
    {
        return false;
    }
    if !kdf::ct_eq(&buf, CHACHA_PLAINTEXT) {
        return false;
    }

    // ---- negative: a corrupted tag MUST fail-closed (no plaintext trust) ----
    let mut bad = [0u8; 114];
    bad.copy_from_slice(&CHACHA_CIPHERTEXT);
    let mut bad_tag_bytes = CHACHA_TAG;
    bad_tag_bytes[0] ^= 0x01;
    let bad_tag = Tag::from_slice(&bad_tag_bytes);
    if cipher
        .decrypt_in_place_detached(nonce, &CHACHA_AAD, &mut bad, bad_tag)
        .is_ok()
    {
        return false; // a forged tag was accepted — AEAD is broken
    }
    true
}

// ===========================================================================
// 4. Hybrid KEX combiner — ML-KEM-768 ss  (+)  X25519 ss  ->  one hybrid secret.
// ===========================================================================

/// Domain-separated HKDF combine of the two shared secrets into ONE 32-byte hybrid
/// secret, reusing the EXISTING `boot_abi::kdf` HKDF (the P15 seal layer's HKDF).
///
///   hybrid = HKDF-Expand( HKDF-Extract(salt, ML-KEM-ss || X25519-ss), info )
///
/// Concatenation order (PQ leg first, then classical) is fixed for both parties, so
/// the derivation is consistent by construction. This is the shape rustls-hybrid
/// (X25519MLKEM768) and Noise-PQ both use; the only thing M4.2b changes is which
/// bytes get bound as `info`/transcript, not this combine.
pub fn hybrid_combine(mlkem_ss: &[u8; 32], x25519_ss: &[u8; 32]) -> [u8; 32] {
    let mut ikm = [0u8; 64];
    ikm[..32].copy_from_slice(mlkem_ss);
    ikm[32..].copy_from_slice(x25519_ss);
    let prk = kdf::hkdf_extract(b"HEQK-HYBRID-KEX-v1", &ikm);
    // Scrub the concatenated raw secrets promptly (defense-in-depth).
    for b in ikm.iter_mut() {
        unsafe { core::ptr::write_volatile(b, 0) };
    }
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    kdf::hkdf_expand32(&prk, b"hybrid-secret")
}

/// Two-party consistency proof: Alice and Bob must derive the SAME hybrid secret.
///
/// DETERMINISTIC (no RNG): both the ML-KEM seeds and both X25519 static scalars are
/// fixed. On metal these come from the TRNG (Gate R); here they are test seeds.
///
///   ML-KEM leg — Alice = the encapsulator (holds ss_sender), Bob = the decapsulator
///                (recovers the identical ss); both use the ONE ML-KEM shared secret.
///   X25519 leg — Alice(a)·B == Bob(b)·A == g^{ab}; standard ECDH agreement.
///
/// Returns true iff `combine(mlkem_ss, dh_ab)` computed on Alice's side equals the
/// same computed on Bob's side.
fn hybrid_agreement_kat() -> bool {
    // ---- ML-KEM leg (shared secret is identical on both ends by FIPS 203) ----
    let (d, z, m) = mlkem_kat_seeds();
    let (ss_sender, ss_receiver) = mlkem768_roundtrip(&d, &z, &m);
    if !kdf::ct_eq(&ss_sender, &ss_receiver) {
        return false;
    }

    // ---- X25519 leg (two fixed static secrets -> agreeing DH) ----
    let alice_sk_bytes = sha256::digest(b"HEQK-M4.2a-X25519-alice-static");
    let bob_sk_bytes = sha256::digest(b"HEQK-M4.2a-X25519-bob-static");
    let alice_sk = StaticSecret::from(alice_sk_bytes);
    let bob_sk = StaticSecret::from(bob_sk_bytes);
    let alice_pk = PublicKey::from(&alice_sk);
    let bob_pk = PublicKey::from(&bob_sk);
    let dh_alice = alice_sk.diffie_hellman(&bob_pk).to_bytes(); // a·B
    let dh_bob = bob_sk.diffie_hellman(&alice_pk).to_bytes(); // b·A
    if !kdf::ct_eq(&dh_alice, &dh_bob) {
        return false;
    }

    // ---- combine on each side; the whole point is these MUST match ----
    let hybrid_alice = hybrid_combine(&ss_sender, &dh_alice);
    let hybrid_bob = hybrid_combine(&ss_receiver, &dh_bob);
    kdf::ct_eq(&hybrid_alice, &hybrid_bob)
}

// ===========================================================================
// The [P19-pqc-kat] gate — all four primitives, all DETERMINISTIC.
// ===========================================================================

/// Run every M4.2a KAT and print a per-primitive line. Returns true iff ALL pass.
/// Everything here is deterministic (seeded/fixed) so the result is reproducible in
/// QEMU with no entropy source — the real TRNG-fed keygen is metal (Gate R).
pub fn securechannel_selftest() -> bool {
    let mut all = true;

    // 1. ML-KEM-768: round-trip equality + pinned KAT shared secret.
    let (d, z, m) = mlkem_kat_seeds();
    let (ss_a, ss_b) = mlkem768_roundtrip(&d, &z, &m);
    let mlkem_rt = kdf::ct_eq(&ss_a, &ss_b);
    let mlkem_kat = kdf::ct_eq(&ss_a, &MLKEM768_KAT_SS);
    kprint!(
        "   [1] ML-KEM-768 (FIPS 203): encaps/decaps round-trip {} · pinned-KAT ss {}\n",
        if mlkem_rt { "OK" } else { "MISMATCH" },
        if mlkem_kat { "OK" } else { "MISMATCH" }
    );
    all &= mlkem_rt && mlkem_kat;

    // 2. X25519: RFC 7748 §5.2 single-computation vector.
    let x_out = x25519(X25519_RFC7748_SCALAR, X25519_RFC7748_U);
    let x_ok = kdf::ct_eq(&x_out, &X25519_RFC7748_OUT);
    kprint!(
        "   [2] X25519 (RFC 7748 §5.2): known-answer vector {}\n",
        if x_ok { "OK" } else { "MISMATCH" }
    );
    all &= x_ok;

    // 3. ChaCha20-Poly1305: RFC 8439 §2.8.2 vector + auth round-trip + forgery reject.
    let c_ok = chacha20poly1305_kat();
    kprint!(
        "   [3] ChaCha20-Poly1305 (RFC 8439 §2.8.2): AEAD vector + forgery-reject {}\n",
        if c_ok { "OK" } else { "FAIL" }
    );
    all &= c_ok;

    // 4. Hybrid combiner: Alice and Bob derive the SAME hybrid secret.
    let h_ok = hybrid_agreement_kat();
    kprint!(
        "   [4] Hybrid combiner (HKDF: ML-KEM ss + X25519 ss): Alice==Bob {}\n",
        if h_ok { "OK" } else { "MISMATCH" }
    );
    all &= h_ok;

    all
}
