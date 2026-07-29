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
use ml_kem::{EncapsulateDeterministic, EncodedSizeUser, KemCore, MlKem768, B32};
use x25519_dalek::{x25519, PublicKey, StaticSecret};

// --- M4.2b (Noise handshake) additional imports ---
use boot_abi::kdf::{hmac_sha256, hmac_sha256_2};
use ed25519_compact::{KeyPair, PublicKey as EdPub, Signature as EdSig};

/// Local console print (the `kprint!` macro lives in main.rs and isn't exported;
/// every module reaches the early console through the same arch seam).
macro_rules! kprint {
    ($($t:tt)*) => { arch_aarch64::_print(format_args!($($t)*)) };
}

// ---------------------------------------------------------------------------
// M4.3 #7 — fixed, heap-free wire buffers (auditor tracked condition #2).
//
// The M4.2b handshake originally returned `alloc::Vec` records. On heqk's bump
// allocator (`heap.rs`) there is NO reclaim, so every per-record `Vec` LEAKS a
// slice of a 1 MiB arena — a slow-motion OOM under any real record rate. These
// fixed-capacity stack buffers replace every handshake/transport `Vec`: the
// ChaCha20-Poly1305 core is already detached/in-place, so nothing here needs the
// heap. `Buf<N>` is a tiny bounded push-buffer; the transport hot path uses
// caller-provided `&mut [u8]` (`encrypt_into`/`decrypt_into`) so record size is
// not even capped by a fixed return type. No `alloc` symbol remains in this
// module — the base kernel (no `securechannel`) already linked none.
// ---------------------------------------------------------------------------

/// A bounded, heap-free byte buffer. `push` fails closed (returns false) rather
/// than truncating or panicking if the content would exceed `N`.
pub struct Buf<const N: usize> {
    b: [u8; N],
    n: usize,
}

impl<const N: usize> Buf<N> {
    #[inline]
    pub const fn new() -> Self {
        Buf { b: [0u8; N], n: 0 }
    }
    /// Append `s`; returns false (and appends nothing) if it would overflow.
    #[inline]
    #[must_use]
    fn push(&mut self, s: &[u8]) -> bool {
        let end = match self.n.checked_add(s.len()) {
            Some(e) if e <= N => e,
            _ => return false,
        };
        self.b[self.n..end].copy_from_slice(s);
        self.n = end;
        true
    }
    #[inline]
    pub fn as_slice(&self) -> &[u8] {
        &self.b[..self.n]
    }
    #[inline]
    pub fn len(&self) -> usize {
        self.n
    }
}

/// Largest single handshake message on the wire. msg1 =
/// e_x(32) + e_k_ek(1184) + es-ct(1088) + id(32+16) + sig(64+16) + payload+16;
/// 4096 leaves comfortable headroom for the enrollment payload.
pub const HS_MSG_MAX: usize = 4096;
/// Largest handshake AEAD RECORD plaintext (device id 32, transcript sig 64, and
/// small enrollment request/response payloads). 1024 is ample; a larger payload
/// is refused rather than heap-allocated.
pub const HS_REC_MAX: usize = 1024;

/// A handshake message buffer.
pub type HsMsg = Buf<HS_MSG_MAX>;
/// A handshake AEAD-record buffer (encrypt/decrypt-and-hash plaintext/ciphertext).
pub type HsRec = Buf<HS_REC_MAX>;

/// Volatile-scrub a 32-byte secret (raw ML-KEM / X25519 shared secret) once it
/// has been folded into the chaining key — defense-in-depth in the spirit of
/// auditor condition #3 (full `zeroize`-crate adoption on the dalek types is the
/// deferred metal item; this at least does not leave the raw `ss`/`dh` on the
/// stack after use).
#[inline]
fn scrub32(b: &mut [u8; 32]) {
    for x in b.iter_mut() {
        unsafe { core::ptr::write_volatile(x, 0) };
    }
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
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

// ###########################################################################
// #  M4.2b — the PQ-HYBRID secure-channel HANDSHAKE (Noise, ADR 0004 HTP-v2) #
// ###########################################################################
//
// FRAMING DECISION (Director): Noise, NOT rustls TLS 1.3. The channel is between
// two of OUR endpoints (device <-> control-plane), so there is no TLS-server
// interop requirement; Noise is far smaller and more auditable for no_std, and
// ADR 0004 already chose it ("Noise-style authenticated DH, e.g. an IK/XX
// equivalent ... hybrid X25519 + ML-KEM-768 ... mutual PUF-anchored Ed25519").
//
// ---------------------------------------------------------------------------
// STANDARD constructions this implements (NO bespoke crypto invented):
//   * Noise Protocol Framework, revision 34 (Trevor Perrin) — the SymmetricState
//     (MixHash / MixKey / EncryptAndHash / Split) and CipherState machinery are
//     implemented EXACTLY per spec §5 (SymmetricState), §4.3 (the Noise HKDF), and
//     §12.3 (the ChaChaPoly nonce = 4 zero bytes || LE64(n)).
//   * KEM-in-Noise follows "Post-Quantum Noise" (Angel/Dowling/Hülsing/Rösler,
//     IACR ePrint 2022/539) — a KEM `encapsulate` replaces a DH, its ciphertext is
//     put on the wire and MixHash'd, and its shared secret is MixKey'd.
//   * Hybrid (classical+PQ) KEX follows the hybrid-KEM Noise approach (Kampanakis
//     et al., "Practical Hybrid PQ Key Exchange for Noise"): each key-agreement
//     step contributes BOTH an X25519 DH AND an ML-KEM-768 encapsulation; the two
//     shared secrets are folded together with `hybrid_combine` (the M4.2a KAT'd
//     HKDF combiner) before the single MixKey — so the chaining key is safe if
//     EITHER primitive holds.
//   * Device authentication is a transcript SIGNATURE (the Noise "Signatures"
//     extension shape): the device signs the handshake hash `h` with its
//     PUF-anchored Ed25519 identity (the same key model as `attest_svc.rs`), and
//     the responder verifies against the enrolled device public key. Ed25519 is a
//     signature, not a DH, so it cannot be a Noise `ss`/`se` token; signing `h`
//     is the standard way to bind a signature identity to a Noise transcript.
//     (ADR 0002/0004's ML-DSA-65 co-signature is the roadmap PQ auth leg — the
//     kernel has Ed25519 + SLH-DSA today, not ML-DSA; flagged for M4.2b review.)
//
// PATTERN IMPLEMENTED  (`Noise_HTP2hybrid_25519+MLKEM768_ChaChaPoly_SHA256`,
// an IK-analog: the Initiator is the DEVICE, the Responder is the control plane
// whose static keys the device Knows from enrollment):
//
//     <- s                         (pre-message: responder static X25519 + ML-KEM ek)
//     ...
//     -> e, es, s, sig             (msg1: device ephemerals; hybrid es to resp static;
//                                    device Ed25519 identity + transcript signature)
//     <- e, ee                     (msg2: responder ephemeral; hybrid ee for FS)
//
// where every `es`/`ee` is the HYBRID pair {X25519 DH, ML-KEM-768 encapsulation}
// combined via `hybrid_combine`. `es` uses the responder STATIC key (authenticates
// the responder — only the enrolled responder can derive it); `ee` uses BOTH
// parties' EPHEMERAL keys (forward secrecy). Split() yields two independent
// CipherStates: {initiator->responder} and {responder->initiator}.
//
// SECURITY PROPERTIES (proved by the [P19-noise] KATs below, loopback in QEMU):
//   * Mutual auth  — responder proven by `es` (wrong/unenrolled responder static
//     key => the device's transport key diverges => msg2 AEAD fails => ABORT);
//     device proven by the Ed25519 transcript signature over `h` (unenrolled or
//     forged device => responder ABORTS at msg1).
//   * Forward secrecy — the transport key depends on `ee`, keyed by fresh per-
//     session ephemerals; two sessions with identical statics but different
//     ephemerals derive DIFFERENT transport keys.
//   * Hybrid — each MixKey folds ML-KEM ss AND X25519 ss; the key changes if
//     either leg changes (`hybrid_either_leg_binds`), so it is secure if either
//     primitive holds.
//   * Nonce discipline — Noise CipherState: a 64-bit counter per key, RESET to 0
//     by every MixKey (fresh key) and strictly incremented per AEAD op; send and
//     recv are SEPARATE CipherStates with independent counters. No (key, nonce)
//     pair is ever reused.
//   * Replay/tamper — a replayed transport record hits the receiver at the wrong
//     counter => AEAD fails => rejected; any tampered handshake/transport byte =>
//     AEAD auth fails => ABORT.
//
// HONESTY (Track-C): this is LOOPBACK-proven in QEMU (both parties in-process),
// with DETERMINISTIC SEEDED ephemerals so the KAT is reproducible. The real
// hardware-TRNG ephemerals + the software-PUF-regenerated device identity + the
// responder PKI are METAL (Gate R). Carrying this over the M4.1 smoltcp stack as
// a real network transport (incl. an anti-replay WINDOW for reordering) is M4.3.
// Do NOT read anything below as network- or metal-proven.

/// ML-KEM-768 wire sizes (FIPS 203): encapsulation key, ciphertext (shared secret
/// is 32). Fixed so the parser can slice the wire deterministically.
const MLKEM_EK_LEN: usize = 1184;
const MLKEM_CT_LEN: usize = 1088;
const X_PUB_LEN: usize = 32;
const ED_PUB_LEN: usize = 32;
const ED_SIG_LEN: usize = 64;
const AEAD_TAG_LEN: usize = 16;

/// Noise protocol name -> the initial `h`/`ck`. `IK`-analog, hybrid suite.
const PROTOCOL_NAME: &[u8] = b"Noise_HTP2hybrid_25519+MLKEM768_ChaChaPoly_SHA256";
/// Prologue: domain-separation context both peers MUST agree on (enrollment/tenant
/// binding would live here on metal; fixed + non-empty for the KAT).
const PROLOGUE: &[u8] = b"HTP2-hybrid-v1";

type MlEk = <MlKem768 as KemCore>::EncapsulationKey;
type MlDk = <MlKem768 as KemCore>::DecapsulationKey;

/// Handshake abort reasons — distinct so a test asserts the EXACT failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NoiseErr {
    /// A wire message was shorter than the pattern requires.
    Truncated,
    /// A public key / ciphertext failed to decode.
    BadKeyMaterial,
    /// An AEAD tag failed — tampered bytes, or a diverged key (e.g. wrong
    /// responder static key). Fail-closed: no plaintext is trusted.
    AeadAuth,
    /// The device's Ed25519 identity is not the enrolled one.
    UnenrolledIdentity,
    /// The device's Ed25519 transcript signature did not verify.
    BadSignature,
    /// M4.4 #9 — a record authenticated but its sequence number was an exact replay
    /// or fell below the RFC 6479 anti-replay window (a genuine-but-stale record).
    Replay,
}

// ---------------------------------------------------------------------------
// Noise CipherState — one direction, one key, one strictly-monotonic counter.
// ---------------------------------------------------------------------------

/// A transport CipherState (Noise §5.1): AEAD under `k` with a per-message nonce
/// derived from the counter `n`. Encrypt and decrypt each ADVANCE `n`; the counter
/// is NEVER rewound, so no (k, nonce) pair repeats.
#[derive(Clone)]
pub struct CipherState {
    k: [u8; 32],
    n: u64,
}

impl CipherState {
    /// Noise §12.3 nonce for ChaChaPoly: 4 zero bytes followed by the 64-bit
    /// counter in little-endian. (This exact layout is load-bearing — a different
    /// encoding silently breaks interop AND the nonce-uniqueness argument.)
    fn nonce_bytes(n: u64) -> [u8; 12] {
        let mut nb = [0u8; 12];
        nb[4..].copy_from_slice(&n.to_le_bytes());
        nb
    }

    /// AEAD-encrypt `pt` (associated data `ad`) IN PLACE into `out`, writing
    /// `ciphertext || tag` and returning its length. Heap-free (auditor #2): the
    /// caller owns `out` (a stack/embedded buffer), so no per-record arena leak.
    /// Advances the counter. Fails closed (returns `None`) if `out` cannot hold
    /// `pt.len() + AEAD_TAG_LEN`. The counter is NOT advanced on a capacity miss.
    pub fn encrypt_into(&mut self, ad: &[u8], pt: &[u8], out: &mut [u8]) -> Option<usize> {
        let total = pt.len().checked_add(AEAD_TAG_LEN)?;
        if out.len() < total {
            return None;
        }
        out[..pt.len()].copy_from_slice(pt);
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&self.k));
        let nb = Self::nonce_bytes(self.n);
        let tag = cipher
            .encrypt_in_place_detached(Nonce::from_slice(&nb), ad, &mut out[..pt.len()])
            .expect("chacha20poly1305 encrypt is infallible for valid key/nonce");
        out[pt.len()..total].copy_from_slice(tag.as_slice());
        self.n = self.n.wrapping_add(1);
        Some(total)
    }

    /// AEAD-decrypt `ciphertext || tag` (associated data `ad`) IN PLACE into
    /// `out`, returning the plaintext length. `out` must hold at least
    /// `ct_tag.len() - AEAD_TAG_LEN` bytes. Advances the counter ONLY on success.
    /// A wrong counter (replay), tampered bytes, or a diverged key all surface as
    /// `AeadAuth` with no plaintext revealed (`out` is left with undecrypted
    /// bytes, never trusted). Heap-free.
    pub fn decrypt_into(&mut self, ad: &[u8], ct_tag: &[u8], out: &mut [u8]) -> Result<usize, NoiseErr> {
        if ct_tag.len() < AEAD_TAG_LEN {
            return Err(NoiseErr::Truncated);
        }
        let (ct, tag) = ct_tag.split_at(ct_tag.len() - AEAD_TAG_LEN);
        if out.len() < ct.len() {
            return Err(NoiseErr::Truncated);
        }
        out[..ct.len()].copy_from_slice(ct);
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&self.k));
        let nb = Self::nonce_bytes(self.n);
        cipher
            .decrypt_in_place_detached(
                Nonce::from_slice(&nb),
                ad,
                &mut out[..ct.len()],
                Tag::from_slice(tag),
            )
            .map_err(|_| NoiseErr::AeadAuth)?;
        self.n = self.n.wrapping_add(1);
        Ok(ct.len())
    }

    /// Accessor so the [P19-noise]/[P19-enroll] gates can assert send.k ==
    /// peer.recv.k. The transport key NEVER leaves the CipherState in production;
    /// feature-gated behind `securechannel-selftest` (auditor #4) so it cannot be
    /// called from the metal profile.
    #[cfg(feature = "securechannel-selftest")]
    pub fn key_for_test(&self) -> [u8; 32] {
        self.k
    }

    /// M4.4 — the current nonce counter (the sequence number the NEXT record this
    /// CipherState encrypts will use). This is NOT secret — it is exactly what
    /// travels on the wire as a record's sequence — so a network sender can label
    /// each record with its `seq` for the anti-replay RECEIVER below. Distinct from
    /// `key_for_test` (which exposes the key and stays selftest-gated).
    #[inline]
    pub fn counter(&self) -> u64 {
        self.n
    }

    /// M4.4 #9 — build an anti-replay RECEIVER from this cipher's key, for a real
    /// (reordering) network transport. Does NOT expose the key: `AntiReplayRx` keeps
    /// `k` private and only ever uses it for AEAD-open. Use this in place of the
    /// strict in-order `decrypt_into` when records can arrive out of order.
    #[inline]
    pub fn into_anti_replay(&self) -> AntiReplayRx {
        AntiReplayRx {
            k: self.k,
            win: ReplayWindow::new(),
        }
    }
}

// ---------------------------------------------------------------------------
// M4.4 #9 — anti-replay sliding window (RFC 6479 + RFC 4303 §3.4.3).
//
// The in-order `CipherState::decrypt_into` above rejects a replay only IMPLICITLY:
// its counter has advanced, so a replayed record decrypts at the wrong nonce and
// the AEAD tag fails. That is correct ONLY for a strictly in-order transport. A
// REAL network reorders records, so the receiver must (a) ACCEPT an in-window
// out-of-order record and (b) still REJECT an exact replay and a below-window
// record. RFC 6479 ("IPsec Anti-Replay Algorithm without Bit Shifting") gives a
// redundant sliding bitmap that needs no per-packet shifting — the same
// construction WireGuard uses. ORDER (RFC 4303 §3.4.3, LOAD-BEARING): the window is
// advanced ONLY AFTER the AEAD integrity check on that sequence SUCCEEDS, so a
// forged record can never push the window forward and shadow a genuine one.
// ---------------------------------------------------------------------------

/// Redundant-bitmap replay window (RFC 6479). `BITS_TOTAL` is the whole bitmap; the
/// usable reorder window is `BITS_TOTAL - BITS_PER_WORD` (the top word is the RFC's
/// redundant word that absorbs the no-shift trick). Power-of-two word count so the
/// ring index is a mask, never a modulo.
pub struct ReplayWindow {
    bitmap: [u64; ReplayWindow::WORDS],
    last: u64, // highest INTERNAL (1-based) counter accepted; 0 = none yet
}

impl ReplayWindow {
    const BITS_PER_WORD: u64 = 64;
    const WORD_SHIFT: u64 = 6; // log2(64)
    const BITS_TOTAL: u64 = 512; // -> 8 words (power of two)
    const WORDS: usize = (Self::BITS_TOTAL / Self::BITS_PER_WORD) as usize; // 8
    const WINDOW: u64 = Self::BITS_TOTAL - Self::BITS_PER_WORD; // 448 reorder depth
    const WORD_MASK: u64 = (Self::WORDS as u64) - 1; // 7
    const BIT_MASK: u64 = Self::BITS_PER_WORD - 1; // 63

    pub const fn new() -> Self {
        ReplayWindow {
            bitmap: [0u64; Self::WORDS],
            last: 0,
        }
    }

    /// Validate + record sequence `seq` (a record's 64-bit nonce counter). Returns
    /// true iff `seq` is FRESH (strictly in-order OR an in-window reorder not seen
    /// before); false for an exact REPLAY or a BELOW-WINDOW sequence. Mirrors RFC
    /// 6479 / WireGuard `counter_validate`: the external `seq` is shifted +1 so that
    /// `seq == 0` (the first Noise record's nonce) maps to internal counter 1 and is
    /// accepted against the initial `last == 0`. CALL ONLY AFTER the AEAD tag verified.
    pub fn validate(&mut self, seq: u64) -> bool {
        let cur = match seq.checked_add(1) {
            Some(c) => c, // internal 1-based counter
            None => return false, // 2^64-1 records — refuse the wrap
        };
        if cur > self.last {
            // New high-water mark. Clear the bitmap words we skip over (bounded by
            // WORDS — a big jump wipes the whole window, never over-runs it).
            let idx = cur >> Self::WORD_SHIFT;
            let prev = self.last >> Self::WORD_SHIFT;
            let span = core::cmp::min(idx - prev, Self::WORDS as u64);
            let mut i = 1u64;
            while i <= span {
                self.bitmap[((prev + i) & Self::WORD_MASK) as usize] = 0;
                i += 1;
            }
            self.last = cur;
            let w = (idx & Self::WORD_MASK) as usize;
            self.bitmap[w] |= 1u64 << (cur & Self::BIT_MASK);
            true
        } else {
            // seq <= last: an in-window reorder, or a below-window/replay.
            if self.last - cur >= Self::WINDOW {
                return false; // below the window -> stale -> refuse
            }
            let w = ((cur >> Self::WORD_SHIFT) & Self::WORD_MASK) as usize;
            let bit = 1u64 << (cur & Self::BIT_MASK);
            if self.bitmap[w] & bit != 0 {
                return false; // this exact sequence was already accepted -> replay
            }
            self.bitmap[w] |= bit;
            true // in-window reorder, first time seen -> accept
        }
    }
}

/// A transport RECEIVER with an RFC 6479 anti-replay window. Unlike `CipherState`
/// (strict in-order), it consumes the record's sequence number FROM THE WIRE, so it
/// tolerates reordering while still rejecting replays + below-window records. It
/// shares the exact AEAD construction with `CipherState` (Noise §12.3 nonce = 4 zero
/// bytes || LE64(seq)); the window is the only addition. `k` is private and never
/// leaves the receiver.
pub struct AntiReplayRx {
    k: [u8; 32],
    win: ReplayWindow,
}

impl AntiReplayRx {
    /// AEAD-decrypt `ct_tag` at sequence `seq` (associated data `ad`) into `out`,
    /// then admit it through the anti-replay window. Returns the plaintext length.
    /// Fail-closed:
    ///   * a tampered / wrong-key record -> `AeadAuth`, and the window is LEFT
    ///     UNTOUCHED (a forgery can never advance the window or burn a slot);
    ///   * a record that authenticates but is a below-window or exact replay ->
    ///     `Replay`.
    pub fn open(
        &mut self,
        seq: u64,
        ad: &[u8],
        ct_tag: &[u8],
        out: &mut [u8],
    ) -> Result<usize, NoiseErr> {
        if ct_tag.len() < AEAD_TAG_LEN {
            return Err(NoiseErr::Truncated);
        }
        let (ct, tag) = ct_tag.split_at(ct_tag.len() - AEAD_TAG_LEN);
        if out.len() < ct.len() {
            return Err(NoiseErr::Truncated);
        }
        out[..ct.len()].copy_from_slice(ct);
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&self.k));
        let nb = CipherState::nonce_bytes(seq);
        cipher
            .decrypt_in_place_detached(
                Nonce::from_slice(&nb),
                ad,
                &mut out[..ct.len()],
                Tag::from_slice(tag),
            )
            .map_err(|_| NoiseErr::AeadAuth)?;
        // AEAD verified -> ONLY NOW consult + advance the window (RFC 4303 §3.4.3).
        if !self.win.validate(seq) {
            return Err(NoiseErr::Replay);
        }
        Ok(ct.len())
    }
}

// ---------------------------------------------------------------------------
// Noise SymmetricState — the transcript hash `h`, chaining key `ck`, and the
// handshake-phase AEAD key. Implemented exactly per Noise rev-34 §5.2.
// ---------------------------------------------------------------------------

struct SymmetricState {
    ck: [u8; 32],
    h: [u8; 32],
    /// Handshake AEAD key, `None` until the first MixKey (Noise "empty key").
    k: Option<[u8; 32]>,
    n: u64,
}

/// The Noise one-way KDF (rev-34 §4.3) over HMAC-SHA256, reusing boot_abi HMAC:
///   temp = HMAC(ck, ikm)              [= HKDF-Extract]
///   o1   = HMAC(temp, 0x01)
///   o2   = HMAC(temp, o1 || 0x02)
/// Returns (o1, o2); Noise uses o1 as the new chaining key and o2 as the key.
fn noise_hkdf2(ck: &[u8; 32], ikm: &[u8]) -> ([u8; 32], [u8; 32]) {
    let temp = hmac_sha256(ck, ikm);
    let o1 = hmac_sha256(&temp, &[0x01]);
    let o2 = hmac_sha256_2(&temp, &o1, &[0x02]);
    (o1, o2)
}

impl SymmetricState {
    /// InitializeSymmetric(protocol_name): `h` = name (padded to 32 if it fits,
    /// else its SHA-256); `ck` = `h`; no key yet.
    fn new(protocol_name: &[u8]) -> Self {
        let mut h = [0u8; 32];
        if protocol_name.len() <= 32 {
            h[..protocol_name.len()].copy_from_slice(protocol_name);
        } else {
            h = sha256::digest(protocol_name);
        }
        SymmetricState {
            ck: h,
            h,
            k: None,
            n: 0,
        }
    }

    /// MixHash(data): `h = SHA-256(h || data)`.
    fn mix_hash(&mut self, data: &[u8]) {
        let mut hh = boot_abi::sha256::Hasher::new();
        hh.update(&self.h);
        hh.update(data);
        self.h = hh.finish();
    }

    /// MixKey(ikm): fold a new shared secret into `ck`, derive a fresh handshake
    /// key, and RESET the nonce counter to 0 (the nonce-safety invariant).
    fn mix_key(&mut self, ikm: &[u8]) {
        let (ck, temp_k) = noise_hkdf2(&self.ck, ikm);
        self.ck = ck;
        self.k = Some(temp_k);
        self.n = 0;
    }

    /// EncryptAndHash(pt): AEAD-seal under (k, n) with `h` as associated data (so
    /// the whole transcript authenticates the ciphertext), then MixHash the
    /// ciphertext. With no key set, returns the plaintext (Noise semantics).
    /// Heap-free: the record is built in a fixed `HsRec` (auditor #2). Returns
    /// `None` if the record would exceed `HS_REC_MAX` (fail-closed, never truncate).
    fn encrypt_and_hash(&mut self, pt: &[u8]) -> Option<HsRec> {
        let mut rec = HsRec::new();
        match self.k {
            Some(k) => {
                if !rec.push(pt) {
                    return None;
                }
                let cipher = ChaCha20Poly1305::new(Key::from_slice(&k));
                let nb = CipherState::nonce_bytes(self.n);
                let ptlen = rec.n;
                let tag = cipher
                    .encrypt_in_place_detached(Nonce::from_slice(&nb), &self.h, &mut rec.b[..ptlen])
                    .expect("handshake AEAD encrypt infallible");
                if !rec.push(tag.as_slice()) {
                    return None;
                }
                self.n = self.n.wrapping_add(1);
            }
            None => {
                if !rec.push(pt) {
                    return None;
                }
            }
        }
        self.mix_hash(rec.as_slice());
        Some(rec)
    }

    /// DecryptAndHash(ct): the inverse. MixHash uses the CIPHERTEXT (as on the
    /// sender), so `h` stays in lock-step even though it is authenticated per-op.
    /// Heap-free: plaintext is recovered in place in a fixed `HsRec`.
    fn decrypt_and_hash(&mut self, ct: &[u8]) -> Result<HsRec, NoiseErr> {
        let mut out = HsRec::new();
        match self.k {
            Some(k) => {
                if ct.len() < AEAD_TAG_LEN {
                    return Err(NoiseErr::Truncated);
                }
                let (body, tag) = ct.split_at(ct.len() - AEAD_TAG_LEN);
                if !out.push(body) {
                    return Err(NoiseErr::Truncated);
                }
                let cipher = ChaCha20Poly1305::new(Key::from_slice(&k));
                let nb = CipherState::nonce_bytes(self.n);
                let blen = out.n;
                cipher
                    .decrypt_in_place_detached(
                        Nonce::from_slice(&nb),
                        &self.h,
                        &mut out.b[..blen],
                        Tag::from_slice(tag),
                    )
                    .map_err(|_| NoiseErr::AeadAuth)?;
                self.n = self.n.wrapping_add(1);
            }
            None => {
                if !out.push(ct) {
                    return Err(NoiseErr::Truncated);
                }
            }
        }
        self.mix_hash(ct);
        Ok(out)
    }

    /// Split(): derive the two transport CipherStates (Noise §5.2). First is
    /// initiator->responder, second responder->initiator.
    fn split(&self) -> (CipherState, CipherState) {
        let (t1, t2) = noise_hkdf2(&self.ck, &[]);
        (
            CipherState { k: t1, n: 0 },
            CipherState { k: t2, n: 0 },
        )
    }
}

// ---------------------------------------------------------------------------
// Long-term / static key material.
// ---------------------------------------------------------------------------

/// The control plane's static identity, held by the responder. From enrollment the
/// device knows the PUBLIC halves (`ResponderPub`). Authenticating `es` against
/// these is what proves the responder is the enrolled one.
///
/// M4.4 #3 (defense-in-depth): the ONLY constructor (`from_seeds`) is now gated
/// behind `securechannel-selftest`, so on the metal profile a `ResponderStatic`
/// CANNOT be built — the device is always the INITIATOR and never holds a responder
/// static. The type + the responder read/write functions still compile (they are the
/// loopback test's control-plane peer, and the shape a future off-device control
/// plane would use), but the seeded-static path is out of the device binary.
#[cfg_attr(not(feature = "securechannel-selftest"), allow(dead_code))]
pub struct ResponderStatic {
    x_sk: StaticSecret,
    x_pk: [u8; 32],
    k_dk: MlDk,
    k_ek_bytes: [u8; MLKEM_EK_LEN],
}

/// What the device holds about the responder (the enrolled public static key).
#[derive(Clone)]
pub struct ResponderPub {
    x_pk: [u8; 32],
    k_ek_bytes: [u8; MLKEM_EK_LEN], // ML-KEM-768 encapsulation key (1184 bytes)
}

impl ResponderPub {
    /// The responder's static X25519 public key (bound into an `Enrollment`).
    #[inline]
    pub fn x_pk(&self) -> [u8; 32] {
        self.x_pk
    }
}

impl ResponderStatic {
    /// Derive the responder static keypair deterministically from seeds (TRNG on
    /// metal, Gate R). `x_seed` -> X25519 static; `(d,z)` -> ML-KEM static.
    /// These are the MSSP's long-term PROVISIONED keys (the device knows the public
    /// halves from enrollment bootstrap), NOT per-session entropy.
    ///
    /// M4.4 #3: SELFTEST-ONLY. A metal device is always the initiator and never
    /// constructs a responder static, so this seeded path is compiled OUT of the
    /// device binary (a `compile_error!` already refuses `securechannel-selftest`
    /// together with `cm5`, so it can never reach metal).
    #[cfg(feature = "securechannel-selftest")]
    pub fn from_seeds(x_seed: &[u8; 32], d: &[u8; 32], z: &[u8; 32]) -> Self {
        let x_sk = StaticSecret::from(*x_seed);
        let x_pk = PublicKey::from(&x_sk).to_bytes();
        let (k_dk, k_ek) = MlKem768::generate_deterministic(&Array(*d), &Array(*z));
        let mut k_ek_bytes = [0u8; MLKEM_EK_LEN];
        k_ek_bytes.copy_from_slice(k_ek.as_bytes().as_slice());
        ResponderStatic {
            x_sk,
            x_pk,
            k_dk,
            k_ek_bytes,
        }
    }
    pub fn public(&self) -> ResponderPub {
        ResponderPub {
            x_pk: self.x_pk,
            k_ek_bytes: self.k_ek_bytes,
        }
    }
}

/// Per-session ephemeral randomness for the INITIATOR (device).
///
/// M4.3 #6: the fields are PRIVATE and the ONLY production constructor is
/// `from_entropy`, which draws from a fail-closed `EntropySource`. There is no
/// public seeded constructor outside `securechannel-selftest`, so on the metal
/// profile the ONLY way to obtain this is fresh hardware-TRNG output — a seeded
/// path is not just unused, it does not compile (see `entropy.rs`).
pub struct InitiatorRandomness {
    e_x_seed: [u8; 32], // ephemeral X25519
    e_k_d: [u8; 32],    // ephemeral ML-KEM keygen d
    e_k_z: [u8; 32],    // ephemeral ML-KEM keygen z
    m_es: [u8; 32],     // encaps randomness for the es step (to responder static)
}

impl InitiatorRandomness {
    /// PRODUCTION path: draw all four per-session ephemerals from the entropy
    /// source. On metal `e` is `MetalEntropy<HwTrng>`, which FAILS CLOSED if the
    /// TRNG is unavailable — so a session either uses fresh HW entropy or is not
    /// created at all. Never seeded on metal.
    pub fn from_entropy(
        e: &mut dyn crate::entropy::EntropySource,
    ) -> Result<Self, crate::entropy::EntropyError> {
        Ok(InitiatorRandomness {
            e_x_seed: e.fill_32()?,
            e_k_d: e.fill_32()?,
            e_k_z: e.fill_32()?,
            m_es: e.fill_32()?,
        })
    }

    /// SELFTEST-ONLY deterministic constructor (fixed seeds → reproducible KAT).
    /// Compiled out of the metal profile.
    #[cfg(feature = "securechannel-selftest")]
    pub(crate) fn from_test_seeds(
        e_x_seed: [u8; 32],
        e_k_d: [u8; 32],
        e_k_z: [u8; 32],
        m_es: [u8; 32],
    ) -> Self {
        InitiatorRandomness { e_x_seed, e_k_d, e_k_z, m_es }
    }
}

/// Per-session ephemeral randomness for the RESPONDER. Same #6 discipline.
pub struct ResponderRandomness {
    re_x_seed: [u8; 32], // ephemeral X25519
    m_ee: [u8; 32],      // encaps randomness for the ee step (to device ephemeral)
}

impl ResponderRandomness {
    /// PRODUCTION path: fail-closed TRNG-sourced ephemerals.
    pub fn from_entropy(
        e: &mut dyn crate::entropy::EntropySource,
    ) -> Result<Self, crate::entropy::EntropyError> {
        Ok(ResponderRandomness {
            re_x_seed: e.fill_32()?,
            m_ee: e.fill_32()?,
        })
    }

    /// SELFTEST-ONLY deterministic constructor. Compiled out of the metal profile.
    #[cfg(feature = "securechannel-selftest")]
    pub(crate) fn from_test_seeds(re_x_seed: [u8; 32], m_ee: [u8; 32]) -> Self {
        ResponderRandomness { re_x_seed, m_ee }
    }
}

/// Carried by the initiator between msg1 and msg2 (its private ephemerals + the
/// running symmetric state). Ephemeral secrets here are the forward-secrecy roots.
pub struct InitiatorPending {
    ss: SymmetricState,
    e_x_sk: StaticSecret,
    e_k_dk: MlDk,
}

/// The completed handshake for one party: its two transport CipherStates plus the
/// final transcript hash (channel-binding value).
pub struct Session {
    pub send: CipherState,
    pub recv: CipherState,
    pub handshake_hash: [u8; 32],
}

// ---------------------------------------------------------------------------
// ml-kem wire (de)serialization helpers.
// ---------------------------------------------------------------------------

fn ek_from_bytes(b: &[u8]) -> Option<MlEk> {
    let enc = ml_kem::Encoded::<MlEk>::try_from(b).ok()?;
    Some(<MlEk as EncodedSizeUser>::from_bytes(&enc))
}
fn ct_from_bytes(b: &[u8]) -> Option<ml_kem::Ciphertext<MlKem768>> {
    ml_kem::Ciphertext::<MlKem768>::try_from(b).ok()
}

// ---------------------------------------------------------------------------
// Message 1 — initiator (device) -> responder:  e, es, s, sig
// ---------------------------------------------------------------------------

/// Build msg1 and return the wire bytes + the initiator's pending state.
/// `dev` is the device's PUF-anchored Ed25519 identity keypair.
pub fn initiator_write_msg1(
    dev: &KeyPair,
    resp_pub: &ResponderPub,
    rnd: &InitiatorRandomness,
    payload1: &[u8],
) -> Option<(HsMsg, InitiatorPending)> {
    let mut ss = SymmetricState::new(PROTOCOL_NAME);
    ss.mix_hash(PROLOGUE);
    // pre-message: the responder static keys the device knows from enrollment.
    ss.mix_hash(&resp_pub.x_pk);
    ss.mix_hash(&resp_pub.k_ek_bytes);

    let mut msg = HsMsg::new();

    // token e (hybrid ephemeral): X25519 pub + ML-KEM ephemeral ek, both cleartext.
    let e_x_sk = StaticSecret::from(rnd.e_x_seed);
    let e_x_pub = PublicKey::from(&e_x_sk).to_bytes();
    let (e_k_dk, e_k_ek) = MlKem768::generate_deterministic(&Array(rnd.e_k_d), &Array(rnd.e_k_z));
    let mut e_k_ek_bytes = [0u8; MLKEM_EK_LEN];
    e_k_ek_bytes.copy_from_slice(e_k_ek.as_bytes().as_slice());
    ss.mix_hash(&e_x_pub);
    ss.mix_hash(&e_k_ek_bytes);
    if !msg.push(&e_x_pub) || !msg.push(&e_k_ek_bytes) {
        return None;
    }

    // token es (hybrid, to responder STATIC -> authenticates the responder):
    //   X25519(e, RS_x)  AND  ML-KEM.Encaps(RS_k).
    let rs_x = PublicKey::from(resp_pub.x_pk);
    let dh_es = e_x_sk.diffie_hellman(&rs_x).to_bytes();
    let rs_ek = ek_from_bytes(&resp_pub.k_ek_bytes)?;
    let (ct_es, ss_es) = rs_ek.encapsulate_deterministic(&Array(rnd.m_es)).ok()?;
    let mut ss_es_b = [0u8; 32];
    ss_es_b.copy_from_slice(ss_es.as_slice());
    ss.mix_hash(ct_es.as_slice());
    if !msg.push(ct_es.as_slice()) {
        return None;
    }
    ss.mix_key(&hybrid_combine(&ss_es_b, &dh_es));
    // Scrub the raw es shared secret once folded (defense-in-depth, auditor #3 spirit).
    scrub32(&mut ss_es_b);

    // token s: the device's Ed25519 identity, AEAD-encrypted under the es key.
    let mut id_pub = [0u8; 32];
    id_pub.copy_from_slice(&dev.pk[..]); // PublicKey derefs to [u8; 32]
    let c_id = ss.encrypt_and_hash(&id_pub)?;
    if !msg.push(c_id.as_slice()) {
        return None;
    }

    // token sig: Ed25519 signature over the CURRENT transcript hash `h` (device
    // authentication, bound to this responder + these ephemerals), then encrypted.
    let sig = dev.sk.sign(&ss.h, None);
    let c_sig = ss.encrypt_and_hash(&sig[..])?;
    if !msg.push(c_sig.as_slice()) {
        return None;
    }

    // optional handshake payload (also authenticated + encrypted).
    let c_pl = ss.encrypt_and_hash(payload1)?;
    if !msg.push(c_pl.as_slice()) {
        return None;
    }

    Some((
        msg,
        InitiatorPending {
            ss,
            e_x_sk,
            e_k_dk,
        },
    ))
}

/// The responder's view after reading msg1: the running state, the device
/// ephemerals it needs for msg2, and the decrypted msg1 payload.
pub struct ResponderPending {
    ss: SymmetricState,
    e_x_pub: [u8; 32],
    e_k_ek: MlEk,
    pub payload1: HsRec,
}

/// Parse msg1, authenticate the device, and derive the shared es key. Aborts
/// (fail-closed) on truncation, bad key material, AEAD failure (tamper OR wrong
/// responder static key), an unenrolled identity, or a bad signature.
pub fn responder_read_msg1(
    resp: &ResponderStatic,
    enrolled_device: &EdPub,
    msg: &[u8],
) -> Result<ResponderPending, NoiseErr> {
    let mut ss = SymmetricState::new(PROTOCOL_NAME);
    ss.mix_hash(PROLOGUE);
    ss.mix_hash(&resp.x_pk);
    ss.mix_hash(&resp.k_ek_bytes);

    let mut off = 0usize;
    let take = |off: &mut usize, n: usize| -> Result<&[u8], NoiseErr> {
        if *off + n > msg.len() {
            return Err(NoiseErr::Truncated);
        }
        let s = &msg[*off..*off + n];
        *off += n;
        Ok(s)
    };

    // token e.
    let e_x_pub_s = take(&mut off, X_PUB_LEN)?;
    let mut e_x_pub = [0u8; 32];
    e_x_pub.copy_from_slice(e_x_pub_s);
    let e_k_ek_s = take(&mut off, MLKEM_EK_LEN)?;
    ss.mix_hash(&e_x_pub);
    ss.mix_hash(e_k_ek_s);
    let e_k_ek = ek_from_bytes(e_k_ek_s).ok_or(NoiseErr::BadKeyMaterial)?;

    // token es: responder decapsulates / DHs with its STATIC private keys.
    let ct_es_s = take(&mut off, MLKEM_CT_LEN)?;
    let dh_es = resp
        .x_sk
        .diffie_hellman(&PublicKey::from(e_x_pub))
        .to_bytes();
    let ct_es = ct_from_bytes(ct_es_s).ok_or(NoiseErr::BadKeyMaterial)?;
    let ss_es = resp
        .k_dk
        .decapsulate(&ct_es)
        .map_err(|_| NoiseErr::BadKeyMaterial)?;
    let mut ss_es_b = [0u8; 32];
    ss_es_b.copy_from_slice(ss_es.as_slice());
    ss.mix_hash(ct_es_s);
    ss.mix_key(&hybrid_combine(&ss_es_b, &dh_es));
    scrub32(&mut ss_es_b);

    // token s: decrypt the device identity (AEAD failure here == tamper OR a wrong
    // responder static key, both of which diverge the es key -> ABORT).
    let c_id = take(&mut off, ED_PUB_LEN + AEAD_TAG_LEN)?;
    let id_pub_rec = ss.decrypt_and_hash(c_id)?;
    let id_pub_bytes = id_pub_rec.as_slice();
    // Enrollment gate: the identity MUST be the enrolled device (constant-time).
    if !kdf::ct_eq(id_pub_bytes, &enrolled_device[..]) {
        return Err(NoiseErr::UnenrolledIdentity);
    }
    let device_pub = EdPub::from_slice(id_pub_bytes).map_err(|_| NoiseErr::BadKeyMaterial)?;

    // token sig: `h` here equals the value the device signed (both sides have just
    // MixHash'd c_id and nothing since). Capture it BEFORE decrypting the sig record.
    let signed_h = ss.h;
    let c_sig = take(&mut off, ED_SIG_LEN + AEAD_TAG_LEN)?;
    let sig_rec = ss.decrypt_and_hash(c_sig)?;
    let sig = EdSig::from_slice(sig_rec.as_slice()).map_err(|_| NoiseErr::BadSignature)?;
    device_pub
        .verify(signed_h, &sig)
        .map_err(|_| NoiseErr::BadSignature)?;

    // optional payload (rest of the message).
    let c_pl = &msg[off..];
    let payload1 = ss.decrypt_and_hash(c_pl)?;

    Ok(ResponderPending {
        ss,
        e_x_pub,
        e_k_ek,
        payload1,
    })
}

// ---------------------------------------------------------------------------
// Message 2 — responder -> initiator:  e, ee   (+ Split)
// ---------------------------------------------------------------------------

/// Build msg2, mix the forward-secret `ee` step, and Split into the responder's
/// transport session (send = responder->initiator, recv = initiator->responder).
pub fn responder_write_msg2(
    mut pend: ResponderPending,
    rnd: &ResponderRandomness,
    payload2: &[u8],
) -> Option<(HsMsg, Session)> {
    let mut msg = HsMsg::new();

    // token e (responder ephemeral X25519).
    let re_x_sk = StaticSecret::from(rnd.re_x_seed);
    let re_x_pub = PublicKey::from(&re_x_sk).to_bytes();
    pend.ss.mix_hash(&re_x_pub);
    if !msg.push(&re_x_pub) {
        return None;
    }

    // token ee (hybrid, EPHEMERAL-EPHEMERAL -> forward secrecy):
    //   X25519(re, e_x)  AND  ML-KEM.Encaps(e_k_ek).
    let dh_ee = re_x_sk
        .diffie_hellman(&PublicKey::from(pend.e_x_pub))
        .to_bytes();
    let (ct_ee, ss_ee) = pend.e_k_ek.encapsulate_deterministic(&Array(rnd.m_ee)).ok()?;
    let mut ss_ee_b = [0u8; 32];
    ss_ee_b.copy_from_slice(ss_ee.as_slice());
    pend.ss.mix_hash(ct_ee.as_slice());
    if !msg.push(ct_ee.as_slice()) {
        return None;
    }
    pend.ss.mix_key(&hybrid_combine(&ss_ee_b, &dh_ee));
    scrub32(&mut ss_ee_b);

    // key-confirmation payload (an AEAD tag the initiator verifies -> responder
    // authenticated to the initiator).
    let c_pl = pend.ss.encrypt_and_hash(payload2)?;
    if !msg.push(c_pl.as_slice()) {
        return None;
    }

    let (cs_i2r, cs_r2i) = pend.ss.split();
    Some((
        msg,
        Session {
            send: cs_r2i, // responder sends on the responder->initiator cipher
            recv: cs_i2r,
            handshake_hash: pend.ss.h,
        },
    ))
}

/// Parse msg2, mix `ee`, verify the responder's key-confirmation tag, and Split
/// into the initiator's transport session (send = initiator->responder).
pub fn initiator_read_msg2(
    mut pend: InitiatorPending,
    msg: &[u8],
) -> Result<(Session, HsRec), NoiseErr> {
    let mut off = 0usize;
    if X_PUB_LEN + MLKEM_CT_LEN > msg.len() {
        return Err(NoiseErr::Truncated);
    }
    let mut re_x_pub = [0u8; 32];
    re_x_pub.copy_from_slice(&msg[off..off + X_PUB_LEN]);
    off += X_PUB_LEN;
    pend.ss.mix_hash(&re_x_pub);

    let ct_ee_s = &msg[off..off + MLKEM_CT_LEN];
    off += MLKEM_CT_LEN;
    let dh_ee = pend
        .e_x_sk
        .diffie_hellman(&PublicKey::from(re_x_pub))
        .to_bytes();
    let ct_ee = ct_from_bytes(ct_ee_s).ok_or(NoiseErr::BadKeyMaterial)?;
    let ss_ee = pend
        .e_k_dk
        .decapsulate(&ct_ee)
        .map_err(|_| NoiseErr::BadKeyMaterial)?;
    let mut ss_ee_b = [0u8; 32];
    ss_ee_b.copy_from_slice(ss_ee.as_slice());
    pend.ss.mix_hash(ct_ee_s);
    pend.ss.mix_key(&hybrid_combine(&ss_ee_b, &dh_ee));
    scrub32(&mut ss_ee_b);

    // key confirmation: this decrypt fails if the responder derived a different ck
    // (e.g. the device used a WRONG responder static key) -> responder NOT authentic.
    let payload2 = pend.ss.decrypt_and_hash(&msg[off..])?;

    let (cs_i2r, cs_r2i) = pend.ss.split();
    Ok((
        Session {
            send: cs_i2r, // initiator sends on the initiator->responder cipher
            recv: cs_r2i,
            handshake_hash: pend.ss.h,
        },
        payload2,
    ))
}

// ===========================================================================
// The [P19-noise] gate — full handshake + the six required property proofs.
// All DETERMINISTIC (seeded ephemerals); real TRNG/PUF/PKI = metal (Gate R).
//
// The ENTIRE test harness below is behind `securechannel-selftest`: it uses the
// deterministic seed constructors + `key_for_test`, both of which are compiled
// OUT of the metal profile (auditor #4/#6). The production handshake functions
// above carry NO test coupling.
// ===========================================================================

/// Deterministic test seeds, all distinct + domain-labelled (never all-zero).
#[cfg(feature = "securechannel-selftest")]
pub(crate) struct TestVectors {
    pub dev: KeyPair,
    pub resp: ResponderStatic,
    pub irand: InitiatorRandomness,
    pub rrand: ResponderRandomness,
}

#[cfg(feature = "securechannel-selftest")]
pub(crate) fn test_vectors() -> TestVectors {
    let dev = KeyPair::from_seed(ed25519_compact::Seed::new(sha256::digest(
        b"HEQK-M4.2b-device-PUF-identity",
    )));
    let resp = ResponderStatic::from_seeds(
        &sha256::digest(b"HEQK-M4.2b-resp-static-x25519"),
        &sha256::digest(b"HEQK-M4.2b-resp-static-mlkem-d"),
        &sha256::digest(b"HEQK-M4.2b-resp-static-mlkem-z"),
    );
    let irand = InitiatorRandomness::from_test_seeds(
        sha256::digest(b"HEQK-M4.2b-init-eph-x25519"),
        sha256::digest(b"HEQK-M4.2b-init-eph-mlkem-d"),
        sha256::digest(b"HEQK-M4.2b-init-eph-mlkem-z"),
        sha256::digest(b"HEQK-M4.2b-init-encaps-es-m"),
    );
    let rrand = ResponderRandomness::from_test_seeds(
        sha256::digest(b"HEQK-M4.2b-resp-eph-x25519"),
        sha256::digest(b"HEQK-M4.2b-resp-encaps-ee-m"),
    );
    TestVectors {
        dev,
        resp,
        irand,
        rrand,
    }
}

/// Drive a full initiator<->responder handshake. Returns both sessions on success.
#[cfg(feature = "securechannel-selftest")]
fn run_handshake(tv: &TestVectors) -> Option<(Session, Session)> {
    let (msg1, ipend) =
        initiator_write_msg1(&tv.dev, &tv.resp.public(), &tv.irand, b"hello-from-device")?;
    let rpend = responder_read_msg1(&tv.resp, &tv.dev.pk, msg1.as_slice()).ok()?;
    // The device's msg1 payload was delivered + authenticated to the responder.
    if rpend.payload1.as_slice() != b"hello-from-device" {
        return None;
    }
    let (msg2, rsession) = responder_write_msg2(rpend, &tv.rrand, b"welcome")?;
    let (isession, _p2) = initiator_read_msg2(ipend, msg2.as_slice()).ok()?;
    Some((isession, rsession))
}

/// Prove the hybrid combiner binds BOTH legs: changing either the ML-KEM ss or the
/// X25519 ss changes the derived key. So the transport key is secure if EITHER
/// primitive holds (an attacker who breaks only one still lacks the other's input).
#[cfg(feature = "securechannel-selftest")]
fn hybrid_either_leg_binds() -> bool {
    let a = sha256::digest(b"mlkem-ss");
    let b = sha256::digest(b"x25519-ss");
    let z = [0u8; 32];
    let full = hybrid_combine(&a, &b);
    let no_pq = hybrid_combine(&z, &b); // ML-KEM leg missing
    let no_ec = hybrid_combine(&a, &z); // X25519 leg missing
    let neither = hybrid_combine(&z, &z);
    !kdf::ct_eq(&full, &no_pq)
        && !kdf::ct_eq(&full, &no_ec)
        && !kdf::ct_eq(&full, &neither)
        && !kdf::ct_eq(&no_pq, &no_ec)
}

/// The [P19-noise] self-test: full handshake + all six required properties.
#[cfg(feature = "securechannel-selftest")]
pub fn noise_selftest() -> bool {
    let tv = test_vectors();
    let mut all = true;

    // (A) Full handshake -> MATCHING transport keys, correctly crossed.
    let (mut isess, mut rsess) = match run_handshake(&tv) {
        Some(s) => s,
        None => {
            kprint!("   [A] handshake FAILED to complete\n");
            return false;
        }
    };
    let keys_match = kdf::ct_eq(&isess.send.key_for_test(), &rsess.recv.key_for_test())
        && kdf::ct_eq(&isess.recv.key_for_test(), &rsess.send.key_for_test());
    // send != recv within a party (separate directions, independent keys).
    let dirs_separate = !kdf::ct_eq(&isess.send.key_for_test(), &isess.recv.key_for_test());
    let hh_match = kdf::ct_eq(&isess.handshake_hash, &rsess.handshake_hash);
    kprint!(
        "   [A] handshake completes · i.send==r.recv & i.recv==r.send {} · send!=recv {} · transcript-hash agree {}\n",
        if keys_match { "OK" } else { "MISMATCH" },
        if dirs_separate { "OK" } else { "SHARED!" },
        if hh_match { "OK" } else { "MISMATCH" }
    );
    all &= keys_match && dirs_separate && hh_match;

    // (B) A transport record round-trips (confidentiality + integrity) and a
    //     REPLAY of it is REJECTED (nonce counter has advanced).
    let plaintext = b"evidence-record-42";
    let mut recbuf = [0u8; 64];
    let rlen = isess.send.encrypt_into(b"", plaintext, &mut recbuf).unwrap_or(0);
    let mut ptbuf = [0u8; 64];
    let got = rsess.recv.decrypt_into(b"", &recbuf[..rlen], &mut ptbuf);
    let rt_ok = matches!(&got, Ok(n) if kdf::ct_eq(&ptbuf[..*n], plaintext));
    // Replay the SAME record: receiver is now at n=1, so it must reject.
    let mut ptbuf2 = [0u8; 64];
    let replay = rsess.recv.decrypt_into(b"", &recbuf[..rlen], &mut ptbuf2);
    let replay_rejected = replay == Err(NoiseErr::AeadAuth);
    kprint!(
        "   [B] transport record round-trip {} · replayed record rejected {}\n",
        if rt_ok { "OK" } else { "FAIL" },
        if replay_rejected { "OK" } else { "ACCEPTED!" }
    );
    all &= rt_ok && replay_rejected;

    // (C) A TAMPERED handshake msg1 -> responder ABORTS (AEAD auth fails).
    let (msg1, _ip) =
        initiator_write_msg1(&tv.dev, &tv.resp.public(), &tv.irand, b"x").unwrap();
    let mut msg1b = [0u8; HS_MSG_MAX];
    let m1len = msg1.len();
    msg1b[..m1len].copy_from_slice(msg1.as_slice());
    msg1b[m1len - 1] ^= 0x01; // flip a byte in the (encrypted) tail
    let tamper_abort = responder_read_msg1(&tv.resp, &tv.dev.pk, &msg1b[..m1len]).is_err();
    kprint!(
        "   [C] tampered handshake message -> abort {}\n",
        if tamper_abort { "OK" } else { "ACCEPTED!" }
    );
    all &= tamper_abort;

    // (D) WRONG responder static key -> handshake ABORTS. The device is given an
    //     unenrolled responder public key; the real responder decaps with its real
    //     key -> the es key diverges -> msg1's identity record fails to decrypt.
    let wrong_resp = ResponderStatic::from_seeds(
        &sha256::digest(b"WRONG-resp-x25519"),
        &sha256::digest(b"WRONG-resp-mlkem-d"),
        &sha256::digest(b"WRONG-resp-mlkem-z"),
    );
    let (msg1_w, _ipw) =
        initiator_write_msg1(&tv.dev, &wrong_resp.public(), &tv.irand, b"x").unwrap();
    // real responder tries to read a msg1 built for a DIFFERENT static key.
    let wrongkey_abort = responder_read_msg1(&tv.resp, &tv.dev.pk, msg1_w.as_slice()).is_err();
    kprint!(
        "   [D] wrong responder static key -> abort {}\n",
        if wrongkey_abort { "OK" } else { "ACCEPTED!" }
    );
    all &= wrongkey_abort;

    // (E) UNENROLLED / forged device identity -> responder ABORTS. A different
    //     device identity signs a valid handshake, but it is not the enrolled key.
    let rogue = KeyPair::from_seed(ed25519_compact::Seed::new(sha256::digest(b"ROGUE-device")));
    let (msg1_r, _ipr) =
        initiator_write_msg1(&rogue, &tv.resp.public(), &tv.irand, b"x").unwrap();
    let unenrolled_abort = matches!(
        responder_read_msg1(&tv.resp, &tv.dev.pk, msg1_r.as_slice()),
        Err(NoiseErr::UnenrolledIdentity)
    );
    kprint!(
        "   [E] unenrolled device identity -> abort {}\n",
        if unenrolled_abort { "OK" } else { "ACCEPTED!" }
    );
    all &= unenrolled_abort;

    // (F) Hybrid: the combiner binds BOTH the ML-KEM and X25519 legs (secure if
    //     either holds), and forward secrecy: fresh ephemerals -> different keys.
    let hybrid_ok = hybrid_either_leg_binds();
    let mut tv2 = test_vectors();
    // Different per-session ephemerals (same statics) -> forward secrecy.
    tv2.irand = InitiatorRandomness::from_test_seeds(
        sha256::digest(b"HEQK-M4.2b-DIFFERENT-init-eph-x"),
        sha256::digest(b"HEQK-M4.2b-DIFFERENT-init-eph-d"),
        sha256::digest(b"HEQK-M4.2b-DIFFERENT-init-eph-z"),
        sha256::digest(b"HEQK-M4.2b-init-encaps-es-m"),
    );
    tv2.rrand = ResponderRandomness::from_test_seeds(
        sha256::digest(b"HEQK-M4.2b-DIFFERENT-resp-eph-x"),
        sha256::digest(b"HEQK-M4.2b-resp-encaps-ee-m"),
    );
    let fs_ok = match (run_handshake(&tv), run_handshake(&tv2)) {
        (Some((s1, _)), Some((s2, _))) => {
            !kdf::ct_eq(&s1.send.key_for_test(), &s2.send.key_for_test())
        }
        _ => false,
    };
    kprint!(
        "   [F] hybrid combiner binds both legs {} · forward-secrecy (fresh ephemerals -> new key) {}\n",
        if hybrid_ok { "OK" } else { "FAIL" },
        if fs_ok { "OK" } else { "FAIL" }
    );
    all &= hybrid_ok && fs_ok;

    all
}
