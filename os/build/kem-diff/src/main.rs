//! kem-diff — Phase 2 gate: libcrux ML-KEM-768 vs the shipping RustCrypto ml-kem 0.2.3, byte for byte.
//!
//! For N deterministic seeds (FIPS 203 internal API: keygen(d, z), encaps(m)):
//!   1. identical encapsulation key + decapsulation key,
//!   2. identical ciphertext + shared secret,
//!   3. cross-decapsulation both ways recovers the same secret,
//!   4. implicit rejection: a tampered ciphertext gives the SAME pseudo-random secret in both (≠ the real one),
//!   5. libcrux public-key validation accepts every honest key and rejects an out-of-range coefficient.
//! Prints a SHA-256 over the whole transcript (pin it to catch silent drift) and host timings.
//!
//!   cargo run --release -- [N]        (default 1000)
use kem::Decapsulate;
use ml_kem::EncapsulateDeterministic;
use ml_kem::array::Array;
use ml_kem::{EncodedSizeUser, KemCore, MlKem768};
use sha2::{Digest, Sha256};
use std::time::{Duration, Instant};

fn seed(tag: &[u8], i: u32) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"kem-diff v1");
    h.update(tag);
    h.update(i.to_le_bytes());
    h.finalize().into()
}

fn main() {
    let n: u32 = std::env::args().nth(1).and_then(|s| s.parse().ok()).unwrap_or(1000);
    let mut transcript = Sha256::new();
    let (mut fails, mut t_rc, mut t_lc) = (0u32, Duration::ZERO, Duration::ZERO);
    for i in 0..n {
        let (d, z, m) = (seed(b"d", i), seed(b"z", i), seed(b"m", i));

        // RustCrypto
        let t0 = Instant::now();
        let (rc_dk, rc_ek) = MlKem768::generate_deterministic(&Array(d), &Array(z));
        let (rc_ct, rc_ss) = rc_ek.encapsulate_deterministic(&Array(m)).unwrap();
        let rc_back = rc_dk.decapsulate(&rc_ct).unwrap();
        t_rc += t0.elapsed();

        // libcrux (portable code path on this host build as well as the CM5 softfloat target)
        let mut dz = [0u8; 64];
        dz[..32].copy_from_slice(&d);
        dz[32..].copy_from_slice(&z);
        let t1 = Instant::now();
        let kp = libcrux_ml_kem::mlkem768::generate_key_pair(dz);
        let (lc_ct, lc_ss) = libcrux_ml_kem::mlkem768::encapsulate(kp.public_key(), m);
        let lc_back = libcrux_ml_kem::mlkem768::decapsulate(kp.private_key(), &lc_ct);
        t_lc += t1.elapsed();

        let rc_ek_b = rc_ek.as_bytes();
        let rc_dk_b = rc_dk.as_bytes();
        let keys_eq = rc_ek_b.as_slice() == kp.public_key().as_slice() && rc_dk_b.as_slice() == kp.private_key().as_slice();
        let enc_eq = rc_ct.as_slice() == lc_ct.as_slice() && rc_ss.as_slice() == lc_ss.as_slice();
        let self_ok = rc_back == rc_ss && lc_back == lc_ss;

        // cross-decapsulation
        let lc_ct_as_rc = ml_kem::Ciphertext::<MlKem768>::try_from(lc_ct.as_slice().as_slice()).unwrap();
        let cross_rc = rc_dk.decapsulate(&lc_ct_as_rc).unwrap();
        let rc_ct_as_lc = libcrux_ml_kem::mlkem768::MlKem768Ciphertext::from(<[u8; 1088]>::try_from(rc_ct.as_slice()).unwrap());
        let cross_lc = libcrux_ml_kem::mlkem768::decapsulate(kp.private_key(), &rc_ct_as_lc);
        let cross_ok = cross_rc.as_slice() == lc_ss.as_slice() && cross_lc == rc_ss.as_slice();

        // implicit rejection on a tampered ciphertext
        let mut bad = <[u8; 1088]>::try_from(rc_ct.as_slice()).unwrap();
        bad[(i as usize * 7) % 1088] ^= 1 << (i % 8);
        let rej_rc = rc_dk.decapsulate(&ml_kem::Ciphertext::<MlKem768>::try_from(&bad[..]).unwrap()).unwrap();
        let rej_lc = libcrux_ml_kem::mlkem768::decapsulate(kp.private_key(), &libcrux_ml_kem::mlkem768::MlKem768Ciphertext::from(bad));
        let rej_ok = rej_rc.as_slice() == rej_lc.as_slice() && rej_rc != rc_ss;

        // public-key validation (FIPS 203 §7.2 modulus check)
        let valid_ok = libcrux_ml_kem::mlkem768::validate_public_key(kp.public_key());

        if !(keys_eq && enc_eq && self_ok && cross_ok && rej_ok && valid_ok) {
            fails += 1;
            if fails <= 5 {
                eprintln!("seed {i}: keys={keys_eq} encaps={enc_eq} self={self_ok} cross={cross_ok} rejection={rej_ok} pk-valid={valid_ok}");
            }
        }
        transcript.update(rc_ek_b.as_slice());
        transcript.update(rc_ct.as_slice());
        transcript.update(rc_ss.as_slice());
        transcript.update(rej_rc.as_slice());
    }

    // A public key with one coefficient set to q = 3329 (not reduced) must be rejected.
    let kp = libcrux_ml_kem::mlkem768::generate_key_pair([7u8; 64]);
    let mut pk = *kp.public_key().as_slice();
    pk[0] = 0x01; // first 12-bit coefficient = 0xD01 = 3329
    pk[1] = (pk[1] & 0xf0) | 0x0d;
    let bad_pk_rejected = !libcrux_ml_kem::mlkem768::validate_public_key(&libcrux_ml_kem::mlkem768::MlKem768PublicKey::from(pk));

    let digest: [u8; 32] = transcript.finalize().into();
    let hex: String = digest.iter().map(|b| format!("{b:02x}")).collect();
    println!("kem-diff: {n} seeds, mismatches={fails}, unreduced public key rejected={bad_pk_rejected}");
    println!("transcript sha256 {hex}");
    println!(
        "host time per keygen+encaps+decaps: RustCrypto {:.1} us, libcrux {:.1} us",
        t_rc.as_secs_f64() * 1e6 / n as f64,
        t_lc.as_secs_f64() * 1e6 / n as f64
    );
    if fails == 0 && bad_pk_rejected {
        println!("KEM-DIFF: PASS");
    } else {
        println!("KEM-DIFF: FAIL");
        std::process::exit(1);
    }
}
