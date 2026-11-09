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
//!   cargo run --release -- fuzz [N]   differential fuzz: random / mutated ciphertexts + keys (default 200 000)
/// Byte-level view of the shipping RustCrypto ml-kem 0.3.4 (0.3 keys are seed-based; the expanded 2400-byte
/// decapsulation key is the deprecated-but-supported FIPS 203 encoding the vectors use).
#[allow(deprecated)]
mod rc {
    use ml_kem::ml_kem_768::{DecapsulationKey, EncapsulationKey};
    use ml_kem::{Decapsulate, ExpandedKeyEncoding, KeyExport};
    pub fn keygen(d: &[u8; 32], z: &[u8; 32]) -> ([u8; 1184], [u8; 2400]) {
        let mut seed = [0u8; 64];
        seed[..32].copy_from_slice(d);
        seed[32..].copy_from_slice(z);
        let dk = DecapsulationKey::from_seed(seed.into());
        let ek: [u8; 1184] = dk.encapsulation_key().to_bytes().as_slice().try_into().unwrap();
        (ek, dk.to_expanded_bytes().as_slice().try_into().unwrap())
    }
    /// None = the library refuses the key (0.3 validates FIPS 203 §7.2 in `EncapsulationKey::new`).
    pub fn encaps(ek: &[u8; 1184], m: &[u8; 32]) -> Option<([u8; 1088], [u8; 32])> {
        let ek = EncapsulationKey::new(&(*ek).into()).ok()?;
        let (ct, ss) = ek.encapsulate_deterministic(&(*m).into());
        Some((ct.as_slice().try_into().unwrap(), ss.as_slice().try_into().unwrap()))
    }
    /// None = the library refuses the expanded key (0.3 checks H(ek) per FIPS 203 §7.3).
    pub fn decaps(dk: &[u8; 2400], ct: &[u8; 1088]) -> Option<[u8; 32]> {
        let dk = DecapsulationKey::from_expanded_bytes(&(*dk).into()).ok()?;
        Some(dk.decapsulate(&(*ct).into()).as_slice().try_into().unwrap())
    }
    pub fn ek_valid(ek: &[u8]) -> bool {
        <[u8; 1184]>::try_from(ek).ok().is_some_and(|e| EncapsulationKey::new(&e.into()).is_ok())
    }
    pub fn dk_valid(dk: &[u8]) -> bool {
        <[u8; 2400]>::try_from(dk).ok().is_some_and(|d| DecapsulationKey::from_expanded_bytes(&d.into()).is_ok())
    }
}
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
    if std::env::args().nth(1).as_deref() == Some("acvp") {
        let dir = std::env::args().nth(2).unwrap_or_else(|| concat!(env!("CARGO_MANIFEST_DIR"), "/acvp").into());
        std::process::exit(if acvp(&dir) { 0 } else { 1 });
    }
    if std::env::args().nth(1).as_deref() == Some("fuzz") {
        let n: u64 = std::env::args().nth(2).and_then(|s| s.parse().ok()).unwrap_or(200_000);
        std::process::exit(if fuzz(n) { 0 } else { 1 });
    }
    let n: u32 = std::env::args().nth(1).and_then(|s| s.parse().ok()).unwrap_or(1000);
    let mut transcript = Sha256::new();
    let (mut fails, mut t_rc, mut t_lc) = (0u32, Duration::ZERO, Duration::ZERO);
    for i in 0..n {
        let (d, z, m) = (seed(b"d", i), seed(b"z", i), seed(b"m", i));

        // RustCrypto
        let t0 = Instant::now();
        let (rc_ek_b, rc_dk_b) = rc::keygen(&d, &z);
        let (rc_ct, rc_ss) = rc::encaps(&rc_ek_b, &m).unwrap();
        let rc_back = rc::decaps(&rc_dk_b, &rc_ct).unwrap();
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

        let keys_eq = rc_ek_b.as_slice() == kp.public_key().as_slice() && rc_dk_b.as_slice() == kp.private_key().as_slice();
        let enc_eq = rc_ct.as_slice() == lc_ct.as_slice() && rc_ss.as_slice() == lc_ss.as_slice();
        let self_ok = rc_back == rc_ss && lc_back == lc_ss;

        // cross-decapsulation
        let cross_rc = rc::decaps(&rc_dk_b, lc_ct.as_slice()).unwrap();
        let rc_ct_as_lc = libcrux_ml_kem::mlkem768::MlKem768Ciphertext::from(rc_ct);
        let cross_lc = libcrux_ml_kem::mlkem768::decapsulate(kp.private_key(), &rc_ct_as_lc);
        let cross_ok = cross_rc.as_slice() == lc_ss.as_slice() && cross_lc == rc_ss.as_slice();

        // implicit rejection on a tampered ciphertext
        let mut bad = rc_ct;
        bad[(i as usize * 7) % 1088] ^= 1 << (i % 8);
        let rej_rc = rc::decaps(&rc_dk_b, &bad).unwrap();
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
        transcript.update(rc_ek_b);
        transcript.update(rc_ct);
        transcript.update(rc_ss);
        transcript.update(rej_rc);
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

// ---------------------------------------------------------------- NIST ACVP (FIPS 203), ML-KEM-768

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len() / 2).map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap()).collect()
}

/// FIPS 203 §7.2 encapsulation-key input check: every 12-bit coefficient of the 1152-byte t-part < q.
pub fn ek_modulus_ok(ek: &[u8]) -> bool {
    ek.len() == 1184
        && ek[..1152].chunks(3).all(|c| {
            let a = u16::from(c[0]) | (u16::from(c[1] & 0x0f) << 8);
            let b = u16::from(c[1] >> 4) | (u16::from(c[2]) << 4);
            a < 3329 && b < 3329
        })
}

/// FIPS 203 §7.3 decapsulation-key input check: length, and H(ek) stored inside dk == SHA3-256(ek inside dk).
pub fn dk_hash_ok(dk: &[u8]) -> bool {
    use sha3::{Digest as _, Sha3_256};
    if dk.len() != 2400 {
        return false;
    }
    let ek = &dk[1152..1152 + 1184];
    let h = &dk[1152 + 1184..1152 + 1184 + 32];
    Sha3_256::digest(ek).as_slice() == h
}

fn acvp(dir: &str) -> bool {
    let load = |f: &str| -> serde_json::Value {
        serde_json::from_str(&std::fs::read_to_string(format!("{dir}/{f}.json")).unwrap_or_else(|e| panic!("{dir}/{f}.json: {e} (run fetch-acvp.sh)"))).unwrap()
    };
    let (mut pass, mut fail) = (0u32, 0u32);
    let mut tally = |ok: bool, what: &str, tc: u64| {
        if ok {
            pass += 1;
        } else {
            fail += 1;
            eprintln!("ACVP FAIL {what} tcId {tc}");
        }
    };
    let h = |t: &serde_json::Value, k: &str| unhex(t[k].as_str().unwrap());
    for g in load("ML-KEM-keyGen-FIPS203")["testGroups"].as_array().unwrap() {
        if g["parameterSet"] != "ML-KEM-768" {
            continue;
        }
        for t in g["tests"].as_array().unwrap() {
            let tc = t["tcId"].as_u64().unwrap();
            let (d, z, ek, dk) = (h(t, "d"), h(t, "z"), h(t, "ek"), h(t, "dk"));
            let (rc_ek, rc_dk) = rc::keygen(&d.clone().try_into().unwrap(), &z.clone().try_into().unwrap());
            tally(rc_ek[..] == ek[..] && rc_dk[..] == dk[..], "keyGen RustCrypto", tc);
            let mut dz = [0u8; 64];
            dz[..32].copy_from_slice(&d);
            dz[32..].copy_from_slice(&z);
            let kp = libcrux_ml_kem::mlkem768::generate_key_pair(dz);
            tally(kp.public_key().as_slice() == &ek[..] && kp.private_key().as_slice() == &dk[..], "keyGen libcrux", tc);
        }
    }
    for g in load("ML-KEM-encapDecap-FIPS203")["testGroups"].as_array().unwrap() {
        if g["parameterSet"] != "ML-KEM-768" {
            continue;
        }
        let func = g["function"].as_str().unwrap_or("");
        for t in g["tests"].as_array().unwrap() {
            let tc = t["tcId"].as_u64().unwrap();
            match func {
                "encapsulation" => {
                    let (ek, m, c, k) = (h(t, "ek"), h(t, "m"), h(t, "c"), h(t, "k"));
                    let r = rc::encaps(&ek.clone().try_into().unwrap(), &m.clone().try_into().unwrap());
                    tally(r.is_some_and(|(rc_c, rc_k)| rc_c[..] == c[..] && rc_k[..] == k[..]), "encaps RustCrypto", tc);
                    let pk = libcrux_ml_kem::mlkem768::MlKem768PublicKey::from(<[u8; 1184]>::try_from(&ek[..]).unwrap());
                    let (lc_c, lc_k) = libcrux_ml_kem::mlkem768::encapsulate(&pk, m.try_into().unwrap());
                    tally(lc_c.as_slice() == &c[..] && lc_k.as_slice() == &k[..], "encaps libcrux", tc);
                }
                "decapsulation" => {
                    let (dk, c, k) = (h(t, "dk"), h(t, "c"), h(t, "k"));
                    let r = rc::decaps(&dk.clone().try_into().unwrap(), &c.clone().try_into().unwrap());
                    tally(r.is_some_and(|rc_k| rc_k[..] == k[..]), "decaps RustCrypto", tc);
                    let sk = libcrux_ml_kem::mlkem768::MlKem768PrivateKey::from(<[u8; 2400]>::try_from(&dk[..]).unwrap());
                    let ct = libcrux_ml_kem::mlkem768::MlKem768Ciphertext::from(<[u8; 1088]>::try_from(&c[..]).unwrap());
                    tally(libcrux_ml_kem::mlkem768::decapsulate(&sk, &ct).as_slice() == &k[..], "decaps libcrux", tc);
                }
                "encapsulationKeyCheck" => {
                    let (ek, want) = (h(t, "ek"), t["testPassed"].as_bool().unwrap());
                    tally(ek_modulus_ok(&ek) == want, "ekCheck heqk helper", tc);
                    tally(rc::ek_valid(&ek) == want, "ekCheck RustCrypto 0.3.4", tc);
                    let ok = ek.len() == 1184
                        && libcrux_ml_kem::mlkem768::validate_public_key(&libcrux_ml_kem::mlkem768::MlKem768PublicKey::from(<[u8; 1184]>::try_from(&ek[..]).unwrap()));
                    tally(ok == want, "ekCheck libcrux", tc);
                }
                "decapsulationKeyCheck" => {
                    let (dk, want) = (h(t, "dk"), t["testPassed"].as_bool().unwrap());
                    tally(dk_hash_ok(&dk) == want, "dkCheck heqk helper", tc);
                    tally(rc::dk_valid(&dk) == want, "dkCheck RustCrypto 0.3.4", tc);
                    let ok = dk.len() == 2400
                        && libcrux_ml_kem::mlkem768::validate_private_key(&libcrux_ml_kem::mlkem768::MlKem768PrivateKey::from(<[u8; 2400]>::try_from(&dk[..]).unwrap()), &libcrux_ml_kem::mlkem768::MlKem768Ciphertext::from([0u8; 1088]));
                    tally(ok == want, "dkCheck libcrux", tc);
                }
                _ => {}
            }
        }
    }
    println!("ACVP ML-KEM-768 (FIPS 203): {pass} checks passed, {fail} failed");
    fail == 0 && pass > 0
}

// ---------------------------------------------------------------- differential fuzz (gate: "Fuzzing")

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        // xorshift64* — reproducible from the printed seed
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }
    fn fill(&mut self, b: &mut [u8]) {
        for c in b.chunks_mut(8) {
            let v = self.next().to_le_bytes();
            c.copy_from_slice(&v[..c.len()]);
        }
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }
}

/// Mutate `b` the way a fuzzer would: bit flips, byte sets, a random run, all-0x00 / all-0xff stretches.
fn mutate(r: &mut Rng, b: &mut [u8]) {
    for _ in 0..1 + r.below(4) {
        let i = r.below(b.len());
        match r.below(5) {
            0 => b[i] ^= 1 << r.below(8),
            1 => b[i] = r.next() as u8,
            2 => {
                let l = (1 + r.below(64)).min(b.len() - i);
                r.fill(&mut b[i..i + l]);
            }
            3 => {
                let l = (1 + r.below(64)).min(b.len() - i);
                b[i..i + l].fill(0);
            }
            _ => {
                let l = (1 + r.below(64)).min(b.len() - i);
                b[i..i + l].fill(0xff);
            }
        }
    }
}

/// The shipping library: None when it refuses the key (0.3 validates expanded keys, unlike 0.2.3).
fn rc_decaps(dk: &[u8; 2400], ct: &[u8; 1088]) -> Option<[u8; 32]> {
    rc::decaps(dk, ct)
}

fn lc_decaps(dk: &[u8; 2400], ct: &[u8; 1088]) -> [u8; 32] {
    let dk = libcrux_ml_kem::mlkem768::MlKem768PrivateKey::from(*dk);
    libcrux_ml_kem::mlkem768::decapsulate(&dk, &libcrux_ml_kem::mlkem768::MlKem768Ciphertext::from(*ct))
}

fn rc_encaps(ek: &[u8; 1184], m: &[u8; 32]) -> Option<([u8; 1088], [u8; 32])> {
    rc::encaps(ek, m)
}

fn lc_encaps(ek: &[u8; 1184], m: &[u8; 32]) -> ([u8; 1088], [u8; 32]) {
    let (ct, ss) = libcrux_ml_kem::mlkem768::encapsulate(&libcrux_ml_kem::mlkem768::MlKem768PublicKey::from(*ek), *m);
    (*ct.as_slice(), ss)
}

/// Differential fuzz. HARD failures (exit 1): any panic, or any disagreement on inputs a production caller can
/// reach — a hostile ciphertext against an honest key, an encapsulation key that passes the §7.2 check.
/// REPORTED only: keys outside FIPS 203 input checks (production refuses them before use).
fn fuzz(n: u64) -> bool {
    let fseed: u64 = 0x6865_716b_2d6b_656d; // "heqk-kem"
    let mut r = Rng(fseed);
    let keys: Vec<([u8; 1184], [u8; 2400], [u8; 1088])> = (0..16u32)
        .map(|i| {
            let mut dz = [0u8; 64];
            dz[..32].copy_from_slice(&seed(b"fz-d", i));
            dz[32..].copy_from_slice(&seed(b"fz-z", i));
            let kp = libcrux_ml_kem::mlkem768::generate_key_pair(dz);
            let (ct, _) = libcrux_ml_kem::mlkem768::encapsulate(kp.public_key(), seed(b"fz-m", i));
            (*kp.public_key().as_slice(), *kp.private_key().as_slice(), *ct.as_slice())
        })
        .collect();
    let (mut ct_cases, mut ct_bad) = (0u64, 0u64);
    let (mut ek_valid, mut ek_valid_bad, mut ek_invalid, mut ek_invalid_diff) = (0u64, 0u64, 0u64, 0u64);
    let (mut dk_cases, mut dk_diff) = (0u64, 0u64);
    let mut panics = 0u64;
    let t0 = Instant::now();
    for it in 0..n {
        let (ek, dk, ct0) = &keys[r.below(keys.len())];
        let kind = r.below(10);
        let res = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| -> (u8, bool) {
            let mut rr = Rng(fseed ^ it.wrapping_mul(0x9e37_79b9_7f4a_7c15) | 1);
            match kind {
                // 0-5: hostile ciphertext (mutated honest one, or fully random) against an honest key
                0..=5 => {
                    let mut ct = *ct0;
                    if kind == 5 { rr.fill(&mut ct) } else { mutate(&mut rr, &mut ct) }
                    (0, rc_decaps(dk, &ct) == Some(lc_decaps(dk, &ct)))
                }
                // 6-7: encapsulation to a mutated / random public key
                6 | 7 => {
                    let mut e = *ek;
                    if kind == 7 { rr.fill(&mut e) } else { mutate(&mut rr, &mut e) }
                    let mut m = [0u8; 32];
                    rr.fill(&mut m);
                    // a key that passes §7.2 must be accepted by the shipping library AND agree with libcrux;
                    // one that fails it must be REFUSED by the shipping library (0.3 validates itself)
                    if ek_modulus_ok(&e) {
                        (1, rc_encaps(&e, &m) == Some(lc_encaps(&e, &m)))
                    } else {
                        (2, rc_encaps(&e, &m).is_none())
                    }
                }
                // 8-9: decapsulation with a mutated private key (outside FIPS 203 §7.3 — reported only)
                _ => {
                    let mut d = *dk;
                    mutate(&mut rr, &mut d);
                    // outside §7.3: the shipping library may refuse (H(ek) check) — compare only what it accepts
                    (3, rc_decaps(&d, ct0).map_or(true, |k| k == lc_decaps(&d, ct0)))
                }
            }
        }));
        match res {
            Err(_) => {
                panics += 1;
                if panics <= 5 {
                    eprintln!("iteration {it} kind {kind}: PANIC");
                }
            }
            Ok((0, same)) => {
                ct_cases += 1;
                if !same {
                    ct_bad += 1;
                    if ct_bad <= 5 {
                        eprintln!("iteration {it}: hostile ciphertext — implementations DISAGREE");
                    }
                }
            }
            Ok((1, same)) => {
                ek_valid += 1;
                if !same {
                    ek_valid_bad += 1;
                    if ek_valid_bad <= 5 {
                        eprintln!("iteration {it}: valid public key — encapsulation DISAGREES");
                    }
                }
            }
            Ok((2, same)) => {
                ek_invalid += 1;
                ek_invalid_diff += !same as u64; // here: NOT refused by the shipping library
            }
            Ok((_, same)) => {
                dk_cases += 1;
                dk_diff += !same as u64;
            }
        }
    }
    let pass = panics == 0 && ct_bad == 0 && ek_valid_bad == 0 && ek_invalid_diff == 0;
    println!("kem-diff fuzz: {n} iterations in {:.1} s, seed {fseed:#x}", t0.elapsed().as_secs_f64());
    println!("  hostile ciphertexts vs honest keys: {ct_cases}, disagreements {ct_bad}");
    println!("  encapsulation to mutated/random keys: {ek_valid} pass the FIPS 203 §7.2 check (disagreements {ek_valid_bad}), {ek_invalid} fail it (accepted by the shipping library: {ek_invalid_diff} — must be 0)");
    println!("  decapsulation with mutated private keys (outside §7.3, reported only): {dk_cases}, differ {dk_diff}");
    println!("  panics: {panics}");
    println!("KEM-FUZZ: {}", if pass { "PASS" } else { "FAIL" });
    pass
}
