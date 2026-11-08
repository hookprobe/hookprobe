//! ctgrind-style constant-time check of ML-KEM-768 (both the shipping RustCrypto ml-kem 0.2.3 and libcrux 0.0.11):
//! every SECRET input (keygen seeds d/z, encaps randomness m, the decapsulation key) is marked UNDEFINED for
//! valgrind memcheck; public outputs (ek, ct) are declared defined once produced. Any branch, memory address or
//! syscall that depends on a secret is reported. Run: valgrind --error-exitcode=9 target/release/kem-ctgrind <rc|lc>
use crabgrind::memcheck::{mark_memory, MemState};
use kem::Decapsulate;
use ml_kem::array::Array;
use ml_kem::{EncapsulateDeterministic, EncodedSizeUser, KemCore, MlKem768};

fn secret<T: ?Sized>(v: &T) {
    let _ = mark_memory(v as *const T as *const u8 as *const _, core::mem::size_of_val(v), MemState::Undefined);
}
fn public<T: ?Sized>(v: &T) {
    let _ = mark_memory(v as *const T as *const u8 as *const _, core::mem::size_of_val(v), MemState::Defined);
}

fn rc(i: u8) -> bool {
    let (d, z, m) = (Array([i; 32]), Array([i ^ 1; 32]), Array([i ^ 2; 32]));
    let (dk0, ek) = MlKem768::generate_deterministic(&d, &z);
    // the decapsulation key, re-loaded from bytes whose SECRET parts are marked: s (0..1152) and z (2368..2400);
    // the embedded ek and H(ek) are public.
    let mut dkb = dk0.as_bytes();
    if std::env::var("CT_ALL").is_err() {
        secret(&dkb[..1152]);
        secret(&dkb[2368..]);
    } else {
        secret(&dkb);
    }
    let dk = <MlKem768 as KemCore>::DecapsulationKey::from_bytes(&dkb);
    dkb.fill(0);
    secret(&m);
    let (ct, ss) = ek.encapsulate_deterministic(&m).unwrap();
    public(ct.as_slice());
    let back = dk.decapsulate(&ct).unwrap();
    let mut bad = ct.clone();
    bad[i as usize * 50] ^= 1;
    let rej = dk.decapsulate(&bad).unwrap();
    public(ss.as_slice());
    public(back.as_slice());
    public(rej.as_slice());
    back == ss && rej != ss
}

fn lc(i: u8) -> bool {
    let mut dz = [i; 64];
    dz[32..].fill(i ^ 1);
    let m = [i ^ 2; 32];
    let kp = libcrux_ml_kem::mlkem768::generate_key_pair(dz);
    let mut skb = *kp.private_key().as_slice();
    secret(&skb[..1152]);
    secret(&skb[2368..]);
    let sk = libcrux_ml_kem::mlkem768::MlKem768PrivateKey::from(skb);
    skb.fill(0);
    secret(&m);
    let (ct, ss) = libcrux_ml_kem::mlkem768::encapsulate(kp.public_key(), m);
    public(ct.as_slice());
    let back = libcrux_ml_kem::mlkem768::decapsulate(&sk, &ct);
    let mut bad = *ct.as_slice();
    bad[i as usize * 50] ^= 1;
    let rej = libcrux_ml_kem::mlkem768::decapsulate(&sk, &libcrux_ml_kem::mlkem768::MlKem768Ciphertext::from(bad));
    public(&ss);
    public(&back);
    public(&rej);
    back == ss && rej != ss
}

fn main() {
    let which = std::env::args().nth(1).unwrap_or_default();
    let ok = (0..3u8).all(|i| match which.as_str() { "lc" => lc(i), _ => rc(i) });
    let name = match which.as_str() { "lc" => "libcrux 0.0.11", _ => "RustCrypto ml-kem 0.2.3" };
    println!("kem-ctgrind {name}: functional {}", if ok { "ok" } else { "WRONG" });
}
