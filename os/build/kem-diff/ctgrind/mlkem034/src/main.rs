//! ctgrind-style constant-time check of RustCrypto ml-kem 0.3.4 (see ../src/main.rs for the method). Secret:
//! the 64-byte decapsulation seed and the encapsulation randomness m. Run under valgrind --error-exitcode=9.
use crabgrind::memcheck::{mark_memory, MemState};

fn secret<T: ?Sized>(v: &T) {
    let _ = mark_memory(v as *const T as *const u8 as *const _, core::mem::size_of_val(v), MemState::Undefined);
}
fn public<T: ?Sized>(v: &T) {
    let _ = mark_memory(v as *const T as *const u8 as *const _, core::mem::size_of_val(v), MemState::Defined);
}

fn run(i: u8) -> bool {
    use ml_kem::{Decapsulate, KeyExport};
    let mut seed = [i; 64];
    seed[32..].fill(i ^ 1);
    let dk0 = ml_kem::ml_kem_768::DecapsulationKey::from_seed(seed.into());
    let ek = dk0.encapsulation_key().clone();
    // 0.3 keys are seed-based: the secret is the 64-byte seed the key is (re)built from
    let mut s2 = dk0.to_bytes();
    secret(&s2);
    let dk = ml_kem::ml_kem_768::DecapsulationKey::from_seed(s2);
    s2.fill(0);
    let m = ml_kem::B32::from([i ^ 2; 32]);
    secret(&m);
    let (ct, ss) = ek.encapsulate_deterministic(&m);
    public(ct.as_slice());
    let back = dk.decapsulate(&ct);
    let mut bad = ct.clone();
    bad[i as usize * 50] ^= 1;
    let rej = dk.decapsulate(&bad);
    public(ss.as_slice());
    public(back.as_slice());
    public(rej.as_slice());
    back == ss && rej != ss
}

fn main() {
    let ok = (0..3u8).all(run);
    println!("kem-ctgrind RustCrypto ml-kem 0.3.4: functional {}", if ok { "ok" } else { "WRONG" });
}
