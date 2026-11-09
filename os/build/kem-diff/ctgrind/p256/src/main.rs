//! ctgrind-style constant-time check of the device TLS key's ECDSA P-256 signing (p256 0.13.2, as tlsprov
//! uses it): the private scalar is marked UNDEFINED for valgrind memcheck; the message is public; the signature
//! is declared defined once produced. Any branch / address depending on the scalar is reported.
use crabgrind::memcheck::{mark_memory, MemState};
use p256::ecdsa::{signature::Signer, Signature, SigningKey};

fn mark<T: ?Sized>(v: &T, st: MemState) {
    let _ = mark_memory(v as *const T as *const u8 as *const _, core::mem::size_of_val(v), st);
}

fn main() {
    let mut ok = true;
    for i in 1..4u8 {
        let mut scalar = [i; 32];
        scalar[0] = 0x3a; // < n
        mark(&scalar, MemState::Undefined);
        let k = SigningKey::from_bytes((&scalar).into()).expect("valid scalar");
        let msg = [0x42u8 ^ i; 64];
        let sig: Signature = k.sign(&msg);
        let b = sig.to_bytes();
        mark(&b[..], MemState::Defined);
        ok &= b.iter().any(|&x| x != 0);
    }
    println!("p256-ctgrind: signatures {}", if ok { "produced" } else { "WRONG" });
}
