#![no_std]
//! Exported entry points so the linker keeps keygen / encaps / decaps (size + symbol check only).
use libcrux_ml_kem::mlkem768;

#[no_mangle]
pub extern "C" fn hq_mlkem768_roundtrip(dz: &[u8; 64], m: &[u8; 32], ss_out: &mut [u8; 32]) -> bool {
    let kp = mlkem768::generate_key_pair(*dz);
    let (ct, ss) = mlkem768::encapsulate(kp.public_key(), *m);
    let back = mlkem768::decapsulate(kp.private_key(), &ct);
    ss_out.copy_from_slice(&ss);
    back == ss
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    loop {}
}
