#![no_main]
// The OS-update / boot verifier (boot_abi::verify, shared by HBoot and the kernel's os_image upload) over an
// attacker-shaped header + body. Input = an 8-byte floor, then a PayloadHeader, then the body. The verifier
// must never panic, and an Ok must be sound: the hash is OUR digest of exactly `size` body bytes, the SVN
// clears the floor, and both signatures verified (a random input reaching Ok would be a forgery).
use boot_abi::{sha256, verify, PayloadHeader};
use core::mem::size_of;
use libfuzzer_sys::fuzz_target;

const H: usize = size_of::<PayloadHeader>();

fuzz_target!(|data: &[u8]| {
    if data.len() < 8 + H {
        return;
    }
    let floor = u64::from_le_bytes(data[..8].try_into().unwrap());
    let mut raw = [0u8; H];
    raw.copy_from_slice(&data[8..8 + H]);
    // SAFETY: PayloadHeader is repr(C), all fields are plain integers / byte arrays (every bit pattern valid)
    let hdr: PayloadHeader = unsafe { core::ptr::read_unaligned(raw.as_ptr() as *const PayloadHeader) };
    let body = &data[8 + H..];
    let _ = verify::check_header(&hdr);
    match verify::verify_payload(&hdr, body, floor) {
        Ok(v) => {
            let size = hdr.size as usize;
            assert!(size > 0 && size <= body.len());
            assert_eq!(v.hash, sha256::digest(&body[..size]), "Ok with a hash that is not the body's");
            assert!(v.svn >= floor && v.svn == hdr.svn);
            panic!("verify_payload accepted fuzzer-built input — signature forgery or a broken check");
        }
        Err(_) => {}
    }
    // the streaming path (OS update): the caller's digest of the body; a wrong digest must never verify
    let d = sha256::digest(body);
    assert!(verify::verify_digest(&hdr, &d, floor).is_err(), "verify_digest accepted fuzzer-built input");
});
