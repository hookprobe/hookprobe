#![no_main]
// ADR 0059: the HQCFG1 bundle verifier on attacker-shaped bytes. Mode 0: raw (signature sector + bundle, as an
// uploader could send them) — must refuse cleanly. Mode 1: the fuzzed bundle is SIGNED with the public RFC 8032
// test key first, so the header / section table / canonical-text walk behind the signature gate is exercised too.
// Invariants: never panics; an accepted bundle's sections lie inside the buffer, are canonical and in kind order.
use heqk_kernel_fuzz::cfgbundle as cb;
use libfuzzer_sys::fuzz_target;

const SEED: [u8; 32] = [
    0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c, 0xc4, 0x44, 0x49, 0xc5, 0x69,
    0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae, 0x7f, 0x60,
];

fuzz_target!(|data: &[u8]| {
    if data.len() < 2 {
        return;
    }
    let (mode, floor) = (data[0] & 1, (data[1] & 7) as u64);
    let body = &data[2..];
    let kp = ed25519_compact::KeyPair::from_seed(ed25519_compact::Seed::new(SEED));
    let pk: [u8; 32] = *kp.pk;
    let dev = [0u8; 16];
    let mut sig = [0u8; 512];
    let bundle: &[u8] = if mode == 0 {
        let n = body.len().min(512);
        sig[..n].copy_from_slice(&body[..n]);
        &body[n..]
    } else {
        let d = boot_abi::sha256::digest(body);
        let mut m = [0u8; 10 + 32];
        m[..10].copy_from_slice(b"HQCFG1-SIG");
        m[10..].copy_from_slice(&d);
        let s = kp.sk.sign(&m[..], None);
        sig[..8].copy_from_slice(cb::SIG_MAGIC);
        sig[8] = 1;
        sig[9..13].copy_from_slice(&(body.len() as u32).to_le_bytes());
        sig[13..45].copy_from_slice(&d);
        sig[45..109].copy_from_slice(&s[..]);
        body
    };
    if let Ok(v) = cb::verify(bundle, &sig, &pk, &dev, floor) {
        assert!(v.generation > floor);
        let mut last = 0u8;
        for k in [cb::KIND_WAN, cb::KIND_WIFI, cb::KIND_POLICY] {
            if let Some(s) = v.section(k) {
                assert!(k > last);
                last = k;
                assert!(cb::canonical(k, s).is_ok());
                let (a, b) = (s.as_ptr() as usize, bundle.as_ptr() as usize);
                assert!(a >= b && a + s.len() <= b + bundle.len());
            }
        }
    }
});
