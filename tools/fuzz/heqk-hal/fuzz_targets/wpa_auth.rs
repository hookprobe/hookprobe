#![no_main]
// ADR 0050 D4 step 5b: the authenticator's M2 / M4 crypto that runs in el0-lansvc, on attacker-shaped frames (both
// AKMs, any length): never panics; a returned PTK always verifies the same frame's MIC under its own KCK.
use hal::wpaauth as w;
use libfuzzer_sys::fuzz_target;
fuzz_target!(|d: &[u8]| {
    if d.len() < 2 {
        return;
    }
    let akm8 = d[0] & 1 != 0;
    let pmk = [d[1]; 32];
    let f = &d[2..];
    if let Some(p) = w::on_m2(&pmk, &[2, 0, 0, 0, 0, 1], &[2, 0, 0, 0, 0, 2], &[7; 32], akm8, f) {
        let kck: [u8; 16] = p[..16].try_into().unwrap();
        assert!(w::on_m4(&kck, akm8, f));
    }
    let _ = w::on_m4(&[d[1]; 16], akm8, f);
});
