#![no_main]
// ADR 0050 D4 step 5a: the WPA authenticator's station-frame parsing that runs in el0-lansvc (EAPOL-Key
// classification, M2 RSNE MFP walk) on attacker bytes: never panics, and a returned length always fits the frame.
use hal::eapolwire as e;
use libfuzzer_sys::fuzz_target;
fuzz_target!(|data: &[u8]| {
    if data.len() < 15 {
        return;
    }
    let sta: [u8; 6] = data[..6].try_into().unwrap();
    let replay = u64::from_le_bytes(data[7..15].try_into().unwrap());
    let f = &data[15..];
    if let Some(n) = e::eapol_key(f, &sta, data[6] & 1 != 0, replay) {
        assert!(14 + n <= f.len());
    }
    let _ = e::m2_mfpc(f, (data[6] as usize) & 0x0f);
});
