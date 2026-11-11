#![no_main]
// ADR 0050 D4 step 3b: the PPPoE discovery tag walk (runs in el0-lansvc) on attacker frames, plus the kernel's
// decode of the EL0 record (lengths clamped).
use libfuzzer_sys::fuzz_target;
fuzz_target!(|data: &[u8]| {
    if data.len() < 2 {
        return;
    }
    let plen = u16::from_le_bytes([data[0], data[1]]) as usize;
    let d = hal::pppwire::disc_tags(&data[2..], plen);
    assert!(hal::pppwire::decode_disc(&hal::pppwire::encode_disc(&d)) == d);
    if data.len() >= hal::pppwire::DISC_LEN {
        let r = hal::pppwire::decode_disc(data[..hal::pppwire::DISC_LEN].try_into().unwrap());
        assert!(r.cookie_len <= 64 && r.relay_len <= 64 && r.ac_name_len <= 32 && (r.hu_len <= 32 || r.hu_len == 0xff));
    }
});
