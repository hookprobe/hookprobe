#![no_main]
// SDPCM frame headers from the Wi-Fi firmware (hardware tag + software header): decode never panics, and an
// accepted header is internally consistent (header fits, data offset within the frame).
use libfuzzer_sys::fuzz_target;
fuzz_target!(|data: &[u8]| {
    if let Ok(Some(h)) = hal::sdpcm_hdr(data) {
        assert!(h.len as usize >= hal::SDPCM_HDRLEN);
        assert!(h.doff >= hal::SDPCM_HDRLEN && h.doff <= h.len as usize);
        assert!(h.chan < 16);
    }
});
