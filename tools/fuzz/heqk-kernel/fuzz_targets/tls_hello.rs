#![no_main]
// The first TLS record of every forwarded TCP flow (JA4 + SNI, rule 126 / Shield categories decide on it).
use heqk_kernel_fuzz::tlshello::client_hello;
use libfuzzer_sys::fuzz_target;
fuzz_target!(|data: &[u8]| {
    if let Some(h) = client_hello(data) {
        assert!((h.sni_len as usize) <= h.sni.len());
        let _ = h.ja4_str();
        let _ = h.sni_str();
    }
});
