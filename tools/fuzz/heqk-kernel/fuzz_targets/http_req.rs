#![no_main]
// Mission Control request bytes straight off the socket (any LAN host), then the query string and the form body
// helpers every POST handler uses.
use heqk_kernel_fuzz::httpreq::{form_get, parse, query_str, query_u32};
use libfuzzer_sys::fuzz_target;
fuzz_target!(|data: &[u8]| {
    if let Ok(r) = parse(data) {
        assert!(r.consumed <= data.len());
        let mut qb = [0u8; 96];
        let _ = query_str(r.query, "id", &mut qb);
        let _ = query_u32(r.query, "off");
        let mut fb = [0u8; 192];
        for k in ["owner_key", "reason", "op", "target", "seq", "permanent", "confirm"] {
            let _ = form_get(r.body, k, &mut fb);
        }
    }
    let mut fb = [0u8; 192];
    let _ = form_get(data, "owner_key", &mut fb);
});
