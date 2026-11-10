#![no_main]
// DNS messages from clients (queries) and from upstream (answers with compression pointers).
use heqk_kernel_fuzz::dnswire::{parse_query, read_name};
use libfuzzer_sys::fuzz_target;
fuzz_target!(|data: &[u8]| {
    let _ = parse_query(data);
    let mut out = [0u8; 256];
    if let Some((n, _)) = read_name(data, 12, &mut out, true) {
        assert!(n <= 255);
    }
    // a name starting anywhere (answer RRs, CNAME targets), pointers allowed
    if data.len() > 2 {
        let o = (data[0] as usize) % data.len();
        let _ = read_name(data, o, &mut out, true);
        let _ = read_name(data, o, &mut out, false);
    }
});
