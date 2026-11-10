#![no_main]
// DNS messages from clients (queries) and from upstream (answers with compression pointers).
use heqk_kernel_fuzz::dnswire::{parse_query, read_name, walk_answers, WALK0};
use libfuzzer_sys::fuzz_target;
fuzz_target!(|data: &[u8]| {
    let _ = parse_query(data);
    // the upstream answer walk Shield runs (now in the EL0 LAN-services server)
    let mut w = WALK0;
    if walk_answers(data, &mut w).is_some() {
        assert!(w.qnl <= 255 && w.qend <= data.len() && w.ncname <= w.cnames.len());
    }
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
