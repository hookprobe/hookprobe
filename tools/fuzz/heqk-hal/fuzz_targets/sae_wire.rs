#![no_main]
// ADR 0050 D4 step 5c: the WPA3-SAE station-frame walk that runs in el0-lansvc, on attacker-shaped Authentication
// frame bodies (any length, either H2E setting): never panics; the record survives encode/decode unchanged; an
// accepted commit always carries a scalar in 1 < s < r and an element on the curve, with a valid Rejected Groups
// list; an over-long body is always refused whole.
use hal::saewire as w;
use libfuzzer_sys::fuzz_target;
fuzz_target!(|d: &[u8]| {
    if d.is_empty() {
        return;
    }
    let h2e_ok = d[0] & 1 != 0;
    let body = &d[1..];
    let m = w::parse(body, h2e_ok);
    assert_eq!(w::decode(&w::encode(&m)), m);
    if body.len() > w::BODY_MAX {
        assert!(m.kind == w::K_DROP && m.reason == w::R_TOO_LONG);
    }
    if m.kind == w::K_COMMIT {
        assert!(w::scalar_in_range(&m.scalar) && w::on_curve(&m.element));
        assert!(m.rej_len <= 32 && m.rej_len % 2 == 0);
        assert!(!m.h2e || h2e_ok);
    }
    if m.kind == w::K_CONFIRM {
        assert_eq!(body.len(), 40);
    }
});
