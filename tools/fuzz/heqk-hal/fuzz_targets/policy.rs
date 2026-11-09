#![no_main]
// POLICY.TXT (operator-signed, but parsed after verification on every boot and by the image factory): any
// input must parse or refuse, never panic; a parsed policy must evaluate any frame without panicking.
use libfuzzer_sys::fuzz_target;
fuzz_target!(|data: &[u8]| {
    let mut p = hal::policy::Policy::new();
    if hal::policy::parse_policy(data, &mut p).is_ok() {
        let f = [0u8; 60];
        if let Some(k) = hal::policy::facts(&f) {
            for i in [hal::policy::If::Lan, hal::policy::If::Wan, hal::policy::If::Mgmt, hal::policy::If::Eth1] {
                let _ = p.check(i, hal::policy::Dir::In, &k);
                let _ = p.check(i, hal::policy::Dir::Out, &k);
            }
            let _ = p.route(&k.src, &k.dst, &|_| true);
        }
    }
    let _ = hal::policy::parse_v6(data);
    let _ = hal::policy::parse_prefix(data);
});
