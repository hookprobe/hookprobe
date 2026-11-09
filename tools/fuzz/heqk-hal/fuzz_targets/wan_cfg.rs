#![no_main]
// WAN.TXT is NOT signed (the flasher / Mission Control rewrite it): fully attacker-shaped input.
use libfuzzer_sys::fuzz_target;
fuzz_target!(|data: &[u8]| {
    let _ = hal::parse_wan_cfg(data);
    let _ = hal::parse_wan_link(data);
});
