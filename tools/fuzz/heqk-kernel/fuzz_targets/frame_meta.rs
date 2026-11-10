#![no_main]
// Every Ethernet frame the IDS sees.
use libfuzzer_sys::fuzz_target;
fuzz_target!(|data: &[u8]| {
    let _ = heqk_kernel_fuzz::net::parse(data);
});
