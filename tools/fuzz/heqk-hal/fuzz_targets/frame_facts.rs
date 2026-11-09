#![no_main]
// Every frame from the air or the wire passes `facts` / `rx_tags` before policy: hostile by definition.
use libfuzzer_sys::fuzz_target;
fuzz_target!(|data: &[u8]| {
    let _ = hal::policy::facts(data);
    let _ = hal::policy::rx_tags(data);
    let _ = hal::inet_csum(data, 0);
});
