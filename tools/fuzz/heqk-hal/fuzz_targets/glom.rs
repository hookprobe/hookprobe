#![no_main]
// SDIO glom (superframe) descriptors and superframes from the Wi-Fi firmware.
use libfuzzer_sys::fuzz_target;
fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }
    let blk = [64usize, 128, 256, 512][(data[0] & 3) as usize];
    let mut plan = [0u16; hal::GLOM_MAX_SUBS];
    if let Some((n, _total)) = hal::glom_plan(&data[1..], blk, &mut plan) {
        let mut subs = [hal::GlomSub::default(); hal::GLOM_MAX_SUBS];
        let _ = hal::glom_split(&data[1..], &plan[..n], &mut subs);
    }
});
