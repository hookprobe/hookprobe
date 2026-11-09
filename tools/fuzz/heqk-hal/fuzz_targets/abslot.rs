#![no_main]
// A/B OTA slot derivation (hal::abslot) over an attacker-shaped "card": the eMMC driver's Gate-1 input for
// inactive-slot writes. The fuzzer supplies up to 64 sectors (sector k = bytes [k*512, k*512+512), missing
// sectors read as unreadable); any Some(run) must be a sane, non-overlapping range.
use libfuzzer_sys::fuzz_target;
fuzz_target!(|data: &[u8]| {
    let read = |lba: u64, b: &mut [u8; 512]| {
        let o = (lba as usize).checked_mul(512);
        match o.and_then(|o| data.get(o..o + 512)) {
            Some(s) => {
                b.copy_from_slice(s);
                true
            }
            None => false,
        }
    };
    if let Some(r) = hal::abslot::inactive_slot_run(read) {
        assert!(r.lo < r.hi && r.active_lo < r.active_hi);
        assert!(r.hi <= r.active_lo || r.active_hi <= r.lo, "inactive run overlaps the active slot");
        assert!(r.active == b'a' || r.active == b'b');
    }
});
