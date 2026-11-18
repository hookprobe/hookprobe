//! Host stand-in for the kernel's `lanaccess::table()`, the one item `ownerjournal`'s replay calls (A-01 owner
//! exceptions, #1263). It hands out the REAL `hal::lanaccess::Table`, so the fuzzed replay adds / removes / clears
//! exactly as on the device; only the kernel module's beat counters and forwarding checks (which need `ratelimit` /
//! `devpolicy`) are left out — they are not part of the replay.
use hal::lanaccess::Table;

static mut TABLE: Table = Table::new();

pub fn table() -> &'static mut Table {
    unsafe { &mut *core::ptr::addr_of_mut!(TABLE) }
}

/// R4 (#1323): the replay asks whether one more exception of this scope fits before adding it. Same as the kernel's
/// `lanaccess::can_add`, with the clock fixed at 0 (the fuzz replay has no clock, so nothing expires): the room check
/// itself is the real `hal::lanaccess::Table::has_room`.
pub fn can_add(x: &hal::lanaccess::Exception) -> bool {
    let t = table();
    t.prune(0);
    t.has_room(x)
}
