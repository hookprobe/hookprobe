//! Host stand-in for the kernel's `lanaccess::table()`, the one item `ownerjournal`'s replay calls (A-01 owner
//! exceptions, #1263). It hands out the REAL `hal::lanaccess::Table`, so the fuzzed replay adds / removes / clears
//! exactly as on the device; only the kernel module's beat counters and forwarding checks (which need `ratelimit` /
//! `devpolicy`) are left out — they are not part of the replay.
use hal::lanaccess::Table;

static mut TABLE: Table = Table::new();

pub fn table() -> &'static mut Table {
    unsafe { &mut *core::ptr::addr_of_mut!(TABLE) }
}
