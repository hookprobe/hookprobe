//! The detectors' clock: the hardware counter, or — only while the detection benchmark replays a recorded
//! corpus (`detbench`) — the recorded timestamp of the frame being replayed, so rate / window / beacon
//! detectors see the traffic's real timing. Nothing else ever sets the override.

use core::sync::atomic::{AtomicU64, Ordering};

static OVERRIDE: AtomicU64 = AtomicU64::new(0);

#[inline]
fn hw() -> u64 {
    let v: u64;
    unsafe { core::arch::asm!("mrs {}, cntpct_el0", out(reg) v, options(nomem, nostack)) };
    v
}

/// Counter ticks (`cntfrq` per second).
#[inline]
pub fn ticks() -> u64 {
    match OVERRIDE.load(Ordering::Relaxed) {
        0 => hw(),
        t => t,
    }
}

#[inline]
pub fn freq() -> u64 {
    let v: u64;
    unsafe { core::arch::asm!("mrs {}, cntfrq_el0", out(reg) v, options(nomem, nostack)) };
    v
}

/// Replay only: pin the clock to `t` ticks (0 = back to the hardware counter).
#[cfg_attr(not(feature = "detbench"), allow(dead_code))]
pub fn replay_set(t: u64) {
    OVERRIDE.store(t, Ordering::Relaxed);
}
