//! BCM2712 PM watchdog — the A/B trial-boot safety timer (reliability keystone).
//!
//! HBoot arms this right before it launches the kernel at EL1. If the kernel is
//! healthy it confirms via `hvc #1` (the EL2 gate disarms the watchdog in
//! `boot.s`); if the kernel HANGS or PANICS before confirming, the watchdog
//! fires and full-resets the SoC. On the reset the Pi firmware's one-shot
//! `tryboot` flag has been consumed, so it boots the KNOWN-GOOD slot
//! (config.txt) instead of the candidate (tryboot.txt) — automatic A/B
//! fallback with no mutable persistent store required in HBoot.
//!
//! The registers mirror `reset_platform` in boot.s exactly (same PM base,
//! offsets and password) — that path is already proven to reset this silicon;
//! it is literally this watchdog with a 10-tick (immediate) timeout.

use core::ptr::{read_volatile, write_volatile};

const PM_BASE: usize = 0x10_7D20_0000; // BCM2712 PM block (== reset_platform base)
const PM_RSTC: usize = PM_BASE + 0x1c;
const PM_WDOG: usize = PM_BASE + 0x24;

const PM_PASSWORD: u32 = 0x5a00_0000;
const RSTC_WRCFG_MASK: u32 = 0x0000_0030;
const RSTC_WRCFG_FULL_RESET: u32 = 0x0000_0020;
/// The 20-bit down-counter ticks at ~65536 Hz, so the max timeout is ~16 s.
const WDOG_TICKS_PER_SEC: u32 = 65536;
const WDOG_MAX_TICKS: u32 = 0x000f_ffff;

/// Arm the watchdog for `secs` seconds (clamped to the ~16 s hardware max).
/// After this, the SoC full-resets unless `disarm` is called (via the `hvc #1`
/// gate) before the timer expires. Returns the actual seconds armed.
pub fn arm(secs: u32) -> u32 {
    let ticks = secs
        .saturating_mul(WDOG_TICKS_PER_SEC)
        .clamp(1, WDOG_MAX_TICKS);
    unsafe {
        write_volatile(PM_WDOG as *mut u32, PM_PASSWORD | ticks);
        let cur = read_volatile(PM_RSTC as *const u32);
        let val = (cur & !RSTC_WRCFG_MASK) | PM_PASSWORD | RSTC_WRCFG_FULL_RESET;
        write_volatile(PM_RSTC as *mut u32, val);
    }
    (ticks / WDOG_TICKS_PER_SEC).max(1)
}

/// Disarm a running watchdog by clearing the RSTC write-config field (the
/// down-counter stops counting toward a reset). Idempotent and harmless if the
/// watchdog was never armed. Mirrors the Linux bcm2835_wdt stop sequence.
#[allow(dead_code)] // the live disarm runs in the EL2 hvc-gate (boot.s); kept for host/tests
pub fn disarm() {
    unsafe {
        let cur = read_volatile(PM_RSTC as *const u32);
        write_volatile(PM_RSTC as *mut u32, (cur & !RSTC_WRCFG_MASK) | PM_PASSWORD);
    }
}
