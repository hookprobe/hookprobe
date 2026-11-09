//! Runtime watchdog (production phase 3a): after the trial boot is confirmed (`hvc #1` disarms
//! HBoot's trial watchdog), the AP main loop keeps the BCM2712 PM watchdog armed through HBoot's
//! `hvc #3` gate. A loop that stops returning (a driver spin, a deadlock, a livelocked parser)
//! stops petting, and the SoC resets into the committed slot instead of sitting dead in a closet.
//!
//! Only armed when HBoot advertises `BOOT_FLAG_RT_WDOG` (an older HBoot treats any unknown
//! immediate as a reboot request). The pet is rate-limited to once a second; the hardware maximum
//! is ~16 s, so the longest blocking step anywhere in the loop must stay well below that — the
//! worst gap seen between pets is tracked and reported in the heartbeat (`[WDOG]`).
//!
//! Fail-open for customers: a watchdog reset reboots into the same committed slot (the device is
//! back forwarding in ~60 s); it never touches enforcement state.

use core::sync::atomic::{AtomicBool, AtomicU64, Ordering::Relaxed};

/// Seconds the PM watchdog is re-armed for on each pet (hardware max ~16).
pub const PET_SECS: u64 = 16;

static ARMED: AtomicBool = AtomicBool::new(false);
/// HBoot serves hvc #3 (read from the handoff by `start`).
static CAPABLE: AtomicBool = AtomicBool::new(false);
/// The trial boot was confirmed (`hvc #1`). Petting before that would keep the TRIAL watchdog
/// alive forever and defeat the A/B rollback, so nothing arms until this is set.
static CONFIRMED: AtomicBool = AtomicBool::new(false);
static PREV_WDOG_RESET: AtomicBool = AtomicBool::new(false);
static LAST_HVC: AtomicU64 = AtomicU64::new(0);
static LAST_CALL: AtomicU64 = AtomicU64::new(0);
static MAX_GAP: AtomicU64 = AtomicU64::new(0);
static PETS: AtomicU64 = AtomicU64::new(0);

/// Pure decision: arm only with an EL2 gate that advertises the pet hypercall.
pub fn should_arm(magic_ok: bool, el2_gate: u64, boot_flags: u64) -> bool {
    magic_ok && el2_gate != 0 && boot_flags & boot_abi::BOOT_FLAG_RT_WDOG != 0
}

/// Read the HBoot handoff once (after the trial confirm). Returns whether the watchdog is armed.
#[cfg(feature = "hboot")]
pub fn start(now: u64) -> bool {
    use boot_abi::{BootInfo, BOOTINFO_ADDR, BOOTINFO_MAGIC, BOOT_FLAG_WDOG_RESET};
    let bi = unsafe { &*(BOOTINFO_ADDR as *const BootInfo) };
    let ok = bi.magic == BOOTINFO_MAGIC;
    PREV_WDOG_RESET.store(ok && bi.boot_flags & BOOT_FLAG_WDOG_RESET != 0, Relaxed);
    CAPABLE.store(should_arm(ok, bi.el2_gate, bi.boot_flags), Relaxed);
    LAST_CALL.store(now, Relaxed);
    try_arm(now);
    CAPABLE.load(Relaxed)
}

/// Called by `boot_confirm` right after `hvc #1`.
pub fn note_confirmed() {
    CONFIRMED.store(true, Relaxed);
}

fn try_arm(now: u64) {
    if !ARMED.load(Relaxed) && CAPABLE.load(Relaxed) && CONFIRMED.load(Relaxed) {
        ARMED.store(true, Relaxed);
        #[cfg(feature = "hboot")]
        hvc_pet();
        LAST_HVC.store(now, Relaxed);
    }
}

/// Without HBoot (QEMU, firmware-direct) there is no EL2 gate: never armed.
#[cfg(not(feature = "hboot"))]
pub fn start(now: u64) -> bool {
    LAST_CALL.store(now, Relaxed);
    false
}

#[cfg(feature = "hboot")]
fn hvc_pet() {
    // SAFETY: hvc #3 is served by HBoot's EL2 gate (BOOT_FLAG_RT_WDOG checked by the caller);
    // it re-arms the PM watchdog and returns, clobbering only caller-saved registers.
    unsafe {
        core::arch::asm!("hvc #3", inout("x0") PET_SECS => _, clobber_abi("C"));
    }
    PETS.fetch_add(1, Relaxed);
}

/// Called every main-loop iteration (and inside known long steps). Tracks the worst gap between
/// calls; issues the hypercall at most once per second.
#[inline]
pub fn pet(now: u64, freq: u64) {
    let last = LAST_CALL.swap(now, Relaxed);
    let gap = now.wrapping_sub(last);
    if last != 0 && gap > MAX_GAP.load(Relaxed) {
        MAX_GAP.store(gap, Relaxed);
    }
    if !ARMED.load(Relaxed) {
        try_arm(now); // arms on the first call after the trial confirm
        return;
    }
    if now.wrapping_sub(LAST_HVC.load(Relaxed)) >= freq {
        #[cfg(feature = "hboot")]
        hvc_pet();
        LAST_HVC.store(now, Relaxed);
    }
}

/// (armed, hypercall pets, worst gap between loop calls in ms, previous reset was a watchdog reset)
pub fn stats(freq: u64) -> (bool, u64, u64, bool) {
    let f = freq.max(1);
    (ARMED.load(Relaxed), PETS.load(Relaxed), MAX_GAP.load(Relaxed) * 1000 / f, PREV_WDOG_RESET.load(Relaxed))
}

/// `[P-rtwdog]`: the arm decision and the gap accounting (no hypercall in QEMU).
pub fn selftest() -> bool {
    let f = boot_abi::BOOT_FLAG_RT_WDOG;
    let decide = should_arm(true, 1, f | boot_abi::BOOT_FLAG_TRIAL_WDOG)
        && !should_arm(true, 1, boot_abi::BOOT_FLAG_TRIAL_WDOG) // older HBoot: never hvc #3
        && !should_arm(true, 0, f) // no EL2 gate
        && !should_arm(false, 1, f); // no handoff
    // Gap accounting while disarmed: 3 calls 100 / 400 / 450 ticks at freq 1000 -> worst 300 ms.
    ARMED.store(false, Relaxed);
    LAST_CALL.store(0, Relaxed);
    MAX_GAP.store(0, Relaxed);
    pet(100, 1000);
    pet(400, 1000);
    pet(450, 1000);
    let (armed, _, gap_ms, _) = stats(1000);
    // Never armed before the trial confirm, even with a capable HBoot.
    CAPABLE.store(true, Relaxed);
    let was = CONFIRMED.swap(false, Relaxed);
    try_arm(500);
    let early = ARMED.load(Relaxed);
    CAPABLE.store(false, Relaxed);
    CONFIRMED.store(was, Relaxed);
    let ok = decide && !armed && gap_ms == 300 && !early;
    MAX_GAP.store(0, Relaxed);
    LAST_CALL.store(0, Relaxed);
    ok
}
