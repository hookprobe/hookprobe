//! ARM generic timer (EL1 physical timer, CNTP_*). Fires as PPI 14 == GIC
//! INTID 30. Drives the preemptive scheduler tick.

use core::sync::atomic::{AtomicU64, Ordering};

/// GIC interrupt id of the non-secure EL1 physical timer (PPI 14 -> INTID 30).
pub const TIMER_INTID: u32 = 30;

static INTERVAL: AtomicU64 = AtomicU64::new(0);

#[inline]
fn cntfrq() -> u64 {
    let f: u64;
    unsafe { core::arch::asm!("mrs {}, cntfrq_el0", out(reg) f) };
    f
}

#[inline]
fn set_tval(ticks: u64) {
    unsafe { core::arch::asm!("msr cntp_tval_el0, {}", in(reg) ticks) };
}

/// The generic timer as a HAL `Timer`.
pub struct GenericTimer;

impl hal::Timer for GenericTimer {
    fn start(&self, hz: u32) {
        let interval = cntfrq() / hz as u64;
        INTERVAL.store(interval, Ordering::Relaxed);
        set_tval(interval);
        // CNTP_CTL_EL0: ENABLE=1, IMASK=0.
        unsafe { core::arch::asm!("msr cntp_ctl_el0, {}", in(reg) 1u64) };
    }
    fn rearm(&self) {
        set_tval(INTERVAL.load(Ordering::Relaxed));
    }
}
