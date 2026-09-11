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

/// P17 — grant EL0 read access to the monotonic physical counter
/// (`CNTPCT_EL0`) by setting `CNTKCTL_EL1.EL0PCTEN` (bit0). This is the ONE
/// register P17's userspace smoltcp service needs for a monotonic `Instant`.
///
/// Deliberately narrow: EL0PCTEN grants the *count* register only — NOT the
/// compare registers (EL0PTEN, bit9, stays 0) and NOT the event stream. EL0
/// cannot arm a timer, take a timer interrupt, or program the compare; it can
/// only read a free-running monotonic tick. `CNTFRQ_EL0` is already EL0-readable
/// on ARMv8, so the service can convert ticks to microseconds unaided.
///
/// SECURITY: exposing a high-resolution monotonic counter to EL0 is a timing
/// side-channel primitive. On a single-tenant edge box (one owner, one tenant,
/// no untrusted co-resident workloads) that is an accepted risk — see SECURITY.md
/// — and the ring header also publishes a kernel-stamped `time_us` fallback so
/// the grant can be revoked without breaking the service.
pub fn enable_el0_counter() {
    unsafe {
        let mut v: u64;
        core::arch::asm!("mrs {}, cntkctl_el1", out(reg) v);
        v |= 1; // EL0PCTEN = 1 (physical counter readable at EL0)
        core::arch::asm!("msr cntkctl_el1, {}", in(reg) v);
        core::arch::asm!("isb");
    }
}

/// Arm the generic-timer EVENT STREAM: CNTKCTL_EL1.EVNTEN=1 with EVNTI=10 (counter bit 10
/// → a `wfe` wakes every ~19 µs at 54 MHz), EVNTDIR=0. Lets IRQs-off polled loops park in
/// `wfe` instead of spinning the A76 at 100 % (the thermal fix that previously reached
/// only the prod drain loop). Idempotent; leaves EL0PCTEN and the compare bits untouched.
pub fn enable_event_stream() {
    unsafe {
        let mut v: u64;
        core::arch::asm!("mrs {}, cntkctl_el1", out(reg) v, options(nomem, nostack));
        v &= !0b1111_1000; // clear EVNTI(7:4) + EVNTDIR(3) + EVNTEN(2)
        v |= (10u64 << 4) | (1u64 << 2);
        core::arch::asm!("msr cntkctl_el1, {}", in(reg) v, options(nomem, nostack));
        core::arch::asm!("isb");
    }
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
