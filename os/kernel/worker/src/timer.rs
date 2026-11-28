// SPDX-License-Identifier: AGPL-3.0-only
//! This core's EL1 physical timer (CNTP, PPI INTID 30), as a worker uses it (ADR 0060 S1c). The registers are
//! banked per core: a worker arming its timer never touches core 0's scheduler tick. Taken like the doorbell:
//! IRQs stay masked, the pending timer wakes `wfi`, and the executive re-arms it before EOI.

/// GIC INTID of the EL1 physical timer (PPI 14).
pub const INTID: u32 = 30;

/// The system counter (CNTPCT_EL0).
#[inline]
pub fn now() -> u64 {
    let c: u64;
    // SAFETY: reading the counter has no side effects.
    unsafe { core::arch::asm!("isb", "mrs {}, cntpct_el0", out(reg) c, options(nomem, nostack)) };
    c
}

/// Counter frequency (CNTFRQ_EL0).
#[inline]
pub fn freq() -> u64 {
    let f: u64;
    // SAFETY: as above.
    unsafe { core::arch::asm!("mrs {}, cntfrq_el0", out(reg) f, options(nomem, nostack)) };
    f
}

/// Fire once, `ticks` counter ticks from now (also clears a pending expiry). ENABLE=1, IMASK=0.
#[inline]
pub fn arm(ticks: u64) {
    // SAFETY: this core's own timer registers.
    unsafe {
        core::arch::asm!(
            "msr cntp_tval_el0, {t}",
            "msr cntp_ctl_el0, {c}",
            "isb",
            t = in(reg) ticks, c = in(reg) 1u64,
            options(nomem, nostack),
        )
    };
}
