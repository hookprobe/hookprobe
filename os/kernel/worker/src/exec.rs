// SPDX-License-Identifier: AGPL-3.0-only
//! The worker loop: wait for the doorbell, drain the job ring, execute, publish results.

use crate::job::{self, op, status, Done, Job};
use crate::ring::{Consumer, Producer};
use core::sync::atomic::{AtomicU64, AtomicU8};

/// Everything a worker gets from core 0. Built by core 0 before start; afterwards core 0 only
/// reads the atomics. The ring ends are unique (see `Ring::split`).
pub struct Ctx {
    pub jobs: Consumer<Job>,
    pub done: Producer<Done>,
    /// Read-only data window: SUM64/FNV64 addresses must lie inside it.
    pub window_base: u64,
    pub window_len: u64,
    pub gicd: usize,
    pub gicc: usize,
    pub sgi: u32,
    /// Published by the worker: its GIC CPU-interface mask (0 until the doorbell is up).
    pub cpu_mask: AtomicU8,
    /// Jobs completed (diagnostics).
    pub served: AtomicU64,
}

/// Execute one job. Pure except for the deliberate fault and the reads inside the granted window.
pub fn execute(j: &Job, window_base: u64, window_len: u64) -> Done {
    let (st, value) = match j.op {
        op::ECHO => (status::OK, j.a ^ j.b),
        op::SUM64 => {
            let Some(bytes) = j.b.checked_mul(8) else { return done(j, status::OUT_OF_WINDOW, 0) };
            if !job::in_window(j.a, bytes, 8, window_base, window_len) {
                return done(j, status::OUT_OF_WINDOW, 0);
            }
            // SAFETY: inside the read-only window core 0 granted, aligned, bounds-checked above.
            let s = unsafe { core::slice::from_raw_parts(j.a as usize as *const u64, j.b as usize) };
            (status::OK, job::sum64(s))
        }
        op::FNV64 => {
            if !job::in_window(j.a, j.b, 1, window_base, window_len) {
                return done(j, status::OUT_OF_WINDOW, 0);
            }
            // SAFETY: as above.
            let s = unsafe { core::slice::from_raw_parts(j.a as usize as *const u8, j.b as usize) };
            (status::OK, job::fnv64(s))
        }
        op::FAULT => {
            #[cfg(target_arch = "aarch64")]
            // SAFETY: a deliberate exception; the worker vectors park this core.
            unsafe {
                core::arch::asm!("brk #0x77", options(nomem, nostack))
            };
            (status::UNKNOWN_OP, 0)
        }
        _ => (status::UNKNOWN_OP, 0),
    };
    done(j, st, value)
}

fn done(j: &Job, status: u32, value: u64) -> Done {
    Done { id: j.id, status, value }
}

/// The worker main loop. Never returns.
///
/// # Safety
/// Called once, on a worker core, with the context core 0 built for it.
#[cfg(target_arch = "aarch64")]
pub unsafe fn run(ctx: &mut Ctx) -> ! {
    use core::sync::atomic::Ordering;
    // SAFETY: bases from core 0's boot context; this core only.
    let mask = unsafe { crate::gic::enable_doorbell(ctx.gicd, ctx.gicc, ctx.sgi) };
    ctx.cpu_mask.store(mask, Ordering::Release);
    loop {
        while let Some(j) = ctx.jobs.pop() {
            let d = execute(&j, ctx.window_base, ctx.window_len);
            while !ctx.done.push(d) {
                core::hint::spin_loop(); // core 0 drains results; the ring is sized for a burst
            }
            ctx.served.fetch_add(1, Ordering::Relaxed);
            // SAFETY: plain event signal for a core 0 waiting in wfe.
            unsafe { core::arch::asm!("sev", options(nomem, nostack)) };
        }
        // SAFETY: after enable_doorbell on this core. A doorbell rung while we were draining is
        // still pending, so this returns at once: no lost wake-up.
        unsafe { crate::gic::wait(ctx.gicc) };
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn execute_checks_the_window() {
        static DATA: [u64; 4] = [1, 2, 3, u64::MAX];
        let base = DATA.as_ptr() as u64;
        let ok = execute(&Job { id: 7, op: op::SUM64, a: base, b: 4 }, base, 32);
        assert_eq!(ok, Done { id: 7, status: status::OK, value: 5 }); // wraps
        let out = execute(&Job { id: 8, op: op::SUM64, a: base, b: 5 }, base, 32);
        assert_eq!(out.status, status::OUT_OF_WINDOW);
        let huge = execute(&Job { id: 9, op: op::SUM64, a: base, b: u64::MAX }, base, 32);
        assert_eq!(huge.status, status::OUT_OF_WINDOW);
        assert_eq!(execute(&Job { id: 1, op: op::ECHO, a: 5, b: 3 }, 0, 0).value, 6);
        assert_eq!(execute(&Job { id: 2, op: 42, a: 0, b: 0 }, 0, 0).status, status::UNKNOWN_OP);
    }
}
