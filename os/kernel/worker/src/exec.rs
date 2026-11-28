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
    /// S2: entry of the hard-float engine image mapped in this worker's tables (0 = none).
    pub engine: usize,
    /// Published by the worker: CPACR_EL1 after it enabled FP/SIMD for itself, and ID_AA64ISAR0_EL1.
    pub cpacr: AtomicU64,
    pub isar0: AtomicU64,
    /// S1c: this core's timer period in counter ticks (0 = no timer). Set by core 0 before start.
    pub tick_period: u64,
    /// Published by the worker: timer expiries handled while idle (a heartbeat), and the counter value at the
    /// last one. A worker that stops ticking while idle is dead or wedged.
    pub ticks: AtomicU64,
    pub last_tick: AtomicU64,
    /// Published by the worker: the counter value when the current job started, 0 when idle. A busy worker does not
    /// tick (IRQs stay masked during a job), so core 0 tells "long job" from "dead" with this.
    pub busy_since: AtomicU64,
}

/// Execute one job. Pure except for the deliberate fault and the reads inside the granted window.
/// `engine` is the entry of the hard-float engine image (0 = none); it is only called on a worker core that has
/// enabled FP/SIMD for itself.
pub fn execute(j: &Job, window_base: u64, window_len: u64, engine: usize, clock: fn() -> u64) -> Done {
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
        #[cfg(all(feature = "mmu-probe", target_arch = "aarch64"))]
        op::PROBE_READ => {
            // SAFETY: deliberately unchecked; the worker's page tables decide (a fault parks this core).
            (status::OK, unsafe { core::ptr::read_volatile(j.a as usize as *const u64) })
        }
        #[cfg(all(feature = "mmu-probe", target_arch = "aarch64"))]
        op::PROBE_WRITE => {
            // SAFETY: as above.
            unsafe { core::ptr::write_volatile(j.a as usize as *mut u64, j.b) };
            (status::OK, 0)
        }
        op::GEMV_I8 => gemv(j, window_base, window_len, engine),
        op::SPIN => spin(j.a, j.b, clock),
        _ => (status::UNKNOWN_OP, 0),
    };
    done(j, st, value)
}

/// GEMV_I8: the parameter block, W and x must all lie in the read-only window; y lives on this core's stack.
fn gemv(j: &Job, window_base: u64, window_len: u64, engine: usize) -> (u32, u64) {
    let psz = core::mem::size_of::<job::GemvParams>() as u64;
    if !job::in_window(j.a, psz, 8, window_base, window_len) {
        return (status::OUT_OF_WINDOW, 0);
    }
    // SAFETY: inside the window, aligned, bounds-checked above.
    let p = unsafe { core::ptr::read_volatile(j.a as usize as *const job::GemvParams) };
    if p.rows == 0 || p.rows > job::GEMV_MAX_ROWS || p.cols == 0 || p.cols > job::GEMV_MAX_COLS || p.cols % 16 != 0 {
        return (status::BAD_PARAMS, 0);
    }
    let (rows, cols) = (p.rows as usize, p.cols as usize);
    let wlen = (rows * cols) as u64; // <= 256 * 4096: no overflow
    if !job::in_window(p.w, wlen, 1, window_base, window_len) || !job::in_window(p.x, cols as u64, 1, window_base, window_len) {
        return (status::OUT_OF_WINDOW, 0);
    }
    let mut y = [0i32; job::GEMV_MAX_ROWS as usize];
    let st = if p.path == job::path::SCALAR {
        // SAFETY: both ranges inside the window (checked above).
        let (w, x) = unsafe {
            (
                core::slice::from_raw_parts(p.w as usize as *const i8, rows * cols),
                core::slice::from_raw_parts(p.x as usize as *const i8, cols),
            )
        };
        job::gemv_i8_scalar(w, x, rows, cols, &mut y);
        status::OK
    } else if engine != 0 {
        // SAFETY: `engine` is the entry core 0 mapped into this worker's tables; FP/SIMD is enabled on this core
        // (`run`); the parameter block, W and x were checked against the window; y holds GEMV_MAX_ROWS.
        let f: job::EngineEntry = unsafe { core::mem::transmute::<usize, job::EngineEntry>(engine) };
        let params = j.a as usize as *const job::GemvParams;
        unsafe { f(op::GEMV_I8, params, y.as_mut_ptr(), y.len()) }
    } else {
        status::UNSUPPORTED
    };
    if st != status::OK {
        return (st, 0);
    }
    (status::OK, job::hash_i32(&y[..rows]))
}

/// SPIN: `iters` rounds of an integer mix, checking the clock every 1024 rounds against `budget` ticks.
fn spin(iters: u64, budget: u64, clock: fn() -> u64) -> (u32, u64) {
    let start = clock();
    let mut h: u64 = 0x9E37_79B9_7F4A_7C15;
    let mut i = 0u64;
    while i < iters {
        h = (h ^ i).wrapping_mul(0x0000_0100_0000_01b3).rotate_left(17);
        i += 1;
        if i % 1024 == 0 && clock().wrapping_sub(start) > budget {
            return (status::DEADLINE, i);
        }
    }
    (status::OK, h)
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
    // S2: enable FP/SIMD for THIS core only (CPACR_EL1.FPEN = 0b11). Core 0 is untouched and stays softfloat;
    // the worker's own Rust never uses the V registers, only the engine image does.
    let (cpacr, isar0): (u64, u64);
    // SAFETY: EL1 system registers of this core.
    unsafe {
        core::arch::asm!(
            "mrs {c}, cpacr_el1",
            "orr {c}, {c}, #(3 << 20)",
            "msr cpacr_el1, {c}",
            "isb",
            "mrs {i}, id_aa64isar0_el1",
            c = out(reg) cpacr, i = out(reg) isar0,
            options(nostack),
        )
    };
    ctx.cpacr.store(cpacr, Ordering::Relaxed);
    ctx.isar0.store(isar0, Ordering::Relaxed);
    // S1c: this core's own timer, a heartbeat while idle.
    if ctx.tick_period != 0 {
        // SAFETY: GICD base from core 0; banked PPI of this core.
        unsafe { crate::gic::enable_ppi(ctx.gicd, crate::timer::INTID) };
        crate::timer::arm(ctx.tick_period);
    }
    ctx.cpu_mask.store(mask, Ordering::Release);
    loop {
        while let Some(j) = ctx.jobs.pop() {
            ctx.busy_since.store(crate::timer::now().max(1), Ordering::Release);
            let d = execute(&j, ctx.window_base, ctx.window_len, ctx.engine, crate::timer::now);
            ctx.busy_since.store(0, Ordering::Release);
            while !ctx.done.push(d) {
                core::hint::spin_loop(); // core 0 drains results; the ring is sized for a burst
            }
            ctx.served.fetch_add(1, Ordering::Relaxed);
            // SAFETY: plain event signal for a core 0 waiting in wfe.
            unsafe { core::arch::asm!("sev", options(nomem, nostack)) };
        }
        // SAFETY: after enable_doorbell on this core. A doorbell rung while we were draining is
        // still pending, so this returns at once: no lost wake-up.
        let (period, ticks, last) = (ctx.tick_period, &ctx.ticks, &ctx.last_tick);
        unsafe {
            crate::gic::wait(ctx.gicc, |id| {
                if id == crate::timer::INTID && period != 0 {
                    // Re-arm before EOI (the timer is level-sensitive), then publish the heartbeat.
                    crate::timer::arm(period);
                    last.store(crate::timer::now(), Ordering::Relaxed);
                    ticks.fetch_add(1, Ordering::Release);
                }
            })
        };
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;

    static CLOCK: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    /// Advances by 1 on every read: a budget of N ticks lets about N*1024 rounds run.
    fn fake_clock() -> u64 {
        CLOCK.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    }

    #[test]
    fn spin_stops_at_its_budget() {
        let done = execute(&Job { id: 1, op: op::SPIN, a: 1 << 40, b: 10 }, 0, 0, 0, fake_clock);
        assert_eq!(done.status, status::DEADLINE);
        assert!(done.value >= 10 * 1024 && done.value <= 13 * 1024, "{}", done.value);
        let small = execute(&Job { id: 2, op: op::SPIN, a: 100, b: 10 }, 0, 0, 0, fake_clock);
        assert_eq!(small.status, status::OK);
    }

    #[test]
    fn execute_checks_the_window() {
        static DATA: [u64; 4] = [1, 2, 3, u64::MAX];
        let base = DATA.as_ptr() as u64;
        let ok = execute(&Job { id: 7, op: op::SUM64, a: base, b: 4 }, base, 32, 0, fake_clock);
        assert_eq!(ok, Done { id: 7, status: status::OK, value: 5 }); // wraps
        let out = execute(&Job { id: 8, op: op::SUM64, a: base, b: 5 }, base, 32, 0, fake_clock);
        assert_eq!(out.status, status::OUT_OF_WINDOW);
        let huge = execute(&Job { id: 9, op: op::SUM64, a: base, b: u64::MAX }, base, 32, 0, fake_clock);
        assert_eq!(huge.status, status::OUT_OF_WINDOW);
        assert_eq!(execute(&Job { id: 1, op: op::ECHO, a: 5, b: 3 }, 0, 0, 0, fake_clock).value, 6);
        assert_eq!(execute(&Job { id: 2, op: 42, a: 0, b: 0 }, 0, 0, 0, fake_clock).status, status::UNKNOWN_OP);
    }

    #[test]
    fn gemv_in_the_window() {
        #[repr(C, align(8))]
        struct Win([u8; 4096]);
        let mut win = Win([0; 4096]);
        let base = win.0.as_ptr() as u64;
        for (i, b) in win.0.iter_mut().enumerate().skip(64) {
            *b = (i as u8).wrapping_mul(29) ^ 0x5a;
        }
        let (rows, cols) = (8u32, 32u32);
        let p = job::GemvParams { w: base + 64, x: base + 64 + 256, rows, cols, path: job::path::SCALAR, _pad: 0 };
        unsafe { core::ptr::write(win.0.as_mut_ptr() as *mut job::GemvParams, p) };
        let d = execute(&Job { id: 1, op: op::GEMV_I8, a: base, b: 0 }, base, 4096, 0, fake_clock);
        let w: &[i8] = unsafe { core::slice::from_raw_parts((base + 64) as *const i8, 256) };
        let x: &[i8] = unsafe { core::slice::from_raw_parts((base + 320) as *const i8, 32) };
        let mut y = [0i32; 8];
        job::gemv_i8_scalar(w, x, 8, 32, &mut y);
        assert_eq!(d, Done { id: 1, status: status::OK, value: job::hash_i32(&y) });
        // NEON without an engine image: unsupported, never computed elsewhere.
        unsafe { (*(win.0.as_mut_ptr() as *mut job::GemvParams)).path = job::path::NEON };
        assert_eq!(execute(&Job { id: 2, op: op::GEMV_I8, a: base, b: 0 }, base, 4096, 0, fake_clock).status, status::UNSUPPORTED);
        // W running past the window.
        unsafe { (*(win.0.as_mut_ptr() as *mut job::GemvParams)).rows = 200 };
        assert_eq!(execute(&Job { id: 3, op: op::GEMV_I8, a: base, b: 0 }, base, 4096, 0, fake_clock).status, status::OUT_OF_WINDOW);
        // cols not a multiple of 16.
        unsafe { (*(win.0.as_mut_ptr() as *mut job::GemvParams)).cols = 30 };
        assert_eq!(execute(&Job { id: 4, op: op::GEMV_I8, a: base, b: 0 }, base, 4096, 0, fake_clock).status, status::BAD_PARAMS);
    }
}
