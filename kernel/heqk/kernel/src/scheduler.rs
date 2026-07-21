//! Priority preemptive scheduler — arch-neutral. A thread's context is an opaque
//! `sp: usize`; the arch builds/saves/restores the real frame. Accessed only from
//! IRQ context (single core, non-reentrant), so no locking is needed.
//!
//! Selection: highest-priority *alive* thread; round-robin among equal priority
//! (so equal-priority threads share fairly and none starves). Slot 0 is the
//! idle/boot thread (priority 0, always alive) — the floor when all workers exit.

use core::ptr::{addr_of, addr_of_mut};

const MAX_THREADS: usize = 8;

static mut SP: [usize; MAX_THREADS] = [0; MAX_THREADS];
static mut PRIO: [u8; MAX_THREADS] = [0; MAX_THREADS];
static mut ALIVE: [bool; MAX_THREADS] = [false; MAX_THREADS];
static mut BLOCKED: [bool; MAX_THREADS] = [false; MAX_THREADS]; // waiting on IPC
static mut NUM: usize = 0;
static mut CUR: usize = 0;

/// Initialize with slot 0 = the idle/boot thread (priority 0, alive).
pub fn init() {
    unsafe {
        addr_of_mut!(ALIVE).cast::<bool>().add(0).write(true);
        addr_of_mut!(PRIO).cast::<u8>().add(0).write(0);
        addr_of_mut!(NUM).write(1);
        addr_of_mut!(CUR).write(0);
    }
}

/// Register a runnable thread by initial stack pointer + priority. Before IRQs on.
pub fn spawn(sp: usize, prio: u8) {
    unsafe {
        let n = addr_of!(NUM).read();
        if n >= MAX_THREADS {
            return;
        }
        addr_of_mut!(SP).cast::<usize>().add(n).write(sp);
        addr_of_mut!(PRIO).cast::<u8>().add(n).write(prio);
        addr_of_mut!(ALIVE).cast::<bool>().add(n).write(true);
        addr_of_mut!(NUM).write(n + 1);
    }
}

/// Mark the current thread dead; it is never scheduled again.
pub fn exit_current() {
    unsafe {
        let cur = addr_of!(CUR).read();
        addr_of_mut!(ALIVE).cast::<bool>().add(cur).write(false);
    }
}

/// The currently-running thread's id (scheduler slot).
pub fn current_tid() -> usize {
    unsafe { addr_of!(CUR).read() }
}

/// Block the current thread (waiting on IPC); it won't be scheduled until unblocked.
pub fn block_current() {
    unsafe {
        let cur = addr_of!(CUR).read();
        addr_of_mut!(BLOCKED).cast::<bool>().add(cur).write(true);
    }
}

/// Wake a blocked thread.
pub fn unblock(tid: usize) {
    unsafe { addr_of_mut!(BLOCKED).cast::<bool>().add(tid).write(false) };
}

/// Is `tid` currently blocked?
pub fn is_blocked(tid: usize) -> bool {
    unsafe { addr_of!(BLOCKED).cast::<bool>().add(tid).read() }
}

/// Timer-tick decision: save the interrupted context, pick the next thread
/// (highest priority alive; round-robin within a priority), return its context.
pub fn on_tick(current_sp: usize) -> usize {
    unsafe {
        let sp = addr_of_mut!(SP).cast::<usize>();
        let prio = addr_of!(PRIO).cast::<u8>();
        let alive = addr_of!(ALIVE).cast::<bool>();
        let blocked = addr_of!(BLOCKED).cast::<bool>();
        let num = addr_of!(NUM).read();
        let cur = addr_of!(CUR).read();
        sp.add(cur).write(current_sp);

        // Runnable = alive and not blocked. Highest priority among runnable.
        let runnable = |i: usize| alive.add(i).read() && !blocked.add(i).read();
        let mut maxp = 0u8;
        for i in 0..num {
            if runnable(i) {
                let p = prio.add(i).read();
                if p > maxp {
                    maxp = p;
                }
            }
        }
        // Round-robin among runnable threads at that priority (start after CUR).
        let mut next = cur;
        for k in 1..=num {
            let i = (cur + k) % num;
            if runnable(i) && prio.add(i).read() == maxp {
                next = i;
                break;
            }
        }
        // Fallback: if the chosen thread isn't actually runnable (e.g. `cur`
        // itself blocked/exited and nothing else was found), resume slot 0 —
        // the idle thread, which is always alive and never blocks. Prevents
        // ever returning the SP of a blocked/dead thread.
        if !runnable(next) {
            next = 0;
        }
        addr_of_mut!(CUR).write(next);
        sp.add(next).read()
    }
}

/// Count of live threads (including idle).
pub fn alive_workers() -> usize {
    unsafe {
        let alive = addr_of!(ALIVE).cast::<bool>();
        let num = addr_of!(NUM).read();
        (1..num).filter(|&i| alive.add(i).read()).count()
    }
}
