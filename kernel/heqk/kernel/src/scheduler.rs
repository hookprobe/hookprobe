//! Priority preemptive scheduler — arch-neutral. A thread's context is an opaque
//! `sp: usize`; the arch builds/saves/restores the real frame. Accessed only from
//! IRQ context (single core, non-reentrant), so no locking is needed.
//!
//! Selection: highest-priority *alive* thread; round-robin among equal priority
//! (so equal-priority threads share fairly and none starves). Slot 0 is the
//! idle/boot thread (priority 0, always alive) — the floor when all workers exit.

use core::ptr::{addr_of, addr_of_mut};

pub const MAX_THREADS: usize = 8;

static mut SP: [usize; MAX_THREADS] = [0; MAX_THREADS];
static mut PRIO: [u8; MAX_THREADS] = [0; MAX_THREADS];
static mut ALIVE: [bool; MAX_THREADS] = [false; MAX_THREADS];
static mut BLOCKED: [bool; MAX_THREADS] = [false; MAX_THREADS]; // waiting on IPC
// P7c step 3 — per-thread address space: raw TTBR0 value (page-table root | ASID
// << 48). 0 = the kernel/identity space (the arch switches to its own default).
static mut TTBR0: [u64; MAX_THREADS] = [0; MAX_THREADS];
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

/// Register a runnable thread by initial stack pointer + priority (kernel address
/// space). Before IRQs on. Returns `Some(tid)` (the slot), or `None` if full.
pub fn spawn(sp: usize, prio: u8) -> Option<usize> {
    spawn_as(sp, prio, 0)
}

/// Register a runnable thread that runs in a specific address space (raw TTBR0 =
/// root | ASID<<48; 0 = kernel space). Used for isolated EL0 driver servers.
/// CORE-8: returns `None` when the table is full instead of SILENTLY dropping the
/// thread. CORE-6: returns the assigned tid so the caller can arm a per-TCB restart
/// record (`set_restart`).
pub fn spawn_as(sp: usize, prio: u8, ttbr0: u64) -> Option<usize> {
    unsafe {
        let n = addr_of!(NUM).read();
        if n >= MAX_THREADS {
            return None;
        }
        addr_of_mut!(SP).cast::<usize>().add(n).write(sp);
        addr_of_mut!(PRIO).cast::<u8>().add(n).write(prio);
        addr_of_mut!(ALIVE).cast::<bool>().add(n).write(true);
        addr_of_mut!(TTBR0).cast::<u64>().add(n).write(ttbr0);
        addr_of_mut!(NUM).write(n + 1);
        Some(n)
    }
}

// CORE-6: per-TCB EL0 fault-restart records. Was a set of GLOBAL statics
// (EL0_RS_ENTRY/USP/KSTACK + one EL0_RESTARTS counter + EL0_SCHED_MODE), so with two
// scheduled EL0 TCBs a fault in one would restart it from the OTHER's entry/stack and
// share the restart budget. Keyed per slot, a fault restarts the FAULTING thread from
// ITS OWN params with ITS OWN budget.
#[derive(Clone, Copy)]
pub struct RestartRec {
    pub sched: bool,   // this TCB's faults restart/reschedule (vs cooperative longjmp)
    pub entry: usize,
    pub usp: usize,
    pub kstack: usize,
    pub used: u32,
}
const EMPTY_RESTART: RestartRec =
    RestartRec { sched: false, entry: 0, usp: 0, kstack: 0, used: 0 };
static mut RESTART: [RestartRec; MAX_THREADS] = [EMPTY_RESTART; MAX_THREADS];

/// Arm a scheduled EL0 TCB's fault-restart record (its faults now restart from these
/// params with a fresh budget, instead of the cooperative longjmp).
pub fn set_restart(tid: usize, entry: usize, usp: usize, kstack: usize) {
    if tid >= MAX_THREADS {
        return;
    }
    unsafe {
        addr_of_mut!(RESTART).cast::<RestartRec>().add(tid).write(RestartRec {
            sched: true,
            entry,
            usp,
            kstack,
            used: 0,
        });
    }
}
/// The restart record for `tid`, or `None` if it isn't a scheduled/armed TCB (in
/// which case a fault falls to the cooperative path).
pub fn restart_rec(tid: usize) -> Option<RestartRec> {
    if tid >= MAX_THREADS {
        return None;
    }
    let r = unsafe { addr_of!(RESTART).cast::<RestartRec>().add(tid).read() };
    if r.sched {
        Some(r)
    } else {
        None
    }
}
/// Increment and return `tid`'s restart count.
pub fn bump_restart(tid: usize) -> u32 {
    if tid >= MAX_THREADS {
        return u32::MAX;
    }
    unsafe {
        let p = addr_of_mut!(RESTART).cast::<RestartRec>().add(tid);
        let mut r = p.read();
        r.used += 1;
        p.write(r);
        r.used
    }
}
/// `tid`'s current restart count (for the P7c report), 0 if none.
pub fn restart_used(tid: usize) -> u32 {
    if tid >= MAX_THREADS {
        return 0;
    }
    unsafe { addr_of!(RESTART).cast::<RestartRec>().add(tid).read().used }
}
/// DISARM a TCB's restart record on kill: clear `sched` so a reused slot can't
/// inherit the scheduled-restart behavior, but KEEP `used` so the fault-restart
/// report can still read how many restarts happened before the kill. (A genuinely
/// reused EL0 slot gets a fresh record via `set_restart`, which resets `used`.)
pub fn clear_restart(tid: usize) {
    if tid >= MAX_THREADS {
        return;
    }
    unsafe {
        let p = addr_of_mut!(RESTART).cast::<RestartRec>().add(tid);
        let mut r = p.read();
        r.sched = false;
        p.write(r);
    }
}

/// Replace a thread's saved context pointer (used to RESTART a faulted EL0
/// driver: rebuild a fresh frame and point the thread at it). P7c step 4b.
/// CORE-8: bounds-check `tid` — a stray/attacker-influenced tid must never write
/// past the fixed-size SP table (latent OOB `static mut` write).
pub fn set_sp(tid: usize, sp: usize) {
    if tid >= MAX_THREADS {
        return;
    }
    unsafe { addr_of_mut!(SP).cast::<usize>().add(tid).write(sp) };
}

/// The TTBR0 (address space) of the currently-running thread (0 = kernel space).
pub fn current_ttbr0() -> u64 {
    unsafe {
        let cur = addr_of!(CUR).read();
        addr_of!(TTBR0).cast::<u64>().add(cur).read()
    }
}

/// Mark the current thread dead; it is never scheduled again.
pub fn exit_current() {
    unsafe {
        let cur = addr_of!(CUR).read();
        addr_of_mut!(ALIVE).cast::<bool>().add(cur).write(false);
    }
}

/// Kill every non-idle thread (slots 1..num) so only the idle/boot thread (slot
/// 0, always alive, priority 0) remains runnable. Used to tear a scheduler demo
/// down DETERMINISTICALLY: an always-runnable TCB (e.g. the P7c-4c EL0 loop
/// driver, which never exits on its own) would otherwise starve the idle thread
/// that runs the demo's wait loop, so the demo could never return. After this the
/// idle thread resumes on the next tick and the demo completes. P7c-4c.
pub fn stop_workers() {
    unsafe {
        let alive = addr_of_mut!(ALIVE).cast::<bool>();
        let num = addr_of!(NUM).read();
        for i in 1..num {
            alive.add(i).write(false);
        }
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

/// Wake a blocked thread. CORE-8: bounds-checked.
pub fn unblock(tid: usize) {
    if tid >= MAX_THREADS {
        return;
    }
    unsafe { addr_of_mut!(BLOCKED).cast::<bool>().add(tid).write(false) };
}

/// Is `tid` currently blocked? CORE-8: bounds-checked (out-of-range => not blocked).
pub fn is_blocked(tid: usize) -> bool {
    if tid >= MAX_THREADS {
        return false;
    }
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
