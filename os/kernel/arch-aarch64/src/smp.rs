// SPDX-License-Identifier: AGPL-3.0-only
//! ADR 0060 amendment (2026-11-26) stage S0a: secondary-core start on tiers WITHOUT HBoot
//! (QEMU `virt` with no EL2, OCI A1 EL1 guest). Core 0 starts each secondary with PSCI
//! `CPU_ON` over HVC; the secondary enters [`secondary_entry`] at EL1 with its MMU off,
//! takes core 0's stage-1 translation regime (MAIR/TCR/TTBR0/SCTLR, read on core 0 at start
//! time), installs its own fault vectors, publishes `ALIVE` and parks in `wfe`.
//!
//! **Worker cores never execute kernel code.** Nothing here touches a kernel `static mut`;
//! the only shared state is one [`BootBlock`] per core, written by core 0 before start and
//! afterwards only by its own core (single writer per field group). This keeps the
//! single-core contract of `ARCHITECTURE.md` true for the kernel, which still runs only on
//! core 0 (ADR 0060 amendment W1).
//!
//! NOT the CM5 path: there HBoot starts cores over SMC and installs stage-2 first
//! (stage S0b, `[P-smp-stage2]`). The kernel refuses `smpboot` together with `cm5`.
//!
//! Known limit carried to S1: core 0's TLB maintenance is core-local (`tlbi vmalle1`), so a
//! worker that does more than park must get broadcast invalidation or private tables.

use core::sync::atomic::{AtomicU64, Ordering};

/// Status values in [`BootBlock::status`].
pub const ST_OFF: u64 = 0;
/// Started over PSCI, not yet in Rust.
pub const ST_STARTED: u64 = 1;
/// In Rust at EL1, MMU on, parked in `wfe`.
pub const ST_ALIVE: u64 = 2;
/// Took an exception; `esr` holds ESR_EL1; the core is parked with interrupts masked.
pub const ST_FAULT: u64 = 3;

/// Maximum cores this stage handles (QEMU gate uses 4; CM5 has 4).
pub const MAX_CORES: usize = 8;
const STACK_SIZE: usize = 16 * 1024;

/// Per-core start block. Read by the secondary with its MMU and caches OFF, so core 0
/// cleans it to the point of coherency before `CPU_ON`. Field offsets are used by the
/// assembly below: keep the layout in sync.
#[repr(C, align(64))]
pub struct BootBlock {
    pub stack_top: u64, // 0
    pub mair: u64,      // 8
    pub tcr: u64,       // 16
    pub ttbr0: u64,     // 24
    pub sctlr: u64,     // 32
    pub vbar: u64,      // 40
    /// Core 0 -> worker: a value the worker must transform (proves it ran Rust with MMU on).
    pub challenge: u64, // 48
    /// Core 0 -> worker: 1 = execute `brk` after coming alive (fault-containment proof).
    pub fault_test: u64, // 56
    // ---- written by the worker only ----
    pub status: AtomicU64,   // 64
    pub mpidr: AtomicU64,    // 72
    pub response: AtomicU64, // 80
    pub esr: AtomicU64,      // 88
    pub el: AtomicU64,       // 96
}

const ZERO_BLOCK: BootBlock = BootBlock {
    stack_top: 0,
    mair: 0,
    tcr: 0,
    ttbr0: 0,
    sctlr: 0,
    vbar: 0,
    challenge: 0,
    fault_test: 0,
    status: AtomicU64::new(ST_OFF),
    mpidr: AtomicU64::new(0),
    response: AtomicU64::new(0),
    esr: AtomicU64::new(0),
    el: AtomicU64::new(0),
};

#[repr(C, align(16))]
struct Stack([u8; STACK_SIZE]);

static mut BLOCKS: [BootBlock; MAX_CORES] = [ZERO_BLOCK; MAX_CORES];
static mut STACKS: [Stack; MAX_CORES] = [const { Stack([0; STACK_SIZE]) }; MAX_CORES];

/// The response a worker must publish for `challenge`.
pub const fn expected_response(challenge: u64, mpidr: u64) -> u64 {
    challenge.wrapping_mul(0x9E37_79B9_7F4A_7C15) ^ mpidr
}

core::arch::global_asm!(
    r#"
.section .text
.balign 4096
.global __smp_worker_vectors
__smp_worker_vectors:
    .rept 16
    .balign 0x80
    b       __smp_worker_fault
    .endr

// Any exception on a worker core: record ESR_EL1 and FAULT in its own block (TPIDR_EL1),
// then park with everything masked. Never returns, never touches kernel state.
__smp_worker_fault:
    msr     daifset, #0xf
    mrs     x0, tpidr_el1
    cbz     x0, 2f
    mrs     x1, esr_el1
    str     x1, [x0, #88]
    add     x2, x0, #64
    mov     x1, #3
    stlr    x1, [x2]
    dsb     ish
    sev
2:  wfe
    b       2b

// PSCI CPU_ON entry: EL1, MMU off, x0 = &BootBlock (identity-mapped PA == VA).
.global __smp_secondary_entry
__smp_secondary_entry:
    msr     daifset, #0xf
    msr     tpidr_el1, x0
    ldr     x1, [x0, #0]
    mov     sp, x1
    ldr     x1, [x0, #40]
    msr     vbar_el1, x1
    ldr     x1, [x0, #8]
    msr     mair_el1, x1
    ldr     x1, [x0, #16]
    msr     tcr_el1, x1
    ldr     x1, [x0, #24]
    msr     ttbr0_el1, x1
    dsb     ish
    isb
    tlbi    vmalle1
    dsb     ish
    isb
    ldr     x1, [x0, #32]
    msr     sctlr_el1, x1
    isb
    bl      __smp_secondary_rust
3:  wfe
    b       3b
"#
);

extern "C" {
    fn __smp_secondary_entry();
    static __smp_worker_vectors: u8;
}

/// First Rust on a worker core. MMU and caches are on; the block is reached through
/// TPIDR_EL1. Only this core's own block is written.
#[no_mangle]
extern "C" fn __smp_secondary_rust(block: *mut BootBlock) -> ! {
    let b = unsafe { &*block };
    let mpidr: u64;
    let el: u64;
    unsafe {
        core::arch::asm!("mrs {}, mpidr_el1", out(reg) mpidr, options(nomem, nostack));
        core::arch::asm!("mrs {}, CurrentEL", out(reg) el, options(nomem, nostack));
    }
    let mpidr = mpidr & 0xff_00ff_ffff;
    b.mpidr.store(mpidr, Ordering::Relaxed);
    b.el.store((el >> 2) & 3, Ordering::Relaxed);
    b.response.store(expected_response(b.challenge, mpidr), Ordering::Relaxed);
    b.status.store(ST_ALIVE, Ordering::Release);
    unsafe { core::arch::asm!("dsb ish", "sev", options(nomem, nostack)) };
    if b.fault_test == 1 {
        // Deliberate fault: the worker vectors must contain it (status -> FAULT, ESR EC 0x3c).
        unsafe { core::arch::asm!("brk #0x5a", options(nomem, nostack)) };
    }
    loop {
        unsafe { core::arch::asm!("wfe", options(nomem, nostack)) };
    }
}

/// PSCI CPU_ON (SMC64 id 0xC400_0003) over HVC: start the core with affinity `mpidr` at physical
/// `entry` with `ctx` in its x0. Returns 0 SUCCESS, -2 INVALID_PARAMETERS (no such core),
/// -4 ALREADY_ON, -5 ON_PENDING, -9 INVALID_ADDRESS. A PSCI function id, so safe on a conduit
/// without SMCCC 1.1 (see `smccc.rs`). The conduit is HVC on QEMU `virt` and OCI A1.
fn psci_cpu_on(mpidr: u64, entry: u64, ctx: u64) -> i64 {
    let mut x0: u64 = 0xC400_0003;
    unsafe {
        core::arch::asm!(
            "hvc #0",
            inout("x0") x0, inout("x1") mpidr => _, inout("x2") entry => _, inout("x3") ctx => _,
            out("x4") _, out("x5") _, out("x6") _, out("x7") _, out("x8") _, out("x9") _,
            out("x10") _, out("x11") _, out("x12") _, out("x13") _, out("x14") _,
            out("x15") _, out("x16") _, out("x17") _,
            options(nostack),
        );
    }
    x0 as i64
}

/// Clean `[addr, addr+len)` to the point of coherency (the worker reads it with caches off).
fn clean_to_poc(addr: usize, len: usize) {
    let line: usize = 64;
    let mut a = addr & !(line - 1);
    while a < addr + len {
        unsafe { core::arch::asm!("dc cvac, {}", in(reg) a, options(nostack)) };
        a += line;
    }
    unsafe { core::arch::asm!("dsb ish", options(nostack)) };
}

/// Outcome of starting one core.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StartResult {
    /// PSCI accepted and the worker published ALIVE (or FAULT, for the fault test).
    Up,
    /// PSCI returned this negative error (e.g. -2 INVALID_PARAMETERS: no such core).
    Refused(i64),
    /// PSCI accepted, but the worker never published within the timeout.
    Timeout,
}

/// Start the core with affinity `mpidr` as worker `idx` (1..MAX_CORES). Must be called on
/// core 0 while it runs on the kernel's own translation table (before any EL0 task swaps
/// TTBR0), because the worker copies core 0's live MAIR/TCR/TTBR0/SCTLR.
///
/// # Safety
/// Core 0 only; `idx` must not be started twice.
pub unsafe fn start_core(idx: usize, mpidr: u64, challenge: u64, fault_test: bool) -> StartResult {
    assert!(idx > 0 && idx < MAX_CORES);
    let b = &mut *core::ptr::addr_of_mut!(BLOCKS[idx]);
    let stack = core::ptr::addr_of_mut!(STACKS[idx]) as usize;
    let (mair, tcr, ttbr0, sctlr): (u64, u64, u64, u64);
    core::arch::asm!("mrs {}, mair_el1", out(reg) mair, options(nomem, nostack));
    core::arch::asm!("mrs {}, tcr_el1", out(reg) tcr, options(nomem, nostack));
    core::arch::asm!("mrs {}, ttbr0_el1", out(reg) ttbr0, options(nomem, nostack));
    core::arch::asm!("mrs {}, sctlr_el1", out(reg) sctlr, options(nomem, nostack));
    b.stack_top = (stack + STACK_SIZE) as u64;
    b.mair = mair;
    b.tcr = tcr;
    b.ttbr0 = ttbr0;
    b.sctlr = sctlr;
    b.vbar = core::ptr::addr_of!(__smp_worker_vectors) as u64;
    b.challenge = challenge;
    b.fault_test = fault_test as u64;
    b.status.store(ST_STARTED, Ordering::Relaxed);
    b.mpidr.store(0, Ordering::Relaxed);
    b.response.store(0, Ordering::Relaxed);
    b.esr.store(0, Ordering::Relaxed);
    clean_to_poc(b as *const BootBlock as usize, core::mem::size_of::<BootBlock>());

    let rc = psci_cpu_on(mpidr, __smp_secondary_entry as *const () as usize as u64, b as *const BootBlock as u64);
    if rc != 0 {
        b.status.store(ST_OFF, Ordering::Relaxed);
        return StartResult::Refused(rc);
    }
    // Bounded wait: 2 s of the generic counter (TCG can be slow to schedule a new vCPU).
    let (freq, t0): (u64, u64);
    core::arch::asm!("mrs {}, cntfrq_el0", out(reg) freq, options(nomem, nostack));
    core::arch::asm!("mrs {}, cntpct_el0", out(reg) t0, options(nomem, nostack));
    loop {
        let s = b.status.load(Ordering::Acquire);
        if s == ST_ALIVE || s == ST_FAULT {
            if fault_test && s == ST_ALIVE {
                // The fault comes right after ALIVE; keep waiting for it.
            } else {
                return StartResult::Up;
            }
        }
        let now: u64;
        core::arch::asm!("mrs {}, cntpct_el0", out(reg) now, options(nomem, nostack));
        if now.wrapping_sub(t0) > freq.saturating_mul(2) {
            return StartResult::Timeout;
        }
        core::hint::spin_loop();
    }
}

/// Read-only view of worker `idx`'s block (core 0 side).
pub fn block(idx: usize) -> &'static BootBlock {
    unsafe { &*core::ptr::addr_of!(BLOCKS[idx]) }
}
