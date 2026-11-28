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
//! S1b: every worker runs on its own private stage-1 tables (`build_worker_tables`), built by
//! core 0 before start and never changed, so core 0's core-local TLB maintenance (`tlbi vmalle1`)
//! cannot leave a worker with stale translations, and kernel .data/.bss is unmapped for workers.

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
const STACK_SIZE: usize = 64 * 1024; // S2b: the engine's load path (verify + admit) runs here too

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
    /// Core 0 -> worker: `*mut heqk_worker::exec::Ctx`, or 0 to park after start (S0a only).
    pub worker: u64, // 104
    /// Written by the fault stub: FAR_EL1 of the faulting access.
    pub far: AtomicU64, // 112
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
    worker: 0,
    far: AtomicU64::new(0),
};

/// Everything one worker core may write, in one page-aligned, page-multiple area (S1b): its boot
/// block (first, so TPIDR_EL1 points at both), its two rings, its executive context and its stack.
/// The worker's private tables map exactly this area read-write and no other kernel data.
#[repr(C, align(4096))]
struct CoreShared {
    block: BootBlock,
    jobs: Ring<Job>,
    done: Ring<Done>,
    ctx: core::mem::MaybeUninit<Ctx>,
    stack: [u8; STACK_SIZE],
}

static mut CORES: [CoreShared; MAX_CORES] = [const {
    CoreShared {
        block: ZERO_BLOCK,
        jobs: Ring::new(),
        done: Ring::new(),
        ctx: core::mem::MaybeUninit::uninit(),
        stack: [0; STACK_SIZE],
    }
}; MAX_CORES];

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
    mrs     x1, far_el1
    str     x1, [x0, #112]
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
    if b.worker != 0 {
        // S1: hand the core to the worker executive (heqk-worker, no kernel code reachable).
        // SAFETY: core 0 built this context for this core only and never touches it again except
        // through its atomics.
        unsafe { heqk_worker::exec::run(&mut *(b.worker as usize as *mut heqk_worker::exec::Ctx)) }
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
pub unsafe fn start_core(idx: usize, mpidr: u64, challenge: u64, fault_test: bool, worker: Option<Port>) -> (StartResult, Option<Port>) {
    assert!(idx > 0 && idx < MAX_CORES);
    let b = &mut *core::ptr::addr_of_mut!(CORES[idx].block);
    let stack = core::ptr::addr_of_mut!(CORES[idx].stack) as usize;
    let (mair, tcr, sctlr): (u64, u64, u64);
    core::arch::asm!("mrs {}, mair_el1", out(reg) mair, options(nomem, nostack));
    core::arch::asm!("mrs {}, tcr_el1", out(reg) tcr, options(nomem, nostack));
    core::arch::asm!("mrs {}, sctlr_el1", out(reg) sctlr, options(nomem, nostack));
    // S1b: the worker runs on its own tables, never core 0's (see `build_worker_tables`).
    let Some(ttbr0) = build_worker_tables(idx) else { return (StartResult::Refused(-100), None) };
    b.stack_top = (stack + STACK_SIZE) as u64;
    b.mair = mair;
    b.tcr = tcr;
    b.ttbr0 = ttbr0;
    b.sctlr = sctlr;
    b.vbar = core::ptr::addr_of!(__smp_worker_vectors) as u64;
    b.challenge = challenge;
    b.fault_test = fault_test as u64;
    b.worker = worker.as_ref().map_or(0, |p| p.ctx as u64);
    b.status.store(ST_STARTED, Ordering::Relaxed);
    b.mpidr.store(0, Ordering::Relaxed);
    b.response.store(0, Ordering::Relaxed);
    b.esr.store(0, Ordering::Relaxed);
    b.far.store(0, Ordering::Relaxed);
    clean_to_poc(b as *const BootBlock as usize, core::mem::size_of::<BootBlock>());

    let rc = psci_cpu_on(mpidr, __smp_secondary_entry as *const () as usize as u64, b as *const BootBlock as u64);
    if rc != 0 {
        b.status.store(ST_OFF, Ordering::Relaxed);
        return (StartResult::Refused(rc), None);
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
                return (StartResult::Up, worker);
            }
        }
        let now: u64;
        core::arch::asm!("mrs {}, cntpct_el0", out(reg) now, options(nomem, nostack));
        if now.wrapping_sub(t0) > freq.saturating_mul(2) {
            return (StartResult::Timeout, None);
        }
        core::hint::spin_loop();
    }
}

/// Read-only view of worker `idx`'s block (core 0 side).
pub fn block(idx: usize) -> &'static BootBlock {
    unsafe { &*core::ptr::addr_of!(CORES[idx].block) }
}

// ------------------------------------------------------------------------------------------------
// S1b: private stage-1 tables per worker core. Built by core 0 from a pool the workers cannot
// reach (the pool is not mapped in any worker table), never changed after start, so a worker needs
// no TLB maintenance and core 0's core-local `tlbi` cannot leave it stale. Identity mapping, the
// granule and VA size of core 0's TCR (4 KiB, 39-bit, walk from L1); MAIR attr0 Device, attr1 Normal.
//
//   kernel .text            read-only, executable at EL1   (the worker's code lives in the image)
//   kernel .rodata          read-only, never executable    (constants the compiled code reads)
//   CORES[idx]              read-write, never executable   (this core's block, rings, context, stack)
//   WINDOW                  read-only, never executable    (core 0's shared data)
//   GICD, GICC (one page each)  Device read-write          (the doorbell)
//   everything else         unmapped: kernel .data/.bss, other cores' areas, the table pool, MMIO

const PAGE: usize = 4096;
const DESC: u64 = 0b11; // table (L1/L2) or page (L3)
const AF: u64 = 1 << 10;
const SH_IS: u64 = 0b11 << 8;
const AP_RO: u64 = 0b10 << 6;
const PXN: u64 = 1 << 53;
const UXN: u64 = 1 << 54;
const ATTR_DEVICE: u64 = 0 << 2;
const ATTR_NORMAL: u64 = 1 << 2;
const ADDR: u64 = 0x0000_FFFF_FFFF_F000;

const TEXT: u64 = ATTR_NORMAL | SH_IS | AF | AP_RO | UXN;
const RODATA: u64 = ATTR_NORMAL | SH_IS | AF | AP_RO | PXN | UXN;
const RW_DATA: u64 = ATTR_NORMAL | SH_IS | AF | PXN | UXN;
const DEVICE: u64 = ATTR_DEVICE | AF | PXN | UXN;

#[repr(C, align(4096))]
struct Table([u64; 512]);
const POOL: usize = 96;
static mut TABLES: [Table; POOL] = [const { Table([0; 512]) }; POOL];
static TABLES_NEXT: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);

extern "C" {
    static __text_start: u8;
    static __text_end: u8;
    static __rodata_end: u8;
}

fn alloc_table() -> Option<*mut u64> {
    let i = TABLES_NEXT.fetch_add(1, Ordering::Relaxed);
    if i >= POOL {
        return None;
    }
    // Fresh from .bss and never reused, so already zero (all entries invalid).
    Some(unsafe { core::ptr::addr_of_mut!(TABLES[i]) } as *mut u64)
}

unsafe fn next_level(t: *mut u64, i: usize) -> Option<*mut u64> {
    let e = unsafe { core::ptr::read_volatile(t.add(i)) };
    if e & DESC == DESC {
        return Some((e & ADDR) as usize as *mut u64);
    }
    let n = alloc_table()?;
    unsafe { core::ptr::write_volatile(t.add(i), n as u64 | DESC) };
    Some(n)
}

unsafe fn map_range(l1: *mut u64, start: usize, end: usize, attrs: u64) -> bool {
    let mut va = start & !(PAGE - 1);
    while va < end {
        let Some(l2) = (unsafe { next_level(l1, (va >> 30) & 511) }) else { return false };
        let Some(l3) = (unsafe { next_level(l2, (va >> 21) & 511) }) else { return false };
        unsafe { core::ptr::write_volatile(l3.add((va >> 12) & 511), (va as u64 & ADDR) | attrs | DESC) };
        va += PAGE;
    }
    true
}

/// Map `[va, va+len)` to `[pa, ...)` (page-aligned) with `attrs`.
unsafe fn map_to(l1: *mut u64, va: usize, pa: usize, len: usize, attrs: u64) -> bool {
    let mut off = 0;
    while off < len {
        let v = va + off;
        let Some(l2) = (unsafe { next_level(l1, (v >> 30) & 511) }) else { return false };
        let Some(l3) = (unsafe { next_level(l2, (v >> 21) & 511) }) else { return false };
        unsafe { core::ptr::write_volatile(l3.add((v >> 12) & 511), ((pa + off) as u64 & ADDR) | attrs | DESC) };
        off += PAGE;
    }
    true
}

// ------------------------------------------------------------------------------------------------
// S2: the worker engine image. Core 0 copies its read-only segments here once, before any worker starts; each
// worker maps them at their link VAs (ENGINE_VA..) in its private tables. Core 0's own tables never map that VA,
// so core 0 cannot execute the engine, and the engine has no writable segment (refused here, and asserted by its
// link map), so one copy serves every worker.

/// S2b: per-worker memory for the engine (model copy, session, executor state) and its answers. Only the first
/// ARENA_CORES cores get one (the QEMU gate uses cores 2 and 3).
const ARENA_CORES: usize = 4;
pub const ARENA_BYTES: usize = 4 * 1024 * 1024;
pub const RESULT_BYTES: usize = 64 * 1024;
#[repr(C, align(4096))]
struct Arena {
    mem: [u8; ARENA_BYTES],
    result: [u8; RESULT_BYTES],
}
static mut ARENAS: [Arena; ARENA_CORES] = [const { Arena { mem: [0; ARENA_BYTES], result: [0; RESULT_BYTES] } }; ARENA_CORES];

/// Link VA of the engine image (see `os/kernel/worker-engine/link.ld`).
pub const ENGINE_VA: usize = 0xB000_0000;
const ENGINE_MAX: usize = 2 * 1024 * 1024;
const ENGINE_MAX_SEGS: usize = 8;

#[repr(C, align(4096))]
struct EngineImage([u8; ENGINE_MAX]);
static mut ENGINE_IMG: EngineImage = EngineImage([0; ENGINE_MAX]);
static mut ENGINE_SEGS: [(usize, usize, bool); ENGINE_MAX_SEGS] = [(0, 0, false); ENGINE_MAX_SEGS];
static ENGINE_NSEGS: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);
static ENGINE_ENTRY: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);

/// One loadable segment of the engine image, as core 0's ELF parser validated it.
pub struct EngineSeg<'a> {
    pub vaddr: usize,
    pub bytes: &'a [u8],
    pub memsz: usize,
    pub exec: bool,
    pub write: bool,
}

/// Load the engine image once (core 0, before starting workers). Refuses a writable segment, a segment outside
/// `[ENGINE_VA, ENGINE_VA + ENGINE_MAX)`, unaligned VAs, and an entry point outside an executable segment.
/// Returns the number of bytes loaded.
///
/// # Safety
/// Core 0 only, before any worker is started.
pub unsafe fn engine_load(segs: &[EngineSeg<'_>], entry: usize) -> Result<usize, &'static str> {
    if ENGINE_NSEGS.load(Ordering::Acquire) != 0 {
        return Err("engine already loaded");
    }
    if segs.is_empty() || segs.len() > ENGINE_MAX_SEGS {
        return Err("bad segment count");
    }
    let mut entry_ok = false;
    let mut total = 0;
    for s in segs {
        if s.write {
            return Err("writable segment (the engine must have no mutable state)");
        }
        let end = s.vaddr.checked_add(s.memsz).ok_or("segment overflows")?;
        if s.vaddr % PAGE != 0 || s.vaddr < ENGINE_VA || end > ENGINE_VA + ENGINE_MAX || s.bytes.len() > s.memsz {
            return Err("segment outside the engine window");
        }
        if s.exec && entry >= s.vaddr && entry < end {
            entry_ok = true;
        }
    }
    if !entry_ok {
        return Err("entry not in an executable segment");
    }
    let img = unsafe { &mut (*core::ptr::addr_of_mut!(ENGINE_IMG)).0 };
    let table = unsafe { &mut *core::ptr::addr_of_mut!(ENGINE_SEGS) };
    for (k, s) in segs.iter().enumerate() {
        let off = s.vaddr - ENGINE_VA;
        img[off..off + s.bytes.len()].copy_from_slice(s.bytes);
        img[off + s.bytes.len()..off + s.memsz].fill(0);
        let len = (s.memsz + PAGE - 1) & !(PAGE - 1);
        table[k] = (s.vaddr, len, s.exec);
        total += s.memsz;
        // Make the copied code visible to other cores' instruction fetch: clean to PoU, invalidate the I-cache
        // (inner-shareable broadcast), then barriers.
        let base = img.as_ptr() as usize + off;
        let mut a = base & !63;
        while a < base + s.memsz {
            unsafe { core::arch::asm!("dc cvau, {}", in(reg) a, options(nostack)) };
            a += 64;
        }
        unsafe { core::arch::asm!("dsb ish", options(nostack)) };
        let mut a = base & !63;
        while a < base + s.memsz {
            unsafe { core::arch::asm!("ic ivau, {}", in(reg) a, options(nostack)) };
            a += 64;
        }
        unsafe { core::arch::asm!("dsb ish", "isb", options(nostack)) };
    }
    ENGINE_ENTRY.store(entry, Ordering::Relaxed);
    ENGINE_NSEGS.store(segs.len(), Ordering::Release);
    Ok(total)
}

/// Build worker `idx`'s private tables; returns its TTBR0 value (ASID 0).
fn build_worker_tables(idx: usize) -> Option<u64> {
    let l1 = alloc_table()?;
    unsafe {
        let text = (core::ptr::addr_of!(__text_start) as usize, core::ptr::addr_of!(__text_end) as usize);
        let rodata_end = core::ptr::addr_of!(__rodata_end) as usize;
        let area = core::ptr::addr_of!(CORES[idx]) as usize;
        let window = core::ptr::addr_of!(WINDOW) as usize;
        // S2: the engine image's segments, at their link VAs, only in worker tables.
        for k in 0..ENGINE_NSEGS.load(Ordering::Acquire) {
            let (va, len, exec) = (*core::ptr::addr_of!(ENGINE_SEGS))[k];
            let pa = core::ptr::addr_of!(ENGINE_IMG) as usize + (va - ENGINE_VA);
            if !map_to(l1, va, pa, len, if exec { TEXT } else { RODATA }) {
                return None;
            }
        }
        // S2b: this worker's own arena + result region, read-write, mapped for no other core's tables.
        if idx < ARENA_CORES {
            let ar = core::ptr::addr_of!(ARENAS[idx]) as usize;
            if !map_range(l1, ar, ar + core::mem::size_of::<Arena>(), RW_DATA) {
                return None;
            }
        }
        let ok = map_range(l1, text.0, text.1, TEXT)
            && map_range(l1, text.1, rodata_end, RODATA)
            && map_range(l1, area, area + core::mem::size_of::<CoreShared>(), RW_DATA)
            && map_range(l1, window, window + core::mem::size_of::<Window>(), RODATA)
            && map_range(l1, GICD, GICD + PAGE, DEVICE)
            && map_range(l1, GICC, GICC + PAGE, DEVICE);
        if !ok {
            return None;
        }
        core::arch::asm!("dsb ish", options(nostack)); // tables visible to the walker before CPU_ON
    }
    Some(l1 as u64)
}

/// Tables used so far (diagnostics for the gate).
pub fn tables_used() -> usize {
    TABLES_NEXT.load(Ordering::Relaxed).min(POOL)
}

// ------------------------------------------------------------------------------------------------
// S1: core 0's side of the worker executive.

/// The worker crate, for core 0's checks (job vocabulary, reference functions).
pub use heqk_worker as worker;
use heqk_worker::exec::Ctx;
use heqk_worker::job::{Done, Job};
use heqk_worker::ring::{Consumer, Producer, Ring};

/// The SGI used as the worker doorbell.
pub const SGI_DOORBELL: u32 = 1;
/// QEMU `virt` GICv2 bases (`smpboot` is refused with `cm5`; CM5 gets its own in S0b/S1 metal).
const GICD: usize = 0x0800_0000;
const GICC: usize = 0x0801_0000;
/// S1c: worker timer rate = counter frequency / this (1 kHz heartbeat).
const TICK_PERIOD_DIV: Option<u64> = Some(1000);
/// Words in the shared read-only data window.
pub const WINDOW_WORDS: usize = 8192;


/// Data core 0 shares with every worker, read-only for them (mapped read-only in their private
/// tables, S1b). Core 0 writes it before submitting the jobs that reference it; the ring's release store
/// publishes those writes.
#[repr(C, align(4096))]
pub struct Window(pub [u64; WINDOW_WORDS]);
pub static mut WINDOW: Window = Window([0; WINDOW_WORDS]);

/// Core 0's handle on one worker: the producer end of its job ring, the consumer end of its result
/// ring, and read access to the worker's published atomics.
pub struct Port {
    pub idx: usize,
    jobs: Producer<Job>,
    done: Consumer<Done>,
    ctx: *mut Ctx,
}

impl Port {
    /// Build worker `idx`'s context and core 0's port. Once per index (the ring split refuses a second).
    pub fn prepare(idx: usize) -> Option<Port> {
        if idx == 0 || idx >= MAX_CORES {
            return None;
        }
        // SAFETY: the rings are only ever reached through the endpoints split hands out once.
        let (jobs, done) = unsafe { (&*core::ptr::addr_of!(CORES[idx].jobs), &*core::ptr::addr_of!(CORES[idx].done)) };
        let (jp, jc) = jobs.split()?;
        let (dp, dc) = done.split()?;
        let base = core::ptr::addr_of!(WINDOW) as u64;
        // SAFETY: CORES[idx].ctx is written once here (the ring split above cannot succeed twice).
        let ctx = unsafe {
            let slot = &mut *core::ptr::addr_of_mut!(CORES[idx].ctx);
            slot.write(Ctx {
                jobs: jc,
                done: dp,
                window_base: base,
                window_len: (WINDOW_WORDS * 8) as u64,
                gicd: GICD,
                gicc: GICC,
                sgi: SGI_DOORBELL,
                cpu_mask: core::sync::atomic::AtomicU8::new(0),
                served: AtomicU64::new(0),
                engine: ENGINE_ENTRY.load(Ordering::Relaxed),
                cpacr: AtomicU64::new(0),
                isar0: AtomicU64::new(0),
                tick_period: TICK_PERIOD_DIV.map_or(0, |d| heqk_worker::timer::freq() / d),
                ticks: AtomicU64::new(0),
                last_tick: AtomicU64::new(0),
                busy_since: AtomicU64::new(0),
                arena: if idx < ARENA_CORES { core::ptr::addr_of!(ARENAS[idx].mem) as u64 } else { 0 },
                arena_len: if idx < ARENA_CORES { ARENA_BYTES as u64 } else { 0 },
                result: if idx < ARENA_CORES { core::ptr::addr_of!(ARENAS[idx].result) as u64 } else { 0 },
                result_len: if idx < ARENA_CORES { RESULT_BYTES as u64 } else { 0 },
                progress: core::sync::atomic::AtomicU32::new(0),
                cancel: core::sync::atomic::AtomicBool::new(false),
            }) as *mut Ctx
        };
        Some(Port { idx, jobs: jp, done: dc, ctx })
    }

    pub fn submit(&mut self, j: Job) -> bool {
        self.jobs.push(j)
    }

    /// Ring the worker's doorbell (after submitting). False until the worker published its mask.
    pub fn doorbell(&self) -> bool {
        let m = self.cpu_mask();
        if m == 0 {
            return false;
        }
        // SAFETY: QEMU virt GICD, device-mapped by core 0's tables.
        unsafe { heqk_worker::gic::send_sgi(GICD, m, SGI_DOORBELL) };
        true
    }

    pub fn poll(&mut self) -> Option<Done> {
        self.done.pop()
    }

    pub fn cpu_mask(&self) -> u8 {
        // SAFETY: only the atomic field is read; the worker owns the rest of the context.
        unsafe { (*core::ptr::addr_of!((*self.ctx).cpu_mask)).load(Ordering::Acquire) }
    }

    /// The worker's CPACR_EL1 (after it enabled FP/SIMD for itself) and ID_AA64ISAR0_EL1.
    pub fn cpacr_isar0(&self) -> (u64, u64) {
        // SAFETY: only atomic fields are read.
        unsafe {
            (
                (*core::ptr::addr_of!((*self.ctx).cpacr)).load(Ordering::Relaxed),
                (*core::ptr::addr_of!((*self.ctx).isar0)).load(Ordering::Relaxed),
            )
        }
    }

    /// S1c heartbeat: (timer ticks handled while idle, counter at the last one, counter when the current job
    /// started or 0 when idle).
    pub fn heartbeat(&self) -> (u64, u64, u64) {
        // SAFETY: only atomic fields are read.
        unsafe {
            (
                (*core::ptr::addr_of!((*self.ctx).ticks)).load(Ordering::Acquire),
                (*core::ptr::addr_of!((*self.ctx).last_tick)).load(Ordering::Relaxed),
                (*core::ptr::addr_of!((*self.ctx).busy_since)).load(Ordering::Acquire),
            )
        }
    }

    /// S2b: the engine's answer-token counter for the job in flight.
    pub fn progress(&self) -> u32 {
        // SAFETY: only the atomic field is read.
        unsafe { (*core::ptr::addr_of!((*self.ctx).progress)).load(Ordering::Acquire) }
    }

    /// S2b: ask the engine to stop the job in flight (read after every pass over the weights).
    pub fn set_cancel(&self, on: bool) {
        // SAFETY: only the atomic field is written.
        unsafe { (*core::ptr::addr_of!((*self.ctx).cancel)).store(on, Ordering::Release) }
    }

    /// S2b: this worker's result region (read by core 0 after the job's Done; the ring's acquire orders it).
    pub fn result(&self) -> Option<&'static mut [u8]> {
        if self.idx >= ARENA_CORES {
            return None;
        }
        // SAFETY: core 0 reads/clears it only between jobs.
        Some(unsafe { core::slice::from_raw_parts_mut(core::ptr::addr_of_mut!(ARENAS[self.idx].result) as *mut u8, RESULT_BYTES) })
    }

    pub fn served(&self) -> u64 {
        // SAFETY: as above.
        unsafe { (*core::ptr::addr_of!((*self.ctx).served)).load(Ordering::Relaxed) }
    }
}
