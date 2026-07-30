//! M5.3 (Track C) — the EL0 Wasm-HOST: a no_std aarch64 EL0 program linking a REAL
//! `wasmi` 0.32 interpreter. The kernel (EL1, the TRUST ROOT) has ALREADY Ed25519-verified
//! the `.wasm` module and copied it — with the input `port` — into this task's RW work
//! page BEFORE spawning us. We run the module's exported `classify(port)` through wasmi and
//! return the verdict to the kernel over the ENFORCED synchronous-IPC path (SYS_CALL on the
//! Endpoint{W} cap at CPtr 0). Then we SYS_TASK_EXIT.
//!
//! ISOLATION: we run at EL0 in our OWN ASID/TTBR0 with ONLY (a) our mapped pages and (b)
//! the single Endpoint{W} cap. A trapping/malformed module makes wasmi RETURN an error (we
//! send the fail sentinel) — and even a Rust panic or an EL0 memory fault is CONTAINED by
//! the kernel's R1 fault-restart; wasmi can never reach EL1. The ~326 KiB of wasmi `.text`
//! lives HERE, entirely OUT of the kernel TCB (ADR 0044 D4 #2).
#![no_std]
#![no_main]

extern crate alloc;

use core::alloc::{GlobalAlloc, Layout};
use core::sync::atomic::{AtomicUsize, Ordering};

// ---- VAs the kernel maps for us (MUST match main.rs EL0_WHOST2_* constants) ----
// Code base is set by link.ld (0x9000_0000). The kernel maps a stack, a heap window and a
// work page at these fixed VAs (none are in our ELF — like the M5.1 fixture's stack).
const HEAP_BASE: usize = 0x9300_0000;
const HEAP_SIZE: usize = 256 * 1024; // 256 KiB — ~26x the measured ~9.5 KiB wasmi high-water
const WORK_BASE: usize = 0x9400_0000;

// ---- syscall numbers (== the kernel's SYS_CALL / SYS_TASK_EXIT; see syscall.s) ----
const SYS_CALL: u64 = 24; // send msg + block for reply on an Endpoint{W} cap
const SYS_TASK_EXIT: u64 = 22;
const EP_CPTR: u64 = 0; // CPtr 0 = our Endpoint{W}
const FAIL: u32 = 0xFFFF_FFFF; // fail-closed sentinel verdict (kernel treats != {0,1} as error)

// ============================ bump allocator ================================
// A monotonic bump over the kernel-mapped [HEAP_BASE, HEAP_BASE+HEAP_SIZE) window. wasmi's
// total allocation for the memoryless classify module is ~9.5 KiB (measured), so a 256 KiB
// window never exhausts for the beachhead. No reclaim (bump) — the task is one-shot.
struct Bump {
    off: AtomicUsize,
}
#[global_allocator]
static ALLOC: Bump = Bump { off: AtomicUsize::new(0) };

unsafe impl Sync for Bump {}
unsafe impl GlobalAlloc for Bump {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let align = layout.align();
        loop {
            let cur = self.off.load(Ordering::Relaxed);
            let start = (HEAP_BASE + cur + align - 1) & !(align - 1);
            let new_off = match (start - HEAP_BASE).checked_add(layout.size()) {
                Some(v) => v,
                None => return core::ptr::null_mut(),
            };
            if new_off > HEAP_SIZE {
                return core::ptr::null_mut(); // exhausted -> null (GlobalAlloc contract)
            }
            if self
                .off
                .compare_exchange_weak(cur, new_off, Ordering::SeqCst, Ordering::Relaxed)
                .is_ok()
            {
                return start as *mut u8;
            }
        }
    }
    unsafe fn dealloc(&self, _ptr: *mut u8, _layout: Layout) {}
}

// ============================ EL0 syscall shims ==============================
#[inline(always)]
fn sys_call(cptr: u64, msg: u64) -> u64 {
    let reply: u64;
    unsafe {
        core::arch::asm!(
            "svc #0",
            in("x0") cptr,
            in("x1") msg,
            in("x8") SYS_CALL,
            lateout("x0") reply,
            lateout("x1") _,
            clobber_abi("C"),
        );
    }
    reply
}

#[inline(always)]
fn sys_task_exit() -> ! {
    unsafe {
        core::arch::asm!("svc #0", in("x8") SYS_TASK_EXIT, options(noreturn));
    }
}

/// Return the verdict to the kernel over the enforced Endpoint{W} IPC, then exit cleanly.
fn send_verdict_and_exit(verdict: u32) -> ! {
    let _ = sys_call(EP_CPTR, verdict as u64);
    sys_task_exit();
}

// ============================ panic / alloc error ============================
// A panic (e.g. an unexpected wasmi internal invariant, or OOM) is CONTAINED: send the
// fail-closed sentinel over IPC and exit. The task never unwinds (panic=abort) and never
// reaches EL1 — worst case the kernel's R1 fault-restart reaps us.
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    send_verdict_and_exit(FAIL)
}

// ============================ the host body ==================================
/// Run the (already kernel-verified) module's `classify(port)` via wasmi.
/// Returns the i32 verdict, or `FAIL` for any wasmi/decoding error — the module can only
/// ever yield a verdict or a fail-closed sentinel, never escape.
fn run_classify(wasm: &[u8], port: i32) -> u32 {
    use wasmi::{Engine, Linker, Module, Store};
    let engine = Engine::default();
    let module = match Module::new(&engine, wasm) {
        Ok(m) => m,
        Err(_) => return FAIL,
    };
    let mut store = Store::new(&engine, ());
    let linker = Linker::<()>::new(&engine);
    let pre = match linker.instantiate(&mut store, &module) {
        Ok(p) => p,
        Err(_) => return FAIL,
    };
    let inst = match pre.ensure_no_start(&mut store) {
        Ok(i) => i,
        Err(_) => return FAIL,
    };
    let func = match inst.get_typed_func::<i32, i32>(&store, "classify") {
        Ok(f) => f,
        Err(_) => return FAIL,
    };
    match func.call(&mut store, port) {
        Ok(v) => v as u32, // includes the wasm-trap case? no: a trap -> Err below
        Err(_) => FAIL,    // a wasm trap (unreachable / div0 / OOB) is contained here
    }
}

/// EL0 entry. The kernel set our SP (via make_el0_thread) and mapped the work page + heap.
/// Work page ABI (== main.rs writes):
///   [+0]=port_a(u64) [+8]=port_b(u64) [+16]=wasm_len(u64) [+24..]=wasm module bytes
/// We run `classify` on BOTH ports through wasmi and pack the two i16 verdicts into one word
/// `(v_a << 16) | (v_b & 0xffff)` — so a SINGLE returned verdict proves BOTH vectors (e.g.
/// classify(4444)=1 AND classify(443)=0 -> 0x0001_0000), i.e. the predicate genuinely
/// COMPUTES, it is not returning a constant. A trapping module yields FAIL for both ->
/// 0xFFFF_FFFF (the (c) isolation signature). One host = one Endpoint = one TCB pair.
#[no_mangle]
pub extern "C" fn _start() -> ! {
    let work = WORK_BASE as usize;
    let (port_a, port_b, wasm_len) = unsafe {
        let a = core::ptr::read_volatile(work as *const u64) as i32;
        let b = core::ptr::read_volatile((work + 8) as *const u64) as i32;
        let n = core::ptr::read_volatile((work + 16) as *const u64) as usize;
        (a, b, n)
    };
    // Bound the module length (belt-and-braces; the kernel already caps the copy). 3 KiB is
    // ample for the beachhead's ~46-byte module and stays well inside the one work page.
    let wasm_len = wasm_len.min(3072);
    let wasm: &[u8] = unsafe { core::slice::from_raw_parts((work + 24) as *const u8, wasm_len) };
    let va = run_classify(wasm, port_a);
    let vb = run_classify(wasm, port_b);
    let packed = ((va & 0xffff) << 16) | (vb & 0xffff);
    send_verdict_and_exit(packed);
}
