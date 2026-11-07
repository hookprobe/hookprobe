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

// ---- VAs the kernel maps for us (MUST match main.rs WASMI_* / WASMI_CM5_* constants) ----
// Code base is set by the link script. The kernel maps a stack, a heap window and a work
// page at these fixed VAs (none are in our ELF — like the M5.1 fixture's stack).
//
// Two ABIs / two VA maps:
//   * default (QEMU IPC server): 0x9000_0000 image, heap 0x9300_0000, work 0x9400_0000.
//   * `syncabi` (CM5 sync excursion): the whole image + heap + work live inside the single
//     2 MiB GB5 EL0 window (0x1_4000_0000..0x1_4020_0000) the CM5 mapper can reach.
#[cfg(not(feature = "syncabi"))]
const HEAP_BASE: usize = 0x9300_0000;
#[cfg(feature = "syncabi")]
const HEAP_BASE: usize = 0x1_4009_0000; // GB5 window, above the ~393 KiB code image + stack
// Heap: the classify/detect modules use ~9.5 KiB, but a REAL std wasm32-wasip1 module (M5.5)
// declares ~1.1 MiB of linear memory + wasmi overhead — so the QEMU host gets a 4 MiB heap
// window (the kernel maps only as many pages as a given host actually touches). The cm5
// `syncabi` host stays at 256 KiB (its whole GB5 window is only 2 MiB; it runs the small
// classify/detect modules, not the big std wasip1 module).
#[cfg(not(feature = "syncabi"))]
const HEAP_SIZE: usize = 4 * 1024 * 1024; // 4 MiB (QEMU): fits a std wasip1 module's ~1.1 MiB memory
#[cfg(feature = "syncabi")]
const HEAP_SIZE: usize = 256 * 1024; // 256 KiB (cm5 GB5 window)
#[cfg(not(feature = "syncabi"))]
const WORK_BASE: usize = 0x9400_0000;
#[cfg(feature = "syncabi")]
const WORK_BASE: usize = 0x1_400D_0000; // GB5 window, above the heap
// M5.5 — the wasip1 module window (QEMU path only): a std wasm32-wasip1 module is ~37 KiB,
// far bigger than the 4 KiB work page, so the kernel maps its bytes in this OWN RO window and
// the work page carries only the WASIP1 header + the stdin bytes.
#[cfg(not(feature = "syncabi"))]
const WASIP1_MODULE_BASE: usize = 0x9500_0000;

// ---- syscall numbers (== the kernel's SYS_CALL / SYS_TASK_EXIT / SYS_DRIVER_REPORT) ----
#[cfg(not(feature = "syncabi"))]
const SYS_CALL: u64 = 24; // send msg + block for reply on an Endpoint{W} cap
#[cfg(not(feature = "syncabi"))]
const SYS_TASK_EXIT: u64 = 22;
#[cfg(not(feature = "syncabi"))]
const EP_CPTR: u64 = 0; // CPtr 0 = our Endpoint{W}
// M5.5 — the CM5 excursion's return path: report the verdict in x0 via a single svc; in
// cooperative (IRQs-off, no-scheduler) mode the kernel's SVC handler stores it into
// DRIVER_REPORT and longjmps back to the enter_user caller (never returns to EL0).
#[cfg(feature = "syncabi")]
const SYS_DRIVER_REPORT: u64 = 7;
const FAIL: u32 = 0xFFFF_FFFF; // fail-closed sentinel verdict (kernel treats != {0,1} as error)

// ---- M5.4 (Track C) DETECT-mode work-page ABI (distinct from the M5.3 classify ABI) ----
// The classify path writes `port_a` (a small int, 4444/443) at work[+0]; the detect path
// writes this MAGIC there instead, so `_start` disambiguates the two WITHOUT changing the
// proven M5.3 classify layout. Detect layout:
//   [+0]=DETECT_MAGIC(u64) [+8]=n_inputs [+16]=stride [+24]=wasm_len
//   [+32..]=inputs (n_inputs*stride bytes) [+512..]=wasm module bytes
const DETECT_MAGIC: u64 = 0x4851_4445_5445_4354; // sentinel ("HQDETECT"), never a port value
const DETECT_INPUTS_OFF: usize = 32;
const DETECT_MODULE_OFF: usize = 512;
const DETECT_FAIL_NIBBLE: u32 = 0xF; // per-input fail-closed marker (trap / bad verdict)

// ---- M5.5 (Track C) wasip1-mode work-page ABI (QEMU path). The module is too big for the
// work page, so it lives in WASIP1_MODULE_BASE; the work page carries only:
//   [+0]=WASIP1_MAGIC(u64) [+8]=wasm_len(u64) [+16]=stdin_len(u64) [+24..]=stdin bytes
#[cfg(not(feature = "syncabi"))]
const WASIP1_MAGIC: u64 = 0x4851_5741_5349_5031; // sentinel ("HQWASIP1")
#[cfg(not(feature = "syncabi"))]
const WASIP1_STDIN_OFF: usize = 24;

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
#[cfg(not(feature = "syncabi"))]
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

#[cfg(not(feature = "syncabi"))]
#[inline(always)]
fn sys_task_exit() -> ! {
    unsafe {
        core::arch::asm!("svc #0", in("x8") SYS_TASK_EXIT, options(noreturn));
    }
}

/// Return the verdict to the kernel over the enforced Endpoint{W} IPC, then exit cleanly.
#[cfg(not(feature = "syncabi"))]
fn send_verdict_and_exit(verdict: u32) -> ! {
    let _ = sys_call(EP_CPTR, verdict as u64);
    sys_task_exit();
}

/// M5.5 (CM5 sync excursion) — report the verdict in x0 via ONE SYS_DRIVER_REPORT svc.
/// The kernel handles it in cooperative mode: store x0 into DRIVER_REPORT, then
/// resume_kernel() back into the enter_user caller. Control never returns to EL0, so this
/// is `-> !` (noreturn) — the mirror of the isolated EL0 GEM driver's report path.
#[cfg(feature = "syncabi")]
fn send_verdict_and_exit(verdict: u32) -> ! {
    unsafe {
        core::arch::asm!(
            "svc #0",
            in("x0") verdict as u64,
            in("x8") SYS_DRIVER_REPORT,
            options(noreturn),
        );
    }
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

// ===================== M5.4 detection host + minimal host-import shim =========
// The M5.3 classify module was MEMORYLESS with NO imports. The M5.4 detection module has
// (a) LINEAR MEMORY and (b) a BESPOKE MINIMAL host ABI — two imports it needs to do real
// detection work: it READS its input via `hp_input` and EMITS its verdict via `hp_emit`.
//
// HONESTY: this is a bespoke 2-function ABI, NOT WASI 0.2/0.3 and NOT wasm32-wasip1. The
// REAL hookprobe modules (napse/dnsxai/qsecbit) are `wasm32-wasip1` binaries that read
// stdin / write stdout (fd_read/fd_write/proc_exit/…) — a strict SUPERSET of this shim,
// NOT reachable here. A full wasip1 host is the continuing road (D4 #4).

/// Per-Store state the two host functions read/write: the CURRENT input header and the
/// verdict the module emitted. One Store is instantiated once; the input is mutated in
/// place between calls (the module's 64 KiB linear memory is allocated ONCE — the bump
/// heap never frees, so re-instantiating per input would exhaust it).
struct DState {
    input: [u8; 64],
    input_len: usize,
    emitted: i32,
}

/// Run the (kernel-verified) DETECTION module over N inputs through wasmi, packing each
/// input's verdict into a nibble: `packed |= (verdict & 0xF) << (4*i)`. A per-input
/// wasm TRAP (e.g. a malformed/too-short header the module defensively rejects) or a
/// non-{PASS,DROP} verdict yields the 0xF fail nibble — CONTAINED at EL0 (wasmi returns
/// Err; the Store is not poisoned, later inputs still run). Any setup failure → FAIL.
fn run_detect(module: &[u8], inputs_base: usize, n: usize, stride: usize) -> u32 {
    use wasmi::{Caller, Engine, Extern, Linker, Module, Store};
    let engine = Engine::default();
    let m = match Module::new(&engine, module) {
        Ok(m) => m,
        Err(_) => return FAIL,
    };
    let mut store = Store::new(&engine, DState { input: [0u8; 64], input_len: 0, emitted: -1 });
    let mut linker = Linker::<DState>::new(&engine);
    // hp_input(ptr, cap) -> len: copy the current input header into the module's exported
    // linear memory at `ptr` (<= cap bytes); return the count. Bounds-safe: a bad ptr/cap
    // can only write inside the wasm memory (wasmi bounds-checks `mem.write`) or return 0.
    if linker
        .func_wrap("hp", "hp_input", |mut caller: Caller<'_, DState>, ptr: i32, cap: i32| -> i32 {
            let (buf, len) = {
                let d = caller.data();
                (d.input, d.input_len)
            };
            let want = len.min(cap.max(0) as usize).min(64);
            let mem = match caller.get_export("memory") {
                Some(Extern::Memory(mm)) => mm,
                _ => return 0,
            };
            if mem.write(&mut caller, ptr.max(0) as usize, &buf[..want]).is_err() {
                return 0;
            }
            want as i32
        })
        .is_err()
    {
        return FAIL;
    }
    // hp_emit(verdict): the module reports its verdict/alert to the host.
    if linker
        .func_wrap("hp", "hp_emit", |mut caller: Caller<'_, DState>, v: i32| {
            caller.data_mut().emitted = v;
        })
        .is_err()
    {
        return FAIL;
    }
    let pre = match linker.instantiate(&mut store, &m) {
        Ok(p) => p,
        Err(_) => return FAIL,
    };
    let inst = match pre.ensure_no_start(&mut store) {
        Ok(i) => i,
        Err(_) => return FAIL,
    };
    let detect = match inst.get_typed_func::<(), i32>(&store, "detect") {
        Ok(f) => f,
        Err(_) => return FAIL,
    };

    let mut packed = 0u32;
    let mut i = 0usize;
    while i < n && i < 8 {
        let off = inputs_base + i * stride;
        {
            let d = store.data_mut();
            d.input = [0u8; 64];
            let s = stride.min(64);
            let mut k = 0;
            while k < s {
                d.input[k] = unsafe { core::ptr::read_volatile((off + k) as *const u8) };
                k += 1;
            }
            d.input_len = s;
            d.emitted = -1;
        }
        // A verdict counts only if the call returned AND the module ALSO emitted the SAME
        // value via hp_emit — proving both imports ran, not just the return path.
        let v = match detect.call(&mut store, ()) {
            Ok(r) if (r == 1 || r == 2) && store.data().emitted == r => (r as u32) & 0xF,
            _ => DETECT_FAIL_NIBBLE, // trap / bad verdict — contained at EL0
        };
        packed |= v << (4 * i);
        i += 1;
    }
    packed
}

// ===================== M5.5 — the REAL wasip1 host (QEMU path) ================
/// Per-Store state for the WASI preview1 host functions: a stdin cursor (the L4 header the
/// kernel staged) and a stdout sink (the module's verdict byte).
#[cfg(not(feature = "syncabi"))]
struct WasiState {
    stdin: [u8; 64],
    stdin_len: usize,
    stdin_pos: usize,
    stdout: [u8; 64],
    stdout_len: usize,
    #[allow(dead_code)]
    exit_code: i32,
}

/// Run a REAL, kernel-verified `wasm32-wasip1` module through wasmi with a minimal WASI
/// preview1 host: it reads the staged L4 header from STDIN (fd_read) and writes its verdict
/// byte to STDOUT (fd_write); environ_* are empty; proc_exit records the code. Returns the
/// first stdout byte (1=PASS, 2=DROP) or FAIL on any wasmi/decoding/OOM error — the module
/// can only ever yield a verdict or the fail-closed sentinel, never escape EL0.
#[cfg(not(feature = "syncabi"))]
fn run_wasip1(module: &[u8], stdin_bytes: &[u8]) -> u32 {
    use wasmi::{Caller, Engine, Extern, Linker, Module, Store};
    let engine = Engine::default();
    let m = match Module::new(&engine, module) {
        Ok(m) => m,
        Err(_) => return FAIL,
    };
    let mut init = WasiState {
        stdin: [0u8; 64],
        stdin_len: 0,
        stdin_pos: 0,
        stdout: [0u8; 64],
        stdout_len: 0,
        exit_code: 0,
    };
    let n = stdin_bytes.len().min(64);
    init.stdin[..n].copy_from_slice(&stdin_bytes[..n]);
    init.stdin_len = n;
    let mut store = Store::new(&engine, init);
    let mut linker = Linker::<WasiState>::new(&engine);
    const WASI: &str = "wasi_snapshot_preview1";

    // fd_read(fd, iovs, iovs_len, nread) -> errno. Copies the stdin cursor into the module's
    // linear memory at each iovec (bounds-checked by wasmi's mem.write). fd 0 only.
    if linker
        .func_wrap(WASI, "fd_read", |mut caller: Caller<'_, WasiState>, fd: i32, iovs: i32, iovs_len: i32, nread: i32| -> i32 {
            if fd != 0 {
                return 8; // EBADF
            }
            let mem = match caller.get_export("memory") {
                Some(Extern::Memory(mm)) => mm,
                _ => return 8,
            };
            let mut total: u32 = 0;
            let mut i = 0i32;
            while i < iovs_len {
                let mut ent = [0u8; 8];
                if mem.read(&caller, (iovs as usize) + (i as usize) * 8, &mut ent).is_err() {
                    return 21; // EFAULT
                }
                let buf = u32::from_le_bytes([ent[0], ent[1], ent[2], ent[3]]) as usize;
                let len = u32::from_le_bytes([ent[4], ent[5], ent[6], ent[7]]) as usize;
                let (pos, slen) = {
                    let d = caller.data();
                    (d.stdin_pos, d.stdin_len)
                };
                let avail = slen - pos;
                let take = len.min(avail);
                if take > 0 {
                    let mut tmp = [0u8; 64];
                    {
                        let d = caller.data();
                        tmp[..take].copy_from_slice(&d.stdin[pos..pos + take]);
                    }
                    if mem.write(&mut caller, buf, &tmp[..take]).is_err() {
                        return 21;
                    }
                    caller.data_mut().stdin_pos += take;
                    total += take as u32;
                }
                if avail == 0 {
                    break; // EOF — stop after the first short/empty iovec
                }
                i += 1;
            }
            let _ = mem.write(&mut caller, nread as usize, &total.to_le_bytes());
            0
        })
        .is_err()
    {
        return FAIL;
    }

    // fd_write(fd, iovs, iovs_len, nwritten) -> errno. fd 1 (stdout) bytes are captured into
    // the state's stdout sink; fd 2 (stderr) is accepted+discarded; all requested bytes are
    // reported written so the module's write loop terminates.
    if linker
        .func_wrap(WASI, "fd_write", |mut caller: Caller<'_, WasiState>, fd: i32, iovs: i32, iovs_len: i32, nwritten: i32| -> i32 {
            if fd != 1 && fd != 2 {
                return 8;
            }
            let mem = match caller.get_export("memory") {
                Some(Extern::Memory(mm)) => mm,
                _ => return 8,
            };
            let mut total: u32 = 0;
            let mut i = 0i32;
            while i < iovs_len {
                let mut ent = [0u8; 8];
                if mem.read(&caller, (iovs as usize) + (i as usize) * 8, &mut ent).is_err() {
                    return 21;
                }
                let buf = u32::from_le_bytes([ent[0], ent[1], ent[2], ent[3]]) as usize;
                let len = u32::from_le_bytes([ent[4], ent[5], ent[6], ent[7]]) as usize;
                if fd == 1 {
                    let sl = caller.data().stdout_len;
                    let cap = 64usize.saturating_sub(sl);
                    let take = len.min(cap);
                    if take > 0 {
                        let mut tmp = [0u8; 64];
                        if mem.read(&caller, buf, &mut tmp[..take]).is_err() {
                            return 21;
                        }
                        caller.data_mut().stdout[sl..sl + take].copy_from_slice(&tmp[..take]);
                        caller.data_mut().stdout_len += take;
                    }
                }
                total += len as u32;
                i += 1;
            }
            let _ = mem.write(&mut caller, nwritten as usize, &total.to_le_bytes());
            0
        })
        .is_err()
    {
        return FAIL;
    }

    // environ_sizes_get(count, buf_size) -> errno: zero environment.
    if linker
        .func_wrap(WASI, "environ_sizes_get", |mut caller: Caller<'_, WasiState>, count: i32, size: i32| -> i32 {
            let mem = match caller.get_export("memory") {
                Some(Extern::Memory(mm)) => mm,
                _ => return 8,
            };
            let _ = mem.write(&mut caller, count as usize, &0u32.to_le_bytes());
            let _ = mem.write(&mut caller, size as usize, &0u32.to_le_bytes());
            0
        })
        .is_err()
    {
        return FAIL;
    }
    // environ_get(environ, buf) -> errno: nothing to write (zero environment).
    if linker
        .func_wrap(WASI, "environ_get", |_caller: Caller<'_, WasiState>, _environ: i32, _buf: i32| -> i32 { 0 })
        .is_err()
    {
        return FAIL;
    }
    // proc_exit(code): record the code; the module halts (the crt's trailing unreachable
    // traps, which we treat as the normal exit — the verdict is already in stdout).
    if linker
        .func_wrap(WASI, "proc_exit", |mut caller: Caller<'_, WasiState>, code: i32| {
            caller.data_mut().exit_code = code;
        })
        .is_err()
    {
        return FAIL;
    }

    let pre = match linker.instantiate(&mut store, &m) {
        Ok(p) => p,
        Err(_) => return FAIL,
    };
    let inst = match pre.ensure_no_start(&mut store) {
        Ok(i) => i,
        Err(_) => return FAIL,
    };
    let start = match inst.get_typed_func::<(), ()>(&store, "_start") {
        Ok(f) => f,
        Err(_) => return FAIL,
    };
    // A trailing trap after proc_exit is EXPECTED (the crt's post-exit unreachable); the
    // verdict was written to stdout before that, so read it back regardless of the result.
    let _ = start.call(&mut store, ());
    let d = store.data();
    if d.stdout_len >= 1 {
        d.stdout[0] as u32
    } else {
        FAIL
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
    // M5.4 — dispatch on the work-page mode word at [+0]. The classify path writes a small
    // port int there; the detect path writes DETECT_MAGIC. Zero-touch to the M5.3 layout.
    let mode = unsafe { core::ptr::read_volatile(work as *const u64) };
    // M5.5 (QEMU) — wasip1 mode: the module is in WASIP1_MODULE_BASE (too big for the work
    // page); the work page carries [MAGIC, wasm_len, stdin_len, stdin bytes].
    #[cfg(not(feature = "syncabi"))]
    if mode == WASIP1_MAGIC {
        let (wasm_len, stdin_len) = unsafe {
            let w = core::ptr::read_volatile((work + 8) as *const u64) as usize;
            let s = core::ptr::read_volatile((work + 16) as *const u64) as usize;
            (w.min(4 * 1024 * 1024), s.min(64))
        };
        let module: &[u8] =
            unsafe { core::slice::from_raw_parts(WASIP1_MODULE_BASE as *const u8, wasm_len) };
        let stdin: &[u8] =
            unsafe { core::slice::from_raw_parts((work + WASIP1_STDIN_OFF) as *const u8, stdin_len) };
        let v = run_wasip1(module, stdin);
        send_verdict_and_exit(v);
    }
    if mode == DETECT_MAGIC {
        let (n, stride, wasm_len) = unsafe {
            let n = core::ptr::read_volatile((work + 8) as *const u64) as usize;
            let s = core::ptr::read_volatile((work + 16) as *const u64) as usize;
            let w = core::ptr::read_volatile((work + 24) as *const u64) as usize;
            (n.min(8), s.min(64), w.min(2048))
        };
        let module: &[u8] =
            unsafe { core::slice::from_raw_parts((work + DETECT_MODULE_OFF) as *const u8, wasm_len) };
        let packed = run_detect(module, work + DETECT_INPUTS_OFF, n, stride);
        send_verdict_and_exit(packed);
    }
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
