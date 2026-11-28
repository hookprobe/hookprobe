// SPDX-License-Identifier: AGPL-3.0-only
//! ADR 0060 S2 — the worker engine image: hard-float, NEON, run only on a worker core that enabled FP/SIMD for
//! itself, mapped executable only in that core's private tables. No writable statics (the link map asserts it):
//! everything mutable lives in the memory the worker passes in ([`EngineEnv`]): the arena (model copy, session,
//! executor state) and per-call scratch. One entry point, C ABI, integers and pointers only ([`EngineEntry`]).
//!
//! Ops:
//! - GEMV_I8 (S2a): int8 GEMV via NEON SMULL/SADALP or SDOT, bit-identical to the scalar reference.
//! - ENGINE_LOAD (S2b): verify the signed HNX model against the key core 0 trusts, admit it, open a session in the
//!   arena and keep a `conductor_p0::P0Executor` there.
//! - ENGINE_INFER (S2b): `conductor_p0::core_job::run` — the Conductor's own job body, unchanged.
#![no_std]
#![no_main]

use conductor_p0::core_job::{self, Link};
use conductor_p0::P0Executor;
use core::arch::aarch64::*;
use core::sync::atomic::{AtomicBool, AtomicU32};
use heqk_worker::job::{op, path, status, EngineEntry, EngineEnv, EngineLoad, GemvParams, GEMV_MAX_COLS, GEMV_MAX_ROWS};
use neuro_gguf::hnx::{admit, Admitted};
use neuro_gguf::p0::{self, Mem, Session};
use neuro_hnx::{scheme, target, Loader, Platform};
use neuro_kernels::Simd;
use neuro_lm::qwen3::Layer;

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    // Contained by the worker's vectors (FAULT + ESR recorded, core parked).
    unsafe { core::arch::asm!("brk #0x7e", options(nomem, nostack)) };
    loop {}
}

// Type check: the entry matches the ABI the worker executive calls.
const _: EngineEntry = engine_entry;

/// ENGINE_LOAD refusals (high half), with the step in the low bits.
pub const LOAD_REFUSED: u32 = 0x0002_0000;
const BATCH: usize = 16;
const STATE_MAGIC: u64 = 0x4845_514B_454E_4731; // "HEQKENG1"
/// HNX signing tag of the gate's test model (QEMU only; a release model carries its own policy).
const TAG: &[u8] = b"test/hnx";

/// # Safety
/// Called only by the worker executive on a core with FP/SIMD enabled; every address in `env` lies in a region
/// core 0 mapped for this worker, and the executive checked the job's own ranges against its window.
#[no_mangle]
#[link_section = ".text.engine_entry"]
pub unsafe extern "C" fn engine_entry(opc: u32, a: u64, b: u64, env: *const EngineEnv, value: *mut u64) -> u32 {
    let env = unsafe { &*env };
    let (st, v) = match opc {
        op::GEMV_I8 => (unsafe { gemv(a, env) }, 0),
        op::ENGINE_LOAD => unsafe { load(a, env) },
        op::ENGINE_INFER => unsafe { infer(a, b, env) },
        _ => (status::UNKNOWN_OP, 0),
    };
    unsafe { *value = v };
    st
}

// ------------------------------------------------------------------------------------------------ S2b: engine

/// The executor, kept at the start of the arena between jobs.
type Exec = P0Executor<'static, fn() -> u64>;
#[repr(C)]
struct State {
    magic: u64,
    exec: Exec,
}

/// Milliseconds of this core's counter (the executor's monotonic clock).
fn clock_ms() -> u64 {
    let (c, f): (u64, u64);
    unsafe {
        core::arch::asm!("isb", "mrs {}, cntpct_el0", out(reg) c, options(nomem, nostack));
        core::arch::asm!("mrs {}, cntfrq_el0", out(reg) f, options(nomem, nostack));
    }
    c / (f / 1000).max(1)
}

/// Carves typed, initialised slices out of the arena, in order, never freeing.
struct Bump {
    at: usize,
    end: usize,
}

impl Bump {
    fn reserve(&mut self, size: usize, align: usize) -> Option<usize> {
        let at = self.at.checked_add(align - 1)? & !(align - 1);
        let end = at.checked_add(size)?;
        if end > self.end {
            return None;
        }
        self.at = end;
        Some(at)
    }

    fn take<T: Copy>(&mut self, n: usize, v: T) -> Option<&'static mut [T]> {
        let at = self.reserve(core::mem::size_of::<T>().checked_mul(n)?, core::mem::align_of::<T>())?;
        let p = at as *mut T;
        for i in 0..n {
            // SAFETY: inside the arena (checked by reserve), aligned for T, not yet handed out.
            unsafe { p.add(i).write(v) };
        }
        // SAFETY: as above; the arena outlives every job (it is never unmapped for this worker).
        Some(unsafe { core::slice::from_raw_parts_mut(p, n) })
    }

    fn place<T>(&mut self, v: T) -> Option<&'static mut T> {
        let at = self.reserve(core::mem::size_of::<T>(), core::mem::align_of::<T>())? as *mut T;
        // SAFETY: as in `take`.
        unsafe {
            at.write(v);
            Some(&mut *at)
        }
    }
}

/// The trust policy for the gate's model: the key core 0 handed over, the QEMU target, AGPL weights.
struct Trust([u8; 32]);
impl Platform for Trust {
    fn target(&self) -> u8 {
        target::QEMU_VIRT
    }
    fn features(&self) -> u32 {
        0
    }
    fn engine_abi(&self) -> u16 {
        1
    }
    fn verify(&self, s: u8, digest: &[u8; 32], sig: &[u8]) -> bool {
        s == scheme::ED25519 && sig.try_into().is_ok_and(|sig: &[u8; 64]| conductor_core::crypto::verify(&self.0, TAG, digest, sig))
    }
    fn licence_allowed(&self, spdx: &[u8]) -> bool {
        spdx == b"AGPL-3.0-only"
    }
    fn min_svn(&self, _: &[u8; 16]) -> u32 {
        1
    }
}

/// ENGINE_LOAD: verify, copy, admit and open the model; keep the executor in the arena.
unsafe fn load(params: u64, env: &EngineEnv) -> (u32, u64) {
    let p: EngineLoad = unsafe { core::ptr::read_volatile(params as usize as *const EngineLoad) };
    // The model's bytes live in the signed kernel image (read-only for this worker).
    let prefix: &'static [u8] = unsafe { core::slice::from_raw_parts(p.prefix as usize as *const u8, p.prefix_len as usize) };
    let bundle: &'static [u8] = unsafe { core::slice::from_raw_parts(p.bundle as usize as *const u8, p.bundle_len as usize) };
    let simd = match p.simd {
        0 => Simd::SCALAR,
        1 if has_dotprod() => unsafe { Simd::neon_dot() }, // DotProd present and FP/SIMD enabled on this core
        _ => return (status::UNSUPPORTED, 0),
    };
    let mut bump = Bump { at: env.arena as usize, end: env.arena as usize + env.arena_len as usize };
    // The state slot first, so ENGINE_INFER finds it at the arena's start.
    let Some(slot) = bump.reserve(core::mem::size_of::<State>(), core::mem::align_of::<State>()) else { return (LOAD_REFUSED | 1, 0) };
    // Mark "not loaded" until the end: a refused load leaves no usable state behind.
    unsafe { core::ptr::write_volatile(slot as *mut u64, 0) };
    let trust = Trust(p.pk);
    let Ok(mut l) = Loader::open(prefix, &trust) else { return (LOAD_REFUSED | 2, 0) };
    let Some(region) = bump.take(bundle.len(), 0u8) else { return (LOAD_REFUSED | 3, 0) };
    let seg = 1usize << 16;
    for i in 0..bundle.len().div_ceil(seg) {
        let (s, e) = (i * seg, ((i + 1) * seg).min(bundle.len()));
        region[s..e].copy_from_slice(&bundle[s..e]);
        if l.accept_in_place(i as u32, region).is_err() {
            return (LOAD_REFUSED | 4, 0);
        }
    }
    let region: &'static [u8] = region;
    let Ok(ad) = admit(&l, region) else { return (LOAD_REFUSED | 5, 0) };
    let Some(ad) = bump.place::<Admitted<'static>>(ad) else { return (LOAD_REFUSED | 6, 0) };
    let ad: &'static Admitted<'static> = ad;
    let z = p0::sizes(&ad.hparams, BATCH);
    let max_answer = p.max_answer as usize;
    let mem = (|| {
        Some(Mem {
            layers: bump.take(z.layers, Layer::EMPTY)?,
            rope: bump.take(z.rope, (0i32, 0i32))?,
            kv_vals: bump.take(z.kv_vals, 0i16)?,
            kv_shifts: bump.take(z.kv_shifts, 0u8)?,
            work_i64: bump.take(z.work_i64, 0i64)?,
            work_i8: bump.take(z.work_i8, 0i8)?,
            work_pairs: bump.take(z.work_pairs, (0i32, 0i32))?,
            work_i32: bump.take(z.work_i32, 0i32)?,
            ids: bump.take(z.ids, 0u32)?,
            prev: bump.take(z.prev, 0u32)?,
            list: bump.take(512, 0u32)?,
            out: bump.take(max_answer, 0u32)?,
        })
    })();
    let Some(mem) = mem else { return (LOAD_REFUSED | 7, 0) };
    let Ok(session) = Session::open(ad, simd, BATCH, mem) else { return (LOAD_REFUSED | 8, 0) };
    let (Some(cps), Some(buf)) = (bump.take(1 << 15, 0u32), bump.take(1 << 15, 0u8)) else { return (LOAD_REFUSED | 9, 0) };
    let exec: Exec = P0Executor::new(session, p.model, cps, buf, clock_ms as fn() -> u64).with_max_answer(max_answer);
    // SAFETY: `slot` was reserved for a State at the arena's start, aligned.
    unsafe { (slot as *mut State).write(State { magic: STATE_MAGIC, exec }) };
    (status::OK, (bump.at - env.arena as usize) as u64)
}

/// ENGINE_INFER: the Conductor's job body on the loaded executor.
unsafe fn infer(a: u64, b: u64, env: &EngineEnv) -> (u32, u64) {
    let state = env.arena as usize as *mut State;
    // SAFETY: the arena's start is the State slot ENGINE_LOAD wrote (or a 0 magic if it never succeeded).
    if env.arena_len < core::mem::size_of::<State>() as u64 || unsafe { core::ptr::read_volatile(state as *const u64) } != STATE_MAGIC {
        return (status::UNSUPPORTED, 0);
    }
    let exec = unsafe { &mut (*state).exec };
    let window = unsafe { core::slice::from_raw_parts(env.window as usize as *const u8, env.window_len as usize) };
    let result = unsafe { core::slice::from_raw_parts_mut(env.result as usize as *mut u8, env.result_len as usize) };
    let progress = unsafe { &*(env.progress as usize as *const AtomicU32) };
    let cancel = unsafe { &*(env.cancel as usize as *const AtomicBool) };
    core_job::run(exec, op::ENGINE_INFER, a, b, Link { window, progress, cancel }, result)
}

// ------------------------------------------------------------------------------------------------ S2a: GEMV

/// GEMV_I8: `params` (checked by the executive) and W/x in the window; y goes to the call's scratch.
unsafe fn gemv(params: u64, env: &EngineEnv) -> u32 {
    let p = unsafe { &*(params as usize as *const GemvParams) };
    let (rows, cols) = (p.rows as usize, p.cols as usize);
    if p.rows == 0 || p.rows > GEMV_MAX_ROWS || rows > env.scratch_len as usize || p.cols == 0 || p.cols > GEMV_MAX_COLS || cols % 16 != 0 {
        return status::BAD_PARAMS;
    }
    let w = unsafe { core::slice::from_raw_parts(p.w as usize as *const i8, rows * cols) };
    let x = unsafe { core::slice::from_raw_parts(p.x as usize as *const i8, cols) };
    let y = unsafe { core::slice::from_raw_parts_mut(env.scratch as usize as *mut i32, rows) };
    match p.path {
        path::NEON => {
            for (r, o) in y.iter_mut().enumerate() {
                *o = unsafe { dot_neon(&w[r * cols..(r + 1) * cols], x) };
            }
            status::OK
        }
        path::SDOT => {
            if !has_dotprod() {
                return status::UNSUPPORTED;
            }
            for (r, o) in y.iter_mut().enumerate() {
                *o = unsafe { dot_sdot(&w[r * cols..(r + 1) * cols], x) };
            }
            status::OK
        }
        _ => status::UNSUPPORTED,
    }
}

/// ID_AA64ISAR0_EL1.DP (bits 47:44) >= 1.
fn has_dotprod() -> bool {
    let isar0: u64;
    unsafe { core::arch::asm!("mrs {}, id_aa64isar0_el1", out(reg) isar0, options(nomem, nostack)) };
    (isar0 >> 44) & 0xF >= 1
}

/// 16 lanes at a time: SMULL/SMULL2 to i16 (|a*b| <= 16384 fits), SADALP into i32 lanes, ADDV at the end.
#[inline(never)]
unsafe fn dot_neon(w: &[i8], x: &[i8]) -> i32 {
    unsafe {
        let mut acc = vdupq_n_s32(0);
        for (a, b) in w.chunks_exact(16).zip(x.chunks_exact(16)) {
            let va = vld1q_s8(a.as_ptr());
            let vb = vld1q_s8(b.as_ptr());
            acc = vpadalq_s16(acc, vmull_s8(vget_low_s8(va), vget_low_s8(vb)));
            acc = vpadalq_s16(acc, vmull_high_s8(va, vb));
        }
        vaddvq_s32(acc)
    }
}

/// SDOT v2.4s, v0.16b, v1.16b, emitted as its encoding so the assembler needs no `dotprod` feature; the caller
/// checked ID_AA64ISAR0_EL1.DP first. Registers are pinned to match the encoding.
#[inline(never)]
unsafe fn dot_sdot(w: &[i8], x: &[i8]) -> i32 {
    unsafe {
        let mut acc = vdupq_n_s32(0);
        for (a, b) in w.chunks_exact(16).zip(x.chunks_exact(16)) {
            let va = vld1q_s8(a.as_ptr());
            let vb = vld1q_s8(b.as_ptr());
            core::arch::asm!(
                ".inst 0x4e819402", // sdot v2.4s, v0.16b, v1.16b
                in("v0") va,
                in("v1") vb,
                inout("v2") acc,
                options(pure, nomem, nostack),
            );
        }
        vaddvq_s32(acc)
    }
}
