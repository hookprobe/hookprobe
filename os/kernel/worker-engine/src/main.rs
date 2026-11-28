// SPDX-License-Identifier: AGPL-3.0-only
//! ADR 0060 S2 — the worker engine image: hard-float, NEON, run only on a worker core that enabled FP/SIMD for
//! itself, mapped executable only in that core's private tables. No writable statics (the link map asserts it):
//! everything mutable lives in the memory the worker passes in ([`EngineEnv`]): the arena (model copy, session,
//! executor state) and per-call scratch. One entry point, C ABI, integers and pointers only ([`EngineEntry`]).
//!
//! Ops:
//! - GEMV_I8 (S2a): int8 GEMV via NEON SMULL/SADALP or SDOT, bit-identical to the scalar reference.
//! - ENGINE_LOAD (S2b/S2c): verify the signed HNX model against the key core 0 trusts, accept and admit its bundle
//!   into the start of the worker's arena, and check the Conductor's `arena_need` for the rest.
//! - ENGINE_INFER (S2c): the Conductor's own C-ABI entry, `conductor_engine_entry::engine_infer` (#1666), over the
//!   admitted model, the rest of the arena, the window, the result and the progress/cancel words. Stateless per
//!   call: the same regions and prompt give the same bytes on any core.
#![no_std]
#![no_main]

use conductor_engine_entry::{arena_need, engine_infer, InferArgs, Limits};
use core::arch::aarch64::*;
use core::sync::atomic::{AtomicBool, AtomicU32};
use heqk_worker::job::{op, path, status, EngineEntry, EngineEnv, EngineLoad, GemvParams, GEMV_MAX_COLS, GEMV_MAX_ROWS};
use neuro_gguf::hnx::admit;
use neuro_hnx::{scheme, target, Loader, Platform};

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
/// HNX signing tag of the gate's test model (QEMU only; a release model carries its own policy).
const TAG: &[u8] = b"test/hnx";
/// The context the gate's model is admitted at (`tools/build/worker-engine-model`).
const MAX_CTX: u32 = 2048;
const MODEL_MAGIC: u64 = 0x4845_514B_4D44_4C32; // "HEQKMDL2"
/// Header at the arena's start: magic, model length, kernel set, answer bound. The model follows, page-aligned;
/// the engine's own memory follows the model.
const HDR: usize = 4096;

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

// ------------------------------------------------------------------------------------------------ S2b/S2c: engine

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

fn page_up(n: usize) -> usize {
    (n + 4095) & !4095
}

/// ENGINE_LOAD: verify the signed model, accept its bundle into the arena (after the header) and admit it; check the
/// Conductor's `arena_need` for what is left. A refused load leaves the header's magic at 0.
unsafe fn load(params: u64, env: &EngineEnv) -> (u32, u64) {
    let p: EngineLoad = unsafe { core::ptr::read_volatile(params as usize as *const EngineLoad) };
    let arena = unsafe { core::slice::from_raw_parts_mut(env.arena as usize as *mut u8, env.arena_len as usize) };
    if arena.len() < HDR {
        return (LOAD_REFUSED | 1, 0);
    }
    arena[..8].fill(0);
    if p.simd > 1 || (p.simd == 1 && !has_dotprod()) {
        return (status::UNSUPPORTED, 0);
    }
    // The model's bytes live in the signed kernel image (read-only for this worker).
    let prefix: &[u8] = unsafe { core::slice::from_raw_parts(p.prefix as usize as *const u8, p.prefix_len as usize) };
    let bundle: &[u8] = unsafe { core::slice::from_raw_parts(p.bundle as usize as *const u8, p.bundle_len as usize) };
    let trust = Trust(p.pk);
    let Ok(mut l) = Loader::open(prefix, &trust) else { return (LOAD_REFUSED | 2, 0) };
    let model_end = HDR + bundle.len();
    if model_end > arena.len() {
        return (LOAD_REFUSED | 3, 0);
    }
    let (head, rest) = arena.split_at_mut(HDR);
    let region = &mut rest[..bundle.len()];
    let seg = 1usize << 16;
    for i in 0..bundle.len().div_ceil(seg) {
        let (s, e) = (i * seg, ((i + 1) * seg).min(bundle.len()));
        region[s..e].copy_from_slice(&bundle[s..e]);
        if l.accept_in_place(i as u32, region).is_err() {
            return (LOAD_REFUSED | 4, 0);
        }
    }
    if admit(&l, region).is_err() {
        return (LOAD_REFUSED | 5, 0);
    }
    let limits = Limits { max_ctx: MAX_CTX, max_answer: p.max_answer };
    let Ok(need) = arena_need(region, limits) else { return (LOAD_REFUSED | 6, 0) };
    let engine_at = page_up(model_end);
    if engine_at as u64 + need > env.arena_len {
        return (LOAD_REFUSED | 7, need);
    }
    head[8..16].copy_from_slice(&(bundle.len() as u64).to_le_bytes());
    head[16..20].copy_from_slice(&(if p.simd == 1 { path::SDOT } else { path::SCALAR }).to_le_bytes());
    head[20..24].copy_from_slice(&p.max_answer.to_le_bytes());
    head[..8].copy_from_slice(&MODEL_MAGIC.to_le_bytes());
    (status::OK, need)
}

/// ENGINE_INFER: the Conductor's C entry over the admitted model and the rest of the arena.
unsafe fn infer(a: u64, b: u64, env: &EngineEnv) -> (u32, u64) {
    let arena = env.arena as usize as *mut u8;
    if (env.arena_len as usize) < HDR {
        return (status::UNSUPPORTED, 0);
    }
    let head = unsafe { core::slice::from_raw_parts(arena, HDR) };
    let word = |at: usize| u64::from_le_bytes(head[at..at + 8].try_into().unwrap_or([0; 8]));
    if word(0) != MODEL_MAGIC {
        return (status::UNSUPPORTED, 0); // no model loaded (or the load was refused)
    }
    let model_len = word(8) as usize;
    let kernels = u32::from_le_bytes(head[16..20].try_into().unwrap_or([0; 4]));
    let max_answer = u32::from_le_bytes(head[20..24].try_into().unwrap_or([0; 4]));
    let engine_at = page_up(HDR + model_len);
    let mut value = 0u64;
    let args = InferArgs {
        model: unsafe { arena.add(HDR) },
        model_len: model_len as u64,
        arena: unsafe { arena.add(engine_at) },
        arena_len: env.arena_len - engine_at as u64,
        window: env.window as usize as *const u8,
        window_len: env.window_len,
        result: env.result as usize as *mut u8,
        result_len: env.result_len,
        progress: env.progress as usize as *const AtomicU32,
        cancel: env.cancel as usize as *const AtomicBool,
        value: &mut value,
        a,
        b,
        limits: Limits { max_ctx: MAX_CTX, max_answer },
        op: op::ENGINE_INFER,
        path: kernels,
    };
    // SAFETY: model, arena (after the model), window and result are distinct regions mapped for this worker;
    // progress/cancel are the worker's words; with SDOT this core has DotProd and FP/SIMD on (checked at load).
    let st = unsafe { engine_infer(&args) };
    (st, value)
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
