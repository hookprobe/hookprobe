// SPDX-License-Identifier: AGPL-3.0-only
//! ADR 0060 S2a — the worker engine image: hard-float, NEON, run only on a worker core that enabled FP/SIMD for
//! itself, mapped executable only in that core's private tables. No writable statics (the link map asserts it):
//! everything mutable is passed in. One entry point, C ABI, integers and pointers only ([`EngineEntry`]).
//!
//! S2a computes int8 GEMV two ways (NEON SMULL/SADALP; SDOT where the CPU has DotProd). Integer arithmetic,
//! wrapping, so each path is bit-identical to the scalar reference in `heqk_worker::job` — the property the
//! Conductor's `quorum` relies on across nodes. S2b swaps this probe for `conductor_p0::core_job`.
#![no_std]
#![no_main]

use core::arch::aarch64::*;
use heqk_worker::job::{op, path, status, EngineEntry, GemvParams, GEMV_MAX_COLS, GEMV_MAX_ROWS};

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    // Contained by the worker's vectors (FAULT + ESR recorded, core parked).
    unsafe { core::arch::asm!("brk #0x7e", options(nomem, nostack)) };
    loop {}
}

// Type check: the entry matches the ABI the worker executive calls.
const _: EngineEntry = engine_entry;

/// # Safety
/// Called only by the worker executive on a core with FP/SIMD enabled, after it checked that `params`, W and x
/// lie in the read-only window and that `out` holds `out_len` i32.
#[no_mangle]
#[link_section = ".text.engine_entry"]
pub unsafe extern "C" fn engine_entry(opc: u32, params: *const GemvParams, out: *mut i32, out_len: usize) -> u32 {
    if opc != op::GEMV_I8 {
        return status::UNKNOWN_OP;
    }
    let p = unsafe { &*params };
    let (rows, cols) = (p.rows as usize, p.cols as usize);
    if p.rows == 0 || p.rows > GEMV_MAX_ROWS || rows > out_len || p.cols == 0 || p.cols > GEMV_MAX_COLS || cols % 16 != 0 {
        return status::BAD_PARAMS;
    }
    let w = unsafe { core::slice::from_raw_parts(p.w as usize as *const i8, rows * cols) };
    let x = unsafe { core::slice::from_raw_parts(p.x as usize as *const i8, cols) };
    let y = unsafe { core::slice::from_raw_parts_mut(out, rows) };
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
