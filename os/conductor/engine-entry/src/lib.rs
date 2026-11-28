// SPDX-License-Identifier: AGPL-3.0-only
//! The engine job as one call over raw regions (ADR 0060 stage S2b).
//!
//! A worker core's engine image has no writable data of its own (S1b unmaps `.data`/`.bss`, S2a's link map
//! refuses them), so everything the engine reads or writes comes in through the call:
//!
//! | Region | Access | What it is |
//! |---|---|---|
//! | model | read | the bundle payload core 0 verified and admitted (model, tokenizer tables, RoPE pairs, packed matrices) |
//! | arena | read, write | all of the engine's memory; [`arena_need`] says how much before anything starts |
//! | window | read | holds the prompt at `a`, length `b` |
//! | result | write | a 16-byte header of counters, then the answer |
//! | progress, cancel | write / read | one word each, shared with core 0 |
//!
//! [`reserve`] bounds the model region and the arena from the signed header alone, before the payload is read.
//!
//! [`run`] is the safe form over slices. [`engine_infer`] is the same over pointers, C ABI, integers and
//! pointers only, for the image's entry stub. The only `unsafe` in the Conductor's engine path is here: turning
//! the caller's pointers into slices, and giving the arena's bytes their types.
//!
//! Each call opens the model again from the regions. With [`run`] and [`engine_infer`] it also starts from an
//! empty cache, so a call depends on nothing but its arguments: the same regions and prompt give the same bytes
//! on any core.
//!
//! [`run_kept`] and [`engine_infer_kept`] give the same bytes and feed less: the cache one job leaves in the
//! arena serves the next job as far as the two prompts start with the same tokens (the system prompt and the
//! framing, for the explainer). The state that outlives the call is the arena itself and one 32-byte block the
//! caller owns, [`Kept`]. The engine image still has no writable data.
#![no_std]
#![deny(unsafe_op_in_unsafe_fn)]
#![deny(clippy::indexing_slicing, clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use conductor_p0::core_job::{self, status, Link};
use conductor_p0::{P0Executor, MAX_ANSWER_TOKENS};
use core::mem::{align_of, size_of};
use core::sync::atomic::{AtomicBool, AtomicU32};
use neuro_gguf::hnx::reopen_bundle;
use neuro_gguf::p0::{self, Mem, Session};
use neuro_kernels::Simd;
use neuro_lm::qwen3::Layer;

pub use conductor_p0::core_job::{op, refused_with, CANCELLED, HEADER};

/// Refusals of this layer, in the same status space as the engine's (`status::REFUSED | code`).
pub mod code {
    /// The model region is not an admitted bundle for this context.
    pub const MODEL: u16 = 0x0301;
    /// The arena is smaller than [`super::arena_need`] says.
    pub const ARENA: u16 = 0x0302;
    /// The kernel set asked for is not one this build has (`path` in [`super::InferArgs`]).
    pub const KERNELS: u16 = 0x0303;
    /// The limits are out of range.
    pub const LIMITS: u16 = 0x0304;
    /// A null pointer where a region is required.
    pub const NULL: u16 = 0x0305;
}

/// Kernel sets, numbered as `heqk_worker::job::path`.
pub mod path {
    pub const SCALAR: u32 = 0;
    /// NEON with the dot-product extension. The caller has checked that the core has it.
    pub const SDOT: u32 = 2;
}

/// Prompt tokens fed per pass.
pub const BATCH: usize = 16;
/// Scratch for normalising a prompt: code points and bytes.
const CPS: usize = 1 << 16;
const BUF: usize = 1 << 16;
/// Bound on the allowed-token list of one answer step.
const LIST: usize = 8192;
/// The largest answer bound a caller may ask for, in tokens.
pub const MAX_ANSWER_LIMIT: u32 = 4096;
/// Bytes the arena may lose to alignment: one gap per carved slice.
const SLACK: usize = 16 * 16;

/// What the caller fixes for a session of a model.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(C)]
pub struct Limits {
    /// The context the bundle was admitted at.
    pub max_ctx: u32,
    /// Bound on the answer in tokens; 0 is Neuro's 700.
    pub max_answer: u32,
}

impl Limits {
    fn answer(self) -> Option<usize> {
        match self.max_answer {
            0 => Some(MAX_ANSWER_TOKENS),
            n if n <= MAX_ANSWER_LIMIT => usize::try_from(n).ok(),
            _ => None,
        }
    }
}

const fn refused(c: u16) -> u32 {
    status::REFUSED | c as u32
}

/// Bytes of arena a job on this model needs. Integer arithmetic only, so core 0 can call it before it grants the
/// region. `Err` is a status ([`code::MODEL`], [`code::LIMITS`]).
pub fn arena_need(model: &[u8], limits: Limits) -> Result<u64, u32> {
    let answer = limits.answer().ok_or(refused(code::LIMITS))?;
    let ctx = usize::try_from(limits.max_ctx).map_err(|_| refused(code::LIMITS))?;
    let ad = reopen_bundle(model, ctx).map_err(|_| refused(code::MODEL))?;
    let fixed = (CPS + LIST + answer).saturating_mul(4).saturating_add(BUF).saturating_add(SLACK);
    u64::try_from(p0::sizes(&ad.hparams, BATCH).bytes().saturating_add(fixed)).map_err(|_| refused(code::LIMITS))
}

/// The largest layer table [`reserve`] allows for. A model with more blocks still runs if the arena it is given
/// covers [`arena_need`]; only the early bound does not hold for it.
pub const RESERVED_LAYERS: usize = 128;
/// Memory is granted in pages of this size.
pub const PAGE: u64 = 4096;

/// What the signed header says about a language model's memory (`neuro_hnx::Manifest`, the four fields that
/// count here). Admission has checked nothing yet when it reads these; `neuro_gguf::hnx::admit` later proves
/// they were true, or refuses the model.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Declared {
    pub payload_bytes: u64,
    pub arena_bytes: u32,
    pub state_bytes_per_session: u32,
    pub max_context: u32,
}

/// Memory to set aside for one model on a worker core, in whole pages.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Reserve {
    /// The read-only model region: the payload.
    pub model: u64,
    /// The read-write arena: not less than [`arena_need`] will ask once the payload is loaded.
    pub arena: u64,
}

impl Reserve {
    pub fn total(self) -> u64 {
        self.model.saturating_add(self.arena)
    }

    /// Two models loaded side by side and run one at a time on the same core: both model regions, one arena.
    pub fn sharing_arena(self, other: Reserve) -> Reserve {
        Reserve { model: self.model.saturating_add(other.model), arena: self.arena.max(other.arena) }
    }
}

const fn pages(n: u64) -> u64 {
    n.saturating_add(PAGE - 1) / PAGE * PAGE
}

/// What to set aside for a model, from its header alone: before a byte of the payload is read from storage,
/// so a device without the memory refuses at once and reserves nothing (ADR 0061 D4). Integer arithmetic only.
///
/// For a model of at most [`RESERVED_LAYERS`] blocks whose manifest admission accepts, `arena` is not less than
/// [`arena_need`] of the loaded payload under the same `limits`. The caller still asks [`arena_need`] after the
/// load and refuses the model if it is more: the header is a promise until admission has checked it.
/// `Err` is a status ([`code::LIMITS`]: the limits are out of range or are not the context the header declares).
pub fn reserve(declared: Declared, limits: Limits) -> Result<Reserve, u32> {
    let answer = limits.answer().ok_or(refused(code::LIMITS))?;
    if limits.max_ctx == 0 || limits.max_ctx != declared.max_context || declared.payload_bytes == 0 {
        return Err(refused(code::LIMITS));
    }
    // The session (`p0::Sizes::bytes`): the manifest's arena is the pass scratch and the RoPE table, its state
    // the KV cache; the token lists (`ids`, `prev`) are two words per position; then the layer table.
    const { assert!(BATCH <= neuro_lm::qwen3::MAX_BATCH) };
    let tokens = u64::from(declared.max_context).saturating_mul(8);
    let layers = (RESERVED_LAYERS as u64).saturating_mul(size_of::<Layer>() as u64);
    let fixed = (CPS + LIST + answer).saturating_mul(4).saturating_add(BUF).saturating_add(SLACK) as u64;
    let arena = u64::from(declared.arena_bytes).saturating_add(u64::from(declared.state_bytes_per_session)).saturating_add(tokens).saturating_add(layers).saturating_add(fixed);
    Ok(Reserve { model: pages(declared.payload_bytes), arena: pages(arena) })
}

/// Types every bit pattern is a valid value of, with no padding: bytes may be read as them.
///
/// # Safety
/// The implementor is such a type.
unsafe trait Plain: Copy {}
// SAFETY: integers, and a pair of the same integer (size 8, align 4, no padding).
unsafe impl Plain for u8 {}
unsafe impl Plain for i8 {}
unsafe impl Plain for i16 {}
unsafe impl Plain for i32 {}
unsafe impl Plain for u32 {}
unsafe impl Plain for i64 {}
unsafe impl Plain for (i32, i32) {}

/// Hands out the arena front to back, each piece once.
struct Carver<'a> {
    rest: &'a mut [u8],
}

impl<'a> Carver<'a> {
    /// The next `n * size` bytes at alignment `align`, removed from the arena.
    fn bytes(&mut self, n: usize, size: usize, align: usize) -> Option<&'a mut [u8]> {
        let rest = core::mem::take(&mut self.rest);
        let pad = rest.as_ptr().align_offset(align);
        let len = n.checked_mul(size)?;
        let (piece, tail) = rest.get_mut(pad..)?.split_at_mut_checked(len)?;
        self.rest = tail;
        Some(piece)
    }

    fn take<T: Plain>(&mut self, n: usize) -> Option<&'a mut [T]> {
        let piece = self.bytes(n, size_of::<T>(), align_of::<T>())?;
        // SAFETY: `piece` is `n * size_of::<T>()` bytes, aligned for `T`, borrowed exclusively for `'a` and no
        // longer reachable through the carver; any bytes are a valid `T` (`Plain`).
        Some(unsafe { core::slice::from_raw_parts_mut(piece.as_mut_ptr().cast::<T>(), n) })
    }

    /// The layer table, every entry set to the empty layer (a `Layer` holds references, so its bytes are
    /// written before they are read).
    fn layers(&mut self, n: usize) -> Option<&'a mut [Layer<'a>]> {
        let piece = self.bytes(n, size_of::<Layer>(), align_of::<Layer>())?;
        let at = piece.as_mut_ptr().cast::<Layer<'a>>();
        for i in 0..n {
            // SAFETY: `at.add(i)` is inside `piece` (`n` entries), aligned, and written before any read.
            unsafe { at.add(i).write(Layer::EMPTY) };
        }
        // SAFETY: `n` initialised entries, exclusively borrowed for `'a`.
        Some(unsafe { core::slice::from_raw_parts_mut(at, n) })
    }
}

/// What one job left in the arena for the next: 32 bytes the caller owns, next to the arena it describes.
///
/// All zero is "nothing kept", and that is what the caller writes whenever it loads a model, grants or moves
/// the arena, or lets anything else write to it. The engine reads the block at the start of a job, clears it
/// while the job runs (a core that faults in a job leaves nothing kept) and writes it again at the end.
///
/// The engine compares the block with the call (context, arena address, model length) and starts from an
/// empty cache when they differ. It cannot see that the arena's bytes or the model's are the ones it left:
/// that is the caller's promise. A block that claims a cache the arena does not hold gives a wrong answer,
/// not a fault.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(C)]
pub struct Kept {
    tag: u32,
    /// Leading tokens whose positions the cache holds.
    tokens: u32,
    max_ctx: u32,
    zero: u32,
    arena: u64,
    model_len: u64,
}

impl Kept {
    /// Nothing kept: the next job feeds its whole prompt.
    pub const EMPTY: Kept = Kept { tag: 0, tokens: 0, max_ctx: 0, zero: 0, arena: 0, model_len: 0 };
    /// Marks a block this build wrote. It changes with the arena's layout ([`BATCH`] is part of it).
    const TAG: u32 = 0x314B_5148;

    /// Tokens the next job may find already in the cache.
    pub fn tokens(&self) -> u32 {
        if self.tag == Self::TAG {
            self.tokens
        } else {
            0
        }
    }

    fn of(tokens: usize, max_ctx: u32, arena: u64, model_len: u64) -> Kept {
        Kept { tag: Self::TAG, tokens: u32::try_from(tokens).unwrap_or(0), max_ctx, zero: 0, arena, model_len }
    }

    /// The tokens to take up, if this block describes this call.
    fn matching(&self, max_ctx: u32, arena: u64, model_len: u64) -> usize {
        let same = self.tag == Self::TAG && self.zero == 0 && self.max_ctx == max_ctx && self.arena == arena && self.model_len == model_len;
        if same {
            usize::try_from(self.tokens).unwrap_or(0)
        } else {
            0
        }
    }
}

/// One engine job, over slices.
pub struct Job<'a, 'l> {
    /// The admitted bundle's payload.
    pub model: &'a [u8],
    /// The engine's memory for this call; at least [`arena_need`] bytes. Its contents on entry do not matter.
    pub arena: &'a mut [u8],
    pub limits: Limits,
    pub simd: Simd,
    /// `op`, `a`, `b` of the executive's job.
    pub op: u32,
    pub a: u64,
    pub b: u64,
    pub link: Link<'l>,
    pub result: &'l mut [u8],
}

/// Run one job. Returns `(status, value)` for the executive's `Done`: on `OK`, `value` is the answer's length
/// after the 16-byte header in `result`.
pub fn run(job: Job<'_, '_>) -> (u32, u64) {
    run_on(job, None)
}

/// [`run`], taking up the cache the last job left in `job.arena` and leaving this job's for the next. The
/// answer is the one [`run`] gives; the fourth counter of the result header says how many prompt tokens were
/// not fed again. See [`Kept`] for what the caller promises.
pub fn run_kept(job: Job<'_, '_>, kept: &mut Kept) -> (u32, u64) {
    run_on(job, Some(kept))
}

fn run_on(job: Job<'_, '_>, kept: Option<&mut Kept>) -> (u32, u64) {
    let Job { model, arena, limits, simd, op: job_op, a, b, link, result } = job;
    if job_op != op::ENGINE_INFER {
        return (status::UNKNOWN_OP, 0);
    }
    let (Some(answer), Ok(ctx)) = (limits.answer(), usize::try_from(limits.max_ctx)) else {
        return (refused(code::LIMITS), 0);
    };
    let Ok(ad) = reopen_bundle(model, ctx) else {
        return (refused(code::MODEL), 0);
    };
    let z = p0::sizes(&ad.hparams, BATCH);
    // What a kept cache is tied to. The address counts: the pieces are aligned from where the arena starts.
    let key = (limits.max_ctx, arena.as_ptr() as usize as u64, model.len() as u64);
    let mut c = Carver { rest: arena };
    let mut carve = || {
        Some((
            Mem {
                layers: c.layers(z.layers)?,
                rope: c.take(z.rope)?,
                kv_vals: c.take(z.kv_vals)?,
                kv_shifts: c.take(z.kv_shifts)?,
                work_i64: c.take(z.work_i64)?,
                work_i8: c.take(z.work_i8)?,
                work_pairs: c.take(z.work_pairs)?,
                work_i32: c.take(z.work_i32)?,
                ids: c.take(z.ids)?,
                prev: c.take(z.prev)?,
                list: c.take(LIST)?,
                out: c.take(answer)?,
            },
            c.take::<u32>(CPS)?,
            c.take::<u8>(BUF)?,
        ))
    };
    let Some((mem, cps, buf)) = carve() else {
        return (refused(code::ARENA), 0);
    };
    let Ok(session) = Session::open(&ad, simd, BATCH, mem) else {
        return (refused(code::MODEL), 0);
    };
    // No clock on a compute core: the times in a result are core 0's to measure.
    let mut engine = P0Executor::new(session, [0; 32], cps, buf, || 0).with_max_answer(answer);
    let Some(kept) = kept else {
        return core_job::run(&mut engine, job_op, a, b, link, result);
    };
    engine.resume(kept.matching(key.0, key.1, key.2));
    // Nothing is kept while the job writes the cache.
    *kept = Kept::EMPTY;
    let done = core_job::run(&mut engine, job_op, a, b, link, result);
    *kept = Kept::of(engine.suspend(), key.0, key.1, key.2);
    done
}

/// The arguments of [`engine_infer`]: regions as pointer and length, the job, and where the value goes.
#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct InferArgs {
    pub model: *const u8,
    pub model_len: u64,
    pub arena: *mut u8,
    pub arena_len: u64,
    pub window: *const u8,
    pub window_len: u64,
    pub result: *mut u8,
    pub result_len: u64,
    /// Answer tokens so far, written after every pass.
    pub progress: *const AtomicU32,
    /// One byte, 0 or 1: set to 1 by core 0 to stop the job. Read after every pass.
    pub cancel: *const AtomicBool,
    /// Receives the job's value (the answer's length on `OK`, else 0).
    pub value: *mut u64,
    pub a: u64,
    pub b: u64,
    pub limits: Limits,
    /// The executive's job op.
    pub op: u32,
    /// The kernel set ([`path`]).
    pub path: u32,
}

/// [`run`] for an engine image's entry stub. Returns the status.
///
/// # Safety
/// - `args` points to a readable `InferArgs`.
/// - `model` and `window` are readable for their lengths; `arena` and `result` are writable for theirs; no two of
///   the four regions overlap, and nothing else reads or writes `arena` or `result` during the call.
/// - `progress`, `cancel` and `value` point to live words; `cancel` holds 0 or 1.
/// - With `path::SDOT`, the calling core has FP/SIMD enabled and the dot-product extension.
pub unsafe extern "C" fn engine_infer(args: *const InferArgs) -> u32 {
    if args.is_null() {
        return refused(code::NULL);
    }
    // SAFETY: the caller's first promise.
    let g = unsafe { *args };
    if g.model.is_null() || g.arena.is_null() || g.window.is_null() || g.result.is_null() || g.progress.is_null() || g.cancel.is_null() || g.value.is_null() {
        return refused(code::NULL);
    }
    // SAFETY: the caller's promises, passed on.
    let (st, value) = unsafe { over_pointers(&g, None) };
    // SAFETY: `value` points to a live word. It is written on every path, so the caller never reads a stale one.
    unsafe { g.value.write(value) };
    st
}

/// [`run_kept`] for an engine image's entry stub: [`engine_infer`] with the cache kept between calls.
///
/// # Safety
/// As [`engine_infer`], and:
/// - `kept` points to a live, writable [`Kept`] that nothing else reads or writes during the call;
/// - the block is all zero, or it is as the last call with this `arena` left it, and since that call nothing
///   has written to `arena`, and `model` holds the same bytes.
pub unsafe extern "C" fn engine_infer_kept(args: *const InferArgs, kept: *mut Kept) -> u32 {
    if args.is_null() || kept.is_null() {
        return refused(code::NULL);
    }
    // SAFETY: the caller's first promise.
    let g = unsafe { *args };
    if g.model.is_null() || g.arena.is_null() || g.window.is_null() || g.result.is_null() || g.progress.is_null() || g.cancel.is_null() || g.value.is_null() {
        return refused(code::NULL);
    }
    // SAFETY: the caller's promises, passed on; `kept` is live and exclusively ours for the call.
    let (st, value) = unsafe { over_pointers(&g, Some(&mut *kept)) };
    // SAFETY: as in `engine_infer`.
    unsafe { g.value.write(value) };
    st
}

/// # Safety
/// As [`engine_infer`], with no null pointer in `g`.
unsafe fn over_pointers(g: &InferArgs, kept: Option<&mut Kept>) -> (u32, u64) {
    let len = |n: u64| usize::try_from(n).ok();
    let (Some(model_len), Some(arena_len), Some(window_len), Some(result_len)) = (len(g.model_len), len(g.arena_len), len(g.window_len), len(g.result_len)) else {
        return (refused(code::LIMITS), 0);
    };
    let simd = match g.path {
        path::SCALAR => Simd::SCALAR,
        // SAFETY: the caller's last promise.
        #[cfg(target_arch = "aarch64")]
        path::SDOT => unsafe { Simd::neon_dot() },
        _ => return (refused(code::KERNELS), 0),
    };
    // SAFETY: the caller's promises about the regions and the words.
    unsafe {
        run_on(
            Job {
            model: core::slice::from_raw_parts(g.model, model_len),
            arena: core::slice::from_raw_parts_mut(g.arena, arena_len),
            limits: g.limits,
            simd,
            op: g.op,
            a: g.a,
            b: g.b,
            link: Link { window: core::slice::from_raw_parts(g.window, window_len), progress: &*g.progress, cancel: &*g.cancel },
            result: core::slice::from_raw_parts_mut(g.result, result_len),
            },
            kept,
        )
    }
}
