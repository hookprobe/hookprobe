// SPDX-License-Identifier: AGPL-3.0-only
//! The engine as a job on a compute-role worker core (ADR 0060 stage S2).
//!
//! The kernel's worker executive (`os/kernel/worker`, HomePods) gives a worker core a closed job vocabulary:
//! core 0 sends `Job { id, op, a, b }` over a ring and gets `Done { id, status, value }` back; a worker never
//! runs kernel code and reads only the window core 0 granted. Its own note says the compute engine is added "as
//! a new op". This module is that op's body, written against slices so that it has no address arithmetic and no
//! `unsafe`: the executive checks the job's range against its window (as it does for its own ops) and hands the
//! window over as a slice.
//!
//! One op, [`op::ENGINE_INFER`]:
//! - `a`, `b`: offset and length of the prompt inside the read window. The prompt is the one the device's
//!   harness built; the answer is closed over the context in it (see the crate documentation).
//! - the answer goes to the worker's result window: a [`HEADER`]-byte header of counters, then the answer bytes.
//! - `Done::value` is the answer's length in bytes; `Done::status` is [`status::OK`] or says why there is none.
//!
//! Core 0 does not wait inside the job. Two shared words carry what it needs meanwhile: `progress` (answer
//! tokens so far, written after every pass over the weights) and `cancel` (set by core 0; read after every pass).
//! A cancelled job returns nothing of its answer.
//!
//! The same request always gives the same bytes, whatever the kernels, the batching or what the session's cache
//! held before (`conductor-mock/tests/p0_worker.rs`). `conductor_core::quorum` relies on that.
use crate::{code, P0Executor};
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

pub mod op {
    /// Answer the prompt at `[a, a + b)` of the read window under the explainer's contract.
    pub const ENGINE_INFER: u32 = 0x0100;
}

pub mod status {
    /// Shared with the executive's own ops.
    pub const OK: u32 = 0;
    pub const UNKNOWN_OP: u32 = 1;
    /// The prompt's range is not inside the read window, or the result window cannot hold the header.
    pub const OUT_OF_WINDOW: u32 = 2;
    /// A refusal or failure of the engine: `REFUSED | code`, with the codes of [`crate::code`].
    pub const REFUSED: u32 = 0x0001_0000;
}

/// Bytes of counters before the answer in the result window: answer tokens, prompt passes, answer passes and
/// prompt tokens not fed again, each a little-endian `u32`.
pub const HEADER: usize = 16;

/// What core 0 shares with the compute core for its jobs.
#[derive(Clone, Copy)]
pub struct Link<'a> {
    /// The read window core 0 granted: prompts lie in it.
    pub window: &'a [u8],
    /// Answer tokens of the job in flight, written by the compute core after every pass.
    pub progress: &'a AtomicU32,
    /// Set by core 0 to stop the job in flight; read by the compute core after every pass.
    pub cancel: &'a AtomicBool,
}

/// Run one job. Returns `(status, value)` for the executive's `Done`.
pub fn run<C: FnMut() -> u64>(engine: &mut P0Executor<'_, C>, job_op: u32, a: u64, b: u64, link: Link<'_>, result: &mut [u8]) -> (u32, u64) {
    let Link { window, progress, cancel } = link;
    if job_op != op::ENGINE_INFER {
        return (status::UNKNOWN_OP, 0);
    }
    let prompt = usize::try_from(a).ok().zip(usize::try_from(b).ok()).and_then(|(at, len)| window.get(at..at.checked_add(len)?));
    let (Some(prompt), Some((head, answer))) = (prompt, result.split_at_mut_checked(HEADER)) else {
        return (status::OUT_OF_WINDOW, 0);
    };
    progress.store(0, Ordering::Release);
    let out = engine.infer(prompt, answer, &mut |tokens| {
        progress.store(u32::try_from(tokens).unwrap_or(u32::MAX), Ordering::Release);
        !cancel.load(Ordering::Acquire)
    });
    let st = engine.last_stats();
    let counters = [st.tokens, st.prefill_passes, st.passes, u32::try_from(engine.last_reused()).unwrap_or(u32::MAX)];
    for (slot, v) in head.as_chunks_mut::<4>().0.iter_mut().zip(counters) {
        slot.copy_from_slice(&v.to_le_bytes());
    }
    match out {
        Ok(r) => (status::OK, r.len as u64),
        Err(c) => (status::REFUSED | u32::from(c), 0),
    }
}

/// True if `status` is the refusal `c` of [`crate::code`].
pub fn refused_with(status: u32, c: u16) -> bool {
    status == status::REFUSED | u32::from(c)
}

/// The refusal for a cancelled job, as a status.
pub const CANCELLED: u32 = status::REFUSED | code::CANCELLED as u32;
