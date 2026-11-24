// SPDX-License-Identifier: AGPL-3.0-only
//! Every size and budget in one place. All buffers are fixed; nothing grows at run time.

/// Evidence items one job may reference.
pub const MAX_EVIDENCE: usize = 32;
/// Bytes of one evidence card's text.
pub const MAX_CARD: usize = 256;
/// Bytes of the operator's intent.
pub const MAX_INTENT: usize = 512;
/// Bytes of the prompt sent to a worker (intent + cards + tool results + instructions).
pub const MAX_PROMPT: usize = 8192;
/// Bytes of one model output (the whole answer of one call).
pub const MAX_OUTPUT: usize = 4096;
/// Bytes of one response CHUNK frame's payload.
pub const MAX_CHUNK: usize = 1024;
/// Bytes of one tool result returned by the device.
pub const MAX_TOOL_RESULT: usize = 512;
/// Model calls per job (each call is a new single-use capability).
pub const MAX_STEPS: u8 = 8;
/// Refused tool calls before the job is rejected (stops injection loops).
pub const MAX_TOOL_REFUSALS: u8 = 2;
/// Citations in one answer.
pub const MAX_CITES: usize = 16;
/// Bytes of the answer's summary text.
pub const MAX_SUMMARY: usize = 2400;
/// Longest a capability may live (device lease and token expiry), in ms.
pub const MAX_TTL_MS: u64 = 5 * 60 * 1000;
/// Ceiling for any single call's compute budget, in ms.
pub const MAX_COMPUTE_MS: u32 = 120_000;
/// Ceiling for input / output units of one call. A unit is 4 bytes of UTF-8 (see [`units`]); the worker's
/// real tokenizer may count differently, so the device enforces its own count as well as the worker's.
#[allow(clippy::cast_possible_truncation)] // 2048 and 1024: far below u32::MAX
pub const MAX_IN_UNITS: u32 = (MAX_PROMPT / 4) as u32;
#[allow(clippy::cast_possible_truncation)]
pub const MAX_OUT_UNITS: u32 = (MAX_OUTPUT / 4) as u32;

/// Deterministic size measure the device can compute without a tokenizer: ceil(bytes / 4).
pub fn units(bytes: usize) -> u32 {
    let u = bytes.div_ceil(4);
    u32::try_from(u).unwrap_or(u32::MAX)
}
