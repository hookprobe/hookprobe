// SPDX-License-Identifier: AGPL-3.0-only
//! The kernel <-> EL0 `neuro` ABI now lives in `hal::neuroabi` (os/kernel/hal/src/neuroabi.rs), shared with the
//! kernel host so the two cannot drift. v1.0 of the wire format is the one this file used to define, unchanged;
//! v1.1 adds the H_ABI version word, an extended CMD_INFO and CMD_HEALTH.
pub use hal::neuroabi::*;
