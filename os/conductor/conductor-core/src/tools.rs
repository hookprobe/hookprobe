// SPDX-License-Identifier: AGPL-3.0-only
//! Typed, read-only tools (design review v2 §06). A model's tool call is a PROPOSAL: it is parsed into a
//! typed value, then authorized independently on every call. Capabilities stop the use of tools a job was
//! never granted; argument scoping stops the abuse of tools it was granted (prompt injection asking to
//! read evidence the job did not include). The data-flow check on results lives in the harness.
//!
//! C0 has no write tools. Write actions will only ever be staged as ADR 0053 TTL-bound proposals.

use crate::job::JobSpec;
use crate::limits::MAX_EVIDENCE;

pub mod bit {
    pub const EVIDENCE_GET: u8 = 1 << 0;
    pub const FLOW_COUNT: u8 = 1 << 1;
    pub const ALL: u8 = EVIDENCE_GET | FLOW_COUNT;
}

/// Longest look-back `flows.count` accepts.
pub const MAX_HOURS: u8 = 24;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ToolCall {
    /// The full text of one evidence item the job included.
    EvidenceGet { ev: u16 },
    /// How many flows the device saw for one included evidence item's subject in the last `hours`.
    FlowCount { ev: u16, hours: u8 },
}

impl ToolCall {
    pub fn bit(&self) -> u8 {
        match self {
            Self::EvidenceGet { .. } => bit::EVIDENCE_GET,
            Self::FlowCount { .. } => bit::FLOW_COUNT,
        }
    }
    pub fn name(&self) -> &'static [u8] {
        match self {
            Self::EvidenceGet { .. } => b"evidence.get",
            Self::FlowCount { .. } => b"flows.count",
        }
    }
    pub fn ev(&self) -> u16 {
        match *self {
            Self::EvidenceGet { ev } | Self::FlowCount { ev, .. } => ev,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u16)]
pub enum ToolRefusal {
    /// The job was not granted this tool.
    NotGranted = 1,
    /// The evidence id is not one this job showed to this provider.
    EvidenceOutOfScope = 2,
    /// An argument is outside its declared range.
    ArgOutOfRange = 3,
    /// The tool's result belongs to a data class this provider may not see.
    DataFlow = 4,
    /// The device could not produce a valid result.
    ToolFailed = 5,
}

/// Authorize one call. `included[i]` says whether evidence `i` was shown to the current provider.
pub fn authorize(call: &ToolCall, job: &JobSpec, included: &[bool; MAX_EVIDENCE]) -> Result<(), ToolRefusal> {
    if job.tools_granted & call.bit() == 0 {
        return Err(ToolRefusal::NotGranted);
    }
    let in_scope = job.index_of(call.ev()).and_then(|i| included.get(i).copied()).unwrap_or(false);
    if !in_scope {
        return Err(ToolRefusal::EvidenceOutOfScope);
    }
    if let ToolCall::FlowCount { hours, .. } = *call {
        if !(1..=MAX_HOURS).contains(&hours) {
            return Err(ToolRefusal::ArgOutOfRange);
        }
    }
    Ok(())
}
