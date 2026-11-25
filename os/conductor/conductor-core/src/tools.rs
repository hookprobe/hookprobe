// SPDX-License-Identifier: AGPL-3.0-only
//! Typed, read-only tools (design review v2 §06). A model's tool call is a PROPOSAL: it is parsed into a
//! typed value, then authorized independently on every call. Capabilities stop the use of tools a job was
//! never granted; argument scoping stops the abuse of tools it was granted (prompt injection asking to
//! read evidence the job did not include). The data-flow check on results lives in the harness.
//!
//! C0 has no write tools. Write actions will only ever be staged as ADR 0053 TTL-bound proposals.
//!
//! Two tool sets, never mixed in one job:
//! - Conductor's own (`evidence.get`, `flows.count`), offered to the explainer turn in Conductor's wording.
//! - Neuro's five investigation tools (`neuro_contract::inv::TOOLS`), offered exactly as Neuro's measured
//!   request offers them. The request always lists all five (that is what was measured); the grant decides
//!   which calls the device runs. `propose_policy_change` is never run: it is staged for the owner.

use crate::job::JobSpec;
use crate::limits::MAX_EVIDENCE;

pub mod bit {
    pub const EVIDENCE_GET: u8 = 1 << 0;
    pub const FLOW_COUNT: u8 = 1 << 1;
    /// Conductor's own two tools.
    pub const ALL: u8 = EVIDENCE_GET | FLOW_COUNT;
    /// Neuro's investigation tools: bit `INV_SHIFT + i` grants `neuro_contract::inv::TOOLS[i]`.
    pub const INV_SHIFT: u8 = 2;
    pub const INV_ALL: u8 = 0b0111_1100;
    /// Every bit a job may carry.
    pub const VALID: u8 = ALL | INV_ALL;
}

/// The grant bit of investigation tool `tool` (an index into `neuro_contract::inv::TOOLS`); 0 if there is none.
pub fn inv_bit(tool: u8) -> u8 {
    if usize::from(tool) < neuro_contract::inv::TOOLS.len() {
        1u8.checked_shl(u32::from(bit::INV_SHIFT).saturating_add(u32::from(tool))).unwrap_or(0)
    } else {
        0
    }
}

/// `policy` of a call that carries none.
pub const NO_POLICY: u8 = 0xff;

/// Longest look-back `flows.count` accepts.
pub const MAX_HOURS: u8 = 24;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ToolCall {
    /// The full text of one evidence item the job included.
    EvidenceGet { ev: u16 },
    /// How many flows the device saw for one included evidence item's subject in the last `hours`.
    FlowCount { ev: u16, hours: u8 },
    /// One of Neuro's investigation tools. `tool` indexes `neuro_contract::inv::TOOLS`, `entity` the aliases
    /// of the context the provider was shown ([`crate::harness::Harness::entity`]), `minutes` is 0 when the
    /// model gave none, `policy` indexes `neuro_contract::inv::POLICIES` or is [`NO_POLICY`].
    Investigate { tool: u8, entity: u8, minutes: u16, policy: u8 },
}

impl ToolCall {
    pub fn bit(&self) -> u8 {
        match self {
            Self::EvidenceGet { .. } => bit::EVIDENCE_GET,
            Self::FlowCount { .. } => bit::FLOW_COUNT,
            Self::Investigate { tool, .. } => inv_bit(*tool),
        }
    }
    pub fn name(&self) -> &'static [u8] {
        match self {
            Self::EvidenceGet { .. } => b"evidence.get",
            Self::FlowCount { .. } => b"flows.count",
            Self::Investigate { tool, .. } => neuro_contract::inv::TOOLS.get(usize::from(*tool)).map_or(b"", |t| t.name.as_bytes()),
        }
    }
    /// The evidence item a Conductor tool reads; 0 for an investigation tool (it names an entity instead).
    pub fn ev(&self) -> u16 {
        match *self {
            Self::EvidenceGet { ev } | Self::FlowCount { ev, .. } => ev,
            Self::Investigate { .. } => 0,
        }
    }
    /// A request for a change. The device never runs it: it is staged for the owner.
    pub fn is_proposal(&self) -> bool {
        matches!(*self, Self::Investigate { tool, .. } if neuro_contract::inv::TOOLS.get(usize::from(tool)).is_some_and(|t| t.policy))
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
    if matches!(call, ToolCall::Investigate { .. }) {
        // Entity scope is checked by `authorize_inv`, which knows the shown context's aliases.
        return Err(ToolRefusal::EvidenceOutOfScope);
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

/// Authorize one investigation call, as parsed by `neuro_contract::inv::parse_answer`, and type it.
/// `n_entities` is the number of aliases in the context this provider was shown. The parser already refuses
/// an unknown tool, alias, policy or an out-of-range `minutes`; every one is checked again here, so the
/// authorization does not depend on the parser.
pub fn authorize_inv(call: &neuro_contract::inv::Call, job: &JobSpec, n_entities: usize) -> Result<ToolCall, ToolRefusal> {
    use neuro_contract::inv::{MINUTES_MAX, POLICIES, TOOLS};
    let Some(tool) = TOOLS.get(usize::from(call.tool)) else { return Err(ToolRefusal::NotGranted) };
    if job.tools_granted & inv_bit(call.tool) == 0 {
        return Err(ToolRefusal::NotGranted);
    }
    if usize::from(call.entity) >= n_entities {
        return Err(ToolRefusal::EvidenceOutOfScope);
    }
    let minutes = match call.minutes {
        None => 0,
        Some(m) if tool.minutes && (1..=MINUTES_MAX).contains(&m) => u16::try_from(m).map_err(|_| ToolRefusal::ArgOutOfRange)?,
        Some(_) => return Err(ToolRefusal::ArgOutOfRange),
    };
    let policy = match call.policy {
        None if !tool.policy => NO_POLICY,
        Some(p) if tool.policy && usize::from(p) < POLICIES.len() => p,
        _ => return Err(ToolRefusal::ArgOutOfRange),
    };
    Ok(ToolCall::Investigate { tool: call.tool, entity: call.entity, minutes, policy })
}
