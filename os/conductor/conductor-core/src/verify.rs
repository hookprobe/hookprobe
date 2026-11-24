// SPDX-License-Identifier: AGPL-3.0-only
//! Verification without overclaiming (design review v2 §07).
//!
//! Levels: STRUCTURAL (the strict parser), EVIDENTIAL (every citation exists in what this provider was
//! shown; required evidence cited) and COMPUTATIONAL (the deterministic L0 verdict, when the core has one,
//! DECIDES; the model only words it — Neuro doc 40). The status is never a claim that a conclusion is
//! proven: VALID means "structure and evidence checked, and the conclusion matches L0 or is purely
//! descriptive". Precedence: REJECTED > CONFLICT > INCOMPLETE > UNVERIFIED > VALID.

use crate::job::{JobSpec, Verdict};
use crate::json::Answer;
use crate::limits::MAX_EVIDENCE;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Status {
    Rejected = 1,
    Conflict = 2,
    Incomplete = 3,
    Unverified = 4,
    Valid = 5,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u16)]
pub enum Finding {
    None = 0,
    /// A citation names evidence that does not exist or was not shown to this provider (fabrication).
    UnknownCitation = 1,
    DuplicateCitation = 2,
    EmptySummary = 3,
    /// The model's verdict differs from the deterministic L0 verdict.
    ContradictsL0 = 4,
    /// Required evidence is not cited.
    MissingRequired = 5,
    /// The model states a verdict L0 cannot reproduce.
    NotReproducible = 6,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Verification {
    pub status: Status,
    pub finding: Finding,
    /// The verdict the UI may show. When L0 has one, it is L0's, whatever the model said.
    pub shown_verdict: Option<Verdict>,
    /// True when the shown verdict came from L0, not the model.
    pub l0_decided: bool,
    pub model_verdict: Option<Verdict>,
}

pub fn verify(a: &Answer, job: &JobSpec, included: &[bool; MAX_EVIDENCE]) -> Verification {
    let mk = |status, finding, shown, l0_decided| Verification {
        status,
        finding,
        shown_verdict: shown,
        l0_decided,
        model_verdict: a.verdict,
    };
    // Evidential: every citation exists AND was shown to this provider.
    let mut cited = [false; MAX_EVIDENCE];
    for &id in a.cites() {
        let Some(i) = job.index_of(id) else { return mk(Status::Rejected, Finding::UnknownCitation, None, false) };
        if !included.get(i).copied().unwrap_or(false) {
            return mk(Status::Rejected, Finding::UnknownCitation, None, false);
        }
        match cited.get_mut(i) {
            Some(c) if *c => return mk(Status::Rejected, Finding::DuplicateCitation, None, false),
            Some(c) => *c = true,
            None => return mk(Status::Rejected, Finding::UnknownCitation, None, false),
        }
    }
    if a.summary.is_empty() {
        return mk(Status::Rejected, Finding::EmptySummary, None, false);
    }
    // Computational: L0 decides where it has a verdict.
    if let (Some(l0), Some(m)) = (job.l0_verdict(), a.verdict) {
        if l0 != m {
            return mk(Status::Conflict, Finding::ContradictsL0, Some(l0), true);
        }
    }
    let missing = job.evidence().iter().enumerate().any(|(i, e)| e.required && !cited.get(i).copied().unwrap_or(false));
    if missing {
        return mk(Status::Incomplete, Finding::MissingRequired, job.l0_verdict(), job.l0_verdict().is_some());
    }
    match (job.l0_verdict(), a.verdict) {
        (Some(l0), _) => mk(Status::Valid, Finding::None, Some(l0), true),
        (None, Some(_)) => mk(Status::Unverified, Finding::NotReproducible, None, false),
        (None, None) => mk(Status::Valid, Finding::None, None, false),
    }
}
