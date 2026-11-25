// SPDX-License-Identifier: AGPL-3.0-only
//! The job the kernel hands the harness: intent, evidence cards with their data classes, granted tools,
//! the deterministic L0 verdict (if the core has one), the model, the budgets and the offload/cache wishes.
//!
//! The kernel is trusted, but the bytes still pass a strict decoder: evidence text is attacker-influenced
//! (it quotes what the network carried), so it is checked as inert text before it can reach a prompt.

use crate::buf::Buf;
use crate::cap::{cache_scope, energy, offload};
use crate::class::DataClass;
use crate::limits::*;
use crate::wire::Reader;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Verdict {
    Benign = 1,
    Suspicious = 2,
    Malicious = 3,
    InsufficientEvidence = 4,
}

impl Verdict {
    pub fn from_u8(v: u8) -> Option<Self> {
        Some(match v {
            1 => Self::Benign,
            2 => Self::Suspicious,
            3 => Self::Malicious,
            4 => Self::InsufficientEvidence,
            _ => return None,
        })
    }
    pub fn parse_name(s: &[u8]) -> Option<Self> {
        Some(match s {
            b"benign" => Self::Benign,
            b"suspicious" => Self::Suspicious,
            b"malicious" => Self::Malicious,
            b"insufficient_evidence" => Self::InsufficientEvidence,
            _ => return None,
        })
    }
}

#[derive(Clone, Copy)]
pub struct Evidence {
    pub id: u16,
    pub class: DataClass,
    /// The answer must cite it (else INCOMPLETE), and placement must find a tier allowed to see it.
    pub required: bool,
    pub card: Buf<MAX_CARD>,
}

impl Evidence {
    pub const EMPTY: Self = Self { id: 0, class: DataClass::Public, required: false, card: Buf::new() };
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Budget {
    pub max_steps: u8,
    pub max_out_units_total: u32,
    pub max_compute_ms_total: u32,
    pub per_call_compute_ms: u32,
    /// Absolute, on the device's monotonic clock.
    pub deadline_ms: u64,
}

#[derive(Clone, Copy)]
pub struct JobSpec {
    pub job_id: [u8; 16],
    pub model_digest: [u8; 32],
    pub tools_granted: u8,
    /// Raw L0 verdict (0 = none); a plain byte so an empty job is all-zero (.bss, not .data).
    pub l0: u8,
    pub budget: Budget,
    pub affinity_id: [u8; 16],
    pub cache_scope: u8,
    pub offload_hints: u8,
    pub energy_policy: u8,
    pub slo_ttft_ms: u32,
    pub slo_tpot_ms: u32,
    pub intent: Buf<MAX_INTENT>,
    pub evidence: [Evidence; MAX_EVIDENCE],
    pub n_evidence: usize,
}

impl JobSpec {
    pub const EMPTY: Self = Self {
        job_id: [0; 16],
        model_digest: [0; 32],
        tools_granted: 0,
        l0: 0,
        budget: Budget { max_steps: 0, max_out_units_total: 0, max_compute_ms_total: 0, per_call_compute_ms: 0, deadline_ms: 0 },
        affinity_id: [0; 16],
        cache_scope: 0,
        offload_hints: 0,
        energy_policy: 0,
        slo_ttft_ms: 0,
        slo_tpot_ms: 0,
        intent: Buf::new(),
        evidence: [Evidence::EMPTY; MAX_EVIDENCE],
        n_evidence: 0,
    };

    /// An investigation turn (Neuro's request with its five tools) instead of an explainer turn.
    pub fn is_investigation(&self) -> bool {
        self.tools_granted & crate::tools::bit::INV_ALL != 0
    }

    pub fn l0_verdict(&self) -> Option<Verdict> {
        Verdict::from_u8(self.l0)
    }

    pub fn evidence(&self) -> &[Evidence] {
        self.evidence.get(..self.n_evidence).unwrap_or(&[])
    }

    pub fn index_of(&self, id: u16) -> Option<usize> {
        self.evidence().iter().position(|e| e.id == id)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum JobError {
    Length,
    Text,
    Class,
    DuplicateId,
    Budget,
    Option,
}

/// Inert text: valid UTF-8; no control characters except newline; no DEL; no bidirectional overrides or
/// isolates (they let text render differently from what it is). Shared by job cards, tool results and the
/// model's summary.
pub fn inert_text(b: &[u8]) -> bool {
    let Ok(s) = core::str::from_utf8(b) else { return false };
    s.chars().all(|c| {
        let cp = c as u32;
        !(cp < 0x20 && c != '\n'
            || cp == 0x7f
            || (0x80..0xa0).contains(&cp)
            || (0x202a..=0x202e).contains(&cp)
            || (0x2066..=0x2069).contains(&cp)
            || cp == 0x200e
            || cp == 0x200f)
    })
}

impl JobSpec {
    /// Decode in place (the struct is ~9 KiB; the EL0 harness keeps it in .bss, never on the stack).
    ///
    /// Layout: job_id[16] model[32] tools u8 l0 u8 steps u8 cache_scope u8 offload u8 energy u8
    /// affinity[16] slo_ttft u32 slo_tpot u32 out_total u32 compute_total u32 per_call u32 deadline u64
    /// intent_len u16 intent n_ev u8 { id u16 class u8 required u8 len u16 text }*
    /// Reset in place (no 9 KiB temporary).
    pub fn reset(&mut self) {
        self.job_id = [0; 16];
        self.model_digest = [0; 32];
        self.tools_granted = 0;
        self.l0 = 0;
        self.budget = Budget::default();
        self.affinity_id = [0; 16];
        self.cache_scope = 0;
        self.offload_hints = 0;
        self.energy_policy = 0;
        self.slo_ttft_ms = 0;
        self.slo_tpot_ms = 0;
        self.intent.clear();
        for e in self.evidence.iter_mut() {
            e.id = 0;
            e.class = DataClass::Public;
            e.required = false;
            e.card.clear();
        }
        self.n_evidence = 0;
    }

    pub fn decode_into(&mut self, b: &[u8]) -> Result<(), JobError> {
        self.reset();
        let r = &mut Reader::new(b);
        let e = JobError::Length;
        self.job_id = r.arr().ok_or(e)?;
        self.model_digest = r.arr().ok_or(e)?;
        self.tools_granted = r.u8().ok_or(e)?;
        // The two tool sets belong to different turns and are never offered together.
        let t = self.tools_granted;
        if t & !crate::tools::bit::VALID != 0 || (t & crate::tools::bit::ALL != 0 && t & crate::tools::bit::INV_ALL != 0) {
            return Err(JobError::Option);
        }
        self.l0 = r.u8().ok_or(e)?;
        if self.l0 != 0 && Verdict::from_u8(self.l0).is_none() {
            return Err(JobError::Option);
        }
        let steps = r.u8().ok_or(e)?;
        self.cache_scope = r.u8().ok_or(e)?;
        self.offload_hints = r.u8().ok_or(e)?;
        self.energy_policy = r.u8().ok_or(e)?;
        if self.cache_scope > cache_scope::MAX || self.offload_hints & !offload::ALL != 0 || self.energy_policy & !energy::ALL != 0 {
            return Err(JobError::Option);
        }
        self.affinity_id = r.arr().ok_or(e)?;
        if self.cache_scope == cache_scope::SESSION && self.affinity_id == [0; 16] {
            return Err(JobError::Option);
        }
        self.slo_ttft_ms = r.u32().ok_or(e)?;
        self.slo_tpot_ms = r.u32().ok_or(e)?;
        self.budget = Budget {
            max_steps: steps,
            max_out_units_total: r.u32().ok_or(e)?,
            max_compute_ms_total: r.u32().ok_or(e)?,
            per_call_compute_ms: r.u32().ok_or(e)?,
            deadline_ms: r.u64().ok_or(e)?,
        };
        let bd = &self.budget;
        if !(1..=MAX_STEPS).contains(&bd.max_steps)
            || bd.max_out_units_total == 0
            || bd.max_compute_ms_total == 0
            || !(1..=MAX_COMPUTE_MS).contains(&bd.per_call_compute_ms)
        {
            return Err(JobError::Budget);
        }
        let n = usize::from(r.u16().ok_or(e)?);
        let intent = r.take(n).ok_or(e)?;
        if intent.is_empty() || !inert_text(intent) {
            return Err(JobError::Text);
        }
        self.intent.set(intent).ok_or(JobError::Length)?;
        let n_ev = usize::from(r.u8().ok_or(e)?);
        if n_ev > MAX_EVIDENCE {
            return Err(JobError::Length);
        }
        for i in 0..n_ev {
            let id = r.u16().ok_or(e)?;
            let class = DataClass::from_u8(r.u8().ok_or(e)?).ok_or(JobError::Class)?;
            let required = match r.u8().ok_or(e)? {
                0 => false,
                1 => true,
                _ => return Err(JobError::Option),
            };
            let len = usize::from(r.u16().ok_or(e)?);
            let text = r.take(len).ok_or(e)?;
            if text.is_empty() || !inert_text(text) {
                return Err(JobError::Text);
            }
            if self.evidence().iter().any(|x| x.id == id) {
                return Err(JobError::DuplicateId);
            }
            let slot = self.evidence.get_mut(i).ok_or(e)?;
            slot.id = id;
            slot.class = class;
            slot.required = required;
            slot.card.set(text).ok_or(JobError::Length)?;
            self.n_evidence = i.checked_add(1).ok_or(e)?;
        }
        if !r.done() {
            return Err(JobError::Length);
        }
        Ok(())
    }
}
