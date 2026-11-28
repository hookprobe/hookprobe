// SPDX-License-Identifier: AGPL-3.0-only
//! The harness: a fixed-size, sans-IO state machine for one job (design review v2 §04).
//!
//! The host feeds [`Event`]s and performs the [`Action`]s it gets back. The harness never signs (it asks
//! for a signature), never opens a socket (it asks for a session), never touches evidence storage (it asks
//! for tool results), and never enforces anything (its outcome is evidence for the operator). Every input
//! that comes from the worker is treated as hostile: one violation ends the job as REJECTED and the lease
//! is closed.
//!
//! Flow per model call: place → OpenSession → SessionOpened → Sign → Signed → (StartLease, Send) →
//! Frames… → FINAL → tool call (RunTool → ToolResult → next call) or answer (verify → Finished).
//!
//! An investigation job (a job granted any of Neuro's five tools) sends Neuro's request and gets free text
//! (no check) or one tool call. A read tool is run by the device; its result joins the context as Neuro's
//! `RESULT <tool> <alias>: <text>` line (`gen_investigate.py`) and the next call asks for the next check,
//! until the model asks for none, the step budget is used, or a call is refused. A policy change is staged
//! for the owner and never applied.

use crate::buf::Buf;
use crate::cap::{self, HpExec, SignRequest, SIGNED_LEN};
use crate::class::{allowed, DataClass, Tier};
use crate::crypto::{ct_eq, sha256, verify as sig_verify, TAG_RESULT};
use crate::frame::{self, Body, Request, Response, REQ_MAX};
use crate::job::{inert_text, JobSpec};
use crate::json::{self, JsonError, ModelOutput};
use neuro_contract::{context_ids, grounding, guard, write_system, IdList, Lang, Sink, CHAT_ASSISTANT, CHAT_SYSTEM, CHAT_USER, USER_HEAD, USER_MID};
use crate::ledger::{Kind, Record};
use crate::limits::*;
use crate::place::{place_excluding, Env, PlaceRefusal};
use crate::tools::{authorize, authorize_inv, ToolCall, ToolRefusal};
use neuro_contract::inv;
use crate::verify::{verify_context, verify_grounded, Grounding, Verification};

#[derive(Clone, Copy, Debug)]
pub enum Event<'a> {
    Start,
    SessionOpened { tier: u8, binding: [u8; 32] },
    SessionFailed,
    Signed(&'a [u8]),
    SignRefused(u16),
    Frame(&'a [u8]),
    ToolResult { class: u8, data: &'a [u8] },
    ToolFailed,
    Tick,
    /// The owner's kill switch or job cancellation.
    Cancel,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Violation {
    Malformed = 1,
    CapabilityMismatch = 2,
    Sequence = 3,
    Oversize = 4,
    OutputHash = 5,
    ResultSignature = 6,
    Usage = 7,
    AfterFinal = 8,
    Schema = 9,
    ToolRefusals = 10,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Abort {
    Budget = 1,
    Deadline = 2,
    Timeout = 3,
    WorkerError = 4,
    SignRefused = 5,
    SignerMismatch = 6,
    Session = 7,
    Cancelled = 8,
    PromptTooLarge = 9,
    ToolFailed = 10,
    HostProtocol = 11,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    /// The model answered and the answer was verified (its status may still be REJECTED, e.g. a fabricated
    /// citation).
    Verified(Verification),
    /// The worker broke the protocol or the schema. Shown as REJECTED; the host should suspend the worker.
    Rejected(Violation),
    /// No provider may run this job, with the reason.
    Refused(PlaceRefusal),
    /// Stopped by budget, time, cancellation or a host-side failure.
    Aborted(Abort),
    /// An investigation turn ended as the protocol allows. This says what happened to the model's request,
    /// never that the request was a good one.
    Investigated(Investigation),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Investigation {
    /// Free text: the model asked for no check.
    NoCheck = 1,
    /// The device ran the read tool the model asked for (see the `RunTool` action and the ledger).
    Checked = 2,
    /// The model asked for a policy change; it is staged for the owner (see the `Propose` action).
    Proposed = 3,
    /// The call was well formed but not permitted for this job (see the `ToolRefused` record).
    Refused = 4,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Action {
    OpenSession { tier: Tier },
    /// Close the session to a worker that declined the job (no data was sent to it).
    CloseSession { tier: Tier },
    /// Ask the signer to sign [`Harness::sign_request`].
    Sign,
    /// Close the data-plane paths for the worker and forget the session's lease. Emitted exactly once per
    /// started lease.
    StartLease { tier: Tier, until_ms: u64, egress_policy_id: [u8; 16] },
    EndLease { tier: Tier },
    /// Send [`Harness::tx`] (signed capability ‖ request frame) on the session.
    Send,
    RunTool(ToolCall),
    /// Stage this call as a proposal for the owner (ADR 0053). The host must never apply it.
    Propose(ToolCall),
    Ledger(Record),
    Finished(Outcome),
}

pub const MAX_ACTIONS: usize = 6;

#[derive(Clone, Copy, Debug, Default)]
pub struct Actions {
    items: [Option<Action>; MAX_ACTIONS],
    n: usize,
}

impl Actions {
    pub const fn new() -> Self {
        Self { items: [None; MAX_ACTIONS], n: 0 }
    }
    fn push(&mut self, a: Action) {
        // Capacity is sized for the largest event (ledger + end lease + finished, or ledger + lease + send);
        // an overflow would be a bug, so the last slot is kept for `Finished`.
        if let Some(slot) = self.items.get_mut(self.n) {
            *slot = Some(a);
            self.n = self.n.saturating_add(1);
        }
    }
    pub fn clear(&mut self) {
        *self = Self::default();
    }
    /// A list holding `items` (those beyond the capacity are dropped). For hosts and tests that encode actions.
    pub fn of(items: &[Action]) -> Self {
        let mut a = Self::new();
        for i in items {
            a.push(*i);
        }
        a
    }
    pub fn iter(&self) -> impl Iterator<Item = &Action> {
        self.items.iter().take(self.n).flatten()
    }
    pub fn len(&self) -> usize {
        self.n
    }
    pub fn is_empty(&self) -> bool {
        self.n == 0
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum State {
    /// First, so the all-zero harness is "done / not loaded" and can live in .bss.
    Done,
    Loaded,
    AwaitSession,
    /// SLO admission: a data-free quote request was sent; waiting for the worker's signed quote.
    AwaitQuote,
    AwaitSign,
    Streaming,
    AwaitTool,
}

/// One job. ~40 KiB, all fixed; the EL0 server keeps it in .bss.
pub struct Harness {
    job: JobSpec,
    env: Env,
    state: State,
    /// Raw tier (0 = none). Raw bytes and flags instead of `Option`s keep the empty harness all-zero.
    tier_raw: u8,
    now_ms: u64,
    step: u8,
    refusals: u8,
    out_units_total: u32,
    compute_ms_total: u32,
    session: [u8; 32],
    included: [bool; MAX_EVIDENCE],
    /// Fact ids and aliases of the context in the current prompt (the closed enums of the contract).
    facts: IdList,
    ents: IdList,
    /// The decoded summary of the last answer (static memory, not stack).
    summary: Buf<MAX_SUMMARY>,
    /// Classes in the prompt: included cards plus tool results already added.
    prompt_classes: u8,
    /// Tool results and refusal notes, carried into the next call's prompt.
    transcript: Buf<MAX_PROMPT>,
    prompt: Buf<MAX_PROMPT>,
    /// The evidence cards of the current prompt as the device wrote them (`F<id> <card>` lines). The provider
    /// is shown these after guard A; guard E, its template and guard G read them as they are here.
    cards: Buf<MAX_PROMPT>,
    /// Tool results as received, one per line group. Never shown to a provider (the transcript holds them
    /// after guard A); guard E reads them, as Neuro's E reads the original context.
    results_raw: Buf<MAX_PROMPT>,
    req_frame: Buf<REQ_MAX>,
    request_hash: [u8; 32],
    sign_req: SignRequest,
    has_sign_req: bool,
    cap: HpExec,
    has_cap: bool,
    tx: Buf<{ SIGNED_LEN + REQ_MAX }>,
    output: Buf<MAX_OUTPUT>,
    expected_seq: u32,
    call_started_ms: u64,
    first_chunk: bool,
    lease: bool,
    /// 0 none, 1 evidence.get, 2 flows.count, 3 an investigation tool.
    pending_kind: u8,
    pending_ev: u16,
    pending_hours: u8,
    /// tool, entity, policy and minutes of a pending investigation call.
    pending_inv: [u8; 3],
    pending_minutes: u16,
    /// Tiers whose worker declined this job's SLO.
    declined: u8,
    quote_nonce: [u8; 16],
    quote_sent_ms: u64,
    /// The accepted quote's predicted TTFT (0 = no quote), to record a broken promise.
    quoted_ttft_ms: u32,
}

/// How long a worker has to answer a quote request.
pub const QUOTE_TIMEOUT_MS: u64 = 2_000;

impl Harness {
    pub const fn new() -> Self {
        Self {
            job: JobSpec::EMPTY,
            env: Env {
                device_pk: [0; 32],
                policy: crate::class::OwnerPolicy {
                    remote_enabled: false,
                    tiers: 0,
                    fingerprints_p1: false,
                    fingerprints_p4: false,
                    addresses_p1: false,
                    addresses_p4: false,
                    aggregate_p5: false,
                    p4_chain_proven: false,
                },
                workers: [crate::place::WorkerInfo::EMPTY; 6],
            },
            state: State::Done,
            tier_raw: 0,
            now_ms: 0,
            step: 0,
            refusals: 0,
            out_units_total: 0,
            compute_ms_total: 0,
            session: [0; 32],
            included: [false; MAX_EVIDENCE],
            facts: IdList::new(),
            ents: IdList::new(),
            summary: Buf::new(),
            prompt_classes: 0,
            transcript: Buf::new(),
            prompt: Buf::new(),
            cards: Buf::new(),
            results_raw: Buf::new(),
            req_frame: Buf::new(),
            request_hash: [0; 32],
            sign_req: SignRequest::ZERO,
            has_sign_req: false,
            cap: HpExec::ZERO,
            has_cap: false,
            tx: Buf::new(),
            output: Buf::new(),
            expected_seq: 0,
            call_started_ms: 0,
            first_chunk: false,
            lease: false,
            pending_kind: 0,
            pending_ev: 0,
            pending_hours: 0,
            pending_inv: [0; 3],
            pending_minutes: 0,
            declined: 0,
            quote_nonce: [0; 16],
            quote_sent_ms: 0,
            quoted_ttft_ms: 0,
        }
    }

    /// Load a job decoded from the kernel's bytes, with the current environment. Resets everything.
    pub fn load(&mut self, job_bytes: &[u8], env: Env) -> Result<(), crate::job::JobError> {
        self.reset();
        self.job.decode_into(job_bytes)?;
        self.env = env;
        self.state = State::Loaded;
        Ok(())
    }

    /// Reset in place, field by field: the harness is ~40 KiB and must never be copied through the stack.
    fn reset(&mut self) {
        self.job.reset();
        self.env = Env::default();
        self.state = State::Done;
        self.tier_raw = 0;
        self.now_ms = 0;
        self.step = 0;
        self.refusals = 0;
        self.out_units_total = 0;
        self.compute_ms_total = 0;
        self.session = [0; 32];
        self.included = [false; MAX_EVIDENCE];
        self.prompt_classes = 0;
        self.transcript.clear();
        self.results_raw.clear();
        self.prompt.clear();
        self.req_frame.clear();
        self.request_hash = [0; 32];
        self.sign_req = SignRequest::ZERO;
        self.has_sign_req = false;
        self.cap = HpExec::ZERO;
        self.has_cap = false;
        self.tx.clear();
        self.output.clear();
        self.expected_seq = 0;
        self.call_started_ms = 0;
        self.first_chunk = false;
        self.lease = false;
        self.pending_kind = 0;
        self.pending_inv = [0; 3];
        self.pending_minutes = 0;
        self.declined = 0;
        self.quote_nonce = [0; 16];
        self.quote_sent_ms = 0;
        self.quoted_ttft_ms = 0;
    }

    fn tier(&self) -> Option<Tier> {
        Tier::from_u8(self.tier_raw)
    }

    fn take_pending(&mut self) -> Option<ToolCall> {
        let k = core::mem::take(&mut self.pending_kind);
        match k {
            1 => Some(ToolCall::EvidenceGet { ev: self.pending_ev }),
            2 => Some(ToolCall::FlowCount { ev: self.pending_ev, hours: self.pending_hours }),
            3 => {
                let [tool, entity, policy] = self.pending_inv;
                Some(ToolCall::Investigate { tool, entity, minutes: self.pending_minutes, policy })
            }
            _ => None,
        }
    }

    pub fn job(&self) -> &JobSpec {
        &self.job
    }
    pub fn sign_request(&self) -> Option<&SignRequest> {
        self.has_sign_req.then_some(&self.sign_req)
    }
    pub fn tx(&self) -> &[u8] {
        self.tx.as_slice()
    }
    /// The decoded summary of the last answer, after guard G.
    pub fn summary(&self) -> &[u8] {
        self.summary.as_slice()
    }
    /// Alias `i` of the context the provider was shown: the `entity` of an investigation call. The kernel
    /// wrote the cards, so it alone can map an alias back to a device.
    pub fn entity(&self, i: u8) -> Option<&[u8]> {
        self.ents.get(usize::from(i))
    }
    pub fn prompt(&self) -> &[u8] {
        self.prompt.as_slice()
    }
    pub fn capability(&self) -> Option<&HpExec> {
        self.has_cap.then_some(&self.cap)
    }
    pub fn is_done(&self) -> bool {
        self.state == State::Done
    }

    fn record(&self, kind: Kind, code: u16, digest: [u8; 32]) -> Record {
        Record {
            kind,
            job_id: self.job.job_id,
            capability_id: if self.has_cap { self.cap.capability_id } else { [0; 16] },
            tier: self.tier_raw,
            step: self.step,
            code,
            digest,
        }
    }

    fn end_lease(&mut self, out: &mut Actions) {
        if self.lease {
            self.lease = false;
            if let Some(t) = self.tier() {
                out.push(Action::EndLease { tier: t });
            }
        }
    }

    fn finish(&mut self, out: &mut Actions, o: Outcome) {
        self.end_lease(out);
        let (kind, code) = match o {
            Outcome::Verified(v) => (Kind::Done, v.status as u16),
            Outcome::Rejected(v) => (Kind::Violation, v as u16),
            Outcome::Refused(r) => (Kind::Refused, r as u16),
            Outcome::Aborted(a) => (Kind::Aborted, a as u16),
            Outcome::Investigated(i) => (Kind::Investigated, i as u16),
        };
        out.push(Action::Ledger(self.record(kind, code, [0; 32])));
        out.push(Action::Finished(o));
        self.state = State::Done;
    }

    /// Feed one event at the device's monotonic time `now_ms` (every event carries the time, so deadlines,
    /// timeouts and time-to-first-token never depend on how often the host ticks). `out` is cleared first.
    pub fn handle(&mut self, now_ms: u64, ev: Event, out: &mut Actions) {
        out.clear();
        if self.state == State::Done {
            return;
        }
        self.now_ms = self.now_ms.max(now_ms);
        if self.state != State::Loaded && self.now_ms >= self.job.budget.deadline_ms {
            return self.finish(out, Outcome::Aborted(Abort::Deadline));
        }
        match (self.state, ev) {
            (_, Event::Cancel) => self.finish(out, Outcome::Aborted(Abort::Cancelled)),
            (State::Loaded, Event::Start) => self.start(out),
            (State::AwaitSession, Event::SessionOpened { tier, binding }) => {
                if self.tier_raw == 0 || self.tier_raw != tier {
                    return self.finish(out, Outcome::Aborted(Abort::HostProtocol));
                }
                self.session = binding;
                if self.job.slo_ttft_ms != 0 || self.job.slo_tpot_ms != 0 {
                    self.request_quote(out);
                } else {
                    self.begin_call(out);
                }
            }
            (State::AwaitQuote, Event::Frame(b)) => self.quote(b, out),
            (State::AwaitQuote, Event::Tick) => {
                if self.now_ms.saturating_sub(self.quote_sent_ms) > QUOTE_TIMEOUT_MS {
                    self.decline(out, 0);
                }
            }
            (State::AwaitSession, Event::SessionFailed) => self.finish(out, Outcome::Aborted(Abort::Session)),
            (State::AwaitSign, Event::Signed(blob)) => self.signed(blob, out),
            (State::AwaitSign, Event::SignRefused(_)) => self.finish(out, Outcome::Aborted(Abort::SignRefused)),
            (State::Streaming, Event::Frame(b)) => self.frame(b, out),
            (State::Streaming, Event::Tick) => {
                let limit = if self.has_cap { (self.cap.req.max_compute_ms, self.cap.expiry_ms) } else { (0, 0) };
                let elapsed = self.now_ms.saturating_sub(self.call_started_ms);
                if elapsed > u64::from(limit.0) || self.now_ms >= limit.1 {
                    self.finish(out, Outcome::Aborted(Abort::Timeout));
                }
            }
            // A worker frame outside a call (late, duplicate FINAL, replayed): the worker misbehaves.
            (_, Event::Frame(_)) => self.finish(out, Outcome::Rejected(Violation::AfterFinal)),
            (State::AwaitTool, Event::ToolResult { class, data }) => self.tool_result(class, data, out),
            (State::AwaitTool, Event::ToolFailed) => self.finish(out, Outcome::Aborted(Abort::ToolFailed)),
            (_, Event::Tick) => {}
            _ => self.finish(out, Outcome::Aborted(Abort::HostProtocol)),
        }
    }

    fn start(&mut self, out: &mut Actions) {
        // A window's context is one piece of evidence with one class: required, and shown whole or not at all.
        let ctx_class = DataClass::from_u8(self.job.context_class).filter(|_| self.job.has_context());
        let required = match ctx_class {
            Some(c) => c.bit(),
            None => self.job.evidence().iter().filter(|e| e.required).fold(0u8, |m, e| m | e.class.bit()),
        };
        match place_excluding(required, self.job.energy_policy, &self.env, self.declined) {
            Err(r) => self.finish(out, Outcome::Refused(r)),
            Ok(t) => {
                self.tier_raw = t as u8;
                // Data minimisation: a card reaches the provider only if its class is allowed there.
                let mut mask = 0u8;
                for (i, e) in self.job.evidence().iter().enumerate() {
                    let ok = allowed(e.class, t, &self.env.policy);
                    if let Some(s) = self.included.get_mut(i) {
                        *s = ok;
                    }
                    if ok {
                        mask |= e.class.bit();
                    }
                }
                self.prompt_classes = mask;
                let shown = match ctx_class {
                    // No fact card in the window (only the REST line): there is nothing to ask a model about.
                    Some(c) => {
                        self.prompt_classes = c.bit();
                        allowed(c, t, &self.env.policy) && !self.job.context_parts().0.is_empty()
                    }
                    None => self.included.iter().any(|x| *x),
                };
                if !shown {
                    // Before any session: nothing is opened, signed or sent.
                    self.tier_raw = 0;
                    return self.finish(out, Outcome::Refused(PlaceRefusal::NoEvidence));
                }
                out.push(Action::Ledger(self.record(Kind::Placed, t as u16, [0; 32])));
                out.push(Action::OpenSession { tier: t });
                self.state = State::AwaitSession;
            }
        }
    }

    /// Send a data-free quote request on the open session.
    fn request_quote(&mut self, out: &mut Actions) {
        let n = sha256(&[b"hookprobe/conductor/quote-nonce/v1\0", &self.session, &self.job.job_id, &[self.declined]]);
        self.quote_nonce.copy_from_slice(n.get(..16).unwrap_or(&[0; 16]));
        let est_in = self.job.evidence().iter().map(|e| e.card.len()).fold(self.job.intent.len(), usize::saturating_add);
        let q = frame::QuoteRequest {
            job_id: self.job.job_id,
            model_digest: self.job.model_digest,
            in_units: units(est_in.saturating_add(512)),
            max_out_units: self.job.budget.max_out_units_total.min(MAX_OUT_UNITS),
            slo_ttft_ms: self.job.slo_ttft_ms,
            slo_tpot_ms: self.job.slo_tpot_ms,
            offload_hints: self.job.offload_hints,
            energy_policy: self.job.energy_policy,
            nonce: self.quote_nonce,
        };
        if self.tx.fill_with(|b| q.encode(b)).is_none() {
            return self.finish(out, Outcome::Aborted(Abort::HostProtocol));
        }
        self.quote_sent_ms = self.now_ms;
        out.push(Action::Send);
        self.state = State::AwaitQuote;
    }

    fn quote(&mut self, b: &[u8], out: &mut Actions) {
        let Some(w) = self.tier().and_then(|t| self.env.worker(t)).copied() else {
            return self.finish(out, Outcome::Aborted(Abort::HostProtocol));
        };
        // A forged, replayed or other-job quote is a protocol violation by the worker.
        let Some(q) = frame::Quote::open(b, &w.public_key) else { return self.finish(out, Outcome::Rejected(Violation::Malformed)) };
        if !ct_eq(&q.job_id, &self.job.job_id) || !ct_eq(&q.nonce, &self.quote_nonce) {
            return self.finish(out, Outcome::Rejected(Violation::Malformed));
        }
        if q.meets(self.job.slo_ttft_ms, self.job.slo_tpot_ms) {
            self.quoted_ttft_ms = q.predicted_ttft_ms;
            out.push(Action::Ledger(self.record(Kind::QuoteAccepted, u16::from(q.offload_profile), [0; 32])));
            self.begin_call(out);
        } else {
            self.decline(out, u16::from(q.offload_profile));
        }
    }

    /// The worker cannot meet the SLO (or did not answer): close its session, try the next tier.
    fn decline(&mut self, out: &mut Actions, code: u16) {
        out.push(Action::Ledger(self.record(Kind::QuoteDeclined, code, [0; 32])));
        if let Some(t) = self.tier() {
            out.push(Action::CloseSession { tier: t });
            self.declined |= t.bit();
        }
        self.tier_raw = 0;
        self.included = [false; MAX_EVIDENCE];
        self.start(out);
    }

    /// The explainer prompt, entirely from `neuro_contract`: Neuro's system prompt and closed schema (the
    /// context's ids as enums), the user framing with the evidence as fact cards (`F<id> <card>`), the
    /// ChatML wrapping. Conductor adds only the tool line (when tools are granted) and tool results.
    ///
    /// Guard A (Neuro doc 25) is applied to the cards on the way in: every quoted value is replaced by a
    /// description of it, so text the network carried never reaches the provider. As in `run_eval.py`, the
    /// ids of the schema are those of the context the provider is shown.
    fn build_prompt(&mut self) -> Option<()> {
        self.build_cards()?;
        if self.job.is_investigation() {
            return self.build_inv_prompt();
        }
        self.build_explainer_prompt()
    }

    /// Neuro's investigation request, byte for byte as llama-server renders it (`neuro_contract::inv`): the
    /// system prompt with the five tools, the cards after guard A, the question. Nothing of Conductor's is
    /// added, so the prompt is the one Neuro measured.
    fn build_inv_prompt(&mut self) -> Option<()> {
        // The transcript is free in an investigation job (results are kept as RESULT lines): scratch space
        // for the shown context. Guard A covers the RESULT lines too, as `guard.redact_all` covers the whole
        // context in `inv_eval.py`.
        let shown = &mut self.transcript;
        shown.clear();
        write_shown(self.cards.as_slice(), self.results_raw.as_slice(), self.job.context_parts().1, shown)?;
        self.facts = IdList::new();
        self.ents = IdList::new();
        context_ids(shown.as_slice(), &mut self.facts, &mut self.ents).ok()?;
        self.prompt.clear();
        inv::write_prompt(LANG, shown.as_slice(), self.job.intent.as_slice(), &mut BufSink(&mut self.prompt)).ok()?;
        shown.clear();
        Some(())
    }

    fn build_cards(&mut self) -> Option<()> {
        self.cards.clear();
        if self.job.has_context() {
            // The fact lines as `neuro_contract::cards` wrote them. The REST line goes last, after any results.
            return self.cards.push(self.job.context_parts().0);
        }
        let mut line = [0u8; 8 + MAX_CARD];
        let mut first = true;
        for (i, e) in self.job.evidence().iter().enumerate() {
            if !self.included.get(i).copied().unwrap_or(false) {
                continue;
            }
            if !first {
                self.cards.push(b"\n")?;
            }
            first = false;
            let n = card_line(e.id, e.card.as_slice(), &mut line)?;
            self.cards.push(line.get(..n)?)?;
        }
        Some(())
    }

    fn build_explainer_prompt(&mut self) -> Option<()> {
        // The ids first: the schema in the system prompt lists them. `prompt` is the scratch space here.
        let rest = self.job.context_parts().1;
        let p = &mut self.prompt;
        p.clear();
        write_shown(self.cards.as_slice(), &[], rest, p)?;
        self.facts = IdList::new();
        self.ents = IdList::new();
        context_ids(p.as_slice(), &mut self.facts, &mut self.ents).ok()?;
        p.clear();
        p.push(CHAT_SYSTEM.as_bytes())?;
        write_system(LANG, &self.facts, &self.ents, true, &mut BufSink(p)).ok()?;
        if self.job.tools_granted != 0 {
            p.push(b" Instead of the answer you may call ONE tool, as one JSON object:")?;
            if self.job.tools_granted & crate::tools::bit::EVIDENCE_GET != 0 {
                p.push(b" {\"tool\":\"evidence.get\",\"args\":{\"id\":\"ev:N\"}}")?;
            }
            if self.job.tools_granted & crate::tools::bit::FLOW_COUNT != 0 {
                p.push(b" {\"tool\":\"flows.count\",\"args\":{\"ev\":\"ev:N\",\"hours\":H}} (H 1-24)")?;
            }
            p.push(b" (N is the number of fact FN).")?;
        }
        p.push(CHAT_USER.as_bytes())?;
        p.push(USER_HEAD.as_bytes())?;
        write_shown(self.cards.as_slice(), &[], rest, p)?;
        p.push(USER_MID.as_bytes())?;
        p.push(self.job.intent.as_slice())?;
        if !self.transcript.is_empty() {
            p.push(b"\n\nTool results:\n")?;
            p.push(self.transcript.as_slice())?;
        }
        p.push(CHAT_ASSISTANT.as_bytes())?;
        Some(())
    }

    fn begin_call(&mut self, out: &mut Actions) {
        let b = self.job.budget;
        if self.step >= b.max_steps || self.out_units_total >= b.max_out_units_total || self.compute_ms_total >= b.max_compute_ms_total {
            return self.finish(out, Outcome::Aborted(Abort::Budget));
        }
        let (Some(tier), Some(w)) = (self.tier(), self.tier().and_then(|t| self.env.worker(t)).copied()) else {
            return self.finish(out, Outcome::Aborted(Abort::HostProtocol));
        };
        if self.build_prompt().is_none() {
            return self.finish(out, Outcome::Aborted(Abort::PromptTooLarge));
        }
        let req = Request { op: cap::op::INFER, model_digest: self.job.model_digest, prompt: self.prompt.as_slice() };
        if self.req_frame.fill_with(|b| req.encode(b)).is_none() {
            return self.finish(out, Outcome::Aborted(Abort::PromptTooLarge));
        }
        self.request_hash = sha256(&[self.req_frame.as_slice()]);
        let remaining_out = b.max_out_units_total.saturating_sub(self.out_units_total).min(MAX_OUT_UNITS);
        let remaining_ms = b.max_compute_ms_total.saturating_sub(self.compute_ms_total).min(b.per_call_compute_ms);
        let ttl = b.deadline_ms.saturating_sub(self.now_ms).min(MAX_TTL_MS);
        self.has_sign_req = true;
        self.sign_req = SignRequest {
            tier: tier as u8,
            worker_public_key: w.public_key,
            session_binding: self.session,
            job_id: self.job.job_id,
            request_hash: self.request_hash,
            model_digest: self.job.model_digest,
            operations: cap::op::INFER,
            data_classes: self.prompt_classes,
            egress_policy_id: w.egress_policy_id,
            max_input_units: units(self.prompt.len()).max(1),
            max_output_units: remaining_out.max(1),
            max_compute_ms: remaining_ms.max(1),
            max_response_bytes: u32::try_from(MAX_OUTPUT).unwrap_or(u32::MAX),
            ttl_ms: ttl.max(1),
            slo_ttft_ms: self.job.slo_ttft_ms,
            slo_tpot_ms: self.job.slo_tpot_ms,
            affinity_id: self.job.affinity_id,
            cache_scope: self.job.cache_scope,
            kv_persist: cap::kv_persist::NONE,
            offload_hints: self.job.offload_hints,
            energy_policy: self.job.energy_policy,
        };
        self.has_cap = false;
        out.push(Action::Sign);
        self.state = State::AwaitSign;
    }

    fn signed(&mut self, blob: &[u8], out: &mut Actions) {
        let Ok(c) = cap::open(blob, &self.env.device_pk) else {
            return self.finish(out, Outcome::Aborted(Abort::SignerMismatch));
        };
        // The signer may shorten the TTL, never change what was asked.
        let r = self.sign_req;
        let ok = self.has_sign_req && SignRequest { ttl_ms: c.req.ttl_ms, ..r } == c.req && c.req.ttl_ms <= r.ttl_ms;
        if !ok || self.tx.set(blob).is_none() || self.tx.push(self.req_frame.as_slice()).is_none() {
            return self.finish(out, Outcome::Aborted(Abort::SignerMismatch));
        }
        self.cap = c;
        self.has_cap = true;
        self.output.clear();
        self.expected_seq = 0;
        self.first_chunk = false;
        self.call_started_ms = self.now_ms;
        self.lease = true;
        let Some(tier) = self.tier() else { return self.finish(out, Outcome::Aborted(Abort::HostProtocol)) };
        out.push(Action::Ledger(self.record(Kind::Signed, 0, self.request_hash)));
        out.push(Action::StartLease { tier, until_ms: c.expiry_ms, egress_policy_id: c.req.egress_policy_id });
        out.push(Action::Send);
        self.state = State::Streaming;
    }

    fn frame(&mut self, b: &[u8], out: &mut Actions) {
        if !self.has_cap {
            return self.finish(out, Outcome::Aborted(Abort::HostProtocol));
        }
        let c = self.cap;
        let Some(r) = Response::decode(b) else { return self.finish(out, Outcome::Rejected(Violation::Malformed)) };
        if !ct_eq(&r.capability_id, &c.capability_id) {
            return self.finish(out, Outcome::Rejected(Violation::CapabilityMismatch));
        }
        if r.seq != self.expected_seq {
            return self.finish(out, Outcome::Rejected(Violation::Sequence));
        }
        let Some(next) = self.expected_seq.checked_add(1) else {
            return self.finish(out, Outcome::Rejected(Violation::Sequence));
        };
        self.expected_seq = next;
        match r.body {
            Body::Chunk(d) => {
                let cap_bytes = usize::try_from(c.req.max_response_bytes).unwrap_or(0);
                if self.output.push(d).is_none() || self.output.len() > cap_bytes {
                    return self.finish(out, Outcome::Rejected(Violation::Oversize));
                }
                if !self.first_chunk {
                    self.first_chunk = true;
                    let ttft = self.now_ms.saturating_sub(self.call_started_ms);
                    if c.req.slo_ttft_ms != 0 && ttft > u64::from(c.req.slo_ttft_ms) {
                        // Recorded for placement feedback; an SLO miss is not a security violation.
                        // Code 2: the worker had quoted that it would meet it (a broken promise).
                        let code = if self.quoted_ttft_ms != 0 { 2 } else { 1 };
                        out.push(Action::Ledger(self.record(Kind::SloMiss, code, [0; 32])));
                    }
                }
            }
            Body::Error(_) => self.finish(out, Outcome::Aborted(Abort::WorkerError)),
            Body::Final { usage, output_hash, sig } => self.final_frame(&c, r.seq, usage, output_hash, sig, out),
        }
    }

    fn final_frame(&mut self, c: &HpExec, seq: u32, usage: frame::Usage, output_hash: [u8; 32], sig: [u8; 64], out: &mut Actions) {
        let actual = sha256(&[self.output.as_slice()]);
        if !ct_eq(&actual, &output_hash) {
            return self.finish(out, Outcome::Rejected(Violation::OutputHash));
        }
        let msg = frame::result_message(&c.capability_id, &self.request_hash, &output_hash, seq, &usage);
        if !sig_verify(&c.req.worker_public_key, TAG_RESULT, &msg, &sig) {
            return self.finish(out, Outcome::Rejected(Violation::ResultSignature));
        }
        // The device enforces its own count as well as the worker's report.
        let dev_out = units(self.output.len());
        let elapsed = u32::try_from(self.now_ms.saturating_sub(self.call_started_ms)).unwrap_or(u32::MAX);
        if usage.out_units > c.req.max_output_units
            || dev_out > c.req.max_output_units
            || usage.in_units > c.req.max_input_units
            || usage.compute_ms > c.req.max_compute_ms
        {
            return self.finish(out, Outcome::Rejected(Violation::Usage));
        }
        self.out_units_total = self.out_units_total.saturating_add(usage.out_units.max(dev_out));
        self.compute_ms_total = self.compute_ms_total.saturating_add(usage.compute_ms.max(elapsed));
        self.step = self.step.saturating_add(1);
        self.end_lease(out);
        out.push(Action::Ledger(self.record(Kind::ResultAccepted, 0, output_hash)));
        if self.job.is_investigation() {
            return self.inv_answer(output_hash, out);
        }
        match json::parse(self.output.as_slice(), &self.facts, &self.ents, &mut self.summary) {
            Err(_e @ (JsonError::Syntax | JsonError::Schema | JsonError::Encoding | JsonError::TooLong | JsonError::Trailing)) => {
                self.finish(out, Outcome::Rejected(Violation::Schema))
            }
            Ok(ModelOutput::Answer(mut a)) => {
                // Guard E (Neuro doc 24): prose that repeats eight or more characters of a quoted value of the
                // cards or of a tool result, as received, is replaced by the deterministic template sentence.
                // Verdict, evidence, entities and next step stay as the provider gave them.
                if guard::echoes(self.cards.as_slice(), self.summary.as_slice()) || guard::echoes(self.results_raw.as_slice(), self.summary.as_slice()) {
                    let before = sha256(&[self.summary.as_slice()]);
                    self.summary.clear();
                    if guard::template_summary(self.cards.as_slice(), LANG, &mut BufSink(&mut self.summary)).is_err() {
                        return self.finish(out, Outcome::Rejected(Violation::Schema));
                    }
                    out.push(Action::Ledger(self.record(Kind::EchoFallback, 0, before)));
                }
                // Guard G (Neuro): delete invented technique ids and unreturned CVE ids from the prose, against
                // the cards and the earlier tool results. Then the verifier checks what G cannot fix, and
                // anything G should have removed.
                let ctx: [&[u8]; 2] = [self.cards.as_slice(), self.transcript.as_slice()];
                let before = sha256(&[self.summary.as_slice()]);
                let mut g = grounding::GuardG { removed: 0, overflow: false, len: 0 };
                self.summary.shrink_with(|b, n| {
                    g = grounding::guard_g(b, n, &ctx);
                    g.len
                });
                a.summary_len = self.summary.len();
                if g.overflow {
                    return self.finish(out, Outcome::Rejected(Violation::Schema));
                }
                if g.removed > 0 {
                    let code = u16::try_from(g.removed).unwrap_or(u16::MAX);
                    out.push(Action::Ledger(self.record(Kind::GroundingEdit, code, before)));
                }
                let s = self.summary.as_slice();
                let found = Grounding {
                    unknown_techniques: grounding::technique_check(s).unknown,
                    ungrounded_cves: grounding::ungrounded_cves(s, &ctx),
                    services_without_port: grounding::services_without_port(s, &ctx),
                };
                let v = if self.job.has_context() { verify_context(&a, &self.job, found) } else { verify_grounded(&a, &self.job, &self.included, found) };
                self.finish(out, Outcome::Verified(v));
            }
            Ok(ModelOutput::Tool(call)) => match authorize(&call, &self.job, &self.included) {
                Ok(()) => {
                    (self.pending_kind, self.pending_ev, self.pending_hours) = match call {
                        ToolCall::EvidenceGet { ev } => (1, ev, 0),
                        ToolCall::FlowCount { ev, hours } => (2, ev, hours),
                        // The explainer's parser never yields one; refuse rather than run it.
                        ToolCall::Investigate { .. } => return self.refuse_tool(call, ToolRefusal::NotGranted, out),
                    };
                    out.push(Action::RunTool(call));
                    self.state = State::AwaitTool;
                }
                Err(why) => self.refuse_tool(call, why, out),
            },
        }
    }

    /// The answer of an investigation turn. A malformed call ends the job as REJECTED, as a schema violation
    /// does for the explainer; a well-formed call is authorized on its own, whatever the model was offered.
    fn inv_answer(&mut self, output_hash: [u8; 32], out: &mut Actions) {
        let call = match inv::parse_answer(self.output.as_slice(), &self.ents) {
            Err(_) => return self.finish(out, Outcome::Rejected(Violation::Schema)),
            Ok(inv::Answer::NoTool) => return self.finish(out, Outcome::Investigated(Investigation::NoCheck)),
            Ok(inv::Answer::Call(c)) => c,
        };
        let typed = match authorize_inv(&call, &self.job, self.ents.len()) {
            Ok(t) => t,
            Err(why) => {
                out.push(Action::Ledger(self.record(Kind::ToolRefused, why as u16, output_hash)));
                return self.finish(out, Outcome::Investigated(Investigation::Refused));
            }
        };
        if typed.is_proposal() {
            out.push(Action::Ledger(self.record(Kind::Proposed, typed.bit().into(), output_hash)));
            out.push(Action::Propose(typed));
            return self.finish(out, Outcome::Investigated(Investigation::Proposed));
        }
        let ToolCall::Investigate { tool, entity, minutes, policy } = typed else {
            return self.finish(out, Outcome::Aborted(Abort::HostProtocol));
        };
        self.pending_kind = 3;
        self.pending_inv = [tool, entity, policy];
        self.pending_minutes = minutes;
        out.push(Action::RunTool(typed));
        self.state = State::AwaitTool;
    }

    /// The device's result for an investigation tool: one line of inert, bounded text with a data class. A
    /// newline would let a result forge a card or another result, so it is refused. The ledger gets the
    /// result's hash, not its content. The result goes into the next call's context only if its class may
    /// reach this provider and a step is left; otherwise the job ends with the check done.
    fn inv_result(&mut self, call: ToolCall, class: u8, data: &[u8], out: &mut Actions) {
        let (Some(class), Some(tier)) = (DataClass::from_u8(class), self.tier()) else {
            return self.finish(out, Outcome::Aborted(Abort::HostProtocol));
        };
        if data.is_empty() || data.len() > MAX_TOOL_RESULT || !inert_text(data) || data.contains(&b'\n') {
            return self.finish(out, Outcome::Aborted(Abort::ToolFailed));
        }
        out.push(Action::Ledger(self.record(Kind::ToolRun, call.bit().into(), sha256(&[data]))));
        if !allowed(class, tier, &self.env.policy) || self.step >= self.job.budget.max_steps {
            return self.finish(out, Outcome::Investigated(Investigation::Checked));
        }
        let ToolCall::Investigate { entity, .. } = call else { return self.finish(out, Outcome::Aborted(Abort::HostProtocol)) };
        // "RESULT <tool> <alias>: <text>", after the cards. `results_raw` is the context's tail as the device
        // wrote it; the provider sees it after guard A.
        let mut alias: Buf<{ neuro_contract::ID_MAX }> = Buf::new();
        let line = self.ents.get(usize::from(entity)).and_then(|a| alias.set(a)).and_then(|()| {
            let r = &mut self.results_raw;
            r.push(b"\nRESULT ")?;
            r.push(call.name())?;
            r.push(b" ")?;
            r.push(alias.as_slice())?;
            r.push(b": ")?;
            r.push(data)
        });
        if line.is_none() {
            return self.finish(out, Outcome::Aborted(Abort::PromptTooLarge));
        }
        self.prompt_classes |= class.bit();
        self.begin_call(out);
    }

    fn refuse_tool(&mut self, call: ToolCall, why: ToolRefusal, out: &mut Actions) {
        self.refusals = self.refusals.saturating_add(1);
        // Ledger first; if the job ends here `finish` adds its own record (capacity holds both).
        let rec = self.record(Kind::ToolRefused, why as u16, [0; 32]);
        if self.refusals > MAX_TOOL_REFUSALS {
            out.push(Action::Ledger(rec));
            return self.finish(out, Outcome::Rejected(Violation::ToolRefusals));
        }
        out.push(Action::Ledger(rec));
        let note = self
            .transcript
            .push(b"[")
            .and_then(|_| self.transcript.push(call.name()))
            .and_then(|_| self.transcript.push(b" refused: not permitted for this job]\n"));
        if note.is_none() {
            return self.finish(out, Outcome::Aborted(Abort::PromptTooLarge));
        }
        self.begin_call_after(out);
    }

    /// `begin_call` appends its own actions; keep the earlier ledger entry in `out`.
    fn begin_call_after(&mut self, out: &mut Actions) {
        self.begin_call(out);
    }

    fn tool_result(&mut self, class: u8, data: &[u8], out: &mut Actions) {
        let Some(call) = self.take_pending() else { return self.finish(out, Outcome::Aborted(Abort::HostProtocol)) };
        if matches!(call, ToolCall::Investigate { .. }) {
            return self.inv_result(call, class, data, out);
        }
        let Some(tier) = self.tier() else { return self.finish(out, Outcome::Aborted(Abort::HostProtocol)) };
        // Data flow: a result goes to the provider only if its class may go there.
        let class_ok = DataClass::from_u8(class).is_some_and(|c| allowed(c, tier, &self.env.policy));
        if !class_ok {
            return self.refuse_tool(call, ToolRefusal::DataFlow, out);
        }
        if data.is_empty() || data.len() > MAX_TOOL_RESULT || !inert_text(data) {
            return self.refuse_tool(call, ToolRefusal::ToolFailed, out);
        }
        let mut entry = || -> Option<()> {
            self.transcript.push(b"[")?;
            self.transcript.push(call.name())?;
            self.transcript.push(b" ev:")?;
            self.transcript.push_dec(u64::from(call.ev()))?;
            self.transcript.push(b"]\n")?;
            // Guard A on the way in, as for the cards: a result can quote what the network carried.
            guard::guard_a(data, &mut BufSink(&mut self.transcript)).ok()?;
            self.transcript.push(b"\n")?;
            // The result as received, for guard E only. The newline keeps a quote from pairing across results.
            self.results_raw.push(data)?;
            self.results_raw.push(b"\n")
        };
        if entry().is_none() {
            return self.finish(out, Outcome::Aborted(Abort::PromptTooLarge));
        }
        if let Some(c) = DataClass::from_u8(class) {
            self.prompt_classes |= c.bit();
        }
        out.push(Action::Ledger(self.record(Kind::ToolRun, call.bit().into(), [0; 32])));
        self.begin_call(out);
    }
}

impl Default for Harness {
    fn default() -> Self {
        Self::new()
    }
}

/// The context a provider is shown, after guard A: the fact lines, then the results of earlier checks (each
/// starts with its own line break), then the window's `REST` line. This is the order of Neuro's contexts: cards,
/// `RESULT` lines, `REST` last.
fn write_shown<const N: usize>(cards: &[u8], results: &[u8], rest: &[u8], out: &mut Buf<N>) -> Option<()> {
    guard::guard_a(cards, &mut BufSink(out)).ok()?;
    guard::guard_a(results, &mut BufSink(out)).ok()?;
    if !rest.is_empty() {
        out.push(b"\n")?;
        guard::guard_a(rest, &mut BufSink(out)).ok()?;
    }
    Some(())
}

/// One evidence card as a fact line: `F<id> <card>`.
fn card_line(id: u16, card: &[u8], out: &mut [u8]) -> Option<usize> {
    let mut b: Buf<{ 8 + crate::limits::MAX_CARD }> = Buf::new();
    b.push(b"F")?;
    b.push_dec(u64::from(id))?;
    b.push(b" ")?;
    b.push(card)?;
    let s = b.as_slice();
    out.get_mut(..s.len())?.copy_from_slice(s);
    Some(s.len())
}

/// The language of the device's prompt and of guard E's template sentence.
const LANG: Lang = Lang::En;

struct BufSink<'b, const N: usize>(&'b mut Buf<N>);
impl<const N: usize> Sink for BufSink<'_, N> {
    fn put(&mut self, s: &[u8]) -> Result<(), neuro_contract::ContractError> {
        self.0.push(s).ok_or(neuro_contract::ContractError::Space)
    }
}
