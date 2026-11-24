// SPDX-License-Identifier: AGPL-3.0-only
//! Host-only C0 bench: a mock kernel that hosts the harness (signer, sessions, leases, tool executor,
//! ledger sink) and a scripted mock worker that can behave or misbehave. Used by the gate tests, the fuzz
//! tests and the measurement tool. Never part of a device image.

use conductor_core::cap::{self, SignRequest};
use conductor_core::class::{DataClass, OwnerPolicy, Tier};
use conductor_core::crypto::{public_key, sha256, sign, TAG_RESULT};
use conductor_core::frame::{self as fr, result_message, Body, Request, Response, Usage};
use conductor_core::crypto::TAG_QUOTE;
use conductor_core::harness::{Action, Actions, Event, Harness, Outcome};
use conductor_core::ledger::Record;
use conductor_core::limits::{units, MAX_CHUNK};
use conductor_core::place::{Env, WorkerInfo};
use conductor_core::pairing::{PairingRecord, RECORD_LEN as PAIR_LEN, TAG_RECORD};
use conductor_core::signer::{CounterStore, Signer};
use conductor_core::tools::ToolCall;
use conductor_core::worker::{Refuse, WorkerGate};

/// RAM-only sealed state for the host mock (counter, epoch). The device uses `conductor_core::durable::Sealed`.
pub struct MemCounter(pub u64, pub u32);
impl MemCounter {
    pub fn new() -> Self {
        Self(0, 1)
    }
}
impl Default for MemCounter {
    fn default() -> Self {
        Self::new()
    }
}
impl CounterStore for MemCounter {
    fn advance(&mut self) -> Option<u64> {
        self.0 = self.0.checked_add(1)?;
        Some(self.0)
    }
    fn epoch(&self) -> Option<u32> {
        Some(self.1.max(1))
    }
    fn bump_epoch(&mut self) -> Option<u32> {
        self.1 = self.1.max(1).checked_add(1)?;
        Some(self.1)
    }
}

/// Deterministic xorshift entropy for reproducible tests.
pub struct Rng(pub u64);
impl Rng {
    pub fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }
    pub fn fill(&mut self, b: &mut [u8]) {
        for v in b {
            *v = self.next_u64() as u8;
        }
    }
    pub fn below(&mut self, n: usize) -> usize {
        (self.next_u64() % n.max(1) as u64) as usize
    }
}

pub const DEVICE_SEED: [u8; 32] = [0x11; 32];
pub const SALT_KEY: [u8; 32] = [0x22; 32];
pub const WORKER_SEED: [u8; 32] = [0x33; 32];
pub const OTHER_SEED: [u8; 32] = [0x44; 32];
pub const EGRESS: [u8; 16] = [0x55; 16];
pub const MODEL: [u8; 32] = [0x66; 32];
pub const OWNER_SEED: [u8; 32] = [0x77; 32];

/// An owner-signed pairing record, as Mission Control would produce after the owner compares the codes.
pub fn owner_pairing(tier: Tier, worker_pk: [u8; 32], valid_until_ms: u64, revision: u32) -> (Vec<u8>, [u8; 64]) {
    let rec = PairingRecord { tier, worker_pk, egress_policy_id: EGRESS, valid_until_ms, revision };
    let mut b = [0u8; PAIR_LEN];
    rec.encode(&mut b);
    let s = sign(&OWNER_SEED, TAG_RECORD, &b).expect("sign");
    (b.to_vec(), s)
}

// ---------------------------------------------------------------- job builder

#[derive(Clone)]
pub struct Ev {
    pub id: u16,
    pub class: DataClass,
    pub required: bool,
    pub text: String,
}

#[derive(Clone)]
pub struct JobBuilder {
    pub job_id: [u8; 16],
    pub tools: u8,
    pub l0: u8,
    pub steps: u8,
    pub cache_scope: u8,
    pub offload: u8,
    pub energy: u8,
    pub affinity: [u8; 16],
    pub slo_ttft: u32,
    pub slo_tpot: u32,
    pub out_total: u32,
    pub compute_total: u32,
    pub per_call: u32,
    pub deadline: u64,
    pub intent: String,
    pub evidence: Vec<Ev>,
}

impl Default for JobBuilder {
    fn default() -> Self {
        Self {
            job_id: [7; 16],
            tools: conductor_core::tools::bit::ALL,
            l0: 0,
            steps: 4,
            cache_scope: 0,
            offload: 0,
            energy: 0,
            affinity: [0; 16],
            slo_ttft: 0,
            slo_tpot: 0,
            out_total: 4096,
            compute_total: 60_000,
            per_call: 20_000,
            deadline: 1_000_000,
            intent: "Explain why host 7 was flagged".into(),
            evidence: vec![
                Ev { id: 1, class: DataClass::Public, required: true, text: "CVE-2024-3400: PAN-OS GlobalProtect command injection".into() },
                Ev { id: 2, class: DataClass::AggregateReviewed, required: false, text: "42 connections to 203.0.113.9:443 in 10 min".into() },
            ],
        }
    }
}

impl JobBuilder {
    pub fn encode(&self) -> Vec<u8> {
        let mut b = Vec::new();
        b.extend_from_slice(&self.job_id);
        b.extend_from_slice(&MODEL);
        b.extend_from_slice(&[self.tools, self.l0, self.steps, self.cache_scope, self.offload, self.energy]);
        b.extend_from_slice(&self.affinity);
        for v in [self.slo_ttft, self.slo_tpot, self.out_total, self.compute_total, self.per_call] {
            b.extend_from_slice(&v.to_le_bytes());
        }
        b.extend_from_slice(&self.deadline.to_le_bytes());
        b.extend_from_slice(&(self.intent.len() as u16).to_le_bytes());
        b.extend_from_slice(self.intent.as_bytes());
        b.push(self.evidence.len() as u8);
        for e in &self.evidence {
            b.extend_from_slice(&e.id.to_le_bytes());
            b.push(e.class as u8);
            b.push(e.required as u8);
            b.extend_from_slice(&(e.text.len() as u16).to_le_bytes());
            b.extend_from_slice(e.text.as_bytes());
        }
        b
    }
}

pub fn policy_p1() -> OwnerPolicy {
    OwnerPolicy { remote_enabled: true, tiers: Tier::P1.bit(), ..Default::default() }
}

pub fn env_with(policy: OwnerPolicy, worker_pk: [u8; 32], tier: Tier) -> Env {
    let mut workers = [WorkerInfo::EMPTY; 6];
    workers[tier as usize] = WorkerInfo { present: true, public_key: worker_pk, egress_policy_id: EGRESS, available: true, idle: true };
    Env { device_pk: public_key(&DEVICE_SEED), policy, workers }
}

// ---------------------------------------------------------------- mock worker

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Tamper {
    None,
    BadResultSig,
    BadOutputHash,
    WrongCapId,
    SkipSeq,
    UsageLie,
    ErrorFrame,
    Silent,
    DoubleFinal,
    Garbage,
    ReplayPreviousCall,
    Oversize,
}

pub struct MockWorker {
    pub gate: WorkerGate,
    pub seed: [u8; 32],
    /// Model output per call; the last one repeats.
    pub outputs: Vec<String>,
    pub tamper: Tamper,
    /// Apply the tamper only from this call index on.
    pub tamper_from: usize,
    pub calls: usize,
    pub refusals: Vec<Refuse>,
    pub prompts: Vec<String>,
    last_frames: Vec<Vec<u8>>,
    /// What this worker quotes: (can_meet, predicted ttft ms, predicted tpot ms, offload profile).
    pub quote: (bool, u32, u32, u8),
    /// Quote misbehaviour: 0 honest, 1 wrong nonce, 2 bad signature, 3 silent.
    pub quote_tamper: u8,
    pub quotes_given: usize,
    /// Quote requests are data-free: record what they carried, to prove it.
    pub quote_requests: Vec<Vec<u8>>,
}

impl MockWorker {
    pub fn new(tier: Tier, outputs: Vec<String>) -> Self {
        Self {
            gate: WorkerGate { my_pk: public_key(&WORKER_SEED), device_pk: public_key(&DEVICE_SEED), tier, high_water: 0, min_epoch: 0 },
            seed: WORKER_SEED,
            outputs,
            tamper: Tamper::None,
            tamper_from: 0,
            calls: 0,
            refusals: vec![],
            prompts: vec![],
            last_frames: vec![],
            quote: (true, 300, 40, fr::profile::ALL_IN_VRAM),
            quote_tamper: 0,
            quotes_given: 0,
            quote_requests: vec![],
        }
    }

    pub fn with_seed(mut self, seed: [u8; 32]) -> Self {
        self.seed = seed;
        self.gate.my_pk = public_key(&seed);
        self
    }

    fn answer_quote(&mut self, tx: &[u8]) -> Vec<Vec<u8>> {
        self.quote_requests.push(tx.to_vec());
        let Some(q) = fr::QuoteRequest::decode(tx) else { return vec![] };
        if self.quote_tamper == 3 {
            return vec![];
        }
        self.quotes_given += 1;
        let (can_meet, ttft, tpot, prof) = self.quote;
        let mut nonce = q.nonce;
        if self.quote_tamper == 1 {
            nonce[0] ^= 1;
        }
        let quote = fr::Quote { job_id: q.job_id, nonce, can_meet, predicted_ttft_ms: ttft, predicted_tpot_ms: tpot, offload_profile: prof, valid_ms: 5_000 };
        let mut body = [0u8; fr::QUOTE_BODY_LEN];
        quote.encode_body(&mut body).unwrap();
        let key = if self.quote_tamper == 2 { OTHER_SEED } else { self.seed };
        let s = sign(&key, TAG_QUOTE, &body).unwrap();
        let mut out = body.to_vec();
        out.extend_from_slice(&s);
        vec![out]
    }

    /// Receive `signed ‖ request` on a session; return the response frames.
    pub fn receive(&mut self, tx: &[u8], session: &[u8; 32], now_ms: u64) -> Vec<Vec<u8>> {
        if tx.starts_with(&fr::QREQ_MAGIC) {
            return self.answer_quote(tx);
        }
        let (signed, request) = tx.split_at(cap::SIGNED_LEN.min(tx.len()));
        let c = match self.gate.accept(signed, session, request, Some(now_ms)) {
            Ok(c) => c,
            Err(e) => {
                self.refusals.push(e);
                return vec![];
            }
        };
        let req = Request::decode(request).expect("gate accepted it");
        self.prompts.push(String::from_utf8_lossy(req.prompt).into_owned());
        let idx = self.calls;
        self.calls += 1;
        let tamper = if idx >= self.tamper_from { self.tamper } else { Tamper::None };
        if tamper == Tamper::ReplayPreviousCall && !self.last_frames.is_empty() {
            return self.last_frames.clone();
        }
        let mut text = self.outputs.get(idx).or(self.outputs.last()).cloned().unwrap_or_default().into_bytes();
        if tamper == Tamper::Oversize {
            text = vec![b'x'; 5000];
        }
        let cap_id = if tamper == Tamper::WrongCapId { [0xee; 16] } else { c.capability_id };
        let mut frames = vec![];
        let mut seq = 0u32;
        for chunk in text.chunks(MAX_CHUNK.min(600)) {
            frames.push(enc(&Response { capability_id: cap_id, seq, body: Body::Chunk(chunk) }));
            seq += if tamper == Tamper::SkipSeq { 2 } else { 1 };
        }
        if tamper == Tamper::Garbage {
            frames.push(b"HQRS\x01\x09garbage".to_vec());
        }
        if tamper == Tamper::ErrorFrame {
            frames.push(enc(&Response { capability_id: cap_id, seq, body: Body::Error(7) }));
            return frames;
        }
        if tamper == Tamper::Silent {
            return vec![];
        }
        let mut usage = Usage { in_units: units(req.prompt.len()), out_units: units(text.len()), compute_ms: 5, ttft_ms: 1 };
        if tamper == Tamper::UsageLie {
            usage.out_units = c.req.max_output_units + 1;
        }
        let mut hash = sha256(&[&text]);
        let sig_hash = hash;
        if tamper == Tamper::BadOutputHash {
            hash[0] ^= 1;
        }
        let msg = result_message(&cap_id, &c.req.request_hash, &sig_hash, seq, &usage);
        let key = if tamper == Tamper::BadResultSig { OTHER_SEED } else { self.seed };
        let s = sign(&key, TAG_RESULT, &msg).expect("sign");
        let fin = enc(&Response { capability_id: cap_id, seq, body: Body::Final { usage, output_hash: hash, sig: s } });
        frames.push(fin.clone());
        if tamper == Tamper::DoubleFinal {
            frames.push(fin);
        }
        self.last_frames = frames.clone();
        frames
    }
}

/// Anything that answers on a worker session: the scripted [`MockWorker`], or the real reference worker
/// (`conductor-worker`) through an adapter in the C2 tests.
pub trait Remote {
    fn tier(&self) -> Tier;
    fn receive(&mut self, tx: &[u8], session: &[u8; 32], now_ms: u64) -> Vec<Vec<u8>>;
}

impl Remote for MockWorker {
    fn tier(&self) -> Tier {
        self.gate.tier
    }
    fn receive(&mut self, tx: &[u8], session: &[u8; 32], now_ms: u64) -> Vec<Vec<u8>> {
        MockWorker::receive(self, tx, session, now_ms)
    }
}

pub fn enc(r: &Response) -> Vec<u8> {
    let mut b = vec![0u8; 4096];
    let n = r.encode(&mut b).expect("encode");
    b.truncate(n);
    b
}

// ---------------------------------------------------------------- mock kernel / driver

pub struct Kernel {
    pub signer: Signer<MemCounter>,
    pub rng: Rng,
    pub now: u64,
    /// Tool results by evidence id: (class, text). Missing = tool failure.
    pub tool_data: Vec<(u16, DataClass, String)>,
    /// Stop answering after this many ticks without progress (simulated silence).
    pub max_ticks: usize,
    /// Cancel after this many Send actions (kill switch test); None = never.
    pub cancel_after_sends: Option<usize>,
    /// Corrupt the signed blob before handing it back (tests the harness's own check).
    pub corrupt_signature: bool,
    /// Fuzzing hook: may alter each worker frame in flight. Returns true if it changed anything.
    pub frame_mutator: Option<fn(&mut Rng, &mut Vec<u8>) -> bool>,
    /// Set when the mutator changed at least one frame.
    pub mutated: bool,
    /// Simulated network + inference latency added before each worker frame is delivered.
    pub latency_ms: u64,
}

#[derive(Default, Debug)]
pub struct Report {
    pub outcome: Option<Outcome>,
    pub ledger: Vec<Record>,
    pub actions: Vec<Action>,
    pub leases_started: usize,
    pub leases_ended: usize,
    pub sign_requests: Vec<SignRequest>,
    pub signed: Vec<Vec<u8>>,
    pub sends: usize,
    pub tool_calls: Vec<ToolCall>,
    pub sessions_opened: Vec<Tier>,
    pub sessions_closed: Vec<Tier>,
}

impl Kernel {
    pub fn new(policy: OwnerPolicy, tier: Tier) -> Self {
        let mut signer = Signer::new(DEVICE_SEED, SALT_KEY, public_key(&OWNER_SEED), policy, MemCounter::new());
        let (rec, sig) = owner_pairing(tier, public_key(&WORKER_SEED), u64::MAX, 1);
        signer.install_pairing(&rec, &sig).expect("owner-signed pairing");
        Self { signer, rng: Rng(0x9e3779b97f4a7c15), now: 1_000, tool_data: vec![], max_ticks: 3, cancel_after_sends: None, corrupt_signature: false, frame_mutator: None, mutated: false, latency_ms: 0 }
    }

    pub fn run<W: Remote>(&mut self, h: &mut Harness, job: &[u8], env: Env, worker: &mut W) -> Report {
        self.run_multi(h, job, env, std::slice::from_mut(worker))
    }

    /// Several workers on different tiers; each Send goes to the worker of the currently open session.
    pub fn run_multi<W: Remote>(&mut self, h: &mut Harness, job: &[u8], env: Env, workers: &mut [W]) -> Report {
        let mut rep = Report::default();
        let mut current: Option<Tier> = None;
        h.load(job, env).expect("job decodes");
        let mut out = Actions::default();
        let mut queue: std::collections::VecDeque<Owned> = std::collections::VecDeque::new();
        queue.push_back(Owned::Start);
        let mut idle_ticks = 0;
        let mut guard = 0;
        while !h.is_done() {
            guard += 1;
            assert!(guard < 10_000, "driver loop did not terminate");
            let ev = match queue.pop_front() {
                Some(e) => {
                    idle_ticks = 0;
                    e
                }
                None => {
                    idle_ticks += 1;
                    if idle_ticks > self.max_ticks {
                        // Simulated silence: jump the clock past every budget.
                        self.now += 200_000;
                    } else {
                        self.now += 10;
                    }
                    Owned::Tick
                }
            };
            self.now += 1;
            if matches!(ev, Owned::Frame(_)) {
                self.now += self.latency_ms;
            }
            let now = self.now;
            match &ev {
                Owned::Start => h.handle(now, Event::Start, &mut out),
                Owned::Tick => h.handle(now, Event::Tick, &mut out),
                Owned::Session(t, b) => h.handle(now, Event::SessionOpened { tier: *t, binding: *b }, &mut out),
                Owned::Signed(b) => h.handle(now, Event::Signed(b), &mut out),
                Owned::SignRefused => h.handle(now, Event::SignRefused(1), &mut out),
                Owned::Frame(b) => h.handle(now, Event::Frame(b), &mut out),
                Owned::Tool(c, d) => h.handle(now, Event::ToolResult { class: *c, data: d.as_bytes() }, &mut out),
                Owned::ToolFailed => h.handle(now, Event::ToolFailed, &mut out),
                Owned::Cancel => h.handle(now, Event::Cancel, &mut out),
            }
            let mut session = [0u8; 32];
            for a in out.iter().copied() {
                rep.actions.push(a);
                match a {
                    Action::OpenSession { tier } => {
                        self.rng.fill(&mut session);
                        queue.push_back(Owned::Session(tier as u8, session));
                        current = Some(tier);
                        rep.sessions_opened.push(tier);
                        WORKER_SESSION.with(|c| *c.borrow_mut() = session);
                    }
                    Action::CloseSession { tier } => {
                        assert_eq!(current, Some(tier), "closing a session that is not open");
                        current = None;
                        rep.sessions_closed.push(tier);
                    }
                    Action::Sign => {
                        let r = *h.sign_request().expect("sign request");
                        rep.sign_requests.push(r);
                        let rng = &mut self.rng;
                        match self.signer.sign(&r, now, &mut |b: &mut [u8]| rng.fill(b)) {
                            Ok(mut blob) => {
                                if self.corrupt_signature {
                                    blob[cap::BODY_LEN + 3] ^= 1;
                                }
                                rep.signed.push(blob.to_vec());
                                queue.push_back(Owned::Signed(blob.to_vec()));
                            }
                            Err(_) => queue.push_back(Owned::SignRefused),
                        }
                    }
                    Action::StartLease { .. } => rep.leases_started += 1,
                    Action::EndLease { .. } => rep.leases_ended += 1,
                    Action::Send => {
                        rep.sends += 1;
                        if self.cancel_after_sends == Some(rep.sends) {
                            queue.push_back(Owned::Cancel);
                            continue;
                        }
                        let s = WORKER_SESSION.with(|c| *c.borrow());
                        let worker = workers.iter_mut().find(|w| Some(w.tier()) == current).expect("a worker for the open session");
                        for mut f in worker.receive(h.tx(), &s, now) {
                            if let Some(m) = self.frame_mutator {
                                if m(&mut self.rng, &mut f) {
                                    self.mutated = true;
                                }
                            }
                            queue.push_back(Owned::Frame(f));
                        }
                    }
                    Action::RunTool(call) => {
                        rep.tool_calls.push(call);
                        match self.tool_data.iter().find(|(id, _, _)| *id == call.ev()) {
                            Some((_, c, t)) => queue.push_back(Owned::Tool(*c as u8, t.clone())),
                            None => queue.push_back(Owned::ToolFailed),
                        }
                    }
                    Action::Ledger(r) => rep.ledger.push(r),
                    Action::Finished(o) => rep.outcome = Some(o),
                }
            }
        }
        rep
    }
}

thread_local! {
    static WORKER_SESSION: std::cell::RefCell<[u8; 32]> = const { std::cell::RefCell::new([0; 32]) };
}

enum Owned {
    Start,
    Tick,
    Session(u8, [u8; 32]),
    Signed(Vec<u8>),
    SignRefused,
    Frame(Vec<u8>),
    Tool(u8, String),
    ToolFailed,
    Cancel,
}

/// One-call convenience: default kernel on P1, given job and worker outputs.
pub fn run_simple(job: &JobBuilder, outputs: &[&str], tamper: Tamper) -> (Report, MockWorker) {
    let mut k = Kernel::new(policy_p1(), Tier::P1);
    let mut w = MockWorker::new(Tier::P1, outputs.iter().map(|s| s.to_string()).collect());
    w.tamper = tamper;
    let mut h = Box::new(Harness::new());
    let env = env_with(policy_p1(), public_key(&WORKER_SEED), Tier::P1);
    let r = k.run(&mut h, &job.encode(), env, &mut w);
    (r, w)
}

/// A block device that loses power, for the C1 and C2 power-loss tests. Sectors live on a shared
/// [`Platter`], so a new `Disk` on the same platter is the next boot.
pub mod disk {
    use conductor_core::durable::{BlockDev, IoError};
    use std::cell::RefCell;
    use std::collections::HashMap;
    use std::rc::Rc;

    /// Sectors that survive power loss, shared between "boots".
    #[derive(Default, Clone)]
    pub struct Platter(pub Rc<RefCell<HashMap<u64, [u8; 512]>>>);

    /// A view of the platter for one boot. After `writes_left` writes reach zero, the next write is torn (its first
    /// `torn` bytes land, the rest of the sector keeps its old content) and the power goes: every later operation
    /// fails. `bad_readback` makes the next read of a just-written sector return different bytes.
    pub struct Disk {
        pub p: Platter,
        pub writes_left: Option<usize>,
        pub torn: usize,
        pub dead: bool,
        pub bad_readback: bool,
    }

    impl Disk {
        pub fn new(p: &Platter) -> Self {
            Disk { p: p.clone(), writes_left: None, torn: 0, dead: false, bad_readback: false }
        }
        pub fn crashing(p: &Platter, after: usize, torn: usize) -> Self {
            Disk { p: p.clone(), writes_left: Some(after), torn, dead: false, bad_readback: false }
        }
    }

    impl BlockDev for Disk {
        fn read_block(&self, lba: u64, out: &mut [u8; 512]) -> Result<(), IoError> {
            if self.dead {
                return Err(IoError);
            }
            *out = self.p.0.borrow().get(&lba).copied().unwrap_or([0; 512]);
            if self.bad_readback {
                out[100] ^= 1;
            }
            Ok(())
        }
        fn write_block(&mut self, lba: u64, data: &[u8; 512]) -> Result<(), IoError> {
            if self.dead {
                return Err(IoError);
            }
            if let Some(n) = self.writes_left.as_mut() {
                if *n == 0 {
                    let mut m = self.p.0.borrow_mut();
                    let old = m.get(&lba).copied().unwrap_or([0; 512]);
                    let mut s = old;
                    s[..self.torn].copy_from_slice(&data[..self.torn]);
                    m.insert(lba, s);
                    self.dead = true;
                    return Err(IoError);
                }
                *n -= 1;
            }
            self.p.0.borrow_mut().insert(lba, *data);
            Ok(())
        }
    }

    pub const TORN: [usize; 9] = [0, 1, 8, 15, 16, 47, 48, 100, 512];
}
