// SPDX-License-Identifier: AGPL-3.0-only
//! C2: the P1 reference worker (`conductor-worker`), the heqk-native worker side.
//! - end to end: the real worker behind the device harness and verifier gives the same verified outcome as
//!   the scripted mock;
//! - at-most-once execution across power loss at every write, torn at every interesting length (a crash can
//!   burn a capability, never run it twice);
//! - the kill switch survives the WORKER's reboot too;
//! - the worker enforces the output budget itself, and runs `infer`, `embed` and `classify`;
//! - quotes are signed by the worker key; an unreadable store serves nothing.
use conductor_core::cap::{self, SignRequest};
use conductor_core::class::Tier;
use conductor_core::crypto::{public_key, sha256, sign};
use conductor_core::frame::{self as fr, Body, QuoteRequest, Request, Response};
use conductor_core::harness::{Harness, Outcome as HOutcome};
use conductor_core::signer::Signer;
use conductor_core::verify::Status;
use conductor_core::worker::Refuse;
use conductor_mock::disk::{Disk, Platter, TORN};
use conductor_mock::*;
use conductor_worker::{code, Executor, Layout, Outcome, ResultKey, Run, Worker};
use std::cell::Cell;
use std::rc::Rc;

const LAYOUT: Layout = Layout { high_water_lo: 64, epoch_lo: 66 };
const ANSWER_MAL: &str = r#"{"verdict":"malicious","severity":"medium","summary":"Exploit attempt matching CVE-2024-3400.","evidence":["F1"],"entities":[],"next_step":"investigate","confidence":50}"#;

struct SeedKey([u8; 32]);
impl ResultKey for SeedKey {
    fn public_key(&self) -> [u8; 32] {
        public_key(&self.0)
    }
    fn sign(&self, tag: &[u8], msg: &[u8]) -> Option<[u8; 64]> {
        sign(&self.0, tag, msg)
    }
}

/// A scripted executor. `runs` is shared across boots, so a test can count executions over power cycles.
struct Script {
    out: Vec<u8>,
    runs: Rc<Cell<usize>>,
    ops: Vec<u8>,
    /// Claim a longer output than the buffer holds (a broken engine).
    lie_len: bool,
}
impl Executor for Script {
    fn run(&mut self, op: u8, _model: &[u8; 32], prompt: &[u8], out: &mut [u8]) -> Result<Run, u16> {
        self.runs.set(self.runs.get() + 1);
        self.ops.push(op);
        let text: Vec<u8> = match op {
            cap::op::EMBED => prompt.iter().map(|b| b.wrapping_mul(3)).take(16).collect(),
            cap::op::CLASSIFY => b"label:exploit".to_vec(),
            _ => self.out.clone(),
        };
        let n = text.len().min(out.len());
        out[..n].copy_from_slice(&text[..n]);
        Ok(Run { len: if self.lie_len { out.len() + 1 } else { n }, compute_ms: 7, ttft_ms: 2 })
    }
    fn quote(&self, q: &QuoteRequest) -> (bool, u32, u32, u8) {
        (q.slo_ttft_ms == 0 || q.slo_ttft_ms >= 300, 300, 40, fr::profile::CPU_ONLY)
    }
}

type W = Worker<Disk, SeedKey, Script>;

fn boot(d: Disk, runs: &Rc<Cell<usize>>, out: &str) -> W {
    let s = Script { out: out.as_bytes().to_vec(), runs: runs.clone(), ops: vec![], lie_len: false };
    Worker::boot(d, LAYOUT, SeedKey(WORKER_SEED), s, public_key(&DEVICE_SEED), Tier::P1).expect("store readable")
}

/// The real worker behind the mock kernel's driver.
struct Real(W);
impl Remote for Real {
    fn tier(&self) -> Tier {
        Tier::P1
    }
    fn receive(&mut self, tx: &[u8], session: &[u8; 32], now_ms: u64) -> Vec<Vec<u8>> {
        let mut v = vec![];
        self.0.handle(tx, session, now_ms, &mut |f| v.push(f.to_vec()));
        v
    }
}

#[test]
fn real_worker_end_to_end_through_harness_and_verifier() {
    let runs = Rc::new(Cell::new(0));
    let p = Platter::default();
    let mut w = Real(boot(Disk::new(&p), &runs, ANSWER_MAL));
    let mut k = Kernel::new(policy_p1(), Tier::P1);
    let mut h = Box::new(Harness::new());
    let env = env_with(policy_p1(), public_key(&WORKER_SEED), Tier::P1);
    let job = JobBuilder { l0: conductor_core::job::Verdict::Malicious as u8, ..Default::default() };
    let r = k.run(&mut h, &job.encode(), env, &mut w);
    match r.outcome {
        Some(HOutcome::Verified(v)) => assert_eq!(v.status, Status::Valid),
        o => panic!("expected Verified, got {o:?}"),
    }
    assert_eq!(runs.get(), 1);
    assert_eq!(r.leases_started, r.leases_ended);
    // The replay state is on the worker's disk, not only in memory.
    let w2 = boot(Disk::new(&p), &runs, "");
    assert_eq!(w2.high_water(), w.0.high_water());
    assert!(w2.high_water() >= 1);
    println!("real worker end to end: Verified/Valid through the device harness; high-water {} durable", w2.high_water());
}

// ------------------------------------------------------------------ capabilities signed directly

fn request_bytes(op: u8, prompt: &[u8]) -> Vec<u8> {
    let mut b = vec![0u8; fr::REQ_MAX];
    let n = Request { op, model_digest: MODEL, prompt }.encode(&mut b).unwrap();
    b.truncate(n);
    b
}

fn sign_req(op: u8, prompt: &[u8], max_out_units: u32, max_bytes: u32) -> SignRequest {
    SignRequest {
        tier: Tier::P1 as u8,
        worker_public_key: public_key(&WORKER_SEED),
        session_binding: [5; 32],
        job_id: [1; 16],
        request_hash: sha256(&[&request_bytes(op, prompt)]),
        model_digest: MODEL,
        operations: op,
        data_classes: 1,
        egress_policy_id: EGRESS,
        max_input_units: 100,
        max_output_units: max_out_units,
        max_compute_ms: 1000,
        max_response_bytes: max_bytes,
        ttl_ms: 60_000,
        slo_ttft_ms: 0,
        slo_tpot_ms: 0,
        affinity_id: [0; 16],
        cache_scope: 0,
        kv_persist: 0,
        offload_hints: 0,
        energy_policy: 0,
    }
}

fn device() -> Signer<MemCounter> {
    let mut s = Signer::new(DEVICE_SEED, SALT_KEY, public_key(&OWNER_SEED), policy_p1(), MemCounter::new());
    let (rec, sig) = owner_pairing(Tier::P1, public_key(&WORKER_SEED), u64::MAX, 1);
    s.install_pairing(&rec, &sig).unwrap();
    s
}

fn tx(dev: &mut Signer<MemCounter>, op: u8, prompt: &[u8], out_units: u32, bytes: u32) -> Vec<u8> {
    let signed = dev.sign(&sign_req(op, prompt, out_units, bytes), 1_000, &mut |b: &mut [u8]| b.fill(9)).unwrap();
    let mut t = signed.to_vec();
    t.extend_from_slice(&request_bytes(op, prompt));
    t
}

fn frames(w: &mut W, t: &[u8]) -> (Outcome, Vec<Vec<u8>>) {
    let mut v = vec![];
    let o = w.handle(t, &[5; 32], 2_000, &mut |f| v.push(f.to_vec()));
    (o, v)
}

#[test]
fn at_most_once_execution_across_power_loss() {
    let mut cases = 0;
    let mut executed_then_refused = 0;
    let mut burnt = 0;
    for crash_at in 0..4usize {
        for torn in TORN {
            let p = Platter::default();
            let runs = Rc::new(Cell::new(0));
            let mut dev = device();
            // An earlier, completed call so both sectors hold state.
            let t0 = tx(&mut dev, cap::op::INFER, b"warm", 100, 400);
            assert!(matches!(frames(&mut boot(Disk::new(&p), &runs, "ok"), &t0).0, Outcome::Done { .. }));
            let t = tx(&mut dev, cap::op::INFER, b"the call", 100, 400);
            // Boot 1: the power goes after `crash_at` writes.
            let mut w = boot(Disk::crashing(&p, crash_at, torn), &runs, "ok");
            let before = runs.get();
            let o1 = frames(&mut w, &t).0;
            let ran_first = runs.get() > before;
            assert_eq!(ran_first, matches!(o1, Outcome::Done { .. }), "{o1:?}");
            if !ran_first {
                assert_eq!(o1, Outcome::NotDurable);
            }
            // Boot 2: the same bytes again (an attacker's replay, or the device retrying).
            let mut w2 = boot(Disk::new(&p), &runs, "ok");
            let o2 = frames(&mut w2, &t).0;
            if ran_first {
                assert_eq!(o2, Outcome::Refused(Refuse::Replay), "crash at {crash_at}, torn {torn}: executed twice");
                executed_then_refused += 1;
            }
            // And a third time on any boot: never more than one execution of this capability in total.
            let _ = frames(&mut boot(Disk::new(&p), &runs, "ok"), &t);
            let n = runs.get() - before;
            assert!(n <= 1, "crash at {crash_at}, torn {torn}: executed {n} times");
            // Never run: the high-water record landed although the write reported failure, so the capability
            // is burnt (the device sees a timeout and issues a new one). Never twice.
            burnt += usize::from(n == 0);
            // The worker still serves new capabilities.
            let t2 = tx(&mut dev, cap::op::INFER, b"next", 100, 400);
            assert!(matches!(frames(&mut boot(Disk::new(&p), &runs, "ok"), &t2).0, Outcome::Done { .. }));
            cases += 1;
        }
    }
    println!("at-most-once: {cases} crash points, no capability executed twice ({executed_then_refused} ran before the crash and were refused as Replay after it; {burnt} burnt without running)");
}

#[test]
fn kill_switch_survives_the_workers_reboot() {
    let p = Platter::default();
    let runs = Rc::new(Cell::new(0));
    let mut dev = device();
    let old = tx(&mut dev, cap::op::INFER, b"before the kill switch", 100, 400);
    let e = dev.bump_epoch().unwrap();
    let ann = dev.announce_epoch(1_500).unwrap();
    let mut w = boot(Disk::new(&p), &runs, "ok");
    assert_eq!(w.on_epoch(&ann), Some(e));
    // A forged announcement is refused.
    let mut forged = ann;
    forged[40] ^= 1;
    assert_eq!(w.on_epoch(&forged), None);
    drop(w);
    let mut w2 = boot(Disk::new(&p), &runs, "ok");
    assert_eq!(w2.min_epoch(), e, "the worker's epoch must survive its reboot");
    assert_eq!(frames(&mut w2, &old).0, Outcome::Refused(Refuse::Revoked));
    assert_eq!(runs.get(), 0);
    let new = tx(&mut dev, cap::op::INFER, b"after", 100, 400);
    assert!(matches!(frames(&mut w2, &new).0, Outcome::Done { .. }));
    println!("kill switch on the worker: epoch {e} durable across the worker's reboot; the old capability refused as Revoked");
}

fn final_of(fs: &[Vec<u8>]) -> Response<'_> {
    Response::decode(fs.last().unwrap()).unwrap()
}

#[test]
fn ops_budget_and_result_signature() {
    let p = Platter::default();
    let runs = Rc::new(Cell::new(0));
    let mut dev = device();
    let mut w = boot(Disk::new(&p), &runs, &"x".repeat(2_500));
    // infer: 2,500 bytes stream as 3 chunks and a FINAL signed by the worker key over the exact output.
    let t = tx(&mut dev, cap::op::INFER, b"explain", 1000, 4000);
    let (o, fs) = frames(&mut w, &t);
    assert!(matches!(o, Outcome::Done { .. }));
    assert_eq!(fs.len(), 4);
    let Body::Final { usage, output_hash, sig } = final_of(&fs).body else { panic!("no FINAL") };
    assert_eq!(output_hash, sha256(&[&vec![b'x'; 2_500]]));
    let c = cap::open(&t[..cap::SIGNED_LEN], &public_key(&DEVICE_SEED)).unwrap();
    let msg = fr::result_message(&c.capability_id, &c.req.request_hash, &output_hash, 3, &usage);
    assert!(conductor_core::crypto::verify(&public_key(&WORKER_SEED), conductor_core::crypto::TAG_RESULT, &msg, &sig));
    // embed and classify run through the same protocol.
    for op in [cap::op::EMBED, cap::op::CLASSIFY] {
        let t = tx(&mut dev, op, b"0123456789abcdef", 100, 400);
        let (o, fs) = frames(&mut w, &t);
        assert!(matches!(o, Outcome::Done { .. }), "{op}: {o:?}");
        assert!(matches!(final_of(&fs).body, Body::Final { .. }));
    }
    assert_eq!(w.executor().ops[1..], [cap::op::EMBED, cap::op::CLASSIFY]);
    // The worker caps the engine at max_response_bytes, and refuses to send more units than granted.
    let t = tx(&mut dev, cap::op::INFER, b"long", 10, 4000);
    let (o, fs) = frames(&mut w, &t);
    assert_eq!(o, Outcome::Failed { counter: cap::open(&t[..cap::SIGNED_LEN], &public_key(&DEVICE_SEED)).unwrap().counter, code: code::OVER_BUDGET });
    assert_eq!(fs.len(), 1);
    assert_eq!(final_of(&fs).body, Body::Error(code::OVER_BUDGET));
    // A broken engine that claims more than its buffer: an ERROR, never an out-of-bounds read.
    let mut broken = Worker::boot(Disk::new(&p), LAYOUT, SeedKey(WORKER_SEED), Script { out: vec![b'y'; 50], runs: runs.clone(), ops: vec![], lie_len: true }, public_key(&DEVICE_SEED), Tier::P1).unwrap();
    let t = tx(&mut dev, cap::op::INFER, b"lie", 100, 40);
    assert!(matches!(frames(&mut broken, &t).0, Outcome::Failed { code: code::EXECUTOR, .. }));
    println!("ops: infer (3 chunks + signed FINAL), embed, classify; output budget and engine length enforced by the worker");
}

#[test]
fn quotes_store_faults_and_refusals() {
    let p = Platter::default();
    let runs = Rc::new(Cell::new(0));
    let mut w = boot(Disk::new(&p), &runs, "ok");
    let q = QuoteRequest { job_id: [3; 16], model_digest: MODEL, in_units: 10, max_out_units: 10, slo_ttft_ms: 500, slo_tpot_ms: 0, offload_hints: 0, energy_policy: 0, nonce: [8; 16] };
    let mut b = [0u8; fr::QREQ_LEN];
    let n = q.encode(&mut b).unwrap();
    let (o, fs) = frames(&mut w, &b[..n]);
    assert_eq!(o, Outcome::Quoted);
    let quote = fr::Quote::open(&fs[0], &public_key(&WORKER_SEED)).expect("signed by the worker key");
    assert_eq!((quote.nonce, quote.can_meet), ([8; 16], true));
    assert!(fr::Quote::open(&fs[0], &public_key(&OTHER_SEED)).is_none());
    // An unreadable store: the worker does not start.
    let mut dead = Disk::new(&p);
    dead.dead = true;
    assert!(Worker::boot(dead, LAYOUT, SeedKey(WORKER_SEED), Script { out: vec![], runs: runs.clone(), ops: vec![], lie_len: false }, public_key(&DEVICE_SEED), Tier::P1).is_none());
    // A store that fails the read-back: nothing runs.
    let mut dev = device();
    let mut bad = Disk::new(&p);
    bad.bad_readback = true;
    let mut w2 = Worker::boot(bad, LAYOUT, SeedKey(WORKER_SEED), Script { out: vec![], runs: runs.clone(), ops: vec![], lie_len: false }, public_key(&DEVICE_SEED), Tier::P1);
    // (A bad read-back also corrupts boot reads; if it boots, the call must not run.)
    if let Some(w2) = w2.as_mut() {
        let t = tx(&mut dev, cap::op::INFER, b"x", 100, 400);
        assert_eq!(frames(w2, &t).0, Outcome::NotDurable);
    }
    assert_eq!(runs.get(), 0);
    // Wrong session, wrong worker, truncated: refused before anything runs.
    let t = tx(&mut dev, cap::op::INFER, b"x", 100, 400);
    let mut o = vec![];
    assert_eq!(w.handle(&t, &[6; 32], 2_000, &mut |f| o.push(f.to_vec())), Outcome::Refused(Refuse::Session));
    assert_eq!(w.handle(&t[..100], &[5; 32], 2_000, &mut |f| o.push(f.to_vec())), Outcome::Unknown);
    assert!(o.is_empty());
    let mut other = Worker::boot(Disk::new(&Platter::default()), LAYOUT, SeedKey(OTHER_SEED), Script { out: vec![], runs: runs.clone(), ops: vec![], lie_len: false }, public_key(&DEVICE_SEED), Tier::P1).unwrap();
    assert_eq!(frames(&mut other, &t).0, Outcome::Refused(Refuse::WrongWorker));
    assert_eq!(runs.get(), 0);
}
