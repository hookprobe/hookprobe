// SPDX-License-Identifier: AGPL-3.0-only
//! The C0 gate (design review v2 §09): capability refusal, replay rejection, budget exhaustion, malformed
//! responses, fault containment — plus injection, data flow, verifier statuses, kill switch and the lease
//! invariant (every lease started is ended exactly once, in every scenario).

use conductor_core::cap::{self, SignRequest};
use conductor_core::class::{DataClass, OwnerPolicy, Tier};
use conductor_core::crypto::public_key;
use conductor_core::harness::{Abort, Harness, Outcome, Violation};
use conductor_core::job::Verdict;
use conductor_core::place::PlaceRefusal;
use conductor_core::signer::SignRefusal;
use conductor_core::tools::ToolRefusal;
use conductor_core::verify::{Finding, Status};
use conductor_core::worker::Refuse;
use conductor_mock::*;

const ANSWER_MAL: &str = r#"{"answer":{"verdict":"malicious","cites":["ev:1"],"summary":"Exploit attempt matching CVE-2024-3400."}}"#;
const ANSWER_DESC: &str = r#"{"answer":{"cites":["ev:1"],"summary":"Traffic matches a known exploit pattern."}}"#;

fn leases_balanced(r: &Report) {
    assert_eq!(r.leases_started, r.leases_ended, "every lease must be ended exactly once: {:?}", r.outcome);
}

fn verified(r: &Report) -> conductor_core::verify::Verification {
    match r.outcome {
        Some(Outcome::Verified(v)) => v,
        o => panic!("expected Verified, got {o:?}"),
    }
}

// ------------------------------------------------------------------ happy paths and verifier statuses

#[test]
fn l0_decides_valid() {
    let job = JobBuilder { l0: Verdict::Malicious as u8, ..Default::default() };
    let (r, w) = run_simple(&job, &[ANSWER_MAL], Tamper::None);
    let v = verified(&r);
    assert_eq!(v.status, Status::Valid);
    assert_eq!(v.shown_verdict, Some(Verdict::Malicious));
    assert!(v.l0_decided);
    assert_eq!(w.calls, 1);
    leases_balanced(&r);
}

#[test]
fn conflict_shows_l0_not_model() {
    let job = JobBuilder { l0: Verdict::Malicious as u8, ..Default::default() };
    let benign = r#"{"answer":{"verdict":"benign","cites":["ev:1"],"summary":"Looks fine."}}"#;
    let v = verified(&run_simple(&job, &[benign], Tamper::None).0);
    assert_eq!((v.status, v.finding), (Status::Conflict, Finding::ContradictsL0));
    assert_eq!(v.shown_verdict, Some(Verdict::Malicious));
    assert_eq!(v.model_verdict, Some(Verdict::Benign));
}

#[test]
fn unverified_when_l0_has_no_opinion() {
    let v = verified(&run_simple(&JobBuilder::default(), &[ANSWER_MAL], Tamper::None).0);
    assert_eq!(v.status, Status::Unverified);
    assert_eq!(v.shown_verdict, None, "a model verdict L0 cannot reproduce is never shown as the verdict");
}

#[test]
fn descriptive_answer_is_valid() {
    let v = verified(&run_simple(&JobBuilder::default(), &[ANSWER_DESC], Tamper::None).0);
    assert_eq!(v.status, Status::Valid);
    assert_eq!(v.shown_verdict, None);
}

#[test]
fn incomplete_when_required_evidence_not_cited() {
    let mut job = JobBuilder::default();
    job.evidence[1].required = true;
    let v = verified(&run_simple(&job, &[ANSWER_DESC], Tamper::None).0);
    assert_eq!((v.status, v.finding), (Status::Incomplete, Finding::MissingRequired));
}

#[test]
fn fabricated_citation_rejected() {
    let fab = r#"{"answer":{"cites":["ev:999"],"summary":"See ev:999."}}"#;
    let v = verified(&run_simple(&JobBuilder::default(), &[fab], Tamper::None).0);
    assert_eq!((v.status, v.finding), (Status::Rejected, Finding::UnknownCitation));
}

#[test]
fn tool_then_answer() {
    let mut k = Kernel::new(policy_p1(), Tier::P1);
    k.tool_data.push((2, DataClass::AggregateReviewed, "17 flows in the last 6 h".into()));
    let mut w = MockWorker::new(
        Tier::P1,
        vec![r#"{"tool":"flows.count","args":{"ev":"ev:2","hours":6}}"#.into(), ANSWER_DESC.into()],
    );
    let mut h = Box::new(Harness::new());
    let r = k.run(&mut h, &JobBuilder::default().encode(), env_with(policy_p1(), public_key(&WORKER_SEED), Tier::P1), &mut w);
    assert_eq!(verified(&r).status, Status::Valid);
    assert_eq!(w.calls, 2);
    assert!(w.prompts[1].contains("17 flows in the last 6 h"), "tool result reaches the next prompt");
    assert_eq!(r.leases_started, 2);
    leases_balanced(&r);
    // Each call got its own single-use capability with a fresh counter.
    let c: Vec<_> = r.signed.iter().map(|b| cap::open(b, &public_key(&DEVICE_SEED)).unwrap()).collect();
    assert_ne!(c[0].capability_id, c[1].capability_id);
    assert!(c[1].counter > c[0].counter);
}

// ------------------------------------------------------------------ capability refusal (placement + signer)

#[test]
fn remote_off_by_default() {
    let mut k = Kernel::new(OwnerPolicy::default(), Tier::P1);
    let mut w = MockWorker::new(Tier::P1, vec![ANSWER_DESC.into()]);
    let mut h = Box::new(Harness::new());
    let r = k.run(&mut h, &JobBuilder::default().encode(), env_with(OwnerPolicy::default(), public_key(&WORKER_SEED), Tier::P1), &mut w);
    assert_eq!(r.outcome, Some(Outcome::Refused(PlaceRefusal::RemoteDisabled)));
    assert_eq!(w.calls, 0);
    assert_eq!(r.sends, 0);
}

#[test]
fn required_fingerprint_needs_owner_approval() {
    let mut job = JobBuilder::default();
    job.evidence.push(Ev { id: 3, class: DataClass::Fingerprint, required: true, text: "device fp 9f2c".into() });
    let (r, w) = run_simple(&job, &[ANSWER_DESC], Tamper::None);
    assert_eq!(r.outcome, Some(Outcome::Refused(PlaceRefusal::NoTierForData)));
    assert_eq!(w.calls, 0);
}

#[test]
fn raw_and_secret_never_leave() {
    for class in [DataClass::Raw, DataClass::Secret] {
        let mut job = JobBuilder::default();
        job.evidence.push(Ev { id: 3, class, required: true, text: "x".into() });
        let all = OwnerPolicy {
            remote_enabled: true,
            tiers: 0xff,
            fingerprints_p1: true,
            fingerprints_p4: true,
            addresses_p1: true,
            addresses_p4: true,
            aggregate_p5: true,
            p4_chain_proven: true,
        };
        let mut k = Kernel::new(all, Tier::P1);
        let mut w = MockWorker::new(Tier::P1, vec![ANSWER_DESC.into()]);
        let mut h = Box::new(Harness::new());
        let r = k.run(&mut h, &job.encode(), env_with(all, public_key(&WORKER_SEED), Tier::P1), &mut w);
        assert_eq!(r.outcome, Some(Outcome::Refused(PlaceRefusal::NoTierForData)), "{class:?}");
    }
}

#[test]
fn optional_card_withheld_from_tier_that_may_not_see_it() {
    let mut job = JobBuilder::default();
    job.evidence.push(Ev { id: 3, class: DataClass::Address, required: false, text: "SECRET-HOSTNAME-fileserver01".into() });
    let (r, w) = run_simple(&job, &[ANSWER_DESC], Tamper::None);
    assert_eq!(verified(&r).status, Status::Valid);
    assert!(!w.prompts[0].contains("SECRET-HOSTNAME"), "an Address card never reaches P1 without the owner's opt-in");
    assert_eq!(r.sign_requests[0].data_classes & DataClass::Address.bit(), 0);
}

#[test]
fn p3_gets_public_only_and_p4_waits_for_proven_chain() {
    let p = OwnerPolicy { remote_enabled: true, tiers: Tier::P3.bit() | Tier::P4.bit(), fingerprints_p4: true, ..Default::default() };
    assert!(!conductor_core::class::allowed(DataClass::Aggregate, Tier::P3, &p));
    assert!(!conductor_core::class::allowed(DataClass::Fingerprint, Tier::P4, &p), "P4 is public-only until C3b proves the chain");
    let proven = OwnerPolicy { p4_chain_proven: true, ..p };
    assert!(conductor_core::class::allowed(DataClass::Fingerprint, Tier::P4, &proven));
    assert!(!conductor_core::class::allowed(DataClass::Fingerprint, Tier::P2, &proven), "fleet_mesh not built");
}

fn sign_req() -> SignRequest {
    SignRequest {
        tier: Tier::P1 as u8,
        worker_public_key: public_key(&WORKER_SEED),
        session_binding: [1; 32],
        job_id: [2; 16],
        request_hash: [3; 32],
        model_digest: MODEL,
        operations: cap::op::INFER,
        data_classes: DataClass::Public.bit(),
        egress_policy_id: EGRESS,
        max_input_units: 10,
        max_output_units: 10,
        max_compute_ms: 10,
        max_response_bytes: 100,
        ttl_ms: 1000,
        slo_ttft_ms: 0,
        slo_tpot_ms: 0,
        affinity_id: [0; 16],
        cache_scope: 0,
        kv_persist: 0,
        offload_hints: 0,
        energy_policy: 0,
    }
}

#[test]
fn signer_does_not_trust_the_harness() {
    let mut k = Kernel::new(policy_p1(), Tier::P1);
    let mut e = |b: &mut [u8]| b.fill(9);
    let s = &mut k.signer;
    assert!(s.sign(&sign_req(), 0, &mut e).is_ok());
    let cases: [(SignRequest, SignRefusal); 7] = [
        (SignRequest { data_classes: DataClass::Raw.bit(), ..sign_req() }, SignRefusal::Invalid(cap::CapError::Classes)),
        (SignRequest { data_classes: DataClass::Fingerprint.bit(), ..sign_req() }, SignRefusal::ClassesNotAllowed),
        (SignRequest { worker_public_key: public_key(&OTHER_SEED), ..sign_req() }, SignRefusal::NotPaired),
        (SignRequest { egress_policy_id: [0; 16], ..sign_req() }, SignRefusal::EgressMismatch),
        (SignRequest { tier: Tier::P2 as u8, ..sign_req() }, SignRefusal::Invalid(cap::CapError::Tier)),
        (SignRequest { operations: 0x80, ..sign_req() }, SignRefusal::Invalid(cap::CapError::Operations)),
        (SignRequest { kv_persist: cap::kv_persist::RAM, ..sign_req() }, SignRefusal::Invalid(cap::CapError::Cache)),
    ];
    for (req, want) in cases {
        assert_eq!(s.sign(&req, 0, &mut e).unwrap_err(), want);
    }
}

#[test]
fn unpaired_worker_aborts_before_anything_is_sent() {
    let mut k = Kernel::new(policy_p1(), Tier::P1);
    k.signer.pairings[0] = None;
    let mut w = MockWorker::new(Tier::P1, vec![ANSWER_DESC.into()]);
    let mut h = Box::new(Harness::new());
    let r = k.run(&mut h, &JobBuilder::default().encode(), env_with(policy_p1(), public_key(&WORKER_SEED), Tier::P1), &mut w);
    assert_eq!(r.outcome, Some(Outcome::Aborted(Abort::SignRefused)));
    assert_eq!(r.sends, 0);
}

#[test]
fn harness_refuses_a_blob_the_signer_did_not_sign() {
    let mut k = Kernel::new(policy_p1(), Tier::P1);
    k.corrupt_signature = true;
    let mut w = MockWorker::new(Tier::P1, vec![ANSWER_DESC.into()]);
    let mut h = Box::new(Harness::new());
    let r = k.run(&mut h, &JobBuilder::default().encode(), env_with(policy_p1(), public_key(&WORKER_SEED), Tier::P1), &mut w);
    assert_eq!(r.outcome, Some(Outcome::Aborted(Abort::SignerMismatch)));
    assert_eq!(r.sends, 0);
}

#[test]
fn cache_salt_is_per_class_and_deterministic() {
    let mut k = Kernel::new(OwnerPolicy { remote_enabled: true, tiers: Tier::P1.bit(), ..Default::default() }, Tier::P1);
    let mut e = |b: &mut [u8]| b.fill(1);
    let pk = public_key(&DEVICE_SEED);
    let a = cap::open(&k.signer.sign(&sign_req(), 0, &mut e).unwrap(), &pk).unwrap();
    let b = cap::open(&k.signer.sign(&sign_req(), 5, &mut e).unwrap(), &pk).unwrap();
    let c = cap::open(&k.signer.sign(&SignRequest { data_classes: DataClass::AggregateReviewed.bit(), ..sign_req() }, 0, &mut e).unwrap(), &pk).unwrap();
    assert_eq!(a.cache_salt, b.cache_salt, "same class, model, affinity, scope: same namespace");
    assert_ne!(a.cache_salt, c.cache_salt, "a different data class never shares a cache namespace");
}

// ------------------------------------------------------------------ replay rejection (worker side and device side)

fn gate_fixture() -> (Kernel, conductor_core::worker::WorkerGate, Vec<u8>, Vec<u8>) {
    let mut k = Kernel::new(policy_p1(), Tier::P1);
    let request = {
        let mut b = vec![0u8; 256];
        let n = conductor_core::frame::Request { op: cap::op::INFER, model_digest: MODEL, prompt: b"hello" }.encode(&mut b).unwrap();
        b.truncate(n);
        b
    };
    let req = SignRequest { request_hash: conductor_core::crypto::sha256(&[&request]), ..sign_req() };
    let mut e = |b: &mut [u8]| b.fill(3);
    let signed = k.signer.sign(&req, 100, &mut e).unwrap().to_vec();
    let gate = MockWorker::new(Tier::P1, vec![]).gate;
    (k, gate, signed, request)
}

#[test]
fn worker_gate_rejects_replay_and_misbinding() {
    let (mut k, mut g, signed, request) = gate_fixture();
    let sess = [1u8; 32];
    assert!(g.accept(&signed, &sess, &request, Some(200)).is_ok());
    assert_eq!(g.accept(&signed, &sess, &request, Some(200)).unwrap_err(), Refuse::Replay);

    let (_, mut g, signed, request) = gate_fixture();
    assert_eq!(g.accept(&signed, &[9; 32], &request, Some(200)).unwrap_err(), Refuse::Session);
    let mut other = request.clone();
    *other.last_mut().unwrap() ^= 1;
    assert_eq!(g.accept(&signed, &sess, &other, Some(200)).unwrap_err(), Refuse::RequestHash);
    assert_eq!(g.accept(&signed, &sess, &request, Some(50)).unwrap_err(), Refuse::NotYetValid);
    assert_eq!(g.accept(&signed, &sess, &request, Some(100 + 1000)).unwrap_err(), Refuse::Expired);
    let mut tampered = signed.clone();
    tampered[40] ^= 1;
    assert!(matches!(g.accept(&tampered, &sess, &request, Some(200)).unwrap_err(), Refuse::Open(cap::OpenError::Signature)));
    let mut wrong_worker = MockWorker::new(Tier::P1, vec![]).gate;
    wrong_worker.my_pk = public_key(&OTHER_SEED);
    assert_eq!(wrong_worker.accept(&signed, &sess, &request, Some(200)).unwrap_err(), Refuse::WrongWorker);
    let mut wrong_tier = MockWorker::new(Tier::P3, vec![]).gate;
    assert_eq!(wrong_tier.accept(&signed, &sess, &request, Some(200)).unwrap_err(), Refuse::WrongTier);

    // Kill switch: once the worker has seen a newer epoch, older capabilities are dead.
    k.signer.bump_epoch();
    let mut e = |b: &mut [u8]| b.fill(4);
    let req = SignRequest { request_hash: conductor_core::crypto::sha256(&[&request]), ..sign_req() };
    let newer = k.signer.sign(&req, 100, &mut e).unwrap();
    let (_, mut g2, old, _) = gate_fixture();
    assert!(g2.accept(&newer, &sess, &request, Some(200)).is_ok());
    assert_eq!(g2.accept(&old, &sess, &request, Some(200)).unwrap_err(), Refuse::Revoked);
}

#[test]
fn device_rejects_frames_replayed_from_a_previous_call() {
    let mut k = Kernel::new(policy_p1(), Tier::P1);
    k.tool_data.push((2, DataClass::Public, "ok".into()));
    let mut w = MockWorker::new(Tier::P1, vec![r#"{"tool":"evidence.get","args":{"id":"ev:2"}}"#.into(), ANSWER_DESC.into()]);
    w.tamper = Tamper::ReplayPreviousCall;
    w.tamper_from = 1;
    let mut h = Box::new(Harness::new());
    let r = k.run(&mut h, &JobBuilder::default().encode(), env_with(policy_p1(), public_key(&WORKER_SEED), Tier::P1), &mut w);
    assert_eq!(r.outcome, Some(Outcome::Rejected(Violation::CapabilityMismatch)));
    leases_balanced(&r);
}

// ------------------------------------------------------------------ malformed and dishonest responses

#[test]
fn every_tamper_is_rejected_and_the_lease_closed() {
    let cases = [
        (Tamper::BadResultSig, Outcome::Rejected(Violation::ResultSignature)),
        (Tamper::BadOutputHash, Outcome::Rejected(Violation::OutputHash)),
        (Tamper::WrongCapId, Outcome::Rejected(Violation::CapabilityMismatch)),
        (Tamper::SkipSeq, Outcome::Rejected(Violation::Sequence)),
        (Tamper::UsageLie, Outcome::Rejected(Violation::Usage)),
        (Tamper::Garbage, Outcome::Rejected(Violation::Malformed)),
        (Tamper::Oversize, Outcome::Rejected(Violation::Oversize)),
        (Tamper::DoubleFinal, Outcome::Rejected(Violation::AfterFinal)),
        (Tamper::ErrorFrame, Outcome::Aborted(Abort::WorkerError)),
        (Tamper::Silent, Outcome::Aborted(Abort::Timeout)),
    ];
    // A long answer so SkipSeq has a second chunk to skip to.
    let long = format!(r#"{{"answer":{{"cites":["ev:1"],"summary":"{}"}}}}"#, "a".repeat(900));
    for (t, want) in cases {
        let (r, _) = run_simple(&JobBuilder::default(), &[long.as_str()], t);
        // DoubleFinal ends the job on the first FINAL; the second frame arrives after Done and is ignored.
        if t == Tamper::DoubleFinal {
            assert!(matches!(r.outcome, Some(Outcome::Verified(_))), "{t:?}: {:?}", r.outcome);
        } else {
            assert_eq!(r.outcome, Some(want), "{t:?}");
        }
        leases_balanced(&r);
    }
}

#[test]
fn strict_schema() {
    let bad = [
        r#"{"answer":{"cites":["ev:1"],"summary":"x","extra":1}}"#,
        r#"{"answer":{"cites":["ev:1"],"summary":"x"}} trailing"#,
        r#"{"answer":{"cites":["ev:1"],"cites":["ev:1"],"summary":"x"}}"#,
        r#"{"answer":{"summary":"x","cites":["ev:1"]}}"#,
        r#"{"answer":{"verdict":"evil","cites":["ev:1"],"summary":"x"}}"#,
        r#"{"answer":{"cites":["ev:01"],"summary":"x"}}"#,
        r#"{"answer":{"cites":["ev:1"],"summary":"tab\there"}}"#,
        "{\"answer\":{\"cites\":[\"ev:1\"],\"summary\":\"\\u0041\"}}",
        "{\"answer\":{\"cites\":[\"ev:1\"],\"summary\":\"bidi \u{202e}override\"}}",
        "{\"answer\":{\"cites\":[\"ev:1\"],\"summary\":\"raw\u{1}ctl\"}}",
        r#"{"tool":"flows.count","args":{"ev":"ev:2","hours":-1}}"#,
        r#"{"tool":"flows.count","args":{"ev":"ev:2","hours":1.5}}"#,
        r#"{"tool":"shell.exec","args":{"cmd":"rm -rf /"}}"#,
        r#"[1,2,3]"#,
        "",
    ];
    for b in bad {
        let (r, _) = run_simple(&JobBuilder::default(), &[b], Tamper::None);
        assert_eq!(r.outcome, Some(Outcome::Rejected(Violation::Schema)), "{b}");
        leases_balanced(&r);
    }
}

// ------------------------------------------------------------------ injection and data flow

#[test]
fn injected_tool_requests_are_refused_then_rejected() {
    let job = JobBuilder { tools: conductor_core::tools::bit::EVIDENCE_GET, ..Default::default() }; // flows.count not granted
    let ask_ungranted = r#"{"tool":"flows.count","args":{"ev":"ev:1","hours":24}}"#;
    let ask_out_of_scope = r#"{"tool":"evidence.get","args":{"id":"ev:77"}}"#;
    let (r, w) = run_simple(&job, &[ask_ungranted, ask_out_of_scope, ask_ungranted, ANSWER_DESC], Tamper::None);
    assert_eq!(r.outcome, Some(Outcome::Rejected(Violation::ToolRefusals)));
    assert!(r.tool_calls.is_empty(), "no refused call ever reached the tool executor");
    let codes: Vec<u16> = r.ledger.iter().filter(|l| l.kind == conductor_core::ledger::Kind::ToolRefused).map(|l| l.code).collect();
    assert_eq!(codes, vec![ToolRefusal::NotGranted as u16, ToolRefusal::EvidenceOutOfScope as u16, ToolRefusal::NotGranted as u16]);
    assert!(w.prompts[1].contains("refused"), "the model is told, so an honest model can recover");
    leases_balanced(&r);
}

#[test]
fn tool_result_of_a_forbidden_class_never_reaches_the_worker() {
    let mut k = Kernel::new(policy_p1(), Tier::P1);
    k.tool_data.push((2, DataClass::Address, "fileserver01.corp.local 10.0.0.5".into()));
    let mut w = MockWorker::new(Tier::P1, vec![r#"{"tool":"evidence.get","args":{"id":"ev:2"}}"#.into(), ANSWER_DESC.into()]);
    let mut h = Box::new(Harness::new());
    let r = k.run(&mut h, &JobBuilder::default().encode(), env_with(policy_p1(), public_key(&WORKER_SEED), Tier::P1), &mut w);
    assert_eq!(verified(&r).status, Status::Valid);
    assert!(w.prompts.iter().all(|p| !p.contains("fileserver01")), "data-flow check withheld the result");
    assert!(r.ledger.iter().any(|l| l.code == ToolRefusal::DataFlow as u16));
}

// ------------------------------------------------------------------ budgets and time

#[test]
fn step_budget_ends_a_tool_loop() {
    let mut k = Kernel::new(policy_p1(), Tier::P1);
    k.tool_data.push((2, DataClass::Public, "ok".into()));
    let mut w = MockWorker::new(Tier::P1, vec![r#"{"tool":"evidence.get","args":{"id":"ev:2"}}"#.into()]);
    let mut h = Box::new(Harness::new());
    let job = JobBuilder { steps: 3, ..Default::default() };
    let r = k.run(&mut h, &job.encode(), env_with(policy_p1(), public_key(&WORKER_SEED), Tier::P1), &mut w);
    assert_eq!(r.outcome, Some(Outcome::Aborted(Abort::Budget)));
    assert_eq!(w.calls, 3);
    leases_balanced(&r);
}

#[test]
fn output_unit_budget_caps_the_capability() {
    let job = JobBuilder { out_total: 8, ..Default::default() };
    let (r, _) = run_simple(&job, &[ANSWER_DESC], Tamper::None);
    assert_eq!(r.sign_requests[0].max_output_units, 8);
    assert!(matches!(r.outcome, Some(Outcome::Rejected(Violation::Usage))), "{:?}", r.outcome);
}

#[test]
fn deadline_aborts() {
    let job = JobBuilder { deadline: 1_005, ..Default::default() };
    let (r, w) = run_simple(&job, &[ANSWER_DESC], Tamper::None);
    assert_eq!(r.outcome, Some(Outcome::Aborted(Abort::Deadline)));
    // A call dispatched just before the deadline is cut off by it: its lease is still closed.
    assert!(w.calls <= 1);
    leases_balanced(&r);
}

#[test]
fn kill_switch_mid_call_closes_the_lease() {
    let mut k = Kernel::new(policy_p1(), Tier::P1);
    k.cancel_after_sends = Some(1);
    let mut w = MockWorker::new(Tier::P1, vec![ANSWER_DESC.into()]);
    let mut h = Box::new(Harness::new());
    let r = k.run(&mut h, &JobBuilder::default().encode(), env_with(policy_p1(), public_key(&WORKER_SEED), Tier::P1), &mut w);
    assert_eq!(r.outcome, Some(Outcome::Aborted(Abort::Cancelled)));
    assert_eq!((r.leases_started, r.leases_ended), (1, 1));
}

// ------------------------------------------------------------------ offload / cache fields

#[test]
fn session_affinity_and_hints_are_carried_and_bound() {
    let job = JobBuilder {
        cache_scope: cap::cache_scope::SESSION,
        affinity: [0xab; 16],
        offload: cap::offload::ALLOW_SPECULATIVE,
        energy: cap::energy::IDLE_ONLY,
        slo_ttft: 2_000,
        slo_tpot: 100,
        ..Default::default()
    };
    let (r, _) = run_simple(&job, &[ANSWER_DESC], Tamper::None);
    let c = cap::open(&r.signed[0], &public_key(&DEVICE_SEED)).unwrap();
    assert_eq!(c.req.affinity_id, [0xab; 16]);
    assert_eq!(c.req.cache_scope, cap::cache_scope::SESSION);
    assert_eq!(c.req.kv_persist, cap::kv_persist::NONE, "no KV persistence before C2's encrypted store");
    assert_eq!((c.req.slo_ttft_ms, c.req.slo_tpot_ms), (2_000, 100));
}

#[test]
fn idle_only_job_waits_for_an_idle_worker() {
    let job = JobBuilder { energy: cap::energy::IDLE_ONLY, ..Default::default() };
    let mut env = env_with(policy_p1(), public_key(&WORKER_SEED), Tier::P1);
    env.workers[1].idle = false;
    let mut k = Kernel::new(policy_p1(), Tier::P1);
    let mut w = MockWorker::new(Tier::P1, vec![ANSWER_DESC.into()]);
    let mut h = Box::new(Harness::new());
    let r = k.run(&mut h, &job.encode(), env, &mut w);
    assert_eq!(r.outcome, Some(Outcome::Refused(PlaceRefusal::WorkerBusy)));
}
