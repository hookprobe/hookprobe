// SPDX-License-Identifier: AGPL-3.0-only
//! SLO admission (Select-N style, heqk as the upper-level scheduler): a data-free, signed, nonce-bound quote
//! before any data leaves; a worker that cannot meet the targets is skipped for the next tier.

use conductor_core::class::{OwnerPolicy, Tier};
use conductor_core::crypto::public_key;
use conductor_core::frame::profile;
use conductor_core::harness::{Abort, Harness, Outcome, Violation};
use conductor_core::ledger::Kind;
use conductor_core::place::{PlaceRefusal, WorkerInfo};
use conductor_core::verify::Status;
use conductor_mock::*;

const ANSWER: &str = r#"{"verdict":"insufficient_evidence","severity":"medium","summary":"ok","evidence":["F1"],"entities":[],"next_step":"investigate","confidence":50}"#;

fn two_tiers() -> (Kernel, conductor_core::place::Env, OwnerPolicy) {
    let p = OwnerPolicy { remote_enabled: true, tiers: Tier::P1.bit() | Tier::P3.bit(), ..Default::default() };
    let mut k = Kernel::new(p, Tier::P1);
    let (r, s) = owner_pairing(Tier::P3, public_key(&OTHER_SEED), u64::MAX, 1);
    k.signer.install_pairing(&r, &s).unwrap();
    let mut env = env_with(p, public_key(&WORKER_SEED), Tier::P1);
    env.workers[Tier::P3 as usize] = WorkerInfo { present: true, public_key: public_key(&OTHER_SEED), egress_policy_id: EGRESS, available: true, idle: true };
    (k, env, p)
}

fn slo_job() -> JobBuilder {
    JobBuilder { slo_ttft: 1_000, slo_tpot: 60, ..Default::default() }
}

#[test]
fn quote_accepted_then_job_runs() {
    let (mut k, env, _) = two_tiers();
    let mut ws = vec![MockWorker::new(Tier::P1, vec![ANSWER.into()]), MockWorker::new(Tier::P3, vec![ANSWER.into()]).with_seed(OTHER_SEED)];
    let mut h = Box::new(Harness::new());
    let r = k.run_multi(&mut h, &slo_job().encode(), env, &mut ws);
    assert!(matches!(r.outcome, Some(Outcome::Verified(v)) if v.status == Status::Valid), "{:?}", r.outcome);
    assert_eq!(ws[0].quotes_given, 1);
    assert_eq!(ws[0].calls, 1);
    assert!(r.ledger.iter().any(|l| l.kind == Kind::QuoteAccepted && l.code == profile::ALL_IN_VRAM as u16));
}

#[test]
fn quote_requests_carry_no_content() {
    let (mut k, env, _) = two_tiers();
    let mut ws = vec![MockWorker::new(Tier::P1, vec![ANSWER.into()]), MockWorker::new(Tier::P3, vec![ANSWER.into()]).with_seed(OTHER_SEED)];
    let mut h = Box::new(Harness::new());
    let job = slo_job();
    k.run_multi(&mut h, &job.encode(), env, &mut ws);
    let q = &ws[0].quote_requests[0];
    assert_eq!(q.len(), conductor_core::frame::QREQ_LEN, "fixed size: sizes and targets only");
    for e in &job.evidence {
        assert!(!q.windows(12).any(|w| e.text.as_bytes().windows(12).any(|t| t == w)), "evidence text leaked into a quote request");
    }
    assert!(!q.windows(12).any(|w| job.intent.as_bytes().windows(12).any(|t| t == w)));
}

#[test]
fn slow_worker_is_skipped_for_the_next_tier_without_receiving_data() {
    let (mut k, env, _) = two_tiers();
    let mut slow = MockWorker::new(Tier::P1, vec![ANSWER.into()]);
    slow.quote = (true, 9_000, 400, profile::NVME_STREAM); // e.g. a big MoE streaming experts from NVMe
    let fast = MockWorker::new(Tier::P3, vec![ANSWER.into()]).with_seed(OTHER_SEED);
    let mut ws = vec![slow, fast];
    let mut h = Box::new(Harness::new());
    let r = k.run_multi(&mut h, &slo_job().encode(), env, &mut ws);
    assert!(matches!(r.outcome, Some(Outcome::Verified(_))), "{:?}", r.outcome);
    assert_eq!(r.sessions_opened, vec![Tier::P1, Tier::P3]);
    assert_eq!(r.sessions_closed, vec![Tier::P1]);
    assert_eq!(ws[0].calls, 0, "the declining worker never received a capability or a prompt");
    assert!(ws[0].prompts.is_empty());
    assert_eq!(ws[1].calls, 1);
    assert!(r.ledger.iter().any(|l| l.kind == Kind::QuoteDeclined && l.code == profile::NVME_STREAM as u16));
    assert_eq!(r.leases_started, r.leases_ended);
}

#[test]
fn nobody_meets_the_slo() {
    let (mut k, env, _) = two_tiers();
    let mut a = MockWorker::new(Tier::P1, vec![ANSWER.into()]);
    a.quote = (false, 0, 0, profile::CPU_ONLY);
    let mut b = MockWorker::new(Tier::P3, vec![ANSWER.into()]).with_seed(OTHER_SEED);
    b.quote_tamper = 3; // silent: times out
    let mut ws = vec![a, b];
    let mut h = Box::new(Harness::new());
    let r = k.run_multi(&mut h, &slo_job().encode(), env, &mut ws);
    assert_eq!(r.outcome, Some(Outcome::Refused(PlaceRefusal::NoWorkerMeetsSlo)));
    assert_eq!(r.sends, 2, "only the two quote requests were ever sent");
    assert_eq!(r.leases_started, 0);
}

#[test]
fn forged_or_replayed_quotes_are_rejected() {
    for t in [1u8, 2] {
        let (mut k, env, _) = two_tiers();
        let mut a = MockWorker::new(Tier::P1, vec![ANSWER.into()]);
        a.quote_tamper = t;
        let mut ws = vec![a, MockWorker::new(Tier::P3, vec![ANSWER.into()]).with_seed(OTHER_SEED)];
        let mut h = Box::new(Harness::new());
        let r = k.run_multi(&mut h, &slo_job().encode(), env, &mut ws);
        assert_eq!(r.outcome, Some(Outcome::Rejected(Violation::Malformed)), "tamper {t}");
        assert_eq!(ws[0].calls, 0);
    }
}

#[test]
fn broken_promise_is_recorded() {
    // The worker quotes 300 ms TTFT; the device measures more. Recorded as SloMiss code 2 (quoted, missed).
    let p = OwnerPolicy { remote_enabled: true, tiers: Tier::P1.bit(), ..Default::default() };
    let mut k = Kernel::new(p, Tier::P1);
    k.latency_ms = 250; // the real first token arrives after 250 ms
    let mut w = MockWorker::new(Tier::P1, vec![ANSWER.into()]);
    let mut h = Box::new(Harness::new());
    let job = JobBuilder { slo_ttft: 100, ..Default::default() };
    w.quote = (true, 80, 20, profile::ALL_IN_VRAM); // promises 80 ms
    let r = k.run(&mut h, &job.encode(), env_with(p, public_key(&WORKER_SEED), Tier::P1), &mut w);
    assert!(matches!(r.outcome, Some(Outcome::Verified(_))));
    assert!(r.ledger.iter().any(|l| l.kind == Kind::SloMiss && l.code == 2));
}

#[test]
fn no_slo_means_no_quote_round_trip() {
    let (r, w) = run_simple(&JobBuilder::default(), &[ANSWER], Tamper::None);
    assert!(matches!(r.outcome, Some(Outcome::Verified(_))));
    assert_eq!(w.quotes_given, 0);
    let _ = Abort::Budget;
}
