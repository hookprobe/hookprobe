// SPDX-License-Identifier: AGPL-3.0-only
//! Neuro's guard G and grounding severities on the device path (Neuro's answers to the Conductor, 2026-11-24):
//! G runs on the decoded summary before the verifier, against the cards and earlier tool results the provider
//! was shown; an edit is a ledger record; what G cannot fix gets Neuro's suggested status.
use conductor_core::class::Tier;
use conductor_core::crypto::public_key;
use conductor_core::harness::{Harness, Outcome};
use conductor_core::job::Verdict;
use conductor_core::ledger::Kind;
use conductor_core::verify::{Finding, Status};
use conductor_mock::*;

fn answer(summary: &str) -> String {
    format!(r#"{{"verdict":"malicious","severity":"medium","summary":"{summary}","evidence":["F1"],"entities":[],"next_step":"investigate","confidence":50}}"#)
}

fn run(summary: &str) -> (Report, Vec<u8>) {
    let mut k = Kernel::new(policy_p1(), Tier::P1);
    let mut w = MockWorker::new(Tier::P1, vec![answer(summary)]);
    let mut h = Box::new(Harness::new());
    let env = env_with(policy_p1(), public_key(&WORKER_SEED), Tier::P1);
    let job = JobBuilder { l0: Verdict::Malicious as u8, ..Default::default() };
    let r = k.run(&mut h, &job.encode(), env, &mut w);
    let s = h.summary().to_vec();
    (r, s)
}

fn verified(r: &Report) -> conductor_core::verify::Verification {
    match r.outcome {
        Some(Outcome::Verified(v)) => v,
        o => panic!("expected Verified, got {o:?}"),
    }
}

fn edits(r: &Report) -> Vec<u16> {
    r.ledger.iter().filter(|e| e.kind == Kind::GroundingEdit).map(|e| e.code).collect()
}

#[test]
fn guard_g_strips_an_invented_technique_and_records_it() {
    let (r, s) = run("Exploit attempt matching CVE-2024-3400 (T9999) over HTTPS.");
    let v = verified(&r);
    assert_eq!((v.status, v.finding), (Status::Valid, Finding::None));
    assert_eq!(String::from_utf8_lossy(&s), "Exploit attempt matching CVE-2024-3400 over HTTPS.");
    assert_eq!(edits(&r), vec![1], "the edit is in the ledger");
}

#[test]
fn guard_g_strips_an_unreturned_cve() {
    let (r, s) = run("Matches CVE-2023-1111 and CVE-2024-3400.");
    assert_eq!(verified(&r).status, Status::Valid);
    assert_eq!(String::from_utf8_lossy(&s), "Matches and CVE-2024-3400.");
    assert_eq!(edits(&r), vec![1]);
}

#[test]
fn an_unreturned_cve_that_survives_neuros_g_is_rejected() {
    // Neuro's G cannot remove a CVE id glued to a letter; the verifier's REJECTED catches it.
    let (r, _) = run("Matches CVE-2021-44228x on the host.");
    let v = verified(&r);
    assert_eq!((v.status, v.finding), (Status::Rejected, Finding::UngroundedCve));
    assert_eq!(v.shown_verdict, None);
}

#[test]
fn a_service_without_its_port_is_unverified_and_l0_still_decides() {
    let (r, _) = run("Brute force over SSH against host 7.");
    let v = verified(&r);
    assert_eq!((v.status, v.finding), (Status::Unverified, Finding::ServiceWithoutPort));
    assert_eq!(v.shown_verdict, Some(Verdict::Malicious), "L0's verdict stands; only the wording is unverified");
    assert!(edits(&r).is_empty());
    // HTTPS is on the cards (:443), so naming it is fine.
    assert_eq!(verified(&run("Beaconing to 203.0.113.9 over HTTPS.").0).status, Status::Valid);
}

#[test]
fn real_ids_are_left_alone() {
    let (r, s) = run("Exploit for public-facing application (T1190) per CVE-2024-3400.");
    assert_eq!(verified(&r).status, Status::Valid);
    assert_eq!(String::from_utf8_lossy(&s), "Exploit for public-facing application (T1190) per CVE-2024-3400.");
    assert!(edits(&r).is_empty());
}
