// SPDX-License-Identifier: AGPL-3.0-only
//! ADR 0071 amendment A3: verified redundancy from bit-exact compute (`conductor_core::quorum`).
//! Honest workers agree byte for byte, so agreement is exact equality of signed output hashes; a single
//! wrong worker produces self-contained, re-verifiable evidence; replays and forged votes do not count;
//! audit sampling hits its rate and cannot be predicted without the device key.

use conductor_core::crypto::{public_key, sha256, sign, TAG_RESULT};
use conductor_core::frame::{result_message, Usage};
use conductor_core::quorum::{audit_selected, Outcome, Quorum, Reject, Vote};

const REQ: &[u8] = b"explain alert 7f3a: evidence cards 1..4";

fn request_hash() -> [u8; 32] {
    sha256(&[REQ])
}

fn worker_seed(i: u8) -> [u8; 32] {
    sha256(&[b"fleet-quorum-test-worker", &[i]])
}

/// A worker's signed vote. `usage` differs per worker (timings are local); only the output is compared.
fn vote(i: u8, output: &[u8]) -> Vote {
    let seed = worker_seed(i);
    let cap_id = {
        let h = sha256(&[b"cap", &[i]]);
        let mut c = [0u8; 16];
        c.copy_from_slice(&h[..16]);
        c
    };
    let output_hash = sha256(&[output]);
    let usage = Usage { in_units: 76, out_units: 40, compute_ms: 900 + u32::from(i) * 37, ttft_ms: 120 + u32::from(i) };
    let seq = 3;
    let m = result_message(&cap_id, &request_hash(), &output_hash, seq, &usage);
    let sig = sign(&seed, TAG_RESULT, &m).expect("sign");
    Vote { worker_pk: public_key(&seed), cap_id, output_hash, seq, usage, sig }
}

const HONEST: &[u8] = b"{\"verdict\":\"observe\",\"evidence\":[\"c1\",\"c3\"]}";
const WRONG: &[u8] = b"{\"verdict\":\"quarantine\",\"evidence\":[\"c1\"]}";

#[test]
fn k_identical_votes_agree() {
    let mut q = Quorum::new(request_hash(), 3).unwrap();
    assert_eq!(q.offer(vote(1, HONEST)), Ok(Outcome::Pending { votes: 1 }));
    assert_eq!(q.offer(vote(2, HONEST)), Ok(Outcome::Pending { votes: 2 }));
    assert_eq!(q.offer(vote(3, HONEST)), Ok(Outcome::Agreed { output_hash: sha256(&[HONEST]) }));
}

#[test]
fn one_wrong_worker_is_a_sticky_conflict_with_valid_evidence() {
    let mut q = Quorum::new(request_hash(), 3).unwrap();
    q.offer(vote(1, HONEST)).unwrap();
    let out = q.offer(vote(2, WRONG)).unwrap();
    let Outcome::Conflict(c) = out else { panic!("expected conflict, got {out:?}") };
    assert!(c.is_valid_evidence(), "both signatures re-verify against the request");
    // More honest votes never turn a conflict into agreement.
    q.offer(vote(3, HONEST)).unwrap();
    q.offer(vote(4, HONEST)).unwrap();
    assert!(matches!(q.outcome(), Outcome::Conflict(_)));
    // Against the device's own reference run, exactly the wrong worker is identified.
    let reference = sha256(&[HONEST]);
    let bad: Vec<_> = q.disagrees_with(&reference).map(|v| v.worker_pk).collect();
    assert_eq!(bad, vec![public_key(&worker_seed(2))]);
}

#[test]
fn tampered_evidence_does_not_verify() {
    let mut q = Quorum::new(request_hash(), 2).unwrap();
    q.offer(vote(1, HONEST)).unwrap();
    let Ok(Outcome::Conflict(mut c)) = q.offer(vote(2, WRONG)) else { panic!() };
    c.b.output_hash = sha256(&[b"something else"]);
    assert!(!c.is_valid_evidence());
}

#[test]
fn replayed_vote_counts_once() {
    // V1 mesh_intelligence.py counted every receipt, so one node could replay itself to the threshold.
    let mut q = Quorum::new(request_hash(), 2).unwrap();
    let v = vote(1, HONEST);
    q.offer(v).unwrap();
    assert_eq!(q.offer(v), Err(Reject::DuplicateWorker));
    // A second, different answer from the same worker is not a second vote either.
    assert_eq!(q.offer(vote(1, WRONG)), Err(Reject::DuplicateWorker));
    assert_eq!(q.outcome(), Outcome::Pending { votes: 1 });
}

#[test]
fn forged_or_misbound_votes_are_refused() {
    let mut q = Quorum::new(request_hash(), 2).unwrap();
    // Output swapped after signing.
    let mut v = vote(1, HONEST);
    v.output_hash = sha256(&[WRONG]);
    assert_eq!(q.offer(v), Err(Reject::BadSignature));
    // A vote signed for a different request.
    let mut other = Quorum::new(sha256(&[b"another request"]), 2).unwrap();
    assert_eq!(other.offer(vote(2, HONEST)), Err(Reject::BadSignature));
    // Claiming another worker's key.
    let mut v = vote(3, HONEST);
    v.worker_pk = public_key(&worker_seed(4));
    assert_eq!(q.offer(v), Err(Reject::BadSignature));
    assert_eq!(q.votes(), 0);
}

#[test]
fn bounds() {
    assert!(Quorum::new(request_hash(), 0).is_err());
    assert!(Quorum::new(request_hash(), 9).is_err());
    let mut q = Quorum::new(request_hash(), 8).unwrap();
    for i in 1..=8 {
        q.offer(vote(i, HONEST)).unwrap();
    }
    assert!(matches!(q.outcome(), Outcome::Agreed { .. }));
    assert_eq!(q.offer(vote(9, HONEST)), Err(Reject::Full));
}

#[test]
fn audit_sampling_hits_its_rate_and_depends_on_the_key() {
    let key = sha256(&[b"device audit key"]);
    let other = sha256(&[b"another device"]);
    let n = 200_000u32;
    let rate = 20_000; // 2 %
    let mut hits = 0u32;
    let mut same = 0u32;
    for j in 0..n {
        let mut id = [0u8; 16];
        id[..4].copy_from_slice(&j.to_be_bytes());
        let a = audit_selected(&key, &id, rate);
        if a {
            hits += 1;
        }
        if a == audit_selected(&other, &id, rate) {
            same += 1;
        }
        assert_eq!(a, audit_selected(&key, &id, rate), "deterministic per key and job");
    }
    let expected = n / 50;
    assert!((expected * 9 / 10..=expected * 11 / 10).contains(&hits), "hits {hits} vs ~{expected}");
    // Two independent keys pick different sets: agreement ~ p^2 + (1-p)^2 = 96.08 %, not 100 %.
    assert!(same < n - n / 50, "selection must depend on the device key");
    assert!(audit_selected(&key, &[0; 16], 1_000_000));
    assert!(!audit_selected(&key, &[0; 16], 0));
}
