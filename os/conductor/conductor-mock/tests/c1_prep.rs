// SPDX-License-Identifier: AGPL-3.0-only
//! C1/C2 logic built ahead of the kernel work: the hash-chained ledger with sealed anchor and power-loss
//! recovery, owner pairing (commit-then-reveal + six-digit comparison + owner-signed record), and the
//! signed revocation-epoch announcement (the kill switch reaching workers with no new job).

use conductor_core::chain::{self, Anchor, ChainError, ENTRY_LEN};
use conductor_core::class::Tier;
use conductor_core::crypto::{public_key, sign};
use conductor_core::ledger::{Kind, Record};
use conductor_core::pairing::{self, PairingRecord, TAG_RECORD};
use conductor_core::signer::{PairRefusal, SignRefusal};
use conductor_core::worker::Refuse;
use conductor_mock::*;

const LKEY: [u8; 32] = [0x88; 32];

fn rec(i: u16) -> Record {
    Record { kind: Kind::Done, job_id: [i as u8; 16], capability_id: [1; 16], tier: 1, step: 2, code: i, digest: [3; 32] }
}

fn build(n: u16) -> (Vec<u8>, Anchor) {
    let mut store = vec![];
    let mut head = Anchor::EMPTY;
    for i in 1..=n {
        let (e, a) = chain::append(&LKEY, &head, &rec(i)).unwrap();
        store.extend_from_slice(&e);
        head = a;
    }
    (store, head)
}

// ------------------------------------------------------------------ ledger

#[test]
fn ledger_verifies_and_detects_every_edit() {
    let (store, anchor) = build(20);
    assert_eq!(chain::verify(&LKEY, &store, &anchor), Ok(anchor));
    for pos in [0, 9, 40, 100, ENTRY_LEN * 7 + 60, store.len() - 1] {
        let mut s = store.clone();
        s[pos] ^= 0x20;
        assert!(chain::verify(&LKEY, &s, &anchor).is_err(), "edit at byte {pos} not detected");
    }
    // Wrong key (e.g. a forged ledger written without the sealed key).
    assert!(chain::verify(&[0; 32], &store, &anchor).is_err());
}

#[test]
fn ledger_detects_removed_reordered_and_truncated_entries() {
    let (store, anchor) = build(10);
    // Remove entry 4.
    let mut s = store[..3 * ENTRY_LEN].to_vec();
    s.extend_from_slice(&store[4 * ENTRY_LEN..]);
    assert_eq!(chain::verify(&LKEY, &s, &anchor), Err(ChainError::Sequence(4)));
    // Swap entries 2 and 3.
    let mut s = store.clone();
    let (a, b) = (store[ENTRY_LEN..2 * ENTRY_LEN].to_vec(), store[2 * ENTRY_LEN..3 * ENTRY_LEN].to_vec());
    s[ENTRY_LEN..2 * ENTRY_LEN].copy_from_slice(&b);
    s[2 * ENTRY_LEN..3 * ENTRY_LEN].copy_from_slice(&a);
    assert_eq!(chain::verify(&LKEY, &s, &anchor), Err(ChainError::Sequence(2)));
    // Cut the tail: only the sealed anchor can see this.
    let cut = &store[..7 * ENTRY_LEN];
    assert_eq!(chain::verify(&LKEY, cut, &anchor), Err(ChainError::Truncated { have: 7, anchored: 10 }));
    // Rewrite history from entry 6 on with the real key but a different record: the anchor catches it.
    let (prefix, a5) = build(5);
    let mut forged = prefix.clone();
    let mut head = a5;
    for i in 6..=10u16 {
        let (e, a) = chain::append(&LKEY, &head, &rec(i + 100)).unwrap();
        forged.extend_from_slice(&e);
        head = a;
    }
    assert_eq!(chain::verify(&LKEY, &forged, &anchor), Err(ChainError::AnchorMismatch));
}

#[test]
fn ledger_power_loss_recovery() {
    let (store, a9) = build(9);
    let (e10, a10) = chain::append(&LKEY, &a9, &rec(10)).unwrap();
    // Cut between step 1 (entry written) and step 2 (anchor advanced): roll forward.
    let mut s = store.clone();
    s.extend_from_slice(&e10);
    let r = chain::recover(&LKEY, &s, &a9).unwrap();
    assert!(r.rolled_forward);
    assert_eq!((r.anchor, r.keep_bytes, r.discarded_bytes), (a10, 10 * ENTRY_LEN, 0));
    // Torn write: half an entry after the anchor is discarded.
    let mut s = store.clone();
    s.extend_from_slice(&e10[..ENTRY_LEN / 2]);
    let r = chain::recover(&LKEY, &s, &a9).unwrap();
    assert!(!r.rolled_forward);
    assert_eq!((r.anchor, r.keep_bytes, r.discarded_bytes), (a9, 9 * ENTRY_LEN, ENTRY_LEN / 2));
    // A corrupt entry after the anchor is discarded, never trusted.
    let mut s = store.clone();
    let mut bad = e10;
    bad[50] ^= 1;
    s.extend_from_slice(&bad);
    assert!(!chain::recover(&LKEY, &s, &a9).unwrap().rolled_forward);
    // Tampering BEFORE the anchor is reported, never repaired.
    let mut s = store.clone();
    s[ENTRY_LEN * 3 + 20] ^= 1;
    assert!(chain::recover(&LKEY, &s, &a9).is_err());
    // Two unanchored entries: only the first may roll forward.
    let (e11, _) = chain::append(&LKEY, &a10, &rec(11)).unwrap();
    let mut s = store.clone();
    s.extend_from_slice(&e10);
    s.extend_from_slice(&e11);
    let r = chain::recover(&LKEY, &s, &a9).unwrap();
    assert_eq!((r.anchor, r.discarded_bytes), (a10, ENTRY_LEN));
}

#[test]
fn ledger_records_a_real_job() {
    // The harness's ledger actions, chained: a full tool-then-answer job verifies end to end.
    let (r, _) = run_simple(&JobBuilder::default(), &[r#"{"verdict":"insufficient_evidence","severity":"medium","summary":"ok","evidence":["F1"],"entities":[],"next_step":"investigate","confidence":50}"#], Tamper::None);
    let mut store = vec![];
    let mut head = Anchor::EMPTY;
    for rec in &r.ledger {
        let (e, a) = chain::append(&LKEY, &head, rec).unwrap();
        store.extend_from_slice(&e);
        head = a;
    }
    assert!(r.ledger.len() >= 4);
    assert_eq!(chain::verify(&LKEY, &store, &head), Ok(head));
}

// ------------------------------------------------------------------ pairing

#[test]
fn pairing_sas_and_commitment() {
    let dpk = public_key(&DEVICE_SEED);
    let wpk = public_key(&WORKER_SEED);
    let (dn, wn) = ([1u8; 16], [2u8; 16]);
    let c = pairing::commit(&wpk, &wn);
    assert!(pairing::check_commit(&c, &wpk, &wn));
    // A man in the middle that substitutes its key, or picks its nonce late, fails the commitment.
    assert!(!pairing::check_commit(&c, &public_key(&OTHER_SEED), &wn));
    assert!(!pairing::check_commit(&c, &wpk, &[3; 16]));
    let code = pairing::sas(&dpk, &wpk, &dn, &wn);
    assert!(code < 1_000_000);
    // The codes on the two screens differ if either key differs.
    assert_ne!(code, pairing::sas(&dpk, &public_key(&OTHER_SEED), &dn, &wn));
    // Distribution sanity: over many nonces, codes spread across the range.
    let mut buckets = [0u32; 10];
    for i in 0..10_000u32 {
        let mut n = [0u8; 16];
        n[..4].copy_from_slice(&i.to_le_bytes());
        buckets[(pairing::sas(&dpk, &wpk, &n, &wn) / 100_000) as usize] += 1;
    }
    assert!(buckets.iter().all(|&b| (850..=1150).contains(&b)), "{buckets:?}");
}

#[test]
fn only_owner_signed_pairings_install_and_never_roll_back() {
    let mut k = Kernel::new(policy_p1(), Tier::P1); // installs revision 1 for WORKER_SEED
    let wpk = public_key(&WORKER_SEED);
    // Signed by someone else (e.g. a compromised harness or a LAN attacker).
    let r = PairingRecord { tier: Tier::P1, worker_pk: public_key(&OTHER_SEED), egress_policy_id: EGRESS, valid_until_ms: u64::MAX, revision: 1 };
    let mut b = [0u8; pairing::RECORD_LEN];
    r.encode(&mut b);
    let forged = sign(&OTHER_SEED, TAG_RECORD, &b).unwrap();
    assert_eq!(k.signer.install_pairing(&b, &forged), Err(PairRefusal::NotOwnerSigned));
    // An owner signature over another purpose does not count either (domain separation).
    let wrong_tag = sign(&OWNER_SEED, b"hookprobe/other/v1\0", &b).unwrap();
    assert_eq!(k.signer.install_pairing(&b, &wrong_tag), Err(PairRefusal::NotOwnerSigned));
    // Replaying an older (or equal) owner-signed revision cannot undo a revocation.
    let (revoke, s2) = owner_pairing(Tier::P1, wpk, 0, 2);
    k.signer.install_pairing(&revoke, &s2).unwrap();
    let (old, s1) = owner_pairing(Tier::P1, wpk, u64::MAX, 1);
    assert_eq!(k.signer.install_pairing(&old, &s1), Err(PairRefusal::Stale));
    // P2 records are refused (fleet_mesh not built).
    let (p2, s3) = owner_pairing(Tier::P2, wpk, u64::MAX, 9);
    assert_eq!(k.signer.install_pairing(&p2, &s3), Err(PairRefusal::NotOwnerSigned));
}

#[test]
fn lapsed_pairing_stops_signing() {
    let mut k = Kernel::new(policy_p1(), Tier::P1);
    let (r, s) = owner_pairing(Tier::P1, public_key(&WORKER_SEED), 5_000, 2);
    k.signer.install_pairing(&r, &s).unwrap();
    let job = JobBuilder::default();
    let mut w = MockWorker::new(Tier::P1, vec![r#"{"verdict":"insufficient_evidence","severity":"medium","summary":"ok","evidence":["F1"],"entities":[],"next_step":"investigate","confidence":50}"#.into()]);
    let mut h = Box::new(conductor_core::harness::Harness::new());
    k.now = 10_000; // past valid_until
    let rep = k.run(&mut h, &job.encode(), env_with(policy_p1(), public_key(&WORKER_SEED), Tier::P1), &mut w);
    assert_eq!(rep.outcome, Some(conductor_core::harness::Outcome::Aborted(conductor_core::harness::Abort::SignRefused)));
    let mut e = |b: &mut [u8]| b.fill(1);
    let req = rep.sign_requests[0];
    assert_eq!(k.signer.sign(&req, 10_000, &mut e).unwrap_err(), SignRefusal::PairingExpired);
}

// ------------------------------------------------------------------ kill switch reaching workers

#[test]
fn epoch_announcement_revokes_outstanding_capabilities() {
    let mut k = Kernel::new(policy_p1(), Tier::P1);
    // A capability issued at epoch 1 but not yet delivered (e.g. queued, or captured by an attacker).
    let request = {
        let mut b = vec![0u8; 128];
        let n = conductor_core::frame::Request { op: conductor_core::cap::op::INFER, model_digest: MODEL, prompt: b"hi" }.encode(&mut b).unwrap();
        b.truncate(n);
        b
    };
    let req = conductor_core::cap::SignRequest {
        tier: 1,
        worker_public_key: public_key(&WORKER_SEED),
        session_binding: [5; 32],
        job_id: [1; 16],
        request_hash: conductor_core::crypto::sha256(&[&request]),
        model_digest: MODEL,
        operations: conductor_core::cap::op::INFER,
        data_classes: 1,
        egress_policy_id: EGRESS,
        max_input_units: 10,
        max_output_units: 10,
        max_compute_ms: 100,
        max_response_bytes: 100,
        ttl_ms: 60_000,
        slo_ttft_ms: 0,
        slo_tpot_ms: 0,
        affinity_id: [0; 16],
        cache_scope: 0,
        kv_persist: 0,
        offload_hints: 0,
        energy_policy: 0,
    };
    let mut e = |b: &mut [u8]| b.fill(2);
    let old = k.signer.sign(&req, 100, &mut e).unwrap();
    // Owner presses the kill switch: epoch 2, announced to every paired worker.
    k.signer.bump_epoch();
    let ann = k.signer.announce_epoch(200).unwrap();
    let mut gate = MockWorker::new(Tier::P1, vec![]).gate;
    assert_eq!(gate.apply_epoch(&ann), Ok(2));
    assert_eq!(gate.accept(&old, &[5; 32], &request, Some(300)).unwrap_err(), Refuse::Revoked);
    // A forged or replayed-lower announcement cannot lower the epoch or come from another key.
    let mut forged = ann;
    forged[33] ^= 1;
    assert_eq!(gate.apply_epoch(&forged), Err(Refuse::Epoch));
    let other = conductor_core::signer::Signer::new(OTHER_SEED, SALT_KEY, public_key(&OWNER_SEED), policy_p1(), MemCounter::new());
    assert_eq!(gate.apply_epoch(&other.announce_epoch(1).unwrap()), Err(Refuse::Epoch));
    assert_eq!(gate.min_epoch, 2);
}

#[test]
fn c1_decoders_never_panic() {
    let mut rng = Rng(42);
    let (store, anchor) = build(3);
    let n = std::env::var("FUZZ_ITERS").ok().and_then(|v| v.parse().ok()).unwrap_or(100_000usize);
    let mut gate = MockWorker::new(Tier::P1, vec![]).gate;
    for _ in 0..n {
        let len = rng.below(store.len() + 64);
        let mut b: Vec<u8> = if rng.below(2) == 0 { store[..len.min(store.len())].to_vec() } else { (0..len).map(|_| rng.next_u64() as u8).collect() };
        if !b.is_empty() {
            let i = rng.below(b.len());
            b[i] ^= rng.next_u64() as u8;
        }
        let _ = chain::verify(&LKEY, &b, &anchor);
        let _ = chain::recover(&LKEY, &b, &anchor);
        let _ = PairingRecord::decode(&b);
        let _ = pairing::open_record(&b, &[0; 64], &[1; 32]);
        let _ = gate.apply_epoch(&b);
    }
}
