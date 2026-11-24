// SPDX-License-Identifier: AGPL-3.0-only
//! Fault containment (C0 gate): every decoder survives random and mutated input without panicking (the
//! profile is panic=abort, so a panic fails the run), and an end-to-end integrity property: if any byte of
//! any worker frame is altered in flight, the job never ends as Verified, and every lease is closed.

use conductor_core::{abi, cap, frame, json};
use conductor_core::class::Tier;
use conductor_core::crypto::public_key;
use conductor_core::harness::{Harness, Outcome};
use conductor_core::job::JobSpec;
use conductor_mock::*;

fn iters(default: usize) -> usize {
    std::env::var("FUZZ_ITERS").ok().and_then(|v| v.parse().ok()).unwrap_or(default)
}

fn mutate(rng: &mut Rng, b: &mut Vec<u8>) -> bool {
    let before = b.clone();
    match rng.below(5) {
        0 if !b.is_empty() => {
            let i = rng.below(b.len());
            b[i] ^= (rng.below(255) + 1) as u8;
        }
        1 if !b.is_empty() => b.truncate(rng.below(b.len())),
        2 => b.push(rng.next_u64() as u8),
        3 if b.len() > 1 => {
            let i = rng.below(b.len());
            b.remove(i);
        }
        _ => {
            let n = rng.below(4) + 1;
            for _ in 0..n {
                if b.is_empty() {
                    break;
                }
                let i = rng.below(b.len());
                b[i] = rng.next_u64() as u8;
            }
        }
    }
    *b != before
}

fn corpus() -> Vec<Vec<u8>> {
    let job = JobBuilder::default();
    let (r, _) = run_simple(&job, &[r#"{"answer":{"verdict":"benign","cites":["ev:1"],"summary":"ok"}}"#], Tamper::None);
    let mut c = vec![job.encode(), r.signed[0].clone(), r.signed[0][..cap::BODY_LEN].to_vec()];
    c.push(br#"{"tool":"flows.count","args":{"ev":"ev:2","hours":6}}"#.to_vec());
    c.push(br#"{"answer":{"verdict":"malicious","cites":["ev:1","ev:2"],"summary":"line\nnext \"q\" \\ /"}}"#.to_vec());
    let mut e = vec![0u8; abi::ENV_LEN];
    e[32] = 1;
    c.push(e);
    let mut fb = vec![0u8; 256];
    let n = frame::Request { op: cap::op::INFER, model_digest: MODEL, prompt: b"hi" }.encode(&mut fb).unwrap();
    c.push(fb[..n].to_vec());
    c.push(enc(&frame::Response { capability_id: [1; 16], seq: 0, body: frame::Body::Chunk(b"abc") }));
    c.push(enc(&frame::Response {
        capability_id: [1; 16],
        seq: 1,
        body: frame::Body::Final { usage: frame::Usage { in_units: 1, out_units: 1, compute_ms: 1, ttft_ms: 1 }, output_hash: [2; 32], sig: [3; 64] },
    }));
    c
}

#[test]
fn decoders_never_panic() {
    let mut rng = Rng(0xdead_beef_1234_5678);
    let corpus = corpus();
    let dpk = public_key(&DEVICE_SEED);
    let mut job = Box::new(JobSpec::EMPTY);
    let n = iters(200_000);
    for i in 0..n {
        let mut b = if i % 10 == 0 {
            let len = rng.below(600);
            (0..len).map(|_| rng.next_u64() as u8).collect()
        } else {
            corpus[rng.below(corpus.len())].clone()
        };
        for _ in 0..=rng.below(3) {
            mutate(&mut rng, &mut b);
        }
        let _ = cap::HpExec::decode(&b);
        let _ = cap::open(&b, &dpk);
        let _ = frame::Response::decode(&b);
        let _ = frame::Request::decode(&b);
        let _ = json::parse(&b);
        let _ = job.decode_into(&b);
        let _ = abi::decode_env(&b);
        let _ = abi::decode_event(&b);
        let _ = frame::QuoteRequest::decode(&b);
        let _ = frame::Quote::open(&b, &dpk);
    }
}

#[test]
fn altered_worker_frames_are_never_verified() {
    let n = iters(3_000);
    let mut caught = 0;
    for i in 0..n {
        let mut k = Kernel::new(policy_p1(), Tier::P1);
        k.rng = Rng(0x1234_5678 + i as u64 * 7919);
        k.tool_data.push((2, conductor_core::class::DataClass::Public, "17 flows".into()));
        k.frame_mutator = Some(|rng, f| if rng.below(3) == 0 { mutate(rng, f) } else { false });
        let long = format!(r#"{{"answer":{{"verdict":"benign","cites":["ev:1"],"summary":"{}"}}}}"#, "z".repeat(i % 1500));
        let mut w = MockWorker::new(Tier::P1, vec![r#"{"tool":"evidence.get","args":{"id":"ev:2"}}"#.into(), long]);
        let mut h = Box::new(Harness::new());
        // Every other run uses SLO admission, so quote frames are mutated too.
        let job = if i % 2 == 0 { JobBuilder::default() } else { JobBuilder { slo_ttft: 5_000, ..Default::default() } };
        let r = k.run(&mut h, &job.encode(), env_with(policy_p1(), public_key(&WORKER_SEED), Tier::P1), &mut w);
        assert_eq!(r.leases_started, r.leases_ended, "lease invariant, iteration {i}");
        if k.mutated {
            caught += 1;
            assert!(!matches!(r.outcome, Some(Outcome::Verified(_))), "iteration {i}: an altered frame produced {:?}", r.outcome);
        }
    }
    assert!(caught > n / 4, "the mutator must actually fire ({caught}/{n})");
}
