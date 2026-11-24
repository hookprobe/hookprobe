// SPDX-License-Identifier: AGPL-3.0-only
//! C0 timing on the BUILD HOST (x86-64). Not a CM5 number: the CM5 measurement is a C1 metal task.
//! Reports per-job harness CPU time (everything the device does, excluding the signer and the worker),
//! and the cost of the two primitives it runs per call.
use conductor_core::class::{DataClass, Tier};
use conductor_core::crypto::{public_key, sha256, sign, verify, TAG_RESULT};
use conductor_core::harness::Harness;
use conductor_mock::*;
use std::time::Instant;

fn main() {
    let n = 2000;
    let mut h = Box::new(Harness::new());
    let job = JobBuilder::default().encode();
    let env = env_with(policy_p1(), public_key(&WORKER_SEED), Tier::P1);
    let outputs = vec![
        r#"{"tool":"flows.count","args":{"ev":"ev:2","hours":6}}"#.to_string(),
        r#"{"verdict":"malicious","severity":"medium","summary":"Exploit attempt; 17 flows in 6 h.","evidence":["F1","F2"],"entities":[],"next_step":"investigate","confidence":50}"#.to_string(),
    ];
    let t = Instant::now();
    for i in 0..n {
        let mut k = Kernel::new(policy_p1(), Tier::P1);
        k.rng = Rng(1 + i as u64);
        k.tool_data.push((2, DataClass::Public, "17 flows in the last 6 h".into()));
        let mut w = MockWorker::new(Tier::P1, outputs.clone());
        let r = k.run(&mut h, &job, env, &mut w);
        assert!(r.outcome.is_some());
    }
    let whole = t.elapsed().as_secs_f64() / n as f64;
    // Primitive costs, to separate the harness's own work from signing (kernel) and worker work.
    let msg = [7u8; 100];
    let sig = sign(&WORKER_SEED, TAG_RESULT, &msg).unwrap();
    let pk = public_key(&WORKER_SEED);
    let t = Instant::now();
    for _ in 0..n {
        assert!(verify(&pk, TAG_RESULT, &msg, &sig));
    }
    let v = t.elapsed().as_secs_f64() / n as f64;
    let t = Instant::now();
    for _ in 0..n {
        sign(&DEVICE_SEED, TAG_RESULT, &msg).unwrap();
    }
    let s = t.elapsed().as_secs_f64() / n as f64;
    let big = vec![1u8; 8192];
    let t = Instant::now();
    for _ in 0..n {
        std::hint::black_box(sha256(&[&big]));
    }
    let hsh = t.elapsed().as_secs_f64() / n as f64;
    println!("host x86-64, release, {n} iterations (NOT CM5)");
    println!("two-call job end to end (harness + mock signer + mock worker): {:.1} us", whole * 1e6);
    println!("  of which per call on the device side: 2 x ed25519 verify = {:.1} us, sha256(8 KiB) = {:.1} us", 2.0 * v * 1e6, hsh * 1e6);
    println!("  signer (kernel side, C1): ed25519 sign = {:.1} us", s * 1e6);
}
