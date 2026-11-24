// SPDX-License-Identifier: AGPL-3.0-only
//! Runtime Proof 001 on the build host: replay neuro-dp's real capture fixture through all six workloads.
use conductor_core::class::Tier;
use conductor_core::crypto::public_key;
use conductor_core::harness::{Harness, Outcome};
use conductor_core::job::Verdict;
use conductor_core::place::PlaceRefusal;
use conductor_core::verify::Status;
use conductor_mock::*;
use runtime_proof::*;
use std::sync::Mutex;
use std::time::Instant;

static PROOF: Mutex<Proof> = Mutex::new(Proof::new());
const PCAP: &[u8] = include_bytes!("../../../neuro/neuro-dp/tests/fixture.pcap");

fn macs() -> Vec<[u8; 6]> {
    include_str!("../../../neuro/neuro-dp/tests/fixture.macs")
        .lines()
        .filter_map(|l| {
            let v: Vec<u8> = l.split_whitespace().next()?.split(':').map(|h| u8::from_str_radix(h, 16).unwrap()).collect();
            v.try_into().ok()
        })
        .collect()
}

fn replay(p: &mut Proof, findings: &mut Vec<Finding>) {
    let devs = macs();
    let dev_of = |m: &[u8]| devs.iter().position(|d| d[..] == *m).map(|i| i as u16);
    let mut i = 24;
    while i + 16 <= PCAP.len() {
        let s = u32::from_le_bytes(PCAP[i..i + 4].try_into().unwrap()) as u64;
        let us = u32::from_le_bytes(PCAP[i + 4..i + 8].try_into().unwrap()) as u64;
        let cap = u32::from_le_bytes(PCAP[i + 8..i + 12].try_into().unwrap()) as usize;
        let fr = &PCAP[i + 16..i + 16 + cap];
        p.frame(fr, s * 1_000_000 + us, dev_of(&fr[6..12]), dev_of(&fr[0..6]), &mut |f| findings.push(f));
        i += 16 + cap;
    }
    p.close_hour(&mut |f| findings.push(f));
}

#[test]
fn six_workloads_one_runtime() {
    let mut p = PROOF.lock().unwrap();
    // Workload 3's model is a data package, packed here (build side) and admitted by the engine.
    static S1_PKG: std::sync::OnceLock<Vec<u8>> = std::sync::OnceLock::new();
    let pkg: &'static [u8] = S1_PKG.get_or_init(|| {
        use neuro_l1::s1_model::{BQ, THR_Q, WQ};
        let mut b = vec![0u8; 512];
        let n = neuro_engine::pack::linear_specialist(&mut b, &WQ, BQ, THR_Q).unwrap();
        b.truncate(n);
        b
    });
    let model = neuro_engine::Model::admit(pkg).unwrap();
    println!("specialist package: {} bytes, root {:02x?}…, {} MACs per run", pkg.len(), &model.root()[..4], model.macs());
    assert!(p.set_specialist(model));
    let mut findings = vec![];
    let t = Instant::now();
    replay(&mut p, &mut findings);
    let el = t.elapsed();
    let c = p.c;
    println!("state: {} bytes, fixed, no heap ({} devices)", std::mem::size_of::<Proof>(), DEVICES);
    println!("frames {}  bytes {}  events {}  device-hours {}  findings {}", c.frames, c.frame_bytes, c.events, c.hours_closed, c.findings);
    println!("host x86-64 (NOT CM5): {:.0} ns/frame, payload bytes copied: 0 (frames are borrowed), event record: {} bytes", el.as_nanos() as f64 / c.frames as f64, std::mem::size_of::<neuro_dp::Out>());
    for f in &findings {
        println!("  dev {} hour {}: dna {:>4}/256 alarm={} s1 {} alert={} -> {:?}", f.dev, f.hour, f.dna.score, f.dna_alarm, f.s1_score, f.s1_alert, f.verdict);
    }
    assert!(c.frames > 1000 && c.events > 100 && c.hours_closed >= 8);

    // Workload 6 for every finding with a verdict, in both deployment modes.
    let mut jobs = 0;
    for f in findings.iter().filter(|f| f.verdict.is_some()) {
        let mut job = [0u8; 1024];
        let n = investigation_job(f, [f.dev as u8 + 1; 16], MODEL, 1_000_000, &mut job).unwrap();
        // (a) Standalone, the default: remote execution is off. The device still has its deterministic verdict.
        let mut h = Box::new(Harness::new());
        let off = conductor_core::class::OwnerPolicy::default();
        let mut k = Kernel::new(off, Tier::P1);
        let mut w = MockWorker::new(Tier::P1, vec![]);
        let r = k.run(&mut h, &job[..n], env_with(off, public_key(&WORKER_SEED), Tier::P1), &mut w);
        assert_eq!(r.outcome, Some(Outcome::Refused(PlaceRefusal::RemoteDisabled)));
        assert_eq!(r.sends, 0, "nothing leaves an air-gapped device");
        // (b) Owner enabled a LAN worker: the explanation is checked against the evidence, L0 decides.
        let answer = r#"{"verdict":"malicious","severity":"high","summary":"The device contacted peers it had not used before.","evidence":["F1"],"entities":[],"next_step":"investigate","confidence":70}"#.to_string();
        let mut k = Kernel::new(policy_p1(), Tier::P1);
        let mut w = MockWorker::new(Tier::P1, vec![answer]);
        let r = k.run(&mut h, &job[..n], env_with(policy_p1(), public_key(&WORKER_SEED), Tier::P1), &mut w);
        match r.outcome {
            Some(Outcome::Verified(v)) => {
                // The model said "malicious"; L0's verdict is what may be shown.
                assert_eq!(v.status, Status::Conflict);
                assert_eq!(v.shown_verdict, f.verdict);
                assert!(v.l0_decided);
            }
            o => panic!("{o:?}"),
        }
        assert!(w.prompts[0].contains("device slot"), "cards reached the worker");
        assert!(!w.prompts[0].contains("3c:22:fb") && !w.prompts[0].contains("192.168."), "no address or MAC in a prompt");
        jobs += 1;
    }
    println!("investigation jobs run: {jobs} (each in standalone and LAN-worker mode)");
    assert!(jobs > 0, "the fixture should produce at least one finding to investigate");
    let _ = Verdict::Benign;
}
