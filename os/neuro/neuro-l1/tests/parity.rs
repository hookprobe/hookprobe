// SPDX-License-Identifier: AGPL-3.0-only
//! Parity with the Python reference on real (pseudonymised) dev windows: tests/fixture.txt is written by
//! tests/gen_fixture.py from tools/neuro-research/bench/dna_features.py + models/s1/s1_model.json.
//! Required: every S1 decision equal; every u8 feature within 1 of the reference (fixed-point vs float rounding).
use neuro_l1::{alert, score, Conn, HourAgg, Proto};

struct Win {
    id: String,
    q: [u8; 28],
    acc: i32,
    alert: bool,
    conns: Vec<Conn>,
}

fn parse(text: &str) -> Vec<Win> {
    let mut out: Vec<Win> = Vec::new();
    let mut pending: Vec<Conn> = Vec::new(); // records before an "E" line (streamed fixtures)
    for line in text.lines() {
        let f: Vec<&str> = line.split(' ').collect();
        match f[0] {
            "E" => {
                let q: Vec<u8> = f[3].split(',').map(|v| v.parse().unwrap()).collect();
                out.push(Win { id: f[1].to_string(), q: q.try_into().unwrap(), acc: f[4].parse().unwrap(), alert: f[5] == "1", conns: core::mem::take(&mut pending) });
            }
            "W" => {
                let q: Vec<u8> = f[3].split(',').map(|v| v.parse().unwrap()).collect();
                out.push(Win { id: f[1].to_string(), q: q.try_into().unwrap(), acc: f[4].parse().unwrap(), alert: f[5] == "1", conns: Vec::new() });
            }
            "C" => {
                let n = |i: usize| -> u64 { f[i].parse().unwrap() };
                let port = n(5) as u32;
                let sink = if text.starts_with('W') { &mut out.last_mut().unwrap().conns } else { &mut pending };
                sink.push(Conn {
                    t_us: n(1) as u32,
                    out: n(2) == 1,
                    peer: n(3) as u32,
                    peer_lan: n(4) == 1,
                    port: if port == 65_536 { None } else { Some(port as u16) },
                    proto: match f[6] { "t" => Proto::Tcp, "u" => Proto::Udp, "i" => Proto::Icmp, _ => Proto::Other },
                    failed: n(7) == 1,
                    bytes_out: n(8),
                    bytes_in: n(9),
                    dur_us: n(10),
                    pkts: n(11) as u32,
                    novel: n(12) == 1,
                });
            }
            _ => {}
        }
    }
    out
}

pub fn run(text: &str) -> (usize, usize, usize, usize, u32, Vec<String>) {
    let wins = parse(text);
    let mut agg = Box::new(HourAgg::new());
    let (mut feats_off, mut max_off, mut dec_diff, mut acc_ref_ok) = (0usize, 0u32, 0usize, 0usize);
    let mut notes = Vec::new();
    for w in &wins {
        agg.clear();
        for c in &w.conns {
            agg.add(c);
        }
        let q = agg.quantise();
        assert_eq!(score(&w.q), w.acc, "{}: the reference accumulator must equal score(reference q)", w.id);
        acc_ref_ok += 1;
        for i in 0..28 {
            let d = (q[i] as i32 - w.q[i] as i32).unsigned_abs();
            if d > 0 {
                feats_off += 1;
                if d > 1 {
                    notes.push(format!("{} feature {} rust {} ref {} overflow {:?}", w.id, i, q[i], w.q[i], agg.overflow));
                }
            }
            max_off = max_off.max(d);
        }
        if alert(&q) != w.alert {
            dec_diff += 1;
            notes.push(format!("{} DECISION rust {} ref {} (acc {} vs {})", w.id, alert(&q), w.alert, score(&q), w.acc));
        }
    }
    (wins.len(), acc_ref_ok, feats_off, dec_diff, max_off, notes)
}

#[test]
fn parity_with_python_reference() {
    let (n, _, off, dec, max_off, notes) = run(include_str!("fixture.txt"));
    for m in &notes {
        eprintln!("{m}");
    }
    eprintln!("windows {n}, u8 features off by 1: {off} of {}, decisions differ: {dec}, max |dq| {max_off}", n * 28);
    assert!(n >= 100);
    assert_eq!(dec, 0, "every S1 decision must equal the reference");
    assert!(max_off <= 1, "a u8 feature is more than 1 quantum off the reference");
}

/// Local, large check (not in CI): NEURO_L1_FIXTURE=<file from gen_fixture.py --all> cargo test --release -- --ignored
/// Reports instead of asserting the |dq| <= 1 bound, since windows past the state bounds are expected to differ.
#[test]
#[ignore]
fn parity_large_local() {
    let p = std::env::var("NEURO_L1_FIXTURE").expect("set NEURO_L1_FIXTURE");
    let text = std::fs::read_to_string(p).unwrap();
    let (n, _, off, dec, max_off, notes) = run(&text);
    for m in notes.iter().take(400) {
        eprintln!("{m}");
    }
    eprintln!("LARGE: windows {n}, u8 features off: {off} of {}, notes {}, decisions differ: {dec}, max |dq| {max_off}", n * 28, notes.len());
}

#[test]
fn hour_agg_size() {
    eprintln!("HourAgg = {} B", core::mem::size_of::<HourAgg>());
}
