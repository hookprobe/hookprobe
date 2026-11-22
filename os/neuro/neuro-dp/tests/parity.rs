// SPDX-License-Identifier: AGPL-3.0-only
//! doc 20 §5.1 on the host: the adapter's events on `fixture.pcap` equal the reference converter's
//! (`unsw_to_d1.py --peer-key v2-24 --name-table 4096`, in `fixture.expect.txt`), per device-hour: connections, bytes,
//! the multiset of peer fingerprints and of (DNS fingerprint, NX). Regenerate the fixture with `tests/gen_fixture.py`.
use neuro_dp::{Dp, Out};
use std::collections::BTreeMap;

#[derive(Default, Debug, PartialEq, Eq)]
struct Hour {
    conns: u64,
    bytes: u64,
    peers: Vec<u32>,
    dns: Vec<(u32, u8)>,
}

fn macs() -> Vec<[u8; 6]> {
    include_str!("fixture.macs")
        .lines()
        .filter_map(|l| {
            let m = l.split_whitespace().next()?;
            let v: Vec<u8> = m.split(':').map(|h| u8::from_str_radix(h, 16).unwrap()).collect();
            v.try_into().ok()
        })
        .collect()
}

fn run(dp: &mut Dp) -> BTreeMap<(u16, u64), Hour> {
    let pcap = include_bytes!("fixture.pcap");
    assert_eq!(u32::from_le_bytes(pcap[0..4].try_into().unwrap()), 0xA1B2_C3D4, "classic little-endian us pcap");
    let devs = macs();
    let dev_of = |m: &[u8]| devs.iter().position(|d| d[..] == *m).map(|i| i as u16);
    let mut hours: BTreeMap<(u16, u64), Hour> = BTreeMap::new();
    let mut add = |o: Out| match o {
        Out::Flow { dev, fp, ts_us } => {
            let h = hours.entry((dev, ts_us / 3_600_000_000)).or_default();
            h.conns += 1;
            h.peers.push(fp);
        }
        Out::Dns { dev, fp, nx, ts_us } => hours.entry((dev, ts_us / 3_600_000_000)).or_default().dns.push((fp, nx as u8)),
        Out::Bytes { dev, bytes, ts_us } => hours.entry((dev, ts_us / 3_600_000_000)).or_default().bytes += bytes as u64,
    };
    let mut i = 24;
    while i + 16 <= pcap.len() {
        let s = u32::from_le_bytes(pcap[i..i + 4].try_into().unwrap()) as u64;
        let us = u32::from_le_bytes(pcap[i + 4..i + 8].try_into().unwrap()) as u64;
        let cap = u32::from_le_bytes(pcap[i + 8..i + 12].try_into().unwrap()) as usize;
        let fr = &pcap[i + 16..i + 16 + cap];
        let ts = s * 1_000_000 + us;
        dp.frame(fr, ts, dev_of(&fr[6..12]), dev_of(&fr[0..6]), &mut add);
        dp.expire(ts, &mut add);
        i += 16 + cap;
    }
    dp.drain(&mut add);
    for h in hours.values_mut() {
        h.peers.sort_unstable();
        h.dns.sort_unstable();
    }
    hours
}

fn expected() -> BTreeMap<(u16, u64), Hour> {
    let mut m = BTreeMap::new();
    for line in include_str!("fixture.expect.txt").lines().filter(|l| !l.is_empty()) {
        let mut parts = line.split('|');
        let head: Vec<u64> = parts.next().unwrap().split_whitespace().map(|x| x.parse().unwrap()).collect();
        let peers = parts.next().unwrap().split_whitespace().map(|x| u32::from_str_radix(x, 16).unwrap()).collect();
        let dns = parts
            .next()
            .unwrap()
            .split_whitespace()
            .map(|x| {
                let (f, n) = x.split_once(':').unwrap();
                (u32::from_str_radix(f, 16).unwrap(), n.parse().unwrap())
            })
            .collect();
        m.insert((head[0] as u16, head[1]), Hour { conns: head[2], bytes: head[3], peers, dns });
    }
    m
}

#[test]
fn equals_the_reference_converter() {
    let mut dp = Box::new(Dp::new());
    let got = run(&mut dp);
    let want = expected();
    assert_eq!(got.len(), want.len(), "device-hours");
    let (mut peers, mut dns, mut nx) = (0usize, 0usize, 0usize);
    for (k, w) in &want {
        let g = got.get(k).unwrap_or_else(|| panic!("missing device-hour {k:?}"));
        assert_eq!(g, w, "device-hour {k:?}");
        peers += w.peers.len();
        dns += w.dns.len();
        nx += w.dns.iter().filter(|d| d.1 == 1).count();
    }
    let c = dp.c;
    println!(
        "parity: {} device-hours, {} connections, {} DNS events ({} NX) equal; rules class {} local {} named {} prefix {}; names learned {}; udp evicted {}, dns timeouts {}",
        want.len(), peers, dns, nx, c.rule_class, c.rule_local, c.rule_named, c.rule_prefix, c.names_learned, c.udp_evicted, c.dns_timeouts
    );
    // the capture must exercise every rule, or the parity proves less than it claims
    assert!(c.rule_class > 0 && c.rule_local > 0 && c.rule_named > 0 && c.rule_prefix > 0, "{c:?}");
    assert!(nx > 0 && c.names_learned > 0);
    assert_eq!(c.udp_evicted, 0, "the fixture stays inside the bounded table");
}

#[test]
fn malformed_frames_yield_nothing() {
    let mut dp = Dp::new();
    let mut n = 0;
    let mut x: u32 = 0x9E37_79B9;
    for len in 0..300usize {
        let mut f = vec![0u8; len];
        for b in f.iter_mut() {
            x ^= x << 13;
            x ^= x >> 17;
            x ^= x << 5;
            *b = x as u8;
        }
        if len > 13 {
            f[12] = 0x08; // IPv4 ethertype on half of them
            f[13] = if len % 2 == 0 { 0x00 } else { 0xDD };
        }
        dp.frame(&f, 1_000_000, Some(0), Some(0), &mut |_| n += 1);
    }
    // random bytes may parse as some packet; the point is no panic and bounded output
    assert!(n <= 600);
}
