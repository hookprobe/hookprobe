// SPDX-License-Identifier: AGPL-3.0-only
//! C2 gate, host part (ADR 0071 D4): a deliberately compromised, root-owned P1 worker on the compute segment.
//! Every unauthorised path fails, each attempt is evidence, and the first one suspends the worker. The honest
//! flows pass. The metal half of the gate (the same frames on the CM5's segment port, the 33-row separation
//! matrix and the data-plane timings unchanged) needs KR-3 item 5.
use conductor_core::lease::{evidence, proto, Dest, EgressPolicy, Evidence, LeaseRefusal, Segment, Verdict, WorkerAddr, Why, LINGER_MS, MAX_DESTS};
use conductor_mock::{Rng, EGRESS};

const GW_MAC: [u8; 6] = [2, 0, 0, 0, 0, 1];
const GW_IP: [u8; 4] = [10, 77, 0, 1];
const WK_MAC: [u8; 6] = [2, 0, 0, 0, 0, 2];
const WK_IP: [u8; 4] = [10, 77, 0, 2];
const CONTROL: u16 = 4433;
const API: Dest = Dest { ip: [198, 51, 100, 7], port: 443, proto: proto::TCP };
const BCAST: [u8; 6] = [0xff; 6];

fn policy() -> EgressPolicy {
    let mut dests = [None; MAX_DESTS];
    dests[0] = Some(API);
    EgressPolicy { id: EGRESS, dests }
}

fn eth(dst: [u8; 6], src: [u8; 6], et: u16, payload: &[u8]) -> Vec<u8> {
    let mut f = dst.to_vec();
    f.extend_from_slice(&src);
    f.extend_from_slice(&et.to_be_bytes());
    f.extend_from_slice(payload);
    f
}

fn l4(p: u8, sport: u16, dport: u16) -> Vec<u8> {
    let mut h = vec![0u8; if p == proto::TCP { 20 } else { 8 }];
    h[..2].copy_from_slice(&sport.to_be_bytes());
    h[2..4].copy_from_slice(&dport.to_be_bytes());
    h
}

fn ipv4(src: [u8; 4], dst: [u8; 4], p: u8, l4: &[u8], frag: u16, options: usize) -> Vec<u8> {
    let ihl = 20 + options;
    let mut h = vec![0u8; ihl];
    h[0] = 0x40 | (ihl / 4) as u8;
    h[2..4].copy_from_slice(&((ihl + l4.len()) as u16).to_be_bytes());
    h[6..8].copy_from_slice(&frag.to_be_bytes());
    h[8] = 64;
    h[9] = p;
    h[12..16].copy_from_slice(&src);
    h[16..20].copy_from_slice(&dst);
    h.extend_from_slice(l4);
    h
}

fn ip_frame(dst_mac: [u8; 6], src_mac: [u8; 6], src: [u8; 4], dst: [u8; 4], p: u8, dport: u16) -> Vec<u8> {
    eth(dst_mac, src_mac, 0x0800, &ipv4(src, dst, p, &l4(p, 40_000, dport), 0x4000, 0))
}

fn worker_to(dst: [u8; 4], p: u8, dport: u16) -> Vec<u8> {
    ip_frame(GW_MAC, WK_MAC, WK_IP, dst, p, dport)
}

fn arp(dst_mac: [u8; 6], op: u16, sha: [u8; 6], spa: [u8; 4], tpa: [u8; 4]) -> Vec<u8> {
    let mut a = vec![0, 1, 8, 0, 6, 4];
    a.extend_from_slice(&op.to_be_bytes());
    a.extend_from_slice(&sha);
    a.extend_from_slice(&spa);
    a.extend_from_slice(&[0; 6]);
    a.extend_from_slice(&tpa);
    eth(dst_mac, sha, 0x0806, &a)
}

fn leased(now: u64) -> Segment {
    let mut s = Segment::new(GW_MAC, GW_IP, CONTROL);
    s.pair(WorkerAddr { mac: WK_MAC, ip: WK_IP }, EGRESS);
    s.start_lease(now, now + 60_000, 1, &policy()).unwrap();
    s
}

fn honest() -> Vec<(&'static str, Vec<u8>)> {
    vec![
        ("ARP who-has gateway", arp(BCAST, 1, WK_MAC, WK_IP, GW_IP)),
        ("ARP reply to gateway", arp(GW_MAC, 2, WK_MAC, WK_IP, GW_IP)),
        ("control channel to heqk", worker_to(GW_IP, proto::TCP, CONTROL)),
        ("DNS via heqk (UDP)", worker_to(GW_IP, proto::UDP, 53)),
        ("DNS via heqk (TCP)", worker_to(GW_IP, proto::TCP, 53)),
        ("lease destination", worker_to(API.ip, proto::TCP, 443)),
    ]
}

fn attacks() -> Vec<(&'static str, Vec<u8>, Why)> {
    let mut v = vec![
        ("direct internet", worker_to([8, 8, 8, 8], proto::TCP, 443), Why::OutsideLease),
        ("other LAN host (SMB)", worker_to([192, 168, 1, 10], proto::TCP, 445), Why::OutsideLease),
        ("lease host, wrong port", worker_to(API.ip, proto::TCP, 80), Why::OutsideLease),
        ("lease host, wrong protocol (QUIC)", worker_to(API.ip, proto::UDP, 443), Why::OutsideLease),
        ("DNS bypass", worker_to([8, 8, 8, 8], proto::UDP, 53), Why::DnsElsewhere),
        ("DNS over TLS bypass", worker_to([1, 1, 1, 1], proto::TCP, 853), Why::DnsElsewhere),
        ("DNS to lease host", worker_to(API.ip, proto::UDP, 53), Why::DnsElsewhere),
        ("gateway SSH", worker_to(GW_IP, proto::TCP, 22), Why::GatewayPort),
        ("gateway control port over UDP", worker_to(GW_IP, proto::UDP, CONTROL), Why::GatewayPort),
        ("L2 bypass to another MAC", ip_frame([2, 0, 0, 0, 0, 9], WK_MAC, WK_IP, API.ip, proto::TCP, 443), Why::NotViaGateway),
        ("spoofed source MAC", ip_frame(GW_MAC, [2, 0, 0, 0, 0, 3], WK_IP, API.ip, proto::TCP, 443), Why::Spoof),
        ("spoofed source IP", ip_frame(GW_MAC, WK_MAC, [10, 77, 0, 9], API.ip, proto::TCP, 443), Why::Spoof),
        ("gratuitous ARP for the gateway's IP", arp(BCAST, 2, WK_MAC, GW_IP, GW_IP), Why::Arp),
        ("ARP for another host", arp(BCAST, 1, WK_MAC, WK_IP, [10, 77, 0, 3]), Why::Arp),
        ("ARP with a forged sender MAC", arp(BCAST, 1, [2, 0, 0, 0, 0, 3], WK_IP, GW_IP), Why::Spoof),
        ("ICMP tunnel", worker_to(API.ip, proto::ICMP, 0), Why::Icmp),
        ("GRE", eth(GW_MAC, WK_MAC, 0x0800, &ipv4(WK_IP, API.ip, 47, &[0; 8], 0, 0)), Why::OtherProtocol),
        ("IPv6", eth(GW_MAC, WK_MAC, 0x86dd, &[0x60; 60]), Why::Ipv6),
        ("802.1Q VLAN hop", eth(GW_MAC, WK_MAC, 0x8100, &[0, 5, 8, 0, 0x45, 0, 0, 40]), Why::Vlan),
        ("802.1ad Q-in-Q", eth(GW_MAC, WK_MAC, 0x88a8, &[0; 46]), Why::Vlan),
        ("LLDP", eth([1, 0x80, 0xc2, 0, 0, 0x0e], WK_MAC, 0x88cc, &[0; 46]), Why::OtherEthertype),
        ("first fragment (MF)", eth(GW_MAC, WK_MAC, 0x0800, &ipv4(WK_IP, API.ip, proto::TCP, &l4(proto::TCP, 1, 443), 0x2000, 0)), Why::Fragment),
        ("later fragment (port hidden)", eth(GW_MAC, WK_MAC, 0x0800, &ipv4(WK_IP, [8, 8, 8, 8], proto::TCP, &[0; 20], 0x0003, 0)), Why::Fragment),
        ("IP options", eth(GW_MAC, WK_MAC, 0x0800, &ipv4(WK_IP, API.ip, proto::TCP, &l4(proto::TCP, 1, 443), 0, 4)), Why::IpOptions),
        ("limited broadcast", ip_frame(BCAST, WK_MAC, WK_IP, [255; 4], proto::UDP, 67), Why::Broadcast),
        ("mDNS multicast", ip_frame([1, 0, 0x5e, 0, 0, 0xfb], WK_MAC, WK_IP, [224, 0, 0, 251], proto::UDP, 5353), Why::Broadcast),
        ("subnet broadcast via gateway MAC", worker_to([10, 77, 0, 255], proto::UDP, 9), Why::Broadcast),
        ("oversize frame", { let mut f = worker_to(API.ip, proto::TCP, 443); f.resize(1600, 0); f }, Why::Oversize),
        ("truncated TCP header", eth(GW_MAC, WK_MAC, 0x0800, &ipv4(WK_IP, API.ip, proto::TCP, &[0; 10], 0, 0)), Why::Malformed),
        ("runt frame", vec![0; 10], Why::Malformed),
    ];
    // IP total length larger than the frame (a parser-confusion attempt).
    let mut lie = worker_to(API.ip, proto::TCP, 443);
    lie[16..18].copy_from_slice(&2000u16.to_be_bytes());
    v.push(("IP length beyond the frame", lie, Why::Malformed));
    v
}

#[test]
fn compromised_worker_every_path_fails_and_is_evidence() {
    // Honest flows pass on one segment, together.
    let mut s = leased(1_000);
    for (name, f) in honest() {
        assert_eq!(s.egress(1_100, &f), Verdict::Pass, "honest flow refused: {name}");
    }
    assert_eq!(s.ingress(1_100, API, WK_IP), Verdict::Pass, "a reply from the lease destination");
    assert!(!s.is_suspended());

    let mut log: Vec<Evidence> = vec![];
    let atk = attacks();
    for (name, f, why) in &atk {
        let mut s = leased(1_000);
        let v = s.egress(1_100, f);
        assert_eq!(v, Verdict::Drop { why: *why, suspended: true }, "attack not stopped as expected: {name}");
        let e = evidence(v, 1_100, f).expect("every drop is evidence");
        assert_eq!(e.encode().len(), Evidence::LEN);
        log.push(e);
        // Suspended: even the honest control channel is cut, inbound replies too, and no lease can start.
        assert!(s.is_suspended());
        assert_eq!(s.egress(1_200, &worker_to(GW_IP, proto::TCP, CONTROL)), Verdict::Drop { why: Why::Suspended, suspended: false }, "{name}");
        assert_eq!(s.egress(1_200, &worker_to(API.ip, proto::TCP, 443)), Verdict::Drop { why: Why::Suspended, suspended: false });
        assert!(matches!(s.ingress(1_200, API, WK_IP), Verdict::Drop { .. }));
        assert_eq!(s.start_lease(1_300, 9_000, 1, &policy()), Err(LeaseRefusal::Suspended));
        // Only the owner resumes it.
        s.resume();
        assert_eq!(s.egress(1_400, &worker_to(GW_IP, proto::TCP, CONTROL)), Verdict::Pass);
    }
    println!("red team: {} attack paths stopped, each recorded as evidence and suspending the worker; {} honest flows pass", atk.len(), honest().len());
}

#[test]
fn lease_lifecycle_kill_switch_and_inbound() {
    let lease_frame = worker_to(API.ip, proto::TCP, 443);
    // Before any lease.
    let mut s = Segment::new(GW_MAC, GW_IP, CONTROL);
    assert_eq!(s.egress(0, &lease_frame), Verdict::Drop { why: Why::NotPaired, suspended: false });
    s.pair(WorkerAddr { mac: WK_MAC, ip: WK_IP }, EGRESS);
    assert_eq!(s.egress(0, &worker_to(GW_IP, proto::TCP, CONTROL)), Verdict::Pass, "the control channel needs no lease");
    assert_eq!(s.egress(0, &lease_frame), Verdict::Drop { why: Why::NoLease, suspended: true });
    s.resume();
    // Start refusals.
    let mut other = policy();
    other.id = [0x99; 16];
    assert_eq!(s.start_lease(0, 10_000, 1, &other), Err(LeaseRefusal::PolicyMismatch));
    assert_eq!(s.start_lease(10_000, 10_000, 1, &policy()), Err(LeaseRefusal::Expired));
    // Expiry: tail frames within LINGER_MS are dropped and recorded but do not suspend; after it, they do.
    s.start_lease(0, 10_000, 1, &policy()).unwrap();
    assert_eq!(s.egress(9_999, &lease_frame), Verdict::Pass);
    assert_eq!(s.egress(10_000, &lease_frame), Verdict::Drop { why: Why::LeaseEnded, suspended: false });
    assert!(matches!(s.ingress(10_000, API, WK_IP), Verdict::Drop { why: Why::InboundUnsolicited, .. }));
    assert_eq!(s.egress(10_000 + LINGER_MS, &lease_frame), Verdict::Drop { why: Why::NoLease, suspended: true });
    s.resume();
    // EndLease from the harness behaves the same.
    s.start_lease(20_000, 80_000, 1, &policy()).unwrap();
    s.end_lease(30_000);
    assert!(!s.lease_active(30_001));
    assert_eq!(s.egress(30_500, &lease_frame), Verdict::Drop { why: Why::LeaseEnded, suspended: false });
    // Kill switch mid-lease: the lease ends at once, there is no linger, and old capabilities cannot start one.
    s.start_lease(40_000, 100_000, 1, &policy()).unwrap();
    assert_eq!(s.egress(40_001, &lease_frame), Verdict::Pass);
    s.on_epoch(2, 40_002);
    assert_eq!(s.egress(40_003, &lease_frame), Verdict::Drop { why: Why::NoLease, suspended: true });
    s.resume();
    assert_eq!(s.start_lease(40_004, 100_000, 1, &policy()), Err(LeaseRefusal::Revoked));
    s.start_lease(40_004, 100_000, 2, &policy()).unwrap();
    // Inbound: only replies from the active lease's destinations, only to the worker.
    assert_eq!(s.ingress(40_005, API, WK_IP), Verdict::Pass);
    assert!(matches!(s.ingress(40_005, Dest { ip: [203, 0, 113, 9], port: 443, proto: proto::TCP }, WK_IP), Verdict::Drop { why: Why::InboundUnsolicited, .. }));
    assert!(matches!(s.ingress(40_005, Dest { port: 444, ..API }, WK_IP), Verdict::Drop { .. }));
    assert!(matches!(s.ingress(40_005, API, [10, 77, 0, 3]), Verdict::Drop { .. }));
    // The usual policy: nothing beyond the gateway.
    let mut n = Segment::new(GW_MAC, GW_IP, CONTROL);
    n.pair(WorkerAddr { mac: WK_MAC, ip: WK_IP }, EGRESS);
    n.start_lease(0, 10_000, 1, &EgressPolicy::none(EGRESS)).unwrap();
    assert_eq!(n.egress(1, &lease_frame), Verdict::Drop { why: Why::OutsideLease, suspended: true });
    // Unpairing cuts everything.
    s.unpair();
    assert_eq!(s.egress(50_000, &worker_to(GW_IP, proto::TCP, CONTROL)), Verdict::Drop { why: Why::NotPaired, suspended: false });
    println!("lease lifecycle: expiry with {LINGER_MS} ms linger, EndLease, kill switch (no linger, old epoch refused), inbound replies only");
}

/// Mutation fuzz with an independent oracle: whatever passes must be, read at fixed offsets, one of the allowed
/// shapes. (No IP options are accepted, so the offsets are fixed.)
#[test]
fn fuzz_nothing_unexpected_passes() {
    let iters: usize = std::env::var("FUZZ_ITERS").ok().and_then(|v| v.parse().ok()).unwrap_or(300_000);
    let mut rng = Rng(0x005e_edc2);
    let seeds: Vec<Vec<u8>> = honest().into_iter().map(|h| h.1).chain(attacks().into_iter().map(|a| a.1)).collect();
    let (mut passed, mut dropped) = (0usize, 0usize);
    for i in 0..iters {
        let mut f = seeds[i % seeds.len()].clone();
        for _ in 0..1 + rng.next_u64() % 4 {
            if f.is_empty() {
                break;
            }
            let at = (rng.next_u64() as usize) % f.len().min(64);
            f[at] = rng.next_u64() as u8;
        }
        if rng.next_u64().is_multiple_of(16) {
            f.truncate((rng.next_u64() as usize) % (f.len() + 1));
        }
        let mut s = leased(0);
        match s.egress(1, &f) {
            Verdict::Pass => {
                passed += 1;
                assert_eq!(&f[6..12], &WK_MAC, "passed with a foreign source MAC: {f:02x?}");
                let et = u16::from_be_bytes([f[12], f[13]]);
                if et == 0x0806 {
                    assert!(f[0..6] == BCAST || f[0..6] == GW_MAC);
                    assert_eq!((&f[22..28], &f[28..32], &f[38..42]), (&WK_MAC[..], &WK_IP[..], &GW_IP[..]));
                    continue;
                }
                assert_eq!(et, 0x0800);
                assert_eq!(&f[0..6], &GW_MAC);
                assert_eq!(f[14], 0x45, "IPv4 without options");
                assert_eq!(u16::from_be_bytes([f[20], f[21]]) & 0x3fff, 0, "no fragments");
                assert_eq!(&f[26..30], &WK_IP);
                let (p, dst, dport) = (f[23], [f[30], f[31], f[32], f[33]], u16::from_be_bytes([f[36], f[37]]));
                let ok = (dst == GW_IP && ((p == proto::TCP && dport == CONTROL) || ((p == proto::TCP || p == proto::UDP) && dport == 53)))
                    || (Dest { ip: dst, port: dport, proto: p } == API);
                assert!(ok, "an unexpected flow passed: proto {p} to {dst:?}:{dport}");
            }
            Verdict::Drop { suspended, why } => {
                dropped += 1;
                assert!(suspended, "a worker drop on an active lease must suspend: {why:?}");
            }
        }
    }
    println!("lease fuzz: {iters} mutated frames, {passed} passed (all allowed shapes), {dropped} dropped and suspended");
}

/// Main-loop impact, host only (CM5 numbers need KR-3 item 5 on metal).
#[test]
fn per_frame_cost_host() {
    // Worst case: the matching destination is the last of a full policy.
    let mut dests = [Some(Dest { ip: [203, 0, 113, 1], port: 443, proto: proto::TCP }); MAX_DESTS];
    dests[MAX_DESTS - 1] = Some(API);
    let mut s = Segment::new(GW_MAC, GW_IP, CONTROL);
    s.pair(WorkerAddr { mac: WK_MAC, ip: WK_IP }, EGRESS);
    s.start_lease(0, 60_000, 1, &EgressPolicy { id: EGRESS, dests }).unwrap();
    let f = worker_to(API.ip, proto::TCP, 443);
    let n = 2_000_000u64;
    let t = std::time::Instant::now();
    let mut pass = 0u64;
    for i in 0..n {
        if s.egress(std::hint::black_box(1 + (i & 1)), std::hint::black_box(&f)) == Verdict::Pass {
            pass += 1;
        }
    }
    let ns = t.elapsed().as_nanos() as f64 / n as f64;
    assert_eq!(pass, n);
    println!("lease decision: {ns:.1} ns per frame on the build host (x86-64, NOT CM5), match in the last of {MAX_DESTS} policy entries");
}
