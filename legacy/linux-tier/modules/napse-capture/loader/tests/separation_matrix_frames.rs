//! Enforcement-separation validation matrix — FRAME-LEVEL companion (2026-07-07 operator step-3
//! requirement: "the SOC breaks a legit device" bug class must never ship again, unnoticed).
//!
//! This is the raw-frame half of the matrix. Its sibling,
//! `crates/hookprobe-manifest/tests/separation_matrix.rs`, owns everything above the frame layer
//! (`scan_responder::decide`, `l2_responder::decide_l2`, `nac::resolve`, RA-Guard rendering,
//! `evaluate_resource_reality`) and pulls in the packet-layer trackers defined in THIS crate
//! (`MacFloodTracker`/`BroadcastStormTracker`/`PortScanTracker`/`BeaconTracker`/
//! `LateralMovementTracker`) as a dev-dependency. This file stays local to `napse-loader` because
//! `napse_loader::dpi` — the raw byte-level predicates every drop decision ultimately rests on —
//! is this crate's OWN public API; no cross-crate dependency is needed to reach it.
//!
//! Every assertion below calls a REAL, exported `napse_loader::dpi` function — never a
//! reimplementation. `bpf_would_drop` (the compiled TC-bpf mirror in
//! `modules/napse-l2guard/loader/src/predicates.rs`) is proven, by that crate's OWN 16-test parity
//! suite (`cargo test -p napse-l2guard`), to agree with `dpi::frame_anomaly_reason_local` /
//! `dpi::parse_arp_obs` on every case exercised here — see this file's bottom "NOT directly
//! assertable" note for why `bpf_would_drop` itself can't be called from an external test crate.
//!
//! Pass condition (operator's step-3 requirement): ZERO false-drops in the LEGIT section below.

use napse_loader::dpi;

// ---------------------------------------------------------------------------------------------
// Minimal, LOCAL frame builders — deliberately NOT shared with `dpi.rs`'s or
// `napse-l2guard/loader/src/predicates.rs`'s own test-module builders, so this file can never
// silently inherit a construction bug from the very helpers it exists to catch.
// ---------------------------------------------------------------------------------------------

fn pad_to(mut f: Vec<u8>, len: usize) -> Vec<u8> {
    while f.len() < len {
        f.push(0);
    }
    f
}

fn eth_frame(dst: [u8; 6], src: [u8; 6], ethertype: u16, payload: &[u8]) -> Vec<u8> {
    let mut f = Vec::new();
    f.extend_from_slice(&dst);
    f.extend_from_slice(&src);
    f.extend_from_slice(&ethertype.to_be_bytes());
    f.extend_from_slice(payload);
    f
}

/// A minimal Ethernet+ARP packet. `pad` mirrors the real wire behavior split this matrix cares
/// about: a genuine on-wire ARP frame is exactly 42 bytes (14 eth + 28 ARP body), never padded by
/// software — only `pad=true` constructs the padded-to-60 shape some captures still show.
fn arp_frame(eth_src: [u8; 6], sender_mac: [u8; 6], sender_ip: [u8; 4], target_ip: [u8; 4], pad: bool) -> Vec<u8> {
    let mut arp = Vec::new();
    arp.extend_from_slice(&1u16.to_be_bytes()); // htype ethernet
    arp.extend_from_slice(&0x0800u16.to_be_bytes()); // ptype ipv4
    arp.push(6); // hlen
    arp.push(4); // plen
    arp.extend_from_slice(&1u16.to_be_bytes()); // opcode: request
    arp.extend_from_slice(&sender_mac);
    arp.extend_from_slice(&sender_ip);
    arp.extend_from_slice(&[0u8; 6]); // target mac (unknown at request time)
    arp.extend_from_slice(&target_ip);
    let f = eth_frame([0xff; 6], eth_src, 0x0806, &arp);
    if pad {
        pad_to(f, 60)
    } else {
        f
    }
}

fn udp_frame_exact(src_mac: [u8; 6], src_ip: [u8; 4], dst_ip: [u8; 4], sport: u16, dport: u16) -> Vec<u8> {
    let mut ip = vec![0u8; 20];
    ip[0] = 0x45; // v4, ihl 5
    ip[9] = 17; // udp
    ip[12..16].copy_from_slice(&src_ip);
    ip[16..20].copy_from_slice(&dst_ip);
    let mut udp = vec![0u8; 8];
    udp[0..2].copy_from_slice(&sport.to_be_bytes());
    udp[2..4].copy_from_slice(&dport.to_be_bytes());
    let mut payload = ip;
    payload.extend_from_slice(&udp);
    eth_frame([0xff; 6], src_mac, 0x0800, &payload) // 14 + 20 + 8 = 42 bytes exactly, unpadded
}

fn tcp_frame(src_mac: [u8; 6], dst_mac: [u8; 6], src_ip: [u8; 4], dst_ip: [u8; 4], sport: u16, dport: u16, flags: u8) -> Vec<u8> {
    let mut ip = vec![0u8; 20];
    ip[0] = 0x45;
    ip[9] = 6; // tcp
    ip[12..16].copy_from_slice(&src_ip);
    ip[16..20].copy_from_slice(&dst_ip);
    let mut tcp = vec![0u8; 20];
    tcp[0..2].copy_from_slice(&sport.to_be_bytes());
    tcp[2..4].copy_from_slice(&dport.to_be_bytes());
    tcp[12] = 5 << 4; // data offset 5, no options
    tcp[13] = flags;
    let mut payload = ip;
    payload.extend_from_slice(&tcp);
    eth_frame(dst_mac, src_mac, 0x0800, &payload) // 14 + 20 + 20 = 54 bytes exactly, unpadded
}

const IOS_RANDOM_MAC: [u8; 6] = [0xaa, 0xff, 0x48, 0x06, 0xa6, 0x2d]; // the confirmed live-pentest MAC
const NORMAL_SRC: [u8; 6] = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
const NORMAL_DST: [u8; 6] = [0x99, 0x88, 0x77, 0x66, 0x55, 0x44];

fn anomaly(frame: &[u8]) -> Option<&'static str> {
    dpi::frame_anomaly_reason_local(frame, dpi::DEFAULT_MIN_FRAME_LEN, dpi::DEFAULT_MAX_FRAME_LEN, &[])
}

// =================================================================================================
// LEGIT — real function under test: `napse_loader::dpi::frame_anomaly_reason_local`.
// Must NEVER classify these as an anomaly (which is what a wire-level FrameDrop would key off).
// =================================================================================================

/// ROW (LEGIT): iPhone 42-byte unpadded ARP, MAC `aa:ff:48:06:a6:2d` — the confirmed live-pentest
/// false positive (an iPhone associated to the AP got no connectivity because its ARP was dropped
/// as "runt") that the 2026-07-07 protocol-aware runt-floor fix closed.
#[test]
fn legit_iphone_42_byte_unpadded_arp_is_never_flagged_anomalous() {
    let f = arp_frame(IOS_RANDOM_MAC, IOS_RANDOM_MAC, [192, 168, 1, 50], [192, 168, 1, 1], false);
    assert_eq!(f.len(), 42, "sanity: a real, unpadded ARP frame is exactly 42 bytes");
    assert_eq!(
        anomaly(&f),
        None,
        "a well-formed, unpadded 42-byte ARP frame from an iOS-randomized MAC must never be flagged — \
         this is the exact confirmed live false positive"
    );
}

/// ROW (LEGIT): a bare 54-byte TCP ACK (a real handshake/teardown segment on a mirror-sink capture
/// with no hardware wire-padding), a bare 42-byte UDP datagram, and an EAPOL (802.1X) frame — none
/// may be flagged.
#[test]
fn legit_bare_54_byte_tcp_ack_42_byte_udp_and_eapol_are_never_flagged_anomalous() {
    let tcp_ack = tcp_frame(NORMAL_SRC, NORMAL_DST, [10, 66, 0, 20], [1, 1, 1, 1], 51000, 443, 0x10 /* ACK */);
    assert_eq!(tcp_ack.len(), 54, "sanity: a bare ACK segment is exactly 54 bytes");
    assert_eq!(anomaly(&tcp_ack), None, "a bare 54-byte TCP ACK must never be flagged");

    let udp = udp_frame_exact(NORMAL_SRC, [10, 66, 0, 20], [1, 1, 1, 1], 51000, 53);
    assert_eq!(udp.len(), 42, "sanity: a bare UDP datagram with zero payload is exactly 42 bytes");
    assert_eq!(anomaly(&udp), None, "a bare 42-byte UDP datagram must never be flagged");

    // EAPOL (802.1X, ethertype 0x888E) — a normal Wi-Fi/wired 802.1X supplicant<->authenticator
    // frame; `frame_anomaly_reason_local` has no ethertype allowlist/denylist (only ARP/VLAN get
    // special-cased), so a benign, correctly-sized EAPOL frame must pass on length/MAC grounds
    // alone, same as any other non-ARP/non-VLAN ethertype.
    let eapol = pad_to(eth_frame(NORMAL_DST, NORMAL_SRC, 0x888E, &[0x01, 0x00, 0x00, 0x00]), 60);
    assert_eq!(anomaly(&eapol), None, "a benign EAPOL (802.1X) frame must never be flagged");
}

/// ROW (LEGIT): a randomized/locally-administered unicast MAC (0x02 set in the first octet, I/G
/// bit 0x01 CLEAR) must never trip the multicast/broadcast-source-MAC check — that check is keyed
/// on the I/G bit (LSB of the first octet) only, never on the U/L bit.
#[test]
fn legit_randomized_locally_administered_unicast_mac_never_trips_the_multicast_source_check() {
    let randomized_src = [0x02, 0xaa, 0xbb, 0xcc, 0xdd, 0xee];
    assert_eq!(randomized_src[0] & 0x01, 0, "sanity: I/G bit clear (unicast)");
    assert_eq!(randomized_src[0] & 0x02, 0x02, "sanity: U/L bit set (locally administered / randomized)");
    let f = pad_to(eth_frame(NORMAL_DST, randomized_src, 0x0800, &[0u8; 20]), 64);
    assert_eq!(
        anomaly(&f),
        None,
        "a locally-administered (randomized) but still UNICAST source MAC must never be flagged as a \
         multicast/broadcast source"
    );
}

// =================================================================================================
// ATTACKER — real function under test: `napse_loader::dpi::{frame_anomaly_reason_local,
// parse_arp_obs, ArpObs}`. Each of these IS a genuine structural anomaly and MUST be flagged.
// =================================================================================================

/// ROW (ATTACKER): a genuinely truncated frame (<14 bytes) must be flagged — it cannot even be
/// classified further.
#[test]
fn attacker_frame_shorter_than_a_bare_ethernet_header_is_flagged() {
    let f = vec![0u8; 10];
    assert!(anomaly(&f).is_some(), "a <14-byte frame must always be flagged");
}

/// ROW (ATTACKER): a frame that CLAIMS to be ARP (ethertype 0x0806) but is shorter than the full
/// 28-byte ARP body (42 bytes total) must still be flagged as a runt — the protocol-aware
/// exemption is length-AND-structure, never "any ARP-shaped prefix passes".
#[test]
fn attacker_frame_claiming_arp_but_truncated_below_42_bytes_is_flagged() {
    let full = arp_frame(NORMAL_SRC, NORMAL_SRC, [10, 0, 0, 5], [10, 0, 0, 1], false);
    assert_eq!(full.len(), 42);
    let truncated = &full[..30]; // claims ARP, but well short of the real 28-byte body
    assert!(
        anomaly(truncated).is_some(),
        "a genuinely truncated claims-ARP-but-<42B frame must still be flagged, never exempted"
    );
}

/// ROW (ATTACKER): a multicast/broadcast SOURCE MAC (the I/G bit set) is never a legitimate
/// frame source (IEEE 802.3 forbids it) and must always be flagged.
#[test]
fn attacker_multicast_or_broadcast_source_mac_is_flagged() {
    let bogus_multicast_src = [0x01, 0x00, 0x5e, 0x00, 0x00, 0x01];
    let f = pad_to(eth_frame(NORMAL_DST, bogus_multicast_src, 0x0800, &[]), 64);
    assert!(anomaly(&f).is_some(), "a multicast-bit source MAC must always be flagged");

    let broadcast_src = [0xff, 0xff, 0xff, 0xff, 0xff, 0xff];
    let f2 = pad_to(eth_frame(NORMAL_DST, broadcast_src, 0x0800, &[]), 64);
    assert!(anomaly(&f2).is_some(), "a broadcast source MAC must always be flagged");
}

/// ROW (ATTACKER): a frame exceeding the configured MTU/jumbo cap (1522 bytes, no `local_macs`
/// GSO/TSO provenance exemption supplied) must be flagged.
#[test]
fn attacker_oversized_frame_beyond_1522_bytes_is_flagged() {
    let f = pad_to(eth_frame(NORMAL_DST, NORMAL_SRC, 0x0800, &[]), 2000);
    assert!(anomaly(&f).is_some(), "an oversized (>1522B) frame from an unrecognized MAC must always be flagged");
}

/// ROW (ATTACKER): a double/stacked 802.1Q VLAN tag (QinQ) on a topology that expects at most one
/// tag is exactly the ambiguity a VLAN-hopping attack relies on — must always be flagged.
#[test]
fn attacker_double_tagged_vlan_frame_is_flagged() {
    let mut f = Vec::new();
    f.extend_from_slice(&NORMAL_DST);
    f.extend_from_slice(&NORMAL_SRC);
    f.extend_from_slice(&dpi::ETHERTYPE_VLAN.to_be_bytes());
    f.extend_from_slice(&[0x00, 0x0a]);
    f.extend_from_slice(&dpi::ETHERTYPE_VLAN.to_be_bytes()); // stacked tag
    f.extend_from_slice(&[0x00, 0x0b]);
    f.extend_from_slice(&0x0800u16.to_be_bytes());
    let f = pad_to(f, 64);
    assert!(anomaly(&f).is_some(), "a double-tagged (QinQ) VLAN frame must always be flagged");
}

/// ROW (ATTACKER): a malformed ARP header (a non-standard htype/ptype/hlen/plen) is a real spoof
/// tell — `ArpObs::is_malformed` (the SAME predicate `l2_responder::decide_l2`'s `arp_spoof` /
/// `malformed_fields` branch and `modules/napse-l2guard`'s BPF mirror both key their FrameDrop
/// verdict on) must report it malformed.
#[test]
fn attacker_malformed_arp_header_is_flagged_malformed() {
    let mut arp = Vec::new();
    arp.extend_from_slice(&7u16.to_be_bytes()); // bogus htype (not 1/Ethernet)
    arp.extend_from_slice(&0x0800u16.to_be_bytes());
    arp.push(6);
    arp.push(4);
    arp.extend_from_slice(&1u16.to_be_bytes());
    arp.extend_from_slice(&[0u8; 20]);
    let f = pad_to(eth_frame([0xff; 6], NORMAL_SRC, 0x0806, &arp), 60);
    let obs = dpi::parse_arp_obs(&f).expect("must still parse (8-byte fixed header present)");
    assert!(obs.is_malformed(), "a bogus ARP htype must be classified malformed");
}

/// ROW (ATTACKER): the ARP payload's OWN `sender_mac` disagreeing with the outer Ethernet frame's
/// source MAC is a classic spoofing/injection tell — `ArpObs::eth_mismatch` (the SAME predicate
/// `l2_responder::decide_l2`'s `arp_spoof` / `eth_mismatch` branch keys its FrameDrop verdict on)
/// must report the mismatch.
#[test]
fn attacker_arp_sender_mac_eth_src_mismatch_is_flagged() {
    let attacker_mac = [0xde, 0xad, 0xbe, 0xef, 0x00, 0x01];
    // Ethernet frame is sent BY attacker_mac; the ARP payload claims to be NORMAL_SRC.
    let f = arp_frame(attacker_mac, NORMAL_SRC, [10, 0, 0, 5], [10, 0, 0, 1], true);
    let obs = dpi::parse_arp_obs(&f).expect("must parse");
    assert!(!obs.is_malformed(), "sanity: the header shape itself is standard");
    assert!(obs.eth_mismatch(), "an ARP sender-mac vs Ethernet-src mismatch must be flagged as a real spoof tell");
}

// ---------------------------------------------------------------------------------------------
// FIN/NULL/XMAS scan-probe classification — `napse_loader::dpi::classify_scan_probe`. Feeds
// `crates/hookprobe-manifest/tests/separation_matrix.rs`'s ATTACKER row "FIN/NULL/XMAS (never
// confirmed) -> scan_responder::decide = RateLimit": this file proves the SHAPE is recognized;
// the sibling file proves the resulting enforcement verdict.
// ---------------------------------------------------------------------------------------------

#[test]
fn fin_null_xmas_probe_shapes_are_recognized_by_classify_scan_probe() {
    assert_eq!(dpi::classify_scan_probe(0x01 /* FIN only */), Some(dpi::ScanProbeKind::Fin));
    assert_eq!(dpi::classify_scan_probe(0x00 /* no flags */), Some(dpi::ScanProbeKind::Null));
    assert_eq!(dpi::classify_scan_probe(0x01 | 0x08 | 0x20 /* FIN+PSH+URG */), Some(dpi::ScanProbeKind::Xmas));
    // A normal established/return ACK packet is never misread as a probe shape.
    assert_eq!(dpi::classify_scan_probe(0x10 /* ACK only */), None, "an ACK-bearing packet must never be a probe shape");
}

// ---------------------------------------------------------------------------------------------
// HONEST GAP — flagged, not faked (per this matrix's own instructions).
//
// `modules/napse-l2guard/loader/src/predicates.rs`'s `bpf_would_drop` (the compiled TC-bpf
// mirror's Rust proof-of-parity) is declared `#[cfg(test)] mod predicates;` inside a BINARY-ONLY
// crate (napse-l2guard has no `[lib]`/`src/lib.rs` — only `[[bin]] name = "napse-l2guard"`), so it
// is not reachable from ANY external integration-test crate, `cfg(test)` or not. It can only be
// exercised by napse-l2guard's OWN in-crate unit tests (`cargo test -p napse-l2guard`), which this
// gate ladder's `0.3-test-debug`/`1.1-test-release` gates already run and which already contain
// the exact iPhone-42-byte-ARP row this matrix duplicates above
// (`bare_42_byte_arp_frame_passes_on_both_sides_ios_randomized_mac`). We deliberately did NOT add
// a `[lib]` target to napse-l2guard to work around this — that would be a production
// crate-structure change, out of scope for a validation-only task. Every row this matrix cares
// about is instead asserted here against `dpi::frame_anomaly_reason_local`/`dpi::parse_arp_obs` —
// the exact same production functions `bpf_would_drop` mirrors — so the real detection logic is
// still under test; only the COMPILED-BPF-BYTECODE mirror itself is unreachable from here.
// ---------------------------------------------------------------------------------------------
