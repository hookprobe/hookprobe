//! P5 — Packet Engine: the zero-copy SPSC datapath (the north-star).
//!
//! A descriptor ring carries indices + metadata; packet payloads live once in a
//! frame pool and are inspected IN PLACE (never copied through the ring). The
//! producer (NIC-side) writes a packet into a pool frame and publishes a
//! descriptor with release ordering; the consumer (detection-side) acquires it,
//! runs a verdict against the payload in place, and frees the slot. Layout per
//! ZEROCOPY_IPC_RING.md. The verdict here is a native stand-in for the JIT'd
//! RFC 9669 BPF program (that's the AI Runtime, P6); the datapath is the point.

use core::ptr::{addr_of_mut, write_volatile};
use core::sync::atomic::{AtomicU32, Ordering};

const RING_SIZE: u32 = 8; // power of two
const POOL: usize = 8;
pub const FRAME_SZ: usize = 2048;
const BLOCKED_PORT: u16 = 4444;

pub const PASS: u16 = 1;
pub const DROP: u16 = 2;

#[derive(Clone, Copy)]
struct Desc {
    frame: u32,
    len: u16,
    verdict: u16,
}

// Region A: producer/consumer indices (own cache lines in production — separated
// to avoid false sharing). Region B: the descriptor ring.
static HEAD: AtomicU32 = AtomicU32::new(0);
static TAIL: AtomicU32 = AtomicU32::new(0);
static mut DESCS: [Desc; RING_SIZE as usize] =
    [Desc { frame: 0, len: 0, verdict: 0 }; RING_SIZE as usize];

fn frame_ptr(pool_base: usize, frame: usize) -> usize {
    pool_base + frame * FRAME_SZ
}

/// NIC-side: "receive" packet `idx` by writing its bytes into a pool frame (the
/// DMA-equivalent write — the only data move), then publish a descriptor.
/// Returns false if the ring is full (backpressure).
pub fn produce(pool_base: usize, idx: usize) -> bool {
    let h = HEAD.load(Ordering::Relaxed);
    let t = TAIL.load(Ordering::Acquire);
    if h.wrapping_sub(t) >= RING_SIZE {
        return false; // ring full
    }
    let frame = (h as usize) % POOL;
    let p = frame_ptr(pool_base, frame) as *mut u8;
    // A REAL Ethernet/IPv4/UDP frame with the dst port at its true L4 offset, so
    // the datapath exercises the parser + L4-offset rule end to end.
    let port: u16 = if idx % 2 == 0 { BLOCKED_PORT } else { 80 };
    let flen = {
        let buf = unsafe { core::slice::from_raw_parts_mut(p, FRAME_SZ) };
        build_udp_frame(buf, port)
    };
    let slot = (h % RING_SIZE) as usize;
    unsafe {
        addr_of_mut!(DESCS)
            .cast::<Desc>()
            .add(slot)
            .write(Desc { frame: frame as u32, len: flen as u16, verdict: 0 });
    }
    HEAD.store(h.wrapping_add(1), Ordering::Release); // publish (release)
    true
}

/// Like `produce`, but for a REAL packet: copy `bytes` into a pool frame (the
/// NIC's DMA already delivered them; this is the driver handing them to the
/// engine) and publish a descriptor. Returns false if the ring is full.
pub fn produce_raw(pool_base: usize, bytes: &[u8]) -> bool {
    let h = HEAD.load(Ordering::Relaxed);
    let t = TAIL.load(Ordering::Acquire);
    if h.wrapping_sub(t) >= RING_SIZE {
        return false;
    }
    let frame = (h as usize) % POOL;
    let p = frame_ptr(pool_base, frame) as *mut u8;
    let n = bytes.len().min(FRAME_SZ);
    for (i, b) in bytes.iter().take(n).enumerate() {
        unsafe { write_volatile(p.add(i), *b) };
    }
    let slot = (h % RING_SIZE) as usize;
    unsafe {
        addr_of_mut!(DESCS)
            .cast::<Desc>()
            .add(slot)
            .write(Desc { frame: frame as u32, len: n as u16, verdict: 0 });
    }
    HEAD.store(h.wrapping_add(1), Ordering::Release);
    true
}

/// Detection-side: dequeue one descriptor, inspect the payload IN PLACE (no
/// copy) via the verdict, write the verdict back, free the slot. Returns
/// (dst_port, verdict), or None if the ring is empty.
pub fn consume_one(pool_base: usize) -> Option<(u16, u16)> {
    let t = TAIL.load(Ordering::Relaxed);
    let h = HEAD.load(Ordering::Acquire); // see the published descriptor + payload
    if t == h {
        return None; // empty
    }
    let slot = (t % RING_SIZE) as usize;
    let dp = unsafe { addr_of_mut!(DESCS).cast::<Desc>().add(slot) };
    let mut d = unsafe { dp.read() };
    let p = frame_ptr(pool_base, d.frame as usize) as *const u8;
    // Parse + classify in place (zero copy): one parse yields both the real
    // L4 dst-port and the verdict.
    let frame = unsafe { core::slice::from_raw_parts(p, d.len as usize) };
    let (port, verdict) = classify(frame);
    if verdict == DROP {
        // DET-10: COUNT the drop but do not add to the score here. A rule-driven drop
        // was already scored with its rule's SEVERITY inside classify (emit_rule_hit);
        // adding the generic PacketDrop weight too would double-count it. A malformed
        // drop is fail-closed hygiene that shouldn't inflate the threat score.
        crate::telemetry::emit_count(crate::telemetry::Event::PacketDrop);
    }
    d.verdict = verdict;
    unsafe { dp.write(d) };
    TAIL.store(t.wrapping_add(1), Ordering::Release); // free the slot
    Some((port, verdict))
}

/// The verdict IS the AI Runtime (P6): parse the frame (Ethernet/IPv4/L4, all
/// bounds-checked in `net.rs`), then run the signed threat rule against the
/// located L4 header in place. Returns (dst_port, verdict). Malformed/truncated
/// frames fail safe to DROP; non-TCP/UDP frames (ARP, ICMP, …) carry no port
/// threat and PASS.
/// DET-4: the L2 and FLOW tiers self-parse at FIXED offsets (ethertype@12, IP@14,
/// proto@23, src@26, TCP-flags@47). A single 802.1Q tag shifts every field +4, so a
/// tagged SYN flood or blocklisted source reads as a non-IPv4 frame and slips the
/// ARP-guard, the rate-limiter and the threat-feed. Normalize by STRIPPING VLAN tags
/// into `buf` so those tiers always see a canonical untagged frame. Returns the raw
/// frame unchanged on the fast path (no tags → no copy).
fn strip_vlan<'a>(frame: &'a [u8], buf: &'a mut [u8]) -> &'a [u8] {
    use crate::net::{ETHERTYPE_QINQ, ETHERTYPE_VLAN, MAX_VLAN_TAGS};
    if frame.len() < 16 {
        return frame; // too short to carry a tag; nothing to strip
    }
    let et0 = ((frame[12] as u16) << 8) | frame[13] as u16;
    if et0 != ETHERTYPE_VLAN && et0 != ETHERTYPE_QINQ {
        return frame; // fast path: untagged
    }
    // Walk (bounded) to the inner ethertype and the L3 start, mirroring net::parse.
    let mut l3 = crate::net::ETH_HLEN; // 14
    let mut inner = et0;
    let mut tags = 0;
    while (inner == ETHERTYPE_VLAN || inner == ETHERTYPE_QINQ) && tags < MAX_VLAN_TAGS {
        // AUD-NET-1: a VLAN tag is [TPID:2][TCI:2][inner ethertype:2]. `l3` points at
        // the TCI, so the inner ethertype is at l3+2 — NOT l3 (which is the TCI). The
        // original code read the TCI as the ethertype, writing garbage into the
        // normalized frame and re-opening the DET-4 bypass. Mirror net::parse exactly.
        if l3 + 4 > frame.len() {
            return frame; // truncated tag; leave to net::parse to fail-close
        }
        inner = ((frame[l3 + 2] as u16) << 8) | frame[l3 + 3] as u16; // ethertype after the 2-byte TCI
        l3 += 4;
        tags += 1;
    }
    // Build dst(6)+src(6)+inner_ethertype(2)+L3.. into buf.
    let l3_len = frame.len() - l3;
    if 14 + l3_len > buf.len() {
        return frame; // won't fit; raw frame is the safe fallback
    }
    buf[..12].copy_from_slice(&frame[..12]);
    buf[12] = (inner >> 8) as u8;
    buf[13] = inner as u8;
    buf[14..14 + l3_len].copy_from_slice(&frame[l3..]);
    &buf[..14 + l3_len]
}

/// P17 — the public verdict entry point. Both IPS gates (netq::rx_publish on
/// ingress, netq::tx_drain on egress) call THIS so the userspace IP service is a
/// *client* of the signed rule plane, never a bypass of it. Returns
/// (dst_port, verdict) where verdict is PASS or DROP. Malformed/truncated frames
/// fail closed to DROP. Same code path as the inline datapath verdict.
pub fn verdict(frame: &[u8]) -> (u16, u16) {
    classify(frame)
}

/// AUD-NET-1 regression guard: prove strip_vlan reconstructs the CANONICAL untagged
/// frame for 1 and 2 (QinQ) tags — a VLAN-tagged frame, stripped, must be byte-identical
/// to the same frame untagged (so the L2/FLOW fixed-offset tiers see the true ethertype
/// and IP source). The off-by-2 bug (reading the TCI as the ethertype) fails this.
pub fn strip_vlan_selftest() -> bool {
    let mut u = [0u8; FRAME_SZ];
    let ulen = build_udp_frame(&mut u, 4444); // untagged eth/IPv4/UDP -> :4444
    // Insert `ntags` 802.1Q tags after the eth src (offset 12): [0x8100][TCI].
    let tagged = |ntags: usize, out: &mut [u8]| -> usize {
        out[..12].copy_from_slice(&u[..12]);
        let mut p = 12;
        for _ in 0..ntags {
            out[p] = 0x81;
            out[p + 1] = 0x00; // TPID 0x8100
            out[p + 2] = 0x0a;
            out[p + 3] = 0xbc; // TCI (arbitrary vid/pcp — MUST NOT leak into the ethertype)
            p += 4;
        }
        out[p..p + (ulen - 12)].copy_from_slice(&u[12..ulen]);
        p + (ulen - 12)
    };
    let mut ok = true;
    for ntags in 1..=2 {
        let mut t = [0u8; FRAME_SZ];
        let tlen = tagged(ntags, &mut t);
        let mut nbuf = [0u8; FRAME_SZ];
        let stripped = strip_vlan(&t[..tlen], &mut nbuf);
        // The stripped frame must equal the original untagged frame byte-for-byte.
        if stripped != &u[..ulen] {
            ok = false;
        }
        // And its IPv4 source must be recovered (DET-11), not 0/garbage.
        if crate::net::eth_ipv4_src(stripped) != crate::net::eth_ipv4_src(&u[..ulen]) {
            ok = false;
        }
    }
    ok
}

/// PH1 production-datapath proof. The persistent sensor's core decision is: for each
/// frame, `verdict()` -> ENFORCE (PASS => forward on the wire, threat => drop). This
/// runs a mixed batch (benign :53 + threat :4444) as the continuous loop would see it
/// and asserts EVERY benign frame is forwarded and EVERY threat frame dropped. The
/// metal `cm5_prod_service` loop wraps this exact decision around a real EL0-driven
/// NIC (with self-heal on driver crash); this gates the enforce logic on QEMU.
/// Returns (ok, forwarded, dropped).
pub fn prod_datapath_selftest() -> (bool, u32, u32) {
    let mut benign = [0u8; FRAME_SZ];
    let blen = build_udp_frame(&mut benign, 53);
    let mut threat = [0u8; FRAME_SZ];
    let tlen = build_udp_frame(&mut threat, 4444);
    let (mut forwarded, mut dropped, mut ok) = (0u32, 0u32, true);
    for i in 0..16u32 {
        let is_threat = i % 3 == 0; // threats at 0,3,6,9,12,15 -> 6 threat, 10 benign
        let frame: &[u8] = if is_threat { &threat[..tlen] } else { &benign[..blen] };
        let (_port, v) = verdict(frame);
        let forward = v == PASS;
        if forward {
            forwarded += 1;
        } else {
            dropped += 1;
        }
        // The enforce invariant: benign MUST forward, threat MUST drop.
        if is_threat && forward {
            ok = false;
        }
        if !is_threat && !forward {
            ok = false;
        }
    }
    ok = ok && forwarded == 10 && dropped == 6;
    (ok, forwarded, dropped)
}

fn classify(frame: &[u8]) -> (u16, u16) {
    // DET-4: run the fixed-offset L2 + FLOW tiers on a VLAN-normalized view.
    let mut nbuf = [0u8; FRAME_SZ];
    let nframe = strip_vlan(frame, &mut nbuf);
    // DET-11: the IPv4 source (0 if not IPv4), attributed on any detection below.
    let src = crate::net::eth_ipv4_src(nframe);
    // L2 structural tier (napse-l2guard parity: malformed-ARP / ARP-spoof) — runs
    // on EVERY frame, R1 = the (normalized) L2 start, before any L4 parsing.
    if crate::rules::run_l2(nframe, src) == DROP {
        return (0, DROP);
    }
    // Stateful flow tier (per-source SYN-flood rate-limit) — self-parses IPv4/TCP/SYN
    // and keys the limiter by IP source, on the normalized frame.
    if crate::rules::run_flow(nframe, src) == DROP {
        return (0, DROP);
    }
    match crate::net::parse(frame) {
        Some(m) if m.has_l4_ports() => {
            // Run the signed rule set on a normalized L4 view: R1 = L4 header, so
            // each rule reads dst-port at a fixed offset regardless of eth/VLAN/IHL.
            let l4 = &frame[m.l4_off..];
            // TCP-flag scan tier (NULL/FIN/Xmas/SYN-FIN) — TCP only.
            if m.ip_proto == crate::net::IPPROTO_TCP && crate::rules::run_tcp(l4, src) == DROP {
                return (m.dst_port, DROP);
            }
            // Port/threat rules (TCP + UDP). A DROP scores a QSecBit hit.
            let v = crate::rules::run_l4(l4, src);
            (m.dst_port, v)
        }
        Some(m) => (m.dst_port, PASS), // valid non-port traffic (ARP/ICMP/…)
        None => (0, DROP),             // malformed/truncated -> fail-closed
    }
}

/// Build a minimal real Ethernet/IPv4/UDP frame with `dst_port` into `buf`,
/// returning the frame length. Used by the synthetic producer so the P5 test
/// exercises the real parser + L4-offset rule (not a hand-placed port at 0..1).
fn build_udp_frame(buf: &mut [u8], dst_port: u16) -> usize {
    const N: usize = 14 + 20 + 8; // eth + ipv4(IHL=5) + udp
    for b in buf.iter_mut().take(N) {
        *b = 0;
    }
    buf[12] = 0x08; // ethertype IPv4
    buf[13] = 0x00;
    buf[14] = 0x45; // IPv4, IHL=5
    let total = 20 + 8; // IP total length
    buf[16] = (total >> 8) as u8;
    buf[17] = (total & 0xff) as u8;
    buf[23] = 17; // protocol = UDP
    // UDP header at offset 34: src(0..2)=1234, dst(2..4)=dst_port.
    buf[34] = 0x04;
    buf[35] = 0xd2; // src port 1234
    buf[36] = (dst_port >> 8) as u8;
    buf[37] = (dst_port & 0xff) as u8;
    N
}
