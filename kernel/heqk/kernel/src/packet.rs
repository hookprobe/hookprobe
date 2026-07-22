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
        crate::telemetry::emit(crate::telemetry::Event::PacketDrop);
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
fn classify(frame: &[u8]) -> (u16, u16) {
    // L2 structural tier (napse-l2guard parity: malformed-ARP / ARP-spoof) — runs
    // on EVERY frame, R1 = the raw L2 start, before any L4 parsing.
    if crate::rules::run_l2(frame) == DROP {
        return (0, DROP);
    }
    match crate::net::parse(frame) {
        Some(m) if m.has_l4_ports() => {
            // Run the whole signed rule set on a normalized L4 view: R1 = L4
            // header, so each rule reads dst-port at a fixed offset regardless of
            // eth/VLAN/IHL. The registry JITs each rule (interpreter fallback) and
            // scores a hit into QSecBit on a DROP — P8 detection plane.
            let l4 = &frame[m.l4_off..];
            let v = crate::rules::run_l4(l4);
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
