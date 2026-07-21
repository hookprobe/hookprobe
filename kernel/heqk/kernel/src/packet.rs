//! P5 — Packet Engine: the zero-copy SPSC datapath (the north-star).
//!
//! A descriptor ring carries indices + metadata; packet payloads live once in a
//! frame pool and are inspected IN PLACE (never copied through the ring). The
//! producer (NIC-side) writes a packet into a pool frame and publishes a
//! descriptor with release ordering; the consumer (detection-side) acquires it,
//! runs a verdict against the payload in place, and frees the slot. Layout per
//! ZEROCOPY_IPC_RING.md. The verdict here is a native stand-in for the JIT'd
//! RFC 9669 BPF program (that's the AI Runtime, P6); the datapath is the point.

use core::ptr::{addr_of_mut, read_volatile, write_volatile};
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

fn read_port(p: *const u8) -> u16 {
    unsafe { ((read_volatile(p) as u16) << 8) | (read_volatile(p.add(1)) as u16) }
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
    // Minimal packet: bytes[0..2] = dst_port (big-endian); byte[2] = a payload id.
    let port: u16 = if idx % 2 == 0 { BLOCKED_PORT } else { 80 };
    unsafe {
        write_volatile(p.add(0), (port >> 8) as u8);
        write_volatile(p.add(1), (port & 0xff) as u8);
        write_volatile(p.add(2), idx as u8);
    }
    let slot = (h % RING_SIZE) as usize;
    unsafe {
        addr_of_mut!(DESCS)
            .cast::<Desc>()
            .add(slot)
            .write(Desc { frame: frame as u32, len: 64, verdict: 0 });
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
    let verdict = verdict_bpf(p, d.len); // reads the packet in place — zero copy
    let port = read_port(p);
    if verdict == DROP {
        crate::telemetry::emit(crate::telemetry::Event::PacketDrop);
    }
    d.verdict = verdict;
    unsafe { dp.write(d) };
    TAIL.store(t.wrapping_add(1), Ordering::Release); // free the slot
    Some((port, verdict))
}

/// The verdict IS the AI Runtime (P6): the RFC 9669 BPF VM runs the signed
/// threat rule against the packet in place. INVALID (sandbox violation) fails
/// safe to DROP.
fn verdict_bpf(pkt: *const u8, len: u16) -> u16 {
    match crate::bpf::run(&crate::bpf::THREAT_RULE, pkt, len as usize) {
        crate::bpf::PASS => PASS,
        _ => DROP, // DROP or INVALID -> fail-safe
    }
}
