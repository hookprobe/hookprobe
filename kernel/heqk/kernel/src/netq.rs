//! P17 — the net-class queue: the transport between the EL1/TCB packet plane and
//! an untrusted EL0 IP service (smoltcp), per OVERLAY_CONVERGENCE.md §A3.1.
//!
//! THE security property (OVERLAY_CONVERGENCE §A3.3): the IPS enforcement point
//! stays in the TCB on BOTH sides of the queue. `rx_publish` runs the signed rule
//! plane (`packet::verdict`) on ingress — a DROP frame never enters the ring, so
//! the userspace stack cannot even observe it (a smoltcp parser bug is unreachable
//! by traffic the rules rejected). `tx_drain` re-runs the SAME rule plane on
//! egress — so a fully compromised IP stack still cannot put a frame on the wire
//! that the signed rules reject (no C2 beacon, no spoofed ARP, no scan pattern).
//! The service is a *client* of the IPS, never a bypass of it.
//!
//! ABI — per-slot ownership, NOT head/tail (OVERLAY_CONVERGENCE §A3.1, audit M-7).
//! There is deliberately NO EL0-writable index. With a head/tail ring a compromised
//! service writes `head = 0xFFFF_FFFF` and the kernel indexes out of bounds. Here
//! the kernel iterates its OWN `0..NETQ_SLOTS`, treats the EL0-written `state` as a
//! single validated boolean (SLOT_FREE / SLOT_FULL, any other bit pattern is
//! ignored), and treats `len` as an untrusted value it CLAMPS to `frame_sz` itself
//! — it is never used to index anything.
//!
//! Concurrency: single SPSC producer/consumer per direction, using the release/
//! acquire discipline of `events.rs` — the producer fills the frame + len, then
//! `Release`-stores the state; the consumer `Acquire`-loads the state, then reads
//! the frame it now owns. Per ARCHITECTURE.md "Concurrency invariant" HEQK is
//! single-core: there is exactly one hart, so the two ends never run truly
//! concurrently — the acquire/release pair is what carries the frame bytes across
//! the EL1<->EL0 privilege switch (both ends map the ring Normal-NC, so no cache
//! maintenance is needed and EL0 cannot execute `dc` anyway).

use core::sync::atomic::{fence, AtomicU32, Ordering};

/// Slots per direction (power of two; the kernel iterates 0..NETQ_SLOTS).
pub const NETQ_SLOTS: usize = 8;
/// Per-slot frame capacity — the kernel clamps every `len` to this.
pub const NETQ_FRAME_SZ: usize = 2048;
/// Ring header magic ("NETQ" — sanity/ABI check, never a trust decision).
pub const NETQ_MAGIC: u32 = 0x4E45_5451;

/// Slot ownership — the ONLY EL0-written control field, validated as a boolean.
pub const SLOT_FREE: u32 = 0; // consumer owns it; producer may fill
pub const SLOT_FULL: u32 = 1; // producer published; consumer may take

/// One ring slot. `state` is the ownership flag (the only synchronization word);
/// `len` is EL0-writable and therefore UNTRUSTED — the kernel clamps it and never
/// indexes with it. `_rsv` pads the control block away from the frame bytes.
#[repr(C)]
pub struct NetSlot {
    pub state: AtomicU32,
    pub len: u32,
    pub _rsv: [u32; 2],
}

/// The net-class queue — one page-aligned region mapped Normal-NC on both sides.
/// Header first (kernel-published ABI + timebase), then the per-slot control
/// array, then the frame payloads. `#[repr(C, align(4096))]` so it maps cleanly
/// into an EL0 grant and the header layout is stable across the trust boundary.
#[repr(C, align(4096))]
pub struct NetQueue {
    // --- header (kernel writes; EL0 reads) ---
    pub magic: u32,
    pub slots: u32,
    pub frame_sz: u32,
    pub flags: u32,
    pub cntfrq: u64,   // CNTFRQ_EL0 so EL0 can convert ticks -> time
    pub time_us: u64,  // kernel-stamped fallback clock (revocable EL0PCTEN)
    pub _hdr_rsv: [u64; 4],
    // --- control + payload ---
    pub slot: [NetSlot; NETQ_SLOTS],
    pub frame: [[u8; NETQ_FRAME_SZ]; NETQ_SLOTS],
}

const EMPTY_SLOT: NetSlot = NetSlot { state: AtomicU32::new(SLOT_FREE), len: 0, _rsv: [0; 2] };

impl NetQueue {
    pub const fn new() -> Self {
        NetQueue {
            magic: NETQ_MAGIC,
            slots: NETQ_SLOTS as u32,
            frame_sz: NETQ_FRAME_SZ as u32,
            flags: 0,
            cntfrq: 0,
            time_us: 0,
            _hdr_rsv: [0; 4],
            slot: [EMPTY_SLOT; NETQ_SLOTS],
            frame: [[0; NETQ_FRAME_SZ]; NETQ_SLOTS],
        }
    }

    /// Initialize the header (kernel side) and mark every slot FREE. Publishes the
    /// counter frequency so EL0 can build a monotonic `Instant` from CNTPCT_EL0.
    pub fn init(&mut self) {
        self.magic = NETQ_MAGIC;
        self.slots = NETQ_SLOTS as u32;
        self.frame_sz = NETQ_FRAME_SZ as u32;
        self.flags = 0;
        self.cntfrq = cntfrq();
        self.time_us = 0;
        for s in self.slot.iter() {
            s.state.store(SLOT_FREE, Ordering::Release);
        }
    }
}

#[inline]
fn cntfrq() -> u64 {
    let f: u64;
    unsafe { core::arch::asm!("mrs {}, cntfrq_el0", out(reg) f, options(nomem, nostack)) };
    f
}

/// INGRESS gate (kernel is the producer; EL0 service is the consumer).
///
/// Runs the signed rule plane FIRST. A DROP frame is counted and returned without
/// ever touching the ring — it never becomes visible to the EL0 service, so a
/// smoltcp parser bug is unreachable by traffic the rules rejected. A PASS frame is
/// copied into the first FREE slot (len clamped to frame_sz) and published with a
/// Release store. Returns the verdict (`PASS`/`DROP`); `PASS` with a full ring is
/// backpressure — the frame is dropped rather than blocking the datapath (same
/// non-blocking discipline as the P8 SOAR event ring).
pub fn rx_publish(q: &NetQueue, frame: &[u8]) -> u16 {
    // THE ingress property: classify before the ring, not after.
    let (_port, v) = crate::packet::verdict(frame);
    if v == crate::packet::DROP {
        crate::telemetry::emit_count(crate::telemetry::Event::PacketDrop);
        return crate::packet::DROP;
    }
    let n = frame.len().min(NETQ_FRAME_SZ);
    for i in 0..NETQ_SLOTS {
        let s = &q.slot[i];
        if s.state.load(Ordering::Acquire) == SLOT_FREE {
            // We now own slot i. Fill payload + len, THEN release the state — the
            // Release pairs with the consumer's Acquire (single-core: this is what
            // carries the bytes across the EL1->EL0 switch).
            let dst = q.frame[i].as_ptr() as *mut u8;
            for k in 0..n {
                unsafe { core::ptr::write_volatile(dst.add(k), frame[k]) };
            }
            // SAFETY: sole owner of slot i's control block while state==FREE.
            let lenp = core::ptr::addr_of!(s.len) as *mut u32;
            unsafe { core::ptr::write_volatile(lenp, n as u32) };
            fence(Ordering::Release);
            s.state.store(SLOT_FULL, Ordering::Release); // publish
            return crate::packet::PASS;
        }
    }
    // Ring full: PASS-but-dropped (backpressure). Losing a frame is acceptable;
    // stalling the datapath is not.
    crate::telemetry::emit_count(crate::telemetry::Event::PacketDrop);
    crate::packet::PASS
}

/// EGRESS gate (EL0 service is the producer; kernel is the consumer).
///
/// For each of the kernel's OWN slot indices `0..NETQ_SLOTS`, if the slot is FULL:
/// CLAMP the EL0-written `len` (never trusted, never used as an index), read the
/// frame the service placed there, and run the SAME signed rule plane. Only a PASS
/// frame is handed to `sink` (the "wire"); a DROP is blocked — so even a fully
/// compromised IP stack cannot emit a frame the rules reject. The slot is then
/// freed with a Release store so the service can reuse it. Returns
/// (forwarded, blocked).
pub fn tx_drain<F: FnMut(&[u8])>(q: &NetQueue, mut sink: F) -> (u32, u32) {
    let mut forwarded = 0u32;
    let mut blocked = 0u32;
    for i in 0..NETQ_SLOTS {
        let s = &q.slot[i];
        if s.state.load(Ordering::Acquire) != SLOT_FULL {
            continue; // not published by the service; leave it
        }
        fence(Ordering::Acquire);
        // CLAMP the untrusted length. len is EL0-written; a hostile service may set
        // it to 0xFFFF_FFFF. We bound it to frame_sz and only ever read our own
        // fixed-size buffer — len is a value, never an index.
        let claimed = unsafe { core::ptr::read_volatile(core::ptr::addr_of!(s.len)) };
        let n = (claimed as usize).min(NETQ_FRAME_SZ);
        let bytes = &q.frame[i][..n];
        // THE egress property: re-classify EVERY frame the service tries to send.
        let (_port, v) = crate::packet::verdict(bytes);
        // M4.4 — the ADR-0004 WAN-egress KILL-SWITCH rides here: even a rule-PASS
        // frame is CUT if it is WAN-bound while an ENROLLED device's secure tunnel is
        // down/compromised (fail-closed, no plaintext leak). Disarmed by default and
        // ALWAYS for a standalone/air-gapped device -> `egress_allowed` returns true,
        // so this is a no-op unless enrollment armed it. Governs WAN egress ONLY; the
        // local SOC, LAN, and the PoP-reconnect path are never cut.
        if v == crate::packet::PASS && crate::edge::egress_allowed(bytes) {
            sink(bytes); // reaches the wire
            forwarded += 1;
        } else {
            crate::telemetry::emit_count(crate::telemetry::Event::PacketDrop);
            blocked += 1; // NEVER on the wire — the IPS + kill-switch are authoritative over EL0
        }
        s.state.store(SLOT_FREE, Ordering::Release); // free the slot for reuse
    }
    (forwarded, blocked)
}
