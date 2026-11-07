//! P8 / SOAR — the async telemetry exfiltration path ("the OS is the sensor" can
//! now REPORT). The BPF verdict engine, in the TCB, pushes a fixed-size event
//! HEADER (never the packet payload) into an SPSC ring on a rule hit; an EL0
//! Telemetry Exporter drains it and ships it (TLS/MQTT) to the SIEM.
//!
//! Non-blocking by construction: if the ring is full, `push` increments an
//! OVERRUN counter and DROPS the export (the inline packet drop already
//! happened) — an attacker who triggers a flood of events must NOT be able to
//! stall the datapath. Losing visibility (a counted overrun the SIEM sees) is
//! acceptable; stalling the wire is not. Same zero-copy/release-acquire discipline
//! as the P5 packet ring; the EL0 exporter's wakeup is a batched P12 Notification.

use core::ptr::{addr_of, addr_of_mut};
use core::sync::atomic::{AtomicU32, Ordering};

/// One telemetry event — a compact header (24 bytes in RAM). No payload bytes ever leave
/// the TCB through here (privacy + bounded size).
#[derive(Clone, Copy)]
#[repr(C)]
pub struct Event {
    pub ts: u64,      // cntpct at detection
    /// Source attribution. For the IPv4-scoped rules this is the host-order IPv4
    /// source (0 if not flow-scoped). RULE-KEYED EXCEPTION (A9-5, security-auditor
    /// ruling 2026-09-11): for the IPv6 RA rules 121/122/123 (`RULE_ROGUE_RA`,
    /// `RULE_RA_FLOOD`, `RULE_IPV6_UNPARSEABLE`) an IPv6 frame has no IPv4 source, so
    /// this carries the low 32 bits of `ratelimit::mac_hash(src MAC)` — the source
    /// MAC's first four octets, LE. The exporter serializes it as a raw LE u32
    /// (`export.rs`), never renders it as an address; consumers MUST key the
    /// interpretation on `rule_id`.
    pub src: u32,
    pub rule_id: u16, // which signed rule fired
    pub severity: u8, // QSecBit severity points
    pub verdict: u8,  // 1 = PASS, 2 = DROP (the wire action — unchanged meaning)
    /// Tri-state class behind `verdict` (`verdict::CLASS_*`, 0 = unknown): Observe vs an
    /// under/over-limit RateLimit vs FrameDrop vs Quarantine vs the Allowlisted floor.
    pub class: u8,
}

impl Event {
    pub const EMPTY: Event = Event { ts: 0, src: 0, rule_id: 0, severity: 0, verdict: 0, class: 0 };
}
const EMPTY: Event = Event::EMPTY;

const RING: usize = 64; // power of two
static mut BUF: [Event; RING] = [EMPTY; RING];
static HEAD: AtomicU32 = AtomicU32::new(0); // producer (verdict engine)
static TAIL: AtomicU32 = AtomicU32::new(0); // consumer (EL0 exporter)
static OVERRUN: AtomicU32 = AtomicU32::new(0);

#[inline]
fn cntpct() -> u64 {
    let c: u64;
    unsafe { core::arch::asm!("mrs {}, cntpct_el0", out(reg) c, options(nomem, nostack)) };
    c
}

/// Producer (in the TCB): record a rule hit. Non-blocking — full ring ⇒ count an
/// overrun and drop the export. Stamps the timestamp internally.
pub fn push_hit(rule_id: u16, severity: u8, verdict: u8, class: u8, src: u32) {
    let h = HEAD.load(Ordering::Relaxed);
    let t = TAIL.load(Ordering::Acquire);
    if h.wrapping_sub(t) >= RING as u32 {
        OVERRUN.fetch_add(1, Ordering::Relaxed);
        return;
    }
    let ev = Event { ts: cntpct(), src, rule_id, severity, verdict, class };
    unsafe { core::ptr::write_volatile(addr_of_mut!(BUF).cast::<Event>().add((h as usize) % RING), ev) };
    HEAD.store(h.wrapping_add(1), Ordering::Release); // publish (release)
}

/// Events waiting in the ring (the serve loop drains on demand once this passes a threshold, so
/// a burst between heartbeats does not overrun the 64-slot ring).
pub fn pending() -> usize {
    HEAD.load(Ordering::Acquire).wrapping_sub(TAIL.load(Ordering::Relaxed)) as usize
}

/// Ring capacity.
pub const CAPACITY: usize = RING;

/// Consumer (the EL0 Telemetry Exporter): drain up to `out.len()` events into
/// `out`, returning the count. Zero-copy read + release the slot.
pub fn drain(out: &mut [Event]) -> usize {
    let mut n = 0;
    while n < out.len() {
        let t = TAIL.load(Ordering::Relaxed);
        let h = HEAD.load(Ordering::Acquire); // see the published event
        if t == h {
            break; // empty
        }
        out[n] = unsafe { core::ptr::read_volatile(addr_of!(BUF).cast::<Event>().add((t as usize) % RING)) };
        TAIL.store(t.wrapping_add(1), Ordering::Release); // free the slot
        n += 1;
    }
    n
}

/// Non-consuming peek at the most recently PUSHED event (None if nothing was ever
/// pushed). For self-tests that need to assert what a detector just recorded
/// without stealing the event from the EL0 exporter's drain.
pub fn peek_last() -> Option<Event> {
    let h = HEAD.load(Ordering::Acquire);
    if h == 0 {
        return None;
    }
    let i = (h.wrapping_sub(1) as usize) % RING;
    Some(unsafe { core::ptr::read_volatile(addr_of!(BUF).cast::<Event>().add(i)) })
}

/// Count of events dropped because the ring was full (a SIEM-visible signal).
pub fn overruns() -> u32 {
    OVERRUN.load(Ordering::Relaxed)
}
