//! P6b — Telemetry Bus ("the OS is the sensor") + a QSecBit-lite scorer.
//!
//! The capability kernel mediates every resource access, so it can emit
//! tamper-evident security events from the TCB itself: capability revocations,
//! contained faults, dropped packets, and self-heals. A weighted sum of those
//! events is a running threat score (QSecBit-lite). This is the differentiator
//! that justifies a custom kernel — detection rooted in a tiny owned TCB.

use core::sync::atomic::{AtomicU32, Ordering};

#[repr(u8)]
#[derive(Clone, Copy)]
pub enum Event {
    CapRevoke = 0,
    Fault = 1,
    PacketDrop = 2,
    SelfHeal = 3,
}

const N: usize = 4;
static COUNTS: [AtomicU32; N] = [
    AtomicU32::new(0),
    AtomicU32::new(0),
    AtomicU32::new(0),
    AtomicU32::new(0),
];
static SCORE: AtomicU32 = AtomicU32::new(0);

fn weight(e: Event) -> u32 {
    match e {
        Event::CapRevoke => 1,
        Event::PacketDrop => 2,
        Event::SelfHeal => 3,
        Event::Fault => 5,
    }
}

/// Record a security event from the TCB and update the threat score.
pub fn emit(e: Event) {
    COUNTS[e as usize].fetch_add(1, Ordering::Relaxed);
    SCORE.fetch_add(weight(e), Ordering::Relaxed);
}

pub fn count(e: Event) -> u32 {
    COUNTS[e as usize].load(Ordering::Relaxed)
}

/// The running QSecBit-lite threat score.
pub fn score() -> u32 {
    SCORE.load(Ordering::Relaxed)
}
