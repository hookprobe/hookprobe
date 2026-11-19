// SPDX-License-Identifier: AGPL-3.0-only
//! ADR 0067 D8 — inspection shedding with evidence, step 1.
//!
//! Under CPU pressure heqk sheds INSPECTION, never traffic. This first step sheds only the
//! observe-only behavioural detectors (beaconing, lateral movement, brute force, DNS anomaly): they
//! can never produce a drop (`FindingClass::Behavioral` is unconditional Observe), so pausing them
//! changes no wire verdict. Every enforcing tier keeps running: L2, flow, scan, the resource sheds,
//! the TLS/Shield enforcement, the TCP-flag and port rules.
//!
//! What was not inspected is recorded, not hidden: each interval in which anything was shed raises
//! one event, rule `RULE_INSPECTION_SHED`, which takes the normal path to Mission Control and the
//! sealed evidence log. RULE-KEYED EXCEPTION (like the IPv6 RA rules): its `src` field is not an
//! address, it is the number of connection observations skipped in that interval.
//!
//! Limits, stated plainly: the pressure signal is `ratelimit::under_pressure()` (run-queue depth),
//! which is near zero in today's single polled product loop, so on current images this rarely
//! engages; a loop-gap signal is the follow-on. The interval's event is raised by the next
//! observation after the interval ends, so with no traffic at all it waits for traffic.
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicU8, Ordering};

/// Seconds per evidence interval.
pub const INTERVAL_S: u64 = 10;
/// The pressure signal is re-read once per this many observations (it is not a per-packet query).
const REFRESH_EVERY: u32 = 64;

static CALLS: AtomicU32 = AtomicU32::new(0);
static SHEDDING: AtomicBool = AtomicBool::new(false);
/// Observations skipped in the current interval, and since boot.
static SKIPPED: AtomicU32 = AtomicU32::new(0);
static SKIPPED_TOTAL: AtomicU64 = AtomicU64::new(0);
static SEEN_TOTAL: AtomicU64 = AtomicU64::new(0);
static INTERVAL_START: AtomicU64 = AtomicU64::new(0);
static RECORDS: AtomicU32 = AtomicU32::new(0);
/// Self-test override: 0 = follow the pressure signal, 1 = shed, 2 = do not shed.
static FORCE: AtomicU8 = AtomicU8::new(0);

/// (observations seen, observations skipped, evidence records raised) since boot — the honest
/// inspected fraction for the operator.
pub fn totals() -> (u64, u64, u32) {
    (SEEN_TOTAL.load(Ordering::Relaxed), SKIPPED_TOTAL.load(Ordering::Relaxed), RECORDS.load(Ordering::Relaxed))
}

fn refresh(now_s: u64) {
    let on = match FORCE.load(Ordering::Relaxed) {
        1 => true,
        2 => false,
        _ => crate::ratelimit::under_pressure(),
    };
    SHEDDING.store(on, Ordering::Relaxed);
    let n = SKIPPED.load(Ordering::Relaxed);
    if n == 0 {
        INTERVAL_START.store(now_s, Ordering::Relaxed); // idle: the interval starts at the first skip
    } else if now_s.saturating_sub(INTERVAL_START.load(Ordering::Relaxed)) >= INTERVAL_S {
        // one evidence event for the interval; `src` = how many observations were not inspected
        crate::events::push_hit(crate::rules::RULE_INSPECTION_SHED, crate::rules::SEV_LOW as u8, crate::packet::PASS as u8, crate::verdict::CLASS_OBSERVE, n);
        RECORDS.fetch_add(1, Ordering::Relaxed);
        SKIPPED.store(0, Ordering::Relaxed);
        INTERVAL_START.store(now_s, Ordering::Relaxed);
    }
}

/// Called where the observe-only behavioural detectors would run for a connection observation.
/// `true` = skip them for this one (it is counted and will be reported).
pub fn skip_observers() -> bool {
    skip_observers_at(crate::behavioral::now_secs)
}

fn skip_observers_at(now_s: fn() -> u64) -> bool {
    SEEN_TOTAL.fetch_add(1, Ordering::Relaxed);
    if CALLS.fetch_add(1, Ordering::Relaxed).is_multiple_of(REFRESH_EVERY) {
        refresh(now_s());
    }
    if SHEDDING.load(Ordering::Relaxed) {
        SKIPPED.fetch_add(1, Ordering::Relaxed);
        SKIPPED_TOTAL.fetch_add(1, Ordering::Relaxed);
        true
    } else {
        false
    }
}

/// `[P-inspshed]`
pub fn selftest() -> bool {
    use crate::events::Event;
    static NOW: AtomicU64 = AtomicU64::new(0);
    fn now() -> u64 {
        NOW.load(Ordering::Relaxed)
    }
    let reset = || {
        CALLS.store(0, Ordering::Relaxed);
        SKIPPED.store(0, Ordering::Relaxed);
        SHEDDING.store(false, Ordering::Relaxed);
        INTERVAL_START.store(0, Ordering::Relaxed);
    };
    let drain_shed = || {
        let mut evs = [Event { ts: 0, src: 0, rule_id: 0, severity: 0, verdict: 0, class: 0, dport: 0, dst: 0 }; 64];
        let mut got: [u32; 8] = [0; 8];
        let mut k = 0;
        loop {
            let n = crate::events::drain(&mut evs);
            if n == 0 {
                break;
            }
            for e in &evs[..n] {
                if e.rule_id == crate::rules::RULE_INSPECTION_SHED && k < got.len() {
                    // an evidence event: observe class, PASS on the wire
                    if e.verdict as u16 != crate::packet::PASS || e.class != crate::verdict::CLASS_OBSERVE {
                        got[k] = u32::MAX;
                    } else {
                        got[k] = e.src;
                    }
                    k += 1;
                }
            }
        }
        (got, k)
    };
    let _ = drain_shed();
    let (seen0, skip0, rec0) = totals();
    // 1. no pressure: nothing is skipped, nothing is recorded
    reset();
    FORCE.store(0, Ordering::Relaxed);
    crate::ratelimit::set_synthetic_pressure(0);
    NOW.store(100, Ordering::Relaxed);
    let calm = (0..200).all(|_| !skip_observers_at(now));
    let (_, kcalm) = drain_shed();
    // 2. pressure (the real signal, injected): observations are skipped from the next refresh on, and counted
    crate::ratelimit::set_synthetic_pressure(100);
    reset();
    NOW.store(200, Ordering::Relaxed);
    let mut skipped = 0u32;
    for _ in 0..REFRESH_EVERY * 3 {
        skipped += skip_observers_at(now) as u32;
    }
    let sheds = skipped == REFRESH_EVERY * 3; // the refresh at the first call already saw the pressure
    let (_, kearly) = drain_shed(); // the interval has not ended: no record yet
    // 3. the interval ends: one record carrying the count, then a new interval
    NOW.store(200 + INTERVAL_S, Ordering::Relaxed);
    for _ in 0..REFRESH_EVERY {
        let _ = skip_observers_at(now);
    }
    let (got, k) = drain_shed();
    // the record is raised by the refresh at the start of this batch: it counts what came before it
    let recorded = k == 1 && got[0] == REFRESH_EVERY * 3;
    // 4. pressure clears: observers run again; the last partial interval is still reported
    crate::ratelimit::set_synthetic_pressure(0);
    NOW.store(200 + 2 * INTERVAL_S, Ordering::Relaxed);
    let mut resumed = 0u32;
    for _ in 0..REFRESH_EVERY * 2 {
        resumed += (!skip_observers_at(now)) as u32;
    }
    let (got2, k2) = drain_shed();
    let reverts = resumed == REFRESH_EVERY * 2 && k2 == 1 && got2[0] == REFRESH_EVERY;
    crate::ratelimit::clear_synthetic_pressure();
    // 5. the wire verdict of a frame is the same with observers shed and not shed (they are observe-only)
    let mut f = [0u8; 64];
    f[12] = 0x08;
    f[14] = 0x45;
    f[16..18].copy_from_slice(&40u16.to_be_bytes());
    f[22] = 64;
    f[23] = 6;
    f[26..30].copy_from_slice(&[10, 77, 0, 9]);
    f[30..34].copy_from_slice(&[198, 51, 100, 20]);
    f[34..36].copy_from_slice(&40_000u16.to_be_bytes());
    f[46] = 0x50;
    let mut wire_same = true;
    for (port, flags) in [(443u16, 0x02u8), (22, 0x02), (53, 0x18), (4444, 0x02), (443, 0x29), (443, 0x12)] {
        f[36..38].copy_from_slice(&port.to_be_bytes());
        f[47] = flags;
        reset();
        FORCE.store(2, Ordering::Relaxed);
        let a = crate::packet::verdict(&f[..54]).1;
        reset();
        FORCE.store(1, Ordering::Relaxed);
        let b = crate::packet::verdict(&f[..54]).1;
        wire_same &= a == b;
    }
    FORCE.store(0, Ordering::Relaxed);
    reset();
    let _ = drain_shed();
    let (seen1, skip1, rec1) = totals();
    let honest = seen1 > seen0 && skip1 - skip0 >= (REFRESH_EVERY * 4) as u64 && rec1 - rec0 >= 2;
    let pass = calm && kcalm == 0 && sheds && kearly == 0 && recorded && reverts && wire_same && honest;
    arch_aarch64::_print(format_args!(
        " [P-inspshed] {} — ADR 0067 D8 step 1: under CPU pressure the observe-only behavioural detectors are paused, never traffic, and every {}-second interval in which anything was skipped raises ONE evidence event (rule 129, observe class, PASS) carrying the count: no pressure -> nothing skipped, no record={} pressure -> observations skipped and counted={} no record before the interval ends={} one record with the exact count={} pressure clears -> observers run again and the last partial interval is still reported={} the wire verdict is the same with observers shed and not shed (SYN, SSH, DNS, a blocked port, an Xmas scan, a SYN-ACK)={} totals (seen / skipped / records) are kept={}\n",
        if pass { "PASS" } else { "FAIL" }, INTERVAL_S, calm && kcalm == 0, sheds, kearly == 0, recorded, reverts, wire_same, honest
    ));
    pass
}
