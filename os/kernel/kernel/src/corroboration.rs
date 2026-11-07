//! M2 / A11 — multi-signal CORROBORATION as a SOC severity signal (NOT a wire action).
//!
//! A source that trips several INDEPENDENT detection axes (IOC reputation, scan shape,
//! C2 beacon, lateral fan-out, exfil volume, DNS anomaly) is stronger evidence for the
//! SOC than any one axis alone. This module accumulates, per source, which axes have
//! fired within a window, so an alert's SEVERITY / QSECBIT can reflect corroboration.
//!
//! CRITICAL DESIGN CONSTRAINT (security-auditor threat model, 2026-09-08): corroboration
//! **NEVER changes the wire verdict.** A durable `Quarantine` from corroboration is
//! rejected BY DESIGN, not merely unbuilt:
//!   * the axes are POSITIVELY CORRELATED for legitimate infrastructure — a backup server
//!     (exfil+lateral), an Ansible/monitoring host (lateral+beacon), an operator-run
//!     vuln-scanner (scan+lateral+dns) all reach K>=3 benignly, so no K is FP-safe;
//!   * the axes share ONE forgeable trust root (the src IP) with zero return-path proof,
//!     so an on-path attacker can frame a VICTIM across axes with a handful of spoofed
//!     packets -> a durable block would be a trivial DoS-via-IPS against a legit host;
//!   * heqk has no segment-isolation primitive, so "quarantine-to-segment" could only be
//!     a full `FrameDrop` of the source — exactly the legit-customer outage ADR 0023
//!     forbids.
//! So `decide_core` keeps mapping these findings to `Observe`; this module only RAISES
//! the alert severity the SOC sees. AI/heuristics propose; the deterministic gate still
//! says PASS (contract C9). The same observe-by-default posture that keeps the behavioral
//! axes off the wire "by construction" (behavioral.rs / verdict.rs).
//!
//! Bounded + `no_std`: a small direct-mapped, window-reset per-source table, exactly the
//! `ratelimit::touch_scan_slot` discipline (a colliding source EVICTS the slot, never
//! counts against another's mask).

use core::sync::atomic::{AtomicU64, Ordering};

/// Independent corroboration axes (one bit each). REPUTATION is the only axis an attacker
/// cannot frame onto an arbitrary victim (you can't put a victim's IP on the blocklist);
/// every other axis is both spoofable and FP-prone — which is precisely why corroboration
/// informs severity, never the wire.
pub const AXIS_REPUTATION: u32 = 1 << 0;
pub const AXIS_SCAN: u32 = 1 << 1;
pub const AXIS_BEACON: u32 = 1 << 2;
pub const AXIS_LATERAL: u32 = 1 << 3;
pub const AXIS_EXFIL: u32 = 1 << 4;
pub const AXIS_DNS: u32 = 1 << 5;

/// Distinct axes that make an alert "corroborated" (raise severity). NOT a wire threshold
/// — no verdict changes at this or any count. Legit infra can and does reach this benignly;
/// that is acceptable BECAUSE the only consequence is a higher-severity SOC alert.
pub const CORR_CRITICAL_AXES: u32 = 3;

/// Per-source slots (direct-mapped, window-reset, collision-evict). 16 mirrors
/// `ratelimit::FLOW_SRCS`.
const CORR_SRCS: usize = 16;

/// The corroboration window — deliberately long enough to span the SLOW axes (a beacon
/// needs 6 intervals x >=8 s; the lateral window is 300 s), so genuinely related signals
/// land in one window. Window length is a SOC-signal tuning knob here, NOT an FP-safety
/// parameter, since nothing is ever dropped on it.
const CORR_WINDOW_SECS: u64 = 600;

static CORR_SRC: [AtomicU64; CORR_SRCS] = [const { AtomicU64::new(0) }; CORR_SRCS];
static CORR_WIN: [AtomicU64; CORR_SRCS] = [const { AtomicU64::new(0) }; CORR_SRCS];
static CORR_MASK: [AtomicU64; CORR_SRCS] = [const { AtomicU64::new(0) }; CORR_SRCS];

#[inline]
fn cntpct() -> u64 {
    let v: u64;
    unsafe { core::arch::asm!("mrs {}, cntpct_el0", out(reg) v, options(nomem, nostack)) };
    v
}
#[inline]
fn cntfrq() -> u64 {
    let v: u64;
    unsafe { core::arch::asm!("mrs {}, cntfrq_el0", out(reg) v, options(nomem, nostack)) };
    v
}

/// Locate + refresh source `src`'s slot for the CURRENT window. A new source aliasing the
/// slot, or an expired window, resets the mask (collision-evict discipline — one source's
/// axes are never counted against another's), mirroring `ratelimit::touch_scan_slot`.
#[inline]
fn touch_corr_slot(src: u64) -> usize {
    let s = (src as usize) % CORR_SRCS;
    let now = cntpct();
    let win = cntfrq().max(1).saturating_mul(CORR_WINDOW_SECS);
    let start = CORR_WIN[s].load(Ordering::Relaxed);
    if CORR_SRC[s].load(Ordering::Relaxed) != src || now.wrapping_sub(start) >= win {
        CORR_SRC[s].store(src, Ordering::Relaxed);
        CORR_WIN[s].store(now, Ordering::Relaxed);
        CORR_MASK[s].store(0, Ordering::Relaxed);
    }
    s
}

/// Record that `src` (host-order IPv4) tripped `axis`; return the running distinct-axis
/// count for the current window. `src == 0` (no attribution) is ignored — corroboration
/// needs an identity. This is a SEVERITY signal only; NO verdict is derived from it.
pub fn corr_observe(src: u64, axis: u32) -> u32 {
    if src == 0 {
        return 0;
    }
    let s = touch_corr_slot(src);
    let prev = CORR_MASK[s].fetch_or(axis as u64, Ordering::Relaxed);
    ((prev | axis as u64) as u32).count_ones()
}

/// Distinct corroboration axes for `src` this window (0 if evicted / unattributed). For
/// the SIEM / severity stamp and the self-test. Never feeds a drop decision.
pub fn corr_axes(src: u64) -> u32 {
    if src == 0 {
        return 0;
    }
    let s = (src as usize) % CORR_SRCS;
    let now = cntpct();
    let win = cntfrq().max(1).saturating_mul(CORR_WINDOW_SECS);
    if CORR_SRC[s].load(Ordering::Relaxed) == src
        && now.wrapping_sub(CORR_WIN[s].load(Ordering::Relaxed)) < win
    {
        (CORR_MASK[s].load(Ordering::Relaxed) as u32).count_ones()
    } else {
        0
    }
}

/// Is `src` currently CORROBORATED (>= CORR_CRITICAL_AXES distinct axes)? A SOC-severity
/// predicate — callers raise alert severity / QSECBIT, they DO NOT change the wire verdict.
pub fn is_corroborated(src: u64) -> bool {
    corr_axes(src) >= CORR_CRITICAL_AXES
}
