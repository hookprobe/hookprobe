//! Campaign limiter (ADR 0020 D3 condition 1) — enforces `limits:` fail-closed, in-process, checked
//! on every packet a probe wants to send. The AF_XDP/line-rate TX path is gated behind BOTH this
//! limiter AND the `topology` assertion (condition 1: "never line-rate without both") — a probe
//! calls `Limiter::admit(n_bytes)` per frame and MUST stop sending the instant it returns `Err`.
#![forbid(unsafe_code)]

use crate::roe::Limits;
use anyhow::{bail, Result};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

pub struct Limiter {
    limits: Limits,
    started: Instant,
    frames_total: AtomicU64,
    bytes_total: AtomicU64,
    // Per-probe pps bookkeeping: a coarse fixed-window counter (reset every second) is sufficient
    // for a hard ceiling check — this is a safety limiter, not a QoS shaper, so simplicity over a
    // token bucket is the right trade (fewer moving parts in a security-critical control).
    window_start: std::sync::Mutex<Instant>,
    window_frames: AtomicU64,
}

impl Limiter {
    pub fn new(limits: Limits) -> Self {
        Self {
            limits,
            started: Instant::now(),
            frames_total: AtomicU64::new(0),
            bytes_total: AtomicU64::new(0),
            window_start: std::sync::Mutex::new(Instant::now()),
            window_frames: AtomicU64::new(0),
        }
    }

    /// Call BEFORE sending one frame of `n_bytes`. `Err` means: STOP — a ceiling has been breached,
    /// fail-closed, no matter which one. The caller must abort the probe (and the campaign records
    /// this as an aborted/inconclusive finding, never a silent partial run).
    pub fn admit(&self, n_bytes: u64) -> Result<()> {
        // Wall-clock deadline.
        if self.started.elapsed() > Duration::from_secs(self.limits.max_wall_clock_seconds) {
            bail!(
                "campaign wall-clock deadline exceeded ({}s) -- aborting fail-closed",
                self.limits.max_wall_clock_seconds
            );
        }
        // Per-probe pps: reset the 1s window when it rolls over.
        {
            let mut w = self.window_start.lock().expect("limiter mutex poisoned");
            if w.elapsed() >= Duration::from_secs(1) {
                *w = Instant::now();
                self.window_frames.store(0, Ordering::SeqCst);
            }
        }
        let in_window = self.window_frames.fetch_add(1, Ordering::SeqCst) + 1;
        if in_window > self.limits.max_pps_per_probe {
            bail!(
                "max_pps_per_probe ({}) exceeded -- aborting fail-closed",
                self.limits.max_pps_per_probe
            );
        }
        // Campaign-total budgets.
        let frames = self.frames_total.fetch_add(1, Ordering::SeqCst) + 1;
        if frames > self.limits.max_frames_per_campaign {
            bail!(
                "max_frames_per_campaign ({}) exceeded -- aborting fail-closed",
                self.limits.max_frames_per_campaign
            );
        }
        let bytes = self.bytes_total.fetch_add(n_bytes, Ordering::SeqCst) + n_bytes;
        if bytes > self.limits.max_bytes_per_campaign {
            bail!(
                "max_bytes_per_campaign ({}) exceeded -- aborting fail-closed",
                self.limits.max_bytes_per_campaign
            );
        }
        Ok(())
    }

    pub fn frames_sent(&self) -> u64 {
        self.frames_total.load(Ordering::SeqCst)
    }
    pub fn bytes_sent(&self) -> u64 {
        self.bytes_total.load(Ordering::SeqCst)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn limits(pps: u64, frames: u64, bytes: u64, wall: u64) -> Limits {
        Limits {
            max_pps_per_probe: pps,
            max_frames_per_campaign: frames,
            max_bytes_per_campaign: bytes,
            max_wall_clock_seconds: wall,
            max_concurrency: 1,
        }
    }

    #[test]
    fn admits_under_every_ceiling() {
        let l = Limiter::new(limits(1000, 1000, 1_000_000, 300));
        for _ in 0..10 {
            assert!(l.admit(64).is_ok());
        }
        assert_eq!(l.frames_sent(), 10);
        assert_eq!(l.bytes_sent(), 640);
    }

    #[test]
    fn aborts_fail_closed_on_frame_budget_breach() {
        let l = Limiter::new(limits(1000, 5, 1_000_000, 300));
        for _ in 0..5 {
            assert!(l.admit(1).is_ok());
        }
        assert!(l.admit(1).is_err(), "the 6th frame must be refused (max_frames_per_campaign=5)");
    }

    #[test]
    fn aborts_fail_closed_on_byte_budget_breach() {
        let l = Limiter::new(limits(1000, 1000, 100, 300));
        assert!(l.admit(60).is_ok());
        assert!(l.admit(60).is_err(), "cumulative bytes (120) exceed the 100-byte campaign ceiling");
    }

    #[test]
    fn aborts_fail_closed_on_pps_breach_within_one_second() {
        let l = Limiter::new(limits(3, 1000, 1_000_000, 300));
        assert!(l.admit(1).is_ok());
        assert!(l.admit(1).is_ok());
        assert!(l.admit(1).is_ok());
        assert!(l.admit(1).is_err(), "the 4th frame in the same 1s window exceeds max_pps_per_probe=3");
    }

    #[test]
    fn aborts_fail_closed_on_wall_clock_deadline() {
        let l = Limiter::new(limits(1000, 1000, 1_000_000, 0));
        // max_wall_clock_seconds=0 would normally be refused by Roe::validate (condition 1), but the
        // limiter itself is independently defensive: elapsed() is always >= Duration::ZERO, so the
        // very first admit() must fail closed here too (belt-and-braces, never rely on one check).
        assert!(l.admit(1).is_err());
    }
}
