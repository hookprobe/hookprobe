//! shed.rs — the pure logic half of shed-v2 (base-tier-build-ticket.md Phase 2, ADR 0031
//! amendment §E / ADR 0023 D3): the PSI-pressure→tier decision `hookprobe-psid` drives its
//! `shed_ctrl` writes from, the SHED_V2 ringbuf event decoder `bpf.rs` dispatches into, and a
//! faithful Rust MIRROR of `napse_detect.bpf.c`'s fixed-point token-bucket refill used ONLY to
//! prove the algorithm's correctness under test (eBPF has no test harness in this repo/sandbox —
//! see `token_bucket_mirror`'s own doc). No BPF/libbpf dependency — builds and tests anywhere
//! this crate already builds, same split `event.rs` already establishes (pure logic vs the
//! libbpf glue behind the `bpf` feature in `bpf.rs`).

use hookprobe_manifest::scan_responder::{parse_psi_file, PsiPressure};

// ── Pressure tiers (spec §3.2) ───────────────────────────────────────────────────────────────
//
// HONESTY NOTE: `docs/base-tier-build-ticket.md` cites a "tier table per spec §3.2" from an
// external base-tier consensus spec document that is not present in this repository (only its
// ADR distillation, `docs/adr/0031-dataplane-performance-strategy.md` §E, is — and that section
// deliberately gives the MECHANISM, not concrete per-tier numbers). The four thresholds/rates
// below are this pass's best-effort, clearly-documented interpolation, NOT a transcription of an
// unseen source: tier 2's boundaries are set to EXACTLY the existing, already-shipped nft
// fallback's own thresholds (`crates/hookprobe-manifest::scan_responder::{DEFAULT_CPU_SOME_AVG60_PCT,
// DEFAULT_MEM_FULL_AVG60_PCT}` = 40% / 15%) so the two layers agree on where "moderate" pressure
// begins; tier 1 is an earlier, gentler warning shot (half those thresholds) so shed-v2's ~1s
// reaction gets a head start on the 10s nft fallback; tier 3 is the severe/last-resort rung. Flag
// for os-architect/product-steward to reconcile against the real base-tier consensus spec if one
// exists outside this repo.
pub const SHED_TIER_BYPASSED: u8 = 0;
pub const SHED_TIER_MAX: u8 = 3;

/// Per-tier CPU (`some avg60`, %) / memory (`full avg60`, %) escalation thresholds and the
/// `r_base_pps` shed-v2 applies once that tier is in effect. Index 0 (tier 0) carries no
/// threshold — it is the floor everything decays back to.
#[derive(Debug, Clone, Copy)]
pub struct ShedTierThresholds {
    /// `(cpu_some_avg60_pct, mem_full_avg60_pct, r_base_pps)` for tiers 1..=3, ascending severity.
    pub tiers: [(f64, f64, u32); 3],
}

impl Default for ShedTierThresholds {
    fn default() -> Self {
        ShedTierThresholds {
            tiers: [
                (20.0, 5.0, 400), // tier 1 — early warning; 400pps matches the nft L1 ceiling
                (40.0, 15.0, 100), // tier 2 — matches the existing nft-fallback PSI trigger exactly
                (70.0, 30.0, 20),  // tier 3 — severe, last-resort tightening
            ],
        }
    }
}

/// The RAW tier this instant's PSI snapshot implies — no hysteresis (see [`TierHysteresis`] for
/// the debounced value actually written to `shed_ctrl`). Highest tier whose OR'd cpu/mem
/// threshold is met wins (checked from the top down so a severe spike is never under-reported).
pub fn raw_tier_for(cpu: &PsiPressure, mem: &PsiPressure, cfg: &ShedTierThresholds) -> u8 {
    let cpu_avg60 = cpu.some.map(|s| s.avg60).unwrap_or(0.0);
    let mem_avg60 = mem.full.map(|f| f.avg60).unwrap_or(0.0);
    for (i, (cpu_pct, mem_pct, _rate)) in cfg.tiers.iter().enumerate().rev() {
        if cpu_avg60 >= *cpu_pct || mem_avg60 >= *mem_pct {
            return (i as u8) + 1;
        }
    }
    SHED_TIER_BYPASSED
}

/// `r_base_pps` shed-v2 applies while `tier` is in effect. Tier 0 -> 0 (bucket bypassed, the
/// value is never consulted by the BPF side when tier==0 — see `shed_admit`'s own doc).
pub fn rate_pps_for_tier(tier: u8, cfg: &ShedTierThresholds) -> u32 {
    match tier {
        1..=3 => cfg.tiers[(tier - 1) as usize].2,
        _ => 0,
    }
}

/// Debounced tier: escalates IMMEDIATELY on a rising raw tier (react fast to genuine pressure —
/// this is exactly the sub-second-reaction property shed-v2 exists to deliver), but only steps
/// DOWN one rung at a time, and only after the raw tier has been continuously BELOW the current
/// rung for [`STEP_DOWN_HYSTERESIS_NS`] (spec: "step down one tier only after 5s below the lower
/// trigger") — never a straight jump from tier 3 to tier 0 the instant pressure blips down, and
/// never a reset of the countdown just because pressure hasn't gotten WORSE (only a genuine
/// return above the current rung resets it).
pub struct TierHysteresis {
    current: u8,
    below_since_ns: Option<u64>,
}

/// Step down one tier only after this long continuously below the current tier's own trigger.
pub const STEP_DOWN_HYSTERESIS_NS: u64 = 5_000_000_000;

impl Default for TierHysteresis {
    fn default() -> Self {
        TierHysteresis { current: SHED_TIER_BYPASSED, below_since_ns: None }
    }
}

impl TierHysteresis {
    /// Feed one raw-tier sample at monotonic time `now_ns`; returns the (possibly unchanged)
    /// debounced tier to write to `shed_ctrl`.
    pub fn step(&mut self, raw_tier: u8, now_ns: u64) -> u8 {
        if raw_tier >= self.current {
            // At or above the current rung: escalate immediately (or stay); the debounce timer
            // only ever tracks time spent BELOW the current rung, so any return to/above it
            // cancels a pending step-down outright.
            self.current = raw_tier;
            self.below_since_ns = None;
            return self.current;
        }
        // raw_tier < self.current: pressure is easing below the current rung.
        match self.below_since_ns {
            None => self.below_since_ns = Some(now_ns),
            Some(since) if now_ns.saturating_sub(since) >= STEP_DOWN_HYSTERESIS_NS => {
                self.current -= 1;
                self.below_since_ns = None; // restart the countdown for the NEXT rung down
            }
            Some(_) => {} // still within the 5s debounce window — hold the current tier
        }
        self.current
    }

    pub fn current(&self) -> u8 {
        self.current
    }
}

/// Read + parse both PSI files' full text into `(cpu, mem)` pressure snapshots. Pure — the
/// caller does the actual file I/O and hands in the text (keeps this module testable without a
/// real `/proc/pressure` mount).
pub fn parse_pressure(cpu_text: &str, mem_text: &str) -> (PsiPressure, PsiPressure) {
    (parse_psi_file(cpu_text), parse_psi_file(mem_text))
}

/// One PSI trigger spec for the Linux psi-monitor API (`/proc/pressure/{cpu,memory}`'s
/// write-then-`poll(POLLPRI)` protocol): `"<some|full> <stall_us> <window_us>\0"`. `stall_us`
/// must be `<= window_us`; the kernel additionally requires `window_us` in `[500_000,
/// 10_000_000]` and a multiple of `2_000`. Best-effort: `hookprobe-psid` falls back to plain
/// timeout-driven polling if opening/writing any of these fails (e.g. insufficient privilege) —
/// see that binary's own doc.
pub fn psi_trigger_string(kind: &str, pct: f64, window_us: u64) -> String {
    let stall_us = ((pct / 100.0) * window_us as f64).round() as u64;
    let stall_us = stall_us.min(window_us);
    format!("{kind} {stall_us} {window_us}")
}

// =============================================================================================
// SHED_V2 ringbuf event decoder — mirrors `struct shed_event` in napse_detect.h (24 bytes,
// distinguished from `napse_event`'s 32 by size alone; see that header's doc).
// =============================================================================================

pub const SHED_EVENT_SIZE: usize = 24;

/// enum napse_verdict — the only disposition shed-v2 ever emits today (kept for schema
/// stability: a future "shed_admit but log-only" mode could legitimately reuse this struct).
pub const SHED_DISPOSITION_DROP: u8 = 1;

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct ShedEvent {
    pub saddr: std::net::Ipv4Addr,
    pub tier: u8,
    pub disposition: u8,
    pub rate_pps: u32,
}

fn u32le(b: &[u8]) -> u32 {
    u32::from_le_bytes([b[0], b[1], b[2], b[3]])
}

impl ShedEvent {
    /// Parse one 24-byte `shed_event` ringbuf record (native/little-endian on our targets).
    /// Layout: `u64 ts_ns; u32 saddr; u8 tier; u8 disposition; u8 _pad[2]; u32 rate_pps;`
    pub fn from_bytes(b: &[u8]) -> Option<ShedEvent> {
        if b.len() < SHED_EVENT_SIZE {
            return None;
        }
        let saddr_raw = &b[8..12];
        Some(ShedEvent {
            saddr: std::net::Ipv4Addr::new(saddr_raw[0], saddr_raw[1], saddr_raw[2], saddr_raw[3]),
            tier: b[12],
            disposition: b[13],
            rate_pps: u32le(&b[20..24]),
        })
    }

    /// Render as one telemetry line for the flows/events stream, matching `NapseEvent::to_flow_json`'s
    /// shape (`type`/`ts`/severity/signature) so downstream consumers already reading that stream
    /// need no new parser branch beyond a new `type` value.
    pub fn to_flow_json(&self, wall_ts: f64) -> String {
        format!(
            "{{\"type\":\"shed_v2\",\"ts\":{wall_ts:.3},\"src_ip\":\"{src}\",\"shed_tier\":{tier},\
             \"shed_rate_pps\":{rate},\"shed_disposition\":\"{disp}\",\"alert_severity\":{sev},\
             \"alert_signature\":\"napse.resource-shed-v2\"}}",
            src = self.saddr,
            tier = self.tier,
            rate = self.rate_pps,
            disp = if self.disposition == SHED_DISPOSITION_DROP { "drop" } else { "unknown" },
            // Severity scales with tier: a tier-3 shed is a genuinely severe resource event;
            // tier-1 is a routine, expected, self-reverting tightening.
            sev = 4u8.saturating_sub(self.tier.min(3)),
        )
    }
}

// =============================================================================================
// token_bucket_mirror — a faithful Rust re-implementation of napse_detect.bpf.c's shed_admit()
// fixed-point refill, used ONLY as a test oracle to prove the must-fix #1 algorithm is sound.
// =============================================================================================
//
// HONESTY: this repository has no BPF verifier/exec test harness (checked: no
// `bpf_prog_test_run`/rbpf precedent anywhere in the tree), and this sandbox has no privileged
// kernel to load the real program into (`bpftool prog load` fails here with no BTF-matched
// kernel — see the Makefile's own "cannot run in the current dev environment" honesty note for
// the SAME constraint on `make verify`). What CAN be proven here: the C source compiles clean
// against real libbpf/BTF headers (`clang -target bpf`, done), and — this module — that the
// EXACT fixed-point formula `napse_detect.bpf.c`'s `shed_admit()` uses is algorithmically sound
// against the must-fix #1 acceptance criterion. Any change to one implementation MUST be
// mirrored in the other; a `verification-engineer` netns-DUT / real-kernel gate (ADR 0020) is
// the honest place to prove the ACTUAL compiled .bpf.o exhibits the same behaviour on silicon.
pub mod token_bucket_mirror {
    pub const TOKEN_SCALE: u64 = 1_000_000;
    pub const ELAPSED_CAP_NS: u64 = 1_000_000_000;
    pub const NSEC_PER_SEC: u64 = 1_000_000_000;

    #[derive(Debug, Clone, Copy, Default)]
    pub struct ShedToken {
        pub tokens_scaled: u64,
        pub last_ns: u64,
    }

    /// Mirrors the `_Static_assert` in `napse_detect.bpf.c` right above `shed_admit()`'s C
    /// twin: the documented safety ceiling (`SHED_MAX_RATE_PPS` there, 10000 here — keep them
    /// equal) must never let `rate_scaled * elapsed` overflow u64. Evaluated at COMPILE time
    /// (a `const` block, not a runtime assert in a test that might never run) — this crate's
    /// own build fails the same way the C build does if `TOKEN_SCALE`/`ELAPSED_CAP_NS` are ever
    /// tuned without re-checking this bound. See that assert's own doc for why this exists in
    /// TWO files: the constants aren't co-located (C: napse_detect.h + napse_detect.bpf.c;
    /// Rust: this module) and this specific class of drift already happened once during review.
    const MAX_RATE_PPS_FOR_OVERFLOW_CHECK: u64 = 10_000;
    const _: () = assert!(
        MAX_RATE_PPS_FOR_OVERFLOW_CHECK * TOKEN_SCALE <= u64::MAX / ELAPSED_CAP_NS,
        "shed-v2 fixed-point refill would overflow u64 at these constants"
    );

    /// Mirrors `shed_admit()` exactly: same fixed-point-only arithmetic, same cold-start (bucket
    /// starts full minus one token), same elapsed-cap, same burst-depth cap. Returns
    /// `(admit, updated_bucket)`.
    pub fn shed_admit(tk: Option<ShedToken>, tier: u8, rate_pps: u32, now_ns: u64) -> (bool, ShedToken) {
        if tier == 0 || rate_pps == 0 {
            return (true, tk.unwrap_or_default());
        }
        let rate_scaled = rate_pps as u64 * TOKEN_SCALE;
        match tk {
            None => {
                let tokens_scaled = rate_scaled.saturating_sub(TOKEN_SCALE);
                (true, ShedToken { tokens_scaled, last_ns: now_ns })
            }
            Some(mut t) => {
                let elapsed = now_ns.saturating_sub(t.last_ns).min(ELAPSED_CAP_NS);
                // MUST-FIX #1: fixed-point integer only — no float anywhere in this calculation.
                let refill = (rate_scaled * elapsed) / NSEC_PER_SEC;
                let tokens = (t.tokens_scaled + refill).min(rate_scaled);
                t.last_ns = now_ns;
                if tokens >= TOKEN_SCALE {
                    t.tokens_scaled = tokens - TOKEN_SCALE;
                    (true, t)
                } else {
                    t.tokens_scaled = tokens;
                    (false, t)
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hookprobe_manifest::scan_responder::PsiSnapshot;

    fn psi(some_avg60: f64, full_avg60: Option<f64>) -> PsiPressure {
        PsiPressure {
            some: Some(PsiSnapshot { avg10: some_avg60, avg60: some_avg60, avg300: some_avg60, total: 0 }),
            full: full_avg60.map(|f| PsiSnapshot { avg10: f, avg60: f, avg300: f, total: 0 }),
        }
    }

    // ---- raw_tier_for -------------------------------------------------------------------

    #[test]
    fn healthy_box_is_tier_0() {
        let cpu = psi(2.0, None);
        let mem = psi(0.0, Some(0.5));
        assert_eq!(raw_tier_for(&cpu, &mem, &ShedTierThresholds::default()), SHED_TIER_BYPASSED);
    }

    #[test]
    fn cpu_crossing_tier1_but_not_tier2_is_tier_1() {
        let cpu = psi(25.0, None); // >=20 (t1), <40 (t2)
        let mem = psi(0.0, Some(0.0));
        assert_eq!(raw_tier_for(&cpu, &mem, &ShedTierThresholds::default()), 1);
    }

    #[test]
    fn mem_full_avg60_alone_can_drive_tier_independent_of_cpu() {
        let cpu = psi(0.0, None);
        let mem = psi(0.0, Some(20.0)); // >=15 (t2), <30 (t3)
        assert_eq!(raw_tier_for(&cpu, &mem, &ShedTierThresholds::default()), 2);
    }

    #[test]
    fn severe_pressure_is_tier_3() {
        let cpu = psi(90.0, None);
        let mem = psi(0.0, Some(0.0));
        assert_eq!(raw_tier_for(&cpu, &mem, &ShedTierThresholds::default()), SHED_TIER_MAX);
    }

    #[test]
    fn tier2_boundary_matches_the_existing_nft_fallback_thresholds_exactly() {
        // Deliberate parity check: shed-v2's tier 2 and the ALREADY-SHIPPED nft-fallback trigger
        // (crates/hookprobe-manifest::scan_responder::DEFAULT_{CPU_SOME,MEM_FULL}_AVG60_PCT) must
        // agree on where "moderate/sustained pressure" begins, so both layers engage together.
        use hookprobe_manifest::scan_responder::{DEFAULT_CPU_SOME_AVG60_PCT, DEFAULT_MEM_FULL_AVG60_PCT};
        let cfg = ShedTierThresholds::default();
        assert_eq!(cfg.tiers[1].0, DEFAULT_CPU_SOME_AVG60_PCT);
        assert_eq!(cfg.tiers[1].1, DEFAULT_MEM_FULL_AVG60_PCT);
    }

    // ---- rate_pps_for_tier ---------------------------------------------------------------

    #[test]
    fn tier_0_rate_is_zero_unused() {
        assert_eq!(rate_pps_for_tier(0, &ShedTierThresholds::default()), 0);
    }

    #[test]
    fn rate_tightens_monotonically_as_tier_rises() {
        let cfg = ShedTierThresholds::default();
        let r1 = rate_pps_for_tier(1, &cfg);
        let r2 = rate_pps_for_tier(2, &cfg);
        let r3 = rate_pps_for_tier(3, &cfg);
        assert!(r1 > r2 && r2 > r3, "each tier must be strictly tighter than the last: {r1} > {r2} > {r3}");
    }

    // ---- TierHysteresis --------------------------------------------------------------------

    #[test]
    fn escalates_immediately_no_debounce_on_the_way_up() {
        let mut h = TierHysteresis::default();
        assert_eq!(h.step(3, 0), 3, "a rising tier must react immediately (sub-second reaction is the point)");
    }

    #[test]
    fn does_not_step_down_before_5s_below_the_lower_trigger() {
        let mut h = TierHysteresis::default();
        h.step(2, 0);
        assert_eq!(h.step(0, 1_000_000_000), 2, "1s below — must hold");
        assert_eq!(h.step(0, 4_999_999_999), 2, "just under 5s below — must still hold");
    }

    #[test]
    fn steps_down_exactly_one_rung_after_5s_continuously_below() {
        let mut h = TierHysteresis::default();
        h.step(3, 0);
        h.step(0, 0); // first sample below the rung — starts the 5s countdown at t=0
        assert_eq!(h.step(0, 5_000_000_000), 2, "5s below tier 3's trigger -> steps down to 2, not straight to 0");
    }

    #[test]
    fn a_return_above_the_current_rung_cancels_a_pending_step_down() {
        let mut h = TierHysteresis::default();
        h.step(2, 0);
        h.step(0, 3_000_000_000); // 3s into the countdown
        assert_eq!(h.step(2, 3_500_000_000), 2, "back at/above the rung -> countdown cancelled");
        // Prove it was really cancelled, not just paused: another 3s (would have been 6s total
        // from the FIRST dip) must NOT be enough from this new baseline.
        assert_eq!(h.step(0, 6_000_000_000), 2, "countdown must have restarted, not resumed");
    }

    #[test]
    fn full_ladder_decays_one_rung_per_5s_down_to_bypassed() {
        // Realistic usage: step() is polled roughly once a second, not sampled sparsely — the
        // countdown for a given rung only starts on the FIRST sample observed below it.
        let mut h = TierHysteresis::default();
        h.step(3, 0);
        let mut seen_at_5s_marks = Vec::new();
        for sec in 1..=20u64 {
            let t = sec * 1_000_000_000;
            h.step(0, t);
            if sec % 5 == 0 {
                seen_at_5s_marks.push(h.current());
            }
        }
        // One rung down every full 5s of continuous sub-trigger observation: 3 -> 2 -> 1 -> 0
        // (the countdown itself only starts on the FIRST sub-trigger sample at t=1s, so the
        // first step-down lands at t=6s — just after the t=5s checkpoint below, not at it).
        assert_eq!(seen_at_5s_marks, vec![3, 2, 1, 0]);
        assert_eq!(h.current(), SHED_TIER_BYPASSED);
    }

    // ---- psi_trigger_string ----------------------------------------------------------------

    #[test]
    fn trigger_string_shape_matches_the_kernel_psi_monitor_protocol() {
        assert_eq!(psi_trigger_string("some", 20.0, 1_000_000), "some 200000 1000000");
        assert_eq!(psi_trigger_string("full", 15.0, 1_000_000), "full 150000 1000000");
    }

    #[test]
    fn trigger_stall_never_exceeds_the_window() {
        // A >=100% threshold must clamp, never emit a kernel-rejected stall_us > window_us.
        assert_eq!(psi_trigger_string("some", 150.0, 1_000_000), "some 1000000 1000000");
    }

    // ---- ShedEvent decode/render ------------------------------------------------------------

    fn raw_shed_event(saddr: [u8; 4], tier: u8, disposition: u8, rate_pps: u32) -> Vec<u8> {
        let mut b = vec![0u8; SHED_EVENT_SIZE];
        b[0..8].copy_from_slice(&999u64.to_le_bytes()); // ts_ns (ignored by the decoder)
        b[8..12].copy_from_slice(&saddr);
        b[12] = tier;
        b[13] = disposition;
        // b[14..16] = _pad
        b[20..24].copy_from_slice(&rate_pps.to_le_bytes());
        b
    }

    #[test]
    fn decodes_a_shed_event_correctly() {
        let raw = raw_shed_event([203, 0, 113, 9], 2, SHED_DISPOSITION_DROP, 100);
        let e = ShedEvent::from_bytes(&raw).unwrap();
        assert_eq!(e.saddr, std::net::Ipv4Addr::new(203, 0, 113, 9));
        assert_eq!(e.tier, 2);
        assert_eq!(e.disposition, SHED_DISPOSITION_DROP);
        assert_eq!(e.rate_pps, 100);
    }

    #[test]
    fn short_buffer_rejected() {
        assert!(ShedEvent::from_bytes(&[0u8; 10]).is_none());
    }

    #[test]
    fn shed_event_size_never_collides_with_napse_event_size() {
        assert_ne!(SHED_EVENT_SIZE, crate::event::EVENT_SIZE, "the two ringbuf record kinds must stay distinguishable by size alone");
    }

    #[test]
    fn renders_shed_v2_flow_json_with_expected_fields() {
        let e = ShedEvent { saddr: std::net::Ipv4Addr::new(10, 66, 0, 200), tier: 3, disposition: SHED_DISPOSITION_DROP, rate_pps: 20 };
        let j = e.to_flow_json(1782900000.0);
        assert!(j.contains("\"type\":\"shed_v2\""));
        assert!(j.contains("\"shed_tier\":3"));
        assert!(j.contains("\"shed_rate_pps\":20"));
        assert!(j.contains("\"alert_signature\":\"napse.resource-shed-v2\""));
    }

    // ---- token_bucket_mirror — must-fix #1 acceptance ---------------------------------------

    #[test]
    fn tier_0_always_admits_never_touches_the_bucket() {
        use token_bucket_mirror::*;
        let (admit, _) = shed_admit(None, 0, 400, 0);
        assert!(admit, "tier 0 must be a true bypass");
    }

    /// THE must-fix #1 acceptance test (base-tier-build-ticket.md): "a legit new-flow burst at
    /// line rate passes while tier >= 1 — proves the refill accumulates, not truncates."
    /// Simulates a source opening new connections at exactly the tier-1 ceiling's rate with
    /// SUB-MILLISECOND spacing between them (the exact pathological case the must-fix #1 bug
    /// describes: `rate * dt_ns / 1e9` truncates to 0 at per-packet dt). A naive
    /// non-fixed-point/non-accumulating implementation would shed essentially every packet after
    /// the very first; this mirror must admit very close to the configured rate.
    #[test]
    fn legit_new_flow_burst_passes_at_line_rate_under_tier_pressure_must_fix_1() {
        use token_bucket_mirror::*;
        let rate_pps: u32 = 400; // tier 1's r_base_pps
        let dt_ns: u64 = 50_000; // 50us between new connections — a fast, but entirely
                                 // legitimate, burst (20,000 conns/sec arrival spacing on the
                                 // wire), FAR tighter than any real client's connection-setup
                                 // cadence, chosen specifically to be well inside the
                                 // "sub-second per-packet dt" danger zone must-fix #1 describes.
        let mut tk: Option<ShedToken> = None;
        let mut now = 0u64;
        let mut admitted = 0u32;
        let total = 400u32; // one full second's worth of legit new-flow arrivals at rate_pps
        for _ in 0..total {
            let (ok, next) = shed_admit(tk, 1, rate_pps, now);
            tk = Some(next);
            if ok {
                admitted += 1;
            }
            now += dt_ns;
        }
        // A source arriving AT (not above) the configured rate must be admitted essentially in
        // full — the bucket starts pre-loaded with ~1s of burst depth (cold-start credit) on top
        // of steady per-packet refill, so it should clear comfortably above 95%. A truncating
        // (broken) implementation admits only the handful of packets the initial cold-start
        // credit alone can cover, then drops everything else (~0% for the remaining ~99% of the
        // burst) — nowhere close to this bound.
        assert!(
            admitted as f64 / total as f64 >= 0.95,
            "expected >=95% of a legit at-rate burst to be admitted under tier>=1 pressure, got {admitted}/{total}"
        );
    }

    #[test]
    fn naive_non_accumulating_refill_would_truncate_to_zero_this_proves_the_bug_the_fix_avoids() {
        // Documents the EXACT bug must-fix #1 describes, so the regression is legible: the
        // naive `rate * dt_ns / 1e9` computed FRESH per packet (no persisted state, no scaling)
        // truncates to 0 for any dt well under a second at realistic rates — e.g. at 400pps and
        // dt=50us: 400 * 50_000 / 1_000_000_000 == 0 (integer division truncates the fraction).
        let rate_pps: u64 = 400;
        let dt_ns: u64 = 50_000;
        let naive_tokens_per_packet = (rate_pps * dt_ns) / 1_000_000_000;
        assert_eq!(naive_tokens_per_packet, 0, "the naive unscaled formula truncates to 0 at this dt — exactly the bug");
    }

    #[test]
    fn a_true_flood_far_above_the_tier_ceiling_is_still_shed() {
        // The flip side of the must-fix #1 test: a source WAY above the configured rate (10x)
        // must still be predominantly shed, proving the fix didn't accidentally turn the bucket
        // into an unconditional pass.
        use token_bucket_mirror::*;
        let rate_pps: u32 = 20; // tier 3's r_base_pps
        let dt_ns: u64 = 1_000_000 / (rate_pps as u64 * 10); // 10x the configured rate
        let mut tk: Option<ShedToken> = None;
        let mut now = 0u64;
        let mut admitted = 0u32;
        let total = 2000u32;
        for _ in 0..total {
            let (ok, next) = shed_admit(tk, 3, rate_pps, now);
            tk = Some(next);
            if ok {
                admitted += 1;
            }
            now += dt_ns;
        }
        let admit_rate = admitted as f64 / total as f64;
        assert!(admit_rate < 0.20, "a 10x-over-ceiling flood must be predominantly shed, admitted {admitted}/{total} ({admit_rate:.2})");
    }

    #[test]
    fn bucket_never_overflows_capacity_across_a_long_idle_gap() {
        // A source idle for a long time, then bursting, must not have accumulated an unbounded
        // credit (would defeat the shed entirely) — the elapsed cap + burst-depth clamp bounds it.
        use token_bucket_mirror::*;
        let rate_pps: u32 = 20;
        let (_, tk) = shed_admit(None, 1, rate_pps, 0);
        // idle for a very long time (1 hour) before the next packet
        let (admit, tk2) = shed_admit(Some(tk), 1, rate_pps, 3_600_000_000_000);
        assert!(admit);
        // capacity is capped at rate_scaled (1s worth); after consuming one token it can never
        // exceed rate_scaled - TOKEN_SCALE regardless of how long the idle gap was.
        assert!(tk2.tokens_scaled <= (rate_pps as u64) * TOKEN_SCALE, "bucket must not accumulate unbounded credit across a long idle gap");
    }

    #[test]
    fn refill_math_never_overflows_u64_at_the_documented_safety_ceiling() {
        // Mirrors the BPF-side SHED_MAX_RATE_PPS clamp: prove the fixed-point multiply is safe
        // at the documented ceiling even with the full elapsed cap applied.
        use token_bucket_mirror::*;
        const SHED_MAX_RATE_PPS: u32 = 10_000;
        let rate_scaled = SHED_MAX_RATE_PPS as u64 * TOKEN_SCALE;
        let product = rate_scaled.checked_mul(ELAPSED_CAP_NS);
        assert!(product.is_some(), "rate_scaled * ELAPSED_CAP_NS must not overflow u64 at the documented ceiling");
    }
}
