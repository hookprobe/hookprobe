// SPDX-License-Identifier: AGPL-3.0-only
//! SLO quotes from MEASURED timings (Select-N: per-layer decode time is deterministic, so a profile measured
//! once predicts well). `calibrate` writes the profile; quotes read it. Predictions only decide placement
//! (speed); a broken promise is recorded by the device.

use conductor_core::frame::{profile, Quote, QuoteRequest};
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Profile {
    /// Offload profile of the engine's current configuration (`frame::profile`).
    pub offload: u8,
    /// Time to first token for an empty prompt, and its growth per 1,000 input units (prefill).
    pub ttft_base_ms: u32,
    pub ttft_per_kunit_ms: u32,
    /// Time per output token (decode).
    pub tpot_ms: u32,
}

impl Default for Profile {
    /// Conservative until calibrated: a worker that was never measured promises little.
    fn default() -> Self {
        Self { offload: profile::CPU_ONLY, ttft_base_ms: 2_000, ttft_per_kunit_ms: 4_000, tpot_ms: 200 }
    }
}

pub const PROFILE_FILE: &str = "profile";

impl Profile {
    pub fn load(dir: &Path) -> Self {
        let Ok(text) = std::fs::read_to_string(dir.join(PROFILE_FILE)) else { return Self::default() };
        let get = |k: &str| text.lines().find_map(|l| l.strip_prefix(k).and_then(|r| r.strip_prefix('=')).and_then(|v| v.trim().parse().ok()));
        let d = Self::default();
        Self {
            offload: get("offload").unwrap_or(d.offload as u32) as u8,
            ttft_base_ms: get("ttft_base_ms").unwrap_or(d.ttft_base_ms),
            ttft_per_kunit_ms: get("ttft_per_kunit_ms").unwrap_or(d.ttft_per_kunit_ms),
            tpot_ms: get("tpot_ms").unwrap_or(d.tpot_ms),
        }
    }
    pub fn save(&self, dir: &Path) -> Result<(), String> {
        crate::files::atomic_write(
            &dir.join(PROFILE_FILE),
            format!(
                "offload={}\nttft_base_ms={}\nttft_per_kunit_ms={}\ntpot_ms={}\n",
                self.offload, self.ttft_base_ms, self.ttft_per_kunit_ms, self.tpot_ms
            )
            .as_bytes(),
        )
    }
    pub fn predict_ttft(&self, in_units: u32) -> u32 {
        self.ttft_base_ms.saturating_add((u64::from(in_units) * u64::from(self.ttft_per_kunit_ms) / 1000).min(u32::MAX as u64) as u32)
    }
}

/// "Is the accelerator idle?" — the owner's own check (e.g. a script calling nvidia-smi). Run directly,
/// never through a shell, with no stdin, and a time limit. Exit status 0 = idle. No command = always idle.
pub struct IdleProbe {
    pub cmd: Option<Vec<String>>,
    pub timeout: Duration,
}

impl IdleProbe {
    pub fn idle(&self) -> bool {
        let Some(cmd) = &self.cmd else { return true };
        let Some((prog, args)) = cmd.split_first() else { return true };
        let Ok(mut child) = Command::new(prog).args(args).stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null()).spawn() else {
            return false;
        };
        let start = Instant::now();
        loop {
            match child.try_wait() {
                Ok(Some(st)) => return st.success(),
                Ok(None) if start.elapsed() < self.timeout => std::thread::sleep(Duration::from_millis(20)),
                _ => {
                    let _ = child.kill();
                    let _ = child.wait();
                    return false; // a hung probe means "not idle"
                }
            }
        }
    }
}

pub fn answer(q: &QuoteRequest, p: &Profile, idle: bool) -> Quote {
    let predicted_ttft_ms = p.predict_ttft(q.in_units);
    let predicted_tpot_ms = p.tpot_ms;
    let idle_ok = idle || q.energy_policy & conductor_core::cap::energy::IDLE_ONLY == 0;
    let nvme_ok = p.offload != profile::NVME_STREAM || q.offload_hints & conductor_core::cap::offload::ALLOW_NVME_STREAM != 0;
    let mut quote = Quote {
        job_id: q.job_id,
        nonce: q.nonce,
        can_meet: idle_ok && nvme_ok,
        predicted_ttft_ms,
        predicted_tpot_ms,
        offload_profile: p.offload,
        valid_ms: 10_000,
    };
    quote.can_meet = quote.can_meet && quote.meets(q.slo_ttft_ms, q.slo_tpot_ms);
    quote
}
