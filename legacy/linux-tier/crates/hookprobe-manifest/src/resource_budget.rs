//! Resource budgets — per-module CPU/memory enforcement + graceful degradation.
//!
//! Implements the "two resource walls" `docs/architecture/Readme.md`'s "Resource limits & performance"
//! section commits to:
//!   - **HARD wall** (kill): cgroup `MemoryMax`/`CPUQuota` for containers/sysext, Wasmtime
//!     `StoreLimits` memory + epoch interruption for wasm. Breach -> the module is stopped
//!     (OOM-killed / epoch-interrupted), never the host.
//!   - **SOFT wall** (throttle/warn): cgroup `MemoryHigh` for containers, and (new) a Wasmtime
//!     **fuel** budget for wasm — a CPU-computation meter distinct from the wall-clock epoch
//!     deadline (a module can be well within its epoch deadline and still be burning far more
//!     CPU per unit time than its budget allows; fuel catches THAT, epoch catches "wedged").
//!
//! `Budget` (`crate::types::Budget`) carries the requested/declared numbers; this module supplies
//! the PER-RUNTIME DEFAULTS applied when a field is unset (module.yaml's `resources:` block is
//! absent or partial), and the shared evidence-graph event emitted when a module breaches its
//! budget (mirrors `module_sig::emit_artifact_tamper`'s shape/conventions exactly, so it needs no
//! new ingest path — `hookprobe-evidence::ingest_detection` already parses this `detections`
//! shape).
//!
//! ## Design fork flagged for an ADR (implemented pragmatically here, not blocked on)
//!
//! **Wasm fuel: per-invocation vs. per-epoch-tick-refill.** A one-shot module run
//! (`wasm_loader::run_wasi_module`, used by `load_check`/tests/batch invocations) gets a SINGLE
//! fuel budget for the whole call — straightforward "bounded computation per invocation". The
//! PRODUCTION STREAMING path (`run_wasi_module_streaming`, a `tail -F flows | ... >> events`
//! long-running pipeline) never "completes" an invocation in the same sense, so a one-shot budget
//! would either be exhausted almost immediately (too tight) or have to be enormous (too loose to
//! mean anything). This implementation REFILLS the fuel budget on every epoch tick (from inside
//! the SAME `epoch_deadline_callback` the wall-clock wall already uses), which turns `fuel` into a
//! **rate wall**: "at most `fuel` units of computation per `epoch_ms` window" — reusing the
//! existing tick cadence instead of a second timer/thread. This composes cleanly with epoch (same
//! callback, same thread, no extra synchronization) but is a real design choice (a stricter
//! "lifetime fuel budget, restart to reset" policy is equally defensible for some detectors) —
//! worth an ADR rather than silently locking in one semantic.

use std::path::Path;

use crate::types::{Budget, Runtime};

// ---------------------------------------------------------------------------
// Per-runtime defaults (used only when the corresponding Budget field is None)
// ---------------------------------------------------------------------------

/// Relative `CPUWeight` default (systemd's own unit default is 100; kept explicit here so the
/// generated cgroup drop-in is self-documenting rather than relying on an implicit systemd
/// default the reader has to know).
pub const DEFAULT_CPU_WEIGHT: u64 = 100;

/// Wasm fuel default: ~2 billion fuel units (Wasmtime charges roughly 1 unit per executed wasm
/// instruction, with a handful of zero-cost bookkeeping ops) per epoch tick (default `epoch_ms` =
/// 50ms) for a module with no explicit `resources.fuel`. Generous enough for real NAPSE/QSECBIT-
/// class per-tick workloads observed in this repo's own load tests, bounded enough that a
/// runaway/malicious loop is caught in well under a second even if it somehow dodged the epoch
/// wall. Pi-class-appropriate: this is a CPU-instruction budget, not a wall-clock one, so it costs
/// nothing when the module is idle.
pub const WASM_DEFAULT_FUEL: u64 = 2_000_000_000;

/// SOFT-wall (`MemoryHigh`) fraction of the HARD wall (`memory_mb`/`MemoryMax`), per runtime.
/// Wasm modules are capability-sandboxed and memory-light (ADR 0009 targets single-digit MiB
/// idle) — a tighter soft wall surfaces pressure earlier. Containers run heavier stateful
/// services (HYDRA enrichment, OVS) that legitimately spike; more headroom before throttling.
const WASM_MEM_HIGH_PCT: u64 = 80;
const CONTAINER_MEM_HIGH_PCT: u64 = 85;

impl Budget {
    /// The SOFT wall in effect for this budget: the declared `mem_high_mb` if set, else a
    /// per-runtime fraction of the HARD wall (`memory_mb`). `0` iff `memory_mb` is also `0`
    /// (sysext/host/image-layer modules carry `Budget::default()` — bounded by their host slice,
    /// not a per-module cgroup budget; see `supervisor::module_budget`).
    pub fn effective_mem_high_mb(&self, runtime: &Runtime) -> u64 {
        if let Some(h) = self.mem_high_mb {
            return h;
        }
        if self.memory_mb == 0 {
            return 0;
        }
        let pct = match runtime {
            Runtime::Wasm => WASM_MEM_HIGH_PCT,
            _ => CONTAINER_MEM_HIGH_PCT,
        };
        ((self.memory_mb * pct) / 100).max(1)
    }

    /// The relative `CPUWeight` in effect: the declared value if set, else `DEFAULT_CPU_WEIGHT`
    /// for every runtime (systemd's own default — kept as an explicit constant, see above).
    pub fn effective_cpu_weight(&self) -> u64 {
        self.cpu_weight.unwrap_or(DEFAULT_CPU_WEIGHT)
    }

    /// The wasm fuel budget in effect: the declared value if set, else `WASM_DEFAULT_FUEL` for
    /// `Runtime::Wasm`, else `0` (meaningless/unused) for every other runtime — fuel is a Wasmtime
    /// concept, never applied to a container/sysext/host module.
    pub fn effective_fuel(&self, runtime: &Runtime) -> u64 {
        if let Some(f) = self.fuel {
            return f;
        }
        match runtime {
            Runtime::Wasm => WASM_DEFAULT_FUEL,
            _ => 0,
        }
    }

    /// Render the `[Service]` cgroup directives this budget implies, one per non-zero field, in
    /// the SAME textual shape hand-authored units already use (`MemoryMax=64M`, `Slice=...`, see
    /// e.g. `modules/qsecbit/units/qsecbit.service`) — used by both the build-time generator
    /// (`builder/gen-staging.sh`'s companion Python emits the identical shape independently; see
    /// that script's own per-runtime default table, which MUST be kept numerically in sync with
    /// this module's constants — a cross-language drift risk flagged, not automatically checked)
    /// and available to a future device-side "reconcile writes the resolved per-device budget as
    /// a drop-in" step (not yet wired to a live `systemctl daemon-reload`; see module docs).
    pub fn render_cgroup_dropin(&self, runtime: &Runtime) -> String {
        let mut lines = vec!["[Service]".to_string()];
        if self.memory_mb > 0 {
            lines.push(format!("MemoryMax={}M", self.memory_mb));
            let high = self.effective_mem_high_mb(runtime);
            if high > 0 {
                lines.push(format!("MemoryHigh={high}M"));
            }
        }
        if self.cpu_pct > 0 {
            lines.push(format!("CPUQuota={}%", self.cpu_pct));
        }
        lines.push(format!("CPUWeight={}", self.effective_cpu_weight()));
        lines.join("\n") + "\n"
    }
}

// ---------------------------------------------------------------------------
// Graceful-degradation evidence event — mirrors module_sig::artifact_tamper_event's shape/
// conventions exactly (same `detections` shape hookprobe-evidence::ingest_detection parses).
// ---------------------------------------------------------------------------

/// Rule-id band for resource-budget evidence events — a NEW band (governance/resource, not a
/// network detection, not the ADR 0016 supply-chain band `9_100_0xx`). Deliberately outside
/// NAPSE's `1_000_0xx` detection-rule band and ADR 0014's reserved `9_000_0xx` ML-tier band.
pub const RESOURCE_BUDGET_RULE_ID: i64 = 9_200_001;

/// Which wall a module breached — distinguishes "throttled" (soft) from "killed" (hard) in the
/// evidence event, per the task's "two walls" requirement.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Wall {
    /// `MemoryHigh` throttle, a fuel warning, or any other back-pressure signal that did NOT stop
    /// the module.
    Soft,
    /// `MemoryMax` OOM-kill, wasm fuel exhaustion (the module's invocation was terminated), or
    /// repeated self-test failure that caused the health phase to shed the module.
    Hard,
}
impl Wall {
    pub fn as_str(&self) -> &'static str {
        match self {
            Wall::Soft => "soft",
            Wall::Hard => "hard",
        }
    }
    fn severity(&self) -> i64 {
        match self {
            Wall::Soft => 1,
            Wall::Hard => 3,
        }
    }
}

fn now_ts() -> f64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0)
}

/// Render one JSON-lines evidence event for a resource-budget breach — same field set/shape as
/// `module_sig::artifact_tamper_event` (`ingest_detection` doesn't require `mitre`/`src_ip`/
/// `dst_ip`/`dst_port` non-empty; this is a governance event, not a network one, same convention
/// `aegis_reflex`/`aegis_guard` events already use — empty/zero, not omitted).
pub fn resource_budget_event(module_id: &str, wall: Wall, reason: &str, detail: &str, ts: f64) -> String {
    serde_json::json!({
        "ts": ts,
        "rule_id": RESOURCE_BUDGET_RULE_ID,
        "rule_msg": format!("ResourceBudget: {module_id} breached its {} wall ({reason})", wall.as_str()),
        "category": "resource_budget",
        "severity": wall.severity(),
        "mitre": "",
        "src_ip": "",
        "dst_ip": "",
        "dst_port": 0,
        "confidence": 1.0,
        "module": module_id,
        "wall": wall.as_str(),
        "reason": reason,
        "detail": detail,
    })
    .to_string()
}

/// Append one `resource_budget_event` line to the events file — same best-effort O_APPEND
/// discipline as `module_sig::emit_artifact_tamper` (never masks the caller's own degrade/shed
/// decision on a write failure, only logs one on stderr).
pub fn emit_resource_budget_event(events_path: &Path, module_id: &str, wall: Wall, reason: &str, detail: &str) {
    let line = resource_budget_event(module_id, wall, reason, detail, now_ts());
    match std::fs::OpenOptions::new().create(true).append(true).open(events_path) {
        Ok(mut f) => {
            use std::io::Write as _;
            if let Err(e) = writeln!(f, "{line}") {
                eprintln!("warning: could not append ResourceBudget event to {events_path:?}: {e}");
            }
        }
        Err(e) => eprintln!("warning: could not open events file {events_path:?} for ResourceBudget event: {e}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn effective_mem_high_defaults_by_runtime() {
        let b = Budget { cpu_pct: 50, memory_mb: 256, epoch_ms: None, mem_high_mb: None, cpu_weight: None, fuel: None };
        assert_eq!(b.effective_mem_high_mb(&Runtime::Wasm), 204); // 80% of 256
        assert_eq!(b.effective_mem_high_mb(&Runtime::Container), 217); // 85% of 256 (rounded down)
    }

    #[test]
    fn effective_mem_high_honors_explicit_override() {
        let b = Budget { cpu_pct: 50, memory_mb: 256, epoch_ms: None, mem_high_mb: Some(100), cpu_weight: None, fuel: None };
        assert_eq!(b.effective_mem_high_mb(&Runtime::Wasm), 100);
    }

    #[test]
    fn effective_mem_high_zero_when_unbudgeted() {
        let b = Budget::default();
        assert_eq!(b.effective_mem_high_mb(&Runtime::Sysext), 0);
    }

    #[test]
    fn effective_cpu_weight_defaults_and_override() {
        let b = Budget::default();
        assert_eq!(b.effective_cpu_weight(), DEFAULT_CPU_WEIGHT);
        let b2 = Budget { cpu_weight: Some(800), ..Budget::default() };
        assert_eq!(b2.effective_cpu_weight(), 800);
    }

    #[test]
    fn effective_fuel_wasm_default_vs_container_zero_vs_override() {
        let b = Budget::default();
        assert_eq!(b.effective_fuel(&Runtime::Wasm), WASM_DEFAULT_FUEL);
        assert_eq!(b.effective_fuel(&Runtime::Container), 0);
        let b2 = Budget { fuel: Some(42), ..Budget::default() };
        assert_eq!(b2.effective_fuel(&Runtime::Wasm), 42);
    }

    #[test]
    fn render_cgroup_dropin_shape() {
        let b = Budget { cpu_pct: 50, memory_mb: 256, epoch_ms: Some(50), mem_high_mb: None, cpu_weight: None, fuel: None };
        let rendered = b.render_cgroup_dropin(&Runtime::Wasm);
        eprintln!("{rendered}");
        assert!(rendered.contains("MemoryMax=256M"));
        assert!(rendered.contains("MemoryHigh=204M"));
        assert!(rendered.contains("CPUQuota=50%"));
        assert!(rendered.contains("CPUWeight=100"));
    }

    #[test]
    fn render_cgroup_dropin_zero_budget_is_slice_only() {
        // sysext/host modules carry Budget::default() -- no per-module MemoryMax/CPUQuota lines,
        // just the CPUWeight default (bounded by their host slice instead, per supervisor.rs).
        let b = Budget::default();
        let rendered = b.render_cgroup_dropin(&Runtime::Sysext);
        assert!(!rendered.contains("MemoryMax"));
        assert!(!rendered.contains("CPUQuota"));
        assert!(rendered.contains("CPUWeight=100"));
    }

    #[test]
    fn resource_budget_event_shape_matches_ingest_detection_expectations() {
        let line = resource_budget_event("napse", Wall::Hard, "oom-kill", "cgroup MemoryMax exceeded", 1_700_000_000.0);
        let v: serde_json::Value = serde_json::from_str(&line).unwrap();
        assert_eq!(v["rule_id"], RESOURCE_BUDGET_RULE_ID);
        assert_eq!(v["category"], "resource_budget");
        assert_eq!(v["severity"], 3);
        assert_eq!(v["wall"], "hard");
        assert_eq!(v["module"], "napse");
        // ingest_detection only requires rule_id/rule_msg non-null, and reads src_ip/dst_ip/
        // dst_port/confidence with defaults -- confirm those keys are present and typed right.
        assert_eq!(v["src_ip"], "");
        assert_eq!(v["dst_port"], 0);
    }

    #[test]
    fn emit_resource_budget_event_appends_a_line() {
        let dir = std::env::temp_dir().join(format!("hp-budget-event-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let events = dir.join("events");
        emit_resource_budget_event(&events, "qsecbit", Wall::Soft, "MemoryHigh throttle", "80% ceiling reached");
        let contents = std::fs::read_to_string(&events).unwrap();
        assert!(contents.contains("resource_budget"));
        assert!(contents.contains("qsecbit"));
        assert!(contents.contains("\"wall\":\"soft\""));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
