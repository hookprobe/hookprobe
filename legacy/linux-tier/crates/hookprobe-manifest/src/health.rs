//! Post-reconcile health: self-test → bounded heal → graceful shed, plus
//! commit-confirmed (verify-after-apply) for data-plane modules.
//!
//! Runs AFTER `reconcile()` (which gates on capabilities + budget). This phase
//! confirms each loaded module actually WORKS, heals transient failures with
//! bounded retries, sheds anything that stays broken (the box degrades, never
//! bricks), and for data-plane modules verifies the management path survived —
//! auto-reverting if not, so a reconcile can never lock the operator out.
//!
//! Reset discipline (see docs/architecture/OS-platform-report.md §A): this phase only sheds
//! ephemeral module state. It never touches the device identity or the data
//! partition — those survive heal and rollback; only a deliberate factory reset
//! wipes data.

use std::collections::HashMap;
use std::path::Path;

use crate::module_def::ModuleDef;
use crate::resource_budget::{emit_resource_budget_event, Wall};
use crate::types::{Manifest, ModuleEntry, Runtime};

/// Pluggable health backend. The shipping supervisor probes the live module and
/// queries connectivity; tests/CLI inject deterministic outcomes.
pub trait HealthProbe {
    /// Self-test a loaded module. `Ok(())` = healthy; `Err(reason)` = unhealthy.
    fn self_test(&mut self, id: &str, runtime: &Runtime) -> Result<(), String>;
    /// After a DATA-PLANE module is applied, confirm the management path still
    /// works. `Ok(())` = connectivity preserved; `Err(reason)` = lost → revert.
    fn verify_connectivity(&mut self, after_id: &str) -> Result<(), String>;
    /// Resource-budget check (the "two resource walls" graceful-degradation hook, resource-
    /// budgets feature) — did this module breach its budget since the last check? `Ok(())` = within
    /// budget. `Err(reason)` = a HARD-wall breach was observed: cgroup OOM-kill (`MemoryMax`),
    /// Wasm fuel exhaustion, or any other enforcement-layer kill signal the shipping probe wires
    /// up (`systemctl show <unit> --property=Result` reporting `oom-kill`, or a `ResourceBudget`
    /// event this module's own run already appended to the events file — see
    /// `wasm_loader::run_wasi_module_streaming`). Default: always healthy (no resource signal
    /// available) — a NON-BREAKING addition so existing `HealthProbe` implementors (tests, the
    /// reference CLI's `DemoProbe`) that predate this feature keep compiling unchanged.
    fn check_resource_budget(&mut self, _id: &str, _runtime: &Runtime) -> Result<(), String> {
        Ok(())
    }
}

/// Bounded-heal policy. `max_attempts` includes the first try.
#[derive(Debug, Clone, Copy)]
pub struct HealthPolicy {
    pub max_attempts: u32,
}
impl Default for HealthPolicy {
    fn default() -> Self {
        Self { max_attempts: 3 }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum HealthState {
    Healthy,
    Healed,
    Failed,
    Reverted,
}
impl HealthState {
    pub fn as_str(&self) -> &'static str {
        match self {
            HealthState::Healthy => "healthy",
            HealthState::Healed => "healed",
            HealthState::Failed => "failed",
            HealthState::Reverted => "reverted",
        }
    }
}

#[derive(Debug, Clone)]
pub struct HealthOutcome {
    pub id: String,
    pub state: HealthState,
    pub attempts: u32,
    pub detail: String,
}

/// A module touches the network path (so it needs a commit-confirmed apply).
fn is_data_plane(provides: &[String], runtime: &Runtime) -> bool {
    matches!(runtime, Runtime::Sysext | Runtime::ImageLayer)
        || provides.iter().any(|p| {
            matches!(
                p.as_str(),
                "sdn" | "flows" | "packets" | "inline_ips" | "firewall" | "segmentation"
            )
        })
}

/// Run the health phase over the currently-running modules in `manifest.modules`.
/// Sheds failed/reverted modules from the manifest (graceful degradation) and
/// returns a per-module outcome list. Healthy modules are a no-op (idempotent).
///
/// `events_path`, when given, gets one `ResourceBudget` evidence-graph line appended (same
/// `detections` shape/conventions as `module_sig`'s `ArtifactTamper`) whenever a module is shed
/// because it breached its resource budget — queryable the same way any other detection is
/// (resource-budgets feature; see `crate::resource_budget`). `None` (e.g. tests, `--fleet`-only
/// invocations with no events sink configured) silently skips emission — never a hard error, same
/// best-effort discipline `module_sig::emit_artifact_tamper` already uses.
pub fn run_health<P: HealthProbe>(
    manifest: &mut Manifest,
    modules: &[ModuleDef],
    policy: HealthPolicy,
    probe: &mut P,
    events_path: Option<&Path>,
) -> Vec<HealthOutcome> {
    let provides_of: HashMap<&str, &[String]> = modules
        .iter()
        .map(|m| (m.id.as_str(), m.provides.capabilities.as_slice()))
        .collect();

    let mut survivors: Vec<ModuleEntry> = Vec::new();
    let mut outcomes: Vec<HealthOutcome> = Vec::new();

    for entry in manifest.modules.clone() {
        // --- self-test + resource-budget check, with bounded heal (restart-with-backoff; exp
        //     backoff would sleep 2^attempt * base here in the shipping impl) sharing ONE budget
        //     of attempts — a module that keeps tripping its resource budget gets the SAME
        //     bounded-retry-then-shed treatment as one that keeps failing its self-test, so there
        //     is no second, parallel degrade path to keep in sync with this one. ---
        let mut attempts = 0u32;
        let mut healthy = false;
        let mut last = String::new();
        let mut budget_breach = false;
        while attempts < policy.max_attempts {
            attempts += 1;
            match probe.self_test(&entry.id, &entry.runtime) {
                Ok(()) => match probe.check_resource_budget(&entry.id, &entry.runtime) {
                    Ok(()) => {
                        healthy = true;
                        budget_breach = false;
                        break;
                    }
                    Err(e) => {
                        last = e;
                        budget_breach = true;
                    }
                },
                Err(e) => {
                    last = e;
                    budget_breach = false;
                }
            }
        }
        if !healthy {
            let detail = if budget_breach {
                format!(
                    "resource budget exceeded after {attempts} attempts ({last}) — shed; box stays up"
                )
            } else {
                format!(
                    "self-test failed after {attempts} attempts ({last}) — shed; box stays up"
                )
            };
            if budget_breach {
                if let Some(ep) = events_path {
                    emit_resource_budget_event(
                        ep,
                        &entry.id,
                        Wall::Hard,
                        "repeated resource-budget breach",
                        &format!("shed after {attempts} bounded restart-with-backoff attempts: {last}"),
                    );
                }
            }
            outcomes.push(HealthOutcome {
                id: entry.id.clone(),
                state: HealthState::Failed,
                attempts,
                detail,
            });
            continue; // shed: not a survivor
        }

        // --- commit-confirmed for data-plane modules ---
        let provides = provides_of.get(entry.id.as_str()).copied().unwrap_or(&[]);
        if is_data_plane(provides, &entry.runtime) {
            if let Err(e) = probe.verify_connectivity(&entry.id) {
                outcomes.push(HealthOutcome {
                    id: entry.id.clone(),
                    state: HealthState::Reverted,
                    attempts,
                    detail: format!(
                        "data-plane verify failed ({e}) — auto-reverted to preserve the management path"
                    ),
                });
                continue; // revert == shed the change
            }
        }

        let healed = attempts > 1;
        outcomes.push(HealthOutcome {
            id: entry.id.clone(),
            state: if healed {
                HealthState::Healed
            } else {
                HealthState::Healthy
            },
            attempts,
            detail: if healed {
                format!("recovered after {attempts} attempts")
            } else {
                "self-test ok".to_string()
            },
        });
        survivors.push(entry);
    }

    manifest.modules = survivors;
    outcomes.sort_by(|a, b| a.id.cmp(&b.id));
    outcomes
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::builder::build_manifest;
    use crate::scan::ScanProfile;
    use crate::types::{Budget, ModuleState, SignatureStatus};

    const N100_FIXTURE: &str = include_str!("../../../manifest/fixtures/n100.profile.json");

    /// A minimal-but-real Manifest (built the SAME way `aegis.rs`'s tests do) with one
    /// already-`running` module entry — everything `run_health` actually reads.
    fn manifest_with_one_running_module(id: &str) -> Manifest {
        let scan = serde_json::from_str::<ScanProfile>(N100_FIXTURE).expect("fixture").scan;
        let platforms = crate::load_platforms(std::path::Path::new(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../platforms"
        )))
        .expect("platforms");
        let (platform, mi) = crate::classify(&scan, &platforms).expect("classify");
        let mut m = build_manifest(&scan, platform, &mi, "2026-01-01T00:00:00Z", "img", "sha256:0")
            .expect("manifest");
        m.modules = vec![ModuleEntry {
            id: id.to_string(),
            version: "1.0.0".to_string(),
            runtime: Runtime::Wasm,
            state: ModuleState::Running,
            budget: Budget { cpu_pct: 25, memory_mb: 128, ..Budget::default() },
            signature: SignatureStatus::Verified,
        }];
        m
    }

    /// A probe whose resource-budget check ALWAYS breaches for the named module(s) — models a
    /// module wedged in a cgroup-OOM-kill / fuel-exhaustion restart loop.
    struct BudgetBreachProbe {
        breach: Vec<String>,
        self_test_calls: u32,
        budget_calls: u32,
    }
    impl HealthProbe for BudgetBreachProbe {
        fn self_test(&mut self, _id: &str, _rt: &Runtime) -> Result<(), String> {
            self.self_test_calls += 1;
            Ok(())
        }
        fn verify_connectivity(&mut self, _after_id: &str) -> Result<(), String> {
            Ok(())
        }
        fn check_resource_budget(&mut self, id: &str, _rt: &Runtime) -> Result<(), String> {
            self.budget_calls += 1;
            if self.breach.iter().any(|x| x == id) {
                Err("cgroup MemoryMax exceeded (oom-kill)".to_string())
            } else {
                Ok(())
            }
        }
    }

    /// (a)/(c) task proof: a module that repeatedly breaches its resource budget is retried
    /// bounded-times (restart-with-backoff — the SAME attempts loop self-test failures use), then
    /// SHED (graceful degradation, not a crash), a `ResourceBudget` event is appended to the
    /// events file, and the health verdict surfaces "resource budget exceeded" in its detail.
    #[test]
    fn repeated_budget_breach_is_bounded_retried_then_shed_and_emits_event() {
        let mut manifest = manifest_with_one_running_module("napse");
        let modules: Vec<ModuleDef> = Vec::new();
        let policy = HealthPolicy { max_attempts: 3 };
        let mut probe = BudgetBreachProbe { breach: vec!["napse".to_string()], self_test_calls: 0, budget_calls: 0 };

        let dir = std::env::temp_dir().join(format!("hp-health-budget-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let events = dir.join("events");

        let outcomes = run_health(&mut manifest, &modules, policy, &mut probe, Some(&events));

        assert_eq!(outcomes.len(), 1);
        assert_eq!(outcomes[0].state, HealthState::Failed);
        assert!(outcomes[0].detail.contains("resource budget exceeded"), "got: {}", outcomes[0].detail);
        assert_eq!(outcomes[0].attempts, 3, "bounded restart-with-backoff must exhaust policy.max_attempts");
        assert_eq!(probe.self_test_calls, 3, "each bounded attempt re-tries self-test too");
        assert_eq!(probe.budget_calls, 3);
        assert!(manifest.modules.is_empty(), "the box degrades gracefully -- the breaching module is shed, not crashed");

        let contents = std::fs::read_to_string(&events).expect("ResourceBudget event must be appended");
        assert!(contents.contains("resource_budget"), "got: {contents}");
        assert!(contents.contains("\"wall\":\"hard\""), "got: {contents}");
        assert!(contents.contains("napse"), "got: {contents}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A module that breaches once then recovers (models a transient MemoryHigh throttle that
    /// clears) is HEALED, not shed — proves the bounded-heal path (not just bounded-shed) applies
    /// to resource-budget breaches exactly like it already does to self-test failures.
    #[test]
    fn transient_budget_breach_then_recovery_is_healed_not_shed() {
        struct FlakyBudgetProbe {
            calls: std::collections::HashMap<String, u32>,
        }
        impl HealthProbe for FlakyBudgetProbe {
            fn self_test(&mut self, _id: &str, _rt: &Runtime) -> Result<(), String> {
                Ok(())
            }
            fn verify_connectivity(&mut self, _after_id: &str) -> Result<(), String> {
                Ok(())
            }
            fn check_resource_budget(&mut self, id: &str, _rt: &Runtime) -> Result<(), String> {
                let n = self.calls.entry(id.to_string()).or_insert(0);
                *n += 1;
                if *n == 1 {
                    Err("MemoryHigh throttle (transient)".to_string())
                } else {
                    Ok(())
                }
            }
        }
        let mut manifest = manifest_with_one_running_module("qsecbit");
        let modules: Vec<ModuleDef> = Vec::new();
        let mut probe = FlakyBudgetProbe { calls: Default::default() };

        let outcomes = run_health(&mut manifest, &modules, HealthPolicy::default(), &mut probe, None);
        assert_eq!(outcomes.len(), 1);
        assert_eq!(outcomes[0].state, HealthState::Healed);
        assert_eq!(manifest.modules.len(), 1, "a recovered module survives -- not shed");
    }

    /// No resource-budget breach at all (the default `HealthProbe::check_resource_budget` impl,
    /// and any probe that just returns `Ok`) -- pre-existing self-test-only behavior is UNCHANGED.
    #[test]
    fn no_budget_breach_is_a_no_op_healthy() {
        struct AlwaysHealthy;
        impl HealthProbe for AlwaysHealthy {
            fn self_test(&mut self, _id: &str, _rt: &Runtime) -> Result<(), String> {
                Ok(())
            }
            fn verify_connectivity(&mut self, _after_id: &str) -> Result<(), String> {
                Ok(())
            }
            // uses the trait default check_resource_budget (always Ok) -- proves the additive
            // trait method needs no implementor changes to keep working.
        }
        let mut manifest = manifest_with_one_running_module("dnsxai");
        let modules: Vec<ModuleDef> = Vec::new();
        let mut probe = AlwaysHealthy;
        let outcomes = run_health(&mut manifest, &modules, HealthPolicy::default(), &mut probe, None);
        assert_eq!(outcomes.len(), 1);
        assert_eq!(outcomes[0].state, HealthState::Healthy);
        assert_eq!(manifest.modules.len(), 1);
    }
}
