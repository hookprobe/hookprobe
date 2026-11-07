//! Supervisor / reconciler — level-triggered, idempotent module reconciliation.
//!
//! Mirrors `reconcile()` + `_try_load()` in `supervisor/reference/supervisor.py`.
//!
//! The "load" action here is a MOCK — the shipping supervisor (Rust) loads Wasm via
//! Wasmtime (epoch + StoreLimits) and containers via Podman/Quadlet, enforcing
//! budgets at the cgroup + Wasmtime layers. This reference proves the resolution logic.
//!
//! TODO: Wasmtime (epoch+StoreLimits) for wasm, Podman/Quadlet for container;
//!       enforce budgets at cgroup + Wasmtime layers.

use std::collections::{HashMap, HashSet};

use crate::module_def::ModuleDef;
use crate::types::{Budget, CapabilityState, Manifest, ModuleEntry, ModuleState, Runtime, SignatureStatus};

/// Result for a single module during reconciliation.
#[derive(Debug, Clone)]
pub struct ModuleOutcome {
    pub id: String,
    pub state: OutcomeState,
    pub detail: String,
}

#[derive(Debug, Clone, PartialEq)]
pub enum OutcomeState {
    Running,
    Refused,
    Deferred,
}

impl OutcomeState {
    pub fn as_str(&self) -> &'static str {
        match self {
            OutcomeState::Running => "running",
            OutcomeState::Refused => "refused",
            OutcomeState::Deferred => "deferred",
        }
    }

    pub fn sort_key(&self) -> u8 {
        match self {
            OutcomeState::Running => 0,
            OutcomeState::Refused => 1,
            OutcomeState::Deferred => 2,
        }
    }
}

/// Whether the module's signature is acceptable.
///
/// The supervisor binary performs cosign-style verification (over the module
/// artifact digest vs. the baked-in trust store) BEFORE reconcile and records the
/// result in `sig_verified`. `Some(true/false)` = the externally-computed verdict, always
/// honored. `None` = NOT externally checked — fail CLOSED: a module whose policy is
/// `signature: required` is refused (never silently trusted because verification was
/// skipped); only a module that does not require a signature may pass unchecked. The
/// enforcement decision thus comes from device policy (the module's required-ness +
/// the externally-computed verdict), not from a field the module artifact controls.
pub fn verify_signature(module: &ModuleDef) -> bool {
    match module.sig_verified {
        Some(verified) => verified,
        None => module.signature != "required",
    }
}

/// Reconcile a manifest against desired module definitions.
///
/// Level-triggered + idempotent: re-running on the same manifest with the same
/// modules is a no-op (already-running modules are detected and skipped).
///
/// Returns `(updated_manifest, per-module outcomes sorted by state then id)`.
pub fn reconcile(
    manifest: &mut Manifest,
    modules: &[ModuleDef],
) -> Vec<ModuleOutcome> {
    let caps = &manifest.capabilities;
    let alloc = &manifest.resources.allocatable;
    let defaults = &manifest.resources.defaults;

    // Granted capability set = capabilities state==granted from the manifest.
    let mut granted: HashSet<String> = caps
        .iter()
        .filter(|(_, c)| c.state == CapabilityState::Granted)
        .map(|(k, _)| k.clone())
        .collect();

    // Track remaining allocatable budget (mutable copy).
    let mut remaining_cpu = alloc.cpu_pct;
    let mut remaining_mem = alloc.memory_mb;

    // Already-running modules from the manifest (idempotency: these are no-ops).
    let mut running_ids: HashSet<String> = HashSet::new();
    let mut running_entries: Vec<ModuleEntry> = Vec::new();

    for entry in &manifest.modules {
        if entry.state.is_live() {
            // Deduct their budget from remaining.
            remaining_cpu = remaining_cpu.saturating_sub(entry.budget.cpu_pct);
            remaining_mem = remaining_mem.saturating_sub(entry.budget.memory_mb);
            running_ids.insert(entry.id.clone());
            running_entries.push(entry.clone());
        }
    }

    let mut report: Vec<ModuleOutcome> = running_ids
        .iter()
        .map(|id| ModuleOutcome {
            id: id.clone(),
            state: OutcomeState::Running,
            detail: "already running (no-op)".to_string(),
        })
        .collect();

    // Index desired modules by id.
    let desired: HashMap<String, &ModuleDef> =
        modules.iter().map(|m| (m.id.clone(), m)).collect();

    let mut decided: HashSet<String> = running_ids.clone();

    // Fixpoint loop: resolves provides->requires chains regardless of module order.
    let mut progress = true;
    while progress {
        progress = false;
        for (mid, mod_def) in &desired {
            if decided.contains(mid.as_str()) {
                continue;
            }
            let outcome = try_load(
                mod_def,
                caps,
                &granted,
                remaining_cpu,
                remaining_mem,
                defaults,
                false,
            );
            if outcome.state == OutcomeState::Deferred {
                continue; // may unblock after another module provides a capability
            }
            decided.insert(mid.clone());
            progress = true;
            if outcome.state == OutcomeState::Running {
                // Commit budget and provides.
                let budget = module_budget(mod_def, defaults);
                remaining_cpu = remaining_cpu.saturating_sub(budget.cpu_pct);
                remaining_mem = remaining_mem.saturating_sub(budget.memory_mb);
                for cap in &mod_def.provides.capabilities {
                    granted.insert(cap.clone());
                }
                running_entries.push(ModuleEntry {
                    id: mid.clone(),
                    version: mod_def.version.clone(),
                    runtime: mod_def.runtime.clone(),
                    state: ModuleState::Running,
                    budget,
                    signature: SignatureStatus::Verified,
                });
            }
            report.push(outcome);
        }
    }

    // Anything still undecided is genuinely blocked (circular or impossible).
    for (mid, mod_def) in &desired {
        if !decided.contains(mid.as_str()) {
            let outcome = try_load(
                mod_def,
                caps,
                &granted,
                remaining_cpu,
                remaining_mem,
                defaults,
                true, // final=true: no more deferral
            );
            report.push(outcome);
        }
    }

    // Update manifest.modules with the running set.
    manifest.modules = running_entries;

    // Mark signature stale (shipping supervisor re-signs here).
    manifest.signature.sig = "STALE-RESIGN-REQUIRED".to_string();

    // Sort report: running first, then refused, then deferred; alphabetically within.
    report.sort_by(|a, b| {
        a.state.sort_key().cmp(&b.state.sort_key())
            .then_with(|| a.id.cmp(&b.id))
    });

    report
}

/// Attempt to load a single module.
///
/// Returns `Deferred` if a required capability is not yet in the granted set but
/// may be provided by a later module (unless `final` is true).
fn try_load(
    mod_def: &ModuleDef,
    caps: &std::collections::HashMap<String, crate::types::Capability>,
    granted: &HashSet<String>,
    remaining_cpu: u64,
    remaining_mem: u64,
    defaults: &crate::types::Defaults,
    final_pass: bool,
) -> ModuleOutcome {
    let mid = &mod_def.id;

    // 1. Capability gate.
    let mut missing: Vec<String> = Vec::new();
    for cap_name in &mod_def.requires.capabilities {
        if granted.contains(cap_name.as_str()) {
            continue;
        }
        let info = caps.get(cap_name.as_str());
        if info.is_none() && !final_pass {
            return ModuleOutcome {
                id: mid.clone(),
                state: OutcomeState::Deferred,
                detail: format!("awaiting capability '{cap_name}'"),
            };
        }
        // Convert enum state to the snake_case schema value. Distinguish a KNOWN-but-absent
        // capability from an UNKNOWN token (a typo in `requires:` that names no real
        // capability) so a misspelled requirement is visibly flagged, not silently "absent".
        let state_str = cap_state_str(info);
        let reason = if info.is_none() {
            "UNKNOWN capability token — not a defined capability (typo in requires?)".to_string()
        } else {
            info.and_then(|c| c.reason.as_deref()).unwrap_or("not present").to_string()
        };
        missing.push(format!("{cap_name} (state={state_str}: {reason})"));
    }
    if !missing.is_empty() {
        return ModuleOutcome {
            id: mid.clone(),
            state: OutcomeState::Refused,
            detail: format!("unmet capabilities: {}", missing.join("; ")),
        };
    }

    // 2. Signature gate.
    if mod_def.signature == "required" && !verify_signature(mod_def) {
        return ModuleOutcome {
            id: mid.clone(),
            state: OutcomeState::Refused,
            detail: "signature required but not verified".to_string(),
        };
    }

    // 3. Budget: module's own resources or runtime default.
    let budget = module_budget(mod_def, defaults);

    if budget.memory_mb < mod_def.requires.min_memory_mb {
        return ModuleOutcome {
            id: mid.clone(),
            state: OutcomeState::Refused,
            detail: format!(
                "budget memory_mb={} < requires.min_memory_mb={}",
                budget.memory_mb, mod_def.requires.min_memory_mb
            ),
        };
    }

    // 4. Resource fit.
    if budget.cpu_pct > remaining_cpu {
        return ModuleOutcome {
            id: mid.clone(),
            state: OutcomeState::Refused,
            detail: format!(
                "insufficient cpu_pct: needs {}, {} allocatable left",
                budget.cpu_pct, remaining_cpu
            ),
        };
    }
    if budget.memory_mb > remaining_mem {
        return ModuleOutcome {
            id: mid.clone(),
            state: OutcomeState::Refused,
            detail: format!(
                "insufficient memory_mb: needs {}, {} allocatable left",
                budget.memory_mb, remaining_mem
            ),
        };
    }

    let provides = &mod_def.provides.capabilities;
    ModuleOutcome {
        id: mid.clone(),
        state: OutcomeState::Running,
        detail: format!(
            "loaded ({}, cpu={} mem={}MB)  provides={:?}",
            runtime_str(&mod_def.runtime),
            budget.cpu_pct,
            budget.memory_mb,
            provides,
        ),
    }
}

/// Resolve the effective budget for a module.
fn module_budget(mod_def: &ModuleDef, defaults: &crate::types::Defaults) -> Budget {
    if let Some(res) = &mod_def.resources {
        // Any declared field (not just the accounting cpu_pct/memory_mb pair) counts as "this
        // module set its own budget" -- e.g. a module that only overrides `fuel` or `mem_high_mb`
        // still gets the runtime default's cpu_pct/memory_mb layered in below it would otherwise
        // silently lose, so merge onto the runtime default rather than replacing wholesale.
        let declared = res.cpu_pct > 0
            || res.memory_mb > 0
            || res.mem_high_mb.is_some()
            || res.cpu_weight.is_some()
            || res.fuel.is_some();
        if declared {
            let base = match mod_def.runtime {
                Runtime::Wasm => defaults.wasm.clone(),
                Runtime::Container => defaults.container.clone(),
                Runtime::Sysext | Runtime::ImageLayer | Runtime::Host => Budget::default(),
            };
            return Budget {
                cpu_pct: if res.cpu_pct > 0 { res.cpu_pct } else { base.cpu_pct },
                memory_mb: if res.memory_mb > 0 { res.memory_mb } else { base.memory_mb },
                epoch_ms: res.epoch_ms.or(base.epoch_ms),
                mem_high_mb: res.mem_high_mb.or(base.mem_high_mb),
                cpu_weight: res.cpu_weight.or(base.cpu_weight),
                fuel: res.fuel.or(base.fuel),
            };
        }
    }
    match mod_def.runtime {
        Runtime::Wasm => defaults.wasm.clone(),
        Runtime::Container => defaults.container.clone(),
        // sysext + image-layer are host-integral (baked into the image / merged
        // at boot), bounded by a cgroup slice, not a Wasm fuel budget.
        // sysext/image-layer/host are host-integral (baked / merged / native helper), bounded by a
        // cgroup slice, not a Wasm fuel budget.
        Runtime::Sysext | Runtime::ImageLayer | Runtime::Host => Budget::default(),
    }
}

fn cap_state_str(info: Option<&crate::types::Capability>) -> &'static str {
    match info.map(|c| &c.state) {
        Some(CapabilityState::Granted) => "granted",
        Some(CapabilityState::PresentUnsafe) => "present_unsafe",
        Some(CapabilityState::PolicyDenied) => "policy_denied",
        Some(CapabilityState::Absent) | None => "absent",
    }
}

fn runtime_str(r: &Runtime) -> &'static str {
    match r {
        Runtime::Wasm => "wasm",
        Runtime::Container => "container",
        Runtime::Sysext => "sysext",
        Runtime::ImageLayer => "image-layer",
        Runtime::Host => "host",
    }
}
