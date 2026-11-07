//! Capability mapper — grant = presence ∧ known-good ∧ policy (Architecture.md C6).
//!
//! Mirrors `map_capabilities()` + helpers in `bootstrap/reference/generate_manifest.py`.
//!
//! Resulting state ∈ granted | present_unsafe | policy_denied | absent.

use std::collections::{HashMap, HashSet};

use crate::platform::{CapabilityPolicy, PlatformSpec};
use crate::scan::HardwareScan;
use crate::types::{Capability, CapabilityState, InterfaceRole, InterfaceType};

/// Friendly absence reasons for well-known requirement expressions that need NO scan
/// context. `npu.driver_ready` is deliberately NOT here — it is scan-dependent (see
/// `absent_reason`): "no NPU present" and "NPU present but driver not loaded" are two
/// different, honest facts and must not be collapsed into one misleading string.
fn friendly_absent(expr: &str) -> Option<&'static str> {
    match expr {
        "wifi.present" => Some("no Wi-Fi radio present"),
        "network.role:inline" => Some("no interface assigned an inline role"),
        _ => None,
    }
}

/// Human-readable absence reason for numeric/count/feature requirements that need the scan.
fn absent_reason(expr: &str, scan: &HardwareScan) -> String {
    if expr == "network.interfaces>=2" {
        return format!(
            "requires >=2 network interfaces; {} present",
            scan.interfaces.len()
        );
    }
    if expr == "memory_mb>=8192" {
        return format!("requires >=8192 MB; {} present", scan.memory_mb);
    }
    // HONESTY (per the project's no-fabricated-capabilities discipline): distinguish
    // "no accelerator silicon at all" from "silicon IS present but its kernel driver is
    // not loaded, so the edge_ai runtime (WASI-NN NPU backend) is unreachable". Reporting
    // "no NPU present" on an RK3588 that HAS a 6-TOPS NPU but is missing the rknpu driver
    // would be a fabricated fact. The grant stays correctly withheld either way; only the
    // reason becomes truthful and actionable (vendor the driver -> capability lights up).
    if expr == "npu.driver_ready" {
        return if scan.npu.present {
            "NPU present but its driver is not loaded — edge_ai runtime unreachable; vendor the accelerator driver in the image".to_string()
        } else {
            "no NPU/accelerator present".to_string()
        };
    }
    // `ptp_hw` (base-tier-build-ticket.md Phase 3, ADR 0031 §B): a real per-board fact from
    // `ethtool -T <iface>` (bootstrap's `probe::ethtool_hw_timestamping`), not a platform-class
    // guess — so, like `npu.driver_ready` above, the honest reason distinguishes "no wired
    // ethernet interface scanned at all" from "interface(s) scanned but none confirmed hardware
    // rx/tx timestamping + a bound PHC".
    if expr == "network.hw_timestamping" {
        let eth = scan
            .interfaces
            .iter()
            .filter(|i| i.iface_type == InterfaceType::Ethernet)
            .count();
        return if eth == 0 {
            "no wired ethernet interface scanned — hardware PTP timestamping requires one".to_string()
        } else {
            format!(
                "ethtool -T reports no hardware rx/tx timestamping + bound PHC on any of {eth} ethernet interface(s)"
            )
        };
    }
    format!("requires not met: {expr}")
}

/// Negative evidence string for a failing requirement.
fn neg_evidence(expr: &str, scan: &HardwareScan) -> String {
    match expr {
        "network.interfaces>=2" => format!("network.interfaces=={}", scan.interfaces.len()),
        "wifi.present" => "wifi.present=false".to_string(),
        "npu.driver_ready" => {
            if !scan.npu.present {
                "npu.present=false".to_string()
            } else {
                "npu.driver_ready=false".to_string()
            }
        }
        "network.role:inline" => "network.interfaces:no-inline".to_string(),
        "network.hw_timestamping" => "hw_timestamping=false (all scanned interfaces)".to_string(),
        _ => expr.to_string(),
    }
}

/// Evaluate a single requirement expression against the scan and already-granted caps.
fn eval_requirement(expr: &str, scan: &HardwareScan, cap_tokens: &HashSet<String>, granted: &HashMap<String, CapabilityState>) -> bool {
    // capability dependency
    if cap_tokens.contains(expr) {
        return granted.get(expr) == Some(&CapabilityState::Granted);
    }
    // base fact presence
    match expr {
        "cpu" | "memory_mb" | "arch" => return true, // always present in a valid scan
        _ => {}
    }
    // threshold comparisons
    if let Some(idx) = expr.find(">=") {
        let left = &expr[..idx];
        let num: u64 = expr[idx + 2..].parse().unwrap_or(0);
        return match left {
            "memory_mb" => scan.memory_mb >= num,
            "network.interfaces" => scan.interfaces.len() as u64 >= num,
            _ => false,
        };
    }
    // feature flags
    match expr {
        "wifi.present" => scan.wifi.present,
        "npu.driver_ready" => scan.npu.driver_ready,
        "network.role:inline" => scan.interfaces.iter().any(|i| i.role == InterfaceRole::Inline),
        // `ptp_hw`'s real fact (base-tier-build-ticket.md Phase 3, ADR 0031 §B) — see
        // `absent_reason`/`neg_evidence` above for the honest withheld-reason wiring, and
        // `bootstrap::probe::ethtool_hw_timestamping` for how this bool is actually measured.
        "network.hw_timestamping" => scan.interfaces.iter().any(|i| i.hw_timestamping),
        _ => false,
    }
}

/// Find the first inline interface in the scan.
fn inline_iface(scan: &HardwareScan) -> Option<&crate::scan::ScanInterface> {
    scan.interfaces.iter().find(|i| i.role == InterfaceRole::Inline)
}

/// Compute state for a single capability token.
///
/// `cpu_tier` is `PlatformSpec::cpu_tier` verbatim (e.g. `Some("cortex-a76")` for rpi5/
/// rk3588, `None` for the A72 baseline/rpi4) — the SAME build-time fact
/// `builder/refresh-aot.sh --with-a76` already uses to pick the `<id>.a76.cwasm` AOT blob,
/// reused here for the `ml_cpu` known-good gate (base-tier-build-ticket.md Phase 4) instead
/// of inventing a second probe.
fn compute_one(
    token: &str,
    pol: &CapabilityPolicy,
    scan: &HardwareScan,
    cap_tokens: &HashSet<String>,
    granted: &HashMap<String, CapabilityState>,
    cpu_tier: Option<&str>,
) -> Capability {
    // Step 1: evaluate requirements
    let failed: Vec<&str> = pol
        .requires
        .iter()
        .filter(|r| !eval_requirement(r, scan, cap_tokens, granted))
        .map(|r| r.as_str())
        .collect();

    if !failed.is_empty() {
        let first = failed[0];
        let reason = friendly_absent(first)
            .map(|s| s.to_string())
            .unwrap_or_else(|| absent_reason(first, scan));
        return Capability {
            state: CapabilityState::Absent,
            reason: Some(reason),
            evidence: vec![neg_evidence(first, scan)],
        };
    }

    // Step 2: known-good check (currently: NIC driver for inline_ips)
    if token == "inline_ips" {
        let iface = inline_iface(scan);
        let drv = iface.and_then(|i| i.driver.as_deref());
        let known_good = drv
            .map(|d| pol.known_good_nic_drivers.iter().any(|k| k == d))
            .unwrap_or(false);
        if !known_good {
            let iface_name = iface.map(|i| i.name.as_str()).unwrap_or("unknown");
            let kg_reason = format!(
                "NIC offload (TSO/LRO) not on known-good list for driver '{}'",
                drv.unwrap_or("unknown")
            );
            return Capability {
                state: CapabilityState::PresentUnsafe,
                reason: Some(kg_reason),
                evidence: vec![format!("network.role:inline:{iface_name}")],
            };
        }
    }

    // Step 2b: known-good check for `ml_cpu` (base-tier-build-ticket.md Phase 4, ADR 0014 D6).
    // The dga-lm int8 DGA classifier's SDOT-accelerated fast path is only verified to hold the
    // 50 ms QSECBIT epoch budget on Cortex-A76-class silicon (`+dotprod`, ARMv8.2) — exactly
    // the platforms that declare `cpu_tier: cortex-a76` in their `platforms/*.yaml` (rpi5,
    // rk3588). On the A72 baseline (`cpu_tier` absent, e.g. rpi4/CM4) the widening-NEON
    // fallback has NOT been measured to hold the epoch on real silicon (no on-device epoch
    // benchmark exists yet — telemetry-analyst TODO), so the grant is deliberately SCOPED, not
    // global: `present_unsafe`, never a fabricated `granted`. dga-lm still ships and scores
    // there; QSECBIT just doesn't trust the number — `p_attack` stays 0.0 on that tier (wired
    // in modules/qsecbit).
    if token == "ml_cpu" && cpu_tier != Some("cortex-a76") {
        return Capability {
            state: CapabilityState::PresentUnsafe,
            reason: Some(
                "dga-lm int8 SDOT fast path not verified within the 50ms QSECBIT epoch on this \
                 CPU tier (no cortex-a76/+dotprod) — scoped per ADR 0014 D6; p_attack stays 0.0 here"
                    .to_string(),
            ),
            evidence: vec![format!(
                "cpu_tier:{}",
                cpu_tier.unwrap_or("baseline (no dotprod)")
            )],
        };
    }

    // `ptp_hw` (base-tier-build-ticket.md Phase 3, ADR 0031 §B) no longer has a special-cased
    // "always present_unsafe" arm here: it is now wired through the SAME requirement-grammar
    // Step 1 above uses `npu.driver_ready` for `edge_ai` — declared as `requires:
    // ["network.hw_timestamping"]` in platforms/{rpi4,rpi5,rk3588}.yaml, evaluated by
    // `eval_requirement`'s `"network.hw_timestamping"` arm (reads the REAL per-interface
    // `ScanInterface::hw_timestamping` fact, itself populated by `ethtool -T <iface>` in
    // `bootstrap::probe::ethtool_hw_timestamping` — Phase-0 §5's exact metal gate: hardware
    // rx/tx timestamping + a bound PHC index). Absent from Step 1 above ⇒ `Absent` with an
    // honest reason; present ⇒ falls through to policy + Granted below, same as any other
    // fact-gated token. No fabricated proxy, no static platform-class constant.

    // Step 3: policy gate
    if pol.policy != "enabled" {
        return Capability {
            state: CapabilityState::PolicyDenied,
            reason: Some(format!(
                "withheld on '{}' platform class by policy",
                "this"  // class is set by the caller; generic.rs uses the profile class
            )),
            evidence: pol.requires.clone(),
        };
    }

    // Granted
    let mut evidence: Vec<String> = pol.requires.clone();
    if token == "inline_ips" {
        let drv = inline_iface(scan).and_then(|i| i.driver.as_deref()).unwrap_or("unknown");
        evidence.push(format!("nic:{drv} known-good"));
    }
    if token == "ml_cpu" {
        evidence.push("cpu_tier:cortex-a76 (+dotprod, --with-a76 AOT blob eligible)".to_string());
    }
    if token == "ptp_hw" {
        let iface = scan
            .interfaces
            .iter()
            .find(|i| i.hw_timestamping)
            .map(|i| i.name.as_str())
            .unwrap_or("unknown");
        evidence.push(format!(
            "iface:{iface}:hw_timestamping=true (ethtool -T: hardware rx/tx timestamping + bound PHC)"
        ));
    }
    Capability {
        state: CapabilityState::Granted,
        reason: None,
        evidence,
    }
}

/// Map platform capability policies + scan facts -> manifest capabilities.
///
/// Uses a fixpoint loop so that `ids -> soc` (or any deeper) dep chains
/// resolve regardless of the order capabilities appear in the YAML.
pub fn map_capabilities(
    scan: &HardwareScan,
    platform: &PlatformSpec,
) -> HashMap<String, Capability> {
    let cap_tokens: HashSet<String> = platform.capabilities.keys().cloned().collect();
    let mut granted: HashMap<String, CapabilityState> = HashMap::new();
    let mut caps_out: HashMap<String, Capability> = HashMap::new();
    let cpu_tier = platform.cpu_tier.as_deref();

    // Build a work-list of (token, policy) pairs.
    let mut remaining: Vec<(&str, &CapabilityPolicy)> = platform
        .capabilities
        .iter()
        .map(|(k, v)| (k.as_str(), v))
        .collect();

    let mut progress = true;
    while progress && !remaining.is_empty() {
        progress = false;
        let mut deferred = Vec::new();
        for (token, pol) in remaining {
            // Check if any capability-token requirement is not yet resolved.
            let has_unresolved = pol
                .requires
                .iter()
                .filter(|r| cap_tokens.contains(r.as_str()))
                .any(|r| !granted.contains_key(r.as_str()));
            if has_unresolved {
                deferred.push((token, pol));
                continue;
            }
            let cap = compute_one(token, pol, scan, &cap_tokens, &granted, cpu_tier);
            granted.insert(token.to_string(), cap.state.clone());
            caps_out.insert(token.to_string(), cap);
            progress = true;
        }
        remaining = deferred;
    }
    // Any remaining (impossible cycle in practice): resolve with what we have.
    for (token, pol) in remaining {
        let cap = compute_one(token, pol, scan, &cap_tokens, &granted, cpu_tier);
        granted.insert(token.to_string(), cap.state.clone());
        caps_out.insert(token.to_string(), cap);
    }

    // Patch the policy_denied reason with the actual platform class.
    for cap in caps_out.values_mut() {
        if cap.state == CapabilityState::PolicyDenied {
            cap.reason = Some(format!(
                "withheld on '{}' platform class by policy",
                platform.class
            ));
        }
    }

    caps_out
}
