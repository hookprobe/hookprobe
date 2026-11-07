//! Continuous trust — segment membership is NOT decided once at join time. A device
//! that authenticated cleanly can later be compromised; this module re-evaluates it
//! against a live posture signal (the QSECBIT resilience/risk score + a HYDRA threat
//! verdict) and, when warranted, **dynamically re-segments it to quarantine** — emitting
//! the move as a high-priority override flow (the AEGIS plan-as-diff). This closes the
//! loop between segmentation and the detection plane (Senzorium → HYDRA → QSECBIT).
//!
//! The override is a single OpenFlow rule at a priority ABOVE the device's normal
//! segment binding, so quarantine takes effect immediately and reverts cleanly when the
//! posture clears — no teardown of the underlying segmentation.

use crate::multi_wan::GeneratedFile;
use hookprobe_mgmt_guard::{protect_reason, ProtectPolicy};

/// HYDRA threat verdict for a device.
#[derive(Debug, Clone, Copy, PartialEq, serde::Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum ThreatLevel {
    #[default]
    None,
    Suspicious,
    Malicious,
}

/// Where a posture signal came from — used by the enforcement gate to decide whether it may
/// quarantine on its own. **Finding-1 (2026-07-10):** a HYDRA threat-intel match is a much
/// weaker, more spoofable/false-positive-prone basis for quarantine than a completed-handshake
/// port scan or a durable identity block. This tag lets the reconciler require independent
/// corroboration before an intel-only signal quarantines a customer, WITHOUT touching the
/// confirmed paths (scan-responder, blocked_macs) — those keep the `Direct` default and behave
/// exactly as before.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub enum SignalProvenance {
    /// A directly-confirmed signal: a completed-handshake port scan (`scan_responder::decide`), a
    /// durable `blocked_macs` identity block, or a QSECBIT resilience-score-derived risk. May
    /// quarantine on its own — this is the default so every existing producer is unchanged.
    #[default]
    Direct,
    /// A HYDRA threat-intel indicator match. Must be independently CORROBORATED (see
    /// `PostureSignal::corroborated`) before it may quarantine; uncorroborated, it can at most
    /// step-up/document — mirroring the scan-responder's "confirmed handshake" requirement.
    IntelOnly,
}

/// A live posture signal for one device (emitted by QSECBIT/HYDRA).
#[derive(Debug, Clone, serde::Deserialize)]
pub struct PostureSignal {
    pub mac: String,
    /// The segment the device is currently in (from AEGIS auto-segmentation).
    pub current_segment: String,
    /// Risk score 0–100 (higher = worse). Derived from the QSECBIT resilience score and
    /// per-device anomaly. ≥ the policy threshold → quarantine.
    #[serde(default)]
    pub risk: f64,
    #[serde(default)]
    pub threat: ThreatLevel,
    #[serde(default)]
    pub reasons: Vec<String>,
    /// Provenance of this signal (Finding-1). Defaults to `Direct` (serde default) so existing
    /// producers and stored posture JSON are unaffected; a HYDRA-sourced bridge sets `IntelOnly`.
    #[serde(default)]
    pub provenance: SignalProvenance,
    /// True when an `IntelOnly` signal has been independently corroborated (≥ N distinct signals,
    /// or an IOC hit plus a beaconing/QSECBIT-anomaly signal — see `hookprobe_hydra::verdict`).
    /// Required before an `IntelOnly` signal may quarantine. Ignored for `Direct` signals.
    #[serde(default)]
    pub corroborated: bool,
}

/// What continuous trust decides to do.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum TrustAction {
    /// Posture is fine — leave the device in its segment.
    Keep,
    /// Borderline — keep but force re-authentication / step-up (suspicious, not malicious).
    StepUp,
    /// Re-segment the device to quarantine immediately.
    Quarantine,
}
impl TrustAction {
    pub fn as_str(&self) -> &'static str {
        match self {
            TrustAction::Keep => "keep",
            TrustAction::StepUp => "step-up",
            TrustAction::Quarantine => "quarantine",
        }
    }
}

/// Continuous-trust policy.
#[derive(Debug, Clone, serde::Deserialize)]
#[serde(default)]
pub struct TrustPolicy {
    /// Risk score at/above which a device is quarantined (0–100). Default 70.
    pub risk_threshold: f64,
    /// Risk score at/above which a device is stepped up (re-auth). Default 40.
    pub stepup_threshold: f64,
    pub quarantine_segment: String,
    pub quarantine_vlan: u32,
    /// Finding-1 (2026-07-10): when true (default), an `IntelOnly` (HYDRA threat-intel) signal
    /// that has NOT been independently corroborated can never quarantine — it is capped at
    /// step-up/document. Set false only to restore the old "any malicious verdict quarantines"
    /// behavior (config is policy). Never affects `Direct` signals (scan/blocked/QSECBIT).
    pub intel_requires_corroboration: bool,
}
impl Default for TrustPolicy {
    fn default() -> Self {
        TrustPolicy {
            risk_threshold: 70.0,
            stepup_threshold: 40.0,
            quarantine_segment: "quarantine".to_string(),
            quarantine_vlan: 666,
            intel_requires_corroboration: true,
        }
    }
}
impl TrustPolicy {
    pub fn parse(yaml: &str) -> anyhow::Result<TrustPolicy> {
        Ok(serde_yaml::from_str(yaml)?)
    }
}

/// One continuous-trust decision (the re-segmentation diff, or a no-op).
#[derive(Debug, Clone)]
pub struct TrustDecision {
    pub mac: String,
    pub action: TrustAction,
    pub from_segment: String,
    pub to_segment: String,
    pub reason: String,
}

/// Evaluate one device's posture against the policy. Malicious OR risk ≥ threshold →
/// quarantine; suspicious OR risk ≥ stepup → step-up; otherwise keep.
pub fn evaluate(p: &PostureSignal, policy: &TrustPolicy) -> TrustDecision {
    // The base verdict from threat/risk alone.
    let would_quarantine = p.threat == ThreatLevel::Malicious || p.risk >= policy.risk_threshold;
    // Finding-1 enforcement gate: a threat-intel-only signal that has NOT been independently
    // corroborated must never quarantine a device — it can at most step-up/document. This mirrors
    // the scan-responder's completed-handshake "confirmed" requirement one layer up, and closes
    // the defect where a single HYDRA IOC-IP hit (e.g. a customer phone touching a shared/CGNAT/
    // cloud IP that was ever an indicator) re-segmented a legitimate customer within one cycle.
    // Confirmed/durable signals (`Direct`) are unaffected.
    let intel_blocked = policy.intel_requires_corroboration
        && p.provenance == SignalProvenance::IntelOnly
        && !p.corroborated;

    let (action, to, reason) = if would_quarantine && !intel_blocked {
        (
            TrustAction::Quarantine,
            policy.quarantine_segment.clone(),
            format!(
                "threat={} risk={:.0} ≥ {:.0} → re-segment to quarantine{}",
                threat_str(p.threat), p.risk, policy.risk_threshold,
                fmt_reasons(&p.reasons)
            ),
        )
    } else if would_quarantine && intel_blocked {
        (
            TrustAction::StepUp,
            p.current_segment.clone(),
            format!(
                "threat={} risk={:.0} but intel-only + UNCORROBORATED → NOT quarantined                  (documented + step-up; corroboration required to quarantine){}",
                threat_str(p.threat), p.risk, fmt_reasons(&p.reasons)
            ),
        )
    } else if p.threat == ThreatLevel::Suspicious || p.risk >= policy.stepup_threshold {
        (
            TrustAction::StepUp,
            p.current_segment.clone(),
            format!("threat={} risk={:.0} ≥ {:.0} → step-up (force re-auth), keep segment{}",
                threat_str(p.threat), p.risk, policy.stepup_threshold, fmt_reasons(&p.reasons)),
        )
    } else {
        (TrustAction::Keep, p.current_segment.clone(), "posture clean → keep".to_string())
    };
    TrustDecision { mac: p.mac.clone(), action, from_segment: p.current_segment.clone(), to_segment: to, reason }
}

fn threat_str(t: ThreatLevel) -> &'static str {
    match t {
        ThreatLevel::None => "none",
        ThreatLevel::Suspicious => "suspicious",
        ThreatLevel::Malicious => "malicious",
    }
}
fn fmt_reasons(r: &[String]) -> String {
    if r.is_empty() { String::new() } else { format!(" [{}]", r.join("; ")) }
}

pub fn evaluate_all(signals: &[PostureSignal], policy: &TrustPolicy) -> Vec<TrustDecision> {
    signals.iter().map(|s| evaluate(s, policy)).collect()
}

const BANNER: &str = "# GENERATED by hookprobe continuous-trust reconciler from live posture signals.\n# Do NOT edit — this is a dynamic AEGIS plan-as-diff (reverts when posture clears).\n";

/// Render the re-segmentation OVERRIDE flows for quarantined devices. The override sits
/// at priority 250 — ABOVE the normal per-device binding (200) and the onboarding
/// catch-all (10) — so quarantine wins immediately and reverts when the flow is removed.
pub fn render_quarantine_flows(decisions: &[TrustDecision], policy: &TrustPolicy) -> GeneratedFile {
    let mut s = String::from(BANNER);
    s.push_str(&format!(
        "# Quarantine overrides (apply: ovs-ofctl add-flows <br> -). VLAN {} = {}.\n",
        policy.quarantine_vlan, policy.quarantine_segment
    ));
    let q: Vec<&TrustDecision> = decisions.iter().filter(|d| d.action == TrustAction::Quarantine).collect();
    if q.is_empty() {
        s.push_str("# (no devices quarantined this cycle)\n");
    }
    for d in q {
        s.push_str(&format!(
            "priority=250,dl_src={mac},actions=mod_vlan_vid:{vlan},normal  # {from}→quarantine: {reason}\n",
            mac = d.mac, vlan = policy.quarantine_vlan, from = d.from_segment, reason = d.reason
        ));
    }
    GeneratedFile { path: "fabric/64-trust.quarantine.of".to_string(), content: s }
}

// ---------------------------------------------------------------------------
// Live posture feed — build PostureSignals from the detection plane's own files.
// ---------------------------------------------------------------------------

/// One device's live ARP presence (from V1 `arp-status.json`).
#[derive(Debug, Clone, PartialEq)]
pub struct ArpEntry {
    pub mac: String,
    pub ip: Option<String>,
    pub online: bool,
}

fn norm_mac(m: &str) -> String {
    m.to_ascii_lowercase()
}

/// Parse `arp-status.json` (`{"MAC": {"online":bool,"state":..,"ip":..}, …}`).
pub fn parse_arp_status(text: &str) -> Vec<ArpEntry> {
    let v: serde_json::Value = match serde_json::from_str(text) {
        Ok(v) => v,
        Err(_) => return Vec::new(),
    };
    v.as_object()
        .map(|m| {
            m.iter()
                .map(|(mac, e)| ArpEntry {
                    mac: norm_mac(mac),
                    ip: e.get("ip").and_then(|x| x.as_str()).map(String::from),
                    online: e.get("online").and_then(|x| x.as_bool()).unwrap_or(false),
                })
                .collect()
        })
        .unwrap_or_default()
}

/// True if `mac` is named in the `blocked` list, which (V1 `blocked_macs.json`) may hold
/// either plain MACs OR the **MD5 of the MAC**. We test the plain MAC and the MD5 of four
/// normalizations (lower/upper × colon/no-colon) so any of V1's encodings matches.
pub fn mac_is_blocked(mac: &str, blocked_set: &std::collections::BTreeSet<String>) -> bool {
    let lc = norm_mac(mac);
    let no_colon_lc: String = lc.chars().filter(|c| *c != ':').collect();
    let uc = lc.to_ascii_uppercase();
    let no_colon_uc: String = no_colon_lc.to_ascii_uppercase();
    let forms = [lc.as_str(), no_colon_lc.as_str(), uc.as_str(), no_colon_uc.as_str()];
    // PLAIN match: a blocked entry may be the MAC in any of the four normalizations.
    if forms.iter().any(|f| blocked_set.contains(*f)) {
        return true;
    }
    // HASHED match: V1 stores the MD5 of the MAC (in some normalization).
    forms
        .iter()
        .any(|f| blocked_set.contains(&crate::md5::md5_hex(f.as_bytes())))
}

/// Build posture signals for online devices: a device whose MAC is in `blocked`
/// (HYDRA/V1 `blocked_macs.json`, plain or MD5-hashed) is `malicious` at high risk;
/// others are clean. The `segments` map (mac→segment) supplies current_segment.
///
/// **`intel` (ADR 0023 task #19 / ADR 0027 Layer-1, 2026-07-16):** additional, ALREADY-SHAPED
/// `IntelOnly` posture signals — typically HYDRA's corroboration-gated verdicts, resolved to a MAC
/// via [`intel_signals_from_hydra`] — folded in unchanged (never re-derived/re-gated here; the
/// corroboration/enforcement gate lives entirely in [`evaluate`]'s `intel_requires_corroboration`
/// check, so there is exactly ONE place a single/uncorroborated intel signal can be blocked from
/// quarantining, no matter which producer fed it in).
///
/// Every online ARP device already gets a (possibly-clean, `risk=0`/`threat=None`) `Direct` entry
/// below, so "fold in" means: a device with NO durable `blocked_macs` hit (`threat == None`) has
/// its trivial clean placeholder REPLACED by its intel signal, if any — otherwise every intel
/// signal would be silently shadowed by that placeholder and never reach [`evaluate`] at all. A
/// device that DOES have a durable block keeps ONLY the `Direct` entry — it is strictly more
/// decisive than an intel-only hit on the same MAC, so the intel entry would be redundant noise,
/// never a second, weaker override.
///
/// **mgmt-safety floor (2026-07-16 security-auditor AMBER-2 backstop):** before returning, every
/// entry whose MAC resolves (via this same `arp` snapshot) to a management-path address
/// (`hookprobe_mgmt_guard::protect_reason` — the mgmt /28 + gateway/resolver) is neutralized to
/// clean/`Keep`, unconditionally, for EVERY provenance. This is defense-in-depth against a forged
/// or compromised `IntelOnly` producer (e.g. the `hydra-verdicts` sidecar file) setting
/// `corroborated: true` for a management device — the ONE funnel every live-plane posture signal
/// passes through, so there is no way to route a forged signal around it.
pub fn build_posture(
    arp: &[ArpEntry],
    blocked: &[String],
    intel: &[PostureSignal],
    segments: &[(String, String)],
    default_segment: &str,
) -> Vec<PostureSignal> {
    // Blocked entries may be plain MACs (normalize) or already-hashed (keep verbatim).
    let blocked_set: std::collections::BTreeSet<String> = blocked
        .iter()
        .flat_map(|b| [norm_mac(b), b.trim().to_string()])
        .collect();
    let mut out: Vec<PostureSignal> = arp
        .iter()
        .filter(|e| e.online)
        .map(|e| {
            let current = segments
                .iter()
                .find(|(m, _)| norm_mac(m) == e.mac)
                .map(|(_, s)| s.clone())
                .unwrap_or_else(|| default_segment.to_string());
            let blocked = mac_is_blocked(&e.mac, &blocked_set);
            PostureSignal {
                mac: e.mac.clone(),
                current_segment: current,
                risk: if blocked { 90.0 } else { 0.0 },
                threat: if blocked { ThreatLevel::Malicious } else { ThreatLevel::None },
                reasons: if blocked { vec!["listed in blocked_macs (HYDRA/IDS)".to_string()] } else { vec![] },
                // A durable blocked_macs entry is a confirmed identity block, not an unproven
                // intel-only hit — it keeps the `Direct` provenance so it quarantines as before.
                provenance: SignalProvenance::Direct,
                corroborated: false,
            }
        })
        .collect();

    let intel_by_mac: std::collections::BTreeMap<String, &PostureSignal> =
        intel.iter().map(|s| (norm_mac(&s.mac), s)).collect();
    for entry in out.iter_mut() {
        if entry.threat == ThreatLevel::None {
            if let Some(sig) = intel_by_mac.get(&norm_mac(&entry.mac)) {
                *entry = (*sig).clone();
            }
        }
    }
    // Defensive: an intel signal for a MAC with no ARP entry at all (the producer above SHOULD
    // already be ARP-filtered, e.g. `intel_signals_from_hydra`, but a differently-sourced intel
    // signal must still be honoured, never silently dropped just because it wasn't in `out` yet).
    let present: std::collections::BTreeSet<String> = out.iter().map(|s| norm_mac(&s.mac)).collect();
    out.extend(intel.iter().filter(|s| !present.contains(&norm_mac(&s.mac))).cloned());

    // 2026-07-16 security-auditor AMBER-2 backstop: the SAME mgmt-safety `Allowlisted` floor
    // `scan_responder`/`aegis-guard` already honour (`hookprobe_mgmt_guard::protect_reason` — the
    // mgmt /28 + gateway/resolver) applies HERE too, defense-in-depth, unconditionally, for EVERY
    // provenance — `Direct` and `IntelOnly` alike. The `enforce`/`corroborated` bit on an
    // `IntelOnly` signal is trusted VERBATIM from whatever produced it (e.g. the `hydra-verdicts`
    // sidecar file, which is data, not code — a forged or compromised producer could otherwise
    // set `corroborated: true` for a management device and reach `evaluate`'s quarantine branch
    // with no independent check). Neutralize threat/risk/corroboration to the same clean state a
    // never-flagged device gets, so `evaluate()` always yields `Keep` for a protected address —
    // no changes needed in `evaluate()` itself, and no way to route around this by constructing a
    // `PostureSignal` directly (every live-plane entry point funnels through here).
    let mgmt = ProtectPolicy::default();
    for entry in out.iter_mut() {
        let ip = arp
            .iter()
            .find(|e| norm_mac(&e.mac) == norm_mac(&entry.mac))
            .and_then(|e| e.ip.as_deref());
        let Some(ip) = ip else { continue };
        let Some(reason) = protect_reason(ip, None, &mgmt) else { continue };
        if entry.threat != ThreatLevel::None || entry.risk > 0.0 || entry.corroborated {
            entry.reasons.push(format!("mgmt floor: {reason} — never enforced regardless of signal/provenance"));
        }
        entry.threat = ThreatLevel::None;
        entry.risk = 0.0;
        entry.corroborated = false;
    }
    out
}

/// One HYDRA-shaped, corroboration-gated device verdict — the exact JSON line
/// `hookprobe_hydra::verdict::HydraVerdict::to_intel_json` emits (ADR 0023 task #19 / ADR 0027
/// Layer-1). `hookprobe-manifest` deliberately does NOT depend on the `hookprobe-hydra` crate
/// (layering: `trust` is the generic continuous-trust reconciler; HYDRA is one detection-plane
/// producer among several, same as the live ARP/blocked-macs feed above) — this struct is the
/// shared JSON *contract* between the two crates, proven by `intel_signals_from_hydra`'s own tests.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct HydraDeviceVerdict {
    pub device_ip: String,
    #[serde(default)]
    pub threat: ThreatLevel,
    #[serde(default)]
    pub risk: f64,
    /// True ONLY when HYDRA's own `verdict::assess` gate judged this device's signals
    /// independently corroborated (>= N distinct signals AND aggregate score over its quarantine
    /// bar) — becomes [`PostureSignal::corroborated`] verbatim. A lone IOC hit is `false` by
    /// construction on the HYDRA side; this field is never re-derived here, only carried through.
    #[serde(default)]
    pub enforce: bool,
    #[serde(default)]
    pub reasons: Vec<String>,
}

/// Turn HYDRA's per-device verdicts into `IntelOnly` [`PostureSignal`]s, resolving each
/// `device_ip` to a MAC via the SAME live ARP snapshot [`build_posture`] uses (a HYDRA verdict is
/// IP-keyed — flows carry no MAC). A device not currently in the online ARP table is skipped: there
/// is no MAC to key a quarantine override flow on, and an offline device needs no live posture
/// update this cycle (mirrors `build_posture`'s own online-only filter).
///
/// This is the ONLY place a `device_ip` becomes a `mac` — the corroboration/enforcement decision
/// itself (`enforce` → `corroborated`) is untouched, carried straight through from HYDRA's own
/// gate so the SAME `intel_requires_corroboration` check in [`evaluate`] is what ultimately decides
/// whether it may quarantine.
pub fn intel_signals_from_hydra(
    verdicts: &[HydraDeviceVerdict],
    arp: &[ArpEntry],
    segments: &[(String, String)],
    default_segment: &str,
) -> Vec<PostureSignal> {
    verdicts
        .iter()
        .filter_map(|v| {
            let entry = arp.iter().find(|e| e.online && e.ip.as_deref() == Some(v.device_ip.as_str()))?;
            let current = segments
                .iter()
                .find(|(m, _)| norm_mac(m) == entry.mac)
                .map(|(_, s)| s.clone())
                .unwrap_or_else(|| default_segment.to_string());
            Some(PostureSignal {
                mac: entry.mac.clone(),
                current_segment: current,
                risk: v.risk,
                threat: v.threat,
                reasons: v.reasons.clone(),
                provenance: SignalProvenance::IntelOnly,
                corroborated: v.enforce,
            })
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Reverting reconcile — what makes continuous-trust CONTINUOUS (converges/cycle).
// ---------------------------------------------------------------------------

/// The diff between this cycle's decisions and the previously-quarantined set:
/// devices to quarantine NOW (add override) and devices to RELEASE (remove override
/// because their posture cleared). This is the AEGIS reconcile — idempotent per cycle.
#[derive(Debug, Clone)]
pub struct QuarantineReconcile {
    pub newly_quarantined: Vec<TrustDecision>,
    pub recovered: Vec<String>,
    /// The full current quarantined set (to persist as the next cycle's `previous`).
    pub current: Vec<String>,
}

/// Reconcile decisions against the previously-quarantined MACs.
pub fn reconcile(decisions: &[TrustDecision], previously_quarantined: &[String]) -> QuarantineReconcile {
    let prev: std::collections::BTreeSet<String> =
        previously_quarantined.iter().map(|m| norm_mac(m)).collect();
    let current_set: std::collections::BTreeSet<String> = decisions
        .iter()
        .filter(|d| d.action == TrustAction::Quarantine)
        .map(|d| norm_mac(&d.mac))
        .collect();
    let newly_quarantined: Vec<TrustDecision> = decisions
        .iter()
        .filter(|d| d.action == TrustAction::Quarantine && !prev.contains(&norm_mac(&d.mac)))
        .cloned()
        .collect();
    // Recovered = previously quarantined but NOT quarantined this cycle.
    let recovered: Vec<String> = prev.iter().filter(|m| !current_set.contains(*m)).cloned().collect();
    QuarantineReconcile {
        newly_quarantined,
        recovered,
        current: current_set.into_iter().collect(),
    }
}

/// Render the convergent flow diff: add overrides for the newly quarantined, and
/// `del-flows` for the recovered (so quarantine auto-reverts when posture clears).
/// `bridge` is substituted into the `ovs-ofctl` commands so the output is runnable.
pub fn render_reconcile(rec: &QuarantineReconcile, policy: &TrustPolicy, bridge: &str) -> GeneratedFile {
    let mut s = String::from(BANNER);
    s.push_str("# Continuous-trust reconcile (run each cycle; converges).\n");
    s.push_str(&format!("# ADD overrides (newly quarantined → VLAN {}):\n", policy.quarantine_vlan));
    if rec.newly_quarantined.is_empty() {
        s.push_str("#   (none)\n");
    }
    for d in &rec.newly_quarantined {
        s.push_str(&format!(
            "ovs-ofctl add-flow {bridge} priority=250,dl_src={mac},actions=mod_vlan_vid:{vlan},normal  # {reason}\n",
            mac = d.mac, vlan = policy.quarantine_vlan, reason = d.reason
        ));
    }
    s.push_str("# REMOVE overrides (recovered → posture cleared, restore normal segment):\n");
    if rec.recovered.is_empty() {
        s.push_str("#   (none)\n");
    }
    for mac in &rec.recovered {
        // No quotes: the flowspec has no spaces, so the consumer can word-split into argv
        // and exec ovs-ofctl directly (no `eval` / shell-injection surface).
        s.push_str(&format!("ovs-ofctl del-flows {bridge} priority=250,dl_src={mac}  # recovered → released\n"));
    }
    GeneratedFile { path: "fabric/64-trust.reconcile.sh".to_string(), content: s }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sig(mac: &str, seg: &str, risk: f64, threat: ThreatLevel) -> PostureSignal {
        PostureSignal { mac: mac.into(), current_segment: seg.into(), risk, threat, reasons: vec![], provenance: SignalProvenance::Direct, corroborated: false }
    }

    fn intel_sig(mac: &str, risk: f64, threat: ThreatLevel, corroborated: bool) -> PostureSignal {
        PostureSignal {
            mac: mac.into(),
            current_segment: "byod".into(),
            risk,
            threat,
            reasons: vec![],
            provenance: SignalProvenance::IntelOnly,
            corroborated,
        }
    }

    // Finding-1 (2026-07-10): the enforcement gate. A HYDRA intel-only signal that has NOT been
    // corroborated must NEVER quarantine — even a `Malicious` threat at high risk only steps up.
    #[test]
    fn intel_only_uncorroborated_malicious_never_quarantines() {
        let d = evaluate(&intel_sig("de:ad:00:00:00:01", 95.0, ThreatLevel::Malicious, false), &TrustPolicy::default());
        assert_eq!(d.action, TrustAction::StepUp, "a lone/uncorroborated IOC hit is capped at step-up");
        assert_eq!(d.to_segment, "byod", "step-up keeps the device in its segment — customer traffic still passes");
        assert!(d.reason.contains("NOT quarantined"), "the reason must state it was not enforced");
    }

    // High-risk-alone (no threat verdict) from an uncorroborated intel signal is also gated.
    #[test]
    fn intel_only_uncorroborated_high_risk_never_quarantines() {
        let d = evaluate(&intel_sig("de:ad:00:00:00:02", 88.0, ThreatLevel::None, false), &TrustPolicy::default());
        assert_ne!(d.action, TrustAction::Quarantine);
    }

    // A corroborated intel signal (the genuine, active, multi-signal threat) STILL quarantines —
    // no regression in real-threat response.
    #[test]
    fn intel_only_corroborated_malicious_still_quarantines() {
        let d = evaluate(&intel_sig("de:ad:00:00:00:03", 82.0, ThreatLevel::Malicious, true), &TrustPolicy::default());
        assert_eq!(d.action, TrustAction::Quarantine, "corroborated active threat is enforced");
        assert_eq!(d.to_segment, "quarantine");
    }

    // The confirmed paths (scan-responder / blocked_macs use `Direct`) are unaffected by the gate.
    #[test]
    fn direct_malicious_still_quarantines_unconditionally() {
        let d = evaluate(&sig("de:ad:00:00:00:04", "iot", 95.0, ThreatLevel::Malicious), &TrustPolicy::default());
        assert_eq!(d.action, TrustAction::Quarantine, "a confirmed scan/blocked signal quarantines as before");
    }

    // The gate is policy, not hardcoded: an operator may opt back into single-signal enforcement.
    #[test]
    fn intel_corroboration_gate_is_policy_tunable() {
        let policy = TrustPolicy { intel_requires_corroboration: false, ..TrustPolicy::default() };
        let d = evaluate(&intel_sig("de:ad:00:00:00:05", 95.0, ThreatLevel::Malicious, false), &policy);
        assert_eq!(d.action, TrustAction::Quarantine, "gate disabled → old behavior restored");
    }

    // A HYDRA verdict's posture JSON deserializes straight into a PostureSignal and flows through
    // the gate: uncorroborated → step-up; the round-trip proves the two crates agree on the shape.
    #[test]
    fn hydra_posture_json_shape_deserializes_and_is_gated() {
        let line = r#"{"mac":"aa:bb:cc:dd:ee:ff","current_segment":"byod","risk":36.0,"threat":"suspicious","provenance":"intel-only","corroborated":false,"reasons":["IOC 50.16.16.211 (ip)"]}"#;
        let sig: PostureSignal = serde_json::from_str(line).unwrap();
        assert_eq!(sig.provenance, SignalProvenance::IntelOnly);
        assert!(!sig.corroborated);
        let d = evaluate(&sig, &TrustPolicy::default());
        assert_ne!(d.action, TrustAction::Quarantine, "intel-only suspicious → never quarantine");
    }

    /// A malicious HYDRA verdict quarantines regardless of score.
    #[test]
    fn malicious_threat_quarantines() {
        let d = evaluate(&sig("aa:bb:cc:dd:ee:ff", "byod", 5.0, ThreatLevel::Malicious), &TrustPolicy::default());
        assert_eq!(d.action, TrustAction::Quarantine);
        assert_eq!(d.to_segment, "quarantine");
    }

    /// High QSECBIT-derived risk quarantines even with no explicit threat verdict.
    #[test]
    fn high_risk_quarantines() {
        let d = evaluate(&sig("a", "iot", 85.0, ThreatLevel::None), &TrustPolicy::default());
        assert_eq!(d.action, TrustAction::Quarantine);
    }

    /// Mid risk / suspicious → step-up (re-auth), device stays in its segment.
    #[test]
    fn suspicious_steps_up_keeps_segment() {
        let d = evaluate(&sig("a", "byod", 50.0, ThreatLevel::Suspicious), &TrustPolicy::default());
        assert_eq!(d.action, TrustAction::StepUp);
        assert_eq!(d.to_segment, "byod", "step-up keeps the current segment");
    }

    /// Clean posture → keep.
    #[test]
    fn clean_posture_keeps() {
        let d = evaluate(&sig("a", "trusted", 10.0, ThreatLevel::None), &TrustPolicy::default());
        assert_eq!(d.action, TrustAction::Keep);
    }

    /// Live feed: arp-status parses, and a blocked MAC becomes a malicious posture
    /// while the others stay clean — built from the N100's own files.
    #[test]
    fn posture_from_live_arp_and_blocked() {
        // Deliberately regular LAN (10.66.0.0/24) addresses, NOT the 10.200.0.0/28 mgmt subnet —
        // see `mgmt_floor_neutralizes_a_blocked_device_inside_the_mgmt_subnet` below for the
        // dedicated mgmt-floor-vs-blocked-macs interaction test.
        let arp = r#"{"9E:A3:53:C7:FE:EC":{"online":true,"state":"REACHABLE","ip":"10.66.0.3"},
                      "40:ED:CF:82:62:6B":{"online":true,"state":"REACHABLE","ip":"10.66.0.12"},
                      "AA:BB:CC:00:00:09":{"online":false,"ip":"10.66.0.99"}}"#;
        let entries = parse_arp_status(arp);
        assert_eq!(entries.len(), 3);
        let segs = vec![("40:ed:cf:82:62:6b".to_string(), "iot".to_string())];
        let posture = build_posture(&entries, &["40:ED:CF:82:62:6B".into()], &[], &segs, "byod");
        // Offline device is skipped; online blocked one is malicious; clean one is none.
        assert_eq!(posture.len(), 2, "offline device excluded");
        let blocked = posture.iter().find(|p| p.mac == "40:ed:cf:82:62:6b").unwrap();
        assert_eq!(blocked.threat, ThreatLevel::Malicious);
        assert_eq!(blocked.current_segment, "iot", "segment from the AEGIS map");
        let clean = posture.iter().find(|p| p.mac == "9e:a3:53:c7:fe:ec").unwrap();
        assert_eq!(clean.threat, ThreatLevel::None);
    }

    /// V1 stores MD5(MAC) in blocked_macs — a device is matched via the hash, in any of
    /// the four MAC normalizations.
    #[test]
    fn blocked_matches_md5_of_mac() {
        let mac = "aa:bb:cc:dd:ee:ff";
        // MD5 of the uppercase, no-colon form (one of V1's likely encodings).
        let hash = crate::md5::md5_hex(b"AABBCCDDEEFF");
        let arp = vec![ArpEntry { mac: mac.into(), ip: None, online: true }];
        let posture = build_posture(&arp, &[hash], &[], &[], "byod");
        assert_eq!(posture[0].threat, ThreatLevel::Malicious, "hashed MAC must match");
        // A clean MAC is not matched.
        let arp2 = vec![ArpEntry { mac: "11:22:33:44:55:66".into(), ip: None, online: true }];
        assert_eq!(build_posture(&arp2, &[crate::md5::md5_hex(b"AABBCCDDEEFF")], &[], &[], "byod")[0].threat, ThreatLevel::None);
    }

    /// Reconcile converges: a new threat is added, a recovered device is released.
    #[test]
    fn reconcile_adds_new_and_releases_recovered() {
        let policy = TrustPolicy::default();
        // This cycle: only device B is malicious.
        let decisions = evaluate_all(
            &[
                sig("aa:00:00:00:00:0a", "byod", 5.0, ThreatLevel::None),     // clean now
                sig("bb:00:00:00:00:0b", "iot", 95.0, ThreatLevel::Malicious), // newly bad
            ],
            &policy,
        );
        // Previous cycle had A quarantined (now recovered).
        let rec = reconcile(&decisions, &["aa:00:00:00:00:0a".into()]);
        assert_eq!(rec.newly_quarantined.len(), 1);
        assert_eq!(rec.newly_quarantined[0].mac, "bb:00:00:00:00:0b");
        assert_eq!(rec.recovered, vec!["aa:00:00:00:00:0a".to_string()], "A recovered → released");
        let f = render_reconcile(&rec, &policy, "hp-br0");
        assert!(f.content.contains("add-flow hp-br0 priority=250,dl_src=bb:00:00:00:00:0b"));
        assert!(f.content.contains("del-flows hp-br0 priority=250,dl_src=aa:00:00:00:00:0a"));
    }

    /// Only quarantined devices get an override flow, at priority 250 (above the 200
    /// normal binding) so it wins; it reverts when removed.
    #[test]
    fn quarantine_override_flow_is_high_priority() {
        let policy = TrustPolicy::default();
        let decisions = evaluate_all(
            &[
                sig("ca:fe:00:00:00:01", "cameras", 95.0, ThreatLevel::Malicious),
                sig("ca:fe:00:00:00:02", "trusted", 5.0, ThreatLevel::None),
            ],
            &policy,
        );
        let f = render_quarantine_flows(&decisions, &policy);
        assert!(f.content.contains("priority=250,dl_src=ca:fe:00:00:00:01,actions=mod_vlan_vid:666,normal"));
        assert!(!f.content.contains("ca:fe:00:00:00:02"), "clean device gets no override");
    }

    // ---------------------------------------------------------------------------------------
    // ADR 0023 task #19 / ADR 0027 Layer-1 wiring — HYDRA verdicts -> build_posture -> evaluate.
    // The end-to-end path the supervisor's `--arp` live-trust branch now runs (main.rs:1315 no
    // longer passes `&[]` for intel). These prove the corroboration invariant holds ACROSS the
    // full pipeline, not just at `evaluate`'s own gate (already covered above).
    // ---------------------------------------------------------------------------------------

    fn online_arp(mac: &str, ip: &str) -> ArpEntry {
        ArpEntry { mac: norm_mac(mac), ip: Some(ip.to_string()), online: true }
    }

    // (a) A single, uncorroborated HYDRA verdict (a lone IOC hit — `enforce: false`) resolves to
    // Observe/StepUp, NEVER quarantine, once folded through build_posture -> evaluate_all.
    #[test]
    fn single_uncorroborated_hydra_verdict_never_quarantines_end_to_end() {
        let arp = vec![online_arp("de:ad:00:00:01:01", "10.66.0.60")];
        let verdicts = vec![HydraDeviceVerdict {
            device_ip: "10.66.0.60".to_string(),
            threat: ThreatLevel::Suspicious,
            risk: 40.0,
            enforce: false, // HYDRA's own gate: one signal, not corroborated
            reasons: vec!["IOC 50.16.16.211 (ip)".to_string()],
        }];
        let intel = intel_signals_from_hydra(&verdicts, &arp, &[], "byod");
        assert_eq!(intel.len(), 1);
        assert_eq!(intel[0].provenance, SignalProvenance::IntelOnly);
        assert!(!intel[0].corroborated);

        let posture = build_posture(&arp, &[], &intel, &[], "byod");
        assert_eq!(posture.len(), 1, "build_posture's 3rd arg is no longer &[] — the intel signal must appear");
        let decisions = evaluate_all(&posture, &TrustPolicy::default());
        assert_ne!(decisions[0].action, TrustAction::Quarantine, "a single/uncorroborated HYDRA hit must never quarantine a customer");
        assert_eq!(decisions[0].to_segment, "byod", "device stays in its segment — traffic still passes");
    }

    // (b) TWO corroborating HYDRA signals (verdict::assess already set enforce=true because it saw
    // >= min_distinct_signals AND crossed its own quarantine_score) MAY escalate to quarantine.
    #[test]
    fn corroborated_hydra_verdict_may_escalate_end_to_end() {
        let arp = vec![online_arp("de:ad:00:00:01:02", "10.66.0.61")];
        let verdicts = vec![HydraDeviceVerdict {
            device_ip: "10.66.0.61".to_string(),
            threat: ThreatLevel::Malicious,
            risk: 82.0,
            enforce: true, // HYDRA's own gate: IOC hit + beaconing corroboration crossed the bar
            reasons: vec!["IOC 50.16.16.211 (ip)".to_string(), "corroboration: C2 beaconing".to_string()],
        }];
        let intel = intel_signals_from_hydra(&verdicts, &arp, &[], "byod");
        assert!(intel[0].corroborated);

        let posture = build_posture(&arp, &[], &intel, &[], "byod");
        let decisions = evaluate_all(&posture, &TrustPolicy::default());
        assert_eq!(decisions[0].action, TrustAction::Quarantine, "a corroborated, genuinely-active HYDRA threat must still be enforceable");
        assert_eq!(decisions[0].to_segment, "quarantine");
    }

    // (c) A Direct signal (durable blocked_macs identity block) still escalates unconditionally,
    // unaffected by the new intel plumbing — proves the two provenances don't interfere.
    #[test]
    fn direct_signal_still_escalates_unconditionally_alongside_intel_wiring() {
        let arp = vec![online_arp("aa:aa:aa:aa:aa:aa", "10.66.0.62"), online_arp("bb:bb:bb:bb:bb:bb", "10.66.0.63")];
        // bb:.. has an UNCORROBORATED intel hit; aa:.. is Direct-blocked. Both present this cycle.
        let verdicts = vec![HydraDeviceVerdict {
            device_ip: "10.66.0.63".to_string(),
            threat: ThreatLevel::Malicious,
            risk: 95.0,
            enforce: false,
            reasons: vec![],
        }];
        let intel = intel_signals_from_hydra(&verdicts, &arp, &[], "byod");
        let posture = build_posture(&arp, &["aa:aa:aa:aa:aa:aa".to_string()], &intel, &[], "byod");
        assert_eq!(posture.len(), 2, "one Direct (blocked) + one IntelOnly (uncorroborated)");
        let decisions = evaluate_all(&posture, &TrustPolicy::default());
        let direct = decisions.iter().find(|d| d.mac == "aa:aa:aa:aa:aa:aa").unwrap();
        assert_eq!(direct.action, TrustAction::Quarantine, "the confirmed/durable Direct block still quarantines as before");
        let intel_only = decisions.iter().find(|d| d.mac == "bb:bb:bb:bb:bb:bb").unwrap();
        assert_ne!(intel_only.action, TrustAction::Quarantine, "the uncorroborated intel-only hit on the OTHER device must not quarantine");
    }

    // (d) build_posture's intel argument is no longer a dead `&[]` literal: a non-empty intel
    // slice actually appears (unmodified) in the returned posture.
    #[test]
    fn build_posture_receives_and_carries_non_empty_intel() {
        let arp = vec![online_arp("cc:cc:cc:cc:cc:cc", "10.66.0.64")];
        let intel = vec![PostureSignal {
            mac: "cc:cc:cc:cc:cc:cc".to_string(),
            current_segment: "byod".to_string(),
            risk: 36.0,
            threat: ThreatLevel::Suspicious,
            reasons: vec!["IOC hit".to_string()],
            provenance: SignalProvenance::IntelOnly,
            corroborated: false,
        }];
        assert!(!intel.is_empty());
        let posture = build_posture(&arp, &[], &intel, &[], "byod");
        assert_eq!(posture.len(), 1);
        assert_eq!(posture[0].provenance, SignalProvenance::IntelOnly);
        assert_eq!(posture[0].risk, 36.0);
    }

    // A device offline / not in the ARP snapshot has no MAC to key on — its HYDRA verdict is
    // dropped, never silently invented a MAC for.
    #[test]
    fn intel_signals_from_hydra_skips_devices_not_in_the_online_arp_table() {
        let arp = vec![online_arp("dd:dd:dd:dd:dd:dd", "10.66.0.65")];
        let verdicts = vec![HydraDeviceVerdict {
            device_ip: "10.66.0.99".to_string(), // never seen in this ARP snapshot
            threat: ThreatLevel::Malicious,
            risk: 90.0,
            enforce: true,
            reasons: vec![],
        }];
        let intel = intel_signals_from_hydra(&verdicts, &arp, &[], "byod");
        assert!(intel.is_empty(), "no MAC to key a quarantine override on — must be dropped, not fabricated");
    }

    // ---------------------------------------------------------------------------------------
    // 2026-07-16 security-auditor AMBER-2 backstop: the mgmt-safety floor in `build_posture`.
    // ---------------------------------------------------------------------------------------

    // A DURABLE blocked_macs hit (`Direct`, normally quarantines unconditionally — see
    // `direct_malicious_still_quarantines_unconditionally`) is STILL neutralized when the device's
    // live-ARP IP is inside the mgmt /28 — mirrors scan_responder's own "gateway/mgmt subnet must
    // never self-lock" invariant, now enforced in the continuous-trust path too.
    #[test]
    fn mgmt_floor_neutralizes_a_blocked_device_inside_the_mgmt_subnet() {
        let arp = vec![online_arp("40:ed:cf:82:62:6b", "10.200.0.12")]; // inside 10.200.0.0/28
        let posture = build_posture(&arp, &["40:ED:CF:82:62:6B".into()], &[], &[], "byod");
        assert_eq!(posture.len(), 1);
        assert_eq!(posture[0].threat, ThreatLevel::None, "mgmt floor must neutralize even a durable Direct block");
        assert_eq!(posture[0].risk, 0.0);
        let decision = evaluate(&posture[0], &TrustPolicy::default());
        assert_ne!(decision.action, TrustAction::Quarantine, "a mgmt-subnet device must never be quarantined, confirmed block or not");
    }

    // The exact forged-sidecar scenario the audit named: a HYDRA verdict claims
    // `enforce: true`/`Malicious` for a device whose live-ARP IP is the mgmt gateway
    // (`10.66.0.1`) — the mgmt floor must neutralize it BEFORE `evaluate()` ever sees a
    // corroborated signal, with no dependency on `hookprobe-hydra`/the sidecar file being honest.
    #[test]
    fn mgmt_floor_neutralizes_a_forged_corroborated_hydra_verdict_for_the_gateway() {
        let arp = vec![online_arp("aa:aa:aa:aa:aa:01", "10.66.0.1")]; // the default-protected LAN gateway
        let verdicts = vec![HydraDeviceVerdict {
            device_ip: "10.66.0.1".to_string(),
            threat: ThreatLevel::Malicious,
            risk: 99.0,
            enforce: true, // forged/compromised sidecar claiming full corroboration
            reasons: vec!["forged".to_string()],
        }];
        let intel = intel_signals_from_hydra(&verdicts, &arp, &[], "byod");
        assert!(intel[0].corroborated, "sanity: the (forged) intel signal itself claims corroborated");

        let posture = build_posture(&arp, &[], &intel, &[], "byod");
        assert_eq!(posture.len(), 1);
        assert_eq!(posture[0].threat, ThreatLevel::None, "mgmt floor must neutralize the forged verdict");
        assert!(!posture[0].corroborated, "corroboration bit must be cleared too — no partial trust survives the floor");
        let decision = evaluate(&posture[0], &TrustPolicy::default());
        assert_ne!(decision.action, TrustAction::Quarantine, "the gateway must never be quarantined, forged corroboration or not");
    }

    // A non-mgmt device with the SAME corroborated verdict shape still escalates normally — the
    // floor is address-scoped, not a blanket downgrade of all IntelOnly signals.
    #[test]
    fn mgmt_floor_does_not_suppress_corroborated_verdicts_on_non_mgmt_devices() {
        let arp = vec![online_arp("bb:bb:bb:bb:bb:02", "10.66.0.42")]; // ordinary LAN device
        let verdicts = vec![HydraDeviceVerdict {
            device_ip: "10.66.0.42".to_string(),
            threat: ThreatLevel::Malicious,
            risk: 90.0,
            enforce: true,
            reasons: vec!["IOC + beaconing".to_string()],
        }];
        let intel = intel_signals_from_hydra(&verdicts, &arp, &[], "byod");
        let posture = build_posture(&arp, &[], &intel, &[], "byod");
        assert_eq!(posture[0].threat, ThreatLevel::Malicious, "a normal device's genuine corroborated verdict is unaffected by the mgmt floor");
        let decision = evaluate(&posture[0], &TrustPolicy::default());
        assert_eq!(decision.action, TrustAction::Quarantine);
    }
}
