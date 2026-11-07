//! HYDRA verdict-shaping (Finding-1 fix, 2026-07-10) — turn a device's raw IOC hits into a
//! **bounded, corroboration-gated** trust contribution, so a single low-signal indicator match can
//! NEVER by itself put a customer's device in quarantine.
//!
//! # Why this module exists
//! ADR 0027 states HYDRA is "alert/enrich ONLY, never enforcement" (gate 0.7). The IOC matcher
//! ([`crate::matcher`]) already honours that for DETECTION — every hit is ingested to the evidence
//! graph unchanged, this module never silences it. What was missing was the guard on the OTHER
//! side: nothing stopped a HYDRA-sourced signal from being handed to the continuous-trust
//! reconciler (`hookprobe_manifest::trust`) as a `threat = malicious` / `risk >= 70` posture, which
//! quarantines UNCONDITIONALLY. A single injected flow to one bundled C2 IOC IP — or to a
//! shared/CGNAT/cloud IP that was ever an indicator — would then re-segment a legitimate customer
//! within one reconcile cycle. That violates the operator's hard rule: *a legit customer connection
//! must ALWAYS pass; drop/quarantine only CONFIRMED attacks*
//! (`hookprobe-enforcement-separation`).
//!
//! # The gate (mirrors the scan-responder's "confirmed handshake" discipline one layer up)
//! [`assess`] aggregates a device's hits into a [`HydraVerdict`] under an operator-tunable
//! [`HydraTrustPolicy`]:
//!  1. **active-only for enforcement** — an `active: false` (historical/offline) indicator
//!     contributes ZERO enforcement score (it is still recorded to evidence by the matcher; this
//!     module only shapes ENFORCEMENT). Belt-and-suspenders on top of `IocFeed::lookup`'s own
//!     `active` filter — a safety invariant must never rely on an upstream filter staying correct.
//!  2. **confidence + severity weighting** — each qualifying hit adds `weight(ioc_type) *
//!     confidence`; an IP match (shared/CGNAT/cloud-heavy, high false-positive surface) is weighted
//!     LOWER than a file-hash or domain match.
//!  3. **corroboration / N-signal before quarantine** — a `malicious` (quarantine-worthy) verdict
//!     requires BOTH `>= min_distinct_signals` INDEPENDENT, PER-DEVICE signals AND an aggregate
//!     score `>= quarantine_score`. A lone hit (even a 0.9-confidence active C2 IP) is exactly ONE
//!     signal, so it can only ever reach `suspicious` (document + step-up), never `malicious`.
//!     Corroboration can come from a second distinct indicator or a beaconing/periodicity signal —
//!     both genuinely per-device — exactly like the scan-responder requires a completed handshake,
//!     not a single spoofable packet. **The host-global QSECBIT composite reading (2026-07-16
//!     security-auditor RED fix) may raise the SCORE but never counts toward the distinct-signal
//!     requirement** — it is one `dev:self` reading applied identically to every device this pass,
//!     so treating it as "a 2nd independent signal" would collateral-quarantine every device on the
//!     box the instant the host's own resilience score dipped, which is exactly the kind of
//!     spoofable/non-independent basis this gate exists to reject.
//!  4. **mgmt-allowlist floor** — a device whose address is the mgmt subnet / gateway / resolver
//!     (`hookprobe_mgmt_guard::protect_reason`) is never enforced against, regardless of score.
//!  5. Non-quarantine verdicts have their emitted `risk` capped strictly BELOW `quarantine_score`,
//!     so a high-fidelity-but-uncorroborated single hit cannot cross the trust risk threshold via
//!     the risk path either.

use std::collections::BTreeSet;

use hookprobe_mgmt_guard::{protect_reason, ProtectPolicy};
use serde::Deserialize;

use crate::feed::IocType;
use crate::matcher::Hit;

/// The trust contribution a HYDRA situation is allowed to make. Maps 1:1 onto
/// `hookprobe_manifest::trust::ThreatLevel`'s lowercase serde representation (`none`/`suspicious`/
/// `malicious`) so [`HydraVerdict::to_posture_json`] deserializes straight into a `PostureSignal`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HydraThreat {
    None,
    Suspicious,
    Malicious,
}
impl HydraThreat {
    pub fn as_str(&self) -> &'static str {
        match self {
            HydraThreat::None => "none",
            HydraThreat::Suspicious => "suspicious",
            HydraThreat::Malicious => "malicious",
        }
    }
}

/// Corroborating, non-IOC signals for a device, supplied by the caller from the SAME evidence
/// graph HYDRA reads. These are what let a genuine, active threat cross the quarantine bar without
/// a second IOC hit — mirroring "IOC hit AND a beaconing signal" from the operator's brief.
#[derive(Debug, Clone, Copy, Default)]
pub struct Corroboration {
    /// This device is already flagged for C2 beaconing/periodicity (NAPSE rule `1_000_040`) —
    /// genuinely PER-DEVICE, counts toward `min_distinct_signals`.
    pub beaconing: bool,
    /// This HOST's global QSECBIT composite reading (0–100; NOT per-device — see
    /// `EvidenceGraph::list_qsecbit`'s doc). `>= qsecbit_anomaly_min` raises the SCORE but
    /// (2026-07-16 security-auditor RED fix) deliberately does NOT count toward
    /// `min_distinct_signals` — see [`assess`]'s doc comment point 3 for why.
    pub qsecbit_anomaly: f64,
}

/// Operator-tunable HYDRA→trust weighting/corroboration policy (config is policy, not hardcode).
/// All fields `#[serde(default)]` so a partial YAML/JSON override only changes the knobs it names.
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct HydraTrustPolicy {
    /// An `active: false` indicator contributes zero enforcement score when true (default).
    pub enforce_requires_active: bool,
    /// A hit below this confidence contributes zero enforcement score (still documented).
    pub min_enforce_confidence: f64,
    /// Per-IOC-type base weights (multiplied by the indicator's confidence). IP is deliberately the
    /// weakest (shared/CGNAT/cloud IPs dominate false positives); a file hash is the strongest.
    pub weight_ip: f64,
    pub weight_domain: f64,
    pub weight_sha256: f64,
    pub weight_ja3: f64,
    pub weight_ja4: f64,
    pub weight_ja4s: f64,
    /// Score added by a beaconing corroboration signal.
    pub beacon_weight: f64,
    /// Host-global QSECBIT anomaly at/above which it contributes to the SCORE (never the
    /// distinct-signal count — see [`Corroboration::qsecbit_anomaly`]'s doc), and the multiplier
    /// applied to the anomaly value when it does.
    pub qsecbit_anomaly_min: f64,
    pub qsecbit_weight: f64,
    /// Aggregate score AND distinct-signal count both required to reach `malicious`/quarantine.
    pub quarantine_score: f64,
    pub min_distinct_signals: usize,
    /// Score at/above which a (non-quarantine) verdict is `suspicious` (document + step-up).
    pub stepup_score: f64,
}
impl Default for HydraTrustPolicy {
    fn default() -> Self {
        HydraTrustPolicy {
            enforce_requires_active: true,
            min_enforce_confidence: 0.5,
            // Tuned so that NO single indicator type at any confidence reaches `quarantine_score`
            // (70) on its own, but two solid signals (or one IOC + a beacon/anomaly) do.
            weight_ip: 40.0,
            weight_domain: 45.0,
            weight_sha256: 70.0,
            weight_ja3: 40.0,
            weight_ja4: 50.0,
            weight_ja4s: 45.0,
            beacon_weight: 45.0,
            qsecbit_anomaly_min: 50.0,
            qsecbit_weight: 0.6,
            quarantine_score: 70.0,
            min_distinct_signals: 2,
            stepup_score: 30.0,
        }
    }
}
impl HydraTrustPolicy {
    pub fn parse_yaml(yaml: &str) -> anyhow::Result<HydraTrustPolicy> {
        Ok(serde_yaml::from_str(yaml)?)
    }
    fn weight_for(&self, t: IocType) -> f64 {
        match t {
            IocType::Ip => self.weight_ip,
            IocType::Domain => self.weight_domain,
            IocType::Sha256 => self.weight_sha256,
            IocType::Ja3 => self.weight_ja3,
            IocType::Ja4 => self.weight_ja4,
            IocType::Ja4s => self.weight_ja4s,
        }
    }
}

/// The shaped, gated HYDRA contribution for one device.
#[derive(Debug, Clone)]
pub struct HydraVerdict {
    pub device_ip: String,
    pub threat: HydraThreat,
    /// 0–100. For a `malicious` verdict this is `>= quarantine_score`; for any other verdict it is
    /// capped strictly BELOW `quarantine_score` so it can never cross the trust risk threshold.
    pub risk: f64,
    /// True ONLY when the verdict is corroborated + `malicious` — i.e. genuinely quarantine-worthy.
    /// Carried into the posture as `corroborated`, which the trust reconciler's enforcement gate
    /// requires before it will quarantine an intel-only signal.
    pub enforce: bool,
    /// Count of INDEPENDENT, PER-DEVICE signals that contributed (distinct qualifying indicator
    /// values + a per-device beacon signal). Deliberately EXCLUDES the host-global QSECBIT
    /// contribution (2026-07-16 security-auditor RED fix) — see [`Corroboration::qsecbit_anomaly`].
    pub distinct_signals: usize,
    pub score: f64,
    /// Human-readable, honest reasons — every hit is named, whether or not it enforced.
    pub reasons: Vec<String>,
}

impl HydraVerdict {
    /// Serialize as the JSON line a `hookprobe_manifest::trust::PostureSignal` deserializes from.
    /// Emits `provenance: "intel-only"` so the trust reconciler's enforcement gate treats it as a
    /// threat-intel signal that must be corroborated before it can quarantine.
    ///
    /// Requires a `mac`/`current_segment` the caller must already have (e.g. from a live ARP
    /// snapshot) — HYDRA itself never learns a MAC (flows are IP-keyed). When the caller does NOT
    /// yet have that mapping (the live pipeline case — see `hookprobe-hydra`'s `main.rs`), emit
    /// [`Self::to_intel_json`] instead and let the MAC resolution happen downstream, in
    /// `hookprobe_manifest::trust::intel_signals_from_hydra`.
    pub fn to_posture_json(&self, mac: &str, current_segment: &str) -> String {
        serde_json::json!({
            "mac": mac,
            "current_segment": current_segment,
            "risk": self.risk,
            "threat": self.threat.as_str(),
            "provenance": "intel-only",
            "corroborated": self.enforce,
            "reasons": self.reasons,
        })
        .to_string()
    }

    /// Serialize IP-keyed (no MAC yet) — the exact JSON line
    /// `hookprobe_manifest::trust::HydraDeviceVerdict` deserializes from (ADR 0023 task #19 / ADR
    /// 0027 Layer-1, 2026-07-16). This is HYDRA's live-pipeline output: `hookprobe-hydra`'s main.rs
    /// writes one of these per assessed device to `/var/lib/hookprobe/hydra-verdicts`
    /// (`--verdicts-out`), and the trust reconciler (`hookprobe-supervisor --hydra-verdicts`)
    /// resolves `device_ip` -> MAC via its own live ARP snapshot before folding it into posture.
    pub fn to_intel_json(&self) -> String {
        serde_json::json!({
            "device_ip": self.device_ip,
            "threat": self.threat.as_str(),
            "risk": self.risk,
            "enforce": self.enforce,
            "distinct_signals": self.distinct_signals,
            "score": self.score,
            "reasons": self.reasons,
        })
        .to_string()
    }
}

/// Filter a whole matcher pass's hits down to the ones that concern `device_ip` (it is either the
/// LAN device that connected out, or the LAN device an inbound indicator targeted, or the host a
/// file-hash IOC dropped on). The caller groups by device, then calls [`assess`] per device.
pub fn hits_for_device<'a>(all_hits: &'a [Hit], device_ip: &str) -> Vec<&'a Hit> {
    all_hits
        .iter()
        .filter(|h| h.src_ip == device_ip || h.dst_ip == device_ip)
        .collect()
}

/// The LAN device a single [`Hit`] concerns — the SAME attribution convention
/// `matcher::scan_flow_candidates`'s own doc comment establishes and its tests prove: an INBOUND
/// IP match (`matched_field == "src_ip"`, the indicator itself IS the attacker's address) puts the
/// LAN device in `dst_ip`; every other match (an OUTBOUND IP indicator on `dst_ip`, a domain/JA3/
/// JA4/JA4S/sha256 match) puts the LAN device in `src_ip`. Never re-invents the convention —
/// mirrors [`hits_for_device`]'s own src-OR-dst membership test, just inverted to derive the device
/// set instead of filtering by one already known.
pub fn device_ip_of(hit: &Hit) -> &str {
    if hit.matched_field == "src_ip" {
        &hit.dst_ip
    } else {
        &hit.src_ip
    }
}

/// Group a whole matcher pass's hits by the LAN device they concern (see [`device_ip_of`]) — the
/// live-pipeline counterpart to [`hits_for_device`]: instead of filtering by an already-known
/// device, this ENUMERATES every device this pass actually touched, so `hookprobe-hydra`'s main.rs
/// can call [`assess`] once per real device without needing a separate device inventory.
pub fn group_hits_by_device(hits: &[Hit]) -> std::collections::BTreeMap<String, Vec<&Hit>> {
    let mut m: std::collections::BTreeMap<String, Vec<&Hit>> = std::collections::BTreeMap::new();
    for h in hits {
        m.entry(device_ip_of(h).to_string()).or_default().push(h);
    }
    m
}

/// Shape a device's IOC hits (+ corroborating signals) into a bounded, corroboration-gated
/// [`HydraVerdict`]. `mgmt` is the same mgmt-allowlist policy the scan-responder uses; a protected
/// address is never enforced against.
pub fn assess(
    device_ip: &str,
    hits: &[&Hit],
    corrob: Corroboration,
    policy: &HydraTrustPolicy,
    mgmt: &ProtectPolicy,
) -> HydraVerdict {
    let mut score = 0.0f64;
    let mut signal_values: BTreeSet<&str> = BTreeSet::new();
    let mut reasons: Vec<String> = Vec::new();

    for h in hits {
        let ind = &h.indicator;
        // (1) active-only for enforcement.
        if policy.enforce_requires_active && !ind.active {
            reasons.push(format!(
                "documented (not enforced): {} ({}) is marked active=false — historical/offline",
                ind.value,
                ind.ioc_type.as_str()
            ));
            continue;
        }
        // (2) confidence floor.
        if ind.confidence < policy.min_enforce_confidence {
            reasons.push(format!(
                "documented (not enforced): {} ({}) confidence {:.2} < {:.2}",
                ind.value,
                ind.ioc_type.as_str(),
                ind.confidence,
                policy.min_enforce_confidence
            ));
            continue;
        }
        let contribution = policy.weight_for(ind.ioc_type) * ind.confidence;
        score += contribution;
        signal_values.insert(ind.value.as_str());
        reasons.push(format!(
            "IOC {} ({}, conf {:.2}) via {} → +{:.0}",
            ind.value,
            ind.ioc_type.as_str(),
            ind.confidence,
            h.matched_field,
            contribution
        ));
    }

    let mut distinct_signals = signal_values.len();
    if corrob.beaconing {
        score += policy.beacon_weight;
        distinct_signals += 1;
        reasons.push(format!("corroboration: C2 beaconing (rule 1000040) → +{:.0}", policy.beacon_weight));
    }
    // 2026-07-16 security-auditor RED fix: QSECBIT is a HOST-GLOBAL composite reading
    // (`EvidenceGraph::list_qsecbit`'s single `dev:self` row), applied IDENTICALLY to every device
    // assessed this pass (`hookprobe-hydra`'s main.rs) — it is NOT an independent per-device signal
    // and must NEVER satisfy `min_distinct_signals`. Doing so let a lone per-device IOC hit (one
    // distinct signal) plus an elevated global QSECBIT reading (bumping the count to two) reach
    // `Malicious`/`enforce=true` for EVERY device on the box the instant the host's own resilience
    // score dipped — collateral-quarantining legitimate customers whenever the host was under
    // attack, exactly the violation this module exists to prevent (see the module doc's rule #3).
    // It MAY still raise the SCORE (a genuinely degraded host is real signal), just never the
    // distinct-signal COUNT — only genuinely per-device corroboration (beaconing above, or a 2nd
    // distinct IOC) can do that.
    if corrob.qsecbit_anomaly >= policy.qsecbit_anomaly_min {
        let add = corrob.qsecbit_anomaly * policy.qsecbit_weight;
        score += add;
        reasons.push(format!(
            "QSECBIT anomaly {:.0} (>= {:.0}) → +{:.0} score (host-global — does NOT count toward the {} distinct-signal requirement)",
            corrob.qsecbit_anomaly, policy.qsecbit_anomaly_min, add, policy.min_distinct_signals
        ));
    }
    let score = score.min(100.0);

    // (4) mgmt-allowlist floor — never enforce against the operator's own management path.
    if let Some(reason) = protect_reason(device_ip, None, mgmt) {
        reasons.push(format!("mgmt floor: {reason}"));
        return HydraVerdict {
            device_ip: device_ip.to_string(),
            threat: HydraThreat::None,
            risk: 0.0,
            enforce: false,
            distinct_signals,
            score,
            reasons,
        };
    }

    // (3) + (5) corroboration-gated verdict; non-quarantine risk capped below the quarantine bar.
    let cap = (policy.quarantine_score - 1.0).max(0.0);
    let (threat, risk, enforce) =
        if distinct_signals >= policy.min_distinct_signals && score >= policy.quarantine_score {
            (HydraThreat::Malicious, score, true)
        } else if score >= policy.stepup_score {
            (HydraThreat::Suspicious, score.min(cap), false)
        } else {
            (HydraThreat::None, score.min(cap), false)
        };

    if threat != HydraThreat::Malicious && score >= policy.quarantine_score {
        reasons.push(format!(
            "NOT quarantined: score {:.0} >= {:.0} but only {} independent signal(s) < {} required — \
             documented + step-up, corroboration needed to quarantine",
            score, policy.quarantine_score, distinct_signals, policy.min_distinct_signals
        ));
    }

    HydraVerdict {
        device_ip: device_ip.to_string(),
        threat,
        risk,
        enforce,
        distinct_signals,
        score,
        reasons,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::feed::Indicator;

    fn ind(value: &str, ioc_type: IocType, confidence: f64, active: bool) -> Indicator {
        Indicator {
            value: value.to_string(),
            ioc_type,
            family: "test".to_string(),
            source: "test".to_string(),
            confidence,
            first_seen: String::new(),
            active,
            mitre: String::new(),
            tlp: String::new(),
            note: String::new(),
        }
    }

    fn hit(device_ip: &str, dst_ip: &str, ind: Indicator) -> Hit {
        Hit {
            ts: 1000.0,
            matched_field: "dst_ip",
            src_ip: device_ip.to_string(),
            dst_ip: dst_ip.to_string(),
            dst_port: 443,
            indicator: ind,
        }
    }

    fn mgmt() -> ProtectPolicy {
        ProtectPolicy::default() // protects 10.200.0.0/28 + 10.66.0.1
    }

    // (a) A single active:false historical IOC-IP hit → NOT quarantined (documented only).
    #[test]
    fn single_inactive_historical_ioc_ip_is_documented_never_enforced() {
        let dev = "10.66.0.50";
        let h = hit(dev, "162.243.103.246", ind("162.243.103.246", IocType::Ip, 0.9, false));
        let v = assess(dev, &[&h], Corroboration::default(), &HydraTrustPolicy::default(), &mgmt());
        assert_eq!(v.threat, HydraThreat::None, "an active:false indicator must never enforce");
        assert!(!v.enforce);
        assert_eq!(v.score, 0.0, "inactive indicator contributes zero enforcement score");
        assert!(v.reasons.iter().any(|r| r.contains("active=false")), "still documented, not silenced");
    }

    // (b) A single low-confidence active hit → not quarantined.
    #[test]
    fn single_low_confidence_hit_is_not_quarantined() {
        let dev = "10.66.0.51";
        let h = hit(dev, "203.0.113.4", ind("203.0.113.4", IocType::Ip, 0.3, true));
        let v = assess(dev, &[&h], Corroboration::default(), &HydraTrustPolicy::default(), &mgmt());
        assert_ne!(v.threat, HydraThreat::Malicious);
        assert!(!v.enforce);
        assert!(v.risk < HydraTrustPolicy::default().quarantine_score);
    }

    // The load-bearing case: a lone ACTIVE HIGH-confidence C2-IP hit (the exact defect repro:
    // one flow → one bundled C2 IOC IP) is ONE signal → suspicious/step-up, NEVER quarantine.
    #[test]
    fn single_active_high_confidence_ip_hit_steps_up_but_never_quarantines() {
        let dev = "10.66.0.52"; // could be a customer's phone that hit a shared/cloud IP
        let h = hit(dev, "50.16.16.211", ind("50.16.16.211", IocType::Ip, 0.9, true));
        let v = assess(dev, &[&h], Corroboration::default(), &HydraTrustPolicy::default(), &mgmt());
        assert_eq!(v.distinct_signals, 1);
        assert_eq!(v.threat, HydraThreat::Suspicious, "one high-conf IP hit → step-up, not malicious");
        assert!(!v.enforce, "a lone IOC-IP hit must never be quarantine-worthy");
        assert!(v.risk < HydraTrustPolicy::default().quarantine_score, "risk capped below the quarantine bar");
    }

    // 2026-07-16 security-auditor RED-fix regression (THE invariant test): a lone 0.9-confidence
    // active IP IOC hit (score 36, ONE distinct signal) PLUS an elevated HOST-GLOBAL QSECBIT
    // reading (score +54, clears qsecbit_anomaly_min) reaches an AGGREGATE score of 90 — well over
    // quarantine_score (70) — but must NOT reach Malicious/enforce, because the global QSECBIT
    // reading must NEVER satisfy `min_distinct_signals` (it is one `dev:self` reading applied
    // identically to every device this pass, not independent per-device corroboration). Before the
    // fix this was exactly the collateral-quarantine defect: EVERY device with even one low-signal
    // IOC hit would be quarantined the instant the host's own resilience score dipped.
    #[test]
    fn lone_ioc_hit_plus_global_qsecbit_never_reaches_malicious_or_enforce() {
        let dev = "10.66.0.90"; // a legit customer device that happened to touch one bundled IOC
        let h = hit(dev, "50.16.16.211", ind("50.16.16.211", IocType::Ip, 0.9, true));
        let policy = HydraTrustPolicy::default();
        let corrob = Corroboration { beaconing: false, qsecbit_anomaly: 90.0 }; // clears qsecbit_anomaly_min (50)
        let v = assess(dev, &[&h], corrob, &policy, &mgmt());
        assert_eq!(v.distinct_signals, 1, "the global QSECBIT reading must NOT bump the distinct-signal count");
        assert!(v.score >= policy.quarantine_score, "sanity: the aggregate score DOES cross the quarantine bar (36 IOC + 54 QSECBIT = 90)");
        assert_ne!(v.threat, HydraThreat::Malicious, "one distinct signal is not enough, regardless of score — must stay Suspicious/StepUp");
        assert_eq!(v.threat, HydraThreat::Suspicious);
        assert!(!v.enforce, "a lone IOC hit backstopped only by the host-global QSECBIT score must never enforce/quarantine a legit customer");
        assert!(v.risk < policy.quarantine_score, "risk stays capped below the quarantine bar");

        // And the exact downstream posture the trust reconciler would evaluate must be Observe/
        // StepUp, never Quarantine — round-trip through the SAME `to_intel_json`/`HydraDeviceVerdict`
        // shape `hookprobe_manifest::trust::intel_signals_from_hydra` consumes.
        let line = v.to_intel_json();
        let j: serde_json::Value = serde_json::from_str(&line).unwrap();
        assert_eq!(j["enforce"], false, "corroborated=false downstream — evaluate()'s gate must keep this device out of quarantine");
    }

    // A lone maximum-fidelity file-hash hit is still ONE signal → capped below quarantine.
    #[test]
    fn lone_high_fidelity_file_hash_still_needs_corroboration() {
        let dev = "10.66.0.53";
        let h = hit(dev, "deadbeef", ind("deadbeef", IocType::Sha256, 1.0, true));
        let v = assess(dev, &[&h], Corroboration::default(), &HydraTrustPolicy::default(), &mgmt());
        assert_eq!(v.distinct_signals, 1);
        assert_ne!(v.threat, HydraThreat::Malicious, "even a 1.0 malware-hash alone is not enough to quarantine");
        assert!(!v.enforce);
    }

    // (c) A genuine active high-confidence + CORROBORATED threat → STILL quarantined.
    #[test]
    fn active_high_confidence_ioc_plus_beaconing_still_quarantines() {
        let dev = "10.66.0.54";
        let h = hit(dev, "50.16.16.211", ind("50.16.16.211", IocType::Ip, 0.9, true));
        let corrob = Corroboration { beaconing: true, qsecbit_anomaly: 0.0 };
        let v = assess(dev, &[&h], corrob, &HydraTrustPolicy::default(), &mgmt());
        assert!(v.distinct_signals >= 2, "IOC + beaconing = two independent signals");
        assert_eq!(v.threat, HydraThreat::Malicious, "corroborated active threat still quarantines");
        assert!(v.enforce);
        assert!(v.risk >= HydraTrustPolicy::default().quarantine_score);
    }

    // Two distinct active IOC hits on the same device (IP + domain) also cross the bar.
    #[test]
    fn two_distinct_active_iocs_corroborate_and_quarantine() {
        let dev = "10.66.0.55";
        let h1 = hit(dev, "50.16.16.211", ind("50.16.16.211", IocType::Ip, 0.9, true));
        let mut h2 = hit(dev, "evil.example", ind("evil.example", IocType::Domain, 0.8, true));
        h2.matched_field = "sni";
        let v = assess(dev, &[&h1, &h2], Corroboration::default(), &HydraTrustPolicy::default(), &mgmt());
        assert_eq!(v.distinct_signals, 2);
        assert_eq!(v.threat, HydraThreat::Malicious);
        assert!(v.enforce);
    }

    // (d) The mgmt-allowlist floor holds — a mgmt/gateway address is never enforced against, even
    // with a fully corroborated malicious set.
    #[test]
    fn mgmt_floor_holds_even_for_a_corroborated_malicious_set() {
        let dev = "10.200.0.1"; // inside the protected mgmt subnet 10.200.0.0/28
        let h = hit(dev, "50.16.16.211", ind("50.16.16.211", IocType::Ip, 0.95, true));
        let corrob = Corroboration { beaconing: true, qsecbit_anomaly: 90.0 };
        let v = assess(dev, &[&h], corrob, &HydraTrustPolicy::default(), &mgmt());
        assert_eq!(v.threat, HydraThreat::None, "mgmt floor: never quarantine the management path");
        assert!(!v.enforce);
        assert!(v.reasons.iter().any(|r| r.contains("mgmt floor")));
    }

    // The gate is operator-tunable: lowering min_distinct_signals to 1 lets a lone hit quarantine
    // (proving it is policy, not a hardcoded magic constant).
    #[test]
    fn policy_is_tunable_not_hardcoded() {
        let dev = "10.66.0.56";
        let h = hit(dev, "50.16.16.211", ind("50.16.16.211", IocType::Ip, 1.0, true));
        let policy = HydraTrustPolicy { min_distinct_signals: 1, quarantine_score: 30.0, ..HydraTrustPolicy::default() };
        let v = assess(dev, &[&h], Corroboration::default(), &policy, &mgmt());
        assert_eq!(v.threat, HydraThreat::Malicious, "operator opted into single-signal quarantine");
    }

    // The posture JSON round-trips into the exact fields the trust reconciler reads.
    #[test]
    fn to_posture_json_emits_intel_only_provenance() {
        let dev = "10.66.0.57";
        let h = hit(dev, "50.16.16.211", ind("50.16.16.211", IocType::Ip, 0.9, true));
        let v = assess(dev, &[&h], Corroboration::default(), &HydraTrustPolicy::default(), &mgmt());
        let line = v.to_posture_json("aa:bb:cc:dd:ee:ff", "byod");
        let j: serde_json::Value = serde_json::from_str(&line).unwrap();
        assert_eq!(j["provenance"], "intel-only");
        assert_eq!(j["threat"], "suspicious");
        assert_eq!(j["corroborated"], false);
    }

    // ---- ADR 0023 task #19 / ADR 0027 Layer-1 live-pipeline wiring (2026-07-16) ----------------

    // The IP-keyed `to_intel_json` round-trips into the exact shape
    // `hookprobe_manifest::trust::HydraDeviceVerdict` deserializes from.
    #[test]
    fn to_intel_json_emits_device_ip_keyed_shape() {
        let dev = "10.66.0.58";
        let h = hit(dev, "50.16.16.211", ind("50.16.16.211", IocType::Ip, 0.9, true));
        let v = assess(dev, &[&h], Corroboration::default(), &HydraTrustPolicy::default(), &mgmt());
        let line = v.to_intel_json();
        let j: serde_json::Value = serde_json::from_str(&line).unwrap();
        assert_eq!(j["device_ip"], dev);
        assert_eq!(j["threat"], "suspicious");
        assert_eq!(j["enforce"], false);
        assert_eq!(j["distinct_signals"], 1);
    }

    // device_ip_of: outbound IP match (matched_field="dst_ip") attributes the LAN device as src_ip.
    #[test]
    fn device_ip_of_outbound_ip_match_is_src_ip() {
        let h = hit("10.66.0.5", "162.243.103.246", ind("162.243.103.246", IocType::Ip, 0.9, true));
        assert_eq!(device_ip_of(&h), "10.66.0.5");
    }

    // device_ip_of: inbound IP match (matched_field="src_ip", the indicator itself IS the
    // attacker) attributes the LAN device as dst_ip — the flipped case.
    #[test]
    fn device_ip_of_inbound_ip_match_is_dst_ip() {
        let mut h = hit("162.243.103.246", "10.66.0.9", ind("162.243.103.246", IocType::Ip, 0.9, true));
        h.matched_field = "src_ip";
        assert_eq!(device_ip_of(&h), "10.66.0.9");
    }

    // device_ip_of: a domain/JA3/JA4/JA4S/sha256 match always attributes the LAN device as src_ip
    // (the indicator itself never rides in src_ip for these match kinds).
    #[test]
    fn device_ip_of_domain_match_is_src_ip() {
        let mut h = hit("10.66.0.5", "evil.example", ind("evil.example", IocType::Domain, 0.8, true));
        h.matched_field = "sni";
        assert_eq!(device_ip_of(&h), "10.66.0.5");
    }

    // group_hits_by_device: two hits on two different devices (one outbound, one inbound) enumerate
    // into two distinct groups, each keyed by the correct LAN device — no device inventory needed.
    #[test]
    fn group_hits_by_device_enumerates_distinct_devices() {
        let h1 = hit("10.66.0.5", "162.243.103.246", ind("162.243.103.246", IocType::Ip, 0.9, true));
        let mut h2 = hit("162.243.103.246", "10.66.0.9", ind("162.243.103.246", IocType::Ip, 0.9, true));
        h2.matched_field = "src_ip";
        let hits = [h1, h2];
        let grouped = group_hits_by_device(&hits);
        assert_eq!(grouped.len(), 2);
        assert!(grouped.contains_key("10.66.0.5"));
        assert!(grouped.contains_key("10.66.0.9"));
        assert_eq!(grouped["10.66.0.5"].len(), 1);
    }

    // End-to-end: group_hits_by_device -> assess -> to_intel_json for a lone hit on one device
    // yields exactly the corroboration-gated, never-enforce shape the live pipeline depends on.
    #[test]
    fn live_pipeline_shape_single_hit_never_enforces() {
        let h = hit("10.66.0.59", "50.16.16.211", ind("50.16.16.211", IocType::Ip, 0.9, true));
        let hits = [h];
        let grouped = group_hits_by_device(&hits);
        assert_eq!(grouped.len(), 1);
        for (device_ip, hits) in &grouped {
            let v = assess(device_ip, hits, Corroboration::default(), &HydraTrustPolicy::default(), &mgmt());
            assert!(!v.enforce, "a lone hit must never be quarantine-worthy in the live pipeline either");
            let j: serde_json::Value = serde_json::from_str(&v.to_intel_json()).unwrap();
            assert_eq!(j["enforce"], false);
        }
    }
}
