//! Finding / attack_run JSON shapes (ADR 0020 D6) — the ONLY output this engine ever produces. No
//! blocklist write, no quarantine call, no enforcement action anywhere in this module or its
//! callers (condition 4 / the ADR's NO-GO ruling on the blocklist loop): a campaign emits
//! `attack_run`/`finding` JSON, full stop. `hookprobe-evidence` ingests these files exactly like it
//! ingests `release.json`/`beacon.json` (see `crates/hookprobe-evidence/src/lib.rs`'s
//! `ingest_attack_run`/`ingest_finding`) -- this crate has NO dependency on hookprobe-evidence and
//! never touches the evidence.db directly, keeping the two trust boundaries decoupled (D4's
//! dependency-light rationale).
#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};
use std::io::Write;
use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Cadence {
    Smoke,
    Full,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Verdict {
    Pass,
    Amber,
    Red,
}

/// The pre-fire audit node (ADR 0020 D3 contract #5): written BEFORE the first probe fires, so
/// there is no un-audited campaign, ever. `verdict` starts `Amber` ("in progress" -- no result yet)
/// and the CALLER overwrites the same file with the final verdict once every probe has run; a
/// crash mid-campaign therefore leaves an honest "amber, in-progress" record, never a fabricated
/// pass.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackRun {
    pub id: String,
    pub ts: String,
    pub roe_hash: String,
    pub cadence: Cadence,
    pub image_version: String,
    pub dut_targets: Vec<String>,
    pub operator: String,
    pub verdict: Verdict,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Layer {
    L1,
    L2,
    L3,
    L4,
    L5,
    L6,
    L7,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Outcome {
    Withstood,
    Breached,
    Inconclusive,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Red,
    Amber,
    Info,
}

/// One probe outcome (ADR 0020 D6). `verified_fired=false` MUST always pair with
/// `outcome=Inconclusive` -- `Finding::new` enforces this in code (the loop-closing principle: an
/// attack is only "withstood" if we OBSERVED the defense fire, never merely that the attacker
/// failed for an unknown reason).
#[derive(Debug, Clone, Serialize)]
pub struct Finding {
    pub id: String,
    pub attack_run: String,
    pub ts: String,
    pub layer: Layer,
    pub probe: String,
    pub target_component: String,
    pub outcome: Outcome,
    pub severity: Severity,
    pub verified_fired: bool,
    pub evidence_ref: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mitre_attck: Option<String>,
    pub repro_seed: u64,
    /// Optional ADR this finding validates (D6 `validates` edge) -- e.g. "0018".
    #[serde(skip_serializing_if = "Option::is_none")]
    pub validates_adr: Option<String>,
}

impl Finding {
    /// Construct a finding, enforcing the D6 honesty invariant in code (not just documentation):
    /// `verified_fired=false` can only ever produce `Outcome::Inconclusive`, regardless of what the
    /// caller *wanted* to claim -- a defense we could not confirm fired is never reported withstood.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        id: String,
        attack_run: String,
        ts: String,
        layer: Layer,
        probe: String,
        target_component: String,
        claimed_outcome: Outcome,
        severity: Severity,
        verified_fired: bool,
        evidence_ref: String,
        mitre_attck: Option<String>,
        repro_seed: u64,
        validates_adr: Option<String>,
    ) -> Self {
        let outcome = if verified_fired { claimed_outcome } else { Outcome::Inconclusive };
        Self {
            id,
            attack_run,
            ts,
            layer,
            probe,
            target_component,
            outcome,
            severity,
            verified_fired,
            evidence_ref,
            mitre_attck,
            repro_seed,
            validates_adr,
        }
    }

    /// RED-class gate semantics (ADR 0020 D5): a finding blocks Gate R iff it is severity=Red AND
    /// its outcome is NOT `Withstood` -- i.e. `Breached` OR `Inconclusive` (an unconfirmed RED-class
    /// probe fails Gate R closed, per D6's honesty rule: "we do not ship a defense we could not
    /// confirm fired").
    pub fn blocks_gate_r(&self) -> bool {
        self.severity == Severity::Red && self.outcome != Outcome::Withstood
    }
}

pub fn write_json_line(path: &Path, value: &impl Serialize) -> anyhow::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let mut f = std::fs::OpenOptions::new().create(true).append(true).open(path)?;
    let line = serde_json::to_string(value)?;
    writeln!(f, "{line}")?;
    Ok(())
}

/// Overwrite (not append) -- used for the `attack_run` record, which is updated in place (Amber ->
/// final verdict) rather than accumulated as a log.
pub fn write_json_overwrite(path: &Path, value: &impl Serialize) -> anyhow::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let text = serde_json::to_string_pretty(value)?;
    std::fs::write(path, text)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unverified_fire_is_always_inconclusive_never_withstood() {
        let f = Finding::new(
            "f:1".into(), "ar:1".into(), "2026-07-05T00:00:00Z".into(),
            Layer::L4, "syn-flood".into(), "napse-quarantine".into(),
            Outcome::Withstood, // caller CLAIMED withstood...
            Severity::Red, false /* ...but we never observed it fire */,
            "".into(), None, 1, None,
        );
        assert_eq!(f.outcome, Outcome::Inconclusive, "verified_fired=false must force Inconclusive");
        assert!(f.blocks_gate_r(), "a RED-class inconclusive finding must block Gate R");
    }

    #[test]
    fn verified_withstood_does_not_block() {
        let f = Finding::new(
            "f:2".into(), "ar:1".into(), "2026-07-05T00:00:00Z".into(),
            Layer::L4, "syn-flood".into(), "napse-quarantine".into(),
            Outcome::Withstood, Severity::Red, true,
            "resp:xyz".into(), None, 2, Some("0018".into()),
        );
        assert!(!f.blocks_gate_r());
    }

    #[test]
    fn amber_breach_never_blocks_gate_r() {
        let f = Finding::new(
            "f:3".into(), "ar:1".into(), "2026-07-05T00:00:00Z".into(),
            Layer::L2, "mac-flood".into(), "napse-dpi".into(),
            Outcome::Breached, Severity::Amber, true,
            "det:abc".into(), None, 3, None,
        );
        assert!(!f.blocks_gate_r(), "AMBER never auto-blocks (operator decides, ADR 0011 D3)");
    }

    #[test]
    fn red_breach_blocks() {
        let f = Finding::new(
            "f:4".into(), "ar:1".into(), "2026-07-05T00:00:00Z".into(),
            Layer::L4, "wan-ingress-spoof".into(), "scan_responder".into(),
            Outcome::Breached, Severity::Red, true,
            "resp:def".into(), Some("T1595.001".into()), 4, Some("0018".into()),
        );
        assert!(f.blocks_gate_r());
    }

    #[test]
    fn writes_and_appends_json_lines() {
        let mut p = std::env::temp_dir();
        p.push(format!("redteam-findings-test-{}.jsonl", std::process::id()));
        let _ = std::fs::remove_file(&p);
        let f1 = Finding::new(
            "f:a".into(), "ar:1".into(), "t".into(), Layer::L3, "p".into(), "c".into(),
            Outcome::Withstood, Severity::Info, true, "e".into(), None, 1, None,
        );
        write_json_line(&p, &f1).unwrap();
        write_json_line(&p, &f1).unwrap();
        let text = std::fs::read_to_string(&p).unwrap();
        assert_eq!(text.lines().count(), 2);
        let _ = std::fs::remove_file(&p);
    }
}
