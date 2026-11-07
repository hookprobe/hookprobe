//! Campaign orchestration (ADR 0020 D3 contract #5 / D5 two cadences). Ties `roe`/`target_guard`/
//! `limiter`/`kill_switch`/`findings` together: writes the pre-fire `attack_run` audit BEFORE any
//! probe runs, then (the caller's probes having produced `Finding`s) computes the Gate-R verdict and
//! overwrites the same record with the final result. This module contains NO send path itself --
//! it never touches a socket; it is pure bookkeeping around whatever probes the CLI chooses to run.
#![forbid(unsafe_code)]

use crate::findings::{write_json_overwrite, AttackRun, Cadence, Finding, Verdict};
use anyhow::Result;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

/// ISO-8601 UTC "now", second precision — shared by `AttackRun.ts` (here) and the CLI's
/// `Finding.ts` (`redteam-engine.rs`), so every timestamp this crate emits uses the SAME convention
/// `hookprobe-evidence`'s other lifecycle ingest paths already assume (ISO-8601 TEXT, not epoch
/// seconds — see that crate's schema doc comment).
pub fn now_iso8601() -> String {
    let secs = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
    // Minimal, dependency-free ISO-8601 (UTC, second precision) -- avoids pulling in `chrono` for
    // one timestamp format in a dependency-light security tool (D4's own rationale, applied here).
    humantime_like_utc(secs)
}

/// A tiny epoch->ISO-8601 UTC formatter with no external crate. Correct for all dates this tool
/// will ever produce (post-2020); leap seconds are not modeled (matches every other `ts` field in
/// this repo's evidence-graph JSON, which is also plain civil-calendar UTC).
fn humantime_like_utc(secs: u64) -> String {
    const SECS_PER_DAY: u64 = 86_400;
    let days = secs / SECS_PER_DAY;
    let rem = secs % SECS_PER_DAY;
    let (h, m, s) = (rem / 3600, (rem % 3600) / 60, rem % 60);
    // Civil-from-days (Howard Hinnant's algorithm) -- a well-known, dependency-free date algorithm.
    let z = days as i64 + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m_ = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m_ <= 2 { y + 1 } else { y };
    format!("{y:04}-{m_:02}-{d:02}T{h:02}:{m:02}:{s:02}Z")
}

pub struct Campaign {
    attack_run_path: PathBuf,
    findings_path: PathBuf,
}

impl Campaign {
    pub fn new(out_dir: &Path) -> Self {
        Self {
            attack_run_path: out_dir.join("attack_run.json"),
            findings_path: out_dir.join("findings.jsonl"),
        }
    }

    pub fn attack_run_path(&self) -> &Path {
        &self.attack_run_path
    }
    pub fn findings_path(&self) -> &Path {
        &self.findings_path
    }

    /// Contract #5: write the pre-fire audit BEFORE the first probe fires. Starts `Amber`
    /// ("in-progress, no verdict yet") -- a crash mid-campaign leaves this exact honest record
    /// rather than a fabricated pass.
    ///
    /// **Multi-probe campaigns:** a real campaign fires several probes, often as SEPARATE process
    /// invocations of the CLI (one per probe) sharing the same `--out` dir and the same `id` (the
    /// caller derives a stable campaign id up front, e.g. from the ROE hash + a fixed timestamp, and
    /// passes it to every probe invocation). `start()` truncates `findings.jsonl` ONLY when it is
    /// beginning a genuinely NEW campaign (no existing `attack_run.json`, or one with a DIFFERENT
    /// `id`) -- continuing an existing campaign (same `id`) leaves prior findings in place, so a
    /// second probe's invocation of `start()` never wipes the first probe's already-recorded
    /// finding. This is what makes "one campaign, many probes, many processes" safe.
    pub fn start(
        &self,
        id: String,
        roe_hash: String,
        cadence: Cadence,
        image_version: String,
        dut_targets: Vec<String>,
        operator: String,
    ) -> Result<AttackRun> {
        let is_new_campaign = match std::fs::read_to_string(&self.attack_run_path) {
            Ok(text) => match serde_json::from_str::<AttackRun>(&text) {
                Ok(prior) => prior.id != id,
                Err(_) => true, // unreadable/corrupt prior record -- treat as a fresh campaign
            },
            Err(_) => true, // no prior attack_run.json at all -- definitely fresh
        };
        let run = AttackRun {
            id,
            ts: now_iso8601(),
            roe_hash,
            cadence,
            image_version,
            dut_targets,
            operator,
            verdict: Verdict::Amber,
        };
        if is_new_campaign {
            // truncate any prior findings file for a fresh campaign -- never mix runs in one file.
            let _ = std::fs::remove_file(&self.findings_path);
        }
        write_json_overwrite(&self.attack_run_path, &run)?;
        Ok(run)
    }

    /// Record one finding as it is produced (appended immediately -- a crash mid-campaign still
    /// leaves every finding recorded so far, never silently lost).
    pub fn record_finding(&self, finding: &Finding) -> Result<()> {
        crate::findings::write_json_line(&self.findings_path, finding)
    }

    /// D5 verdict computation: RED iff any recorded finding `blocks_gate_r()`; AMBER iff any
    /// finding breached/inconclusive but none RED-class; else PASS. Overwrites the SAME attack_run
    /// record (contract #5's audit node gains its final verdict once every probe has run).
    pub fn finish(&self, mut run: AttackRun, findings: &[Finding]) -> Result<AttackRun> {
        let any_red = findings.iter().any(|f| f.blocks_gate_r());
        let any_amber = findings
            .iter()
            .any(|f| matches!(f.outcome, crate::findings::Outcome::Breached | crate::findings::Outcome::Inconclusive));
        run.verdict = if any_red {
            Verdict::Red
        } else if any_amber {
            Verdict::Amber
        } else {
            Verdict::Pass
        };
        write_json_overwrite(&self.attack_run_path, &run)?;
        Ok(run)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::findings::{Finding, Layer, Outcome, Severity};

    fn tmp_dir(name: &str) -> PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!("redteam-campaign-test-{name}-{}", std::process::id()));
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    #[test]
    fn start_writes_amber_before_any_probe() {
        let dir = tmp_dir("start");
        let c = Campaign::new(&dir);
        let run = c
            .start("ar:1".into(), "deadbeef".into(), Cadence::Smoke, "0.0.0-test".into(), vec!["napse".into()], "ci".into())
            .unwrap();
        assert_eq!(run.verdict, Verdict::Amber);
        assert!(c.attack_run_path().exists(), "the attack_run record must exist BEFORE any probe runs");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn finish_computes_pass_with_no_findings() {
        let dir = tmp_dir("pass");
        let c = Campaign::new(&dir);
        let run = c.start("ar:2".into(), "h".into(), Cadence::Smoke, "v".into(), vec![], "ci".into()).unwrap();
        let done = c.finish(run, &[]).unwrap();
        assert_eq!(done.verdict, Verdict::Pass);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn finish_computes_red_on_a_blocking_finding() {
        let dir = tmp_dir("red");
        let c = Campaign::new(&dir);
        let run = c.start("ar:3".into(), "h".into(), Cadence::Full, "v".into(), vec![], "ci".into()).unwrap();
        let f = Finding::new(
            "f:1".into(), run.id.clone(), "t".into(), Layer::L4, "syn-flood".into(), "napse-quarantine".into(),
            Outcome::Breached, Severity::Red, true, "e".into(), None, 1, None,
        );
        c.record_finding(&f).unwrap();
        let done = c.finish(run, &[f]).unwrap();
        assert_eq!(done.verdict, Verdict::Red);
        let text = std::fs::read_to_string(c.attack_run_path()).unwrap();
        assert!(text.contains("\"red\""));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn finish_computes_amber_on_a_nonred_breach() {
        let dir = tmp_dir("amber");
        let c = Campaign::new(&dir);
        let run = c.start("ar:4".into(), "h".into(), Cadence::Smoke, "v".into(), vec![], "ci".into()).unwrap();
        let f = Finding::new(
            "f:1".into(), run.id.clone(), "t".into(), Layer::L2, "mac-flood".into(), "napse-dpi".into(),
            Outcome::Breached, Severity::Amber, true, "e".into(), None, 1, None,
        );
        let done = c.finish(run, &[f]).unwrap();
        assert_eq!(done.verdict, Verdict::Amber);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn iso8601_formatter_roundtrips_a_known_date() {
        // 2026-07-05T00:00:00Z == 1783382400 (sanity: computed independently, checked here as a
        // fixed known-good vector so a future refactor of the formatter can't silently drift).
        assert_eq!(humantime_like_utc(1_783_209_600), "2026-07-05T00:00:00Z");
    }

    #[test]
    fn continuing_the_same_campaign_id_preserves_prior_findings() {
        // A real campaign fires several probes as SEPARATE process invocations sharing one `--out`
        // dir and one explicit campaign id -- start() must NOT wipe findings.jsonl on the second
        // invocation just because it's a new Campaign/process, only on a genuinely NEW id.
        let dir = tmp_dir("continue");
        let c = Campaign::new(&dir);
        let run1 = c.start("ar:shared".into(), "h".into(), Cadence::Smoke, "v".into(), vec![], "ci".into()).unwrap();
        let f1 = Finding::new(
            "f:1".into(), run1.id.clone(), "t".into(), Layer::L2, "mac-flood".into(), "napse-dpi".into(),
            Outcome::Withstood, Severity::Amber, true, "e".into(), None, 1, None,
        );
        c.record_finding(&f1).unwrap();

        // A SECOND `Campaign` (simulating a second process) with the SAME id must preserve f1.
        let c2 = Campaign::new(&dir);
        let run2 = c2.start("ar:shared".into(), "h".into(), Cadence::Smoke, "v".into(), vec![], "ci".into()).unwrap();
        assert_eq!(run2.id, run1.id);
        let f2 = Finding::new(
            "f:2".into(), run2.id.clone(), "t".into(), Layer::L4, "syn-scan".into(), "napse-dpi".into(),
            Outcome::Withstood, Severity::Amber, true, "e".into(), None, 2, None,
        );
        c2.record_finding(&f2).unwrap();

        let text = std::fs::read_to_string(c2.findings_path()).unwrap();
        assert_eq!(text.lines().count(), 2, "continuing the same campaign id must keep BOTH probes' findings");
        assert!(text.contains("\"f:1\"") && text.contains("\"f:2\""));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_new_campaign_id_truncates_a_stale_findings_file() {
        let dir = tmp_dir("fresh");
        let c = Campaign::new(&dir);
        let run1 = c.start("ar:old".into(), "h".into(), Cadence::Smoke, "v".into(), vec![], "ci".into()).unwrap();
        let f1 = Finding::new(
            "f:stale".into(), run1.id.clone(), "t".into(), Layer::L2, "mac-flood".into(), "napse-dpi".into(),
            Outcome::Withstood, Severity::Amber, true, "e".into(), None, 1, None,
        );
        c.record_finding(&f1).unwrap();

        // A DIFFERENT campaign id reusing the same --out dir must start fresh (no leftover finding).
        let run2 = c.start("ar:new".into(), "h".into(), Cadence::Smoke, "v".into(), vec![], "ci".into()).unwrap();
        assert_ne!(run2.id, run1.id);
        assert!(!c.findings_path().exists(), "a genuinely new campaign id must truncate stale findings");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
