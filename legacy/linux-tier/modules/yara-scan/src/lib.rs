//! # hookprobe-yara-scan — YARA file scanning (a first, honest engine)
//!
//! Detect workspace advertises "Suricata/Sigma/YARA/AI/Behavioral" engines
//! (`docs/architecture/MissionControl.md` §4) — YARA was mock. This crate is a real, first YARA scanning
//! engine: it loads bundled YARA rules with [`yara-x`](https://crates.io/crates/yara-x) (VirusTotal's
//! maintained, pure-Rust re-implementation of YARA — no `libyara`/C dependency) and scans a
//! configured set of host files, firing a real `detections` row through the SAME
//! `hookprobe_evidence::EvidenceGraph::ingest_detection` path every other engine in this workspace
//! already uses (no evidence-graph changes needed).
//!
//! ## Engine + arch honesty (state plainly — see `modules/yara-scan/module.yaml`'s doc header for
//! the full build-status record)
//!
//! `yara-x` is pure Rust (no C toolchain, unlike the historical `libyara`-wrapping `yara` crate),
//! which is why it was chosen over the C-wrapping alternative — it fits this workspace's
//! Rust/Wasm supply-chain posture (no new C dependency to audit/cross-compile/patch). It DOES pull
//! in its own internal `wasmtime`/`cranelift` (YARA-X compiles a rule's `condition:` to Wasm and
//! JITs it) — a heavier dependency tree than every other module in this workspace, but a real,
//! maintained one (see the crate's own docs: "already mature and stable... running in production
//! at VirusTotal... scanning billions of files"). This crate compiles+tests clean on
//! **amd64/x86_64-unknown-linux-gnu** (proven by this crate's own test suite). **arm64
//! (aarch64-unknown-linux-gnu) build status is NOT proven in this pass** — `yara-x`'s dependency
//! graph is pure Rust so it SHOULD cross-compile via the same aarch64-gnu target every other native
//! loader in this repo already uses (`modules/host-telemetry`/`modules/evidence`), but this has not
//! been verified end to end (time-boxed out of this v1's scope) — see `module.yaml`'s
//! `staging.build` doc comment for the exact, honest status and how to close the gap.
#![forbid(unsafe_code)]

use std::path::Path;

/// See `hookprobe_sigma::SIGMA_RULE_ID_BASE`'s doc for the numbering rationale — same idiom, a
/// DIFFERENT reserved band so Sigma's and YARA's derived rule_ids can never collide with each
/// other or with any other engine's hand-enumerated literal band (all < 10_000_000).
pub const YARA_RULE_ID_BASE: i64 = 3_000_000_000;

fn fnv1a(s: &str) -> u64 {
    // Same FNV-1a idiom as `hookprobe_sigma`/`hookprobe_evidence::sid` — duplicated rather than
    // shared (no inter-module dependency), matching the "same numbering space, no shared type"
    // idiom `crates/hookprobe-manifest/src/l2_responder.rs` already uses for its own duplicated
    // rule-id constants.
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in s.as_bytes() {
        h ^= *b as u64;
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    h
}

pub fn yara_rule_id(rule_name: &str) -> i64 {
    YARA_RULE_ID_BASE + (fnv1a(rule_name) & 0x0FFF_FFFF) as i64
}

pub const SEV_CRITICAL: i64 = 1;
pub const SEV_HIGH: i64 = 2;
pub const SEV_MEDIUM: i64 = 3;
pub const SEV_LOW: i64 = 4;
pub const SEV_INFO: i64 = 5;

fn severity_from_meta(s: &str) -> i64 {
    match s.to_ascii_lowercase().as_str() {
        "critical" => SEV_CRITICAL,
        "high" => SEV_HIGH,
        "medium" => SEV_MEDIUM,
        "low" => SEV_LOW,
        "informational" | "info" => SEV_INFO,
        _ => SEV_MEDIUM, // unrecognized/absent meta.severity -> documented default
    }
}

/// First `attack.tNNNN[.NNN]` TAG (case-insensitive) becomes the MITRE technique id — same
/// extraction discipline `hookprobe_sigma::extract_mitre` uses (never fabricated when absent).
fn extract_mitre<'a>(tags: impl Iterator<Item = &'a str>) -> String {
    for t in tags {
        let lc = t.to_ascii_lowercase();
        if let Some(rest) = lc.strip_prefix("attack.t") {
            if rest.chars().next().is_some_and(|c| c.is_ascii_digit()) {
                return format!("T{rest}").to_ascii_uppercase();
            }
        }
    }
    String::new()
}

/// One YARA rule match, ready to become a `detections` row via the SAME JSON schema
/// `hookprobe_evidence::EvidenceGraph::ingest_detection` already consumes.
#[derive(Debug, Clone, PartialEq)]
pub struct YaraFinding {
    pub rule_name: String,
    pub tags: Vec<String>,
    pub severity: i64,
    pub mitre: String,
    pub rule_id: i64,
}

/// Result of loading the bundled rule set — how many files/rules loaded vs skipped, and why.
/// Mirrors `hookprobe_sigma::load_bundled_rules`'s "skip with a reason, never silently drop"
/// contract, adapted to YARA-X's per-source-string compile granularity (one bundled `.yar` FILE
/// compiles independently, so a bad rule in one file never takes down every other bundled rule).
#[derive(Debug, Default)]
pub struct LoadOutcome {
    pub loaded_files: usize,
    pub loaded_rule_names: Vec<String>,
    pub skipped: Vec<(String, String)>,
}

pub struct YaraEngine {
    rulesets: Vec<(String, yara_x::Rules)>,
}

const BUNDLED: &[(&str, &str)] = &[
    ("eicar_test_string.yar", include_str!("../rules/eicar_test_string.yar")),
    ("hookprobe_test_signature.yar", include_str!("../rules/hookprobe_test_signature.yar")),
];

impl YaraEngine {
    /// Compile the bundled starter rules (see `modules/yara-scan/rules/*.yar`). Each bundled FILE
    /// compiles independently — a syntax error in one never blocks the others (skipped with the
    /// compiler's own reason, never silently dropped).
    pub fn load_bundled() -> (Self, LoadOutcome) {
        Self::load_from(BUNDLED)
    }

    fn load_from(sources: &[(&str, &str)]) -> (Self, LoadOutcome) {
        let mut rulesets = Vec::new();
        let mut outcome = LoadOutcome::default();
        for (label, text) in sources {
            let mut compiler = yara_x::Compiler::new();
            match compiler.add_source(*text) {
                Ok(_) => {
                    let rules = compiler.build();
                    for r in rules.iter() {
                        outcome.loaded_rule_names.push(r.identifier().to_string());
                    }
                    rulesets.push((label.to_string(), rules));
                    outcome.loaded_files += 1;
                }
                Err(e) => outcome.skipped.push((label.to_string(), e.to_string())),
            }
        }
        (Self { rulesets }, outcome)
    }

    /// Scan raw bytes against every loaded ruleset; returns every distinct rule that matched
    /// (a file can legitimately trip more than one rule).
    pub fn scan_bytes(&self, data: &[u8]) -> Vec<YaraFinding> {
        let mut out = Vec::new();
        for (_, rules) in &self.rulesets {
            let mut scanner = yara_x::Scanner::new(rules);
            let Ok(results) = scanner.scan(data) else { continue };
            for m in results.matching_rules() {
                let tags: Vec<String> = m.tags().map(|t| t.identifier().to_string()).collect();
                let severity = m
                    .metadata()
                    .into_iter()
                    .find(|(k, _)| *k == "severity")
                    .and_then(|(_, v)| match v {
                        yara_x::MetaValue::String(s) => Some(severity_from_meta(s)),
                        _ => None,
                    })
                    .unwrap_or(SEV_MEDIUM);
                let mitre = extract_mitre(tags.iter().map(|s| s.as_str()));
                out.push(YaraFinding {
                    rule_name: m.identifier().to_string(),
                    tags,
                    severity,
                    mitre,
                    rule_id: yara_rule_id(m.identifier()),
                });
            }
        }
        out
    }

    /// Scan one file from disk. `Err` is an I/O error (e.g. permission denied, vanished between
    /// enumeration and read) — the caller's job is to log-and-continue, never abort the whole scan
    /// sweep over one unreadable file.
    pub fn scan_file(&self, path: &Path) -> std::io::Result<Vec<YaraFinding>> {
        let data = std::fs::read(path)?;
        Ok(self.scan_bytes(&data))
    }

    pub fn rule_count(&self) -> usize {
        self.rulesets.iter().map(|(_, r)| r.iter().count()).sum()
    }
}

/// Serialize one finding into the SAME JSON detection schema every other engine in this workspace
/// emits (`rule_id`/`rule_msg`/`category`/`severity`/`mitre`/`src_ip`/`dst_ip`/`dst_port`/
/// `confidence`) — `src_ip` carries the DEVICE's own identity (a host-origin finding has no
/// network endpoints, same convention `hookprobe_evidence::insert_host_detection` documents for
/// host-EDR detections).
pub fn finding_to_alert_json(finding: &YaraFinding, device_ip: &str, file_path: &str, ts: f64) -> String {
    // No native YARA "confidence" signal (a YARA match is boolean, not probabilistic) — a fixed,
    // documented value per severity tier mirrors `hookprobe_sigma::Level::confidence`'s own stated
    // heuristic (never fabricated as a false precision).
    let confidence = match finding.severity {
        SEV_CRITICAL => 0.90,
        SEV_HIGH => 0.75,
        SEV_MEDIUM => 0.60,
        SEV_LOW => 0.45,
        _ => 0.30,
    };
    serde_json::json!({
        "ts": ts,
        "rule_id": finding.rule_id,
        "rule_msg": format!(
            "[YARA] rule={} tags=[{}] file={}",
            finding.rule_name,
            finding.tags.join(","),
            file_path,
        ),
        "category": "yara_match",
        "severity": finding.severity,
        "mitre": finding.mitre,
        "src_ip": device_ip,
        "dst_ip": "",
        "dst_port": 0,
        "confidence": confidence,
    })
    .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bundled_rules_load_with_no_skips() {
        let (engine, outcome) = YaraEngine::load_bundled();
        assert_eq!(outcome.loaded_files, 2, "both bundled .yar files should compile cleanly");
        assert!(outcome.skipped.is_empty(), "unexpected skip(s): {:?}", outcome.skipped);
        assert_eq!(engine.rule_count(), 2);
        assert!(outcome.loaded_rule_names.contains(&"Eicar_Test_String".to_string()));
        assert!(outcome.loaded_rule_names.contains(&"HookProbe_Yara_Test_Signature".to_string()));
    }

    #[test]
    fn eicar_string_fires_the_bundled_rule() {
        let (engine, _) = YaraEngine::load_bundled();
        let eicar = br#"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"#;
        let findings = engine.scan_bytes(eicar);
        assert!(!findings.is_empty(), "expected the EICAR test rule to fire");
        assert!(findings.iter().any(|f| f.rule_name == "Eicar_Test_String"));
    }

    #[test]
    fn hookprobe_test_marker_fires_its_own_rule() {
        let (engine, _) = YaraEngine::load_bundled();
        let content = b"some file content HOOKPROBE-YARA-TEST-SIGNATURE-88f3c2 trailing bytes";
        let findings = engine.scan_bytes(content);
        assert!(findings.iter().any(|f| f.rule_name == "HookProbe_Yara_Test_Signature"));
    }

    #[test]
    fn benign_content_never_fires_bundled_rules() {
        let (engine, _) = YaraEngine::load_bundled();
        let findings = engine.scan_bytes(b"just an ordinary text file, nothing suspicious here");
        assert!(findings.is_empty());
    }

    #[test]
    fn scan_file_reads_and_scans_a_real_file() {
        let (engine, _) = YaraEngine::load_bundled();
        let dir = std::env::temp_dir();
        let path = dir.join(format!("hookprobe-yara-test-{}.txt", std::process::id()));
        std::fs::write(&path, b"marker HOOKPROBE-YARA-TEST-SIGNATURE-88f3c2 here").unwrap();
        let findings = engine.scan_file(&path).unwrap();
        let _ = std::fs::remove_file(&path);
        assert!(findings.iter().any(|f| f.rule_name == "HookProbe_Yara_Test_Signature"));
    }

    #[test]
    fn a_bad_rule_file_is_skipped_without_blocking_the_others() {
        let sources: &[(&str, &str)] = &[
            ("good.yar", "rule Good { strings: $a = \"hello\" condition: $a }"),
            ("bad.yar", "rule Bad { this is not valid yara syntax !!! }"),
        ];
        let (engine, outcome) = YaraEngine::load_from(sources);
        assert_eq!(outcome.loaded_files, 1);
        assert_eq!(outcome.skipped.len(), 1);
        assert_eq!(outcome.skipped[0].0, "bad.yar");
        assert!(!engine.scan_bytes(b"hello world").is_empty());
    }

    #[test]
    fn detection_json_carries_rule_name_and_file_path() {
        let finding = YaraFinding {
            rule_name: "Eicar_Test_String".to_string(),
            tags: vec!["test".to_string(), "benign".to_string()],
            severity: SEV_INFO,
            mitre: String::new(),
            rule_id: yara_rule_id("Eicar_Test_String"),
        };
        let json = finding_to_alert_json(&finding, "127.0.0.1", "/tmp/sample.txt", 42.0);
        assert!(json.contains("\"category\":\"yara_match\""));
        assert!(json.contains("Eicar_Test_String"));
        assert!(json.contains("/tmp/sample.txt"));
        assert!(json.contains("\"src_ip\":\"127.0.0.1\""));
    }

    #[test]
    fn rule_id_is_deterministic_and_in_reserved_band() {
        let a = yara_rule_id("Eicar_Test_String");
        let b = yara_rule_id("Eicar_Test_String");
        assert_eq!(a, b);
        assert!(a >= YARA_RULE_ID_BASE);
        assert!(a > 10_000_000);
        // A distinct, non-overlapping literal band from Sigma's own (2_000_000_000) — documented,
        // not derived (no cross-crate dependency between the two engines).
        assert_ne!(YARA_RULE_ID_BASE, 2_000_000_000);
    }
}
