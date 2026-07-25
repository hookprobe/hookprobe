//! Detect-workspace engine status (`GET /api/engines`) — ends part of the mock era on
//! `ui/src/store/detectMock.ts`'s hard-coded `ENGINES` array (`docs/MissionControl.md` §4:
//! "Suricata/Sigma/YARA/AI/Behavioral" engine row).
//!
//! **Only Sigma and YARA go real here** (ADR 0026 — this is exactly what those two engines'
//! status files exist for: `modules/sigma`'s `hookprobe-sigma` writes
//! `/var/lib/hookprobe/sigma-status.json`; `modules/yara-scan`'s `hookprobe-yara-scan` writes
//! `/var/lib/hookprobe/yara-status.json`). Suricata/AI Detection/Behavioral have NO backing engine
//! in this workspace yet — this endpoint does not fabricate numbers for them; each entry below
//! carries `"source": "real"` or `"source": "mock"` so the UI can render an honest per-engine
//! label instead of a single blanket "· mock" on the whole panel.
//!
//! Reads plain JSON status files off disk — never touches the evidence DB (this is operational
//! engine state, not a graph query) — same "read a small file directly" pattern
//! `manifest_view::manifest_view_json` already uses for the Platform Manifest. A missing/
//! unparsable status file (engine never run yet, or the data partition not mounted) is reported
//! honestly as `"status": "not_yet_run"` with `loaded_rules: null` — NEVER a fabricated zero or a
//! stale cached number.
use serde_json::{json, Value};
use std::path::Path;

/// One real, on-disk engine status file → its Detect-panel entry. `path` is the file
/// `hookprobe-sigma`/`hookprobe-yara-scan` writes (see each crate's `main.rs` doc comment).
fn real_engine_entry(name: &str, kind: &str, path: &Path) -> Value {
    let parsed: Option<Value> = std::fs::read_to_string(path).ok().and_then(|s| serde_json::from_str(&s).ok());
    let Some(v) = parsed else {
        return json!({
            "name": name,
            "kind": kind,
            "source": "real",
            "status": "not_yet_run",
            "loaded_rules": Value::Null,
            "skipped_rules": Value::Null,
            "hits": Value::Null,
            "last_run_ts": Value::Null,
        });
    };
    // Sigma's status carries `alerts_emitted`+`last_event_ts`; YARA's carries `matches`+
    // `last_scan_ts` — normalize both onto the same `hits`/`last_run_ts` field names so the UI
    // has one shape to render regardless of which engine produced it.
    let hits = v.get("alerts_emitted").or_else(|| v.get("matches")).cloned().unwrap_or(Value::Null);
    let last_run_ts = v.get("last_event_ts").or_else(|| v.get("last_scan_ts")).cloned().unwrap_or(Value::Null);
    json!({
        "name": name,
        "kind": kind,
        "source": "real",
        "status": "active",
        "loaded_rules": v.get("loaded_rules").cloned().unwrap_or(Value::Null),
        "skipped_rules": v.get("skipped_rules").cloned().unwrap_or(Value::Null),
        "hits": hits,
        "last_run_ts": last_run_ts,
    })
}

/// A NOT-yet-real engine (no backing status file exists in this workspace at all) — kept in the
/// response so the Detect panel's row count/order doesn't change, but honestly labelled `"source":
/// "mock"` with `null` numbers rather than a fabricated rule count. `hits`/`kind` are left `null`
/// too — this crate does not know the real numbers so it does not print pretend ones; the UI is
/// free to keep showing its OWN static placeholder for anything still `"source": "mock"`.
fn mock_engine_entry(name: &str) -> Value {
    json!({
        "name": name,
        "kind": Value::Null,
        "source": "mock",
        "status": "unknown",
        "loaded_rules": Value::Null,
        "skipped_rules": Value::Null,
        "hits": Value::Null,
        "last_run_ts": Value::Null,
    })
}

/// `data_dir` is the directory the evidence DB lives in (`/var/lib/hookprobe` on a real device) —
/// `sigma-status.json`/`yara-status.json` are siblings of `evidence.db` by convention (same dir
/// every other stream/status file in this OS lives in).
pub fn engines_json(data_dir: &Path) -> String {
    let engines = vec![
        real_engine_entry("Sigma", "Log rules", &data_dir.join("sigma-status.json")),
        real_engine_entry("YARA", "File patterns", &data_dir.join("yara-status.json")),
        mock_engine_entry("Suricata"),
        mock_engine_entry("AI Detection"),
        mock_engine_entry("Behavioral"),
    ];
    json!({ "engines": engines }).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    /// Hand-rolled temp-dir helper (no `tempfile` dev-dependency needed) — same
    /// `std::env::temp_dir().join(format!(...))` idiom `lib.rs`'s own tests already use for a
    /// scratch evidence DB path, applied here to a scratch directory instead of a single file.
    struct ScratchDir(std::path::PathBuf);
    impl ScratchDir {
        fn new(tag: &str) -> Self {
            let p = std::env::temp_dir().join(format!("hp-api-engine-status-test-{tag}-{}", std::process::id()));
            std::fs::create_dir_all(&p).expect("create scratch dir");
            Self(p)
        }
        fn path(&self) -> &std::path::Path {
            &self.0
        }
    }
    impl Drop for ScratchDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn missing_status_files_report_not_yet_run_never_fabricated() {
        let dir = ScratchDir::new("missing");
        let s = engines_json(dir.path());
        let v: Value = serde_json::from_str(&s).unwrap();
        let engines = v["engines"].as_array().unwrap();
        let sigma = engines.iter().find(|e| e["name"] == "Sigma").unwrap();
        assert_eq!(sigma["source"], "real");
        assert_eq!(sigma["status"], "not_yet_run");
        assert!(sigma["loaded_rules"].is_null());
    }

    #[test]
    fn real_sigma_status_file_is_reflected_honestly() {
        let dir = ScratchDir::new("sigma-real");
        let path = dir.path().join("sigma-status.json");
        let mut f = std::fs::File::create(&path).unwrap();
        write!(
            f,
            r#"{{"loaded_rules":5,"skipped_rules":1,"events_processed":42,"alerts_emitted":3,"last_event_ts":100.5}}"#
        )
        .unwrap();
        let s = engines_json(dir.path());
        let v: Value = serde_json::from_str(&s).unwrap();
        let engines = v["engines"].as_array().unwrap();
        let sigma = engines.iter().find(|e| e["name"] == "Sigma").unwrap();
        assert_eq!(sigma["status"], "active");
        assert_eq!(sigma["loaded_rules"], 5);
        assert_eq!(sigma["skipped_rules"], 1);
        assert_eq!(sigma["hits"], 3);
        assert_eq!(sigma["last_run_ts"], 100.5);
    }

    #[test]
    fn real_yara_status_file_normalizes_matches_and_last_scan_ts() {
        let dir = ScratchDir::new("yara-real");
        let path = dir.path().join("yara-status.json");
        let mut f = std::fs::File::create(&path).unwrap();
        write!(f, r#"{{"loaded_rules":2,"skipped_rules":0,"matches":7,"last_scan_ts":200.0}}"#).unwrap();
        let s = engines_json(dir.path());
        let v: Value = serde_json::from_str(&s).unwrap();
        let engines = v["engines"].as_array().unwrap();
        let yara = engines.iter().find(|e| e["name"] == "YARA").unwrap();
        assert_eq!(yara["status"], "active");
        assert_eq!(yara["loaded_rules"], 2);
        assert_eq!(yara["hits"], 7);
        assert_eq!(yara["last_run_ts"], 200.0);
    }

    #[test]
    fn suricata_ai_behavioral_stay_honestly_labelled_mock() {
        let dir = ScratchDir::new("mock-labels");
        let s = engines_json(dir.path());
        let v: Value = serde_json::from_str(&s).unwrap();
        let engines = v["engines"].as_array().unwrap();
        for name in ["Suricata", "AI Detection", "Behavioral"] {
            let e = engines.iter().find(|e| e["name"] == name).unwrap();
            assert_eq!(e["source"], "mock", "{name} must stay labelled mock — no backing engine exists");
            assert!(e["loaded_rules"].is_null(), "{name} must never carry a fabricated rule count");
        }
    }

    #[test]
    fn malformed_status_file_is_treated_as_not_yet_run_not_a_crash() {
        let dir = ScratchDir::new("malformed");
        std::fs::write(dir.path().join("sigma-status.json"), b"not valid json{{{").unwrap();
        let s = engines_json(dir.path());
        let v: Value = serde_json::from_str(&s).unwrap();
        let sigma = v["engines"].as_array().unwrap().iter().find(|e| e["name"] == "Sigma").unwrap();
        assert_eq!(sigma["status"], "not_yet_run");
    }
}
