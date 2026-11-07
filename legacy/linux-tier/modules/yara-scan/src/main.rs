//! `hookprobe-yara-scan` — one scan sweep over a configured file set, then exit.
//!
//! Run periodically by `hookprobe-yara-scan.timer` (same "oneshot binary + timer" shape as
//! `hookprobe-evidence-prune.timer` — file scanning is I/O/CPU-heavy, so this is deliberately NOT
//! a continuous service like `napse`/`hookprobe-sigma`; a bounded sweep respects the edge resource
//! budget (ADR 0003) instead of competing with the live detection path).
//!
//! ## Scan set (v1 — a small, tractable, honest scope)
//!
//! Defaults to the same "world-writable/staging" paths `hookprobe_evidence::host_edr`'s
//! `EXEC_FROM_WRITABLE_PATH` check already watches (`/tmp`, `/var/tmp`, `/dev/shm`) — where a
//! dropped payload is staged before execution, the highest-value place to catch one with a
//! signature match. Override with `HOOKPROBE_YARA_SCAN_PATHS` (colon-separated). A full host
//! filesystem sweep is explicitly OUT of this v1's scope (CPU/IO budget on Pi-class hardware) —
//! this is a stated, tractable v1 limit, not a claim of comprehensive on-disk AV coverage.
//!
//! ## Output protocol
//!
//! One JSON alert per line on stdout, in the SAME schema
//! `hookprobe_evidence::EvidenceGraph::ingest_detection` already consumes — the unit appends it to
//! `/var/lib/hookprobe/events`, identical to every other engine's alert stream.
//!
//! ## Status file (the Detect workspace's real "YARA: N rules loaded, last scan …" surface)
//!
//! Writes `/var/lib/hookprobe/yara-status.json` (override via `HOOKPROBE_YARA_STATUS_PATH`) once
//! per sweep — `{"loaded_rules","skipped_rules","skipped","files_scanned","files_skipped_too_large",
//! "matches","scan_paths","arch","arch_proven","last_scan_ts"}`. `crates/hookprobe-api`'s
//! `/api/engines` reads this file.

use hookprobe_yara_scan::{finding_to_alert_json, YaraEngine};
use std::io::Write;
use std::path::{Path, PathBuf};

fn now_ts() -> f64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0)
}

fn scan_paths() -> Vec<PathBuf> {
    std::env::var("HOOKPROBE_YARA_SCAN_PATHS")
        .unwrap_or_else(|_| "/tmp:/var/tmp:/dev/shm".to_string())
        .split(':')
        .filter(|s| !s.is_empty())
        .map(PathBuf::from)
        .collect()
}

fn max_files() -> usize {
    std::env::var("HOOKPROBE_YARA_MAX_FILES").ok().and_then(|s| s.parse().ok()).unwrap_or(2_000)
}

fn max_file_bytes() -> u64 {
    std::env::var("HOOKPROBE_YARA_MAX_FILE_BYTES").ok().and_then(|s| s.parse().ok()).unwrap_or(20_000_000)
}

fn max_depth() -> usize {
    std::env::var("HOOKPROBE_YARA_MAX_DEPTH").ok().and_then(|s| s.parse().ok()).unwrap_or(6)
}

fn status_path() -> PathBuf {
    std::env::var("HOOKPROBE_YARA_STATUS_PATH")
        .unwrap_or_else(|_| "/var/lib/hookprobe/yara-status.json".to_string())
        .into()
}

/// Bounded, symlink-safe recursive walk. Regular files only (never follows symlinks — avoids a
/// loop and avoids scanning something outside the declared scan set via a crafted link); stops
/// once `budget` files have been ENUMERATED (not necessarily scanned — oversized files are
/// skipped but still count against the budget, so a directory full of huge files can't make the
/// walker spin forever).
fn walk(root: &Path, depth: usize, max_depth: usize, budget: &mut usize, out: &mut Vec<PathBuf>) {
    if *budget == 0 || depth > max_depth {
        return;
    }
    let entries = match std::fs::read_dir(root) {
        Ok(e) => e,
        Err(_) => return, // missing/unreadable dir -> skip silently, not fatal to the sweep
    };
    for entry in entries.flatten() {
        if *budget == 0 {
            return;
        }
        let path = entry.path();
        let file_type = match entry.file_type() {
            Ok(t) => t,
            Err(_) => continue,
        };
        if file_type.is_symlink() {
            continue; // never follow -- avoids symlink loops / escaping the declared scan set
        }
        if file_type.is_dir() {
            walk(&path, depth + 1, max_depth, budget, out);
        } else if file_type.is_file() {
            out.push(path);
            *budget -= 1;
        }
    }
}

fn main() {
    let started_ts = now_ts();
    let (engine, load_outcome) = YaraEngine::load_bundled();
    for (name, reason) in &load_outcome.skipped {
        eprintln!("[hookprobe-yara-scan] SKIPPING rule file '{name}': {reason}");
    }
    eprintln!(
        "[hookprobe-yara-scan] loaded {} rule(s) from {} file(s), skipped {}",
        load_outcome.loaded_rule_names.len(),
        load_outcome.loaded_files,
        load_outcome.skipped.len()
    );

    let device_ip = std::env::var("HOOKPROBE_DEVICE_IP").unwrap_or_else(|_| "127.0.0.1".to_string());
    let paths = scan_paths();
    let depth_cap = max_depth();
    let mut budget = max_files();
    let size_cap = max_file_bytes();

    let mut candidates = Vec::new();
    for root in &paths {
        walk(root, 0, depth_cap, &mut budget, &mut candidates);
    }

    let stdout = std::io::stdout();
    let mut out = std::io::LineWriter::new(stdout.lock());

    let mut files_scanned = 0u64;
    let mut files_skipped_too_large = 0u64;
    let mut files_unreadable = 0u64;
    let mut matches = 0u64;

    for path in &candidates {
        let meta = match std::fs::symlink_metadata(path) {
            Ok(m) => m,
            Err(_) => {
                files_unreadable += 1;
                continue;
            }
        };
        if meta.len() > size_cap {
            files_skipped_too_large += 1;
            continue;
        }
        let findings = match engine.scan_file(path) {
            Ok(f) => f,
            Err(_) => {
                files_unreadable += 1;
                continue;
            }
        };
        files_scanned += 1;
        for finding in &findings {
            let ts = now_ts();
            let line = finding_to_alert_json(finding, &device_ip, &path.to_string_lossy(), ts);
            if writeln!(out, "{line}").is_err() {
                break;
            }
            matches += 1;
        }
    }
    let _ = out.flush();

    let arch = std::env::consts::ARCH;
    // Honest, not aspirational: this build's OWN process reports the arch it is actually running
    // as; `arch_proven` records whether THIS specific arch has been exercised by this crate's own
    // test suite in CI (amd64 today — see the module doc + module.yaml for the arm64 status).
    let arch_proven = arch == "x86_64";

    let status = serde_json::json!({
        "engine": "yara",
        "loaded_rules": load_outcome.loaded_rule_names.len(),
        "loaded_rule_names": load_outcome.loaded_rule_names,
        "skipped_rules": load_outcome.skipped.len(),
        "skipped": load_outcome.skipped.iter().map(|(n, r)| serde_json::json!({"rule_file": n, "reason": r})).collect::<Vec<_>>(),
        "scan_paths": paths.iter().map(|p| p.to_string_lossy().to_string()).collect::<Vec<_>>(),
        "files_scanned": files_scanned,
        "files_skipped_too_large": files_skipped_too_large,
        "files_unreadable": files_unreadable,
        "matches": matches,
        "arch": arch,
        "arch_proven": arch_proven,
        "started_ts": started_ts,
        "last_scan_ts": now_ts(),
    });
    if let Err(e) = std::fs::write(status_path(), status.to_string()) {
        eprintln!("[hookprobe-yara-scan] failed to write status file: {e}");
    }
    eprintln!(
        "[hookprobe-yara-scan] scan complete — files_scanned={files_scanned} matches={matches} \
         skipped_too_large={files_skipped_too_large} unreadable={files_unreadable}"
    );
}
