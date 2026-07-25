//! `hookprobe-sigma` — native entry point for the Sigma detection engine.
//!
//! ## Input protocol
//!
//! One JSON object per line on stdin, merging TWO of HookProbe's event streams
//! (systemd unit merges them with `tail -q -F` — see `modules/sigma/units/sigma.service`):
//! `/var/lib/hookprobe/flows` (`"type":"conn"|"dns"|"tls"|"http"`, the same schema
//! `modules/napse` reads) and `/var/lib/hookprobe/host-events`
//! (`"type":"process"|"file"|"registry"|"credential"`, the same schema
//! `hookprobe_evidence::ingest_host_event` reads). Unrecognized lines/types are skipped, not fatal.
//!
//! ## Output protocol
//!
//! One JSON alert per line on stdout, in the SAME schema `hookprobe_evidence::EvidenceGraph::
//! ingest_detection` already consumes — appended to `/var/lib/hookprobe/events` by the systemd
//! unit, exactly like a NAPSE alert. **No evidence-graph code changes were needed for this path.**
//!
//! ## Status file (the Detect workspace's real "Sigma: N rules loaded" surface)
//!
//! Writes `/var/lib/hookprobe/sigma-status.json` (path overridable via
//! `HOOKPROBE_SIGMA_STATUS_PATH`) once at startup and again every 100 processed events / on every
//! fired alert — `{"loaded_rules","skipped_rules","skipped","events_processed","alerts_emitted",
//! "last_event_ts","started_ts"}`. `crates/hookprobe-api`'s `/api/engines` reads this file to
//! report REAL loaded-rule counts instead of `ui/src/store/detectMock.ts`'s hard-coded numbers.

use hookprobe_sigma::{evaluate_event, event_from_flow_json, event_from_host_json, load_bundled_rules, SigmaRule};
use std::collections::HashMap;
use std::io::{self, BufRead, Write};

fn now_ts() -> f64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0)
}

fn status_path() -> std::path::PathBuf {
    std::env::var("HOOKPROBE_SIGMA_STATUS_PATH")
        .unwrap_or_else(|_| "/var/lib/hookprobe/sigma-status.json".to_string())
        .into()
}

/// Write the engine-status file. Best-effort: a write failure (e.g. the data partition isn't
/// mounted yet at very-early boot) is logged to stderr and never crashes the detection loop —
/// losing the status surface is a UI-honesty regression, not a detection-path failure.
fn write_status(
    loaded_rules: &[SigmaRule],
    skipped: &[(String, String)],
    events_processed: u64,
    alerts_emitted: u64,
    last_event_ts: f64,
    started_ts: f64,
) {
    let doc = serde_json::json!({
        "engine": "sigma",
        "loaded_rules": loaded_rules.len(),
        "skipped_rules": skipped.len(),
        "skipped": skipped.iter().map(|(n, r)| serde_json::json!({"rule": n, "reason": r})).collect::<Vec<_>>(),
        "events_processed": events_processed,
        "alerts_emitted": alerts_emitted,
        "last_event_ts": last_event_ts,
        "started_ts": started_ts,
        "status_written_ts": now_ts(),
    });
    if let Err(e) = std::fs::write(status_path(), doc.to_string()) {
        eprintln!("[hookprobe-sigma] failed to write status file: {e}");
    }
}

fn main() {
    let started_ts = now_ts();
    let (rules, skipped) = load_bundled_rules();
    for (name, reason) in &skipped {
        // Honesty rule (module doc): unsupported constructs are SKIPPED with a printed warning,
        // never silently dropped or mis-evaluated.
        eprintln!("[hookprobe-sigma] SKIPPING rule '{name}': {reason}");
    }
    eprintln!("[hookprobe-sigma] loaded {} rule(s), skipped {}", rules.len(), skipped.len());
    write_status(&rules, &skipped, 0, 0, started_ts, started_ts);

    // Best-effort pid->name cache (device_ip, pid) -> name, so ParentImage-based rules (e.g. the
    // bundled `sigma_root_shell_not_cron.yml`) can resolve a parent process's name from the SAME
    // live stream — mirrors `hookprobe_evidence::ingest_host_event`'s own best-effort parent-name
    // lookup (there: a SQL query; here: an in-memory cache, since this binary has no DB). Unknown
    // parent -> the field is simply absent, never fabricated (see `event_from_host_json`'s doc).
    let mut pid_name: HashMap<(String, i64), String> = HashMap::new();
    const PID_CACHE_CAP: usize = 20_000; // generous bound for an edge device's process churn

    let stdin = io::stdin();
    let stdout = io::stdout();
    let mut out = io::LineWriter::new(stdout.lock());

    let mut events_processed: u64 = 0;
    let mut alerts_emitted: u64 = 0;
    let mut last_event_ts = started_ts;

    for line in stdin.lock().lines() {
        let line = match line {
            Ok(l) => l,
            Err(e) => {
                eprintln!("[hookprobe-sigma] stdin read error: {e}");
                break;
            }
        };
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let v: serde_json::Value = match serde_json::from_str(trimmed) {
            Ok(v) => v,
            Err(_) => continue, // not JSON (or a stray partial line) -- skip, not fatal
        };

        let rtype = v["type"].as_str().unwrap_or("");
        let event = if v.get("device_ip").is_some() {
            // host-events stream
            if rtype == "process" {
                let device_ip = v["device_ip"].as_str().unwrap_or("").to_string();
                let pid = v["pid"].as_i64().unwrap_or(0);
                let ppid = v["parent_pid"].as_i64().unwrap_or(0);
                let name = v["name"].as_str().unwrap_or("").to_string();
                if !device_ip.is_empty() && pid != 0 && !name.is_empty() {
                    if pid_name.len() >= PID_CACHE_CAP {
                        pid_name.clear(); // simple bounded reset -- an edge device's cache, not a ledger
                    }
                    pid_name.insert((device_ip.clone(), pid), name);
                }
                let parent_name = if ppid != 0 { pid_name.get(&(device_ip, ppid)).cloned() } else { None };
                event_from_host_json(&v, parent_name.as_deref())
            } else {
                event_from_host_json(&v, None)
            }
        } else {
            event_from_flow_json(&v)
        };

        let event = match event {
            Some(e) => e,
            None => continue,
        };
        events_processed += 1;
        last_event_ts = event.ts;

        for alert in evaluate_event(&rules, &event) {
            if let Err(e) = writeln!(out, "{}", alert.to_json()) {
                eprintln!("[hookprobe-sigma] stdout write error: {e}");
                break;
            }
            if let Err(e) = out.flush() {
                eprintln!("[hookprobe-sigma] stdout flush error: {e}");
                break;
            }
            alerts_emitted += 1;
        }

        if events_processed.is_multiple_of(100) {
            write_status(&rules, &skipped, events_processed, alerts_emitted, last_event_ts, started_ts);
        }
    }

    if let Err(e) = out.flush() {
        eprintln!("[hookprobe-sigma] stdout flush error: {e}");
    }
    write_status(&rules, &skipped, events_processed, alerts_emitted, last_event_ts, started_ts);
    eprintln!("[hookprobe-sigma] done — events={events_processed} alerts={alerts_emitted}");
}
