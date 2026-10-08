//! hookprobe-evidence — build the evidence graph from the SOC's flow/event streams (ADR 0009 step 2).
//! Reads `/var/lib/hookprobe/flows` + `/var/lib/hookprobe/events` (JSON lines) into SQLite nodes+edges,
//! so detections trace to their flows + device. Exports JSONEachRow (the ClickHouse offload artifact).
use anyhow::{Context, Result};
use clap::Parser;
use hookprobe_evidence::EvidenceGraph;
use std::io::{BufRead, Read};
use std::path::PathBuf;

enum Kind {
    Flow,
    Detection,
    Host,
    Response,
    DnsVerdict,
    AegisVerdict,
    HeqkExport,
    QsecbitScore,
    Finding,
}

#[derive(Parser)]
#[command(name = "hookprobe-evidence", version, about)]
struct Cli {
    /// SQLite DB file (default: in-memory).
    #[arg(long)]
    db: Option<PathBuf>,
    /// Flows file to ingest (JSON lines).
    #[arg(long)]
    flows: Option<PathBuf>,
    /// Events/detections file to ingest (JSON lines).
    #[arg(long)]
    events: Option<PathBuf>,
    /// Host-telemetry file to ingest (process/file/registry JSON lines) — the threat-graph host layer.
    #[arg(long)]
    host: Option<PathBuf>,
    /// AEGIS reflex response events to ingest (JSON lines — e.g. the scan-responder's
    /// ENRICH/DROP/DOCUMENT cycle: "quarantined via nft, TTL 300s" / "released" / "allowlisted").
    /// Linked to the detection(s) they responded to by natural key (rule_id/src_ip/dst_ip/dst_port).
    #[arg(long)]
    responses: Option<PathBuf>,
    /// dnsxai DNS/DGA verdicts to ingest (JSON lines, `/var/lib/hookprobe/dns-verdicts` — F-B6:
    /// previously computed but never entering the graph). Only suspicious/malicious verdicts
    /// become Detection-class nodes; benign is skipped as evidence-free noise.
    #[arg(long)]
    dns_verdicts: Option<PathBuf>,
    /// AEGIS Guard reflex/policy verdicts to ingest (JSON lines, `/var/lib/hookprobe/aegis-verdicts`
    /// — F-B6). Only escalated reflex levels (JITTER/SHADOW/DISCONNECT) and non-routine guard
    /// verdicts (RequireApproval/Deny) become Detection-class nodes.
    #[arg(long)]
    aegis_verdicts: Option<PathBuf>,
    /// heqk (CM5 microkernel sensor) M6 evidence export stream to ingest (JSON lines written by
    /// the MSSP receiver, `kernel/responder-sim --live --evidence-out`): detections with sensor
    /// provenance + verdict class, and per-boot loss accounting.
    #[arg(long)]
    heqk_export: Option<PathBuf>,
    /// QSECBIT composite-resilience readings to ingest (JSON lines,
    /// `/var/lib/hookprobe/qsecbit-scores` — F-B6): the Mission Control "Organism Status" orb's
    /// backing node, attached to the synthetic `dev:self` device via a `qsecbit_score_of` edge.
    #[arg(long)]
    qsecbit_scores: Option<PathBuf>,
    /// Trace this detection id → device → flows (prints the drill-down JSON).
    #[arg(long)]
    trace: Option<String>,
    /// Correlate all detections on this device_ip → an incident, then print its attack path (threat graph).
    #[arg(long)]
    correlate: Option<String>,
    /// Generate (or regenerate) the executive Report node for this incident id — the
    /// MissionControl-required terminus of the evidence chain, drilling back to every raw evidence
    /// node it cites (S2). Falls back to the standard on-disk graph (like `--stats`) when `--db`
    /// isn't given: this is an on-demand operator action against the live graph, not a batch ingest.
    #[arg(long)]
    report: Option<String>,
    /// Auto-correlate EVERY device with a new detection into an incident since the last watermark
    /// (F-B5 — the fix for "the incidents table is always empty today"). Runs unconditionally on
    /// every invocation (unlike `--correlate <ip>`, which is on-demand/manual); idempotent — a
    /// rerun with no new detections since the watermark does nothing. Runs AFTER the batched
    /// ingest commit so it sees this pass's freshly-ingested detections.
    #[arg(long)]
    correlate_all: bool,
    /// Export node tables as JSONEachRow in this dir (ClickHouse offload artifact).
    #[arg(long)]
    export: Option<PathBuf>,
    /// F5: print a read-only, at-a-glance operator summary — per-table node/edge counts (devices,
    /// flows, detections, incidents, processes, files, edges, …) AND a per-category/per-rule_id
    /// detection breakdown (e.g. "port_scan: 145, brute_force: 21") — then exit 0. The DB can be
    /// healthy (hundreds of detections, thousands of edges) with zero visibility into WHAT fired;
    /// before this flag there was no way to see that at a glance (`hookprobe-evidence --stats`
    /// previously errored: "unexpected argument"). Read-only: does not open a write transaction.
    #[arg(long)]
    stats: bool,

    // ---- ADR 0011 build step 2: the lifecycle graph (product-cortex ingest paths) -----------------
    /// Ingest every `docs/adr/NNNN-*.md` in this directory → `adrs` nodes (+ `supersedes` edges).
    #[arg(long)]
    ingest_adrs: Option<PathBuf>,
    /// Ingest a schema-1 `release.json` bundle (ADR 0012 D3) → a `releases` node + `commits` +
    /// `gate_results` nodes and their edges.
    #[arg(long)]
    ingest_release: Option<PathBuf>,
    /// Ingest a schema-1 `beacon.json` (ADR 0012 D5), or every `*.json` in this dir → `beacons` nodes,
    /// linked to their release by `image_version` when that release has already been ingested.
    #[arg(long)]
    ingest_beacon: Option<PathBuf>,
    /// Field-feedback edge (ADR 0011 D1): `<src_node_id> <requirement_slug>` → creates the requirement
    /// if absent and an `informed_by` edge src→requirement.
    #[arg(long, num_args = 2, value_names = ["SRC_NODE_ID", "REQUIREMENT_SLUG"])]
    link_feedback: Option<Vec<String>>,
    /// Requirement title, used only with `--link-feedback` when the requirement node doesn't exist yet.
    #[arg(long)]
    title: Option<String>,

    /// ADR 0013 dev-time lifecycle bus: ingest a JSONL event log from the Claude Code `cortex-emit`
    /// hooks (intent/change/gate/red_action) → session + lifecycle_events nodes + led_to/in_session
    /// edges. Makes every prompt→build interaction a graph query. Records only; never enforces (C9).
    #[arg(long)]
    ingest_lifecycle: Option<PathBuf>,

    // ---- ADR 0020 adversarial-resilience harness (security/redteam/) ----
    /// Ingest an `attack_run.json` (the redteam-engine's pre-fire audit / final-verdict record) →
    /// an `attack_runs` node. Idempotent -- safe to re-ingest the same campaign's file at any point.
    #[arg(long)]
    ingest_attack_run: Option<PathBuf>,
    /// Ingest a `findings.jsonl` (one line per probe outcome), or every `*.jsonl` in this dir, →
    /// `findings` nodes linked to their `attack_run`.
    #[arg(long)]
    ingest_findings: Option<PathBuf>,

    // ---- Retention (backend-audit gap 1: evidence.db has no bound today) --------------------------
    /// Prune the graph: delete raw/timeline nodes+edges older than --retention-days (and/or over
    /// --max-db-size-mb, oldest-first), sweep now-evidence-free incidents/reports as a coherent
    /// unit, then VACUUM to actually reclaim disk. Wired into its OWN daily timer
    /// (`hookprobe-evidence-prune.timer`) rather than the 2-minute ingest cadence — VACUUM rewrites
    /// the whole file, not something to do every 2 minutes on SD-card-class storage. Falls back to
    /// the standard on-disk graph when `--db` is omitted (like `--stats`/`--report`).
    #[arg(long)]
    prune: bool,
    /// `--prune`'s age-based retention window, in days. Falls back to env
    /// `HOOKPROBE_RETENTION_DAYS`, then `hookprobe_evidence::DEFAULT_RETENTION_DAYS` (30).
    #[arg(long = "retention-days")]
    retention_days: Option<f64>,
    /// `--prune`'s optional size cap, in MiB (deletes oldest-first across every raw table until
    /// under this cap OR the age-based retention is the limiting factor). Falls back to env
    /// `HOOKPROBE_MAX_DB_MB`. Unset = no size cap (age-based retention only).
    #[arg(long = "max-db-size-mb")]
    max_db_size_mb: Option<i64>,
    /// Trigger-to-evidence pcap capture (roadmap D) directory to sweep alongside `--prune` — the
    /// SAME `.pcap`-file retention `EvidenceGraph::prune_pcap_dir` enforces (age window THEN size
    /// cap, ADR 0003), never a second timer. Falls back to env `HOOKPROBE_PCAP_DIR`, then
    /// `/var/lib/hookprobe/pcap`.
    #[arg(long = "pcap-dir")]
    pcap_dir: Option<PathBuf>,
    /// `--prune`'s pcap-directory size cap, in MiB. Falls back to env `HOOKPROBE_PCAP_CAP_MB`,
    /// then `hookprobe_evidence::PCAP_DIR_CAP_BYTES` (8192 MiB / 8 GiB, ADR 0003).
    #[arg(long = "pcap-cap-mb")]
    pcap_cap_mb: Option<i64>,
    /// `--prune`'s pcap-directory age window, in hours — any `.pcap` file older than this is
    /// deleted unconditionally, regardless of the size cap. Falls back to env
    /// `HOOKPROBE_PCAP_MAX_AGE_HOURS`, then `hookprobe_evidence::DEFAULT_PCAP_MAX_AGE_SECS` (24h,
    /// ADR 0003's "window: hours").
    #[arg(long = "pcap-max-age-hours")]
    pcap_max_age_hours: Option<f64>,
}

fn ingest_file(g: &EvidenceGraph, path: &PathBuf, kind: Kind) -> Result<usize> {
    // 4 MiB per-line cap → a maliciously newline-less stream can't OOM us; lossy UTF-8 → one bad byte
    // (realistic for attacker-influenced names/paths) skips that line instead of aborting the whole run.
    const MAX_LINE: u64 = 4 << 20;
    // a stream may not exist yet (e.g. host-events before host-telemetry starts) — skip, don't fail
    // the whole run (this is a timer-driven service ingesting several streams).
    let file = match std::fs::File::open(path) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(0),
        Err(e) => return Err(e.into()),
    };
    let mut reader = std::io::BufReader::new(file);
    let mut buf = Vec::new();
    let mut n = 0usize;
    loop {
        buf.clear();
        let read = (&mut reader).take(MAX_LINE).read_until(b'\n', &mut buf)?;
        if read == 0 {
            break;
        }
        let cow = String::from_utf8_lossy(&buf);
        let line = cow.trim();
        if line.is_empty() {
            continue;
        }
        let got = match kind {
            Kind::Flow => g.ingest_flow(line)?,
            Kind::Detection => g.ingest_detection(line)?,
            Kind::Host => g.ingest_host_event(line)?,
            Kind::Response => g.ingest_response(line)?,
            Kind::DnsVerdict => g.ingest_dns_verdict(line)?,
            Kind::AegisVerdict => g.ingest_aegis_verdict(line)?,
            Kind::HeqkExport => g.ingest_heqk_export(line)?,
            Kind::QsecbitScore => g.ingest_qsecbit_score(line)?,
            Kind::Finding => g.ingest_finding(line)?,
        };
        if got.is_some() {
            n += 1;
        }
    }
    Ok(n)
}

/// F5 `--stats`: render `EvidenceGraph::graph_stats()` (per-table node/edge counts) +
/// `EvidenceGraph::detection_breakdown()` (per-category/per-rule_id detection counts, highest-first)
/// as a plain-text operator summary. Both underlying calls are read-only queries; this function only
/// formats their JSON — it issues no INSERT/UPDATE of its own.
fn print_stats(g: &EvidenceGraph) -> Result<()> {
    let stats: serde_json::Value = serde_json::from_str(&g.graph_stats()?).context("parse graph_stats json")?;
    let nodes = &stats["nodes"];
    println!();
    println!("=== hookprobe-evidence --stats ===");
    println!("-- node counts --");
    // Fixed, meaningful order (network -> host -> correlation -> lifecycle) rather than the
    // BTreeMap's alphabetical one — easier for an operator to scan at a glance.
    const ORDER: &[&str] = &[
        "devices", "interfaces", "flows", "net_sessions", "applications", "users",
        "detections", "processes", "files", "registry_keys", "credentials",
        "incidents", "reports", "iocs", "responses", "adrs", "requirements", "commits", "releases",
        "gate_results", "beacons", "sessions", "lifecycle_events", "qsecbit_scores",
        "attack_runs", "findings",
    ];
    for key in ORDER {
        if let Some(n) = nodes.get(*key) {
            println!("  {key:<16} {n}");
        }
    }
    println!("  {:<16} {}", "edges (total)", stats["total_edges"]);

    let breakdown: serde_json::Value =
        serde_json::from_str(&g.detection_breakdown()?).context("parse detection_breakdown json")?;
    println!("-- detections by category (highest first) --");
    match breakdown["by_category"].as_array() {
        Some(rows) if !rows.is_empty() => {
            for row in rows {
                println!("  {}: {}", row["category"].as_str().unwrap_or("?"), row["count"]);
            }
        }
        _ => println!("  (no detections yet)"),
    }
    println!("-- detections by rule_id (highest first) --");
    match breakdown["by_rule_id"].as_array() {
        Some(rows) if !rows.is_empty() => {
            for row in rows {
                println!("  {}: {}", row["rule_id"], row["count"]);
            }
        }
        _ => println!("  (no detections yet)"),
    }

    // Retention visibility (backend-audit gap 1): current on-disk size + the last --prune pass, so
    // an operator can see retention is actually running, not just trust a cron job.
    println!("-- retention --");
    let size = stats["db_size_bytes"].as_i64().unwrap_or(0);
    println!("  db size: {size} bytes ({:.2} MiB)", size as f64 / (1024.0 * 1024.0));
    match &stats["last_prune"] {
        serde_json::Value::Null => println!("  last prune: never (run --prune, or wait for hookprobe-evidence-prune.timer)"),
        lp => {
            println!(
                "  last prune: ts={} retention_days={} max_db_bytes={} vacuumed={}",
                lp["ts"], lp["retention_days"], lp["max_db_bytes"], lp["vacuumed"]
            );
            println!(
                "    deleted: {} node(s), {} edge(s), {} incident(s), {} report(s)",
                lp["deleted_nodes"], lp["deleted_edges"], lp["deleted_incidents"], lp["deleted_reports"]
            );
            println!("    size: {} -> {} bytes", lp["size_before_bytes"], lp["size_after_bytes"]);
        }
    }
    Ok(())
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let g = match &cli.db {
        Some(p) => EvidenceGraph::open(p)?,
        // G3 (2026-07-06): a read-only `--stats` with no explicit `--db` must read the STANDARD
        // on-disk graph (where hookprobe-evidence.service writes) — an in-memory default made
        // `--stats` always print 0 even with a fully-populated DB. Ingest paths still default to
        // in-memory (they always pass an explicit --db). `--prune` gets the SAME fallback (its own
        // timer never passes --db either — see hookprobe-evidence-prune.service).
        None if cli.stats || cli.report.is_some() || cli.prune =>
            EvidenceGraph::open(std::path::Path::new("/var/lib/hookprobe/evidence.db"))?,
        None => EvidenceGraph::open_memory()?,
    };
    // batch the whole ingest into one transaction — one fsync instead of thousands (SD-card critical)
    let ingesting = cli.flows.is_some() || cli.events.is_some() || cli.host.is_some() || cli.responses.is_some()
        || cli.dns_verdicts.is_some() || cli.aegis_verdicts.is_some() || cli.heqk_export.is_some() || cli.qsecbit_scores.is_some()
        || cli.ingest_adrs.is_some() || cli.ingest_release.is_some() || cli.ingest_beacon.is_some()
        || cli.link_feedback.is_some() || cli.ingest_attack_run.is_some() || cli.ingest_findings.is_some();
    if ingesting {
        g.begin()?;
    }
    if let Some(p) = &cli.flows {
        eprintln!("ingested {} flows", ingest_file(&g, p, Kind::Flow)?);
    }
    if let Some(p) = &cli.events {
        eprintln!("ingested {} detections", ingest_file(&g, p, Kind::Detection)?);
    }
    if let Some(p) = &cli.host {
        eprintln!("ingested {} host events", ingest_file(&g, p, Kind::Host)?);
    }
    if let Some(p) = &cli.responses {
        eprintln!("ingested {} response event(s)", ingest_file(&g, p, Kind::Response)?);
    }
    if let Some(p) = &cli.dns_verdicts {
        eprintln!("ingested {} dns verdict(s)", ingest_file(&g, p, Kind::DnsVerdict)?);
    }
    if let Some(p) = &cli.aegis_verdicts {
        eprintln!("ingested {} aegis verdict(s)", ingest_file(&g, p, Kind::AegisVerdict)?);
    }
    if let Some(p) = &cli.heqk_export {
        eprintln!("ingested {} heqk export line(s)", ingest_file(&g, p, Kind::HeqkExport)?);
    }
    if let Some(p) = &cli.qsecbit_scores {
        eprintln!("ingested {} qsecbit score(s)", ingest_file(&g, p, Kind::QsecbitScore)?);
    }
    if let Some(dir) = &cli.ingest_adrs {
        let mut n = 0usize;
        for entry in std::fs::read_dir(dir).with_context(|| format!("read_dir {}", dir.display()))? {
            let path = entry?.path();
            if path.extension().and_then(|s| s.to_str()) == Some("md")
                && g.ingest_adr_file(&path)?.is_some()
            {
                n += 1;
            }
        }
        eprintln!("ingested {n} ADRs from {}", dir.display());
    }
    if let Some(p) = &cli.ingest_release {
        let text = std::fs::read_to_string(p).with_context(|| format!("read {}", p.display()))?;
        let id = g.ingest_release(&text)?;
        eprintln!("ingested release {} -> {:?}", p.display(), id);
    }
    if let Some(p) = &cli.ingest_beacon {
        let meta = std::fs::metadata(p).with_context(|| format!("stat {}", p.display()))?;
        let mut n = 0usize;
        if meta.is_dir() {
            for entry in std::fs::read_dir(p).with_context(|| format!("read_dir {}", p.display()))? {
                let bp = entry?.path();
                if bp.extension().and_then(|s| s.to_str()) == Some("json") {
                    let text = std::fs::read_to_string(&bp).with_context(|| format!("read {}", bp.display()))?;
                    if g.ingest_beacon(&text)?.is_some() {
                        n += 1;
                    }
                }
            }
        } else {
            let text = std::fs::read_to_string(p).with_context(|| format!("read {}", p.display()))?;
            if g.ingest_beacon(&text)?.is_some() {
                n += 1;
            }
        }
        eprintln!("ingested {n} beacon(s) from {}", p.display());
    }
    if let Some(p) = &cli.ingest_attack_run {
        let text = std::fs::read_to_string(p).with_context(|| format!("read {}", p.display()))?;
        let id = g.ingest_attack_run(&text)?;
        eprintln!("ingested attack_run {} -> {:?}", p.display(), id);
    }
    if let Some(p) = &cli.ingest_findings {
        let meta = std::fs::metadata(p).with_context(|| format!("stat {}", p.display()))?;
        let mut n = 0usize;
        if meta.is_dir() {
            for entry in std::fs::read_dir(p).with_context(|| format!("read_dir {}", p.display()))? {
                let fp = entry?.path();
                if fp.extension().and_then(|s| s.to_str()) == Some("jsonl") {
                    n += ingest_file(&g, &fp, Kind::Finding)?;
                }
            }
        } else {
            n += ingest_file(&g, p, Kind::Finding)?;
        }
        eprintln!("ingested {n} finding(s) from {}", p.display());
    }
    if let Some(vals) = &cli.link_feedback {
        let [src, slug] = &vals[..] else {
            anyhow::bail!("--link-feedback needs exactly 2 values: <src_node_id> <requirement_slug>");
        };
        let req_id = g.link_feedback(src, slug, cli.title.as_deref())?;
        eprintln!("linked {src} --informed_by--> {req_id}");
    }
    if ingesting {
        g.commit()?;
    }
    // Retention (backend-audit gap 1): runs its OWN transaction internally (`EvidenceGraph::prune`)
    // and ends with a bare VACUUM, which SQLite refuses inside a pending transaction — dispatched
    // here, strictly AFTER the ingest commit above, so no transaction is left open when it runs.
    // Deliberately BEFORE `--correlate-all` below: no point correlating detections this same pass
    // is about to delete.
    if cli.prune {
        let retention_days = cli
            .retention_days
            .or_else(|| std::env::var("HOOKPROBE_RETENTION_DAYS").ok().and_then(|v| v.parse().ok()))
            .unwrap_or(hookprobe_evidence::DEFAULT_RETENTION_DAYS);
        let max_db_bytes = cli
            .max_db_size_mb
            .or_else(|| std::env::var("HOOKPROBE_MAX_DB_MB").ok().and_then(|v| v.parse().ok()))
            .map(|mb: i64| mb * 1024 * 1024);
        let stats = g.prune(retention_days, max_db_bytes)?;
        eprintln!(
            "prune: retention_days={} max_db_bytes={:?} -> deleted {} node(s), {} edge(s), {} incident(s), {} report(s); size {} -> {} bytes (vacuumed={})",
            stats.retention_days, stats.max_db_bytes, stats.deleted_nodes, stats.deleted_edges,
            stats.deleted_incidents, stats.deleted_reports, stats.size_before_bytes, stats.size_after_bytes,
            stats.vacuumed
        );
        // Trigger-to-evidence pcap capture (roadmap D, GAP-4): the filesystem tier `prune` above
        // (SQLite rows only) knows nothing about — same `--prune` invocation, same daily timer,
        // one retention pass, not a second daemon.
        let pcap_dir = cli
            .pcap_dir
            .clone()
            .or_else(|| std::env::var("HOOKPROBE_PCAP_DIR").ok().map(PathBuf::from))
            .unwrap_or_else(|| PathBuf::from("/var/lib/hookprobe/pcap"));
        let pcap_cap_bytes = cli
            .pcap_cap_mb
            .or_else(|| std::env::var("HOOKPROBE_PCAP_CAP_MB").ok().and_then(|v| v.parse().ok()))
            .map(|mb: i64| mb * 1024 * 1024)
            .unwrap_or(hookprobe_evidence::PCAP_DIR_CAP_BYTES);
        let pcap_max_age_secs = cli
            .pcap_max_age_hours
            .or_else(|| std::env::var("HOOKPROBE_PCAP_MAX_AGE_HOURS").ok().and_then(|v| v.parse().ok()))
            .map(|h: f64| h * 3600.0)
            .unwrap_or(hookprobe_evidence::DEFAULT_PCAP_MAX_AGE_SECS);
        let pcap_stats = g.prune_pcap_dir(&pcap_dir, pcap_cap_bytes, pcap_max_age_secs)?;
        eprintln!(
            "prune (pcap dir {}): cap_bytes={} max_age_hours={:.1} -> deleted {} file(s) ({} bytes), {} row(s); size {} -> {} bytes",
            pcap_dir.display(), pcap_stats.cap_bytes, pcap_max_age_secs / 3600.0, pcap_stats.deleted_files,
            pcap_stats.deleted_bytes, pcap_stats.deleted_rows, pcap_stats.size_before_bytes, pcap_stats.size_after_bytes
        );
    }
    // F-B5: auto-correlate AFTER the batched ingest commit so this pass's freshly-ingested
    // detections are visible to it. Unconditional (not gated behind `ingesting`) so a bare
    // `--correlate-all` run (e.g. a manual catch-up pass) still works with no ingest flags.
    if cli.correlate_all {
        let n = g.correlate_all(0.0)?;
        eprintln!("correlate-all: {n} device(s) correlated into incidents");
    }
    // Dispatched OUTSIDE the batch txn above: ingest_lifecycle_file manages its own transaction
    // (session-anchor tracking spans the whole file), so it must not be nested inside g.begin().
    if let Some(p) = &cli.ingest_lifecycle {
        let n = g.ingest_lifecycle_file(p)?;
        eprintln!("ingested {n} lifecycle event(s) from {} (ADR 0013 dev-time bus)", p.display());
    }
    let (d, f, det, e) = g.counts()?;
    println!("evidence graph: {d} devices · {f} flows · {det} detections · {e} edges");
    if cli.stats {
        print_stats(&g)?;
    }
    if let Some(id) = &cli.trace {
        println!("trace {id}: {}", g.trace_detection(id)?);
    }
    if let Some(ip) = &cli.correlate {
        let inc = g.correlate_incident(ip, "Correlated incident")?;
        println!("incident {inc}");
        println!("attack path (threat graph): {}", g.attack_path(&inc)?);
    }
    if let Some(id) = &cli.report {
        match g.generate_report(id)? {
            Some(rep_id) => {
                let detail = g.report_detail(&rep_id)?.unwrap_or_default();
                println!("report {rep_id}: {detail}");
            }
            None => eprintln!("--report: no incident found with id {id}"),
        }
    }
    if let Some(p) = &cli.export {
        g.export_jsonl(p)?;
        eprintln!("exported JSONEachRow (ClickHouse offload) → {}", p.display());
    }
    Ok(())
}
