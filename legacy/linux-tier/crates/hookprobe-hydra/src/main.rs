//! `hookprobe-hydra` CLI — run HYDRA's IOC matcher on a device (ADR 0027).
//!
//! Driven by `hookprobe-hydra.timer` on the bundled-feed cadence. Reads the bundled, dated IOC feed
//! together with the evidence graph's own flow/application data (since HYDRA's own watermark),
//! matches, and folds every hit straight back into the SAME evidence graph via
//! `EvidenceGraph::ingest_ioc_match` — mirroring `hookprobe-exploit`'s own main.rs shape exactly
//! (a direct, self-contained reader+writer of `evidence.db`, its own begin/commit transaction; NOT
//! a stream file another process re-ingests). Air-gapped by default — no network; a live STIX/
//! TAXII/MISP fetch is an ADDITIVE enrollment feature, not built in this first version.
//!
//! **Layer-1 corroboration-gated verdict shaping (ADR 0023 task #19 / ADR 0027 Layer-1, 2026-07-16
//! — Finding-1's `verdict.rs` was type-complete but never LINKED into a built binary path):** after
//! matching, this pass ALSO groups the SAME hits by the LAN device they concern
//! (`verdict::group_hits_by_device`), corroborates each device with the evidence graph's own
//! beaconing detections (rule `1_000_040` / category `c2_beacon`) and this host's latest QSECBIT
//! composite-resilience reading, and shapes a bounded, corroboration-gated `HydraVerdict` per
//! device (`verdict::assess`) — the SAME gate proven in `verdict.rs`'s own tests: a lone IOC hit
//! can never enforce. Written IP-keyed (`HydraVerdict::to_intel_json`) to `--verdicts-out`, a JSON-
//! lines sidecar the trust reconciler (`hookprobe-supervisor --hydra-verdicts`) reads as `IntelOnly`
//! posture input, resolving `device_ip` -> MAC via its own live ARP snapshot.
use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::Parser;

use hookprobe_evidence::EvidenceGraph;
use hookprobe_hydra::{feed::IocFeed, matcher};
use hookprobe_hydra::verdict::{self, Corroboration, HydraTrustPolicy};
use hookprobe_mgmt_guard::ProtectPolicy;

#[derive(Parser, Debug)]
#[command(name = "hookprobe-hydra", about = "HYDRA IOC/threat-intel matcher (ADR 0027) — bundled feed x evidence graph")]
struct Args {
    /// The bundled, dated IOC feed (`hookprobe-ioc-v1`).
    #[arg(long, default_value = "/usr/share/hookprobe/threat-intel/ioc-feed.json")]
    feed: PathBuf,
    /// The evidence graph DB (read candidates from + write matches into — same file
    /// `hookprobe-evidence.timer`/`hookprobe-exploit.timer` already share; `busy_timeout` in
    /// `EvidenceGraph::open` already covers this crate being a third independent writer).
    #[arg(long, default_value = "/var/lib/hookprobe/evidence.db")]
    db: PathBuf,
    /// Cap on flow candidates scanned per pass (bounded edge-CPU cost; a rerun with a smaller
    /// remaining backlog just catches up over several passes rather than one unbounded scan).
    #[arg(long, default_value_t = 5000)]
    max_candidates: i64,
    /// Print a JSON summary (feed freshness, candidates scanned, hits) to stdout.
    #[arg(long)]
    print: bool,
    /// Where to write this pass's corroboration-gated, IP-keyed HYDRA verdicts (JSON lines,
    /// `HydraVerdict::to_intel_json`) — `hookprobe-supervisor --hydra-verdicts` reads this as
    /// `IntelOnly` posture input (ADR 0023 task #19 / ADR 0027 Layer-1).
    #[arg(long, default_value = "/var/lib/hookprobe/hydra-verdicts")]
    verdicts_out: PathBuf,
    /// Operator override for the HYDRA-to-trust weighting/corroboration policy (YAML). Optional —
    /// absent means the tuned default (`HydraTrustPolicy::default`, see that type's doc).
    #[arg(long)]
    trust_policy: Option<PathBuf>,
}

fn main() -> Result<()> {
    let args = Args::parse();

    let feed = IocFeed::load(&args.feed)
        .with_context(|| format!("loading bundled IOC feed {:?}", args.feed))?;

    let db = EvidenceGraph::open(&args.db).with_context(|| format!("opening {:?}", args.db))?;
    db.begin().ok();

    let candidates_json = db.ioc_flow_candidates(args.max_candidates)?;
    let candidates: Vec<matcher::FlowCandidate> =
        serde_json::from_str(&candidates_json).context("parsing ioc_flow_candidates JSON")?;
    let flow_scanned = candidates.len();

    let mut hits = matcher::scan_flow_candidates(&feed, &candidates);

    // File-hash IOC scan (2026-07-09 — closes ADR 0027's original honest gap: `match_hash` used to
    // be type-complete but never called here). Same shape as the flow scan above: its OWN
    // watermark (`ioc_file_candidates` — see that function's doc for why it's separate from the
    // flow watermark), matched, folded into the SAME `hits` list so one commit/print covers both.
    let file_candidates_json = db.ioc_file_candidates(args.max_candidates)?;
    let file_candidates: Vec<matcher::FileCandidate> =
        serde_json::from_str(&file_candidates_json).context("parsing ioc_file_candidates JSON")?;
    let file_scanned = file_candidates.len();
    hits.extend(matcher::scan_file_candidates(&feed, &file_candidates));

    let mut ingested = 0usize;
    for hit in &hits {
        let line = hit.to_ioc_match_json();
        if db.ingest_ioc_match(&line)?.is_some() {
            ingested += 1;
        }
    }
    db.commit().ok();

    // Layer-1 corroboration-gated verdict shaping (ADR 0023 task #19 / ADR 0027 Layer-1) — see the
    // module doc comment above for the full rationale. Read-only from here on; failures here must
    // never undo the ioc_match ingestion that already committed above (still the primary job).
    let trust_policy = match &args.trust_policy {
        Some(p) => HydraTrustPolicy::parse_yaml(&std::fs::read_to_string(p).with_context(|| format!("reading trust-policy {p:?}"))?)?,
        None => HydraTrustPolicy::default(),
    };
    let mgmt = ProtectPolicy::default();

    // Global QSECBIT composite-resilience corroboration: this host's own Mahalanobis/attack-
    // probability/entropy composite is a SINGLE `dev:self` reading, not per-device (see
    // `EvidenceGraph::ingest_qsecbit_score`'s own doc) — applied UNIFORMLY as one corroborating
    // input to every device assessed this pass, honestly, never invented as a fake per-device
    // anomaly. `score` is HYDRA/QSECBIT's own 0.0-1.0 composite risk; `Corroboration::qsecbit_
    // anomaly` is a 0-100 scale (see `verdict::HydraTrustPolicy::qsecbit_anomaly_min`'s doc).
    let qsecbit_anomaly: f64 = db
        .list_qsecbit(1)
        .ok()
        .and_then(|s| serde_json::from_str::<serde_json::Value>(&s).ok())
        .and_then(|v| v["scores"].get(0).and_then(|r| r["score"].as_f64()))
        .map(|s| (s * 100.0).clamp(0.0, 100.0))
        .unwrap_or(0.0);

    // Beaconing corroboration (rule 1_000_040 / category "c2_beacon", src_ip = the LAN device that
    // is beaconing — the same attribution `beacon.rs`'s own detection already uses).
    let beacon_devices: std::collections::BTreeSet<String> = db
        .detections_by_categories(&["c2_beacon"], 500)
        .ok()
        .and_then(|s| serde_json::from_str::<serde_json::Value>(&s).ok())
        .map(|v| v["detections"].as_array().cloned().unwrap_or_default())
        .unwrap_or_default()
        .iter()
        .filter_map(|d| d["src_ip"].as_str().map(String::from))
        .collect();

    let grouped = verdict::group_hits_by_device(&hits);
    let mut verdict_lines = String::new();
    for (device_ip, dev_hits) in &grouped {
        let corrob = Corroboration { beaconing: beacon_devices.contains(device_ip), qsecbit_anomaly };
        let v = verdict::assess(device_ip, dev_hits, corrob, &trust_policy, &mgmt);
        verdict_lines.push_str(&v.to_intel_json());
        verdict_lines.push('\n');
    }
    std::fs::write(&args.verdicts_out, &verdict_lines)
        .with_context(|| format!("writing {:?}", args.verdicts_out))?;

    eprintln!(
        "hookprobe-hydra: feed {:?} ({} indicators, generated {}) — scanned {} flow candidate(s) + {} file candidate(s), {} hit(s), {} ingested, {} device verdict(s) -> {:?}",
        args.feed, feed.len(), feed.generated, flow_scanned, file_scanned, hits.len(), ingested, grouped.len(), args.verdicts_out
    );
    if args.print {
        println!(
            "{}",
            serde_json::json!({
                "feed_generated": feed.generated,
                "feed_indicators": feed.len(),
                "candidates_scanned": flow_scanned,
                "file_candidates_scanned": file_scanned,
                "hits": hits.len(),
                "ingested": ingested,
                "device_verdicts": grouped.len(),
            })
        );
    }
    Ok(())
}
