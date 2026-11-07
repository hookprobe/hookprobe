//! `hookprobe-planner` — the HTTP surface for the AEGIS BYO-LLM planner (ADR 0025).
//!
//! A SEPARATE service/port from `hookprobe-api` (ADR 0001), deliberately: `hookprobe-api` is
//! read-only BY CONSTRUCTION (`EvidenceGraph::open_readonly`, `SQLITE_OPEN_READ_ONLY`) — it must
//! never gain a write route. This binary is the ONE, narrow, additive write surface the planner
//! needs (`EvidenceGraph::record_ai_explanation` — attaching an explanation to an existing
//! incident, never creating one, never touching enforcement state).
//!
//! Routes:
//! - `GET  /api/planner/status` — is a model configured? (non-secret endpoint/model id only).
//! - `POST /api/planner/propose` — `{"intent": "..."}` → a [`hookprobe_planner::PlannerResponse`]
//!   (a plan-as-diff, or an answer-only response, or an honest error).
//! - `POST /api/planner/incidents/{id}/explain` — same as `propose`, grounded in one incident's
//!   existing evidence, and on success ALSO calls `EvidenceGraph::record_ai_explanation` so
//!   `/api/incidents/{id}`'s `model` field (served by `hookprobe-api`) stops being null.
//! - `POST /api/planner/approve` — stages a previously-returned `change.artifacts` list under
//!   `/var/lib/hookprobe/planner/staged/<id>/` for operator review. Deliberately NOT a live
//!   `/etc/hookprobe` write and NOT a call to `hookprobe-supervisor --network-write` — promoting a
//!   staged proposal into the device's actual config remains the existing, unchanged, deterministic
//!   `hookprobe-supervisor --reconcile-network --network-write` step. This binary never shells out,
//!   never calls a firewall/OVS/nft API, never touches a live path — see `schema`'s module doc for
//!   the full C9 boundary argument.
#![forbid(unsafe_code)]

use anyhow::{Context, Result};
use axum::{
    body::Body,
    extract::{Path as AxPath, State},
    http::{header, Method, StatusCode},
    response::Response,
    routing::{get, post},
    Router,
};
use clap::Parser;
use hookprobe_evidence::EvidenceGraph;
use hookprobe_manifest::aegis::{HookprobeIntent, NetworkIntent};
use hookprobe_manifest::types::Manifest;
use hookprobe_planner::{Adapter, LlmConfig, PlanContext};
use hookprobe_rbac::{RbacState, RolePolicy, TokenStore, Verb};
use serde::Deserialize;
use serde_json::json;
use std::net::SocketAddr;
use std::path::{Path as StdPath, PathBuf};
use std::sync::Arc;
use tower_http::cors::{Any, CorsLayer};

/// The Red-action gate (ADR 0008 + ADR 0028, C9 governance): `POST /api/planner/approve` — staging
/// an AI-proposed AEGIS plan-as-diff for operator review — requires the `configure` verb
/// (`tenant-admin`/`admin` only in `security/rbac/roles.yaml`). `propose`/`explain` (asking the
/// planner a question, or grounding an answer in one incident) require `investigate` (`analyst`+ —
/// SOC tier-1/2 already has this verb). `status` is a `view`-gated read. Any OTHER (future,
/// currently-unmapped) mutating route defaults to `configure` — fail-closed to the highest bar
/// rather than silently shipping a new write endpoint nobody gated.
fn required_verb(method: &Method, path: &str) -> Verb {
    match (method, path) {
        (&Method::GET, "/api/planner/status") => Verb::View,
        (&Method::POST, "/api/planner/propose") => Verb::Investigate,
        (&Method::POST, p) if p.starts_with("/api/planner/incidents/") && p.ends_with("/explain") => Verb::Investigate,
        (&Method::POST, "/api/planner/approve") => Verb::Configure,
        (m, _) if *m == Method::GET => Verb::View,
        _ => Verb::Configure,
    }
}

#[derive(Parser)]
#[command(
    name = "hookprobe-planner",
    version,
    about = "HookProbe OS AEGIS BYO-LLM planner (ADR 0025) — assistive-only intent-to-diff HTTP surface."
)]
struct Cli {
    /// Signed Platform Manifest. Missing is fine — network-intent proposals degrade to
    /// answer-only with an honest warning (see `PlanContext::manifest`'s doc comment).
    #[arg(long, default_value = "/var/lib/hookprobe/manifest.json")]
    manifest: PathBuf,
    /// Operator-declared `network:` intent document — the SAME file
    /// `hookprobe-supervisor --reconcile-network` reads. Missing is fine (safe defaults).
    #[arg(long, default_value = "/etc/hookprobe/network.yaml")]
    network_intent: PathBuf,
    /// Evidence graph SQLite file, opened READ-WRITE (unlike `hookprobe-api`'s read-only handle) —
    /// this binary's one write is `EvidenceGraph::record_ai_explanation`.
    #[arg(long, default_value = "/var/lib/hookprobe/evidence.db")]
    db: PathBuf,
    /// Where `/api/planner/approve` stages proposal artifacts for operator review. NEVER a live
    /// `/etc/hookprobe` path.
    #[arg(long, default_value = "/var/lib/hookprobe/planner/staged")]
    staging_dir: PathBuf,
    #[arg(long, default_value = "127.0.0.1:8421")]
    listen: String,
    /// RBAC bearer-token store (ADR 0008's own store dir) — same file `hookprobe-api` reads.
    /// Missing is fine — degrades to an empty, fail-closed store that never affects the
    /// standalone-loopback-no-token path (see `hookprobe_rbac::authorize`).
    #[arg(long, default_value = "/var/lib/hookprobe/rbac/tokens.json")]
    rbac_tokens: PathBuf,
}

#[derive(Clone)]
struct AppState {
    /// Read once at startup from the process environment (`LlmConfig::from_env`). `None` is the
    /// honest "no model configured" state this whole service stays additive around — restarting
    /// the unit after setting `HOOKPROBE_AI_ENDPOINT`/`HOOKPROBE_AI_MODEL` picks up a new config,
    /// matching how every other systemd-unit-configured piece of this OS already works (no
    /// separate hot-reload mechanism exists anywhere else in this codebase either).
    llm_config: Arc<Option<LlmConfig>>,
    manifest_path: Arc<PathBuf>,
    network_intent_path: Arc<PathBuf>,
    db_path: Arc<PathBuf>,
    staging_dir: Arc<PathBuf>,
    /// RBAC enforcement seam (ADR 0008 + ADR 0028) — gates `/api/planner/approve` (the Red-action:
    /// approving/staging an AEGIS plan-as-diff) to the `configure` verb.
    rbac: Arc<RbacState>,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let llm_config = LlmConfig::from_env();
    match &llm_config {
        Some(cfg) => eprintln!("hookprobe-planner: AI model configured -> {}", cfg.describe()),
        None => eprintln!(
            "hookprobe-planner: no AI model configured ({}/{} unset) -- running additive-only; \
             every OTHER OS function is unaffected (air-gap default)",
            hookprobe_planner::config::ENV_ENDPOINT,
            hookprobe_planner::config::ENV_MODEL
        ),
    }

    let rbac = RbacState::new(RolePolicy::built_in(), TokenStore::load(&cli.rbac_tokens), required_verb);
    let state = AppState {
        llm_config: Arc::new(llm_config),
        manifest_path: Arc::new(cli.manifest),
        network_intent_path: Arc::new(cli.network_intent),
        db_path: Arc::new(cli.db),
        staging_dir: Arc::new(cli.staging_dir),
        rbac,
    };

    let app = build_router(state);
    let listener = tokio::net::TcpListener::bind(&cli.listen).await.with_context(|| format!("bind {}", cli.listen))?;
    eprintln!("hookprobe-planner listening on {} (rbac-tokens={})", cli.listen, cli.rbac_tokens.display());
    // See `hookprobe-api/src/main.rs`'s identical wiring: `ConnectInfo` is what lets the RBAC
    // middleware see a REAL non-loopback peer, not just a test-inserted one.
    axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>())
        .with_graceful_shutdown(shutdown_signal())
        .await
        .context("serve")?;
    Ok(())
}

async fn shutdown_signal() {
    let ctrl_c = async { tokio::signal::ctrl_c().await.expect("install Ctrl-C handler") };
    #[cfg(unix)]
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("install SIGTERM handler")
            .recv()
            .await;
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();
    tokio::select! { _ = ctrl_c => {}, _ = terminate => {} }
}

fn build_router(state: AppState) -> Router {
    let cors = CorsLayer::new().allow_origin(Any).allow_methods(Any).allow_headers(Any);
    let rbac = state.rbac.clone();
    Router::new()
        .route("/api/planner/status", get(status))
        .route("/api/planner/propose", post(propose_handler))
        .route("/api/planner/incidents/{id}/explain", post(explain_incident_handler))
        .route("/api/planner/approve", post(approve_handler))
        // RBAC (ADR 0008 + ADR 0028) — the Red-action gate on /approve. Runs before the outer CORS
        // layer (added after, so it stays outermost — see hookprobe-api's identical ordering note).
        .layer(axum::middleware::from_fn_with_state(rbac, hookprobe_rbac::enforce_middleware))
        .layer(cors)
        .with_state(state)
}

fn raw_json(status: StatusCode, body: serde_json::Value) -> Response {
    Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(body.to_string()))
        .expect("building a response from a JSON value cannot fail")
}

/// `GET /api/planner/status` — the honest "is a model configured" check `CommandPalette.tsx` polls
/// before rendering anything else. Never leaks the API key.
async fn status(State(state): State<AppState>) -> Response {
    match state.llm_config.as_ref() {
        Some(cfg) => raw_json(StatusCode::OK, json!({"configured": true, "endpoint": cfg.base_url, "model": cfg.model})),
        None => raw_json(
            StatusCode::OK,
            json!({
                "configured": false,
                "endpoint": null,
                "model": null,
                "message": "No AI model configured. Connect a model at Administration → AI Models.",
            }),
        ),
    }
}

#[derive(Deserialize)]
struct ProposeBody {
    intent: String,
}

/// Loads the manifest (honest `None` if absent), the operator's `network.yaml` (safe default if
/// absent — mirrors `hookprobe-supervisor`'s own `load_network_intent`), and a real evidence-graph
/// summary (`EvidenceGraph::graph_stats`) into one [`PlanContext`]. Shared by both `/propose` and
/// `/explain` (which then overrides `evidence_summary` with the one incident's own detail JSON —
/// see its call site).
fn build_context(manifest_path: &StdPath, network_intent_path: &StdPath, graph: &EvidenceGraph) -> PlanContext {
    let manifest: Option<Manifest> = std::fs::read_to_string(manifest_path).ok().and_then(|s| serde_json::from_str(&s).ok());
    let current_intent = load_network_intent(network_intent_path);
    let evidence_summary = graph.graph_stats().unwrap_or_else(|_| "{}".to_string());
    PlanContext { manifest, current_intent, evidence_summary }
}

/// Mirrors `supervisor/src/main.rs`'s own `load_network_intent` exactly (that copy is a private
/// `fn` in a binary crate this crate cannot import) — safe default (`NetworkIntent::default()`,
/// "auto fabric, idle Wi-Fi, manifest WAN order") when the file doesn't exist yet, never an error.
fn load_network_intent(path: &StdPath) -> NetworkIntent {
    match std::fs::read_to_string(path) {
        Ok(text) => match HookprobeIntent::parse(&text) {
            Ok(doc) => doc.network,
            Err(e) => {
                eprintln!("hookprobe-planner: {path:?} failed to parse ({e:#}); using NetworkIntent::default()");
                NetworkIntent::default()
            }
        },
        Err(_) => NetworkIntent::default(),
    }
}

/// `POST /api/planner/propose` — `{"intent": "..."}` → a plan-as-diff or an honest error. Never
/// calls the adapter at all when no model is configured (503, not a fabricated response).
async fn propose_handler(State(state): State<AppState>, axum::Json(body): axum::Json<ProposeBody>) -> Response {
    let Some(cfg) = state.llm_config.as_ref().clone() else {
        return not_configured_response();
    };
    let db_path = state.db_path.clone();
    let manifest_path = state.manifest_path.clone();
    let network_intent_path = state.network_intent_path.clone();
    let intent = body.intent;

    let result = tokio::task::spawn_blocking(move || -> Result<hookprobe_planner::PlannerResponse, String> {
        let graph = EvidenceGraph::open(&db_path).map_err(|e| format!("open evidence graph: {e:#}"))?;
        let ctx = build_context(&manifest_path, &network_intent_path, &graph);
        let adapter = Adapter::new(cfg);
        hookprobe_planner::propose(&adapter, &intent, &ctx).map_err(|e| e.to_string())
    })
    .await;

    match result {
        Ok(Ok(resp)) => raw_json(StatusCode::OK, serde_json::to_value(resp).expect("PlannerResponse serializes")),
        Ok(Err(msg)) => raw_json(StatusCode::BAD_GATEWAY, json!({"error": "adapter_error", "message": msg})),
        Err(join_err) => raw_json(StatusCode::INTERNAL_SERVER_ERROR, json!({"error": "internal", "message": join_err.to_string()})),
    }
}

#[derive(Deserialize, Default)]
struct ExplainBody {
    /// Optional extra operator framing on top of the incident's own evidence
    /// (e.g. "focus on whether this is a false positive"). Empty is fine.
    #[serde(default)]
    intent: String,
}

/// `POST /api/planner/incidents/{id}/explain` — grounds the SAME `propose()` call in one
/// incident's existing deterministic evidence (`EvidenceGraph::incident_detail`), then, on success,
/// calls `EvidenceGraph::record_ai_explanation` so `/api/incidents/{id}`'s `model` field (served
/// read-only by `hookprobe-api`) stops being null. 404s honestly if the incident doesn't exist —
/// never fabricates one to explain.
async fn explain_incident_handler(
    State(state): State<AppState>,
    AxPath(incident_id): AxPath<String>,
    body: Option<axum::Json<ExplainBody>>,
) -> Response {
    let Some(cfg) = state.llm_config.as_ref().clone() else {
        return not_configured_response();
    };
    let db_path = state.db_path.clone();
    let manifest_path = state.manifest_path.clone();
    let network_intent_path = state.network_intent_path.clone();
    let operator_note = body.map(|b| b.0.intent).unwrap_or_default();

    let result = tokio::task::spawn_blocking(move || -> Result<Option<hookprobe_planner::PlannerResponse>, String> {
        let graph = EvidenceGraph::open(&db_path).map_err(|e| format!("open evidence graph: {e:#}"))?;
        let Some(detail_json) = graph.incident_detail(&incident_id).map_err(|e| format!("incident_detail: {e:#}"))? else {
            return Ok(None); // signals 404 below
        };
        let mut ctx = build_context(&manifest_path, &network_intent_path, &graph);
        ctx.evidence_summary = detail_json.clone(); // ground the explanation in THIS incident's own evidence, not the whole-graph summary
        let intent_text = if operator_note.trim().is_empty() {
            format!("Explain incident {incident_id} to the operator: why did it happen, how confident are we, what should they do?")
        } else {
            format!("For incident {incident_id}: {operator_note}")
        };
        let adapter = Adapter::new(cfg);
        let resp = hookprobe_planner::propose(&adapter, &intent_text, &ctx).map_err(|e| e.to_string())?;

        // Record the explanation — the ONE write this whole crate performs. Never blocks the
        // response on a failure to record (the operator still gets the answer); logged to stderr.
        let line = json!({
            "incident_id": incident_id,
            "model": resp.explanation.model,
            "why": resp.explanation.why,
            "confidence": resp.explanation.confidence,
            "reasoning": resp.answer,
        })
        .to_string();
        if let Err(e) = graph.record_ai_explanation(&line) {
            eprintln!("hookprobe-planner: failed to record ai_explanation for {incident_id}: {e:#}");
        }

        Ok(Some(resp))
    })
    .await;

    match result {
        Ok(Ok(Some(resp))) => raw_json(StatusCode::OK, serde_json::to_value(resp).expect("PlannerResponse serializes")),
        Ok(Ok(None)) => raw_json(StatusCode::NOT_FOUND, json!({"error": "incident not found"})),
        Ok(Err(msg)) => raw_json(StatusCode::BAD_GATEWAY, json!({"error": "adapter_error", "message": msg})),
        Err(join_err) => raw_json(StatusCode::INTERNAL_SERVER_ERROR, json!({"error": "internal", "message": join_err.to_string()})),
    }
}

fn not_configured_response() -> Response {
    raw_json(
        StatusCode::SERVICE_UNAVAILABLE,
        json!({
            "error": "not_configured",
            "message": "No AI model configured. Connect a model at Administration → AI Models.",
        }),
    )
}

#[derive(Deserialize)]
struct ArtifactIn {
    path: String,
    content: String,
}

#[derive(Deserialize)]
struct ApproveBody {
    artifacts: Vec<ArtifactIn>,
}

/// `POST /api/planner/approve` — stages artifacts from a PREVIOUSLY-returned `change.artifacts`
/// list under a fresh `staging_dir/<proposal-id>/` directory. This is NOT an apply: nothing here
/// is read by any running service, nft/OVS/systemd is never touched, and the files are plain
/// previews for a human to read. Promoting a staged proposal into the device's live config still
/// requires the operator to run the existing, unchanged `hookprobe-supervisor --reconcile-network
/// --network-write /etc/hookprobe` (or a future, explicitly-reviewed automation of that SAME
/// command — never invoked automatically from here).
async fn approve_handler(State(state): State<AppState>, axum::Json(body): axum::Json<ApproveBody>) -> Response {
    if body.artifacts.is_empty() {
        return raw_json(StatusCode::BAD_REQUEST, json!({"error": "no artifacts to stage"}));
    }
    for a in &body.artifacts {
        if a.path.contains("..") || a.path.starts_with('/') {
            return raw_json(StatusCode::BAD_REQUEST, json!({"error": "invalid artifact path", "path": a.path}));
        }
    }

    let proposal_id = format!(
        "proposal-{}",
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_nanos()).unwrap_or(0)
    );
    let staging_dir = state.staging_dir.as_path();
    let dest_dir = staging_dir.join(&proposal_id);
    let artifacts = body.artifacts;
    let dest_dir_for_write = dest_dir.clone();

    let result = tokio::task::spawn_blocking(move || -> std::io::Result<usize> {
        std::fs::create_dir_all(&dest_dir_for_write)?;
        for a in &artifacts {
            let dest = dest_dir_for_write.join(&a.path);
            if let Some(parent) = dest.parent() {
                std::fs::create_dir_all(parent)?;
            }
            std::fs::write(&dest, &a.content)?;
        }
        Ok(artifacts.len())
    })
    .await;

    match result {
        Ok(Ok(n)) => raw_json(
            StatusCode::OK,
            json!({
                "staged": true,
                "proposal_id": proposal_id,
                "staged_dir": dest_dir.display().to_string(),
                "artifact_count": n,
                "note": "staged for operator review only — apply via the existing `hookprobe-supervisor --reconcile-network --network-write` step",
            }),
        ),
        Ok(Err(e)) => raw_json(StatusCode::INTERNAL_SERVER_ERROR, json!({"error": "staging_failed", "message": e.to_string()})),
        Err(join_err) => raw_json(StatusCode::INTERNAL_SERVER_ERROR, json!({"error": "internal", "message": join_err.to_string()})),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use http_body_util::BodyExt;
    use hookprobe_planner::adapter::test_server::serve_once;
    use tower::ServiceExt;

    fn temp_path(tag: &str) -> PathBuf {
        std::env::temp_dir().join(format!("hp-planner-test-{tag}-{}", std::process::id()))
    }

    fn state_with(llm_config: Option<LlmConfig>, db_path: PathBuf, staging_dir: PathBuf) -> AppState {
        state_with_tokens(llm_config, db_path, staging_dir, TokenStore::default())
    }

    fn state_with_tokens(llm_config: Option<LlmConfig>, db_path: PathBuf, staging_dir: PathBuf, tokens: TokenStore) -> AppState {
        AppState {
            llm_config: Arc::new(llm_config),
            manifest_path: Arc::new(temp_path("no-manifest.json")),
            network_intent_path: Arc::new(temp_path("no-network.yaml")),
            db_path: Arc::new(db_path),
            staging_dir: Arc::new(staging_dir),
            rbac: RbacState::new(RolePolicy::built_in(), tokens, required_verb),
        }
    }

    async fn call(app: &Router, method: &str, uri: &str, body: serde_json::Value) -> (StatusCode, serde_json::Value) {
        let req = axum::http::Request::builder()
            .method(method)
            .uri(uri)
            .header("content-type", "application/json")
            .body(Body::from(body.to_string()))
            .unwrap();
        let resp = app.clone().oneshot(req).await.unwrap();
        let status = resp.status();
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        let v: serde_json::Value = if bytes.is_empty() { json!(null) } else { serde_json::from_slice(&bytes).unwrap_or(json!(null)) };
        (status, v)
    }

    #[tokio::test]
    async fn status_reports_the_honest_no_config_default() {
        let db_path = temp_path("status-db.sqlite");
        let staging = temp_path("status-staging");
        let state = state_with(None, db_path, staging);
        let app = build_router(state);
        let (status, v) = call(&app, "GET", "/api/planner/status", json!(null)).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(v["configured"], false);
        assert!(v["message"].as_str().unwrap().contains("Administration"));
    }

    #[tokio::test]
    async fn propose_returns_503_when_not_configured_never_calling_out() {
        let db_path = temp_path("propose-noconfig-db.sqlite");
        let staging = temp_path("propose-noconfig-staging");
        let state = state_with(None, db_path, staging);
        let app = build_router(state);
        let (status, v) = call(&app, "POST", "/api/planner/propose", json!({"intent": "block the camera"})).await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(v["error"], "not_configured");
    }

    #[tokio::test]
    async fn propose_returns_a_real_answer_when_configured_against_a_fixture_endpoint() {
        let body = r#"{"choices":[{"message":{"role":"assistant","content":"{\"answer\":\"ok\",\"confidence\":80}"}}]}"#;
        let base = serve_once("HTTP/1.1 200 OK", "application/json", body);
        let cfg = LlmConfig { base_url: base, model: "test-model".to_string(), api_key: None, timeout: std::time::Duration::from_secs(5) };
        let db_path = temp_path("propose-ok-db.sqlite");
        std::fs::remove_file(&db_path).ok();
        let staging = temp_path("propose-ok-staging");
        let state = state_with(Some(cfg), db_path.clone(), staging);
        let app = build_router(state);
        let (status, v) = call(&app, "POST", "/api/planner/propose", json!({"intent": "is my network safe"})).await;
        assert_eq!(status, StatusCode::OK, "response: {v}");
        assert_eq!(v["answer"], "ok");
        std::fs::remove_file(&db_path).ok();
    }

    #[tokio::test]
    async fn explain_incident_404s_honestly_on_an_unknown_incident() {
        let body = r#"{"choices":[{"message":{"role":"assistant","content":"{\"answer\":\"n/a\"}"}}]}"#;
        let base = serve_once("HTTP/1.1 200 OK", "application/json", body);
        let cfg = LlmConfig { base_url: base, model: "test-model".to_string(), api_key: None, timeout: std::time::Duration::from_secs(5) };
        let db_path = temp_path("explain-404-db.sqlite");
        std::fs::remove_file(&db_path).ok();
        { EvidenceGraph::open(&db_path).unwrap(); } // create the schema, but no incidents
        let staging = temp_path("explain-404-staging");
        let state = state_with(Some(cfg), db_path.clone(), staging);
        let app = build_router(state);
        let (status, _v) = call(&app, "POST", "/api/planner/incidents/inc:doesnotexist/explain", json!({})).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        std::fs::remove_file(&db_path).ok();
    }

    #[tokio::test]
    async fn explain_incident_writes_model_field_visible_to_incident_detail() {
        let body = r#"{"choices":[{"message":{"role":"assistant","content":"{\"answer\":\"this looks like an SSH brute force attempt\",\"why\":\"repeated auth failures\",\"confidence\":88}"}}]}"#;
        let base = serve_once("HTTP/1.1 200 OK", "application/json", body);
        let cfg = LlmConfig { base_url: base, model: "test-model".to_string(), api_key: None, timeout: std::time::Duration::from_secs(5) };
        let db_path = temp_path("explain-ok-db.sqlite");
        std::fs::remove_file(&db_path).ok();
        let incident_id = {
            let w = EvidenceGraph::open(&db_path).unwrap();
            w.ingest_detection(r#"{"ts":1000.0,"rule_id":1000001,"rule_msg":"NAPSE SSH Brute Force","category":"brute_force","severity":2,"mitre":"T1110","src_ip":"203.0.113.11","dst_ip":"192.168.1.20","dst_port":22,"confidence":0.8}"#).unwrap();
            w.correlate_incident("203.0.113.11", "SSH brute force incident").unwrap()
        };
        let staging = temp_path("explain-ok-staging");
        let state = state_with(Some(cfg), db_path.clone(), staging);
        let app = build_router(state);

        let (status, v) = call(&app, "POST", &format!("/api/planner/incidents/{incident_id}/explain"), json!({})).await;
        assert_eq!(status, StatusCode::OK, "response: {v}");
        assert_eq!(v["answer"], "this looks like an SSH brute force attempt");

        // The write actually landed — hookprobe-evidence's OWN incident_detail now serves a
        // non-null model, exactly what hookprobe-api's read-only /api/incidents/:id route reads.
        let g = EvidenceGraph::open(&db_path).unwrap();
        let detail: serde_json::Value = serde_json::from_str(&g.incident_detail(&incident_id).unwrap().unwrap()).unwrap();
        assert!(!detail["explanation"]["model"].is_null(), "model must be populated after /explain ran");
        assert_eq!(detail["explanation"]["ai_reasoning"]["why"], "repeated auth failures");
        std::fs::remove_file(&db_path).ok();
    }

    #[tokio::test]
    async fn approve_stages_artifacts_and_rejects_path_traversal() {
        let db_path = temp_path("approve-db.sqlite");
        let staging = temp_path("approve-staging");
        std::fs::remove_dir_all(&staging).ok();
        let state = state_with(None, db_path, staging.clone());
        let app = build_router(state);

        let good = json!({"artifacts": [{"path": "60-nac.nft", "content": "table inet hookprobe_nac { }\n"}]});
        let (status, v) = call(&app, "POST", "/api/planner/approve", good).await;
        assert_eq!(status, StatusCode::OK, "response: {v}");
        let staged_dir = v["staged_dir"].as_str().unwrap();
        assert!(std::path::Path::new(staged_dir).join("60-nac.nft").exists(), "the artifact must actually be written");

        let traversal = json!({"artifacts": [{"path": "../../etc/passwd", "content": "pwned"}]});
        let (status, v) = call(&app, "POST", "/api/planner/approve", traversal).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "response: {v}");

        std::fs::remove_dir_all(&staging).ok();
    }

    /// RBAC proof #1 (standalone-permissive / anti-self-lockout): with NO bearer token and no
    /// `ConnectInfo` (the in-process test shape — identical to every call above), the Red-action
    /// route stays reachable exactly like before this crate existed. This is what keeps a
    /// standalone, no-account device's own dashboard able to approve its OWN AEGIS proposals
    /// without ever needing to log in.
    #[tokio::test]
    async fn rbac_standalone_loopback_can_still_approve_with_no_identity() {
        let db_path = temp_path("rbac-standalone-approve-db.sqlite");
        let staging = temp_path("rbac-standalone-approve-staging");
        std::fs::remove_dir_all(&staging).ok();
        let state = state_with(None, db_path, staging.clone());
        let app = build_router(state);

        let body = json!({"artifacts": [{"path": "60-nac.nft", "content": "table inet hookprobe_nac { }\n"}]});
        let (status, v) = call(&app, "POST", "/api/planner/approve", body).await;
        assert_eq!(status, StatusCode::OK, "response: {v}");
        std::fs::remove_dir_all(&staging).ok();
    }

    /// RBAC proof #2 — the Red-action gate itself: a `viewer` identity (the least-privileged role,
    /// no `configure` verb) MUST NOT be able to approve/stage an AEGIS plan-as-diff, even though the
    /// SAME identity can reach the read-only `/status` route just fine.
    #[tokio::test]
    async fn rbac_a_viewer_identity_cannot_approve_a_plan_as_diff() {
        let db_path = temp_path("rbac-viewer-approve-db.sqlite");
        let staging = temp_path("rbac-viewer-approve-staging");
        std::fs::remove_dir_all(&staging).ok();
        let tokens = TokenStore::from_plaintext_tokens(&[("viewer-tok", "viewer", "vic")]);
        let state = state_with_tokens(None, db_path, staging.clone(), tokens);
        let app = build_router(state);

        let req = axum::http::Request::builder()
            .method("POST")
            .uri("/api/planner/approve")
            .header(header::AUTHORIZATION, "Bearer viewer-tok")
            .header("content-type", "application/json")
            .body(Body::from(json!({"artifacts": [{"path": "60-nac.nft", "content": "x"}]}).to_string()))
            .unwrap();
        let resp = app.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN, "viewer must be denied the configure-gated approve route");

        // the SAME viewer identity reaches the view-gated status route without trouble.
        let req2 = axum::http::Request::builder()
            .method("GET")
            .uri("/api/planner/status")
            .header(header::AUTHORIZATION, "Bearer viewer-tok")
            .body(Body::empty())
            .unwrap();
        let resp2 = app.oneshot(req2).await.unwrap();
        assert_eq!(resp2.status(), StatusCode::OK);

        assert!(!std::path::Path::new(&staging).exists() || std::fs::read_dir(&staging).map(|mut d| d.next().is_none()).unwrap_or(true), "a denied approve must never actually stage anything");
        std::fs::remove_dir_all(&staging).ok();
    }

    /// RBAC proof #3 — an `admin` (or `tenant-admin`) identity, the roles `security/rbac/roles.yaml`
    /// grants `configure` to, CAN approve — the Red-action gate is precise (denies below the bar,
    /// allows at/above it), not a blanket lockout once RBAC is wired in.
    #[tokio::test]
    async fn rbac_an_admin_identity_can_approve_a_plan_as_diff() {
        let db_path = temp_path("rbac-admin-approve-db.sqlite");
        let staging = temp_path("rbac-admin-approve-staging");
        std::fs::remove_dir_all(&staging).ok();
        let tokens = TokenStore::from_plaintext_tokens(&[("admin-tok", "admin", "alice")]);
        let state = state_with_tokens(None, db_path, staging.clone(), tokens);
        let app = build_router(state);

        let req = axum::http::Request::builder()
            .method("POST")
            .uri("/api/planner/approve")
            .header(header::AUTHORIZATION, "Bearer admin-tok")
            .header("content-type", "application/json")
            .body(Body::from(json!({"artifacts": [{"path": "60-nac.nft", "content": "table inet hookprobe_nac { }\n"}]}).to_string()))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        std::fs::remove_dir_all(&staging).ok();
    }
}
