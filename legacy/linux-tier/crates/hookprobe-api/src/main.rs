//! hookprobe-api — Mission Control read-API binary (ADR 0001: Rust/Axum).
//!
//! Serves the evidence graph (`/var/lib/hookprobe/evidence.db`) READ-ONLY over HTTP + SSE, and the
//! Platform Manifest's capability/mode view, to the Mission Control UI. Never writes a byte to the
//! evidence DB — see `hookprobe_api::AppState::open` / `hookprobe_evidence::EvidenceGraph::open_readonly`.
//!
//! RBAC (ADR 0008 + ADR 0028): standalone-loopback callers are unaffected (no account required to
//! run the device) — enforcement activates only once a bearer token or a non-loopback peer shows
//! up, see `hookprobe_rbac`'s crate doc. `into_make_service_with_connect_info` below is what makes
//! the "non-loopback peer" half of that decision real (rather than only test-time-observable).
#![forbid(unsafe_code)]

use anyhow::{Context, Result};
use clap::Parser;
use hookprobe_api::{build_router, AppState};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

#[derive(Parser)]
#[command(
    name = "hookprobe-api",
    version,
    about = "HookProbe OS Mission Control read-API — read-only HTTP+SSE over the evidence graph (ADR 0001)."
)]
struct Cli {
    /// Evidence graph SQLite file (opened strictly read-only). Must already exist — this binary
    /// never creates or migrates it; `hookprobe-evidence.timer` owns that.
    #[arg(long, default_value = "/var/lib/hookprobe/evidence.db")]
    db: PathBuf,
    /// Signed Platform Manifest (capabilities + identity). Missing is fine — the safe standalone
    /// default is served instead (see `manifest_view::manifest_view_json`).
    #[arg(long, default_value = "/var/lib/hookprobe/manifest.json")]
    manifest: PathBuf,
    /// Claim record (the explicit deployment-mode string). Missing is fine — same fallback.
    #[arg(long, default_value = "/var/lib/hookprobe/claim.json")]
    claim: PathBuf,
    /// Address to listen on. Loopback by default. RBAC (ADR 0008 + ADR 0028) stays permissive for
    /// loopback callers with no bearer token — the standalone, no-account default — and enforces
    /// per-role access the moment a bearer token OR a non-loopback peer is observed.
    #[arg(long, default_value = "127.0.0.1:8420")]
    listen: String,
    /// `/api/stream` watermark-poll interval, milliseconds. A dashboard refresh cadence, not a
    /// firehose — keep it edge-cheap.
    #[arg(long, default_value_t = 2000)]
    sse_interval_ms: u64,
    /// RBAC bearer-token store (ADR 0008's own store dir). Missing is fine — degrades to an empty,
    /// fail-closed store that never affects the standalone-loopback-no-token path.
    #[arg(long, default_value = "/var/lib/hookprobe/rbac/tokens.json")]
    rbac_tokens: PathBuf,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    let state = AppState::open(
        &cli.db,
        cli.manifest.clone(),
        cli.claim.clone(),
        Duration::from_millis(cli.sse_interval_ms),
        &cli.rbac_tokens,
    )
    .with_context(|| format!("open evidence db read-only: {}", cli.db.display()))?;

    let app = build_router(state);

    let listener = tokio::net::TcpListener::bind(&cli.listen)
        .await
        .with_context(|| format!("bind {}", cli.listen))?;
    eprintln!(
        "hookprobe-api listening on {} (db={}, read-only, sse-interval={}ms, rbac-tokens={})",
        cli.listen,
        cli.db.display(),
        cli.sse_interval_ms,
        cli.rbac_tokens.display()
    );

    // `into_make_service_with_connect_info::<SocketAddr>()` is what lets `hookprobe_rbac`'s
    // middleware see the REAL peer address (so a non-loopback caller with no bearer token is
    // actually denied, not merely denied in a test that manually inserted `ConnectInfo`) — see
    // `hookprobe_rbac::axum_mw::is_trusted_local`'s doc for why its absence defaults open instead.
    axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>())
        .with_graceful_shutdown(shutdown_signal())
        .await
        .context("serve")?;
    Ok(())
}

/// SIGINT/SIGTERM graceful shutdown (systemd sends SIGTERM on stop) — a plain `Ctrl-C`-only handler
/// would ignore the unit's normal stop signal and rely on `TimeoutStopSec` killing it instead.
async fn shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c().await.expect("install Ctrl-C handler");
    };
    #[cfg(unix)]
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("install SIGTERM handler")
            .recv()
            .await;
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }
}
