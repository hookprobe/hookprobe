//! hookprobe-evidence MCP server (ADR 0013 D4a / D4's "MCP tool surface" — the read-only,
//! dev-time-now slice). Standalone stdio JSON-RPC 2.0 server per the Model Context Protocol spec:
//! `initialize` handshake, `tools/list`, `tools/call`. Exposes the hookprobe-evidence graph as
//! READ-ONLY tools so any MCP client (Claude Code, Cursor) — and later the AEGIS planner (ADR 0011
//! D2 Ring 2) — can query the ONE graph the SOC and the product lifecycle share ("operational graph,
//! not delivery graph"), instead of every client re-implementing graph queries. Reuses the EXISTING
//! `EvidenceGraph` methods (`graph_stats`, `correlate`, `trace_detection`, `recent_detections`,
//! `lifecycle_trace`) — this binary is JSON-RPC plumbing only, no query logic lives here.
//!
//! C9 (ADR 0009/0011, unchanged): this server QUERIES the graph, it never enforces. Four of the five
//! tools never write a row (`graph_stats`, `trace`, `recent_detections`, `lifecycle_trace` all run
//! plain SELECTs). `correlate` is the one exception — flagged, not hidden, in `EvidenceGraph::correlate`'s
//! doc comment and in `docs/adr/0013-cortex-evolution-apis.md`'s deferred-items note: it reuses the
//! existing `correlate_incident` (an idempotent incident-node upsert, the SAME side effect the CLI's
//! `--correlate` flag and the scan-responder pipeline already produce today), never a network/policy
//! action — so it stays inside "records, never enforces" even though it is technically a write.
//!
//! Transport: newline-delimited JSON-RPC 2.0 over stdio (the MCP stdio transport — no Content-Length
//! framing, no embedded newlines: one complete JSON-RPC object per line, in and out). stdout carries
//! ONLY JSON-RPC frames; all diagnostics go to stderr, exactly like the ingest binary's `eprintln!`
//! convention, so a client parsing stdout never trips over a log line.
//!
//! Minimal deps by design (matches this crate's dependency posture — no heavy MCP SDK pulled in for
//! a ~150-line read-only shim): `serde_json` for JSON-RPC framing (already a crate dep), `clap` for
//! the CLI (already a crate dep), `anyhow` for error plumbing (already a crate dep).
use anyhow::{Context, Result};
use clap::Parser;
use hookprobe_evidence::EvidenceGraph;
use serde_json::{json, Value};
use std::io::{BufRead, Write};
use std::path::PathBuf;

/// MCP protocol versions this server understands (oldest→newest so `.last()` is the newest). We echo
/// back the client's requested version when we support it (permissive interop); otherwise we fall
/// back to our newest supported version, per the spec's version-negotiation guidance — a client that
/// can't work with that can close the connection.
const SUPPORTED_PROTOCOL_VERSIONS: &[&str] = &["2025-06-18", "2025-11-25"];

#[derive(Parser)]
#[command(
    name = "hookprobe-evidence-mcp",
    version,
    about = "Read-only MCP server over the hookprobe-evidence graph (ADR 0013 D4a)."
)]
struct Cli {
    /// Evidence graph SQLite file to query. Defaults to the dev-time Product Cortex graph
    /// (`.claude/cortex/lifecycle.db`, ADR 0013's dev-time lifecycle bus, fed by the `cortex-emit`
    /// hooks); point it at `/var/lib/hookprobe/evidence.db` to query a live device's SOC graph
    /// instead (same schema, `hookprobe-evidence.service` keeps it current on a timer).
    #[arg(long, default_value = ".claude/cortex/lifecycle.db")]
    db: PathBuf,
}

/// One tool's static metadata: name, human description, and its JSON-Schema input shape — this is
/// what `tools/list` returns; MCP clients render it directly, so keep it accurate and minimal.
struct ToolDef {
    name: &'static str,
    description: &'static str,
    input_schema: Value,
}

fn tool_defs() -> Vec<ToolDef> {
    vec![
        ToolDef {
            name: "graph_stats",
            description: "Node and edge counts by type across the whole evidence graph (network, host, correlation, and lifecycle layers). No arguments.",
            input_schema: json!({"type": "object", "properties": {}, "additionalProperties": false}),
        },
        ToolDef {
            name: "correlate",
            description: "Correlate all detections for a device/scanner IP into one incident, then return its attack path (the threat graph). NOTE: reuses the existing correlate_incident method, which upserts an idempotent incident-summary node (the same side effect the CLI's --correlate flag already produces) — never a network/policy action.",
            input_schema: json!({
                "type": "object",
                "properties": {"ip": {"type": "string", "description": "Device or scanner IP address"}},
                "required": ["ip"],
                "additionalProperties": false
            }),
        },
        ToolDef {
            name: "trace",
            description: "Trace a detection -> its device -> the device's flows (the track/trace drill-down).",
            input_schema: json!({
                "type": "object",
                "properties": {"detection_id": {"type": "string", "description": "Detection node id, e.g. det:0123abcd..."}},
                "required": ["detection_id"],
                "additionalProperties": false
            }),
        },
        ToolDef {
            name: "recent_detections",
            description: "Latest N detections, newest first.",
            input_schema: json!({
                "type": "object",
                "properties": {"limit": {"type": "integer", "description": "Max rows to return (clamped server-side to 1..500)", "default": 20}},
                "additionalProperties": false
            }),
        },
        ToolDef {
            name: "lifecycle_trace",
            description: "A dev-time Claude Code session's intent (the prompt) -> the changes/gates it led to (ADR 0013 dev-time lifecycle bus). Pass a session_key, or \"latest\" for the most recently active session.",
            input_schema: json!({
                "type": "object",
                "properties": {"session": {"type": "string", "description": "session_key, or \"latest\"", "default": "latest"}},
                "additionalProperties": false
            }),
        },
    ]
}

/// stdout carries ONLY JSON-RPC frames (spec: one complete object per line, no embedded newlines).
fn write_msg(v: &Value) {
    let mut out = std::io::stdout().lock();
    let _ = writeln!(out, "{v}");
    let _ = out.flush();
}

fn respond_ok(id: &Value, result: Value) {
    write_msg(&json!({"jsonrpc": "2.0", "id": id, "result": result}));
}

fn respond_err(id: &Value, code: i64, message: &str) {
    write_msg(&json!({"jsonrpc": "2.0", "id": id, "error": {"code": code, "message": message}}));
}

/// Wrap a tool's `Result<String>` (every `EvidenceGraph` query method already returns a JSON-string
/// payload) into an MCP `tools/call` result shape: `content: [{type: "text", text: ...}]`, `isError`
/// on failure. No reformatting of the payload — the graph methods already emit valid JSON text via
/// `serde_json`, so `text` is that string verbatim (an MCP client that wants structured data parses
/// it; a human-facing client just displays it).
fn tool_result(r: Result<String>) -> Value {
    match r {
        Ok(text) => json!({"content": [{"type": "text", "text": text}], "isError": false}),
        Err(e) => json!({"content": [{"type": "text", "text": format!("error: {e:#}")}], "isError": true}),
    }
}

fn call_tool(graph: &EvidenceGraph, name: &str, args: &Value) -> Value {
    match name {
        "graph_stats" => tool_result(graph.graph_stats()),
        "correlate" => match args["ip"].as_str() {
            Some(ip) if !ip.is_empty() => tool_result(graph.correlate(ip)),
            _ => tool_result(Err(anyhow::anyhow!("missing required argument \"ip\""))),
        },
        "trace" => match args["detection_id"].as_str() {
            Some(id) if !id.is_empty() => tool_result(graph.trace_detection(id)),
            _ => tool_result(Err(anyhow::anyhow!("missing required argument \"detection_id\""))),
        },
        "recent_detections" => {
            let limit = args["limit"].as_i64().unwrap_or(20);
            tool_result(graph.recent_detections(limit))
        }
        "lifecycle_trace" => {
            let session = args["session"].as_str().unwrap_or("latest");
            tool_result(graph.lifecycle_trace(session))
        }
        other => json!({"content": [{"type": "text", "text": format!("unknown tool: {other}")}], "isError": true}),
    }
}

/// Dispatch one JSON-RPC request/notification. Writes its response (if any) directly to stdout via
/// `respond_ok`/`respond_err`; returns nothing (the write IS the side effect) so `main`'s loop stays
/// a flat read-dispatch-repeat without threading a response value back out.
fn handle(graph: &EvidenceGraph, req: &Value) {
    let id = req.get("id").cloned();
    let method = req["method"].as_str().unwrap_or("");
    let params = req.get("params").cloned().unwrap_or_else(|| json!({}));

    match method {
        "initialize" => {
            let requested = params["protocolVersion"].as_str().unwrap_or("");
            let version = if SUPPORTED_PROTOCOL_VERSIONS.contains(&requested) {
                requested.to_string()
            } else {
                (*SUPPORTED_PROTOCOL_VERSIONS.last().unwrap()).to_string()
            };
            let id = id.unwrap_or(Value::Null);
            respond_ok(
                &id,
                json!({
                    "protocolVersion": version,
                    "capabilities": {"tools": {}},
                    "serverInfo": {"name": "hookprobe-evidence-mcp", "version": env!("CARGO_PKG_VERSION")}
                }),
            );
        }
        "notifications/initialized" => {} // client notification, no response expected
        "ping" => {
            if let Some(id) = id {
                respond_ok(&id, json!({}));
            }
        }
        "tools/list" => {
            let id = id.unwrap_or(Value::Null);
            let tools: Vec<Value> = tool_defs()
                .into_iter()
                .map(|t| json!({"name": t.name, "description": t.description, "inputSchema": t.input_schema}))
                .collect();
            respond_ok(&id, json!({"tools": tools}));
        }
        "tools/call" => {
            let id = id.unwrap_or(Value::Null);
            let name = params["name"].as_str().unwrap_or("");
            let args = params.get("arguments").cloned().unwrap_or_else(|| json!({}));
            respond_ok(&id, call_tool(graph, name, &args));
        }
        _ => {
            // unknown method: only a REQUEST (has an id) gets an error reply; a notification is
            // silently ignored per JSON-RPC 2.0 semantics.
            if let Some(id) = id {
                respond_err(&id, -32601, &format!("Method not found: {method}"));
            }
        }
    }
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    if !cli.db.exists() {
        eprintln!(
            "hookprobe-evidence-mcp: warning: {} does not exist yet — an empty (schema-only) graph will be created",
            cli.db.display()
        );
    }
    let graph = EvidenceGraph::open(&cli.db)
        .with_context(|| format!("open evidence graph {}", cli.db.display()))?;
    eprintln!("hookprobe-evidence-mcp: serving read-only MCP tools over stdio, db={}", cli.db.display());

    let stdin = std::io::stdin();
    for line in stdin.lock().lines() {
        let line = line.context("read stdin")?;
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        match serde_json::from_str::<Value>(line) {
            Ok(req) => handle(&graph, &req),
            Err(e) => {
                eprintln!("hookprobe-evidence-mcp: parse error on line: {e}");
                respond_err(&Value::Null, -32700, "Parse error");
            }
        }
    }
    Ok(())
}
