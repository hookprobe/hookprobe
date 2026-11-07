//! WASI entry point for the NAPSE detection-synthesis module.
//!
//! ## Role in the V2 architecture
//!
//! The supervisor starts this binary under Wasmtime with the grants declared
//! in `module.yaml`:
//! - `read: /var/lib/hookprobe/flows` — the napse-capture sysext writes
//!   normalized flow/event records here; stdin is redirected from this pipe.
//! - `wasi-nn: cpu` — reserved for the GNN embedding upgrade path.
//!
//! ## Input protocol
//!
//! One JSON object per line, written by the napse-capture sysext after
//! normalizing raw packets/flows to the common event schema. Blank lines and
//! lines starting with `#` are ignored.
//!
//! Required fields for all record types:
//! ```text
//! {"type":"conn","ts":1735000000.0,"src_ip":"192.168.1.10","src_port":54321,
//!  "dst_ip":"10.0.0.1","dst_port":22,"proto":"tcp","conn_state":"S0",
//!  "orig_bytes":0,"resp_bytes":0}
//! ```
//!
//! DNS records (type="dns") add:
//! ```text
//! "query":"long.subdomain.evil.xyz","query_len":55,"query_entropy":4.2
//! ```
//!
//! TLS records (type="tls") add:
//! ```text
//! "ja3":"72a589da586844d7f0818ce684948eea","tls_version":"TLSv1.3"
//! ```
//!
//! HTTP records (type="http") add:
//! ```text
//! "uri":"/api?id=1' union select 1--","method":"GET"
//! ```
//!
//! Any record may carry:
//! ```text
//! "payload_entropy":7.8
//! ```
//!
//! ## Output protocol
//!
//! One JSON alert per line written to stdout **only when a threat is detected**
//! (benign records produce no output — unlike qsecbit which scores every tick).
//!
//! Example alerts:
//! ```json
//! {"ts":1735000000.000,"src_ip":"203.0.113.1","src_port":54000,"dst_ip":"192.168.1.1","dst_port":22,"proto":"tcp","severity":2,"rule_id":1000001,"rule_msg":"NAPSE SSH Brute Force Attempt","mitre":"T1110","category":"brute_force","confidence":0.7500,"intent_phase":"RECONNAISSANCE","risk_score":0.1234,"alert_action":"alert","p_attack":0.0000}
//! {"ts":1735000001.000,"src_ip":"10.0.0.5","src_port":54322,"dst_ip":"1.2.3.4","dst_port":443,"proto":"tcp","severity":1,"rule_id":1000004,"rule_msg":"NAPSE Potential C2 Communication (JA3 match)","mitre":"T1071.001","category":"malware_c2","confidence":0.9000,"intent_phase":"BENIGN","risk_score":0.1000,"alert_action":"alert","p_attack":0.0000}
//! ```
//!
//! `p_attack` (roadmap C, `napse::tabular`) is the tabular-ML seed scorer's output for
//! the triggering entity, gated on `ml_cpu` (`tabular::p_attack_for_qsecbit`) — always
//! `0.0000` until this binary opts in via `NapseSynthesizer::set_ml_cpu_granted(true)`,
//! which it does not do yet (see that method's doc comment on `NapseSynthesizer` for the
//! precise residual wire: reading `ml_cpu` from the signed Platform Manifest at runtime
//! needs either a new `module.yaml` grant or supervisor-side capability plumbing, neither
//! of which exists yet and both of which are outside this task's file scope).
//! `base/scripts/telemetry-export.sh` reads this field out of the most recent alert line
//! to populate QSECBIT's optional 5th CSV field.
//!
//! Stderr receives diagnostic messages (supervisor may redirect to the log).
//!
//! ## TODO(wasi-nn)
//!
//! When the GNN model is available (V1 GraphEmbedder exported to ONNX):
//! ```ignore
//! // Load once at startup when `edge_ai` is granted:
//! // use wasi_nn::{GraphBuilder, GraphEncoding, ExecutionTarget};
//! // let graph = GraphBuilder::new(GraphEncoding::Onnx, ExecutionTarget::CPU)
//! //     .build_from_files(["/var/lib/hookprobe/models/napse-embedder.onnx"])
//! //     .expect("load GNN model");
//! // let ctx = graph.init_execution_context().expect("init ctx");
//! //
//! // Per entity tick: replace heuristic_deviation() with:
//! // let feat_f32: Vec<f32> = entity.feature_vector().iter().map(|&x| x as f32).collect();
//! // ctx.set_input(0, wasi_nn::TensorType::F32, &[1, 16], &feat_f32)?;
//! // ctx.compute()?;
//! // let mut emb = vec![0f32; 64];
//! // ctx.get_output(0, &mut emb)?;
//! // // cosine_distance(emb, golden_harmonic) → deviation in [0,1]
//! ```

use napse::{FlowRecord, NapseSynthesizer};
use std::io::{self, BufRead, Write};

// ─── Minimal JSON field extractor (zero-dependency) ───────────────────────────
//
// We hand-roll extraction instead of pulling in a crate to keep the .wasm
// small and the supply-chain surface minimal (same policy as qsecbit/dnsxai).
//
// Each helper searches for `"key":"value"` or `"key":number` in a flat JSON
// object string. Sufficient for one-level-deep flow records with scalar values.

/// Extract a string value for `key` from a flat JSON object string.
///
/// Matches `"key":"..."` with basic backslash-escape awareness.
fn json_str(json: &str, key: &str) -> Option<String> {
    // Tolerate optional whitespace after the colon (`"key": "v"` as well as `"key":"v"`) so ANY
    // JSON producer — not just our compact writers — parses. (json_num already trims; this matched it.)
    let needle = format!("\"{}\":", key);
    let start = json.find(&needle)? + needle.len();
    let rest = json[start..].trim_start().strip_prefix('"')?;
    let mut out = String::new();
    let mut escape = false;
    for c in rest.chars() {
        if escape {
            match c {
                '"' => out.push('"'),
                '\\' => out.push('\\'),
                'n' => out.push('\n'),
                'r' => out.push('\r'),
                't' => out.push('\t'),
                _ => {
                    out.push('\\');
                    out.push(c);
                }
            }
            escape = false;
            continue;
        }
        if c == '\\' {
            escape = true;
            continue;
        }
        if c == '"' {
            break;
        }
        out.push(c);
    }
    Some(out)
}

/// Extract a numeric value for `key` from a flat JSON object string.
///
/// Matches `"key":number` (integer or float, optional sign/exponent).
/// Returns `None` if the value is `null` or a quoted string.
fn json_num(json: &str, key: &str) -> Option<f64> {
    let needle = format!("\"{}\":", key);
    let start = json.find(&needle)? + needle.len();
    let rest = json[start..].trim_start();
    // Skip null and string values
    if rest.starts_with("null") || rest.starts_with('"') {
        return None;
    }
    let end = rest
        .find(|c: char| !matches!(c, '0'..='9' | '.' | '-' | '+' | 'e' | 'E'))
        .unwrap_or(rest.len());
    rest[..end].parse::<f64>().ok()
}

/// Parse one JSON line into a `FlowRecord`.
///
/// Unknown fields are silently ignored; missing required fields (`src_ip`,
/// `dst_ip`) cause the line to be skipped with a stderr diagnostic.
fn parse_record(json: &str) -> Option<FlowRecord> {
    let src_ip = json_str(json, "src_ip").unwrap_or_default();
    let dst_ip = json_str(json, "dst_ip").unwrap_or_default();

    if src_ip.is_empty() || dst_ip.is_empty() {
        eprintln!("[napse] missing src_ip/dst_ip, skipping: {json:.80}…");
        return None;
    }

    let ts = json_num(json, "ts").unwrap_or(0.0);
    let src_port = json_num(json, "src_port").unwrap_or(0.0) as u16;
    let dst_port = json_num(json, "dst_port").unwrap_or(0.0) as u16;

    Some(FlowRecord {
        record_type: json_str(json, "type").unwrap_or_default(),
        ts,
        uid: json_str(json, "uid").unwrap_or_default(),
        src_ip,
        src_port,
        dst_ip,
        dst_port,
        proto: json_str(json, "proto").unwrap_or_default(),
        service: json_str(json, "service").unwrap_or_default(),
        orig_bytes: json_num(json, "orig_bytes").unwrap_or(0.0) as u64,
        resp_bytes: json_num(json, "resp_bytes").unwrap_or(0.0) as u64,
        orig_pkts: json_num(json, "orig_pkts").unwrap_or(0.0) as u32,
        resp_pkts: json_num(json, "resp_pkts").unwrap_or(0.0) as u32,
        conn_state: json_str(json, "conn_state").unwrap_or_default(),
        // DNS
        query: json_str(json, "query"),
        query_len: json_num(json, "query_len").map(|v| v as u32),
        query_entropy: json_num(json, "query_entropy"),
        // TLS
        ja3: json_str(json, "ja3"),
        tls_version: json_str(json, "tls_version"),
        tls_sni: json_str(json, "tls_sni"),
        // HTTP
        uri: json_str(json, "uri"),
        method: json_str(json, "method"),
        // Payload / alert
        payload_entropy: json_num(json, "payload_entropy"),
        alert_severity: json_num(json, "alert_severity").map(|v| v as u8),
        alert_signature: json_str(json, "alert_signature"),
    })
}

// ─── Main loop ────────────────────────────────────────────────────────────────

fn main() {
    // 1 000 entities × ~2 KB each ≈ 2 MB entity table, well inside the
    // wasm-M 256 MB budget declared in module.yaml for Pi-class hardware.
    let mut synth = NapseSynthesizer::new(1_000, 300.0);
    let stdin = io::stdin();
    let stdout = io::stdout();
    let mut out = io::LineWriter::new(stdout.lock());

    // Bounded exact-duplicate suppression: the flow stream is a shared file that senzorium rotates
    // by inode-swap, so `tail -F` replays old records after a rotation. Replayed lines are BYTE-
    // IDENTICAL (same 5-tuple + same ts), so hashing the raw line and skipping repeats drops the
    // replay without touching legitimate records (which differ by ts). Ring-bounded so memory is O(1).
    const DEDUP_CAP: usize = 8192;
    let mut seen: std::collections::HashSet<u64> = std::collections::HashSet::new();
    let mut seen_order: std::collections::VecDeque<u64> = std::collections::VecDeque::new();

    for line in stdin.lock().lines() {
        let line = match line {
            Ok(l) => l,
            Err(e) => {
                eprintln!("[napse] stdin read error: {e}");
                break;
            }
        };
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }

        // FNV-1a of the raw line → skip exact duplicates (rotation replay).
        let mut h: u64 = 0xcbf29ce484222325;
        for &b in trimmed.as_bytes() {
            h ^= b as u64;
            h = h.wrapping_mul(0x100000001b3);
        }
        if !seen.insert(h) {
            continue;
        }
        seen_order.push_back(h);
        if seen_order.len() > DEDUP_CAP {
            if let Some(old) = seen_order.pop_front() {
                seen.remove(&old);
            }
        }

        let record = match parse_record(trimmed) {
            Some(r) => r,
            None => continue,
        };

        if let Some(alert) = synth.ingest(&record) {
            if let Err(e) = writeln!(out, "{}", alert.to_json()) {
                eprintln!("[napse] stdout write error: {e}");
                break;
            }
            // Flush per alert: this runs as a CONTINUOUS service (`tail -F flows | napse >> events`),
            // so a buffered alert would never reach the event store until the 8 KB buffer filled or
            // the process exited. Alerts are infrequent, so a flush each is cheap + timely.
            if let Err(e) = out.flush() {
                eprintln!("[napse] stdout flush error: {e}");
                break;
            }
        }
    }

    // Flush buffered output before the process exits.
    if let Err(e) = out.flush() {
        eprintln!("[napse] stdout flush error: {e}");
    }

    eprintln!(
        "[napse] done — events={} alerts={}",
        synth.events_processed,
        synth.alerts_emitted
    );
}
