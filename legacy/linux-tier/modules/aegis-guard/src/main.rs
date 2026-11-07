//! WASI entry point for the AEGIS Guard module.
//!
//! ## Protocol
//!
//! The supervisor starts this binary under Wasmtime with the grants declared in
//! `module.yaml`:
//! - `read: /var/lib/hookprobe/policy` — active policy / desired-state from the
//!   AEGIS reconciler.
//! - `read: /var/lib/hookprobe/events` — normalized telemetry events from
//!   Senzorium; stdin is redirection of this stream.
//!
//! **Input** (one event per line, comma-separated fields):
//! ```text
//! # Guard check:  guard,<action>,<risk>[,<trust_score>]
//! # Reflex eval:  reflex,<ip>,<score>[,<velocity>]
//! # Blank lines and lines starting with '#' are ignored.
//!
//! guard,update_report,low
//! guard,full_quarantine,medium,0.0
//! guard,disable_firewall,low
//! guard,block_ip,low,0.9
//! reflex,192.168.1.1,0.25,0.0
//! reflex,10.0.0.1,0.45,0.12
//! reflex,10.0.0.2,0.70,0.0
//! reflex,10.0.0.3,0.90,-0.06
//! ```
//!
//! Fields:
//! - `action`       — action name (snake_case), e.g. `disable_firewall`
//! - `risk`         — declared impact: `low | medium | high | critical`
//! - `trust_score`  — target device trust score in `[0.0, 1.0]` (default 0.0)
//! - `ip`           — source IP string (label only; no IP parsing)
//! - `score`        — QSecBit score in `[0.0, 1.0]`
//! - `velocity`     — dQ/dt in score-units/second (default 0.0)
//!
//! **Output** (one JSON object per input line, written to stdout):
//! ```json
//! {"mode":"guard","action":"update_report","verdict":"AutoApply","reason":"Action permitted: no principle violations, within impact threshold."}
//! {"mode":"guard","action":"full_quarantine","verdict":"RequireApproval","reason":"Action is in the confirmation-required set; human approval needed before execution."}
//! {"mode":"guard","action":"disable_firewall","verdict":"Deny","reason":"Never disable firewall, IDS, DNS protection, or any security service","principle":"never_disable_protection"}
//! {"mode":"guard","action":"block_ip","verdict":"RequireApproval","reason":"Cannot auto-block a device with trust score 90% (> 80%). Human approval required (principle: never_block_trusted).","principle":"never_block_trusted"}
//! {"mode":"reflex","ip":"192.168.1.1","score":0.2500,"level":"OBSERVE","response":"monitor","jitter_ms":0,"reason":"ip=192.168.1.1 Q=0.250 → OBSERVE"}
//! {"mode":"reflex","ip":"10.0.0.1","score":0.4500,"level":"JITTER","response":"add_jitter","jitter_ms":132,"reason":"ip=10.0.0.1 Q=0.450 → JITTER (fast rise dQ/dt=0.1200)"}
//! {"mode":"reflex","ip":"10.0.0.2","score":0.7000,"level":"SHADOW","response":"redirect_to_honeypot","jitter_ms":0,"reason":"ip=10.0.0.2 Q=0.700 → SHADOW"}
//! {"mode":"reflex","ip":"10.0.0.3","score":0.9000,"level":"DISCONNECT","response":"block_ip","jitter_ms":0,"reason":"ip=10.0.0.3 Q=0.900 → DISCONNECT (rapid decay dQ/dt=-0.0600)"}
//! ```
//!
//! JSON fields for guard output:
//! - `mode`      — always `"guard"`
//! - `action`    — the action that was evaluated
//! - `verdict`   — `"AutoApply" | "RequireApproval" | "Deny"`
//! - `reason`    — human-readable explanation
//! - `principle` — (Deny only, and never_block_trusted) violated principle key
//!
//! JSON fields for reflex output:
//! - `mode`      — always `"reflex"`
//! - `ip`        — source IP string
//! - `score`     — QSecBit score passed in
//! - `level`     — `"OBSERVE" | "JITTER" | "SHADOW" | "DISCONNECT"`
//! - `response`  — prescribed response token
//! - `jitter_ms` — jitter delay in ms (0 unless JITTER level)
//! - `reason`    — human-readable explanation with velocity annotation
//!
//! **Stderr** receives diagnostic messages (supervisor may redirect to the log).

use aegis_guard::{check_action, evaluate_reflex, RiskLevel};
use std::io::{self, BufRead, Write};

fn main() {
    let stdin = io::stdin();
    let stdout = io::stdout();
    let mut out = io::LineWriter::new(stdout.lock());

    for line in stdin.lock().lines() {
        let line = match line {
            Ok(l) => l,
            Err(e) => {
                eprintln!("[aegis-guard] stdin read error: {e}");
                break;
            }
        };
        let trimmed = line.trim();

        // Skip blank lines and comments.
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }

        let parts: Vec<&str> = trimmed.split(',').collect();
        if parts.is_empty() {
            continue;
        }

        let json = match parts[0].trim() {
            "guard" => handle_guard(&parts),
            "reflex" => handle_reflex(&parts),
            other => {
                eprintln!("[aegis-guard] unknown mode {other:?}; expected 'guard' or 'reflex'");
                continue;
            }
        };

        match json {
            Some(j) => {
                if let Err(e) = writeln!(out, "{j}") {
                    eprintln!("[aegis-guard] stdout write error: {e}");
                    break;
                }
                // TA1 (2026-07-17 field root-cause): FLUSH per verdict. A `LineWriter` over a WASI
                // stdout does NOT reliably flush on newline in the wasm streaming context, so on a
                // LOW-verdict-rate device (a quiet, well-defended network — the COMMON case) each
                // verdict sat in the buffer indefinitely and NEVER reached
                // `/var/lib/hookprobe/aegis-verdicts` (0 bytes), making the ADR-0023 reflex
                // ENFORCEMENT path look DEAD. A busy device only "worked" because verdict volume
                // happened to fill the buffer — which is exactly why this presented as an
                // "A72-only" bug (the quiet Pi4 vs the busy CM5), when it is really rate-dependent
                // and CPU-agnostic. Explicit flush = every verdict is delivered the instant it's
                // decided, at any rate.
                if let Err(e) = out.flush() {
                    eprintln!("[aegis-guard] stdout flush error: {e}");
                    break;
                }
            }
            None => {} // error already printed to stderr
        }
    }
}

// ─── Guard handler ─────────────────────────────────────────────────────────────

fn handle_guard(parts: &[&str]) -> Option<String> {
    // guard,<action>,<risk>[,<trust_score>]
    if parts.len() < 3 {
        eprintln!(
            "[aegis-guard] guard: expected ≥3 fields (guard,action,risk), got: {:?}",
            parts
        );
        return None;
    }

    let action = parts[1].trim();
    let risk_str = parts[2].trim();
    let trust_score: f64 = if parts.len() >= 4 {
        match parts[3].trim().parse() {
            Ok(v) => v,
            Err(_) => {
                eprintln!(
                    "[aegis-guard] guard: non-numeric trust_score {:?}",
                    parts[3]
                );
                return None;
            }
        }
    } else {
        0.0
    };

    let risk = match RiskLevel::parse_str(risk_str) {
        Some(r) => r,
        None => {
            eprintln!(
                "[aegis-guard] guard: unknown risk level {risk_str:?}; \
                 expected low|medium|high|critical"
            );
            return None;
        }
    };

    let decision = check_action(action, risk, trust_score);

    let json = if let Some(principle) = decision.principle {
        format!(
            concat!(
                r#"{{"mode":"guard","action":"{action}","#,
                r#""verdict":"{verdict}","reason":"{reason}","principle":"{principle}"}}"#,
            ),
            action = json_escape(action),
            verdict = decision.verdict.as_str(),
            reason = json_escape(&decision.reason),
            principle = principle,
        )
    } else {
        format!(
            concat!(
                r#"{{"mode":"guard","action":"{action}","#,
                r#""verdict":"{verdict}","reason":"{reason}"}}"#,
            ),
            action = json_escape(action),
            verdict = decision.verdict.as_str(),
            reason = json_escape(&decision.reason),
        )
    };

    Some(json)
}

// ─── Reflex handler ────────────────────────────────────────────────────────────

fn handle_reflex(parts: &[&str]) -> Option<String> {
    // reflex,<ip>,<score>[,<velocity>]
    if parts.len() < 3 {
        eprintln!(
            "[aegis-guard] reflex: expected ≥3 fields (reflex,ip,score), got: {:?}",
            parts
        );
        return None;
    }

    let ip = parts[1].trim();
    let score: f64 = match parts[2].trim().parse() {
        Ok(v) => v,
        Err(_) => {
            eprintln!("[aegis-guard] reflex: non-numeric score {:?}", parts[2]);
            return None;
        }
    };
    let velocity: f64 = if parts.len() >= 4 {
        match parts[3].trim().parse() {
            Ok(v) => v,
            Err(_) => {
                eprintln!(
                    "[aegis-guard] reflex: non-numeric velocity {:?}",
                    parts[3]
                );
                return None;
            }
        }
    } else {
        0.0
    };

    let decision = evaluate_reflex(ip, score, velocity);

    let json = format!(
        concat!(
            r#"{{"mode":"reflex","ip":"{ip}","score":{score:.4},"#,
            r#""level":"{level}","response":"{response}","#,
            r#""jitter_ms":{jitter_ms},"reason":"{reason}"}}"#,
        ),
        ip = json_escape(ip),
        score = score,
        level = decision.level.as_str(),
        response = decision.response,
        jitter_ms = decision.jitter_ms,
        reason = json_escape(&decision.reason),
    );

    Some(json)
}

// ─── JSON string escaper ───────────────────────────────────────────────────────

/// Minimal JSON string escaper — zero dependencies.
///
/// Handles the characters that appear in aegis-guard output: `"`, `\`, and
/// control characters. The `→` arrow in reason strings is valid UTF-8 and safe
/// in JSON without escaping.
fn json_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 4);
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                out.push_str(&format!("\\u{:04x}", c as u32));
            }
            c => out.push(c),
        }
    }
    out
}
