//! WASI entry point for the dga-lm DGA (Domain Generation Algorithm) classifier module.
//!
//! ## Protocol
//!
//! No WASI filesystem grants are needed — this is a pure stdin -> stdout transform
//! (see `module.yaml`'s empty `grants:` list, the tightest possible sandbox).
//!
//! **Input** (one domain name per line):
//! ```text
//! google.com
//! xkj4q9zvw2fh7bqm1.example
//! # comment lines and blank lines are ignored
//! ```
//!
//! **Output** (one JSON object per line, written to stdout):
//! ```json
//! {"domain":"google.com","p_dga":0.0025,"logits":[60,0],"model":"dga-lm-seed-v0.1"}
//! ```
//!
//! JSON fields:
//! - `domain`  — the input domain (echoed back for correlation)
//! - `p_dga`   — softmax-normalized DGA probability, in `[0.0, 1.0]`
//! - `logits`  — raw `[benign_logit, dga_logit]` (pre-softmax, for debugging)
//! - `model`   — model identity string (see `lib.rs::MODEL_ID`; `model/MODEL_CARD.md`)
//!
//! ## Wiring into QSECBIT (advisory/observe-only, C9)
//!
//! This module does NOT itself talk to QSECBIT (each Wasm module is an isolated stdin/
//! stdout process — see `docs/architecture/Readme.md`'s Wasm component model). An orchestrator
//! (reconciler pipeline, os-architect's lane) feeds this module's `p_dga` into
//! `qsecbit`'s stdin as the OPTIONAL 5th CSV field — see `modules/qsecbit/src/main.rs`'s
//! doc comment for the exact contract. The gating itself (whether that 5th field is
//! `p_dga` or the neutral `0.0`) is `ml_cpu_granted` per
//! `crates/hookprobe-manifest/src/capabilities.rs`'s `ml_cpu` known-good gate
//! (base-tier-build-ticket.md Phase 4, ADR 0014 D6), and is now a pure, unit-tested
//! function on this side of the wire: [`dga_lm::p_attack_for_qsecbit`]. That function's
//! doc comment ("QSECBIT connector" block in `lib.rs`) is the authoritative record of
//! what is wired vs. what live-telemetry plumbing (module registration, the
//! event-cadence-vs-5s-tick merge stage) is still missing.
//!
//! **Stderr** receives error diagnostics (supervisor may redirect to the log).

use dga_lm::Scorer;
use std::io::{self, BufRead, Write};

fn main() {
    let scorer = match Scorer::load_seed() {
        Ok(s) => s,
        Err(e) => {
            eprintln!("[dga-lm] failed to load seed model: {e:?}");
            std::process::exit(1);
        }
    };

    let stdin = io::stdin();
    let stdout = io::stdout();
    let mut out = io::LineWriter::new(stdout.lock());

    for line in stdin.lock().lines() {
        let line = match line {
            Ok(l) => l,
            Err(e) => {
                eprintln!("[dga-lm] stdin read error: {e}");
                break;
            }
        };
        let domain = line.trim();

        if domain.is_empty() || domain.starts_with('#') {
            continue;
        }

        let result = scorer.score(domain);

        // Hand-crafted JSON — zero dependencies, minimal allocations (matches
        // modules/qsecbit's convention). `domain` is escaped minimally (only `"`/`\`
        // matter for a domain-name-shaped string; a malformed/adversarial "domain"
        // containing control characters is still handled safely by `escape_json`).
        let json = format!(
            concat!(
                r#"{{"domain":"{domain}","p_dga":{p:.4},"#,
                r#""logits":[{l0},{l1}],"model":"{model}"}}"#,
            ),
            domain = escape_json(&result.domain),
            p = result.p_dga,
            l0 = result.logits[0],
            l1 = result.logits[1],
            model = result.model_id,
        );

        if let Err(e) = writeln!(out, "{json}") {
            eprintln!("[dga-lm] stdout write error: {e}");
            break;
        }
        // TA1 (2026-07-17): flush per line — a LineWriter over WASI stdout doesn't reliably flush on
        // newline in the wasm streaming context (see aegis-guard/dnsxai/qsecbit/napse). Harmless if
        // this ever runs oneshot; required the moment it's driven as a continuous `tail -F` stream.
        if let Err(e) = out.flush() {
            eprintln!("[dga-lm] stdout flush error: {e}");
            break;
        }
    }
}

/// Minimal JSON string escaping (quote + backslash + control characters) — zero
/// dependencies, matches the hand-crafted-JSON convention already used across this
/// module set (see `modules/qsecbit/src/main.rs`, which doesn't need this because its
/// fields are all numeric; `domain` here is attacker-influenced input, so it must be
/// escaped before interpolation into a JSON string literal).
fn escape_json(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escapes_quotes_and_backslashes() {
        assert_eq!(escape_json(r#"a"b\c"#), r#"a\"b\\c"#);
    }

    #[test]
    fn escapes_control_characters() {
        assert_eq!(escape_json("a\nb"), "a\\nb");
    }

    #[test]
    fn passes_through_plain_domain() {
        assert_eq!(escape_json("example.com"), "example.com");
    }
}
