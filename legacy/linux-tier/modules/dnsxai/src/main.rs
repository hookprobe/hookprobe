//! WASI entry point for the dnsxai detection module.
//!
//! ## Protocol
//!
//! The supervisor starts this binary under Wasmtime with the grants declared in
//! `module.yaml`:
//! - `read: /var/lib/hookprobe/events` — Senzorium writes newline-delimited DNS
//!   query events here; this process tails the file via stdin redirection.
//! - `wasi-nn: cpu` — reserved for the WASI-NN upgrade path.
//!
//! **Input** — THREE tolerated shapes, tried in order (see [`parse_input_line`]):
//! ```text
//! google.com
//! kq3v9z7x1p2w.com<TAB>10.66.0.20
//! {"type":"dns","query":"kq3v9z7x1p2w.com","src_ip":"10.66.0.20", ...}
//! # comment lines and blank lines are ignored
//! ```
//! 1. **Plain domain** (unchanged since this module's first cut — zero regression for any
//!    existing feed): the whole trimmed line is the domain; no `src_ip` is known.
//! 2. **2026-07-05 device-attribution fix (EDR #10) — tab-separated `domain<TAB>src_ip`**: the
//!    simplest possible extension a shell/awk feed script can emit with zero new dependencies on
//!    either side of the pipe (a domain name can never itself contain a literal tab, so this is
//!    unambiguous).
//! 3. **2026-07-05 device-attribution fix (EDR #10) — a JSON line matching
//!    `napse_loader::dpi::parse_dns`'s ACTUAL emitted DNS event schema**
//!    (`modules/napse-capture/loader/src/dpi.rs`'s `parse_dns`: `{"type":"dns",...,"src_ip":"...",
//!    ...,"query":"...",...}`) — tolerated so this binary can consume that event stream directly,
//!    without a separate domain-extraction step upstream. Extracts `query` (falls back to
//!    `domain` for forward-compat with a differently-shaped future feed) for the domain, and
//!    `src_ip` for attribution. A minimal, hand-rolled string-field extractor — NOT a general JSON
//!    parser (see [`extract_json_string_field`]'s doc) — deliberately, to keep this module's
//!    documented zero-external-dependency posture (`Cargo.toml`'s doc comment: "keeps the .wasm
//!    binary small and the security surface minimal").
//!
//! **Why this closes EDR #10**: before this fix, a DGA/DNS-tunneling verdict had NO requesting-IP
//! at all — a confirmed-malicious query could never be tied back to the infected host that made
//! it. `src_ip`, when the input line carries one (shape 2 or 3), now rides straight through into
//! the output verdict line (below) — the evidence-graph edge wiring from there to a `device` node
//! is a SEPARATE file (`hookprobe-evidence`, outside this pass's ownership); this fix's job is
//! only to make sure the field is PRESENT for that wiring to consume. **Coordination note**: the
//! ACTUAL feed writer (Senzorium / whatever assembles `/var/lib/hookprobe/events` for this
//! process's stdin) must be updated to emit shape 2 or 3 instead of shape 1 for this to have any
//! live effect — that writer is outside this module's ownership; this fix makes the READER side
//! ready and is backward-compatible with the writer unchanged (shape 1 still works exactly as
//! before, `src_ip` simply absent from the output, identical to pre-fix behavior).
//!
//! **Output** (one JSON object per line, written to stdout, consumed by Senzorium):
//! ```json
//! {"domain":"google.com","score":0.0000,"verdict":"benign","reasons":[]}
//! {"domain":"kq3v9z7x1p2w.com","score":0.5500,"verdict":"suspicious","reasons":["very_low_vowels:0.00","high_digit_ratio:0.42","elevated_entropy:3.58"],"src_ip":"10.66.0.20"}
//! ```
//! `src_ip` is present iff the input line carried one (shapes 2/3 above) — omitted entirely
//! (never a fabricated/empty value) for a plain shape-1 line, matching the optional-field
//! convention this codebase already uses elsewhere (e.g. `l2_responder`/`scan_responder`'s
//! `mac_field`/`claimed_ip` optional JSON fields).
//!
//! **Stderr** receives error diagnostics (supervisor may redirect to the log).
//!
//! ## TODO(wasi-nn)
//!
//! When the ONNX model is available, add:
//! ```ignore
//! // let graph = load_wasi_nn_graph("/var/lib/hookprobe/models/dnsxai.onnx");
//! // let result = infer_with_model(&graph, &features.as_tensor());
//! ```
//! and replace `classifier.classify(domain)` with the model inference path.
//! The `DomainFeatures::as_tensor()` method already produces the compatible
//! input tensor.

use dnsxai::DomainClassifier;
use std::io::{self, BufRead, Write};

/// One parsed input line: the domain to classify, plus the requesting source IP when the line's
/// shape carried one (see the module doc's "THREE tolerated shapes"). `src_ip: None` is the
/// honest default for a plain shape-1 line — never fabricated. `domain` is always owned: shape 3
/// (JSON) necessarily allocates a new string when extracting the `query`/`domain` field, so this
/// type owns in every shape rather than being zero-copy in two of the three and requiring a
/// separate code path for the third (that split previously risked exactly the kind of
/// "unreachable in theory, reachable in practice" bug this module's zero-panic discipline forbids
/// — kept simple and uniform instead).
#[derive(Debug, Clone, PartialEq)]
struct ParsedInput {
    domain: String,
    src_ip: Option<String>,
}

/// Minimal, hand-rolled extraction of one `"key":"value"` string field from a JSON-ish line —
/// NOT a general JSON parser (this module ships zero external dependencies by design; see the
/// module doc). Tolerates a backslash-escaped quote inside the value (the ONLY escape this
/// producer's schema ever needs — see `dpi::jesc`, which strips control chars and neutralizes
/// embedded quotes/backslashes to a space, so a well-formed producer's output never actually
/// contains one, but a malformed/adversarial line must not panic or mis-extract either way).
/// Returns `None` if the key isn't present as a `"key":"..."` pair, or its value never closes.
fn extract_json_string_field(line: &str, key: &str) -> Option<String> {
    let needle = format!("\"{key}\":\"");
    let start = line.find(&needle)? + needle.len();
    let rest = line.get(start..)?;
    let mut value = String::new();
    let mut chars = rest.char_indices();
    while let Some((_, ch)) = chars.next() {
        match ch {
            '\\' => {
                // Skip one escaped character (e.g. `\"`) — never let it prematurely close the
                // value, and never panic if the escape is the last byte (malformed input).
                if let Some((_, escaped)) = chars.next() {
                    value.push(escaped);
                } else {
                    return None; // truncated escape — malformed, fail closed (no field)
                }
            }
            '"' => return Some(value), // unescaped quote — the value's real end
            other => value.push(other),
        }
    }
    None // never closed — truncated/malformed line
}

/// Parse one (already trimmed, already known non-blank/non-comment) input line per the module
/// doc's three tolerated shapes, in order: JSON-ish (shape 3) → tab-separated (shape 2) → the
/// whole line as the domain (shape 1, the exact pre-fix behavior — this function is a pure
/// widening of what used to be accepted, never a narrowing). `None` only for a JSON-shaped line
/// that carries neither a `query` nor a `domain` field — nothing can be classified from raw JSON
/// text alone, so the caller skips (never silently treats the JSON text itself as a domain).
fn parse_input_line(line: &str) -> Option<ParsedInput> {
    if line.starts_with('{') {
        let domain = extract_json_string_field(line, "query").or_else(|| extract_json_string_field(line, "domain"))?;
        let src_ip = extract_json_string_field(line, "src_ip");
        return Some(ParsedInput { domain, src_ip });
    }
    if let Some((domain, ip)) = line.split_once('\t') {
        let ip = ip.trim();
        if !domain.is_empty() && !ip.is_empty() {
            return Some(ParsedInput { domain: domain.to_string(), src_ip: Some(ip.to_string()) });
        }
    }
    Some(ParsedInput { domain: line.to_string(), src_ip: None })
}

/// Render one classification result as the exact stdout JSON line `main()` writes — pulled out as
/// its own function (rather than inlined in the stdin loop) so a test can exercise the FULL
/// pipeline (`parse_input_line` → `classifier.classify` → this) end-to-end. That distinction
/// matters for the F3 fix (2026-07-06): EDR #10's regression was that shape-2's `domain<TAB>src_ip`
/// input was scored AS ONE STRING (never split), which a test of `parse_input_line` alone — or of
/// `classify()` alone — cannot catch; only a test that runs a shape-2 line through this whole
/// pipeline and compares it against the bare-domain form proves the fix. Hand-crafted JSON — zero
/// dependencies, minimal allocations (matches this module's documented zero-external-dependency
/// posture). Format mirrors V1 `ClassificationResult.to_dict()`.
fn format_verdict_json(r: &dnsxai::ClassifyResult, src_ip: Option<&str>) -> String {
    let reasons_json = {
        let mut s = String::new();
        for (i, reason) in r.reasons.iter().enumerate() {
            if i > 0 {
                s.push(',');
            }
            s.push('"');
            // Escape any double-quotes inside a reason string.
            for ch in reason.chars() {
                if ch == '"' {
                    s.push('\\');
                }
                s.push(ch);
            }
            s.push('"');
        }
        s
    };

    // 2026-07-05 device-attribution fix (EDR #10): append `src_ip` only when the input line
    // actually carried one — never a fabricated/empty value for a plain shape-1 line.
    let src_ip_field = match src_ip {
        Some(ip) => format!(r#","src_ip":"{}""#, ip.replace('"', "\\\"")),
        None => String::new(),
    };

    format!(
        r#"{{"domain":"{domain}","score":{score:.4},"verdict":"{verdict}","reasons":[{reasons}]{src_ip_field}}}"#,
        // Escape domain if it contains '"' (should never happen for valid FQDNs).
        domain = r.domain.replace('"', "\\\""),
        score = r.score,
        verdict = r.verdict,
        reasons = reasons_json,
        src_ip_field = src_ip_field,
    )
}

fn main() {
    let classifier = DomainClassifier::new();
    let stdin = io::stdin();
    let stdout = io::stdout();
    let mut out = io::LineWriter::new(stdout.lock());

    for line in stdin.lock().lines() {
        let line = match line {
            Ok(l) => l,
            Err(e) => {
                eprintln!("[dnsxai] stdin read error: {e}");
                break;
            }
        };
        let trimmed = line.trim();

        // Skip blank lines and comments.
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }

        let Some(ParsedInput { domain, src_ip }) = parse_input_line(trimmed) else {
            // Only reachable for a JSON-shaped line with no query/domain field at all — logged,
            // never silently treated as if the raw JSON text itself were a domain.
            eprintln!("[dnsxai] skipping JSON-shaped line with no query/domain field: {trimmed}");
            continue;
        };

        let r = classifier.classify(&domain);
        let json = format_verdict_json(&r, src_ip.as_deref());

        if let Err(e) = writeln!(out, "{json}") {
            eprintln!("[dnsxai] stdout write error: {e}");
            break;
        }
        // TA1 (2026-07-17): flush per verdict. This runs as a CONTINUOUS service
        // (`tail -F flows | dnsxai >> dns-verdicts`); a `LineWriter` over WASI stdout does not
        // reliably flush on newline in the wasm streaming context, so on a low-DNS-rate device a
        // buffered verdict never reached the file until the buffer filled — the same rate-dependent
        // starvation that made aegis-guard look dead on the quiet Pi4. Same fix napse already carries.
        if let Err(e) = out.flush() {
            eprintln!("[dnsxai] stdout flush error: {e}");
            break;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_json_string_field_finds_a_simple_value() {
        let line = r#"{"type":"dns","query":"kq3v9z7x1p2w.com","src_ip":"10.66.0.20"}"#;
        assert_eq!(extract_json_string_field(line, "query"), Some("kq3v9z7x1p2w.com".to_string()));
        assert_eq!(extract_json_string_field(line, "src_ip"), Some("10.66.0.20".to_string()));
        assert_eq!(extract_json_string_field(line, "nope"), None);
    }

    #[test]
    fn extract_json_string_field_tolerates_an_escaped_quote_without_panicking() {
        let line = r#"{"query":"exa\"mple.com","src_ip":"10.0.0.1"}"#;
        assert_eq!(extract_json_string_field(line, "query"), Some("exa\"mple.com".to_string()));
    }

    #[test]
    fn extract_json_string_field_fails_closed_on_truncated_input() {
        assert_eq!(extract_json_string_field(r#"{"query":"unterminated"#, "query"), None);
        assert_eq!(extract_json_string_field(r#"{"query":"trailing-escape\"#, "query"), None);
        assert_eq!(extract_json_string_field("", "query"), None);
        assert_eq!(extract_json_string_field("not json at all", "query"), None);
    }

    #[test]
    fn parse_input_line_shape1_plain_domain_is_unchanged() {
        let p = parse_input_line("google.com").expect("shape 1 always parses");
        assert_eq!(p.domain, "google.com");
        assert_eq!(p.src_ip, None, "plain domain line must never fabricate a src_ip");
    }

    #[test]
    fn parse_input_line_shape2_tab_separated_domain_and_src_ip() {
        let p = parse_input_line("kq3v9z7x1p2w.com\t10.66.0.20").expect("shape 2 parses");
        assert_eq!(p.domain, "kq3v9z7x1p2w.com");
        assert_eq!(p.src_ip, Some("10.66.0.20".to_string()));
    }

    #[test]
    fn parse_input_line_falls_back_to_the_whole_line_on_a_malformed_tab_shape() {
        // an empty domain or empty ip before/after the tab isn't shape 2 — treat the whole
        // (trimmed) line as the domain, exactly like a plain shape-1 line would be.
        let p = parse_input_line("\t10.66.0.20").expect("falls back to shape 1");
        assert_eq!(p.domain, "\t10.66.0.20", "malformed shape-2 falls back to shape 1, never panics");
        assert_eq!(p.src_ip, None);
    }

    #[test]
    fn parse_input_line_shape3_json_extracts_query_and_src_ip() {
        let line = r#"{"type":"dns","ts":100.0,"src_ip":"10.66.0.20","src_port":40000,"dst_ip":"1.1.1.1","dst_port":53,"proto":"udp","service":"dns","query":"kq3v9z7x1p2w.com","query_len":16,"query_entropy":3.9}"#;
        let p = parse_input_line(line).expect("shape 3 (dpi::parse_dns's real schema) must parse");
        assert_eq!(p.domain, "kq3v9z7x1p2w.com");
        assert_eq!(p.src_ip, Some("10.66.0.20".to_string()));
    }

    #[test]
    fn parse_input_line_shape3_falls_back_to_domain_field_name() {
        let line = r#"{"domain":"example.com","src_ip":"192.168.1.5"}"#;
        let p = parse_input_line(line).expect("domain field name is a tolerated fallback");
        assert_eq!(p.domain, "example.com");
        assert_eq!(p.src_ip, Some("192.168.1.5".to_string()));
    }

    #[test]
    fn parse_input_line_shape3_without_src_ip_still_classifies() {
        let line = r#"{"type":"dns","query":"google.com"}"#;
        let p = parse_input_line(line).expect("query present, src_ip absent is fine");
        assert_eq!(p.domain, "google.com");
        assert_eq!(p.src_ip, None);
    }

    #[test]
    fn parse_input_line_shape3_with_neither_query_nor_domain_is_none() {
        let line = r#"{"type":"conn","src_ip":"10.0.0.1"}"#;
        assert_eq!(parse_input_line(line), None, "a JSON line with nothing to classify must be skipped, not misparsed");
    }

    // ---- 2026-07-06 F3 proper fix: shape-2 (`domain<TAB>src_ip`) must classify IDENTICALLY to the
    // bare-domain form -----------------------------------------------------------------------------

    /// The exact regression this fix closes: before it, a bare DGA domain scored ~0.83 (malicious)
    /// but `domain<TAB>src_ip` scored 0.0 (benign) because the whole tab-joined string was tokenized
    /// as one "domain" (short/numeric labels dilute every heuristic signal). Runs the FULL pipeline
    /// (`parse_input_line` → `classify` → `format_verdict_json`) for both forms and asserts the
    /// domain, score, and verdict are IDENTICAL, and that ONLY the shape-2 form's output carries
    /// `src_ip`.
    #[test]
    fn shape2_scores_identically_to_bare_form_and_carries_src_ip() {
        let classifier = DomainClassifier::new();
        let bare = "kq3xr7z9v1p2w8x4a0zzqwx.com";
        let shape2 = "kq3xr7z9v1p2w8x4a0zzqwx.com\t10.1.1.9";

        let p_bare = parse_input_line(bare).expect("bare form always parses");
        let p_shape2 = parse_input_line(shape2).expect("shape 2 parses");
        assert_eq!(p_bare.domain, p_shape2.domain, "shape 2 must extract the SAME domain as the bare form");
        assert_eq!(p_shape2.src_ip, Some("10.1.1.9".to_string()));
        assert_eq!(p_bare.src_ip, None, "the bare form must never fabricate a src_ip");

        let r_bare = classifier.classify(&p_bare.domain);
        let r_shape2 = classifier.classify(&p_shape2.domain);
        eprintln!("bare:   score={:.4} verdict={} reasons={:?}", r_bare.score, r_bare.verdict, r_bare.reasons);
        eprintln!("shape2: score={:.4} verdict={} reasons={:?}", r_shape2.score, r_shape2.verdict, r_shape2.reasons);

        // Both forms must be malicious (~0.83) — the confirmed live false negative was shape-2
        // scoring 0.0 (benign) instead.
        assert_ne!(r_bare.verdict, dnsxai::Verdict::Benign, "the bare domain must score as DGA/malicious");
        assert_eq!(r_bare.score, r_shape2.score, "shape 2 must score IDENTICALLY to its bare form");
        assert_eq!(r_bare.verdict, r_shape2.verdict, "shape 2 must reach the SAME verdict as its bare form");
        assert_eq!(r_bare.reasons, r_shape2.reasons, "shape 2 must produce the SAME XAI reasons as its bare form");
        assert!(
            r_bare.score >= 0.60,
            "kq3xr7z9v1p2w8x4a0zzqwx.com is expected to be malicious (~0.83), got {:.4}",
            r_bare.score
        );

        // The rendered JSON: shape 2's output line carries src_ip; the bare form's never does.
        let json_bare = format_verdict_json(&r_bare, p_bare.src_ip.as_deref());
        let json_shape2 = format_verdict_json(&r_shape2, p_shape2.src_ip.as_deref());
        assert!(!json_bare.contains("\"src_ip\""), "the bare form's output must never carry src_ip");
        assert!(json_shape2.contains(r#""src_ip":"10.1.1.9""#), "shape 2's output must carry the requesting src_ip");
        // Domain/score/verdict/reasons fields must be byte-identical between the two outputs, apart
        // from the trailing src_ip field shape 2 alone carries.
        let json_bare_prefix = json_bare.trim_end_matches('}');
        assert!(
            json_shape2.starts_with(json_bare_prefix),
            "shape 2's output must be the bare form's output plus only the appended src_ip field:\n  bare:   {json_bare}\n  shape2: {json_shape2}"
        );
    }
}
