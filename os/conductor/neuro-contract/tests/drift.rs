// SPDX-License-Identifier: AGPL-3.0-only
//! Drift gate: this crate mirrors Neuro's `tools/neuro-research/eval/run_eval.py`, the upstream truth for the
//! explainer contract. This test reads that file (as text; nothing runs it) and fails on any difference, so
//! a change on the Neuro side cannot silently diverge from what the device decodes and verifies.
use neuro_contract::*;

fn source() -> String {
    let p = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../tools/neuro-research/eval/run_eval.py");
    std::fs::read_to_string(&p).unwrap_or_else(|e| panic!("cannot read {}: {e}", p.display()))
}

/// The Python list literal assigned to `name` at the start of a line, as strings.
fn list(src: &str, name: &str) -> Vec<String> {
    let line = src.lines().find(|l| l.starts_with(&format!("{name} = ["))).unwrap_or_else(|| panic!("{name} not found"));
    let inner = &line[line.find('[').unwrap() + 1..line.rfind(']').unwrap()];
    inner.split(',').map(|s| s.trim().trim_matches('"').to_string()).collect()
}

/// Concatenate the adjacent string literals of the parenthesised value after `key` (Python implicit
/// concatenation), resolving the escapes these strings use.
fn literals_after(src: &str, key: &str) -> String {
    let start = src.find(key).unwrap_or_else(|| panic!("{key} not found")) + key.len();
    let rest = &src[start..];
    let end = rest.find("),").unwrap_or_else(|| panic!("end of {key} not found"));
    let body = &rest[..end];
    let mut out = String::new();
    let mut chars = body.chars().peekable();
    while let Some(c) = chars.next() {
        if c != '"' {
            continue;
        }
        while let Some(c) = chars.next() {
            match c {
                '"' => break,
                '\\' => match chars.next() {
                    Some('n') => out.push('\n'),
                    Some(x) => out.push(x),
                    None => {}
                },
                _ => out.push(c),
            }
        }
    }
    out
}

#[test]
fn contract_matches_run_eval_py() {
    let src = source();
    assert_eq!(list(&src, "VERDICTS"), VERDICTS);
    assert_eq!(list(&src, "SEVERITIES"), SEVERITIES);
    assert_eq!(list(&src, "NEXT"), NEXT_STEPS);
    assert_eq!(literals_after(&src, "\"en\": ("), SYSTEM_EN, "SYSTEM[en] differs");
    assert_eq!(literals_after(&src, "\"ro\": ("), SYSTEM_RO, "SYSTEM[ro] differs");
    // Exact source fragments the device mirrors. Each one is the Python text as written.
    let required = format!("\"required\": [{}]", KEYS.iter().map(|k| format!("\"{k}\"")).collect::<Vec<_>>().join(", "));
    let fragments = [
        // the id rule
        r#"facts = re.findall(r"^(F\d+)\b", ctx, re.M)"#.to_string(),
        r#"ents = sorted(set(re.findall(r"\b([HRD]\d+)\b", ctx)), key=lambda x: (x[0], int(x[1:])))"#.to_string(),
        // the schema
        r#"ev = {"type": "string", "enum": facts} if (closed and facts) else {"type": "string"}"#.to_string(),
        r#"en = {"type": "string", "enum": ents} if (closed and ents) else {"type": "string"}"#.to_string(),
        r#""type": "object", "additionalProperties": False,"#.to_string(),
        required,
        format!(r#""summary": {{"type": "string", "maxLength": {SUMMARY_MAX_CHARS}}},"#),
        format!(r#""evidence": {{"type": "array", "items": ev, "maxItems": {LIST_MAX}}},"#),
        format!(r#""entities": {{"type": "array", "items": en, "maxItems": {LIST_MAX}}},"#),
        format!(r#""confidence": {{"type": "integer", "minimum": {CONFIDENCE_MIN}, "maximum": {CONFIDENCE_MAX}}},"#),
        r#""verdict": {"type": "string", "enum": VERDICTS},"#.to_string(),
        r#""severity": {"type": "string", "enum": SEVERITIES},"#.to_string(),
        r#""next_step": {"type": "string", "enum": NEXT},"#.to_string(),
        // the prompt framing
        r#""CONTEXT (untrusted):\n<<<\n%s\n>>>\n\nQUESTION: %s""#.to_string(),
        r#"msgs[0]["content"] += (" Reply with ONE JSON object and nothing else, matching this JSON schema exactly ""#.to_string(),
        r#""(lowercase enum values): " + json.dumps(schema, ensure_ascii=False))"#.to_string(),
        // closed mode = this schema as a grammar
        r#"extra["response_format"] = {"type": "json_schema", "json_schema": {"name": "triage", "strict": True, "schema": schema}}"#.to_string(),
    ];
    for f in &fragments {
        assert!(src.contains(f.as_str()), "run_eval.py no longer contains:\n  {f}\nUpdate neuro-contract to match Neuro's change.");
    }
    // The pieces above, reassembled, are this crate's constants.
    assert_eq!(USER_HEAD, "CONTEXT (untrusted):\n<<<\n");
    assert_eq!(USER_MID, "\n>>>\n\nQUESTION: ");
    assert_eq!(FORMAT_LEAD, " Reply with ONE JSON object and nothing else, matching this JSON schema exactly (lowercase enum values): ");
    // Key order in `properties` equals `required` and KEYS.
    let props = &src[src.find("\"properties\": {").unwrap()..];
    let mut last = 0usize;
    for k in KEYS {
        let at = props.find(&format!("\"{k}\": {{")).unwrap_or_else(|| panic!("property {k} missing"));
        assert!(at >= last, "property {k} out of order");
        last = at;
    }
    println!("drift gate: neuro-contract equals run_eval.py ({} fragments, 3 enums, 2 system prompts)", fragments.len());
}
