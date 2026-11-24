// SPDX-License-Identifier: AGPL-3.0-only
//! The contract: id rule against a regex reference, schema text, the answer automaton.
use neuro_contract::*;

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
}

fn ids(ctx: &str) -> (IdList, IdList) {
    let (mut f, mut e) = (IdList::new(), IdList::new());
    context_ids(ctx.as_bytes(), &mut f, &mut e).unwrap();
    (f, e)
}

fn strs(l: &IdList) -> Vec<String> {
    l.iter().map(|s| String::from_utf8(s.to_vec()).unwrap()).collect()
}

/// `facts_and_entities` re-implemented with the regex crate (ASCII digits, as documented).
fn reference(ctx: &str) -> (Vec<String>, Vec<String>) {
    let facts = regex::Regex::new(r"(?m)^(F[0-9]+)\b").unwrap();
    let ents = regex::Regex::new(r"\b([HRD][0-9]+)\b").unwrap();
    let f = facts.captures_iter(ctx).map(|c| c[1].to_string()).collect();
    let mut e: Vec<String> = ents.captures_iter(ctx).map(|c| c[1].to_string()).collect::<std::collections::BTreeSet<_>>().into_iter().collect();
    e.sort_by_key(|x| (x.as_bytes()[0], x[1..].parse::<u128>().unwrap()));
    (f, e)
}

#[test]
fn context_ids_match_the_regex_reference() {
    let (f, e) = ids("F1 port scan from H2 to R1\nF2 dns D10 D9 H2\nF3x not\n F4 indented\nF12 ok H1_x R5.\nH7");
    assert_eq!(strs(&f), ["F1", "F2", "F12"]);
    assert_eq!(strs(&e), ["D9", "D10", "H2", "H7", "R1", "R5"]);
    let mut r = Rng(3);
    let alphabet = b"FHRD0123456789 \n_.:,x";
    for _ in 0..50_000 {
        let n = (r.next() % 60) as usize;
        let s: String = (0..n).map(|_| alphabet[(r.next() % alphabet.len() as u64) as usize] as char).collect();
        let (f, e) = ids(&s);
        let (rf, re) = reference(&s);
        if rf.iter().chain(&re).any(|x| x.len() > ID_MAX) || rf.len() > IDS_MAX || re.len() > IDS_MAX {
            continue;
        }
        assert_eq!((strs(&f), strs(&e)), (rf, re), "{s:?}");
    }
}

#[test]
fn schema_text_is_python_json_dumps() {
    let (f, e) = ids("F1 a H1\nF2 b R3");
    let mut buf = [0u8; 4096];
    let mut o = Out::new(&mut buf);
    write_schema(&f, &e, true, &mut o).unwrap();
    let n = o.n;
    let got = std::str::from_utf8(&buf[..n]).unwrap();
    // What `json.dumps(triage_schema(ctx, True), ensure_ascii=False)` prints for this context.
    let want = r#"{"type": "object", "additionalProperties": false, "required": ["verdict", "severity", "summary", "evidence", "entities", "next_step", "confidence"], "properties": {"verdict": {"type": "string", "enum": ["malicious", "suspicious", "benign", "insufficient_evidence"]}, "severity": {"type": "string", "enum": ["info", "low", "medium", "high", "critical"]}, "summary": {"type": "string", "maxLength": 600}, "evidence": {"type": "array", "items": {"type": "string", "enum": ["F1", "F2"]}, "maxItems": 8}, "entities": {"type": "array", "items": {"type": "string", "enum": ["H1", "R3"]}, "maxItems": 8}, "next_step": {"type": "string", "enum": ["observe", "investigate", "harden", "isolate_review"]}, "confidence": {"type": "integer", "minimum": 0, "maximum": 100}}}"#;
    assert_eq!(got, want);
    // No facts: the items fall back to plain strings (as triage_schema does).
    let (f0, e0) = ids("no ids here");
    let mut o = Out::new(&mut buf);
    write_schema(&f0, &e0, true, &mut o).unwrap();
    let n = o.n;
    assert!(std::str::from_utf8(&buf[..n]).unwrap().contains(r#""evidence": {"type": "array", "items": {"type": "string"}, "maxItems": 8}"#));
    // Too small a buffer is refused.
    let mut small = [0u8; 10];
    assert_eq!(write_schema(&f, &e, true, &mut Out::new(&mut small)), Err(ContractError::Space));
}

fn accepts(text: &str, f: &IdList, e: &IdList) -> bool {
    let mut m = Machine::new(Allowed { facts: f, entities: e, closed: true });
    m.feed(text.as_bytes()) && m.accepting()
}

#[test]
fn automaton_accepts_exactly_the_contract() {
    let (f, e) = ids("F1 a H1\nF2 b R3\nF10 c");
    let good = [
        r#"{"verdict":"suspicious","severity":"medium","summary":"H1 scanned R3 (F1).","evidence":["F1","F10"],"entities":["H1"],"next_step":"investigate","confidence":60}"#,
        r#"{"verdict": "benign", "severity": "info", "summary": "", "evidence": [], "entities": [], "next_step": "observe", "confidence": 0}"#,
        "{\n  \"verdict\": \"malicious\",\n  \"severity\": \"critical\",\n  \"summary\": \"a \\\"quoted\\\" \\u00e9 é ✓\",\n  \"evidence\": [ \"F2\" ],\n  \"entities\": [\"R3\", \"H1\"],\n  \"next_step\": \"isolate_review\",\n  \"confidence\": 100\n} ",
        r#"{"verdict":"insufficient_evidence","severity":"low","summary":"x","evidence":["F1","F1"],"entities":[],"next_step":"harden","confidence":9}"#,
    ];
    for g in good {
        assert!(accepts(g, &f, &e), "refused: {g}");
        let a = parse(g.as_bytes(), &f, &e).unwrap();
        assert!(VERDICTS.contains(&a.verdict_name()));
    }
    let a = parse(good[0].as_bytes(), &f, &e).unwrap();
    assert_eq!((a.verdict_name(), a.severity, a.next_step, a.confidence), ("suspicious", 2, 1, 60));
    assert_eq!(a.summary(good[0].as_bytes()), b"H1 scanned R3 (F1).");
    assert_eq!((a.evidence(), a.entities()), (&[0u8, 2][..], &[0u8][..]));
    let bad = [
        // fabricated ids, wrong order, unknown key, out-of-enum, bounds, leading zero, trailing text
        r#"{"verdict":"benign","severity":"info","summary":"","evidence":["F3"],"entities":[],"next_step":"observe","confidence":1}"#,
        r#"{"verdict":"benign","severity":"info","summary":"","evidence":[],"entities":["H2"],"next_step":"observe","confidence":1}"#,
        r#"{"severity":"info","verdict":"benign","summary":"","evidence":[],"entities":[],"next_step":"observe","confidence":1}"#,
        r#"{"verdict":"Benign","severity":"info","summary":"","evidence":[],"entities":[],"next_step":"observe","confidence":1}"#,
        r#"{"verdict":"benign","severity":"info","summary":"","evidence":[],"entities":[],"next_step":"observe","confidence":101}"#,
        r#"{"verdict":"benign","severity":"info","summary":"","evidence":[],"entities":[],"next_step":"observe","confidence":07}"#,
        r#"{"verdict":"benign","severity":"info","summary":"","evidence":[],"entities":[],"next_step":"observe","confidence":7}x"#,
        r#"{"verdict":"benign","severity":"info","summary":"","evidence":["F1",],"entities":[],"next_step":"observe","confidence":7}"#,
        r#"{"verdict":"benign","severity":"info","summary":"","evidence":["F1","F1","F1","F1","F1","F1","F1","F1","F1"],"entities":[],"next_step":"observe","confidence":7}"#,
        r#"{"verdict":"benign","severity":"info","summary":"tab	raw","evidence":[],"entities":[],"next_step":"observe","confidence":7}"#,
        r#"{"verdict":"benign","severity":"info","summary":"\x","evidence":[],"entities":[],"next_step":"observe","confidence":7}"#,
        r#"{"verdict":"benign","severity":"info","summary":"","evidence":[],"entities":[],"next_step":"observe","confidence":7,"extra":1}"#,
        r#"{ "verdict":"benign","severity":"info","summary":"","evidence":[],"entities":[],"next_step":"observe","confidence":7 }"#.replace("{ ", "{  ").leak(),
        "{\t\"verdict\":\"benign\",\"severity\":\"info\",\"summary\":\"\",\"evidence\":[],\"entities\":[],\"next_step\":\"observe\",\"confidence\":7}",
    ]
    .into_iter()
    .map(String::from)
    .collect::<Vec<_>>();
    for b in &bad {
        assert!(!accepts(b, &f, &e), "accepted: {b}");
        assert_eq!(parse(b.as_bytes(), &f, &e).err(), Some(ContractError::Invalid));
    }
    // Summary: exactly 600 characters allowed (multi-byte and escapes count as one), 601 refused.
    let mk = |s: &str| format!(r#"{{"verdict":"benign","severity":"info","summary":"{s}","evidence":[],"entities":[],"next_step":"observe","confidence":1}}"#);
    assert!(accepts(&mk(&"é".repeat(600)), &f, &e));
    assert!(accepts(&mk(&"\\n".repeat(600)), &f, &e));
    assert!(!accepts(&mk(&"a".repeat(601)), &f, &e));
    // Whitespace rule: "" | " " | "\n"{1,2} [ \t]{0,20}
    let w = |ws: &str| format!(r#"{{"verdict":{ws}"benign","severity":"info","summary":"","evidence":[],"entities":[],"next_step":"observe","confidence":1}}"#);
    for ok in ["", " ", "\n", "\n\n", "\n\t\t", &format!("\n{}", " ".repeat(20))] {
        assert!(accepts(&w(ok), &f, &e), "ws {ok:?}");
    }
    for no in ["  ", "\n\n\n", " \n", &format!("\n{}", " ".repeat(21)), "\t"] {
        assert!(!accepts(&w(no), &f, &e), "ws {no:?}");
    }
    // Prefix property: every prefix of a good answer is accepted, and only the complete one is accepting.
    for g in good {
        let mut m = Machine::new(Allowed { facts: &f, entities: &e, closed: true });
        for (i, b) in g.bytes().enumerate() {
            assert!(m.feed(&[b]), "prefix {i} of {g}");
            assert_eq!(m.accepting(), i >= g.rfind('}').unwrap(), "accepting at {i}");
        }
    }
    // Not closed: any id strings are allowed.
    let mut m = Machine::new(Allowed { facts: &f, entities: &e, closed: false });
    assert!(m.feed(br#"{"verdict":"benign","severity":"info","summary":"","evidence":["anything"],"entities":["Z9"],"next_step":"observe","confidence":1}"#) && m.accepting());
}

#[test]
fn ids_by_line_equal_ids_of_the_joined_context_and_unescape_works() {
    let mut r = Rng(11);
    let alphabet = b"FHRD0123456789 _.:,x";
    for _ in 0..20_000 {
        let lines: Vec<String> = (0..(1 + r.next() % 5)).map(|_| (0..(r.next() % 20)).map(|_| alphabet[(r.next() % alphabet.len() as u64) as usize] as char).collect()).collect();
        let joined = lines.join("\n");
        let (f, e) = ids(&joined);
        let (mut f2, mut e2) = (IdList::new(), IdList::new());
        for l in &lines {
            ids_add(l.as_bytes(), &mut f2, &mut e2).unwrap();
        }
        ids_finish(&mut e2);
        assert_eq!((strs(&f), strs(&e)), (strs(&f2), strs(&e2)), "{joined:?}");
    }
    let un = |s: &str| -> Result<String, ContractError> {
        let mut b = [0u8; 256];
        let mut o = Out::new(&mut b);
        unescape(s.as_bytes(), &mut o)?;
        let n = o.n;
        Ok(String::from_utf8(b[..n].to_vec()).unwrap())
    };
    assert_eq!(un(r#"a\"b\\c\ndé😀"#).unwrap(), "a\"b\\c\nd\u{e9}\u{1f600}");
    assert_eq!(un("\\u202e").unwrap(), "\u{202e}");
    assert_eq!(un(r#"\ud83d"#), Err(ContractError::Invalid));
    assert_eq!(un(r#"\ud83dx"#), Err(ContractError::Invalid));
    assert_eq!(un(r#"\x"#), Err(ContractError::Invalid));
}
