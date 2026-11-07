//! The C9 structural boundary: every type the model's output can be deserialized into, and every
//! type this crate hands back to a caller.
//!
//! **The invariant (CLAUDE.md / ADR 0025): the AI planner is ASSISTIVE and NEVER in the
//! enforcement path.** This module is where that invariant is enforced structurally, not just by
//! instruction:
//!
//! - [`RawLlmOutput`] is the ONLY shape the model's JSON text is ever deserialized into. It has
//!   exactly four fields: a prose `answer`, a prose `why`, a numeric `confidence`, and one
//!   `Option<String>` — `network_intent_patch` — that holds nothing but a YAML blob. There is no
//!   field named `action`/`command`/`execute`/`run`, no enum variant of any kind that represents
//!   "do this now". A model that ignores its instructions and emits e.g. `{"action":"block_ip",
//!   "target":"10.0.0.5"}` produces a `RawLlmOutput` with `answer: ""` (missing required field —
//!   see the parsing fallback in [`parse_llm_json`]) and nothing else; `serde` silently drops
//!   unknown fields (no `deny_unknown_fields`, which would be a worse failure mode: rejecting a
//!   benign extra field). The unrecognized `action`/`target` keys are never read by any code path
//!   in this crate — there is no code that knows how to interpret them.
//! - `network_intent_patch` is a `String`, not a struct — it carries NO authority on its own. It
//!   only becomes meaningful once [`crate::plan::propose`] independently deserializes it as
//!   `hookprobe_manifest::aegis::HookprobeIntent` (the EXISTING schema the deterministic
//!   reconciler already consumes). A patch that fails that parse is dropped with a warning, never
//!   forwarded. `NetworkIntent`'s own fields (`wan`/`wifi`/`fabric`/`microseg`/`trust`/`nac`/
//!   `inspect`) are all DECLARATIVE state — there is no field anywhere in that schema that means
//!   "run this command" either; the deepest an operator or a model can reach is e.g. "set this
//!   device's NAC policy to `isolated`", which the SAME deterministic reconciler + the SAME
//!   `aegis_guard::check_action` policy guard + an explicit human approval must still process
//!   before anything is written to a live config path, let alone applied.
//! - This crate never calls `std::process::Command`, never writes to a live `/etc/hookprobe` (or
//!   any OS-owned) path, and never calls a network/firewall API. The only filesystem write this
//!   crate performs is staging a proposal's generated config-file PREVIEWS under
//!   `/var/lib/hookprobe/planner/staged/<id>/` for operator review (see `main.rs`'s `/approve`
//!   handler) — applying a staged proposal still requires the existing, unchanged
//!   `hookprobe-supervisor --reconcile-network --network-write` step.

use serde::{Deserialize, Serialize};

/// The ONLY shape the model's raw JSON text is deserialized into. See the module doc for why this
/// is the C9 structural boundary. `#[serde(default)]` on every optional field means a model that
/// returns a partial or slightly-malformed-but-still-valid-JSON object degrades gracefully (e.g.
/// no `why` → empty string) rather than failing the whole turn.
#[derive(Debug, Clone, Deserialize, Default, PartialEq)]
pub struct RawLlmOutput {
    /// The model's prose answer to the operator's intent/question. Always shown verbatim.
    #[serde(default)]
    pub answer: String,
    /// The model's own one-line justification (feeds the explanation envelope's `why`, alongside
    /// — never replacing — the deterministic evidence already computed elsewhere).
    #[serde(default)]
    pub why: String,
    /// The model's own confidence, 0–100. Clamped by [`crate::plan::propose`]; never trusted as a
    /// safety signal (it is not consulted anywhere in the enforcement path).
    #[serde(default)]
    pub confidence: f64,
    /// An OPTIONAL YAML blob the model proposes as a `network:` intent-document fragment — see the
    /// module doc for the validation this must survive before it becomes a diff. `None`/absent
    /// means the model is answering a question with no proposed state change at all (the common
    /// case for "what happened last night" / "is my Apple TV ok" style intents).
    #[serde(default)]
    pub network_intent_patch: Option<String>,
}

/// Parse a model's raw text response into [`RawLlmOutput`]. Handles the common "wrapped the JSON
/// in a markdown code fence" failure mode (\`\`\`json ... \`\`\` or bare \`\`\` ... \`\`\`) before
/// giving up. Never panics; a response that is not JSON at all (even after fence-stripping) is
/// treated as a plain-text answer with no proposed diff — the model's own words are not lost, but
/// nothing is ever promoted to a `network_intent_patch` from unstructured text.
pub fn parse_llm_json(raw: &str) -> RawLlmOutput {
    let candidate = strip_code_fence(raw);
    match serde_json::from_str::<RawLlmOutput>(candidate) {
        Ok(v) => v,
        Err(_) => RawLlmOutput { answer: raw.trim().to_string(), ..Default::default() },
    }
}

/// Strips a single leading/trailing markdown code fence (\`\`\`json / \`\`\`) if present; returns
/// the input unchanged otherwise. Only trims whitespace-adjacent fences — does not attempt to find
/// JSON embedded mid-paragraph (kept deliberately simple: any first-version dishonesty here would
/// be "we tried to be clever and half-parsed something", which is worse than the plain-text
/// fallback in [`parse_llm_json`]).
fn strip_code_fence(raw: &str) -> &str {
    let trimmed = raw.trim();
    let Some(after_open) = trimmed.strip_prefix("```") else { return trimmed };
    let after_open = after_open.strip_prefix("json").unwrap_or(after_open);
    let after_open = after_open.trim_start_matches(['\n', '\r']);
    match after_open.rfind("```") {
        Some(idx) => after_open[..idx].trim(),
        None => trimmed,
    }
}

/// One line of a plan-as-diff.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(tag = "kind", content = "text", rename_all = "snake_case")]
pub enum DiffLine {
    Added(String),
    Removed(String),
    Unchanged(String),
}

/// The assistive explanation envelope — MissionControl.md's *why · confidence · evidence · model*
/// contract, from the planner's side. `model` is always the non-secret `endpoint::model_id`
/// identity (see `LlmConfig::describe`) — never null here, because reaching this struct at all
/// means a model call succeeded; the honest `null` case lives entirely in
/// `hookprobe-evidence`/`hookprobe-api`'s `incident_detail`, for incidents the planner has never
/// been run over.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Explanation {
    pub why: String,
    pub confidence: f64,
    pub model: String,
}

/// A config-file PREVIEW — the same `{path, content}` shape as
/// `hookprobe_manifest::multi_wan::GeneratedFile` (which this crate does not modify or re-export;
/// that type doesn't derive `Serialize`, and `multi_wan` is owned by another Tier-3 agent — see
/// `plan::compute_change`'s conversion at the boundary). Never written to a live path by this
/// crate — see the module doc.
#[derive(Debug, Clone, Serialize)]
pub struct ArtifactPreview {
    pub path: String,
    pub content: String,
}

/// A proposed, deterministically-computed desired-state change. Every field here is the OUTPUT of
/// `hookprobe_manifest::aegis::reconcile_network` — a pure function — run once against the
/// CURRENT intent and once against the model's proposed merge; nothing here is model-authored
/// prose. `artifacts` are config-file PREVIEWS only (never written to a live path by this crate —
/// see the module doc).
#[derive(Debug, Clone, Serialize)]
pub struct ProposedChange {
    pub before_plan: Vec<String>,
    pub after_plan: Vec<String>,
    pub diff: Vec<DiffLine>,
    pub artifacts: Vec<ArtifactPreview>,
    pub warnings: Vec<String>,
}

/// The full result of one `propose()` call — what `POST /api/planner/propose` returns and what
/// `CommandPalette.tsx` renders.
#[derive(Debug, Clone, Serialize)]
pub struct PlannerResponse {
    pub answer: String,
    pub explanation: Explanation,
    /// `None` when the model proposed no state change (a plain question) OR its proposed patch
    /// failed validation (see `warnings` for why) — the operator sees the answer text either way,
    /// never a blank screen.
    pub change: Option<ProposedChange>,
    pub warnings: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_clean_json() {
        let raw = r#"{"answer":"ok","why":"because","confidence":80,"network_intent_patch":null}"#;
        let out = parse_llm_json(raw);
        assert_eq!(out.answer, "ok");
        assert_eq!(out.why, "because");
        assert_eq!(out.confidence, 80.0);
        assert!(out.network_intent_patch.is_none());
    }

    #[test]
    fn strips_a_json_code_fence() {
        let raw = "```json\n{\"answer\":\"fenced\"}\n```";
        let out = parse_llm_json(raw);
        assert_eq!(out.answer, "fenced");
    }

    #[test]
    fn strips_a_bare_code_fence() {
        let raw = "```\n{\"answer\":\"bare fence\"}\n```";
        let out = parse_llm_json(raw);
        assert_eq!(out.answer, "bare fence");
    }

    #[test]
    fn non_json_text_becomes_a_plain_answer_never_a_patch() {
        let raw = "I can't help with that particular request, but here is some prose.";
        let out = parse_llm_json(raw);
        assert_eq!(out.answer, raw);
        assert!(out.network_intent_patch.is_none());
    }

    /// THE C9 boundary test: even if the model tries to smuggle a direct enforcement action
    /// through unknown JSON fields, `RawLlmOutput` has nowhere to put it — the extra fields are
    /// silently dropped by serde (no `action`/`command`/`execute` field exists on this struct),
    /// and no code anywhere in this crate ever reads `raw_value`-style catch-alls.
    #[test]
    fn unknown_enforcement_looking_fields_are_structurally_inert() {
        let raw = r#"{
            "answer": "done",
            "action": "block_ip",
            "target": "10.0.0.5",
            "command": "iptables -A INPUT -s 10.0.0.5 -j DROP",
            "execute_now": true
        }"#;
        let out = parse_llm_json(raw);
        assert_eq!(out.answer, "done");
        // There is no field on `RawLlmOutput` to even assert the absence of "action"/"command" —
        // that IS the point. Compile-time proof: this line would not build if such a field existed
        // and this test tried (and failed) to read it. The struct's own definition above is the
        // real assertion; this test exists to document exactly the attack it defeats.
        assert!(out.network_intent_patch.is_none());
    }

    #[test]
    fn confidence_out_of_range_is_not_clamped_here_caller_clamps() {
        // schema-level parsing is honest about what the model said, even if out of range —
        // `plan::propose` is responsible for clamping before it reaches an operator-facing field.
        let raw = r#"{"answer":"x","confidence":250}"#;
        let out = parse_llm_json(raw);
        assert_eq!(out.confidence, 250.0);
    }
}
