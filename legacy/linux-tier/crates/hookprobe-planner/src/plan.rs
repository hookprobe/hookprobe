//! Intent → plan-as-diff. The one function that ties the adapter, the schema boundary, and the
//! EXISTING deterministic reconciler together.
//!
//! ```text
//!  operator intent (NL text) ──┐
//!  manifest + evidence summary ┤─▶ Adapter::chat (BYO-LLM) ─▶ RawLlmOutput (schema boundary)
//!                              │                                     │
//!                              │              network_intent_patch (YAML, untrusted) │
//!                              │                                     ▼
//!                              │            parse as hookprobe_manifest::aegis::HookprobeIntent
//!                              │              (fails → dropped + warning, NEVER forwarded)
//!                              │                                     │
//!                              │                              merge into current intent
//!                              │                                     │
//!                              └────────────────────────▶ aegis::reconcile_network (PURE, EXISTING,
//!                                                          UNCHANGED — computes the actual diff)
//! ```
//!
//! The model never sees or produces anything downstream of `network_intent_patch`'s YAML text —
//! `reconcile_network` is the same function `hookprobe-supervisor --reconcile-network` already
//! calls for operator-authored intent files, so a model-proposed intent is held to EXACTLY the
//! same schema and produces EXACTLY the same class of plan/artifacts/warnings a human-authored one
//! would. Nothing here writes to a live path or calls an enforcement API — see `schema`'s module
//! doc for the full boundary argument.

use crate::adapter::{Adapter, AdapterError};
use crate::diff::diff_plan;
use crate::schema::{parse_llm_json, ArtifactPreview, Explanation, PlannerResponse, ProposedChange};
use hookprobe_manifest::aegis::{self, HookprobeIntent, NetworkIntent};
use hookprobe_manifest::types::{CapabilityState, Manifest};

/// Everything `propose` needs about the device's current, real state. Built by the caller
/// (`main.rs`) from the signed Platform Manifest + the on-disk `network.yaml` + an evidence-graph
/// summary string — this module has no opinion about where those come from.
pub struct PlanContext {
    /// `None` on a device that hasn't first-booted yet (no `manifest.json` on disk) — the honest
    /// default, same convention `hookprobe-api::manifest_view` already uses. A model-proposed
    /// `network_intent_patch` is still validated for SCHEMA-VALIDITY either way, but computing an
    /// actual diff requires a real manifest (`reconcile_network`'s first argument), so `propose`
    /// degrades to "answer only, with a warning" rather than fabricating one.
    pub manifest: Option<Manifest>,
    pub current_intent: NetworkIntent,
    /// A short, human-readable grounding blurb (e.g. device counts, recent incidents) folded into
    /// the model's user turn. May be empty.
    pub evidence_summary: String,
}

impl PlanContext {
    /// Whether the `openvswitch` capability is granted on this device — `reconcile_network`'s
    /// third argument. Mirrors the exact lookup `hookprobe-supervisor`'s `--reconcile-network` CLI
    /// path already uses (see `supervisor/src/main.rs`), so a model-proposed reconcile and an
    /// operator-authored one are evaluated identically. `false` (the safe Linux-bridge-fallback
    /// default `fabric::plan` already applies) when no manifest is present at all.
    pub fn ovs_granted(&self) -> bool {
        self.manifest.as_ref().is_some_and(|m| {
            m.capabilities.get("openvswitch").is_some_and(|c| matches!(c.state, CapabilityState::Granted))
        })
    }
}

const SYSTEM_PROMPT: &str = r#"You are the AEGIS assistive planner for HookProbe OS, a home/small-site security
appliance. You are NEVER allowed to directly execute, block, quarantine, or disconnect anything —
you only ANSWER questions and, when appropriate, PROPOSE a declarative change to the operator's
`network:` intent document. A separate, deterministic system computes the actual effect of any
proposed change and a human operator must explicitly approve it before anything is applied.

Reply with STRICT JSON only (no markdown, no commentary outside the JSON object), matching exactly:
{
  "answer": "<plain-English answer to the operator, always present>",
  "why": "<one-line justification>",
  "confidence": <integer 0-100>,
  "network_intent_patch": "<a YAML string with a single top-level `network:` key containing ONLY
     the section(s) you want to change (e.g. `nac`), or null if you are not proposing any change>"
}

The `network_intent_patch`, if present, must be valid YAML matching this schema (all sections
optional; include only what you are changing):
network:
  nac:
    devices:
      - identity: <string>
        mac: <string, optional>
        policy: full_access | lan_only | internet_only | streaming | onboarding_grace | isolated
  trust:
    quarantine_segment: <string>
    quarantine_vlan: <integer>
    risk_threshold: <number>

Never invent a MAC address, device identity, or fact not present in the context you were given."#;

/// Run one planning turn. Returns `Err(AdapterError::NotConfigured)` immediately, before any
/// network call, if `adapter` wraps no configured endpoint — callers should check
/// `LlmConfig::from_env().is_some()` themselves and prefer surfacing that as a distinct "not
/// configured" UI state rather than routing it through this error path, but this function is
/// defensively honest either way (see `main.rs`'s `/propose` handler for the primary check).
pub fn propose(adapter: &Adapter, intent_text: &str, ctx: &PlanContext) -> Result<PlannerResponse, AdapterError> {
    let user = build_user_prompt(intent_text, ctx);
    let raw_text = adapter.chat(SYSTEM_PROMPT, &user)?;
    let parsed = parse_llm_json(&raw_text);

    let mut warnings = Vec::new();
    let change = match &parsed.network_intent_patch {
        Some(yaml) if !yaml.trim().is_empty() => match validate_patch(yaml) {
            Ok(patch) => match &ctx.manifest {
                Some(manifest) => Some(compute_change(manifest, ctx, &patch)),
                None => {
                    warnings.push(
                        "no Platform Manifest present on this device yet — network intent \
                         proposals need one to compute a real diff; showing the answer only"
                            .to_string(),
                    );
                    None
                }
            },
            Err(e) => {
                warnings.push(format!(
                    "the model proposed a network_intent_patch that failed validation ({e}); \
                     showing the answer only, no diff to review"
                ));
                None
            }
        },
        _ => None,
    };

    let why = if parsed.why.trim().is_empty() { parsed.answer.clone() } else { parsed.why.clone() };
    Ok(PlannerResponse {
        answer: parsed.answer,
        explanation: Explanation { why, confidence: parsed.confidence.clamp(0.0, 100.0), model: adapter.describe() },
        change,
        warnings,
    })
}

/// Validate a model-proposed YAML patch by deserializing it into the EXISTING intent schema.
/// Deliberately does nothing else — this function's only job is "does this parse", so a failure
/// here can never be confused with a reconciliation failure (which `compute_change` handles via
/// `ReconcileResult::warnings`, an entirely separate, already-existing concept).
fn validate_patch(yaml: &str) -> anyhow::Result<NetworkIntent> {
    Ok(HookprobeIntent::parse(yaml)?.network)
}

/// Merge a validated patch into the current intent: for each optional section, the patch's value
/// wins IF PRESENT, else the current value is kept. A model that includes only `nac:` in its patch
/// (the common case) leaves every other section — WAN, Wi-Fi, fabric, microseg, trust, inspect —
/// completely untouched.
fn merge_intent(current: &NetworkIntent, patch: &NetworkIntent) -> NetworkIntent {
    NetworkIntent {
        wan: patch.wan.clone().or_else(|| current.wan.clone()),
        wifi: patch.wifi.clone().or_else(|| current.wifi.clone()),
        fabric: patch.fabric.clone().or_else(|| current.fabric.clone()),
        microseg: patch.microseg.clone().or_else(|| current.microseg.clone()),
        trust: patch.trust.clone().or_else(|| current.trust.clone()),
        nac: patch.nac.clone().or_else(|| current.nac.clone()),
        inspect: patch.inspect.clone().or_else(|| current.inspect.clone()),
    }
}

/// Run the SAME `aegis::reconcile_network` pure function twice — once against the device's
/// current intent, once against the model's proposed merge — and diff the two plans. This is the
/// "the reconciler translates" step: everything in the returned [`ProposedChange`] is
/// deterministic-computed, not model-authored.
fn compute_change(manifest: &Manifest, ctx: &PlanContext, patch: &NetworkIntent) -> ProposedChange {
    let ovs_granted = ctx.ovs_granted();
    let before = aegis::reconcile_network(manifest, &ctx.current_intent, ovs_granted);
    let merged = merge_intent(&ctx.current_intent, patch);
    let after = aegis::reconcile_network(manifest, &merged, ovs_granted);
    let diff = diff_plan(&before.plan, &after.plan);
    let artifacts = after.artifacts.into_iter().map(|f| ArtifactPreview { path: f.path, content: f.content }).collect();
    ProposedChange {
        before_plan: before.plan,
        after_plan: after.plan,
        diff,
        artifacts,
        warnings: after.warnings,
    }
}

fn build_user_prompt(intent_text: &str, ctx: &PlanContext) -> String {
    format!(
        "Operator intent: {intent_text}\n\nDevice context (evidence-graph summary):\n{}\n",
        if ctx.evidence_summary.trim().is_empty() { "(no evidence summary available)" } else { &ctx.evidence_summary }
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::adapter::test_server::serve_once;
    use hookprobe_manifest::scan::ScanProfile;
    use std::time::Duration;

    const N100_FIXTURE: &str = include_str!("../../../manifest/fixtures/n100.profile.json");

    fn n100_manifest() -> Manifest {
        let scan = serde_json::from_str::<ScanProfile>(N100_FIXTURE).expect("fixture").scan;
        let platforms_dir = std::path::Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/../../platforms"));
        let platforms = hookprobe_manifest::load_platforms(platforms_dir).expect("platforms");
        let (platform, mi) = hookprobe_manifest::classify(&scan, &platforms).expect("classify");
        hookprobe_manifest::build_manifest(&scan, platform, &mi, "2026-01-01T00:00:00Z", "img", "sha256:0").expect("manifest")
    }

    fn chat_json_response(json_body: &'static str) -> Adapter {
        let raw = format!(r#"{{"choices":[{{"message":{{"role":"assistant","content":{}}}}}]}}"#, serde_json::to_string(json_body).unwrap());
        let raw: &'static str = Box::leak(raw.into_boxed_str());
        let base = serve_once("HTTP/1.1 200 OK", "application/json", raw);
        Adapter::new(crate::config::LlmConfig {
            base_url: base,
            model: "test-model".to_string(),
            api_key: None,
            timeout: Duration::from_secs(5),
        })
    }

    fn ctx() -> PlanContext {
        PlanContext { manifest: Some(n100_manifest()), current_intent: NetworkIntent::default(), evidence_summary: String::new() }
    }

    fn ctx_no_manifest() -> PlanContext {
        PlanContext { manifest: None, current_intent: NetworkIntent::default(), evidence_summary: String::new() }
    }

    /// The headline fixture: a well-formed LLM response containing a valid `network_intent_patch`
    /// → a REAL plan-as-diff, computed by the deterministic reconciler.
    #[test]
    fn a_valid_fixture_response_produces_a_real_diff() {
        let body = r#"{"answer":"I've isolated the camera on the network.","why":"declared policy: isolated","confidence":91,"network_intent_patch":"network:\n  nac:\n    devices:\n      - identity: hik-cam\n        mac: \"00:0c:b5:00:00:09\"\n        policy: isolated\n"}"#;
        let adapter = chat_json_response(body);
        let resp = propose(&adapter, "block the camera", &ctx()).expect("propose should succeed");

        assert_eq!(resp.answer, "I've isolated the camera on the network.");
        assert_eq!(resp.explanation.confidence, 91.0);
        assert_eq!(resp.explanation.model, adapter.describe());
        assert!(resp.warnings.is_empty(), "a valid patch must not warn: {:?}", resp.warnings);

        let change = resp.change.expect("a valid network_intent_patch must produce a ProposedChange");
        assert!(change.after_plan.iter().any(|l| l.contains("NAC")), "the NAC domain must appear in the deterministic plan: {:?}", change.after_plan);
        assert!(!change.diff.is_empty(), "before (no NAC) vs after (camera isolated) must differ");
        assert!(
            change.artifacts.iter().any(|a| a.path.contains("nac.nft") && a.content.contains("00:0c:b5:00:00:09")),
            "the generated nft artifact must bind the real MAC: {:?}",
            change.artifacts.iter().map(|a| &a.path).collect::<Vec<_>>()
        );
    }

    /// A plain question (no patch) → an answer with no diff to review — the common Copilot case.
    #[test]
    fn a_plain_question_produces_no_change() {
        let body = r#"{"answer":"Your network is protected. No active threats.","why":"qsecbit + recent detections","confidence":95,"network_intent_patch":null}"#;
        let adapter = chat_json_response(body);
        let resp = propose(&adapter, "is my network safe", &ctx()).expect("propose should succeed");
        assert!(resp.change.is_none());
        assert!(resp.warnings.is_empty());
    }

    /// A patch that fails to parse as `NetworkIntent` is dropped with a warning — the answer still
    /// comes through, never a hard failure of the whole turn.
    #[test]
    fn an_invalid_patch_is_dropped_with_a_warning_not_forwarded() {
        let body = r#"{"answer":"I'll try to change your firmware.","confidence":50,"network_intent_patch":"this: [is, not, - valid: yaml: at all"}"#;
        let adapter = chat_json_response(body);
        let resp = propose(&adapter, "do something weird", &ctx()).expect("propose should still succeed");
        assert!(resp.change.is_none(), "an invalid patch must never produce a ProposedChange");
        assert_eq!(resp.warnings.len(), 1);
        assert!(resp.warnings[0].contains("failed validation"));
    }

    /// THE C9 boundary test at the orchestration level: a model response that tries to smuggle a
    /// direct enforcement instruction as its "patch" — valid YAML, but NOT a `network:`-shaped
    /// document at all (e.g. a bare scalar/list) — fails `HookprobeIntent::parse`'s schema check
    /// (it deserializes to the type's defaults / errors), so it is dropped exactly like malformed
    /// YAML. There is no path from "the model said something" to "a command ran".
    #[test]
    fn a_patch_with_no_network_key_is_dropped_not_treated_as_a_command() {
        let body = r#"{"answer":"ok","confidence":50,"network_intent_patch":"- block_ip: 10.0.0.5\n- quarantine_subnet: true\n"}"#;
        let adapter = chat_json_response(body);
        let resp = propose(&adapter, "block this ip now", &ctx()).expect("propose should still succeed");
        // A YAML list at the top level parses as an empty `HookprobeIntent` (no `network:` key
        // present -> every section defaults) rather than erroring — either way, no enforcement
        // action exists anywhere in the schema for it to land in: the result is at most a no-op
        // reconcile against an all-default NetworkIntent, never a "block 10.0.0.5" action.
        if let Some(change) = &resp.change {
            assert!(change.diff.iter().all(|l| matches!(l, crate::schema::DiffLine::Unchanged(_))), "a no-op patch must diff to nothing but Unchanged lines");
        }
    }

    /// A device with no Platform Manifest yet (no `manifest.json` on disk — the pre-first-boot or
    /// dev-box case): a valid patch still degrades to "answer only, with a warning" rather than
    /// panicking or fabricating a fake manifest to reconcile against.
    #[test]
    fn no_manifest_present_degrades_to_answer_only_with_a_warning() {
        let body = r#"{"answer":"I'll isolate the camera once the device has a manifest.","confidence":70,"network_intent_patch":"network:\n  nac:\n    devices:\n      - identity: hik-cam\n        policy: isolated\n"}"#;
        let adapter = chat_json_response(body);
        let resp = propose(&adapter, "block the camera", &ctx_no_manifest()).expect("propose should still succeed");
        assert!(resp.change.is_none(), "no manifest -> no diff, ever");
        assert_eq!(resp.warnings.len(), 1);
        assert!(resp.warnings[0].contains("Platform Manifest"), "the warning must explain WHY there's no diff: {:?}", resp.warnings);
    }

    /// The honest no-config path: propose() is never even reachable without an `Adapter`, but
    /// `LlmConfig::from_env()` returning `None` (tested in `config.rs`) is what `main.rs` checks
    /// BEFORE constructing one — this test documents that `propose` itself makes no assumption
    /// that lets a caller skip that check by accident: an adapter pointed at a closed port fails
    /// exactly like any other network error, never silently "succeeding" with fabricated content.
    #[test]
    fn an_unreachable_adapter_fails_honestly_never_fabricates_a_plan() {
        let adapter = Adapter::new(crate::config::LlmConfig {
            base_url: "http://127.0.0.1:1".to_string(),
            model: "test-model".to_string(),
            api_key: None,
            timeout: Duration::from_secs(2),
        });
        let err = propose(&adapter, "anything", &ctx()).expect_err("an unreachable endpoint must error");
        assert!(matches!(err, AdapterError::Network(_)));
    }
}
