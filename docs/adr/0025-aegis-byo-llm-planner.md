# ADR 0025 — AEGIS BYO-LLM Planner: assistive intent-to-diff, never in the enforcement path

**Status:** 🟢 Accepted (2026-07-08). Implemented as a working, tested, gate-green first version:
the `hookprobe-planner` crate (`crates/hookprobe-planner/`), the `ai_explanations` evidence node
class + `EvidenceGraph::record_ai_explanation`, `incident_detail`'s `model`/`ai_reasoning` wiring,
the `hookprobe-planner.service` unit, and `CommandPalette.tsx`/`store/plannerApi.ts` wired to real
HTTP calls (replacing the Layer-0 canned-response corpus). Not yet folded into an image build
(deliberately — no operator has a BYO-LLM endpoint to point at yet; this ADR ships the adapter +
intent→diff→approve loop + the honest no-config path, not a flash).
**Deciders:** os-architect (author; the assistive/never-enforcement boundary, C9), code-developer
(the adapter + Copilot wiring), security-auditor (the structural boundary argument — the model must
be barred from enforcement by *type*, not by instruction alone), ux-architect (the Copilot's honest
states: not-configured / unreachable / error, never a fake canned response in their place).
**Relates to:** [CLAUDE.md contract C9](../../CLAUDE.md) ("AEGIS = deterministic reconciler...+ AI
planner...assistive, never in the enforcement path"), [ADR 0011](0011-product-cortex.md) (the same
"AI proposes, deterministic gates enforce" governance discipline, here applied to the OS's own
runtime instead of the Product Cortex), [ADR 0009](0009-soc-brain-edge-cloud.md) (the ONE evidence
graph the explanation folds into), `crates/hookprobe-manifest/src/aegis.rs` (the EXISTING
deterministic reconciler this crate reuses verbatim, never reimplements),
`modules/aegis-guard/src/lib.rs` (the deterministic policy guard's own doc comment already marks
its `TODO(ai-planner)` hooks — this ADR is the planner those hooks anticipated, still not wired
into the guard itself this pass — see Honest limits).

## Context

Per `docs/BuildPlan.md`/CLAUDE.md, AEGIS today is **deterministic-reconciler-only**: `aegis.rs`'s
`reconcile_network` turns a declared `network:` intent into a plan-as-diff + generated artifacts,
and `aegis-guard`'s `check_action`/`evaluate_reflex` gate proposed actions into
`AutoApply`/`RequireApproval`/`Deny`. The AI planner leg — "operate by intent, not query
languages", the single biggest differentiator vs FortiSOC/Sentinel/Defender XDR per the roadmap —
was ⬜: `CommandPalette.tsx` (⌘K) rendered a **canned response corpus** keyed by keyword match, and
`hookprobe-evidence`'s `incident_detail` returned `model: null` as a permanent, honest stub (no
planner existed to populate it).

The hard constraint, stated three times in the project's own canon before this ADR (CLAUDE.md,
`aegis-guard`'s module doc, `aegis.rs`'s own header) and repeated here because it is the entire
point of this design:

> **The AI planner is ASSISTIVE and NEVER in the enforcement path.** It PROPOSES; the deterministic
> reconciler APPLIES and VERIFIES.

Two forces shape the design:

1. **The invariant must be structural, not just instructional.** A system prompt telling a model
   "never execute anything" is necessary but insufficient — a security architecture cannot rely on
   an LLM reliably following English instructions. The boundary has to hold even when the model
   ignores its own system prompt, hallucinates, or is adversarially prompted by an operator.
2. **Air-gap-capable by the OS's own invariant.** "Model is the operator's choice" — any
   OpenAI-compatible endpoint, or a local Ollama/llama.cpp/vLLM server. With nothing configured,
   every other OS function must keep working exactly as today; the planner is purely additive.

## Decision

Build the planner as its own crate, **`hookprobe-planner`**, that (a) adapts to any
OpenAI-compatible `chat/completions` endpoint, (b) turns an operator's intent into a **plan-as-diff
computed by the EXISTING deterministic `aegis::reconcile_network`** — never by the model itself —
and (c) is barred from enforcement **by the type system**, not by convention.

### Data flow

```
operator intent (NL)  ──┐
manifest + evidence      ┤──▶ Adapter::chat (BYO-LLM, OpenAI-compatible)  ──▶ RawLlmOutput
  summary (grounding)    │            (config.rs / adapter.rs)                (schema.rs — the
                         │                                                    ONLY shape the
                         │                    network_intent_patch (YAML, UNTRUSTED)  model's text is
                         │                                  │                 deserialized into)
                         │                                  ▼
                         │      parse as hookprobe_manifest::aegis::HookprobeIntent
                         │        (fails → DROPPED + warning, NEVER forwarded)
                         │                                  │
                         │                          merge into current intent
                         │                                  │
                         └──────────────────────▶ aegis::reconcile_network (PURE, EXISTING,
                                                    UNCHANGED — computes the REAL plan/diff/
                                                    artifacts; called TWICE — before/after —
                                                    and diffed, plan.rs::compute_change)
                                                              │
                                                    operator reviews in CommandPalette.tsx,
                                                    Approve → POST /api/planner/approve
                                                              │
                                                    staged under /var/lib/hookprobe/planner/
                                                    staged/<id>/ — a PREVIEW, not an apply
                                                              │
                                          (existing, unchanged, separate step, NOT invoked here)
                                          hookprobe-supervisor --reconcile-network --network-write
```

### D1 — The C9 boundary is enforced by the type system, not by instruction

`schema::RawLlmOutput` is the **only** shape the model's JSON text is ever deserialized into:

```rust
pub struct RawLlmOutput {
    pub answer: String,
    pub why: String,
    pub confidence: f64,
    pub network_intent_patch: Option<String>,   // a YAML BLOB — no authority of its own
}
```

There is no `action`/`command`/`execute` field, no enum variant anywhere in this crate that means
"do this now". A model that ignores its system prompt and emits
`{"action":"block_ip","target":"10.0.0.5","command":"iptables ..."}` produces a `RawLlmOutput` with
those keys silently dropped by `serde` (no field exists to read them into) — proven by
`schema::tests::unknown_enforcement_looking_fields_are_structurally_inert`. `network_intent_patch`
is a bare `String`; it becomes meaningful only once independently re-parsed as
`hookprobe_manifest::aegis::HookprobeIntent` — the **existing** schema
`hookprobe-supervisor --reconcile-network` already consumes for **operator-authored** intent files.
A patch that fails that parse (malformed YAML, or valid YAML with no `network:` key at all — e.g. a
bare list trying to look like an imperative command list) is **dropped with a warning, never
forwarded** — `plan::tests::a_patch_with_no_network_key_is_dropped_not_treated_as_a_command` and
`an_invalid_patch_is_dropped_with_a_warning_not_forwarded` cover both shapes.

Even a *validated* patch reaches nothing but `NetworkIntent`'s own fields — all DECLARATIVE state
(`wan`/`wifi`/`fabric`/`microseg`/`trust`/`nac`/`inspect`). The deepest either an operator or a
model can reach is e.g. "declare this device's NAC policy as `isolated`" — which still has to pass
through the SAME `aegis::reconcile_network`, the SAME `aegis_guard::check_action` policy guard
(unchanged by this ADR), and an explicit human approval before anything is written to a live path.

Structurally, this crate:
- **Never calls `std::process::Command`** — grep-verified, zero occurrences.
- **Never writes to a live `/etc/hookprobe` (or any OS-owned) path** — its one filesystem write
  (`main.rs`'s `/approve` handler) targets `/var/lib/hookprobe/planner/staged/<id>/` only, a
  preview directory nothing else reads.
- **Never calls a firewall/OVS/nft/systemd API.**
- Runs `aegis::reconcile_network` **twice** (current intent vs. proposed merge) and diffs the two
  *plans* (`diff.rs`, a small hand-rolled LCS) — everything in `ProposedChange` is
  deterministically computed, not model-authored prose.

### D2 — BYO-LLM adapter: OpenAI-compatible, no vendor hardcoded

`config::LlmConfig::from_env()` reads `HOOKPROBE_AI_ENDPOINT` / `HOOKPROBE_AI_MODEL` /
`HOOKPROBE_AI_API_KEY` (optional) / `HOOKPROBE_AI_TIMEOUT_MS`; **absence → `None`**, the honest
air-gap-default "no model configured" state — never a fabricated default endpoint. `adapter::Adapter`
is a minimal `POST {base_url}/chat/completions` client (`ureq` 3, rustls backend — no native-openssl
build dependency; plain HTTP for a local Ollama/llama.cpp endpoint, rustls only for an `https://`
hosted one). Every failure mode is a typed, non-fabricating `AdapterError`
(`NotConfigured`/`Timeout`/`Network`/`Http{status,body}`/`BadResponse`) — never a panic, never a
synthesized success. Verified against a dependency-free local HTTP fixture
(`adapter::test_server`, a `std::net::TcpListener` thread): happy path, non-2xx with body, malformed
JSON, zero choices, unreachable endpoint, and a hung endpoint (timeout) — six adapter tests, all
green.

### D3 — Wiring `model` into the evidence graph, honestly

`hookprobe-evidence` gains ONE new table, `ai_explanations` (`incident_id, ts, model, why,
confidence, reasoning`), and ONE new writer, `EvidenceGraph::record_ai_explanation` — the *only*
way `incident_detail`'s `model` field ever becomes non-null. It attaches an explanation to an
**existing** incident (`SELECT 1 FROM incidents WHERE id=?` gates the write); it never creates or
mutates an incident, and nothing about it touches enforcement state. `incident_detail` now serves:

```jsonc
"explanation": {
  "why": "...",            // UNCHANGED — the deterministic correlation's own title, always
  "confidence": 91.0,       // UNCHANGED — threat_score-derived, never overwritten by the planner
  "evidence": 4,            // UNCHANGED
  "model": null,            // null until record_ai_explanation has run for THIS incident
  "related_events": [...],
  "ai_reasoning": {         // ADDITIVE — null+reason before a planner run, the model's own
    "why": null,            // envelope after one
    "reason": "no AI planner run / no model configured"
  }
}
```

`hookprobe-planner`'s `POST /api/planner/incidents/{id}/explain` grounds a `propose()` call in that
incident's own `incident_detail` JSON, then calls `record_ai_explanation` with the result — a
narrow, additive write, never blocking the HTTP response if the write itself fails (logged, not
fatal). `hookprobe-evidence` tests
(`record_ai_explanation_populates_model_and_ai_reasoning_after_a_planner_run`) and
`hookprobe-planner` integration tests
(`explain_incident_writes_model_field_visible_to_incident_detail`) cover the full loop, including
the pre-existing `incident_detail_returns_explanation_envelope_and_none_for_unknown_id` test's
`model: null` assertion, which continues to pass byte-for-byte unchanged for any incident the
planner has never touched.

### D4 — A separate service/port from `hookprobe-api`, not a new route on it

`hookprobe-api` is read-only **by construction**
(`EvidenceGraph::open_readonly`/`SQLITE_OPEN_READ_ONLY`) — ADR 0001's read-API must never gain a
write route. `hookprobe-planner` runs as its own binary/systemd unit on its own port (`:8421` vs.
`:8420`), the one narrow additive write surface this feature needs. `ProtectSystem=strict` +
explicit `ReadWritePaths=` scoped to exactly `evidence.db` + its own staging directory (see
`units/hookprobe-planner.service`) — everything else on the data partition stays read-only from
this service's perspective too.

### D5 — Approve stages a preview; it does not apply

`POST /api/planner/approve` writes a proposal's `ArtifactPreview`s under
`/var/lib/hookprobe/planner/staged/<proposal-id>/` (path-traversal-rejecting — no `..`, no leading
`/`) for **operator review**. Nothing reads that directory automatically. Promoting a staged
proposal into the device's actual `/etc/hookprobe` config remains the **existing, unchanged**
`hookprobe-supervisor --reconcile-network --network-write` step an operator (or a future,
explicitly-reviewed automation of that exact command) still has to run. This keeps "approve" from
quietly becoming "apply" — the diff the operator saw is exactly the diff staged, and the actual
device-state mutation is a separate, already-audited, deterministic code path this ADR does not
touch.

### D6 — Copilot UI: honest states, never a fake response in their place

`CommandPalette.tsx` (⌘K) now checks `GET /api/planner/status` on open and renders one of five
honest states — `checking` / **`not-configured`** ("Connect a model at Administration → AI
Models.") / **`unreachable`** (the planner *service* itself down — distinct from "not configured")
/ `loading` / `answered` (real answer + why/confidence/model, an optional plan-as-diff with
Approve/Reject) / `error` (the real `AdapterError` message, verbatim). The Layer-0 canned-response
corpus this replaced is gone from this component entirely — no keyword-matched fake answer is ever
shown, at any phase.

## Honest limits

- **`aegis-guard`'s `TODO(ai-planner)` hooks are still unwired.** This ADR builds the planner and
  proves the C9 boundary for the **network-intent** surface (`aegis::reconcile_network`); it does
  NOT yet attach the planner to `aegis-guard::check_action`'s `RequireApproval` hooks (suggesting a
  course of action for e.g. `full_quarantine`/`block_ip` at high trust). That remains future work —
  tracked, not fabricated as done.
- **No conversation history / multi-turn context.** Each Copilot submission is one independent
  `propose()` call; the model does not see prior turns in the same session. Tractable-first-version
  by design (per the build brief) — a real agentic loop is explicitly out of scope for this pass.
- **Merge strategy is section-level, not field-level.** A proposed patch that includes a `nac:`
  section replaces the operator's ENTIRE current `nac:` section (not a per-device merge) — simple
  and predictable, but an operator with a large hand-authored NAC list should review the diff
  carefully rather than assume additive-only behavior. Documented in `plan::merge_intent`'s doc
  comment.
- ~~`GET/POST /api/planner/*` has no auth of its own~~ **Closed by [ADR 0028](0028-rbac-enforcement.md)
  (2026-07-08):** `hookprobe-rbac`'s middleware now gates every route here — `/status` (`view`),
  `/propose`+`/explain` (`investigate`), and `/approve` (`configure` — tenant-admin/admin only, the
  Red-action gate on approving a plan-as-diff). Standalone-loopback with no identity presented stays
  fully permissive, unchanged from before this ADR.

## Consequences

- Mission Control's Copilot (⌘K) is real: an operator's natural-language intent produces either a
  grounded answer or a genuine, deterministically-computed plan-as-diff to approve — the "operate
  by intent, not query languages" differentiator now has a first, honest implementation.
- `incident_detail`'s `model` field stops being a permanent stub; it reflects reality (null until a
  planner run, populated after one) without ever fabricating a model identity.
- New surface to keep honest going forward: `aegis-guard`'s remaining `TODO(ai-planner)` hooks
  (security-auditor + os-architect to scope a follow-up ADR), and the section-level merge strategy
  if a future pass wants field-level NAC merging.

## Alternatives considered

- **Let the model call tools/execute actions directly (agentic function-calling).** Rejected: this
  is exactly the enforcement-path violation C9 forbids. Even a well-behaved model occasionally
  hallucinates a tool call; the only safe design is one where no such tool exists to call.
- **A single hardcoded vendor (e.g. OpenAI-only).** Rejected: violates "model is the operator's
  choice" and the air-gap requirement — a fixed vendor endpoint cannot serve a sovereign/air-gapped
  deployment.
- **Apply staged artifacts automatically on Approve.** Rejected for this pass: collapses "operator
  reviewed a diff" and "operator authorized this exact byte-for-byte config to go live" into one
  click, with no re-verification step. Staging-then-manual-promote (D5) keeps the existing,
  already-audited apply path as the sole mutator of live config.

---

## heqk migration — see [ADR 0043](0043-heqk-microkernel-substrate.md)

**Coupling: SOFT.** The planner and its C9 type-enforced boundary survive; the planner's `NetworkIntent` output → `reconcile_network` artifact generation retargets from Linux nft/OVS/WireGuard to heqk's dataplane config. The planner itself likely runs in the Zone-4 guest / hosted control node initially. → **Phases M4/M5**.
