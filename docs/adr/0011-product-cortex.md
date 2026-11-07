# ADR 0011 — Product Cortex: agentic product-lifecycle management on the evidence graph

**Status:** ✅ Accepted (2026-07-03).
**Deciders:** operator, product-steward (new), os-architect.
**Relates to:** [ADR 0009](0009-soc-brain-edge-cloud.md) (evidence graph, SQLite-edge/ClickHouse-cloud), [ADR 0005](0005-unified-ebpf-detection.md) (eBPF posture + CI-side verification), `docs/roadmap/BuildPlan.md` (the living tracker this ADR upgrades), `.claude/agents/` (the Ring-1 roster), `crates/hookprobe-evidence`, [ADR 0012](0012-release-definition-cortex-pass.md) (release definition + the Cortex release pass that fills D1's `release_image` emitter), [ADR 0013](0013-cortex-evolution-apis.md) (Cortex evolution: event bus, roster raised to 11, table-stakes closes), [ADR 0014](0014-continuous-improvement-detection-lifecycle.md) (the continuous-improvement detection loop — the `informed_by` field-feedback edge applied to detection, requirement→retirement, C9-bound, no on-device self-training).

## Context

V2 needs to move from *AI-assisted* development to **AI-operational lifecycle management**: the
platform owning its own lifecycle context — roadmap, decisions, code, tests, gates, benchmarks and
field telemetry connected in one queryable substrate, with agents that plan, verify, and learn over
it. The market (Harness "Software Delivery Knowledge Graph", GitHub/AWS DevOps agents) glues this
on top of fragmented external tools; generic agent frameworks (LangGraph, OpenAI Agents SDK) ship
plumbing with zero systems/security domain knowledge. HookProbe's structural advantage is that it
already **owns the substrate**: one evidence graph, kernel-level telemetry, a deterministic
reconciler, and a hardware-validated gate ladder.

**"One system" applies to the Cortex too.** The Product Cortex is *not* a separate product or a
parallel graph — it is a **lens on the same evidence graph**, exactly as SOC workspaces are.

## Reality check — the pitch vs. what the repo actually has

The originating proposal made assumptions that do not survive contact with the ADRs. Each is
resolved here so the Cortex builds on what exists:

| Pitch assumption | Repo reality | Decision |
|---|---|---|
| "ClickHouse-backed graph layer" | ClickHouse is **cloud-tier only**; the edge evidence store is **SQLite** (ADR 0009 reversed DuckDB→SQLite; edge ClickHouse explicitly dropped) | Lifecycle graph = new node/edge types in `crates/hookprobe-evidence` (SQLite, FNV-1a stable ids, same `edges` table); JSONEachRow offload to cloud ClickHouse like every other node type |
| "MCP servers per module" | **No MCP anywhere yet**; Copilot is a mock; BYO-LLM planner is designed but ⬜ | Adopt **MCP as the tool protocol of the Phase-4 backend**: each workspace exposes read tools + plan-proposal tools; the AEGIS planner and Copilot are MCP clients. One protocol for in-product agents *and* dev-time agents |
| "Firecracker microVM sandboxes" | A working **gate ladder** exists: podman `smoketest.sh` (Gate 0/2) → mkosi/QEMU amd64+arm64 boot (Gates 1/3) → greenboot health-gate → `bootc rollback` → real Pi4/N100 (Gates 4/5) | The gate ladder **is** the sandbox. No new isolation tech; agents get a *harness* to drive the existing gates. MicroVMs only if a future need outgrows QEMU |
| "OPA/Rego governance engine" | `aegis-guard` already is the deterministic policy engine — model-free, **Deny final, LLM cannot override**; plan-as-diff policy gates (auto-apply / RequireApproval) already specified | **Extend aegis-guard verdicts to lifecycle actions.** Green/Amber/Red = the existing gate semantics. No second policy engine |
| "Heavy eBPF/XDP substrate everywhere" | Tiered posture: native XDP+ZC on N100 `igc`; Pi `bcmgenet` copy-mode; Wi-Fi TC-bpf; kernel ≥5.19; out-of-band default | Cortex agents reason **from the Platform Manifest capabilities**, never from a uniform-XDP assumption — same "capabilities, not branches" rule as everything else |
| "Testing Agent runs eBPF verifier on-device" | eBPF verification is **compile-time in CI** (CO-RE + BTFGen); devices are immutable, no toolchain | Verifier/complexity checks stay CI-side, owned by the verification-engineer agent |

## Decision

### D1 · The lifecycle graph is an extension of the evidence graph

Add lifecycle node types to `crates/hookprobe-evidence`: `adr`, `requirement`, `commit`,
`test_run`, `gate_result`, `benchmark`, `release_image`, `platform_target`. Add edge types:
`implements`, `decided_by`, `validated_by`, `measured_on`, `regressed_by`, `supersedes`,
`shipped_in`, plus the crucial **field-feedback edge** `informed_by` (Incident/Detection →
requirement) that closes the loop from production telemetry back into the roadmap. Same SQLite
store, same stable-id scheme, same offload path. An ADR, a commit, a gate PASS, and a live
detection become nodes in *the same graph* an operator's incident already lives in.

### D2 · Two rings, one contract

- **Ring 1 — dev-time Cortex (now):** the `.claude/agents/` roster below operates the lifecycle
  during development: roadmap truth, security audit, gate verification, releases, field-evidence
  analysis. It works over the repo + `docs/roadmap/BuildPlan.md` today and over the lifecycle graph as D1
  lands.
- **Ring 2 — in-product Cortex (ships with A-Phase 4 backend + Track-B Phase 2 AEGIS LLM
  adapter):** the same roles become AEGIS-planner personas over MCP, surfaced in Mission Control
  (Automate / Administration → OS Lifecycle). BYO-LLM, capability-gated by `ai_planner`.

Both rings inherit contract **C9 unchanged**: *the AI plans and proposes; only the deterministic
reconciler and gate ladder enforce.* An agent's output is always a **plan-as-diff** with
*why · confidence · evidence · model*; a Deny verdict from aegis-guard or a failed gate is final.

### D3 · Governance = the existing verdict model

| Gate | Meaning | Mechanism (already exists) |
|---|---|---|
| 🟢 Green | auto-apply | low-impact plan-as-diff auto-apply (`Readme.md` guardrails) |
| 🟠 Amber | human approval | RequireApproval queue (Investigate / Automate approval flows) |
| 🔴 Red | refused, no override | aegis-guard Deny — final, LLM cannot override |

Dev-time equivalents: Green = docs/status/changelog edits and analysis; Amber = code, ADRs,
roadmap re-sequencing (operator reviews); Red = git commits/pushes/releases/flashing without
explicit operator instruction — agents never do these autonomously.

### D4 · The gate ladder is the verification sandbox

Cortex verification = drive what exists, in order: workspace tests (174+) → clippy → `podman
build` + `builder/smoketest.sh` → mkosi/QEMU boot (amd64 KVM, arm64 emulated) → greenboot
health-gate semantics → hardware gates (Pi4/N100) run by the operator on request. Every gate
result is recorded (a `gate_result` node once D1 lands; the BuildPlan Change Log today).

### D5 · The agent roster (Ring 1)

| Agent | Cortex role | Owns |
|---|---|---|
| `product-steward` ★new | PLM brain / lifecycle graph keeper | `BuildPlan.md` truth, ADR hygiene, traceability, doc-sync, roadmap reviews |
| `os-architect` (existing) | Architecture agent | OS contracts, manifest, reconciler, dataplane |
| `ux-architect` (existing) | Experience agent | Mission Control flows, fewer-steps |
| `code-developer` (existing) | Development agent | implementation, benchmarks |
| `security-auditor` ★new | Security agent | threat models, supply chain (cosign/SBOM/CBOM/SLSA), PQC posture, kernel-space safety review |
| `verification-engineer` ★new | Testing agent | the gate ladder, test/benchmark honesty, hardware matrix, CI |
| `release-engineer` ★new | Release agent | `builder/` pipeline, signing, images, rollout rings, changelog discipline |
| `telemetry-analyst` ★new | Observability + learning agent | field evidence → lifecycle feedback (`informed_by` edges), perf regressions, capability-tier truth |

**Roster extension (ADR 0013 D3 — cap raised 8 → 11):** the requirement→retirement lifecycle adds
three Ring-1 personas — `ideation-scout` (upstream signal → candidate requirements),
`market-intelligence` (positioning / competitive tracking; owns `docs/research/product-cortex-competitive.md`),
`retirement-agent` (dead-API/feature/rule/hardware EOL proposals). See ADR 0013 for rationale and the
event-bus they subscribe to. The cap is now 11; a 12th still needs an ADR.

## Consequences

- **+** No new database, policy engine, or isolation stack — the Cortex reuses the three hardest
  things the project already validated (evidence graph, verdict model, gate ladder).
- **+** Field-to-roadmap feedback becomes a first-class graph edge, not tribal knowledge.
- **+** MCP gives one tool protocol for the Copilot, the AEGIS planner, and external BYO-LLM
  clients — and it's an open standard, matching the open-core posture.
- **−** SQLite lifecycle graph is per-device/per-repo; fleet-wide product intelligence requires the
  cloud ClickHouse tier (accepted — same shape as all telemetry).
- **−** Ring 2 is gated behind the Phase-4 backend and the unbuilt AEGIS LLM adapter; until then
  the Cortex is dev-time only. That is the correct order: substrate before autonomy.
- **⚠** Agent sprawl is a real risk. The roster is **capped at 11 (ADR 0013)** — the original 8 plus
  `ideation-scout`/`market-intelligence`/`retirement-agent` (the requirement→retirement extension);
  new roles still need an ADR.

## Build steps (small, sequenced)

1. ✅ Ring-1 roster in `.claude/agents/` + this ADR (2026-07-03).
2. Lifecycle node/edge types in `crates/hookprobe-evidence` (+ ingest: `docs/adr/*`,
   `BuildPlan.md` phases/Change Log, git log, gate outputs).
3. `product-steward` runs a weekly roadmap-truth pass: BuildPlan vs repo vs docs; contradictions
   flagged, never silently resolved.
4. Phase-4 backend exposes the MCP tool surface (read + plan-proposal per workspace).
5. Ring-2 personas on the AEGIS planner (BYO-LLM), capability-gated, C9-bound.

---

## heqk migration — see [ADR 0043](0043-heqk-microkernel-substrate.md)

**Coupling: NEUTRAL.** Substrate-independent dev-time/cloud tooling — essentially unaffected. This is the lifecycle machinery that *drives* the migration: it owns ADR 0043's supersession of ADR 0035 D3, the requirement→retirement unbuild of Linux, and the gate ladder rebuilt on heqk.
