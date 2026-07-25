# ADR 0013 — Product Cortex evolution: Autonomous Product Intelligence System (full-lifecycle, event-driven, competitively-positioned)

**Status:** ✅ Accepted (2026-07-03).
**Deciders:** operator, product-steward, os-architect.
**Relates to:** [ADR 0011](0011-product-cortex.md) (the Product Cortex — lifecycle graph, two rings, Green/Amber/Red, the roster), [ADR 0012](0012-release-definition-cortex-pass.md) (release definition + the Cortex release pass, D5 beacon), [ADR 0009](0009-soc-brain-edge-cloud.md) (evidence graph, SQLite-edge/ClickHouse-cloud, C9 AI-never-enforces), `docs/product-cortex-competitive.md` (the verified 2026 competitive pass this ADR operationalizes), `.claude/agents/` (the Ring-1 roster), `crates/hookprobe-evidence`, [ADR 0014](0014-continuous-improvement-detection-lifecycle.md) (the continuous-improvement detection loop — a concrete instance of this ADR's event-driven requirement→retirement lifecycle applied to detection, using the D3 roster incl. `retirement-agent`).

## Context

ADR 0011 built the Product Cortex as a lens on the evidence graph, with a Ring-1 roster capped at 8.
A verified competitive-research pass (`docs/product-cortex-competitive.md`, 2026-07-03: 23 sources,
25 claims 3-vote-verified, 0 refuted) then mapped the 2026 agentic-SDLC field against that bet. The
finding: **the field is converging on exactly the Cortex shape** (a lifecycle knowledge graph
grounding a ring of named pre-built agents behind human-deployment-grade gates), which validates ADR
0011 — but **every verified incumbent stops at the CI/CD or portal boundary**, and none owns the
substrate we do (`docs/product-cortex-competitive.md:5-7`).

Three structural facts fall out of that pass and need to be recorded as decisions before the window
closes (Harness shipped its agent ring 2026-06-30, three days before the research —
`docs/product-cortex-competitive.md:21,80`):

1. The "APIS" vision doc's advice to *avoid relational databases and build on a graph DB* is
   **contradicted by the leaders** — GitLab Orbit runs on ClickHouse, Harness uses schema-driven
   joins (`docs/product-cortex-competitive.md:26`). Our existing SQLite-edge/ClickHouse-cloud choice
   (ADR 0009) is the mainstream-correct one, and the only one that runs on a Pi. This must be locked
   so it is not relitigated.
2. An **event-driven lifecycle bus is genuine whitespace** — no verified competitor ships one
   (`docs/product-cortex-competitive.md:27,51,59`).
3. **No competitor ships ideation, market-intelligence, or retirement/EOL agents** — the field stops
   at code/build/deploy/security; the full requirement→retirement lifecycle (the hardware-PLM
   framing) is unclaimed in software (`docs/product-cortex-competitive.md:38-40,61`). Capturing it
   requires lifting the ADR 0011 roster cap — which needs an ADR. **This is that ADR.**

Plus two table-stakes closes the same pass names as *now expected, not novel*: an MCP tool surface
and Harness-grade governance rigor (scoped ephemeral creds, per-agent budget caps, per-identity
audit) — `docs/product-cortex-competitive.md:48-49,57-58`.

**"One system" still holds.** Nothing here is a new product or a parallel graph. The bus is the
existing `/var/lib/hookprobe` event-stream pattern; the new agents are Ring-1 personas over the same
evidence graph; the umbrella stays the Product Cortex.

## Decision

### D1 · Lock graph-on-relational (supersede the vision doc's "avoid relational DBs")

The lifecycle knowledge graph is, and remains, a **graph *model* over a relational/analytical
*store*** — the SQLite `edges` table at the edge (ADR 0009 revision 2026-07-02; ADR 0011 D1) and
ClickHouse in the cloud. This is the verified state of the art: GitLab's Orbit "lifecycle context
graph" is built on **ClickHouse**, and Harness's "Software Delivery Knowledge Graph" is schema-driven
joins, *not* a native graph DB (`docs/product-cortex-competitive.md:14,26`). It is also the **only**
option that runs on a Pi — a standalone graph DB cannot (`docs/product-cortex-competitive.md:26,68`).

**Explicitly rejected:** a standalone/native graph database at the edge (Neo4j/dgraph/etc.). The
"APIS" vision doc's advice to *avoid relational databases* is **superseded** by this decision; it was
contradicted by both verified leaders and by our own hardware constraint. The design is deliberate,
mainstream-correct, and hardware-validated (measured on the live Pi 4: 0.9s ingest of 1063
flows + 15k edges; `attack_path` 10.7s→0.115s with `idx_edges_dst` — ADR 0009 revision). Document it
as a chosen position, not a compromise.

### D2 · Adopt an event-driven lifecycle bus (edge-honest)

Add an **append-only lifecycle event log** the Cortex reasons over. Immutable events —
`idea`, `requirement`, `commit`, `gate_result`, `release_image`, `telemetry`/`beacon`, `incident`,
`retirement` — are appended; Ring-1 agents **subscribe** to the event types relevant to their role,
do **bounded** reasoning, **emit** new events, and **hand off** to the next subscriber. Because the
log is append-only and immutable, it is **replayable = a full audit trail**. No competitor ships this
(`docs/product-cortex-competitive.md:27,51,59`).

**Edge-honesty (non-negotiable, same discipline as ADR 0009/0011):**

| Tier | Bus mechanism |
|---|---|
| **Edge** (Pi/CM5/N100) | The event log **is** an append-only file/stream under `/var/lib/hookprobe`, ingested by the evidence graph on the existing **timer-ingest** pattern already in use (the same `--ingest-*` + daily-timer shape ADR 0012's beacon and the lifecycle ingest already use). **No Kafka/NATS-broker on a Pi.** |
| **Cloud / Mesh** | May use a real broker (NATS JetStream is already the nerve — ADR 0009 D6) for fleet-scale fan-out; same event shape, offloaded like every other node type. |

The bus **carries** events; it does **not** enforce. **C9 is unchanged** (ADR 0009 / ADR 0011 D2):
an agent emitting an event never actuates anything — only the deterministic reconciler and gate
ladder do. A `gate_result` or a `retirement` event is a *record and a trigger for the next agent's
bounded reasoning*, never an action. Events are graph nodes; the bus is the ordering + subscription
layer over the graph that already exists, not a new datastore.

### D3 · Extend the lifecycle end-to-end — raise the roster cap from 8 to 11

Every verified agent ring stops at code/build/deploy/security. To own the **full
requirement→retirement lifecycle** that is unclaimed in software
(`docs/product-cortex-competitive.md:38-40,61`), add three Ring-1 personas — one upstream of code,
two downstream — and lift the ADR 0011 cap to match:

| New agent | Cortex role | Owns | Model |
|---|---|---|---|
| `ideation-scout` ★new | Upstream signal → candidate requirements | scans market / CVE / MITRE ATT&CK / competitor moves / GitHub-issue signal → proposes candidate `requirement` nodes (as `idea` events) | opus |
| `market-intelligence` ★new | Positioning & competitive tracking | the hookprobe.com narrative; ongoing competitive tracking; **owns `docs/product-cortex-competitive.md`** | opus |
| `retirement-agent` ★new | Downstream EOL | finds dead APIs / unused features / stale detection rules / unsupported hardware → proposes EOL `retirement` events | sonnet |

These three **complete the requirement→retirement lifecycle** (the hardware-PLM framing — Teamcenter
et al. model this end-to-end; it is unclaimed in software). They extend the ring *past* where
Harness/GitLab stop, turning "more agents" into genuine differentiation.

**Governance of the cap:** new roles require an ADR (ADR 0011 D5). **This ADR is that gate for these
three.** ADR 0011's "capped at 8" note is amended to **"capped at 11 (ADR 0013)"** in its D5 and its
sprawl consequence. **The discipline holds: any 12th agent still needs a new ADR.** The cap is a
deliberate anti-sprawl control (`docs/product-cortex-competitive.md:66`), not a suggestion.

### D4 · Sequence the table-stakes closes (now expected, not novel)

The research names two capabilities that are table-stakes across all four majors and that we are
currently behind on (`docs/product-cortex-competitive.md:48-49,57-58`). Both are ⬜ direction here,
not implemented by this ADR.

**(a) MCP tool surface.** Adopt MCP as the Phase-4 backend tool protocol (already the ADR 0011 plan —
ADR 0011 reality-check row + D2 Ring 2). Each workspace exposes read tools + plan-proposal tools; the
**Copilot, the AEGIS planner, and the dev-time agents share one protocol**. Without it we look behind
(`docs/product-cortex-competitive.md:48,57`). Gated behind the A-Phase 4 backend, as ADR 0011 already
sequences.

**(b) Governance parity with Harness's benchmark.** Layer three rigor points *on top of* our existing
Green/Amber/Red + aegis-guard Deny-final (ADR 0011 D3 — which already matches Harness's verdict model,
not exceeds it):

| Parity item | Harness (`docs/product-cortex-competitive.md:13`) | HookProbe today | Gap |
|---|---|---|---|
| Verdict/policy engine | OPA at 3 points | Green/Amber/Red + aegis-guard Deny-final (ADR 0011 D3) | **have it — parity, honest** |
| Scoped ephemeral creds | agent∩user RBAC, per-run | — | **lack it** |
| Per-agent budget / token caps | budget caps | — | **lack it** |
| Per-identity audit trail | per-identity audit | evidence-graph nodes exist; per-agent-run identity does not | **partial** |

**Honest statement:** we have the *verdict* model and match it; we **lack the credential/budget/audit
rigor** today. This is the cheapest credibility win (`docs/product-cortex-competitive.md:58`) and it
is real work, owned by os-architect + code-developer (build steps below).

### D5 · Naming & positioning

- **Product name = "Product Cortex."** Never "PLM" — the term carries manufacturing baggage
  (`docs/product-cortex-competitive.md:76`).
- **Category descriptor = "APIS / Autonomous Product Intelligence System."** This is the
  external/marketing framing for hookprobe.com; Product Cortex is the product, APIS is the category it
  defines. Position it as *"the security OS that defends your network autonomously — and evolves
  itself the same way, in public, over one verifiable graph"* (`docs/product-cortex-competitive.md:75`).
- **Anti-pattern immunity is a positioning asset.** The research names the "partial-determinism
  illusion" — deterministic-looking workflows hiding non-deterministic LLM decisions in the critical
  path (`docs/product-cortex-competitive.md:67`). Our **C9 (AI never in the enforcement path;
  aegis-guard Deny is final)** makes us *structurally immune* to it. State this as a differentiator,
  not a footnote.

## Consequences

- **+** Owns the **full lifecycle on an owned, signed, hardware-validated substrate** — the verified
  moat (`docs/product-cortex-competitive.md:36,50`): one evidence graph serving both the shipped
  security product and its own development, which no competitor can replicate without owning an OS +
  kernel telemetry + a running product.
- **+** The event bus gives **replay/audit** and **decouples agents** (subscribe/emit/hand-off) —
  directly mitigating the agent-sprawl coupling risk it might otherwise add.
- **−** **11 agents is more surface** than 8 (attack surface + cost + confusion —
  `docs/product-cortex-competitive.md:66`). Mitigated by: the hard cap + the ADR-gate on any 12th +
  the bus's **bounded-subscription** model (each agent sees only its event types, reasons in bounded
  steps).
- **−** The moat is **time-sensitive** — Harness shipped its ring 2026-06-30
  (`docs/product-cortex-competitive.md:21,80`); the window to own the full-lifecycle-on-owned-substrate
  position is now, not next quarter.
- **−** D4's table-stakes (MCP, governance-parity) are **real work we are currently behind on**, not a
  claim we already lead.
- **−** **Nothing here is implemented by this ADR.** The event bus, the 3 agents' *runtime* wiring,
  the MCP surface, and governance-parity creds/budget/audit are all **⬜** — this ADR is **direction,
  not implementation**. (The three agent *definitions* in `.claude/agents/` land with this ADR; their
  event-bus subscription runtime does not.)

## Build steps (small, sequenced)

1. ✅ This ADR + the three agent definitions in `.claude/agents/` (`ideation-scout`,
   `market-intelligence`, `retirement-agent`) + canon updates (ADR 0011 cap, root CLAUDE.md roster,
   `docs/BuildPlan.md`) — product-steward, this session (2026-07-03).
2. ⬜ **Event-bus schema** in `crates/hookprobe-evidence`: the 8 lifecycle event types on the
   append-only `/var/lib/hookprobe` log + timer-ingest, replayable, C9-bound (carries, never enforces)
   — code-developer.
3. 🟡 **partial** — **MCP tool surface.** The **read-only, dev-time-now slice** (D4a) is built:
   `crates/hookprobe-evidence/src/bin/mcp-server.rs`, a stdio JSON-RPC 2.0 server exposing
   `graph_stats`/`correlate`/`trace`/`recent_detections`/`lifecycle_trace` over the evidence graph —
   code-developer, 2026-07-03 (see "Progress — E3 MCP surface" below). Still ⬜: plan-proposal tools
   per workspace, and wiring this protocol into the A-Phase 4 backend so Copilot + the AEGIS planner
   share it (that half needs the Phase-4 backend, which doesn't exist yet).
4. ⬜ **Governance parity**: scoped ephemeral per-agent-run credentials, per-agent budget/token caps,
   per-identity audit trail — layered on Green/Amber/Red + aegis-guard — os-architect + code-developer.
5. ⬜ `market-intelligence` runs the **ongoing competitive-tracking pass** and keeps
   `docs/product-cortex-competitive.md` current as the field moves — market-intelligence agent.

## Execution detail (operator-directed, 2026-07-03) — the "how" for build steps 2–4

The operator's execution plan for the ⬜ items, recorded with the edge-honesty reconciliations that
keep it buildable on a Pi (this is a security OS that ships to edge hardware; the plan is correct once
split by tier and by the C9 propose-vs-enforce boundary).

### E1 · Event bus (build step 2) — the foundation; build first
- **Immutable event sourcing.** Every action is an immutable, ordered, replayable event: a NAPSE
  anomaly, a gate failure, an engineer's note, a CVE ingest, a retirement proposal.
- **Tiered transport (reconciles D2 — do NOT put a broker on the edge):** *edge* = append-only
  `/var/lib/hookprobe/lifecycle-events` + the existing timer-ingest into the evidence graph (no
  Kafka/NATS/Redpanda on a Pi); *cloud/mesh* = **NATS JetStream / Redpanda** for fleet-scale fan-out
  into cloud ClickHouse (the "high-throughput broker" belongs here, not on the device).
- **Reactive subscriptions, never direct calls (the anti-sprawl fix the research named).** Agents
  subscribe to event *topics*; they do not call each other. `ideation-scout` subscribes to
  `telemetry.anomaly_cluster`; when a novel evasion repeatedly bypasses current rules the bus wakes it,
  it reasons in bounded steps and emits a `requirement.draft` event.
- Seed topic taxonomy: `telemetry.*` (anomaly_cluster, beacon), `gate.*` (result), `release.*`
  (image, promote), `requirement.*` (draft), `retirement.*` (proposal), `commit.*`.

### E2 · Governance parity (build step 4) — the immediate defensive maneuver
- **JIT execution roles — zero standing privileges.** Agents hold no static keys. A JIT credential
  broker mints a token **scoped to a single target and bound to the triggering event's hash on the
  bus**, expiring the instant execution finishes (depends on E1 — the event hash is the scope anchor).
- **Cryptographic audit trail.** Every agent action is signed with an **agent-specific identity key**
  (reuse the ed25519/cosign foundation, ADR 0002/0007) → verifiable chain of custody: which agent,
  which policy gate approved, why; lands as signed nodes in the graph.
- **Blast-radius budgets.** Hard per-session caps on compute + network manipulation (e.g. max eBPF
  (re)compiles per dev-agent session) so an LLM loop can't run away. **Reconciles ADR 0005/0011:** the
  eBPF (re)compile + verifier run happen **CI/dev-time, not on the immutable edge** (no on-device
  toolchain, no microVM); the budget caps the dev-time agent, and the verifier is exposed via MCP (E3).

### E3 · MCP surface (build step 3) — table-stakes defensive
- **Expose the eBPF verifier + CO-RE compile as an MCP tool (CI/dev-time).** `code-developer` asks
  *before* committing: "will this instruction set pass the kernel verifier / complexity limits?" —
  shift-left, matching ADR 0005's compile-time-verification posture.
- **Expose the graph via MCP (read tool).** Any agent — or a human in a compatible IDE — asks "which
  requirement generated this line?" / "which detection has had zero hits in 90 days?" This is the
  traceability the moat is built on.

### E4 · Edge agents (build step 5+) — the offensive differentiators
- `ideation-scout` + `market-intelligence` cross-reference external feeds (CVE / MITRE / competitor)
  **against live Senzorium/NAPSE telemetry** — if a zero-day pattern is *actually hitting edge nodes*,
  propose an Epic. This is "operational graph, not delivery graph" in action.
- `retirement-agent` (the lean enforcer) queries the graph for eBPF maps / routing rules / API
  endpoints with **zero hits in a configurable window (default 90 days)**, verifies removal won't
  break the mesh, and **proposes** a deprecation PR.
- **Governance reconciliation (non-negotiable, C9 / ADR 0011 D3):** "autonomously drafts an Epic /
  submits a PR" is **Amber, not Red** — agents *propose* (draft the Epic, open the deprecation PR for
  review); the operator approves the merge. **No agent autonomously commits, merges, or deploys.** The
  autonomy is in the analysis and the draft, never the actuation.

### Positioning capture (`market-intelligence` owns this line)
Incumbents build a **software-*delivery* graph** (guessing context from Jira tickets and GitHub PRs);
HookProbe owns the **software-*operational* graph** — the actual dropped packets and live runtime
evidence in the same graph as the code that handles them. Uncopyable because it requires owning the OS
from the kernel up, **natively** (a custom in-house engine, not parsing logs from Zeek/Snort wrappers).
This is the sharpest one-liner for hookprobe.com.

## Progress — E3 MCP surface, read-only slice (code-developer, 2026-07-03)

**Built now:** `crates/hookprobe-evidence/src/bin/mcp-server.rs` — a standalone stdio JSON-RPC 2.0
MCP server (`initialize` → `tools/list` → `tools/call`) exposing five READ-mostly tools —
`graph_stats`, `correlate`, `trace`, `recent_detections`, `lifecycle_trace` — all thin wrappers over
`EvidenceGraph` methods already in `lib.rs` (no query logic duplicated). Verified: 25/25 crate tests
pass (9 new: `graph_stats`/`recent_detections`/`lifecycle_trace`/`correlate` + their edge cases), 0
clippy warnings (`--all-targets`), a real stdin/stdout JSON-RPC session against both the dev-time
graph (`.claude/cortex/lifecycle.db`) and a seeded demo graph, and a clean `aarch64-unknown-linux-gnu`
cross-build of both binaries in the package (same target the mkosi arm64 builder already uses for
`hookprobe-evidence`, ADR 0009 rev.). Example client registration (Claude Code `.mcp.json`):

```json
{
  "mcpServers": {
    "hookprobe-evidence": {
      "command": "/home/andrei/hookprobe-os/target/debug/mcp-server",
      "args": ["--db", ".claude/cortex/lifecycle.db"]
    }
  }
}
```

**Flagged, not silently resolved:** four of the five tools are byte-for-byte read-only (`SELECT`
only). `correlate` is the one exception — it reuses the *existing* `correlate_incident` method,
which upserts an idempotent `incidents` node + edges (the same side effect the CLI's `--correlate`
flag and the scan-responder pipeline already produce today). This satisfies C9 ("records, never
enforces" — no network/policy action results) but is **not** the strict "opens the DB read-only"
posture this build step's brief asked for. A stricter split (e.g. a side-effect-free "preview"
correlate, or a genuinely `SQLITE_OPEN_READ_ONLY` connection for the four pure-read tools with a
separate read-write handle only for `correlate`) is a clean follow-up, not built in this pass —
os-architect/security-auditor should weigh in on whether the idempotent-upsert posture is acceptable
long-term or whether `correlate` needs the stricter split before this ships past dev-time use.

**Deferred / blocked-on (D4 + E2/E4 items genuinely infra-gated on this edge box today):**

| Item | What it needs | Why it can't be built here now |
|---|---|---|
| **Governance parity — JIT scoped ephemeral per-agent-run credentials** (E2) | An **agent runtime** that actually executes tool calls under a broker-minted, event-hash-scoped token | There is no agent-execution runtime on this box to scope a credential *to* — Ring-1 agents today are Claude Code personas invoked by a human operator inside this session, not an autonomous runtime process the credential broker mints a token for. Needs the Phase-4 AEGIS-planner runtime (ADR 0011 D2 Ring 2) or an equivalent standalone agent-runner before JIT credentials have anything to scope. |
| **Governance parity — per-agent budget/token caps** (E2) | The same runtime, plus a metering point in front of it | Caps bound a *running* agent loop's compute/network use; with no long-running agent process (only interactive Claude Code turns), there is nothing to meter against a cap — this is a runtime feature, not a library or MCP-server feature. |
| **Governance parity — per-identity cryptographic audit trail** (E2) | Per-agent-run identity keys (ed25519, reusing ADR 0002/0007's foundation) signing each action as a graph node | The evidence-graph *nodes* already exist (`lifecycle_events`, `gate_results`) but no agent has its own identity key yet — that requires deciding a key-issuance/rotation story for agent identities, which is a security-auditor + os-architect decision (PQC-agile posture, ADR 0002), not a schema change this pass can make unilaterally. |
| **Event-bus CLOUD tier (NATS JetStream fan-out)** (D2/E1) | A mesh/cloud control-plane node running a broker | Explicitly out of scope for the **edge** tier by D2's own edge-honesty table ("no Kafka/NATS-broker on a Pi") — this box IS the edge tier (append-only file + timer-ingest, already built and tested). The cloud tier needs `mssp.hookprobe.com` infrastructure that does not exist yet; building it here would violate the edge-honesty discipline the ADR itself sets. |
| **The 3 new agents' bus-subscription runtime** (`ideation-scout`/`market-intelligence`/`retirement-agent`, D3/E1/E4) | The Phase-4 backend event loop (subscribe → bounded-reason → emit → handoff) + the BYO-LLM adapter (ADR 0011 D2 Ring 2, ⬜) | The agent *definitions* exist (`.claude/agents/`); what's missing is the always-on process that watches `telemetry.*`/`gate.*`/etc. topics and wakes the right persona. That process doesn't exist until the Phase-4 backend + LLM adapter land — until then these three agents run only when a human operator invokes them by name inside a Claude Code session, which is Ring-1-dev-time-only exactly as ADR 0011 D2 already scopes it. |

Everything in this table is unbuilt for the reason stated, not silently dropped; each row names the
exact missing infrastructure and the ADR/decision that already anticipated the gap.

---

## heqk migration — see [ADR 0043](0043-heqk-microkernel-substrate.md)

**Coupling: NEUTRAL.** Substrate-independent dev tooling (append-only lifecycle bus, 11-agent roster, MCP). Unaffected — and it is the governance surface through which the migration's `requirement`/`retirement` events and ADR 0043 supersession flow.
