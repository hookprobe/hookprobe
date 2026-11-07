# Product Cortex — competitive positioning & strategy (2026)

> Grounded in a verified deep-research pass (2026-07-03, 23 sources, 25 claims 3-vote-verified, 0 refuted) + our own repo reality. Read with `docs/adr/0011-product-cortex.md` and `docs/adr/0012-release-definition-cortex-pass.md`. Analysis is Green (docs); any roadmap/ADR change it implies is Amber.

## TL;DR — the field is converging on our architecture, and no one owns our substrate

The 2026 agentic-SDLC field is racing toward *exactly* the Product Cortex shape — a **lifecycle knowledge graph** grounding a **ring of named pre-built agents** governed by **human-deployment-grade policy gates**. That convergence validates our ADR 0011 bet. But **every verified incumbent stops at the CI/CD or portal boundary**: none co-locates the lifecycle graph with a *running product's* kernel/eBPF telemetry on an owned, signed, hardware-validated runtime. That gap — *one evidence graph serving both the shipped security product and its own development lifecycle* — is HookProbe's structural, hard-to-copy position.

## The verified competitive map (substrate axis)

| Player | What they ship | Substrate | KG-native? | Governance | Open? |
|---|---|---|---|---|---|
| **Harness** ★ closest | "Software Delivery **Knowledge Graph**"; 6 named agents (Autofix, Code Review, Feature-Flag Cleanup, Code Coverage, Manifest Remediator, IaCM Remediation); MCP server (Cursor/Claude Code) | **CI/CD pipeline platform** — agents run as pipeline-native steps in Docker containers in isolated VMs; *not* an OS/product runtime | **Yes** (schema-driven graph, explicitly "not raw APIs") | Mature: sandboxing, **scoped ephemeral creds** (agent∩user RBAC), OPA at 3 points, per-identity audit, **budget caps** | Proprietary (MCP server OSS) |
| **GitLab** | Orbit "**lifecycle context graph**" (ClickHouse, REST/MCP) grounding Duo Agent Platform; Planner/Developer/Security agents | DevOps portal + context graph — decoupled from any running product | **Yes** (Orbit, public beta) | Platform RBAC | Open-core; Orbit repo OSS |
| **GitHub** | Copilot coding agent: assign a Jira issue → draft PR | **Tool-glue** — bridges Jira↔GitHub via two vendor apps | No | Draft PR + branch protections | Proprietary |
| **Google** | Gemini Code Assist agent mode | **Tool-orchestration** (function-calling + MCP) | No | IDE/user perms | Proprietary |
| **Atlassian** | Rovo (`@atlassian-rovo` MCP into Copilot) + Rovo Dev issue→PR | **Glue** over external dev runtimes | Teamwork Graph (integration graph) | Platform | Proprietary |
| **Port** | Context Lake + Workflow Orchestration + Agent Mgmt + Governance | **Governance/control proxy** over BYO agents; triggers *your* infra | Context Lake (portal graph) | Its whole pitch is guardrails | Proprietary |
| **AIBOM paper** (arXiv 2605.19755) | Crypto-signed provenance chains + sandboxed autonomous agents (env inspection, vuln enrichment, reproducibility audit) | **Toolkit, not a product** | Provenance graph | Signed, human-inspectable | OSS toolkit |

**Coverage caveat (honest):** AWS Amazon Q, LangGraph, OpenAI Agents SDK, Anthropic Agent SDK, Cognition Devin, Factory.ai, Cursor's own agents, and hardware PLM (Teamcenter/Windchill/Arena) did **not** produce claims that survived 3-vote verification — that's a *coverage gap in this pass, not evidence they lack features*. Harness's agents launched 2026-06-30 (3 days pre-report); much sourcing is vendor-launch material, not independent audit. GitLab Orbit is beta. Treat the map as directional, not complete.

## Fact-checking the "APIS" vision doc

- **"Harness has a Software Delivery Knowledge Graph"** → **TRUE, verified** (their own launch + engineering blog "Why Harness AI Uses a Knowledge Graph, Not Raw APIs"). The vision's competitive read was accurate.
- **"Avoid relational databases; build on a knowledge graph"** → **contradicted by the leaders.** GitLab's Orbit graph is built on **ClickHouse** (analytical-relational); Harness uses schema-driven joins. The state of the art is a *graph model over a relational/analytical store* — which is **exactly our SQLite-edges + ClickHouse-cloud choice** (ADR 0009/0011). Our design is mainstream-correct, and uniquely runs on a **Pi** where a standalone graph DB can't. Keep it; document it as deliberate.
- **"16 agents, event-driven bus"** → the 16 are mostly *phases* our 8 Ring-1 agents already span; but the **event-driven bus is real whitespace** (no verified competitor ships one) and worth adopting.
- **OpenAI "handoff primitives," LangGraph "deterministic checkpointing," Devin/Factory** → **unverified in this pass.** Don't cite them as fact until confirmed.

## The moat, stated precisely (medium confidence — analytical inference from verified substrate facts)

Incumbents split into two camps, **neither spanning product-runtime *and* lifecycle**:
1. **Own a substrate, but it's decoupled from any running product** (Harness = CI/CD; GitLab/Port = portal/context graph).
2. **Glue external tools** (GitHub, Gemini, Atlassian Rovo).

HookProbe is the only design where **the same evidence graph, deterministic reconciler, and gate ladder serve both continuous delivery (of the OS) and continuous improvement (from live field telemetry)** — on an owned, cosign-signed, hardware-validated runtime. We *proved the primitive today*: real NAPSE detections and lifecycle `release_image`/`gate_result`/`informed_by` nodes already coexist in one SQLite graph on a real Pi 4, and a field signal (a port scan) flowed detect→enrich→drop→document into that same graph. **No competitor can replicate that without owning an OS + kernel telemetry + a running security product — which none of them do.**

## The whitespace no one has claimed: the *full* requirement→retirement lifecycle

Every verified agent ring stops at **code/build/deploy/security**. **None ships ideation, market-intelligence, or retirement/EOL agents, or an event-driven agent bus.** That is the hardware-PLM framing (Teamcenter et al. model requirement→…→retirement end-to-end) — *unclaimed in software*. This is where the APIS vision's **Ideation / Market-Intelligence / Retirement** roles become genuine differentiation rather than "more agents": they extend the lifecycle *past* where Harness/GitLab stop.

## What we have vs. what we need

| Capability | Incumbent status | HookProbe status | Action |
|---|---|---|---|
| Lifecycle knowledge graph | table-stakes (Harness, GitLab) | ✅ built (evidence-graph extension) | keep; extend node types upstream/downstream |
| Named pre-built agent ring | table-stakes (Harness 6, GitLab several) | ✅ 8 Ring-1 (dev-time) | ship **Ring-2 in-product** personas |
| **MCP tool surface** | table-stakes (all four majors) | ⬜ deferred to Phase-4 backend | **build it** — this is now expected, not novel |
| Human-deployment-grade governance | Harness benchmark (scoped creds, OPA, budget caps, audit) | 🟡 Green/Amber/Red + aegis-guard Deny | **harden**: scoped ephemeral creds, per-agent budget caps, per-identity audit |
| Shared product+lifecycle graph on owned runtime | **nobody** | ✅ proven on Pi 4 | **lead with this** |
| Event-driven agent bus | nobody | ⬜ | build — replayable, auditable, decouples agents |
| Ideation / Market-Intel / Retirement agents | nobody | ⬜ | the differentiating whitespace; roster is capped at 11 (ADR 0013 raised it from 8) → new roles need an ADR |
| Crypto-signed lifecycle provenance | academic only (AIBOM) | 🟡 cosign/SBOM/CBOM + release pass | productize what's a paper elsewhere |

## Prioritized "what we need"

1. **MCP tool surface** (with the Phase-4 backend) — table-stakes; the Copilot + AEGIS planner + dev agents share it (already the ADR 0011 plan). Without it we look behind.
2. **Governance parity with Harness** — scoped ephemeral credentials per agent run, per-agent budget caps, per-identity audit trail. We have the *verdict* model (Green/Amber/Red, Deny-final); we lack the *credential/budget* rigor. Cheapest credibility win.
3. **Event-driven agent bus** — immutable lifecycle events (idea/requirement/commit/gate/telemetry) on a bus; agents subscribe, emit, hand off; full replay/audit. Whitespace + fixes agent-sprawl coupling.
4. **Ring-2 in-product agents** (AEGIS-planner personas over MCP) — turns the dev-time Cortex into a shipped feature; needs the BYO-LLM adapter.
5. **Lead the lifecycle end-to-end** — add Ideation/Market-Intelligence/Retirement roles (new ADR; roster cap) to own requirement→retirement, which no competitor does.
6. **Productize signed lifecycle provenance** — what the AIBOM paper prototypes, we can ship (release pass + evidence graph + cosign).

## Risks / anti-patterns (verified)

- **Agent sprawl** — unbounded agents = attack surface + cost + confusion. *Mitigation already in ADR 0011*: roster capped at 11 (ADR 0013); new roles need an ADR. Hold the line.
- **"Partial-determinism illusion"** — deterministic-looking workflows hiding non-deterministic LLM decisions in the critical path. *Our C9 already forbids AI in the enforcement path* (aegis-guard Deny is final; today's reflex quarantine is deterministic). This is a named industry anti-pattern we're structurally immune to — say so.
- **Knowledge-graph-vs-relational at the edge** — the vision says "avoid relational"; the leaders don't. Our graph-on-SQLite is correct for a Pi. Lock it in an ADR so it isn't relitigated.
- **Vendor-launch hype vs. reality** — Harness's model is stated, not independently benchmarked. Don't overclaim ours either; our edge is *demonstrated on hardware*, which is a stronger claim than a press release.

## The hookprobe.com angle

For an **open-source** security project, an agent-operated lifecycle is a *marketing and trust asset*, not just internal tooling:
- **"Watch the product build itself, in the open."** Every design decision (ADR), gate result, benchmark, and field-driven improvement is a traceable node — contributors see *why* a feature exists and *what validated it*. That transparency is something proprietary incumbents (Harness/GitLab) structurally can't offer to the public.
- **Differentiator line for the site:** *"HookProbe is the security OS that defends your network autonomously — and evolves itself the same way, in public, over one verifiable graph."* Position Product Cortex as the proof that the same AI-native discipline runs the product *and* its development.
- Do **not** market it as "PLM" (manufacturing baggage). "Product Cortex" / "autonomous product intelligence" is the right frame — and now demonstrably ahead of where Harness/GitLab market themselves (delivery-only).

## Recommendation

Accept this as the competitive basis; open an **ADR 0013** to (a) lock the graph-on-relational decision, (b) add the event bus + the three upstream/downstream agent roles to the roadmap (lifting the cap deliberately), and (c) sequence MCP + governance-parity as the near-term table-stakes closes. The moat is real but **time-sensitive** — Harness shipped its ring 3 days before this analysis; the window to own the *full-lifecycle-on-owned-substrate* position is now.

## Akrites (Linux Foundation, 2026-06-25) — the upstream-remediation complement

> Verified 2026-07-08 against the LF press release ("…Launch Akrites to Defend Critical Open
> Source Software Against AI-Enabled Cyber Threats") + akrites.org. Directional/vendor-stated,
> not benchmarked. Repo gaps below confirmed by grep, not assumed.

**What Akrites is:** a coordination initiative (not a product) — a shared SIRT running a
confidentiality-first 4-stage CVD pipeline (intake → dedup/validate → remediate → synchronized
disclosure, TLP:RED throughout, VINCE + isolated enclaves), on standards
CVE/CWE/CVSS/EPSS/SSVC/VEX/TLP 2.0. Alpha-Omega seed funding; "maintainer of last resort" for
unmaintained critical OSS; tiers Premier/General/Associate. Founders incl. AWS, Anthropic,
Cisco, Google, IBM, Microsoft/GitHub, NVIDIA, OpenAI, Red Hat, Rust Foundation, Sonatype,
**Vodafone, Ericsson** (telco edge = our SASE space), JPMorganChase, Citi, Zscaler. Threat
model: AI-accelerated discovery ("weeks → minutes"), <5% of vulns ever patched.

**Not a competitor — the upstream half of our own stack.** Akrites fixes critical OSS *before*
exploitation; HookProbe is the *downstream, on-device* layer defending the disclosure-to-deploy
window Akrites structurally cannot close — the exact window AI-accelerated attackers exploit.
HookProbe both *consumes* critical OSS (benefits from Akrites directly) and *is* an OSS security
project that should live by Akrites' discipline.

**Our verified edge (lead with this):** behavioral on-device enforcement that catches
exploitation **regardless of patch status** — napse-dpi L2/L7, host EDR (rules 1000100-115),
behavioral quarantine (ADR 0022, keyed on resource-reality not signatures), proven on Pi 4.
Upstream remediation can't protect the pre-patch window; behavioral edge enforcement can.

**Honest gaps vs the Akrites-era standard (all ⬜/🟡 — none shippable as a claim yet):**

| # | Missing capability | HookProbe today | Value×Effort |
|---|---|---|---|
| 1 | CVD process + `SECURITY.md` + SIRT-equiv | ⬜ none (no root SECURITY.md/CONTRIBUTING.md — confirmed) | HIGH × LOW — cheapest credibility win |
| 2 | AI-accelerated-threat model + narrative | ⬜ absent (our "AI-native" is defender-only) | HIGH × LOW (doc; Amber claim) |
| 3 | EPSS exploit-prob prioritization | ⬜ (mock UI sorts by CVSS only) | HIGH × LOW (free FIRST feed) |
| 4 | VEX from the signed SBOM (reachability) | ⬜ (SBOM proves *what*, not *exploitable*) | HIGH × MED — our differentiator |
| 5 | SSVC operator act/track/attend decision | ⬜ | MED-HIGH × LOW-MED |
| 6 | HYDRA live CVE-IOC enrichment (SBOM↔CVE) | 🟡 `modules/hydra/module.yaml` = `status: stub`; Intelligence CVE surface is mock (`os/mission-control/src/store/itlMock.ts`) | HIGH × HIGH — the enabler for 3–5 |
| 7 | Akrites/OSV ecosystem ingest via ideation-scout+HYDRA | ⬜ (on-ramp exists in both charters) | MED-HIGH × MED — telco-edge partnership hook |

**Positioning line (Amber — product-steward gate before hookprobe.com):** *"Akrites fixes open
source upstream; HookProbe OS defends the window before the fix reaches your device —
behaviorally, on owned hardware, regardless of patch status."*

**Honesty flags:** items 1–7 are gaps, not features. Our AI-defense today is a deterministic
reflex layer + an assistive BYO-LLM planner barred from enforcement (C9) — do not market it as
autonomous AI-vs-AI defense. Vendor material is stated, not benchmarked.

### Site-claim gate (codified honesty guardrail — product-steward-owned)

The AI-accelerated-attacker threat model is now in canon (`docs/architecture/Readme.md` `### Threat model` →
*The AI-accelerated attacker (Akrites-era)*). It draws a hard line for hookprobe.com copy:

- **MAY NOT be claimed as a capability until built (Tier 2, all ⬜/🟡):** VEX reachability from the
  signed SBOM, EPSS exploit-probability prioritization, SSVC operator decisions, live CVE↔SBOM
  enrichment (HYDRA is `status: stub`, Intelligence CVE surface is mock). Also barred: any framing
  of the AI as *autonomous*, *predictive*, or *AI-vs-AI* defense — the planner is assistive and
  C9-barred from enforcement.
- **CAN be led with now (proven on Pi 4 metal):** behavioral edge enforcement that catches
  exploitation **regardless of patch status** — napse-dpi L2/L7, host EDR (`host_edr.rs` rules
  `1_000_100..=1_000_115`), behavioral quarantine (ADR 0022), observe-by-default enforcement
  separation (ADR 0023). This is a stronger claim than a press release: demonstrated, not stated.
- **The positioning line** (above) stays **Amber** until product-steward + operator sign-off; the
  complement-not-competitor + Vodafone/Ericsson telco-edge hook ships *with* it, never as a
  standalone competitive dig.
