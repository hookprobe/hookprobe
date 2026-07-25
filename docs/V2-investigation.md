# HookProbe OS V2 — Customer-First Investigation

> **Thesis under test:** can HookProbe be an easy-to-use *"SOC on a budget"* that is **ahead of FortiSOC / Microsoft Sentinel / Defender XDR** on the only axes customers feel — time-to-value, number of steps, and predictable cost? **Finding: yes, and the V2 architecture is already aimed at exactly the incumbents' three open wounds.** This document turns that into concrete, fewer-steps design direction, with `docs/MissionControl.md` as the guiding spec.

**Date:** 2026-06-27 · Sources: two commissioned web-research passes (competitive UX + stack benchmarks). Companion: [ADR 0001 — Mission Control stack](adr/0001-mission-control-stack.md).

---

## 1. The market opening (what the research proved)

Every incumbent is fighting the **same three battles and losing at least two** — and they admit it:

| Wound | Incumbent evidence | HookProbe's structural answer |
|---|---|---|
| **Too many steps / too long to value** | Sentinel: 90–120 min just for first data; legacy migration "up to 15 months." Darktrace: 4–32 weeks to value with poor early signal. Fortinet: setup "confusing even for experienced users." | **SOC live on first boot.** Bootstrap writes the manifest once; monitoring runs from boot. Time-to-SOC ≈ first boot. |
| **Too many consoles** | Defender XDR: **~10.9 consoles per analyst**. Microsoft forcing Sentinel→Defender merge **by Mar 2027**. Fortinet launched "FortiSOC" **Mar 2026** to fix its own "tool sprawl." | **Born unified — "one system, many lenses."** One evidence graph, one telemetry fabric, one console. No migration deadline; we *start* where they're spending until 2027 to arrive. |
| **Unpredictable, ingestion-driven cost** | Sentinel ≈ $2.46/GB; commitment tiers you can only guess; "cost predictions remain challenging." Darktrace "$100k+/yr," opaque. Arctic Wolf ~$44k/yr floor. | **Local-first, open-core, ingestion-decoupled.** Standalone device is free; retention is bounded by *your* storage, not billed per GB. The paid lever is the managed cloud layer. |

The incumbents rate well on *capability* (Sentinel 4.6★). **The attack surface is usability and cost, not features.** So V2 must not chase feature parity — it must win on fewest-steps-to-the-answer.

**The mid-market bar to beat is Blumira, not the enterprise giants:** ~4-hour deploy, usable by IT generalists, ~15–30 min/week to operate, auto-tuned detections, flat price with a free tier. HookProbe should match Blumira's *ease* while exceeding it on *depth* (full local SOC, intent operation, edge + fleet).

## 2. Seven places HookProbe wins — mapped to Mission Control

Each opportunity is tied to a named incumbent weakness **and** the workspace/pattern in `docs/MissionControl.md` that delivers it.

1. **Zero-setup SOC from first boot** → *Mission Control* lands on Organism Status already populated; no "set up the SOC" step. Beats Sentinel's 90–120 min and Darktrace's weeks. **Design rule:** the common case needs zero configuration; first-run shows value, not a wizard.

2. **Intent / plain-language instead of a query language** → the *AI Copilot* (`⌘/Ctrl-K`) and the intent bar are the front door; KQL-equivalents are advanced/optional. Beats Sentinel's KQL barrier (SC-200 to even query). **Design rule:** "show me logins from new countries this week" must work without anyone learning a syntax; the generated query is shown as evidence, not required as input.

3. **One unified console — say it out loud** → the *whole navigation map* (Observe/Detect/Investigate/Protect/Automate/Intelligence over one graph). Beats the 10.9-console swivel-chair. **Narrative to use:** *"They're spending until 2027 to unify consoles; we're born unified."*

4. **Transparent, flat, ingestion-decoupled pricing** → *Business* workspace + open-core model. Beats Sentinel bill-shock, Fortinet quote-only, Darktrace opacity. **Design rule:** never punish the customer for logging more; standalone is free, the bounded-retention model is honest about limits.

5. **Curated, auto-tuned detections — low alert fatigue by default** → *Detect · NAPSE* ships signed, MITRE-mapped rule-packs tuned out of the box; *QSecBit* rolls noise into one posture number. Beats Darktrace/Defender false-positive pileups and Fortinet's heavy correlation tuning. **Design rule:** high day-1 signal-to-noise without an engineer writing correlation rules.

6. **Glass-box explainability, not black-box automation** → the *AI explanation panel* everywhere (*why · confidence · evidence · model · related events*) and *Investigate*'s "Why AEGIS decided this." Directly beats Darktrace's "limited transparency" that makes leaders distrust autonomous response. **This is a UX feature, not a footnote** — trust is sold by showing the reasoning and the diff before action.

7. **Capability-gated simplicity / progressive disclosure** → manifest-driven rendering hides what the box can't do; advanced knobs appear only when asked. Beats "powerful but you must learn workbooks/parsers/playbooks first." **Headline metric is time-to-value and fewest-steps, not feature count.**

**Sharpest one-liner (positioning):**
> *The incumbents are spending until 2027 unifying consoles, charging you by the gigabyte, and making you learn a query language. HookProbe OS is a full SOC the moment you boot it — one console, plain-English questions, one flat price.*

## 3. Customer-first simplification mandate ("less is more")

Concrete rules for `ux-architect` and `code-developer` to enforce against `docs/MissionControl.md`:

- **Count the steps.** Every primary task ("am I safe right now?", "isolate this host", "show me last night", "add a detection") gets a click/decision budget; design drives it down and the doc records before→after.
- **Zero-config default, power on demand.** The safe, useful behavior is the default; configuration is a generated artifact reachable through intent, never a prerequisite. Preserve "time-to-SOC ≈ first boot."
- **One concept, one node.** The same incident/asset/IOC is the same evidence-graph node in every workspace — never re-modeled per page. No dead-end numbers; everything drills to evidence.
- **Intent first, syntax optional.** Natural-language + a plan-as-a-diff is the primary path; raw rules/queries are an advanced reveal.
- **Explain every action.** No automated action without a plain-language *why · confidence · evidence · model*. Trust is the product.
- **Render only what exists.** Capability-gate from the manifest; design the greyed-with-reason and degraded states deliberately.
- **Honest, not infinite.** Show the real retention window and offer offload — don't pretend (the inverse of Sentinel bill-shock and Darktrace opacity).

## 4. Stack decision (summary — see ADR 0001)

**LOCKED (ADR 0001, Accepted):** **Astro + SolidJS + Rust/Axum** — one component language across both surfaces, quantum-ready at the transport layer.

- **UI everywhere:** **SolidJS** — fine-grained reactivity beats React's VDOM under high-frequency live updates; one component language for both the content islands and the dashboard. Astro is framework-agnostic, so this is a single-framework stack, not a forced split.
- **Content surface (Knowledge/CMS/SEO):** **Astro** hosting Solid islands — zero-JS content/blog/docs/SEO; interactivity as Solid islands.
- **Live dashboard:** **SolidJS SPA** route served alongside the Astro content surface.
- **Backend / control API:** **Rust + Axum** — ~8.5 MB RSS vs ~82 MB Node, flat p99 (no GC), reinforces the OS's Rust/Wasm supply-chain posture, and is the strongest **PQC** ecosystem (rustls hybrid X25519MLKEM768; RustCrypto ML-KEM/ML-DSA) — quantum-ready TLS for free, serving the manifest's `ml-kem-768+x25519` / `ml-dsa-65` posture.
- **Transport:** **SSE over HTTP/2** for telemetry/score fan-out + **one WebSocket** for control. WebTransport deferred ~12 months.

`code-developer` builds a Pi-5/N100 vertical slice over hybrid-PQC TLS to *tune* (not reverse) the decision, and validates the Knowledge-workspace editors against framework-agnostic cores (ProseMirror/TipTap, CodeMirror).

## 5. Open decisions for the operator (you)

1. **Pricing model** — adopt the flat, ingestion-decoupled, free-standalone model (Blumira-style) as the explicit answer to Sentinel bill-shock? This is a business decision the architecture already supports.
2. **Stack sign-off** — accept ADR 0001's SolidJS + Astro + Rust/Axum direction, or have `code-developer` prototype Svelte 5 as the dashboard alternative first?
3. **Auto-tuned detection sourcing** — which rule ecosystems ship pre-tuned at first boot (Suricata/Sigma/YARA packs) to hit Blumira-grade day-1 signal-to-noise?
4. **Positioning copy** — adopt the "born unified / SOC on first boot / one flat price" narrative on the webpage and in Mission Control's first-run?

## 6. Next actions

- `ux-architect`: take one primary task (proposed: **first-boot → first answer**) and produce the fewest-steps flow + wireframes against MissionControl.md, with a before→after step count vs Sentinel/Defender.
- `os-architect`: confirm the first-boot bootstrap + manifest path makes "SOC live on boot" real, and define the local read/write API the dashboard binds to.
- `code-developer`: build the SolidJS ← SSE/WS ← Axum vertical slice on Pi 5 + N100; report bundle/TTI/memory/latency to validate ADR 0001.
