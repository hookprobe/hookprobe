# 09 — Intelligence designed for HookProbe, not for chat (Gate 9)

> Native Inference Research Programme, 2026-11-18. Evidence classes:
> - **measured** — Phase 0 / 0b, development host or real traffic, as labelled;
> - **simulated**;
> - **proposed**.
>
> The rule that does not move: **no model authorises enforcement**. Enforcement passes through
> the deterministic `decide()` path and the separation matrix (ADR 0023; contract C9).

## 1. Five kinds of intelligence, five different machines

| Tier | Job | Mechanism | Where it runs on heqk | Per-event cost | Evidence |
|---|---|---|---|---|---|
| **A. Deterministic security** | parse, match, rate-limit, enforce | rules, BPF (interpreter + arm64 JIT), reputation and IOC tables, `decide()` | EL1 data plane (ADR 0050) | **398–441 ns/pkt**, 2.3–2.5 Mpps per A76 core | metal (`00` §3.8) |
| **B. Fast intelligence** | classify flows/devices, DGA, anomaly scores | int8 trees, logistic heads, char-CNN, embeddings ≤ 100 KB | one EL0 server, scalar integer, bounded excursion | µs | proposed (E-DS1); heads exist as untrained seeds |
| **C. Temporal intelligence** | "is this device unlike itself?", change and drift, correlation across time | **Neural DNA** (672 B/device) → tiny int8 recurrent cell → owner-confirmed adaptation | same EL0 server | µs | **measured on real traffic**: peer novelty flags all 14 semi-synthetic onsets; real Hue honeypot 2 alarms/day after the cold-start fix |
| **D. Language intelligence** | explain, summarise an investigation, answer the owner | evidence cards → small LM under evidence-closed decoding; the model writes, L0 decides | leased tier (needs `12`), off-device fallback | 2–13 s per incident (projected) | **measured (blind)**: models are worse judges than L0 (0.37–0.50 vs 0.59) but best explainers (explanation coverage 0.27 → 0.56–0.73) |
| **E. Distributed intelligence** | share validated patterns, update models, optional remote inference | signed behavioural deltas, signed HNX packages, the existing PQ-hybrid secure channel | control plane | network-bound | proposed |

**The most efficient design is a set of small specialists under deterministic control, with one
language model used rarely and only to explain.** The evidence:
- Phase 0: on the blind set every model was worse at verdicts than the rules core, and roughly
  equal to answering a constant (0.42–0.43).
- Phase 0: every model was useful at explaining.
- Phase 0b: the free-mode baseline showed small models **anchor on whatever verdict an example
  suggests**. That is exactly the wrong property for a judge, and acceptable for a writer whose
  verdict is supplied.

## 2. Neural DNA — what it is made of, precisely

| Ingredient | Kind | Lives where | Changes how | Signed? |
|---|---|---|---|---|
| Statistical profile per device: diurnal activity, volume, fan-out EWMAs; learned novelty rate; aging Bloom filters of peers and DNS suffixes; cold-start pooled profile | **per-device state** | device RAM (672 B), sealed snapshot to the evidence store | online, guarded: alarming hours do not teach, except cold-slot statistics; new peers need 6 alarming hours (`PERSIST_K`) | snapshots sealed (HQKSEAL1) |
| Learned recurrent cell weights (if E-N2 passes) | **model weights** | HNX package, shared by all devices | offline training only; shipped as a signed package | yes (HNX) |
| Recurrent hidden state per device | **per-device state** | device RAM (64–256 B) | every event | sealed snapshot |
| Prototypes / embeddings of device *types* | **model weights** (learned) or **threat intelligence** (curated) | package or intel feed | offline / feed | yes |
| Known-bad patterns, IOCs, reputation | **threat intelligence** | artifact store (16 MiB caps) | feed updates | operator-signed packs (existing) |
| What to do about a deviation | **deterministic policy** | `decide()`, separation matrix | operator intent via AEGIS | config is generated, signed images |
| Owner confirmations ("yes, that new app is normal") | **per-device state + audit record** | evidence log | owner action only | evidence log (sealed) |

The four categories are kept in separate stores with separate update paths:
1. learned weights;
2. per-device state;
3. threat intelligence;
4. deterministic policy.

**A model update can never change policy, and a feed update can never change a model.** The owner's
confirmation is the only thing that turns a deviation into "normal" faster than `PERSIST_K`.

## 3. Representation options for the per-device memory

| Option | Bytes per device | Learns | Explains itself | Poisoning resistance | Status |
|---|---|---|---|---|---|
| Statistical sketches (current DNA) | 672 | statistics only | **yes**: every alarm names its driver (volume, fan-out, novelty, DNS, activity) | guarded updates; persistence k | simulated + real traffic |
| Small recurrent state (GRU / minimal RNN, int8) | 64–256 | patterns over sequences | weakly; needs attribution | depends on the update guard | proposed (E-N2) |
| Quantised embedding of recent behaviour | 32–128 | similarity to prototypes | via nearest prototype | stable (no online learning) | proposed |
| Learned prototypes (device-type centroids) | shared, not per device | offline | "behaves like a camera" | stable | proposed |
| Signed behavioural deltas (for the mesh) | 100s of B per update | — | carries its evidence | **requires signing and a quorum; mesh poisoning is the main risk** | proposed (tier E) |

**Recommendation:** keep the statistical DNA as the always-on base: it is measured, explainable and
integer-friendly. Add a learned cell **only if it beats DNA at equal bytes** (E-N2 kill
criterion). Never replace an explainable signal with an opaque one without a measured gain.

## 4. How the tiers meet in Mission Control

- Detections and DNA alarms (tiers A–C) land as **evidence-graph nodes**. They are already
  template-explained (`det_row`, `mcstate.rs:744-785`).
- An incident's explanation panel ("why · confidence · evidence · model · related events",
  `MissionControl.md`) is filled in this order:
  1. **L0 template, always**;
  2. **model-written summary when a language tier is available**, closed to the incident's
     evidence cards and labelled with the model's name;
  3. otherwise the template stays.
- `/api/planner/*` keeps answering `not_configured` until a language tier is admitted, so the honest
  default stays honest.
- AEGIS proposals remain plans-as-diffs that the deterministic reconciler applies and verifies. A
  language model may *word* a proposal and may never *apply* one.

## 5. Security of the intelligence itself

| Threat | Control |
|---|---|
| Prompt injection inside telemetry | context marked untrusted; evidence-closed decoding; canary tests (blind set: closed mode 0.92–1.00 canary-safe vs free 0.60–0.96) |
| Poisoning the per-device memory (a slow-ramp attacker) | guarded updates; `PERSIST_K`; owner confirmation; the cold-slot learning exception is limited to statistics (Phase 0b risk noted) |
| A malicious or tampered model | HNX signature, manifest admission, read-only mapping, no code in packages (`06`) |
| A model starving the packet path | leases, bandwidth pacing, preemption by data-plane pressure (`08`, `12`); E-INT kill criteria (`11`) |
| Mesh poisoning (tier E) | signed deltas, quorum, never auto-applied to policy |
| Over-trusting a model's verdict | the model never supplies the verdict (L0 does); constant-answer baselines published next to every model score |
