# 30: Working protection model: architecture, CM5 budget and milestones (proposal, 2026-11-22)

**Status: PROPOSAL.** It builds on the audit of 2026-11-22, the literature review summarised in §6, and the
benchmark in doc 28. It respects ADR 0023 / C9, 0053, 0055, 0058, 0059, and docs 09, 13 and 20. It supersedes
none of them.

## 1. What exists today

| Layer | Implemented (product) | Implemented (reference) | Validated | Proposed |
|---|---|---|---|---|
| L0 detection (kernel EL1) | ✅ rule catalogue `rulecat.rs`, behavioural thresholds, ratelimit, IOC/JA4/DGA, devbase | — | detbench (synthetic); **DET-01: 768/768 false positives in 24 h at home**; no precision/recall on public data before doc 28 | DET-01 fixes |
| Enforcement | ✅ HQCFG1 signed bundles, cfgd trial/revert, per-device classes, ADR 0053 TTL actions, owner journal | — | metal-proven | expiry, evidence refs, deltas (doc 29 §7) |
| Temporal DNA | `neuro-core` (Rust, host-tested, not in product) | `behavioural_memory`, `dna_fixed`, `dna_features` (v1, doc 27) | evidence-only (D1/D1b/D1c, P2) | on-device record (doc 27) |
| Supervised classifier | — | `bench.py` (LightGBM etc.) | dev benchmark (doc 28) | on-device scorer |
| Policy compiler | — | `tools/neuro_policy` (HQPROP1, 8 property tests) | tests only | doc 29 |
| Explainer (LLM) | — | ftDg + guard A/E | explanation gain on 2 of 3 blind sets; injection safety solved (doc 25) | doc 26 retrain running |

**Why fine-tuning has not consistently beaten the base model** (docs 23–26):
- an over-benign shortcut learned from template data (role ⇒ benign);
- the E filter wiping summaries that legitimately name a family;
- large variance in difficulty between blind-set authors.

**None of this affects protection.** The explainer is descriptive only and is not on the enforcement path.

## 2. Architecture: the smallest hybrid that can work on CM5

```
packets ──> heqk L0 (EL1, Rust; existing)  ──> detector events + incidents ─┐
              │ flow metadata                                                │
              └──> DNA v1 record per device-hour (doc 27) ──> deviation ────┤ (evidence)
                        │ 32 features                                        │
                        └──> LightGBM scorer (companion tier, ~1 MB) ───────┤ (confirmation)
                                                                             ▼
                            evidence bundle (refs) ──> POLICY COMPILER (doc 29; deterministic, signed proposals)
                                                                             │ owner approves (K_own; later K_adm)
                                                                             ▼
                            existing signed HEQK paths: ADR 0053 TTL action / owner journal / HQCFG1
LLM explainer (guard A+E) ── describes proposals and incidents to the owner; never ranks, creates or applies anything
```

**Decision rule (doc 29 §5):** **an L0 detector AND a confirming classifier.** Either signal alone never acts. DNA
deviation only raises confidence. Doc 28 shows this combination is the best measured balance.

**Deliberately not built now** (literature review §6, doc 28):
- temporal GNNs;
- federated learning (poisoning without client compromise; DISS 2020);
- per-packet GRU/TCN;
- any LLM or model output in the detection or enforcement path.

## 3. CM5 resource estimates

Measured figures are marked **M**; the rest are estimates.

| Component | Where | Memory | CPU |
|---|---|---|---|
| L0 (existing) | EL1 | existing tables (IOC 16 MiB file; devpolicy 256; devbase 64 × 16) | **M** 398–441 ns/pkt; 2.3–2.5 Mpps per A76 core |
| DNA v1: current records + baselines, 256 devices | EL0 server or companion | ≈ 90 KiB resident (doc 27 §5) | O(1) per flow; one vector per device-hour |
| DNA history, 7 days | storage / companion | ≈ 4 MiB | — |
| neuro-core (existing Rust, 64 devices) | EL0 (not wired) | **M** 83–85 KiB `.bss`; 1,296 B per device | **M** (QEMU) 51–88 ns/event; 148 µs per 64-device hour close |
| LightGBM, 200 trees × 15 leaves | companion tier (FP available) | ≈ 0.2–1 MB model | microseconds per vector; 256 vectors/h is negligible |
| Policy compiler | companion | < 1 MB | per incident |
| Explainer 1.7B Q8 | language tier (4 GB SKU and up) | ≈ 1.8 GB | seconds per explanation; off the protection path |

**EL0 constraint:** no FP/SIMD in EL0, so tree inference in EL0 would need fixed-point thresholds. The
recommendation is to keep LightGBM in the companion tier first. The quantised features of DNA v1 make a
fixed-point tree port possible later.

## 4. Milestones (smallest working protection first)

| # | Milestone | Done when | Owner |
|---|---|---|---|
| **M1** | **Measure real L0 on public data.** Replay IoT-23 and CTU-13 dev captures through heqk's detectors (QEMU or host harness) and score kernel output with the doc 28 protocol. | A kernel-measured row replaces the "kernel-style" approximation. | Neuro + HomePods (harness only) |
| **M2** | **DNA v1 per-device baseline** (doc 27 §4) in the reference, and alert aggregation per incident. | Doc 28 re-run gives ≤ 0.14 false alerts per device-day (about one a week) at recall ≥ 0.9 on dev. | Neuro |
| **M3** | **Sealed confirmation.** Pre-register thresholds and decision rule, then run once on the IoT-23 + CTU-13 test splits (sealed in intel-data) and Deakin IoT v2 (sealed holdout). | Pre-registered precision / FPR / per-device-day targets met or reported failed. | Neuro + intel-data |
| **M4** | **Policy compiler integration.** HQPROP1 proposals rendered in the owner app; approval through HQMGMT1 → ADR 0053 actions. No kernel change. | End-to-end on QEMU: incident → proposal → owner approve → TTL action → expiry. | Neuro + app |
| **M5** | **Kernel requests R-P1…R-P4** (doc 29 §7). | HomePods decision recorded. | HomePods |
| **M6** | **Field study (P7).** One lived-in home, 2+ weeks, observe-only. | Alerts per device-week and owner-rated precision. | operator |
| **M7** | **Explainer:** doc 26 result → blind v6 or ship guard + base. | Gate result recorded. | Neuro (running) |
| **Research (after M3)** | DNA v2 (DNS features), 10-min windows, drift detection (ADWIN), fixed-point trees in EL0 | — | — |

## 5. Dataset and licence register

`data/licence-register.md`, generated read-only from the intel-data registry: 205 sources, with
training / evaluation / live_intel / redistribution decided per source.

**Key facts for this plan:**
- IoT-23 (CC BY 4.0) and CTU-13 (CC BY 2.0): OPEN, with test splits sealed.
- UNSW-IoTraffic: **CC0-1.0, verified 2026-11-22.**
- Deakin IoT v2: sealed holdout, licence not yet verified by the registry.
- The CIC datasets: evaluation only (`licence_caveats`).
- abuse.ch: no training; Feodo as live intel only.

## 6. Literature summary

Full report with citations: session notes, 2026-11-22.

- **Strongest feasible:** tree ensembles on window features, and robust per-device baselines (Arp et al.: a boxplot
  baseline beat Kitsune on its own Mirai trace).
- **Evaluation:** split by capture or time and report at realistic base rates. The CIC-IDS2017/2018 label errors
  (Engelen et al. 2021; Liu et al. 2022) make random-split numbers unreliable.
- **Defer:** temporal GNNs (an enterprise lateral-movement focus) and federated learning (poisoning risk).
- **Governance mapping:**
  - NIST AI RMF and AI 100-2 E2025: poisoning, evasion and prompt injection.
  - ENISA, Securing ML Algorithms.
  - MITRE ATLAS: red-team plan for the detector itself.
  - OWASP LLM01: telemetry is data, never instructions. Guard A/E covers this.
