# NEURO_FINAL_RECOMMENDATION — Gate 6 decision, Gate 7 request

> HookProbe Neuro Engine, Research Gate 001 (2026-11-17). This is a **recommendation awaiting operator
> approval**. Nothing it proposes has been built. Evidence behind each statement is classified in §5;
> no result in this package was measured on a CM5.

## 0. Phase 0 update (2026-11-18) — read first

Phase 0 ran (blind set, real-traffic replay, six models; details in
[`NEURO_PHASE0_RESULTS.md`](NEURO_PHASE0_RESULTS.md)). It **confirms the decision below with
independent evidence** and sharpens it:

- On 215 independently written cases every candidate model (0.35–2B) was **significantly worse than
  the deterministic core at verdicts** (best 0.50 vs 0.59; McNemar p ≤ 0.04), while **L0 verdict + model
  explanation** raised explanation coverage from 0.27 to 0.56–0.73 at the same verdict accuracy. The
  model is an explainer, never the judge.
- Grammar-closed decoding is mandatory ≤ 2B (free decoding: worse verdicts, more injection leakage,
  0% valid output for Qwen3.5-0.8B).
- Explainer shortlist: **Qwen3.5-0.8B** (fast tier, Romanian 1.00, projected ~6 s/incident on CM5),
  **Qwen3-1.7B** (best coverage, ~13 s/incident). Hybrid models lose llama.cpp prompt-cache reuse —
  fix with state snapshots (P5).
- Evidence cards on real held-out malware traffic: 0.88 identity / 0.65 evidence recall (synthetic
  had 1.00) — weakest on C&C. Behavioural memory: peer novelty works on real devices; the
  hour-of-day profile fails cold-start. Both have concrete fixes; neither is at its kill criterion.
- Still **no CM5 measurement** — a reachable bench unit is the blocking item.

## 1. The decision

**Build HookProbe's local intelligence as "Evidence-First, Model-Last" (architecture D).**

Every answer the product depends on — classify, correlate, remember, explain — is produced by an
integer-only core that runs on heqk today: deterministic rules and templates (EN/RO), an evidence
compiler, a per-device behavioural memory, and (next) distilled tiny specialists. A generative model
is a **leased, optional, bandwidth-paced, evidence-closed** enhancement that adds natural language,
correlation narrative and owner-context reasoning. It runs wherever resources exist: the device's own
CPU on 8/16 GB SKUs once heqk can host it, an NPU on the RK3588 board, or the owner's companion/PoP
through the existing ADR 0025 BYO endpoint. The product never depends on it.

Why this and not a "best small LLM": on CM5 a model is the most expensive and least reliable
component, and on heqk today it cannot run at all. The measurable levers are upstream of the model —
how much evidence reaches it, how often it is needed, and how much DRAM bandwidth it may take.
Architecture D scored 4.10 / 5 under the specified value weights, against 3.60 for the closest
alternative (C, the same ladder with on-device generation as a hard dependency). It stayed first under
every single-weight change of ±50% and every named scenario, and ranked first in 82% of 20,000
randomised weight/score draws. It ties C on value alone; it wins on feasibility, reliability and
efficiency (`NEURO_ARCHITECTURE_COMPARISON.md`).

## 2. The six answers

| Question | Answer |
|---|---|
| **Best overall direction** | Architecture D — evidence-first, model-last, generation as a pluggable lease. |
| **Best immediate opportunity** | **Validate D's core on real traffic, with no model and no kernel dependency**: replay labelled captures through the evidence compiler and the behavioural memory, and build the blind eval set (E-SC2, E-BM2, E-EV1). Two to three weeks, a development host and public datasets. It decides whether the core holds before anything is built. In parallel, run `cm5_bench.sh` on one Linux CM5 bench unit to replace this package's theoretical numbers with measurements (E-HW1/2/6/7, E-LLM1/2, E-INT1). |
| **Best long-term innovation** | **Owner-taught behavioural memory**: a per-device baseline of ~0.6 KB that never learns from alarming observations on its own, asks the owner — through a one-line model explanation — whether a new behaviour is normal, and records the answer as a signed update. It turns every HookProbe into a network that learns its owner's normal over time, explained in the owner's language. Prior art exists for each part (Cisco US 10,220,167; RAAD; Kitsune), so the advantage is the **integrated, measured system plus HookProbe's own data** (eval sets, calibration data, distilled specialists), not a patentable mechanism. |
| **What not to build** | See §4. Headlines: a resident general-purpose LLM; a custom inference runtime now; a recurrent LM as the network's memory; separate-draft-model speculative decoding; storage-backed decode; ≤ 3-bit post-training quantisation of small models; GPU (VideoCore) inference; federated LLMs. |
| **Recommended investment (first)** | (1) the blind eval set + replay experiments; (2) the evidence compiler and fixed-point behavioural memory as heqk EL0 / Wasm modules; (3) EN/RO templates; (4) teacher-labelled distillation of the untrained L1 models (NAPSE tabular, `dga-lm`) using an Apache-2.0 teacher. Generative-tier work is limited to measurement until the kernel prerequisites in §6 land. |
| **Evidence required** | E-SC2 (≥ 0.9 identity recall at 1K tokens on real traffic, no silent drop of a sev ≤ 2 detection); E-BM2 (< 1 nuisance alert per device per week, slow-poisoning test); E-DS1 (distilled heads beat the heuristic seeds on an independently labelled set); E-INT1/2 (decode's effect on packet-path p99, and whether pacing restores it); E-LLM2 + E-EV2 (a generative backend passes the eval gate in closed mode on its target SKU). Kill criteria for each are in `NEURO_EXPERIMENT_DESIGN.md`. |

## 3. The ten Gate-6 questions

1. **Smallest useful local intelligence architecture?** Rules + templates + evidence compiler +
   behavioural memory: **≤ a few MiB, integer-only, no model** — it classifies, correlates across
   cards, remembers per-device behaviour and explains in EN/RO templates. Simulated, it compiled an
   hour of telemetry (~323K tokens raw) into ~500 tokens with full incident recall, and separated
   injected anomalies at AUC 0.999 with 638 bytes per device. What it cannot do is converse or weigh
   free-text context; that is the generative tier's job.
2. **Can we avoid keeping a generative LLM resident?** **Yes, by design.** Idle generative memory is
   zero; a lease costs ~1–11 s of cold activation from eMMC for 0.6–1.7B Q4_0 models (theoretical),
   reduced by restoring a pre-computed prefix KV snapshot. That latency suits investigations, not chat.
3. **Can recurrent models replace transformers for some workloads?** **For the memory, yes — but the
   winner is not a recurrent *language model*.** A statistic recurrent state (EWMA + aging Bloom
   filters) holds per-device behaviour in bytes; an RWKV state is ~12 MiB per stream and is written by
   untrusted input. For generation, hybrids (Qwen3.5 DeltaNet, Granite-4.0-H) are reasonable choices
   on quality and licence grounds, but their memory advantage is small at the short contexts the
   evidence compiler produces (Granite-H's constant state, ~54 MiB, *exceeds* a transformer's KV below
   ~4K tokens). A learned recurrent behavioural state must beat the statistic baseline at equal bytes
   (E-BM2) or be dropped.
4. **Can native ternary inference give a material advantage on Cortex-A76?** **Plausibly, not yet
   proven.** Ternary halves the bytes read per token (decode bound ~15 tok/s for BitNet 2B4T vs ~10 for
   a 1.7B Q4_0, theoretical); T-MAC measured BitNet-3B at ~11 tok/s on a Pi 5, but against a 2024
   llama.cpp. BitNet's general quality is below Qwen-class models and it names no Romanian. Decide
   with E-LB1; do not plan on it.
5. **Can storage extend practical model capacity?** **Only as the cold tier.** Dense decode re-reading
   weights from eMMC or Gen2-×1 NVMe costs seconds per token. Storage holds models that are loaded
   whole into RAM on demand; it never substitutes for RAM during decode. heqk has no NVMe driver and no
   page cache.
6. **Can specialised intelligence replace general generation?** **For decisions, yes; for language,
   no.** Verdicts on compiled evidence are largely determined by heqk's deterministic categories (the
   contaminated L0 baseline hints at this; the blind set must confirm it). Generation earns its cost in
   explanation, owner-context weighing, multi-card narrative and Romanian. HookProbe's L1 specialists
   are currently **untrained placeholders**; distillation is the missing investment.
7. **Useful Romanian and English conversation?** **Not on the device today.** Templates give reliable,
   limited EN/RO explanations immediately. Conversational Romanian needs a generative backend: Qwen3
   names Romanian among its 119 languages; EuroLLM names it and is Apache-2.0; Qwen3.5 (201 languages)
   and Gemma 4 do not name it on their primary pages. Every candidate must pass the RO cases of the
   blind set.
8. **Can security performance be preserved during inference?** **Yes, if inference is a budgeted
   tenant**: never on a data-plane core (ADR 0060), RAM from its own shed-first budget (ADR 0061),
   DRAM bandwidth paced from bytes per token, duty-cycle cut before thermal throttling, and an honest
   "deferred: network busy" answer under pressure. Published work shows the victim of bandwidth
   interference suffers far more than the model (ResQ, Sereno). The size of the effect on heqk is
   unmeasured (E-INT1).
9. **Build internally vs adopt?** **Build:** the evidence compiler, behavioural memory, router and
   budget governor, validator and closed-schema builder, templates, eval sets and distillation
   pipeline — the parts that encode HookProbe's knowledge and its kernel's admission model. **Adopt:**
   llama.cpp (MIT) as the first generative backend behind a backend trait; Apache-2.0 / MIT models;
   bitnet.cpp if E-LB1 wins; HailoRT on the RK3588 board. **Do not build** an inference engine until
   heqk can host one and a measured gap justifies it (P8).
10. **Most promising original HookProbe innovation?** The **integrated** loop — evidence compiled
    before inference, behaviour remembered without a model, generation leased and paced, output closed
    to the evidence, and learning only from signed owner decisions — running on a capability microkernel
    that admits AI as a budgeted tenant. Prior art covers each part individually; no single mechanism
    should be presented as an invention without a professional search.

## 4. What not to build (rejected, with the reason that kills it)

| Rejected | Reason |
|---|---|
| A resident general-purpose LLM as the product's AI | lowest value score (1.90); competes with the data plane permanently; raw-log prompts are infeasible on CM5 |
| A custom inference runtime / AOT executor now (P8) | heqk cannot host one yet; no measured gap over llama.cpp to justify it |
| A recurrent language model as the network's memory (architecture B) | MiB of untrusted-written, opaque state per stream vs bytes of inspectable statistics; no A76 evidence |
| Separate-draft-model speculative decoding | 0.67–0.83× on 1.5–1.7B targets in EACL 2026 (GPU); worse on a bandwidth-bound CPU (theoretical) |
| Storage-backed decode, LLM-in-a-flash style | seconds per token for dense models; needs ReLU-sparse models |
| ≤ 3-bit post-training quantisation of 0.6–4B models | collapses to chance-level MMLU |
| Unstructured sparsity (SparseGPT/Wanda) for CPU | no sparse kernels in GGUF; no gain |
| VideoCore VII / Vulkan inference | unsupported upstream; patched path ~80× slower than CPU |
| Hailo-10H on CM5-on-heqk | no driver; revisit on the RK3588 board |
| Federated learning of LLMs | federate only small L1 heads, later |
| Ollama in the device stack | extra overhead and RAM over llama.cpp (secondary evidence) with no capability HookProbe needs |
| Shipping LFM2/2.5/3, Gemma 3/3n, Llama 3.2, Hunyuan, OpenLLM-Ro weights | licence: LFM revenue cap (≥ US$10M); Gemma Terms / Llama AUP pass-through conflicts with shipping inside AGPL images; Hunyuan excludes the EU; OpenLLM-Ro is non-commercial |
| Distilling from Gemma, Llama, OpenAI or Anthropic outputs | derivative-model or anti-competition terms; use Apache-2.0 teachers |

## 5. Findings by evidence class

| Class | Findings |
|---|---|
| **Verified on actual CM5** | none |
| **Read from this repository** | heqk on CM5: one core, FP/SIMD trapped (CORE-7), 4 GiB mapped, 128 MiB EL0 frame pool without free, no NVMe driver, no page cache, no RAM facts or pressure signal; Mission Control returns `not_configured` for the planner; L1 models are untrained seeds |
| **Verified on ARM64 (published)** | Pi 5 decode bandwidth-bound, peaks at 2 threads; Q4_0 0.5B ≈ 34 tok/s, 1.5B ≈ 12 tok/s; T-MAC BitNet-3B ≈ 11 tok/s on Pi 5; Hailo-10H prefill ~6× faster than Pi 5 CPU, decode slower |
| **Scientifically demonstrated (elsewhere)** | KV quantisation (KIVI, KVQuant); speculative decoding slows small models (EACL 2026, GPU); cascades/routers cut cost (FrugalGPT, RouteLLM); bandwidth interference harms co-runners (ResQ, Sereno); distillation step-by-step |
| **Demonstrated in implementations** | llama.cpp closed JSON schema, slot save/restore, KV types, repack; bitnet.cpp TL1 on ARM; grammar-closed citations (FullCite, Citeformer); token-budgeted alert compilation (AIDR, Slips) |
| **Theoretical (this study)** | E-RF1 decode/prefill bounds, state memory, bandwidth-share tables, storage-tier and activation times |
| **Simulated (this study)** | E-SC1 evidence cards; E-BM1 behavioural memory and its drift/poisoning trade-off; E-EV0 L0 baseline (contaminated) |
| **Hypotheses** | quality cost of closed decoding (E-EV2); benefit of bandwidth pacing (E-INT2); learned vs statistic memory (E-BM2); ternary advantage on A76 (E-LB1); explain-to-learn reduces nuisance without enabling poisoning |

## 6. Prerequisites owned by HomePods (requested, not modified)

On-device generation on CM5 requires kernel decisions that this study did not and will not make:

1. **ADR 0060** — start secondary cores; an MG/best-effort core role that can host an AI tenant.
2. **CORE-7 / A5** — an FP/SIMD policy for EL0 (enable `CPACR_EL1.FPEN` with q-register save and scrub
   on context switch), at least for tasks granted a capability such as `edge_ai`.
3. **ADR 0061** — RAM discovery beyond 4 GiB, budgets backed by Untyped, a freeing allocator, a
   memory-pressure signal, and admission of a shed-first AI budget.
4. An eMMC sustained-read figure and a loader path from storage into an admitted budget (activation).
5. A data-plane pressure signal the AI governor can read (for bandwidth pacing).
6. Mission Control proxy routes: `/api/planner/*` currently returns `not_configured` (`http.rs:427`,
   `:698`); forwarding evidence-card requests to a configured backend is a change in `os/kernel/**`.

The integer-only core (evidence compiler, behavioural memory, templates) needs **none** of 1–3: it fits
the existing EL0/Wasm host.

## 7. Roadmap — Gate 7 (approval required before each phase)

| Phase | Scope | Effort (rough) | Exit criterion | Needs |
|---|---|---|---|---|
| **0 · Prove the core** | E-EV1 blind set (EN/RO, ≥ 200 cases, independent author); E-SC2 and E-BM2 on replayed public + bench traffic; `cm5_bench.sh` on one Linux CM5 bench unit (E-HW1/2/6/7, E-LLM1/2 for 3–4 Apache models, E-INT1, E-TH1) | 2–3 weeks | kill criteria in the experiment design pass or fail | operator approval to download candidate models to a lab unit; a bench CM5 with Raspberry Pi OS |
| **1 · Ship the core on heqk** | evidence compiler + fixed-point behavioural memory as EL0/Wasm modules; EN/RO templates in Mission Control's explanation panel; owner "learn as normal" via the ADR 0055 journal | 4–8 weeks | E-BM3 cost < 1% of a core; mc-e2e green; no separation-matrix regression | Amber review; HomePods for any kernel-side hook |
| **2 · Train the specialists** | Apache-2.0 teacher labelling + distillation of NAPSE tabular and `dga-lm` (E-DS1) | 4–6 weeks | beat the heuristic seeds on held-out independent labels | labelled corpus licences checked |
| **3 · Generative lease** | backend trait (llama.cpp first), closed-schema builder, validator, bandwidth governor; first through the BYO endpoint (companion/PoP), then on-device for 8/16 GB once §6 lands; model chosen by E-LLM2/E-EV2/E-LB1 | after §6 | eval gate passed on target SKU; E-INT2 pacing restores p99 | §6 prerequisites |
| **4 · Scale out** | RK3588 NPU backend; signed behavioural-signature exchange; federated L1 heads | later | — | ADR 0064 H-gates |

### Generative-tier candidates to measure in Phase 0 (licence-checked; none measured)

| SKU target | Candidates (Apache-2.0 / MIT) | Why | Watch |
|---|---|---|---|
| 4 GB (on-demand) | **Qwen3.5-0.8B**, Qwen3-0.6B | smallest credible instruct + tools; Qwen3 names Romanian | quality floor; RO for Qwen3.5 unconfirmed |
| 4–8 GB | **Qwen3.5-2B**, **Qwen3-1.7B**, Granite-4.0-H-1B / 4.1-3B | tool calling, IFEval/BFCL published; hybrid options | Granite names no Romanian |
| low-bit challenger | **BitNet b1.58 2B4T** (MIT, bitnet.cpp TL1) | best bytes/token | quality, 4K context, no RO |
| 8–16 GB | **Qwen3.5-4B** / Qwen3-4B-Instruct-2507; **EuroLLM-9B-Instruct-2512** for Romanian | stronger reasoning; EuroLLM explicitly targets Romanian | decode ~2–5 tok/s (theoretical) |
| excluded | LFM family, Gemma 3/3n, Llama 3.2, Hunyuan, OpenLLM-Ro, Qwen2.5-3B | licences (see §4) | Gemma 4 E2B/E4B are Apache-2.0 and may be added |

## 8. One paragraph for the operator

Do not ship a chatbot on the CM5. Ship a network that understands and remembers itself in kilobytes,
explains itself in EN/RO without a model, and asks its owner — in one sentence — before it learns
something new. Make the language model an optional, leased guest that is constrained to the evidence
and never allowed to slow the data plane, and let it move to wherever silicon is free (a bigger SKU,
an NPU, a companion). Spend the first three weeks proving the core on real traffic and measuring one
real CM5, because every number in this package is still theoretical or simulated.
