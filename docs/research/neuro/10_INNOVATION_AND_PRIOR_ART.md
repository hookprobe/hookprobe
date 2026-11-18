# 10 — Innovation proposals and prior art (Gate 10)

> Native Inference Research Programme, 2026-11-18. Prior-art searches were done on the web on
> 2026-11-18. References continue the numbering of
> `docs/research/neuro-engine/NEURO_LITERATURE_REVIEW.md` (1–86) as **R87–R176** (§5); the full research
> notes are summarised here.
>
> **Labels:** UNVERIFIED = not confirmed from a primary page. DERIVED = computed from published configs.
>
> **Patents:** this is not a professional search. Google Patents returned HTTP 503 after three queries,
> so patent coverage is **partial**. No legal conclusions are drawn.

## 1. Six candidate architectures

Each is a different answer to "what should run natively on heqk". Scores (1–5) are judgements
grounded in `00`–`07`; the weighted ranking is in `13`.

| # | Architecture | What it is | Novelty vs prior art (§2) | CM5 / heqk feasibility | RAM | CPU | Latency | Security | Maintainability | Future HW |
|---|---|---|---|---|---|---|---|---|---|---|
| A1 | **Native ternary inference engine** | Rust no_std engine; BitNet-class models trained ternary; bit-plane LUT kernels (`01` §4) | low — bitnet.cpp TL1/TL2, T-MAC exist; the no_std port and the LUT layout tuned for A76 are engineering | 2 — needs NEON, large mappings, load path (`12`) | 0.9–1 GiB for 2B | compute-bound: ~2–4 cores to saturate the bus | ~5–13 tok/s ceiling | good (no FP, read-only weights) | medium | good (any SIMD ISA) |
| A2 | **Recurrent security intelligence engine** | per-device temporal models over the detection/flow/DNS stream: statistical DNA (done) → tiny learned recurrent cell (int8) → optional RWKV-7 for language | medium — Tiresias, DÏoT, Kitsune, OWAD cover parts; **a persistent per-device recurrent state on an ARM gateway with measured cost was not found** | **4** — the integer tier fits a 4 MiB EL0 server today | KiB per device | µs per event | per event, not per token | good (no generation, bounded) | high | excellent |
| A3 | **Model-to-AArch64 compiler with static execution plans (HNX)** | offline compiler emits target-packed weights, plan of signed kernel ids, memory plan, resource manifest (`06`) | medium — ExecuTorch `.pte`, TinyEngine, ACETONE, X-CUBE-AI cover AOT + static memory; **OS admission from a signed manifest not found** | 3 — the plan format works for any size; large models need `12` | arena ≪ weights | — | removes load-time work | **strong** (no code in packages, admission before load) | high once built | excellent (one source, many targets) |
| A4 | **Kernel-aware adaptive inference scheduler** | leases (CPU, bandwidth, memory) granted by heqk; engine paces decode from known bytes/token; data-plane pressure preempts | low-to-medium — MemGuard, RT-Gang, Honeywell US 12,327,136, Intel MBA patents, Sereno | 2 — no SMP, scheduler, PMU or pressure signal yet (`00`) | — | protects the DP | slower AI under load, by design | **strong** (packet path first) | medium | good (MPAM where present) |
| A5 | **Distributed behavioural intelligence mesh** | signed behavioural deltas and validated patterns shared between nodes; optional remote inference | low — FL-IDS (DÏoT is federated), threat-intel sharing (STIX/TAXII, MISP) | 3 — needs only the existing secure channel | small | small | network-bound | risk: poisoning across nodes; needs signing and quorum | medium | excellent |
| A6 | **Hybrid: integer core + temporal specialists + HNX-packaged, leased, evidence-closed language tier** | A2 + A3 + A4, with A1 as the language tier's format option and A5 later | combination (see §3) | **staged** — tier 1 today, tiers 2–3 behind `12` | per SKU (`07`) | per tier | per tier | strongest | medium | excellent |

## 2. Prior art by building block

| Building block | Closest prior art | What remains open |
|---|---|---|
| Ternary CPU inference | bitnet.cpp (I2_S, TL1, TL2) [lit. review], T-MAC (EuroSys 2025), BitNet b1.58 2B4T; Falcon-E / Falcon3-1.58 (Falcon licence, weak quality) [R107][R108]; Bi-Mamba 1-bit SSM [R109]; Ternary Mamba QAT (2026) [R110] | **no ternary RWKV found**; no no_std/heqk implementation; A76-specific LUT layout (`01`, `02`) |
| Recurrent LMs on CPU | RWKV-7 "Goose" (Apache-2.0, 0.19–2.9B; state 64·D per layer, DERIVED 6.2 MiB at 0.4B) [R87][R88]; Mamba-2 (Apache-2.0; ~8× RWKV-7's state at 1.3B, DERIVED) [R91] | no A76 or CM5 measurement of any recurrent LM |
| Per-device behaviour modelling | Kitsune (NDSS 2018); **DÏoT** (ICDCS 2019, per-device-type, federated, 95.6% Mirai) [R111]; IoT Sentinel [R112]; **Tiresias** (CCS 2018, RNN over per-machine event sequences) [R114]; **OWAD** (NDSS 2023, normality shift: detect → explain → adapt) [R129]; CADE [R128] | **a persistent per-device recurrent state, updated on a gateway SoC from a detection/DNS/flow stream, with measured cost — not found** |
| Learned traffic classifiers | ET-BERT, YaTC, NetGPT, netFound, NetMamba [R116–R123] | **largely invalidated**: SIGCOMM 2025 "Sweet Danger of Sugar" — under per-flow splits a shallow baseline beats them; a random-init ET-BERT matches the pre-trained one [R120][R121]. Do not build on these results. |
| Evaluation hygiene | Sommer & Paxson 2010 [R130]; **Arp et al., USENIX Sec 2022** (10 pitfalls) [R131]; CICIDS2017 label errors [R132] | HookProbe's E-SC2/E-BM2 already split by scenario; next: temporal splits, realistic base rates, own captures |
| OS co-designed ML | KML [R133], LinnOS [R134], LAKE [R135]; eBPF int8 NN IPS [R136][R137]; N3IC [R138]; **KataOS/Cantrip on seL4** (Rust, capability-isolated ML apps; archived 2024) [R139][R140]; Apple compiled `.mlmodelc` + OS-owned model with version-locked adapters [R149][R150]; TinyEngine/MCUNet [R152]; ACETONE (WCET-predictable NN code) [R145] | **no system combines a signed model package whose manifest a capability microkernel admits and enforces (memory, bandwidth, CPU) beside a packet data plane** |
| Bandwidth regulation for co-running ML | MemGuard, PALLOC [R142]; RT-Gang (DNN case study) [R143]; Biondi RTAS 2026 [R144]; Arm MPAM in Linux 6.19 [R146]; **Honeywell US 12,327,136 B2** (AI-coprocessor DDR quotas per window, issued 2025-06-10) [R147]; Intel US 11,726,910 B2 and MBA family [R157][R158] | pacing **LLM decode from known bytes/token** to protect a packet path — no patent found claiming that specifically; Honeywell '136 is the most likely citation against P4 |
| Per-device behaviour patents | Palo Alto/ZingBox US 11,888,718, US 12,244,479 (per-IoT-device LOF), US 12,255,906, US 12,289,328 [R161][R162]; Avast US 11,477,202 [R163]; Darktrace US 10,701,093, US 12,126,636 [R164]; Acronis US 2024/0323208 [R160]; Cisco US 10,220,167 | no patent found claiming a **recurrent hidden state kept per device**; absence not confirmed (search incomplete) |
| Signed model packages | OpenSSF Model Signing (hash manifest), Modelstamp (arXiv 2609.01781), Apple adapter version-locking | **no patent or system found for a signed package carrying a resource manifest enforced by the OS**; needs a professional search (CPC G06F 21/51–57 with G06N 3/) |
| Vocabulary trimming | Ushio et al., Findings EMNLP 2023 (~half the vocab, same quality) [R165]; VocabTrim [R166]; FR-Spec ACL 2025 [R167]; Compact [R168]; VocabTailor [R169] | an EN/RO/security trim for a gateway model is application, not invention |
| **Grammar-driven sparse output projection** | engines checked (llama.cpp, vLLM, SGLang, XGrammar, Outlines, llguidance, MLC/WebLLM, TensorRT-LLM) all compute **full** logits, then mask [R170–R172]; shortlist methods (Shi & Knight ACL 2017; Learning-to-Screen) are approximations [R173][R174]; WO2023175089A1, WO2025179276A1 restrict *sampling* after full scoring [R175] | **not found anywhere: computing only the logits of grammar-allowed tokens.** Unlike shortlists it is *exact* (the softmax over the allowed set equals the masked softmax). Source code was not inspected, so "not found" ≠ "absent". |

## 3. What may be original (hypotheses, ranked by evidence of novelty)

| Rank | Candidate | Why it might be new | What would kill it |
|---|---|---|---|
| 1 | **Grammar-sparse logits (GSL)** — under evidence-closed decoding, compute logits only for grammar-allowed token ids; the allowed sets come precompiled in the HNX package | no engine, paper or patent found doing it; exact, not approximate; large effect on small models whose head is 25–40% of per-token bytes (`07`) | a source-level find in an engine; or measurement showing constrained positions are too few to matter (summary text is free) — **measure the share of constrained tokens per answer** (`11` E-N6) |
| 2 | **Admission-controlled model packages** — signed HNX manifest (memory, state, bytes/token, CPU features) checked by a capability microkernel before load, enforced by read-only mappings and leases | the four-axis combination was not found; components all exist (ExecuTorch planning, TinyEngine codegen, KataOS isolation, Apple version-locking, MemGuard budgets) | a professional patent search; it is a **combination claim** at best |
| 3 | **Per-device recurrent security state on the gateway** — learned int8 recurrent cell per device, alongside the statistical DNA, fed by the detection stream, with owner-confirmed adaptation | Tiresias (server, per machine), DÏoT (per device *type*, federated), Kitsune (statistics) cover parts; the on-device per-device learned state with measured cost was not found | the learned cell must beat the statistical DNA by ≥ 0.02 AUC at equal bytes (E-BM2 kill criterion); prior art in a deeper search |
| 4 | **Decode pacing from known bytes per token** to protect a packet data plane | MemGuard/RT-Gang regulate by PMU counters; Honeywell '136 by transaction quotas; using the *model's own declared* bytes/token from its manifest is a narrower variant | Honeywell '136 claims; heqk has no PMU access today, which makes declared rates *more* useful, not less |
| 5 | **A76 bit-plane LUT ternary kernel with packed indices** | T-MAC/TL are the method; the specific layout is engineering | not a novelty candidate; listed because it is the fastest kernel measured here (`02`) |

Nothing above is claimed as novel. Each is a hypothesis for a prior-art search by counsel.

## 4. Rejected or deprioritised ideas (with reason)

| Idea | Reason |
|---|---|
| In-kernel inference (KML/LinnOS style) on heqk | the kernel image has 33 KB of headroom (`00` §3.8); a model in EL1 breaks the security boundary; HomePods owns the kernel |
| Pre-trained transformer traffic classifiers (ET-BERT, YaTC, NetGPT, netFound, NetMamba) | results do not survive leakage-free evaluation [R120][R121] |
| Small MoE on CM5 (OLMoE-1B-7B, Granite 1B-A400M) | RAM must hold every expert (~3.9 GB at Q4 for OLMoE); Granite 1B-A400M is at chance on MMLU [R101–R103]; storage-backed experts fail on heqk's eMMC (`07`) |
| LayerSkip / early exit with released checkpoints | the checkpoints are non-commercial [R105]; the method stays open for HookProbe-trained models |
| LFM2, xLSTM, RecurrentGemma, Falcon-E as base models | licences (US$10M cap, €100M cap + attribution, Gemma terms, Falcon licence) [R94][R96][R98][R107] |
| Wasm (wasmi) as the inference host | interpreter, no fuel, 256 KiB heap on CM5 (`00`) |

## 5. References added in this programme (R87–R176)

| Ref | Title / item, venue, date | URL |
|---|---|---|
| R87 | Peng et al., *RWKV-7 "Goose"*, arXiv 2503.14456, 2025-03-18 | https://arxiv.org/abs/2503.14456 |
| R88 | BlinkDL rwkv-7-world model card (Apache-2.0) | https://huggingface.co/BlinkDL/rwkv-7-world |
| R89 | BlinkDL rwkv7-g1 model card (date UNVERIFIED) | https://huggingface.co/BlinkDL/rwkv7-g1 |
| R90 | Peng et al., *Eagle and Finch*, arXiv 2404.05892, v4 2024-09-26 | https://arxiv.org/abs/2404.05892 |
| R91 | state-spaces mamba2-1.3b model card | https://huggingface.co/state-spaces/mamba2-1.3b |
| R92 | Beck et al., *xLSTM*, arXiv 2405.04517, 2024-05-07 | https://arxiv.org/abs/2405.04517 |
| R93 | Beck et al., *xLSTM 7B*, ICML 2025 | https://arxiv.org/abs/2503.13427 |
| R94 | NXAI Community License, 2024-12-12 | https://huggingface.co/NX-AI/xLSTM-7b/raw/main/LICENSE |
| R95 | Botev et al., *RecurrentGemma*, arXiv 2404.07839 | https://arxiv.org/abs/2404.07839 |
| R96 | recurrentgemma-2b model card | https://huggingface.co/google/recurrentgemma-2b |
| R97 | LFM2-1.2B model card | https://huggingface.co/LiquidAI/LFM2-1.2B |
| R98 | LFM Open License v1.0 | https://huggingface.co/LiquidAI/LFM2-1.2B/raw/main/LICENSE |
| R99 | Qwen3.5 small series coverage (secondary), 2026-03-02 | https://huggingface.co/blog/mlabonne/qwen35 |
| R100 | Qwen3.5-0.8B config.json | https://huggingface.co/Qwen/Qwen3.5-0.8B/raw/main/config.json |
| R101 | Muennighoff et al., *OLMoE*, arXiv 2409.02060 | https://arxiv.org/abs/2409.02060 |
| R102 | OLMoE-1B-7B-0125-Instruct model card | https://huggingface.co/allenai/OLMoE-1B-7B-0125-Instruct |
| R103 | granite-3.1-1b-a400m-instruct model card, 2024-12-18 | https://huggingface.co/ibm-granite/granite-3.1-1b-a400m-instruct |
| R104 | Elhoushi et al., *LayerSkip*, ACL 2024 | https://arxiv.org/abs/2404.16710 |
| R105 | layerskip-llama3.2-1B model card (FAIR Noncommercial) | https://huggingface.co/facebook/layerskip-llama3.2-1B |
| R106 | Wang, Ma, Wei, *BitNet a4.8*, arXiv 2411.04965 | https://arxiv.org/abs/2411.04965 |
| R107 | Falcon-E-1B-Instruct model card | https://huggingface.co/tiiuae/Falcon-E-1B-Instruct |
| R108 | Falcon3 1.58-bit model card | https://huggingface.co/tiiuae/Falcon3-3B-Instruct-1.58bit |
| R109 | Tang et al., *Bi-Mamba*, TMLR 2025 | https://arxiv.org/abs/2411.11843 |
| R110 | *Ternary Mamba*, arXiv 2606.18114, 2026-06-16 | https://arxiv.org/abs/2606.18114 |
| R111 | Nguyen et al., *DÏoT*, ICDCS 2019 | https://arxiv.org/abs/1804.07474 |
| R112 | Miettinen et al., *IoT Sentinel*, ICDCS 2017 | DOI 10.1109/ICDCS.2017.283 |
| R113 | Ortiz, Crawford, Le, *DeviceMien*, IoTDI 2019 | https://dblp.uni-trier.de/rec/html/conf/iotdi/OrtizCL19 |
| R114 | Shen et al., *Tiresias*, CCS 2018 | https://arxiv.org/abs/1905.10328 |
| R115 | Kim et al., *LSTM-RNN classifier for intrusion detection*, PlatCon 2016 | (no primary URL) |
| R116 | Lin et al., *ET-BERT*, WWW 2022 | https://arxiv.org/abs/2202.06335 |
| R117 | Zhao et al., *YaTC*, AAAI 2023 | https://ojs.aaai.org/index.php/AAAI/article/view/25674 |
| R118 | Meng et al., *NetGPT*, arXiv 2304.09513 | https://arxiv.org/abs/2304.09513 |
| R119 | *netFound*, arXiv 2310.17025 | https://arxiv.org/abs/2310.17025 |
| R120 | Zhao et al., *The Sweet Danger of Sugar*, SIGCOMM 2025 | https://arxiv.org/abs/2507.16438 |
| R121 | *SoK: encrypted traffic classifiers*, arXiv 2503.20093 | https://arxiv.org/abs/2503.20093 |
| R122 | Wang et al., *NetMamba*, arXiv 2405.11449 | https://arxiv.org/abs/2405.11449 |
| R123 | *NetMamba+*, arXiv 2601.21792 | https://arxiv.org/abs/2601.21792 |
| R124 | Edge SSM IDS papers (Edge-Mamba, MeeDet, FedMamba-Guard), 2026 | https://www.mdpi.com/2079-9292/15/5/1017 |
| R125 | Diab et al., arXiv 2512.02272 | https://arxiv.org/abs/2512.02272 |
| R126 | *Realguard*, Sensors 2022 | https://mdpi.com/1424-8220/22/2/432 |
| R127 | Dong et al., *HorusEye*, USENIX Security 2023 | https://www.usenix.org/conference/usenixsecurity23/presentation/dong-yutao |
| R128 | Yang et al., *CADE*, USENIX Security 2021 | https://www.usenix.org/conference/usenixsecurity21/presentation/yang |
| R129 | Han et al., *OWAD*, NDSS 2023 | https://www.ndss-symposium.org/ndss-paper/anomaly-detection-in-the-open-world-normality-shift-detection-explanation-and-adaptation |
| R130 | Sommer & Paxson, *Outside the Closed World*, IEEE S&P 2010 | https://ieeexplore.ieee.org/document/5504793 |
| R131 | Arp et al., *Dos and Don'ts of ML in Computer Security*, USENIX Security 2022 | https://www.usenix.org/conference/usenixsecurity22/presentation/arp |
| R132 | Engelen, Rimmer, Joosen, *Troubleshooting CICIDS2017*, IEEE SPW 2021 | https://dblp.uni-trier.de/rec/conf/sp/EngelenRJ21.html |
| R133 | Akgun et al., *KML*, HotStorage 2021 / TOS 2023 | https://arxiv.org/abs/2111.11554 |
| R134 | Hao et al., *LinnOS*, OSDI 2020 | https://www.usenix.org/conference/osdi20/presentation/hao |
| R135 | Fingler et al., *LAKE*, ASPLOS 2023 | https://dspace.mit.edu/handle/1721.1/147824 |
| R136 | Hara & Sasabe, eBPF NN IDS, Computer Networks 2024 | DOI 10.1016/j.comnet.2024.110188 |
| R137 | Zhang et al., NN IPS in eBPF, DSN 2024 | https://dsn2024uq.github.io/Proceedings/pdfs/DSN2024-6rvE3SSpzFYmysif75Dkid/410500a416/410500a416.pdf |
| R138 | Siracusano et al., *N3IC*, NSDI 2022 | https://www.usenix.org/conference/nsdi22/presentation/siracusano |
| R139 | Google, *Announcing KataOS and Sparrow*, 2022-10 | https://opensource.googleblog.com/2022/10/announcing-kataos-and-sparrow.html |
| R140 | AmbiML sparrow-cantrip-full (archived 2024-01-04) | https://github.com/AmbiML/sparrow-cantrip-full |
| R141 | Leon, *The Dark Side of Unikernels for ML*, arXiv 2004.13081 | https://arxiv.org/abs/2004.13081 |
| R142 | Yun et al., *MemGuard* (RTAS 2013), *PALLOC* (RTAS 2014) | https://github.com/heechul/palloc |
| R143 | Ali & Yun, *RT-Gang*, RTAS 2019 | https://ittc.ku.edu/~heechul/papers/rtgang-rtas2019-camera.pdf |
| R144 | Biondi et al., RTAS 2026 | https://retis.santannapisa.it/~a.biondi/papers/RTAS26.pdf |
| R145 | Silva et al., *ACETONE*, ECRTS 2022 | https://drops.dagstuhl.de/entities/document/10.4230/LIPIcs.ECRTS.2022.3 |
| R146 | Arm MPAM in Linux 6.19 (arm64 pull request) | https://lkml.iu.edu/hypermail/linux/kernel/2512.0/03301.html |
| R147 | Honeywell, US 12,327,136 B2, issued 2025-06-10 | https://patents.google.com/patent/US12327136 |
| R148 | Mei et al., *AIOS*, arXiv 2403.16971 | https://arxiv.org/abs/2403.16971 |
| R149 | Apple, `MLModel.compileModel(at:)` documentation | https://developer.apple.com/documentation/coreml/mlmodel/compilemodel(at:)-6442s |
| R150 | Apple, *Foundation Language Models Tech Report 2025*, arXiv 2507.13575 | https://arxiv.org/abs/2507.13575 |
| R151 | Android NNAPI migration guide | https://developer.android.com/ndk/guides/neuralnetworks/migration-guide |
| R152 | Lin et al., *MCUNet*, NeurIPS 2020 | https://papers.nips.cc/paper/2020/hash/86c51678350f656dcc7f490a43946ee5-Abstract.html |
| R153 | Rotem et al., *Glow*, arXiv 1805.00907 | https://arxiv.org/abs/1805.00907 |
| R154 | NNoM | https://github.com/majianjia/nnom |
| R155 | ST X-CUBE-AI | https://www.st.com/en/embedded-software/x-cube-ai.html |
| R156 | US 2019/0332814 A1 | https://patents.google.com/patent/US20190332814A1/en |
| R157 | Intel, US 11,726,910 B2 | https://patents.google.com/patent/US11726910 |
| R158 | Intel MBA patents (US 12,160,368 B2; US 12,210,434 B2; US 2021/0258265 A1) | https://patents.google.com/patent/US12160368B2 |
| R159 | US 12,681,760 (assignee UNVERIFIED) | https://image-ppubs.uspto.gov/dirsearch-public/print/downloadPdf/12681760 |
| R160 | US 2024/0323208 A1 (catalogue record) | https://vufind-test.katalog.k.utb.cz/SummonRecord/FETCH-epo_espacenet_US2024323208A13 |
| R161 | Palo Alto Networks / ZingBox patents | https://patents.google.com/patent/US12289328 |
| R162 | US 12,255,906 B2 | https://patents.google.com/patent/US12255906 |
| R163 | Avast, US 11,477,202 B2 | https://patents.google.com/patent/US11477202 |
| R164 | Darktrace patents | https://patents.justia.com/assignee/darktrace-holdings-limited |
| R165 | Ushio, Zhou, Camacho-Collados, vocabulary trimming, Findings EMNLP 2023 | https://aclanthology.org/2023.findings-emnlp.981 |
| R166 | *VocabTrim*, arXiv 2506.22694 | https://arxiv.org/abs/2506.22694 |
| R167 | Zhao et al., *FR-Spec*, ACL 2025 | https://aclanthology.org/2025.acl-long.198 |
| R168 | *Compact*, arXiv 2509.06836 | https://arxiv.org/abs/2509.06836 |
| R169 | *VocabTailor*, arXiv 2508.15229 | https://arxiv.org/abs/2508.15229 |
| R170 | NVIDIA TensorRT-LLM, guided + speculative decoding blog | https://nvidia.github.io/TensorRT-LLM/latest/blogs/tech_blog/blog12_Combining_Guided_Decoding_and_Speculative_Decoding.html |
| R171 | Dong et al., *XGrammar*, arXiv 2411.15100 | https://arxiv.org/abs/2411.15100 |
| R172 | Sun et al., *Earley-driven dynamic pruning*, ICML 2025 | https://arxiv.org/abs/2506.01151 |
| R173 | Shi & Knight, ACL 2017 | https://aclanthology.org/P17-2091/ |
| R174 | *Learning to Screen*, arXiv 1810.12406 | https://arxiv.org/abs/1810.12406 |
| R175 | WO2023175089A1; WO2025179276A1 | https://patents.google.com/patent/WO2023175089A1/en |
| R176 | *GRID*, arXiv 2607.11951 | https://www.alphaxiv.org/abs/2607.11951 |
