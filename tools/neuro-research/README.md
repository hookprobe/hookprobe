# tools/neuro-research — Neuro Engine Research Gate 001 harness

Non-invasive research scripts for `docs/research/neuro-engine/`. Python 3.9+, **standard library
only**, run with `python3 -I`. Nothing here downloads a model, touches a device, or runs on heqk.
Results are labelled by origin: `theoretical`, `simulated` (synthetic data on a development host),
`cm5-linux` (bench unit running Raspberry Pi OS), `cm5-heqk`.

| File | Experiment | Label | Runs where |
|---|---|---|---|
| `synth_events.py` | seeded synthetic telemetry in heqk's detection-row shape (`mcstate.rs::det_row`, `rulecat.rs`) + ground truth | simulated | anywhere |
| `semantic_compression.py` | E-SC1: RAW vs detections vs top-K vs evidence cards at token budgets; identity/evidence recall | simulated | anywhere; real token counts if `NEURO_LLAMA_TOKENIZE` (llama.cpp `llama-tokenize`) and `NEURO_VOCAB` (a vocab-only GGUF from llama.cpp's `models/`) are set |
| `behavioural_memory.py` | E-BM1: "Neural DNA" fixed-size per-device state, guarded updates, drift vs poisoning | simulated | anywhere |
| `roofline.py` | E-RF1: decode/prefill bounds, KV vs recurrent state, bandwidth-budgeted decoding, storage tier, cold activation | theoretical | anywhere |
| `decision_matrix.py` | Gate 6 weighted scoring + sensitivity / Monte Carlo | — | anywhere |
| `eval/cases.jsonl` | 28 HookProbe cases, EN + RO: triage, false positives, insufficient evidence, correlation, prompt injection in telemetry, copilot, tool choice | — | — |
| `eval/run_eval.py` | eval runner: `template` (Level-0, no model) or `openai` (any OpenAI-compatible endpoint); `--mode closed` = evidence-closed decoding | simulated / cm5-linux | anywhere |
| `cm5_bench.sh` | Gate-5 measurement plan for a CM5 **bench unit** on Raspberry Pi OS (bandwidth, storage, llama-bench sweep, server profile, interference, thermal soak). **Prepared, not run.** | cm5-linux | a lab CM5 only |

```bash
python3 -I semantic_compression.py --seeds 1,2,3 --show-cards 512
python3 -I behavioural_memory.py --seeds 1,2,3
python3 -I roofline.py
python3 -I eval/run_eval.py --backend template
python3 -I decision_matrix.py
```

Known limits: the synthetic generator and the mechanisms were written by the same author (circular
validation risk — see E-SC2/E-BM2/E-EV1 in `NEURO_EXPERIMENT_DESIGN.md`); `cm5_bench.sh` was
syntax-checked (`bash -n`) but not shellchecked or run on hardware.
