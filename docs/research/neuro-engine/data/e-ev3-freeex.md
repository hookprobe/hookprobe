# E-EV3 — free mode with a plain-words contract + one fixed example answer (blind set, 175 triage+injection cases)

Dev host (Apple M5 Pro, Metal, llama.cpp b12477, --reasoning off, T=0). Closed and free (Phase 0) columns re-scored from data/runs-blind/; free+example outputs in data/runs-blind-freeex/. Design frozen on the 28 dev cases before the blind run (one blind run, no retuning).

gold verdict mix: {'malicious': 50, 'malicious|suspicious': 15, 'suspicious': 16, 'suspicious|benign': 14, 'suspicious|malicious': 11, 'insufficient_evidence': 6, 'insufficient_evidence|benign': 9, 'insufficient_evidence|suspicious': 5, 'benign': 35, 'benign|suspicious': 12, 'suspicious|insufficient_evidence': 1, 'benign|insufficient_evidence': 1}
| model | verdict closed | verdict free (Phase 0) | verdict free+example | McNemar closed vs free+ex (p) | canary safe closed / free / free+ex | halluc./case free+ex | schema ok free+ex | 'suspicious' share closed / free+ex |
|---|---|---|---|---|---|---|---|---|
| Qwen3-0.6B-Q4_0 | 0.377 | 0.309 | 0.354 | 0.738 (closed-only 42, free+ex-only 38) | 1.00 / 0.76 / 0.80 | 0.01 | 0.93 | 0.00 / 0.63 |
| Qwen3-1.7B-Q4_0 | 0.371 | 0.400 | 0.411 | 0.230 (closed-only 9, free+ex-only 16) | 0.92 / 0.60 / 0.80 | 0.10 | 0.98 | 0.43 / 0.37 |
| Qwen3.5-0.8B-Q4_0 | 0.440 | 0.000 | 0.423 | 0.836 (closed-only 48, free+ex-only 45) | 0.96 / 0.84 / 0.88 | 0.03 | 0.90 | 0.03 / 0.93 |
| Qwen3.5-2B-Q4_0 | 0.474 | 0.240 | 0.440 | 0.286 (closed-only 14, free+ex-only 8) | 1.00 / 0.80 / 0.96 | 0.01 | 0.98 | 0.80 / 0.97 |
| granite-4.0-h-1b-Q4_0 | 0.497 | 0.331 | 0.434 | 0.117 (closed-only 26, free+ex-only 15) | 0.92 / 0.80 / 0.92 | 0.04 | 0.98 | 0.45 / 0.71 |
| granite-4.0-h-350m-Q4_0 | 0.246 | 0.194 | 0.126 | 0.006 (closed-only 38, free+ex-only 17) | 0.92 / 0.96 / 0.96 | 0.01 | 0.01 | 0.31 / 0.33 |

Constant-answer baselines on the same 175 cases (accepted verdicts from gold): always 'suspicious' = 74/175 = 0.42; always 'malicious' = 76/175 = 0.43; always 'benign' = 71/175 = 0.41. L0 template = 0.594.
