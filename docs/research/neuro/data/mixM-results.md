# Doc 44 result: ftM (investigation adapter v2) on the sealed inv-blind v3: PASS (2026-11-24)

One look, as pre-registered in `44_INVESTIGATION_ADAPTER_V2_PREREGISTRATION.md`. inv-blind v3 SHA-256 `7e616bda…`
was re-checked by the run before any model saw it.

| model | next+multi (80) | alert (25) | decoy exact (25) | invisible (15) | unreturned CVE raw | invented T-id raw | service w/o port | policy on decoy | tool calls |
|---|---|---|---|---|---|---|---|---|---|
| base17g | 0.138 | 0.080 | 0.640 | 1.000 | 0 | 0 | 12 | 0 | 88 |
| ftLg (incumbent) | 0.525 | 0.400 | 0.040 | 0.267 | 0 | 0 | 0 | 0 | 135 |
| **ftMg** | **0.512** | **0.680** | **0.760** | **1.000** | 0 | 0 | 0 | 0 | 105 |

| # | Condition | Result |
|---|---|---|
| 1 | alert ≥ 0.60 and > ftL | 0.680 vs 0.400 ✅ |
| 2 | decoy exact ≥ 0.60 and > ftL | 0.760 vs 0.040 ✅ |
| 3 | invisible ≥ 0.80 | 1.000 ✅ |
| 4 | next+multi ≥ ftL − 0.05 | 0.512 ≥ 0.475 ✅ (McNemar p = 1, 7 vs 8: no difference) |
| 5 | grounding / policy | 0 / 0 / 0 ✅ |

**Verdict: PASS.** ftM replaces ftL as the investigation adapter.

## End to end (operator rule): run 7 on the attack fixture

| Alert | ftL (run 6) | ftM (run 7) | Pre-registered expectation |
|---|---|---|---|
| Telnet scan (L1 alert) | `query_dns` H1 | `query_flows` H1 | `query_flows` on the camera ✅ |
| SSH brute force (L1 alert) | `query_dns` H1 | `lookup_reputation` R1 | `lookup_reputation` on R1 ✅ |

- 0.38 s per investigation turn, the same as ftL.
- Grounding clean; guard G edited neither answer.
- The triage stage (ftFg + A/E/G) gave the same results as run 6: 22/22 schema, 19/22 citations, 0 fallbacks.

## What ftM did not fix, and what to watch

- **next+multi did not improve** (0.51 vs 0.53, not significant). ftM checks on alerts, stops on ordinary windows
  and declines the invisible, but it is no better at the ordinary next step.
- **Validation loss spiked at step 100** (0.482 → 2.248), then fell to 0.029. The pre-registered rule took the
  lowest valid loss, the final checkpoint (428).
- **Small subsets** (alert 25, decoy 25, invisible 15) and a synthetic E2E fixture with two turns. The rows are rates;
  the E2E row is an observation.
- **Second annotator 44/44**, partly because gold accepts more than one answer (doc 44 §7).

## Reproduce / artefacts

| Artefact | SHA-256 |
|---|---|
| `gguf-mixM-q8_0.gguf` (ftMg) | `9576cfacef5ad23728e171f157321aedf8ab12c4aba926f89fd0527d5d23dcc9` |
| `ft/adapters.safetensors` (checkpoint 428) | `5cc933ba6222729d0a78b420cb41548877accce577282f10d8815fc4c851548b` |

```bash
bash tools/neuro-research/mixM_chain.sh "$PWD/tools/neuro-research"
```

```bash
INV_GGUF=<ftMg> bash tools/neuro-research/e2e_neuro.sh <out> <ftFg> <llama-server> <python> <attack pcap>
```
