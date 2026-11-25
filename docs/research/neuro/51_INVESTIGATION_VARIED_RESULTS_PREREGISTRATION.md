# 51: Investigation adapter v4: varied tool results, unchanged first-check data (pre-registration, 2026-11-25)

Written **before** inv-blind v5, the new training rows or the candidate exists. Doc 50 is reserved for doc 48's
`dev=` follow-up after the kernel soak.

## 1. What doc 49 measured

[`data/mixR-results.md`](data/mixR-results.md), inv-blind v4 (spent):

| | next (45) | multi (35) | next+multi |
|---|---|---|---|
| ftM | 0.556 | 0.114 | 0.362 |
| ftR (doc 49) | 0.400 | 0.229 | 0.325 |

Restoring the multi-step targets doubled multi but cost the first check. In E2E run 11 ftR made no call on either real
alert.

**Two causes this doc removes:**
1. **ftR's first-check data changed.** Generator v5 draws a new case stream, so the `next`, `alert`, `decoy` and
   `invisible` examples differed from ftM's.
2. **The RESULT lines are four fixed phrases,** one per (tool, supports/clears). A model can key on the exact phrase
   instead of its meaning, and the hand-written blind sets word results differently.

## 2. Changes

- **Generator v6** (`gen_investigate.py --version 6`) is v5 with varied RESULT wording: 6 phrasings per tool and
  outcome for the three lookup tools, 4 for `lookup_exposure`, the same meaning each time. `--kinds` writes only
  chosen kinds.
  - `--version 4` and `--version 5` are byte-identical to before. v4 still equals ftM's training cases.
  - On seed 5101 (600 multi/clears cases) it gives 38 distinct RESULT texts; the multi golds are 206 policy proposals
    and 162 move-on checks; 232 are clears.
- **Training rows:**
  - **ftM's own rows without a RESULT line**, byte for byte: 595 train and 32 valid, from `mixM/data`. The chain pins
    their SHA-256 (`2ef27e1c…`, `4dfc0187…`) and filters them by script. The first-check data is therefore exactly
    what ftM learned.
  - **Plus 600 gen v6 multi/clears cases** (seed 5101, `build_inv_sft --seed 51`). They replace ftM's 260
    result-following rows.
- **ftS** = ftM's adapter (`5cc933ba…`) continued for **1 epoch at 5e-5**, as doc 49. Checkpoints every 50 steps;
  lowest validation loss is selected. The chain first checks that ftM's adapter re-exports to ftMg's 310 tensors.

## 3. inv-blind v5

- **Brief:** `data/inv-brief-v5.md`, SHA-256 `cd6cceecac8de6a3f532fdcb93122b3380e0c583a88dce162d4b8bd3789ca78f`. It is
  v4's brief, unchanged except for the title.
- **Mix:** 175 cases, as v3 and v4.
- **People:** a new isolated author and a new isolated annotator (44-case sample). The author adjudicates any
  disagreement.
- **Seal:** collisions are checked against inv-blind v1–v4 and the v4, v5 and v6 generator case files. The SHA-256 is
  pushed here before any model sees the set.

## 4. Gate (`mixS_gate.py`, one look, ftSg against the incumbent ftMg)

| # | Condition |
|---|---|
| 1 | `multi` (35) > ftMg's **and** next+multi (80) > ftMg's |
| 2 | `next` (45) ≥ ftMg's − 0.05 |
| 3 | `alert` (25) ≥ ftMg's − 0.05 |
| 4 | `decoy` (25) ≥ ftMg's − 0.05 |
| 5 | `invisible` (15) ≥ 0.80 |
| 6 | 0 unreturned CVE ids; invented technique ids ≤ 2%; no policy proposal on a decoy |

**Change from doc 49, stated now:**
- The absolute 0.60 floor is gone. On inv-blind v4 neither model came near it, because a harder hand-written set moved
  every row. The gate now asks for improvement over ftM on what this doc targets.
- It also asks that the first check does not slip (condition 2), which is doc 49's failure.

**Pass:** ftS replaces ftM. `inv_contract.json` is unchanged; the Conductor gets the new GGUF and regenerates its
vectors, with notice first. **Fail:** ftM stays.

**E2E (operator rule), whatever the verdict:** the attack fixture is re-run with ftFg for triage and ftSg for
investigation. Expected, as in doc 44: `query_flows` on the camera for the scan, `lookup_reputation` on R1 for the
SSH brute force. Reported, not gated.

## 5. Pinned

| File | SHA-256 |
|---|---|
| `gen_investigate.py` (v6) | `707e3fa9c9208e5434ba7d976d7093e640948064d8cf73b49e86c9068f0354b7` |
| `mixS_chain.sh` | `50f08373fa15f6a5457e8f065ab5d06242b17c004a0b2f1469e2d9b7aa28e55a` |
| `mixS_gate.py` | `742831777751d238078d5b00a8ce7508b72539b75c39737916e9d522f2e538fb` |
| `data/inv-brief-v5.md` | `cd6cceecac8de6a3f532fdcb93122b3380e0c583a88dce162d4b8bd3789ca78f` |
| `build_inv_sft.py`, `inv_eval.py`, `inv_seal.py`, `export_gguf.sh`, `gguf_to_hf.py` | as doc 49 §5 / doc 46 §6 |

**Dry runs** (mechanics only):
- `mixS_gate.py` on doc 49's spent inv-blind v4 outputs (ftR in the candidate slot) fails conditions 1 and 2, as it
  should.
- The chain's row filter keeps exactly 595 + 32 of ftM's rows (checked on a stub).
- v4 and v5 outputs are unchanged.

## 6. Limits

- Varied wording is still synthetic: 38 phrasings, not real tool output.
- Multi is 35 cases. A doubling from about 0.11 is about 4 cases, so the gate detects only clear changes.
- Clears (30) are not gated. They use v6 wording in training and are reported in the table as usual.

## 7. Seal (2026-11-25, before any model has seen the set)

- `blind_cases.jsonl` SHA-256 **`1e5439e9dee83fe9adc0918e710892e934d5ed3709705fae6a1de9692532b9c7`**.
- **Mix:** next 45, multi 35, clears 30, decoy 25, invisible 15, alert 25 (175 cases); 21 Romanian (12.0%).
- **Seal checks: PASS.** 0 collisions with inv-blind v1–v4 and the v4, v5 and v6 generator case files.
- **Second annotator** (isolated, 44-case sample): **44/44**, so nothing needed adjudication. It flagged 10 cases as
  genuinely ambiguous.
