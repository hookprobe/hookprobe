# 44: Investigation adapter v2 (ftM): read the L1-alert card, stop on decoys, say "cannot see" (pre-registration, 2026-11-24)

Written after doc 43's PASS (ftL) and E2E run 6, and **before** inv-blind v3, the v4 training cases or ftM exist.

## 1. What is wrong with ftL

| Weakness | Evidence |
|---|---|
| **Reads the device's real alert poorly.** On the E2E attack fixture, both S1 alerts (a Telnet scan; SSH brute force) arrive as the device's generic `det=behaviour_change[-,sev2,alert, l1]`. ftL asked `query_dns` on the camera for both; the playbooks call for the device's flows (scan) and the remote's reputation (brute force) | `data/e2e-attack-2026-11-24.md`, stage F |
| **Looks things up on ordinary windows.** Exact "no tool" on decoys was 0.240, the same as base. It passed only because "stop" accepted read-only lookups | doc 43 result |
| **Tries to look up the invisible.** 0.400 against base's 1.000 | doc 43 result |

**Diagnosis.** The training cases never had the L1-alert card shape (no category, no technique), so ftL fell back to a
generic lookup. Decoy and invisible cases were 19% and 7% of the data, and invisible targets accepted a flow query.

## 2. Data and training for ftM (fixed now)

- **Generator v4** (`gen_investigate.py --version 4`): 900 cases, seed 44.
  - **New `alert` kind** in the exact L1-alert card format the E2E harness renders. The card's **shape** decides
    the check:
    - fan-out with failures (scan) → `query_flows` on the device;
    - one remote with repeated SSH/Telnet/RDP attempts, a periodic beacon, or a large upload →
      `lookup_reputation` on the remote;
    - many remotes in many countries (proxying) → `query_flows` on the device.
  - **More decoy and invisible cases:** about 18% decoy and 10% invisible, against 17% and 7% in v3.
  - **Invisible gold = no tool only.**
  - On a 900-case sample, the alert cases cover all 5 shapes (25–40 each). There are 0 undefined aliases and
    0 gold entities missing.
  - v1, v2 and v3 still regenerate **byte for byte**, checked against `main`'s generator.
- **Targets:** `build_inv_sft.py`, unchanged (no teacher).
- **Recipe:** as doc 43. Doc 26's settings on **base** Qwen3-1.7B @ `70d244cc`, investigation rows only, 2 epochs;
  validation and checkpoints every 50 steps; lowest valid loss. Exported as **ftMg**.

**Toolchain.** The session scratchpad was lost on 2026-11-24, so the toolchain was rebuilt under
`~/.cache/hookprobe-neuro` at the pinned versions: llama.cpp `b12477`; mlx 0.32.4, mlx-lm 0.32.2, mlx-metal 0.32.4,
transformers 5.23.0; converter with torch 2.15.0 and transformers 4.57.6.
- **Reproduction check:** re-exporting the base model gives a Q8_0 GGUF whose 311 tensors are byte-identical to
  the original `base17-q8_0.gguf`. Only `general.name`, taken from the output folder, differs.
- A 5-iteration training smoke run on v4 data trains, as before, 1.013% of parameters.

## 3. inv-blind v3 (fresh; v1 and v2 are spent)

- **Brief:** `inv-brief-v3.md` (SHA-256 `3748d8288cd71c42e9d4b0832cafc56f67f077ab827ef54adedb8070545034da`). It is
  the doc 41 brief with one addition: **25 `alert` cases** carrying the exact generic alert. The analyst reads the
  card's shape to choose the check, and gold never accepts `null` or a policy. 175 cases, about 12% Romanian.
- **People:** a new isolated author and a new isolated annotator (44-case stratified sample); the author
  adjudicates.
- **Seal checks:** `INV_SET=v3 inv_seal.py check` against every earlier set, inv-blind v1 and v2, and every
  generator output. The SHA-256 is pushed here before any model sees it.

## 4. Gate (`mixM_gate.py`; one look; ftMg against the incumbent ftLg, base17g reported)

| # | Condition |
|---|---|
| 1 | `alert` (25): step ≥ 0.60 **and** > ftLg's |
| 2 | `decoy` exact no-tool (25): ≥ 0.60 **and** > ftLg's |
| 3 | `invisible` (15): step ≥ 0.80 |
| 4 | non-inferiority on next + multi (80): ≥ ftLg's − 0.05 |
| 5 | 0 raw unreturned CVE ids; raw invented technique ids ≤ 2%; no policy proposal on a decoy |

**Pass:** ftM replaces ftL as the investigation adapter. **Fail:** ftL stays.

**E2E (operator rule):** stage F re-runs on the attack fixture with ftM, whatever the verdict. The expectation is
written now: `query_flows` on the camera for the scan alert, and `lookup_reputation` on R1 for the brute-force
alert. This is reported, not gated (two turns).

**Dry run** (mechanics only, on spent inv-blind v1, which has no alert cases): ftFg stands in for ftL and base for
ftM. The script reads every row and fails 1 and 2 as it should.

## 5. Pinned

| File | SHA-256 |
|---|---|
| `gen_investigate.py` (v4) | `cf4d2b94875767ffe798109134f7adf66592c980930d49e5dacb0c7161bacd0f` |
| `build_inv_sft.py` | `473ce09d70938e83c897e1f515c50b9269de901ead2bd6f5dbc0a05dc9aab776` |
| `inv_eval.py` | `342192c374f9480361478ff8197b6430afb58e48d99152ba5adb5b9fbbfa57e2` |
| `inv_seal.py` (v3 mix) | `7720e76972ba55935b1b49e40fc062cd2243bb77fce13812d8ff33ee1a68d721` |
| `eval/grounding.py` | `ba38fbabe0a051c22f48a66630472374f8d32ff3da5479927b136eb703b08d87` |
| `export_gguf.sh` | `cb538f58290cc33ce7de9672dae6b9ff2de2c79c4d33449092c86fb9727fc8ab` |
| `mixM_gate.py` | `072a390c72a7d941a29aea5a53cb306f8cbe14d6499b600fd3c30021f776da21` |
| `mixM_chain.sh` | `066f2ef7f31ac78a79ccd0acff077eeb0321e941468fccf178145a8641a4fd97` |
| `inv-brief-v3.md` | `3748d8288cd71c42e9d4b0832cafc56f67f077ab827ef54adedb8070545034da` |

## 6. Limits, stated now

1. **The alert shape rules are ours.** They encode the playbooks' first steps. The isolated blind author, reading
   the same alert format cold, is the check that the rules are what an analyst would do.
2. **A small alert subset** (25 cases). Condition 1 is a bar plus a point comparison, not a significance test.
3. **Still synthetic training cards.** Template risk as in docs 38 and 43.

## 7. Seal (2026-11-24, before any model has seen the set)

- `blind_cases.jsonl` SHA-256 **`7e616bda2ce1e9ac3665f4c55071882f57e5d7b32d41bdce62730f15261f3de2`**.
- **Mix:** next 45, multi 35, clears 30, decoy 25, invisible 15, alert 25, so 175 cases; 21 are Romanian (12.0%).
  The author's validator passed. It also rejected 8 cases the author broke on purpose.
- **Collisions (normalised context hashes): 0** against all of these:
  - every earlier blind and dev set (blind v1–v7, dev v8, eval/cases);
  - inv-blind v1 and v2;
  - every E2E fixture (runs 1–6);
  - the generator outputs v1–v4, including ftM's own 900 training cases.

  ftL's own training cases were lost with the scratchpad, so they could not be checked; the regenerated v1–v3
  samples stand in for them. Any overlap there would favour the incumbent, not ftM.
- **Second annotator** (isolated, 44-case stratified sample, context only): **44/44 agreement**, so nothing
  needed adjudication. The annotator flagged 7 cards as ambiguous. Agreement is scored against gold, which may
  accept more than one answer; this is not a test of a single exact answer.
