# 49: Investigation adapter v3: restore the multi-step targets (pre-registration, 2026-11-25)

Written **before** inv-blind v4, the new training data or the candidate exists. (Doc 48's `dev=` follow-up, if it
goes ahead after the kernel soak, becomes doc 50.)

## 1. The gap, and its cause

On inv-blind v3 (doc 44, spent), ftM got the next step right 0.733 of the time (45 cases) but the step after a
returned result only **0.257** (35 cases). Doc 44 reported only the two combined (0.512). Of ftM's 33 wrong tools on
next+multi, 14 had gold `propose_policy_change`. In those cases, once the evidence is in, ftM looks something up
again or stops.

**Cause: a generator regression, not the model.** Doc 43 fixed the multi-step targets in `gen_investigate.py`. After
a supporting result the next check is a *different* tool, and once two results support it, the step is a policy
proposal. The fix sat behind `if a.version == 3`. Doc 44's `--version 4` fell through to doc 42's branch, so ftM's
900 training cases contain:
- **0** policy proposals;
- **0** `lookup_exposure` calls;
- multi-step targets that repeat a lookup.

## 2. Changes

- **Generator v5** (`gen_investigate.py --version 5`): v4's mix with doc 43's multi-step branch. On seed 4901 it gives
  86 policy proposals, 5 `lookup_exposure` and 68 move-on lookups among 159 multi cases.
  - `--version 4` is unchanged: it reproduces ftM's 900 training cases byte for byte, checked before and after the
    edit.
- **ftR** = ftM's own LoRA adapter (SHA-256 `5cc933ba…`) trained further (`--resume-adapter-file`) on 900 v5 cases
  (seed 4901), for **1 epoch at learning rate 5e-5**. Otherwise doc 44's settings: rank 16, scale 20, batch 4,
  checkpoints every 50 steps, lowest validation loss. The gold is the target, deterministically; no teacher is
  used.
  - The chain first checks that ftM's adapter re-exports to ftMg (`9576cfac…`) exactly.

## 3. inv-blind v4

- **Brief:** `data/inv-brief-v4.md`, SHA-256 `a6dbadde9d98ee071ceadfb071bdaa0792292324797fa923726662de8f461b20`. It is
  inv-blind v3's brief (`3748d828…`), unchanged except for the title.
- **Mix:** next 45, multi 35, clears 30, decoy 25, invisible 15, alert 25 (175 cases).
- **People:** a new isolated author, and a new isolated second annotator on the 44-case sample (`inv_seal.py`).
- **Seal:** `INV_SET=v3 inv_seal.py check` against inv-blind v1–v3 and both generator case files (v4 and v5). The
  SHA-256 is pushed here before any model sees the set.

## 4. Gate (`mixR_gate.py`, one look, ftRg against the incumbent ftMg)

| # | Condition |
|---|---|
| 1 | step_ok on next+multi (80) ≥ 0.60 **and** > ftMg's |
| 2 | `alert` (25) ≥ ftMg's − 0.05 |
| 3 | `decoy` (exact: no tool, 25) ≥ ftMg's − 0.05 |
| 4 | `invisible` (15) ≥ 0.80 |
| 5 | 0 raw answers with an unreturned CVE id; raw invented technique ids ≤ 2%; no policy proposal on a decoy |

Reported, not gated: base17g; next and multi separately; McNemar ftRg vs ftMg on next+multi; services named without
their port.

**Pass:** ftR replaces ftM as the investigation adapter. The request contract (`inv_contract.json`) is unchanged,
because the tools and prompt are the same. The Conductor gets the new GGUF, and its fidelity vectors are
regenerated, with notice first. **Fail:** ftM stays.

**E2E (operator rule), whatever the verdict:** the attack fixture is re-run with ftFg for triage and ftRg for
investigation. The expected first checks are the same as doc 44's run 7: `query_flows` on the camera for the scan
and `lookup_reputation` on R1 for the SSH brute force. Reported, not gated.

## 5. Pinned

| File | SHA-256 |
|---|---|
| `gen_investigate.py` (v5) | `3b34f92c4e76797196ec96d41dc93b4a6d71bd5b0d501bb5da63025d4f14acfb` |
| `mixR_chain.sh` | `eebf35bbf4d98950d8b126f697e05339db64c9a1b4bab4af4012b03a7a293f1f` (replaced by §7) |
| `mixR_gate.py` | `c620b9fd5007dbafa099abc58ba133717159be6818fdb5a5a9425391f5a8dec3` |
| `build_inv_sft.py` | `473ce09d70938e83c897e1f515c50b9269de901ead2bd6f5dbc0a05dc9aab776` |
| `inv_eval.py` | `342192c374f9480361478ff8197b6430afb58e48d99152ba5adb5b9fbbfa57e2` |
| `inv_seal.py` | `7720e76972ba55935b1b49e40fc062cd2243bb77fce13812d8ff33ee1a68d721` |
| `export_gguf.sh` | `cb538f58290cc33ce7de9672dae6b9ff2de2c79c4d33449092c86fb9727fc8ab` |
| `data/inv-brief-v4.md` | `a6dbadde9d98ee071ceadfb071bdaa0792292324797fa923726662de8f461b20` |

**Dry run** (mechanics only): `mixR_gate.py` on doc 44's spent inv-blind v3 outputs reproduces doc 44's table, with
ftL in the incumbent slot and ftM in the candidate slot. It also prints the next/multi split above.

## 6. Limits

- The multi-step cases are synthetic: RESULT lines are written into the context. The device feeds real tool results
  back as tool messages, which the E2E fixture does not exercise (one turn per alert).
- The subsets are small (multi 35). A one-look gate on 80 cases detects only large changes.
- Training continues ftM's adapter, so ftR inherits ftM's behaviour on the kinds v5 shares with v4. That is the
  intent.

## 7. Addendum before training (2026-11-25 19:50)

The chain's first check stopped the run before any data or training. It compared the re-exported ftM file's SHA-256
with ftMg's. The 310 tensors are identical; only the header field `general.name` differs, because the converter
derives it from the export directory name ("Rt ftM Fused" vs "Gguf mixM Fused").
- **Fix:** the check compares tensors (`gguf_to_hf.py verify`, as doc 46 does), not file bytes.
- New SHA-256 of `mixR_chain.sh`: `8f534f8476eb9baffb8b0765beda891ee387fa493b823c5e02d2219bdc728fb0`.
- Nothing else changed.

## 8. Seal (2026-11-25, before any model has seen the set)

- `blind_cases.jsonl` SHA-256 **`b4ac283d356fc46a86da94c4ba4315c91bf7249d5d2969d8bfe40d6c777b426b`**.
- **Mix:** next 45, multi 35, clears 30, decoy 25, invisible 15, alert 25 (175 cases); 21 Romanian (12.0%).
- **Seal checks: PASS** (`INV_SET=v3 inv_seal.py check`): 0 collisions with inv-blind v1–v3, ftM's v4 training
  cases and ftR's v5 training cases. No CVE id is present.
- **Second annotator** (isolated, 44-case sample): **43/44** before adjudication.
  - The one disagreement was `alert-022`. The author kept their gold and added the annotator's step as a second
    acceptable answer (decision b, recorded in the set's README).
  - After adjudication the agreement is 44/44, and the seal checks pass on the final file (the hash above).
- ftR finished training before the seal: checkpoint 200 of 214 (valid 0.010; 0.408 at step 1). Adapter SHA-256
  `76fdeffa…`, GGUF `3da86e16…`.
