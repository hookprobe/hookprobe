# 54: Doc 51 re-run with the generator's move-on targets fixed (pre-registration, 2026-11-28)

Written **before** inv-blind v6, the new training rows or the candidate exists.

## 1. A defect that confounds docs 49 and 51

Rule P's reference (`l0_playbook.py`, #1640) was checked against the generator's multi-step cases, and the check
exposed a defect in `gen_investigate.py`. Since doc 43 (v3), a "move on to a different check" case has taken its
gold entity, and the alias on its second RESULT line, from the **first** step's target instead of the new step's
playbook target (`on`).

| Training data | move-on cases | gold entity contradicts the playbook's target |
|---|---|---|
| doc 49, gen v5 (ftR) | 73 | **68** |
| doc 51, gen v6 (ftS) | 162 | **154** |

The commonest errors:
- `lookup_reputation` on the household's own device (34 and 72);
- `query_flows` on a remote server (20 and 42);
- `lookup_reputation` on the device where the playbook targets a domain (11 and 31).

**Consequence:** docs 49 and 51 concluded that multi-step training *itself* costs the first check. They trained on
mostly wrong targets. Teaching `lookup_reputation(H1)` also corrupts the first check's choice of entity, so that
conclusion is confounded, not established. This doc re-runs doc 51 with only that fixed.

## 2. The one change: generator v7

`gen_investigate.py --version 7` is v6 with each move-on target taken from the step's own `on` wording:
- the gold entity;
- the alias on the second RESULT line.

The mapping is `STEP_TARGET`, equal to `l0_playbook.TARGET`. The alias is read from the window's cards: the detection
card's R alias for remote targets, and the D alias (or R) for domain targets. A window with no alias for the target
(e.g. a proxy card `->*` asked about "the coordinating peer") is ill-posed and is skipped.
- On seed 5401 (600 multi/clears cases): 148 move-on cases, **0** contradicting the playbook, **0** naming an alias
  missing from the window. There are 203 policy proposals and 249 clears.
- `--version 4`, `5` and `6` are byte-identical to before; v4 still equals ftM's training cases.

Everything else is doc 51's, exactly:
- ftM's 595 + 32 rows without a RESULT line, byte for byte (hashes pinned);
- plus 600 gen v7 multi/clears cases (seed 5401, `build_inv_sft --seed 54`);
- ftT = ftM's adapter continued for 1 epoch at 5e-5; lowest validation loss over checkpoints every 50 steps.

## 3. inv-blind v6

- **Brief:** `data/inv-brief-v6.md`, SHA-256 `3ac4eb946ecee81bf4c50bbef247d67c0a898fdfbf95e75ab3b5452e67cbd7e8`. It is
  v5's brief, unchanged except for the title.
- **People:** a new isolated author and a new isolated annotator (44-case sample).
- **Seal:** collisions are checked against inv-blind v1–v5 and the gen v4–v7 case files.

## 4. Gate (`mixT_gate.py`): doc 51's six conditions, unchanged

1. `multi` > ftM's **and** next+multi > ftM's;
2. `next` ≥ ftM's − 0.05;
3. `alert` ≥ ftM's − 0.05;
4. `decoy` ≥ ftM's − 0.05;
5. `invisible` ≥ 0.80;
6. grounding clean and no policy proposal on a decoy.

**Reading the result:**
- **Pass:** ftT replaces ftM, and docs 49/51's conclusion is withdrawn.
- **Fail with `next` still dropping:** docs 49/51's conclusion stands on cleaner evidence.
- **Fail otherwise:** reported as measured.

**E2E (operator rule), whatever the verdict:** ftFg for triage and ftTg for investigation. The expected first
checks are `query_flows` on the camera and `lookup_reputation` on R1.

## 5. Pinned

| File | SHA-256 |
|---|---|
| `gen_investigate.py` (v7) | `9bd39a142e12311d26f9416cd1223403778b89473d99ded00899fb7fb88fb63c` |
| `mixT_chain.sh` | `0a4c00d31ab6c34817de003c66ae911c2f4538c327b1f46e500c474cac55e46c` |
| `mixT_gate.py` | `726d43ab122df9d7c198cb19b755fe2dee814d31dc7d5e76e8bdf1e97cb59be8` |
| `data/inv-brief-v6.md` | `3ac4eb946ecee81bf4c50bbef247d67c0a898fdfbf95e75ab3b5452e67cbd7e8` |
| `build_inv_sft.py`, `inv_eval.py`, `inv_seal.py`, `export_gguf.sh`, `gguf_to_hf.py` | unchanged since doc 51 |

**Dry run:** `mixT_gate.py` on doc 51's spent inv-blind v5 outputs (ftS in the candidate slot) reproduces doc 51's
verdict.

## 6. Limits

- The first-step targets in the `next` rows are unchanged; they were checked as consistent with the playbooks' first
  steps in doc 44.
- **Policy proposals keep the generator's two acceptable policies** (`isolated`, `internet_only`), including for
  playbooks that list only owner actions. Only the move-on entities change, so this stays a one-variable re-run.
- **The window ends at 09:00 on 2026-11-28** (operator). If it cannot finish by then, it stops, and this doc says
  where.

## 7. Seal (2026-11-28, before any model has seen the set)

- `blind_cases.jsonl` SHA-256 **`37a8693d16a39ee9564f5e3ed3baa75efb6da741e92c8893b477cff048ade94b`**.
- **Mix:** next 45, multi 35, clears 30, decoy 25, invisible 15, alert 25 (175 cases); 21 Romanian (12.0%).
- **Seal checks: PASS.** 0 collisions with inv-blind v1–v5 and the gen v4–v7 case files.
- **Second annotator** (isolated, 44-case sample): **40/44** before adjudication.
  - The author chose (b) for all four disagreements (`next-037`, `multi-022`, `alert-005`, `alert-009`): keep the gold
    and add the annotator's step as a second acceptable answer.
  - `alert-005` now accepts three tools, the only case above the brief's two-tool limit; the set's README records it.
  - After adjudication the agreement is 44/44, and the seal checks pass on the final file (the hash above).
- ftT finished training before the seal: checkpoint 200 of 292 (valid 0.018; 0.429 at step 1). Adapter
  `2cfa4103…`, GGUF `40fd46d4…`.

## 8. Result (2026-11-28, one look)

**VERDICT: FAIL** (condition 2 only).
- Passed: multi 0.286 vs ftM's 0.114; next+multi 0.487 vs 0.463, the first candidate above ftM; alert, decoy,
  invisible and grounding unchanged.
- Failed: next fell to 0.644, below the floor of 0.683 (ftM's 0.733 − 0.05).
- Against doc 51, fixing the targets cut the first-check loss from 7 to 4 cases and tripled the multi gain (2 → 6).
- E2E run 13 chose both expected checks.

ftM stays. Separating the two decisions by construction is the next step: Rule P, or routing by turn (ftM without a
RESULT line, ftT with one). Full tables: [`data/mixT-results.md`](data/mixT-results.md).
