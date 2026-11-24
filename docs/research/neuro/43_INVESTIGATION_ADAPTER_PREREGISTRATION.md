# 43: A separate investigation adapter (ftL), triage left on ftFg; guard G by default (pre-registration, 2026-11-24)

Written after doc 42's FAIL and the E2E attack path (`data/e2e-attack-2026-11-24.md`), and **before**
inv-blind v2, the v3 training cases or ftL exist.

## 1. What docs 42 and the E2E runs showed

| Finding | Source |
|---|---|
| One model for triage **and** investigation (ftKg) restored tool calling, but triage regressed: 12% of blind v7 malicious cases called benign | doc 42 |
| ftKg more than doubled base on the first check (0.511 vs 0.222), but was worse on multi-step (0.029 vs 0.086): the generator's multi-step targets repeated step 1's tool | doc 42 |
| The fine-tuned explainer invents ATT&CK technique ids (ftFg 1–2% of answers; base 0%) and misreads services (NTP on an SSH card) | grounding checks |
| Guard G (delete-only) removes invented technique ids and unreturned CVE ids; mention unchanged on two sets | guard G |

## 2. Design (fixed now)

**Two parts, routed by turn:**
- **Triage** (the alert explanation) stays on **ftFg**, with weights unchanged, followed by guards A, E and G and
  rule T where it applies. Triage cannot regress: its model does not change.
- **Investigation** (the next-check turn, with tools) runs on **ftL**, a LoRA adapter trained on the **base**
  student with investigation data only.

Both are Q8_0 GGUFs today (about 1.7 GB each). llama.cpp can also serve one base with two LoRA adapters; whether
that saves memory is a deployment question, not tested here.

**Guard G becomes the default output filter for both** (after guard E and rule T). It is delete-only and changed no
mention score on blind v7 or dev v8. Its effect is reported in every run. It is adopted without a gate, as guard E
was, because it can only remove tokens that are invalid by construction.

## 3. Data and training for ftL

- **Generator v3** (`gen_investigate.py --version 3`): 720 cases, seed 43.
  - A multi-step case now **moves on**: after a supporting result, the gold is a **different** tool; once two
    results support it, the gold is a policy proposal (isolated or internet_only).
  - On the v3 sample, 0 of 191 multi-step golds repeat a tool already used; 115 are proposals.
  - v1 (`--v1`) and v2 (default) still regenerate byte for byte; doc 42's training cases are unchanged.
- **Targets:** `build_inv_sft.py`, unchanged: the exact `inv_eval.py` prompt, guard A, and six tools, no teacher.
- **Recipe:** doc 26's settings (LoRA rank 16, scale 20, learning rate 1e-4, batch 4, 2 epochs, mask prompt) on
  **base** Qwen3-1.7B @ `70d244cc`, investigation rows only. With about 342 iterations, validation and
  checkpoints come every 50 steps; the checkpoint with the lowest valid loss is kept. Exported as **ftLg**.

## 4. inv-blind v2 (fresh; v1 is spent)

- **Brief:** the doc 41 brief, unchanged (SHA-256 `a0be71ec…`): 150 cases, the same mix.
- **People:** a **new** isolated author and a new isolated annotator (25% sample, `inv_seal.py`); the author
  adjudicates.
- **Seal checks:** `inv_seal.py check`, against every set doc 41 listed **plus** inv-blind v1, the v2 and v3
  generator outputs, and blind v7. The SHA-256 is pushed here before any model sees the set. The chain re-checks it
  and stops on a collision with the v3 training cases.

## 5. Gate (`mixL_gate.py`; one look; ftLg against base17g, both with tools and guard A)

| # | Condition |
|---|---|
| 1 | `step_ok` on next + multi > base17g's, exact McNemar p < 0.05 |
| 2 | `step_ok` on **multi** ≥ base17g's (doc 42's gap) |
| 3 | `stop_ok` on clears + decoy ≥ 0.80 and ≥ base17g's |
| 4 | **0** raw answers (before guard G) with an unreturned CVE id |
| 5 | raw answers with an invented ATT&CK technique id ≤ 2% |
| 6 | no policy proposal on any decoy |

Reported, not gated: service named without its port on the cards, and every grounding count after guard G.

**Pass:** the explainer becomes ftFg (triage) + ftL (investigation), with guard G. **Fail:** ftFg stays alone,
without investigation, with guard G.

**Dry run** on the spent inv-blind v1, ftKg standing in for ftLg: FAIL on 1 (p = 0.052) and 2 (multi 0.029 vs
0.086). This is the doc 42 picture, so the gate reads correctly.

## 6. End to end (operator rule)

After the look, `e2e_neuro.sh` re-runs on the benign captures (run 1) and on the injected-attack capture, with guard
G. Investigation turns are not yet part of the E2E chain. Adding one turn per alert is follow-up work, stated so it
is not mistaken for done.

## 7. Pinned

| File | SHA-256 |
|---|---|
| `gen_investigate.py` (v3) | `f09e4cb8ef3b3bf08f714a4e4073d71acb79cdfa810d443e07210d2905a5e79b` |
| `build_inv_sft.py` | `473ce09d70938e83c897e1f515c50b9269de901ead2bd6f5dbc0a05dc9aab776` |
| `inv_eval.py` | `342192c374f9480361478ff8197b6430afb58e48d99152ba5adb5b9fbbfa57e2` |
| `inv_seal.py` | `abacb6685b0c31aa46d512fd3bab5d506c14e0217c008cebc3a5fde76d2c84d2` |
| `guard_ground.py` | `2ccc422b13df79e6666d1d81cd731f2238a690dc82b85ff0b5291ebda70a7cd2` |
| `eval/grounding.py` | `ba38fbabe0a051c22f48a66630472374f8d32ff3da5479927b136eb703b08d87` |
| `mixL_gate.py` | `70520b10377e34c92ec712420cab893fe18ff8cc5c16aa77fbdf9ebae5d91a69` |
| `mixL_chain.sh` | `1a31a9a3eadd2665e373c9e41f01a2d6742e9fd6238a40edb5658cb50e2a062c` |
| inv brief | `a0be71ec464b86827b6a30f77ebd80dd750418fea2fe6f4cbf374a8f835fafeb` |

## 8. Limits, stated now

1. **Template targets** remain: v3 fixes the observed multi-step pattern, not template learning in general. The
   fresh blind author is the check.
2. **Two models in memory** at the companion tier, until LoRA hot-swap is measured.
3. **The service misreads** (NTP on SSH) are not addressed by training here; they stay a reported rate.
