# 52: A deterministic playbook rule after a tool result (design note, 2026-11-25)

A design note, **not** a pre-registration. Nothing here changes a model, the request contract or the device.

## 1. Why the model is not the lever (again)

Two pre-registered attempts tried to teach the investigation model what to do **after** a tool result: move on to a
different check, stop when the result clears the signal, or propose a policy once the evidence is conclusive.

| | first check (`next`) | after a result (`multi`) |
|---|---|---|
| doc 49 (ftR), inv-blind v4: ftM → ftR | 0.556 → **0.400** | 0.114 → 0.229 |
| doc 51 (ftS), inv-blind v5: ftM → ftS | 0.733 → **0.578** | 0.229 → 0.286 |

Doc 51 kept ftM's first-check training rows **byte for byte** and still lost the first check. Training for the
second step costs the first, as docs 33–38 found for triage hedging and docs 45–47 for the generic alert. Doc 40 solved
the triage case by moving the decision out of the model (rule T). This note proposes the same for the investigation.

## 2. The decision is already written down

`data/playbooks.json` has 15 observable techniques. For each one it lists:
- `next`: the ordered checks, each a tool plus whom it targets ("the device", "the peer", "the inbound sources", …);
- `confirms` and `clears`: what a result must show to support the technique or to explain it away;
- `close`: the responses. 13 of the 15 include a network policy the tool contract accepts (`isolated` 9,
  `internet_only` 4), next to owner actions (25).

So the step after a result is a table lookup, once two facts are known: **which playbook**, and **whether each result
supports or clears it**.

## 3. Rule P

Inputs:
- the playbook id;
- the checks already run, each with a typed outcome: `supports`, `clears` or `none`;
- the window's aliases.

1. **A result clears it → stop.** No further call. The explanation says what the result showed.
2. **Conclusive → propose.** If two results support it (or the playbook's last check supports it),
   `propose_policy_change(entity = the device, policy = the first `close` entry with a contract policy)`. If the
   playbook has no such entry, stop and leave the owner action in the explanation.
3. **Otherwise → the next check.** The first playbook step not yet run, with its tool. The entity comes from `on`:
   "the device" is the H alias; "the peer", "the server" and "the sources" are the R alias.
4. **Nothing left → stop,** with the supports and clears in the explanation.

**The model keeps:**
- the first check (ftM; its doc 44 behaviour on alerts, decoys and invisible cases is the incumbent);
- every explanation;
- any window without a known playbook.

**Fails closed:** the rule only reads, looks up and proposes. A proposal is never applied without the owner, as today.

## 4. What is missing (each is a decision, not code)

1. **Typed tool outcomes.** On the device, today's read tools return text that the harness writes as
   `RESULT <tool> <alias>: <text>` (#1615). Rule P needs each tool to also return `supports | clears | none` against
   the playbook's `confirms` and `clears`. Examples: reputation listed or not; new outbound peers or not; random-looking
   names or not; known exposure or not. The tools' owner (the kernel side) decides whether they can.
2. **The playbook id.**
   - A named detection carries its technique (`det=port_scan[T1046,…]`).
   - The generic L1 alert carries none. There it would come from doc 48's `dev=` token (e.g. `ssh+4.0` →
     T1110); otherwise the model keeps the step after a result.
3. **Where it runs.** Rule P sits in the investigation turn after each read tool, so in the Conductor's harness (or
   the job issuer). Its source is Neuro's (`playbooks.json` plus a reference implementation), and it is mirrored and
   drift-gated like guards A/E/G.

## 5. How it would be tested (a later pre-registration)

- A reference `l0_playbook.py` in Neuro, plus vectors for the Conductor's mirror.
- A fresh sealed inv-blind set whose `multi` and `clears` cases also state each result's typed outcome, as the device
  would supply it.
- Gate: ftM + Rule P against ftM alone.
  - The first check is unchanged by construction: the same model makes the same call.
  - Rule P must beat ftM on `multi` and `clears` without any policy proposal on a decoy.
- E2E: the fixture's two alerts end in the pre-registered first checks, then follow the playbook.

## 6. Limits

- **Typed outcomes move judgement into the tools.** A wrong outcome (a feed listing a CDN, for example) leads to a
  wrong step, and the playbooks' wording must become checkable conditions.
- **Two supporting results is a fixed threshold,** chosen by reading the playbooks, not measured.
- **The L1-alert case depends on doc 48** (`dev=`) and therefore on the kernel decision after the soak (Friday
  2026-11-27 17:00).
