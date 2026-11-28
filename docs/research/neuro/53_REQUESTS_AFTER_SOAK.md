# 53 — Requests to HomePods and the operator after the 72 h soak (R10–R13)

> 2026-11-28. **Requests, not changes.** `os/kernel/**` is owned by HomePods and was not modified. The soak passed
> (REL-05, `ae712636`: 847 samples, 0 faults or traps). Same format as doc 12 (R0–R9): evidence, whether it is
> needed, and the smallest interface. Approved for raising after the soak by the operator on 2026-11-25.

These come from Neuro's work on 2026-11-24/25: docs 45–52, the Conductor's card-builder mirror (#1617) and its
investigation turn (#1615).

| | What | Who decides | Blocks |
|---|---|---|---|
| **R10** | S1's alert carries its top-3 feature deviations (`dev=`) | HomePods (ABI), operator | the generic-alert triage gap (docs 45–48) |
| **R11** | A window with no evidence card never becomes an explainer job | HomePods (job issuer) | nothing; removes a failure by construction |
| **R12** | Where the evidence cards are built on the device | operator | every on-device explanation |
| **R13** | Read tools return a typed outcome next to their text | HomePods / the tools' owner | doc 56's design (router + stop rule; PASS) |

---

## R10 — S1's alert says what deviated (doc 48)

**Evidence**
- Three pre-registered triage attempts (docs 45, 46, 47) traded benign-alert accuracy for attack-alert accuracy, about
  one for one. The generic alert `det=behaviour_change[-,sev2,alert, l1]` gives the explainer one bit.
- S1 is linear: score = Σ wᵢ·zᵢ + b. On the E2E fixture, the largest |zᵢ| names the attack: `ssh_frac +4.0` for the
  SSH brute force, `telnet_frac +3.4` for the scan. These are the two readings ftFg got wrong in runs 3–10.
- S1 is not deployed yet. Its integer twin is `os/neuro/neuro-l1` (candidate; gated on doc 35 M4 and a signed
  package, D3). The kernel's own `behaviour_change` (`rulecat.rs:58`, rule 128) is a different detector.
- **There is a precedent:** the DNA engine's result record already names what drove its score (`driver`: volume,
  fan-out, novel peers, dns, activity; `hal/src/neuroabi.rs`, result record).

**Needed:** only when S1 is deployed, and only if the triage explainer is to read the alert.

**Smallest interface**
- When S1 deploys, its result carries 3 × (feature id `u8`, z `i16` Q8): 9 bytes, integer only, computed in the EL0
  server from the u8 features it already has.
- The kernel validates the bytes as it validates every server byte, and attaches them to the alert's detection. The
  card builder renders them as ` dev=<name><±z>,…`.
- Neuro provides the integer function and its parity vectors in `neuro-l1`, the same way S1's own twin is provided.
  The Conductor mirrors the card rendering.

**Gate:** parity vectors (Neuro float reference ↔ `neuro-l1` integer ↔ the card text). Then a doc 50 pre-registration
decides whether the explainer is retrained to read `dev=`.

## R11 — No evidence card, no explainer job

**Evidence**
- On the E2E fixture, 151 of 679 scored windows (22%) produce no fact card, only the REST line. Every explainer
  then fails: ftFg cites "none" (citation failure), and the delta models invent F1/H1.
- Nothing in code stops such a window reaching triage. The design says "alerts only", but the job issuer is the
  kernel's.
- The Conductor's harness now refuses such a job (`Refused(NoEvidence)`, #1615) as a second line of defence.

**Needed:** yes, cheap.

**Smallest interface:** the job issuer does not create an explainer job for a window with no `F` card. If an answer is
shown at all, it is fixed: benign, observe, "only ordinary traffic the device has seen before". No model call.

## R12 — Who builds the evidence cards on the device

**Evidence**
- Today the job carries ready cards and the harness writes only `F<id> <card>` lines: no REST line and no CONTEXT
  lines. That is not the text the models were trained and evaluated on.
- The Conductor's `neuro_contract::cards::build_context` (#1617) equals Neuro's builder byte for byte. It matches on
  22 fixture vectors and 6,400 synthetic windows, with no float and no allocation, and it already follows #1618's
  fixes (`a7144edd`).
- Not yet mirrored: DNS and behaviour cards (the job has no input for them yet).

**Needed:** yes, before any on-device explanation is trusted.

**Decision for the operator:** run `build_context` in (a) the harness (EL0, where the mirror already lives), (b) its
own EL0 server, or (c) EL1. **Neuro recommends (a):** it keeps text handling out of EL1 and reuses the mirror that is
drift-gated against Neuro's sources.

**Decided (operator, 2026-11-28): (a), in the harness.** The Conductor's `build_context` builds the cards. For the
card kinds the fixture vectors do not cover (DNS, behaviour records, verbatim detections), Neuro adds
`card_contract_synth.py`: deterministic vectors on synthetic windows (RFC 1918/5737 addresses only), at budgets 64,
128, 256 and 512.

## R13 — Typed tool outcomes (only if Rule P goes ahead, doc 52)

**Evidence**
- Two attempts (docs 49, 51) showed that training the investigation model for the step after a tool result costs its
  first check.
- Doc 52 proposes Rule P: a result that clears → stop; two supporting results → propose the playbook's policy;
  otherwise → the playbook's next check. It needs each result as `supports | clears | none`.
- Today the harness writes tool results as text (`RESULT <tool> <alias>: <text>`, #1615).

**Needed:** only if the operator chooses Rule P.

**Smallest interface:** each read tool returns one outcome byte next to its text, judged against the playbook's
`confirms` and `clears` (for example, listed on a feed or not; new outbound peers or not). The text stays as it is.

**Update after doc 56 (2026-11-28).** R13 now has evidence of its own.
- **Doc 56 PASSED** on inv-blind v8 (sealed, one look; [`data/mixV-results.md`](data/mixV-results.md)). The design
  is Rule P's first rule only: any result typed `clears` → stop; otherwise ftT after a result and ftM before one.
  Against ftM alone:
  - multi 0.457 vs 0.114;
  - next+multi 0.637 vs 0.487 (McNemar p = 0.0018);
  - clears 0.967 vs 0.833.
- **The outcomes were simulated:** an isolated labeller read each result sentence alone. So this is an upper bound
  until tools type their own results.
- **What changes in the interface:**
  - Only `clears` drives a decision. Rules 2–3 of Rule P, and the playbook ids they need (R10), are **not** needed
    for this step.
  - `clears` means a **specific benign explanation**: the device vendor's own cloud, a known update host, the owner's
    own job or scanner. "Not listed", "nothing found", and shared hosting, CDN or sinkhole ranges are `none`. That
    rule is in the labeller brief, [`data/inv-outcome-brief-v1.md`](data/inv-outcome-brief-v1.md).
  - Fail closed: a missing or unknown outcome is `none`. The outcome comes from the tool only, never from a model or a
    worker.
- **What it costs (Conductor):**
  - two model bundles, about 1.9 GB each, with one arena serving both, one at a time;
  - a full prompt pass on the first ftT turn, because switching adapters drops the cache.
- **Still untested:** an investigation where one tool clears and another supports. As written, it stops. The
  Conductor will count such cases as telemetry if R13 goes ahead.
- **Needed:** only if the operator adopts doc 56's design. The decision is HomePods' (the tool result format) and the
  operator's.

---

## Order

1. **R11:** cheap; it closes a failure by construction.
2. **R12:** decide before trusting any on-device answer. Then the Conductor can add DNS/behaviour cards with Neuro
   vectors.
3. **R10:** with S1's deployment.
4. **R13:** only with a decision for Rule P.

None of them brings in Linux, a filesystem or floating point in EL1.
