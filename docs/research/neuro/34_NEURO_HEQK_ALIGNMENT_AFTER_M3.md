# 34: Neuro ↔ heqk alignment after M3 (2026-11-23)

**Follows** doc 32 and HomePods' updates to `docs/design/heqk-neuro-integration.md` (§9a, §9b and the status
register), up to the CM5 fault injection (#1487). This note changes no kernel code or decision. It gives the Neuro
side's results and their consequences, so that the design doc and the register can be updated from evidence.

## 1. M3 failed: what changes for heqk

Doc 31's sealed run (`data/m3-results.md`, PR #1507) failed **all three** systems on recall:

| System | Recall | Home false alerts / device-day |
|---|---|---|
| S1 (L1 candidate) | 0.680 (IoT-23 0.993, CTU-13 0.320) | 0.003 |
| S2 (L0-gated) | 0.425 | 0.042 |
| S3 | 0.404 | 0.002 |

| heqk item | Before | After M3 |
|---|---|---|
| register `m3` | not_started | **measured: failed** (doc 31 result) |
| §6 L1 / §9 P5 | gated on M3 | **stays gated; there is no approved L1 model.** The integer scorer (doc 32 §1) remains a validated *mechanism*, not a deployable model |
| §10 D2 | (a) integer-only through L1 | unchanged. The argument still holds for any logistic-regression-class L1, but nothing urgent depends on it now |
| R-D1 (beacon gating in L0) | pending M3 S2 | **not recommended.** The gate cuts home false alarms about 180× but leaves CTU-13 C2 recall at 0.047. DET-01's beacon false positives remain an L0 problem that a gate does not solve without losing C2 |
| doc 29 rule table | `rules_ver = 1` | unchanged |

**What M3 does support**, measured on unseen data:
- the DNA v1 + logistic-regression design produces about **one false alert per device per year** on unseen home
  IoT;
- it catches IoT scanning botnets almost completely.

The gap is C2/spam/click-fraud botnets that don't scan. A next attempt needs more diverse C2 in training and new
sealed data (doc 31 stop rule). That is Neuro work and asks nothing of the kernel.

## 2. Connection rule: the kernel's doc 20 rule is confirmed for the benign side

Doc 32 §2 promised a re-measure (`data/conn-rule-and-reset.md` §1). Re-cutting the UNSW home captures with the
kernel's rule (TCP SYN, or UDP idle ≥ 120 s):
- **does not raise home false alerts:** S1 0.002–0.003 → 0.000 per device-day; S2 unchanged; the ungated rules go
  down;
- leaves the median of every DNA v1 feature unchanged. Only the tails of duration and periodicity features move.

**Keep the doc 20 rule in `neuro-dp`.** Recall under it cannot be measured, because the malicious data is Zeek-only.
Any future L1 must therefore be validated on traffic cut by `neuro-dp` itself before thresholds reach a device.

## 3. After an el0-neuro reset: a sensitivity gap, not false alarms

The CM5 fault test (#1487) showed the reset path works: the server is reset from its signed ELF, the memory is lost,
and Neuro relearns. `data/conn-rule-and-reset.md` §2 measures what relearning means for the evidence:
- the bit-exact reference engine, reset on day 7, 14 or 21 of real UNSW traffic, flags **fewer** deviant hours than
  an engine that kept its memory: about 0.3× at 24–72 h, ≥ 0.87× by week 2, about 1.0× after two weeks;
- the cold-slot widening does this by design.

**Proposal for the host and UI. No ABI change; for HomePods and the UI owner to decide.**
- EL1 already counts `server_resets`. The host could keep the time of the last reset and attach "**relearning since
  ⟨time⟩**" to behaviour evidence for 14 days after it.
- The doc 20 wording "behaved differently from its own history" would otherwise overstate the history behind it.
- The `[NEURO beat]` and `/api` evidence fields (P2's open item) are the natural place for it.
- The same applies to a device's first two weeks. It is the same mechanism, so a new device and a reset can share
  one "learning" state.

**Dropped events while held off.** These are already counted (`dropped=35` on metal). No change needed. They are
not replayed, which is correct for evidence.

## 4. Data contract for any future L1 (not needed now)

`neuro-dp` produces exactly what N0 needs: per-device-hour connection counts, peer and DNS fingerprints, NX, bytes.
DNA v1 (doc 27) also needs **per-connection** fields that N0 never uses:

| DNA v1 needs | Per connection | `neuro-dp` today |
|---|---|---|
| out/in bytes, ratio | bytes each direction | bytes per device-hour only |
| duration, packets per flow | first/last time, packets | — |
| ports, port entropy, service shares | destination port | port is hashed into the peer key |
| fail ratio | state: no reply / reset / ok | — |
| inbound sources | initiator direction | device-sent SYNs only |
| LAN share | peer class | yes (class/local) |

This is **not a request now**. There is no approved L1 model (§1). If a future model passes its sealed gate, the
adapter would need a per-connection summary at close (about 24 B per connection, bounded like the UDP table).
Neuro would provide the fixed-point extractor with golden tests against the Python reference, as in doc 32 §6.

## 5. Updated joint steps

| Step | Who | Gate |
|---|---|---|
| Register `m3` → measured: failed; P5 note; R-D1 not recommended | HomePods (register owner) | this doc |
| "Relearning since" on behaviour evidence after a reset or for a new device (§3) | HomePods + UI owner | their decision; no ABI change |
| Next protection-model attempt: C2-diverse training data, new sealed data, new pre-registration | Neuro + intel-data | before any L1 work |
| Per-connection summary in `neuro-dp` (§4) | HomePods | only after a model passes |
