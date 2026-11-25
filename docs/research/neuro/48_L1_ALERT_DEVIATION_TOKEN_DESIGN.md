# 48: Let the L1 alert say what deviated (design note, 2026-11-25)

A design note, **not** a pre-registration. Nothing here changes the card contract. The HEQK kernel is in a
72-hour soak until **Friday 2026-11-27 17:00**, so no device-side change is proposed before then.

## 1. Why the model is not the lever

Docs 45–47 trained three triage adapters for the device's generic alert
`det=behaviour_change[-,sev2,alert, l1]`, each on a fresh sealed blind set.

| | gain on `alb` (benign behind the alert) | cost on `alm` (attack behind the alert) |
|---|---|---|
| doc 45 (rebuild + alert data) | +0.23 | none, but caution failed elsewhere |
| doc 46 (delta on ftFg) | +0.43 | −0.13, and 11/40 `mal` called insufficient |
| doc 47 (balanced delta) | +0.20 | −0.20 (6 vs 6 discordant) |

The generic alert carries one bit: "S1 fired". From the card's numbers, the explainer has to guess which behaviour
changed. Every data mix moved it along the same trade-off. Making it more sceptical of the alert cost attack windows
by about as much as it gained on benign ones.

## 2. What the sensor already knows

S1 (`bench/s1_apply.py`, frozen `s1_model.json`) is a **linear** model over 28 standardized DNA features:
`score = Σ wᵢ·zᵢ + b`, alert when `score > thr`. So on the device, every alert already has exact, deterministic
per-feature numbers. Nothing has to be learned.

**Probe** (the E2E attack fixture, 2 alerts; exploration, not evidence):

| Alert | Top S1 contributions `wᵢ·zᵢ` | Top deviations `zᵢ` |
|---|---|---|
| Telnet scan | tcp_frac +1.65, telnet_frac +1.10, log_remotes +0.88 | **telnet_frac +3.4**, log_mean_dur +1.6, tcp_frac +1.3 |
| SSH brute force (score −0.32, threshold −0.62) | tcp_frac +1.39, log_mean_dur +0.52, web_frac +0.47 | **ssh_frac +4.0**, lan_peer_frac +1.3, fail_ratio −1.2 |

- **S1's own reasons would not help the SSH case.** `ssh_frac` has weight 0.03, so the alert fired for generic
  reasons ("mostly TCP, little web").
- **The largest deviation names it.** SSH share is 4 standard deviations above the norm, and Telnet share is
  3.4 above for the scan. These are the two readings ftFg got wrong in runs 3–10 (it called the SSH flood "periodic
  NTP").

## 3. Proposal

Extend the alert's card line with the top deviations, deterministic and bounded:

```
det=behaviour_change[-,sev2,alert, l1] dev=ssh+4.0,lan_peer+1.3,fail-1.2
```

- **Content:** the top 3 features by |z|, using S1's own normalisation (`mu`, `sd` from the frozen model), with
  short names and the sign. It is computed where S1 runs: about 30 multiply-adds, no model and no network.
- **The token is separate,** like `svc=`. A parser that ignores it reads the line exactly as today.
- **It does not change the alert decision.** S1 still decides; `dev=` only describes the decision.
- **Grounding rule:** a `dev=` name is card text, so citing it is grounded. Inventing a deviation that is not on
  the card counts as a hallucinated entity.

## 4. What would have to happen (each step needs a decision first)

1. **After the soak (Friday 17:00 or later):** the operator and the HomePods kernel side decide whether S1's
   device output may carry the top deviations. The Conductor then mirrors the card grammar; it asked to be told
   before any card-grammar or template-regex change.
2. **Training data.** The generator writes synthetic cards, not DNA vectors. Two options:
   - (a) the generator computes the same 28 features from each synthetic window's flows and applies S1's
     normalisation;
   - (b) a per-family table (brute force → ssh/telnet/rdp share up, fail ratio up; scan → remotes and ports up …).
   - (a) is faithful to the device. (b) is quicker but hand-made. **Recommendation: (a).**
3. **Pre-registration (doc 49),** written only after steps 1–2 are agreed: an exact ftFg rebuild plus a delta (the
   method that held the incumbent in docs 46 and 47), a fresh sealed blind set whose alert cases carry `dev=`, and
   doc 46's nine conditions.

## 5. Limits

- **Two alerts.** The probe shows that the deviations name the right behaviour on this fixture only. Whether the
  top 3 are informative on benign alerts (updates, backups) is unmeasured.
- **Normalisation is global,** not per device. A device whose normal is SSH-heavy (a jump host) would show
  `ssh+` on every alert. A per-device baseline is more faithful but needs device state.
- **The alert threshold is unchanged,** so false alarms reach the explainer as often as today. `dev=` can only help
  it explain them.
