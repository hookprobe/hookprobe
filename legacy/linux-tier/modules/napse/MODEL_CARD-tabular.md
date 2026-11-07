# napse tabular-ML seam — model card (SEED / BASELINE, not a trained model)

**Status:** seed placeholder. This is NOT a trained classifier. Mirrors
`modules/dga-lm/model/MODEL_CARD.md`'s honesty contract exactly: real training happens
OFF-DEVICE (ADR 0014's precedent), on a labelled attack/benign corpus derived from real
NAPSE entity feature vectors — no such corpus or training pipeline exists yet. This
checked-in weight vector exists so the model seam (`src/tabular.rs`'s `TabularScorer`
trait), the capability gate (`ml_cpu`), and the QSECBIT `p_attack` connector can all be
exercised and tested end to end before a real model exists.

## What it actually computes

A single-layer logistic regression: `p_attack = sigmoid(bias + w · normalize(features))`,
where `features` is NAPSE's existing 16-D `EntityState::feature_vector()` (see
`src/lib.rs:568-586` for the exact index layout) and `w`/`bias` are the hand-derived
constants in `src/tabular.rs::SEED_WEIGHTS`/`SEED_BIAS`.

**Feature normalization** (`src/tabular.rs::normalize`) divides each raw feature by a cap
chosen to align with thresholds ALREADY used elsewhere in this module, not invented
numbers:

| Feature | Cap | Source of the cap |
|---|---|---|
| unique dest ports / ips | 50 | rule 1000003's port-scan threshold |
| DNS query count | 100 | rule 1000002's DNS-tunneling volume threshold |
| port entropy | 10 | `heuristic_deviation()`'s own `/10.0` divisor |
| alert count | 5 | `heuristic_deviation()`'s own `/5.0` divisor |
| connection rate | 10 | `heuristic_deviation()`'s own `/10.0` divisor |
| MB sent/received | 1000 | `feature_vector()` already caps bytes at 1 GB = 1000 MB |
| byte send/receive ratio | log1p-compressed, /10 | unbounded raw ratio, log-compressed like real traffic-ratio features |
| hours active | 24 | one-day normalization |

**Weight sign/magnitude rationale** (see `src/tabular.rs::SEED_WEIGHTS`'s doc comment for
the per-index table): scanning signals (port count, port entropy, port-scan indicator)
and pre-existing-alert signals (alert count, has_alerts) carry the heaviest positive
weight; failed connections and connection rate (brute-force/automation) are next; bytes
received and hours active carry small NEGATIVE weight (a long-lived, mostly-inbound
entity trends more benign than a fresh, bursty, mostly-outbound one). This is the same
class of hand-derived domain intuition that already backs
`EntityState::heuristic_deviation()` — just applied to more of the 16 already-computed
features, and through a real (if seed-weighted) logistic model instead of a fixed linear
blend of three signals.

## What it is NOT

- Not trained on any real attack/benign entity corpus — there is no such labelled corpus
  yet.
- Not validated against a held-out test set, ROC/AUC, precision/recall, or any of the
  metrics a real model card would report — there are none to report yet.
- Not a substitute for signature rules (`run_signatures`), HYDRA's IOC/threat-intel feeds,
  or the HMM/Viterbi intent decoder — this is an additional, advisory/observe-only signal
  (C9 — never in the ADR 0023 `decide()` enforcement path) that feeds two consumers:
  1. NAPSE's own HMM `deviation` input (gated: falls back to
     `EntityState::heuristic_deviation()` when `ml_cpu` isn't granted — see
     `tabular::gated_deviation`).
  2. QSECBIT's optional `p_attack` CSV field (gated: stays `0.0` when `ml_cpu` isn't
     granted — see `tabular::p_attack_for_qsecbit`, the `dga_lm::p_attack_for_qsecbit`-parity
     contract).

## Shape / footprint

- Input: the existing 16-D `f64` feature vector — zero new capture/telemetry surface.
- Model: 16 `f64` weights + 1 `f64` bias = 136 bytes, compiled into the binary as `const`
  arrays (no blob file, no `include_bytes!`, no parser — unlike `dga-lm`'s int8 blob, this
  is small enough that a Rust `const` array is the simplest honest representation).
- Compute: one dot product (16 multiply-adds) + one `sigmoid` per entity per event —
  negligible next to the existing HMM Viterbi step it feeds.

## Regeneration

There is no `ci/quantize.py`-equivalent generation script for this seed (unlike
`dga-lm`) — the weights are hand-edited constants directly in `src/tabular.rs::SEED_WEIGHTS`
/`SEED_BIAS`. Bump `tabular::MODEL_ID` (`"napse-tabular-seed-v0.1"` → `v0.2`, etc.)
whenever those values change, so the model identity string stays truthful in any
downstream display (mirrors `dga_lm::MODEL_ID`'s own bump convention).
