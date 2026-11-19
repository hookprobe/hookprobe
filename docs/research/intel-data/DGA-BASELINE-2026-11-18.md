# dga.rs baseline on licence-clean data (2026-11-18)

> **measured** on the development Mac. The scorer is `os/kernel/kernel/src/dga.rs`, run through its bit-exact Python port
> (`tools/intel-data/heqkdata/dga_ref.py`, identical scores on 20,009 names against the compiled Rust).
> Reproduce with `python3 -I tools/intel-data/heqk_data.py dga-eval` after fetching the sources below.

## Data

| Set | Source | Licence | Names |
|---|---|---|---|
| DGA (50 families) | UMUDGA 1000-name sample per family, Mendeley y8ph45msv8 v1, sha256 checked | MIT | 49,898 |
| Phishing hosts | PhiUSIIL (UCI 967), label 0, domain column only | CC BY 4.0 | 85,054 |
| Benign | PhiUSIIL label 1 + UMUDGA `legit` | CC BY 4.0 / MIT | 135,796 |

Caveat: both benign sets are popularity-derived lists published under the dataset authors' grant; counsel should confirm the grant covers them (research doc §2). The scorer is not trained, so all names are used, not just a test split.

## Result

| Set | ≥ 300 | ≥ 400 | ≥ 500 | ≥ 600 |
|---|---|---|---|---|
| benign false-positive rate | 2.73% | 0.57% | 0.08% | 0.00% |
| DGA recall (all families) | 33.5% | 22.7% | 12.4% | 6.8% |
| phishing hosts flagged | 8.3% | 5.3% | 3.2% | 2.5% |

**At the device threshold (600): zero false positives on 135,796 benign names, but 6.8% DGA recall; 31 of 50 families are never flagged.**

## What it means

- dga.rs does what ADR 0052 asked of it: an observe-only signal that never cries wolf. It is not a DGA detector in the recall sense.
- Lowering the threshold buys little: at 400, recall reaches 22.7% for 0.57% false positives. A home network sees thousands of distinct names a day, so that would be dozens of false alerts.
- The misses are structural. Dictionary-based DGAs (suppobox, matsnu, gozi, banjori, pizd) produce pronounceable names. Short random labels can never reach the 4-bit entropy bonus, because a label of n characters has at most log2(n) bits.
- Phishing hosts are a different problem (2.5% flagged): they are lookalikes and compromised sites, not random strings.
- **This is the case for the tier-B DNS specialist** (HEQK-TRAINING-STRATEGY.md R6): an int8 character model trained on these licence-clean sets, judged against these exact numbers (FP at equal recall, per family), with dga.rs kept as the zero-FP floor.

## Per family (recall)

| family | n | ≥ 300 | ≥ 400 | ≥ 500 | ≥ 600 |
|---|---|---|---|---|---|
| banjori | 1000 | 0.00 | 0.00 | 0.00 | 0.00 |
| kraken_v1 | 1000 | 0.00 | 0.00 | 0.00 | 0.00 |
| pushdo | 1000 | 0.00 | 0.00 | 0.00 | 0.00 |
| simda | 1000 | 0.00 | 0.00 | 0.00 | 0.00 |
| suppobox_2 | 998 | 0.00 | 0.00 | 0.00 | 0.00 |
| symmi | 1000 | 0.00 | 0.00 | 0.00 | 0.00 |
| vawtrak_v2 | 1000 | 0.00 | 0.00 | 0.00 | 0.00 |
| vawtrak_v3 | 1000 | 0.00 | 0.00 | 0.00 | 0.00 |
| pizd | 956 | 0.00 | 0.00 | 0.00 | 0.00 |
| suppobox_1 | 962 | 0.01 | 0.00 | 0.00 | 0.00 |
| nymaim | 1000 | 0.02 | 0.00 | 0.00 | 0.00 |
| ramdo | 1000 | 0.03 | 0.03 | 0.00 | 0.00 |
| matsnu | 996 | 0.04 | 0.00 | 0.00 | 0.00 |
| suppobox_3 | 1000 | 0.05 | 0.00 | 0.00 | 0.00 |
| corebot | 1000 | 0.06 | 0.06 | 0.00 | 0.00 |
| sisron | 1000 | 0.10 | 0.00 | 0.00 | 0.00 |
| gozi_luther | 1000 | 0.13 | 0.00 | 0.00 | 0.00 |
| kraken_v2 | 1000 | 0.16 | 0.05 | 0.00 | 0.00 |
| gozi_nasa | 991 | 0.19 | 0.02 | 0.02 | 0.00 |
| tempedreve | 1000 | 0.24 | 0.06 | 0.00 | 0.00 |
| gozi_rfc4343 | 995 | 0.24 | 0.05 | 0.04 | 0.00 |
| gozi_gpl | 1000 | 0.24 | 0.02 | 0.01 | 0.00 |
| fobber_v2 | 1000 | 0.28 | 0.07 | 0.00 | 0.00 |
| alureon | 1000 | 0.29 | 0.07 | 0.00 | 0.00 |
| pykspa_noise | 1000 | 0.33 | 0.13 | 0.00 | 0.00 |
| proslikefan | 1000 | 0.35 | 0.14 | 0.00 | 0.00 |
| pykspa | 1000 | 0.35 | 0.15 | 0.00 | 0.00 |
| rovnix | 1000 | 0.37 | 0.01 | 0.01 | 0.00 |
| padcrypt | 1000 | 0.40 | 0.40 | 0.07 | 0.00 |
| vawtrak_v1 | 1000 | 0.48 | 0.32 | 0.09 | 0.00 |
| tinba | 1000 | 0.55 | 0.30 | 0.04 | 0.00 |
| ccleaner | 1000 | 0.64 | 0.28 | 0.01 | 0.00 |
| qadars | 1000 | 0.32 | 0.18 | 0.03 | 0.00 |
| cryptolocker | 1000 | 0.39 | 0.21 | 0.04 | 0.00 |
| ramnit | 1000 | 0.41 | 0.29 | 0.06 | 0.01 |
| ranbyus_v1 | 1000 | 0.39 | 0.14 | 0.03 | 0.01 |
| murofet_v2 | 1000 | 0.54 | 0.47 | 0.17 | 0.01 |
| fobber_v1 | 1000 | 0.66 | 0.66 | 0.27 | 0.03 |
| locky | 1000 | 0.48 | 0.30 | 0.14 | 0.03 |
| shiotob | 1000 | 0.38 | 0.21 | 0.08 | 0.03 |
| dircrypt | 1000 | 0.49 | 0.36 | 0.14 | 0.03 |
| bedep | 1000 | 0.53 | 0.44 | 0.17 | 0.03 |
| necurs | 1000 | 0.52 | 0.37 | 0.17 | 0.04 |
| ranbyus_v2 | 1000 | 0.65 | 0.61 | 0.29 | 0.05 |
| qakbot | 1000 | 0.65 | 0.51 | 0.33 | 0.12 |
| chinad | 1000 | 0.76 | 0.56 | 0.35 | 0.14 |
| murofet_v1 | 1000 | 0.99 | 0.94 | 0.92 | 0.46 |
| zeus-newgoz | 1000 | 1.00 | 0.90 | 0.86 | 0.66 |
| dyre | 1000 | 1.00 | 0.99 | 0.85 | 0.82 |
| murofet_v3 | 1000 | 1.00 | 1.00 | 0.98 | 0.91 |
