# M3 results: sealed confirmation of the protection decision rules (doc 31), 2026-11-23

**Outcome: all three pre-registered systems FAIL their criteria.** By doc 31's stop rule, none is deployed in its
role:
- S2 and S3 do not enter the doc 29 rule table (no `rules_ver = 2`);
- R-D1 (beacon gating in the kernel) is **not** recommended;
- L1 (P5 in the heqk design) stays gated;
- a new attempt needs new sealed data.

**Run.**
- One run, at 2026-11-23 07:55, from pinned commit `01578a72` (Addendum B pushed before the run).
- `bench/m3_run.py` and `dna_features.py` are unchanged since `128b2520`.
- Command: `m3_run.py --dev iot23_dev.jsonl,ctu13_dev.jsonl --test iot23_test.jsonl,ctu13_test.jsonl --home unsw_m3_second.jsonl`.

## Output, verbatim

```
M3 sealed run: dev windows 544 | test windows 889 (malicious 275, 22 captures) | home windows 14360 (27 devices)

| system | recall [95% CI] | precision | home false alerts / device-day | worst device | criteria | PASS? |
|---|---|---|---|---|---|---|
| S1 notify | 0.680 [0.621, 0.735] | 0.866 | 0.003 | BelkinWemoMotionSensor 0.03 | recall ≥ 0.90, ≤ 0.14/day | FAIL |
| S2 L0-gated | 0.425 [0.366, 0.486] | 0.750 | 0.042 | CanaryCamera 8.68 | recall ≥ 0.80, ≤ 0.14/day | FAIL |
| S3 act | 0.404 [0.345, 0.464] | 0.799 | 0.002 | BelkinWemoSwitch 0.02 | recall ≥ 0.80, ≤ 0.02/day | FAIL |
| logreg (32 features, incl. context) | 0.753 [0.697, 0.803] | 0.877 | 0.008 | TribySpeaker 0.14 | — | — |
| rules any (ungated) | 0.564 [0.503, 0.623] | 0.486 | 7.660 | BelkinWemoSwitch 22.91 | — | — |
| lightgbm | 0.887 [0.844, 0.922] | 0.862 | 2.916 | iHome 23.28 | — | — |
| iforest | 0.407 [0.349, 0.468] | 0.789 | 0.211 | NestDropCam 4.65 | — | — |

per-capture recall (S1 / S2 / S3):
  CTU-13.Dataset-43: 0.75 / 0.00 / 0.00
  CTU-13.Dataset-44: 0.70 / 0.00 / 0.00
  CTU-13.Dataset-45: 0.40 / 0.00 / 0.00
  CTU-13.Dataset-47: 1.00 / 0.00 / 0.00
  CTU-13.Dataset-48: 0.00 / 0.00 / 0.00
  CTU-13.Dataset-50: 0.22 / 0.00 / 0.00
  CTU-13.Dataset-52: 0.00 / 0.00 / 0.00
  CTU-13.Dataset-53: 0.00 / 0.50 / 0.00
  CTU-13.Dataset-54: 0.24 / 0.00 / 0.00
  CTU-IoT-Malware-Capture-17-1: 1.00 / 1.00 / 1.00
  CTU-IoT-Malware-Capture-33-1: 1.00 / 1.00 / 1.00
  CTU-IoT-Malware-Capture-34-1: 0.93 / 0.13 / 0.13
  CTU-IoT-Malware-Capture-35-1: 1.00 / 1.00 / 1.00
  CTU-IoT-Malware-Capture-36-1: 1.00 / 1.00 / 1.00
  CTU-IoT-Malware-Capture-39-1: 1.00 / 1.00 / 1.00
  CTU-IoT-Malware-Capture-43-1: 1.00 / 1.00 / 1.00
  CTU-IoT-Malware-Capture-8-1: 1.00 / 0.04 / 0.04
  CTU-IoT-Malware-Capture-9-1: 1.00 / 1.00 / 1.00
```

## Per-dataset breakdown

Descriptive only: computed after the run with the same frozen models and thresholds. Nothing is tuned.

```
dev windows: IoT-23 373 (mal 215), CTU-13 171 (mal 27)
IoT-23 test: 289 windows, 147 malicious, 142 benign | recall S1 0.993 S2 0.755 S3 0.755 | benign-window alerts S1 23 S2 28 S3 23
CTU-13 test: 600 windows, 128 malicious, 472 benign | recall S1 0.320 S2 0.047 S3 0.000 | benign-window alerts S1 6 S2 11 S3 5

malicious windows per capture (S1 hits / total):
  CTU-13.Dataset-43: mal 4 (S1 3), benign 19
  CTU-13.Dataset-44: mal 23 (S1 16), benign 264
  CTU-13.Dataset-45: mal 5 (S1 2), benign 34
  CTU-13.Dataset-47: mal 3 (S1 3), benign 17
  CTU-13.Dataset-48: mal 1 (S1 0), benign 9
  CTU-13.Dataset-50: mal 60 (S1 13), benign 42
  CTU-13.Dataset-52: mal 3 (S1 0), benign 7
  CTU-13.Dataset-53: mal 12 (S1 0), benign 10
  CTU-13.Dataset-54: mal 17 (S1 4), benign 70
  CTU-Honeypot-Capture-4-1: mal 0 (S1 0), benign 22
  CTU-Honeypot-Capture-5-1: mal 0 (S1 0), benign 31
  CTU-IoT-Malware-Capture-17-1: mal 25 (S1 25), benign 0
  CTU-IoT-Malware-Capture-20-1: mal 0 (S1 0), benign 25
  CTU-IoT-Malware-Capture-21-1: mal 0 (S1 0), benign 25
  CTU-IoT-Malware-Capture-33-1: mal 25 (S1 25), benign 0
  CTU-IoT-Malware-Capture-34-1: mal 15 (S1 14), benign 10
  CTU-IoT-Malware-Capture-35-1: mal 2 (S1 2), benign 23
  CTU-IoT-Malware-Capture-36-1: mal 25 (S1 25), benign 0
  CTU-IoT-Malware-Capture-39-1: mal 9 (S1 9), benign 0
  CTU-IoT-Malware-Capture-43-1: mal 2 (S1 2), benign 0
  CTU-IoT-Malware-Capture-8-1: mal 24 (S1 24), benign 1
  CTU-IoT-Malware-Capture-9-1: mal 20 (S1 20), benign 5
```

## Reading

1. **Home false alerts are solved; recall is not.** S1 raises 0.003 false alerts per device-day on 27 unseen UNSW
   devices: about one per device per year, 47× under its limit. Its recall is 0.680 against ≥ 0.90.

2. **Cross-family generalisation is the failure.**
   - IoT-23 test: S1 recall **0.993**. Every Mirai/Gafgyt/Okiru-style capture is caught.
   - CTU-13 test: S1 recall **0.320**. Dataset-48, 52 and 53 are entirely missed; 50 (Neris-style, 60 windows)
     reaches only 13/60.
   - The training data had only **27 CTU-13 malicious windows**, against 215 for IoT-23. A logistic regression
     trained mostly on IoT scanning botnets learns "scanning = malicious". It does not learn 2011-era IRC/HTTP C2,
     spam or click-fraud.

3. **The dev estimate was optimistic.** Doc 31's leave-one-capture-out ablation gave CTU-13 recall 0.815 for 28
   features. Sealed CTU-13 gives 0.320. With 3 dev CTU-13 captures, leave-one-out could not show how far apart the
   scenarios are. **This is the main methodological lesson:** a dev protocol with three captures from one dataset
   cannot estimate generalisation to that dataset's other scenarios.

4. **S2 behaved as predicted** (doc 31, "Expectation recorded before the run"):
   - CTU-13 recall 0.047; the gated beacon misses established C2;
   - IoT-23 recall 0.755;
   - home 0.042 per device-day. That is 180× below the ungated rules (7.66), but one device, CanaryCamera, reaches
     8.68.

   R-D1 therefore stays a rejected trade-off: the gate removes home false alarms only by giving up C2 recall.

5. **S3 = S2 ∧ S1** inherits S2's recall: CTU-13 0.000, overall 0.404.

6. **Extras (not gated).**
   - LightGBM reaches recall 0.887 but makes 2.9 false alerts per device-day, far too noisy for a home.
   - The 32-feature logreg (with context) reaches 0.753 at 0.008/day. Its context features are not
     deployment-faithful on old captures (doc 31).

7. **Precision.** S1's 23 false alerts on IoT-23 benign windows sit inside malware captures (34-1, 35-1, 9-1 and
   others): hosts labelled benign in a lab capture that also contains the infected host.

## What follows (doc 31 stop rules, applied as written)

| Item | Decision |
|---|---|
| S1 as owner-notification tier | **not deployed** (recall 0.680 < 0.90) |
| S2 as kernel L0 rule set, R-D1 beacon gate | **not recommended**; no kernel change |
| S3 as enforcement-proposal tier | **not deployed**; doc 29 table stays at `rules_ver = 1` |
| heqk P5 (L1 behind M3) | stays **gated**; the integer S1 scorer (doc 32 §1) remains a validated *mechanism* only |
| IoT-23 and CTU-13 test splits | **spent** (`sealed.json`, PR #1503) |
| Next attempt | needs new sealed data (a new home capture or field study M6, and more C2 diversity in training); new pre-registration |

**What M3 does support.** These are measured on unseen data. They are facts about the systems, not passes:
- S1's home false-alert rate (0.003/device-day);
- detection of IoT scanning botnets (0.993).

The L0 kernel rules' known home false alarms (doc 28; DET-01) are unchanged by this result.

## Inputs

| Input | SHA-256 |
|---|---|
| `iot23_dev.jsonl` (dev build `windows-00af0005d9b1`, doc 28) | `fd2da8810d68a613ed0177f80a61365de9e7be510d67a81fac1d7fa954c04c89` |
| `ctu13_dev.jsonl` (dev build `windows-8ada671b2e1e`) | `af6599bad42d2b982b573095a45657a896f8fe98d7ce60d4f14ad5e96ed6fb0f` |
| `iot23_test.jsonl` (build `windows-f1677e2e31b2`) | `2abcb0d2c61601b4081d263083e128615d26c846b79a9ca2da65719e6ba9ab00` |
| `ctu13_test.jsonl` (build `windows-3a93dfd92bed`) | `96741d0440e2509e16b5ff0051c96d216d460ca4ac122e48b7f9c79c86f1ce0e` |
| `unsw_m3_second.jsonl` | `c8adabb1d18964ca8c52d91c525b11d83d04909a19a44791f9d259038d81799c` |

**Window counts.** `bench.load` keeps windows with ≥ 3 events, the same filter as dev. This gives:
- 889 test windows, out of 988 extracted (313 IoT-23 + 675 CTU-13);
- 14,360 home windows, out of 15,413 lines.

Addendum A's "counts lines" should read "counts lines with ≥ 3 events". The filter is part of the frozen code.
