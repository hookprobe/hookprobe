# 37: M4, the L1-IoT sealed test of the frozen S1 model (pre-registration, 2026-11-23)

Written **before** either sealed set is acquired. Kitsune (#1515) and `unsw-iot-homes-ipfix` (#1524) are sealed
by name in `tools/intel-data/registry/sealed.json`: no data, no hashes, never opened. Everything below was built and
checked on **spent** data only (doc 35 §1, `data/ipfix-to-dna.md`, §5 here).

**Question.** Doc 35 split L1 by device class. Does the **frozen** M3 S1 model, unchanged, detect infected IoT
devices on a new lab's captures while staying quiet in new real homes?

## 1. Candidate (frozen; nothing is fitted)

- `tools/neuro-research/models/s1/s1_model.json`, SHA-256
  `20f38f337863a934d825fd0cfecf57609865779a60cfd702063ff41a32c81df5`: 28 features, logistic regression, its
  threshold as frozen. `s1_apply.load_model` refuses any other file.
- The integer twin (`os/neuro/neuro-l1`) makes the same decisions on every window checked (doc 35 §4). M4 scores
  with the float form.

## 2. Data (evaluation only; never training)

| Role | Source | What is used | Cut |
|---|---|---|---|
| IoT malware | `kitsune-network-attack` (UCI 516; licence OPEN) | all 9 captures; the **gated** set is the capture(s) whose name contains `mirai` | the kernel's doc 20 rule, from PCAP (`pcap_to_dna.py --rule doc20`) |
| Home benign | `unsw-iot-homes-ipfix` (12 homes, KDDI; RESEARCH, evaluation use only) | every home and device | the **exporter's** YAF cut; flow records cannot be re-cut (`data/ipfix-to-dna.md` §2) |

**Acquisition.** intel-data downloads each set only after the operator approves (size stated in the request), into
its own directory, and records file hashes in `sealed.json` **before** any Neuro script reads it.

## 3. Pipeline (pinned scripts)

| Step | Script | SHA-256 |
|---|---|---|
| Kitsune PCAP → device-hour vectors, with per-frame labels | `bench/pcap_to_dna.py` | `f35c718cb0cdda2bad87b904a22dd49156e4a724c53acedd74df39e7404f9e45` |
| Home IPFIX CSV → device-hour vectors | `bench/ipfix_to_dna.py` | `941a32b26e6d7e5d2efcf67b204579d546663dd0186c9b1ae6ec5ccbabacafde` |
| Intake counts (model never loaded) and the one look | `bench/m4_gate.py` | `bea93c3350bc75a2d2bde7d03d06cd90a8b417feb6496a7c2a11c0f0b5f0b84b` |
| Frozen helpers | `bench/unsw_to_dna.py`, `unsw_to_d1.py`, `bench/dna_features.py`, `bench/s1_apply.py` | unchanged at `b4611dea` (#1526) |

**Commands.**

```bash
python3 -I tools/neuro-research/bench/pcap_to_dna.py $M4/kitsune.jsonl <each capture pcap> --labels <its labels csv> ... --lookup <lookup build> --rule doc20 --dataset kitsune
```

```bash
python3 -I tools/neuro-research/bench/ipfix_to_dna.py $M4/homes.jsonl <each home csv> --dataset unsw-iot-homes --lookup <lookup build> [--map ...] [--device-cols ...]
```

```bash
python3 -I tools/neuro-research/bench/m4_gate.py --counts $M4/kitsune.jsonl $M4/homes.jsonl
```

```bash
python3 -I tools/neuro-research/bench/m4_gate.py $M4/kitsune.jsonl $M4/homes.jsonl
```

**Labels and devices.**
- **Kitsune devices:** every LAN MAC that sends IPv4 from a local address, minus MACs that forward remote-source
  traffic (≥ 1% of their IPv4 packets; routers). 0.0.0.0 counts as neither.
- **Kitsune labels:** the per-frame label file, aligned by frame order. A device-hour is **malicious** if the device
  sent at least one attack-labelled IP frame in it. The converter stops if the label rows and frames differ in count.
- **Home devices:** each local endpoint address. If the header carries a per-row device MAC column, it is used via
  `--device-cols` instead (decided from the header alone, at intake).
- **Home labels:** every home window is benign. A home is excluded only if the dataset's own documentation says it
  contained compromised or attack traffic, and only before the look. No alert is relabelled afterwards.

## 4. Gate (`m4_gate.py`; one look)

| # | Condition | Minimum to decide |
|---|---|---|
| 1 | **Mirai recall ≥ 0.90**: malicious device-hours (≥ 3 events) in the Mirai capture(s) that S1 alerts on | ≥ 20 such windows |
| 2 | **Home false alerts ≤ 0.14 per device-day** (24 × alerts / scored windows, every device; as M3) | ≥ 2,400 scored windows (100 device-days) |

- **PASS** if both hold with both minimums met.
- **FAIL** if either fails, whatever the minimums.
- **INCONCLUSIVE** if neither fails but a minimum is not met. INCONCLUSIVE is never read as a pass.
- Also reported, **not gated:** recall on the other eight captures' attacking hosts (mostly the attacker's machine,
  outside L1-IoT's scope); alerts on the lab's benign device-hours; Wilson 95% interval; worst five home devices.

**What PASS would mean.** The frozen S1 enters the L1-IoT design as the candidate for an EL0 L1 server (doc 32
§1), behind heqk's signed-package and sealed-pass gates (D3). It is **not** an enforcement change: S1 notifies; it
does not block. **FAIL** closes S1 for L1-IoT; doc 35's refit findings (§1E) then say a new model must re-earn the home
side on new data.

## 5. Checked on spent data before this was written

| Check | Result |
|---|---|
| `pcap_to_dna.py` (auto MACs, doc 20) vs `unsw_to_dna_conn.py --rule doc20` on all 27 spent UNSW pcaps, own device | **31,676 of 31,676 windows identical** (vectors, event counts, host). All 27 devices found automatically; the gateway MAC excluded in every file |
| `ipfix_to_dna.py` vs the frozen home vectors (Zeek cut) | 0 S1 decision differences on 14,269 paired windows (`data/ipfix-to-dna.md` §1) |
| Exporter effect, YAF vs Zeek-like cut, spent UNSW home | 0.003 → 0.005 false alerts per device-day (§2 there) |
| `m4_gate.py` dry run, spent stand-ins (§6) | mechanics only: a label file 5 rows short → STOP; a benign UNSW device given fake "mirai" labels → 0 / 284 detected, FAIL; YAF-cut spent home as the home side → 0.005 per device-day, as `data/ipfix-to-dna.md` |

## 6. Known gaps, stated now

1. **Power.** Kitsune's captures are short lab recordings. The number of Mirai device-hours is unknown until
   intake and may be below 20. If `--counts` shows that, this document is amended **before the look** to add a
   second sealed IoT malware source (CICIoT2023 or Stratosphere MCFP, after a registry licence decision). Counts are
   not outcomes; nothing is scored at intake.
2. **Two cuts.** The malware side is cut with the kernel's rule; the home side with YAF's. On spent data the
   exporter moved home false alerts 0.003 → 0.005; recall under YAF is unmeasured. No correction is applied.
3. **One lab, one botnet.** A pass shows S1 on Mirai in one camera-and-IoT lab. It does not cover other families.
4. **Intake amendments.** Before the look, only plumbing may change (label alignment, column mapping, a parse
   failure), each pushed here with its reason and new hashes. After the look nothing changes.

## 7. Order

1. This document is merged.
2. Operator approves the two downloads; intel-data acquires them and records hashes.
3. Intake: convert both, run `m4_gate.py --counts`, push the counts and output hashes here.
4. If the minimums are met: one look with `m4_gate.py`. If not: amend per §6.1 first.
5. Results in `data/m4-results.md`, whatever the verdict.
