# 37: M4, the L1-IoT sealed test of the frozen S1 model (pre-registration, 2026-11-23)

Written **before** any sealed set is acquired. Kitsune (#1515) and `unsw-iot-homes-ipfix` (#1524) are sealed
by name in `tools/intel-data/registry/sealed.json`: no data, no hashes, never opened. The second malware source,
Stratosphere MCFP (§2), was added before acquisition (amendment A, §8). Everything below was built and
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
| IoT malware | `kitsune-network-attack` (UCI 516; licence OPEN) | all 9 captures; the **gated** part is the capture(s) whose name contains `mirai` | the kernel's doc 20 rule, from PCAP (`pcap_to_dna.py --rule doc20`) |
| IoT malware | `ciciot2023` (CIC, UNB; RESEARCH, evaluation use only; amendment B, §9) | the Mirai-category captures are **gated**; every other category is reported only | doc 20 rule, from PCAP |
| IoT malware | `stratosphere-mcfp-captures`: the `CTU-IoT-Malware-Capture-*` captures **not** among IoT-23's 20 malware captures (selection rules in §8) | every selected capture is **gated** | doc 20 rule, from PCAP |
| Home benign | `unsw-iot-homes-ipfix` (12 homes, KDDI; RESEARCH, evaluation use only) | every home and device | the **exporter's** YAF cut; flow records cannot be re-cut (`data/ipfix-to-dna.md` §2) |

**Acquisition.** intel-data downloads each set only after the operator approves (size stated in the request), into
its own directory, and records file hashes in `sealed.json` **before** any Neuro script reads it.

## 3. Pipeline (pinned scripts)

| Step | Script | SHA-256 |
|---|---|---|
| Kitsune and MCFP PCAP → device-hour vectors, with per-frame or per-host labels | `bench/pcap_to_dna.py` | `90ff273cfe07742e5daa2290ea96d39191fba5ae7dd7763d5ba61d39d1df6e2f` |
| Home IPFIX CSV → device-hour vectors | `bench/ipfix_to_dna.py` | `941a32b26e6d7e5d2efcf67b204579d546663dd0186c9b1ae6ec5ccbabacafde` |
| Intake counts (model never loaded) and the one look | `bench/m4_gate.py` | `9d406bd3e08c47820df95aab3bc50acf7ed27c58ff65c7bd92f7a46e42b03ce6` |
| Frozen helpers | `bench/unsw_to_dna.py`, `unsw_to_d1.py`, `bench/dna_features.py`, `bench/s1_apply.py` | unchanged at `b4611dea` (#1526) |

**Commands.**

```bash
python3 -I tools/neuro-research/bench/pcap_to_dna.py $M4/kitsune.jsonl <each capture pcap> --labels <its labels csv> ... --lookup <lookup build> --rule doc20 --dataset kitsune
```

```bash
python3 -I tools/neuro-research/bench/pcap_to_dna.py $M4/mcfp.jsonl <each capture pcap> --labels infected:<its documented host IPs> ... --lookup <lookup build> --rule doc20 --dataset mcfp
```

```bash
python3 -I tools/neuro-research/bench/ipfix_to_dna.py $M4/homes.jsonl <each home csv> --dataset unsw-iot-homes --lookup <lookup build> [--map ...] [--device-cols ...]
```

```bash
python3 -I tools/neuro-research/bench/m4_gate.py --counts $M4/malware.jsonl $M4/homes.jsonl
```

```bash
python3 -I tools/neuro-research/bench/m4_gate.py $M4/malware.jsonl $M4/homes.jsonl
```

**Labels and devices.**
`$M4/malware.jsonl` is `kitsune.jsonl` followed by `mcfp.jsonl`.

- **Malware-side devices (both sources):** every LAN MAC that sends IPv4 from a local address, minus MACs that forward remote-source
  traffic (≥ 1% of their IPv4 packets; routers). 0.0.0.0 counts as neither.
- **Kitsune labels:** the per-frame label file, aligned by frame order. A device-hour is **malicious** if the device
  sent at least one attack-labelled IP frame in it. The converter stops if the label rows and frames differ in count.
- **MCFP labels:** by host. Every IP frame sent from an infected address that the capture's own documentation names
  is an attack frame, so every device-hour of the infected device with traffic is malicious.
- **Home devices:** each local endpoint address. If the header carries a per-row device MAC column, it is used via
  `--device-cols` instead (decided from the header alone, at intake).
- **Home labels:** every home window is benign. A home is excluded only if the dataset's own documentation says it
  contained compromised or attack traffic, and only before the look. No alert is relabelled afterwards.

## 4. Gate (`m4_gate.py`; one look)

| # | Condition | Minimum to decide |
|---|---|---|
| 1 | **IoT-malware recall ≥ 0.90**, pooled: malicious device-hours (≥ 3 events) in Kitsune's Mirai capture(s) and in every MCFP capture that S1 alerts on | ≥ 20 such windows |
| 2 | **Home false alerts ≤ 0.14 per device-day** (24 × alerts / scored windows, every device; as M3) | ≥ 2,400 scored windows (100 device-days) |

- **PASS** if both hold with both minimums met.
- **FAIL** if either fails, whatever the minimums.
- **INCONCLUSIVE** if neither fails but a minimum is not met, or a side has no scored windows. INCONCLUSIVE is never
  read as a pass.
- Also reported, **not gated:** recall per source (Kitsune-Mirai, MCFP); recall on the other eight captures' attacking hosts (mostly the attacker's machine,
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
| Amendment A re-checks (§8) | the unlabelled path is byte-identical after the change (1,240 windows, two pcaps); the frame-label path is identical to the dry run above; per-host labels mark only the named host; pooled and per-source recall print; an empty gated set → INCONCLUSIVE |

## 6. Known gaps, stated now

1. **Power.** Kitsune's Mirai capture is the smallest of its nine (8.1 MB compressed, per intel-data's size check),
   so it alone very likely gives fewer than 20 device-hours. MCFP was therefore added **before** acquisition
   (amendment A). If the pooled count is still below 20 at intake, the verdict is INCONCLUSIVE; no further source is
   added after counts exist. Counts are not outcomes; nothing is scored at intake.
2. **Two cuts.** The malware side is cut with the kernel's rule; the home side with YAF's. On spent data the
   exporter moved home false alerts 0.003 → 0.005; recall under YAF is unmeasured. No correction is applied.
3. **Same lab as training.** MCFP comes from the Stratosphere lab, as IoT-23 (S1's training source) does: new
   captures, the same capture setup. If MCFP windows dominate the pool, a pass shows S1 on new infections in a known
   lab more than on a new lab. Kitsune-Mirai recall is reported on its own for that reason.
4. **Host labels are coarse.** Every hour of an MCFP infected device counts as malicious, including quiet hours of
   the malware. That makes the recall bar harder, not easier.
5. **Intake amendments.** Before the look, only plumbing may change (label alignment, column mapping, a parse
   failure), each pushed here with its reason and new hashes. After the look nothing changes.

## 7. Order

1. This document is merged.
2. Operator approves the downloads; intel-data acquires them and records hashes (MCFP: also the per-capture licence
   decision and the documented infected IPs, §8).
3. Intake: convert all three, run `m4_gate.py --counts`, push the counts and output hashes here.
4. One look with `m4_gate.py`, whatever the counts. Below a minimum the verdict is INCONCLUSIVE (§4).
5. Results in `data/m4-results.md`, whatever the verdict.

## 8. Amendment A (2026-11-23, before any acquisition): Stratosphere MCFP as the second IoT malware source

**Why.** intel-data's size check showed Kitsune's Mirai capture is far smaller than the other eight (§6.1). The
operator chose MCFP over CICIoT2023. Nothing had been downloaded, so no count or outcome informed this.

**Selection (fixed now; intel-data applies it and records the result in `sealed.json` before any Neuro read).**
1. Candidates: every `CTU-IoT-Malware-Capture-<n>-<m>` capture in MCFP whose id is **not** one of IoT-23's 20
   malware captures. Honeypot and benign captures are excluded.
2. Licence: intel-data's per-capture pass. A capture with no clear licence is excluded before download.
3. Labels: the capture's own documentation (README or page) must name the infected host's IP address(es). A capture
   without one is excluded before download. The named IPs are recorded with the capture's hashes.
4. A PCAP must be available. Captures with only flow logs are excluded.
5. Size: at most 100 GB in total for MCFP. If the eligible captures exceed it, they are taken in ascending capture
   number until the cap.
6. Each capture goes into the sealed MCFP directory and is hashed. Nothing is opened beyond hashing until intake.

**Code changes (re-pinned in §3).**
- `pcap_to_dna.py`: `--labels infected:IP[,IP]` labels by host. The unlabelled and per-frame paths are unchanged
  (§5).
- `m4_gate.py`: condition 1 pools Kitsune-Mirai and MCFP; recall is reported per source; a side with no scored
  windows is INCONCLUSIVE, not FAIL.

**Unchanged:** the model, the bars (0.90, 0.14), the minimums (20, 2,400), the home side, one look.

## 9. Amendment B (2026-11-23, before any count exists): CICIoT2023 replaces MCFP as the second malware source

**Why.** MCFP could not pass §8: its host still times out, and the only known mirror holds CTU-13, not the IoT
captures (intel-data, 2026-11-23). The four MCFP candidates stay sealed by name (#1530) and enter only if the host
returns before intake. The operator chose CICIoT2023 and registers for it. No intake count existed when this was
written: the intake is held until amendment B is merged.

**Selection (intel-data applies it and records the result in `sealed.json` before any Neuro read).**
1. Source: `ciciot2023`, PCAPs only. Gated: every capture of the **Mirai** category. All other categories may be
   reported, not gated; their PCAPs are fetched only if the size cap allows after the Mirai ones.
2. Size: at most 100 GB in total for CICIoT2023, Mirai captures first, then in the site's listing order.
3. Labels: by host. Every IP frame sent from an attacking device's address is an attack frame. The paper (Sensors
   23(13):5941) names no attacking address. It says Mirai ran from five of the testbed's Raspberry Pis, and its
   Table 1 lists the ten Raspberry Pi MACs (recorded by intel-data, #1534). So intake applies this rule, to counts
   only and before scoring: in each Mirai capture, an **attacker** is one of those ten MACs that sends at least 10%
   of the capture's IP frames; its IPv4 source addresses in that capture are passed as `--labels infected:`. If no
   Pi qualifies in a capture, that capture is reported, not gated.
4. Each capture is hashed into the sealed CICIoT2023 directory. Nothing is opened beyond hashing until intake.

**Code.** `m4_gate.py` gains a third gated source, `ciciot2023-mirai`, so condition 1 now pools Kitsune-Mirai,
MCFP and CICIoT2023-Mirai (§3 re-pinned). A dry run with stand-ins checks that CICIoT2023 Mirai is gated and its
other categories are reported only. `pcap_to_dna.py` is unchanged: `--labels infected:` already labels by host.

**Unchanged:** the model, the bars (0.90, 0.14), the minimums (20, 2,400), the home side, one look.

**Limit added.** CICIoT2023's Mirai captures are volumetric floods from lab devices. S1 learnt Mirai from IoT-23's
scanning and C2. Recall per source stays reported, so the reader can see which lab drives the pooled number.

## 10. Amendment C (2026-11-23, before any CICIoT2023 file is downloaded): which Mirai files

**Why.** The CICIoT2023 PCAP folder is about 500 GB, and each Mirai variant is split by tcpdump into files of at most
2 GB: `Mirai-greeth_flood` holds the base file plus `…1` to `…28`. Downloads are one click each, in the operator's
registered browser session. §9.2's "listing order until 100 GB" would take one variant and skip the others. So it
is replaced, before any file or count exists, by:

**Rule.** For each of the three Mirai variants (`Mirai-greeth_flood`, `Mirai-greip_flood`, `Mirai-udpplain`), take
the base file plus files `1` to `15` in numeric order: at most 16 files per variant, and at most 96 GB in the 2 GB
worst case. A variant with fewer files contributes all of them.

**If a download stops early.** The subset is whatever was complete, in that numeric order, when the operator
stopped. It is recorded with the hashes before intake. No file is added after intake counts exist.

**Unchanged:** §9.3's Raspberry Pi MAC rule (labels), gating on the Mirai category, the bars and minimums, one look.

**Power note, stated now.** Device-hour windows depend on how long each capture runs, not on its size. A 2 GB file
of flood traffic may span minutes, so more files may add few new hours. Whether the gated minimum of 20 is reached
is known only at intake; if not, the verdict is INCONCLUSIVE (§4).

## 11. Amendment D (2026-11-23, intake plumbing, before any count): the homes export is not IE-named

**Found at intake** (stage "headers": file names and CSV header lines only, plus summaries of plumbing columns on
200,000 rows of one home; no window, count or score). The 12 home CSVs are UNSW's "ML instance" export, not YAF/IPFIX
information elements:
- `start` is a millisecond datetime;
- `duration` is in seconds, capped at exactly 1,800, YAF's active timeout, which confirms §6.2's exporter cut;
- `src` is always the initiator (`deviceInitiated` = 1 when the device's MAC is `srcMac`, 0 when it is `destMac`,
  in 100% of the sampled rows);
- byte and packet counts are from the device's side (out/in);
- each row names its device, whose MAC is on every one of its rows.

**Fix (plumbing, §6.5).** `bench/homes_ml_to_yaf.py` (SHA-256 `012c8c1cfbfe062854078571dabb7098ab3cbe9e154bb403547267705e39388f`) rewrites each row into the YAF biflow CSV that
`ipfix_to_dna.py` reads:
- end = start + duration;
- initiator/responder counts from out/in, by `deviceInitiated`;
- device = its MAC (`--device-cols deviceMac,deviceAddress`), as §3 prefers when the export carries one.

No row is dropped. `ipfix_to_dna.py` is unchanged.

**Check on spent data.** A spent UNSW YAF-cut flow file was rewritten into the ML-instance layout and passed back
through the adapter and `ipfix_to_dna.py`: 1,880 device-hours, **0 S1 decision differences**. The 209 differing
vectors are sub-millisecond rounding (periodicity CV ≤ 0.003, mean duration ≤ 2e-5), the precision the export itself
has.

**Unchanged:** the homes set, the bars and minimums, the model, one look.

## 12. Intake (2026-11-23), recorded before the look

**Data.** The final malware side is Kitsune only: MCFP was unreachable (§8) and CICIoT2023 was dropped by the
operator (§9–10, subset final and empty). The home side is the 12 homes. All 43 files matched their `sealed.json`
hashes (#1541) before reading.

**Aborted first run.** It was started and stopped within minutes when the operator weighed holding M4 for
CICIoT2023. It had converted only the first, non-gated capture (Active Wiretap). Its partial output was set aside
unread and the operator then chose to run now; the run below is the full one.

**Conversion.**
- Kitsune: 9 captures, every frame-label file aligned with its capture; no router MAC excluded.
- Homes: 12 CSVs, 13.1 M rows through `homes_ml_to_yaf.py`, then 502 devices and 188,707 device-hours from
  `ipfix_to_dna.py`. Broadcast and multicast peers and non-TCP/UDP/ICMP rows were skipped, as frozen.

**Counts** (`m4_gate.py --counts`; windows with ≥ 3 events):

| Set | Malicious windows | Benign windows |
|---|---|---|
| **Kitsune Mirai (gated)** | **18** | 30 |
| Kitsune, other 8 captures (reported only) | 1–5 each | 1–10 each |
| **Homes** | — | **175,145** (474 devices) |

**Power.** The gated malware side has **18 < 20** windows, so condition 1 cannot reach PASS: by §4, recall ≥ 0.90
gives INCONCLUSIVE, and recall < 0.90 is a FAIL. The home side has 175,145 ≥ 2,400 windows, about 7,300
device-days, so condition 2 is decided.

**Output hashes (SHA-256).**
- `kitsune.jsonl` = `malware.jsonl`: `ba2817cb45408e2c6c2f3569048c693912c390c6b2bf46659a7250c224362c42`
- `homes.jsonl`: `9be55bc233df2d2d7ba04b1170d731a24373019af0338d105b6570c04044149f`

**Next.** One look with `m4_gate.py malware.jsonl homes.jsonl`, unchanged.
