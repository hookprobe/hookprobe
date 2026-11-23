# IPFIX / YAF flow records → DNA v1, checked on spent data (doc 35 M4 groundwork, 2026-11-23)

**Why.** The real-home holdout candidate for M4 (`unsw-iot-homes-ipfix`) ships as IPFIX/YAF flow CSVs, not PCAP.
intel-data has sealed it by name (#1524); nothing has been downloaded. This note builds and checks the converter on
**spent** data only (UNSW-IoTraffic: its first half was dev, its second half was spent by M3), so the holdout is
never touched before M4 is pre-registered.

## Tools (`tools/neuro-research/bench/`)

| Script | What |
|---|---|
| `ipfix_to_dna.py` | YAF/IPFIX biflow CSV → DNA v1 host-hour vectors. Column names are IPFIX information elements (`--map` renames). Device = each local endpoint, or `--device-cols` when the export names the device. Same aggregation, baseline and conn_state rules as the frozen UNSW path |
| `unsw_to_flows.py` | spent UNSW pcaps → synthetic YAF CSV, one file per device. The frozen connection loop plus a responder packet count and, for `--rule yaf`, YAF's 1800 s active timeout. `--rule zeek` = the frozen cut; `--rule yaf` = YAF defaults (300 s idle for all protocols, 1800 s active, FIN/RST ends a flow) |
| `s1_apply.py` | applies the frozen S1 model (`models/s1/s1_model.json`, hash-checked) to vectors; alerts per device-day and paired decision differences. Nothing is fitted |

## 1. Parity: the converter reproduces the frozen home vectors

`unsw_to_flows.py --rule zeek` → `ipfix_to_dna.py` (with the same lookup build), against `unsw_to_dna_conn.py --rule
zeek --half second` (itself equal to the frozen M3 home file):

```
reference windows 15299 (distinct ids); found 15299; missing 0; identical (x, n_events, host) 15086
duplicate ids in frozen file: 114 max copies 2
duplicates whose parts sum to the converter's merged window: 114
non-duplicate windows: 15185, differing: 99      (novel_pair_frac 80, log_mean_dur 19)
```

```
unsw_zeek_second.jsonl (frozen): windows (>= 3 events) 14360, S1 alerts 2, 0.003 per device-day
paired window ids 14269; S1 decisions differing 0
```

**Reading.**
- **0 S1 decisions differ.** The frozen M3 home figure (0.003 false alerts per device-day) is reproduced through the
  flow path.
- **A quirk of the frozen path, found here.** 114 device-hours appear **twice** in the frozen file (15,413 lines,
  15,299 distinct ids). An hour can be closed while a connection that started in it is still open; when that
  connection ends, the hour is re-opened and emitted again as a second window. The converter emits one window per
  device-hour, and every one of the 114 equals the sum of the two frozen parts. M3 counted those 114 as separate
  windows: 0.8% of the home windows, no effect on any result (0 decision differences).
- **The 99 remaining differences** are two benign approximations:
  - `novel_pair_frac`, 80 windows: the converter's baseline is "the previous 24 device-hours with flows". The frozen
    path also counts hours that had packets but no new flow.
  - `log_mean_dur`, 19 windows: timestamps travel as milliseconds with 3 decimals.

## 2. Exporter effect: YAF's cut vs the Zeek-like cut on the same traffic

The same spent second half, cut the way YAF does (`--rule yaf`), against the Zeek-like cut (`--rule zeek`), both
through `ipfix_to_dna.py`, restricted to each device's second half:

```
dna-zeek-second.jsonl: windows (>= 3 events) 14270, S1 alerts 2, 0.003 per device-day
dna-yaf-second.jsonl:  windows (>= 3 events) 14727, S1 alerts 3, 0.005 per device-day
paired window ids 14257; S1 decisions differing 3 (zeek only 1, yaf only 2); ids only in zeek 13, only in yaf 470
```

| feature (top 10 by p90 shift) | median diff (yaf − zeek) | p90 abs diff | windows changed |
|---|---|---|---|
| log_mean_dur | +3.871 | 5.486 | 91.0% |
| log_period_s | +0.000 | 5.066 | 46.0% |
| log_bytes_out | +0.215 | 3.408 | 87.0% |
| log_pkts_per_flow | +0.458 | 2.798 | 91.0% |
| log_bytes_in | +0.144 | 2.676 | 87.5% |
| log_out_in_ratio | +0.029 | 1.044 | 87.6% |
| warninglist_frac | +0.020 | 1.000 | 55.9% |
| port_entropy | +0.024 | 1.000 | 77.5% |
| periodic_cv | +0.000 | 0.910 | 46.0% |
| log_flows | +0.000 | 0.824 | 89.9% |

**Reading.**
- **The exporter's cut moves the vectors a lot.** YAF's 300 s UDP idle (Zeek-like: 60 s) merges repeated UDP
  exchanges into long flows, so mean duration rises by about 3.9 log units and bytes and packets per flow rise with
  it. The 1800 s active timeout splits long flows, so some hours gain flow starts (470 more windows).
- **The frozen S1's home false-alarm rate barely moves:** 0.003 → 0.005 per device-day (2 → 3 alerts on about
  14,500 windows), 3 paired decisions differ.
- **What this does not show.** The effect on **recall**. The malicious side of S1's training (IoT-23, CTU-13) exists
  only as Zeek-cut records. Attack windows cut by YAF could score differently; there is no spent YAF-cut attack
  data to check it on.

## For the M4 pre-registration (not decided here)

1. **The home holdout's cut is the exporter's.** It cannot be re-cut from flow records. Measure home false alarms
   under the YAF cut as they come, and quote §2 as the known exporter effect (0.003 → 0.005 on spent data).
2. **Check the export's timeouts first.** If the holdout's YAF settings are documented, run `unsw_to_flows.py`
   with those values on spent data before the look, and pre-register that number as the expected shift.
3. **The converter's device rule.** "Every local endpoint" assumes stable addresses. Under DHCP a device can change
   address within the capture; if the export carries MAC columns, use them via `--device-cols`.
4. **The frozen path's duplicate hours** (§1) do not change M3, but M4 should count one window per device-hour on
   every side.
5. **Everything above used spent data only.** The holdout stays sealed, unread and unlisted until the
   pre-registration is pushed and the operator approves the download.

## Reproduce

```bash
python3 -I tools/neuro-research/bench/unsw_to_flows.py <UNSW pcap dir> <out>/flows-zeek --rule zeek
```

```bash
python3 -I tools/neuro-research/bench/ipfix_to_dna.py <out>/dna-zeek.jsonl <out>/flows-zeek/*.csv --dataset unsw-iotraffic --device-cols device,deviceAddress --lookup <lookup build>
```

```bash
python3 -I tools/neuro-research/bench/s1_apply.py <unsw_to_dna_conn.py --rule zeek --half second output> <out>/dna-zeek.jsonl
```

Repeat the first two with `--rule yaf`, then restrict both to each device's second half: from its first hour in the
frozen second-half file onwards.
