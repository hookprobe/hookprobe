# 17 — D1 pre-registration: the temporal engine on months of real device traffic (UNSW-IoTraffic)

> 2026-11-19. **Committed before the data was downloaded or seen.** Plan: `14` P1/P2. It extends `15`
> (P2 on IoT-23, preliminary).

## Data

**Source.** UNSW-IoTraffic: UNSW Sydney (Wannigama, Sivanathan, Habibi Gharakheili), Dryad
`doi:10.5061/dryad.w0vt4b94b`, version 392848, **CC0-1.0**.
- Content: 27 consumer IoT devices, about 203 days, raw packet captures (`pcaps.zip`, SHA-256
  `feb647d4…`).
- It is a **lab testbed**: real devices talking to their real clouds, but no people in the home.
  Nuisance rates may therefore be **optimistic** compared with a lived-in home.

**Conversion** (`tools/neuro-research/unsw_to_d1.py`). Packets become the engine's own inputs, in the
format of `dna_fixed.py` and `el0-neuro`:

| Field | Definition |
|---|---|
| Device | the UNSW device identity (its MAC address). Every IPv4/IPv6 address the device uses maps back to it. |
| Peer | `fingerprint(peer_key(ipv4, port))` for IPv4 peers. For IPv6 peers: `fingerprint(fnv1a64(ipv6 bytes ‖ port))`. Flows are counted per new connection (TCP SYN, or the first UDP packet of a 5-tuple after 120 s of silence). |
| DNS | per query the device sends: `fingerprint(fnv1a64(registered domain))`, where the registered domain is the last two labels, or three when the second-to-last is ≤ 3 characters (a simple, pinned rule). NXDOMAIN is taken from the matching response's rcode = 3. |
| Per device-hour | the hour of day in UTC; bytes sent; connections; the peer and DNS events above |
| Never written | addresses, names, payloads |

## Splits (fixed now)

- **Time:** for each device, its first 50% of active days are *history* (learning, training and
  tuning), the next 25% are *dev*, the last 25% are *test*. Test is opened once.
- **Devices:** 5 of the 27, chosen by `sha256(device id) % 27 < 5`, are **held out entirely**. They
  are used for test only, to check that nothing learned is specific to one device.

## Questions and metrics

**Q1. Nuisance (the ship gate).**
- Benign alarms per device per week of the integer DNA (`el0-neuro`, unchanged) on the test portion,
  at the fixed engine threshold (score ≥ 1.0).
- **Gate:** ≤ 1 per device per week, reported per device and as a median.
- Everything in this testbed is assumed benign except any labelled attack periods. If the authors
  label none, every hour is benign.

**Q2. The DNS false-alarm fix.**
- Candidate rule: the NX term counts only when the hour has ≥ `q_min` DNS queries.
- `q_min` is chosen on **dev** from {3, 5, 10, 20}, as the smallest value reaching ≤ 1 alarm per device
  per week, with detection of the semi-synthetic DGA onsets (below) ≥ 0.9.
- Reported on test once.

**Q3. Detection on real device timelines (semi-synthetic, as in `15`).**
- Real attack hours (IoT-23 malware hours, and the generator's DGA, scan and exfil bursts) are spliced
  into **test-period** timelines of the held-out and regular devices.
- Metrics: incident detection within 4 h at the fixed threshold; hour-level AUC.

**Q4. Learned cell, second try (`15` candidate B, unchanged design).**
- Ridge readout trained on *history* hours of non-held-out devices; ridge chosen on dev.
- Same decision rule as `15`: it wins only with ≥ 0.02 AUC over the DNA at ≤ equal bytes per device,
  without raising nuisance.

## Decisions this can take

- **If Q1 passes with the Q2 fix:** the DNA (plus the DNS rule) is cleared for P5 integration on
  usefulness grounds.
- **If Q1 fails even with Q2:** the temporal tier does **not** ship as an alarm source. It stays as an
  evidence feature, with no alarms of its own, until a fix passes a new pre-registration.
- **Q4** is decided by the rule above.

## Analysis addendum (2026-11-19, after conversion, before any score was computed)

The data was received and converted. Only coverage (devices, hours, days) was looked at: no engine score,
alarm or detection number existed when this was written. Implementation: `tools/neuro-research/d1_analysis.py`.

**A1. Data received.**
- The browser auto-extracted `pcaps.zip`, so its SHA-256 could not be checked.
- Integrity rests on the archive tool's per-member CRC-32 check during extraction.
- 27 files (26 `.pcap`, 1 `.pcapng`, 27 GB) match the 27 documented devices.
- Conversion: 95,543,405 packets became 37,555 device-hours for 27 devices. Each device is identified by the MAC address in its file name (`--macs`).

**A2. Clock errors.**
- 9 device-hours carry timestamps before 2016-09-01 (1970 or 1981), on 4 devices. They are dropped.
- The rest of the data spans 2016-09-22 to 2017-04-13.

**A3. Held-out devices.**
- The rule `sha256(device id) % 27 < 5` is applied to the converter's MAC string (`aa:bb:cc:dd:ee:ff`).
- It selects **7** devices, not the 5 the text expected: AwairAirQuality, BelkinWemoMotionSensor, HPPrinter, PhilipsHue, TPLinkSmartPlug, WithingsSleepSensor and WithingsSmartScale.
- The rule as written is kept. Disclosure: the colon-free MAC form was also computed and gives a different set. The colon form was chosen because it is the identity the converter writes.

**A4. Engine run.**
- `dna_fixed.DNAFixed` is fed event by event (bit-exact with `el0-neuro`). An hour is closed only if the device had traffic in it, as `el0-neuro` does.
- The engine streams history unscored, then dev. For test it streams history and dev unscored, then test.

**A5. Semi-synthetic attacks (Q2, Q3).**
- Attacks are **overlaid** on a real device hour: added on top of that hour's own traffic.
- 8 deterministic onsets per device, per kind, per period.
- Kinds:
  - DGA: 150 NX queries per hour to random registered domains, for 4 h. Random subdomains of a single parent would collapse to one fingerprint under the pinned eTLD rule.
  - Scan: 59 LAN hosts × {22, 445}, 118 connections, 1 h.
  - Exfiltration: +2 GB to one new peer, 1 h.
  - IoT-23: up to 4 consecutive malicious hours of an infected host. They come from the IoT-23 **dev** split for the dev period and the **test** split for the test period.
- An incident counts as detected when an alarm (score ≥ 1.0) fires in one of its attack hours.
- AUC: attack hours against the period's benign hours.

**A6. How Q1 and Q2 are read.**
- Alarms per week = alarms in the period ÷ (the device's active days in that period ÷ 7).
- The median uses devices with ≥ 7 active days in the period. For the test period that is 21 of the 27 devices; the other 6 are listed but not counted in the median.
- **Gate:** passed when that median is ≤ 1. The strict reading (every device ≤ 1) is reported next to it, and each device above 1 is named.
- Q2 chooses `q_min` on dev with the same median.

**A7. Q4.**
- The readout is trained on the history hours of non-held-out devices, and the ridge is chosen on dev by AUC.
- B's threshold is calibrated on dev benign hours at 1 alarm per device-week.
- "Without raising nuisance" means B's test median ≤ the DNA's test median.
- Labelled attack periods: the authors' README was not downloaded, so none are known. Every hour is treated as benign (as pre-registered).
