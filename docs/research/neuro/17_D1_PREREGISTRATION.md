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
