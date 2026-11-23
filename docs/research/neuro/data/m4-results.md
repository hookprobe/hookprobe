# M4 result: the frozen S1 model on Kitsune and 12 real homes (doc 37, one look, 2026-11-23)

**Verdict: FAIL.** Condition 1 (IoT-malware recall) fails, and it is also underpowered. Condition 2 (home false
alerts) passes. Under doc 37 §4, a failed condition is a FAIL whatever the minimums. **S1 is closed as the L1-IoT
candidate.**

## Inputs (all recorded before the look, doc 37 §12)

| Item | Value |
|---|---|
| Model | `s1_model.json`, SHA-256 `20f38f33…` (frozen M3 S1, hash-checked by the gate) |
| Gate | `m4_gate.py`, SHA-256 `9d406bd3…` (on main) |
| Malware vectors | `malware.jsonl` `ba2817cb…`: Kitsune, 9 captures, doc 20 cut, frame labels |
| Home vectors | `homes.jsonl` `9be55bc2…`: 12 homes, YAF cut (exporter's), via `homes_ml_to_yaf.py` |

## Output (unedited)

```
| capture | malicious windows | detected | recall | benign windows | alerts on benign |
|---|---|---|---|---|---|
| ARP MitM_pcap | 5 | 0 | 0.000 | 0 | 0 |
| Active Wiretap_pcap | 4 | 0 | 0.000 | 3 | 0 |
| Fuzzing_pcap | 2 | 0 | 0.000 | 1 | 0 |
| Mirai_pcap | 18 | 4 | 0.222 | 30 | 3 |
| OS Scan_pcap | 2 | 1 | 0.500 | 3 | 0 |
| SSDP Flood_pcap | 2 | 0 | 0.000 | 10 | 7 |
| SSL Renegotiation_pcap | 2 | 0 | 0.000 | 6 | 4 |
| SYN DoS_pcap | 1 | 1 | 1.000 | 10 | 8 |
| Video Injection_pcap | 2 | 0 | 0.000 | 5 | 0 |
malicious windows skipped (< 3 events): 0
recall by source (not gated): kitsune-mirai 4 / 18 = 0.222

GATED
  pooled IoT-malware recall: 4 / 18 = 0.222 (Wilson 95% 0.090-0.452); need >= 0.90 with >= 20 windows
  home false alerts: 735 on 175145 windows (474 devices) = 0.101 per device-day; need <= 0.14 with >= 2400 windows
  worst home devices: 6a:16:31:42:27:3d 15.16 (12/19), ac:e4:b5:e6:02:bd 14.63 (64/105), b6:a7:f7:e0:fa:6d 12.00 (2/4), 60:8b:0e:0e:55:86 12.00 (5/10), da:79:ce:77:f3:83 8.00 (1/3)
VERDICT: FAIL (recall 0.222 < 0.90) [also underpowered: gated malware windows 18 < 20]
```

## Reading (descriptive; nothing below changes the verdict)

1. **Recall on a new lab's Mirai is far below IoT-23's.** S1 reached 0.993 on unseen IoT-23 malware captures
   (doc 35). On Kitsune's Mirai it catches 4 of 18 infected-device hours. Even the upper end of the 95% interval
   (0.45) is far below the 0.90 bar. The IoT-23 number does not transfer to another lab. Possible reasons, not
   tested here:
   - Kitsune's devices are cameras on a lab network, whose infection hours look unlike IoT-23's Raspberry Pi;
   - labelling an hour malicious after a single attack frame counts light hours;
   - the doc 20 cut differs from S1's Zeek-cut training.
2. **Home false alerts, measured for the first time on real homes, are within the bar but 20–30× the lab figure.**
   0.101 per device-day across 474 devices, against 0.003–0.005 on the UNSW lab homes (`data/ipfix-to-dna.md`).
   They concentrate on a few devices: the worst five run at 8–15 per device-day, a handful of noisy devices. A
   0.10 rate is about one alert every 10 days per device; a home with 20 devices would see two a day.
3. **The non-Mirai Kitsune attacks are mostly invisible to S1** (0 of 5 ARP MitM, 0 of 4 wiretap, 0 of 2 video
   injection), as expected. They are lab-network attacks (MitM, injection) that a host-hour C2/scan model was never
   meant to see. They were reported, not gated.
4. **Benign-device alerts inside the attack captures** (SSDP flood 7/10, SYN DoS 8/10, SSL renegotiation 4/6) are
   bystanders on a network under attack. They are not home windows and are not counted as false alerts.

## Consequences

- **S1 is not the L1-IoT model.** Under doc 37 §4, FAIL closes it, and doc 35 §1E says a refit must re-earn the
  home side on new data. Nothing goes to the device. heqk P5 stays gated (doc 34).
- **What carries forward:**
  - a real-home benign benchmark at scale (474 devices, 175k windows), with the measured exporter cut;
  - the converter chain (PCAP and IPFIX, both checked on spent data);
  - a measured gap: models trained on one lab's captures do not carry their recall to another lab.
- **Spent now:** Kitsune (all 9 captures) and the 12-homes set. Both stay sealed; never train on them. A later
  model needs new sealed malware and home data. CICIoT2023, if acquired, is a candidate for that test.
- **For the next L1 attempt** (to be pre-registered separately, not designed here): train across more than one
  lab's malware; set the threshold on real-home benign windows from a held-out part of a *different* home set; and
  test cross-lab from the start, with a power check before acquisition.
