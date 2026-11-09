# heqk detection benchmark — first run (2026-11-09)

Readiness checklist item 4.1. `tools/detbench` replays a **labelled** frame corpus through the real heqk
detection pipeline under QEMU (`packet::verdict` → rule plane, rate / scan / behavioural tiers, JA4, IOC;
plus the AP's Shield DNS path and exfil accounting) with the detectors' clock pinned to each frame's recorded
time (`clock::replay_set`), and counts every alert per rule and label.

```
tools/detbench/gen-attacks.py DIR                       # 8 synthetic attack episodes (pure Python)
tools/detbench/pcap2hqdb.py OUT.img benign:bg.pcap scan:DIR/portscan.pcap ...   # label 0 = benign
tools/detbench/run.sh OUT.img report.md                 # build --features detbench, replay, table
tools/detbench/ci.sh                                    # CI gate: every attack class detected, no storm
```

## Corpus (this run)
- **Benign:** 10 minutes of real traffic on the bench subnet (87,510 frames after removing 105 host
  offload super-frames that never exist on a wire). Kept outside the repository.
- **Attacks (synthetic, one episode each, each in its own time slot over the benign background):** LAN port
  scan with real RST/SYN-ACK answers, known C2 / backdoor / telnet ports, SSH brute force (40 sessions /
  80 s), C2 beacon (60 s ± 1 s for 20 min), DGA DNS lookups, ARP cache poisoning of the gateway (after the
  real gateway's ARP), 80 MB upload in ~60 s, lateral SMB/RDP sweep over 58 hosts.

## Defects the benchmark found (all fixed the same day)
| # | Defect | Effect | Fix |
|---|---|---|---|
| 1 | `ratelimit::slot()` hashed with multiply + bits 32..40 — key bits above 40 never reached the slot | MAC keys differing only in the last octet (two devices of one vendor, every randomized phone MAC) shared a slot; alternating frames looked like an endless stream of new MACs → **rule 111 MAC flood fired continuously** (24k alerts on one upload) | splitmix64 avalanche finalizer — every key bit affects every table that uses `slot()` |
| 2 | No per-(rule, source) event de-duplication outside the behavioral tier | one port scan → 974 events, one flow to a blocklisted address → 9,001 — each **evicting the 256-row detection ring** | `fire()` raises one event per (rule, source) per 60 s; wire verdicts unchanged; repeats counted — `[P-alert-dedup]` |
| 3 | Rule 102 only flags an ARP whose sender MAC ≠ Ethernet source | **classic ARP poisoning (consistent MACs) went undetected** | new rule 127: an unsolicited ARP claim of an IP bound to a different MAC within 10 min (observe-only) |
| 3b | (in the new rule) proxy-ARP answers by a router / range extender | 7 false positives on real traffic | only UNSOLICITED claims count (a reply answering a who-has from the last 2 s is proxy ARP) |

## Result after the fixes
Every attack class detected with one alert per episode (beacon: 3 over 20 min; the IOC rule adds its
own once-a-minute event where the destination is on the bench IOC pack). **1 false positive over 87,510
benign frames** — a rogue-RA alert for the bench subnet's real router (on the AP an RA from a Wi-Fi client
*is* rogue; the capture point differs from the AP's LAN side).

## Limits (honest)
- The attacks are synthetic and modelled on common tool behaviour; evasive variants (slow scans, jittered
  beacons, low-and-slow exfil under 50 MB/min) are not covered yet.
- The benign corpus is 10 minutes of one small subnet, not a household. Next: hours of real home traffic
  (phones, TVs, IoT, gaming, video calls, cloud backup — the last one tests the 50 MB/min exfil bar) and
  public datasets for attack breadth.
- The replay drives `packet::verdict` + the Shield DNS path + exfil accounting; detections that only run
  inside AP-loop glue are covered as the G0 extraction moves them into `apcore`.
