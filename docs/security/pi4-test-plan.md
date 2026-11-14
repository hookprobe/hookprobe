# Pi 4 wireless sensor — test plan & results

> Receive-only wireless; LAN tests non-root and non-disruptive; everything time-shared with the heqk bench.
> **A test passes only when the expected observation is independently seen and correctly classified.**
> Updated live as tests run (2026-11-14).

## Status key: ✅ pass · ⏸ pending (gated) · ▶ running

| ID | Objective | Method | Expected | Result |
|---|---|---|---|---|
| **T-U1** | Metadata extractor correctness | 13 unit tests, synthetic tshark rows (`tests/test_extract.py`) | security class, PMF, probe-SSID hashing, data→counters, deauth/auth | ✅ 13/13 (dev host + Pi) |
| **T-I1** | Extractor on real capture | run on M0 pcap | counts match M0; CM5 = WPA2/WPA3-transition; no cleartext probe SSID | ✅ 3341 beacons; transition+PMF-opt; no leak |
| **T-M1** | Monitor mode works, mgmt link survives | `m0-monitor-test.sh` 60 s ch36 | frames captured, 0 kernel drops, wlan0 stays associated, clean release | ✅ 3773 frames, 0 drops, wlan0 up 12/12, restored |
| **T-H1** | **Pre-emption hand-back** | heqk writes `heqk` to lock; measure detect→release | release <60 s (target ~15 s), wlan1 managed+NM+same driver, hq-wpa3 intact | ✅ detect 7 s, release 4 s, **total 11 s**; re-acquired +11 s (12:02:46→12:02:57, journal) |
| **T-S1** | Service honest coverage | start service, read health.json | coverage=on only while capturing; =off w/ reason when lock=heqk | ✅ coverage=on/capturing; =off on yield |
| **T-DFS52** | AP beaconing on DFS ch52 after CAC | `dfs-watch.sh 5260 5290 ch52 120` on heqk signal | time-to-first CM5 beacon ≈ ≥60 s CAC; or silent | ⏸ awaiting "ch52 go" |
| **T-DFS100** | AP beaconing on DFS ch100 (weather) | `dfs-watch.sh 5500 5530 ch100 660` | time-to-first beacon up to ~600 s CAC; or silent | ⏸ awaiting signal |
| **T-SOAK** | ≥2 h capture soak | service on ch36 across heqk windows | drops bounded, stalls self-recover, yields clean, temp stable | ▶ running (expect bounces during heqk reboots) |
| **T-LAN1** | CM5 mgmt exposure | `nmap -sT -T2` of 192.168.200.146 (post-DFS) | only intended ports; TLS/HTTP posture; login throttle observed | ⏸ after "DFS done" (~13:20) |
| **T-LAN2** | AP-side exposure + client isolation | from wlan0 client: mgmt not on AP; `ap_isolate` on; DNS :53 posture | MC absent on AP; cannot reach other stations | ⏸ after "DFS done" |
| **T-LAN3** | RA/DHCP options handed to client | read RA prefix/route on wlan0 | matches L-01 (doc prefix, by design); L-01b no-PD→no-RA later | ⏸ later window |

## Validation rules
- Wireless detections (rogue AP, evil-twin, open-AP, security-config change) are validated by **replaying recorded
  PCAPs offline** into the extractor/detector — never by transmitting (receive-only).
- Each result records the evidence location (pcap/jsonl path) and the coverage limitation in force at the time.

## Evidence locations (on the Pi)
- Live rings: `/var/lib/pi4-wsensor/pcap/{mgmt,data}/`, events `…/events/*.jsonl`, health `…/health.json`.
- DFS captures: `/var/lib/pi4-wsensor/dfs/dfs-<label>-<ts>.pcap`.
- M0 baseline: `/var/tmp/pi4-wsensor/m0-*.pcap`.
