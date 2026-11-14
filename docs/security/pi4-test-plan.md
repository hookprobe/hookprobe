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
| **T-DFS52** | AP behaviour / beacon IEs on DFS ch52 | `dfs-watch.sh` + sweep + ground-truth vs wlan0 | capture ch52 beacons | ❌ **NOT POSSIBLE on this bench** — the RTL8811AU dongle does not RX on DFS channels (see HW-DFS below). Proven: AP confirmed on 5260 (heqk wlan0 associated, −55 dBm) yet dongle tuned to ch52 saw 0 beacons/15 s; same dongle 200 beacons/5 s on ch36 |
| **HW-DFS** | Dongle DFS receive capability | ground-truth comparison | — | ❌ RTL8811AU/rtw88_8821au tunes to ch52/100 but **delivers no frames on DFS channels** in monitor mode. DFS monitoring needs a different adapter (e.g. MT7612U) or AP-side capture |
| **T-DFS100** | AP beaconing on DFS ch100 (weather) | — | — | ❌ same HW-DFS limitation as ch52 |
| **T-SOAK** | ≥2 h capture soak | service on ch36 across heqk windows | drops bounded, stalls self-recover, yields clean, temp stable | ▶ running (expect bounces during heqk reboots) |
| **T-LAN1** | CM5 mgmt exposure | `nmap -sT -T2` of 192.168.200.146 | only intended ports; TLS/HTTP posture; login throttle | ✅ 80+443 only (998 filtered); TLS1.3-only; auth-gated; login 429 after ~2 fails. **Full `-p-` sweep triggered A-03 (MC DoS) and was aborted** |
| **A-03** | **MC DoS: one off-subnet TCP conn** (High) | single-probe repro + serial ARP/slot trace + no-WiFi repro | — | ✅ **root cause confirmed on metal**: one TCP conn from any off-subnet source wedges MC until reboot — node ARPs for its own address (gateway=own AP addr), starving smoltcp's shared ARP limit. Broader than Wi-Fi (repro'd from routed 10.200.0.1). Fix building (heqk) |
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
