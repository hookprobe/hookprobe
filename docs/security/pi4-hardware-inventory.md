# Pi 4 wireless sensor — M0 hardware inventory & visibility report

> **Status:** M0 complete (2026-11-14). Measured on the bench, not assumed.
> **Scope:** standalone **bench/lab tool** on the Linux Pi 4. Its purpose is **hardening heqk** (the CM5 AP and the
> rest of the heqk device). It is not a Linux-tier product feature (ADR 0047). Findings feed heqk.
> **Rules of engagement:** 802.11 is **receive-only**. Nothing transmits or injects management frames (no
> beacons, deauth/disassoc or probe floods). Wireless detections are validated by replaying PCAPs offline.
> Router settings are never changed.
> **Tooling:** `tools/pi4-wsensor/` (`m0-inventory.sh` read-only, `dongle-lock.sh`, `m0-monitor-test.sh`).

## 1. Platform

| Item | Value |
|---|---|
| Board | Raspberry Pi 4 Model B **Rev 1.2** (revision `c03112`, 4 GB) |
| OS | Debian GNU/Linux 13 (trixie), Raspberry Pi OS kernel **`6.18.50+rpt-rpi-v8`** aarch64 |
| Hostname | `hookprobe-test`. Stock RPi OS; the July hookprobe-edge image has been replaced |
| CPU / RAM | 4 × Cortex-A72 · 3795 MB (≈3.5 GB available idle) · 2 GB zram swap |
| Storage | 32 GB microSD (`mmcblk0`), 15 % used. **No USB SSD.** M6 should add one for sustained capture |
| Thermal | 35 °C idle, `throttled=0x0` |
| USB | Bus 1 (USB 2.0, 480M) → VIA `2109:3431` hub → Wi-Fi dongle. Bus 2 (USB 3.0, 5 Gb/s) empty |
| Regulatory | kernel `country RO: DFS-ETSI` (via `cfg80211.ieee80211_regdom=RO`). Onboard **firmware** `country 99: DFS-UNSET` (known brcmfmac handoff bug) |
| Access | `claude@10.200.0.4` (key auth, passwordless sudo), shared with the heqk metal bench |

## 2. Interface map (identity, never by `wlanN` name)

| Netdev | Identity (stable) | Driver / FW | Bus | Role | Mode |
|---|---|---|---|---|---|
| `eth0` | MAC `dc:a6:32:a4:b6:87` | `bcmgenet` | platform | **Management** (10.200.0.4/28 on the fortress LAN) | managed |
| `wlan0` | MAC `dc:a6:32:a4:b6:88`, SDIO `mmc1:0001:1` | `brcmfmac` + `brcmfmac_cyw`, BCM4345/6 FW **7.45.265** (2023-08-29) | SDIO | **heqk bench station**: client of the CM5 AP `HookProbe-Setup-R3Q1` (ch36/80) | managed |
| `wlan1` | USB **`2357:011e`** TP-Link **Archer T2U Nano** (Realtek **RTL8811AU**, 1×1 AC600), MAC `a8:29:48:…` | in-kernel **`rtw88_8821au`** (`rtw88_core/usb/88xxa/8821a`), FW **42.4.0** | USB 2.0 via hub, 480M | **Time-shared:** heqk second SAE station ↔ **monitor sensor** | managed (monitor in windows) |

- **No driver install needed.** The dongle uses the mainline `rtw88_8821au` driver (merged in 6.14; the kernel
  is 6.18). Earlier repo notes say `88XXau` (aircrack-ng out-of-tree). That was the old image and is **obsolete
  on this box**.
- Interface names swap across reboots (seen before). Scripts select the dongle by **USB bus** (`dongle-lock.sh`)
  and the management radio as the non-USB Wi-Fi netdev.
- NetworkManager is active and owns all three. `wlan1` sits `disconnected` (managed). `dongle-lock.sh` sets it
  `managed no` before monitor mode, so NM cannot reclaim it mid-capture, and restores it afterwards.
- Spec deviation: the operator's spec put management on the built-in Wi-Fi. On this bench **`eth0` is the
  management path** and the built-in Wi-Fi belongs to the heqk bench (it must not be repurposed).

## 3. Capabilities (`iw list`)

| | `phy1` dongle (RTL8811AU) | `phy0` onboard (BCM43455) |
|---|---|---|
| Interface modes | IBSS, managed, AP, AP/VLAN, **monitor** | IBSS, managed, AP, P2P-client/GO/device. **No monitor** |
| Concurrency | **"interface combinations are not supported"**: one mode at a time (monitor ⇒ no STA) | n/a |
| 2.4 GHz | ch 1–13 (14 disabled), HT20/HT40, 20 dBm | (not used as sensor) |
| 5 GHz | ch 36–48 (23 dBm), 52–64 + 100–144 **DFS/radar** (20–26 dBm), 149–165 (13 dBm) | |
| Width | HT40, **VHT80** (SGI-80). No 160 / 80+80 | |
| Streams | 1×1 | |

**Consequences:** the dongle is the only possible monitor radio. Monitoring and the heqk SAE station are mutually
exclusive, which is why the time-share protocol below exists. 6 GHz / Wi-Fi 6E/7 traffic is invisible.

## 4. Monitor-mode evidence (2026-11-14 09:40, receive-only, 60 s)

`m0-monitor-test.sh 5180 80 5210 60`: lock acquired (lock was absent) → `wlan1` monitor, **ch36 5180 MHz,
80 MHz, center 5210** → `tcpdump -y IEEE802_11_RADIO -s 256` → released.

| Check | Result |
|---|---|
| Monitor mode entered and tuned | ✅ `type monitor`, `channel 36 (5180 MHz), width: 80 MHz, center1: 5210 MHz` |
| Frames captured | ✅ **3773** in 60 s (3830 received by filter) |
| Kernel (BPF) drops | ✅ **0** |
| Netdev `rx_dropped` | ⚠️ 36 of 3866 (≈0.9 %), driver-level |
| Management/LAN stays up | ✅ `wlan0` associated to the CM5 AP for the whole run (−51 dBm), gateway ping **12/12 ok** |
| Clean release | ✅ `wlan1` → `type managed`, NM `disconnected` (as found), driver `rtw88_8821au`, lock removed |

**Frame mix:** 3341 beacons · 266 data · 40 action · 17 probe responses · 12 probe requests (8 distinct
transmitters, **all randomised MACs**) · 0 deauth/disassoc · **0 control frames (ACK/RTS/CTS/BA)**.

**Radiotap fields delivered:** TSFT, flags, data rate, channel frequency/flags, **antenna signal (dBm)**, antenna
index, RX flags. **Not delivered:** antenna **noise** (so no SNR), and control frames (the rtw88 monitor filter).

### APs observed on ch36 (beacons, 60 s)

| BSSID | SSID | Signal min/avg/max | AKM | PMF | Notes |
|---|---|---|---|---|---|
| `76:0d:02:f8:d2:da` | `HookProbe-Setup-R3Q1` (**heqk CM5 AP**) | −50/−49/−46 | **PSK + SAE** (2, 8) | capable, **not required** | RSN caps `0x008c`, CCMP-128, country IE `RO` |
| `04:f0:21:c4:c4:78` | `hookprobe` (fortress001 `wlan_5ghz`) | −44/−42/−40 | PSK + PSK-SHA256 + SAE (2, 6, 8) | capable, not required | protected Action frames seen |
| 5 × third-party | (neighbours, anonymised) | −82 … −58 | PSK only | mostly none | not ours: inventory only, no further analysis |

## 5. heqk hardening findings (first, from passive capture)

| ID | Finding | Evidence | Recommendation (heqk) |
|---|---|---|---|
| **W-01** | CM5 AP advertises **WPA2/WPA3 transition mode** (AKM PSK + SAE). Any client may use WPA2-PSK, so a captured 4-way handshake allows offline dictionary attack on the shared PSK, and SAE→PSK downgrade (Dragonblood class) is possible | beacon RSN IE, AKM 2 + 8 | Make WPA3-SAE-only (+ H2E) the default once the client population allows. Expose transition mode as an explicit, greyed-with-reason compatibility choice in Mission Control, and flag it in the security score |
| **W-02** | **PMF optional** (MFPC = 1, **MFPR = 0**). Legacy/PSK clients' deauth/disassoc are unprotected | RSN caps `0x008c` | With SAE-only, set PMF **required** (mandatory for WPA3). In transition mode, keep PMF required for SAE stations |
| **W-03** | Country IE advertises DFS channels 52–140 (RO) while the CYW43455 firmware is `DFS-UNSET` (world domain). Advertised and actual regulatory capability disagree | beacon country IE vs `iw reg get` phy0 | Advertise only the channels the radio can actually use (UNII-1 while DFS is unsupported). Tracks the known brcmfmac country-handoff bug |
| W-04 | Not yet assessed: RSNX (SAE-H2E/PK), beacon protection, WPS, vendor IEs, VHT op. **The beacon was truncated at snaplen 256** | capture setting | M1 captures beacons at full length (`-s 0` for mgmt) |

**Triage with the heqk session (2026-11-14):**
- **W-01 — accepted-by-design.** Transition mode is the shipping default (operator decision 2026-11-10) for client
  compatibility. The owner can switch to WPA3-only (`security=wpa3` in a signed Wi-Fi bundle; live switching is
  metal-proven). Residual risk: WPA2 clients stay exposed to offline guessing. SAE clients that have cached the AP
  as SAE cannot be downgraded.
- **W-02 — accepted-by-design for transition mode.** MFPR=1 would lock out WPA2-only clients, and SAE associations
  negotiate PMF. **Follow-up:** re-check MFPR=1 when the AP is in WPA3-only mode (passive capture during an agreed
  window).
- **W-03 — OPEN, tagged for the compliance package (RED / EN 18031).** Known CLM limitation: heqk runs
  `allow_dfs=false` and serves UNII-1 ch36–48 only, but the country IE still advertises channels it never uses.

These findings are *observed* (from beacons). Their exploitability has **not** been tested, and won't be over the
air (receive-only rule).

## 6. Bench limitations (state these in every coverage report)

- **Single radio, time-shared.** No monitoring while heqk holds the dongle. Coverage is part-time by construction.
- **No control frames, no noise floor** from rtw88 monitor mode. Channel-utilisation and SNR metrics are
  unavailable or estimated only.
- **1×1, ≤ VHT80, no 160 MHz, no 6 GHz.** Wider and 6 GHz traffic is invisible, and frames sent with more spatial
  streams than the dongle has are decoded only when the dongle can.
- **Fixed-channel or hopping, never both.** Hopping creates observation gaps. Continuous coverage of all
  channels is never claimed.
- WPA2/WPA3 payloads are encrypted. Passive capture yields **management metadata, not client traffic**, and is
  **not** equivalent to an AP-side mirror.
- Driver stability: `rtw88_8821au` logs `firmware failed to leave lps state` / `failed to get tx report` (≈10× in
  ~2 days of STA use). M1 watches for capture stalls and recovers by bouncing the interface.
- USB 2.0 via a hub (480M), fine for 1×1 capture. The microSD is the storage bottleneck for long PCAP retention.
- **No DFS-channel capture (proven 2026-11-14).** The RTL8811AU/`rtw88_8821au` accepts `iw set freq` on DFS/radar
  channels (52–64, 100–144) but **delivers no frames** there in monitor mode. Verified against ground truth: with
  the CM5 AP confirmed beaconing on ch52 (heqk `wlan0` associated, −55 dBm), the dongle tuned to ch52 captured 0
  beacons in 15 s, while the same dongle saw 200 beacons/5 s on ch36. DFS monitoring would need a DFS-capable
  adapter (e.g. MT7612U) or AP-side capture. Non-DFS channels (36–48, 149–165, 2.4 GHz) capture normally.

## 7. Time-share protocol (agreed with the heqk session, 2026-11-14)

`/run/lock/hp-dongle.owner` = `heqk <ts>` | `monitor <ts>` | absent.

1. heqk writes `heqk <ts>` for every metal batch and removes it afterwards. The monitor takes the dongle only when
   the lock is absent or already says `monitor`.
2. On release: `type managed`, NetworkManager-managed, same driver, heqk NM profiles untouched. `dongle-lock.sh
   release` verifies all three and **keeps the lock and reports** if any check fails.
3. No driver change while the lock says heqk.
4. heqk can pre-empt at any time ("need the dongle"). Release within 1 minute.
5. The onboard radio (`wlan0`) belongs to heqk and is never touched.

## 8. Recommended capture strategy

**Fixed channel on the CM5 AP's channel (ch36, VHT80 center 5210)** during time-share windows: this maximises
continuity on the asset we are hardening. Rotation (2.4 GHz 1/6/11 + 5 GHz UNII-1/3) is a secondary mode for
rogue/evil-twin coverage, with dwell and missed-coverage accounting. A second monitor adapter would remove the
time-share, but is not a prerequisite.

## 9. Proposed M1 (wireless sensor) — awaiting approval

1. `pi4-wsensor-capture.service` (systemd, unprivileged where possible): waits on `dongle-lock.sh acquire`, captures
   fixed-channel with **full-length mgmt frames** (`-s 0` mgmt, truncated data), and does a rotating-ring PCAP
   (bounded, e.g. 1 GB on microSD) plus a per-frame metadata JSONL (type/subtype, BSSID/SA/DA, channel, dBm, RSN
   AKM/PMF/ciphers, SSID) extracted with `tshark -T fields`.
2. Health: frames/s, kernel and netdev drops, last-frame age (stall ⇒ bounce), lock owner, and an explicit
   `coverage=off` while heqk holds the dongle (never claim monitoring that is not happening).
3. Automatic yield: poll the lock every 10 s and release within 1 min when heqk writes it.
4. Beacon baseline for the CM5 AP and fortress AP (BSSID, channel, RSN IE hash). The first detections are
   security-config change, open-AP and same-SSID-different-BSSID, validated by **offline PCAP replay** only.
5. Tests: unit tests for the metadata extractor against recorded PCAPs; a soak (≥ 2 h window) recording drops and
   stalls; a release/restore check after every window.
6. Deliverables: `pi4-wireless-monitoring.md`, an updated version of this report, and W-01…W-04 filed against heqk.
