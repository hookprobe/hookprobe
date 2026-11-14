# Pi 4 wireless sensor — assessment & bug-fix plan

> **Purpose:** the findings this bench has produced so far, and a per-owner fix plan. The bench exists to
> **harden heqk**; findings are routed to the session that owns the fix.
> **As of 2026-11-14.** 802.11 is receive-only; LAN checks are non-root and non-disruptive.
> **Status legend:** 🔴 open · 🟡 accepted-by-design (residual risk noted) · 🟢 fixed · ⏸ blocked.

## A. Findings register

| ID | Sev | Finding | Evidence | Owner | Status |
|---|---|---|---|---|---|
| **W-01** | Med | CM5 AP in **WPA2/WPA3 transition mode** (AKM PSK+SAE); WPA2 clients downgradable, offline PSK guess from captured handshake | beacon RSN AKM `2,8` (M0 §5, verified by extractor) | heqk | 🟡 accepted (shipping default 2026-11-10) |
| **W-02** | Med | **PMF optional** (MFPC=1, MFPR=0) in transition mode; unprotected deauth/disassoc for PSK clients | RSN caps `0x008c` | heqk | 🟡 accepted for transition; **verify MFPR=1 in WPA3-only** |
| **W-03** | Med | Country IE advertises **DFS ch52–140 (RO)** the firmware can't use (`allow_dfs=false`, UNII-1 only); advertise-vs-use mismatch | beacon country IE vs `iw reg get` phy0 `country 99 DFS-UNSET` | heqk | 🔴 open — tagged **RED / EN 18031 compliance** |
| **L-01** | Med | **CM5 AP advertises a documentation IPv6 prefix** `2001:db8:ff00::/64` via RA (RFC 3849, non-routable); AP clients get unusable global IPv6, and the RA default route points at the AP | Pi `wlan0` SLAAC `2001:db8:ff00:0:…/64`, `… proto ra`, RA router LL ↔ BSSID `76:0d:02:f8:d2:da` (M0 capture) | heqk | 🔴 open (confirm intent: bench placeholder vs bug) |
| **W-04** | — | Beacon RSNX / beacon-protection / WPS / vendor IEs / VHT-op not yet assessed (M0 beacon truncated at snaplen 256) | — | this bench | ⏸ needs an M1 window (full-length mgmt capture) |
| **UI-01** | Low | Mission Control has **no Wireless / rogue-AP view and no 802.11 telemetry source** in Observe | wireframe session report | wireframe | 🔴 open (needs the sensor API shape) |
| **INFRA-1** | — | Bench `sudo` needs a password this session can't obtain; sensor service install blocked | classifier denials; `/etc/sudoers.d/010_global-tty` shares the timestamp | operator | ⏸ needs operator to run `bootstrap-sudo.sh` |
| **INFRA-2** | Low | heqk `hq-wpa3` NM profile vanished (delete+recreate each run; reboot/interrupt leaves it missing) | heqk; M0 showed it absent pre-acquire | heqk | 🟢 fixing (persistent + create-if-absent) |

Severities are bench judgement; heqk owns final triage of its own items. L-01/W-03/W-04 are *observed*, not
exploited (receive-only rule).

## B. Fix plan by owner

### heqk kernel session
1. **W-03 (RED/EN 18031, highest):** make the advertised country IE match actual capability — emit only the
   channels the firmware will use (UNII-1 ch36–48 while `allow_dfs=false`), not the full RO DFS list. Tracks the
   known brcmfmac country-handoff bug; the compliance risk is advertising channels never used.
2. **L-01:** stop advertising `2001:db8::/32` on the AP. Use a ULA (`fd00::/8`) or a delegated GUA, or disable the
   IPv6 RA/prefix on the AP side if IPv6 isn't intended on the bench. Confirm whether this is a placeholder.
3. **W-02 follow-up:** when the AP is switched to WPA3-only, confirm beacons advertise **MFPR=1**. The bench will
   verify this by passive capture in an agreed window (no TX).
4. **INFRA-2:** land the create-if-absent `hq-wpa3` change (in progress).
5. **W-01:** no code change required (accepted). Optional: surface transition-mode as an explicit, greyed-with-
   reason compatibility choice and reflect it in the security score.

### wireframe-artifact-integration session
1. **UI-01:** add an **802.11 source** to the Observe event table (`/observe/live`), not a separate app. The
   sensor emits JSONL events; proposed per-event shape below. A Wireless status card under Network/Gateway can
   later read the sensor `health.json` (coverage on/off, channel, drops) — capability-gated, sample-only when no
   sensor answers, and it must show `coverage=off` honestly when the radio is time-shared away.

```json
{"event_id":"uuid","ts":1731570020.5,"source":"wireless","kind":"beacon|deauth|probe_req|...",
 "classification":"observed","channel":36,"dbm":-49,"bssid":"76:0d:02:f8:d2:da","sa":"...","da":"...",
 "ssid":"HookProbe-Setup-R3Q1","security":"WPA2/WPA3-transition","akm":["PSK","SAE"],
 "pmf_capable":true,"pmf_required":false,"protected":true}
```
(probe-request events carry `ssid_hash`+`ssid_len`, never a cleartext SSID — privacy.)

### operator
1. **INFRA-1:** run once — `! ssh -t claude@10.200.0.4 'bash ~/pi4-wsensor/bootstrap-sudo.sh'` — to install the
   sensor and grant the narrow sensor-only sudo rule. Until then M1 capture and the soak can't run.

## C. Tests behind these findings
- `wsensor_extract.py`: **13 unit tests pass** (security classification incl. the W-01 transition case; probe-SSID
  hashing proven not to leak; data→counters; deauth/auth/short-row handling). Run on the dev host and the Pi.
- **Integration** against the real M0 capture: 3341 beacons extracted, CM5 classified WPA2/WPA3-transition with
  PMF capable/not-required (matches W-01/W-02); no cleartext probe SSID in output.
- **Pending (needs M1 window + root):** release/restore of the dongle via `dongle-lock.sh`; an honest-coverage
  check across a heqk pre-emption; a ≥2 h soak for drops/stalls/thermal; full-length beacon capture to close W-04.

## D. What's blocked and on whom
- M1 **capture service + soak** → operator (INFRA-1 root) **and** heqk window (free after ~12:45).
- **LAN assessment** of `192.168.200.146` / AP side → heqk window (after "done"); non-root, T2, no cred brute.
- **W-04** → first full-length M1 capture window.
