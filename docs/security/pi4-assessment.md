# Pi 4 wireless sensor — assessment & bug-fix plan

> **Purpose:** the findings this bench has produced so far, and a per-owner fix plan. The bench exists to
> **harden heqk**; findings are routed to the session that owns the fix.
> **As of 2026-11-14.** 802.11 is receive-only; LAN checks are non-root and non-disruptive.
> **Status legend:** 🔴 open · 🟡 accepted-by-design (residual risk noted) · 🟢 fixed · ⏸ blocked.

## A. Findings register

| ID | Sev | Finding | Evidence | Owner | Status |
|---|---|---|---|---|---|
| **A-03** | **High** | **Management UI DoS — one off-subnet TCP connection (root cause confirmed on metal by heqk; broader than Wi-Fi).** A **single unauthenticated TCP connection to Mission Control from ANY source outside the node's own subnets** (routed admin, NATed Wi-Fi hairpin, or spoofed) **wedges MC** (`:443` + `:80`) **until reboot.** Mechanism: the MC node's default gateway is **its own AP address**, so any reply to an off-subnet source makes it **ARP for itself**; the unresolvable neighbour monopolises **smoltcp's shared ARP rate limit** until every real peer's ARP entry expires and egress freezes (all 16 HTTP slots FIN-WAIT, all 8 HTTPS slots SYN-RCVD, 0 gated / 0 lost). Reproduced with **no Wi-Fi at all**: one `curl --interface 10.200.0.1` from fortress wedged MC in ~45 s. The earlier port scan was a **red herring** | wlan0 probe 14:51 + 15:08; serial slot/ARP trace; no-WiFi repro from 10.200.0.1 | heqk | 🟢 **FIXED + verified on bench image**: client RST 0.003 s (was 5 s timeout); heqk fortress-side = 4 off-subnet connects + 18 health checks over 3 min all 200, slots back to Listen. Fix = **PR #1165** (fix/mc-mgmt-wedge), validate green; metal evidence `docs/design/metal-evidence/20261114-a03-mc-wedge.md`. Fix: host answers the node ARP for its own address + refuse-local (RST) + rule-113 attribution |
| **DNS-01** | Low | **heqk-owned; characterized + fix validated here.** Locally-built (sinkholed NXDOMAIN) DNS replies suffered a frequent multi-second hold while benign/upstream replies stayed fast. **rl1 baseline (20 sinkholed):** 6/20 timeout >10 s, 6/20 2.3–5.8 s, 3/20 0.18–0.89 s, 5/20 3–7 ms (12/20 ≥2 s). **dfr20 (20 ms deferral):** all 20/20 at **23–27 ms**, benign unaffected. An earlier RX/TX-ordering hypothesis was disproved on metal first | 2× identical 25-query runs (unique sinkholed subdomains + benign), rl1 vs dfr20 | heqk | 🟢 fix validated on metal — **PR #1187** (`fix/dns01-local-reply-defer`, 20 ms hold, default) |
| **A-04** | Med | **Regression from the A-03 fix (#1165), caught during DNS-01 validation.** A-03's defence-in-depth refused client packets to *all* of the device's own addresses — **including the AP address `10.99.0.1`** — so AP clients' DNS to Shield got ICMP host-unreachable before Shield could answer. AP-client DNS via the AP was broken on the bench from ~15:56 (benign + blocked names both unreachable, ICMP to the gw still up) | dig @10.99.0.1 host-unreachable throughout boot 1; same DNS answered pre-#1165 | heqk | 🟢 fix **PR #1179** (refuse only the mgmt/WAN addresses, exclude the AP address; regression test added) |
| **W-01** | Med | CM5 AP in **WPA2/WPA3 transition mode** (AKM PSK+SAE); WPA2 clients downgradable, offline PSK guess from captured handshake | beacon RSN AKM `2,8` (M0 §5, verified by extractor) | heqk | 🟡 accepted (shipping default 2026-11-10) |
| **W-02** | Med | **PMF optional** (MFPC=1, MFPR=0) in transition mode; unprotected deauth/disassoc for PSK clients | RSN caps `0x008c` | heqk | 🟡 accepted for transition; heqk code-verified MFPR=1 is set in WPA3-only (mfp=2). Beacon confirmation needs a WPA3-only bench image (ping before switching — affects the soak client) |
| **W-03** | — | ~~Country IE advertises DFS channels the firmware can't use~~ **Not a defect (heqk, verified).** The 802.11d country IE correctly states the **RO regdomain's** permitted channels (36–64, 100–140, DFS included), not the AP's own channel set. The "firmware can't do DFS" premise was wrong: the CYW43455 ran CAC on ch52/80 and beaconed on metal 2026-11-14 (R2), WPA3 client joined; DFS channels are opt-in selectable (PR #1158). No advertise-vs-use mismatch | beacon country IE = RO regdomain; metal CAC on ch52 | heqk | 🟢 resolved — not a defect |
| **L-01** | — | CM5 AP advertises IPv6 prefix `2001:db8:ff00::/64` via RA. **Bench config, by design** (heqk): the AP numbers its LAN from the prefix delegated over WAN by DHCPv6-PD; fortress deliberately delegates documentation space on the bench, so nothing leaks; a real ISP would delegate a routable GUA | Pi `wlan0` SLAAC `2001:db8:ff00:0:…/64`, RA router LL ↔ BSSID `76:0d:02:f8:d2:da` | heqk | 🟡 by design |
| **L-01b** | Med | **Real gap (derived from L-01), fixed:** on WAN prefix loss the AP didn't withdraw — an unrenewed delegation never expired and the LAN went silent instead of withdrawing | heqk | heqk | 🟢 fixed **PR #1176**: an unrenewed PD now lapses; the AP sends one RA with router-lifetime 0 + prefix valid/preferred 0, then stops (no-PD→no-RA was already correct) |
| **W-04** | — | Beacon RSNX / beacon-protection / WPS / vendor IEs / VHT-op not yet assessed (M0 beacon truncated at snaplen 256) | — | this bench | ⏸ needs an M1 window (full-length mgmt capture) |
| **UI-01** | Low | Mission Control has **no Wireless / rogue-AP view and no 802.11 telemetry source** in Observe | wireframe session report | wireframe | 🔴 open (needs the sensor API shape) |
| **INFRA-1** | — | Bench `sudo` needs a password this session can't obtain; sensor service install blocked | classifier denials; `/etc/sudoers.d/010_global-tty` shares the timestamp | operator | ⏸ needs operator to run `bootstrap-sudo.sh` |
| **INFRA-2** | Low | heqk `hq-wpa3` NM profile vanished (delete+recreate each run; reboot/interrupt leaves it missing) | heqk; M0 showed it absent pre-acquire | heqk | 🟢 fixing (persistent + create-if-absent) |

Severities are bench judgement; heqk owns final triage of its own items. L-01/W-03/W-04 are *observed*, not
exploited (receive-only rule).

### LAN assessment of the device management UI (192.168.200.146, from fortress VLAN 200, 2026-11-14)

| ID | Sev | Finding | Evidence | Status |
|---|---|---|---|---|
| **LAN+** | — | **Strong baseline:** TLS 1.3 only (SSLv3/TLS1.0/1.1/1.2 all rejected); `Server: heqk`; UI auth-gated (302→/login); `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Cache-Control: no-store`; HTTP :80 → HTTPS 308 redirect; cert from local "HookProbe owner CA (heqk)" | openssl/curl | ✅ good |
| **L-02** | Low | Cert SAN (`heqk.local`, `10.99.0.1`, `10.200.0.6`) **omits the mgmt IP `192.168.200.146`** → name mismatch when reaching the UI by its mgmt address | `openssl x509 -ext subjectAltName` | 🟡 heqk: provisioning note, not code (SAN comes from the provisioned addresses) |
| **H-01** | Low | No **CSP**, `Referrer-Policy` or `Permissions-Policy` response headers on the mgmt UI (HSTS intentionally omitted — local CA) | `curl -kI` | 🟢 heqk: fixed in **PR #1161** + Referrer-Policy follow-up **PR #1168** (`same-origin`; `no-referrer` broke Chrome sign-in via the Origin CSRF guard). HSTS left off by design (local CA) |
| **L-03** | info | PQ TLS group `X25519MLKEM768` **not testable from this host** (fortress openssl can't offer it); negotiated classical X25519 + TLS_CHACHA20_POLY1305_SHA256 | openssl | ⏸ retest with a PQ-capable client |
| **LAN++** | — | **Login rate-limit works:** `/api/login` returns **429** after ~2 failed attempts from one source (fast 429, not a slow drip); confirms the per-source brute-force throttle | 10 benign identical POSTs → 303,303,429×8 | ✅ good |
| **T-LAN1** | — | TCP surface of 192.168.200.146: **only 80+443 open, 998/1000 filtered (dropped)** on top-1000; full 65535 sweep in progress | nmap -sT -T2 | ▶ full sweep running |

### AP-side assessment (from wlan0 client 10.99.0.10 of HookProbe-Setup-R3Q1, 2026-11-14)

| ID | Sev | Finding | Evidence | Status |
|---|---|---|---|---|
| **AP+** | — | **Good:** Mission Control is NOT served on the AP gateway (10.99.0.1:80/443 no-connect, G12-M); mgmt UI 80/443 **filtered from the AP side**; Shield DNS filters ads (`doubleclick.net` → no answer), no `version.bind` leak, `ANY` returns nothing (no amplification), normal names resolve | curl/dig/`/dev/tcp` | ✅ |
| **A-01** | Med? | **AP clients can reach upstream RFC1918 networks via the CM5 WAN:** from wlan0, `192.168.200.1:22` (mgmt-VLAN host, fortress) is **TCP-open**, `192.168.200.146` answers ICMP, `10.200.0.1` (fortress LAN) is reachable. MC's own ports are filtered, but the surrounding segments are routable from a Wi-Fi client | `ping -I wlan0`, `/dev/tcp/192.168.200.1/22` OPEN, `ip route get → via 10.99.0.1 dev wlan0` | 🔴 open — **heqk to judge.** Likely bench-topology-influenced (fortress routes between the CM5 WAN and the mgmt/LAN segments; in production the WAN is the ISP). Real question: should the CM5 AP block client→RFC1918-on-WAN by default? |
| **A-02** | info | **Client↔client reachable on the main SSID — by design (heqk).** The radio's `ap_isolate` **is on** (`cyw43.rs iovar_set_u32("ap_isolate",1)`), so stations are never bridged by the firmware; heqk **relays** client-to-client traffic through itself so the IDS and per-device policy inspect every frame (lateral-movement detection, V1 parity G10). My phone→Pi ICMP went phone → heqk → Pi (inspected, not bridged). Per-device isolation = device policy (`internet_only`/`quarantine` in DEVICES.TXT / owner journal); the guest SSID is isolated by default; a network-wide "isolate all clients" is an operator product decision | `ap-isolate-test.sh` → ICMP OK (relayed); heqk bring-up log | 🟢 by design — not a gap |
| **L-01✓** | — | RA on the AP hands the documentation prefix `2001:db8:ff00::/64` (reconfirmed) — by design on the bench | `ip -6 route dev wlan0` | 🟡 by design |

## B. Fix plan by owner

### heqk kernel session — status (all resolved/triaged as of 2026-11-14)
- **A-03 (High):** fixed + metal-verified — PR #1165.
- **W-03:** resolved, **not a defect** — the country IE correctly advertises the RO regdomain; DFS is usable (CAC verified on metal; opt-in via PR #1158).
- **L-01b:** fixed — PR #1176 (unrenewed PD now lapses + withdraws via RA lifetime 0).
- **H-01:** fixed — PR #1161 + #1168 (Referrer-Policy `same-origin`); HSTS off by design (local CA).
- **W-02:** code-verified MFPR=1 in WPA3-only; beacon confirmation pending a WPA3-only bench image (ping before switching — affects the soak client).
- **W-01:** accepted (transition mode is the shipping default); optional UX surfacing of the residual risk.
- **A-01:** operator/heqk judgment — whether the AP should block client→RFC1918-on-WAN by default.
- **A-02:** by design — radio `ap_isolate` on; heqk relays+inspects client traffic (G10 lateral-movement).
- **L-01 / L-02:** by design (bench DHCPv6-PD doc prefix) / provisioning (cert SAN).

### wireframe-artifact-integration session
1. **UI-01:** add an **802.11 source** to the Observe event table (`/observe/live`), not a separate app. The
   sensor emits JSONL events; per-event shape below, confirmed by the wireframe session and mapped to the Observe
   row `{ts, source:"Wireless", entity, severity, summary, facts}` (entity = ssid for beacon/probe_resp, bssid
   otherwise; probe_req shows "hidden SSID (len N)", never cleartext; facts drawer = dBm/security/AKM/PMF/protected).
   A Wireless health card reads `health.json` and says "not listening (radio shared with the bench)" when off.

   ⚠️ **Blocked on an architecture decision (ARCH-1), not on the UI.** Mission Control is served by heqk on the
   device and only calls its own same-origin `/api`; per ADR 0047, new product capability lands in heqk and Linux
   is only a dev host. So a Linux-side Pi sensor **cannot be a Mission Control source by itself**. For Observe to
   show wireless, **heqk must expose/ingest** the events (e.g. device `GET /api/wireless {coverage, events[]}`).
   The UI chip + card can be wired only once that device endpoint exists.

```json
{"event_id":"uuid","ts":1731570020.5,"source":"wireless","kind":"beacon|deauth|probe_req|...",
 "classification":"observed","channel":36,"dbm":-49,"bssid":"76:0d:02:f8:d2:da","sa":"...","da":"...",
 "ssid":"HookProbe-Setup-R3Q1","security":"WPA2/WPA3-transition","akm":["PSK","SAE"],
 "pmf_capable":true,"pmf_required":false,"protected":true}
```
(probe-request events carry `ssid_hash`+`ssid_len`, never a cleartext SSID — privacy.)

### ARCH-1 — how the sensor's data reaches Mission Control (operator + heqk decision)
The sensor is a standalone Linux bench tool (ADR 0047). Two non-exclusive paths:
- **(default, needs nobody) Standalone local dashboard on the Pi** — the original project spec §8 asks for a local
  dashboard over the management LAN. The sensor serves its own read-only dashboard from `health.json` + the event
  JSONL. This ships without any heqk change and is what this bench builds next (M3).
- **(additive, operator-gated) heqk ingests** — heqk exposes `GET /api/wireless` (or accepts a push) so the events
  appear as the Observe "Wireless" source inside Mission Control. This is the "one system" end state but needs heqk
  work and an operator call; it does not block the standalone dashboard.
**Bench decision (reasonable default, revisit on request):** build the standalone dashboard now; offer heqk the
endpoint shape for the additive path. No work is blocked waiting on ARCH-1.

### operator (optional hardware)
- **HW-DFS:** the RTL8811AU monitor dongle cannot receive on DFS/radar channels (52–64, 100–144) — proven against
  ground truth. DFS-channel wireless monitoring (rogue/beacon analysis on DFS, verifying the AP's DFS/CAC and
  beacon IEs over the air) needs a **DFS-capable monitor adapter (MT7612U-class)**. Not required for non-DFS
  coverage or the LAN work; it's the right ask only if over-the-air DFS monitoring is wanted. heqk takes DFS beacon
  IEs from its own `wlan0` client scans in the meantime.

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
