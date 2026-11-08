# heqk — metal test plan (features built + QEMU-proven, awaiting the CM5)

Living list. Every row is **built, committed, and green in `validate.sh` + `mc-e2e.sh`**; what remains is
proof on silicon. Bench = CM5 on fortress port 4 (`docs/design/bench-task26/fortress-vlan-bench.sh setup`),
serial `/dev/ttyUSB2` → `~/heqk-metal-logs/`, an iPhone (and ideally an Android/laptop) on `heqk-ap`.
Build: `os/build/make-cm5-heqk-disk.sh` with the bench args in `heqk-session-2026-11-06-07.md` §3
(+ `--blocklist-file docs/design/bench-task26/block-bench.txt`). Flash: rpiboot + `os/kernel/cm5-boot/flash-image.sh`.

Legend — **Evidence** = what to capture into `~/heqk-metal-logs/<date>-<id>.txt`.

## A. Shield v2 — DNS protection (ADR 0052)

| ID | Test | Expected | Evidence |
|---|---|---|---|
| A1 | Boot | `[SHIELD] v2: N blocked + M allowed domains … operator signature OK` | serial |
| A2 | iPhone: Settings → iCloud → Private Relay **off**, airplane-mode toggle, rejoin, open `example.org` (non-Safari browser too) | page fails; `/network/dns` query log shows `example.org` **blocked**; heartbeat `blocked≥1` | screenshot + serial `[SHIELD]` line |
| A3 | Same with Private Relay **on** | `/network/dns` shows the phone with a bypass signal (`relay-seen`) | screenshot |
| A4 | Join with an iPhone (iOS 16+) | query log shows `_dns.resolver.arpa` answered (`ddr`) | `/api/dns` JSON |
| A5 | Firefox on a laptop on the AP | `use-application-dns.net` → `canary` | `/api/dns` |
| A6 | Android "Private DNS: Automatic" | DoT 853 refused (`dot-refused`), the phone falls back and still browses | `/api/dns` + browsing works |
| A7 | `nslookup example.org 8.8.8.8` from a laptop (hard-coded resolver) | NXDOMAIN (intercepted, any destination) | terminal |
| A8 | `dig +tcp example.org @1.1.1.1` | connection reset (TCP/53 blocked name) | terminal |
| A9 | `example.com` and everyday browsing | unaffected; `captive.apple.com` never blocked | — |
| A10 | Tampered BLOCK.TXT (1 byte) | `[SHIELD] list REFUSED (DigestMismatch)`, DNS still works, nothing blocked | serial |

## B. AP services

| ID | Test | Expected | Evidence |
|---|---|---|---|
| B1 | DHCP (G2): join/leave 3 devices, `/api/health` `wan.clients` | counts **active** leases, not cumulative | JSON |
| B2 | DHCP reclaim: join ≥ 17 distinct MACs (phones with private-MAC rotation) | every device gets an address (old pool refused the 17th) | `[P11-AP3 beat]` pool line |
| B3 | Device inventory (G1): Observe → devices | each client with MAC, hostname, OS guess, private-MAC flag, active | screenshot |
| B4 | Wall clock (G11): boot, wait ≤ 30 s | `[AP-NTP] wall clock set from …`; detection/flow times are today's date | serial + Detect feed |
| B5 | DHCP option 15 | client sees domain `home.arpa` | `ipconfig getpacket en0` / Android |
| B6 | RDNSS (ADR 0052 D1) on an IPv6 WAN | clients' DNS server list shows only the AP | phone network details |

## C. Detection & response

| ID | Test | Expected | Evidence |
|---|---|---|---|
| C1 | nmap `-sS` from a LAN client to an internet host it can't reach | no detection (one-sided, ADR 0049 D3) | Detect feed |
| C2 | nmap `-sS` 1-1000 against an open host via the AP | rule 113; `/api/enforcement` shows the source **rate_limited → quarantined** with `expires_in_s`, then disappears after the window | JSON timeline |
| C3 | Beacon (G4): a client curls the same URL every 60 s for 10 min | **one** beacon detection per 5 min (cooldown), not one per packet | Detect feed count |
| C4 | Long download (keep-alive) | no beacon detection (SYN-only observation) | Detect feed |
| C5 | Exfil (G3): upload > 50 MB in a minute from one client | one `exfiltration` detection (observe-only), upload not interrupted | Detect feed |
| C6 | QSECBIT (G5): run C2, then idle | orb rises to AMBER/RED during the scan, decays smoothly (≈ half after 5 min), GREEN after ~30 min | screenshots over time |
| C7 | DGA (G8): `nslookup xjw3kq9vzt2lmpr8.com`, `goog1e.com` | `dns_dga` detection (observe-only); the names still resolve | Detect feed |

## D. Mission Control

| ID | Test | Expected | Evidence |
|---|---|---|---|
| D1 | Investigate: open the C2 incident | explanation (no AI model claimed), attack path, timeline with detections + flows, report with MITRE + actions | screenshots |
| D2 | Detect → engines | real tiers with rule counts and hits (no "mock") | screenshot |
| D3 | Observe → flows | live NAT flows with bytes each way | screenshot |
| D4 | Evidence explorer: click a rule node, a device node | subgraph drills (rule → sources; device → MAC/IP/rules/targets) | screenshot |
| D5 | `/api/evidence/stats` | live counts, `storage: ram`, `last_prune: null` | JSON |

## F. Signed configuration & operations (batch 3–4)

| ID | Test | Expected | Evidence |
|---|---|---|---|
| F1 | IOC pack (G7): from a client `nslookup c2.ioc-test.example`; `curl http://203.0.113.10` | `ioc_match` detections (observe-only, nothing dropped); `/api/intel` counts | Detect feed + JSON |
| F2 | Device policy (G9): put the phone's MAC in DEVICES.TXT as `internet_only` | the phone browses; `http://10.99.0.1` does not load; `/api/devices` shows `policy: internet_only`; `/api/intel` denied counter rises | screenshots |
| F3 | Same MAC as `quarantine` | only DHCP/DNS work; browsing fails | phone |
| F4 | WIFI.TXT (G20): image built WITHOUT `HEQK_AP_PSK`, SSID/PSK from WIFI.TXT | `[WIFI] WIFI.TXT: SSID …`; the phone joins with the file's PSK | serial + join |
| F5 | WIFI.TXT tampered / absent and no build PSK | `REFUSED` → build defaults; with no PSK at all the AP does **not** start (never open) | serial |
| F6 | SIEM export (G15): `nc -ulk 514` on fortress (VLAN 200), run the C2 scan | RFC 5424 lines with rule/MITRE/src/dst arrive; `[SIEM] … sent=N lost=0` | nc capture |
| F7 | WAN health (G16): unplug the fortress uplink behind a live VLAN 100 gateway (or drop ICMP to 1.1.1.1/9.9.9.9 on fortress) | `[WAN-HEALTH] down` after 3 probes, traffic fails over to the mgmt route; `up` again after 2 good probes | serial + speed test |

## G. Batch 5

| ID | Test | Expected | Evidence |
|---|---|---|---|
| G1 | Rule pack: image with `--rules-file docs/design/bench-task26/rules-bench.txt` | `[RULES] rule pack: 10 rules armed (operator signature OK)`; Detect → engines shows "Signed rule pack" 10 rules | serial + UI |
| G2 | From a client: `nc -vz <internet host> 6667` | `IRC C2 channel (6667)` detection, observe-only (connection not dropped) | Detect feed |
| G3 | Client isolation (G10): AP start line | `client isolation (ap_isolate) ON`; phone A cannot ping phone B directly (only through heqk, visible to the IDS) | serial + ping |
| G4 | Sign out (G28) from the top bar | back to /login; the old cookie gets 401; another signed-in device stays signed in | browser |

## H. Operator actions (G14, ADR 0053)

| ID | Test | Expected | Evidence |
|---|---|---|---|
| H1 | Shield → DNS clients → "Hold 1 h" on a test client (reason entered) | that client's traffic stops (WAN + LAN); the Actions panel lists it with a countdown; audit row shows session, kind, target, reason | phone browsing + UI |
| H2 | "End now" on the hold | traffic resumes at once; audit shows the revoke | phone + UI |
| H3 | Hold with TTL 60 s (curl, see below), wait | expires by itself after ~60 s without any UI action | UI countdown + phone |
| H4 | Hold active, power cycle the board | after boot no action is active (RAM-only, S2/S6) | UI |
| H5 | Shield query log → "Allow 1 h" on a blocked name; owner key entered | the name now resolves; a wrong owner key is refused ("re-authentication failed") and audited | phone + UI |
| H6 | Investigate → incident → "Acknowledge" | status "acknowledged"; no traffic change | UI |
| H7 | curl replay of an accepted POST (same seq) | 409, audited as refused | curl |
| H8 | curl POST with `Origin: https://evil.example` or no `X-HQ-CSRF` | 403, nothing applied | curl |
| H9 | curl POST `ttl=999999` | 400 "ttl out of bounds" | curl |
| H10 | Hold an address inside the management floor (e.g. the mgmt laptop) | refused "management floor" (audited); management access never interrupted | curl + browser |

## I. AP provisioning (G12, ADR 0054)

| ID | Test | Expected | Evidence |
|---|---|---|---|
| I1 | Image with no WIFI.TXT and no build PSK | serial `[WIFI] setup AP "HookProbe-Setup-XXXX" — per-device passphrase …`; that SSID is visible on the phone | serial + phone |
| I2 | Join with the printed passphrase (or scan the QR payload) | joins, DHCP lease, internet; Mission Control still asks for the owner key | phone |
| I3 | Power cycle / re-flash the same board | same SSID + passphrase (device-unique, stable); never a shared default | serial |
| I4 | Same image on a second board (when available) | different SSID suffix + passphrase | serial |
| I5 | Image with a signed WIFI.TXT | the client AP (operator SSID) replaces the setup AP | serial + phone |

## E. Platform (from earlier sessions, still open)

| ID | Test | Expected |
|---|---|---|
| E1 | eth1 (RTL8111H) wired client, zero-Linux image | link up, DHCP lease, browsing (PCIe link + NIC already proven) |
| E2 | Intra-BSS isolation (G10): phone A pings phone B on the AP | decide: firmware bridges it (bypasses IDS) → set `ap_isolate` |
| E3 | Wi-Fi TX stall | capture a stall with the kick counters + brcmfmac trace |
| E4 | P-256 signing timing (dudect) | no secret-dependent timing |
| E5 | Stateful-in fix `1cea191` | unsolicited inbound refused on the VLAN bench |
