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

## E. Platform (from earlier sessions, still open)

| ID | Test | Expected |
|---|---|---|
| E1 | eth1 (RTL8111H) wired client, zero-Linux image | link up, DHCP lease, browsing (PCIe link + NIC already proven) |
| E2 | Intra-BSS isolation (G10): phone A pings phone B on the AP | decide: firmware bridges it (bypasses IDS) → set `ap_isolate` |
| E3 | Wi-Fi TX stall | capture a stall with the kick counters + brcmfmac trace |
| E4 | P-256 signing timing (dudect) | no secret-dependent timing |
| E5 | Stateful-in fix `1cea191` | unsolicited inbound refused on the VLAN bench |
