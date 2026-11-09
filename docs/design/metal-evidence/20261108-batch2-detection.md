# Metal evidence — 2026-11-08 batch 2: parse-once datapath, IPv6 detection coverage, rule 125, TLS in My Network

Image `hookprobe-heqk-cm5-71544bb5-zerolinux.img` + this commit's tree, flashed and booted unattended by the relay
rig (`cm5-metal-loop.sh`); client = the bench Pi 4 on the CM5 AP (10.99.0.10, built-in Wi-Fi `dc:a6:32`).

| Gate | Result |
|---|---|
| `validate.sh` (QEMU, incl. `[P-ja4]` IPv6 leg) | PASS |
| `tools/mc-e2e.sh` (API + browser) | PASS |
| factory image + unattended flash/boot | PASS |
| G14 actions H-suite (`actions-metal.sh`) | PASS (H-ok, H5neg, H7–H11c) |
| LAN client (`cm5-lan-client.sh`) | **15/15** |
| discovery D2 (`cm5-discovery-check.sh`) | PASS — `Raspberry Pi sbc pinned-oui high`, mDNS name |

New rows proven on metal:
- **Rule 125** (TLS client on the signed IOC pack): the Pi's `openssl s_client` (JA4 `t13d301000_1d37bd780c83_44bd9d9dad66`,
  listed in `bench-task26/ioc-bench.txt`) → `ioc:true` + detection 1200125; its curl (`t13d3011h2_…`) → not flagged.
- **G35 JA4 over IPv6**: `/api/tls` shows `client 2001:db8:ff00:0:dea6:32ff:fea4:b688, lease 10.99.0.10`, same JA4,
  `ioc:true` — the IOC match follows the client across address families.
- **G36 rule 124 over IPv6**: 30 answered attempts to `[2001:db8:100::1]:22` → detection 1200124 attributed to
  10.99.0.10 (SYN-ACK evidence credited on the inbound IPv6 path).
- **G34 step 2** (one `net::parse` per verdict, reach-gate work skipped while disarmed), boot `[IDS-BENCH]`:
  `tcp-data-1400=546 tcp-ack=539 udp-dns=444 ipv6-tcp-1274=381 arp=72 | mix avg=511 ns -> 1956 kpps/core`
  (step 1: 536-549 ns; baseline before G34: 802 ns — −36 % overall).

Finding on the way: the first IPv6 JA4 attempt targeted example.net, but the bench IPv6 is a lab prefix with no
internet route, so no TCP connection and no ClientHello — the test now targets the WAN-side router's sshd.
UI changes (Shield never shows the sample layout on a device; per-device TLS line in My Network) are covered by the
device UI build + `mc-e2e.sh`, not by a metal browser session.
