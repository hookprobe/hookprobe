# 2026-11-08 discovery D1 (legacy Fingerbank parity) — image d6a62268 + devid, real client

```
   10.99.0.10 dc:a6:32:a4:b6:88 hookprobe-test | Raspberry Pi Raspberry Pi sbc Linux | 95 pinned-oui high
DISCOVERY: PASS 1 devices

== LAN client 10.99.0.10 on wlan0 (Wi-Fi via the CM5)
ok  IPv4 web through the CM5
ok  IPv6 (delegated prefix, SLAAC) reaches the WAN-side router
ok  Shield: example.org -> NXDOMAIN
ok  Shield: an allowed name resolves
ok  JA4: the Pi's TLS clients appear in /api/tls ("hellos":64)
ok  rule 126: TLS to example.org (DNS bypassed via a pinned IP) flagged shield_bypass
ok  rule 126 detection raised
ok  rule 124 brute force: 30 attempts to 10.100.0.1:22 (answered) detected
ok  G14 hold: the held client cannot reach the internet
ok  G14 revoke: traffic resumes at once
LAN-CLIENT: PASS (10/10)
```
