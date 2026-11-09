# 2026-11-08 IDS/IPS cost on metal — first measured baseline (CM5 Cortex-A76, image 0a74b9ad, signed rule pack armed)

```
 [IDS-BENCH] packet::verdict ns/pkt (all detection tiers, 2000 iters each): tcp-data-1400=819 tcp-ack=814 udp-dns=749 ipv6-tcp-1274=631 arp=193 | mix avg=783 ns -> 1277 kpps/core (14302 Mbps at 1400 B)
```

Reading: ~0.8 us/packet for every detection tier + the signed rules; ~1.28 Mpps per core. At the Wi-Fi path's ~150 Mb/s (~13 kpps) inspection uses ~1% of one core. Legacy V1 had no measured number (its inspector was per-packet Python on a mirror port).
