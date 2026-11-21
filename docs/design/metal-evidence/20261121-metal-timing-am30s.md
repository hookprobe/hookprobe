# Metal timing capture — am30S, 4 CM5 boots (2026-11-21)

Requested by the efficiency session (ADR 0067 G6): run `tools/ci/metal_timing.py` on 1–3 boots of an image containing #1379 and #1388. Image `am30S-8fdc26be` (main at 2026-11-21 + PR #1432 E1b; the IDS path is main's), bench AP flavour `hboot,apmc,wifi-bigtx,appersist,wpa3`, four boots (OTA trial boots of the bench restore after other rounds). Console lines taken from the bench serial capture, one file per boot.

## Tool output

```
  ids.arp = 100 ns  (baseline —)
  ids.ipv6-tcp-1274 = 190 ns  (baseline —)
  ids.mix = 276 ns  (baseline 321)
  ids.tcp-ack = 286 ns  (baseline —)
  ids.tcp-data-1400 = 290 ns  (baseline —)
  ids.udp-dns = 278 ns  (baseline —)
  tier.conn-rate = 14 ns  (baseline —)
  tier.flow = 55 ns  (baseline —)
  tier.ja4 = 3 ns  (baseline —)
  tier.l2 = 23 ns  (baseline —)
  tier.l2-stateful = 18 ns  (baseline —)
  tier.l4-rules = 46 ns  (baseline 52)
  tier.parse = 12 ns  (baseline —)
  tier.resource-shed = 30 ns  (baseline —)
  tier.scan = 30 ns  (baseline —)
  tier.sum = 260 ns  (baseline 306)
  tier.tcp-flags = 29 ns  (baseline 36)
metal-timing: ok (4 boots); 4 timings within the baseline
```

## Raw lines per boot

### boot1
```
 [IDS-BENCH] packet::verdict ns/pkt (all detection tiers, 2000 iters each): tcp-data-1400=290 tcp-ack=286 udp-dns=278 ipv6-tcp-1274=191 arp=100 | mix avg=276 ns -> 3623 kpps/core (40577 Mbps at 1400 B)
 [IDS-TIERS] tcp-data ns per tier: parse=12 l2-stateful=18 l2=23 flow=55 scan=30 conn-rate=14 resource-shed=30 ja4=3 tcp-flags=29 l4-rules=46 | sum=260
```

### boot2
```
 [IDS-BENCH] packet::verdict ns/pkt (all detection tiers, 2000 iters each): tcp-data-1400=290 tcp-ack=286 udp-dns=278 ipv6-tcp-1274=190 arp=100 | mix avg=276 ns -> 3623 kpps/core (40577 Mbps at 1400 B)
 [IDS-TIERS] tcp-data ns per tier: parse=12 l2-stateful=18 l2=23 flow=55 scan=30 conn-rate=14 resource-shed=30 ja4=3 tcp-flags=29 l4-rules=46 | sum=260
```

### boot3
```
 [IDS-BENCH] packet::verdict ns/pkt (all detection tiers, 2000 iters each): tcp-data-1400=290 tcp-ack=286 udp-dns=278 ipv6-tcp-1274=190 arp=100 | mix avg=276 ns -> 3623 kpps/core (40577 Mbps at 1400 B)
 [IDS-TIERS] tcp-data ns per tier: parse=12 l2-stateful=18 l2=23 flow=56 scan=30 conn-rate=14 resource-shed=30 ja4=3 tcp-flags=29 l4-rules=46 | sum=261
```

### boot4
```
 [IDS-BENCH] packet::verdict ns/pkt (all detection tiers, 2000 iters each): tcp-data-1400=290 tcp-ack=286 udp-dns=278 ipv6-tcp-1274=190 arp=100 | mix avg=276 ns -> 3623 kpps/core (40577 Mbps at 1400 B)
 [IDS-TIERS] tcp-data ns per tier: parse=12 l2-stateful=18 l2=23 flow=55 scan=30 conn-rate=14 resource-shed=30 ja4=3 tcp-flags=29 l4-rules=46 | sum=260
```

## Note

Every value is under its baseline (`tools/ci/baselines/perf-metal.json`): ids.mix 276 ns against a 321 ns limit, tier.sum 260 against 306. The baseline is NOT changed here; tightening it is a separate reviewed commit that can cite this file.
