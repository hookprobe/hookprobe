<!-- SPDX-License-Identifier: AGPL-3.0-only -->
# IDS ns/packet with and without Neuro on CM5 (2026-11-22/23)

**Class: CM5 metal.** Status register `cm5-metal` open item "IDS ns/pkt" (design doc §9 P3: "`[IDS-BENCH]` ns/packet
unchanged"). `[IDS-BENCH]` runs on every AP boot after the signed rule and IOC packs load: 2,000 iterations of
`packet::verdict` (all detection tiers) per frame kind. These figures come from the boots of the bench images
installed on 2026-11-22/23 (serial log; each `[ID] git=` line is paired with the next `[IDS-BENCH]` line).

| image (git) | neuro | tcp-data-1400 | tcp-ack | udp-dns | ipv6-tcp | arp | mix avg |
|---|---|---|---|---|---|---|---|
| am35B `78cb7095` (11 boots) | no | 293–296 | 289–292 | 279–281 | 184 | 92–99 | **278–280** |
| `cand-7f6bc8ba` (shipping set) | no | 283 | 280 | 270 | 182 | 100 | 269 |
| `evb-f51d4ae9` (+wifi-inject) | no | 303 | 299 | 293 | 196 | 105 | 288 |
| `c3509d7a` | yes | 293 | 289 | 279 | 194 | 98 | 278 |
| `2921e907` | yes | 298 | 294 | 286 | 194 | 97 | 283 |
| `neu-7f6bc8ba` (6 h run) | yes | 295 | 291 | 280 | 184 | 100 | 279 |
| `nxt-fa54e26a` (timing) | yes | 296 | 292 | 284 | 185 | 94 | 281 |
| `napi-dd95d743` (**MVP shipping set + neuro**) | yes | 296 | 291 | 284 | 200 | 104 | 282 |

**Result: unchanged.**
- With Neuro the mix average is 278–283 ns. Without it, 269–288 ns, with the same reference image steady at
  278–280 ns across 11 boots.
- The spread between images (± ~3 %) is code layout, not Neuro. `[IDS-BENCH]` times `packet::verdict`, and the Neuro
  taps sit outside it in the AP loop.
- The taps' own cost is the per-excursion timing (`20261123-neuro-excursion-cm5.md`: 633 ns per EVENTS batch), plus
  the `neuro-dp` adapter per frame. The 6 h and A/B runs cover that end to end: loop per-beat p50 equal, worst gap
  464–470 ms.

Still open on metal: 64-device slot pressure (needs 64 clients; the bench has one).
