# heqk Wi-Fi AP + NAT — iPhone investigation, 2026-11-04

**Question:** with heqk as the Wi-Fi AP (`apmode`), an iPhone joins and gets a lease, but pages do
not load. Why?

Bench: CM5, heqk `apmode`, WAN = end0 (GEM) on the fortress bridge (`02:00:00:00:00:02`,
NAC `internet_only`), AP `heqk-ap` WPA2. Six AP images were flashed today; that was too many — each
carried one hypothesis, and two of those hypotheses were guesses (channel; block-mode RX). This
report separates what the evidence proves from what it only suggests.

## What works (evidence)

| Claim | Evidence |
|---|---|
| AP bring-up, WPA2 4-way, DHCP | every image: `[P11-AP2] PASS`, `[P11-AP3] PASS … leased` |
| WAN uplink | `[M-NAT0] PASS … 8.8.8.8 ttl=118` |
| Outbound NAT (client → internet), incl. 1378-B QUIC | tcpdump on the bridge: translated, checksums valid, servers answer |
| GEM receives large frames | 20 × 1200-B UDP from the host → GEM `1024-1518` counter +20, `wan_poll` +20 |
| **TCP through the NAT, end to end** | `[NAT-TRACE]` img 7e84ab0: a second client did DNS, a full TLS session to 1.1.1.1:443 (dozens of 470-B segments `wifi=sent`) and an HTTP exchange with Apple to FIN |
| Large frames *from* the phone (block-mode CMD53 read, incrementing address) | img d20ea71: phone's 1378-B QUIC packets crossed intact (servers replied) |

So NAT itself is not the problem. The failure is on the **Wi-Fi leg toward the phone**, and it is
triggered by **large frames** — which an iPhone produces immediately (QUIC / iCloud Private Relay).
TCP works because the MSS clamp (430) keeps every TCP frame under 512 B.

## Defects proven (code + metal evidence agree)

**D1 — every WAN→phone frame > ~1008 B is refused.** `cyw43::sdpcm_data_tx` builds the frame in
`DL_CHUNK + 64` = 1464 B. A 1228-B QUIC reply + 16-B header block-pads to 3 × 512 = 1536 B >
1464, so `need > frame.len()` returns false — without counting it. Metal: `big_tx ok=0 fail=0`
in every run, credit available (`credit=40`). Arithmetic, not inference.

**D2 — one refused frame blocks all deliveries to every station.** The in-order delivery queue
`break`s on any `ap_tx` failure, so the refused QUIC reply sits at the head forever: `pending=48`,
`flushed` frozen, every later NAT reply to the phone lost. Matches run 1 (`wifi_tx_fail=462,
flushed=0`) and run 6 (`pending=48`, credit 40).

Both are fixed in **58c13a1** (QEMU gate green, NOT flashed): buffer = 4 blocks; a frame refused
while credit is available is retried 3× then dropped and counted.

## Not yet explained — the failed join (run 6)

The phone could not re-join after the stall. D2 does **not** explain it: EAPOL M1/M3 and DHCP are
sent with `sdpcm_data_tx` directly, bypassing the queue (`cyw43.rs:2935/3011/2667`), and credit
was available. What the log shows instead: `big_rx` ran away (10 → 229) while `wifi_frames`
froze at 873 — the RX side kept reading "large frames" it could not parse = **the RX stream lost
sync**, so the phone's M2 was never seen.

That runaway appears **only in img 7e84ab0**, whose one functional change was mine: the F2 block
READ switched from incrementing to FIXED address (to match brcmfmac's `sdio_readsb`). In the prior
image (incrementing) the phone's QUIC crossed and RX stayed healthy. **Most likely cause: that
change.** Not proven; it is a correlation across two boots. (The brcmfmac reference is real, but
heqk computes the F2 address differently from brcmfmac, so "match the op-code bit" was not a
like-for-like change.)

## Still unproven on this hardware

- **Block-mode CMD53 WRITE** (frames > 512 B toward the phone) has never actually run: D1 refused
  every candidate before it reached the SDIO bus. Multi-block CMD53 has never been exercised on
  this SDHCI for writes (the F1 firmware upload is pinned to 1 block). On 2026-10-09, *chunked*
  writes desynced the firmware; whether *block* writes work is the open question.

## Recommendation — one image, decided in advance

Build **58c13a1 with the F2 read reverted to incrementing** (the configuration that carried the
phone's QUIC intact), channel pinned 36. Outcomes are decided before flashing:

1. `big_tx ok` rises, no stall, pages load → done; then un-pin the channel (ACS) and raise the MSS.
2. `big_tx ok` rises, then a stall → block-mode write is broken on this SDHCI → ship the
   non-`wifi-bigtx` path (TX > 512 B refused + counted, **no wedge thanks to D2's fix**): TCP
   browsing works, QUIC is lost and iOS falls back to TCP. Block-mode write becomes a separate,
   bench-only investigation.
3. `big_tx fail` rises → the CMD53 itself errors; `CMD53_DIAG` names the stage.

## Also delivered today (unaffected by the above)

- Channel selection from the scan (`hal::acs_choose`, `[P11-acs]` GREEN in QEMU): the bench's
  fortress AP occupies the same 5 GHz 80 MHz block; ACS would pick 2.4 GHz ch11. Not the cause of
  the NAT failure (the operator confirmed: phone next to the board, same result).
- Diagnostics on the AP beat: SDPCM credit, big TX/RX, GEM hardware RX stats, `[NAT-TRACE]`.

## Result — img 4a57a46 (`wifi-bigrx` + brcmfmac `rxfail` port), 2026-11-04 21:50

**iPhone browses through heqk's AP + NAT: pages load (slowly), speed test 7–8 Mbps in bursts.**
The link no longer wedges: NAT out 1,403 / in 3,018, `wifi_frames` 2,074 and rising, TX credit
recovers (40 → 11 → 20), no WIFI STALL, station stays associated. QUIC replies are refused at the
inbound gate (`too_big` 443) and iOS falls back to TCP. `rx_terminated` 89, `never_zeroed` 0 —
the ported termination recovers the stream every time.

The real root cause of "no NAT traffic" was on the SDIO RX side: frames from the phone larger than
one 512-B transfer were read **partially** and the remainder was left in the F2 FIFO, so the
firmware's TX window stopped advancing and the stream wedged (credit 40 → 0). brcmfmac never does
that (`brcmf_sdio_rxfail`). Defects D1/D2 were real but secondary.

Why it is slow (each is measurable, none fixed yet):
1. TCP MSS clamped to 430 (every segment ≤ 512 B because TX > 512 B is refused).
2. QUIC dropped → iOS waits for its TCP fallback.
3. 89 phone frames terminated instead of read → TCP retransmits. Why a block read fails is open.
4. One polled loop, PIO SDIO, ~2 ms dry passes; credit dips under load.

Next (in order): (a) record why block reads fail (the 89); (b) trace brcmfmac's CMD53 WRITE on the
Linux v8 image on this board, then enable block TX → full MTU, MSS 1460, QUIC; (c) IDS/IPS test on
the AP path; (d) DNS on the AP's own address (10.99.0.1); (e) un-pin the channel (ACS).
Log: `~/heqk-metal-logs/20261104-AP-NAT-iphone-browsing-4a57a46.log`.
