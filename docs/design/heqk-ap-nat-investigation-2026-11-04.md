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

## IDS/IPS on the AP path — 2026-11-04 22:00 (PASS)

First attempt was not a test: with iCloud Private Relay on, Safari tunneled `http://1.1.1.1:4444`
through Apple's relay (4,939 packets to 172.224.x:443, zero to 1.1.1.1) — no on-path device can see
the real port. With Private Relay off for `heqk-ap`: the phone's SYNs to 1.1.1.1:4444 were DROPPED by
heqk — `ids_drop out` 0 → 43, beat `drop_rules 1:44` = rule id 1 `block-port-4444` (signed BPF,
"Known C2 port 4444", T1571, HIGH), and tcpdump on the CM5 port saw **zero** packets to :4444.
Other traffic kept flowing (ADR 0023). Operational note: an IPS on the path cannot inspect traffic
the client tunnels (Private Relay / VPN / ECH); that is a property of the client, not a heqk gap.

## The Linux reference trace — 2026-11-04 22:20

Linux v8 (sha `ed6a151e`, brcmfmac + sdhci-brcmstb on `1001100000.mmc`) on the SAME CM5, an iPhone
on its AP (ch36/80) browsing + speed test, `mmc_request_start` filtered to CMD53: 114,439 requests,
80,861 on F2. Archived: `~/heqk-metal-logs/20261104-linux-v8-brcmfmac-mmc1-cmd53-trace.txt`.

| F2 transfer (Linux) | count |
|---|---|
| W block incr 0x8000 2x512 **followed immediately by** W byte incr **0x8400** 508 (one 1532-B frame) | 12,289 pairs |
| R byte **FIXED** 0x8000 64 (first read) | 35,175 |
| R block **FIXED** 0x8000 1x512 / 3x512 (remainder, padded to blocks) | 2,695 |
| W block FIXED 0x8000 4–6x512 (TX glom superframes — heqk does not glom) | 328 |

So a large TX frame = whole blocks + a byte-mode TAIL at the ADVANCED address (no padding to an
extra block, never restarting at 0x8000); every F2 READ is fixed-address. heqk differed in exactly
these two places; both now mirror the trace.

## Result — img 57ff6d1 (Linux-traced SDIO sequence, `wifi-bigtx`), 2026-11-04 22:45

**Block-mode TX works.** iPhone through heqk AP + NAT: YouTube and Facebook play, speed test
~11 Mbps. `big_tx ok` 1,773 / fail 0 (full-MTU frames incl. QUIC reach the phone), `too_big` 0,
no stall, credit refreshing (14–40), NAT 62,385 in / 9,854 out (≈20x the previous image).
Log: `~/heqk-metal-logs/20261104-AP-NAT-linuxseq-57ff6d1-youtube.log`.

Open: `rx_terminated` 132 (some phone frames still not read whole — the recovery holds the link,
each costs a retransmit); TCP MSS still clamped to 430 (now unnecessary: TX > 512 B works).

## Result — img 4a1a996 (RX glom = brcmf_sdio_rxglom port, MSS 1460), 2026-11-04 23:15

**Steady ~22 Mbps speed test, no drop-out; browsing works afterwards.** glom superframes 9,791 →
37,569 sub-frames delivered, 0 dropped; `rx_terminated` **0** (was 89–300 on every earlier image);
`big_tx` 73,429 ok / 0 fail; NAT 55,118 out / 77,086 in; credit recovers; no stall.
Remaining small item: `wifi_tx_fail` 89 (delivery-queue overflow during brief credit=0 moments).
Log: `~/heqk-metal-logs/20261104-AP-NAT-glom-4a1a996-22mbps.log`.

### The whole chain, as finally understood
| # | Defect | How found | Fix |
|---|---|---|---|
| 1 | RX frames > 512 B read **partially**, remainder left in the F2 FIFO → firmware stops granting TX credit → link freezes | counters (credit 40→0 after trunc) + brcmfmac source | port `brcmf_sdio_rxfail`; read frames whole |
| 2 | TX build buffer 1464 B < 1536 B block-padded QUIC reply; delivery queue head-of-line | `[NAT-TRACE]` + arithmetic | 4-block buffer; drop a refused head |
| 3 | Large TX sent as one padded block transfer; F2 reads incrementing | **Linux v8 mmc trace on this CM5** | blocks + byte tail at 0x8000+N·512; F2 reads fixed |
| 4 | Firmware superframes (channel 3) discarded whole under load | termination-reason counters (`last_chan=3`) + brcmfmac source | port `brcmf_sdio_rxglom` |

Progression on the same iPhone: no traffic → 7–8 Mbps → ~11 Mbps → 22 Mbps (then collapse) →
**22 Mbps steady**. Method lesson: measure, then copy the reference (brcmfmac source / a Linux trace
on the same board) — the guesses (channel, block-RX) cost images; the trace and counters did not.

## 2026-11-05 — DNS, ACS, regdomain, SDIO High-Speed, real VHT80 → ~45 Mbps

| Image | Change | Metal result |
|---|---|---|
| 2146169 | DNS on the AP address (forwarded upstream), queue 128, ACS un-pinned | `dns_redir` 13, `wifi_tx_fail` 0; ACS picked 2.4 GHz ch11 → **15 Mbps** |
| eacc4cc | SDIO High-Speed (Linux `mmc_sdio_switch_hs`), ACS = max expected throughput, regdomain list, channel readback | **SDCLK 50 MHz verified** (was 12.5 MHz default speed = 50 Mbit/s raw ceiling); readback exposed **ch36/20 (`0xd024`) instead of the requested 80 MHz** |
| 89138e5 | `chanspec` as a 4-byte int (brcmfmac `iovar_int_set`), SET_INFRA before SET_AP, `chanspecs` GET with an input chanspec | chanspec accepted, readback **`0xe02a` = ch36/80**, 66 regdomain chanspecs (RO), 3 periodic readbacks / 0 mismatches; **~45 Mbps** |

Root causes (all confirmed against the brcmfmac source or a Linux register read, not inferred):
the SDIO bus never left default-speed timing (12.5 MHz); the AP was **never** 80 MHz — the 2-byte
chanspec was refused and a silent 20-MHz `WLC_SET_CHANNEL` fallback reported success; the
`chanspecs` request lacked its input chanspec (count 0); `bcdc_dcmd` carried its own pre-fix frame
reader (now uses the fixed one). Log: `~/heqk-metal-logs/20261105-AP-vht80-hs50-45mbps-89138e5.log`.

Remaining gap to Linux (~150 Mbps): polled single loop + PIO SDIO, per-frame interrupt-status
CMD52/CMD53 overhead, 1-ms dry-poll delays, no TX glomming; 802.11ax is impossible on the
CYW43455 (Wi-Fi 5, 1x1) — Wi-Fi 6 needs a PCIe module + a new heqk driver (hardware tier).

## 2026-11-05 evening — PPPoE stall, WAN loss and the 40→150 Mbps fix (evidence chain)

All on CM5 metal, ISP PPPoE (Digi, PAP) on end0, iPhone on heqk's AP ch36/VHT80. Serial log
`~/heqk-metal-logs/20261105-ap-serial.log`; Linux driver-load trace
`~/heqk-metal-logs/20261105-linux-v8-brcmfmac-INIT-journal.txt` (journald, because the dmesg ring wraps).

| step | img | hypothesis / change | evidence | verdict |
|---|---|---|---|---|
| 1 | Linux | init-time firmware config (`tlv`/proptxstatus) differs | Linux sends no `tlv` (fcmode 0); TX framing identical (4-B round, block + byte tail) | ruled out |
| 2 | 1de38c4 | bus clock (HT/KSO) dropped | at the stall CHIPCLKCSR=0xd0 (HT), SLEEPCSR=0x03 (KSO), F2 ready; wake = no-op, no recovery | ruled out |
| 3 | 1de38c4 | RX glom drops cause it | sessions with 15 drops did not stall, stalled ones had 0 | ruled out |
| 4 | 1de38c4 | — | after the stall `big_rx` kept rising with tx_max == tx_seq: firmware stopped TX to an awake station, holding 40 frames | firmware-side TX freeze |
| 5 | 825b073 | reserve 2 control credits (brcmfmac TXCTL_CREDITS) | 3/3 stalls recovered ~4.1 s, right after the snapshot's first control frame; sta_info ver=4: ASSOC+AUTHO, PS=false, AMPDU | a host->dongle event restarts it |
| 6 | 6ed4833 | bare SMB_DEV_INT vs one control frame | DEV_INT 0/2, control frame 2/2 within ~5 ms | only an ioctl restarts it |
| 7 | 1c1594c | kick at 100 ms; WAN ring drained only in the Wi-Fi Idle arm, 1 frame/loop | kicks 5/5 in 103-142 ms; GEM res_err 325k -> 155 | fixed (kick = mitigation) |
| 8 | 78c42de | 16-KB glom buffer < 23-KB superframes; wq overflow | glom drops 166 -> 0, wq drops 7,158 -> 0 | fixed |
| 9 | 31e5466 | profiler + txbf=1 (Linux preinit) | loop ~80% asleep in 1-ms dry-poll delays of the RX read; TX only 10-12% (40 us/frame) | root cause of the speed cap |
| 10 | f9982c6 | non-blocking RX poll (max_dry 0) | **120-160 Mbps**; 61k frames/5 s; TX 49% of loop; 0 queue/glom/TX drops; 62/62 kicks | **fixed — Linux parity** |

Open:
- The firmware TX-to-station freeze is MITIGATED (control-frame kick, ~100-140 ms) not root-caused. No trap,
  quiet console, PS=false. ~62 kicks per heavy session.
- GEM overrun under saturation (13,944 at 150 Mbps) is the intended single loss point now that the Wi-Fi
  queue applies backpressure (TCP paces on it); a deeper ring needs a multi-page EL0 grant.
- PADT on shutdown (the ISP rejected the first PAP after a reflash: stale session; retry 8 succeeded).

## 2026-11-05 night — IPv6 over PPPoE, stages 1+2: test-ipv6.com 10/10 (img 0c685a6)

Digi PPPoE: IPV6CP up; DHCPv6 IA_NA /128 (WAN) + IA_PD /56 (infinite lifetimes), DNS 2a02:2f0c:8000:3::1;
the ISP's RA (fe80::1, lifetime 1800, M=1, no PIO) arrives periodically, not in answer to RS. LAN = first /64
of the delegation, router prefix::1; RA (SLAAC, MTU 1492, RDNSS) on the AP; the iPhone took a stable +
temporary address, router fe80::ba27:…. Forwarded out/in 707/2,565, 0 TX fail, 0 firewall no_flow drops,
0 IDS drops; test-ipv6.com **10/10**. Stateful default-deny inbound is QEMU-proven ([P-ip6]); a metal proof
needs an outside IPv6 host. Also: PPPoE stale-session PADT sweep (img fcba6d5; not exercised yet — no
stale session in these boots).
