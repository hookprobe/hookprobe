# Metal evidence — 2026-11-08/09: detection speed + correctness, PQC, Wi-Fi station relay, Shield profiles

Every row below was built, flashed and booted unattended by the relay rig and checked from the bench Pi 4 (a real
Wi-Fi client of the CM5 AP, two adapters). Each cycle = `validate.sh` (QEMU) + `mc-e2e.sh` (API + Chromium) +
signed factory image + flash/boot + G14 actions suite + the LAN-client suite + the batch's own checks.

## IDS cost per packet (boot `[IDS-BENCH]`, CM5 A76, all detection tiers, home WAN mix)

| Step | ns/pkt (mix) | Mpps/core | Commit |
|---|---|---|---|
| start of G34 | 802 | 1.25 | — |
| no per-packet 2 KB zeroing | 536 | 1.87 | `fe507d6e` |
| one `net::parse` per verdict | 511 | 1.96 | `b43a84c6` |
| bench measures normal traffic (was an IOC hit) | 517 | 1.93 | `ed066e13` |
| resource-shed answers "not top talker" first | 483 | 2.07 | `aab75fc8` |
| BPF CALL in the arm64 JIT (flow tier native: 140 -> 58 ns) | 419 | 2.39 | `ae5c9ad9` |
| later batches (boot-to-boot spread ~±5 %) | 398-441 | 2.27-2.51 | — |

`[IDS-TIERS]` (per tier, TCP data) now: parse 11, l2-stateful 16, l2 20, flow 53, scan 24, conn-rate 13,
resource-shed 30, ja4 4, tcp-flags 45, l4-rules 91 ns.

## Detection bugs found and fixed (each with a regression test)

| Bug | Effect before | Fix / proof |
|---|---|---|
| SYN limiter slot = first octet of the LE-loaded source | per-source SYN-flood limiter never tripped on a busy LAN (all 10.x shared one slot) | hashed slots, 64-slot tables; busy-LAN flooder trips (`[P8-JIT-CALL]`) |
| Beacon table direct-mapped on the source's last octet | C2 beaconing from any host that did anything else was never detected | 4096 slots, 2-way, evict shorter history; `[P-beacon-busy]` (old code: detected=false) |
| Built-in IOC seed live on devices | a LAN on 10.66.66.0/24 raised an IOC detection on every packet | seed is self-test only once `ioc::load` runs |
| JA4 / rules 125-126 IPv4-only | IPv6 TLS clients invisible | JA4 on the IPv6 LAN path, attributed to the IPv4 lease (metal) |
| Brute force / beacon IPv4-only | IPv6 attempts invisible | v6 fed under the lease, peer folded into 240/4; 124-over-v6 on metal |
| IOC pack IPv4-only | an IPv6 C2 never matched | IPv6 `ip`/`cidr` lines, LPM + expiry; metal: 302 for the Pi's IPv6 connection |

## Crypto

- ML-KEM-768: ctgrind found the shipping RustCrypto ml-kem 0.2.3 doing a secret-indexed table lookup
  (SamplePolyCBD); upgraded to 0.3.4 (upstream fix #386). ctgrind 0 errors, ACVP 180/180, differential + fuzz
  clean, wire-compatible; metal: Mission Control HTTPS negotiates **X25519MLKEM768** with Chromium.
- libcrux 0.0.11: ctgrind clean; its `check-secret-independence` feature does not build as published.
- P-256 ECDSA (device TLS key): ctgrind shows only validity-flag declassifications (`20261108-p256-ct.md`).
- The kernel build now rebuilds the EL0 TLS host when tlsprov or its lockfile change (it silently did not).

## Network

- **G10 Wi-Fi station-to-station THROUGH heqk** — the firmware honours `ap_isolate` (no IDS bypass) but heqk
  never relayed, so two Wi-Fi devices could not talk at all. Now: proxy-ARP + IPv4 unicast relay, discovery
  multicast (mDNS/SSDP/LLMNR, rate-capped unicast copies), IPv6 NS fan-out + unicast — all after the lease, IDS
  and DEVICES.TXT LAN-policy gates. Metal (`cm5-intrabss-check.sh`, the Pi's second adapter in a netns):
  ping + the IDS sees B's 4444 attempt at A; B's SSDP reaches A; B pings A's IPv6 link-local.
- **G22 per-client Shield profiles** (`shield=standard|off|strict` in the signed DEVICES.TXT) — metal: Private
  Relay blocked for the strict Pi.

## Discovery

- Full IEEE OUI registry (40 455 MA-L) as a signed OUI.TXT on the boot partition (no image bytes); the Pi's 2025
  TP-Link adapter, unknown to the legacy table and nmap, is named on metal.

## For the UI designer — new API fields (no UI work was done for these)

| Endpoint | Field | Meaning |
|---|---|---|
| `/api/devices` | `vendor`, `id_source: "ieee-oui"`, `confidence` | vendor from the IEEE registry when the curated table has none |
| `/api/devices` | `shield_profile` | `standard` / `off` / `strict` from DEVICES.TXT |
| `/api/tls` | `lease` | for an IPv6 TLS client: the device's IPv4 lease (the `client` field is then an IPv6 address) |
| `/api/detections` | rule 1200302 for IPv6 peers; 1200124/1200125/1200126 now also from IPv6 traffic | attributed to the device's IPv4 lease |

## Still open (see `heqk-parity-gaps.md`)

G0 (AP loop as a pure `apcore` + QEMU harness), G24b (EL0 migration of HTTP / LAN services / WAN control /
Noise — ADR 0050 D4, multi-week), G19 (HTP/SASE tunnel), G22 list refresh (waits for task #20's upload
channel), IPv6-only devices (no IPv4 lease to attribute to), Shield protection *levels* (a product decision:
the device has one signed list and no categories).
