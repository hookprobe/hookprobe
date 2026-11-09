# heqk production plan — phases (2026-11-09)

Source: a code-verified gap audit of the shipping AP image (`hboot,apmc,wifi-bigtx,appersist`) against
`os/kernel/PRODUCTION_READINESS.md`, cross-checked with the parity-gap register and the metal test plan.
Scope: hardware, kernel and detection. The UI is out of scope (designer-owned). Every item keeps the existing
invariants: signature verification is never weakened, the management path stays safe, enforcement stays
separated (observe by default), and the device fails open for customer traffic.
No OTP writes, no fuse programming and no irreversible key commitment are in scope (operator 2026-11-09).

Order: the biggest risk to a shipped unit comes first. Each phase ends with QEMU gates plus a CM5 bench run.

## Phase 1 — OTA trust chain (a field unit can be updated safely)
| # | Item | Why |
|---|---|---|
| 1a | `os_image` artifact kind in the signed upload (ADR 0056 phase 2) | today a unit can only be reflashed over USB |
| 1b | eMMC driver admits writes to the **inactive** A/B slot only (never the running one, never the store) | the write window is the store region only |
| 1c | Streaming verify: hash while writing, verify the hybrid signature before the tryboot flip | a 4 MiB image never sits in RAM |
| 1d | SVN floor taken from `BootInfo` (HBoot reads the OTP floor live) — refuse a lower-SVN image before writing | rollback via the upload path |
| 1e | `abboot` commit wired into the AP image (`appersist`), confirm only after Wi-Fi **and** WAN are up | today a trial boot that never brings the radio up can still commit |
| 1f | `release.yml` builds and signs the AP flavour (the shipping image), not only the generic one | the release is the wrong flavour |

## Phase 2 — key custody and anti-rollback (operator decisions)
Production signing custody (HSM / ceremony), a persistent anti-rollback counter without OTP writes (RPMB or a
sealed monotonic counter), and the POLICY generation floor persisted across reflash. Design notes only until
the operator decides.

## Phase 3 — field self-heal (a unit recovers without a human)
| # | Item |
|---|---|
| 3a | Runtime watchdog (BCM2712 PM watchdog) petted from the main loop; a hung loop reboots into the same slot |
| 3b | Crash record: the exception vector writes a sealed crash record to the evidence log; shown after reboot |
| 3c | Wi-Fi firmware reload when the TX path stays frozen after the control-frame kick |
| 3d | Non-blocking DHCP renew at T1/T2 (no stall of the forwarding loop) |
| 3e | NAT table ≥ 4,096 entries with LRU eviction and a counter |
| 3f | Heap reclaim for rule / list reloads (no growth per upload) |
| 3g | Event ring drained every loop iteration (no evidence loss under load) |

## Phase 4 — detection on the shipped path
G0 apcore steps 4–5 (Wi-Fi queue, mgmt, tick into `apcore`), IPv6 WAN detection through `apcore`, detbench
driving `apcore` instead of `packet::verdict` alone, IPv6 LAN↔LAN lateral detection, an IoT behaviour baseline,
and a household benign corpus (hours, phones / TVs / IoT / backups) for the false-positive rate.

## Phase 5 — parser isolation (ADR 0050 D4)
Move the network parsers out of EL1 in this order: HTTP → DHCP / DNS server → WAN clients (PPPoE / DHCP / RA)
→ Noise → WPA2 authenticator. Each keeps a host fuzz target (`tools/fuzz`).

## Phase 6 — Wi-Fi product features
WPA3-SAE with PMF (transition mode), a guest SSID on its own segment, a per-radio client cap.

## Phase 7 — legal and factory
CYW43455 firmware redistribution terms, a per-unit provisioning tool (owner token, setup credential, label /
QR, self-test log), factory reset, an RTC (wall clock without a network), and the certification file
(CE/RED + EN 18031, FCC, CRA SBOM / CVD / support period).

## Status log
- 2026-11-09: plan written; G0 steps 3b (`client6`), 3c (`station_relay`) and eth1 → `client4` built.
