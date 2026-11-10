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
| 3b | Crash record: panic / fault reason kept across the EL2-gate reset (reserved DRAM page), shown after reboot — **built** (`[P-crashrec]`, `/api/health last_crash`; metal J10 in batch 30) |
| 3c | Wi-Fi firmware reload when the TX path stays frozen after the control-frame kick — **built as a unit reset** (a stream wedged 120 s resets through the EL2 gate with a recorded reason and a reboot-loop backoff); an in-place firmware reload stays open |
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

**Staging note (2026-11-10, after measuring the code).** The small option parsers (`apparse`: client DHCP, WAN
DHCP reply, firmware events, EAPOL match — ~30 bounds-checked lines each, fuzzed) are not where the EL1 risk
is; moving only them would add an excursion per packet for little gain. The exposure is in the big stateful
components: `cyw43.rs` (5.5k lines, firmware-facing), `securechannel.rs` (1.8k), `shield.rs` DNS path (1.6k),
`pppoe.rs` (1.1k), smoltcp + `http.rs` / `mcserve.rs`. Order of work:
1. Generalise the metal-proven `tlshost` loader (ELF → EL0 image, IO / heap / stack pages, bounded
   excursion, reset on fault or timeout) into one `el0srv` used by every server; TLS moves onto it unchanged
   (`mc-e2e` must stay green).
2. Shield DNS parse + decision in an EL0 server (every client reaches it; name decompression and the list
   lookups are the largest client-reachable parser). The kernel keeps the UDP plumbing and the verdict gate.
3. Mission Control HTTP + smoltcp with it (the TLS server already holds the plaintext; the request parser and
   the handlers' form decoding follow).
4. PPPoE / WAN DHCP / DHCPv6 / RA client state machines.
5. Noise control channel; the WPA2 authenticator moves with the Wi-Fi driver (ADR 0044 D4 #7).
Acceptance per step: AP throughput ≥ the 2026-11-07 baseline, the separation matrix, `mc-e2e`, a host fuzz
target for the moved parser, and an EL0 fault injected in QEMU leaves forwarding + IPS running (ADR 0050 D5).

## Phase 6 — Wi-Fi product features
WPA3-SAE with PMF (transition mode), a guest SSID on its own segment, a per-radio client cap.

**Feasibility note (2026-11-10).** The CYW43455 firmware answers the `mfp` iovar (Linux brcmfmac trace,
2026-11-05), so PMF on the WPA2 AP (IGTK / BIP in the host authenticator, RSN capabilities MFPC) is a host-side
job. WPA3-SAE in **AP** mode needs either in-firmware SAE (`sae` + `fwsup`) or an external-SAE path (`sae_ext`);
this firmware has no in-firmware supplicant (`fwsup`/`idsup` absent, 2026-09-10). The AP bring-up now prints
the full feature string (`[WIFI-CAP]`, batch 30) to settle it. If neither token is present, WPA3-AP needs a
different firmware build from the vendor — a supplier dependency (human register), not a code task.

## Phase 7 — legal and factory
CYW43455 firmware redistribution terms, a per-unit provisioning tool (owner token, setup credential, label /
QR, self-test log), factory reset, an RTC (wall clock without a network), and the certification file
(CE/RED + EN 18031, FCC, CRA SBOM / CVD / support period).

## Status log
- 2026-11-09: plan written; G0 steps 3b (`client6`), 3c (`station_relay`) and eth1 → `client4` built.
- 2026-11-10: Phase 1 steps 1a–1e built and QEMU-gated (`[P-otaverify]` shared verifier at HBoot's bound +
  streaming `verify_digest`; `[P-abslot]` driver-derived inactive-slot admission; `[P15-otaimg]` os_image
  upload → slot B, refusals, trial classification and commit-on-health with 5-min fallback); metal pending.
  Phase 3a runtime watchdog (`[P-rtwdog]`, HBoot `hvc #3`) metal-armed (worst loop gap 330 ms). UI embedded
  gzip (payload 3.16 MB → 2.52 MB). HBoot OTP burn gated behind `otp-provision`. Audit:
  `heqk-audit-2026-11-10.md`.
- 2026-11-10 (later): Phase 1 **metal**: J1 OS update 9/9 (twice), J2 rollback 7/7. Phase 3b crash record,
  3c wedge self-heal reset, 3d in-loop renewal (metal: requests=1 acks=1, worst loop gap 347 ms), 3e NAT 4,096
  hashed, 3g 250-ms drain — all built; Phase 7 RTC built early (board RTC, provisional until NTP). Rule 112
  per source device. Replay guard survives session eviction. Batch 30 queued (J10–J13 + J8 rerun + 24 h soak).
