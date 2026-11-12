# heqk production audit — 2026-11-10

Independent audit of what is built, what is validated and what remains, established from the code (branch
`wip/ota-commit`, based on `feat/heqk-prod-phases` / origin/main `f619e376`), the QEMU gates
(`os/kernel/validate.sh`, `os/kernel/tools/mc-e2e.sh`) and the CM5 bench (relay rig, FTDI serial, bench Pi).
Scope: hardware, kernel, detection and the Mission Control **backend**. The Mission Control UI belongs to the
UI/UX designer; UI findings below only name the missing API wiring. Legend: **V** = validated (gate or metal
run named), **I** = implemented, not validated, **P** = partial, **M** = mock/demo, **D** = designed only,
**B** = blocked on a human decision.

> **PRODUCTION READINESS: BLOCKED by customer OTP provisioning** (owner decision, not executed). Decision record
> for OTP (production blocker) and RPMB (owner decision required) + WPA3 (evidence pending):
> `heqk-decision-record-otp-rpmb-2026-11-10.md`. No OTP or RPMB write was made during the autonomous work.

## 1. Mission Control — feature truth table

Routing: `os/kernel/kernel/src/http.rs` (public `/login`, `/api/login`, `/api/logout`, minimal `/api/health`;
everything else behind the owner session; POST only for owner-rules, upload, actions; any other `/api/*` = 404).

| # | Journey step | Status | Evidence / gap |
|---|---|---|---|
| 1 | Boot & availability | **V** | `[P-mc]`, `[PHprod]`, `[P-rtwdog]`; metal boot loop every batch (`cm5-metal-loop.sh`, markers incl. `Mission Control also on`); runtime watchdog armed on metal, worst loop gap 330 ms (batch 27) |
| 2 | Discovery & first run | **P** | Owner key = OWNER.TXT written by the factory (`make-cm5-heqk-disk.sh`); per-device setup AP credential `[P-apcred]`. No mDNS / device name, no first-run wizard (UI `/setup` is mock). Flasher = task #20 (other owner) |
| 3 | Owner auth & sessions | **V** | `mcauth.rs` (8 sessions, 12 h, HttpOnly + SameSite=Strict); `[P-mcauth]`, mc-e2e. **Gap:** login throttle is device-global (5 failures / 60 s) → any LAN host can lock the owner out |
| 4 | HTTPS & certificates | **V (operator provisioning)** | EL0 TLS 1.3 + X25519MLKEM768, 308 from :80; mc-e2e TLS leg; metal `cm5-tls-pq-check.mjs`. **Gap:** the certificate is provisioned offline (serial → `mctls-provision.py` → boot partition); a default image serves the login over HTTP until then |
| 5 | Dashboard / live status | **P** | QSecBit, incidents, SSE real. UI falls back to mock values on API failure (e.g. after session expiry) — UI-side |
| 6 | Five pillars (Shield, My Network, Get Online, Security, Timeline & Export) | **P** | Get Online and Export have **no backend surface** (no network-config API, no export bundle) |
| 7 | Network configuration | **I as signed boot files, no API** | WAN.TXT `[P-wancfg]`, WIFI.TXT `[P-wificfg]`, VLAN/mgmt `[P-mcmgmt]`, metal `cm5-wan6-*.sh`. Nothing changeable from Mission Control |
| 8 | Shield levels, allow/block | **V (backend)** | `/api/dns`, `POST /api/owner-rules` (journal, `[P-ownerapi]`, `[P-ownerjournal]`), signed packs `[P-upload]`; metal `cm5-shield-levels-check.sh` 12/12, `cm5-owner-rules-check.sh` 10/10 (batch 26b). UI calls none of the write paths |
| 9 | Firewall / policy | **P (read-only)** | `/api/enforcement`, `/api/intel` served, unused by the UI; policy = signed POLICY.TXT / DEVICES.TXT (`[P-policy]`, `[P-policy-sig]`, `[P-devpolicy]`) |
| 10 | Detect / investigate / respond | **V** | detections, incidents, timeline, reports, evidence graph (mc-e2e + browser leg); actions `[P-actions]`, metal `actions-metal.sh` (all 11 refusal/accept cases, batches 26b and 27) |
| 11 | Device mgmt / health / updates | **P** | `/api/health` real. OS update: `os_image` upload + trial + commit-on-health **QEMU-proven** (`[P15-otaimg]`), metal pending. No reboot / diagnostics-bundle endpoint |
| 12 | Persistence | **V** | evidence log `[P-evlog]` + metal `cm5-evlog-check.sh`; owner journal metal 10/10 across a power cut; artifact store metal `cm5-upload-check.sh`. Actions and sessions RAM-only by design (ADR 0053) |
| 13 | Security boundaries | **V** | strict Origin, CSRF, per-session seq (replay → 409), owner re-auth on every write, TTL bounds (mc-e2e, `actions-metal.sh`). Gaps: global login throttle (above), `/api/login` without an Origin check (login-CSRF, low) |

UI ↔ API: every endpoint the UI calls is served with real device state except `/api/exploitability` (404,
dead code) and the AEGIS planner (`plannerApi.ts` calls the viewer's `127.0.0.1:8421`). Served but unused by
the UI: `/api/owner-rules`, `/api/upload*`, `/api/intel`, `/api/enforcement`. UI-side defects for the
designer (no backend change needed): the Detect engines panel discards `/api/engines` (name mismatch with the
mock), status pills ignore `/api/health.status` ("degraded: rule plane not armed"), the network map shows the
sample map without the sample banner after two failed `/api/devices` reads, several all-mock workspaces are
reachable by URL.

## 2. ADR compliance

Current heqk ADRs (0043–0057) are implemented as follows; Linux-tier ADRs (0003, 0005–0008, 0014–0017, 0019,
0021, 0024–0026, 0028–0035, 0038, 0039, 0041) are legacy or superseded by ADR 0044/0047 — their headers do not
yet say so (doc-only fix, no decision change).

| ADR | Status in code |
|---|---|
| 0043 heqk substrate | V (P0–P8, `[PH7-caps]`, M1 metal) |
| 0044 zero-Linux CM5 | P — caps model proven; production EL0 excursions are not yet on per-TCB CSpaces |
| 0047 heqk everywhere / MC on device | V on CM5 + QEMU |
| 0049 WAN policy auth / IPv6 identity / scan evidence | D2, D3 V; **D1 deviates** (see 2.1) |
| 0050 parser placement | P — TLS in EL0 (metal), TLS scalar no longer in EL1; HTTP / DHCP / DNS / WAN / Noise / WPA2 parsers still EL1 |
| 0051 MC HTTPS | V (offline provisioning) |
| 0052 Shield v2 | V (metal) — header still "Proposed" |
| 0052 CI/CD (duplicate number) | I — gates run, never ratified; proposed renumber → 0058 |
| 0053 operator actions | V — per-session write rate limit (`[P-write-rate]`) and eviction-proof replay guard (`[P-seq-floor]`) added 2026-11-10 |
| 0054 per-device AP credential | V |
| 0055 owner journal | V (metal) — revoke-all added 2026-11-10 (`OP_CLEAR`); the signed `pin` token is still missing |
| 0056 upload | phase 1 V (metal); phase 2 `os_image` + trial commit + rollback **V on metal** (J1 9/9, J2 7/7) |
| 0057 Shield levels | V (metal) |

### 2.1 Security deviations (ranked)
1. **ADR 0049 D1 — the policy/pack trust anchor is compiled into the image, not TOFU-pinned per device.**
   **Fixed (part 1) 2026-11-10:** `anchor.rs` pins the first operator key in the DataVolume Header region; a
   different or missing image key can no longer replace it; the POLICY generation floor is persisted
   (`[P-anchor]`). Open: per-pack generation floors, signed key rotation (operator decision). One
   operator key (`HEQK_POLICY_PUBKEY`) and a compile-time generation floor authorise POLICY and every signed
   pack; an image built without a key accepts unsigned files. Whoever builds an image (including an OTA) can
   replace the customer's anchor. **Fix (A):** persist a TOFU pin + per-type generation floors (reuse the
   `enroll.rs` pin), never let an image update replace a pinned key, refuse "no key" once pinned. Key-custody
   model = **B** (operator).
2. **Pack anti-rollback is relative.** `artstore` reports generation 0 when no store copy exists, so an older
   signed pack can come back after a reflash/erase. **Fix (A):** sealed monotonic per-type floor.
3. **HBoot burned customer OTP on a blank unit's first boot** (`ak_derive.rs`), contrary to the operator rule
   of 2026-11-09 ("No OTP writes"). **Fixed 2026-11-10** (`wip/ota-commit`): the burn and the OTP write
   function are compiled only with `hboot --features otp-provision` (factory-only); a normal image uses the
   software AK on a blank unit. The bench CM5 was provisioned in an earlier campaign (69/69 boots in the
   current serial log read "already provisioned"); nothing was written this session.
4. **OTA commit-on-health was claimed but not wired** (SECURITY.md). **Fixed in QEMU 2026-11-10:** the AP loop
   classifies the boot from HBoot's measurement, commits a trial only when the AP serves and the WAN is usable,
   reboots to the old slot after 5 min otherwise, and repairs an interrupted commit every boot
   (`[P15-otaimg]`). **Metal PASS 2026-11-10:** J1 (commit) 9/9 twice, J2 (rollback) 7/7.
5. ADR 0055: ~~no revoke-all~~ (fixed 2026-11-10); journal tail truncation indistinguishable from a torn write (needs a sealed
   high-water mark). ADR 0053: ~~no per-session rate limit~~ (fixed); ~~replay memory lost when the session table evicts~~ (fixed 2026-11-10: evicted high-water mark = floor, `[P-seq-floor]`); replay memory lost when the session table evicts.
6. ~~ADR 0051 D3: the TLS private scalar stays in an EL1 static after INIT~~ — fixed 2026-11-10 (re-derived per INIT, zeroised).
7. ~~ADR 0054 / 0045: nothing refuses a bench `HEQK_AP_PSK` image~~ — fixed 2026-11-10 (factory + release refuse it).
8. ADR 0046 D4: software attestation-key private keys are tracked in git (`hboot/src/attest_keys.rs`); release
   builds must exclude them and verifiers must reject `otp_provisioned=0` quotes in production.
9. ~~ADR 0049 D2: unkeyed IPv6 source hash~~ — fixed 2026-11-10 (SipHash-2-4, per-boot TRNG key).
10. ADR 0050 D3: owner-journal replay and the upload form handlers have no host fuzz target (kernel crate; covered only by the in-kernel fixed-seed `[P-fuzz]`); the OS-image verifier now has one (`boot_abi::verify`, 1.6 M runs).
11. **New (2026-11-10, doc review): `WAN.TXT` is unsigned**, and it carries `mgmt_floor=` — the management
    floor that decides which sources are always allowed (ADR 0023). Physical access to the card can widen it.
    Fix (A): sign WAN.TXT like POLICY.TXT (same operator key, same pinned anchor), or move the floor into the
    signed POLICY family. Release gate item TC-07.
12. **W4 security hygiene (release plan Workstream 4, task #55) — built 2026-11-12 (`feat/sec-hygiene`), QEMU + metal pending.**
    - *HQKSEAL1 nonce.* Was `SHA-256("HQKSEAL1-nonce" ‖ boot salt ‖ seq ‖ cntpct)[0..16]`. The boot salt comes from the
      RNG200 TRNG on the CM5 only; without it (QEMU, or a TRNG fault on metal, where the draw is silently retried)
      `seq` and `cntpct` restart every boot, so two boots could seal different plaintexts under one key with one
      nonce: CTR keystream reuse. Now the nonce is synthetic: `HMAC(k_siv, "HQKSEAL1-siv2" ‖ salt ‖ seq ‖ cntpct ‖
      header[0..96] ‖ plaintext)[0..16]`, `k_siv = HKDF-Expand(PRK, "HQKSEAL1-siv")`. A repeat under one key now
      needs an identical header and plaintext (and then the blobs are identical), with or without the salt. The
      format is unchanged (the nonce stays in the MAC-covered header, so older blobs still unseal). `[P-sealnonce]`.
      No change to the SRK, key custody, OTP or RPMB.
    - *Noise rekey (EL1).* The datagram record layer (`securechannel::RecordTx` / `RecordRx`) rekeys in session
      (Noise §11.3 `REKEY`, one-way) at 2^20 records, 1 GiB or 1 h, whichever comes first. The wire format is
      unchanged: the seq's high 32 bits are the key epoch. Each epoch has its own replay window. The previous
      epoch is accepted for 5 s (reordering) and then wiped. Older epochs (rollback, retired key) are refused
      without decrypting. A next-epoch record moves the receiver only if its tag verifies. An unarmed sender stops
      at 2^32 records instead of wrapping. On the G19 tunnel each side starts rekeying only after the peer's
      CAPS record (type 0x06, bit 0); an older PoP ignores CAPS and is never rekeyed at. The superpop
      (`onboarding/enrollment/superpop`) follows and answers CAPS. Epoch transitions are logged
      (`[G19] rekey: tx epoch … rx epoch …`), key material is not. The 24 h re-handshake stays. The Noise
      handshake and the device identity key are unchanged and stay in EL1. `[P-rekey]`, `[P-g19-rekey]`, superpop
      `rekey_interop` (host, g1).
    - *CI.* `tools/ci/shipping_guard.py` resolves every crate's features for `tools/ci/shipping-features.txt` and
      fails if a development-only feature is active anywhere (hsh-dev, wpa3probe, wifi-pmkid-noexpire, p15-bench,
      crashtest, securechannel-selftest / -host-responder, rpmb/otp-provision, the self-rebooting and bench
      diagnostics). It runs in g1, build-heqk (shipped-flavour job) and release. g4r (nightly reproducibility) now
      builds the shipping flavour instead of `prod`. New fuzz target `record_rx` (tools/fuzz/heqk-securechannel,
      the control channel's record layer): 102 k runs in 60 s, 0 crashes.
    - **Metal must prove:** (1) rekey over the real channel: with the PoP rebuilt from this commit, a G19 tunnel
      on the CM5 logs `[G19] rekey: tx epoch 1 …` after CAPS and a threshold (bench: a low-threshold build or a
      long iperf), and DATA keeps flowing through the transition (no 45 s silence re-handshake). (2) The session
      continues or fails closed: forged or replayed datagrams sent at the PoP / device data port are counted
      (`rx_bad` / `rx_stale`) and never delivered. (3) A reboot or reconnect does not bring back stale key or
      nonce state: after a power cycle the first handshake is at epoch 0 with a new sid, and records captured
      before the cycle are refused. (4) Sealed storage across the nonce change: an image from before this commit
      seals the snapshot / evidence log / owner journal / sealed config, this image restores them (older blobs
      unseal), writes new ones, and they restore again after a power cycle. (`[P-sealnonce]` runs in the QEMU
      sequence only; it is not in the CM5 images.)

## 3. E2E / validation evidence (this audit)

| Run | Where | Result |
|---|---|---|
| `[P-otaverify]` | QEMU | PASS — 3,000,000-byte signed body, streamed digest, both signatures, SVN floor; 4 refusals |
| `[P-abslot]` | QEMU two-boot + host tests | PASS — inactive slot derived from the card on both sides of a commit |
| `[P15-otaimg]` | QEMU (factory-layout disk, real-size image) | PASS — accept → slot B; refuse svn<floor, wrong length, flipped byte, different HBoot, running trial; slot A untouched; trial → commit → cold |
| `[P-rtwdog]` | QEMU | PASS |
| `[P-upload]` | QEMU | PASS after the os_image change (test fixed: `os_image` is now a valid type) |
| batch 26b (`f459d8a4`) | CM5 + Pi | boot PASS, actions PASS, owner rules 10/10 across a power cycle, evidence log PASS, intra-BSS mcast + IPv6 PASS, throughput 106.6 Mbps median; LAN-client 14/18 — the 4 failures are IPv6 (bench v6 router not up after the fortress reboot) |
| batch 27 (`0616c44a`: watchdog + OTA) | CM5 + Pi | boot PASS, actions PASS, `[WDOG] armed=true worst_loop_gap_ms=330`; Wi-Fi checks failed because the bench Pi's NetworkManager had stopped retrying — **bench issue, AP healthy**; fixed with `tools/diagnostics/pi-ensure-ap.sh` |
| batch 27b | CM5 + Pi | owner rules 10/10, evidence log PASS; throughput confounded (Pi on the USB rtw88 adapter; internet speed endpoint 403) — bench fixed |
| **A1 OS update** | CM5 + relay + serial | **PASS on metal**: corrupted image refused (bad signature); signed SVN-2 image (4.6 MB) uploaded over one kept-alive HTTPS connection, verified on the device, written + re-hashed from the inactive slot; tryboot trial classified itself as TRIAL; committed once AP + WAN were healthy; power cycle → HBoot verified it (ed25519 AND SLH-DSA, svn 2) and the cold boot ran the new build — `metal-evidence/20261110-ota-a1.md` |
| local WAN-side sink | CM5 + Pi | **defect found**: ~6 Mbps and 64 % GEM `res_err` from a LAN-speed sender (128-descriptor RX ring overruns on line-rate bursts) → AP ring 512, re-measure in batch 28 |

| **batch 29** (image W, `merged` + 3d/3g/lateral6/A8; SVN 4–6) | CM5 + Pi + relay + serial | **J2 OS-update rollback PASS 7/7** (trial with WAN DHCP blocked never commits, reboots at its 5-min deadline, the next cold boot runs the previous build); **J1 PASS 9/9** again; **J9** in-loop renewal `requests=1 acks=1`, worst loop gap 347 ms (old blocking renewal: 3,279 ms); LAN-client 18/18; intra-BSS mcast + IPv6 PASS; owner rules 10/10; actions PASS; `/api/network` live (SSID, setup credential source, WAN DHCP on VLAN 100, IPv6 prefix); `last_reset: power-on`; detection ring overruns 0. J8: the in-loop DHCP recovery checks PASS; its responsiveness checks used ICMP, which that image did not answer — the AP now answers echo (73a61f18) and J8 probes HTTP. Throughput 37.5 Mbps median = the bench Pi on its USB rtw88 adapter again (the soak, on the built-in radio, measures 45–73 Mbps). Evidence-log check: the sealed detection survived the power cycle; the check wrongly expected it to come from the bench Pi (fixed: compares the lists before and after the cut) |
| broadcast-storm defect (found in batch 29) | code review of the restored detection | the storm counter was **per port, and every frame uses port 0**: every broadcast that reaches the IDS (client IPv4 broadcasts after the lease gate, WAN-side IPv4 broadcasts — client ARP is proxied and never reaches it) shared one 50-per-10-s budget; past it the rate limit dropped them for *every* device and raised unattributed "Broadcast storm (DROP)" detections. Practical customer impact small (such broadcasts are not forwarded anyway), but wrong evidence and against ADR 0023's per-source intent. Fixed per source device (V1 parity), attributed by ARP sender; household self-test |
| 8 h soak (image W) | CM5 + Pi (wlan0) | in progress — first samples health ok, 0 serial faults, 45–73 Mbps |

Environment issues found and fixed: the fortress reboot removed the VLAN/v6 bench (re-run
`docs/design/bench-task26/fortress-vlan-bench.sh setup` + `v6up` + `v6route`); concurrent bench runners
corrupt results (cycle now stops when the boot check fails); validate's 150 s QEMU timeout produced phantom
FAILs under load (now 300 s); QEMU self-tests write scratch LBAs near 8192 (test disks place p1 at 32768).

Image budget: the AP payload had reached 3,157,256 B against the 3,137,736 B ceiling. Fixed by moving three
statics to `.bss` (non-zero initialisers) and embedding the UI gzip-compressed (`Content-Encoding: gzip`):
payload 2,518,296 B, **619 KB headroom**.

### 3.1 Fixed after the first audit pass (2026-11-10, same night)
| Item | Change | Evidence |
|---|---|---|
| A2 | factory pads both slot files to 5 MiB | factory script |
| A3 | CI + release build the shipping AP flavour; `tools/ci/ap-size-gate.sh` | local gate: payload 2,539,144 / 3,137,736 B |
| A4 (part 1) | device-pinned policy key + persisted POLICY floor | `[P-anchor]`, all signed-pack gates unchanged |
| A5 | per-source login throttle; login refuses a cross-origin browser POST | `[P-mcauth]`, mc-e2e PASS incl. the browser leg |
| A6 | release + factory refuse a bench `HEQK_AP_PSK` | scripts |
| A7 (NAT) | 4,096 mappings, hashed forward index (was 256 + per-packet scan) | `[P-nat-index]`, apcore gates |
| WAN RX | AP image GEM RX ring 512 (was 128): bench showed 64 % `res_err` and ~6 Mbps from a LAN-speed sender | build; **metal measurement pending** |
| IPv6 self-heal | Ethernet-WAN IPv6 re-probe after a late Router Advertisement (RA-gated, ≤ every 10 min) | build; metal pending |
| Upload client | `hq-upload.py`: one kept-alive HTTPS connection + resume (per-chunk TLS handshakes made the device reset connections on a 4.6 MB image) | bench |
| Bench | Pi rejoin helper, kea/radvd after a host reboot, local throughput sink, cycle stops on a failed boot | bench runs |

| A8 | `GET /api/network` — Get Online read side (Wi-Fi SSID/source/channel, WAN mode/IP/gateway/VLAN, IPv6 LAN prefix, management VLAN, POLICY state, trust-anchor state) | mc-e2e (session required; honest `available:false` without an AP) |
| 3b | `/api/health` `last_reset` (watchdog-type = recovered from a hang or crash, from HBoot's PM_RSTS flag); a kernel panic on the CM5 now reboots through the EL2 gate (was semihosting exit = a dead unit) | build |
| 3d | WAN DHCP renewal inside the loop (REQUEST from T1, ACK/NAK in `wan_poll`, full bring-up only on NAK / past T2). **Metal evidence of the old defect:** worst loop gap 330 ms → 3,279 ms at the first renewal (`renewals=1`) | build; metal next batch |
| 3g | detection ring drained when a quarter full or every 250 ms (was every 5 s); overruns in the heartbeat | build |
| G36 | IPv6 lateral movement between LAN devices detected under both devices' IPv4 leases | `[P-lateral6]` |
| A9 (part) | `hal::abslot` fuzz target: 12.2 M runs, 0 crashes | libFuzzer |
| J4 | trust anchor on metal: first boot `PINNED`, later power-cycled boots `pinned operator key`, POLICY verified | serial |
| Soak (image Z) | local WAN-side sink 79–86 Mbps per 5-min sample, health ok, DNS ok, 0 serial faults (3 h run in progress) | `cm5-soak.sh` |

| §2.1 #5 | per-session write rate limit (20/min) on actions + owner-rule changes; **revoke-all** (ADR 0055 D7/D8: `op=revoke_all`, alias `/api/owner-rules/revoke-all`, owner re-auth, one sealed `OP_CLEAR` record that survives replay) | `[P-write-rate]`, `[P-ownerapi]`, `[P-ownerjournal]` |
| §2.1 #6 | TLS private scalar no longer kept in EL1: re-derived from the SRK for each INIT (start + every EL0 restart), all EL1 copies zeroised | mc-e2e HTTPS leg (handshake, flood + restarts, chain) |
| §2.1 #9 | IPv6 source identity keyed per boot (SipHash-2-4, hardware TRNG key) | `[P-v6src]` incl. the SipHash KAT |
| WAN outage | DHCP acquisition in the serve loop (no 5-s-in-10 LAN stall during an ISP outage / late cable); NAKed / expired lease re-acquired in the loop | build; metal J8 next batch |
| Bench | `cm5-ota-rollback-check.sh` (J2), `cm5-wan-outage-check.sh` (J8) | scripts |
| Phase 4 | per-device behaviour baseline (IoT / camera / TV / printer learn their services for 24 h; a new service → rule 128, observe-only, hourly cap; phones never baselined) | `[P-devbase]` |

| Phase 3 crash record | a panic / unexpected kernel fault writes its reason (message + location, or ESR/ELR/FAR) into a checksummed, cache-cleaned record in a reserved DRAM page before the EL2-gate reset; the next boot prints `[CRASH]` and serves `/api/health` `last_crash` | `[P-crashrec]`; metal J10 pending (DRAM survival across the reset unproven) |
| Phase 3c self-heal | a Wi-Fi stream wedged 120 s (deliveries waiting, nothing from the firmware — the loop keeps running so the runtime watchdog cannot see it) resets the unit with a recorded reason; backoff: no second such reset when the previous one came < 15 min into its boot | `[P-crashrec]` backoff cases; metal: the reset path is J10's |
| Readiness 3.7 | wall clock from the board RTC before NTP (provisional), RTC written back after NTP; HBoot mailbox proxy: RTC register 0 only (the PMIC's charger register stays unreachable from EL1) | `[P-mc]` provisional-clock case; metal J13 |
| Phase 3f | rule verification off the bump heap: the verifier's per-pc table was a fresh heap `Vec` per call (~450 B per instruction; repeated signed rule-pack uploads ended in rules refused for lack of heap) → reusable `.bss` table. JIT code pages still never free (512-page pool); when exhausted, rules run on the interpreter (same verdicts) | `[P-verify-heap]` |
| Rule 112 | broadcast storm per source device + ARP attribution | `[P8-l2struct]` household case |
| A9 (part) | `boot_abi::verify` fuzz target (OS-update / boot verifier): 1.6 M runs, 0 crashes; `run.sh` abslot length fix | libFuzzer |

Deferred with reason: A10 (detbench through `apcore`) — the corpus is captured on the bench subnet, not from
leased AP clients, so the lease-bound `client4` gate would need a host→lease mapping layer first; the current
replay already exercises the rule plane, Shield DNS and the exfil accounting. §2.1 #8 (software AK in release)
only matters for blank-OTP units, which fail closed today — decided together with factory OTP provisioning (B2).

Known minor (fixed): a stalled upload stayed listed as in flight until the next `begin`; `GET /api/upload` now expires it.
Re-ranked: per-pack generation floors (§2.1 #2) — uploads already refuse an older generation than the active
pack and need the owner key; a boot-time floor would turn a lost store copy into *no* list instead of an older
signed one. Kept as low priority, not built.

## 4. Autonomous completion plan (A — no human needed)

Ordered by dependency and customer impact. Each item: QEMU gate first, then a CM5 bench run.

| # | Item | Acceptance | Validation |
|---|---|---|---|
| A1 | Metal OTA: upload a signed SVN+1 image, trial, commit-on-health; corrupted signature refused; image that never brings up the WAN rolls back | **done 2026-11-10** incl. the rollback scenario (J2, batch 29) | new `tools/diagnostics/cm5-ota-check.sh` (relay + serial + hq-upload.py) |
| A2 | Factory pads slot files to 5 MiB; legacy single-image cards refused with a clear reason | `[P-abslot]` + factory self-check | QEMU + factory |
| A3 | release.yml builds the shipping AP flavour + unsigned-image size gate in CI; phase-ratchet baseline updated | CI green; size gate fails at > 5 MiB | CI |
| A4 | Persisted TOFU policy/pack key pin + sealed per-type generation floors (2.1 #1, #2) | reflash with a different key refused; older pack refused after erase | QEMU two-boot + metal |
| A5 | Per-source login throttle; Origin check on `/api/login`; per-session action rate limit; non-evicting replay state | DoS from a LAN host no longer locks the owner out | mc-e2e + metal |
| A6 | Factory/release refuse `HEQK_AP_PSK` in a signed product image | build fails | CI |
| A7 | Phase 3 self-heal: crash record (sealed, shown after reboot), Wi-Fi firmware reload on persistent TX freeze, non-blocking DHCP renew, NAT ≥ 4096 (today 256), event ring drained every iteration | each with a QEMU gate; metal soak | QEMU + 72 h soak |
| A8 | Network read API (`GET /api/network`: WAN mode, SSID/channel, mgmt VLAN, source + signed state) and export bundle endpoint | served with real state | mc-e2e |
| A9 | Fuzz targets: owner-journal replay, `otaimg::check`/PayloadHeader, upload/owner forms | 0 crashes over 10M runs | host libFuzzer |
| A10 | Phase 4: G0 apcore steps 4–5, IPv6 lateral detection, detbench through apcore, household corpus | gates + benchmark report | QEMU |
| A11 | Phase 5: EL0 parser isolation (HTTP → DHCP/DNS → WAN clients → Noise → WPA2) | each parser behind an excursion | QEMU + metal |
| A12 | Doc hygiene: stale ADR headers, ADR 0052 duplicate → 0058, SECURITY.md built/not-built list, README matrix | docs match code | review |
| A13 | W4 security hygiene (task #55): synthetic HQKSEAL1 nonce, in-session Noise rekey on the record layer + G19 CAPS, shipping-flavour feature guard, g4r on the shipping flavour, `record_rx` fuzz target — **built 2026-11-12, QEMU + metal pending** (§2.1 #12) | `[P-sealnonce]`, `[P-rekey]`, `[P-g19-rekey]` PASS; superpop `rekey_interop`; metal list in §2.1 #12 | QEMU + host + metal |

## 5. Human-dependency register (B — only these need the operator)

1. Production signing-key custody (HSM / ceremony) and the policy/pack key-custody model behind A4.
2. **[PRODUCTION BLOCKER — see the decision record]** Factory OTP provisioning: whether and when to run `hboot --features otp-provision` on production units
   (irreversible). SEC-3 fuses stay out of scope. **Consequence until decided:** a unit with blank customer
   OTP attests with the SOFTWARE attestation key, whose private half is tracked in `hboot/src/attest_keys.rs`
   (§2.1 #8) — its quotes prove nothing. Verifiers (MSSP / enrolment) must reject `otp_provisioned=0` quotes
   in production. With blank OTP there is also **no SRK** (HBoot hands none over) and every SRK consumer fails
   closed: no HTTPS key (`[MC-TLS] OFF`), owner journal RAM-only, no sealed evidence log, no per-device
   setup-AP credential. Secure, but not a sellable unit — **the OTP provisioning decision blocks production.**
   (Minor: the metal self-test `cm5_p15_block_seal` falls back to a constant key; it never runs in the AP image.)
   The bench CM5 is unaffected (provisioned in an earlier campaign).
3. ADR ratifications / countersigns: 0052 CI/CD (+ renumber), 0055 `pin` semantics, 0056 D1 boundary with the
   flasher owner, 0045/0046, retire 0035–0042.
4. **[Owner decision required — see the decision record]** Persistent anti-rollback medium (RPMB vs sealed counter) — technical options can be prototyped (A), the
   choice is the operator's. Update 2026-11-10: a counter on the same eMMC cannot detect owner-journal or pack
   rollback by someone holding the card (both roll back together); only RPMB (or an OTP/fuse counter) can, and
   RPMB needs its authentication key programmed once — irreversible, so it is this decision too.
5. **[Evidence pending]** WPA3-SAE on the AP: firmware feature string (`[WIFI-CAP]`) captured on the next boot decides whether vendor firmware is needed.
6. Certification (CE/RED, EN 18031, FCC), CYW43455 firmware redistribution terms, licence.
7. UI work — owned by the UI/UX designer (wire owner-rules, upload/OTA, enforcement, network API, export).

## 6. Recommended execution sequence

A1 → A2 → A3 (ship a trustworthy update path) · A4 → A5 → A6 (close the security deviations) · A7 + 72 h soak
(field reliability) · A8 + A9 · A10 → A11.
