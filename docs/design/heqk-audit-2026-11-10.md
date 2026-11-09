# heqk production audit — 2026-11-10

Independent audit of what is built, what is validated and what remains, established from the code (branch
`wip/ota-commit`, based on `feat/heqk-prod-phases` / origin/main `f619e376`), the QEMU gates
(`os/kernel/validate.sh`, `os/kernel/tools/mc-e2e.sh`) and the CM5 bench (relay rig, FTDI serial, bench Pi).
Scope: hardware, kernel, detection and the Mission Control **backend**. The Mission Control UI belongs to the
UI/UX designer; UI findings below only name the missing API wiring. Legend: **V** = validated (gate or metal
run named), **I** = implemented, not validated, **P** = partial, **M** = mock/demo, **D** = designed only,
**B** = blocked on a human decision.

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
| 0050 parser placement | P — TLS in EL0 (metal); HTTP / DHCP / DNS / WAN / Noise / WPA2 parsers still EL1 |
| 0051 MC HTTPS | V (offline provisioning) |
| 0052 Shield v2 | V (metal) — header still "Proposed" |
| 0052 CI/CD (duplicate number) | I — gates run, never ratified; proposed renumber → 0058 |
| 0053 operator actions | V — per-session rate limit missing |
| 0054 per-device AP credential | V |
| 0055 owner journal | V (metal) — revoke-all and the signed `pin` token missing |
| 0056 upload | phase 1 V (metal); phase 2 `os_image` + trial commit V in QEMU, metal pending |
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
   (`[P15-otaimg]`). Metal run pending.
5. ADR 0055: no revoke-all; journal tail truncation indistinguishable from a torn write (needs a sealed
   high-water mark). ADR 0053: no per-session rate limit; replay memory lost when the session table evicts.
6. ADR 0051 D3: the TLS private scalar stays in an EL1 static after INIT (ADR text says EL0-only).
7. ADR 0054 / 0045: nothing in the factory or release path refuses an image built with the bench `HEQK_AP_PSK`.
8. ADR 0046 D4: software attestation-key private keys are tracked in git (`hboot/src/attest_keys.rs`); release
   builds must exclude them and verifiers must reject `otp_provisioned=0` quotes in production.
9. ADR 0049 D2: the IPv6 source key uses an unkeyed hash (observe-only today; keyed hash before enforcement).
10. ADR 0050 D3: owner-journal replay, `otaimg::check` and the upload form handlers have no fuzz target.

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

Known minor: a stalled upload stays listed as in flight in `GET /api/upload` until the next `begin` expires it.

## 4. Autonomous completion plan (A — no human needed)

Ordered by dependency and customer impact. Each item: QEMU gate first, then a CM5 bench run.

| # | Item | Acceptance | Validation |
|---|---|---|---|
| A1 | Metal OTA: upload a signed SVN+1 image, trial, commit-on-health; corrupted signature refused; image that never brings up the WAN rolls back | **done 2026-11-10** except the rollback scenario (J2) | new `tools/diagnostics/cm5-ota-check.sh` (relay + serial + hq-upload.py) |
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

## 5. Human-dependency register (B — only these need the operator)

1. Production signing-key custody (HSM / ceremony) and the policy/pack key-custody model behind A4.
2. Factory OTP provisioning: whether and when to run `hboot --features otp-provision` on production units
   (irreversible). SEC-3 fuses stay out of scope.
3. ADR ratifications / countersigns: 0052 CI/CD (+ renumber), 0055 `pin` semantics, 0056 D1 boundary with the
   flasher owner, 0045/0046, retire 0035–0042.
4. Persistent anti-rollback medium (RPMB vs sealed counter) — technical options can be prototyped (A), the
   choice is the operator's.
5. Certification (CE/RED, EN 18031, FCC), CYW43455 firmware redistribution terms, licence.
6. UI work — owned by the UI/UX designer (wire owner-rules, upload/OTA, enforcement, network API, export).

## 6. Recommended execution sequence

A1 → A2 → A3 (ship a trustworthy update path) · A4 → A5 → A6 (close the security deviations) · A7 + 72 h soak
(field reliability) · A8 + A9 · A10 → A11.
