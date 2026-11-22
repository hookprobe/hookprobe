# heqk — gate and gap status (single source of truth)

Status as of 2026-11-21 (origin/main `c7a48d94d`, #1420). This table supersedes the status columns of
`heqk-remaining-gaps.md`, the 2026-11-10 audit tables and the to-do lists in `heqk-gap-fix-plan-2026-11-18.md`
(gap-fix plan E2). Those documents keep their reasoning; their **status** lives here. Every PR that moves a gate updates
its row here in the same PR.

The machine-checked release gate is still `tools/release-gate/items.txt` + `check.py` (operator-owned; not edited by
this document). Run without logs it reports today: **NOT READY — 4 pass, 1 missing evidence, 15 unverified (needs a
validate / e2e log), 15 blocked, of 35**. `docs/release/signoffs/` holds no sign-off yet.

**States:** `done+metal` (merged, CM5 evidence) · `done-QEMU` (merged, no CM5 record; some by design) · `open` ·
`blocked` (waits on a decision / sign-off / hardware / vendor) · `deferred` (by an operator decision).
**Owners:** eng (engineering, no operator input needed) · op (operator) · bench (needs the bench / a person) · vendor.

**ID prefixes** (several plans reuse the same short IDs): `GF-` = gap-fix plan 2026-11-18 (R, E, H waves) ·
`AH-` = autoheal harness H1–H7 · `EP-` = ADR 0067 efficiency programme · `MT-` = metal test plan.

## Release gates (`tools/release-gate/items.txt`)

| ID | What | Owner | State | Evidence |
|---|---|---|---|---|
| TC-01 | signing-key custody + reproducible build | op | blocked | signoff:key-custody |
| TC-02 | customer OTP provisioning | op | blocked | signoff:otp-provisioning; heqk-decision-record-otp-rpmb-2026-11-10.md |
| TC-03 | SEC-3 secure-boot fuses (or out of scope) | op | blocked | signoff:sec3-secure-boot |
| TC-04 | rollback anchored in RPMB (or risk accepted) | op | blocked | signoff:rpmb |
| TC-05 | device-pinned operator key + persisted POLICY floor | eng | done+metal | Panchor; audit §3.1 J4 |
| TC-06 | OS-image verifier at real image size | eng | done-QEMU (by design) | Potaverify |
| TC-07 | WAN.TXT signed incl. mgmt_floor | eng | done+metal | metal-evidence/20261110-batch31-32.md, 20261111-batch59-63.md |
| OTA-01 | verify → inactive slot → trial → commit on health | eng | done+metal | 20261110-ota-a1.md, 20261113-mb16-ota.md |
| OTA-02 | unhealthy trial rolls back | eng | done+metal | 20261110-batch29.md |
| REL-01 | runtime watchdog armed after confirm | eng | done+metal | 20261110-batch29.md |
| REL-02 | crash record survives the EL2-gate reset | eng | done+metal | 20261110-batch33.md |
| REL-03 | RTC across a warm reset | eng | done+metal | 20261110-batch30.md |
| REL-04 | power-loss torture | eng | done+metal | 20261110-batch30.md |
| REL-05 | 72 h soak | op / bench | deferred (op 2026-11-12) | soak-72h.md not yet written |
| REL-06 | thermal in the enclosure | bench | blocked | not run |
| REL-07 | client scale | bench | blocked | 2 bench clients only |
| REL-08a | Wi-Fi TX-stall root cause | vendor | blocked (mitigated: heal ladder 51/51 on metal) | 20261113-mb15-selfheal.md |
| REL-08b | CYW43455 PMKID use-after-free | vendor / op | blocked (Infineon production firmware; CMP-02) | rel08 doc; 20261114-mb25-mb27.md (7.45.314 test fw: no trap) |
| REL-09 | factory reset erases owner data | eng | done+metal | 20261110-batch38-47.md |
| NET-01 | DNS under saturating download | eng | done+metal | metal-evidence/dns-under-load.md |
| NET-02 | LAN client end to end | eng | done+metal | 20261110-batch29.md |
| NET-03 | WPA3-SAE + PMF, transition default | eng | done+metal | 20261110-batch38-47.md, 20261111-batch59-63.md |
| SEC-01 | ADR 0050 D4 parsers in EL0 | eng → op | **gate text stale** (see C1); work done+metal | 20261111-batch59-63.md, 20261114-evening.md; ADR 0065 D6 |
| SEC-02 | coverage-guided parser fuzzing | eng | done (host) | fuzz-evidence.md |
| SEC-03 | Mission Control e2e (HTTPS PQ, browser, actions) | eng | done-QEMU (gate = mc-e2e) | mc-e2e |
| SEC-04 | replay guard, write rate limit, login throttle | eng | done-QEMU | Pseqfloor, Pwriterate |
| SEC-05 | owner-signed config + G46 enrol/rotate | op | blocked (G46 security review, never waived) | journey 20/20 metal 20261111-batch59-63.md |
| DET-01 | benign-corpus false-positive rate | op | blocked (tuning proposals await op) | det01-home-24h-2026-11-13.md |
| DET-02 | rule 112 per source; reload without heap leak | eng | done-QEMU | Pverifyheap, P8l2struct |
| DET-03 | signed owner alert webhook | eng | done+metal | 20261110-batch34-35.md |
| CMP-01..05 | RED 3.3/EN 18031, firmware licence, RED 3.1/3.2, CRA, FCC | op / vendor | blocked | signoffs missing |

## Gap-fix plan 2026-11-18

| ID | What | Owner | State | Evidence |
|---|---|---|---|---|
| GF-R1 | bus recovery never re-enters the faulted el0-wifi | eng | done+metal | #1308; metal: bus fault injected inside a reload, recovered in EL1 (#1454) |
| GF-R2..R5 | A-01 review fixes (selftest state, grants, table full, own prefix) | eng | done-QEMU | #1310 |
| GF-R6 | v6 A-01 signed-route exemption | eng → bench | done-QEMU; metal needs an IPv6 upstream on the bench WAN (the bench VLAN has none; fortress001's live PPPoE is not touched) | #1310 |
| GF-R7 | authorize retry when the ioctl was never sent | eng | fix corrected on metal (#1454): the iovar fallback did not authorize; re-sending the ioctl does (6/6) | #1309, #1454 |
| GF-R8 | bus-fault episode cap | eng | done+metal | #1309; metal 2026-11-22: 1 Hz bus faults escalated to a firmware reload in 24 s (comment on #1309) |
| GF-R9, R10 | reseed retry gate; doc comments | eng | done | #1309 |
| GF-E1 | first-boot bring-up via el0-wifi (ADR 0065 D4.4) | eng; ADR edit op | done+metal; ADR status edit open (C2) | #1319 |
| GF-E2 | single gate-status source | eng | done (this document) | — |
| GF-E3 | bench restored before / after config-changing checks | eng | done+metal | #1428 (cfgd-live 20/20 with the wrapper on metal) |
| GF-E4 | local mc-e2e uses a stale UI dist | eng | done | #1427 |
| GF-E5 | ~980 ms post-upload reload round trips | eng | not reproduced on current main: 6/6 instrumented reloads 834–838 ms, slowest control request 21–22 ms; the one 988 ms reload was on a pre-#1432 image | #1440 (comments) |
| GF-H1 (W3) | bench certificate SAN (192.168.200.146, unit name) | bench | done+metal | served cert checked 2026-11-21 (`openssl s_client` against 192.168.200.146:443): SAN heqk.local, r3q1.heqk.local, 10.99.0.1, 192.168.200.146, 10.200.0.6, written by the rpiboot flash of 20261120-l01-fwfiles-b1.md |
| GF-H2 (W3) | browser flasher (ADR 0037) | op / bench | open | remaining-gaps #7 |
| GF-H3 (W3) | G19 PoP tunnel on metal | op | blocked (PoP) | device side `[P-g19]` |
| GF-H4 (W3) | /setup as HQCFG1 bundle metal batch | op | deferred (after the soak) | — |

## Autoheal harness

| ID | What | Owner | State | Evidence |
|---|---|---|---|---|
| AH-H1 | failure kinds + recovery journal (`/api/recoveries`) | eng | done+metal | #1320 |
| AH-H1+ | journal across a warm reset (`previous_boot`) | eng | done+metal (owner reboot + panic reset; watchdog reset not exercised) | #1419 (6/6 owner reboot; panic round am31C, comment on #1419) |
| AH-H2 | supervisor table, one restart path | eng | done+metal | #1327 (7/7) |
| AH-H3 | policy decay / hold-off / planned-reset reasons | eng | done+metal (H3a); H3b done-QEMU (pure policy) | #1328, #1336 |
| AH-H4 | probes (H4a/H4b) + complaint channel (H4c) | eng | done+metal (a/b); H4c done-QEMU (no shipping server can be made to break the protocol on metal) | #1339, #1351, #1409 |
| AH-H5 | CPU budget per server per window | eng | done+metal | #1356 (8/8) |
| AH-H6 | software fault-injection campaign | eng / bench | done+metal (CM5: 1000 injections into lansvc / tlshost / hsh, 0 unrecovered; el0-wpa QEMU only, live on metal) | #1365–#1378, #1446 |
| AH-H7 | state classes + el0-wpa saved-state integrity | eng | done+metal | #1418, #1420 (8/8) |
| AH-D1 | abandoned endpoint: probes for el0-hsh and el0-wpa | eng | done-QEMU | #1430 ([P-probe-hsh], [P-probe-wpa]) |

## ADR 0065 (Wi-Fi out of the kernel)

| Step | Owner | State | Evidence |
|---|---|---|---|
| D4.1 measure, D4.2 substrate, D4.3 control plane | eng | done+metal | #1206, #1208, #1209–#1212, #1232 |
| D4.4 RX/TX/ctl, reload 4e-1..4e-3b, first boot 4e-4 | eng | done+metal | #1219–#1226, #1251, #1267, #1296, #1319 |
| D6 two servers (S0–S4), D7 D-a/D-c/D-d | eng | done+metal | #1229–#1246, #1237, #1242 |
| D7 PMKSA status-53 recovery | vendor | deferred (firmware does not support it) | ADR table |

## LAN / Pi4 assessment

| ID | Owner | State | Evidence |
|---|---|---|---|
| A-01 upstream private blocked by default + owner exceptions | eng | done+metal | d372ba10e, ad7d53d68; 20261114-late.md |
| A-02 client↔client relayed | — | closed (by design) | pi4-assessment.md |
| A-03 / A-04 MC wedge; AP DNS regression | eng | done+metal | #1165, #1179 |
| DNS-01 first blocked answer held ~3 s | eng | done+metal | #1187 |
| H-01 security headers | eng | done | #1161, #1168 |
| L-01b PD loss withdraws | eng | done | #1176 |
| L-02 SAN incl. mgmt IP | eng (code) / bench (cert) | done+metal (bench cert = GF-H1) | a2fcd1d21, 44754c2bc |
| L-03 PQ TLS group from a PQ client | bench | done+metal (X25519MLKEM768 negotiated; device pq_hybrid=1) | metal-evidence/20261122-l03-pq-tls.md |
| W-01 transition downgradable | op | accepted (shipping default) | — |
| W-02 PMF in transition | eng | done+metal (WPA3-only); optional by design | 20261114-night.md |
| W-04 RSNX / beacon protection / WPS capture | bench | open | — |
| EVID-01 evidence survives OTA | eng | done+metal | 20261113-mb24-evid01.md |

## Parity gaps still not closed (`heqk-parity-gaps.md`)

| ID | Owner | State | Note |
|---|---|---|---|
| G0 apcore | eng | partial (steps 1–5b merged) | heqk-apcore-plan.md |
| G12 setup QR + hand-off UI | eng (UI session) | open remainder | UI owned by the designer |
| G19 HTP/SASE tunnel | op | done-QEMU; metal blocked on the PoP | = GF-H3 |
| G24c crypto audit / libcrux ML-KEM | op | blocked (decision) | — |
| G46 owner config-key enrol/rotate | op | built + metal; ship blocked on review | = SEC-05 |
| G47 device rename | eng | done-metal | #966; CM5 2026-11-22 `metal-evidence/20261122-g47-device-label.md` (7/7) |
| G48 first-run /setup wizard | eng | UI built; metal batch deferred | = GF-H4 |
| G24b, G28, G31, G43 | eng | done (see C5) | the parity doc's status is stale |

## Other open items

| ID | Owner | State | Note |
|---|---|---|---|
| EP-E1b SDIO bus efficiency | eng | done+metal | #1432: CMD52 −95%, el0-wifi CPU 44–49% → 35–42%, throughput unchanged (~97 Mbps) |
| EP-L0.1 firmware files out of the image | eng / bench | merged; rpiboot case 4a not run | 20261120-l01-fwfiles-b1.md |
| MT-E1 eth1 (RTL8111H) wired client | bench | open | heqk-metal-test-plan.md |
| MT-J5, MT-J6 GEM RX ring 512; IPv6 re-probe | bench | no dedicated record | audit §3.1 |
| P-256 timing (dudect on CM5) | bench | open (host review done) | 20261108-p256-ct.md |
| ADR 0055 pin / 0056 D1 / 0063 ratification; ADR 0065 / 0044 status edits | op | open | ADR edits are the operator's |
| ADR 0060–0062 multi-core / memory / PoP isolation | op | Proposed — no work without acceptance | — |

## Contradictions for the operator (the docs disagree; this table records the evidence)

- **C1 SEC-01:** `items.txt` still says "blocked: authenticator moves with the driver (not built)". ADR 0065 D4.3/D6 are realized on metal (el0-wpa holds the 4-way, SAE, PMKSA and keys; the in-kernel fallback is gone, #1235). The gate text needs re-scoping (operator-owned file).
- **C2 ADR 0065 status table** still marks D4.4 bring-up / firmware download / reload as "[vision], still EL1"; 4e-1..4e-4 are merged with metal evidence.
- **C3** the gap-fix plan and `heqk-remaining-gaps.md` still list merged work (R1–R10, E1, H1–H7, the authenticator) as to-do. Status is here now.
- **C4 REL-08b:** the gate text predates MB25–MB27 (Infineon test firmware 7.45.314 removes the trap in our setup, with a new rare type-0x7 trap; test firmware, not shippable).
- **C5 parity doc:** G24b open (done + one step closed by decision), G28 / G31 "metal next" (PASS in 20261110-batch34-35.md), G43 "no Wi-Fi upload metal record" (live Wi-Fi apply 14/14 in 20261113-mb17.md; whether that covers the ADR 0058 `wifi` upload path still needs one check).
- **C6 sign-offs:** `docs/release/signoffs/README.md` lists a "certification" sign-off and omits `g46-security-review`, which `items.txt` requires.
- **C7 pi4-assessment.md** still calls A-01 open; the audit 4.2 row still lists DNS-01 open. Both are fixed.
