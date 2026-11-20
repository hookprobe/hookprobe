# heqk efficiency programme: autonomous build plan and regression plan (2026-11-19)

**Authority.** ADR 0067 (Proposed). Nothing here ships until the operator accepts the ADR; work
may be built, gated and measured behind feature flags before that.

**Baseline.** `main` at `4ae769886`. Numbers below are from that tree's own evidence files.

| Metric | Baseline | Source |
|---|---|---|
| IDS cost, home WAN mix, one A76 | 398–441 ns per packet | `docs/design/metal-evidence/20261109-detection-network-series.md` |
| EL0 round trip | 388 ns; 1.2 µs with a full frame | ADR 0065 status table |
| AP + NAT throughput after the EL0 split | 98–106 Mbps (release floor 60, post-split median ≥ 96) | ADR 0065; `20261110-batch29.md` |
| Boot to product loop | 60–70 s | `[BOOT-TIMING]` |
| Evidence-log mount | ~1.5 s | `kernel/src/evlog.rs` |

## 0. Status (2026-11-19, end of day)

| Item | State | Evidence |
|---|---|---|
| P0.1 work counters + g2 ratchet | merged (#1344) | `tools/ci/perf_ratchet.py`, `tools/ci/baselines/perf.json` |
| E3 NAT new-flow allocation | merged (#1345) | `nat_newflow_scan_max` 4096 → 32 |
| E4 incremental NAT checksums | merged (#1347) | `nat_rewrite_csum_bytes` 1500 → 22; `[P-nat-csum]` |
| L0.3a quoted Linux lines removed from comments | merged (#1349) | `gem.rs`, `mailbox.rs` |
| L0.4 SPDX headers + g0 check | merged (#1350) | 234 files |
| Machine-wide lock for heavy runs | merged (#1352) | `validate.sh`, `HEQK_HEAVY_LOCK` |
| N1 evidence records name the config in force | merged (#1354) | `RT_EVIDENCE_C`; `[P-evlog]` |
| X1 step 1, dst-port guards | merged (#1355) | `ids_pack64_prog_runs_other_port` 64 → 1; `[P-ruleguard]` |
| X1 step 2, byte guards (TCP flags) | this PR | `ids_tcp_tier_prog_runs_ack` 4 → 0 |
| X4 step 1, inspection shedding with evidence | draft PR #1363 | rule 129; `[P-inspshed]` |
| X2a step 1, flow-event ABI and queue | merged (#1364) | `hal::flowevt`, 7 host tests |
| X2a step 2, batch mode in the wasip1 host | draft PR #1369 | `wasm_events_per_round_trip` = 16; `[P-wasmevt]` |
| L0.1 step 1, vendor files out of the image (`fwfiles`) | merged (#1367) | `[P-fwfiles]`; SHA-256 pins |
| E1 vectored Wi-Fi calls | **measured on CM5, no gain** (2026-11-21); ABI merged (#1377), integration in draft #1393, features off, not for shipping | see "E1 result" below |
| Metal timing ratchet | draft PR #1376 | `tools/ci/metal_timing.py`, `tools/ci/baselines/perf-metal.json` |
| L0.2 driver provenance register | draft PR #1359 (standalone) | `docs/security/driver-provenance.md`; g0 check |
| ADR 0067 amendment (D12 disclosure record, D13 three reviews) | draft PR #1360 | ADR stays Proposed |

None of the merged items has a CM5 timing yet. All are bench batch B2 / B4.

**First metal figures (2026-11-20, one trial boot; indicative).** Image am22F on the bench CM5 (shipping
features + wpa3 + wifi-inject + fwfiles, booted degraded with no Wi-Fi), from the kernel session's B1 run;
the baseline is `docs/design/metal-evidence/20261109-detection-network-series.md`. Different flavour and a
single boot, so this is not yet a ratchet baseline.

| Measure | Before | 2026-11-20 |
|---|---|---|
| `[IDS-BENCH]` mix, ns per packet | 398–441 | 322 |
| `[IDS-TIERS]` l4-rules | 91 | 52 |
| `[IDS-TIERS]` tcp-flags | 45 | 36 |
| `[IDS-TIERS]` l2 | 20 | 30 |
| `[IDS-TIERS]` flow | 53 | 68 |
| `[IDS-TIERS]` l2-stateful / scan (not rule loops) | 16 / 24 | 30 / 30 |

- The guards lowered the two tiers they target, by less than the QEMU work counters suggest: a skipped
  program still costs its loop iteration and compare.
- The l2 and flow tiers got slower. Probable cause, fixed in this PR: the run counter added with the
  guards used `fetch_add`, which on this target (no LSE atomics) is an exclusive load/store loop per
  program run. It is a plain load + store now. The tiers that are not rule loops also read slower, so
  part of the difference is flavour or boot-to-boot spread; a second capture decides.
- **Lesson for D1:** a work counter must not itself cost on the path it counts. New counters on a
  per-packet path use a plain load + store (single data-plane core) or are compiled only into
  self-test builds.

**Three-boot metal figures (2026-11-20 evening, the ratchet baseline).** Image am23F-1db60802 (main before
#1379; shipping + wpa3 + wifi-inject + fwfiles), three boots, medians via `tools/ci/metal_timing.py`
(`ok (3 boots)`); evidence `docs/design/metal-evidence/20261120-l01-fwfiles-b1.md`.
`tools/ci/baselines/perf-metal.json` now holds ids.mix 321, tier.sum 306, l4-rules 52, tcp-flags 36.

| `[IDS-TIERS]`, ns | 2026-11-09 | trial boot 11-20 | three boots 11-20 (median; per boot) |
|---|---|---|---|
| IDS mix | 398–441 | 322 | **321** (316 / 321 / 321) |
| l4-rules | 91 | 52 | **52** (52 / 52 / 52) |
| tcp-flags | 45 | 36 | **36** (36 / 36 / 36) |
| l2 | 20 | 30 | 24 (24 / 24 / 24) |
| flow | 53 | 68 | 73 (74 / 64 / 73) |
| l2-stateful | 16 | 30 | 31 |
| scan | 24 | 30 | 29 |

- #1372 (no atomic read-modify-write in the run counter) brought l2 from 30 back to 24, not to the 20
  of 2026-11-09. Flow did not improve. l2-stateful and scan, which are not rule loops, stay about 6–15 ns
  above 2026-11-09 for a reason not yet found (image flavour, or changes merged by other work since). The
  two tiers with the most spread (flow 64–74) are not in the ratchet; small values with that spread would
  fail an 8 % bound on noise.
- #1379 (decide() context only on a match) was not in this image; the next capture includes it.

**L0.1 on metal with the files present (same image):** AP up and WPA3 7/7 on three boots; throughput
95.1 / 97.0 / 98.3 Mbps, median 97.0 (floor 96; one boot alone was under it). Firmware reload after a
burst of bus faults: PASS (832 ms, both stations back). Bench baseline and the LAN-client suite PASS
(27 checks). NOT run on metal: the truncated / altered / missing-NVRAM-or-CLM states (each needs its own
flash; QEMU 9/9 stands) and the 33-row matrix (needs a sepdiag image). One unexplained outlier: in the
self-heal claims run, one of ten spaced bus faults took 2,188 ms against a 2,000 ms bound; two further
runs on the same boot passed 4/4 (worst 599 and 711 ms).

**E1 "before" (same image, about 98 Mbps):** el0-wifi peak 614.5 ms of EL0 time per second; el0-wpa
20.7, el0-tlshost 8.2, el0-lansvc 5.7.

**E1 result (2026-11-21, kernel session, draft PR #1393).** Same bench, same client, OTA rounds, median of
three throughput runs; el0-wifi = peak µs of EL0 time per second from `/api/recoveries` `cpu[]`:

| Image | Throughput | el0-wifi µs per s | Frames per call |
|---|---|---|---|
| am23F single-frame calls | 97.0 Mbps | 614,522 | 1 |
| am24V vectored READ | 94.2 Mbps | 607,000–806,000 | 0.02 per read |
| am25T vectored WRITE | 96.5 Mbps | 632,527 | 6.76 per write (0 lost, 0 refused replies) |

- Vectored calls work (round 8/8: OTA, WPA3 before and after a reload, self-heal claims, no fault) but do
  not lower el0-wifi time. On receive there is nothing to batch: the device is drained after every frame
  of a download. On transmit, batching removes only the excursion entry and exit, which is small next to
  the bus time: each frame is still one SDIO CMD53 of up to 1.5 KB, inside EL0.
- Conclusion: el0-wifi's ~61 % of a core is SDIO transfer time. The lever is the bus (clock, block mode,
  DMA), not the call shape: new item E1b. The 388 ns – 1.2 µs round trip measured in ADR 0065 was never
  the cost that mattered at this frame rate.
- The vectored code stays off by default and is not for shipping. Whether to merge #1393 as dormant
  infrastructure or close it is an operator decision; this plan's recommendation is to close it unmerged
  (code with no measured benefit is maintenance cost) and keep the branch for reference.
- **Lesson for the plan:** a cost estimated from a microbenchmark (the round trip) is not a measurement of
  where the time goes. E1 was ranked first on that estimate; the per-server CPU accounting (#1356) plus a
  metal round showed the bus is the cost. Measure the breakdown before ranking the next item.

**Separation matrix on metal (2026-11-21, main 6ab20c2e, sepdiag image, kernel session):** all 7 on-metal
self-tests PASS; frame rows 26 of 31 PASS, 0 FAIL, 5 not observed (A4, A5, L7: rule 113; L8: rule 116;
L10: rule 114). Rule 113: since ADR 0049 D3 a distinct port counts only when the target answers, and the
bench frame generator sends SYNs nobody answers. L8 / L10 are "must not fire" rows the parser cannot prove
from absence (also missing in the September log). The kernel session is fixing the harness. Not a
detection regression as far as known, but the matrix is not fully green on metal until it is.

**Firmware separation (L0.1), state on 2026-11-20.** Step 1 merged (#1367). Integration and bench by the
kernel session (boot-degraded prerequisite #1370, integration PR stacked on it):

- Operator-level decisions taken: the image factory writes the three vendor files on the boot partition
  of EVERY image from now on (the device has no FAT writer, so an OTA cannot add them); no FAT writer
  is built; units already deployed without the files get them later through the upload store (ADR
  0056) with the same pins; `fwfiles` stays out of `shipping-features.txt` until every image in
  service has the files or that path exists.
- Prerequisite found: without Wi-Fi at boot the AP image never reached the serve loop, so Mission
  Control was unreachable (independent of fwfiles). #1370 enters the serve loop degraded.
- rpiboot, 2026-11-20 16:50: the one operator-approved full flash (image am23F) did not start — the
  boot ROM never enumerated over USB in 15 s; nothing was written and the board is back on its previous
  image. A second attempt needs a physical check of the USB link and a new go-ahead.
- B1 so far: firmware absent PASS on the CM5 (15/15, by OTA; the trial does not commit); truncated /
  altered / NVRAM or CLM absent PASS in QEMU on the factory disk image (9/9); the fwfiles slot image is
  600,528 bytes smaller and holds no firmware bytes. NOT run: files present with throughput, firmware
  reload, the 26-check regression and the 33-row matrix. They need full flashes (operator go-ahead).
- For counsel (package A): behind `wifi-pmkid-fix`, which the shipping flavour includes through `wpa3`,
  the driver changes instruction bytes of the running firmware in the chip's RAM (REL-08 workaround).

**What the evidence changed in this plan.**

- **P0.2 (PMU timing) is not needed for the IDS path.** `idsbench.rs` already times `packet::verdict`
  and each tier with the generic timer and prints `[IDS-BENCH]` / `[IDS-TIERS]` at AP boot. The last
  metal figures (`docs/design/metal-evidence/20261109-detection-network-series.md`), TCP data, ns per
  tier: parse 11, l2-stateful 16, l2 20, flow 53, scan 24, conn-rate 13, resource-shed 30, ja4 4,
  tcp-flags 45, l4-rules 91. What is missing is the gate: a g6 step that compares those lines with a
  baseline (8 % tolerance). PMU counters stay useful only for paths with no bench of their own.
- **X1 was re-scoped by that table.** The two largest tiers are rule loops over template programs
  (l4-rules 91 ns, tcp-flags 45 ns). Steps 1 and 2 skip those programs with a guard read from the
  program itself. The fused single program of ADR 0067 D5 is deferred until the metal figures after
  B4 show what is left.
- **E1 is the first bench item.** Measured on CM5 by the per-server CPU accounting of #1356, at a
  median 96.5 Mbps through the AP: el0-wifi used up to 610 ms of EL0 time per second (61 % of a
  core); el0-wpa 20.7 ms, el0-tlshost 6.2 ms, el0-lansvc 5.7 ms.
- **E9 (evidence-log mount scan): dropped (operator, 2026-11-19).** The full scan is what
  authenticates and counts every record ([P-evlog] tamper case, the honest-retention count). A
  shortcut would save about 1.5 s of a 60–70 s boot and let one forged slot mislead where the head is.
- **X2a is three steps, not one.** The Wasm host is not resident: each run spawns a host and a server
  thread in the scheduler demo and returns one 32-bit result; the WASI path takes 64 bytes of input
  and returns the first output byte. Step 1 (done): the record format, the 2-bit verdict word
  (16 records per round trip) and a bounded queue, in `hal::flowevt`. Step 2: a batch module in
  `wasip1-fixture` (n records in, n verdict bytes out) and batch mode in `el0-wasmhost` (a 256-byte
  input, the host packs the verdict word), with a QEMU phase `[P-wasmevt]`. Step 3: a resident host
  the product loop calls, which touches the EL0 server supervision (`el0srv.rs`) and is coordinated
  with the autoheal work.
- **X4's trigger is weak today.** Step 1 uses `ratelimit::under_pressure()` (run-queue depth), which is
  near zero in the single polled product loop. A loop-gap signal is the follow-on before X4 means
  anything on metal.
- **E5 (frame zeroing): lowest priority.** It runs only when an EL0 server is spawned.
- **L0.1 (firmware as files) needs a design and the bench.** The firmware is patched in place at
  fixed offsets and written from the embedded image; the kernel heap is a 1 MiB bump allocator; the
  path is CM5-only.
- **Load makes QEMU gates lie.** Two sessions running validate.sh at once starved the TCG guest and
  failed the time-bounded EL0 phases. Heavy runs now take one machine-wide lock (#1352). The cause
  (a scheduler demo that exits after a fixed 300 ticks) is not fixed.

## 1. How the work runs (autonomy rules)

One item = one branch = one draft PR. The loop for each item:

1. Read the item's row; write the work-counter phase in `validate.sh` **first** and see it fail.
2. Implement behind the item's cargo feature.
3. `tools/ci/gates.sh pr`, then `tools/ci/gates.sh full`. Fix until green.
4. Add or update the item's line in `tools/ci/baselines/perf.json` (counters only; timings wait
   for metal).
5. Open a draft PR with the gate output and the counter before/after. Start the next item
   without waiting for the merge.
6. Queue the item's metal check in section 5.

Tiers (CLAUDE.md, ADR 0063):

| Tier | Who | What |
|---|---|---|
| Green | autonomous | analysis, evidence files, provenance register entries |
| Amber | autonomous, operator reviews the PR | code behind a feature flag, gates, baselines, this plan |
| Red | operator only | merges, `shipping-features.txt`, metal batches, flashing, signing, counsel, patent-or-publish, pushing D5–D9 detail |

Stop and ask only when: a Red step blocks the next item; a gate in `tools/ci/heal/protected-paths.txt`
would have to change; an item needs the bench CM5 slot; or a change would weaken a row of the
ADR 0023 separation matrix.

## 2. Wave 0: prerequisites (measurement and licence)

| # | Item | Change | Gate | Tier |
|---|---|---|---|---|
| P0.1 | Work counters | A `perfctr` module: per-loop counters for frames per EL0 round trip, copies per frame, NAT entries scanned per new flow, rule evaluations per packet, excursions per event. Printed as `[PERF] name=value` at the end of the QEMU run | `[P-perfctr] PASS`; `tools/ci/perf_ratchet.py` parses into `out/ci/perf.json` and compares with `tools/ci/baselines/perf.json` in g2; self-test in `tools/ci/tests` | Amber |
| P0.2 | PMU timing | EL1 reads `PMCCNTR_EL0` around the IDS bench, the NAT new-flow path, an EL0 round trip and TLS record seal. EL0 access stays off (ADR 0062 D5) | g6 reads `[PERF-T]` lines; fails beyond 8 % of baseline | Amber, metal Red |
| P0.3 | Throughput probe in the metal regression | The existing AP+NAT measurement becomes a recorded metric, not only a floor | g6 median within 8 % of baseline and ≥ 96 Mbps | Red (bench) |
| L0.1 | Firmware out of the image (F13) | Remove the three `include_bytes!` in `cyw43.rs:594-596`; el0-wifi reads the files from the boot partition; missing files → Wi-Fi capability reported unavailable. Update `stage-firmware.sh`, `make-cm5-heqk-disk.sh`, and remove the tracked copies under `os/kernel/firmware/` | `[P-fwfiles] PASS` (present, absent, truncated, wrong size); `shipping_guard.py` refuses an image whose kernel ELF contains the blob hashes | Amber; removal from git history is Red |
| L0.2 | Provenance register (F14) | `docs/security/driver-provenance.md`: one row per driver file with sources and readers. Confirm the licence of each cited upstream file (brcmfmac is believed ISC, hostapd BSD-3; to be confirmed per file). List the files whose only source is GPL-2.0: `rng200.rs`, `hboot/src/rng.rs`, `gem.rs` RP1 block, `rtl8111.rs` outbound window, `hboot/src/watchdog.rs`, the SDHCI quirk block | g0 check: every file under `arch-aarch64/src` and `hboot/src` has a register row | Green |
| L0.3 | Clean rewrites | For each GPL-2.0-only file in L0.2: one session writes a functional note from the datasheet and observed register behaviour; a separate session that has not opened the Linux file implements from the note | The driver's existing phases stay green; metal check of the device | Amber, counsel Red |
| L0.4 | SPDX headers (F15) | `SPDX-License-Identifier: AGPL-3.0-only` on every first-party source file | g0 check | Amber |
| L0.5 | Patent-or-publish record | A table in ADR 0067 notes: D5–D9, each marked file / publish / hold | none | Red |

P0.1 lands first. Every later item names the counter it moves.

## 3. Wave 1: single-core engineering (ADR 0067 D3, D4)

| # | Item | Change | Counter (QEMU, g2) | Timing (CM5, g6) | Depends |
|---|---|---|---|---|---|
| E1 | Vectored Wi-Fi calls (F2) | **Done and measured: no gain** (see section 0, "E1 result"). The time is SDIO transfer, not round trips. Replaced by E1b | — | — | P0 |
| E1b | SDIO bus efficiency (F2) | The lever E1 found: per-frame bus time inside el0-wifi. Candidates, unmeasured: the SDIO clock the bus runs at, block-mode transfers for larger frames, DMA instead of programmed I/O. Owned by the kernel session (bus driver). Measure the bus clock and the per-frame CMD53 time before choosing | el0-wifi µs per frame (a self-test burst) | el0-wifi ms/s at the throughput check, below 614.5; Mbps not lower | E1 measurement |
| E2 | Async GEM transmit (F3) | TX ring 2 → 64; kick without waiting; reap completions at the top of the loop; back-pressure when full | TX completion polls per frame ≤ 1 | WAN TX ns per frame down ≥ 30 % | P0 |
| E3 | NAT free list + LRU (F4) | Intrusive free list and LRU list in the entry table | entries scanned per new flow = 1 (was up to 4,096) | new-flow ns down ≥ 10× at a full table | P0 |
| E4 | Incremental checksums (F4) | RFC 1624 update on address and port rewrite; full recompute stays as the test oracle | checksum bytes summed per rewrite ≤ 20 | NAT rewrite ns down | P0 |
| E5 | Frame zeroing (F5) | `dc zva` with the block size from `DCZID_EL0`; word loop as fallback | zeroing loop iterations per frame | EL0 server spawn ms down | P0 |
| E6 | Deeper GEM RX ring (F11) | Multi-page EL0 grant; RX ring to 1,024 | `[P-gemring]` grant bounds cases | zero RX overruns at the baseline saturation load | ADR 0061 D2 budget row |
| E7 | Hardware crypto, el0-tlshost (F6) | Read `ID_AA64ISAR0_EL1` into the manifest; a second el0-tlshost build with `+neon,+aes,+sha2`; per-excursion FP enable and `v0–v31` zero on exit | `[P-fpscrub]`: FP registers read zero in the next server; scalar fallback selected when the capability is absent | TLS record seal ns down ≥ 3× | P0.2; security-auditor review |
| E8 | Boot verify cost (F6, F12) | Measure SLH-DSA-128s verify in hboot; build the verifier at `opt-level=3`; if the capability is present use SHA-2 instructions (FP enabled only inside hboot verify) | image size stays under `ap-size-gate.sh` | verify ms recorded, then ratcheted | P0.2 |
| ~~E9~~ | Evidence-log mount (F12) | **Dropped (operator, 2026-11-19)**: the full scan authenticates and counts every record; see section 0 | — | — | — |
| E10 | SMP | Execute ADR 0060 as written, after E1–E4 | ADR 0060 gates | ADR 0060 gates | ADR 0060 accepted |

## 4. Wave 2: distinctive mechanisms (ADR 0067 D5–D9)

Each stays behind its feature until its metal gate passes **and** D12/D13 are recorded.

| # | Item | Steps | Proof |
|---|---|---|---|
| X1 | Policy-specialised path (D5) | 1. cfgd emits a fused program from rules + ACLs + reach + NAT config at commit. 2. PREVAIL verifier, then JIT. 3. Atomic pointer swap at a loop boundary; generic walk as fallback when verify or JIT refuses. 4. Oracle mode: run both on every packet and compare | `[P-spec] PASS`: oracle equality over the detbench corpus and the 33 separation rows; a commit mid-burst never mixes generations; counter: rule evaluations per packet falls; CM5: IDS ns per packet ≤ 300 |
| X2a | Wasm on a batched event path (D6, F8) | Flow-close and periodic flow-summary events are queued and delivered to el0-wasmhost as a vector per round trip | `[P-wasmevt] PASS`; counter: events per excursion ≥ 16; CM5: ns per event recorded |
| X2b | Sign-time native artifact (D6) | 1. `heqk-sign` compiles Wasm → aarch64 on the host and signs both. 2. CI rebuilds and compares hashes (g4r). 3. Differential corpus: native vs wasmi results equal. 4. Loader maps W^X in the module's EL0 space; wasmi fallback | `[P-wasmaot] PASS`: tampered native refused, mismatch refused, fallback taken; CM5: ns per event vs X2a |
| X3 | Verdict tokens (D7) | Per-flow token after N unremarkable packets; revoke on cfgd commit, rule or blocklist update, and budget expiry; flow-level rules and resource-shed counters unaffected | `[P-vtoken] PASS`: all 33 separation rows with tokens on; an attack starting after a token is issued is caught within the budget; revocation is immediate on commit; counter: tier walks per packet on long flows; CM5: Mbps and IDS ns on the WAN mix |
| X4 | Inspection shedding with evidence (D8) | Pressure signal (loop gap, pool watermark) → ordered shedding → sealed record per interval → `/api` field for the inspected fraction | `[P-shed] PASS`: legitimate flows pass under induced pressure; a sealed record exists for every shed interval; confirmed-attack drops continue |
| X5 | Thermal budget (D9) | 1. Read the SoC temperature and clock via the mailbox; record only. 2. Governor: idle strategy and poll interval from load. 3. Clock scaling. 4. Tie to X4 at the upper watermark | `[P-thermal] PASS` with a mocked sensor; CM5 enclosure run: temperature and Mbps logged for 1 h at load |

## 5. Wave 3: system state and learning (ADR 0067 D10)

| # | Item | Change | Proof | Blocker |
|---|---|---|---|---|
| N1 | Same-record provenance | Enforcement evidence records gain config generation + ruleset hash + module version | `[P-evprov] PASS`; record size and records-per-ring recomputed and shown honestly | none |
| N2 | Checkpoint-and-resume recovery | Finish `feat/h1-recovery-journal` / `feat/h2-supervisor-table` on step records with idempotency keys; no history replay | kill-at-every-step test: each workflow resumes once and never repeats a completed step | operator merges those branches |
| N3 | Transactional learning experiment | Wrap Neural DNA updates and the owner's signed confirmation in one `ownerjournal` record; crash, restart, duplicate-confirmation and audit cases | host test + QEMU el0-neuro; memory and ns per event vs the unwrapped baseline | Neuro on `main`; ADR 0048 |
| N4 | Lease admission for signed model packages | Extend ADR 0061 D4: a package manifest reserves memory and CPU share; revocation reclaims without touching the packet path | cfgd refuses over-budget packages with a reason; revoke under load leaves the perf counters unchanged | ADR 0061 accepted |
| N5 | Fleet sharing of observations | Design note only | none | counsel (ADR 0067 D13) |

## 6. Regression plan

**Per PR (autonomous).** `tools/ci/gates.sh pr` (g0 g1 g4), then `full` (adds g2, g3).

| Check | Where | Fails when |
|---|---|---|
| Phase ratchet | g1, `tools/ci/baselines/validate-phases.txt` | any existing `[P-*] PASS` disappears |
| Separation matrix (33 rows) | g2, `0.7-separation-matrix` | any row changes, with every new feature both off and on |
| Work-counter ratchet | g2, `perf_ratchet.py` | a counter is worse than `baselines/perf.json` |
| Oracle equality | g2 (X1, X2b, E4) | fast path and reference path disagree on any corpus input |
| Detection replay | `tools/detbench` | detections differ from the recorded set |
| Mission Control | g3 | typecheck, UI suite or mc-e2e fails (no UI change is planned; this proves none leaked) |
| Supply chain and licence | g4, g0 | a non-permissive dependency, a missing SPDX header, a driver without a provenance row, firmware bytes inside the kernel ELF |
| Reproducibility | g4r (nightly) | two builds of the shipping flavour differ, or an X2b native artifact does not rebuild to the signed hash |
| Image size | `ap-size-gate.sh` | the AP image exceeds its limit |

**Feature matrix.** Each item's phase runs with its feature on. The whole of g2 also runs with
all new features off (the shipping flavour until promoted) and with all on together.

**Metal batches (operator, bench CM5).** Batches are grouped to save flashes: B1 = P0.2 + P0.3 +
L0.1; B2 = E1–E5; B3 = E6–E8; B4 = X1 + X3; B5 = X2a + X2b + X4; B6 = X5 (enclosure). Each batch
runs, in order:

1. `cm5-bench-baseline.sh`, then the 26-check CM5 regression of `main`.
2. The metal separation rows (`mc-e2e-metal.sh`).
3. `[PERF-T]` timings and the AP+NAT throughput run, three boots, median recorded.
4. An evidence file under `docs/design/metal-evidence/`, then the `perf.json` timing baseline
   moves in a reviewed commit.

A batch that misses a floor (60 Mbps release floor, 96 Mbps median, any timing beyond 8 %) is
reverted at the feature flag; the item returns to step 2 of section 1.

**Out of scope.** REL-05 (72 h soak) and REL-08 stay excluded, as in the 2026-11-18 gap plan.

## 7. Order and dependencies

```
P0.1 ─┬─ E1 ─ E2 ─ E3 ─ E4 ─ E5 ──────────── B2 ─┬─ E10 (ADR 0060)
      ├─ L0.1 ─ L0.4 ─ L0.2 ─ L0.3              │
      ├─ P0.2 ─ E7 ─ E8 ─ E6 ──────────────── B3 │
      ├─ X1 ─ X3 ─ X4 ──────────────────────── B4/B5
      ├─ X2a ─ X2b ──────────────────────────── B5
      ├─ X5 ─────────────────────────────────── B6
      └─ N1 ─ N2 ─ (N3, N4 after their ADRs)
```

Operator inputs that unblock the most: accept or amend ADR 0067; the D12 patent-or-publish
record; bench slot for B1; merge of the recovery-journal branches; counsel on F13, F14, D5, D7.
