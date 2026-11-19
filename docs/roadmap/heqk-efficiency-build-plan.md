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
| L0.2 driver provenance register | written, not published | operator decision |

None of the merged items has a CM5 timing yet. All are bench batch B2 / B4.

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
| E1 | Vectored Wi-Fi calls (F2) | `CMD_RX_READV` / `CMD_TX_DATAV`: up to ring-size frames per round trip; one reply buffer; kernel copies once into the NAT scratch | frames per round trip ≥ 8 under a burst; copies per frame falls by ≥ 1 | AP+NAT median ≥ 120 Mbps | P0 |
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
