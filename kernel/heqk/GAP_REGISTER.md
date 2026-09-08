# HEQK Gap Register — deep sweep 2026-07-24

Consolidated from a 5-way parallel audit (CORE / DET / DRV / SEC / DSN+XC), each
cross-checked against HEQK_REMEDIATION_PLAN.md and commit e1da341 so only
STILL-OPEN gaps are listed. Closing top-down, one gap per change.

## CORE (P0–P4) — microkernel

| ID | Sev | File:line | Gap | Fix |
|---|---|---|---|---|
| CORE-1 | High | main.rs:291,2753; caps.rs | revoke can't unmap live MMIO/DMA grants (mapping bypasses cap invocation) | route mapping through Frame/PageTable caps; revoke walks+unmaps (A1) |
| CORE-2 | High | main.rs:2357 static mut ROOT | one global CSpace for all EL0 tasks → confused deputy | per-TCB CSpace root keyed on current_tid (A6) |
| CORE-3 | Med→High | caps.rs:127,184 | retype after revoke reuses Untyped WITHOUT zeroing → stale-secret leak | zero [base,base+need) on retype |
| CORE-4 | Med | mmu.rs:371 | QEMU JIT code RO+X but keeps writable alias (CM5 seals, QEMU doesn't) | port jit_seal to QEMU path (X1/A4) |
| CORE-5 | Med | mmu_cm5.rs:427 map_user_in | per-ASID grant path lacks user_va_ok check + tlbi (L-14 asymmetry) | add range check + tlbi vaae1is (A9) |
| CORE-6 | Med | main.rs:62-67,2452 | EL0 fault-restart state GLOBAL not per-TCB (M-8 not fully closed) | move restart params+count into scheduler slot |
| CORE-7 | Med | thread.rs:9; no CPACR | FP/SIMD traps; frame saves no q-regs; leak if FPEN later set | decide policy: keep trapped+documented, or save/scrub (A5) |
| CORE-8 | Low→Med | scheduler.rs:57,107,112,43 | tid accessors unbounded add() (latent OOB); spawn_as silent drop >8 | bounds-check tid; return spawn error (A8) |
| CORE-9 | Med latent | caps.rs:56,205 | CDT parent = raw slot index, no generation → stale re-attach on reuse | generation-tagged MDB (A11) |
| CORE-10 | Low | mmu.rs:304; mmu_cm5.rs:412 | ASIDs never reclaimed, wrap to 0 (collides kernel TLB tag) | reclaim on TCB death; never issue 0 (A10) |
| CORE-11 | Low | ipc.rs:44,53,83 | recv() returns 0 for both empty + busy; no badge/len; single endpoint | Result return; per-endpoint waiter queues+badges (A7) |
| CORE-12 | Low | heap.rs:58 | bump allocator never frees → alloc-driven DoS | real allocator when untrusted input reaches alloc (A12) |

## SEC (P7-SEC) — secure boot / attestation

V-items: V1 CLOSED, V10 CLOSED(as-documented); V2/V3/V4/V5/V6(partial)/V7/V8/V9 OPEN.
Verified-correct (NOT gaps): hybrid ed25519+SLH-DSA both-required over sha256(svn‖hash);
SVN bound into signed message; load geometry pinned; AK zeroized (moot under SEC-2).

| ID | Sev | File:line | Gap | Fix |
|---|---|---|---|---|
| SEC-1 (V2) | High | ak_derive.rs:203 | first-boot OTP burn discards TRNG liveness → predictable per-device AK fused irreversibly | check live-word count; skip burn + SW-AK fallback if live<8 |
| SEC-2 (V3) | High | stage2.rs:63 | EL1 can read OTP secret via VC mailbox (GB4..511 RW) → reconstructs "non-extractable" AK | invalidate mailbox page in stage-2; expose OTP only via hvc |
| SEC-3 (V4) | High | config.txt:33 | os_check=0 + unsigned hboot8.img → whole chain TOFU | enable BCM2712 signed-boot; until then document TOFU |
| SEC-4 (V7a) | High | main.rs:286→344 | measure→launch TOCTOU: payload hashed then copied, never re-hashed before EL1 entry | re-sha256(load_pa,size) after copy, park on mismatch |
| SEC-5 (V5) | Med | ak_derive.rs:147 | AK = KDF(OTP) only, no PCR0 binding → tampered HBoot derives same AK | ak_seed = KDF(OTP, PCR0_after_self_measure) |
| SEC-6 (V6) | Med | rollback.rs:39 | anti-rollback inert: FLOOR=0, never advanced, images svn=1 | real SVN counter + advance_floor release step |
| SEC-7 (V9) | Med | attest.rs:119 | ephemeral attest seed + nonce ignore TRNG liveness → predictable key | require full liveness or refuse to publish key |
| SEC-8 (V7b) | Med | linker.ld:37 | HBoot stack grows toward image, no guard page → silent overrun corrupts measured bytes | unmapped guard region below __stack_top |
| SEC-9 (V8) | Low-Med | hboot/mmu.rs:53 | EL2 GB0 Normal RWX — HBoot code W^X hole at highest privilege | split GB0, .text RO+X, data RW+XN |
| SEC-10 (V10) | Low | watchdog.rs | A/B hvc#1 is reliability not security (documented) — keep framing | none; keep SECURITY.md framing |

## DRV (P9/P10/P14) — metal drivers

Verified-closed: D1/D2/D5, M-3/L-15 (in read_sdpcm_frame), M-4/M-5/M-6, H-1, L-10/L-11, D4.

| ID | Sev | File:line | Gap | Fix |
|---|---|---|---|---|
| DRV-1 | High | main.rs:1081; gem.rs:610 | NO real IRQ-driven RX. BLOCKED (metal 2026-09-08): RP1 emits NO MSI (both sinks status=0 under load) because its PCI MSI-X table is unprogrammed AND unreachable — heqk EXT_CFG config access to RP1 (bus1) returns 0xffffffff. Polled RX fully works. NOT an M2 gate | needs a PCIe config-access subsystem OR RP1 datasheet OR Linux-ref boot (see DRV-1 detail) |
| DRV-2 | High | main.rs:1054; iommu.rs:96; gem.rs:119 | P14 protects nothing live: iommu2(RTL) fenced but link DOWN; iommu5(GEM, the live master) unfenced; ceiling 1GiB sits ABOVE all kernel/DMA memory | fence iommu5 above live ring PAs; relocate kernel above ceiling or invert window (C1/X5) |
| DRV-3 | Med | iommu.rs:102,45,74 | fence ceiling math unverified: wrapping_sub(1) underflow→0xFFFFFFFF no-op; ADDR_CAP_SHIFT guessed; weak present-check | read back ADDR_CAP + assert; saturating sub; confirm shift on metal (C3/C4) |
| DRV-4 | Med latent | cyw43.rs:2370,2388 | bcdc_dcmd remainder read did NOT get the M-3 fix → control reply >576B assembles STALE bytes of prior frame | same clamp+zero as read_sdpcm_frame; loop transfer in ≤512B chunks |
| DRV-5 | Low | rtl8111.rs:608 | poll_rx ignores FS/LS segment bits; RX-error frames returned as None (indistinguishable from idle) | check FS|LS; surface RX errors as counted, not masked |

## DSN — design-phase gaps (P11/P12/P13/P15/P17)

| ID | Phase | Sev | Gap | To close |
|---|---|---|---|---|
| DSN-1 | P11 | High | P11-R1: EL0 keeps RW on MMIO → can relocate HW ring, defeats H4 (mitigation=iommu fence, which XC-3 shows broken) | doorbell-only MMIO sub-page or kernel register-write syscall; fix XC-3 first |
| DSN-2 | P11 | Med | no substrate: NetDev/LoopDev/own[] table/private capacity unwritten; rings still duplicated | build the trait + impls + ownership table; unify rings |
| DSN-3 | P11 | Med | H3/no-RMW sound only under single-core invariant (XC-1) | land XC-1 first |
| DSN-4 | P12 | High | one CSpace → "publisher may not subscribe" inexpressible (=CORE-2/XC-6) | per-TCB CSpace root |
| DSN-5 | P12 | Med | MAX_THREADS=8 exactly full; needs 16 | raise + re-verify arrays |
| DSN-6 | P12 | Med | SYS_EXIT_USER → stale KRESUME for scheduled TCB (latent bug, fix regardless) | gate on !EL0_SCHED_MODE + SYS_TASK_EXIT + switch_to() |
| DSN-7 | P13 | Med | safety = one deny-list; granting io_bank page = all 28 pins (console/PHY) | SYS_GPIO_OP masked; owner table; validate-before-write; bounded waits |
| DSN-8 | P15 | High | seal claim cosmetic until V3 closes (=SEC-2/XC-10) | close V3 as hard prereq |
| DSN-9 | P15 | Med | brick-risk write path unbuilt; shared clk-emmc2 with live WiFi | sdhci.rs transcribe; dual write gates; get_clock_rate only; no CMD6/38/42/RPMB |
| DSN-10 | P17 | Med | CNTKCTL_EL1 never set (no EL0 Instant); no multi-page EL0 loader; needs per-TCB restart (CORE-6) | set EL0PCTEN + time_us; fixed-VA loader; land CORE-6 |
| DSN-11 | P17 | Med | smoltcp = biggest attack surface; seed must be TRNG not cntpct; pin+measure into PCR3 | pin+checksum; TRNG seed; PCR3 measure |

## XC — cross-cutting (dedup: XC-3≈DRV-2, XC-5/6/7≈CORE-1/2/3, XC-9/10≈SEC-3/2, XC-13≈SEC-1, XC-16≈L-13)

| ID | Sev | Area | Gap | Fix |
|---|---|---|---|---|
| XC-1 | Med(High@P11/12) | ARCHITECTURE.md, events.rs | single-core invariant undocumented AND unenforced (push_hit HEAD non-atomic) | document as contract; push_hit HEAD=fetch_add; ratelimit CAS |
| XC-2 | Med | mmu.rs | W^X hole on QEMU backend (map_code_page leaves RW alias; no jit_seal) | port jit_seal to mmu.rs |
| XC-3 | High | iommu.rs | =DRV-2: fence protects nothing (ceiling below all sensitive mem; shift unverified) | relocate kernel above ceiling; readback ADDR_CAP |
| XC-4 | Med | gem.rs, napi.rs | =DRV-1: RP1 GEM poll-only, no RX-IRQ/MSI-X; NAPI re-arm aspirational | discover INTID + wire GIC SPI to napi |
| XC-5 | High | main.rs, caps.rs | =CORE-1: caps asserted not enforced; revoke can't unmap | route mapping through caps; revoke unmaps |
| XC-6 | Med(High@P12) | main.rs:2357 | =CORE-2: single global CSpace | per-TCB CSpace |
| XC-7 | Med | caps.rs:102 | =CORE-3: no zero-on-reuse → cross-tenant disclosure | write_bytes(0) on retype/reset |
| XC-8 | Med | thread.rs | =CORE-7: no FP/SIMD policy | decide + implement |
| XC-9 | High | hboot main.rs | =SEC-3: unverified first stage (TOFU) | signed-boot or document |
| XC-10 | High | stage2.rs | =SEC-2: EL1 reads OTP via mailbox | remove mailbox page from EL1 map; hvc proxy |
| XC-11 | High latent | ratelimit.rs, l7.rs, bpf.rs | untyped BPF helper ABI: payload_match derefs R1 raw → arbitrary-kernel-read oracle (CVE-2021-4204 class) | per-helper ABI sig table; bounds-check in helper |
| XC-12 | Med | ratelimit.rs:36 | rate-limiter no key tag → victim-targeted DoS via collision | store full key per slot; reset on mismatch |
| XC-13 | Low-Med | ak_derive.rs:205 | =SEC-1: OTP burn not gated on TRNG liveness | gate burn on live==8 |
| XC-14 | Low-Med | bpf.rs:290 | unsound legacy verify() still callable | delete/rename so it can't gate a JIT |
| XC-15 | Med | validate.sh | QEMU-vs-metal coverage gap; no cap-invariant property tests; P11-17 no gate | dual-backend property tests; CSDB after bounds; per-phase gates |
| XC-16 | Low | gem.rs poll_rx | =L-13 (deferred): fabricates len=out.len() → bogus frames to IDS | read len from status writeback only |

## DET (P5–P8) — detection plane

| ID | Sev | File:line | Gap | Fix |
|---|---|---|---|---|
| DET-1 | High | l7.rs:24; bpf.rs:478 | =XC-11: untyped CALL ABI; payload_match derefs rule scalar R1 → kernel-read oracle | per-helper ABI sig table; fold pattern len into min_len |
| DET-2 | Med-High | rules.rs:86 | "signed rule" but NO signature verification exists (only verify_prevail) | ed25519/FIPS-205 gate in compile_set before verify_prevail |
| DET-3 | **High** | net.rs:59,79 | **>3 VLAN tags → fail OPEN** (ip_proto=0, classify PASS) → all L4/scan rules skipped. Exploitable NOW by L2 sender | residual-VLAN after cap → return None (fail closed) |
| DET-4 | Med-High | bpf.rs:157; packet.rs:134 | FLOW tier (SYN-flood/blocklist) self-parses FIXED offsets; ONE VLAN tag shifts +4 → rule PASSes. Exploitable NOW | run FLOW rules against normalized net.rs view |
| DET-5 | Med | ratelimit.rs:14 | =XC-12: rate-limiter no key tag → collision DoS | store full key; reset on mismatch |
| DET-6 | Med | main.rs:674 vs rules.rs:131 | JIT↔interp differential covers only THREAT/PARSE; live corpus JIT'd rules uncrossed-checked | differential over EVERY JIT'd rule |
| DET-7 | Med | bpf_jit.rs:330 | =XC-2/DET: QEMU publish_exec_page never seals RW alias (W^X hole) | port jit_seal to mmu.rs |
| DET-8 | Med | events.rs:44; main.rs:2042 | telemetry ring has NO live drainer → >64 detections silently OVERRUN-dropped | EL0 exporter poll/drain loop |
| DET-9 | Low | rules.rs:131 | VM INVALID (fault) logged identically to DROP → wrong attribution, inflates QSecBit | distinguish INVALID→VmFault event |
| DET-10 | Low | telemetry.rs:43 | QSecBit monotonic no decay; drop scored twice | windowed/EWMA; score once |
| DET-11 | Low | rules.rs:142 | push_hit always src=0 → SIEM can't identify attacker | thread IP-src hash |
| DET-12 | Low | bpf.rs:290 | =XC-14: unsound legacy verify() still callable | delete/rename |
| DET-13 | Low | absdom.rs:114 | tnum transfer fns not harness-checked; tnum_add proven only to width 6 | Abs-level harness + wrap concretes |

---

## MASTER CLOSING PLAN (deduped, ranked value÷risk)

**Wave 1 — detection integrity, small & exploitable now:** ✅ DONE (DET-3, DET-4, DRV-4, XC-16/L-13, DET-9 — commits eaa95e5, 4b3a1f3; QEMU 0 failing)
**Wave 2 — cheap hardening / unblockers:** ✅ DONE (DET-5/XC-12, DET-12/XC-14, CORE-8, DET-11, XC-1)
**Wave 3 — self-contained security:** ✅ 5/6 DONE (CORE-3/XC-7, CORE-5, SEC-4, SEC-1/XC-13, SEC-8; hboot+CM5 items metal-pending). DEFERRED: DET-7/XC-2/CORE-4 jit_seal-on-QEMU (needs boot-MMU restructure, QEMU-only, production sealed)
**Wave 4 — security ABI:** DET-1/XC-11 helper ABI, DET-2 rule signature gate
**Wave 5 — structural (large, gated):** CORE-1/2+XC-5/6 caps+per-TCB CSpace (→P12), CORE-6 per-TCB restart (→P17), DRV-2/XC-3 IOMMU, DRV-1/XC-4 RX-IRQ, SEC-2/3 signed-boot+OTP
**Then:** implement design phases P13 → P15(ro) → P17 → P11 → P12


---
## Progress (2026-07-24)

**CLOSED (21 gaps), all QEMU-green, committed:**
DET-3, DET-4, DRV-4, L-13/XC-16, DET-9, DET-5/XC-12, DET-12/XC-14, CORE-8, DET-11,
XC-1, CORE-3/XC-7, CORE-5, SEC-4, SEC-1/XC-13, SEC-8, DET-1/XC-11, DET-2, SEC-7,
DRV-3, DRV-5, DET-10.

**METAL-PENDING** (build-clean, need a flash to confirm on hardware): CORE-5, DRV-3,
DRV-5 (CM5 driver), SEC-1, SEC-4, SEC-7, SEC-8 (hboot). Image: heqk8.img payload
sha 214b6961..., svn 1, hybrid-signed.

**DEFERRED w/ rationale:** CORE-4/DET-7/XC-2 (jit_seal-on-QEMU — boot-MMU restructure,
QEMU-only, production sealed); DET-2 per-rule sig (tied to unbuilt dynamic loading;
static rules are image-signed).

**REMAINING — large structural / feature (dedicated passes):**
- CORE-1/XC-5 caps enforcement (route mapping through caps; revoke unmaps)
- CORE-2/XC-6 per-TCB CSpace: MECHANISM DONE (spec PER_TCB_CSPACE.md; global ROOT->CSPACE[tid], resolve against caller; P2/P3 green). Delegation (mint_into) + [P2-iso] isolation gate DONE (rights-narrowing cross-CSpace grant proven). Only the per-spawn wiring into real EL0 TCBs remains, lands with P11/P12.
- CORE-6 per-TCB restart params (unblocks P17)
- CORE-9 CDT generation-tagged MDB; CORE-10 ASID reclaim; CORE-11 ipc Result/badges; CORE-12 real allocator
- DRV-1/XC-4 RP1 RX-IRQ MSI-X; DRV-2/XC-3 IOMMU relocate kernel
- SEC-2/XC-10 OTP stage-2 isolation + hvc proxy; SEC-3/XC-9 signed-boot (operator/irreversible);
  SEC-5 AK PCR0 binding; SEC-6 SVN floor; SEC-9 EL2 W^X
- DET-6 differential over all JIT'd rules; DET-8 telemetry drainer (tied to P12); DET-13 tnum harness; XC-15 dual-backend property tests
- Design phases: P13, P15(ro), P17, P11, P12

---
## Update: surgical/medium phase complete (23 closed)

Added since last checkpoint: CORE-10 (never issue ASID 0), CORE-11 (ipc Option/bool).
**Total closed: 23**, all QEMU-green; 21 of them also metal-validated (23 PASS / 0 FAIL
/ 0 faults, inline IPS proven on live wire).

Every remaining gap is NOT a surgical fix — categorized honestly:

**A. Large structural refactors (dedicated session each; several need metal):**
- CORE-1/XC-5  route all mapping through cap invocation + revoke unmaps
- CORE-2/XC-6  per-TCB CSpace (unblocks P12)
- CORE-6 ✅ DONE  per-TCB fault-restart records (P17 prerequisite; QEMU-validated: fault-restart PASS 3x then kill)
- CORE-9       generation-tagged CDT/MDB (enables single-cap delete/move)
- DRV-1/XC-4   program RP1 MSI-X for real RX-IRQ (metal)
- DRV-2/XC-3   relocate kernel above the IOMMU ceiling (metal)
- SEC-2/XC-10  remove OTP mailbox page from EL1 stage-2 + hvc proxy (metal)

**B. Irreversible / operational (must NOT be done autonomously):**
- SEC-3/XC-9   enable BCM2712 signed-boot (fuse key hash — irreversible)
- SEC-6        advance the anti-rollback SVN floor (OTP-latched — irreversible) + a real per-release SVN process
- SEC-5        AK = KDF(OTP, PCR0): correct DICE fix but CHANGES the device attestation identity (re-enroll) — do deliberately, not mid-run

**C. MMU-restructure risk (like the deferred CORE-4):**
- SEC-9        split EL2 GB0 for HBoot W^X
- CORE-4/DET-7/XC-2  jit_seal on the QEMU backend (QEMU-only; production sealed)

**D. Test-coverage / assurance (moderate, own pass):**
- DET-6        differential over ALL JIT'd rules (per-rule input domains)
- DET-13       Abs-level soundness-harness checks for scalar_from_tnum/join/lsh_k/or_x; tnum_add beyond width 6 (offline tool)
- XC-15        cap-invariant property tests on both MMU backends

**E. Tied to an unbuilt feature:**
- DET-8        live telemetry drainer (the EL0 exporter = P12 territory)
- CORE-12      real EL0 allocator (only when untrusted input reaches alloc)

**F. Design-phase implementations:** P13 ✅ + P15 ✅ IMPLEMENTED (P13=8025477 RP1 buses; P15=5336ca8 read-only eMMC + sealing crypto, QEMU-gated [P15 PASS], write behind p15-write, V3 limitation printed). P17 foundation ✅ + P12 ✅ IMPLEMENTED (b4f7dc1: notification objects + capability pub-sub, topics-as-caps via CORE-2 mint_into, blocking WAIT, MAX_THREADS->16, DSN-6 fixed; [P12] PASS — ungranted-subscribe REFUSED proven). P11 core ✅ IMPLEMENTED (695414b: hardened SPSC device-class transport, H1/H2/H3, [P11] PASS — rejects+counts 5 forged-descriptor classes from a hostile driver, queue survives; metal GemDev/RtlDev deferred). ALL 5 DESIGN PHASES now implemented/foundationed.


## METAL FINDING 2026-07-24 (P13/P15 flash)
P13 PASS on metal (deny-list enforced, i2c1 EL0-driver works, eMMC block device up 59640MiB, MBR+guard OK; SPI SRL loopback WARN non-fatal). P15 metal run FOUND a security-critical HMAC bug (commit ff80854): the incremental Hasher dropped a message tail <=32 bytes, so seal tamper detection LEAKED for short ciphertexts — QEMU missed it (36-byte test secret took the good path). Fixed + QEMU gate now uses a 28-byte secret to guard the path. Confirms XC-15 (dual-backend coverage gap).


## DRV-1 (RP1 GEM RX-IRQ) — FULL CHARACTERIZATION 2026-09-07

Taken as far as it can go responsibly WITHOUT the RP1 peripherals datasheet. Not closed;
precisely located and reprioritized.

**DONE + VERIFIED READY (the entire BCM2712 side):**
- GIC SPI 134 -> INTID 166 routing (`Gic::enable_spi(166)`), idempotent.
- GEM `IER.RCOMP` (`gem::rx_irq_enable`).
- `handle_irq` INTID-166 branch: record `GEM_RX_IRQS`, `gem::rx_irq_ack`, `gic.eoi`. Correct.
- `[P8-irq]` bounded probe wires+tests it end-to-end; masks the timer PPI first.
- => the instant the RP1 MIP delivers, RX-IRQ works with NO further BCM2712-side change.

**THE ONE MISSING PIECE:** program the RP1 MIP (MSI-X) entry for internal source 6
(RP1_INT_ETH) so RCOMP emits the MSI write the BCM2712 mip0 converts to SPI 134.

**WHY IT IS NOT SAFE TO DO BLIND (do not "just try" the recipe below on metal):**
1. The prior recipe (BUILD_FLASH_PLAN.md 5.2: `MSIX_CFG_6` at RP1 `0x108000 + 0x08 + 6*4`,
   MSI addr `0xFF_FFFF_F000`, data 6, + maybe an RC2 inbound window
   `0xFF_FFFF_F000 -> 0x10_0013_0000`) was NEVER made to fire — it is an untested hypothesis.
2. Its description is internally inconsistent — "ENABLE + addr + data" cannot fit the single
   u32 register it names, so the true MIP register LAYOUT is unconfirmed.
3. There is NO RP1 irqchip driver in the RPi Linux source (checked): the RP1-internal ->
   GIC-SPI path is RP1 silicon + `pcie-brcmstb` MSI + firmware, so the register map is not
   derivable from the kernel source we have — it needs the RP1 peripherals datasheet.
4. Programming it writes an MSI DMA TARGET ADDRESS into RP1 HW; a wrong value makes RP1
   post a write to that address on every RX frame, and DRV-2 (IOMMU containment) is
   UNRESOLVED — a stray MSI write is exactly the scribble DRV-2 would catch and cannot yet.

**THE SAFE, REFERENCE-DRIVEN UNBLOCK (the "use Linux as reference" method):** boot Linux on
the board (`cm5-boot/linux-observe/`) and DUMP the RP1 MIP registers Linux programs for the
ethernet interrupt (a READ, not a write) — capturing the real base / offset / addr / data /
enable layout from a working system. Then mirror it in `gem::rx_msix_program()` (cm5),
read-back-verified, tested via `[P8-irq]`. This is non-speculative and cannot scribble.

**METAL ADVANCE 2026-09-07 (mipdump probe):** the RP1-side enable is now DONE + VERIFIED
ON METAL, grounded exactly in Linux `drivers/mfd/rp1.c` (not guessed):
- MIP MSIX_CFG regs base = `bar_start + RP1_PCIE_APBS_BASE(0x108000)` = heqk `0x1C_0010_8000`
  (confirmed adjacent to GEM `0x1C_0010_0000`); `MSIX_CFG(x)=0x8+4x`, `RP1_INT_ETH=6` -> `0x20`;
  `REG_SET=0x800`; level-high enable = `ENABLE(b0)|IACK_EN(b3)=0x9`.
- `gem::rx_msix_setup()` wrote it: **`MSIX_CFG(6) pre=0x0 -> post=0x9`** read-back — the RP1
  source-6 enable path, register semantics, and address are all CORRECT on silicon.
- Still `0 INTID-166 IRQs`, `INTSTATL=0` => the PCIe MSI-X TABLE (doorbell addr/data) is NOT
  firmware-programmed. DRV-1 is now isolated to EXACTLY that one remaining piece.

**DELIVERY MODEL RESOLVED — DEVICETREE GROUND TRUTH 2026-09-07 (supersedes the RC-demux
read below; corrects TWO earlier wrong assumptions).** The authoritative BCM2712 devicetree
(`arch/arm64/boot/dts/broadcom/bcm2712.dtsi`, pcie2 + mip0 nodes) is definitive:

  pcie2: pcie@1000120000 { ... msi-parent = <&mip0>; };       // RP1 root complex (RC2)
  mip0: msi-controller@1000130000 {
      compatible = "brcm,bcm2712-mip";
      reg = <0x10 0x00130000 0x00 0xc0>,      // MIP config regs (CPU side)
            <0xff 0xfffff000 0x00 0x1000>;     // doorbell page (PCIe-visible)
      msi-ranges = <&gicv2 GIC_SPI 128 IRQ_TYPE_EDGE_RISING 64>;  // vec v -> SPI (128+v)
      brcm,msi-offset = <0>;
  };

THE TRUE MODEL (neither of the two I guessed):
- The RP1's MSI parent is a DISTINCT **MIP** block (`mip0` @ CPU 0x10_0013_0000), NOT the
  brcmstb RC's internal MSI demux. The RC INTR2 regs I read (0x4500=0, mask=0xffffffff) were
  a RED HERRING — that legacy RC MSI path is unused; the RP1 routes to mip0.
- mip0 maps **one dedicated GIC SPI per vector**, SPI 128..191, **edge-rising**. So this is
  the per-vector-SPI shape (my "model a / consolidated RC demux, single SPI + software
  0x4500 demux" was WRONG — there is NO software demux; the GIC gets a distinct SPI).
- Vector 6 -> SPI (128+6)=134 -> INTID 166. => **heqk's ORIGINAL `GEM_RX_INTID=166` +
  per-source handler branch were correct in SHAPE all along** — it just was never wired
  end-to-end. NO handler rework to a demux is needed; the existing INTID-166 branch is right.
  (One correction: the SPI is EDGE-rising, so the GIC ICFGR for 134 must be edge, and EOI is
  sufficient re-arm at the GIC — plus the RP1 MSIX_CFG IACK per rp1.c to re-arm source 6.)
- The doorbell 0xf_ffff_fffc IS mip0's PCIe-visible page (dma-ranges maps PCIe ff_fffff000
  -> CPU 0x10_0013_0000). Firmware DID program the RP1 endpoint's MSI-X message address to
  it — that part of the earlier read stands.
- RP1 MSI-X mechanism (rp1.c): MSIX_CFG(x) is ONLY enable/IACK bits (ENABLE b0, IACK b2,
  IACK_EN b3) — it does NOT hold addr/data. RP1 is a normal PCIe endpoint with a STANDARD
  PCI MSI-X TABLE (addr_lo/addr_hi/data/vector_ctrl per entry) in one of its BARs; the RP1
  irqchip is a 2nd-level chained domain on top of those 64 PCI MSI-X vectors.

SAFETY FULLY RELIEVED (unchanged): 0xf_ffff_fffc is the MIP doorbell MMIO page, NOT system
RAM — programming the RP1 MSI-X table to target it cannot scribble memory; DRV-2 moot here.

**REMAINING — bounded IMPLEMENTATION, all values now KNOWN except the RP1 MSI-X table BAR/offset:**
1. GICv2 for SPI 134: set ICFGR to EDGE, ISENABLER bit, priority, target CPU. (Keep the
   existing INTID-166 handler branch — it was right; no demux rework.)
2. Program the RP1 endpoint's STANDARD PCI MSI-X TABLE entry for internal source 6:
   addr_lo=0xfffffffc, addr_hi=0x0000000f (doorbell 0xf_ffff_fffc), data=6 (MIP vector 6 ->
   SPI 134), vector_ctrl=0 (unmask). Needs the RP1 MSI-X table BAR+offset = a small READ-ONLY
   ECAM walk of the RP1 endpoint (bus 1 dev 0 behind RC2) to its MSI-X capability. This is the
   ONE remaining unknown and it is a read, not a guess.
3. RP1 MSIX_CFG(6) enable + IACK_EN — ALREADY DONE + metal-verified (pre=0 -> post=9).

The RC2 "pcie"/"msi" SPIs from the dt (233/234) and the legacy-INTx map (229..232) are NOT
needed for this path — the MSI goes mip0 -> SPI 134 directly.

**DECISIVE METAL RESULT 2026-09-08 (dual-sink experiment, image d8c918c2) — DRV-1 is
BLOCKED on a real hardware gap, precisely located.** With heavy traffic flowing (seen
256→3124, ~155 fps, drop=0, faults=0) and BOTH candidate MSI sinks unmasked + the GEM
emitting RX-complete (IER.RCOMP on, RP1 MSIX_CFG(6)=0x9), the sink status registers read
ZERO on every heartbeat:
    [DRV1-hb] mip_statusL=0 mip_statusH=0 rc_status=0   (x4, over 20s of RX)
=> NEITHER sink (mip0 STATUSL/H_HOST nor brcmstb RC MSI_INT_STATUS) ever latches. The RP1
ETH source is NOT emitting MSIs at all, despite the source being enabled. Root cause: the
RP1's PCI MSI-X TABLE entry (addr/data) is UNPROGRAMMED — MSIX_CFG(6) enables the SOURCE
but without a table entry there is no message to send, so no doorbell write, so no sink
latch. This is consistent with the earlier read: RP1 config space is UNREACHABLE from heqk
(EXT_CFG returns 0xffffffff), so heqk can neither find nor program the table.

WHAT THIS DEFINITIVELY ESTABLISHES:
- Polled RX is fully functional on metal (the sensor/enforcer needs nothing more).
- RX-IRQ requires programming the RP1 PCI MSI-X table, which requires PCIe CONFIG-SPACE
  access to the RP1 endpoint — and heqk's brcmstb EXT_CFG path returns 0xffffffff (the RP1
  MMIO outbound window works, but downstream config access does not).
- The mip0-vs-RC-doorbell ambiguity is moot until a table entry exists to point at either.

REMAINING (a bounded but SUBSTANTIAL new subsystem, its own focused effort — NOT M2):
  Option A — teach heqk minimal PCIe config access for the RP1 bridge: diagnose why
    EXT_CFG(bus1,dev0) is 0xffffffff (read the RC's own header at PCIE_RC+0 first as a
    control; check the RC secondary/subordinate-bus regs firmware left; the CFG_READ_UR
    mode at 0x4008), then program the MSI-X table entry (addr=chosen doorbell, data=vector,
    unmask) via the DATA window. Then unmask the matching sink + route its GIC SPI.
  Option B — RP1 datasheet: the MSI-X table's fixed BAR+offset → program it via MMIO
    directly (no config walk), same table-entry values.
  Option C — Linux-on-CM5 reference boot: lspci -vv the RP1 + /proc/interrupts to read the
    live table location, target doorbell, and the actual GIC line — then hardcode. (The
    operator's "use Linux as reference" method; definitive but needs a Linux boot.)

The dual-sink experiment code (gem::msi_sink_unmask/msi_sink_status + the [DRV1-hb] readout)
stays in-tree behind `mipdump` for whichever option runs next. Evidence:
~/heqk-metal-logs/20260908-drv1-dualsink-both-zero-table-unprogrammed.log

**SESSION 2026-09-08 — DRV-1 driven from "blocked mystery" to a fully-built MSI chain with
the sink PROVEN and one narrow gap left (RP1 EP emit).** Went to the RPi Linux drivers AND the
official RP1 peripherals datasheet (not guessing). Every layer below is now metal-verified;
the code is all `mipdump`-gated (prod byte-identical). ~13 flash cycles, evidence in
~/heqk-metal-logs/2026090[78]-drv1-*.log.

WHAT WAS BUILT + PROVEN ON METAL (all in gem.rs, mipdump):
1. pcie_bridge_enumerate() — ROOT CAUSE of the 0xffffffff config reads: the RC PCIe bridge
   was never bus-enumerated (secondary/subordinate=0/0), so bus-1 config = UR = 0xffffffff
   (firmware's AXI_READ_ERROR_DATA). Writing RC bridge class=0x060400 + primary/secondary/
   subordinate=0/1/1 (RC+0x18=0x00010100) + MSE|BME (RC+0x04|=0x06) FIXED it:
   **RP1 bus1 VID/DID=0x00011de4** now reads. (RC status 0x4068=0x0003e0b0 => DL_ACTIVE|
   PHYLINKUP set.)
2. pcie_map_bar0_window() — the MSI-X table lives in RP1 BAR0 (PCIe 0x80410000, 32-bit),
   which had no RC outbound window. Program a FREE brcmstb outbound window (scan 4; free =
   limit<base i.e. BASE_LIMIT=0x10) mapping a linear alias CPU=PCIe+0x40_0000_0000 =>
   CPU 0x40_80400000 -> PCIe 0x80400000. **Table now readable + writable.**
3. pcie_inbound_mip_doorbell() — RC_BAR2 inbound window PCIe 0xff_fffff000 (4KB) -> CPU
   0x10_0013_0000 (mip0 INT_RAISE), since heqk only had the RAM DMA inbound (RC_BAR1).
4. rx_msix_program() — walks the MSI-X cap (cap@0xb0, BIR=0 off=0), sets BME on the EP, and
   programs table entry 6: **addr=0xff_fffff000 data=6 vctrl=0 (read-back CONFIRMED)**, then
   enables MSI-X in msgctrl (0x803c0011).
5. msi_sink_unmask() — mip0 HOST unmask (MASKL/H_HOST=0, CFGL/H_HOST=~0, MASKL/H_VPU=~0).
6. rx_msix_iack() — clears the MSIX_CFG(6) auto-mask.
7. **mip0 -> GIC -> handler PROVEN:** [P8-inj] a CPU write to MIP_INT_RAISE=6 -> **INTID-166
   fired=1**. GIC SPI 134 routing, mip0 CFG, vector->SPI mapping ALL correct. (STATUSL reads
   0 because an unmasked raise forwards immediately — use gic_spi_pending()/fired, not STATUS.)
8. GEM asserts into RP1: INTSTATL bit6 = 0x40 (raw source 6 active) during prod.

THE ONE REMAINING GAP — the RP1 EP does not EMIT the MSI:
- [P8-emit] MSIX_CFG(6).TEST force-emit -> INTID-166 fired=0 (nothing reaches the GIC).
- LEADING HYPOTHESIS (untested cleanly yet): the source is stuck LEVEL-HIGH — prod enables
  GEM IER.RCOMP but NEVER clears the GEM ISR (the EL0/DMA ring path doesn't read ISR), so
  RCOMP stays set => INTSTATL bit6 permanently 0x40. MSIX_CFG likely emitted ONE MSI when the
  level first rose (to the then-unprogrammed table => lost) + auto-masked; a continuously-high
  level makes NO new rising edge, and TEST OR'd onto an already-high source is no edge either,
  so it never re-emits. IACK clears the mask but without an edge nothing re-generates.
- [P8-edge] tried deassert(clear GEM ISR)->reassert, but ran in the PROBE where INTSTATL bit6
  was already 0 (no RX pending pre-prod) — inconclusive, wrong timing.

NEXT STEPS TO CLOSE (pick up here):
  a) Do the deassert/reassert edge test DURING PROD (source high, 0x40): each heartbeat, clear
     the GEM ISR (rx_irq_ack) to drop RCOMP, IACK, then a fresh frame re-asserts (rising edge)
     -> should emit to the correct table -> mip_sL/INTID-166. If it fires, the fix is simply
     "clear the GEM ISR periodically so RCOMP edges" (or wire the GEM RCOMP ack into the drain).
  b) If still nothing, read the MSI-X PBA (cap+8 BIR/offset) bit6 to split generated-but-blocked
     (PBA set => inbound/BME/mask issue) vs not-generated (PBA clear => MSIX_CFG trigger).
  c) Consider the RC-MSI sink alternative (firmware armed it: BAR_CFG=0xfffffffd doorbell
     0xf_ffff_fffc data 0x6540) — point the table there + unmask INTR2 + route GIC SPI 234.
Still NOT an M2 gate — polled RX is fully functional (drop=0). Value = retire the poll-spin.

Reference pulled this session: RP1 peripherals datasheet (MSIX_CFG_x=0x008+4x bit0 ENABLE/
bit1 TEST/bit2 IACK/bit3 IACK_EN; INTSTATL 0x108; eth=source 6; BARs 32-bit; peripherals via
BAR1); irq-bcm2712-mip.c (mip regs, msg.data=vector, GIC SPI 128+v); pcie-brcmstb.c (EXT_CFG,
inbound/outbound win regs, bus-enum). Extracted under /home/andrei/.claude/jobs/*/tmp/.

**SESSION 2026-09-09 — DEFINITIVE: the RP1 EP does NOT emit the MSI (generation gap, not
routing).** Used the references hard (full Linux RP1->mip0->RC trace via subagent + RP1
datasheet) instead of guessing, then a decisive RAM-landing test to settle the ambiguity:
- The reference trace said the fix was the RC inbound window in RC_BAR3 (not BAR2 where I had
  it). Applied it EXACTLY (RC_BAR3_LO=0xfffff01c HI=0xff, UBUS_BAR3_REMAP LO=0x00130001 HI=0x10;
  metal read-back 'before=0' => firmware never set BAR3, confirming the reference). Still no MSI
  reached mip0.
- The subagent INFERRED "the RP1 emits fine, the write is dropped at the RC" from PBA=0. That
  inference is WRONG. [P8-ram] retargets the MSI-X entry (gem::rx_msix_retarget) at a RAM word
  via RC_BAR1 (bus 0x10_..+pa -> CPU pa) — the SAME inbound window the GEM RX DMA uses every
  frame — writes 0, TEST-force-fires, reads back: **0x0**. The RP1 does NOT put the MSI write on
  the bus at all. (PBA=0 was ambiguous: a posted write clears it either way.)

So EVERYTHING the Linux rp1.c driver does is replicated (MSIX_CFG(6)=0x9 ENABLE|IACK_EN, PCI
MSI-X cap enabled msgctrl=0x803c, table entry vctrl=0 unmasked, BME on the EP, source asserting
INTSTATL=0x40) AND the RC in/out windows are correct AND mip0->GIC->handler is PROVEN (CPU-inject
fires INTID-166) — yet the RP1 EP's APBS MSIX_CFG mechanism never generates the upstream MSI
write, even TEST-forced, even aimed at a trivially-reachable RAM address. The GEM's own upstream
DMA writes DO work (frames land in the ring), so the EP's upstream data path is fine — it is
specifically the MSI-X GENERATION that does not fire.

THE REMAINING GAP IS BELOW THE KERNEL SOURCE: the RP1 is a Synopsys DWC PCIe EP whose MSI-X
generation / outbound path is brought up by the RP1's OWN firmware (a separate co-processor),
not by rp1.c. Candidates not visible in the source: (i) a DWC-EP-core MSI-X enable / outbound
iATU that the RP1 firmware must arm (dw_pcie_ep_raise_msix_irq maps an outbound iATU to msg_addr
— if the APBS hardware path depends on an iATU window firmware didn't set for our addresses,
nothing goes out); (ii) an APBS-block-level arm beyond the per-source MSIX_CFG; (iii) the DWC DBI
'APP_DBI_RO_WR_DISABLE' / config-shadow gating the cap enable. None are in the RPi kernel tree.

CLEAN UNBLOCK (recommended): boot Linux ON the CM5 once and OBSERVE the working state — lspci
-vvv on the RP1 (MSI-X cap + BARs), /proc/interrupts (the eth IRQ's actual GIC line + count
climbing), and dump the RP1 PCIE_CFG/DBI + DWC iATU registers while ethernet RX interrupts are
firing. That reveals the exact firmware/DWC state that makes emission work — the one thing
source-reading cannot give. Alternatively bank DRV-1 (NOT an M2 gate; polled RX drop=0) and move
on. Evidence: ~/heqk-metal-logs/20260909-drv1-ramtest-rp1-does-not-emit.log

**REPRIORITIZED — DRV-1 is NOT an M2 gate.** Measured 2026-09-07: heqk sustains ~389 RX
frames/s at drop=0, faults=0, which drives the M2 sustained-load separation-matrix rows
(PSI / conntrack-saturation / self-revert TTL) with paced traffic. DRV-1's payoff is
retiring the poll-spin (CPU efficiency) + instantaneous line-rate BURST absorption
(currently ~500/2000) — a PRODUCTION-HARDENING / burst-resilience property, not enforcement
correctness. It belongs with the PH-tier metal items, gated behind DRV-2 (IOMMU) for the
MSI-write safety net, and behind the RP1 register dump for the layout.

---

## DEEP-INVESTIGATION AUDIT ROUND 2026-07-25 (post-P17, new P11-P17 + CORE code)
A fresh multi-agent audit of the newly-added code (caps/notify/netq/devq/seal/store/rp1/packet) surfaced these. Closed one per commit with a regression gate:

| ID | Sev | Loc | Defect | Status |
|----|-----|-----|--------|--------|
| AUD-NET-1 | High | packet.rs strip_vlan | DET-4 VLAN normalizer read the TCI as the ethertype (off-by-2) → re-opened the FLOW-tier IDS bypass it was meant to close | CLOSED ffcdad9 — [P8-vlan] byte-identical reconstruction gate |
| AUD-CAP-1 | High | main.rs P12 syscalls | resolve_ntfn_cap accepted EITHER Notification or Topic for all 6 ops → Notification{W} could drive PUBLISH (type confusion) | CLOSED e8ef215 — resolve takes expected ObjType, 6 typed callers |
| AUD-STO-1 | High | seal.rs/kdf.rs | CTR keystream deterministic in (SRK,policy) → two same-policy blobs shared a keystream (two-time-pad) | CLOSED 9f5db34 — fresh per-seal nonce in MAC-covered header, ctr_xor_nonce; [P15] no-reuse=DISTINCT gate |
| AUD-BLD-1 | High(build) | linker-cm5.ld | CORE-1 W^X refs __text_start/__text_end in mmu_cm5.rs but linker-cm5.ld never defined them → metal flavour failed to LINK since f754307 | CLOSED (this round) — symbols added; all 4 flavours build |
| AUD-CAP-3 | Med | notify.rs subscribe | no per-tid dedup/quota → one Topic{R} holder loops subscribe() to take all 4 sub slots, starving others (asymmetry: create() has NOTIFY_QUOTA_PER_TASK, subscribe had none) | CLOSED — subscribe idempotent (1 slot per tid) |
| AUD-CAP-4 | Low-Med | notify.rs detach_tcb | frees dead tid's subscriptions but NOT the NOTIFY objects it OWNS → 16-slot leak + a reused tid inherits the dead owner's create-quota | CLOSED — reclaim owner's notifs on death (wake foreign waiter RC_REVOKED, bump gen) |
| AUD-RP1-4 | Low | rp1_gpio get_level/dump/funcsel | unbounded `pin: u8` → `v>>pin` shift-overflow (pin>=32) / out-of-window MMIO read (pin>27) on the read-only paths | CLOSED — guard `pin > BANK0_MAX` at each entry |
| AUD-RP1-5 | Low | rp1_spi set_cs | `1u32 << cs` shift-overflow for `cs>=32` | CLOSED — reject `cs >= 32` |

**Ruled OUT by the re-scan (verified NOT present in the code):**
- **AUD-NET-2** — the interpreter/fallback path IS fully bounds-checked: `run_set` gates JIT on `pkt.len() >= min_len`, else falls to `bpf::run` which range-checks every load and maps INVALID→DROP fail-closed; `net::parse` is `.get()`-based. A short frame yields DROP, never an OOB read.
- **AUD-RP1-1** (write bypasses deny-list) — every MMIO write calls `writable()`/`is_reserved` first; `mux_group` validates the whole slice before applying (no partial mux).
- **AUD-RP1-2** (unbounded poll) — every HW wait uses CNTPCT-bounded `poll_until`/`delay_us`; inner FIFO loops bounded by transfer length.
- **AUD-STO-2/3/4** — seal/unseal arithmetic safe (len checked before the `HDR+ct_len` term in a short-circuit `||`); SealKey volatile-zeroized on drop; CT compares; MBR parse in-bounds; window `[2016,2048)` has no off-by-one.
- **devq.rs / netq.rs** — DevQ copy-then-validate + kernel-private cap + csdb + no-RMW sound; NetQ per-slot ownership with clamped untrusted `len` (never used as an index) sound on both directions.


## PRODUCTION-HARDENING AUDIT ROUND 2026-07-25 (PH1-PH7)
Two parallel auditors swept the PH1-PH7 code (prod service, netsvc/smoltcp, PH2a SRK handoff, cap sweep). Every confirmed finding CLOSED (one commit); the crypto ordering, domain-sep, repr(C) layout, cache-flush range, and enforce/fail-closed logic were all confirmed SOUND.

| ID | Sev | Loc | Defect | Status |
|----|-----|-----|--------|--------|
| D3/D4 | Med | main.rs cm5_prod_service | contained EL0 driver fault indistinguishable from empty RX window (DRIVER_REPORT=0 both) -> crash-loop reads as quiet link | CLOSED — RPT_SENTINEL(0xFFFFFFFF) before enter_user + separate faults counter |
| D2 | Med | main.rs cm5_prod_service | PASS frame whose tx_frame() times out uncounted -> seen != fwd+dropped | CLOSED — tx_fail counter; invariant seen==fwd+dropped+tx_fail |
| D5 | Low | main.rs cm5_prod_service | RX buf 1600 < RXBUF 2048 -> deep-L7 frame truncated before verdict (evasion) | CLOSED — buf = packet::FRAME_SZ (2048) |
| D6 | Low | main.rs cm5_prod_service | dead PRODPOOL allocation | CLOSED — removed |
| D1 | Med | netsvc.rs TxSink | smoltcp multi-frame-per-poll silently overwrote the single tx slot | CLOSED — tx_lost counter (loss now observable) |
| D7 | Low | netsvc.rs selftest | [PH6-net] only tested PASS, never proved the gate DROPs | CLOSED — negative case: UDP:4444 threat REFUSED admission |
| R1 | Med | main.rs read_seal_handoff | SRK sat in plaintext at fixed well-known addr 0x3FFA_0000 for whole runtime, never scrubbed (exposure beyond V3) | CLOSED — seal_srk() copies to kernel-private .bss + scrubs page (write-zero+dsb+dc civac) |
| R3 | Low | main.rs p15 demo | printed "(SYNTHETIC key)" even when using the REAL per-device SRK | CLOSED — honest per-device/synthetic label |
| R2 | Low-Med | caps.rs cap_invariants_selftest | missing CORE-3 zero-on-retype + deep-tree revoke coverage | CLOSED — both subtests added |
| R4 | Low | hboot main.rs | derived SRK unscrubbed on the SEC-4 re-hash-mismatch park() | CLOSED — scrub ak.srk before park |
| R5 | Info | main.rs | CM5 cap-test base hardcoded 0x980000 | ACCEPTED — verified in the free RAM window (above HBoot stack, below kernel image); documented |

**Confirmed SOUND (no defect):** packet::verdict fail-closed + enforce correctness; no crafted-frame panic in the datapath or netsvc; cntfrq div-by-zero guarded (max(1)); rx_desc_status uses HW writeback length (M-7); netsvc dual-gate has no bypass + split-borrow sound; SRK domain-sep / flush-range / write-before-stage2 / repr(C) layout / hw_bound=false fallback / srk-derived-before-wipe all correct; self-heal survival real (kernel never halts). QEMU [PHprod]/[PH7-caps]/[PH6-net] PASS + [ALL] GREEN, 0 failing.

## METAL RUN 2026-08-20 — first ZERO-LINUX CM5 boot (3 boots, M1 3/4)

The board was flashed with a boot partition holding **no Linux at all** (no kernel, no
initramfs, no cmdline, no devicetree) — only heqk A/B slots, `config.txt`, and the Pi
platform firmware. Three consecutive boots; `[P7b] W^X PASS` every time, which is the
FIRST-EVER execution of the `cm5` W^X mapping on silicon (it had not even LINKED until
AUD-BLD-1 was fixed, so this was the single largest unknown in the flash).

### Closed this run

| ID | Sev | Loc | Defect | Status |
|----|-----|-----|--------|--------|
| MET-TX-1 | **High** | `gem.rs` TSR | `TSR` (Transmit Status) was DECLARED at line 38 and never read or written ANYWHERE. On a Cadence GEM, `UBR`/`RLE`/`TFC`/`UND`/`HRESP` HALT the transmitter and are write-1-to-clear — so one latched error stopped TX dead and every subsequent frame timed out until something incidentally restarted it. Measured cost: **8.8%** of PASS frames not forwarded (11/125 post-startup, boot 1) | CLOSED (2c0b342 + 34122ea) — clear before arming, clear on completion, recover by bouncing TE (RE left UP so RX/detection is never interrupted). **Boot 2 measured 1.9% (9/467)** — a ~4x reduction on 3.7x the sample |
| MET-TX-2 | Med | `gem.rs` / `main.rs` hb | `tx_fail` was an ANONYMOUS timeout — a PASS frame silently not forwarded, no cause recorded. Every rate estimate off live traffic swung wildly (20% → 9% → 2% → 9% across windows of the SAME boot) because the link idles 45 s at a stretch and each window held only a few dozen frames | CLOSED — `gem::tx_err_take()` + `txerr=0x..` in the heartbeat. Boot 2's FIRST heartbeat reported `txerr=0x01` = `TSR_UBR`, identifying the exact bit. Also added `gem::tx_burst_selftest(n)` for a traffic-independent measurement (NOT yet wired into the selftest sequence) |
| MET-RX-1 | Low-Med | `main.rs` P8 probe | The "no frames" message asserted *"suspects: PHY reset/link, or RC inbound ATU (BNA)"* UNCONDITIONALLY and MISDIRECTED diagnosis: the link was fine (PHY `speed_code=7` = 1G/full) and the prod sensor went on to receive hundreds of frames — the 5 s probe had simply landed in a quiet stretch | CLOSED (2c0b342) — now distinguishes `RSR.BNA` set (a REAL buffers/ATU fault) from `RSR` clean (an IDLE link, not a fault). Confirmed on boot 3 |
| MET-BLD-1 | Med(build) | `builder/make-cm5-heqk-image.sh` | `mkdir -p "$OUT"` sat 16 lines BELOW the P16 verifier gate that writes `$OUT.vh`, so on a fresh clone/CI/worktree rustc could not create the file — and with stderr sent to `/dev/null` a MISSING DIRECTORY reported itself as **"verifier harness failed"**, i.e. as BPF verifier UNSOUNDNESS. The most alarming false alarm this repo can raise | CLOSED (d200e72) — dir created first; build-failure and soundness-failure now read completely differently |
| MET-FW-1 | **High** | `cm5-boot/flash-clean.sh` | The wipe was indiscriminate and only heqk files were written back, so it DESTROYED `bootcode.bin` / `start4.elf` / `fixup4.dat` — Raspberry Pi PLATFORM firmware, not Linux. Self-inflicted; recovered by hand from the archive before power-cycling | CLOSED (c5dd1a1) — platform firmware restored unconditionally after the wipe; validated on the next two flashes |
| MET-FW-2 | Low | `cm5-boot/flash-clean.sh` | Runs under sudo, so `$HOME` was root's and the "reference to learn from" was written root-owned to `/root/heqk-linux-reference/` | CLOSED (c5dd1a1) — resolves `$SUDO_USER`'s home |

### STILL OPEN after this run

- **MET-TX-3 (Med, throughput).** 2 of boot 2's 9 failures reported `txerr=0x08` — the sentinel for *timeout with a COMPLETELY CLEAN TSR*, no latched error at all. Both landed inside heavy bursts (81 and 94 frames in one window): the **single-descriptor TX ring saturating under load**. This is NOT the UBR halt and must not be conflated with it. Fix = a deeper TX ring (multi-descriptor), a separate and larger change.
- **DRV-1 confirmed on metal.** `[P8-irq]` armed clean but saw 0 INTID-166 IRQs — RP1 `MSIX_CFG_6` is not firmware-preprogrammed, so RX stays polled.
- **V3/SEC-2 confirmed OPEN on metal.** `[P15-SRK]` prints that the SRK is REAL and per-device (OTP-derived, `device_id=0x010256173c495a31`) but that EL1 can still read OTP via the VC mailbox, so on-device binding is not yet tamper-proof (PH2b).
- **M1 criterion 4 (forced-bad-boot rollback) NOT tested.** `[HBoot-AB] PASS` is the trial-CONFIRM path. The designed trigger is `reboot "0 tryboot"` issued ON-DEVICE, and heqk has no such path — closing this needs an hboot-side tryboot hook or a deliberately-corrupted slot staged via rpiboot.

### Doc claims this run proved STALE (all in the project's favour)

- **AK is hardware-bound**, not software-constant: `ak: customer OTP already provisioned -> deriving per-device AK`. `buildPlan.md:185` / the Track-C ledger still say "AK still software-constant = demo-grade".
- **Anti-rollback is live**, not inert: `svn: image=1 floor=1 (BCM2712 OTP block3 (hardware monotonic thermometer))`. SEC-6 above is recorded as "FLOOR=0, never advanced".
- **heqk needs no devicetree**: booted with `dtb 0x0`. `hboot` takes `dtb_pa` in x0 and only PRINTS it.
- **The RTL8111 does NOT need firmware `dtparam=`**: with no DTB at all, `[P9] RC1 LINK UP — HEQK trained the external PCIe!` and `RTL8111H found @01:00.0`. heqk owns RC1 training itself (Path B).

### Method note (worth keeping)

Four separate rate estimates were quoted off small windows before the sample was adequate,
and two of them were later contradicted. Rates measured against opportunistic link traffic
on an idle segment are not trustworthy below a few hundred frames — which is exactly why
`tx_burst_selftest` exists. Prefer a deterministic stimulus over a bigger guess.
