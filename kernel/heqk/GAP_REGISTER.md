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
| DRV-1 | High | main.rs:1081; gem.rs:610 | NO real IRQ-driven RX: RP1 MSI-X (MSIX_CFG_6→SPI134) never programmed, RCOMP never reaches GIC → polling-only despite "PASS" | program RP1 MSI-X entry in rx_init + read back; stop reporting IRQ path as enabled |
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
