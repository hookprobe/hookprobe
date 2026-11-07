# HEQK Remediation Plan — Full Code Audit + Fix Plan (P0–P17)

**Produced:** 2026-07-23, by a 6-agent deep audit + multi-kernel/academic research pass
(code read in full + web/papers). Companion reference: `HEQK_KERNEL_DOSSIER.md`.
**Scope:** the whole HEQK microkernel (~33 K LOC Rust) — core (P0–P6b), boot/attestation
(P7), BPF threat plane (P8), drivers (P9–P10), automation/residuals (P11–P17).

This is the standing plan. Fix items are tagged `[APPLIED]`, `[READY]` (code written, awaiting
flash), or `[TODO]`. Severity is rated against the *intended production* use (a line-rate
security appliance), not the current tiny attack surface.

---

## 0. Executive summary

HEQK's **architecture is unusually well-aligned with the research frontier** — an seL4-style
capability model, isolated/restartable EL0 drivers (MINIX 3 / sDDF / LionsOS), a modular
tnum BPF verifier with an Agni-aware harness, and conservative hash-based hybrid secure boot
(FIPS-205 SLH-DSA + ed25519). The risk is concentrated exactly where the literature predicts:

1. **The capability system is asserted but not yet *enforced*** — mapping/IPC/IRQ aren't cap-gated,
   so `revoke` can't actually sever authority (core A1). The confused-deputy guarantee is a design,
   not a mechanism, today.
2. **A load-bearing single-core invariant is implicit** — every lock-free ring + Relaxed counter is
   sound only on one core, and it's documented only in a comment (P11 V4).
3. **The verifier's helper edge is unsound** — `payload_match` is an arbitrary-kernel-read the
   verifier will bless (BPF V1). Latent (rules are first-party signed) but blocks the third-party goal.
4. **Firmware/DMA + speculation channels this silicon can't fully contain** — the P14 IOMMU "fence"
   as deployed protects nothing (driver C1); Cortex-A76 Spectre is unaddressed.

**Recurring cross-cutting bug (found by 3 independent agents):** the **QEMU MMU backend leaves a
writable alias to RO+X code** (W^X hole) that the CM5 path (`jit_seal`) closes — the two backends
disagree on a security invariant (core A4, BPF V3, P11 V7).

**Two fixes already applied this pass:** the `rand_core` build break (hboot now compiles) and the
**CYW43455 F2-ready fix** (the immediate WiFi blocker).

---

## 1. THE IMMEDIATE BLOCKER — CYW43455 F2-ready `[APPLIED, READY to flash]`

**State reached on metal:** SDIO link up, chip ID 0x4345, CR4 halted (`IOCTL=0x21`, `halted=true`),
609 KB firmware + NVRAM uploaded (block-mode CMD53, `fail_stage=0`), CR4 activated. **F2 never
went ready** → stuck at `stage-B step 7`.

**Root cause (brcmfmac `brcmf_sdio_bus_init`, confirmed 2 agents):** HEQK only **requested** the HT
clock (`SBSDIO_HT_AVAIL_REQ 0x10`); it never **FORCED** it. F2 (the WLAN data function) only becomes
ready / raises its interrupt when the backplane HT clock is *latched* on. Plus three missing pre-F2
steps.

**The fix (applied to `arch-aarch64/src/cyw43.rs` `firmware_upload`, builds clean):**
1. **F2 block size = 512** via FBR `0x210/0x211` (CMD52) — before F2 enable.
2. **FORCE HT**: `saveclk = read CHIPCLKCSR(0x1000E); write saveclk | SBSDIO_FORCE_HT(0x02)` (RMW).
3. **SDPCM version mailbox**: `bp_w32(sdio_dev_core + 0x48, 4<<16 = 0x0004_0000)`.
4. On F2-ready: keep the watermark write (`0x10008=8`) **and add** `hostintmask`
   `bp_w32(sdio_dev_core + 0x24, 0x0800_00F0)`.

**Diagnostic to read first (`f2_diag`):** `cr4_ioctl` must be ~`0x01` (CPUHALT cleared = CPU running);
`chipclkcsr` should show `HT_AVAIL 0x80` (good = `0xC0`; `0x50` = PLL not locked → HT never came up).

**Anticipated path AFTER F2-ready (so we know it in advance):**
- **SDPCM/BCDC framing bug to fix first** (`bcdc_dcmd`): the SDPCM sw-header **`doffset` must be in
  byte 3, not byte 6**. Layout word0 = `seq(b0) | chan<<8(b1,0=ctrl) | nextlen<<16(b2) | doffset<<24(b3)`,
  doffset = hw-tag(4)+sw-hdr(8) = **12**. `[TODO]`
- **TX credits**: read `txmax` (byte 5) from each RX SDPCM header; only TX while `tx_seq != txmax`,
  bump per frame — or firmware silently drops control frames after the first window. `[TODO]`
- **clmload BEFORE country** (already ordered right); then `country` iovar → readback ∉ {"00","99"}.
  Since `stage-wifi-firmware.sh` bakes `ccode=RO` + fw ≥ 7.45.265, the runtime set is confirmation.
- **The BCM43455 reset trap:** toggling only `wl-on` doesn't fully reset the silicon (retention/VDDIO)
  → PLL can stay wedged, "works once then dead until power-cycle." Add a real chip-reset path + make
  the WiFi driver restartable (MINIX pattern). `[TODO]`

---

## 2. Cross-cutting / systemic fixes (do these first — they unblock whole phases)

| # | Finding | Severity | Fix | Status |
|---|---|---|---|---|
| X1 | **W^X hole: QEMU MMU backend keeps a writable alias to RO+X code** (core A4, BPF V3, P11 V7). CM5 `jit_seal` is correct; `mmu.rs` isn't. | Med | Port `mmu_cm5::jit_seal` to `mmu.rs` (`map_code_page`/`reserve_region`): split the identity block to L3 + flip the alias RO after emit. Invariant must hold on BOTH backends. | `[TODO]` |
| X2 | **Single-core invariant is implicit + load-bearing** (P11 V4). `events::push_hit` HEAD is a non-atomic load+store (MPSC race the day a 2nd producer exists); rate-limiter reset is a non-atomic pair. | Med (High at P11) | Document single-core as a global safety contract in `ARCHITECTURE.md` NOW; make `push_hit` HEAD a `fetch_add`, the rate-limiter reset a single CAS. Do before P11 lifts `MAX_THREADS`. | `[TODO]` |
| X3 | **`get_or_create_table` treats a block descriptor as a table pointer** (core A3) — no `TABLE`-bit check; splits a live identity block → corruption/forged translation. | Med | In `mmu.rs:68-80` (and `mmu_cm5` walkers): if `VALID && !TABLE` → error (or implement block-split). One-line safety gate. | `[TODO]` |
| X4 | **`rand_core` version drift broke the hboot build** all session (boot V1). | Critical (build) | **APPLIED:** pin `rand_core = "0.6"` in `hboot/Cargo.toml` (matches fips205/ed25519-compact); verified `cargo build -p hboot` exits 0. | `[APPLIED]` |
| X5 | **P14 IOMMU fence protects nothing** (driver C1): ceiling `0x4000_0000`, but kernel + all DMA rings/buffers live BELOW 1 GiB, so the RTL retains full DMA over the kernel. A ceiling only isolates memory ABOVE it. | High | Relocate kernel + sensitive state ABOVE `granted_top`, keep only DMA rings below; or invert with the BYPASS window. Read back `ADDR_CAP` and assert the decoded ceiling before trusting it. | `[TODO]` |

---

## 3. Per-phase findings + fixes

### P0–P6b — Core microkernel (agent 1)
| ID | Sev | Finding (file:line) | Fix |
|---|---|---|---|
| A1 | High | Capability system disconnected from the authority mechanism — EL0 device authority is ad-hoc `map_user_device` (`main.rs:291…`), not a Frame/device cap; only `SYS_CAP_IDENTIFY` is wired; `revoke` can't sever a driver's MMIO/DMA. | Route ALL VSpace mapping through cap invocation (seL4 Frame/PageTable caps); make `revoke` unmap. |
| A2 | Med→High | Retype after revoke doesn't zero reused memory (`caps.rs:102-136`, revoke `:158-189` resets watermark only) → cross-tenant info disclosure. | Zero object backing on retype/reset (seL4 reset-on-reuse). |
| A3 | Med | Block-descriptor-as-table (X3 above). | See X3. |
| A4 | Med | Writable identity alias of RO+X code on QEMU (X1). | See X1. |
| A5 | Med | No FP/SIMD save/restore; FPEN never set (`thread.rs:9`, `vectors.s:50-71`) → FP traps halt, or (if enabled later) cross-thread SIMD leak. | Decide FP policy: keep trapped+documented, or enable FPEN + extend frame + scrub q-regs. |
| A6 | Med | Single global CSpace for all EL0 tasks (`main.rs:2174/2310`) → confused deputy. | Per-TCB CSpace root; resolve CPtrs against the current thread's CSpace. |
| A7 | Med | IPC silently drops messages / returns ambiguous 0 (`ipc.rs:43-46/81-84`); no length check, no badge, no grant. | Return `Result`; per-endpoint waiter queues; add badges/grant + length bounds before buffer IPC. |
| A8 | Low→Med | Scheduler `unblock/is_blocked/set_sp` take unchecked `tid` (`scheduler.rs:57-59/107-114`) → latent OOB write; all `static mut`, single-core. | Bounds-check `tid`; gate module behind single-core cfg. |
| A9/A10 | Low | `map_user_in` omits `tlbi` (`mmu_cm5.rs:412-426`); ASID wraps + can re-issue 0 (`mmu.rs:298`). | Add `tlbi vae1is`; make ASID reclaimable, never hand out 0. |
| A11 | Med | CDT parent is a raw slot index (`caps.rs:55`) — sound only for whole-subtree revoke; breaks the instant delete/move/copy is added. | Generation-tagged MDB (sibling/child links) before adding single-cap ops. |
| A12 | Low | Bump heap never reclaims; OOM aborts (`heap.rs:58`). | Fine for now; note as DoS surface once external input drives allocation. |

### P7 — Boot / attestation (agent 2)
| ID | Sev | Finding | Fix |
|---|---|---|---|
| V1 | Critical(build) | rand_core drift (X4). | **APPLIED** (pin 0.6). |
| V2 | High (irreversible) | Dead TRNG at first boot → predictable per-device AK **permanently fused to OTP** (`ak_derive.rs:202-207` discards liveness count). Popcount gate doesn't catch low entropy. | Gate the OTP burn on full TRNG liveness (`live < 8` → software AK, burn nothing) + a TRNG health test. Ship before more devices are provisioned. |
| V3 | High | EL1 can re-read OTP via the VC mailbox (GB65 = EL1 RW) and **re-derive the AK** → scrubbing it from RAM is theater. | Remove the VC-mailbox page from the EL1 stage-2 map; mediate OTP via an HBoot `hvc` service. Or downgrade the "AK non-extractable" claim. |
| V4 | High | No verified first stage (`os_check=0`, hboot loaded unsigned) → replaced HBoot forges PCR0 + AK. Attestation is TOFU. | Enable BCM2712 signed-boot (fuse the RPi key hash, sign `hboot8.img`). Until then, document TOFU in SECURITY.md. |
| V5 | Med | AK is `KDF(OTP)` only — not measurement-bound (not a DICE CDI); a tampered HBoot keeps the same key. | `ak_seed = KDF(OTP_secret, PCR0_after_self_measure)` → tampered HBoot fails attestation closed. |
| V6 | Med | Anti-rollback inert (all images `svn=1`, OTP floor unprovisioned). | Make SVN a real release counter; advance the OTP floor; CI-assert `EXPECTED_MIN_HW_FLOOR`. |
| V7 | Med | EL2 stack grows toward the measured payload with no guard (`linker.ld:32`); measure→launch TOCTOU (copy never re-verified). | Add a guard region; re-hash `load_pa` after the copy, compare to `computed` before launch. |
| V8/V9/V10 | Low-Med | EL2 maps its own code W+X (`mmu.rs:52`); ephemeral seed/nonce ignore TRNG liveness; A/B `hvc #1` confirm is not a security boundary. | W^X the EL2 map; gate nonce entropy; document A/B confirm as reliability-only. |
| — | ✓ | **Correct (checked):** ed25519+SLH-DSA both required + not bypassable; SVN bound in signed msg; deterministic SLH-DSA is the right FIPS-205 variant (not nonce-reuse); stage-2 hides HBoot region from EL1. | — |

### P8 — BPF threat plane (agent 3)
| ID | Sev | Finding | Fix |
|---|---|---|---|
| V1 | Critical (3rd-party goal) | Untyped helper-call ABI: `payload_match(ptr,id)` derefs `R1` as a raw pointer, no verifier bounds check → a 5-insn BPF prog passes `verify_prevail` and becomes an **arbitrary-kernel-read oracle** (class of CVE-2021-4204). Latent (first-party signed rules). | Per-helper ABI signature table: helper #3 requires `arg1: Pkt`, `arg2:` const id; fold `PATTERNS[id].len()` into `min_len`; pass a length + bound-check inside `payload_match`. |
| V2 | High | Verifier models no helper memory effect even for a legit Pkt ptr — safety rests on the author manually touch-loading the last byte. | Same as V1 (helper memory model). |
| V3 | Med | W^X residual on QEMU JIT backend (X1). | See X1. |
| V4 | Low-Med | Unsound legacy `verify()` still present + callable (`bpf.rs:290`) — permits LDX from any base. | Delete or rename so it can never gate a JIT. |
| V5 | Low | JIT emits alignment-sensitive `LDRH/LDR`; interpreter byte-assembles → differential if `SCTLR.A=1` or odd device offset. | Assert `SCTLR_EL1.A=0` or emit byte loads. |
| — | Coverage | Abstract domain is faithful + harness-proven for the implemented ISA, BUT `scalar_from_tnum`/`join`/`lsh_k`/`or_x` are NOT Abs-checked (the linchpin `scalar_from_tnum` especially); `tnum_add` proven only to width 6; signed-interval vs u64-wrap is safe only because SUB/MUL absent. | Add Abs-level checks + u64-wrap concretes + an end-to-end verify-vs-interpreter differential (Agni-style). If SUB/MUL/64-bit-imm ever added, ship transfer functions + wrap-aware harness FIRST. |

### P9–P10 — Drivers (agent 4)
| ID | Sev | Finding | Fix |
|---|---|---|---|
| F2 | — | F2-ready (section 1). | **APPLIED.** |
| D1 | High | rtl8111 RX DMA overflow: `RMS=0x4000 > RXBUF=2048`, `poll_rx` doesn't clamp to RXBUF (`rtl8111.rs:548/581`; GEM clamps, RTL doesn't). Oversized frame → over-read into adjacent buffers. | `wm16(RMS, RXBUF)` + `let n = len.min(out.len()).min(RXBUF);`. |
| D2 | Med | `poll_rx(i,…)` unbounded descriptor index (`rtl8111.rs:571`). | `let i = i % NRX;`. |
| D3 | Med | `cmd53_read/write` silently truncate to 512 B and return `true`; `bcdc_dcmd` sends up to 1464 B → truncated CLM/BCDC. | Loop the transfer in ≤512 B chunks, or reject `len>512`. |
| D4 | Low-Med | `bcdc_dcmd` SDPCM `doffset` in wrong byte + no TX credits (section 1 post-F2). | See section 1. |
| D5 | Low | NVRAM trailer not masked to 16 bits (`cyw43.rs:614`). | `(token & 0xffff) | ((~token & 0xffff)<<16)`. |
| C1 | High | P14 fence protects nothing (X5). | See X5. |
| C3/C4 | Med | `ADDR_CAP_SHIFT=12` unverified; `wrapping_sub(1)` cliff; enable-without-tables assumption. | Read back `ADDR_CAP`, assert the ceiling; confirm the block's enable semantics on metal (esp. iommu5/GEM). |

### P11–P17 — Automation / residuals (agent 6) — *design plan, not yet code*
| ID | Sev | Finding | Fix |
|---|---|---|---|
| V4 | High | Single-core invariant (X2). | See X2. |
| V1 | High(latent) | Helper memory hole (= BPF V1). | See P8 V1. |
| V2 | Med-High | Rate-limiter: 64-slot hash keyed `ip%64` with no key tag → victim-targeted DoS + poisoning (`ratelimit.rs:35`). | Store the full key + reset on mismatch (or count-min sketch); larger table. |
| V3 | Med | Stateful FLOW tier self-parses fixed offsets (no VLAN/IHL) while L4 tier uses `net.rs` → a VLAN tag bypasses SYN-flood + blocklist. | Run FLOW rules on the normalized `net.rs` view, not fixed offsets. |
| V5 | Low-Med | QSecBit score monotonic-saturating, no decay (`telemetry.rs:43`) → one probe pins it forever. | Windowed/EWMA score; keep the lifetime total separate. |
| V6/V7/V8 | Low-Info | Telemetry `src` hard-coded 0; QEMU JIT W^X (X1); IOMMU `fence` edge (already flagged). | Pass the src hash; X1; verify on metal. |
| — | ✓ | **Correct:** `net.rs` parser (VLAN/QinQ/IPv6 bounded, fail-closed); `virtio.rs` bounds device-supplied id/len; `mailbox.rs` coherency + low-1GB guard; interpreter sandbox. | — |

---

## 4. Literature-grounded threat-model boundaries (write these into SECURITY.md)

1. **Capabilities (seL4):** sound design, but HEQK is *unverified* and its guarantees are *designed* not *proven*. The single-core-no-lock simplification is HEQK's version of seL4's "interrupts disabled in-kernel" — treat it as an explicit defended invariant.
2. **In-kernel BPF over hostile packets** is the highest-risk choice; the verifier is first-class attack surface (Agni CAV'23 found the Linux verifier unsound across many versions). Defensible *because* rules are first-party-signed + the interpreter bounds-checks at runtime; **do not open to third-party rules** until V1 + the P16 Agni-style harness land. Keep the interpreter as the permanent floor.
3. **Firmware/DMA:** the BCM2712 IOMMU has **no stream/requester IDs** → per-device isolation is architecturally impossible; only whole-bus ceiling containment (P14). The RTL8111 (Thunderclap NDSS'19 class) is the real DMA threat; the CYW43455 is PIO/SDIO (no autonomous bus-master DMA — lower reach) but is an **unverified blob** — measure it into a PCR before upload. Doctrine: untrusted radios attach only via non-DMA transports (SPI/UART/USB-behind-EL0), never as bus-mastering peers.
4. **Speculation (Cortex-A76):** spatial isolation ≠ micro-architectural isolation. The BPF bounds checks are a Spectre-v1 gadget surface; add `CSDB`/`nospec` after them. Scope the product to single-tenant edge explicitly.

---

## 5. Prioritized implementation order

**Phase R0 — unblock + safety gates (now):**
1. `[APPLIED]` rand_core 0.6 (X4) — rebuild + re-sign `heqk8.img`.
2. `[READY]` F2-ready fix (§1) — flash + confirm firmware-alive.
3. `[TODO]` X3 block-as-table one-line gate; D1/D2 RTL clamps (cheap, high-value).

**Phase R1 — the security mechanism (before any claim holds):**
4. A1: mapping via capability invocation; `revoke` unmaps. A6: per-TCB CSpace. A2: zero-on-reuse.
5. X1: port `jit_seal` to `mmu.rs` (W^X parity on both backends).
6. X2: document single-core invariant; make `push_hit`/rate-limiter reset atomic.
7. BPF V1/V2: helper ABI typing + `min_len` folding (before third-party rules).

**Phase R2 — boot root-of-trust:**
8. Boot V2 (TRNG-gated OTP burn — **before more provisioning**), V4 (signed-boot), V5 (measurement-bound AK), V3 (mailbox out of EL1 map), V6 (real SVN), V7 (guard + post-copy re-hash).

**Phase R3 — WiFi datapath to regdomain (after F2):**
9. SDPCM doffset fix + TX credits (D4) → BCDC control → clmload → `country=RO` readback ≠ 00/99.
10. WiFi driver restartability + real chip reset (BCM43455 reset trap).

**Phase R4 — DMA containment made real + detection-plane hardening:**
11. X5/C1: relocate kernel above the fence ceiling; C3/C4 verify on metal.
12. P11 V2 (rate-limiter key tags), V3 (normalized FLOW parsing), V5 (decaying score).

**Phase R5 — assurance:**
13. Extend the BPF harness (Abs-level `scalar_from_tnum`/`join`, u64-wrap, end-to-end differential).
14. Property tests for cap invariants (rights monotonicity, revoke completeness, no-reuse-without-zero) on BOTH MMU backends. Add `CSDB` after BPF bounds checks (Spectre-v1).
15. **Strategic:** `CAPABILITY_MODEL.md` §0's own conclusion stands — adopting the verified seL4 core for the TCB and keeping HEQK's drivers/IDS/boot proprietary above the kernel/user line is the strongest long-term de-risking of the whole system.

---

## 6. Sources (consolidated)
seL4 (manual, SOSP'09, whitepaper, comprehensive-verification); QNX Neutrino IPC/resmgr; MINIX 3
(Herder thesis, Tanenbaum reliable-os); Zircon/Fuchsia handles; Redox microkernel; sDDF/LionsOS
(arXiv 2501.06234). BPF: PREVAIL (PLDI'19), tnum (CGO'22, arXiv:2105.05398), Agni (CAV'23, SAS'24/'25),
OSDI'24 state-embedding; CVE-2021-4204/2022-23222/2020-8835. Boot: TCG DICE, DICE★ (USENIX'21),
FIPS-205 SLH-DSA. DMA: Thunderclap (NDSS'19); VFIO/iommufd. Speculation: ARM Cortex-A76 security
bulletin. WiFi: brcmfmac `sdio.c`/`chip.c`, OpenBSD `bwfm_sdio.c`, Infineon `cyw43-driver`, OpenWrt #23069.
Full URLs in the agent transcripts + `HEQK_KERNEL_DOSSIER.md`.
