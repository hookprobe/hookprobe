# HEQK Kernel Dossier — Microkernels, Drivers, SDIO-WiFi, aarch64, Reverse Engineering

Durable reference to convert guessing into engineering. Companion: `HEQK_REMEDIATION_PLAN.md`.
Produced 2026-07-23 from a deep multi-kernel + academic research pass. Citations inline.

---

## Part 1 — Microkernels, compared (what HEQK should adopt)

| Kernel | TCB | Capabilities | IPC | Drivers | Verified |
|---|---|---|---|---|---|
| **seL4** | C, ~10k LOC | Caps in CNodes; all RAM from **Untyped** retyped into objects | Sync **Endpoints** + async **Notifications**; hand-tuned **fastpath** | EL0; device = IRQHandler cap + device Frame cap + Untyped for DMA | **Yes** (to machine code, Isabelle/HOL) |
| **QNX Neutrino** | small C | connection IDs, abilities | sync **MsgSend/Receive/Reply** (copying rendezvous) | userspace **resource managers** register a namespace path | No (safety-certified) |
| **MINIX 3** | ~4–6k C | endpoints + grant tables | sync `sendrec` | userspace, **none as root**; **Reincarnation Server** restarts crashed drivers | No (dependability research) |
| **Zircon/Fuchsia** | C++ | **handles** (process-local) with **rights** bitmasks | channels (msg+handle passing) | userspace, DFv2 | No |
| **Redox** | **Rust** | moving to caps; today "everything is a URL" (schemes) | scheme messages | userspace scheme providers | No |

**seL4 (the model HEQK is closest to):**
- **Capabilities in CNodes** — threads name capability *slots*, never addresses; no ambient authority.
- **Untyped memory = the whole allocator.** No kernel heap after boot. All RAM handed to userspace as
  `Untyped` caps, `Retype`d into typed objects; each Untyped keeps a **watermark**; free = `Revoke` on
  the parent via the **capability derivation tree (CDT)**. Result: kernel memory is bounded + accountable,
  a client can only exhaust its *own* Untyped → whole class of DoS killed, and there's no `kmalloc` to get
  wrong. **Highest-leverage thing for HEQK to adopt.**
- **IPC fastpath:** when a `Call` hits an Endpoint with a waiting receiver, matching badge/rights, a small
  register-only message, and no scheduling decision → **direct context switch** to the receiver, bypassing
  the run-queue. ~10× faster than prior microkernels. Make the fastpath a *specialization* of the slowpath.
- **Why it's provable:** no in-kernel concurrency (single big lock / event-based), no dynamic allocation,
  bounded loops, explicit capability accounting. That *architecture* is the takeaway even without the proof.

**QNX** = the shipping-driver discipline: sync copying message passing (natural flow control +
priority inheritance — server runs at the client's priority); **resource managers** sit in a
`MsgReceive` loop and switch on tagged message type. Lesson: give drivers ONE uniform tagged
request/reply ABI.

**MINIX 3** = self-healing: drivers unprivileged, a supervisor pings them and reloads a fresh copy
from RAM on crash/hang (most driver bugs are transient). Lesson: **design drivers to be restartable**
(state reconstructable, caps re-grantable) — directly relevant to the WiFi "wedged until power-cycle" trap.

**Zircon** = rights-on-the-reference: kernel objects hold no security state; two handles to the same
object can carry different rights. Lets HEQK hand a driver a read-only / no-DMA view cheaply.

**Redox** = proof a Rust `no_std` microkernel is viable at OS scale; validates HEQK's language choice.

**Synthesis — adopt:** (1) seL4 Untyped+CNode+no-kernel-heap backbone; (2) register-only sync IPC
fastpath + uniform tagged driver ABI (QNX); (3) rights-on-the-cap (Zircon); (4) restartable drivers
under a supervisor (MINIX); (5) minimal single-threaded event-based kernel in Rust `no_std`.

---

## Part 2 — Isolated drivers, done right (HEQK P7)

Universal recipe: give a driver exactly **(a) an MMIO window, (b) an IRQ, (c) bounded DMA**, nothing else.

**seL4 device driver = three capabilities:**
- **MMIO** → a **Frame cap** for the register page (from *device Untyped* at a specific PA — you allocate
  dummy objects until the Untyped watermark reaches the target PA). Driver touches only that page.
- **IRQ** → an **IRQHandler cap** bound to a **Notification**; driver `Wait`s, services, `Ack`s to unmask.
  seL4 delivers no further IRQs on that line until Ack → a driver that forgets to Ack just stops getting
  *its own* IRQs (contained failure).
- **DMA** → an Untyped/Frame the driver maps, + (IOMMU platforms) the kernel programs the IOMMU so the
  device reaches only those pages.
- **sDDF** (seL4 Device Driver Framework): drivers are plain EL0 processes; datapath = **shared-memory
  SPSC ring buffers**, zero-copy, RX/TX separate, device sharing via *virtualisers* (which do
  VA↔IOVA + cache mgmt). An Ethernet driver in <600 LOC saturates 1 Gb/s at ~65% CPU — beats Linux.
  **This is the blueprint for HEQK P7.**

**Linux VFIO** = the productized "MMIO + IRQ + IOMMU-enforced DMA to userspace" model; the IOMMU
translates device IOVA→PA so a malicious device can't touch arbitrary RAM. **UIO** = the weaker cousin
(MMIO+IRQ, **no DMA isolation** — only for non-bus-master devices).

**HEQK/BCM2712 reality:** not a clean IOMMU platform. Where there's no per-device IOMMU, "bounded DMA"
must be enforced by handing the driver only a pre-reserved contiguous region AND **capability-checking
the address the driver writes into a DMA-descriptor register** (not just at map time). Treat "the address
a driver may put in a DMA descriptor" as a cap-checked operation.

**P7 checklist:** enumerate MMIO windows + IRQs once; mint a device Frame cap per MMIO page
(**Device-nGnRnE attribute**, non-cacheable); mint an IRQ cap bound to a Notification (ack-to-unmask);
grant a bounded DMA region + enforce descriptor addresses ∈ region; grant nothing else; make it restartable.

---

## Part 3 — SDIO / WiFi FullMAC bring-up (the CYW43455 sequence)

FullMAC = 802.11 MAC/MLME runs in firmware on the chip's internal ARM (+ D11 PHY μcode); the host just
downloads firmware then exchanges control/data over SDIO.

**Phase A — SDHCI host init:** power WiFi domain (`WL_REG_ON` GPIO high), release reset; SDHCI reset,
set voltage, **~400 kHz** ident clock, 1-bit bus.
**Phase B — SDIO enum:** **CMD5** (IO_SEND_OP_COND, wait ready — F0/CCCR, **F1=backplane**, **F2=WLAN
data**), **CMD3** RCA, **CMD7** select; read CCCR/FBR; switch **4-bit** (CCCR 0x07) + high-speed, raise
clock (~50 MHz); enable **F1** (CCCR I/O-Enable 0x02), poll I/O-Ready 0x03.
**Phase C — backplane + firmware (via F1):** read chip ID; request **ALP** (write `ALP_AVAIL_REQ 0x08` to
`CHIPCLKCSR 0x1000E`, poll `ALP_AVAIL 0x40`); **halt the internal ARM core**; **download firmware** to chip
RAM through the F1 window (slide via `SBADDRLOW/MID/HIGH` 0x1000A/B/C); **download NVRAM/CLM** to the top of
RAM; **take the ARM core out of reset**.
**Phase D — F2 ready (the crux, see below).**
**Phase E — SDPCM/BCDC:** firmware speaks **SDPCM** (framing/flow-control over SDIO) with **BCDC**
(control/iovar) on top; enable host mailbox interrupts (`hostintmask`); BCDC handshake (`ver`, `cur_etheraddr`).
**Phase F — regulatory:** `country` iovar (real ccode+regrev, not 00/99), then `up`.

### The F2-ready microscope (why HEQK was stuck)
After releasing the ARM core, `brcmf_sdio_firmware_callback` / `brcmf_sdio_bus_init` does, in order:
1. **FORCE the HT clock:** `saveclk = read CHIPCLKCSR; write saveclk | SBSDIO_FORCE_HT (0x02)` (RMW).
   **Make-or-break** — F2 only becomes ready + raises its interrupt when HT is *latched* on. (43455 is
   not ULP, so it's `FORCE_HT 0x02`, not just `HT_AVAIL_REQ 0x10`.)
2. **F2 block size** (512 for 43455; some parts 64) via FBR 0x210/0x211 — block-size mismatch corrupts
   every transfer.
3. **SDPCM version** to the SDIO-dev core mailbox: `w_sdreg32(tosbmailboxdata = SDPCM_PROT_VERSION<<16)`
   (= `0x0004_0000` to sdio_dev_core + 0x48).
4. **Enable F2** (CCCR I/O-Enable 0x02 bit2), **poll CCCR I/O-Ready 0x03 bit2** — "F2 ready" = IOR2=1,
   set by the *firmware on the chip* once it initialized the data function. If firmware isn't running or
   HT isn't forced, IOR2 never sets.
5. **Program RX watermark** `SBSDIO_WATERMARK 0x10008` + `SBSDIO_DEVCTL F2WM_ENAB 0x10`; **enable device
   interrupts** `hostintmask = I_HMB_SW_MASK(0xF0) | I_CHIPACTIVE(1<<27) = 0x0800_00F0` (sdio_dev_core+0x24);
   manage **KSO** (Keep-Sdio-On) so the interface doesn't gate off between enable and first transfer.

**"Stuck at F2 ready" checklist:** read CHIPCLKCSR — `0x50` = ALP up but **HT not available (PLL not
locked)**, good = `0xC0`; forgot FORCE_HT; wrong FW/NVRAM (core boots, MAC firmware faults); block
size/watermark unset (F2 enables but first SDPCM stalls); the **BCM43455 incomplete-reset trap** —
toggling only `wl-on` doesn't fully reset the silicon, retention/VDDIO can leave the PLL wedged so HT
never locks next attempt; only a full power-cycle recovers → expose a real chip-reset path + restartable driver.

**Post-F2 SDPCM/BCDC gotchas:** SDPCM sw-header **`doffset` is byte 3** (= hw-tag 4 + sw-hdr 8 = 12), word0
= `seq(b0)|chan<<8(b1,0=ctrl)|nextlen<<16(b2)|doffset<<24(b3)`, word1 = `fcmask(b4)|txmax(b5)|rsvd`. **TX
credits:** read `txmax` (b5) each RX header, TX only while `tx_seq != txmax`. `clmload` BEFORE `country`.

**References:** Linux `brcmfmac/sdio.c` (executable spec), OpenBSD `bwfm_sdio.c` (smallest readable port),
Infineon `cyw43-driver` (leanest bare-metal). OpenWrt #23069 (HT timeout `clkctl 0x50` + reset trap).

---

## Part 4 — aarch64 kernel construction (BCM2712/RP1) + common mistakes

**Boot/EL:** VideoCore firmware loads your image, usually drops you at **EL2**, core 0, MMU/caches off,
one core. DTB pointer in `x0`. To run kernel at EL1: `HCR_EL2.RW=1`, program `SPSR_EL2`/`ELR_EL2`, `eret`.
Park secondary cores (spin-table/PSCI) until ready — don't assume all 4 start.

**Exception vectors (`VBAR_EL1`):** 16 entries × 128 B, 2 KB aligned. Save/restore the FULL frame
(x0–x30, SP, ELR_EL1, SPSR_EL1). Read `ESR_EL1` (syndrome) + `FAR_EL1` (fault addr) — your only early window.
*Mistake:* wrong 128-B spacing / not 2 KB aligned → jump mid-handler.

**MMU:** `MAIR_EL1` attribute slots (≥ one **Normal WB cacheable** + one **Device-nGnRnE** for MMIO —
mapping MMIO as Normal-cacheable is a brutal classic bug). `TCR_EL1`: T0SZ/T1SZ, granule TG0/TG1 (4 KB is
`0b00` for TG0 but `0b10` for TG1 — mis-encode = silent wrong granule), IRGN/ORGN/SH for walks, **IPS for
40-bit PA** (BCM2712 needs >32-bit). `TTBR0`=low VAs, `TTBR1`=high VAs (**EL2 has no TTBR1** — no high-half
kernel at EL2). Descriptors: bit0=valid, **bit1=1 table/page vs 0 block** (the single most common table
bug), set `AF` (else every access faults), `SH`=Inner-Shareable for Normal on SMP/DMA coherency. **W^X**:
`AP` + `UXN`/`PXN`; kernel text RX (PXN=0, RO), data/stack RW+PXN+UXN, never W+X. **Enable:** program
MAIR/TCR/TTBR → `dsb ish; tlbi vmalle1; dsb ish; isb` → set `SCTLR_EL1.M` (+`.C`,`.I`) → `isb`; keep an
identity map of the enabling code across the switch.

**GIC (GIC-400/GICv2 on BCM2712, base ~0x107fff8000):** GICD enable + priorities/targets/config/ISENABLER;
GICC PMR=0xFF + CTLR enable. Per-IRQ: read `GICC_IAR` (ack, get INTID), service, write `GICC_EOIR`
(*forgetting EOIR = never get that IRQ again*). Prefer DT for IRQ numbers — RP1 routes its own IRQs (incl. SDIO).

**Timer:** read `CNTFRQ_EL0` (don't assume 19.2 vs 54 MHz); arm `CNTP_TVAL/CVAL` + `CNTP_CTL`; its PPI via GIC.

**Cache coherency / barriers (the SDIO/DMA bug source):** before a device reads your buffer, **clean**
`dc cvac` → RAM; after a device writes, **invalidate** `dc ivac` before CPU read (or `dc civac` when unsure).
`dsb` orders (ish inner-shareable, sy device/DMA completion); `dmb` lighter; `isb` after changing sysregs
(SCTLR/TCR/VBAR). Device-nGnRnE orders *at that peripheral* only — still need `dsb` across peripherals + before
waiting on an IRQ. **I-cache is NOT coherent with D-cache** — after writing code:
`dc cvau → dsb ish → ic ivau → dsb ish → isb`.

**BCM2712/RP1 specifics:** parse the DTB (memory, GIC base, timer freq, UART, SDHCI/SDIO, RP1) — don't
hardcode Pi-4 addresses; on **Pi 5 much peripheral access is via RP1 over PCIe** (GPIO/clocks that were
direct MMIO on Pi 4). VideoCore **property mailbox** for framebuffer/clocks/power-domains/board-rev/MAC.

**Top mistakes:** MMIO cacheable not Device · missing DMA cache maintenance · vector misalignment · MMU
enabled without identity-mapping the enabling instruction + isb · TG1≠TG0 encoding · AF unset · wrong
shareability · forgetting GIC EOIR · hardcoding Pi-4 addresses · W+X pages · using EL2 expecting TTBR1.

---

## Part 5 — Reverse engineering + machine code

**RE an undocumented firmware blob (Ghidra):** identify the arch (AArch64 kernel? Cortex-M/R coprocessor?
DSP μcode? — load under candidates, pick the one that yields clean functions); **find the load base**
(datasheet/reset-vector/pointer clustering; a raw blob defaults to base 0 = wrong; create separate
flash/SRAM memory blocks so xrefs resolve); **map registers** (CMSIS-SVD via SVD-Loader labels MMIO);
find the entry (Cortex-M vector table: [SP, reset, …]); large "code-like but won't disassemble" regions
are usually copied data or another arch's code — don't force it; **corroborate dynamically** — diff your
code's MMIO writes against a known-good register dump from a working driver, use bus traces. **For HEQK's
WiFi:** you rarely RE the WiFi firmware (black box you download) — you RE the *host-side protocol* by reading
brcmfmac/bwfm/cyw43-driver source + capturing the exact SDIO sequence a working system emits, then matching it.

**AArch64 essentials:** fixed 32-bit instructions, 4-byte aligned. x0–x30 (w0–w30 low half); x30=LR,
x31=XZR/SP; x0–x7 args/returns, x8 syscall/indirect-result. **PSTATE** (NZCV, DAIF masks — `msr daifset/clr`
for critical sections). Sysregs via `mrs`/`msr` (`isb` after control-reg changes). `ldr/str`, `ldp/stp`
(frame save/restore); atomics `ldxr/stxr` or LSE (`ldadd/cas`), acquire/release `ldar/stlr`. Exceptions:
`svc`(EL0→EL1), `hvc`, `smc`; return `eret` via ELR/SPSR; `brk` debug. **AAPCS64:** args x0–x7 then stack,
return x0/x1, callee-saved x19–x28+fp/lr, 16-byte stack align (matters at Rust↔asm boundaries).

**W^X/JIT:** never keep a page W+X — write to a RW alias then remap RX (or toggle perms with `dsb;isb`);
after writing code do the full I-cache maintenance dance (Part 4). **MMIO ordering:** preserve BOTH order
*and* barriers/settling-delays/read-backs when reproducing an RE'd init sequence — many chip inits depend on them.

---

*Full source URLs are in the agent transcripts; key study targets: Linux `brcmfmac/sdio.c`,
OpenBSD `bwfm_sdio.c`, Infineon `cyw43-driver`, seL4 reference manual + sDDF, MINIX 3 papers.*
