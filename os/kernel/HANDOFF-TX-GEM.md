# GEM TX 50% alternating failure on CM5 — **RESOLVED**

**Status:** 🟢 **Root cause proven and fixed.** 100/200 (50%) → **1 failure in 6,200 frames (0.016%)**.
**Date:** 2026-08-20 · **Branch:** `worktree-heqk-premetal-gaps` · **Board:** CM5, zero-Linux boot partition.

Two smaller items remain open — see §7. Neither is the alternation.

---

## 1. Root cause

**The GEM silently drops `TSTART` writes** issued too soon after a previous frame, while
the transmitter is still internally busy. The write is discarded, the frame never starts.

`tx_frame` kicked **once** and then polled for ~50 ms, so a dropped kick became a reported
failure — while the *next* frame's kick landed cleanly. That is the deterministic 50%
alternation. It is **frame-sequential**, which is why it appeared identically at `NTX=1`
and `NTX=2`, and why the "perfect WRAP correlation" seen at `NTX=2` was a period-2
confound rather than causation.

### Authoritative confirmation

Linux `drivers/net/ethernet/cadence/macb_main.c:2517` — the reference driver for this
exact controller (source is on this machine, in `builder/kernel-build/linux-rpi-*.tar.gz`):

```c
/* TSTART write might get dropped, so make the IRQ retrigger a buffer read */
if (macb_readl(bp, TSR) & MACB_BIT(TGO))
        queue->tx_pending = 1;
macb_writel(bp, NCR, macb_readl(bp, NCR) | MACB_BIT(TSTART));
```

Linux *expects* the drop: it flags the condition via `TSR.TGO` and has the TCOMP/TXUBR IRQ
retrigger the queue (`:2058`), where `macb_tx_restart()` re-reads `TBQP`, compares the
controller's consumer position against the software head, and **re-issues `TSTART`** if it
has not caught up (`:1834-1843`).

---

## 2. Evidence — quantitative, not correlational

`[P8-txdiag]` `spins` column with `RETRIGGER_SPINS = 2000` (boot 11, image `73316c88`):

```
 seq ok  spins    note
   0 OK    381    first-kick success
   1 OK   2461    ~400 spins AFTER the retrigger fired at 2000
   2 OK    364    first-kick success
   3 OK   2481    ~400 spins after retrigger
```

Frames that previously burned the **entire 200,000-spin budget** complete ~400 spins after
a *second* `TSTART` — the **same** latency as a first-kick success (364–391). The frame was
never slow, never halted, never mis-polled. The kick simply never arrived.

### Scale regression (boot 12, image `05c624d9`)

```
[P8-txburst] MEASURED — 200 frames:  199 sent /  1 FAILED (0.5%)  last_tsr=0x01
[P8-txburst] PASS     — 1000 frames: 1000 sent / 0 FAILED (0.0%)  last_tsr=0x00
[P8-txburst] PASS     — 5000 frames: 5000 sent / 0 FAILED (0.0%)  last_tsr=0x00
```

1,000 and 5,000 are perfectly clean with a fully clear status register. The single failure
is in the **first** burst — a cold-start artifact, not a rate: a 0.5% rate would have
produced ~25 failures at 5,000, and produced zero.

---

## 3. The fix

**Re-issue `TSTART` periodically while polling** — the synchronous equivalent of Linux's
IRQ-driven retrigger, since this path has no interrupts. `RETRIGGER_SPINS = 512`, tuned to
the **measured** ~400-spin transmission latency (2000 made every dropped kick wait ~5×
longer than necessary).

The constant is **shared** between `tx_frame` and `tx_diag_burst` deliberately: they were
briefly allowed to drift (production 512, diagnostic hardcoded 2000) and the diagnostic
then reported spin counts for a configuration that was no longer shipping.

### ⚠️ DO NOT "clean up" the NCR writes into a read-modify-write

`macb` uses `NCR |= TSTART`. **That was tried here and broke transmission completely:**
0 sent / 200 FAILED, `TSR = 0x0000` on every frame — no TXCOMP, no UBR, no TGO, i.e. the
transmitter was not running at all. **`NCR` readback is not trustworthy on this
integration** (`TSTART` is self-clearing and the readback did not carry `TE`), so
`readback | TSTART` left `TE` **clear**. The explicit `RE|TE|MPE|TSTART` write is
load-bearing, not sloppiness.

---

## 4. False hypotheses — all rejected by measurement

| Hypothesis | Verdict and how it died |
|---|---|
| UBR / transmitter halt | **No.** Frames succeed with UBR latched (`tsr=0x0021` throughout) |
| Recovery ordering (3 policies tried) | **No.** The diagnostic applies *no* recovery and alternates identically |
| One-descriptor ring (`NTX=1`) | **No.** `NTX=2` alternated identically |
| Descriptor prefetch aliasing | **No.** Same as above |
| Descriptor reuse / ownership | **No.** `w1_armed` correct on every frame |
| Memory ordering / barriers | **No.** Disassembly: ownership store last, `dsb sy` correctly placed |
| MMIO ordering / posted writes | **No.** `tsr_postkick` stable and identical on both outcomes |
| Completion polling | **No.** `w1_final` truthfully distinguishes every outcome |
| Cache / DMA visibility | **No.** Descriptor reads back correctly every time |
| Queue-pointer desync (`TBQP` rewrite) | **No.** Resync before every kick did not change the 50% |
| **Dropped `TSTART`** | **YES** — confirmed quantitatively (§2) and in the reference driver |

---

## 5. Machine code — verified correct (Phase 4, do not redo)

```asm
1015af8:  str  w21, [x9]        ; word0 = buffer addr_lo
1015afc:  str  w10, [x9, #0x8]  ; word2 = addr_hi
1015b00:  str  w8,  [x9, #0x4]  ; word1 = len|LAST|wrap, USED=0  <- ownership store LAST
1015b0c:  dsb  sy               ; <- barrier AFTER publication, BEFORE MMIO
1015b48:  stur w10, [x8, #-0x14]; NCR = 0x21c = RE|TE|MPE|TSTART
1015b54:  ldr  w1,  [x9, #0x4]  ; poll word1
1015b58:  tbnz w1, #0x1f        ; test bit31 = USED
```

Ownership store last, barrier correctly placed, NCR decodes correctly, poll reads the right
word and bit. **Software ordering was never the defect.**

---

## 6. Measurement discipline — the durable lesson

The failure rate was estimated **five times** from live traffic (20% → 8.7% → 10% → 2% →
9%) and contradicted twice, because the segment idles **45 s at a stretch** and each window
held only a few dozen frames. Nothing converged until a **deterministic stimulus** existed.

* **`[P8-txburst]`** (`gem::tx_burst_selftest`) — fixed-size back-to-back bursts. Caught a
  regression on its first execution.
* **`[P8-txdiag]`** (`gem::tx_diag_burst`) — per-frame hardware state, **no recovery
  applied**, so it records the unmodified mechanism.

**Experiment-design traps hit during this investigation, recorded so they are not repeated:**
* `NTX=2` was **confounded** — rotation period 2 equalled the alternation period 2, making
  slot- and frame-effects indistinguishable. Use `NTX=3`/`4` if ring depth is ever retested.
* One build changed **two variables at once** (retrigger + NCR RMW) and produced a
  self-inflicted 0/200 regression that cost a metal cycle.
* Reasoning about the GEM contract from recall produced three wrong theories. **Read the
  reference driver first** — it was on this disk the whole time.

---

## 7. STILL OPEN (neither is the alternation)

1. **Cold-start TX burst.** The live sensor shows ~15 `tx_fail` in the first ~11 s, then
   **flat** (subsequent frames all forward). The 200-frame burst shows the same shape with
   1 failure. Likely the first transmits after the selftest leaves the controller in a
   particular state. Small, bounded, and no longer a steady-state defect.
2. **`NTX=2` is retained but not independently justified.** The defect proved
   frame-sequential, so `NTX=1` would very likely work identically. Depth 2 is arguably
   more correct hardware usage regardless, but if a minimal diff matters, test `NTX=1` with
   the retrigger before keeping it.

---

## 8. What is NOT broken

* **Enforcement never regressed** across twelve boots: `[P8] PASS — inline IPS: forward :53
  / drop :4444`, and `drop=0` on every real frame observed. A TX failure meant a PASS frame
  was not forwarded — **never** that a threat passed or a legitimate frame was dropped.
* **RX is fine.** `faults=0` on every run; the isolated EL0 driver never crashed.
* **`W^X`, secure boot, attestation** PASS on all boots.
* `[P8-irq]` 0 IRQs is **DRV-1** (RP1 `MSIX_CFG_6` not firmware-preprogrammed) — separate,
  known, unrelated.

---

## 9. Reproduce

```bash
export HEQK_KEYDIR=~/heqk-sign/keys
HOOKPROBE_DEBUG_ACCESS=1 os/build/make-cm5-heqk-image.sh          # builds `prod`
# CM5 in rpiboot (nRPIBOOT jumper + power-cycle):
sudo os/kernel/cm5-boot/flash-clean.sh --no-dtb
# jumper out, power-cycle, read /dev/ttyUSB2 @115200 for [P8-txdiag] and [P8-txburst]
```

Boot logs, each named with its image hash, are in `~/heqk-metal-logs/`.
