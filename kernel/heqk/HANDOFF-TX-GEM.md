# HANDOFF — GEM TX 50% alternating failure on CM5 (OPEN)

**Status:** 🔴 **OPEN.** Six metal cycles spent. Three explanations proposed and each
later contradicted by its own follow-up measurement. **Root cause NOT established.**
**Date:** 2026-08-20 · **Branch:** `worktree-heqk-premetal-gaps` · **Board:** CM5, zero-Linux boot partition.

> **The value of this note is the EVIDENCE (§2) and the RULED-OUT list (§3), not a
> diagnosis.** Several plausible theories are already dead by measurement, and the open
> contradiction in §4 invalidates any explanation that does not account for BOTH datasets.

---

## 1. Symptom

Under back-to-back transmission, exactly half of all frames fail to complete:

```
[P8-txburst] MEASURED — 200 frames: 100 sent / 100 FAILED (50.0%)
```

**100/200 is a PATTERN, not a rate** — probabilistic loss does not land on precisely
half. Failures alternate, strictly. A failing frame's poll burns the full budget
(200 000 spins in the diagnostic; 500 000 in production ≈ 50 ms).

Sparse live traffic reports only ~2–4%, because frames are far enough apart to hide it.
**Never characterise this from live traffic** — see §6.

### What is ACTUALLY broken (this was mis-stated for most of the session)

1. **~50 ms stall on alternate frames.** `tx_frame` is synchronous and sits in the inline
   forwarding path, so the sensor blocks. That caps forwarding at ~20 fps on the stalling
   half. **This is the serious defect**, and it is real regardless of whether the frame
   eventually reaches the wire.
2. **`tx_fail` accounting is wrong in at least some builds** — frames counted as failed
   had in fact transmitted. Every rate quoted this session (8.8% / 1.9% / 3.5%) measured
   MIS-ACCOUNTING, not lost traffic.
3. **Latent descriptor-reuse risk.** Software re-arms a descriptor without knowing the
   controller has consumed the previous one. **Not observed**, but the ring-contract
   violation permits wrong/duplicate bytes on the wire — unacceptable for an inline
   forwarder. Worth a targeted check.

---

## 2. RAW EVIDENCE — the `[P8-txdiag]` tables

`gem::tx_diag_burst` mirrors `tx_frame` exactly but applies **no recovery of any kind**,
so these record the unmodified mechanism.
`word1`: bit31 `USED`, bit30 `WRAP`, bit15 `LAST`, bits[13:0] length.
`0x4000803c` = WRAP|LAST|60 armed · `0xc000803c` = same + USED (completed).

### 2a. `NTX=1` (single descriptor, WRAP always set) — image `ea19a6db`

```
 seq ok  tsr_entry w1_entry   w1_armed   tsr_pre tsr_post w1_postkick spins    w1_final   tsr_final
   0 OK   0x0001   0xc000802a 0x4000803c  0x0001  0x0001  0x4000803c     493  0xc000803c 0x0021
   1 --   0x0021   0xc000803c 0x4000803c  0x0021  0x0021  0x4000803c  200000  0x4000803c 0x0021
   2 OK   0x0021   0x4000803c 0x4000803c  0x0021  0x0021  0x4000803c     481  0xc000803c 0x0021
   3 --   0x0021   0xc000803c 0x4000803c  0x0021  0x0021  0x4000803c  200000  0x4000803c 0x0021
```

**Every frame is armed identically (`0x4000803c`, WRAP set); TSR is identical (`0x0021`)
on both outcomes — yet it alternates.** Software-visible state at `TSTART` is
byte-identical for success and failure.

### 2b. `NTX=2` + `TBQP` resync — image `879a929f`

```
 seq ok  w1_entry   w1_armed   tsr_pre tsr_post spins    w1_final
   0 OK  0xc0000000 0x4000803c  0x0000  0x0000     501  0xc000803c
   1 --  0x8000802a 0x0000803c  0x0021  0x0021  200000  0x0000803c
   2 OK  0xc0000000 0x4000803c  0x0021  0x0021     501  0xc000803c
   3 --  0x0000803c 0x0000803c  0x0021  0x0021  200000  0x0000803c
```

**Success correlates 100% with the WRAP bit in `w1_armed`** (10/10 rows). The controller
transmits a descriptor carrying WRAP and refuses one without it — **even with `TBQP`
pointed directly at that descriptor**.

### 2c. Build-specific: late completion appears and disappears

* `NTX=2`, **no** TBQP resync: `seq 1` ends `w1_final=0x0000803c`; by `seq 3` the same
  descriptor reads `w1_entry=0x8000803c` — **hardware set USED after we stopped polling.**
  The frame transmitted LATE.
* `NTX=2`, **with** TBQP resync: `seq 3` reads `w1_entry=0x0000803c` — USED never set.
  Those frames are genuinely never transmitted.

"Frames complete late" is therefore **build-specific, not a stable property of the
defect.** Do not build a theory on it without re-measuring on your build.

---

## 3. RULED OUT — by measurement, not argument

| Hypothesis | How it was eliminated |
|---|---|
| **DMA / cache visibility of the descriptor** | `w1_armed` reads back correctly on EVERY frame, both outcomes |
| **MMIO ordering / posted writes** | `tsr_postkick` sampled after the kick; stable and identical on both outcomes |
| **Completion misinterpretation by software** | `w1_final` truthfully distinguishes every OK (`0xc0…`) from every FAIL (`0x40…`/`0x00…`) |
| **UBR halting the transmitter** | Frames succeed **with UBR latched** (`tsr=0x0021` throughout, never cleared in the diagnostic) |
| **Recovery policy / ordering** | The diagnostic applies **NO recovery** and alternates identically. Also tested in production: restart-after-completion, never-restart, restart-after-arming — all 100/200 |
| **Compiler / CPU reordering** | Disassembly (§5): ownership store is LAST, `dsb sy` correctly placed between publication and the MMIO kick |
| **`TSTART` changing controller state** | `tsr_postkick == tsr_prekick` on every row, success and failure alike |
| **Queue-pointer desync alone** | `TBQP` resync before every kick did NOT change the 50% |

---

## 4. ⚠️ THE OPEN CONTRADICTION — any theory must explain BOTH

* In **`NTX=2`**, success ⟺ `WRAP` set on the armed descriptor (§2b, 10/10 rows).
* In **`NTX=1`**, **every** frame had `WRAP` set (§2a) — and it **still alternated 50%**.

"WRAP present ⟹ success" is perfect in one dataset and flatly contradicted by the other.
Both are measured, neither inferred. **Until one mechanism explains both, there is no root
cause** — only two partial patterns. Resolving this is the highest-value next step.

---

## 5. Machine code — VERIFIED CORRECT (Phase 4 complete, do not redo)

```asm
1015af8:  str  w21, [x9]        ; word0 = buffer addr_lo
1015afc:  str  w10, [x9, #0x8]  ; word2 = addr_hi
1015b00:  str  w8,  [x9, #0x4]  ; word1 = len|LAST|wrap, USED=0  <- ownership store LAST
1015b0c:  dsb  sy               ; <- barrier AFTER publication, BEFORE MMIO
1015b48:  stur w10, [x8, #-0x14]; NCR = 0x21c = RE|TE|MPE|TSTART
1015b54:  ldr  w1,  [x9, #0x4]  ; poll word1
1015b58:  tbnz w1, #0x1f        ; test bit31 = USED
```

Ownership store is last; `dsb sy` sits between descriptor publication and the kick; NCR
decodes correctly (bits 2,3,4,9); the poll reads the right word and bit. Slot rotation and
WRAP selection also compile as written. **Software ordering is not the defect.**

Incidental: `RXD_FRMLEN` (an RX constant) masks the TX length. Provably a no-op for
`n <= 2048` — the compiler elides it — but it should be renamed.

---

## 6. Measurement discipline — READ BEFORE QUOTING ANY NUMBER

The failure rate was estimated **five times** from live traffic (20% → 8.7% → 10% → 2%
→ 9%) and contradicted twice. That segment idles **45 s at a stretch**; each window held
only a few dozen frames.

**Use `[P8-txburst]`** (`gem::tx_burst_selftest`) — 200 back-to-back frames,
deterministic, traffic-independent. It caught a regression on its first execution.
**Use `[P8-txdiag]`** (`gem::tx_diag_burst`) to see hardware state, not just outcomes.

Both are wired into the P8 selftest. Frames are minimal broadcast, EtherType `0x88b5`
(IEEE 802.1 local experimental) — inert on the segment.

**⚠️ EXPERIMENT DESIGN FLAW TO AVOID:** the `NTX=2` runs are **confounded** — rotation
period 2 equals the alternation period 2, so slot-effects and frame-effects are
indistinguishable in that data. Use **`NTX=3` or `NTX=4`**.

---

## 7. Suggested next experiments (single-variable, designed — NOT fixes)

1. **`NTX=4`.** Breaks the period-2 confound. If failures still alternate per FRAME the
   cause is frame-sequential; if the pattern becomes period-4 it is slot-positional.
2. **`WRAP` set on EVERY descriptor** (deliberately non-standard). Tests the §2b
   correlation directly against the §2a contradiction. If all frames then succeed, WRAP
   presence is causal and §2a needs re-examination.
3. **Confirm whether "failed" frames reach the wire.** Capture on a peer host during the
   burst. This decides whether the defect is *transmission* or *completion reporting* —
   they demand different fixes, and §2c shows it varies by build.
4. **Ground the GEM contract in authoritative documentation** (Cadence GEM / RP1 TRM):
   `TSTART` semantics when the controller is parked, whether `TBQP` writes are honoured
   while `TE=1`, descriptor prefetch behaviour, and whether a one-entry ring is legal.
   Most wrong turns this session came from reasoning off recall rather than sources.

---

## 8. State of the tree — UNJUSTIFIED CHANGES PRESENT

`gem.rs` currently carries **`NTX=2`** and the **`TBQP` resync**. **Neither is supported by
evidence** — both were tested on metal and neither changed the 50%. Per the
smallest-correct-fix rule they should probably be **reverted** before further work, so the
baseline reflects proven state rather than accumulated attempts.

Worth KEEPING: the TSR read/clear (`TSR` was previously **declared and never read at all**
— a genuine bug), and both diagnostics.

---

## 9. What is NOT broken — do not chase these

* **Enforcement is unaffected.** `[P8] PASS — inline IPS: forward :53 / drop :4444` on
  every boot; `drop=0` across every real frame observed (372+ on one boot). A TX failure
  means a PASS frame was not forwarded — **never** that a threat passed, and **never**
  that a legitimate frame was dropped by policy.
* **RX is fine.** `faults=0` on every run; the isolated EL0 driver never crashed.
* **`W^X`, secure boot, attestation** PASS on all boots.
* `[P8-irq]` 0 IRQs is **DRV-1** (RP1 `MSIX_CFG_6` not firmware-preprogrammed; RX stays
  polled) — separate, known, unrelated.

---

## 10. Reproduce

```bash
export HEQK_KEYDIR=~/heqk-sign/keys
HOOKPROBE_DEBUG_ACCESS=1 builder/make-cm5-heqk-image.sh          # builds `prod`
# CM5 in rpiboot (nRPIBOOT jumper + power-cycle):
sudo kernel/heqk/cm5-boot/flash-clean.sh --no-dtb
# jumper out, power-cycle, read /dev/ttyUSB2 @115200 for [P8-txdiag] and [P8-txburst]
```

Boot logs, each named with its image hash, are in `~/heqk-metal-logs/`.
