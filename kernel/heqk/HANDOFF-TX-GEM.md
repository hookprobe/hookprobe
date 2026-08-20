# HANDOFF — GEM TX failure on CM5 (open)

**Status:** 🔴 OPEN — **three fix attempts spent, all verified negative on metal.**
**Owner:** unassigned — pick this up with fresh eyes.

> **Read §3 before proposing anything.** An entire class of fix (halt-recovery ordering)
> is already excluded by measurement. The most valuable thing this note carries is what
> has been ruled OUT.
**Date:** 2026-08-20 · **Branch:** `worktree-heqk-premetal-gaps` · **Board:** CM5, zero-Linux boot partition.

---

## 1. The symptom, stated precisely

Under **back-to-back** transmission the GEM drops **exactly half** the frames:

```
[P8-txburst] MEASURED — 200 frames: 100 sent / 100 FAILED (50.0%), last_tsr=0x..
```

**100 of 200 is a PATTERN, not a rate.** Probabilistic loss does not land on precisely
half. Every *other* frame fails. Any proposed fix must explain the alternation, not just
reduce a percentage.

On sparse live traffic it hides: the running sensor reads ~2–4% because frames there are
far enough apart for the engine to settle between transmits. **Do not measure this against
live traffic** (see §5).

---

## 2. Root cause — PARTIALLY established. Read the caveat.

**Observed and certain:** `NTX = 1` (`gem.rs`, commented *"single-descriptor synchronous
TX (send-one, poll-complete)"*). With one descriptor carrying `TXD_WRAP`, the controller
finishes a frame, wraps straight back to that same descriptor, reads `USED=1`, and latches
**`TSR.UBR`** (Used Bit Read), which halts the transmitter. `txerr=0x01` on metal confirms
UBR really is being latched.

**⚠️ CAVEAT — do not treat the rest as settled.** The natural follow-on story is "the halt
costs one frame, hence alternation." **Three fixes built on that story all failed** (§3).
In particular v4 recovered *after the descriptor was already armed*, which on that story
should have avoided the per-frame cost entirely — and the number did not move at all.

So either the halt is **not** what costs the frame, or something else stalls the very next
transmit independently of the halt. **The UBR observation is solid; the causal chain from
UBR to the 50% is NOT.** That is precisely why the missed-`TSTART` hypothesis (§4.1) is
now ranked first: it explains the alternation *without* relying on the halt at all.

### Why depth alone does NOT fix it

`tx_frame` arms exactly **one** descriptor and then blocks until it completes. So the
controller always advances into an *unarmed* slot regardless of ring size — UBR fires at
`NTX=8` just as it does at `NTX=1`. **A deeper ring only helps together with pipelining**
(arm several, don't block), i.e. an asynchronous TX path. Do not expect `NTX = 8` on its
own to change the number.

*(An earlier note in this repo claimed depth was the fix. It is not, on its own. That
claim was wrong and is corrected here.)*

---

## 3. What has been tried — three metal runs, all measured

| Rev | Change | Burst result | Reading |
|---|---|---|---|
| **v1** `2c0b342` | `TSR` was DEFINED AND NEVER READ. Clear latched status before arming; recover (bounce `TE`) on timeout | live traffic **8.8% → 1.9%** | **Real fix, keep it.** The register was simply never serviced |
| **v2** `34122ea` | Also restart on the **success** path | **100/200, `tsr=0x08`** | **Wrong — reverted.** Re-enables `TE` while the descriptor still reads `USED=1`, so the engine instantly re-latches UBR and halts again before the next frame |
| **v3** `93dcbfd` | Revert v2 — clear only, restart solely on timeout | **100/200, `tsr=0x01`** | Correct handling but insufficient: the halt stands, the next frame's `TSTART` hits a dead engine, only its timeout recovers |
| **v4** `b25b971` | Move recovery to **after arming, before the kick** | **100/200, `tsr=0x08`** | **Verified NEGATIVE.** Arming first did not help either |

### ⛔ RULED OUT: halt-recovery policy, in any ordering

**THREE different recovery policies produced EXACTLY 100/200 each:**

| Policy | `last_tsr` |
|---|---|
| v2 — restart immediately after completion | `0x08` |
| v3 — never restart on the success path | `0x01` |
| v4 — restart after arming, before the kick | `0x08` |

Restarting early, late, and not at all all give the identical alternation. **Do not spend
another metal cycle on halt/restart ordering** — the fault is upstream of recovery. Only
the latched *status bit* changes with policy; the 50% does not move.

---

## 4. Where to go next, in order of expected value

1. **Missed / ignored `TSTART` under back-to-back kicks — TEST THIS FIRST.** It is the
   only hypothesis that explains alternation *independently of recovery policy*, and it is
   cheap. In the burst loop the next `TSTART` is written microseconds after the previous
   frame completed, while the controller may still be finishing internal work (descriptor
   writeback, the wrap read). If that `TSTART` is dropped, the frame never starts, the poll
   burns its full budget, and the *next* call succeeds because the engine has settled —
   exactly the observed alternation, and exactly why no recovery ordering changes it.
   - **Cheapest probe:** re-issue `TSTART` periodically *inside* the poll loop (say every
     ~10k spins) instead of kicking once. If a dropped kick is the cause, failures should
     collapse immediately. This is a handful of lines in `tx_frame` and needs one flash.
   - **Second probe:** insert a bounded settle delay between completion and the next kick
     and see whether the 50% moves. If a delay fixes it, it is a timing/kick problem, not
     a descriptor problem.
2. **Asynchronous multi-descriptor TX.** `NTX` → 8, `TXD_WRAP` on the last descriptor
   only, round-robin arming, and crucially **do not block per frame** — arm, return,
   reap completions lazily. This removes the drain-halt from the steady-state path
   entirely. It changes `tx_frame`'s contract (it currently returns `Some(status)` /
   `None` and the caller counts `fwd` vs `tx_fail` synchronously), so the sensor loop's
   accounting has to be reworked with it.
   - **Entanglement to watch:** `tx_prep_el0` hardcodes `desc[0]` and sets
     `TXD_USED | TXD_WRAP` (`gem.rs` ~line 846). With a multi-slot ring, `WRAP` belongs on
     `desc[NTX-1]` only.
   - **Note:** the EL0 stub at `syscall.s:192` writes `word1 = 0x8040` = `len|LAST` and
     does **not** set `WRAP`, despite the comment on line 183 claiming `len|LAST|WRAP`.
     That is a latent bug at `NTX=1` (the controller runs past the end of the ring) and
     becomes *correct* under a multi-slot ring. Fix the comment either way.
3. **Consider whether synchronous TX is the right contract at all.** Blocking the
   detection datapath on TX completion couples forwarding latency to the wire. Worth an
   ADR-level look before M2 hammers this path.

---

## 5. Measurement discipline — read this before quoting any number

The rate was estimated **five times** off live traffic during this session
(20% → 8.7% → 10% → 2% → 9%) and **contradicted twice**. The segment idles for **45
seconds at a stretch**, so each window held only a few dozen frames — far too few to
distinguish a real change from noise.

**Use `[P8-txburst]`** (`gem::tx_burst_selftest`, wired into the P8 selftest, `b777a32`).
200 back-to-back frames, deterministic, traffic-independent — and because back-to-back
*is* the saturating stimulus, the same test that measures the fix also exercises the bug.
It caught the v2 regression on its first execution.

Frames are minimal broadcast, EtherType `0x88b5` (IEEE 802.1 local experimental) — inert
on the segment.

**`txerr` legend** (heartbeat + burst `last_tsr`):

| Bit | Meaning |
|---|---|
| `0x01` | `UBR` Used Bit Read — **halts** the transmitter |
| `0x04` | `RLE` retry limit exceeded — halts |
| `0x10` | `TFC` frame corruption / buffers exhausted — halts |
| `0x40` | `UND` underrun — halts |
| `0x80` | `HRESP` not OK — halts |
| `0x08` alone | sentinel: timeout with a **completely clean** status register |

---

## 6. Reproduce

```bash
export HEQK_KEYDIR=~/heqk-sign/keys
HOOKPROBE_DEBUG_ACCESS=1 builder/make-cm5-heqk-image.sh          # builds `prod`
# CM5 in rpiboot (nRPIBOOT jumper + power-cycle):
sudo kernel/heqk/cm5-boot/flash-clean.sh --no-dtb
# jumper out, power-cycle, then read /dev/ttyUSB2 @115200 for [P8-txburst]
```

Prior boot logs, each named with its image hash, are in `~/heqk-metal-logs/`.

---

## 7. What is NOT broken (do not chase these)

- **Enforcement is unaffected.** `[P8] PASS — inline IPS: forward :53 / drop :4444` on
  every boot, and `drop=0` across every real frame seen (372+ on boot 3). A TX-completion
  failure means a PASS frame was **not forwarded** — it never means a threat got through,
  and never means a legitimate frame was dropped by policy.
- **RX is fine.** `faults=0` across every run; the isolated EL0 driver never crashed.
- **`W^X`, secure boot, attestation** all PASS on four consecutive boots.
- `[P8-irq]` 0 IRQs is **DRV-1** (RP1 `MSIX_CFG_6` not firmware-preprogrammed, RX stays
  polled) — a separate, known, unrelated item.
