# HANDOFF — GEM TX failure on CM5 (open)

**Status:** 🔴 OPEN. **Owner:** unassigned — pick this up with fresh eyes.
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

## 2. Root cause (established, high confidence)

`NTX = 1` — `gem.rs`, literally commented *"single-descriptor synchronous TX
(send-one, poll-complete)"*.

With one descriptor carrying `TXD_WRAP`, the controller finishes a frame, wraps straight
back to that same descriptor, reads `USED=1`, latches **`TSR.UBR`** (Used Bit Read) and
**halts the transmitter**. This happens after *every single transmit*.

Recovery — whenever and however it happens — costs exactly one frame. Hence alternation.

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
| **v4** (this branch) | Move recovery to **after arming, before the kick** | ⬜ **UNVERIFIED** | Hypothesis: with the descriptor already armed (`USED=0`, real work present), re-enabling `TE` gives the controller something to find instead of an idle slot to re-halt on |

**Opposite policies (v2 restart-early, v3 never-restart) produced the identical 50%.**
That is the strongest single clue: the fault is not the recovery *policy* but the
*sequence position* at which recovery happens relative to arming.

---

## 4. Where to go next, in order of expected value

1. **Verify or kill v4.** Flash, read `[P8-txburst]`. `200/200` = solved. Still `100/200` =
   the ordering hypothesis is wrong too, and the halt/restart approach is a dead end —
   go to (2).
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
