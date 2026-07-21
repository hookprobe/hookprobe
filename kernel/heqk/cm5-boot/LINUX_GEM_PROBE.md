# Reverse-engineering the RP1 GEM RX descriptor under Linux (the "w1=0" oracle)

Goal: on THIS CM5 silicon, observe how the working mainline `macb`/`rp1-gem`
driver gets the RX frame length — does its descriptor **word1** come back non-zero
(⇒ HEQK is missing an init step, #1 is fixable) or does Linux read the length from
elsewhere (⇒ genuine RP1 quirk, and we learn what to read).

HEQK's live values to diff against (from the diagnostic boot):
- GEM base (bare-metal window) `0x1C00100000`  ↔  Linux CPU-phys `0x1f00100000`
- DMACFG (off 0x010) = **0x40200710**   NCFGR (off 0x004) = **0x00180412**
- RX descriptor: w0 = addr+USED (HW-written OK), w1 = **0x00000000** (the bug), w2 = 0x10 addr-hi

Run everything below as root under Linux on the CM5 (serial console or SSH).

## 1. Identity + health (confirm the working driver + link)
```
ethtool -i end0            # expect driver: macb
dmesg | grep -iE 'macb|rp1|ether|gem' | head -40
ip -s link show end0       # RX packets/bytes counting up = Linux gets lengths fine
ethtool -S end0 | head -40 # per-queue rx stats
```

## 2. Live GEM register config — THE key diff (does Linux program DMACFG/NCFGR differently?)
`ethtool -d` dumps the MAC registers the driver actually programmed:
```
ethtool -d end0 raw off | sed -n '1,80p'
```
If your build has raw devmem (busybox/`devmem2`), read them directly (RP1 GEM @ 0x1f00100000).
NOTE: CONFIG_STRICT_DEVMEM may block /dev/mem for these — if so, use `ethtool -d`.
```
# DMACFG (0x010) — compare to HEQK 0x40200710
busybox devmem 0x1f00100010 32       ;  # or: devmem2 0x1f00100010 w
# NCFGR (0x004) — compare to HEQK 0x00180412
busybox devmem 0x1f00100004 32
# NCR (0x000), RSR (0x020)
busybox devmem 0x1f00100000 32 ; busybox devmem 0x1f00100020 32
# RP1 eth_cfg wrapper @ 0x1f00104000: CONTROL(0x00) STATUS(0x04) CLKGEN(0x14)
busybox devmem 0x1f00104000 32 ; busybox devmem 0x1f00104004 32 ; busybox devmem 0x1f00104014 32
```
⇒ If Linux's DMACFG/NCFGR **differ** from HEQK's, that delta is almost certainly the fix.
⇒ If they **match**, the difference is descriptor-memory coherency: Linux uses
   `dma_alloc_coherent` (non-cacheable/coherent) descriptors, which would re-open the
   non-cacheable-ring path for HEQK (K1) — and refute the "DRAM held 0" reasoning.

## 3. The actual RX descriptor word1 under Linux (the decisive observation)
Trace `gem_rx` and dump the descriptor ctrl (word1) + reported length. Needs
bpftrace + kernel BTF/kallsyms. `bp->rx_frm_len_mask` is 0x3fff on RP1 (JUMBO caps).
```
# Does macb read a NON-ZERO length from the descriptor ctrl word?
bpftrace -e 'kprobe:gem_rx { @in[tid]=1 } kretprobe:gem_rx /@in[tid]/ { printf("gem_rx ret=%d\n", retval); delete(@in[tid]); }'
# If gem_rx isn't kprobe-able, trace the length at skb build:
bpftrace -e 'kprobe:macb_rx_frame { printf("macb_rx_frame len arg\n"); }'  # inspect args in bpftrace -lv
funcgraph / trace-cmd alternative:
  trace-cmd record -p function_graph -g gem_rx -- sleep 2 ; trace-cmd report | head
```
Simplest logical proof if bpftrace is unavailable: Linux `ip -s link` RX bytes are
correct → macb (which reads length from word1) is getting a non-zero word1 → word1
CAN be populated on this HW → HEQK is missing something (config in §2, or coherent
descriptor memory).

## 4. Restore HEQK afterwards
```
sudo cm5-boot/restore-linux.sh   # (to GET here: swaps config back to Linux; run in rpiboot)
# ... do the probing ...
sudo cm5-boot/flash-now.sh       # back to HEQK (rpiboot)
```

## Decision
- DMACFG/NCFGR differ  → implement the missing bit in `gem::rx_init`, re-open #1.
- Regs match, word1 non-zero under Linux → it's descriptor-memory coherency: give
  HEQK a non-cacheable descriptor ring (K1) and re-read word1.
- word1 zero under Linux too, length from elsewhere → genuine RP1 quirk, PROVEN;
  document what Linux reads instead and mirror it.
