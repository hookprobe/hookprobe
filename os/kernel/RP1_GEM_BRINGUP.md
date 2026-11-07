# RP1 GEM (end0) bring-up — ground truth + plan

Target: receive one real Ethernet frame on the CM5's RP1 Gigabit MAC, hand it to
the Packet Engine (`produce_raw` → `classify`) for a real IDS verdict on metal.
In-kernel first (move to an isolated EL0 driver server later).

## Ground truth (from this board's DTB, `bcm2712-rpi-cm5-cm5io.dtb`)

- **Controller**: `ethernet@100000`, compatible `raspberrypi,rp1-gem` + `cdns,macb`
  (Cadence GEM / MACB IP, RP1 variant).
- **Register base**: RP1 internal `0x40100000`, size **`0x4000`** (16 KiB).
  - CPU-physical (Linux): `0x1f00100000`
  - **Bare-metal window (ours, pciex4_reset=0): `0x1C00100000`** — same RP1→CPU
    remap as the UART (`0x1f00030000`↔`0x1c00030000`).
- **Clocks** (RP1 clock controller @ `0x1C00018000`, firmware-rated per DTB
  assigned-clock-rates): pclk/hclk = RP1 clk **#12** @200 MHz, tx_clk = clk **#16**
  @125 MHz (RGMII), tsu_clk = clk **#29** @50 MHz. Firmware sets rates; verify the
  ENABLE bit per clk.
- **PHY**: Broadcom, MDIO address **0**, `phy-mode = "rgmii-id"` (RGMII + internal
  delay). `eee-broken`, `brcm,powerdown-enable`.
- **PHY reset**: RP1 GPIO **32**, active-low, hold **5 ms** (`phy-reset-gpios`).
- **PHY IRQ**: RP1 GPIO **37** (pull-up input) — not needed for polled RX.
- RGMII data/clock lines are hardwired in RP1 (no GPIO pinmux for them; only the
  PHY reset/IRQ GPIOs matter to us).
- `local-mac-address` is zero in the DTB (firmware fills it live). For RX we can
  use broadcast-accept / promiscuous and not depend on the real MAC.

## Plan (polled RX, no IRQs first)

1. Map the GEM block at `0x1C00100000` (already in our Device window). Read a
   known register (e.g. the ID/Module ID) to confirm reachability on metal.
2. Enable the 3 RP1 GEM clocks (#12, #16, #29) at `0x1C00018000` if not already.
3. Deassert PHY reset: drive RP1 GPIO 32 low → wait 5 ms → high (active-low), via
   RP1 IO_BANK0 (same mechanism as the UART GPIO14/15 mux).
4. Cadence MACB init (registers/descriptor format from research): soft-reset,
   set NCFGR (MDC divider, accept-broadcast / copy-all-frames), build the RX
   buffer-descriptor ring in the Packet Engine frame pool (hw-owned, last=WRAP),
   write RBQP (64-bit — DMA64), set NCR RE|MPE.
5. Poll the first RX descriptor's ownership bit / RSR; on a received frame, read
   its length, hand `&frame[..len]` to `produce_raw` → `consume_one` → verdict.

## Cadence GEM register map (confirmed vs Linux macb.h, offsets from base)
- NCR `0x000`: RE=bit2, TE=bit3, MPE=bit4 → enable = `0x1C`. (No reset bit; NCR=0 quiesces.)
- NCFGR `0x004`: CAF=bit4 (promiscuous), NBC=bit5 (0=accept broadcast), DRFCS=bit17
  (strip FCS), GEM_CLK MDC divider = bits18-20.
- GEM_DMACFG `0x010`: ADDR64=bit30 (64-bit DMA), RXBS=bits16-23 (RX buf size /64B),
  FBLDO burst=bits0-4.
- RBQP `0x018` (ring base low), GEM_RBQPH `0x4D4` (ring base high).
- RSR `0x020`: REC=bit1 (frame received), BNA=bit0, OVR=bit2.
- ISR `0x024`, SA1B `0x098` / SA1T `0x09c` (MAC: write SA1B then SA1T to latch).
- RX descriptor (DMA64 = 4 words / 16 bytes): word0 addr[31:2]|USED(bit0: 0=HW-owned)|
  WRAP(bit1); word1 ctrl: FRMLEN=bits0-13, SOF=bit14, EOF=bit15; word2 addrh; word3 resvd.

## ★ CRITICAL — DMA address translation (from this board's DTB dma-ranges)
The GEM is a bus master behind the RP1 PCIe endpoint. Its DMA addresses are NOT
CPU-physical. Two-level translation resolved from the DTB:
- BCM2712 RC inbound: PCIe bus `0x10_00000000` → CPU phys `0x0`, size 64 GiB.
- RP1 internal DMA: 1:1 into that bus window.
- **⇒ GEM descriptor buffer/ring address = CPU-physical RAM address + `0x10_0000_0000`.**
Since that is >4 GB, **GEM_ADDR64 (DMACFG bit30) + 16-byte descriptors are MANDATORY**,
even with RX buffers in low RAM: addrh = `0x10`, addrl = the CPU-physical address.
RBQP/RBQPH get the same +64 GiB offset. Getting this wrong = silent memory
corruption; the DTB gave the exact constant.

## On-metal progress (P8 iterations)
- ✓ GEM reachable at 0x1C00100000 (NCFGR=0x540000, DMACFG=0x020704 read back).
- ✓ PHY reset works (ETH_RST_N = RP1 GPIO32 = bank1 idx4; **addresses must be the
  full 10-hex-digit form 0x1C_000D_4000 / 0E_4000 / 0F_4000** — a dropped digit
  gave all-zero GPIO reads). Route pad funcsel=5 (sys_rio), pad OD-clear, RIO
  OE+OUT via normal RMW. Pin goes high, reset released.
- ✓ PHY alive over MDIO at **addr 0**: ID 0x600d84a2 (Broadcom BCM54210).
- ✓ **PHY LINK UP**: BMSR(reg1)=0x796d bit2=1, autoneg complete, gigabit partner.
  Cable is on the correct end0 port (the RJ45 nearest the USB-C).
- ✓ **RGMII/gigabit FIXED** (gigabit mode + rgmii-id delays + eth_cfg override):
  auxstat speed_code=7 (1000/full), gigabit=true, and **RSR went 0 → 0x1 → 0x5**
  (BNA + OVR). The MAC now RECEIVES frames — they reach the DMA engine.
- ✗ **NEW BLOCKER (predicted): DMA can't land frames — RSR.BNA (buffer not
  available) + OVR (overrun).** The BCM2712 PCIe RC2 (RP1's, pcie@1000120000 →
  0x1000120000) INBOUND window/ATU that maps PCIe bus 0x10_00000000 → system
  RAM 0x0 is NOT programmed. Firmware sets the OUTBOUND window (MMIO/UART work)
  but not inbound (RP1→RAM DMA), so the GEM's descriptor/buffer DMA fails → BNA.
  FIX: program the brcmstb RC2 inbound BAR (PCIE_MISC_RC_BAR*) for the 64 GiB
  dma-range. RC2 is already link-trained by firmware (pciex4_reset=0) — only the
  inbound window is missing, not the full link bring-up.

## MDIO helpers implemented (arch/gem.rs)
phy_read/phy_write via GEM MAN (0x034) + NSR IDLE poll; NCR.MPE + NCFGR MDC/128.
diagnose()/gpio_dump()/phy_link() give PHY ID, GPIO regs, BMCR/BMSR/ANLPAR.

## Metal validation (2026-07-21) — descriptor-length quirk #1 REMAINS OPEN
Consolidated audit image booted clean on metal. Results:
- ✓ Secure boot (ed25519 AND SLH-DSA), measured boot (4 events, PCRs reproduce),
  attestation quote — all on metal. [P7a] MMU PASS, [P7b] preemptive scheduler PASS.
- ✓ [P8] datapath: 3 real frames (incl. IPv6 `et=86dd` MLD to 33:33:.. and ARP
  `et=0806`) → parser → BPF verdict PASS on the microkernel. RSR=0x2 (REC, no
  BNA/OVR — inbound window holds).
- ✓ [P8] **#2 IPS DROP demo CONFIRMED on metal**: injected UDP→:4444 → `DROP
  (threat blocked!)`, alongside PASS on live traffic.
- ✓ New IPv6 parser path exercised on metal (the `et=86dd` frame PASSes correctly
  — MLD, no L4 port).
- ✗ **#1 NOT resolved.** Every RX descriptor still reads `w1=0x00000000` (the
  status/length word) even with the poll-until-non-zero loop, on SINGLE frames
  polled sequentially. This **disproves the PCIe-write-ordering hypothesis**
  (commit dff93d6) — and rules out the cache-line false-sharing theory too (that
  needs concurrent neighbor writes; here it's one frame at a time). `w2=0x10`
  (addr-hi) reads correctly, so descriptor offsets are right; the GEM simply is
  not writing the length/SOF/EOF word in this RP1 config. Datapath is fully
  functional via the whole-buffer copy + parser self-bounding (IP total_len), so
  this is a metadata gap, not a data gap.
  - Consequence: the 100k-spin w1 poll in `poll_rx` is now dead latency (spins,
    then falls back to copy_n). REMOVE/replace it in the next descriptor-ring
    rework (folds into the K1 block-splitting pass that also moves the ring to
    non-cacheable memory). Not worth a standalone flash (connector wear).
  - Next root-cause suspects to check: DMACFG=0x00020704 — verify ADDR64 (bit30)
    and RX buffer-size (RXBS) fields; whether RP1 GEM needs GEM-specific RX
    descriptor writeback enabled; whether length lives in a GEM RXUBR/queue
    status reg rather than the descriptor on this IP revision.

## #1 (w1=0) — CLOSED as a documented RP1 GEM quirk (2026-07-21)
After a diagnostic boot pinned the exact behavior (word0 = correct buffer addr +
HW-set USED; word2 = 0x10 addr-hi; **word1 = 0 in DRAM**, on the FIRST-USE,
correctly-aligned descriptor that no recycle ever touched), FOUR independent
theories were tried on metal and NONE populated word1:
1. PCIe write-ordering re-read poll — no effect.
2. DMACFG RXBMS|TXPBMS full-store-and-forward (0x40200710, confirmed applied) — w1 still 0.
3. RX recycle write-discipline (clear USED only, never rewrite word1; invalidate the
   shared 64B line before cleaning to avoid the B-4 false-sharing clobber) — w1 still 0
   (and it can't explain a first-use descriptor anyway).
4. DMACFG RX/TX extended-BD mode bit28|29 (0x70200710, confirmed applied) — w1 STILL 0
   on the aligned descriptor, AND it widened the descriptor with PTP timestamp words,
   corrupting the 16-byte-stride ring (stray w0=0x00000001; frames 3→2). Reverted.

Conclusion: on this RP1 GEM_GXL the RX descriptor **status/length word (word1) is not
written** in our polled 16-byte-DMA64 config, regardless of the DMACFG/NCFGR bits above.
The datapath is UNAFFECTED: frames are received intact, the parser self-bounds the
length via the IPv4/IPv6 header (`total_len`/`payload_len`), and the IDS/IPS verdict +
the `:4444` DROP work on metal. `poll_rx` copies the whole buffer when `desc_len==0`.
Kept: DMACFG=0x40200710 (clean 3-frame datapath) + the recycle write-discipline
hardening. Deferred: exact hardware length is a metadata-only gap; revisit under the
K1 non-cacheable-descriptor rework if it ever matters (it does not for correctness).

## #1 (w1=0) — ACTUALLY FIXED (2026-07-21), via the Linux oracle
Earlier "closed as a quirk" was WRONG. Booting the mainline `macb` driver
(hookprobe-edge 6.12.94, extracted from ~/hookprobe-os and run on THIS CM5)
proved w1 IS writable here: end0 obtained a DHCP lease (10.200.0.6) with
rx_length_errors=0. Reading the exact kernel source + iterating on metal gave the
COMPLETE recipe (all four required, matching mainline macb exactly):

1. **DMACFG = 0x70200710** — ADDR64(30) | RXEXT(28) | TXEXT(29) | RXBMS(9:8=3) |
   TXPBMS(10) | RXBS(2048/64) | FBLDO(16). RXEXT/TXEXT put the GEM in extended-BD
   mode (this PTP-capable GEM registers a gem-ptp-timer, so macb uses it).
2. **6-word (24-byte) descriptors** — {addr_lo, ctrl} + {addr_hi, resvd} + {ts_1,
   ts_2}. Extended-BD widens the descriptor; the ring stride MUST match.
3. **Non-cacheable descriptor ring** — matches macb's dma_alloc_coherent. HEQK maps
   a Normal-NC alias (mmu_cm5 GB257, MAIR attr2=0x44) and touches descriptors ONLY
   through it, so the GEM's status writeback is coherent (no cache-clean clobber).
4. **NCFGR DBW128 (bits22:21=2)** — the RP1 GEM is a 128-bit AXI4 master;
   macb_init_hw() sets it from DCFG1. THE final key: DBW=0 (32-bit) let the narrow
   16-byte ring work but broke the WIDE extended descriptor DMA (1 frame, w1=0).
   With DBW128: NCFGR=0x00580412.

VERIFIED ON METAL: `w1=0x0000c072` on a 114B frame = EOF|SOF|len(114) — exact
match; also 218/64/94. **3 frames RX'd**, real per-frame lengths, no fallback.
**P7a inline IPS enforcement live**: benign UDP->:53 FORWARDED on the wire
(tx_ctrl=0xc000802a, HW USED set), threat UDP->:4444 DROPPED (not forwarded).

Credit: the user's insistence on booting Linux to OBSERVE (not guess) is what
turned a 5th failed guess into the exact fix. The 16-byte "cosmetic quirk"
framing was a dead end; DBW + extended-BD + NC descriptors is the real answer.
