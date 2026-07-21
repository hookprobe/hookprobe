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

## Open (RP1 integration research in flight)
- Whether firmware already enabled the GEM clocks (#12/16/29) or bare-metal must.
- RP1 reset for the GEM (a SYSCFG/reset bit to deassert)?
- RGMII mode-select glue in an RP1 SYSCFG register?
- Broadcom PHY: does it link on its own after reset-deassert, or need MDIO setup?
