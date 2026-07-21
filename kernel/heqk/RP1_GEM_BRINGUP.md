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

## Open (research in flight)
- Exact Cadence register offsets (NCR/NCFGR/RBQP/RSR/ISR/SA1B/DCFGR) + bits.
- RX descriptor bit layout (own/wrap/SOF/EOF/length), DMA64 4-word variant.
- RP1-specific: is the GEM held in an RP1 reset that must be released? Any RP1
  SYSCFG register selecting RGMII mode? Whether firmware already enabled clocks.
