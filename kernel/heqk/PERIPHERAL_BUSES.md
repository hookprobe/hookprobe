# P13 — RP1 peripheral buses (GPIO/pinmux, I²C, SPI, UART) — frozen design

Status: **DESIGNED, not yet implemented.** Researched against the RP1 datasheet and
the Linux RP1 drivers, validated against the working HEQK RP1 code.

## The single most important fact

HEQK's bare-metal RP1 window base is **`0x1C_0000_0000`**, not Linux's
`0x1F_0000_0000`. The firmware HEQK boots under (`pciex4_reset=0`) programs the
prefetchable 64-bit outbound window, which lands at `0x1c_..`. Every working HEQK
RP1 access already uses it (`uart.rs`, `gem.rs`, `boot_cm5.s`).

```
cpu_addr(periph) = 0x1C_0000_0000 + (rp1_addr - 0x4000_0000)
```
Verified against three independently-working blocks: uart0, io_bank0, eth.

## Key addresses (RP1 datasheet Table 2 + rp1.dtsi)

| Block | CPU addr |
|---|---|
| clocks_main | `0x1C_0001_8000` |
| uart0..5 | `0x1C_0003_0000` + n*0x4000 |
| spi0 | `0x1C_0005_0000` |
| i2c0 / i2c1 | `0x1C_0007_0000` / `0x1C_0007_4000` |
| io_bank0 / sys_rio0 / pads_bank0 | `0x1C_000D_0000` / `0x1C_000E_0000` / `0x1C_000F_0000` |

Atomic aliases (`+0x1000` XOR, `+0x2000` SET, `+0x3000` CLR) exist **only** for
io_bank/sys_rio/pads — *not* for spi/i2c/uart, which need plain RMW.

Banks: **bank0 = GPIO0-27 (the 40-pin header)**, bank1 = 28-33, bank2 = 34-53.
`CTRL = io_bank + idx*8 + 4`, `PAD = pads + 4 + idx*4`, FUNCSEL **5 = SYS_RIO**
(software GPIO), `0x1f` = NULL. Pad bit7 = OD (output disable), bit6 = IE.

I²C and SPI are Synopsys DW_apb_i2c / DW_apb_ssi, both clocked from `clk_sys`
(typically 200 MHz — but **derive it, never hard-code it**: `clk_sys_hz()` from the
PLL/divider registers, cross-checked by the RP1 frequency counter FC0).
`I2C COMP_TYPE` must read `0x44570140` — a free liveness probe with no bus traffic.

## The pin deny-list is the load-bearing safety property

```rust
pub const RESERVED: &[u8] = &[14, 15, 32, 37, 38, 39, 44];
```
- **14, 15** = UART0 console. Remuxing them makes the board go dark mid-boot with
  no way to tell why.
- **32** = ETH_RST_N. Remuxing/driving it low drops the GEM PHY into reset — i.e.
  kills the IDS datapath.
- 37 = eth PHY IRQ, 38/39 = i2c6 CSI/DSI, 44 = PWR LED.

Checked **before any MMIO write**, in every entry point. `mux_group` validates the
whole slice before applying, so a partial mux is impossible.

**The WiFi lines cannot be affected**: WL_ON and SDIO2 are BCM2712 `gio`/pinctrl at
`0x10_7D5x_xxxx`, a different block from RP1. Worth an explicit code comment.

## Capability model

Each RP1 bus block sits alone in a 4 KiB page (they are 16 KiB apart), so the
minimum grantable unit is *exactly one controller* — a sensor driver gets i2c1 and
nothing else.

**Pinmux and clocks are NEVER granted to EL0.** `io_bank0`/`pads_bank0` are single
pages holding *all 28 pins'* registers, so granting either would let a compromised
sensor driver kill the console or reset the PHY. Pinmux stays EL1; EL0 GPIO goes
through a narrow `SYS_GPIO_OP` syscall masked against the driver's pin set.
Hardware backstop: RIO bits are inert on pads not funcselled to 5.

## Test plan (`[P13] PASS`, no external hardware)

- **A** clk_sys derived vs FC0-measured (disagreement = WARN, never fatal).
- **B** GPIO23 drive-and-read-back loopback (the pad's own input buffer sees the
  output driver — passes with nothing attached), plus asserting the deny-list
  refuses GPIO14 and GPIO32.
- **C** i2c1 scan of 0x08..0x77. **Zero devices is a PASS** — the controller
  answering 112 NACKs correctly is the proof.
- **D** spi0 internal loopback via `CTRLR0.SRL`, with pads left at FUNCSEL=NULL so
  nothing appears on the header.
- **E** the gate: an isolated EL0 driver granted *only* the i2c1 page runs a real
  transaction. The transaction completing is the proof, not a device being present.

## Hard rules

Every wait bounded (`poll_until`), never a naked `while` — a clock-stretching I²C
slave must produce a timeout, not a wedge. Scan probes with a 1-byte **READ**,
never a write (an SMBus write-quick can latch a relay). **Strictly PIO, no DMA** —
the RP1 DMAC is a bus master and BCM2712 IOMMUs ignore requester IDs. One owner per
pin, tracked kernel-side. `wfence()` (dsb sy) before every read-back — PCIe posted
writes, per datasheet §3.3.1.1.
