# P10-BT — register-exact reference (from the working CM5 Linux oracle, 2026-07-24)

Gathered from the CM5 running hookprobe-edge Linux (10.200.0.6, BCM2712 D0), where
BT works (`hci0` present via serdev), plus the on-disk kernel source
(`pinctrl-bcm2712.c`, `8250_bcm7271.c`). This is the reference I should have read
before writing the first driver.

## The block

- `serial@7d50c000` (uarta), `compatible = "brcm,bcm7271-uart"`, `reg = 0x20`,
  `reg-shift = 2`, `reg-io-width = 4`, **`skip-init`**, `clock-frequency = 96 MHz`.
- Core is a **plain 16550** at reg-shift 2 (byte offsets 0x00..0x1c). Only the
  "uart" reg region exists on this DTB (no "dma" region), so the driver runs
  **PIO-only** — `brcmuart_arbitration` / DMA init do **not** apply.
- **No clock in the Linux clk framework, no genpd, no runtime PM**
  (`power/runtime_status = unsupported`). Its only DT supplier is the pinctrl.
  Treated as an always-on AON UART with a fixed 96 MHz clock.
- Attaches via **serdev** (DT `bluetooth` child, `compatible brcm,bcm43438-bt`) →
  `hci_uart` + `btbcm`. No userspace hciattach.

## Pins (THIS is what my first driver got wrong)

The UART pins are on the **main pinctrl `0x7d504100`** (alias gpio3), NOT the gio.
The `gio@7d508500` line-names (BT_RTS=22…BT_RXD=25) are a **different controller's
namespace** — I read those and muxed the wrong pins. Live pinmux on the working
system:

```
gpio24 -> 107d50c000.serial  function uart0   (RTS)
gpio25 -> 107d50c000.serial  function uart0   (CTS)
gpio26 -> 107d50c000.serial  function uart0   (TXD)
gpio27 -> 107d50c000.serial  function uart0   (RXD)
gpio29 -> 107d50c000.serial  function gpio     (BT_ON / shutdown-gpio, on the gio)
```

### Exact mux register writes (derived from pinctrl-bcm2712.c)

Encoding: `mux_bit = 0x8000 + mr*32 + mb*4`; `reg = (bit>>5)<<2`; `shift = bit&0x1f`;
4-bit field = fsel index. `uart0` is `funcs[3]` for pins 24-27 ⇒ **fsel = 4**.

`GPIO_REGS(24,2,0,5,6) (25,2,1,5,7) (26,2,2,5,8) (27,2,3,5,9)` ⇒ all in **mux reg
`0x08`**, shifts 0/4/8/12:

```
pinctrl 0x10_7D50_4100 + 0x08 : RMW  (val & ~0xFFFF) | 0x4444   // gpio24-27 = uart0
pinctrl 0x10_7D50_4100 + 0x14 : RMW  clear 2-bit fields @ sh 12/14/16/18 => 0 (bias-disable)
```

### BT_ON (unchanged, was correct)

gio `0x10_7D50_8500`, **gpio29** output high = BT core out of reset. (WL_ON = gpio28
in the same registers — RMW-preserve it.)

## UART params (were correct)

96 MHz / 16 / 115200 = **52** (DLL/DLM divisor); 96 MHz / 16 / 3_000_000 = **2**.
3 Mbaud after the vendor `0xFC18` update. reg-shift 2: DLL@0x00 DLM@0x04 (LCR.DLAB),
IER@0x04, FCR@0x08, LCR@0x0C, MCR@0x10, LSR@0x14, MSR@0x18, SCR@0x1C.

## The SError (still the open question)

Even with correct pins, the *register access* to 0x7d50c000 external-aborted under
HEQK and surfaced as a **deferred SError at the next EL0 entry**, killing the next
phase. Linux accesses this block fine; HEQK accesses `gio 0x7d508500` and
`pinctrl 0x7d504100` (same AON region) fine — only the UART faults. Leading theory:
the firmware gates the uarta clock and HEQK's boot (`os_check=0`, bare metal) leaves
it off. Not proven — the firmware is closed and `/dev/mem` is lockdown-blocked.

**Containment is mandatory regardless of the cause:** a BT fault must never poison
another phase. Fix with an **Error Synchronization Barrier (`esb`)** after the BT
probe so any pending external abort is taken at a known point inside the BT window,
plus keep the `p10bt` feature gate. Defensively also try `mailbox::set_clock_rate`
on the UART clock before first access.

## Firmware patch

`BCM-0bb4-0306.hcd` (54734 B, `brcm,bcm43438-bt`) staged at `cm5-boot/bt-fw/`
(gitignored). Optional for HCI Reset + LE scan.
