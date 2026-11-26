# NanoPi M5 bench runbook: serial, power/reboot control, flashing, netboot

**Date:** 2026-11-26 · **Status:** prepared before the board arrives (mid-December 2026). Steps marked
**[day one]** must be confirmed on the real board before anything depends on them.
**Companions:** `heqk-nanopi-m5-hw-datapack-2026-11-26.md` (hardware facts) and
`heqk-nanopi-m5-rk3576-investigation-2026-11-26.md` (decisions).
**Tools:** `tools/diagnostics/m5-*.sh|py`, `tools/diagnostics/m5-netboot/`, `tools/build/m5-firmware-build.sh`.

## 1. Do we need relays?

**Yes. Use two channels, the same rig as the CM5 (Arduino Nano + `cm5-relay-nano` firmware, unchanged), as a second,
dedicated unit.** A third channel (RESET) is optional.

| Situation | Without relays | With POWER relay | With MASK relay |
|---|---|---|---|
| heqk/U-Boot alive, want reboot | PSCI SYSTEM_RESET / U-Boot `reset` / watchdog | same | — |
| heqk hung with no watchdog armed, or wedged in EL3/BL31 | **someone at the bench** | power-cycle (`m5-relay.py cycle`) | — |
| new image on every iteration | — | netboot: power-cycle → U-Boot TFTPs heqk (no flashing) | — |
| SPI-NOR loader update, U-Boot alive | U-Boot `sf update` from TFTP | — | — |
| SPI-NOR holds a loader that is *valid but broken* (boots, then hangs) | **someone at the bench** (hold MASK) | not enough: the ROM keeps booting the bad loader | maskrom → `m5-spi-flash.sh` |
| SPI-NOR empty/corrupt | ROM falls through FSPI → eMMC → **USB maskrom** by itself (strap config 4) | — | not needed |
| warm-reset tests (crash record survives reset, as on CM5) | — | (power-cycle loses DRAM) | 3rd channel on **TP9 RESET** |

Why not fewer: software reset covers the happy path only, and an unattended bench (`m5-metal-loop.sh` overnight) must
recover from a hang and from a bad loader without hands. Why not a smart plug on the PD charger: slow, mains-switched,
and it interrupts a USB-PD contract (see §3.1).

## 2. Parts list (beyond the board, NVMe and Wi-Fi in data pack §8)

| Item | Note |
|---|---|
| Arduino Nano v3 **with FT232RL or ATmega16U2** (unique USB serial) | a CH340 clone collides with the CM5 rig's Nano on `/dev/serial/by-id`; if CH340, use the by-port udev rule |
| 2-channel 5 V relay module (or 4-ch if TP9 RESET is wanted) | active-low default; `ACTIVE_LOW=0` build for active-high |
| 12 V / 3 A DC supply, 5.5×2.1 barrel + **barrel(female) → USB-C(male) DC cable** + a 5.5×2.1 pigtail with screw terminals | M5 accepts plain DC 6–20 V on USB-C (sch p16 "PD 9V/20V · DC 6V~20V") |
| 3.3 V USB-UART, ≥1.5 Mbaud: CP2102N / FT232RL / CH343 | not CP2102 (old) / PL2303 |
| USB-A ↔ USB-A cable (data + VBUS) | maskrom/rockusb on the OTG port; see the back-power check §5 |
| ~30 AWG wire-wrap wire, 2-pin 2.54 mm header | MASK switch pads; TP9 optional |
| Ethernet: a USB-GbE dongle (or spare NIC) on the host for the bench segment + 2 patch cables | netboot + `mc-e2e` on GMAC0; GMAC1 → test client |

## 3. Wiring

```
                 bench host
   ┌──────────────┬──────────────┬───────────────┬──────────────────┐
   │ USB          │ USB          │ USB           │ bench NIC        │
 CP2102N        Nano(M5)      A↔A cable      (dnsmasq DHCP+TFTP)
   │ 1.5 Mbaud    │ D2  D3       │                │
   │              │ │   │        │                │
 J1 GND/TX/RX   POWER MASK    top USB-A        GMAC0 (WAN)
 (debug UART)   relay relay   (OTG, DRD0)       ── NanoPi M5 ──  GMAC1 (LAN) → test client
                  │     └── NO across MASK switch (SARADC_VIN0_BOOT ↔ GND)
 12 V PSU ──(+)── NC ── barrel→USB-C ── M5 USB-C
```

### 3.1 Power (relay 1, NC)
- **+12 V of the bench supply through the relay's COM/NC**, then the barrel→USB-C cable into the M5. Idle relay or
  unplugged Nano = board powered (same fail-safe as the CM5 rig).
- Why plain DC, not the PD charger: cutting VBUS under a live PD contract leaves the source (charger) and the
  board's PD MCU (STM32G030 + FUSB302, sch p16) to renegotiate unpredictably. With plain DC the board just sees VBUS
  appear (6–20 V accepted). The 5 V system buck (SY8386, 8 A) runs from it.
- **Never plug a USB-C PD charger into the board at the same time.**
- No-solder alternative (if the barrel→USB-C cable is unavailable): 12 V into **TP8** (2-pad test point = VDD_USBC +
  GND, sch p16). That needs soldering a header and also puts 12 V on the USB-C VBUS pins, so leave the USB-C port empty.

### 3.2 MASK (relay 2, NO)
- Solder two thin wires to the **MASK tact switch** pads (SMD 3.3×4.5 mm). One side is `SARADC_VIN0_BOOT` via 100 Ω, the
  other side is GND (sch p19). They go to relay 2 COM/NO. Closing the contact = pressing MASK.
- Dry contact, so there is no level or ground-loop concern.
- The firmware auto-releases it after 60 s.
- **[day one]** Identify the pads with a meter: continuity to GND on one side, and the other side reads ~1.8 V idle
  (the ADC strap).

### 3.3 RESET (optional relay 3, NO)
- **TP9** is a 2-pad test point: `RESET_L` and GND, with a TVS (sch p19). Shorting it is a cold reset of the SoC
  without dropping power: DRAM and PMIC rails stay up.
- Needed only for warm-reset tests. The Nano firmware has two channels today. Adding D4 = RESET (pulse only, auto-release)
  is a small firmware change; do it when warm-reset tests start.

### 3.4 Serial console
- J1 (3-pin 2.54 mm, by the edge): pin 1 GND, pin 2 TX (board → host), pin 3 RX (host → board).
- The board's RX has a series Schottky + pull-up (sch p19), so a powered adapter cannot back-power the SoC through RX.
  Still: **never connect the adapter's VCC pin.**
- 1 500 000 8N1, no flow control. The BootROM, DDR blob, SPL, TF-A, U-Boot and heqk all print here.

### 3.5 USB OTG (maskrom / rockusb)
- The top USB-A socket is DRD0 (OTG) per the U-Boot list report. **[day one]** confirm: in maskrom, `lsusb` shows
  `2207:350e` only on that port.
- VBUS from the host is needed: the board detects device mode through `USB2_OTG0_VBUSDET`, a divider on the OTG VBUS rail
  (sch p19). So don't use a VBUS-cut cable.

### 3.6 Ethernet
- GMAC0 = WAN = netboot + `mc-e2e` uplink, on a **dedicated bench segment** (USB-GbE dongle on the host). dnsmasq answers
  only the M5's MAC there.
- GMAC1 = LAN → a test client (separation-matrix rows).
- The EUI-48 EEPROM is **not mounted** (sch p15), so MACs are derived from the OTP chip ID (U-Boot does this). heqk does the
  same (data pack §6).

## 4. Host setup (once)

1. `tools/build/m5-firmware-build.sh --pin`. This downloads U-Boot v2026.10, TF-A v2.15.0, rkbin DDR v1.13 + usbplug and
   rkdeveloptool, and writes their hashes to `tools/build/m5-firmware.sha256`. **Review that file** (compare the
   DDR blob hash with rkbin's published history), commit it, and from then on build without `--pin` (fail-closed on
   mismatch). Output: `~/heqk-m5-bench/fw/` (`u-boot-rockchip-spi.bin`, `u-boot-rockchip.bin`, `mkimage`,
   `rkdeveloptool`, `MANIFEST.txt`).
   *Not yet run: the agent was not allowed to self-pin third-party hashes. This is an operator step.*
2. udev: `tools/diagnostics/m5-netboot/99-hq-m5-bench.rules.example` → `/dev/hq-m5-console`, `/dev/hq-relay-m5`,
   Rockchip `2207:*` for `plugdev`. Then `export M5_CONSOLE=/dev/hq-m5-console M5_RELAY=/dev/hq-relay-m5`, and
   `M5_FORBID=<CM5 rig Nano path>` so the M5 tools can never drive the CM5 relays.
3. Relay Nano: `make -C tools/diagnostics/cm5-relay-nano flash PORT=<M5 Nano>` (same firmware), then
   `tools/diagnostics/m5-relay.py status` → `power=1 mask=0`. Paper-test the sequence first: `m5-relay.py --dry-run maskrom`.
4. Netboot: copy `m5-netboot/dnsmasq-m5.conf.example`, fill the bench interface, M5 GMAC0 MAC and home path.
   Compile the boot script:
   `~/heqk-m5-bench/fw/mkimage -A arm64 -T script -C none -n heqk-m5 -d tools/diagnostics/m5-netboot/boot.cmd ~/heqk-m5-bench/tftp/heqk-m5/boot.scr.uimg`.

## 5. Day one (board arrives): verify before trusting anything

Keep `m5-console.sh` running the whole time.

| # | Check | How | Why |
|---|---|---|---|
| 1 | **SPI-NOR populated** | stock Debian: `cat /proc/mtd` / `dmesg \| grep -i spi-nor` (expect a 16 MiB 1.8 V part on sfc1). Visually: U16 (8-pin) near the SoC | the schematic marks it "OPTIONAL". If absent, the plan switches to a UFS module for the first stage (BootROM UFS boot works) |
| 2 | Stock boot log | FriendlyElec Debian trixie core on microSD, switch **UFS/SD** | the reference log: DDR blob version, BL31, U-Boot, kernel. Compare with the RE findings (§9) |
| 3 | Hardware inventory | `lspci -vv` (NVMe Gen2 ×1 link), `cat /proc/iomem`, `cat /sys/firmware/devicetree/base/model`, `ip link` (MACs), `ethtool -i end0/end1`, `dmesg` (PHY id `0x001cc916`), `cat /proc/cpuinfo` + `dmesg \| grep -i arch_timer` (CNTFRQ 24 MHz) | the "passes QEMU, fails on metal" lesson: record truth first |
| 4 | Auto power-on | relay `cycle` with no button: does it boot? | if not, the power-on mode jumper/setting needs changing, or wire POWER (`PWRON_L`) to a relay |
| 5 | **No back-power** | relay `off` with the console + OTG cable attached: SYS LED fully off, `VCC5V0_SYS` ~0 V | a half-powered SoC defeats the power-cycle. If back-fed via OTG, connect the OTG cable only for recovery (or put it on a uhubctl-switchable hub port) |
| 6 | Maskrom by relay | `m5-relay.py maskrom` → `2207:350e`; `rkdeveloptool ld` → Maskrom | proves the recovery path before we depend on it |
| 7 | Watchdog really resets | stock Linux: `echo 1 > /dev/watchdog` then stop feeding → reboot within the timeout | the DW-WDT → global reset routing is unverified and A/B relies on it |
| 8 | Software maskrom | stock Linux: the reboot-to-loader/maskrom path from the RE findings (§9) | lets U-Boot/heqk enter recovery without the MASK relay |
| 9 | Our loader | `m5-spi-flash.sh` (maskrom path), switch to **FSPI**, power-cycle → mainline U-Boot banner; `bdinfo`, `fdt addr $fdtcontroladdr; fdt print /memory`, `pci enum; nvme scan`, `dhcp` | the chain from data pack §4 is live |

Keep the stock microSD: with the switch on UFS/SD it always brings back a known-good Linux.

## 6. Flashing paths (SPI-NOR first stage)

| Path | When | How |
|---|---|---|
| **A. U-Boot self-update** (normal) | U-Boot is alive | put `u-boot-rockchip-spi.bin` in the TFTP root, then on the console: `setenv autoload no; dhcp; tftpboot ${loadaddr} heqk-m5/u-boot-rockchip-spi.bin; sf probe; sf update ${loadaddr} 0 ${filesize}; reset` |
| **B. Maskrom** (recovery) | bad loader, empty SPI, first time | `tools/diagnostics/m5-spi-flash.sh` (relay MASK → `rkdeveloptool db usbplug_fspi1` → `wl 0` → read-back compare → `rd`); `--in-maskrom` if entered by hand; `--dry-run` to see the steps |
| C. microSD fallback | SPI path unavailable | switch **UFS/SD** + FriendlyElec's SD image (their loader carries the boost fix for BootROM SD boot) |

Never erase or rewrite the SPI-NOR from heqk itself until A/B is designed for it (the same guarded-write discipline as the
CM5 `flashstub`).

## 7. The development loop (no flashing per iteration)

```
m5-console.sh (always running) ──► ~/heqk-metal-logs/m5-*.log
m5-metal-loop.sh --image heqk-m5.img --log <that log>
   1. copies the image to ~/heqk-m5-bench/tftp/heqk-m5/heqk-m5.img
   2. m5-relay.py cycle
   3. U-Boot (SPI-NOR): DHCP from dnsmasq → boot.scr.uimg → tftpboot heqk-m5.img → booti (EL2, x0 = FDT)
   4. waits for --expect markers / --fail markers → PASS/FAIL report next to the log
```

**M5-0 contract** (first heqk milestone, default markers): `== booti` (U-Boot handed off), then heqk prints a banner
containing `heqk` and its entry `EL2`, takes RAM from the FDT `/memory` node, and toggles the SYS LED. Prerequisites in
heqk (data pack §9): a board-profile build (`rk3576` feature), a DW-APB console, link/load addresses above 0x4020_0000,
and an Image header whose `image_size` covers the payload.

## 8. Reboot control: who can reset what

| Mechanism | From | Effect | Status |
|---|---|---|---|
| PSCI `SYSTEM_RESET` (SMC) | heqk EL1/EL2, U-Boot `reset` | full SoC reset via TF-A | upstream TF-A implements it |
| PSCI `SYSTEM_OFF` | heqk | PMIC off (RK806 DEV_OFF). Comes back only via relay power-cycle or an RTC alarm (HYM8563 INT drives `PWRON_L`, sch p15) | **[day one]** |
| DW-WDT (0x2ace_0000) | hboot gate / heqk | reset on missed kicks; the A/B trial arbiter | **[day one]** check 7 |
| Reboot-to-maskrom (boot-mode magic) | U-Boot / heqk | next boot enters USB maskrom without MASK | **[day one]** check 8; register/magic per the RE findings |
| Relay POWER | host | cold power-cycle | rig |
| Relay MASK | host | forced maskrom | rig |
| TP9 RESET (optional) | host | SoC reset, power kept (warm) | 3rd channel |

## 9. Reverse-engineering inputs (vendor firmware, read for facts only)

FriendlyElec's official RK3576 images (mirror `downloads.friendlyelec.com/os-images/rk3576/images/`, SHA-256 checked
against their `.sha256` files): FriendlyWrt 25.12 (`297a71b7…`) and Debian trixie core (`77a6b8d9…`), both dated 2026-08-06.
They supply: vendor loader/blob versions, the U-Boot boot flow and environment, the partition map (`parameter.txt`),
the vendor DTB (`resource.img`), DT overlays, the kernel config, and the shipped Wi-Fi firmwares. Findings:
`heqk-nanopi-m5-vendor-firmware-findings-2026-11-26.md`. Vendor code is never copied (clean-room rule).

## 10. Safety rules for this bench

- Relays idle-safe: board powered, MASK released. The firmware auto-restores after 120 s off / 60 s MASK.
- `m5-*` tools refuse the CM5 console, the CM5 relay Nano (`M5_FORBID`) and the LTE modem, and never auto-detect a relay.
- dnsmasq only on the dedicated bench interface and only for the M5's MAC.
- **Never fuse OTP** (secure-boot key hash) on the bench unit. It is irreversible and RSA-2048-only (data pack §4).
- Wireless is receive-only on this bench as on CM5: no management-frame injection.
- No host IPs, hostnames or MACs in committed files. Fill them only in the local copies of the `.example` files.
