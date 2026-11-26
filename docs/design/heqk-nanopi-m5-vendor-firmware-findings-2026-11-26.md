# NanoPi M5 (RK3576): what FriendlyElec's firmware tells us (interop facts only, clean-room)

Inputs: `dl/friendlywrt25-images-20280806.tgz` (called **WRT** below) and `dl/debian-trixie-core-arm64-images-20280806.tgz` (called **DEB**).
Source: FriendlyElec's mirror `downloads.friendlyelec.com/os-images/rk3576/images/` (dated 2026-08-06), SHA-256 checked
against their `.sha256` files (WRT `297a71b7…`, DEB `77a6b8d9…`). The artifacts and extraction scripts stay on the bench
host (scratch, not committed). All Python ran with `python3 -I`, and nothing from the downloads was executed. Vendor code is
read for facts only, never copied (clean-room rule).
Notation: **[V]** means verified from bytes or a decode. **[I]** means inferred or unverified.

## What this changes for heqk (summary)

| Finding | Consequence |
|---|---|
| Vendor chain: DDR v1.13 + boost (SD/UFS fix) + SPL v1.09 + **rkbin BL31 v1.24** (TF-A v2.3 fork, 2025-12-26) + OP-TEE 3.13 (bl32 v1.10) + U-Boot 2017.09. Header word at 0x60 = 0x100, consistent with the **1 GHz hptimer** boot1 parameter | Our chain (mainline U-Boot + upstream TF-A, 24 MHz) must **not reuse any vendor piece**: pairing timer rates is the documented failure. heqk always reads CNTFRQ. The day-one stock log shows CNTFRQ under the vendor chain, so record it |
| Vendor SPL tries **SD first**, then UFS, then SPI-NOR (with the boost stub) | The stock SD card is a reliable recovery path (runbook §6 C) |
| **Reboot-to-maskrom: write `0xEF08A53C` to PMU0_GRF+0x40 = `0x2602_4040`, then reset** (vendor U-Boot code, [V]); reboot-mode values `0x5242C3xx` (normal 00, loader 01, recovery 03, panic 07, watchdog 08, fastboot 09) | heqk/hboot get software recovery entry without the MASK relay (runbook §8). Record panic/watchdog reasons in the same register, compatible with the vendor convention |
| **ramoops at `0x4011_0000`, 0xE0000 bytes** (inside the firmware-reserved first 2 MiB) | candidate home for heqk's crash record (CM5 `crashrec` equivalent), which survives warm reset. Confirm BL31 does not use it under *upstream* TF-A before adopting |
| GMAC: vendor `rgmii-rxid` + MAC tx_delay 0x21/0x20; mainline `rgmii-id` (both delays in the PHY) | both work. heqk follows mainline (PHY delays, MAC delays off): fewer SoC GRF writes. Vendor values are the fallback if TX fails at 1 Gb/s |
| PCIe0: PERST GPIO2_B4, 3.3 V enable **GPIO0_D3**, card-present **GPIO4_C4**, 1000 ms link wait; combphy0 also claimed by sata0 | heqk checks PRSNT before link training. A generous link timeout matches the ROCK 4D lesson |
| LEDs: sys **GPIO2_B3**, lan GPIO2_B0, wan GPIO4_C5; user key GPIO1_A0 | the M5-0 "blink SYS LED" target |
| Fan: PWM0 ch1 on GPIO0_C3, steps 0/45/70/110/160/255 at 50/55/60/65/70 °C; HW shutdown 120 °C, critical 115 °C | heqk thermal policy defaults (the CM5 WFE/thermal lesson) |
| FriendlyElec ships firmware for **BCM43455/43456 SDIO** (AP6255/AP6256 class) as well as RTL8822CS, AIC8800, AX200/AX210, MT7921/22, and **no BE200 firmware** | supports the Radxa A2 (BCM43456) choice. The BE200 is not a FriendlyElec-supported radio on this board |
| Vendor E-key: RTL8822CS on the vendor out-of-tree driver (rtw88 SDIO blacklisted) | another reason not to use the default AC200 module with heqk |
| Vendor DDR blob = rkbin `rk3576_ddr_lp4_2112MHz_lp5_2736MHz_v1.13.bin` (build e10b4dfeaf) with **2 bytes patched: LPDDR4/4X frequency 2112 → 1866 MHz** (u16 LE at 0x11C7C, 0x0840 → 0x074A) [V by `cmp`] | our pinned blob is the vendor's blob; derate LP4X to 1866 MHz with `ddrbin_tool` if the 4 GB board is used. LPDDR5 is unchanged |

## 0. Which files differ between the two images (sha256)
- These are byte-identical in WRT and DEB: `idbloader.img`, `boot.img`, `dtbo.img`, `misc.img`, and the M5 DTB inside resource.img.
- `MiniLoaderAll.bin` differs by 9 bytes, all in the header build timestamp (`cmp -l`). **[V]**
- `uboot.img` differs. WRT U-Boot is `2017.09-gc5c053fa55-250917-dirty #tzs (Aug 06 2026)`. DEB U-Boot is `2017.09-gc5c053fa557-250917 #fa (Jul 10 2026)`. The BL31 and OP-TEE version strings are the same in both, but the binary hashes differ. **[V]**

## 1. Loader chain

### MiniLoaderAll.bin (rkboot "LDR " container)
Parsed with `re-scripts/ldr.py`. Header fields: tag `LDR `, hdr 0x66, ver 0x164, merger 0x01000000, release time 2026-08-06 18:25:37, chip `3576`, signFlag 0, rc4Flag 1. **[V]**

| group | name | offset | size |
|---|---|---|---|
| 471 | UsbHead | 0x1f5 | 0x800 |
| 471 | **rk3576_ddr_lp4_1866M** | 0x9f5 | 0x13800 (79872) |
| 472 | **nanopi_m5_usbplug** | 0x141f5 | 0x53800 (342016) |
| loader | FlashHead | 0x679f5 | 0x1000 |
| loader | FlashBoost | 0x689f5 | 0x1000 |
| loader | FlashData (DDR) | 0x699f5 | 0x14000 |
| loader | FlashBoot (SPL) | 0x7d9f5 | 0x4f000 |

- The 4 loader entries are RC4-scrambled in 512-byte chunks with the well-known Rockchip key. After descrambling, their concatenation equals `idbloader.img` byte for byte (`re-scripts/rc4chk.py` prints `== idbloader: True`). **[V]**
- The 471 DDR blob equals the first 79872 bytes of the idbloader DDR image (`cmp -n`). The idbloader copy is only zero-padded to 80 KiB. **[V]**
- usbplug: `USB-PLUG 2017.09-g6af4274395d-250917 #fa (May 19 2026 - 14:04:46 +0800)`. It is a rockusb U-Boot. **[V]**

### idbloader.img (RKNS v2 header, 413696 B)
Parsed with `re-scripts/rkns.py`. Header word `size_and_nimage` = 0x00030180, which decodes to 3 images and a 384 B header. `boot_flag` = 1 (SHA-256 per-image hash) **[I]** for the meaning of the value.

| img | file offset | size | load addr | sha256 matches header |
|---|---|---|---|---|
| 0 boost | 0x1000 | 0x1000 | 0x3ffc0000 (SRAM) | yes |
| 1 DDR init | 0x2000 | 0x14000 | 0x3ff81000 (SRAM) | yes |
| 2 SPL | 0x16000 | 0x4f000 | 0xffffffff (DRAM default) | yes |

- Header hash at 0x600 is SHA-256 of `hdr[0:0x600]` (`re-scripts/hdrhash.py`). **[V]**
- There is no RSA signature in the header, so the chain is unsigned and hash-only. **[V]**
- **Non-zero reserved word at header offset 0x60 = `0x00000100`.** It appears in the flash idblock header and in the UsbHead (471). **[V]**
  - This is consistent with BOOT1_PARAM `WORD_2=0x100` (the 1 GHz hptimer setting) if boot_merger writes WORD_0..n starting at 0x58. **[I]** That field mapping is not proven from the bytes.
  - The DDR blob has a 32-byte runtime `.bss` symbol `boot1_parm` at 0x3ff96c30 (from the embedded ELF symbol table, `re-scripts/ddrsyms.py`). U-Boot prints a `[boot1 param]: param[%d]` ATAG block (uboot.bin, file offset 0x105303). So the parameter flows DDR → ATAG → U-Boot/BL31. **[V]** for the strings, **[I]** for the flow.
  - **Recommendation:** a mainline-built idbloader for this board should reproduce `hdr[0x60]=0x100`. Do not mix this vendor DDR blob with a BL31 that assumes a different hptimer rate.
- **Boost stub:** strings `Boot0:%s %s, ver: %s` / `1.03` / `Jan 24 2025 09:13:56`, plus UFS power-mode strings (`ufs set pwr mode fail`, `HCS.UPMCRS`). It is a SRAM pre-stage that brings the UFS link up for the BootROM. **[V]** strings, **[I]** purpose.
- **DDR blob:** `DDR e10b4dfeaf wesley.yao 26/04/29-09:42:15,fwver: v1.13` and `ddr-v1.13-e10b4dfeaf`.
  - Supported types (strings): LPDDR2/3/4/4X/5/5X.
  - The entry is named `rk3576_ddr_lp4_1866M`, so LP4 runs at 1866 MHz.
  - Parameter block magic `0x12345678` is at blob offset 0x11be8, with u16/u32 fields after it. It includes `0x0016e360` = 1500000 baud at 0x11c28. **[V]** The other fields are not decoded. **[I]**
- **SPL:** `U-Boot SPL 2017.09-g6af4274395d-250917 #fa (May 19 2026 - 14:04:48), fwver: v1.09`.
  - Embedded DTB at 0x4d1b8 is saved as `idb-wrt/spl.dts`.
  - `u-boot,spl-boot-order = "/mmc@2a310000" (SD), "same-as-spl", "/ufs@2a2d0000", "/spi@2a300000/flash@0"` (FSPI1 NOR). **[V]**
  - stdout is the UART at 0x2ad40000.
  - SPL DT: SFC1 NOR at 80 MHz, quad rx. eMMC node 0x2a330000 is `okay` (HS400ES). UFS reset/refclk come from the kernel DT. **[V]**

### uboot.img (4 MiB = 2 identical 2 MiB copies, FIT)
Decompiled to `uboot-fit.its`. Images extracted to `fit-wrt/` and `fit-deb/` with `re-scripts/fitx.py`; all FIT sha256 values match. FIT timestamp 2026-08-06 10:25:37 UTC (WRT).

| image | load | size | version |
|---|---|---|---|
| uboot | 0x40200000 | 0x156dd8 | U-Boot 2017.09 (above) |
| atf-1 (BL31, entry/firmware) | 0x40060000 | 0x1e020 | `bl31-v1.24`, `v2.3():v2.3-963-g1430f6b09:<builder>, fwver: v1.24`, `Built : 17:53:59, Dec 26 2025`. GICv2 driver, SCMI, hptimer, DDR DFS |
| atf-2 | 0x400f0000 | 0x5000 | Thumb code, probably an MCU/M-core image **[I]** |
| atf-3 | 0x3fe70000 | 0x4000 | PMU-SRAM suspend code (`pmu_int_st`, `gpio0_st`, `pwm_key`) **[I]** |
| optee (BL32) | 0x48400000 | 0x6d968 | `OP-TEE 3.13.0-1058-g14421695d-dev ... Mar 12 2026, fwver: v1.10`, `bl32-v1.10` |
| fdt | n/a | 0x26c3 | U-Boot control DTB, saved as `fit-wrt/uboot-dtb.dts` |

- Configuration `conf`: firmware=atf-1, loadables=uboot, atf-2, atf-3, optee. A `signature` node exists (sha256,rsa2048, key-name-hint "dev") but it has **no `value`**, so the FIT is unsigned. **[V]**
- **Exception level:** U-Boot contains EL2 context setup (`msr vbar_el2/hcr_el2/sctlr_el2` at 0x40200e98..) and no `spsr_el2` writes, so there is no EL2→EL1 drop. Conclusion: U-Boot runs at EL2 and hands the kernel over at EL2. **[I], strong evidence**
- **Default environment** (uboot.bin offset ~1060213):
  - `bootcmd=boot_fit;boot_android ${devtype} ${devnum};bootrkp;run distro_bootcmd;`
  - `bootdelay=1`, `baudrate=1500000`
  - `kernel_addr_r=0x40400000`, `kernel_addr_c=0x45480000`, `fdt_addr_r=0x48300000`, `ramdisk_addr_r=0x4a200000`, `scriptaddr=0x40500000`, `pxefile_addr_r=0x40600000`
  - `boot_targets=mmc1 mmc0 mtd2 mtd1 mtd0 usb0 pxe dhcp`, plus distro extlinux/boot.scr support
  - `rkimg_bootdev` probes SD (mmc 1), then mmc 0, then spinor
  - There is no `fdtfile`. The kernel DTB is chosen from resource.img by name `rk3576-nanopi5-rev%02x.dtb` (string at uboot.bin offset 0x114f77). **[V]**
  - Board name: `board=nanopi_m5`.
- **U-Boot control DTB** (`fit-wrt/uboot-dtb.dts`):
  - aliases `mmc0=/mmc@2a330000` (eMMC), `mmc1=/mmc@2a310000` (SD), `spi6=/spi@2a300000` (SFC1)
  - SCMI over SMC 0x82000010 with shmem at 0x4010f000
  - `adc-keys` on SARADC ch1, used as the recovery/rockusb key: keyup 1.8 V, press < 1750 µV (`volume up`, code 0x73)

## 2. parameter.txt (the same layout is used for SD and UFS; GPT; unit = 512 B sectors)
Header fields: `FIRMWARE_VER: 14.0`, `MACHINE_MODEL: RK3576`, `MACHINE_ID: 007`, `MACHINE: NanoPi5`, `MAGIC 0x5041524B`, `ATAG: 0x00200800`, `CHECK_MASK 0x80`, `PWR_HLD: 0,0,A,0,1`, `TYPE: GPT`. There are **no `uuid:` lines**.

| # | name | start (sectors) | size (sectors) | start / size |
|---|---|---|---|---|
| p1 | uboot | 0x4000 | 0x2000 | 8 MiB / 4 MiB |
| p2 | misc | 0x6000 | 0x2000 | 12 MiB / 4 MiB |
| p3 | dtbo | 0x8000 | 0x2000 | 16 MiB / 4 MiB |
| p4 | resource | 0xa000 | 0x8000 | 20 MiB / 16 MiB |
| p5 | kernel | 0x12000 | 0x14000 | 36 MiB / 40 MiB |
| p6 | boot (ramdisk) | 0x26000 | 0x10000 | 76 MiB / 32 MiB |
| p7 | recovery | 0x36000 | 0x10000 | 108 MiB / 32 MiB |
| p8 | rootfs | 0x46000 | WRT 0x280000 (1.25 GiB), DEB 0x400000 (2 GiB) | 140 MiB / see size column |
| p9 | userdata | WRT 0x2c6000 (0x300000), DEB 0x446000 (grow) | | |
| p10 | opt (WRT only) | 0x5c6000 | grow | |

- idbloader is not in the table. The usual Rockchip location is sector 64 (0x40). **[I]**
- The p8/p9 numbering matches the dtbo bootargs (`root=...p8 data=...p9`). **[V]**

## 3. resource.img (RSCE, 38 entries, SHA-1 per entry)
Parsed with `re-scripts/rsce.py`. Outputs are in `rsce-wrt/` and `rsce-deb/`.
- It is a multi-board image covering rk3399 nanopi4, rk3528, rk3566 r3, rk3568 nanopi5, rk3576 nanopi5 and rk3588 nanopi6, plus `logo.bmp` and `logo_kernel.bmp`.
- RK3576 entries:
  - `rk3576-nanopi5-rev01.dtb` = **"FriendlyElec NanoPi M5"**, compatible `friendlyelec,nanopi-m5`, `/board hwrev=1`, `machine="NANOPI-M5"`
  - `rev02` = NanoPi R76S
  - `rev03` (DEB only) = Core3576
- The M5 DTB is identical in WRT and DEB.
- Decompiled to **`m5-vendor.dts`**. The DTB has `__symbols__`; `re-scripts/fdtq.py` resolves labels and phandles.
- Board-ID mechanism: U-Boot picks the DTB by `hwrev`. The ADC channel or GPIO it reads was not found statically. **[I]**

## 4. M5 vendor DT: key hardware facts
GPIO notation is `GPIOb_Xn`. Every item below is **[V]** from `m5-vendor.dts` unless marked otherwise.

### E-key SDIO (`sdio`, mmc@2a320000, dw-mshc)
- 4-bit bus, max-frequency 200 MHz, `sd-uhs-sdr104`, `cap-sdio-irq`, `non-removable`, `no-sd`, `no-mmc`, `keep-power-in-suspend`.
- vqmmc = `vcc_1v8_s0` (1.8 V signalling).
- Pins `sdmmc1m0`: D0-D3 = GPIO1_B4..B7, CMD = GPIO1_C0, CLK = GPIO1_C1, func2, pull-up, drive level 2.
- **pwrseq** (`mmc-pwrseq-simple`): `reset-gpios = GPIO1_C2 active-low` (pinctrl `wifi_poweren_gpio`, pull-up), `post-power-on-delay-ms = 200`.
- **Default module child node: `rtl8822cs@1`, compatible `realtek,rtl8822cs`.**
- A `wifi_host_wake_irq` pin (GPIO0_B0, pull-down) is defined, but no node uses it. There is no wireless-wlan or wireless-bluetooth node.
- UART5 with CTS/RTS is enabled: TX/RX GPIO3_D4/D5, CTS GPIO3_D6, RTS GPIO3_D7. It is probably the E-key BT HCI UART. **[I]**

### PCIe0 (pcie@2a200000, M.2 M-key)
- `num-lanes=1`, `max-link-speed=2`, phy `combphy0_ps` (mode PCIe).
- `reset-gpios = GPIO2_B4` (flag 0, active-high).
- `prsnt-gpios = GPIO4_C4` (pull-up).
- `vpcie3v3-supply = vcc3v3_m2_keym`, a fixed regulator enabled by **GPIO0_D3** (active-high).
- Vendor quirks: `rockchip,skip-scan-in-resume`, `rockchip,skip-hw-retry`, `rockchip,wait-for-link-ms = 1000`. combphy0 has `rockchip,ebuff-mode`.
- DBI 0x22000000 (4 MiB), config 0x20000000, MEM32 0x20200000 + 0xe00000, MEM64 0x9_0000_0000 (2 GiB).
- `sata0` is also `okay` on combphy0 (mode SATA), and `pcie1` is disabled. Both pcie0 and sata0 claim combphy0. **[I]** The kernel probably picks one, or this is a vendor DT quirk.

### GMAC0 and GMAC1
| | GMAC0 (0x2a220000) | GMAC1 (0x2a230000) |
|---|---|---|
| phy-mode | **`rgmii-rxid`** | **`rgmii-rxid`** |
| tx_delay | **0x21** | **0x20** |
| rx_delay | none (PHY adds RX delay) | none (PHY adds RX delay) |
| `clock_in_out` | `"output"` | `"output"` |
| PHY | @1, C22, 25 MHz clock from CRU id 0x31 | @1, C22, 25 MHz clock from CRU id 0x32 |
| PHY interrupt | GPIO2_B1, level-low | GPIO3_A2, level-low |
| PHY reset | `snps,reset-gpio = GPIO2_B5` active-low | `snps,reset-gpio = GPIO3_A3` active-low |
| reset delays | 0 / 20000 / 100000 µs | 0 / 20000 / 100000 µs |
| PHY LED setting | `realtek,ledsel = 0xae00` | `realtek,ledsel = 0xae00` |

- The PHY is RTL8211F: `realtek.ko` is built in, and the kernel has `RTL8211F` strings. **[I]**
- The driver reads `rockchip,grf=sdgmac_grf` (0x26038000) and `rockchip,php_grf=ioc_grf`.

### Fan, LEDs, keys
- **Fan:** `pwm-fan` on `pwm0_2ch_1` (0x27331000, channel 0), pin GPIO0_C3 func12. Period 50000 ns.
  - `cooling-levels = 0, 45, 70, 110, 160, 255`.
  - `rockchip,temp-trips = 50°C→1, 55→2, 60→3, 65→4, 70→5`, `hold-time 2000 ms`.
- **LEDs:** `sys_led` GPIO2_B3 (heartbeat), `lan_led` GPIO2_B0, `wan_led` GPIO4_C5. All active-high.
- **Keys:**
  - K1 is `gpio-keys` on **GPIO1_A0 active-low**, code 0x101, wakeup. The vendor pinctrl `key1_pin` says GPIO4_A2, which is inconsistent with the gpios property. Mainline uses GPIO1_A0 for both.
  - `adc0-keys` on SARADC ch0 and `adc1-keys` on ch1 (volume up). Press < 17 mV, keyup 1.8 V.

### UART0 debug console
- 0x2ad40000, pins **GPIO0_D4/D5 func9** (`uart0m0_xfer`), 1500000 baud.
- The kernel uses fiq-debugger (`ttyFIQ0`, serial-id 0, IRQ 0x185); the uart0 node itself is `disabled`.
- earlycon: `uart8250,mmio32,0x2ad40000`.

### Watchdog
`snps,dw-wdt` at 0x2ace0000, IRQ 40 (SPI), clocks CRU 0xa8/0xa7. `okay`.

### RK806 PMIC
- On **I2C1** (0x2ac40000, pins GPIO0_B2/B3 func11), address **0x23**. IRQ GPIO0_A6, level-low. Pin GPIO0_A4 func9 is the PMIC sleep/DVS pin. **[I]** for that pin's role.
- `pmic-reset-func=1`, `buck5-feedback-disable`.
- Main rails:

  | rail | name | voltage |
  |---|---|---|
  | DCDC1 | vdd_cpu_big_s0 | 850 mV init |
  | DCDC3 | vdd_cpu_lit_s0 | 850 mV init |
  | DCDC2 | vdd_npu_s0 | |
  | DCDC5 | vdd_gpu_s0 | 750 mV init |
  | DCDC7 | vdd_logic_s0 | 750 mV init |
  | DCDC4 | vcc_3v3_s3 | |
  | DCDC8 | vcc_1v8_s3 | |
  | DCDC6/9/10 | DDR rails | |
  | PLDO5 | vccio_sd_s0 | 1.8–3.3 V |

### UFS (ufs@2a2d0000)
- reg: hci, mphy 0x2b040000, hci_grf 0x2601f000, mphy_grf 0x2603c000, hci_apb 0x2a2e0000.
- `reset-gpios = GPIO4_D0`. refclk pin GPIO4_D1 func1. 4 LUNs.

### SPI-NOR
- On **SFC1** (0x2a300000, `fspi1m1`): CS GPIO1_C3, CLK/D0-3 = GPIO1_D5, GPIO1_C4..C7 (func3). Quad rx, single tx.
- Speed: kernel 20 MHz, SPL 80 MHz (mainline uses 50 MHz).
- The flash part is not named in any DT (`jedec,spi-nor`). U-Boot only has a generic ID table. **[I]**

### reboot-mode (`syscon-reboot-mode` under **PMU0_GRF 0x26024000, offset 0x40**, i.e. address 0x26024040)
| mode | value |
|---|---|
| normal | 0x5242C300 |
| loader / bootloader | 0x5242C301 |
| recovery | 0x5242C303 |
| panic | 0x5242C307 |
| watchdog | 0x5242C308 |
| fastboot | 0x5242C309 |
| charge | 0x5242C30B |
| ums | 0x5242C30C |
| quiescent | 0x5242C30E |
| winusb | 0x5242C30F |

### Thermal
- tsadc: `hw-tshut-temp` 120 °C, tshut mode 0 (CRU reset), polarity 0.
- Zones (soc, bigcore, little, ddr, npu, gpu): critical trip at 115 °C. The little-core zone also has passive trips at 75 °C and 85 °C.

### Memory
- There is **no `/memory` node**; U-Boot fills it in.
- reserved-memory: `ramoops@0x40110000` size 0xe0000 (record 0x14000, console 0x80000, pmsg 0x30000, boot-log 0x8000×1, ftrace 0). drm-logo, cubic-lut and vendor-storage placeholders have size 0.
- SRAM `mmio-sram` 0x3ff88000 + 0x78000. SCMI shmem 0x4010f000.

### DMC
- `rockchip,rk3576-dmc`, clocked via SCMI clock 0x226, `auto-freq-en`.
- OPPs 528, 1068, 1560 and 2736 MHz. The DDR blob for LP4 is named 1866M, so the top OPP presumably applies to LP5 only. **[I]**

### Other enabled nodes
- i2c0 (`i2c0m1`), i2c2 (HYM8563 RTC @0x51), i2c4, i2c5 (RT5616 codec @0x1b).
- uart3 (GPIO3_A0/A1), uart8 (`uart8m1`, GPIO2_A6/A7).
- USB DRD0 + DRD1, HDMI, NPU, GPU, SARADC.
- Power enables: USB host 5 V GPIO0_C7, Type-C VBUS GPIO0_D1, SD 3.3 V GPIO0_B6.

### Vendor vs mainline `m5src/rk3576-nanopi-m5.dts`
| item | vendor | mainline |
|---|---|---|
| top compatible | `friendlyelec,nanopi-m5` | `friendlyarm,nanopi-m5` |
| E-key SDIO, pwrseq, rtl8822cs, UART5 BT | present | **absent**; the SoC `sdio` node exists but is not enabled |
| pwm-fan + trips | present | **absent** |
| GMAC phy-mode | `rgmii-rxid` + tx_delay 0x21/0x20 | `rgmii-id` (no MAC delays) |
| GMAC PHY reset | via `snps,reset-*` in the MAC node | `reset-gpios` in the PHY node (same pins and delays) |
| PCIe0 | `prsnt-gpios` GPIO4_C4, skip-hw-retry, wait-for-link 1000 ms | reset GPIO2_B4 + vpcie3v3 GPIO0_D3 only |
| combphy0 | pcie0 + sata0 both okay | no sata |
| LED names | sys / lan (GPIO2_B0) / wan (GPIO4_C5) | sys / led1 (GPIO4_C5) / led2 (GPIO2_B0) |
| SD supplies | vmmc vcc_3v3_sd_s0, vqmmc vccio_sd_s0 (PLDO5) | vmmc vcc_3v3_s3, vqmmc vcc3v3_sd_s0 |
| NOR speed | 20 MHz | 50 MHz |
| reboot-mode | in pmu0_grf | not in mainline dtsi |
| reserved-memory | ramoops | none |
| console | fiq-debugger | uart0 `okay`, stdout `serial0:1500000n8` |

## 5. dtbo.img (Android DT table, magic `d7b7ab1e`, 3 entries, id/rev all 0)
Each entry only sets `/chosen/bootargs_ext`:
- entry 0: `root=/dev/mmcblk2p8 ... data=/dev/mmcblk2p9` (eMMC)
- entry 1: `mmcblk0p8/p9` (SD)
- entry 2: `sda8/sda9` (UFS)

All three also carry `cgroup_enable=cpuset cgroup_memory=1 cgroup_enable=memory swapaccount=1 consoleblank=0`. There are no Wi-Fi or LCD overlays. Decompiled outputs are in `dtbo-x/`.

## 6. kernel.img and boot.img
- Both use the Rockchip `KRNL` wrapper: magic, u32 length, payload, 4-byte CRC.
  - `kernel.img` payload is an arm64 `Image` (`ARMd` magic at 0x38), saved as `kern-wrt/Image` and `kern-deb/Image`.
  - `boot.img` payload is a gzip ramdisk.
- Version: **Linux 6.1.141**. WRT was built `#1 SMP Thu Aug 6 18:22:49 CST 2026`, DEB `#56 SMP Wed Aug 5 2026`. Toolchain gcc 11.3.0 (ctng FA).
- **No IKCONFIG** (`grep -ac IKCFG_ST` returns 0). Driver facts below come from DEB `modules.builtin`, `modules.order` and `modules.dep`.
  - **Built in:** pcie-dw-rockchip, pcierockchiphost, nvme-core + nvme, realtek PHY, stmmac / dwmac-rockchip, ufshcd-core / ufshcd-pltfrm / ufs-rockchip, dw_wdt, pstore + ramoops, rockchip efuse/otp nvmem.
  - **Modules (in-tree):** r8169, r8168, iwlwifi (mvm/dvm), brcmfmac, bcmdhd (rkwifi), rtw88 PCIe variants, rtw89 8852a/c, mt76 (7921e/7915e …), btusb/btrtl/btbcm/hci_uart/btsdio, pwm-fan.
  - **Modules (out-of-tree, `extra/`):** `r8125.ko`, **`rtl8822cs.ko`** (Realtek vendor SDIO driver), rtl8822ce/bu, `rtw_8822cs/ce/bs/b/c`, `aic8800_bsp/fdrv/btlpm`.
- Kernel cmdline = DT `bootargs` (`earlycon=uart8250,mmio32,0x2ad40000 console=ttyFIQ0 coherent_pool=1m rcupdate.rcu_expedited=1 rcu_nocbs=all`) + `bootargs_ext` from the dtbo entry for the boot device.

## 7. Debian rootfs (Android sparse → `deb-x/rootfs.raw` ext4, read with `debugfs` only)
- No `/etc/fw_env.config` and no fw_printenv setup.
- `/etc/init.d/friendlyelec_leds.sh` only sets netdev triggers through sysfs: `wan_led` → eth0, `lan_led` → eth1, `link=1`. There is no GPIO poking.
- `/usr/local/bin/cputemp.sh` reads `thermal_zone0` and fan `cooling_device0` state.
- `firstboot` writes `wipedata=yes` to `<data=>/root/var/.init_wipedata`.
- `friendlyelec_firstuse.sh` handles hostname, libmali and NPU setup. Its case list includes `nanopi-m5`.
- **None of these scripts touches reboot-to-maskrom, raw GPIOs or the fan.**
- `/etc/modprobe.d/rtl8822c.conf` **blacklists `rtw_8822c`, `rtw_8821cs`, `rtw_8822cs`, `rtw_8822ce`.** So for the default E-key module FriendlyElec uses the Realtek vendor `rtl8822cs.ko`, not rtw88.
- `r8169.conf` aliases 10ec:8125 and 10ec:8162 to `r8125`. `modules-load.d/r8125.conf` loads r8125.
- `aic8800-bt.conf` loads `aic8800_bsp` before `hci_uart`.
- `/lib/firmware`, i.e. the E-key/USB radios FriendlyElec supports:
  - `rtl_bt/rtl8822cs_{fw,config}.bin`, rtl8821cs, rtl8723b, rtl8761b/bu, rtl8822cu, rtl8851bu
  - `rtw88/rtw8822{b,c}_fw.bin`, `rtw8822c_wow_fw.bin`
  - `brcm/brcmfmac43455-sdio.bin` / `43456-sdio.bin` with generic `.txt` files and nanopi-neo3s/r2 variants. This covers AP6255/AP6256-class and CYW43455.
  - `aic/` AIC8800D80 firmware (`fmacfw_8800d80_*`)
  - Intel iwlwifi cc-a0-59 (AX200) and ty-a0-gf-a0-59/72 (AX210), Intel BT `ibt-20-1-3`
  - MediaTek MT7921/MT7922 and mt7662u
  - There is **no BE200 firmware (iwlwifi-gl-…)**; the newest iwlwifi files are -72 for ty-a0.
  - The rtl8822cs Wi-Fi firmware is presumably built into the vendor driver. **[I]**

## 8. Reboot to maskrom / loader
Verified by disassembling U-Boot (`fit-wrt/uboot.dis`, VMA 0x40200000). The register is **PMU0_GRF + 0x40 = `0x26024040`**, built as `mov x0,#0x4040; movk x0,#0x2602,lsl#16`.
- **Maskrom:** U-Boot `rockusb`/`bootrom` fallback (code at 0x40204740 and 0x40208c94) prints `Enter bootrom download...`, writes **`0xEF08A53C`** to 0x26024040, then calls the reset routine (0x40280df0). **[V]** for the U-Boot behaviour. **[I]** that the BootROM honours it; this is the standard Rockchip contract and has not been tested on metal.
- **Reboot with an argument** (0x40280e64..0x40280ed4): looks up DT `mode-<arg>`. The special string `"bootrom"` maps to 0xEF08A53C. It prints `## Reboot mode: %s(%x)` and stores the value to 0x26024040.
- **At boot** (0x40203388..), U-Boot reads 0x26024040:
  - `0x5242C301` → `boot mode: loader` (rockusb), then clears the register to 0x5242C300
  - `0x5242C30D` → dfu
  - `0x5242C309` → bootloader/fastboot
- **For heqk:**
  - Software reboot-to-maskrom = write 0xEF08A53C to 0x26024040, then reset (PSCI SYSTEM_RESET via BL31, or CRU global soft reset). **[I]** for the exact reset path used.
  - Reboot to the vendor rockusb loader = 0x5242C301. That only works while the vendor U-Boot is in the chain.

## Artifact paths (bench-host scratch, not committed)
- Extracted inputs: `wrt-x/friendlywrt25/*`, `deb-x/debian-trixie-core-arm64/*` (small images only), `deb-x/rootfs.raw` (1.8 GB ext4)
- Loader pieces: `ldr-wrt/` (MiniLoaderAll entries), `idb-wrt/rkns_img{0,1,2}.bin` (boost, DDR, SPL), `idb-wrt/spl.dts`, `idb-wrt/ddr.dis`
- U-Boot FIT: `uboot-fit.its`, `fit-wrt/{uboot,atf-1,atf-2,atf-3,optee,fdt}.bin`, `fit-wrt/uboot-dtb.dts`, `fit-wrt/uboot.dis`, `fit-deb/*`
- DTBs: `rsce-wrt/*.dtb|dts`, `rsce-deb/*`, **`m5-vendor.dts`**, `dtbo-x/*.dtb`
- Kernel and rootfs files: `kern-wrt/Image`, `kern-deb/Image`, `deb-files/` (modules.builtin/order/dep, FriendlyElec scripts)
- Scripts: `re-scripts/{ldr,rkns,rc4chk,hdrhash,ddrsyms,fdtscan,fitx,rsce,fdtq,unsparse,findu32,atagscan,cstr}.py`

## Open items (unverified)
1. How BOOT1_PARAM words map into header 0x58..0x6x.
2. How U-Boot reads the board ID (ADC channel or GPIO) to select `rev01`.
3. The SPI-NOR part number.
4. Whether pcie0 or sata0 wins on combphy0.
5. ~~The BT UART on the E-key.~~ Resolved: UART5_M0 with RTS/CTS (schematic rev 2411 p22).
6. BootROM acceptance of 0xEF08A53C on metal.
