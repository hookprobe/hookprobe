# NanoPi M5 (RK3576): hardware data pack for the heqk port

**Date:** 2026-11-26 · **Status:** reference data (Green). Companion to
`heqk-nanopi-m5-rk3576-investigation-2026-11-26.md`. Board ordered (amazon.de), expected mid-December 2026.

**Sources, in order of authority:**
1. FriendlyElec schematics `NanoPi_M5_LP5_2411_SCH.pdf` and `NanoPi_M5_LP4X_2411_SCH.PDF`, rev 2411, 24 pages
   (wiki.friendlyelec.com/wiki/images/9/97/… and …/1/10/…).
2. Mainline Linux `arch/arm64/boot/dts/rockchip/rk3576.dtsi` + `rk3576-nanopi-m5.dts` (torvalds/linux master, fetched
   2026-11-26). Mainline has a NanoPi M5 board file, so wiring below is open-source-attested. We use these as **hardware
   facts only**: GPL code is read, never copied (clean-room rule, as for every heqk driver).
3. The FriendlyElec wiki and the web sources cited in §10.

Anything not attested by (1) or (2) is marked *(unverified)*.

## 1. SoC memory map (from `rk3576.dtsi`)

| Block | Compatible | Base | Size | IRQ (GIC SPI) | heqk note |
|---|---|---|---|---|---|
| GIC | `arm,gic-400` (GICv2) | GICD `0x2a70_1000`, GICC `0x2a70_2000`, GICH `0x2a70_4000`, GICV `0x2a70_6000` | 0x10000 each | maint. PPI 9 | reuse `gic.rs` (CM5 is also GIC-400), base from board profile |
| Console UART0 | `rockchip,rk3576-uart`, `snps,dw-apb-uart` | `0x2ad4_0000` | 0x100 | 76 | 16550-class, **reg-shift 2, 32-bit access**, 1 500 000 8N1 |
| PCIe0 DBI | `rockchip,rk3576-pcie` (fallback `rk3568-pcie`), DesignWare | `0x2200_0000` | 4 MiB | sys 281, pmc 282, msg 279, legacy 280, err 278, **msi 283** | Gen2 ×1, `dma-coherent`, `num-viewport 8` (iATU) |
| PCIe0 APB (client/GRF) | ″ | `0x2a20_0000` | 64 KiB | | LTSSM/link control |
| PCIe0 config window | ″ | `0x2000_0000` | 1 MiB | | bus range 0x0–0xf, via iATU |
| PCIe0 I/O | ″ | `0x2010_0000` | 1 MiB | | |
| PCIe0 MEM32 | ″ | `0x2020_0000` | 14 MiB | | NVMe BAR0 lands here |
| PCIe0 MEM64 (prefetch) | ″ | `0x9_0000_0000` | 2 GiB | | |
| PCIe1 | ″ | DBI `0x2240_0000` | | | **unused on the M5** (combphy1 is in USB 3 mode) |
| Combo PHY0 | `rockchip,rk3576-naneng-combphy` | `0x2b05_0000` | 0x100 | | PCIe mode → M-key slot |
| Combo PHY1 | ″ | `0x2b06_0000` | 0x100 | | USB 3 mode → USB-A port 2 |
| GMAC0 / GMAC1 | `rockchip,rk3576-gmac`, `snps,dwmac-4.20a` | `0x2a22_0000` / `0x2a23_0000` | 64 KiB | 293 (macirq) / see dtsi | RGMII-ID, MAC drives TX clock (`clock_in_out = "output"`) |
| SD (microSD) | `rockchip,rk3576-dw-mshc` | `0x2a31_0000` | 16 KiB | 251 | **Synopsys DW-MSHC, not SDHCI** |
| SDIO (E-key) | `rockchip,rk3576-dw-mshc` | `0x2a32_0000` | 16 KiB | 252 | not enabled in mainline M5 DTS |
| eMMC (unused on M5) | SDHCI (dwcmshc) | `0x2a33_0000` | | | |
| UFS host | `rockchip,rk3576-ufshc` | `0x2a2d_0000` (+ mphy, hci_grf, mphy_grf, hci_apb) | 64 KiB | 361 | UFSHCI + Rockchip M-PHY glue |
| SFC1 (SPI-NOR) | Rockchip FSPI | `0x2a30_0000` | | | 16 MiB NOR, pins `fspi1m1`, quad read |
| TRNG | `rockchip,rk3576-rng` | `0x2a41_0000` | 0x200 | 181 | entropy source for the DRBG |
| OTP | `rockchip,rk3576-otp` | `0x2a58_0000` | 0x400 | | CPU id/version, trims. Sealing-key source *(layout: see §6)* |
| I²C1 (PMIC) | `rockchip,rk3576-i2c` (rk3399-i2c) | `0x2ac4_0000` | 4 KiB | 89 | RK806 @ 0x23 |
| I²C2 (RTC) | ″ | `0x2ac5_0000` | 4 KiB | | HYM8563 @ 0x51 |
| Watchdog | `rockchip,rk3576-wdt`, `snps,dw-wdt` | `0x2ace_0000` | 0x100 | 40 | boot-health watchdog for A/B |
| Timer0 | `rockchip,rk3576-timer` | `0x2acc_0000` | 0x20 | 45 | not needed (arch timer) |
| GPIO0–4 | Rockchip GPIO | `0x2732_0000`, `0x2ae1_0000`, `0x2ae2_0000`, `0x2ae3_0000`, `0x2ae4_0000` | | | PERST, PHY resets, LEDs, keys |
| CRU | clock controller | `0x2720_0000` | | | |
| PMU | power domains | `0x2738_0000` | | | `RK3576_PD_PHP` must be on for PCIe/GMAC/UFS |
| GRFs | sys `0x2600_a000`, php `0x2602_0000`, pipe_phy0 `0x2602_8000`, sdgmac `0x2603_8000`, ioc `0x2604_0000`, usb `0x2601_e000` | | | | |
| USB DRD0/1 | DWC3 | `0x2300_0000` / `0x2340_0000` | | | xHCI (DRD0 is OTG = maskrom port) |
| SRAM | | `0x3ff8_8000` | | | |

**CPUs:** 4× Cortex-A53 (MPIDR 0x000–0x003, cluster "little") + 4× Cortex-A72 (MPIDR 0x100–0x103, "big"),
`enable-method = "psci"`, PSCI via **SMC**. CPU clocks are **SCMI** (`scmi_clk` ARMCLK_L/B): DVFS is owned by
BL31, so heqk asks firmware for frequency changes and never programs the CPU PLLs.

**No SMMU.** Mainline `rk3576.dtsi` has only per-IP media IOMMUs (e.g. `vdec_mmu` at `0x27b0_0800`), and the PCIe
controllers have no `iommu-map`/`msi-map`. **PCIe DMA cannot be confined**. This is a policy input for any EL0 PCIe
driver (§7).

## 2. Board wiring (schematic rev 2411 + mainline board DTS)

| Function | Wiring | Source |
|---|---|---|
| Debug console | UART0_M0 TX/RX (`UART0_*_M0_DEBUG`), 3-pin 2.54 mm header (GND, TX, RX), 3.3 V, 1.5 Mbaud | sch p6, DTS `stdout-path = "serial0:1500000n8"` |
| Ethernet ×2 | GMAC0 → **RTL8211F-CG** (25 MHz xtal), MDIO addr **1**, reset `GPIO2_B5` active-low; GMAC1 → RTL8211F-CG, addr 1, reset `GPIO3_A3`. `phy-mode = "rgmii-id"` (PHY adds the delays), PHY supply `vcc_3v3_s3` | sch p20/p21, DTS |
| M.2 **M-key 2280** | PCIe0 lane 0 only (lanes 1–3 NC), REFCLK0, `PERST#` = `GPIO2_B4` active-high in DTS, CLKREQ0#, PEWAKE0#; 3.3 V from an SY8089 buck, enabled by `PCIE0_PWREN_H`; `PEDET` = NC → PCIe mode (not SATA) | sch p22, DTS `&pcie0` |
| M.2 **E-key 2230** | **SDIO** (CLK/CMD/D0–3, 1.8 V signalling), **UART5_M0** TX/RX/CTS/RTS (BT HCI), `WIFI_REG_ON_H`, `BT_REG_ON_H`, `WIFI_WAKE_HOST_H`, `BT_WAKE_HOST_H`, `HOST_WAKE_BT_H`, `SUSCLK` 32 kHz from the RTC (`32KOUT_RTC2WIFI`). **PCIe TX/RX/REFCLK pins and USB D+/D− are no-connect.** PCM pins NC. | sch p22 (rendered and checked) |
| Boot storage | UFS **socket** (removable UFS 2.0–4.0 module; VCCQ 1.2 V, VCCQ2 1.8 V, VCC 3.3 V, `UFS_RSTn`); microSD on SDMMC0 (4-bit, `vqmmc` from `vcc3v3_sd_s0`); 16 MiB SPI-NOR on FSPI1_M1 | sch p6/p17, DTS |
| PMIC | **RK806S-5** on I²C1_M0 @ 0x23: CPU big/little rails, GPU, NPU, logic, DDR rails | sch p14, DTS |
| RTC | HYM8563 on I²C2 @ 0x51 (also drives the 32 kHz to the E-key) | DTS, sch p22 |
| USB-C power | **FUSB302 + an on-board STM32 MCU** negotiate PD (6–20 V), with VBUS sensed on `SARADC_VIN2_VUSBC`. **No SoC-side PD driver is needed.** | sch p16 |
| USB | DRD0 (DWC3) = OTG port (maskrom/ADB), DRD1 = host; USB 3 via the USBDP PHY and combphy1 | DTS |
| Keys/LEDs | MASK, User, Recovery (SARADC_VIN1), Power; SYS/LED1/LED2 on GPIO | sch p6, DTS |
| HW revision | `SARADC_VIN5_HW_ID` resistor divider (LP4X vs LP5 builds) | sch p6 |

## 3. Boot-mode strap (sch p6, "Config Table for SARADC_VIN0_BOOT")

The BootROM reads an ADC divider on `SARADC_IN0`. The **BOOT switch SW1** selects one of two rows (both highlighted in red
in the schematic):

| Config | ADC | Order | Switch position |
|---|---|---|---|
| 1 | 0 | USB (maskrom) | MASK key pulls to 0 |
| **4** | 1231 | **FSPI1_M1 (SPI-NOR) → eMMC → USB** | "FSPI" |
| **8** | 2887 | **UFS → SDMMC0 (microSD) → USB** | "UFS/SD" |

(The RK3576 Hardware Design Guide gives the full 11-row strap table. The M5 uses rows 4 and 8. Its ADC value for row 8 is
2862, against the schematic's 2887, which is within tolerance.)

Consequences for heqk:
- **BootROM microSD boot is unreliable on RK3576.** rkbin needed a "boost" stub to fix "BootROM load ddr.bin fail in SD
  card"; mainline idbloaders do not include it, and the July 2026 U-Boot series to fix SD boot is unmerged. **Do not
  use SD as the first stage.**
- **Bench plan:** put the first stage (DDR blob + U-Boot SPL + TF-A + U-Boot) in **SPI-NOR** over USB maskrom, and
  set the switch to **FSPI**. U-Boot (which does have working SD/UFS/NVMe drivers) then loads `hboot`/heqk from microSD,
  UFS or NVMe, or over the network.
- **Production:** the same SPI-NOR first stage; heqk A/B slots on UFS (or the NVMe data volume for evidence only). The
  BootROM cannot boot from NVMe or USB storage.

## 4. Boot chain

```
BootROM ──(strap: FSPI1_M1)──▶ idbloader @ SPI 0x8000 (rksd): rkbin DDR TPL v1.13 + mainline U-Boot SPL
   ──▶ u-boot.itb @ SPI 0x60000: upstream TF-A BL31 (@0x4004_0000, EL3) + U-Boot proper (@0x4080_0000, EL2)
   ──▶ booti hboot (verifies Ed25519 + SLH-DSA, A/B) ──▶ heqk at EL2, x0 = FDT
```

| Stage | What | Source / version | Open? |
|---|---|---|---|
| TPL (DDR init) | `rk3576_ddr_lp4_2112MHz_lp5_2736MHz_v1.13.bin`: one blob covers LPDDR4/4X/5, so it serves both M5 variants | rkbin `bin/rk35` | **closed**, recorded as an unverifiable vendor blob (as CM5's VideoCore firmware is) |
| SPL | mainline U-Boot `nanopi-m5-rk3576_defconfig` (in master since **v2026.01**; **SPL UFS boot from v2026.07**) | u-boot master | GPL, open |
| BL31 | **upstream TF-A ≥ v2.13** `plat/rockchip/rk3576`: PSCI CPU_ON/SYSTEM_RESET/SYSTEM_OFF + **SCMI clock server** (ARMCLK_L/B, DVFS) | trustedfirmware.org | BSD, open |
| BL32 | none (no OP-TEE). rkbin BL32 is a raw blob that mainline binman can't package | n/a | n/a |
| BL33 | U-Boot proper, then `booti` of hboot | mainline | open |
| hboot → heqk | our signed chain, unchanged crypto | os/kernel/hboot | AGPL |

**Rules learned from the field:**
- **Never mix a rkbin MINIALL loader (1 GHz hrtimer via boot1 `WORD_2=0x100`) with a mainline-packaged chain**
  (24 MHz). rkbin BL31 ≥ v1.09 fails with older mainline layouts. The M5 defconfig sets `COUNTER_FREQUENCY=24000000`,
  so heqk reads **CNTFRQ_EL0** and never assumes a value (CM5 is 54 MHz).
- Known-good published pairs: DDR v1.09 + BL31 v1.20 (rkbin, on an M5); DDR v1.12 + BL31 v1.24. With **upstream** TF-A
  the BL31 version question disappears. That is our choice, because it is open and gives us source for PSCI/SCMI.
- U-Boot v2026.07-rc2 had a broken ATF hash on RK3576, so use a released tag.

**Layouts:**
- SPI-NOR (16 MiB): idbloader at **0x8000** (rksd format, RK3576-specific), `u-boot.itb` at **0x60000**. Write
  `u-boot-rockchip-spi.bin` at offset 0.
- SD/UFS (if used later): idbloader at sector 64 (byte 0x8000, `RKNS`), `u-boot.itb` at byte **8 MiB**. UFS has 4 KiB
  sectors (`SPL_UFS_RAW_U_BOOT_SECTOR=0x800`, LUN 0).

**Memory handoff:**
- DRAM base **0x4000_0000**. **Reserve 0x4000_0000–0x401F_FFFF** (BL31 TZRAM at 0x4004_0000–0x4010_0000; DDR
  share-mem at 0x4010_0000 with the **SCMI shmem at 0x4010_f000**; DDR ATAGs at 0x401F_E000).
- U-Boot builds the banks from the DDR blob's ATAG and puts them in the FDT `/memory` node. **heqk must take RAM from
  the FDT, not a constant.** The 16 GiB part spans past 4 GiB (bank 1 at 0x1_0000_0000).
- U-Boot env: `kernel_addr_r=0x4200_0000`, `fdt_addr_r=0x5200_0000`.

**EL at handoff:** SPL hands BL33 to U-Boot at **EL2**. `booti` stays at EL2 unless `ARMV8_SWITCH_TO_EL1` is set
(it is not), so the kernel image is entered at **EL2 with x0 = FDT**. This is verified in source with upstream TF-A, and
it gives heqk the EL2 it uses on CM5 (stage-2 carve-outs, SEC-2 style).

**Maskrom/recovery:**
- Hold MASK, power on, release after ~3 s. USB ID 2207:350e on the OTG (DRD0) port.
- Flash: `rkdeveloptool db rk3576_usbplug_fspi1_v1.03.bin` (or the `u-boot-rockchip-usb471/472.bin` mainline builds),
  then `ef`, then `wl 0 u-boot-rockchip-spi.bin`.
- Upstream rkdeveloptool has no RK3576-specific code but works generically for `db`/`wl` (it has no UFS selector).
- Software entry to maskrom: write `0xEF08A53C` to PMU0_GRF OS_REG16 (`0x2602_4040`) and reset. Useful for a heqk
  "reboot to recovery" path.

**Secure boot (do NOT fuse yet):**
- The BootROM checks the first stage against a SHA-256 hash of an RSA public key in OTP.
- RK3576 is reported as **RSA-2048 only**: status at OTP_S word 0x8, key hash at words 0x184–0x187. That is community
  data and conflicts with the RK35xx-generic "2048/4096".
- Fusing is irreversible and needs upstream OP-TEE's rksecure PTA. RSA-2048 is below our hybrid Ed25519 + SLH-DSA
  bar, so the BootROM anchor would only protect the first stage. hboot keeps the PQ-hybrid verification from there on, as
  on CM5. Record this honestly in the CBOM.

**OTP:**
- The non-secure controller (`0x2a58_0000`) exposes only **0x100 bytes** (CPU version, chip ID, tsadc trims).
- Secure OTP (`0x2a48_0000`: key hash, HUK at OTP_S 0x80) sits behind the secure controller, so it needs BL31/OP-TEE. That
  is inferred from the S/NS split *(unverified)*.
- This is the key design question for a sealing key equal to SEC-2 (§7).

## 5. Clock/power prerequisites heqk inherits from firmware

**Stance for the first milestones:** heqk does not own the CRU or PMIC. U-Boot leaves the console, SD, both GMACs and PCIe0
clocked, powered (PD_PHP, PD_SDGMAC, PD_USB) and pin-muxed, and BL31 owns CPU clocks through SCMI. This is the same
"firmware already did it" stance `pci.rs` takes with edk2.

There are two exceptions, and both come from field evidence:
- **PCIe must be fully reset by heqk** (controller resets, PHY, PERST#), whatever state firmware leaves it in. The ROCK 4D
  "NVMe not detected in mainline" thread (Dec 2025 to Jan 2026) only resolved after re-flashing mainline U-Boot, and no root
  cause was published.
- **The UART0 clock source must be read, not assumed.** 24 MHz / 16 = 1.5 Mbaud exactly (divisor 1), but whether
  SCLK_UART0 is on xin24m at hand-off is *unverified*. Check the CRU clock-select register for UART0 (TRM Part 1 ch2).

Later (owning power): RK806 over I²C1 for DCDC1/2/3 (big/NPU/little, 0.55–0.95 V; BUCKn_ON_VSEL `0x1A+n−1`, 500 mV +
6.25 mV×sel), and power-off via SYS_CFG3 (0x72) bit 0. CPU DVFS stays an SCMI request to BL31 (SMC `0x8200_0010`); the
OS supplies the voltage through the PMIC.

## 6. Per-IP driver notes (hardware facts for clean-room drivers)

Reference documents: **RK3576 TRM V1.2 Part 1** (CRU ch2, GRF ch5, PMU ch6, GIC ch13, WDT ch15, GPIO ch21, I²C ch32,
UART ch33, SDMMC/SDIO ch39) and **Part 2** (GMAC ch8, PCIe ch14, combo PHY ch17, UFS ch26). They are publicly mirrored, not
officially published by Rockchip. Keep them out of the repo, record their hashes, and treat them as reference only. The TRM
leaves out OTP, TRNG and crypto, so those facts come from driver reading (clean-room rule applies).

**UART (DW-APB, ch33):**
- Formula: baud = sclk / (16 × div). 64-byte FIFOs.
- **LCR/DLL/DLH are writable only while USR (0x7C) bit 0 (busy) = 0**, so drain or reset the FIFOs first.
- IIR = 0x7 means busy-detect, cleared by reading USR.
- Wait ≥ 8 clock cycles after DLL before transmitting.

**GIC-400 (ch13):** plain GICv2, so `gic.rs` works once the base comes from the profile. All SPIs are level-high per
the datasheet. The dtsi declares the PCIe INTx parent (SPI 280) edge-rising; test that discrepancy.

**PCIe (DWC, ch14):**
- PCIe 2.1 RC, Gen2 ×1, MPS 128.
- iATU: 8 inbound and 8 outbound regions, **unrolled at DBI+0x30_0000**. DBI2 shadow at DBI+0x10_0000.
- Port logic at 0x700. MSI capability at 0x50, PCIe capability at 0x70.
- Client/APB registers use the hiword write-mask:
  - GENERAL_CON 0x0: mode [7:4] = 4 (RC), bit 2 = LTSSM enable.
  - HOT_RESET_CTRL 0x180, bit 4 = LTSSM "enhance".
  - **LTSSM_STATUS 0x300**: link up when bits [17:16] = 0b11.
  - Interrupts: legacy 0x8 / mask 0x1C, misc 0x10 / mask 0x24.
- Bring-up order:
  1. Assert resets pwr + pipe.
  2. Enable the 3.3 V slot power (`PCIE0_PWREN_H`) **before** PHY init.
  3. Combo PHY init.
  4. Deassert resets and enable clocks (aclk_mst/slv/dbi, pclk, aux).
  5. Set HOT_RESET_CTRL enhance and GENERAL_CON = RC.
  6. In DBI2, zero BAR0/BAR1 (they report a bogus size) and set **N_FTS = 255** for Gen1/2 (the default 210 is broken).
  7. Hold PERST# (`GPIO2_B4`, low = asserted), enable LTSSM, wait 100 ms, release PERST#, poll for link-up.
- MSI: the DWC internal controller (target address + enable/mask/status in port logic) raises SPI 283, with up to 32 vectors.

**Combo PHY (ch17):**
- Ref clock 100 MHz (`CLK_REF_PCIE0_PHY`). The SoC drives REFCLK to the M.2 slot.
- pipe_phy0_grf (0x2602_8000) PCIe config, hiword-masked:
  - con0 = 0x1000, con1 = 0x0000, con2 = 0x0101, con3 = 0x0200.
  - pipe_clk_100m: 0x4 bits [14:13] = 2.
- PHY registers at 100 MHz: 0x74 = 0xC0, 0x80[4:2] = 4, 0x6C = 0x4C, 0x28 = 0x90, 0x2C = 0x43, 0x30 = 0x88, 0x34 = 0x56.
- **Erratum: set bit 5 of 0x64** (force RX-termination detect).
- SSC off on the M5. Deassert the PHY reset last.

**GMAC (DWC Ethernet QoS 4.20a, ch8):**
- sdgmac_grf GMAC_CON0 at +0x20 (GMAC0) / +0x24 (GMAC1):
  - RGMII clock divider [6:5]: 0 = 125 MHz, 3 = 25 MHz, 2 = 2.5 MHz.
  - io_clksel bit 7 = 0 (CRU, since `clock_in_out = output`).
- ioc_grf delay registers (+0x6408/0x640C GMAC0, +0x6410/0x6414 GMAC1): **disabled for rgmii-id**, because the PHY adds the delays.
- Core: DMA_MODE 0x1000 bit 0 = SW reset, MAC_VERSION 0x110. 4-word descriptors, OWN = DES3[31]. The STM32MP15 reference
  manual documents the same QoS 4.20a IP publicly.
- PHY: RTL8211F-CG, ID `0x001cc916`, MDIO addr 1.
  - **Enable the SoC's 25 MHz REFCLKO25M_GMACx output before releasing the PHY reset.**
  - Reset: hold 20 ms, then wait 100 ms.
  - Delays: page 0xd08 reg 0x11 bit 8 = TX delay, reg 0x15 bit 3 = RX delay (set both).
  - Interrupts: `GPIO2_B1` / `GPIO3_A2`.
- `dma-coherent` in the DT (there is a CCI-500). Verify on metal before skipping cache maintenance.

**SD/SDIO (DW-MSHC, ch39):**
- FIFO depth 0x100, ≤ 200 MHz. **The card clock is ciu/2**, so request 2× from the CRU.
- RK3576 uses **internal phase**:
  - TIMING_CON0 0x130 (drive) and TIMING_CON1 0x134 (sample), hiword-masked: [2:1] = 90° steps, [10:3] = fine delay
    (~44–77 ps each), bit 11 = fine-delay enable.
  - MISC_CON 0x138 bit 5 = memory clock auto-gate. Set it at init and resume.
- Tuning sweeps the sample phase and takes the middle of the widest passing window.
- SDIO card interrupt = bit 8.
- E-key Wi-Fi: SDIO, 4-bit SDR104, 1.8 V I/O. REG_ON on `GPIO1_PC2` (active low reset, 200 ms after power), host-wake
  `GPIO0_PB0`. BT on UART5_M0 with RTS/CTS (enable `GPIO3_PC7`, host-wake `GPIO0_PB1`, dev-wake `GPIO3_PD0`). 32 kHz LPO
  from the HYM8563 (`32KOUT_RTC2WIFI`), which the Broadcom/Cypress parts need.

**UFS (UFSHCI 2.0 = JEDEC JESD223C, ch26):**
- UFS 2.0, 2 lanes, HS-G3, UniPro 1.61. UFSHC_VER (0x08) = 0x200. 64-bit addressing; 8 task-management slots.
- Regions: hci 0x2a2d_0000, mphy 0x2b04_0000, hci_grf 0x2601_f000, mphy_grf 0x2603_c000, hci_apb 0x2a2e_0000. SPI 361, PD_USB.
- Device reset `GPIO4_D0` (pulse 20–25 µs).
- After HCE: DME_RESET, DME_ENABLE, then a vendor M-PHY attribute + MMIO sequence. The sequence is recorded in the research
  notes; re-derive it from the TRM before implementing. UniPro/M-PHY specs are MIPI members-only, which is a reason to put UFS
  **after** SD + NVMe.

**TRNG ("RKRNG", standalone, 0x2a41_0000):**
- Read sequence:
  1. CTRL 0x10 = BIT(4) | BIT(20).
  2. Poll STATE 0x14 bit 4.
  3. Write 1 to clear it.
  4. Read 32 bytes from DATA0–7 (0x50–0x6C).
- No public SP 800-90B entropy assessment exists, so heqk runs its own **repetition-count + adaptive-proportion health tests**
  and conditions the output before seeding the DRBG. This is the same contract as RNG200.

**OTP (non-secure, 0x2a58_0000):**
- Only 0x100 bytes are usable, at byte offset 0x700, in 32-bit words.
- Read one word:
  1. AUTO_CTRL 0x04 = (word << 16) | (1 << 8).
  2. AUTO_EN 0x08 = 1.
  3. Poll INT_ST 0x84 bit 1, then write 1 to clear.
  4. Read DOUT0 0x20.
- Cells (byte offsets): cpu-code 0x02, cpu-version 0x05, **chip id 0x0A (16 B)**, leakage, tsadc trims.
- The chip ID is a device identifier, **not a secret** (§7).

**Watchdog (DW-WDT, ch15):**
- CR 0x0 bit 0 = enable (cleared only by reset). TORR 0x4: 2^(16+n) − 1 counts (max ~89 s at 24 MHz, assuming tclk = 24 MHz).
- Kick by writing **0x76 to CRR 0xC**.
- Whether the CRU/PMU routes the WDT to a global reset is *unverified* (TRM ch2/ch6). Prove it on the bench before A/B depends on it.

**I²C (rk3x v1, ch32):**
- Registers: CON 0x00, CLKDIV 0x04, MRXADDR 0x08, MRXRADDR 0x0C, MTXCNT 0x10, MRXCNT 0x14, IEN 0x18, IPD 0x1C,
  TXDATA 0x100, RXDATA 0x200.
- PMIC interrupt `GPIO0_A6`. RTC interrupt `GPIO0_A5`.

## 7. Security posture deltas vs CM5

| Area | CM5 today | NanoPi M5 | Consequence |
|---|---|---|---|
| First-stage anchor | VideoCore firmware + EEPROM (closed) | BootROM → closed DDR blob → open SPL/TF-A | Both have a closed first link. On RK3576 it is only the DDR init, and everything after it is open source we can build and hash into the CBOM |
| Hardware root of trust | none (OTP only, no secure boot fused) | optional BootROM RSA-2048 key hash in OTP (irreversible) | below our PQ-hybrid bar. hboot keeps Ed25519 + SLH-DSA verification. Do not fuse on the bench unit |
| Sealing key (SEC-2) | OTP SRK via VC mailbox, carved by EL2 stage-2 | secure OTP (HUK) is secure-world only. Non-secure OTP has no secret | **design gap.** Either a small BL31 SiP call (our TF-A fork) returns a derived key once per boot to hboot at EL2, or the sealing key goes to a discrete TPM later (ADR 0064 board has one). Decision needed (D-M5-4) |
| DMA isolation | BCM2712 IOMMU (address-ceiling fence; DSN-1 says it is weak) | **no SMMU at all** | Follows the existing doctrine (`HEQK_REMEDIATION_PLAN.md` X5, `DEVICE_CLASS_TRANSPORT.md` H4): DMA addresses are kernel-authored only, rings read-only to EL0, and **no untrusted radio as a bus-mastering PCIe peer**. NVMe (trusted storage, kernel-owned queues) is acceptable. A PCIe Wi-Fi card (BE200) is not, which is another reason for SDIO Wi-Fi on this board |
| TRNG | RNG200 | Rockchip TRNG @ 0x2a41_0000 | same DRBG seeding contract; health tests stay in heqk |
| Watchdog for A/B trial | BCM PM watchdog via hboot `hvc #1/#3` | DW-WDT @ 0x2ace_0000 | hboot's gate stays the same, with a new backend |
| A/B slot select | Pi `tryboot` + `config.txt` `kernel=` line | none in firmware | hboot owns A/B itself: slot header + boot counter in SPI-NOR or a UFS/SD partition, with the watchdog as the arbiter. This is what ADR 0064 D5 already anticipates |

## 8. Bench kit and day-one plan

**Buy with the board (amazon.de or EU distributors):**
- NanoPi M5, **8 GB LPDDR5, without UFS**. LPDDR5 is the open DDR-init RFC's primary target, and the closed blob covers it
  either way. The 4 GB LPDDR4X board is fine if price matters. The DDR blob is one file for both.
- USB-to-TTL adapter **3.3 V, ≥1.5 Mbaud**: CP2102N, FT232RL or CH343. **Not** the original CP2102 or PL2303, which
  cannot do 1.5 Mbaud. 3-pin header: GND, TX, RX.
- USB-C PD supply, 27–30 W (≥15 W required, 6–20 V).
- USB-A↔USB-A cable for maskrom on the OTG port (DRD0, reportedly the **top** USB-A socket; confirm on the bench).
- 2× microSD UHS-I (one for U-Boot env/images, one spare).
- 5 V 30 mm fan with a 2-pin JST ZH 1.5 mm plug, plus an RK3576 heatsink.
- The Verbatim 512 GB NVMe goes in the **M-key** slot. An M.2 thermal pad is optional, since a Gen2 ×1 link stays cool.
- Wi-Fi, in order of preference: **Radxa Wireless Module A2** (AP6256 / BCM43456, the same BCM4345 family as our
  CYW43455, SDIO + UART, U.FL; about €8 at RS / TME) plus 2× U.FL antennas. Its pinout has to be checked against
  schematic p22 before relying on it. FriendlyElec's own AC200 module is RTL8822CS (a new Realtek driver).
- **Do not buy the "BE200HMW" mini-PCIe card.** It is not an Intel SKU and the M5 has no mini-PCIe. If a BE200 is
  wanted for a later board, buy a genuine **BE200NGW** (M.2 2230 E-key, MHF4 antennas).

**Day one (before any heqk code runs):**
1. Serial at 1 500 000 8N1. Boot the stock FriendlyElec image from microSD with the switch on UFS/SD (their image carries
   the boost-patched loader). Capture the full boot log, `/proc/device-tree`, `dmesg`, `lspci -vv` (NVMe link
   Gen2 ×1), `cat /proc/iomem`, CNTFRQ, and the PHY IDs (`0x001cc916` RTL8211F expected). This is the reference
   behaviour we validate against (the "passes QEMU, fails on metal" lesson).
2. Build mainline U-Boot (released tag ≥ v2026.07) + upstream TF-A ≥ v2.13 + rkbin DDR v1.13. Enter maskrom and write
   `u-boot-rockchip-spi.bin` to SPI-NOR. Set the switch to **FSPI**. Confirm that U-Boot sees SD, NVMe and both GMACs, and
   that `bdinfo` and `fdt print /memory` match §4.
3. First heqk milestone **M5-0**: U-Boot `booti` of a minimal heqk/hboot image that prints on UART0 at EL2,
   takes RAM from the FDT, and blinks the SYS LED. Nothing else.

## 9. heqk code delta (from a read-only audit of the tree, 2026-11-26)

Today one aarch64 board is selected **at compile time** with the `cm5` feature (599 cfg sites, 238 in
`kernel/src/main.rs`), and there are two different `kmain`s. The kernel crate makes **939 direct `arch_aarch64::` calls**
(console 244, NICs 148, MMU 124, protocol engines that live in the arch crate 111, firmware/SoC services 106,
CPU/IRQ/timer 89, Wi-Fi 61, storage 55) and has 83 inline `asm!`. That is the ADR 0064 **H1** work, and it must come first.

Things that are already portable:
- **CNTFRQ** is always read, never assumed.
- **GIC-400** register logic (`gic.rs`): only the base constants differ.
- An MMIO **16550 with reg-shift 2** already exists (`bt.rs`, the BT HCI UART), so it is the template for the DW-APB console
  (add the DW `USR` busy check, at offset 0x7C, before LCR writes).
- `boot-abi/src/fdt.rs`: a bounded, allocation-free FDT reader that parses `/memory`, `/reserved-memory`, `/cpus` and `/psci`
  (today used only by the bench `t0inv`).
- The SDIO stack above `cmd52/cmd53` (backplane, SDPCM, firmware upload, CYW43 FullMAC, AP/STA, WPA2/3).
- The `hal::BlockDev`, `Console`, `IrqController`, `Timer` and `Mmu` traits.

Things that must change for any non-CM5 board (RK3576 or RK3588):

| Item | Where | Change |
|---|---|---|
| DRAM-at-0 assumptions | `boot-abi/src/lib.rs` (BOOTINFO 0x3FFE_0000, measure log, attest, seal handoff, `KERNEL_LOAD_PA` 0x0100_0000, hboot base/stack), `kernel/linker-hboot.ld`, `crashrec.rs` REC_PA, `main.rs` crumbs/scratch | per-board layout constants (or FDT-derived), with RK3576 values above 0x4020_0000 |
| hboot EL2 MMU + stage-2 | `hboot/src/mmu.rs`, `stage2.rs` (GB0–3 Normal, GB4+ Device) | on RK3576, **GB0 is MMIO and DRAM is GB1+** (up to 16 GiB). Take the map from the FDT |
| hboot console + reset + watchdog + RNG + OTP | `hboot/src/boot.s` (PL011, BCM PM), `main.rs`, `watchdog.rs`, `rng.rs`, `mailbox.rs`, `ak_derive.rs`, `rollback.rs` | board backends: DW-APB UART, PSCI SYSTEM_RESET, DW-WDT, Rockchip TRNG, sealing-key source (§7) |
| hboot entry | currently linked absolute at 0x200000, Image-header `image_size` 4 MiB < payload | position-correct for `booti` at `kernel_addr_r`, `image_size` covering the payload |
| SMCCC conduit | `smccc.rs` uses `hvc #0`, which hits hboot's reboot gate on CM5 | add an **SMC** conduit (PSCI/SCMI go to TF-A at EL3; hboot leaves `HCR_EL2.TSC` clear) |
| A/B | Pi tryboot (`mailbox.rs`, `ota.rs`, `abboot.rs`, `hal::abslot` `kernel=heqk8-`) | hboot-owned slot header + boot counter + DW-WDT |
| SDIO host seam | `hal/src/sdio.rs` `Bus` is SDHCI-specific. `wifisrvabi` REG_HOST is raw SDHCI | trait at `cmd/cmd52/cmd53*` level; new **DW-MSHC** host (SD + SDIO) |
| PCIe | `pci.rs` is ECAM-only (cloud) | DW root complex: iATU config access, link-up via the APB LTSSM, internal MSI → SPI 283 |
| NIC | no common driver trait; `uplink.rs` hard-binds end0=GEM WAN, eth1=RTL8111 LAN | NIC trait + role binding from the board profile: GMAC0 = WAN, GMAC1 = LAN |
| Board identity | Cargo features + `cm5-boot/` + per-driver constants | a board profile crate/const table (feature `rk3576`), with the profile documented in `appliance/nanopi-m5/` |

## 10. Sources

- FriendlyElec NanoPi M5 wiki and schematics rev 2411 (LP5, LP4X): https://wiki.friendlyelec.com/wiki/index.php/NanoPi_M5
- Linux `rk3576.dtsi` / `rk3576-nanopi-m5.dts`: https://github.com/torvalds/linux/tree/master/arch/arm64/boot/dts/rockchip
- FriendlyElec vendor DTS (`rk3576-nanopi5-common.dtsi`, branch `nanopi6-v6.1.y`): https://github.com/friendlyarm/kernel-rockchip
- RK3576 TRM V1.2 Part 1/2 and datasheet V1.6 (unofficial mirror): https://rockchip.fr/ and https://github.com/DeciHD/rockchip_docs/tree/main/rk3576
- RK3576 datasheet V1.5 (FriendlyElec): https://wiki.friendlyelec.com/wiki/images/b/bf/Rockchip_RK3576_Datasheet_V1.5-20241216.pdf
- RK3576 hardware design guide notes (boot strap table): https://raw.githubusercontent.com/gregordinary/device-ref/main/rk3576/hardware-design-guide.md
- U-Boot `nanopi-m5-rk3576_defconfig`, Rockchip docs, SPL UFS: https://github.com/u-boot/u-boot ; U-Boot list, NanoPi M5: https://lists.denx.de/pipermail/u-boot/2026-May/619499.html
- U-Boot "fix boot from SDMMC on RK3576" series: https://ratatoskr.run/u-boot/2026/07/17250689/t
- U-Boot RK3576 blob-free DRAM init RFC: https://lists.denx.de/pipermail/u-boot/2026-May/619706.html
- TF-A `plat/rockchip/rk3576` (since v2.13.0): https://github.com/ARM-software/arm-trusted-firmware
- rkbin RK3576 release notes and blobs: https://github.com/rockchip-linux/rkbin
- linux-rockchip, BL31 ≥ v1.09 / 1 GHz timer mismatch: https://lists.infradead.org/pipermail/linux-rockchip/2025-June/059839.html
- linux-rockchip, ROCK 4D NVMe not detected: https://lists.infradead.org/pipermail/linux-rockchip/2025-December/066087.html , https://lists.infradead.org/pipermail/linux-rockchip/2026-January/067398.html
- RK3576 secure boot community notes: https://raw.githubusercontent.com/gahingwoo/bl32-rk3576/main/README.md ; barebox RK35xx: https://www.barebox.org/doc/latest/boards/rk35xx.html
- Radxa wireless modules (A2 = AP6256): https://docs.radxa.com/en/rock5/rock5itx/getting-started/interface-usage/pcie-e-key
- Intel BE200 spec: https://www.intel.com/content/www/us/en/products/sku/230078/intel-wifi-7-be200/specifications.html ; no half-mini BE200: https://community.intel.com/t5/Wireless/PCI-Express-Half-Mini-Card-802-11BE200/m-p/1559094
- 1.5 Mbaud USB-UART adapters: https://forum.armbian.com/topic/11332-usb-ttl-converter-for-rk3399-1500000-bps/
