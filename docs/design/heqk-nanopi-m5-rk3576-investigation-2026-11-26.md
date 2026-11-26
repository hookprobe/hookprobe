# heqk on the FriendlyElec NanoPi M5 (RK3576) + Intel BE200 + Verbatim 512 GB NVMe: investigation

**Date:** 2026-11-26 · **Status:** investigation (Green: analysis only, no code). Nothing is decided here.
**Related:** ADR 0047 (heqk everywhere), ADR 0064 (hardware program, gates H0–H5),
`docs/design/heqk-radio-drivers-qcn9274-em9293-plan-2026-11-23.md`, `docs/design/heqk-everywhere-report-2026-10-09.md`.

## 0. Bottom line

1. **The hardware combination as proposed does not fit the board.** The NanoPi M5 has **one** PCIe slot, an M.2 M-key
   at **PCIe 2.1 ×1**. Its M.2 **E-key slot is SDIO + UART only, with no PCIe**. It has **no mini-PCIe slot**. The BE200 is a
   PCIe device, so the BE200 and the NVMe SSD cannot both sit on PCIe. One of them has to move (see §3).
2. **The BE200 is a poor fit for HookProbe's job, whatever the board.** Under Linux `iwlwifi`, Intel AP mode is
   officially **2.4 GHz only**, because the firmware's LAR (location-aware regulatory) marks 5/6 GHz as no-IR. Users report
   that 6 GHz AP stays locked even on a Pi 5. HookProbe's SASE edge default is "the device is the Wi-Fi AP", and Intel
   enforces this in firmware, so a clean-room heqk driver cannot fix it. The BE200 is a good **client/monitor**
   radio (receive-only WIDS sensor). It is not an AP radio. ADR 0064 already chose QCN9274 (ath12k) for AP.
3. **The RK3576 is not the SoC ADR 0064 picked.** ADR 0064 D3 wants a *same-SoC* (RK3588) intermediate board before
   our board, and the ROCK 5B is suggested. The M5 is a sibling SoC. It shares most IP blocks (DWC PCIe, dwcmshc, DW-APB UART,
   GMAC, Rockchip CRU/GRF/OTP, BootROM chain) but not the GIC (GIC-400 vs GIC-600), the PCIe generation, or the
   Ethernet design. Choosing it is an operator call against ADR 0064 D3, and **all Rockchip driver work is gated on
   H0 (CM5 validated)**, which is not green yet.
4. **If the operator wants it anyway**, the M5 is a reasonable *cheap Rockchip bench*. About 60–70% of the
   driver work carries over to RK3588. The heqk port is ~10 new drivers plus a new boot chain (§4). The BE200 itself
   would be the single largest item and the one with the worst payoff.

## 1. What the board actually is (FriendlyElec wiki, 2411 schematics)

| Item | NanoPi M5 | heqk relevance |
|---|---|---|
| SoC | Rockchip **RK3576**: 4× A72 + 4× A53, Mali-G52 MC3, 6 TOPS NPU | new SoC for heqk (CM5 is BCM2712, 4× A76) |
| RAM | 4 GB LPDDR4X or 8/16 GB LPDDR5 (32-bit) | DDR init = closed rkbin TPL blob (§4.1) |
| Boot storage | **UFS 2.0 (optional)**, microSD (UHS-I), 16 MB SPI-NOR. **The SoC cannot boot from M.2 or USB** | UFS host or SD host needed. NVMe is data-only |
| M.2 M-key | **PCIe 2.1 ×1**, "for SSDs" | the only PCIe on the board, ~400 MB/s ceiling |
| M.2 E-key | **"SDIO and an UART, supports SDIO wifi"** (RTL8822CS module offered) | **no PCIe**: a BE200 cannot go here |
| Ethernet | 2× 1 GbE (SoC GMACs + RTL8211F PHYs per BSP notes) | stmmac/DWMAC driver, *not* RTL8125 as on our board |
| USB | 2× USB 3.2 Gen1 Type-A | xHCI (already planned, radio plan M1) |
| Debug UART | UART0_M0, 3-pin header, 3.3 V, **1 500 000 baud** | DW-APB 8250 (16550-class, MMIO) |
| RTC | HYM8563 over I²C | I²C driver |
| Power | USB-C PD or DC, 6–20 V | PD-negotiated; fine for bench |
| Vendor BSP | Linux 6.1.y, U-Boot 2017.09 (`nanopi5-v2017.09`, `nanopi_m5_defconfig`) | reference only (GPL) |
| Mainline | Armbian boots the M5 from UFS on **mainline U-Boot** (2026). A NanoPi M5 U-Boot board patch is on the list (May 2026) | gives us an open SPL/U-Boot to chain `hboot` from |

RK3576 PCIe: two PCIe 2.1 ×1 controllers on combo PHYs. Lane 0 is PCIe/SATA, lane 1 is PCIe/SATA/USB3. Each
controller is DWC (`rockchip,rk3576-pcie`, fallback `rk3568-pcie`), and **MSIs go straight to the GIC, with no ITS**.
That means the DWC internal MSI controller, not GICv3 ITS/LPIs.

## 2. The parts

**Intel BE200.** Intel ships it as an M.2 2230 E-key card (BE200NGW, PCIe + USB for BT). A "BE200HMW" half-mini-PCIe
card is **not an Intel SKU**. Intel makes no HMW form factor, and those listings are third-party repackagings or
adapter assemblies. (The AliExpress page loads by script and could not be read, so its exact form factor is unverified.)
Linux: `iwlwifi` + MLD op-mode, supported since 6.5. Works on Raspberry Pi 5 (ARM) once the firmware is installed,
with reports of firmware-induced driver restarts. AP limits as in §0.2. Bluetooth is a **USB** device on the card,
so it is lost behind any PCIe-only adapter.

**Verbatim 512 GB NVMe.** Any current Verbatim NVMe (Vi3000/Vi5000 class) will link at PCIe 2.1 ×1 on the M5, about
**~400 MB/s**. That is plenty for the evidence/pcap retention tier (ADR "bounded & honest retention"). heqk has **no NVMe
driver today**. NVMe is a small, well-specified driver and is on ADR 0064 D4's list anyway.

## 3. Making the radio + SSD fit: options

| Option | Wi-Fi | Storage | Verdict |
|---|---|---|---|
| **A. SDIO Wi-Fi in E-key, NVMe in M-key** | SDIO module (E-key) | NVMe on PCIe | **Recommended if the M5 is used.** Keeps the SSD on PCIe. heqk already has the full CYW43455 FullMAC stack (`cyw43.rs`, `hal::sdio`, WPA2/SAE, AP mode metal-proven on CM5); only a DW-MSHC host under it is new. Candidate: **Radxa Wireless Module A2** (AP6256 = BCM43456, same BCM4345 family, ~€8); its pinout still has to be checked against sch p22. FriendlyElec's own AC200 (RTL8822CS) needs a new Realtek SoftMAC driver. Wi-Fi 5 only. |
| B. BE200 in M-key (M→E adapter), SSD over USB 3 | BE200, PCIe 2.1 ×1 (~3.2 Gb/s usable) | USB-NVMe enclosure (xHCI + UAS/BOT) | Works electrically. Costs a clean-room iwlwifi-class driver **and** USB mass storage, and still has no 5/6 GHz AP. BT is lost unless the adapter wires USB. Not recommended. |
| C. NVMe in M-key, USB Wi-Fi 7 dongle | USB Wi-Fi 7 | NVMe | Few USB Wi-Fi 7 chips have open drivers. Same new-driver cost. Not recommended. |
| D. Change the board | — | — | A board with M.2 E-key **PCIe** *and* M-key NVMe (e.g., ROCK 5B, the ADR 0064 suggestion) fits a PCIe Wi-Fi 7 card and the SSD together and is the same SoC as our board. |

## 4. heqk port: driver and boot-chain delta for RK3576

What heqk already has that applies (in `os/kernel/arch-aarch64/src`): GICv2/GIC-400 (`gic.rs`, used by CM5),
arch timer, MMU, exception/EL0 model, SDHCI core (`sdhci.rs`/`emmc.rs`), SDIO + CYW43455 Wi-Fi, a minimal ECAM PCI
layer (`pci.rs`, cloud tier, firmware-assigned BARs), an IOMMU skeleton (`iommu.rs`), and a 16550 driver on x86
(`arch-x86_64/src/io.rs`, port-I/O).

| # | Work item | Size | Carries to RK3588? | Notes |
|---|---|---|---|---|
| 0 | **H1 HAL decoupling** (kernel stops calling `arch_aarch64::` directly) | M | yes | Prerequisite for any second aarch64 board (ADR 0064 H1) |
| 1 | **Boot chain**: BootROM → rkbin DDR TPL (closed) → mainline U-Boot SPL → upstream TF-A BL31 → `hboot` → heqk; A/B + rollback replacing `config.txt`/tryboot | M–L | yes (same scheme) | Upstream TF-A reportedly works as RK3576 BL31 (May 2026). An open DDR-init RFC exists but is unmerged, so the DDR blob is recorded as an unverifiable vendor blob, like CM5's VideoCore |
| 2 | GIC-400 at RK3576 base | S | no (RK3588 = GIC-600/v3, already have `gic_v3.rs`) | reuse `gic.rs`, parametrise base from the board profile |
| 3 | DW-APB UART (8250, MMIO, 32-bit stride, 1.5 Mbaud) | S | yes | port the x86 16550 logic to MMIO |
| 4 | Clocks/resets/pinctrl/GRF: **lean on U-Boot's setup first** (the `pci.rs` "firmware already did it" stance) | S → M | mostly | full CRU/PMIC (RK806) + DVFS later. This is the hidden cost of Rockchip ports |
| 5 | Boot medium: **SD** (RK3576 SD/SDIO = **dw_mmc**, not SDHCI) or **UFS** (UFSHCI + Rockchip glue) | M (SD) / L (UFS) | dwcmshc eMMC differs; UFS no | SD is the cheaper first target. UFS is the production target on the M5 |
| 6 | **DWC PCIe root complex** + Rockchip glue + combo PHY, iATU config access (not plain ECAM), DWC internal MSI | M–L | **yes** (RK3588 same IP, Gen3) | first step: inherit U-Boot's link-up + config, as `pci.rs` does with edk2 |
| 7 | **NVMe** (admin + 1 I/O queue pair, polled → MSI) | M | yes | data volume / retention tier. Also unblocks N100/x86 |
| 8 | **GMAC (stmmac/DWMAC) + RTL8211F PHY over MDIO** ×2 | M | partly (RK3588 has GMACs, our board uses RTL8125) | gives the WAN + LAN pair the separation matrix needs |
| 9 | DMA isolation for PCIe/EL0 drivers | S (policy) | n/a (RK3588 has an Arm MMU-600 for PCIe, disabled in mainline DT; verify) | **Resolved: RK3576 has no SMMU.** DMA addresses stay kernel-authored (DEVICE_CLASS_TRANSPORT H4). No untrusted PCIe radio. Whether the DWC inbound iATU could act as a coarse DMA window is a research idea for the security-auditor *(unverified)* |
| 10 | Rockchip TRNG + OTP (sealing key, SEC-2 equivalent) | S–M | yes | device identity HKDF source changes, interface unchanged |
| 11 | xHCI (+ BT on USB if a card needs it) | M | yes | already plan M1 in the radio-drivers doc |
| 12 | **BE200 driver** (clean-room iwlwifi/MLD-class: context-info gen3 boot, TLV firmware, TFH queues, MLD command set, regulatory) | **XL** | n/a (we chose QCN9274) | Linux driver is GPL-2.0, so clean-room only. Biggest item, and the firmware still forbids 5/6 GHz AP |

**Rough sequencing (if approved):** 0 → 1 → 2/3 (serial console on metal) → 4 → 5 (SD boot) → 8 (one GMAC:
`mc-e2e` over the wire) → 6 → 7 (NVMe) → 10 → separation-matrix rows without Wi-Fi → option-A SDIO Wi-Fi. The
BE200 (12) only comes in as a receive-only monitor sensor, if at all.

## 5. Decisions for the operator

- **D-M5-1:** Use the NanoPi M5 (RK3576) as a Rockchip bench, or keep ADR 0064 D3's same-SoC RK3588 board (ROCK 5B)?
  The M5 is cheaper and its IP mostly carries over, but it validates a different SoC than our board. Taking it needs an
  ADR 0064 amendment. Either way it starts **after H0**.
- **D-M5-2:** Radio: drop the BE200 for AP duty (recommended). Use QCN9274 per ADR 0064, or option A (SDIO) on the M5.
  Keep the BE200 only as a candidate receive-only WIDS sensor.
- **D-M5-3:** Storage: Verbatim 512 GB NVMe in the M-key slot as the DataVolume/retention tier, with boot from SD/UFS
  (the SoC cannot boot from NVMe). Recommended.

- **D-M5-4:** Sealing key on RK3576. Secure OTP (HUK) is secure-world only, so choose between a small SiP call in our
  upstream-TF-A build (hands hboot a derived key once per boot) and deferring sealing to a discrete TPM (the ADR 0064 board
  has one). The bench works without it, since non-sealed builds are fine for M5-0…M5-n.

## 6. Verification items: resolved 2026-11-26

All the hardware facts are in **`heqk-nanopi-m5-hw-datapack-2026-11-26.md`** (register map, wiring, boot chain, driver
facts, bench kit, heqk code delta).

| Item | Result |
|---|---|
| SMMU in front of PCIe | **None.** It is absent from both the mainline and Rockchip BSP `rk3576.dtsi`. The GIC is GIC-400 and there is no ITS. PCIe DMA cannot be confined, so no untrusted radio may be a PCIe bus master (doctrine X5). NVMe with kernel-owned queues is acceptable |
| M-key wiring | PCIe0 on combphy0, lane 0 only, PERST# `GPIO2_B4`, slot power enable `PCIE0_PWREN_H`; combphy1 = USB 3 |
| E-key wiring | **schematic-confirmed SDIO + UART5 only**: PCIe and USB pins are no-connect; 32 kHz LPO is wired from the RTC |
| GMAC/PHY | 2× RTL8211F-CG, RGMII-ID, MDIO addr 1 |
| "BE200HMW" | third-party half-mini-PCIe card, not an Intel SKU; **cannot be fitted to the M5 at all**. Do not buy |
| PCIe/NVMe stability | U-Boot has NVMe on the M5. The ROCK 4D mainline-Linux miss resolved after re-flashing mainline U-Boot, with no root cause published, so heqk fully resets PCIe itself |
| Documentation | RK3576 TRM V1.2 Parts 1 and 2 are publicly mirrored (unofficial); OTP/TRNG/crypto are not in it |
| Boot media | BootROM SD boot is unreliable on RK3576, so the first stage goes in SPI-NOR (switch = FSPI) |

## Sources

- FriendlyElec, NanoPi M5 wiki: https://wiki.friendlyelec.com/wiki/index.php/NanoPi_M5
- CNX Software, NanoPi M5 (E-key = SDIO): https://www.cnx-software.com/2025/05/26/nanopi-m5-a-rockchip-rk3576-sbc-with-hdmi-dual-gbe-m-2-nvme-and-sdio-wifi-sockets-ufs-2-0-storage-support/
- Rockchip RK3576 brief datasheet: https://www.rock-chips.com/uploads/pdf/2024.3.18/192/RK3576%20Brief%20Datasheet%20V1.2-20240311.pdf
- Armbian, native UFS boot on NanoPi M5: https://blog.armbian.com/native-ufs-boot-lands-on-the-nanopi-m5/
- Collabora, mainline Rockchip year in review (2026): https://collabora.com/news-and-blog/blog/2026/03/02/running-mainline-linux-u-boot-and-mesa-on-rockchip-a-year-in-review
- U-Boot list, RK3576 blob-free TPL DRAM init RFC: https://lists.denx.de/pipermail/u-boot/2026-May/619706.html
- U-Boot list, NanoPi M5: https://lists.denx.de/pipermail/u-boot/2026-May/619499.html
- linux-rockchip, Rock 4D NVMe not detected in mainline: https://lists.infradead.org/pipermail/linux-rockchip/2025-December/066088.html
- RK3576 PCIe DT binding (MSI direct to GIC): https://lkml.rescloud.iu.edu/2502.3/04388.html
- Linux wireless docs, iwlwifi (AP 2.4 GHz only, LAR): https://wireless.docs.kernel.org/en/latest/en/users/drivers/iwlwifi.html
- BE200 on Raspberry Pi 5 (geerlingguy issue #670): https://github.com/geerlingguy/raspberry-pi-pcie-devices/issues/670
- Jeff Geerling, Wi-Fi 7 on Pi 5: https://www.jeffgeerling.com/blog/2025/exploring-wifi-7-2-gbps-on-raspberry-pi-5/
- Intel Community, BE200 iwlwifi restarts on Pi 5: https://community.intel.com/t5/Wireless/iwlwifi-linux-driver-reboot-crush-on-Raspberry-Pi5-with-WiFi7/m-p/1729141
- Intel Community, half-mini-card BE200 request: https://community.intel.com/t5/Wireless/PCI-Express-Half-Mini-Card-802-11BE200/m-p/1559094
