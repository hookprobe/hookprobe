# appliance/nanopi-m5 — FriendlyElec NanoPi M5 (RK3576), Rockchip bench board

**Status: bench only. Ordered, arrives mid-December 2026. No heqk port yet.** Its role was decided in
[ADR 0064 A1](../../docs/adr/0064-hookprobe-hardware-program.md) (operator, 2026-11-26): an early Rockchip bench
before H2. It does not replace ADR 0064 D3's RK3588 intermediate board, and it is never a product target. **Until H0:**
bench tooling, research and the `m5probe` bring-up probe only. The heqk port (H1 and the drivers) waits for H0.

This page is only how HookProbe OS sees the board. Facts and procedures:

| What | Where |
|---|---|
| Decisions, options, driver delta | [`heqk-nanopi-m5-rk3576-investigation-2026-11-26.md`](../../docs/design/heqk-nanopi-m5-rk3576-investigation-2026-11-26.md) |
| Register map, wiring, boot chain, per-IP driver facts | [`heqk-nanopi-m5-hw-datapack-2026-11-26.md`](../../docs/design/heqk-nanopi-m5-hw-datapack-2026-11-26.md) |
| Vendor firmware facts (loader/BL31 versions, reboot-to-maskrom, vendor DT) | [`heqk-nanopi-m5-vendor-firmware-findings-2026-11-26.md`](../../docs/design/heqk-nanopi-m5-vendor-firmware-findings-2026-11-26.md) |
| Bench: relays, serial, flashing, netboot, day-one checks | [`heqk-nanopi-m5-bench-runbook-2026-11-26.md`](../../docs/design/heqk-nanopi-m5-bench-runbook-2026-11-26.md) |
| First-stage firmware (pinned U-Boot + TF-A + rkbin DDR) | [`tools/build/m5-firmware-build.sh`](../../tools/build/m5-firmware-build.sh) |
| Bring-up probe (booti payload, day one) | [`os/kernel/m5probe/`](../../os/kernel/m5probe/), [`tools/diagnostics/m5-probe-build.sh`](../../tools/diagnostics/m5-probe-build.sh) |
| Host rehearsal of the netboot chain | [`tools/diagnostics/m5-qemu-rehearsal.py`](../../tools/diagnostics/m5-qemu-rehearsal.py) |

## Ports and roles

| Port | Silicon | heqk driver needed | Role |
|---|---|---|---|
| ETH0 | RK3576 GMAC0 (DWC Ethernet QoS 4.20a) + RTL8211F-CG, RGMII-ID | DWC QoS + RTL8211F (new) | **WAN** (also the bench netboot + `mc-e2e` link) |
| ETH1 | RK3576 GMAC1 + RTL8211F-CG | same | **LAN** (test client; separation-matrix rows) |
| M.2 M-key 2280 | PCIe0 Gen2 ×1 (combo PHY 0) | DWC PCIe RC + NVMe (new) | NVMe data volume (evidence / retention) |
| M.2 E-key 2230 | SDIO (DW-MSHC, 1.8 V) + UART5 (BT) only: **no PCIe, no USB** | DW-MSHC host under the existing SDIO/CYW stack | Wi-Fi (receive-only WIDS / AP) with a BCM43456-class module |
| Debug header J1 | UART0 (DW-APB), 1 500 000 8N1 | DW-APB console (new; `bt.rs` is the MMIO 16550 template) | console |
| UFS socket · microSD · 16 MiB SPI-NOR | UFS 2.0 host · DW-MSHC · FSPI1 | later · DW-MSHC · none (U-Boot owns it) | heqk A/B slots (UFS) · recovery · first stage |
| USB-A ×2 | DWC3 (DRD0 = OTG/maskrom, DRD1 = host) | xHCI (planned, radio plan M1) | maskrom/rockusb on the bench |

## Capabilities the board would grant (once each driver passes its metal gate)

Granted from the Platform Manifest, never from the board name. Everything starts absent.

| Capability (ADR 0003 token) | Hardware | Note |
|---|---|---|
| `soc`, `ids`, `inline_ips` (two-port inline) | 2× GMAC 1 GbE | bench only |
| local retention on NVMe (storage fact) | M.2 NVMe (Gen2 ×1, ~400 MB/s) | sizes the retention window |
| `wifi`, `wifi_ap` | SDIO BCM43456-class module (Radxa A2) | Wi-Fi 5. Not the Intel BE200: it does not fit, its AP mode is 2.4 GHz only, and there is no SMMU |
| `tpm`, `tpm_sealed` | **absent**: no TPM on the board. Secure OTP is secure-world only | ADR 0064 A1 D-M5-4 |
| `edge_ai` | RK3576 NPU (6 TOPS) | not planned on the bench |

## Board facts heqk must not assume away

- **DRAM starts at 0x4000_0000**, and the first 2 MiB belong to TF-A (BL31, SCMI shmem, ATAGs). RAM comes from the FDT
  `/memory` node, never a constant.
- **Entered at EL2 by U-Boot `booti`, x0 = FDT.** The image must be position-independent or linked above 0x4020_0000.
- **GIC-400 (GICv2)**, arch timer **24 MHz**. CPU DVFS is SCMI to BL31 over SMC `0x8200_0010`.
- **No SMMU:** no PCIe radio as a bus master; DMA addresses stay kernel-authored.
- **Reboot-to-maskrom:** `0xEF08A53C` → `0x2602_4040`, then reset.
- **SYS LED** GPIO2_B3 · user key GPIO1_A0 · PCIe PERST GPIO2_B4, slot power GPIO0_D3, card-present GPIO4_C4.
- No EUI-48 EEPROM fitted: the MACs are derived (from the OTP chip ID, as U-Boot does).
