# appliance/waveshare-dual-eth — Waveshare CM5-DUAL-ETH-MINI

The bench carrier board for the CM5.

| Port | Chip | heqk driver | Role |
|---|---|---|---|
| RJ45 **furthest** from USB-C (`end0`) | RP1 GEM (PCIe RC2, firmware-trained) | [`gem.rs`](../../os/kernel/arch-aarch64/src/gem.rs) | WAN / Mission Control node |
| RJ45 **nearest** USB-C (`eth1`) | Realtek RTL8111H (PCIe RC1) | [`rtl8111.rs`](../../os/kernel/arch-aarch64/src/rtl8111.rs) | LAN |
| Onboard Wi-Fi/BT | CYW43455 | [`cyw43.rs`](../../os/kernel/arch-aarch64/src/cyw43.rs) | AP / STA |

Details: [`RP1_ETH2_RTL8111.md`](../../os/kernel/RP1_ETH2_RTL8111.md). Note that the zero-Linux
image (`--zero-linux`, no devicetree) leaves the RTL8111 PCIe link untrained by firmware.
That is fine for the passive-first GEM profile (ADR 0037 D4).
