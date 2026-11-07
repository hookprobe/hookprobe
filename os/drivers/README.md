# os/drivers — hardware drivers (index)

The code lives in the heqk workspace (`../kernel/arch-aarch64/src/`). This folder also holds the
**Wi-Fi/BT firmware** that heqk stages into the image.

| Hardware | Source | Notes |
|---|---|---|
| RP1 Gigabit Ethernet (GEM, `end0`) | [`gem.rs`](../kernel/arch-aarch64/src/gem.rs) | [RP1_GEM_BRINGUP.md](../kernel/RP1_GEM_BRINGUP.md) |
| 2nd Ethernet RTL8111H (`eth1`, Waveshare dual-ETH) | [`rtl8111.rs`](../kernel/arch-aarch64/src/rtl8111.rs) | [RP1_ETH2_RTL8111.md](../kernel/RP1_ETH2_RTL8111.md) |
| Wi-Fi CYW43455 (STA + AP, WPA2) | [`cyw43.rs`](../kernel/arch-aarch64/src/cyw43.rs), [`wpa.rs`](../kernel/arch-aarch64/src/wpa.rs) | [P9_P10_BRINGUP.md](../kernel/P9_P10_BRINGUP.md) |
| Bluetooth | [`bt.rs`](../kernel/arch-aarch64/src/bt.rs) | [P10BT_REFERENCE.md](../kernel/P10BT_REFERENCE.md) |
| eMMC / SD | [`emmc.rs`](../kernel/arch-aarch64/src/emmc.rs), [`sdhci.rs`](../kernel/arch-aarch64/src/sdhci.rs) | [SEALED_STORAGE.md](../kernel/SEALED_STORAGE.md) |
| RP1 GPIO / I2C / SPI / UART | `rp1*.rs`, [`uart.rs`](../kernel/arch-aarch64/src/uart.rs) | [PERIPHERAL_BUSES.md](../kernel/PERIPHERAL_BUSES.md) |
| HW RNG, GIC, timer, mailbox, IOMMU | `rng200.rs`, `gic.rs`, `timer.rs`, `mailbox.rs`, `iommu.rs` | |
| QEMU virtio (net, blk) | `virtio*.rs` | the QEMU target |

**Firmware:** [`firmware/brcm-firmware-rpt/`](firmware/brcm-firmware-rpt/) holds the CYW43455 blobs.
`../kernel/cm5-boot/stage-wifi-firmware.sh` copies them into `../kernel/firmware/brcm/` before a build.
