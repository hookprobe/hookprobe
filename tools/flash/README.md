# tools/flash — writing an image to a CM5

The flash scripts live with the CM5 boot files in
[`os/kernel/cm5-boot/`](../../os/kernel/cm5-boot/) because they locate those files and the
bundled `usbboot` (`os/kernel/tools/usbboot/`) by relative path.

| Script | Use |
|---|---|
| `flash-image.sh <img> --backup <file>` | **Recommended.** Guarded whole-eMMC write of a factory image, with read-back verification |
| `flash-now.sh` | Copy only the boot set (`config.txt`, `heqk8.img`, `tryboot.txt`) onto the boot partition |
| `flash-clean.sh` | Archive the existing Linux partitions, then install heqk |
| `ab-update.sh` | Stage slot B and set up a tryboot |

All of them erase or modify the device, so the operator runs them (`sudo`). Serial console:
see [`tools/diagnostics/`](../diagnostics/).
**Not built yet:** the WebUSB browser flasher (ADR 0037).
