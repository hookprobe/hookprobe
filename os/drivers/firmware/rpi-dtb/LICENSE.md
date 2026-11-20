# Source and licence for the CM5 device tree

This file is third-party: it is **not** HookProbe software and is **not** covered by HookProbe's
AGPL-3.0 licence. It is redistributed under the licence of the sources it was compiled from.

| File | sha256 | Built from | Licence |
|---|---|---|---|
| `bcm2712-rpi-cm5-cm5io.dtb` | `2ca3879fc05b8211313d7c60c49ab84626cb14f26ad0ee8e1a0c6e1bf439d11e` | `arch/arm64/boot/dts/broadcom/bcm2712-rpi-cm5-cm5io.dts` in [raspberrypi/linux](https://github.com/raspberrypi/linux) branch `rpi-6.12.y` at commit [`a923c1dcd822385aaa82a4388c6a6ad92cbf9280`](https://github.com/raspberrypi/linux/tree/a923c1dcd822385aaa82a4388c6a6ad92cbf9280/arch/arm64/boot/dts/broadcom) (source tarball sha256 `0564f61dc5a5648acb4378509bf3d74e6ad25ab49e05008c7295ebc0b6669948`), compiled by `dtc` in the kernel build (`make dtbs`) | GPL-2.0 |

**Licence of the sources** (SPDX tags at that commit): `bcm2712-rpi-cm5-cm5io.dts`, `bcm2712-rpi-cm5io.dtsi`,
`bcm2712-rpi.dtsi`, `bcm2712-ds.dtsi` are `GPL-2.0`; `bcm2712-rpi-cm5.dtsi`, `bcm2712.dtsi` are
`GPL-2.0 OR MIT`; `rp1.dtsi` carries no SPDX tag. The compiled blob is therefore GPL-2.0. The
corresponding source is the public commit above; anyone who ships this file in an image must be able
to point to it.

**History.** Built by the Linux-tier kernel build (6.12.94 `hookprobe-edge`) (`legacy/linux-tier/builder/kernel-build/`, removed
2026-11-20; in git history) and kept in its `out/` folder. Moved here unchanged on 2026-11-20 (AB-21 step 1)
so the factory disk image no longer depends on `legacy/`.

**Use.** `os/build/make-cm5-heqk-disk.sh` copies it to the FAT boot partition in the default ("proven")
layout. `--zero-linux` builds without it. heqk itself never parses a devicetree; the CM5 firmware uses
it to train the RTL8111 (eth1) PCIe link. Running without it (`--zero-linux`) is still metal-unproven.
