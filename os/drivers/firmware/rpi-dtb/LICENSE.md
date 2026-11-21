# Source and licence for the CM5 device tree

This file is third-party: it is **not** HookProbe software and is **not** covered by HookProbe's
AGPL-3.0 licence. It is a separate file that sits next to the heqk image on the boot partition (it is
not linked into heqk), and it is redistributed under the licence of the sources it was compiled from.

## The file

| File | sha256 | Licence of the compiled file |
|---|---|---|
| `bcm2712-rpi-cm5-cm5io.dtb` | `2ca3879fc05b8211313d7c60c49ab84626cb14f26ad0ee8e1a0c6e1bf439d11e` | **GPL-2.0** (the strictest licence among its sources; see below) |

Built from `arch/arm64/boot/dts/broadcom/bcm2712-rpi-cm5-cm5io.dts` in
[raspberrypi/linux](https://github.com/raspberrypi/linux), branch `rpi-6.12.y`, commit
[`a923c1dcd822385aaa82a4388c6a6ad92cbf9280`](https://github.com/raspberrypi/linux/tree/a923c1dcd822385aaa82a4388c6a6ad92cbf9280)
(source tarball sha256 `0564f61dc5a5648acb4378509bf3d74e6ad25ab49e05008c7295ebc0b6669948`), compiled by
`dtc` in the kernel build (`make dtbs`). No HookProbe change was made to the sources.

## Licence of each source component

Every file the build read to produce the blob: the `.dts`, the `.dtsi` it includes, and the
`include/dt-bindings/` headers they include. SPDX tags, copyright lines and sha256 are from that commit
(fetched 2026-11-21 from `raw.githubusercontent.com/raspberrypi/linux/a923c1dc…`).

| Source file (at the commit above) | SPDX licence | Copyright line in the file | sha256 |
|---|---|---|---|
| `arch/arm64/boot/dts/broadcom/bcm2712-rpi-cm5-cm5io.dts` | GPL-2.0 | none | `8c90bd9e9939d7d9c3d79985ed27509f5169a7b228ed64eed9a80a3ddf9791f5` |
| `arch/arm64/boot/dts/broadcom/bcm2712-rpi-cm5io.dtsi` | GPL-2.0 | none | `4ed09181b3abc6a6f6fb812d6e70c15e21f4b5470b73b117333030d2e39cc8ff` |
| `arch/arm64/boot/dts/broadcom/bcm2712-rpi-cm5.dtsi` | GPL-2.0 OR MIT | none | `49fcba37bfa6e79072b736fffafc28f62ca6d233507918ea353d4784371bbcc1` |
| `arch/arm64/boot/dts/broadcom/bcm2712-rpi.dtsi` | GPL-2.0 | none | `874963e6586489a6cad16c148499dc93eb77de5f8ce26e37cda7e5e2f37dd7f7` |
| `arch/arm64/boot/dts/broadcom/bcm2712-ds.dtsi` | GPL-2.0 | none | `1198e9d8b68497e93f7f0463a39801a269a5b5dc9ef0b4e98579d2ffb65b88a0` |
| `arch/arm64/boot/dts/broadcom/bcm2712.dtsi` | GPL-2.0 OR MIT | none | `bd550720b792927a5d8a925688b0f662e700a8693e9907268936ddf43e504da0` |
| `arch/arm64/boot/dts/broadcom/rp1.dtsi` | no tag: the kernel's default, GPL-2.0 (`COPYING`) | none | `ab3fe239e9a62742d035187ec50f65ec769cff002788f0e12b2afcad0bbaf460` |
| `include/dt-bindings/clock/rp1.h` | GPL-2.0 | 2021 Raspberry Pi Ltd. | `ba427771249297a45ef7978a390ba3c4bcdb0f526e32f035e200fcc074f01c69` |
| `include/dt-bindings/gpio/gpio.h` | GPL-2.0 OR BSD-2-Clause | none | `5423b3866877ead0920ec978b5b072f06087443033a72445b39faed8f288ddc1` |
| `include/dt-bindings/interrupt-controller/arm-gic.h` | GPL-2.0 OR MIT | none | `80dc56e8aa61b3681ee42fb0bfd34bf35ea2578ac6d82f1fa972b963667e8ff7` |
| `include/dt-bindings/interrupt-controller/irq.h` | GPL-2.0 OR MIT | none | `392400a309a54ea5b1a2ac2e52773d3ab68e07323109b9aed88a69fedc74e082` |
| `include/dt-bindings/mfd/rp1.h` | GPL-2.0 | none | `8e454c1af9fd4e87e05d03ca2de029c217917a6e1ae997e9d61c1bd63ba4e214` |
| `include/dt-bindings/power/raspberrypi-power.h` | GPL-2.0 | 2015 Broadcom | `eae21118acf3c5ec97e48b81424cbaadeb9391f3a5cba3b8aba7badb3a62d2e6` |
| `include/dt-bindings/pwm/pwm.h` | GPL-2.0 | none | `7f76b7b4f29c24cc87710f60cff99e0ac571ed7b6fa69dc127ae370dabd8546a` |
| `include/dt-bindings/reset/raspberrypi,firmware-reset.h` | GPL-2.0 | 2020 Nicolas Saenz Julienne | `b5fed4b44b6e23a3e8596cf3de21d06586ae7ea74289515a5ec6775bf8d2b5b9` |
| `include/dt-bindings/soc/bcm2835-pm.h` | GPL-2.0+ OR MIT | none | `afbc90d64fc82a3e0a2de961a3c845c78971695b565d2c7f4683db8fdb3f008f` |

The dual-licensed files could be used under MIT or BSD-2-Clause alone, but six files (and `rp1.dtsi`,
untagged) are GPL-2.0 only, so the compiled blob as a whole is distributed under **GPL-2.0**. The
`dt-bindings` headers contribute only numeric constants. Copyright in the files with no copyright line
belongs to their authors as recorded in the raspberrypi/linux git history.

Licence texts, copied unchanged from `LICENSES/preferred/` at the same commit:
[`../LICENSES/GPL-2.0.txt`](../LICENSES/GPL-2.0.txt), [`../LICENSES/MIT.txt`](../LICENSES/MIT.txt),
[`../LICENSES/BSD-2-Clause.txt`](../LICENSES/BSD-2-Clause.txt).

## Corresponding source (kept here)

All 16 source files are copied unchanged into [`source/`](source/), at their upstream paths, with
[`source/SHA256SUMS`](source/SHA256SUMS) (105 KB in all). They rebuild the shipped blob **byte for byte**
(checked 2026-11-21 with DTC 1.8.1 on macOS; `-@` keeps the overlay symbols, as the Raspberry Pi build does):

```sh
cd os/drivers/firmware/rpi-dtb
cpp -nostdinc -I source/arch/arm64/boot/dts/broadcom -I source/include -undef -D__DTS__ \
    -x assembler-with-cpp -P source/arch/arm64/boot/dts/broadcom/bcm2712-rpi-cm5-cm5io.dts -o /tmp/cm5io.dts
dtc -q -I dts -O dtb -@ -o /tmp/cm5io.dtb /tmp/cm5io.dts
shasum -a 256 /tmp/cm5io.dtb   # 2ca3879fc05b8211313d7c60c49ab84626cb14f26ad0ee8e1a0c6e1bf439d11e
```

## What GPL-2.0 asks of anyone who ships this file

1. **Licence text:** a copy of GPL-2.0 goes with the image ([`../LICENSES/GPL-2.0.txt`](../LICENSES/GPL-2.0.txt)).
2. **Corresponding source:** GPL-2.0 §3 asks a commercial distributor to ship the source with the
   binary (§3(a)) or give a written offer for it (§3(b)); pointing at upstream (§3(c)) is for
   non-commercial distribution only. The complete source is in `source/` above, and it is published in
   this public repository at the same commit as the image build. Putting `source/` and the licence text
   on the image's boot partition as well (or in the release assets) meets §3(a) for every image on its own.

## History and use

**History.** Built by the Linux-tier kernel build (6.12.94 `hookprobe-edge`)
(`legacy/linux-tier/builder/kernel-build/`, removed 2026-11-20; in git history) and kept in its `out/`
folder. Moved here unchanged on 2026-11-20 (AB-21 step 1) so the factory disk image no longer depends
on `legacy/`.

**Use.** `os/build/make-cm5-heqk-disk.sh` copies it to the FAT boot partition in the default ("proven")
layout. `--zero-linux` builds without it. heqk itself never parses a devicetree; the CM5 firmware uses
it to train the RTL8111 (eth1) PCIe link. Running without it (`--zero-linux`) is still metal-unproven.
