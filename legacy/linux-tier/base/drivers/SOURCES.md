# Vendored out-of-tree USB-Wi-Fi dongle drivers — sources & pinned commits

> Vendored by `builder/mkosi-arm64/vendor-drivers.sh`. Built into the arm64/Pi 4 image
> by `build-dongle-drivers.sh` from these LOCAL trees only (no live external repos).
> Chipsets operator-selected; sources are the de-facto community repos for each.

| Driver | Upstream | Pinned commit |
|---|---|---|
| `rtl8812au` | https://github.com/aircrack-ng/rtl8812au.git | `734485506a30d6237c2deaad666a19f8ca5379f2` |
| `rtl8821cu` | https://github.com/morrownr/8821cu-20210916.git | `7f63a9da2e8ed83403f6f920e9b1628a37b38ef4` |
| `rtl8821au` | https://github.com/morrownr/8821au-20210708.git | `3a7cdb591b64d99d2670e455bde67c8ab338525b` |
| `rtl88x2bu` | https://github.com/morrownr/88x2bu-20210702.git | `fecac340fb117eb979f4bb6d28e29730384c382b` |
| `rtl8852au` | https://github.com/lwfinger/rtl8852au.git | `865ab0fa91471d595c283d2f3db323f7f15455f5` |
| `rtl8188eu` | https://github.com/aircrack-ng/rtl8188eus.git | `af3bf004458f76b7aec33e9ba552cd382ed1f5c3` |
| `rtl8192eu` | https://github.com/clnhub/rtl8192eu-linux.git | `31bb4bbb162c3d42bb323f65caf037f46ab5acd2` |

## Vendored boot artifacts (binary device-tree blobs, not driver source)

> Same pinning discipline as the drivers above, but a single binary file (a compiled DTB), not a
> buildable source tree. Fetched by `builder/mkosi-arm64/make-cm5-image.sh`
> (`CM5_DTB_SOURCE=vendor`, the default) because the artifact does not exist in Debian's own
> kernel packaging yet — see that script's header for the full finding.
>
> **Superseded by the ADR 0029 unified Pi factory (`make-pi-image.sh`) below**: the Raspberry Pi
> downstream kernel package (`linux-image-rpi-2712`) ships `bcm2712-rpi-cm5-cm5io.dtb` natively —
> confirmed 2026-07-08 by direct `dpkg-deb -c` inspection of
> `linux-image-6.12.93+rpt-rpi-2712_6.12.93-1+rpt1_arm64.deb`
> (`./usr/lib/linux-image-6.12.93+rpt-rpi-2712/broadcom/bcm2712-rpi-cm5-cm5io.dtb`, 79779 bytes).
> The one-off GitHub-vendored dtb below is kept as history/fallback for `make-cm5-image.sh` only;
> `make-pi-image.sh` sources ALL DTBs from the pinned RPi kernel package, not a raw vendored blob.

| Artifact | Upstream | Pinned commit | Why vendored (not Debian) |
|---|---|---|---|
| `bcm2712-rpi-cm5-cm5io.dtb` | https://github.com/raspberrypi/firmware (path `boot/bcm2712-rpi-cm5-cm5io.dtb`) | `89752d47a688ec33c9f0c38f6549f627e5c143f9` | Confirmed 2026-07-08 by direct file-list inspection: Debian bookworm-backports' newest kernel (`linux-image-6.12.94+deb12-arm64`) ships `bcm2712-rpi-5-b.dtb` (Pi 5 Model B) but **no CM5/CM5-IO-board variant** — mainline dts upstreaming lands carrier-board variants later than the flagship board. Revisit once Debian/mainline ship a CM5 dtb natively (os-architect call, not a release-engineer default). Superseded for `make-pi-image.sh` — see note above. |

---

## Self-built BTF edge kernel (ADR 0032 — RPi downstream RE-COMPILED with BTF)

> Built by `builder/build-edge-kernel.sh` from the **official `raspberrypi/linux` downstream**
> source (NOT mainline, NOT a fetched binary): the exact downstream kernel RE-COMPILED with a
> ~2-symbol config override (`CONFIG_DEBUG_INFO=y` + `CONFIG_DEBUG_INFO_BTF=y`). WE compile with
> debug-info on, so DWARF exists at build time and `pahole` (v1.25) emits **native** BTF into
> `vmlinux` → `/sys/kernel/btf/vmlinux` present at boot → CO-RE eBPF loads with NO sideload.
> Everything else (CM5 + full-family DTBs, RP1 platform drivers, MMC/USB/NVMe, 16 K pages) is
> UNCHANGED from what the RPi Foundation ships = hardware parity. Fixes BTF for ALL RPi boards.
> The `.deb` is a build OUTPUT; inputs pinned (commit + tarball sha256 + the in-repo config
> fragment) → reproducible.
>
> **Why not the two obvious fixes (both dead, ADR 0032 Context):** (1) `pahole` sideload from the
> RPi `-dbg` pkg — the `-dbg` pkg has NO DWARF, so nothing to encode. (2) Mainline kernel (which
> HAS native BTF) — mainline has NO CM5 device tree (only Pi 5 Model B) in 6.18.32/master/next; the
> CM5 DTS is downstream-only + won't compile against vanilla dtc + the RP1 binding rift. So we
> recompile downstream instead.

| Artifact | Source | Pinned input | Notes |
|---|---|---|---|
| `raspberrypi/linux` tarball (build input) | `codeload.github.com/raspberrypi/linux/tar.gz/<commit>` | commit `a923c1dcd822385aaa82a4388c6a6ad92cbf9280` (`rpi-6.12.y` @ 6.12.94); tarball sha256 `0564f61dc5a5648acb4378509bf3d74e6ad25ab49e05008c7295ebc0b6669948` | Verified live 2026-07-08. `rpi-6.18.y` is the fallback branch. |
| `linux-image-6.12.94-v8-16k-hookprobe-edge_6.12.94-hookprobe1_arm64.deb` (output, Pi5/CM5 — `bcm2712` build; RPi's own `KERNELRELEASE` suffix is confusingly `v8-16k`) | self-built (`FLAVOUR=2712`) | sha256 `9bf176159c120876a02a64d06f3d607ba4779813683f1c903e7393fb43089e2c` (recorded 2026-07-09, `builder/kernel-build/out/SHA256SUMS`) | `bcm2712_defconfig` + BTF override; 16 K pages (`CONFIG_ARM64_16K_PAGES=y`); `CONFIG_DEBUG_INFO_BTF=y` confirmed in `/boot/config-6.12.94-v8-16k-hookprobe-edge`; `.BTF` section 5,105,845 bytes (readelf); pahole reads 8564 structs; 1910 `.ko` modules; bundles all downstream DTBs (bcm2711+bcm2712+cm5). Ships as `kernel_2712.img`. |
| `linux-image-6.12.94-v8-hookprobe-edge_6.12.94-hookprobe1_arm64.deb` (output, Pi4/CM4 — `bcm2711` build) | self-built (`FLAVOUR=v8`) | sha256 `63eaf7211f5bf82236167252380a6c9e2af08c6c0b9f94e4922c605d77beb54a` (recorded 2026-07-09, `out/SHA256SUMS`) | `bcm2711_defconfig` + BTF override; 4 K pages (`CONFIG_PAGE_SIZE_4KB=y`); `CONFIG_DEBUG_INFO_BTF=y` confirmed in `/boot/config-6.12.94-v8-hookprobe-edge`; `.BTF` section 5,105,845 bytes; pahole reads 8564 structs; 1911 `.ko` modules; bundles all downstream DTBs. Ships as `kernel8.img`. |
| `bcm2712-rpi-cm5-cm5io.dtb` (downstream, output) | self-built from the same tree (2712 build) | sha256 `2ca3879fc05b8211313d7c60c49ab84626cb14f26ad0ee8e1a0c6e1bf439d11e` (recorded 2026-07-09, `out/SHA256SUMS`) | The CM5-IO DTB mainline LACKS — carried natively by the downstream tree, unchanged; also bundled inside both `.deb`s above. |

**2026-07-09 proof-gate fix:** `build-edge-kernel.sh`'s step-6(b) BTF-validity check called the HOST's
`bpftool btf dump`, which on the build box is a broken Debian per-kernel-version wrapper (`WARNING:
bpftool not found for kernel 6.12.62-061262` — no `linux-tools` package for the running non-stock
kernel) and silently decoded 0 types, `die()`-ing the build even though both vmlinux's BTF was
valid. This is why `run-both.sh` reported both flavours "FAILED" while the `.deb`s it produced were
actually fine. Fixed: the gate now validates with `pahole` (reads DWARF/BTF straight out of the
vmlinux ELF, independent of the host's running kernel) + a `readelf -SW` `.BTF`-section-size check
(>1 MiB = populated), dropping the bpftool dependency entirely for this proof.

**CM5 (ADR 0032):** the downstream tree builds the **full CM5 family** natively
(`bcm2712-rpi-cm5-cm5io`, `-cm5-cm4io`, `-cm5l-cm5io`, `-cm5l-cm4io`) — no DTB gap. `[cm5]`/`[pi5]`
DTBs + `config.txt` are UNCHANGED; only the kernel *binary* (+ matching modules/initrd) is
substituted. Integration: `make-pi-image.sh` `HOOKPROBE_EDGE_KERNEL=1` + `EDGE_DEB_2712=<path>`.

**What we own:** the CVE/bump cadence of a recompiled downstream kernel (release-engineer bumps
`RPI_COMMIT` + rebuilds + re-pins), tracked in the SBOM as
`source: raspberrypi/linux@<commit> (self-built + BTF override, ADR 0032)`. Once both flavours are
adopted + metal-confirmed, the ADR 0029/0030 `-dbg` BTF-sideload retires (native BTF replaces it).

## Raspberry Pi downstream kernel + firmware (ADR 0029 — unified Pi fat-boot image)

> Fetched by `builder/mkosi-arm64/make-pi-image.sh` ONLY (never `mkosi.conf` — the arm64-UEFI/
> virt rootfs stays 100% Debian-canon, ADR 0029 D2). Source: `archive.raspberrypi.com/debian
> bookworm main` (arm64), pinned versions, GPG-verified against the vendored, scoped keyring
> (`builder/mkosi-arm64/rpi-keyring/raspberrypi-archive-keyring.gpg` — installed via
> `Signed-By=` in `builder/mkosi-arm64/raspberrypi.sources`, confined to that one source, never
> a system-wide trust anchor). All versions + digests below verified live 2026-07-08 by
> fetching `dists/bookworm/InRelease` + `main/binary-arm64/Packages` from the archive and
> cross-checked by an actual `curl` fetch + `sha256sum` of every `.deb` listed (including the
> two real kernel-image debs, not just their meta-packages) — see release-engineer's build log.
>
> **Key fingerprint** (Raspberry Pi Archive Signing Key, RSA-2048): `CF8A 1AF5 02A2 AA2D 763B
> AE7E 82B1 2992 7FA3 303E` — matches the fingerprint published at
> `https://archive.raspberrypi.com/debian/raspberrypi.gpg.key`. Vendored binary keyring:
> `builder/mkosi-arm64/rpi-keyring/raspberrypi-archive-keyring.gpg`
> (SHA-256 `e3669c0d6e5a887c668b6c27a57ce47272aeb77373937ffb9939d020c5c16137`), extracted
> directly from the `raspberrypi-archive-keyring` package below (its
> `/usr/share/keyrings/raspberrypi-archive-keyring.gpg`), not hand-generated.

| Package | Pinned version | Arch | Filename (pool path) | SHA-256 |
|---|---|---|---|---|
| `raspberrypi-archive-keyring` | `2021.1.1+rpt1` | all | `pool/main/r/raspberrypi-archive-keyring/raspberrypi-archive-keyring_2021.1.1+rpt1_all.deb` | `df027ffdd7c400a7e3fc806a681a2db079eccefc7043f23a751fddebffe49e48` |
| `raspi-firmware` | `1:1.20260521-1~bookworm` | all | `pool/main/r/raspi-firmware/raspi-firmware_1.20260521-1~bookworm_all.deb` | `c660bb5a40e1d48a5e2f8306b87ceaa013f870d2be4139195920898f3ac8713d` |
| `linux-image-rpi-v8` (meta) | `1:6.12.93-1+rpt1` | arm64 | `pool/main/l/linux/linux-image-rpi-v8_6.12.93-1+rpt1_arm64.deb` | `08fb6d6f03f67e8f0b8a887d1dd7260166cf62b6434d902858f1b8f0010ed25e` |
| `linux-image-6.12.93+rpt-rpi-v8` (real kernel) | `1:6.12.93-1+rpt1` | arm64 | `pool/main/l/linux/linux-image-6.12.93+rpt-rpi-v8_6.12.93-1+rpt1_arm64.deb` | `ab27b24177b6ccd247e385b88a5bf80159acd6fce84e6b602b5a8c21b4869362` |
| `linux-image-rpi-2712` (meta) | `1:6.12.93-1+rpt1` | arm64 | `pool/main/l/linux/linux-image-rpi-2712_6.12.93-1+rpt1_arm64.deb` | `3197526321f3b81e74d3f58fb454a5345e0a6c854851180a23525c29c772c6ec` |
| `linux-image-6.12.93+rpt-rpi-2712` (real kernel) | `1:6.12.93-1+rpt1` | arm64 | `pool/main/l/linux/linux-image-6.12.93+rpt-rpi-2712_6.12.93-1+rpt1_arm64.deb` | `82bedbb36f23dfa0f164df1f805f6d84e70964c47e6e49b014b0b9c8578a83cd` |
| `linux-image-6.12.93+rpt-rpi-v8-dbg` (debug vmlinux → CO-RE BTF) | `1:6.12.93-1+rpt1` | arm64 | `pool/main/l/linux/linux-image-6.12.93+rpt-rpi-v8-dbg_6.12.93-1+rpt1_arm64.deb` | _PENDING first fetch — `make-pi-image.sh`'s `verify_dbg` prints the observed SHA-256 as `PIN-ME` on the coordinator's egress-enabled build host_ |
| `linux-image-6.12.93+rpt-rpi-2712-dbg` (debug vmlinux → CO-RE BTF) | `1:6.12.93-1+rpt1` | arm64 | `pool/main/l/linux/linux-image-6.12.93+rpt-rpi-2712-dbg_6.12.93-1+rpt1_arm64.deb` | _PENDING first fetch — same as above_ |

**CO-RE BTF for the RPi BSP kernels (ADR 0029/0030) — why the two `-dbg` packages are pinned here:**
The Raspberry Pi Foundation kernels do **not** set `CONFIG_DEBUG_INFO_BTF=y`, so `/sys/kernel/btf/vmlinux`
is ABSENT at runtime and every CO-RE eBPF loader (`napse-quarantine`, `napse-l2guard`) fails
`libbpf: kernel BTF is missing ... -ESRCH` and crash-loops (confirmed on real Pi4 HDMI console).
Debian's kernel HAS BTF, which is why the pre-ADR-0029 Debian-kernel image worked. Fix:
`make-pi-image.sh` fetches these two `-dbg` debs (pinned, same `1:`-epoch handling as the kernels),
extracts each DWARF debug `vmlinux`, and runs `pahole --btf_encode_detached=<out>.btf <vmlinux>` on
the **build host** (pahole reads DWARF; BTF is arch-neutral, so a cross-arch host encode is fine),
validated with `bpftool btf dump file <blob> format raw`. The blobs are staged into the rootfs at
`/usr/lib/hookprobe/btf/vmlinux-<uname -r>.btf`; the loaders' shared
`hookprobe-manifest::xdp::apply_btf_custom_path` points libbpf's `btf_custom_path` at the matching
blob. The `pahole → bpftool` toolchain was proven on the dev box (detached BTF from a DWARF object,
bpftool-parsed); the RPi-specific fetch + on-metal CO-RE relocation is confirmed by the coordinator's
arm64 build + a Pi4/Pi5 boot. Blob size: pahole's BTF is minimal vs the full `-dbg` DWARF (the debs
are large, the shipped `.btf` blobs are small — a few MB each).

**Verified findings from live package inspection (2026-07-08, `dpkg-deb -c`), not assumed:**
- `linux-image-6.12.93+rpt-rpi-2712` ships `./boot/vmlinuz-6.12.93+rpt-rpi-2712` +
  `./lib/modules/6.12.93+rpt-rpi-2712/` + `./usr/lib/linux-image-6.12.93+rpt-rpi-2712/broadcom/`
  containing **all four** target DTBs the ADR 0029 matrix needs from the 2712 package
  (`bcm2712-rpi-5-b.dtb`, `bcm2712-rpi-cm5-cm5io.dtb`) plus, redundantly, the BCM2711 family
  (`bcm2711-rpi-4-b.dtb`, `bcm2711-rpi-cm4.dtb`) — both kernel packages carry the full DTB set,
  `make-pi-image.sh` sources each board's DTB from either package for simplicity/consistency.
- RP1 driver modules present under `kernel/drivers/{firmware/rp1-fw.ko.xz, gpu/drm/rp1/,
  hwmon/rp1-adc.ko.xz, mailbox/rp1-mailbox.ko.xz, media/platform/raspberrypi/rp1_cfe/,
  misc/rp1-pio.ko.xz, pwm/pwm-pio-rp1.ko.xz}` — this is the finding ADR 0029 is built on
  (RP1 support the Debian/mainline kernel lacks before ~6.17-6.18).
- `raspi-firmware`'s `/etc/kernel/postinst.d/z50-raspi-firmware` hook is the AUTHORITATIVE
  naming source `make-pi-image.sh` mirrors exactly (not reverse-engineered/guessed): kernel
  flavour `v8` → `kernel8.img`, flavour `2712` → `kernel_2712.img`; the matching
  `/etc/initramfs/post-update.d/z50-raspi-firmware` hook produces `initramfs8` / `initramfs_2712`
  the same way; DTBs are `rsync`'d flat as `bcm27*.dtb` directly into `/boot/firmware/`.
- Live fetch-and-verify performed 2026-07-08 (not a dry-run claim): all six `.deb` files above
  were `curl`'d from `archive.raspberrypi.com` and their SHA-256 matched this table exactly,
  including the two real (non-meta) kernel-image packages (~32 MB each).

**What we lose / own (ADR 0029 D3, stated plainly):** these two kernels are a Raspberry Pi
downstream fork, not Debian's kernel security-update stream — release-engineer owns the RPi
kernel CVE cadence + bump cadence for the Pi tier from here on, tracked in the image SBOM with
`source: archive.raspberrypi.com` per package (never a hidden `curl`).

## CM5/Pi5 Broadcom Wi-Fi firmware (2026-07-09 — CM5 first-boot: no SSID)
The CM5 radio (BCM4345/6 = brcmfmac43455) needs the board NVRAM
`brcmfmac43455-sdio.raspberrypi,5-compute-module.txt`, which Debian's `firmware-brcm80211`
(pre-CM5) lacks → `brcmf: Direct firmware load ... failed error -2` → no wlan0/AP/SSID.
Staged in `base/drivers/brcm-firmware-rpt/` from RaspberryPi `firmware-brcm80211`
`1:20240709-2~bpo12+1+rpt4` (archive.raspberrypi.com), overlaid into `/usr/lib/firmware/brcm/`
by make-pi-image before the verity seal. Fixes CM5 (and CM4) onboard Wi-Fi AP.
