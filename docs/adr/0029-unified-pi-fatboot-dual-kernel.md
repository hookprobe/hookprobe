# ADR 0029 — Unified Raspberry Pi fat-boot image (one arm64 rootfs, dual RPi kernel, EEPROM-selected)

> ⛔ **Superseded on the rpi-native tier by [ADR 0043](0043-heqk-microkernel-substrate.md) (2026-07-24).** heqk is its own aarch64 boot image; there is no Linux kernel to fat-boot. Retained as history; still informs the UEFI-tier kernel story where applicable.

**Status:** 🟡 Proposed (2026-07-08) — design accepted pending operator sign-off; **no build scripts rewritten yet** (this ADR is the design that gates the follow-on implementation). Classification for all four boards is already in-tree and test-locked; the boot-substrate work is what this ADR authorizes.
**Deciders:** os-architect (author), release-engineer, verification-engineer, security-auditor.
**Relates to:** [ADR 0019](0019-bootc-debian-substrate.md) (boot-model split: rpi-native A/B image-sync vs UEFI bootc — this ADR refines the rpi-native factory it names), [ADR 0017](0017-authenticated-aot-cache.md)/[ADR 0021](0021-multiarch-native-artifact-digests.md) (per-CPU-tier AOT selection — the A76 seam that must keep working per-board from a shared rootfs), [ADR 0003](0003-platform-manifest-schema.md) (manifest classification — the "detect once" contract), [ADR 0016](0016-artifact-hash-signing.md) (supply-chain signing the RPi-repo inputs must not break), `docs/driver-strategy.md` (driver vendoring discipline), `platforms/rpi4.yaml` + `platforms/rpi5.yaml`.

---

## Context — three problems, one root cause

1. **CM5/Pi5 boot but have no network.** `make-cm5-image.sh` builds from Debian's `linux-image-arm64` (bookworm-backports tops out at 6.12.x). BCM2712's **RP1** southbridge (Gigabit Ethernet MAC + USB 2/3) has **no mainline Linux driver before ~6.17, working Ethernet/USB only ~6.18** (confirmed against Phoronix/SUSE upstreaming coverage and raspberrypi/linux issue tracking, 2026-07-08). Debian's kernel therefore boots the CM5 to a console with SD/eMMC root mounted but **no Ethernet or USB** — a network-security appliance with no network path. The current script is honest about this (`HOOKPROBE_CM5_ACCEPT_NO_RP1`) but the honesty is a dead end, not a fix.
2. **CM5 has no Debian DTB.** Debian's backports kernel ships `bcm2712-rpi-5-b.dtb` (Pi 5 Model B) but **no CM5/CM5-IO variant** — `make-cm5-image.sh` must vendor `bcm2712-rpi-cm5-cm5io.dtb` from a pinned `raspberrypi/firmware` commit as a one-off.
3. **Two divergent Pi factories.** `make-pi4-image.sh` (stock Debian kernel, `bcm2711-rpi-4-b.dtb`, GPU-firmware boot chain) and `make-cm5-image.sh` (backports kernel, vendored dtb, EEPROM boot chain) are ~90% duplicated shell that drift independently.

The common root cause: **Debian's mainline-tracking kernel is the wrong kernel for the Raspberry Pi.** The Raspberry Pi Foundation ships a downstream kernel that has carried full RP1 support and every Pi DTB (Pi4, CM4, Pi5, CM5-IO) for over a year. Raspberry Pi OS itself boots **one image across all four boards** by installing both RPi kernels and letting the on-board EEPROM bootloader select the right kernel + DTB per board at boot. That is exactly the operator's proposed strategy, and it dissolves all three problems at once.

### Verified facts (live sources, 2026-07-08 — cited, not assumed)

- **config.txt conditional filters `[pi4]`, `[cm4]`, `[pi5]`, `[cm5]`, `[all]`, `[none]`, `[tryboot]`, `[board-type=…]` are real** and route firmware behaviour per board before Linux loads (raspberrypi.com `config_txt.html`, fetched live).
- **Firmware kernel auto-selection:** Pi5/CM5 firmware defaults to `kernel_2712.img` (16 K-page-optimised, `bcm2712_defconfig`), **falling back to `kernel8.img` if absent**; `kernel=` overrides. Pi5/CM5 **require a `config.txt` present to mark the partition bootable** (same source).
- **Kernel package split (Raspberry Pi apt repo `archive.raspberrypi.com/debian`):** 64-bit `linux-image-rpi-v8` = BCM2711/2837 (Pi3/Pi4/**CM4**) → `kernel8.img`; `linux-image-rpi-2712` = BCM2712 (Pi5/500/**CM5**) → `kernel_2712.img`. Both install **side by side** into `/boot/firmware` (`kernel8.img`+`initramfs8` and `kernel_2712.img`+`initramfs_2712` coexist) — confirmed on RPi forums + docs.
- **The RPi kernel packages carry the RP1 driver and every Pi DTB**, including `bcm2712-rpi-cm5-cm5io.dtb` — the exact blob `make-cm5-image.sh` has to vendor by hand today (raspberrypi/firmware `boot/` tree; RP1 enumerates on PCIe as an Ethernet controller with `kernel driver in use: rp1`). **This is the finding that unblocks CM5.**
- **Board `compatible` chains** (already test-locked in `classify.rs`): Pi4 `raspberrypi,4-model-b`+`brcm,bcm2711`; CM4 `raspberrypi,4-compute-module`+`brcm,bcm2711`; Pi5 `raspberrypi,5-model-b`+`brcm,bcm2712`; CM5 `raspberrypi,5-compute-module`+`brcm,bcm2712`. `rpi4.yaml` already lists the two BCM2711 tokens; `rpi5.yaml` already lists the two BCM2712 tokens. **Classification needs zero code for any of the four boards.**

---

## Decision

**Ship one arm64 Raspberry Pi fat-boot image covering Pi4, CM4, Pi5 and CM5, built from the shared arm64 rootfs, carrying both Raspberry-Pi-repo kernels, with the on-board EEPROM selecting kernel + DTB per board via `config.txt` conditional filters. Collapse `make-pi4-image.sh` + `make-cm5-image.sh` into one `make-pi-image.sh`. Confine the Raspberry-Pi-repo dependency to the Pi factory (not the whole rootfs), pinned and GPG-scoped, tracked in the SBOM/CBOM as a first-class vendored input.**

### D1 · Dual RPi kernel on one fat boot partition; EEPROM selects per board

The Pi boot (FAT32) partition carries **both** RPi kernels + **all four boards' DTBs** + overlays + both initrds + the Pi4-family GPU firmware. The BCM SoC firmware/EEPROM routes to the correct kernel + DTB using `config.txt` conditional filters — the same mechanism Raspberry Pi OS uses.

**Kernel/DTB matrix:**

| Board | SoC | `compatible` (classify) | RPi kernel pkg | Boot kernel file | DTB | Profile / AOT tier |
|---|---|---|---|---|---|---|
| **Pi 4 Model B** | BCM2711 (A72) | `raspberrypi,4-model-b` | `linux-image-rpi-v8` | `kernel8.img` | `bcm2711-rpi-4-b.dtb` | `rpi4` / baseline |
| **CM4** | BCM2711 (A72) | `raspberrypi,4-compute-module` | `linux-image-rpi-v8` | `kernel8.img` | `bcm2711-rpi-cm4.dtb` (CM4-IO) | `rpi4` / baseline |
| **Pi 5 Model B** | BCM2712 (A76) | `raspberrypi,5-model-b` | `linux-image-rpi-2712` | `kernel_2712.img` | `bcm2712-rpi-5-b.dtb` | `rpi5` / cortex-a76 |
| **CM5** | BCM2712 (A76) | `raspberrypi,5-compute-module` | `linux-image-rpi-2712` | `kernel_2712.img` | `bcm2712-rpi-cm5-cm5io.dtb` | `rpi5` / cortex-a76 |

**config.txt (explicit-filter form — the shipping form; deterministic boot is worth more than firmware auto-detect on a security appliance):**

```ini
# HookProbe OS — unified Raspberry Pi boot config (Pi4/CM4/Pi5/CM5).
# The on-board SoC firmware/EEPROM evaluates these [..] filters BEFORE Linux loads and
# routes to the matching kernel + DTB. All kernels/DTBs/initrds below are present on the
# boot partition; each board consumes only its own.
[all]
arm_64bit=1              # accepted+ignored on Pi5/CM5 (64-bit-only); load-bearing on Pi4/CM4
enable_uart=1
disable_overscan=1

[pi4]
kernel=kernel8.img
initramfs initramfs8 followkernel
device_tree=bcm2711-rpi-4-b.dtb
max_framebuffers=2
arm_boost=1

[cm4]
kernel=kernel8.img
initramfs initramfs8 followkernel
device_tree=bcm2711-rpi-cm4.dtb

[pi5]
kernel=kernel_2712.img
initramfs initramfs_2712 followkernel
device_tree=bcm2712-rpi-5-b.dtb

[cm5]
kernel=kernel_2712.img
initramfs initramfs_2712 followkernel
device_tree=bcm2712-rpi-cm5-cm5io.dtb

[all]
```

*(A minimal `auto_initramfs=1` + no `device_tree=`/`kernel=` form also works — the firmware auto-selects kernel + DTB by detected board revision, which is how RPi OS ships. We deliberately choose the explicit form: an appliance boot chain should be auditable and deterministic, not dependent on a firmware board-revision heuristic. Both are documented; explicit ships.)*

`cmdline.txt` is unchanged and board-agnostic (root by `LABEL=hookprobe-root`, `console=ttyAMA0,115200 console=tty1`, `rootwait rw systemd.firstboot=off`) — one cmdline serves all four boards because root is found by label, not by device path.

### D2 · The kernel differs by boot substrate; the rootfs is shared

The **Debian mainline-tracking kernel stays** for the arm64-UEFI/virt image (it has virtio + EFISTUB, boots under AAVMF/systemd-boot, and is what the T3 qemu-virt gate proves). The **RPi downstream kernels are the Pi-native kernels** (they have RP1 + Pi DTBs but are direct-loaded by `config.txt`, not UEFI). This is not a compromise — it is the correct factoring: a kernel is a property of the **boot substrate**, and HookProbe already runs "one rootfs, two boot substrates" (`mkosi.conf` header). The RPi-repo dependency is therefore **confined to `make-pi-image.sh`**, keeping the arm64-UEFI/virt rootfs 100 % Debian-canon and shrinking the supply-chain blast radius.

Mechanically: `make-pi-image.sh` fetches both RPi kernels + `raspi-firmware` from the RPi apt repo (pinned, GPG-verified, cached — the same non-privileged `podman … apt-get download` pattern `make-pi4-image.sh` already uses for `raspi-firmware`), stages **both** RPi `/lib/modules/<ver>` trees + configs into the shared rootfs, then chroots and regenerates **both** initrds (`initramfs8` for v8, `initramfs_2712` for 2712) with the **union** of storage drivers so root mounts on every board:

- Root storage is on-die on both SoCs (**not** behind RP1): `sdhci-iproc`, `sdhci-pltfm`, `sdhci-of-arasan`, `mmc_block`, `bcm2835` (+ `dwc2` for Pi4 USB, `nvme`/`nvme-core` for CM5/Pi5 M.2 carriers). RP1 (network) is **not** needed in the initramfs — it loads from the real rootfs after pivot. That keeps the initramfs module set small and identical in shape to today's, just unioned across both kernels.

### D3 · Supply-chain integrity — the load-bearing tradeoff, addressed head-on

Adding the RPi apt repo means the **kernel is no longer Debian-canon** — it is a Raspberry Pi downstream fork. This is a real cost, stated plainly:

- **What we lose:** Debian's kernel security-update stream no longer applies to the Pi tier; we track the RPi kernel CVE cadence instead. The Pi kernel is a vendor fork, not the reproducible Debian archive.
- **What we keep (the mitigations that preserve "trust nothing unsigned / one signed OCI rootfs"):**
  1. **Pinned versions, never `latest`.** The exact `linux-image-rpi-v8`, `linux-image-rpi-2712`, `raspi-firmware`, and `raspberrypi-archive-keyring` package versions + SHA-256 digests are recorded in `base/drivers/SOURCES.md` (the same discipline already used for the vendored Realtek `.ko` drivers and the one-off CM5 dtb — this generalises it, it does not invent it).
  2. **Scoped repo key.** The RPi archive GPG key is installed via `Signed-By=` pinned to **only** the RPi repo source (`/etc/apt/sources.list.d/raspberrypi.sources` with an explicit key fingerprint), so the RPi key can sign RPi-repo packages and nothing else — it never becomes a system-wide trust anchor.
  3. **First-class SBOM/CBOM entries.** The three RPi packages appear in the image SBOM with `source: archive.raspberrypi.com`, pinned version, and digest — honest provenance, not a hidden `curl`. The final rootfs is still built reproducibly from pinned inputs, and the whole image is still cosign-signed (ADR 0019 D4 image trust and ADR 0016/0017 module trust are untouched — the kernel is substrate, not a signed HookProbe payload).
  4. **Confined blast radius (D2).** Because the RPi repo is only consumed by the Pi factory, the arm64-UEFI/virt and amd64 images stay fully Debian-canon; only the Pi image carries the fork.

This is a strictly better posture than today's `make-cm5-image.sh`, which already `curl`s a dtb from a raw GitHub URL at a pinned commit — the RPi apt repo is *more* auditable (signed archive, versioned packages) than the status quo, not less. The honest residual: we now own RPi-kernel currency for the Pi tier (release-engineer's bump cadence), and Pi-tier kernel CVEs must be tracked against RPi's advisories, not Debian's.

### D4 · One `make-pi-image.sh` factory; classification + AOT unchanged

Collapse the two scripts into one parameterised `make-pi-image.sh` that always produces the **single** unified image (no per-board flag needed for output — one image boots all four; a `--board` flag exists only to build a slimmer single-board image for a constrained SD). Everything downstream is already board-agnostic and needs **no change**:

- **Classification (`classify.rs`)** reads `/proc/device-tree/compatible` at first boot and maps CM4→`rpi4`, Pi5/CM5→`rpi5` — already test-locked (`cm5_classifies_by_device_tree_as_rpi5_profile`, `rpi5_classifies_by_device_tree`). The "detect once" manifest is written on the board it actually boots on, so the same SD in a Pi4 vs a Pi5 self-classifies correctly. *(Honesty note: a card imaged in a Pi4 then physically moved to a Pi5 carries a stale manifest — imaging is per-device, and the first-boot `ConditionFirstBoot` re-probe covers a fresh flash; a board-swap needs a manifest reset. Minor, documented.)*
- **A76 AOT selection (`wasm_loader.rs` / ADR 0017/0021)** keys off `manifest.hardware.cpu.tier` = `cortex-a76` (from `rpi5.yaml`'s `cpu_tier`), so a Pi5/CM5 loads `<id>.a76.cwasm` and a Pi4/CM4 falls to the baseline — **from the same rootfs**, decided at load time by the per-board manifest, failing closed to baseline if the A76 blob is absent. No change; it already works this way.

---

## The whole-platform image map (the "one system" restatement)

With the Pi tier unified, `{Pi4, CM4, Pi5, CM5, VM-arm64, VM-x86, N100, cloud}` (8 targets) collapses to **3 distinct images**, from **2 shared rootfs lineages**:

| Image | Boot substrate | Kernel | Covers |
|---|---|---|---|
| **arm64-Pi fat-boot** | MBR + FAT32 + `config.txt` + SoC EEPROM (direct kernel load) | RPi `linux-image-rpi-v8` **+** `linux-image-rpi-2712` | **Pi4, CM4, Pi5, CM5** |
| **arm64-UEFI/virt** | GPT + ESP + systemd-boot/UKI (bootc D2, ADR 0019) | Debian `linux-image-arm64` | VM-arm64, arm64 cloud *(RK3588 is a 4th arm64 substrate — u-boot/extlinux — tracked separately, not folded here)* |
| **amd64-UEFI** | GPT + ESP + systemd-boot/UKI (bootc) | Debian `linux-image-amd64` | N100, VM-x86, x86 cloud |

**The clean seam (precise):** the arm64-Pi image and the arm64-UEFI image **share one rootfs lineage** — the identical HookProbe userspace (bootstrap, supervisor, Wasm/`.cwasm` modules, presets, trust store, manifest schema). They differ in exactly two things: **(a)** which kernel package(s) + `/lib/modules` trees are staged, and **(b)** the boot packaging (`config.txt`/MBR/FAT32 vs systemd-boot/GPT/ESP). Everything above "Base" (CLAUDE.md's invariant) is byte-identical; only the kernel + boot wrapper — which *is* what "Base" absorbs — differs. They **cannot** be one `.img` (Pi wants MBR + FAT32; UEFI wants GPT + ESP — incompatible partition tables), but they **are** one rootfs. That is the honest limit of "one system": one rootfs, three boot wrappers, driven by capabilities not branches.

This upholds ADR 0019 exactly: the OCI image / rootfs is the universal source of truth; the **update mechanism** splits by boot model (bootc on UEFI, A/B image-sync on rpi-native). This ADR is the refinement of the rpi-native **factory** ADR 0019 D6 names — it makes that factory cover all four Pi boards with a working network on CM5/Pi5.

---

## Ordered implementation plan (build-time-verifiable vs needs-silicon flagged)

1. **`base/drivers/SOURCES.md`** — add pinned `linux-image-rpi-v8`, `linux-image-rpi-2712`, `raspi-firmware`, `raspberrypi-archive-keyring` versions + SHA-256 + repo URL + key fingerprint. *(build-time verifiable)*
2. **RPi repo + scoped key** — a `raspberrypi.sources` (deb822, `Signed-By=` pinned fingerprint) consumed **only** by `make-pi-image.sh`'s cached `podman apt-get download` stage. Do **not** add it to `mkosi.conf` (keep the rootfs Debian-canon — D2). *(build-time verifiable)*
3. **`make-pi-image.sh`** (new, replaces both scripts) — fetch both RPi kernels + firmware (pinned, GPG-verified, cached); stage both `/lib/modules` trees + configs into the rootfs; stage both kernels, all four DTBs, overlays, Pi4 GPU firmware onto p1; regenerate **both** initrds with the storage-driver union; write the unified `config.txt` (D1) + board-agnostic `cmdline.txt`; keep the existing ADR 0008 admin-access gate, verity hooks, and boot-partition static verifier. Delete `make-pi4-image.sh` + `make-cm5-image.sh` (or make them thin `--board` shims for slim single-board builds). *(assembles + statically verifies at build time)*
4. **Boot-partition static gate** — verify presence of `kernel8.img`, `kernel_2712.img`, all four DTBs, both initrds, and (via `unmkinitramfs`) the storage-driver union in each initrd; assert `config.txt` filter block matches the matrix. *(build-time verifiable — this is the honest ceiling of what CI can prove)*
5. **`classify.rs` tests** — add explicit CM4 (`raspberrypi,4-compute-module`→`rpi4`) and Pi5-model (`raspberrypi,5-model-b`→`rpi5`) regression cases alongside the existing CM5 test, so all four boards are asserted, not just three. *(build-time verifiable — pure classification)*
6. **A76-per-board assertion** — a test that `rpi5`/`rpi5.yaml cpu_tier: cortex-a76` yields A76-blob selection and `rpi4` yields baseline, both resolving from one staged rootfs. *(build-time verifiable)*
7. **Docs** — refine `mkosi.conf` header (one rootfs, **three** boot substrates), `docs/driver-strategy.md` (RPi-kernel-for-Pi rationale + RP1), CLAUDE.md/`docs/Readme.md` image map. *(docs)*

**Genuinely needs physical silicon (cannot be build-time-proven):**
- **CM5/Pi5 on-metal boot with the RPi `linux-image-rpi-2712` kernel** — that RP1 Ethernet + USB actually come up (the whole point). This is the single validation that closes the CM5 gap; everything above only proves the image is *assembled* correctly. `rpi5.yaml`'s `hardware_validated: false` stays until this passes.
- **CM4 on-metal** — assembled + classified at build time; boot-gate record needs the board.
- Pi4 remains the only board with a real on-silicon boot-gate record (`rpi4.yaml hardware_validated: true`); the unified image must re-prove the Pi4 path is not regressed on the real Pi4 (10.200.0.4) before the Pi5/CM5 claim is made.

---

## Consequences / residual risk

- **We now own an RPi kernel fork on the Pi tier** (D3) — vendor-fork CVE tracking + bump cadence, distinct from Debian's stream. Bounded, release-engineer-owned, honestly recorded in the SBOM.
- **Bigger boot partition** — two kernels + two initrds + four DTBs + overlays + Pi4 GPU firmware. Bump p1 from 256 M toward ~512 M; trivial on any modern SD/eMMC, called out so the partition table isn't silently under-sized.
- **The arm64-UEFI/virt and Pi images are no longer the same kernel** — intended (D2), but means a Pi-tier kernel bug can hide from the qemu-virt (T3) gate. The Pi-specific boot must be proven on real Pi silicon (T4), never assumed from a green T3 — consistent with the standing "passes-qemu, fails-on-metal is the dominant failure mode" lesson.
- **Firmware-heuristic vs explicit-filter** — we chose explicit filters (auditable); if a future board revision ships a `compatible` the firmware maps to a DTB we didn't stage, the explicit `device_tree=` would need a new filter block. Adding a Pi board stays a `config.txt` + DTB-staging edit in the one factory, plus (if a new SoC family) one `platforms/*.yaml` — the "one file" invariant holds for classification; the boot factory gains one filter block.
- **RPi kernels ship NO kernel BTF — CO-RE eBPF needs a shipped blob (2026-07-08 on-metal regression + fix).** Unlike Debian's kernel, the RPi Foundation kernels (`6.12.93+rpt-rpi-v8`, `6.12.93+rpt-rpi-2712`) build **without** `CONFIG_DEBUG_INFO_BTF`, so `/sys/kernel/btf/vmlinux` is absent at runtime and every CO-RE loader (`napse-quarantine`, `napse-l2guard`, and any CO-RE-using capture/telemetry loader) fails `libbpf: kernel BTF is missing ... -ESRCH` and crash-loops (confirmed on real Pi4 HDMI console — the Debian-kernel image had BTF, which masked this). **Fix (shipped-blob, not a kernel rebuild):** `make-pi-image.sh` fetches the two pinned `-dbg` packages, extracts each DWARF debug `vmlinux`, runs `pahole --btf_encode_detached` on the build host (BTF is arch-neutral; validated with `bpftool btf dump`), and stages `/usr/lib/hookprobe/btf/vmlinux-<uname -r>.btf`. The loaders share ONE wiring fn — `hookprobe-manifest::xdp::apply_btf_custom_path` (a no-op when native BTF exists, sets libbpf `btf_custom_path` to the shipped blob otherwise, hard-errors when neither exists). This is the state until the ADR 0030 single-kernel convergence gives us one mainline arm64 kernel with `CONFIG_DEBUG_INFO_BTF=y` (at which point the blob-ship becomes dead weight to remove). Records: `base/drivers/SOURCES.md` (the two `-dbg` pins), `crates/hookprobe-manifest/src/xdp.rs` (the helper + unit tests).

---

## Alternatives considered

- **pftf/EDK2 UEFI on the Pi + one bootc model (ADR 0019 D5).** Rejected as the path: third-party firmware under our immutable OS, immature on Pi5/CM5, already found flaky. This ADR's dual-RPi-kernel fat-boot is the shipping rpi-native path; pftf stays a tracked convergence.
- **Hold CM5/Pi5 as "console/storage validated, network NOT" until Debian ships an RP1 kernel (~6.17-6.18 in a future backports).** Rejected: indefinitely ships a network appliance with no network, and Debian-backports RP1 is many months out. The RPi kernel solves it today with an auditable supply chain.
- **Switch the whole arm64 rootfs to RPi kernels (drop Debian's).** Rejected: the RPi defconfig (`bcm2711/2712_defconfig`) is not a good qemu-virt UEFI kernel (virtio/EFISTUB coverage differs), and it would forfeit the proven T3 gate and Debian-canon on the arm64-UEFI image for no Pi gain. D2's confinement is strictly safer.
- **Keep two separate Pi scripts.** Rejected: ~90 % duplicated shell that already drifted (different initrd checks, different partition comments); one factory with a matrix is the maintainable form and matches the "adding hardware = one file / one filter block" discipline.

---

## Sources

- [config.txt conditional filters + kernel selection — raspberrypi.com](https://www.raspberrypi.com/documentation/computers/config_txt.html) (`[pi4]`/`[cm4]`/`[pi5]`/`[cm5]`/`[all]`; `kernel_2712.img` default with `kernel8.img` fallback; Pi5/CM5 require config.txt to mark bootable)
- [The Linux kernel — raspberrypi.com](https://www.raspberrypi.com/documentation/computers/linux_kernel.html) (`kernel8`/`bcm2711_defconfig` vs `kernel_2712`/`bcm2712_defconfig`; 64-bit-only flagship/CM5 ignore `arm_64bit`)
- [2 kernel versions on PiOS Bookworm — Raspberry Pi Forums](https://forums.raspberrypi.com/viewtopic.php?t=379128) (`linux-image-rpi-v8` + `linux-image-rpi-2712` install side by side; both kernels+initrds coexist in `/boot/firmware`)
- [bcm2712-rpi-cm5-cm5io.dtb — raspberrypi/firmware](https://github.com/raspberrypi/firmware/blob/master/boot/bcm2712-rpi-cm5-cm5io.dtb) (the CM5-IO DTB the RPi kernel ships)
- [Compute Module 5 DTB — DeepWiki (raspberrypi/firmware)](https://deepwiki.com/raspberrypi/firmware/3.1.2-compute-module-5-dtb) (RP1 on PCIe → `kernel driver in use: rp1`, Ethernet/USB)
- [Raspberry Pi 5 mainline kernel 6.18 — RP1 Ethernet/USB — Raspberry Pi Forums](https://forums.raspberrypi.com/viewtopic.php?t=394796) (mainline RP1 lands ~6.17-6.18; RPi downstream has it today)

---

## heqk migration — see [ADR 0043](0043-heqk-microkernel-substrate.md)

**Coupling: OBSOLETE (rpi-native tier).** Superseded by ADR 0043: the dual-RPi-kernel fat-boot, DTBs, `config.txt` kernel selection, unioned initrds, and shipped BTF blob have no place when heqk *is* the kernel. Marked superseded, not deleted. → **Phase M1/M7 (retirement batch U1)**.
