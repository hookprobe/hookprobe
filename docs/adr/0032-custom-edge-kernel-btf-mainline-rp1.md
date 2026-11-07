# ADR 0032 — BTF-enabled edge kernel: recompile the RPi downstream tree, don't fork or go mainline

> ⛔ **Superseded on the rpi-native tier by [ADR 0043](0043-heqk-microkernel-substrate.md) (2026-07-24).** No Linux kernel means no BTF, no CO-RE requirement, and no `pahole`/`-dbg` rebuild — the entire problem class this ADR solved is deleted.

**Status:** 🟡 Proposed (2026-07-08) — resolves the CM5 network-vs-BTF deadlock. Supersedes the `pahole` `-dbg` BTF-sideload of [ADR 0029](0029-unified-pi-fatboot-dual-kernel.md) + [ADR 0030 §D4-step-5](0030-single-kernel-convergence-bridge.md) for the RPi-kernel tier. Keeps the RPi downstream kernel + its DTBs (ADR 0029) — only re-compiles it. **The BTF kernel is now metal-confirmed on Pi4 + CM5 (2026-07-10 + 2026-07-16: native `/sys/kernel/btf/vmlinux` → CO-RE eBPF attach, no sideload; PSI + `NF_CONNTRACK_PROCFS` live); the ADR stays 🟡 Proposed only because the wider boot-substrate rewrite it belongs to (ADR 0029/0030) still awaits operator sign-off.** (See "Proven vs pending-metal".)
**Deciders:** os-architect (author), release-engineer, verification-engineer, security-auditor.
**Relates to:** ADR 0029, ADR 0030, [ADR 0019](0019-bootc-debian-substrate.md), [ADR 0005](0005-unified-ebpf-detection.md) (CO-RE eBPF), [ADR 0016](0016-artifact-hash-signing.md)/[ADR 0021](0021-multiarch-native-artifact-digests.md), `base/drivers/SOURCES.md`, `builder/build-edge-kernel.sh`, `builder/mkosi-arm64/make-pi-image.sh`.

---

## Context — the CM5 network-vs-BTF deadlock, and why two obvious fixes are dead

CO-RE eBPF (`napse-quarantine`, `napse-l2guard`, host-EDR) needs `/sys/kernel/btf/vmlinux` at runtime. The RaspberryPi Foundation ships its kernels with `CONFIG_DEBUG_INFO_BTF=n`, so that file is absent and the loaders crash-loop `libbpf: kernel BTF is missing … -ESRCH` (confirmed on a real Pi4 HDMI console, memory). Two escape routes were investigated and **both proved dead**:

1. **`pahole` sideload from the RPi `-dbg` package (ADR 0029/0030 approach).** Dead: the RPi `-dbg` packages ship **no DWARF** — `pahole` has nothing to read and cannot emit BTF. (The prior investigation's core finding.)
2. **Switch the bcm2712 tier to a mainline kernel (which HAS native BTF).** Dead for CM5: **mainline Linux has no CM5 device tree.** Direct inspection (2026-07-08) of `arch/arm64/boot/dts/broadcom/` at v6.18.32, torvalds master, AND linux-next shows only `bcm2712-rpi-5-b.dts` + `bcm2712-d-rpi-5-b.dts` (Pi 5 Model B + its D0 stepping) — **no `bcm2712-rpi-cm5*.dts` anywhere upstream.** The CM5 DTS lives only in downstream `raspberrypi/linux`, and depends on downstream-only DT includes / pinctrl macros / clock topologies that do not compile against vanilla `dtc`, on top of the RP1 platform-vs-PCIe-MFD binding rift (mainline models RP1 as a PCIe `MISC_RP1` endpoint whose sub-devices load via a DT overlay; downstream models it as platform devices — the two DTB models are not interchangeable). A vanilla kernel therefore **cannot drive a CM5**, and back/forward-porting DTBs between the two binding models is a maintenance sink. *(An earlier draft of this ADR pursued the mainline path and correctly surfaced the missing-CM5-DTB blocker; that draft is superseded by the approach below.)*

## Decision — re-compile the downstream kernel WITH BTF (a re-compilation layer, not a fork)

Pull the **official** `raspberrypi/linux` source, apply a **~2-symbol config override** that turns BTF on, and rebuild. WE compile with `CONFIG_DEBUG_INFO=y`, so DWARF exists at build time and `pahole` (v1.25, present) emits **native** BTF into `vmlinux`. Every other byte — the CM5 + full-family DTBs, the RP1 platform drivers, the built-in MMC/USB/NVMe stack, 16 K pages — stays **exactly as the RPi Foundation ships it** (production-vetted hardware parity). This is not a fork: it is the identical source, recompiled with debug-info on. It **fixes BTF for every RPi board** (Pi4 `rpi-v8` and Pi5/CM5 `rpi-2712`), not just CM5.

### D1 · Source + fetch path (validated live 2026-07-08)

- Branch **`rpi-6.12.y`** (matches our shipped `6.12.9x+rpt`; **`rpi-6.18.y`** is the fallback if 6.12.y ever regresses BTF). Pinned to commit **`a923c1dcd822385aaa82a4388c6a6ad92cbf9280`** (= `make kernelversion` → **6.12.94**).
- **Egress works via `codeload.github.com`** (github.com/git.kernel.org web UIs may be flaky, but the codeload tarball route returns HTTP 200 — same route proven for other repos): `https://codeload.github.com/raspberrypi/linux/tar.gz/<commit>`. Tarball sha256 **`0564f61dc5a5648acb4378509bf3d74e6ad25ab49e05008c7295ebc0b6669948`** (pinned in `base/drivers/SOURCES.md`). Confirmed the downstream `arch/arm64/boot/dts/broadcom/Makefile` builds the **full CM5 family**: `bcm2712-rpi-cm5-cm5io`, `bcm2712-rpi-cm5-cm4io`, `bcm2712-rpi-cm5l-cm5io`, `bcm2712-rpi-cm5l-cm4io` — the parity mainline lacks.

### D2 · The config override (the ONLY delta vs the RPi defconfig)

Base = the RPi `bcm2712_defconfig` (Pi5/CM5, 16 K pages) — or `bcm2711_defconfig` for the `v8` flavour — **unchanged**. Overlay merged via `scripts/kconfig/merge_config.sh`:

```
CONFIG_DEBUG_INFO_DWARF_TOOLCHAIN_DEFAULT=y
CONFIG_DEBUG_INFO=y
CONFIG_DEBUG_INFO_BTF=y
CONFIG_DEBUG_INFO_BTF_MODULES=y
CONFIG_DEBUG_INFO_REDUCED=n
CONFIG_DEBUG_INFO_SPLIT=n
CONFIG_BPF_SYSCALL=y   (already on in the RPi defconfig; asserted, not assumed)
CONFIG_BPF_JIT=y
```

A **release-blocking config guard** then asserts `CONFIG_DEBUG_INFO=y`, `CONFIG_DEBUG_INFO_BTF=y`, `CONFIG_BPF_SYSCALL=y` are all `=y` after `olddefconfig`, AND that the CM5 DTB is still in the tree Makefile (parity intact) — the build **fails** otherwise. **Result (this build, 2026-07-08): guard PASS** — `DEBUG_INFO_BTF=y`, `BPF_SYSCALL=y`, `bcm2712-rpi-cm5-cm5io.dtb` present.

### D3 · Build + package — `builder/build-edge-kernel.sh` (standalone, repeatable)

`make <defconfig>` → merge BTF fragment → `olddefconfig` → guard → `make -j$(nproc) bindeb-pkg LOCALVERSION=-hookprobe-edge` → prove `.BTF` + CM5 DTB → collect deb + sha256. **Two build flavours:** `FLAVOUR=2712` (Pi5/CM5, default — the board that matters) and `FLAVOUR=v8` (Pi4/CM4, a re-run). Because this build host lacks `debhelper`/`libdw-dev` and cannot `apt install` (no sudo in-sandbox), the pipeline **falls back automatically** to plain `make Image modules dtbs` + a hand-assembled `.deb` via `dpkg-deb` — no root, host-independent, byte-identical layout to the RPi deb (`boot/vmlinuz-<rel>`, `lib/modules/<rel>/`, `usr/lib/linux-image-<rel>/broadcom/*.dtb`). On a build host that has the deb-build deps it uses canonical `bindeb-pkg`.

### D4 · Integration into `make-pi-image.sh` — a deb SUBSTITUTION, zero DTB/config.txt change

Because the edge kernel **is** the downstream kernel, the DTBs and `config.txt` are **unchanged** — `[pi5]` still says `kernel=kernel_2712.img` + `device_tree=bcm2712-rpi-5-b.dtb`; `[cm5]` still uses the downstream `bcm2712-rpi-cm5-cm5io.dtb`. The only change is *which binary* fills `kernel_2712.img` (+ its matching `/lib/modules` + regenerated initrd). Guarded, opt-in, default-off:

- `HOOKPROBE_EDGE_KERNEL=1` + `EDGE_DEB_2712=<path>` (and optional `EDGE_DEB_V8=`) → after the stock `-rpt` kernel is staged into `KCACHE`, `substitute_edge()` overlays the edge deb's `vmlinuz` + `lib/modules/<rel>` + `broadcom/*.dtb` and updates the `KVER` marker. Everything downstream (module copy, DTB copy, initrd `initramfs_2712` generation, `config.txt`) is byte-identical. Default (flag unset) = ship the stock `-rpt` kernel, the metal-proven path, untouched.
- Native BTF makes the ADR 0029/0030 `-dbg` sideload blob (`gen_btf` → `/usr/lib/hookprobe/btf/*`) **redundant but harmless**: `hookprobe-manifest::xdp::apply_btf_custom_path` finds `/sys/kernel/btf/vmlinux` at runtime and no-ops. On full adoption, delete the two `-dbg` fetches + `gen_btf` from `make-pi-image.sh` and the two `-dbg` pins from SOURCES.md (release-engineer's call, after metal-confirm).

### D5 · Retirements

- **Retire the `pahole` `-dbg` BTF-sideload** (ADR 0029 consequences + ADR 0030 D4-step-5) — replaced by native in-kernel BTF for the whole RPi tier. The `apply_btf_custom_path` helper + tests stay (they harmlessly no-op).
- **Do NOT** retire the RPi downstream kernel choice itself (ADR 0029 D1) — this ADR *keeps* it and merely recompiles it. The mainline-convergence bridge (ADR 0030 D4) remains blocked on the upstream CM5 DTB and is unaffected.
- Pi4/CM4 also gain native BTF from this (the `v8` flavour), so the shared rootfs no longer depends on any sideloaded blob on any RPi board once both flavours are adopted.

---

## Proven vs pending-metal (brutally honest)

**Proven on the build host (this ADR):**
- Downstream source reachable + pinned (`rpi-6.12.y` @ `a923c1d`, 6.12.94; tarball sha256 pinned). Full CM5 family in the downstream Makefile.
- Config guard PASS: `DEBUG_INFO_BTF=y` + `BPF_SYSCALL=y` + CM5 DTB in-tree. `resolve_btfids` (the BTF-ID tool, built only when BTF is on) compiles — the BTF pipeline is active.
- **Build result** (`.BTF` section proof via `readelf -S vmlinux | grep .BTF`, compiled `bcm2712-rpi-cm5-cm5io.dtb`, and the `-hookprobe-edge` deb sha256) — recorded in `builder/kernel-build/out/SHA256SUMS` + the SOURCES.md pin once the (long) compile finishes. The guard makes a missing `.BTF` a hard build failure, so a produced deb *implies* BTF present.

**Provable ONLY on real silicon — NOW CONFIRMED (Update 2026-07-10 + 2026-07-16, Pi4 + CM5 metal; see BuildPlan Change Log):**
- ~~That `/sys/kernel/btf/vmlinux` is **populated at boot** on a CM5/Pi5 and CO-RE loaders attach with no sideload.~~ **Confirmed on CM5 + Pi4** — native BTF at boot, CO-RE eBPF (senzorium-flow / TC enforcement filters) attach with no sideload; PSI + `NF_CONNTRACK_PROCFS` native (conntrack flow-detection restored).
- ~~That RP1 **Ethernet + USB come up** on CM5 metal.~~ **Confirmed** — RP1 Ethernet up on CM5 (`end0` WAN), Wi-Fi AP live (VHT80-ch40).
- NVMe (CM5-IO) + the 16 K-page userland behaved as with the stock kernel (validated boots on both boxes).

## Consequences / residual risk

- **We now own the CVE/bump cadence for a recompiled downstream kernel** — same ownership as ADR 0029 D3 (we already shipped a downstream fork), now with an extra recompile step. release-engineer bumps `RPI_COMMIT` + rebuilds + re-pins; SBOM source = `raspberrypi/linux@<commit> (self-built + BTF override, ADR 0032)`.
- **`CONFIG_DEBUG_INFO=y` enlarges the build** (DWARF) and the compile is long; the shipped `vmlinuz` is only marginally larger (BTF is compact; DWARF is not shipped in the Image). Kernel-module `.ko` sizes grow slightly with `DEBUG_INFO_BTF_MODULES`.
- **Recompilation is a config delta, not a source delta** — lowest-risk way to get BTF while keeping exact RPi hardware parity. The one behavioral risk is that debug-info build flags perturb codegen; mitigated by keeping the override minimal and validating on metal.
- **Fixes ALL RPi boards' BTF**, retiring the sideload blob fleet-wide — a net supply-chain simplification vs ADR 0029/0030.
- Pi4 validation image (`make-pi4-image.sh`) + shared rootfs untouched; the mainline-convergence bridge (ADR 0030) still tracks the upstream CM5 DTB independently.

---

## Sources (validated live 2026-07-08)

- Downstream source: `codeload.github.com/raspberrypi/linux/tar.gz/a923c1dcd822385aaa82a4388c6a6ad92cbf9280` (HTTP 200), `Makefile` → 6.12.94, `arch/arm64/configs/bcm2712_defconfig`, `arch/arm64/boot/dts/broadcom/Makefile` (full CM5 family), branch `rpi-6.12.y`.
- Mainline CM5 absence (why not mainline): `arch/arm64/boot/dts/broadcom/{Makefile,tree}` @ `v6.18.32`, torvalds master, linux-next — Pi5-B + `bcm2712-d` only, no CM5.
- Tooling: `pahole v1.25`, `aarch64-linux-gnu-gcc 13.3.0`, `libelf-dev`, `dpkg-deb` (manual-deb fallback).
- Retires: ADR 0029 consequences (`-dbg` sideload) + ADR 0030 D4-step-5 (`pahole` BTF-gen), for the whole RPi tier.

---

## heqk migration — see [ADR 0043](0043-heqk-microkernel-substrate.md)

**Coupling: OBSOLETE (rpi-native tier).** Superseded by ADR 0043. The BTF-enabled RPi kernel recompile existed solely to make Linux eBPF CO-RE work; heqk's RFC 9669 BPF plane needs none of it. Marked superseded, retained as history. → **Phase M7 (retirement batch U2)**.
