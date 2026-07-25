# ADR 0030 — Fat-boot improvements + the single-kernel convergence bridge

> ⛔ **Superseded on the rpi-native tier by [ADR 0043](0043-heqk-microkernel-substrate.md) (2026-07-24).** The "converge to one Linux kernel" goal is replaced by "there is no Linux kernel." Its D4 boot-seam prediction — `config.txt kernel=` can point at any image — is fulfilled by `heqk8.img`.

**Status:** 🟡 Proposed (2026-07-08) — refines and *keeps* ADR 0029; adds three build-time gates, a faster-CM5 bring-up path, a CM5 performance tuning set, and makes the Pi fat-boot an explicit, low-risk **bridge** to a single mainline arm64 kernel. Does not reopen ADR 0029's ship decision.
**Deciders:** os-architect (author), release-engineer, verification-engineer, security-auditor.
**Relates to:** [ADR 0029](0029-unified-pi-fatboot-dual-kernel.md) (the fat-boot this refines), [ADR 0019](0019-bootc-debian-substrate.md) (boot-model split), [ADR 0017](0017-authenticated-aot-cache.md)/[ADR 0021](0021-multiarch-native-artifact-digests.md) (A76 AOT seam), `platforms/rpi5.yaml`, `docs/driver-strategy.md`.

---

## Context — ADR 0029 is right to ship; three things it under-specifies

ADR 0029's dual-RPi-kernel fat-boot is the correct **ship-now** path to a networked CM5: the Raspberry Pi downstream kernel is the *only* kernel that carries **all** of {RP1 Ethernet+USB driver, the CM5-IO DTB, the Pi 5 rev-1.1 DTS} proven on metal **today**. Adversarial review confirms the core decision but finds three gaps and one stale rejection.

### Verified facts (live sources, 2026-07-08)

- **Mainline RP1 Ethernet+USB works from Linux 6.18** (released Dec 2025); RP1 PCI enablement landed 6.17. (Phoronix, CNX Software, RPi forums.)
- **Debian trixie-backports already ships `linux-image-6.18.12` for arm64** (incl. `arm64-16k` and `cloud-arm64`), *now* — not "many months out" as ADR 0029's alternatives section states. That rejection is **stale**. (packages.debian.org/trixie-backports, debian-kernel list.)
- **But mainline DTB coverage is not complete.** 6.18.0 lacks `bcm2712d0-rpi-5-b.dts` (Pi 5 **rev 1.1**); CM5-IO + rev-1.1 patching is still catching up in 6.19-rc1. The RPi fork carries them today. (RPi forums t=394796, home-assistant/operating-system#3782, meta-raspberrypi#1394.) **This is why we still ship the RPi kernel now.**
- **Page-size split:** `linux-image-rpi-v8` (Pi4/CM4) = **4 K** pages (`kernel8.img`); `linux-image-rpi-2712` (Pi5/CM5) = **16 K** pages (`kernel_2712.img`, `CONFIG_ARM64_16K_PAGES=y`, ~7 % random-access win). A 4 K-aligned executable run under a 16 K kernel returns **EINVAL**. (RPi docs; forums t=361390, t=390536.) **ADR 0029 never addresses that one rootfs must satisfy both page sizes** — a genuine on-metal failure mode.
- **RPi defconfig runtime posture:** `bcm2712_defconfig` uses `CONFIG_PREEMPT` (not RT) and the userspace default governor is **ondemand** (udev rule `60-ondemand-governor.rules`) — tuned for a general desktop, not a low-latency appliance. (DeepWiki raspberrypi/linux; forums.)
- **CM5-IO carries PCIe/NVMe**; NVMe ≈ 450–850 MB/s vs microSD ≈ 100 MB/s. (Geerling; raspberry.tips.)

---

## Decision

Keep ADR 0029's fat-boot as shipped. Add the following, and structure the factory so the eventual kernel swap is a deletion, not a rewrite.

### D1 · Page-size safety gate (fixes an ADR 0029 blind spot)

Because the **shared rootfs** boots a **4 K** kernel on Pi4/CM4 and a **16 K** kernel on Pi5/CM5, every HookProbe-built arm64 binary and loadable artifact must be **≥ 16 K max-page-size aligned** (over-alignment is harmless under 4 K). Debian/RPiOS arm64 userland is already 64 K-aligned by port policy — this is why RPiOS runs one userland across all four boards — but **our own** outputs must be checked, not assumed:

- **Build-time gate (new):** assert LOAD-segment alignment ≥ `0x4000` (16 K) via `readelf -l` on every HookProbe arm64 ELF staged into the Pi rootfs (supervisor, bootstrap, `hookprobe-api`, the eBPF loaders, any vendored `.ko`/`.so`), and assert each `.a76.cwasm`/`.cwasm` AOT blob loads under a 16 K-page mmap. Fail the Pi image build on any 4 K-only artifact.
- **Rationale:** without this, a single 4 K-aligned binary silently boots on Pi4 (T4-green) and **EINVAL-fails to exec on Pi5/CM5** — precisely the "passes-on-one-board, fails-on-another" trap. `aarch64-unknown-linux-gnu` (Rust/LLVM) defaults to 64 K max-page-size, so this gate is expected to pass on day one; it exists to *stay* green as build flags drift.

### D2 · Faster-to-working CM5 — ship a slim `--board cm5` first

Use ADR 0029 D4's slim single-board build as the **first CM5 bring-up artifact**, not the full fat-boot: only `linux-image-rpi-2712` + `bcm2712-rpi-cm5-cm5io.dtb` + one initrd + a `[cm5]`-only `config.txt`. It builds/flashes/boots faster, and — critically — makes the single validation that matters (does RP1 Ethernet+USB come up on CM5 silicon?) **unambiguous**: no dual-kernel/union-initrd variables to bisect. Only after RP1 is proven on the slim image do we re-assemble and re-validate the full fat-boot on Pi4 (regression) + Pi5/CM5. This de-risks the imminent flash without abandoning fat-boot as the shipping artifact.

### D3 · CM5 performance tuning set (ranked, manifest-driven, all reversible)

1. **NVMe for the data partition + boot on CM5-IO (highest IO leverage).** Move the persistent/retention partition (pcap → events → SQLite event DB → AOT cache) to the PCIe M.2. ~5–8× storage bandwidth and far better random IOPS vs SD/eMMC — this is the biggest win for the *storage-bound* parts of the workload (retention window, event-DB queries, cold AOT load, boot latency). It does **not** speed the packet path (that is CPU/NIC-bound). Gate on CM5-IO PCIe presence in the manifest (capability, not board-branch).
2. **`performance`/`schedutil` cpufreq governor, not `ondemand` (highest latency-determinism leverage, near-zero cost).** ondemand ramps frequency reactively → adds wake-up latency on bursty packet-path work → tail-latency jitter on a security appliance. Override to `performance` (mains-powered appliance) or `schedutil` via a tmpfiles/udev drop-in, surfaced as a manifest tuning knob. Config-only, high leverage on detection-path determinism.
3. **Keep the 16 K-page `kernel_2712` + A76 AOT + pin RP1 IRQ/RPS.** The 16 K kernel is worth ~7 % on random memory access — a reason the convergence (D4) must not silently regress Pi5 to a 4 K kernel. A76 AOT (`.a76.cwasm`, ADR 0021) already eliminates per-boot JIT and emits A76-tuned codegen (LSE atomics); the CM5 win is *keeping it selected per-board from the shared rootfs*. Add RP1 NIC IRQ affinity + RPS across the A76 cores (single Gigabit → modest, but cheap jitter reduction).

PREEMPT_RT and hugepages are **out of scope**: the workload is soft-real-time with the hot path in eBPF/XDP (kernel context) not a DPDK poll loop; RT complicates the kernel for little gain here.

### D4 · The fat-boot is an explicit BRIDGE — define the exit criteria

ADR 0029's boot substrate (MBR + FAT32 + `config.txt` + EEPROM direct-load) is **kernel-source-agnostic**: `config.txt`'s `kernel=` can point at a Debian `vmlinuz` exactly as at `kernel8.img`/`kernel_2712.img`. The convergence is therefore a **deletion**, not a redesign:

**Convergence trigger — ALL must hold (verify at trigger time; do not assume):**
- (T1) A Debian arm64 kernel ≥ 6.18 **enables RP1** Ethernet+USB (as builtin or shipped module) — *version condition already met in trixie-backports 6.18.12; RP1 enablement in Debian's config must be confirmed.*
- (T2) That kernel **ships all four Pi DTBs incl. `bcm2712-rpi-cm5-cm5io.dtb` and Pi 5 rev-1.1** — *not yet true at 6.18.0; tracking 6.19+. This is the gating item, not the driver.*
- (T3) It is available in a suite we accept (trixie-backports today = churns as versions migrate; a Debian point-release / Debian 14 stable = durable — release-engineer picks the risk tier).
- (T4) A convergence-candidate fat-boot (Debian kernel staged in place of the RPi kernels) **boots RP1-up on Pi4 + Pi5/CM5 metal** and passes the T3 qemu-virt gate with the *same* kernel.

**When the trigger fires, the swap is:**
1. In `make-pi-image.sh`: replace the "fetch both RPi kernels from the RPi apt repo" stage with "stage the Debian `linux-image-arm64` already in the rootfs"; regenerate **one** initrd, not two.
2. Collapse the `[pi4]`/`[cm4]`/`[pi5]`/`[cm5]` `kernel=` lines to a single `kernel=vmlinuz-<ver>`, keeping the per-board `device_tree=` lines (still per-board DTBs).
3. Delete the RPi repo source, the scoped `Signed-By=` key, and the three RPi package entries from `base/drivers/SOURCES.md`. **The RPi-fork dependency retires here.**
4. Then arm64-Pi and arm64-UEFI/virt share **one** kernel package → ADR 0029 D2's Pi-vs-virt kernel split *also* dissolves → the entire arm64 tier becomes **one kernel, two boot wrappers** (config.txt vs systemd-boot). The amd64 tier is untouched.
5. **Retire the shipped CO-RE BTF blob.** Debian's kernel is built with `CONFIG_DEBUG_INFO_BTF=y`, so on convergence `/sys/kernel/btf/vmlinux` is present again and `hookprobe-manifest::xdp::apply_btf_custom_path` falls back to its native no-op path automatically. Delete the two `-dbg` fetch + `pahole` BTF-gen stages from `make-pi-image.sh`, the `/usr/lib/hookprobe/btf/*` staging, and the two `-dbg` pins in `base/drivers/SOURCES.md`. The `apply_btf_custom_path` helper + its unit tests can stay (they harmlessly no-op) or be removed with the blob — release-engineer's call.

**Page-size decision at convergence (call it now):** Debian's *generic* `linux-image-arm64` is **4 K**. Converging onto it forfeits the 16 K ~7 % Pi5 win but needs no userland rework and unifies Pi+virt on one binary. Debian's `linux-image-arm64-16k` keeps the 16 K win but would force 16 K pages on virt/cloud too (and requires the D1 alignment guarantee fleet-wide). **Recommendation:** converge onto the **4 K generic** kernel for one-binary-everywhere simplicity; treat the 7 % as an accepted, measured cost, revisited only if a benchmark shows it matters for the detection path.

**Do NOT adopt mainline sooner as the ship path.** The imminent CM5 flash needs rev-1.1 + CM5-IO DTBs that mainline lacks (T2 open); backports churn (no long-term pin) is the wrong base for a device we are validating on metal this week. Instead, run the convergence candidate as a **parallel validation track** (T4) so that when T2 closes we flip a proven switch, not a hope.

---

## Consequences / residual risk

- **D1 adds a real safety gate** for a failure mode ADR 0029 missed; expected-green today, prevents silent 4 K-alignment drift from EINVAL-ing Pi5/CM5.
- **The convergence is de-risked but not free:** it hinges on T2 (mainline DTB completeness), which is outside our control and tracks 6.19+. Until then the RPi fork stays, honestly SBOM'd (ADR 0029 D3).
- **Choosing the 4 K generic convergence kernel** trades a measured ~7 % Pi5 memory-access win for one-binary-everywhere; reversible by selecting `arm64-16k` if a benchmark ever justifies it.
- **Governor/NVMe/IRQ tuning are capability-gated** (manifest-driven), never board-branched — they degrade gracefully to SD/ondemand when the hardware is absent, upholding "capabilities, not branches."
- **The RPi kernels' missing kernel BTF is a bridge-lifetime cost, not a permanent one.** While the fat-boot ships the RPi fork, CO-RE eBPF (`napse-quarantine`/`napse-l2guard`) depends on a build-host-generated `pahole` BTF blob per kernel (ADR 0029 consequences; `base/drivers/SOURCES.md`) because those kernels lack `CONFIG_DEBUG_INFO_BTF`. This retires automatically at convergence (swap-list step 5). Until then it is an extra build-host tool dependency (`pahole`/`dwarves`) + two large `-dbg` fetches, cached like the kernels — honestly a supply-chain cost of the fork, bounded and release-engineer-owned.

---

## Sources

- [RP1 PCI support for Linux 6.17 — Phoronix](https://www.phoronix.com/news/Raspberry-Pi-RP1-Linux-6.17)
- [Linux 6.18 release (Arm changes, RP1 Ethernet) — CNX Software](https://www.cnx-software.com/2025/12/01/linux-6-18-release-main-changes-arm-risc-v-and-mips-architectures/)
- [Pi 5 rev 1.0 vs 1.1 on mainline v6.18.0 (missing rev-1.1 DTS) — RPi Forums](https://forums.raspberrypi.com/viewtopic.php?t=394796)
- [linux-image 6.18.12 in trixie-backports arm64 — packages.debian.org](https://packages.debian.org/trixie-backports/kernel/)
- [Trixie-backports 6.18 LTS kernel policy — debian-kernel list](https://lists.debian.org/debian-kernel/2025/12/msg00176.html)
- [16 K page size on Pi 5 / EINVAL on 4 K executables — RPi Forums](https://forums.raspberrypi.com/viewtopic.php?t=361390)
- [bcm2712_defconfig (CONFIG_PREEMPT, governor) — DeepWiki raspberrypi/linux](https://deepwiki.com/raspberrypi/linux/4.1-default-configurations)
- [NVMe SSD boot on Raspberry Pi 5 — Jeff Geerling](https://www.jeffgeerling.com/blog/2023/nvme-ssd-boot-raspberry-pi-5/)
- [Add all BCM2712 device trees (CM5 upstreaming) — home-assistant/operating-system#3782](https://github.com/home-assistant/operating-system/pull/3782)

---

## heqk migration — see [ADR 0043](0043-heqk-microkernel-substrate.md)

**Coupling: OBSOLETE (rpi-native tier).** Superseded by ADR 0043. The page-size gate, cpufreq/NVMe/IRQ tuning, and mainline-Debian-kernel exit criteria are moot when the kernel is heqk. Marked superseded, retained as history. → **Phase M1/M7 (retirement batch U1)**.
