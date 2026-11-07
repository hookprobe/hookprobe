# HookProbe OS — "One OS, Every Platform & Architecture": State & Gap Report

**Date:** 2026-06-29 · **Scope:** the OS itself (Track B), not the dashboard. **Question answered:** *where are we, and what do we need, so that installing HookProbe OS on any machine makes it detect what it is and become the OS — across all platforms and architectures?*

Grounded in: the real V1 installer `~/hookprobe/install.sh` (v5.0, 3,067 lines), the V2 `docs/architecture/Readme.md`, and the actual V2 repo (`base/`, `bootstrap/`, `manifest/`, `platforms/`, `supervisor/`, `.github/workflows/`).

---

## 1. What "one OS on all platforms" actually means in V2

Two fundamentally different models — and V2 is a deliberate upgrade:

| | **V1 — `install.sh`** | **V2 — HookProbe OS** |
|---|---|---|
| Install model | Imperative bash script run **on an existing Debian OS**; installs packages/services for a chosen tier | The OS **is** a signed, immutable, multi-arch **bootc OCI image**; you flash/boot it (or `bootc install` it onto a disk) |
| "Detect the machine" | At **script run** — `detect_*` functions probe hardware, then a menu picks a tier | At **first boot** — `bootstrap` probes hardware **once**, writes the signed **Platform Manifest**; everything else reads the manifest ("detect once, query forever") |
| Platform differences | Branching in bash per board/tier | Absorbed by the **manifest + per-board `platforms/*.yaml` profiles**; code asks "is `wifi7`/`openvswitch` granted?", never "is this a Pi?" |
| Tiers | Sentinel / Guardian / Fortress / Nexus = separate install paths | The same image everywhere; tiers become **capability profiles**, not separate builds |
| Trust | none | cosign-signed image + SBOM/CBOM/SLSA; manifest signed + (TPM-sealed where present) |

**The target end-state:** one OCI image builds for `arm64 | amd64 | riscv64`; `bootc-image-builder` turns it into per-platform artifacts (`.img.xz` for Pi/RK3588, `.iso` for x86, `.qcow2`/`.raw`/`.ami` for VM/cloud); on first boot the device probes itself, classifies against `platforms/`, writes a signed manifest, and the supervisor brings up exactly the modules the hardware grants. **Adding a new board = one file in `platforms/`.**

> **"Install like `install.sh`" is still possible** — bootc supports `bootc install to-disk` / `to-existing-root`, i.e. a one-command install onto a running machine that lays down the immutable image. So V2 keeps the "run one command on any machine" UX *and* gains the immutable/signed/self-detecting model.

---

## 2. The V1 reference is the proven detection spec

`install.sh`'s `detect_*` functions are exactly the hardware intelligence V2 needs — they already work on real devices. They detect:

- **System:** arch (`uname -m`), kernel ver, CPU model/cores/freq (`/proc/cpuinfo`), RAM (`/proc/meminfo`), storage, OS name/version.
- **Platform/board:** Raspberry Pi + model (`/proc/device-tree/model`), Jetson, Rockchip, NUC, generic-x86.
- **Network:** eth count/ifaces, Wi-Fi count + hotspot/2.4/5 GHz, LTE, bridges, WAN iface/gateway, default route, internet reachability.
- **Virtualization:** VM type, nested virt, Proxmox/LXC/Docker, cgroups version.
- **Security:** AppArmor (+enforcing), SELinux (+mode), **BPF support**, seccomp.
- **Accelerators:** GPU (type/mem), **NPU** (type/TOPS).
- **Container runtime:** podman/docker + versions.
- → **Tier eligibility:** `CAN_SENTINEL/GUARDIAN/FORTRESS/NEXUS`.

**This logic must be carried forward into V2's prober** — it is the de-facto specification.

---

## 3. The V2 architecture (where the design is already right)

V2's `bootstrap/reference/generate_manifest.py` (the executable reference; Rust is the shipping target) is a clean **4-stage pipeline** — the declarative successor to `install.sh`'s detection, and a better model:

1. **classify** — device-tree (ARM) → DMI-tuple (x86) → fallback, matched against `platforms/*.yaml`.
2. **map_capabilities** — `grant = presence ∧ known-good ∧ policy`; each token resolves to `granted | absent | present_unsafe | policy_denied` with a **reason + evidence** (e.g. inline-IPS gated on a known-good NIC driver).
3. **allocate_resources + compute_retention** — CPU/mem budgets; storage → tiered retention windows.
4. **assemble + sign** — schema-2 manifest: identity (TPM or software idevid), platform, hardware, network, capabilities, resources, crypto (PQC suite), retention, provenance, signature.

This contract is **the strongest, most-finished piece of the whole OS** (JSON Schema validated, fixtures, CI harness, Rust crate). The problem is everything that *feeds* and *consumes* it on real hardware.

---

## 4. Where we are — honest component status

| # | Component (needed for "one OS, everywhere") | Status | Reality |
|---|---|---|---|
| 1 | **Platform Manifest contract** (schema + 4-stage pipeline + validation) | ✅ | Best piece. `manifest/` + `crates/hookprobe-manifest` + Python reference, all tested. |
| 2 | **Real hardware prober** (live scan → `scan` profile) | ✅ | **BUILT + live-validated read-only on N100/Pi4/cloud** (`bootstrap/src/probe.rs`) — reads `/proc`+`/sys`+device-tree+DMI directly, no external tools, works on a bare system. NIC virtual-filter solves the "25 NICs" over-count. See §8. |
| 3 | **Multi-arch bootc image** (`base/Containerfile`) | 🟡 | Handles arm64/amd64/riscv64 (wasmtime + cosign per-arch); reviewed scaffold; **not buildable on this dev box** (no podman/bootc-image-builder/root). |
| 4 | **Manifest signing + device identity** | 🟡 | **Software-PUF identity + Ed25519 manifest signing built + validated** — no TPM required (`crates/hookprobe-manifest/src/identity.rs`). Bootstrap signs; supervisor verifies + **refuses tampered**. ⬜ remaining: hardware sealing (TPM/fTPM/DICE) to upgrade the tier; cosign verification of module artifacts. See §8.2. |
| 5 | **Platform profiles** (`platforms/*.yaml`) | 🟡 | Only `generic`, `n100`, `rk3588`. Missing: **rpi5/cm5, rpi4, jetson, edge-pro, cloud, vm**. (n100 also needs the blank-DMI → CPU-model fallback.) |
| 6 | **`bootc-image-builder` pipeline** (→ `.img.xz`/`.iso`/`.qcow2`/`.ami`) | 🟡 | **`builder/` scaffolded + validated** — `build.sh` reads `base/profiles/*.yaml` `bib.variants` → podman build + bootc-image-builder; `--plan` + `gen-matrix.sh` run on the dev box; `sign-release.sh` bakes the trust store. ⬜ real run needs a build host + a hardened Containerfile. See §8.5. |
| 7 | **Multi-arch CI producing *signed* images** | 🟡 | `build-os.yml` is a canonical *reference* workflow + bootc lint gate; the CI env has "no privileged bootc-image-builder, no arm64 runner" — it doesn't actually emit images yet. |
| 8 | **Installer / first-boot claim UX** | ⬜ | First boot is headless detection; no flash→claim→enroll flow, no `bootc install` wrapper. |
| 9 | **Supervisor + modules running on real hardware** | 🟡 | Supervisor reconciles *mock* modules; 4 Wasm modules ported (dnsxai/qsecbit/aegis-guard/napse) but **never loaded under a grant on a device**. |
| 10 | **`fleet/` GitOps** | ⬜ | Dir missing (Readme Phase 3). |

---

## 5. The gaps that block "install on any machine → it detects itself"

1. **No real prober** — the pipeline is fixture-fed. *Until the device can scan itself, nothing self-detects.* (Highest leverage; `install.sh` is the ready-made spec.)
2. **No buildable/bootable image** — needs a build host with `podman` + `bootc-image-builder` (this dev box can't). Without it there's no artifact to install.
3. **Unsigned, identity-less** — cosign + TPM/software-PUF sealing are stubs → no trust chain, no device identity.
4. **Thin board coverage** — 3 of ~8 real targets; the proven fleet (Pi4/N100/Ampere-cloud) isn't all profiled.
5. **End-to-end never executed** — the loop *image → boot → detect → manifest → supervisor → module-under-grant* has not run once on real hardware.

---

## 6. What we need to do — sequenced

Mapped onto `Readme.md`'s 6-phase OS roadmap, near-term first:

- **Step A — Real hardware prober (Rust).** Port `install.sh`'s `detect_*` logic into `bootstrap` behind the existing `Scanner` trait → emit the `scan` profile the pipeline already consumes (CPU/mem/storage via `/proc`, board via device-tree/DMI, NICs via `ethtool`/`iw`, TPM, virt, NPU). **No special infra — runs on this box + the real devices we can reach (Pi4 `10.200.0.4`, the N100 host, the Ampere cloud VM).** This makes the whole manifest pipeline *real* and directly delivers "detect what machine it is." *(Readme Phase 1.)*
- **Step B — Expand `platforms/`.** Add `rpi5`/`cm5`, `rpi4`, `jetson`, `edge-pro`, `cloud`, `vm`; fix the n100 blank-DMI → `cpu.model` fallback. Validate each by running the prober on the matching real device and diffing the manifest. *(Phase 1/6.)*
- **Step C — Signing + identity.** Real cosign signing + TPM seal, with the software-PUF identity tier for TPM-less boards (Pi4). *(Phase 5.)*
- **Step D — Build the image for real.** Stand up `builder/` + `bootc-image-builder` on a capable build host (podman, privileged) → first `.qcow2` (boot-test in a VM) then `.img` (Pi) and `.iso` (x86). *(Phase 4.)*
- **Step E — First-boot bring-up on hardware.** Flash/`bootc install` → boot → bootstrap writes a *signed* manifest → supervisor loads **one Wasm module under a manifest grant**. This is the Readme's Phase-1 exit criterion and the first true "one OS detects itself" proof.
- **Step F — Multi-arch CI emitting signed images + the installer/claim UX** (flash → first-boot claim → optional enroll). *(Phase 4/5.)*

---

## 7. Recommended immediate next step

**Build the real hardware prober (Step A)** — port the proven `install.sh` detection into the Rust `bootstrap` `Scanner`. Rationale: it is the **#1 blocker**, needs **no build/hardware infra we lack**, can be **validated immediately on the three real devices we already have access to**, turns the strongest existing piece (the manifest pipeline) from fixture-fed into **genuinely self-detecting**, and is the literal answer to *"install it and it detects what machine it is."* Everything downstream (image, signing, install) builds on a device that can first describe itself.

---

## 8. Validation results — live, read-only (2026-06-29)

**Step A is DONE.** `bootstrap/src/probe.rs` is a strictly read-only probe (only opens `/proc`, `/sys`, device-tree, DMI, `/sys/class/net` for reading; no external tools, no writes, no service contact) — so it runs on a *bare* machine with no software installed, and is safe on live devices. Built clean; the 13 manifest tests stay green. Validated on all three real tiers:

| Device | Run | Detected (real) | Identity | Classifies → |
|---|---|---|---|---|
| **N100** `fortress001` | native binary | amd64 · Intel(R) N100 · 4c · 15767 MB · **TPM 2.0** · nvme 512 GB · **4×2.5GbE (igc) + 2×Wi-Fi (ath12k) + 1×LTE (cdc_mbim)** · DMI=`Default string` | TPM idevid, **sealed** | `generic`/fallback |
| **Pi4** `guardian` | read-only capture | aarch64 · `raspberrypi,4-model-b brcm,bcm2711` · 4c · 3796 MB · **no TPM** · **no EFI** · eth0+wlan0+wlan1 · 2 Wi-Fi PHYs | software-PUF | `generic`/fallback |
| **Cloud** `hookprobe-mssp` | read-only capture | aarch64 · **QEMU/KVM** · 4c · 23974 MB · 1×virtio NIC | software | `generic`/fallback |

**What this proves:** detection is correct on every board (including the **NIC virtual-filter** — the container-heavy cloud VM reported its *1* real NIC, and the N100 its *4* physical NICs, not the old 25). **What it surfaces:** all three currently classify `generic` — the remaining work is **classification coverage**, not detection:
- **N100** → needs a `cpu.model ~= "Intel(R) N100"` match (blank DMI defeats the DMI-tuple path).
- **Pi4** → needs `platforms/rpi4.yaml` (+ `rpi5`/`cm5`) device-tree profile.
- **Cloud** → needs a `virt`-method profile (`MatchMethod::Virt` exists; no profile uses it yet).

Once those land, the same prober output classifies N100→`edge-pro`, Pi4→`edge-lite`, cloud→`cloud` — and the right capabilities light up instead of being `policy_denied` on `generic`. **No system was modified during validation.**

### 8.1 — Classification coverage landed + full end-to-end re-validation

Done: a **`cpu-model`** match method (N100 blank-DMI), a **`virt`** match method (cloud/VM), and **`platforms/rpi4.yaml` + `rpi5.yaml`** (rpi5 shaped for the planned **CM5 2×LAN+Wi-Fi mini-router**) + **`cloud.yaml`**. The supervisor now also parses sysext/image-layer modules (cgroup-slice bound, `Runtime::ImageLayer`); the schema accepts `cpu-model`/`image-layer`. 13 lib tests stay green.

**Re-validated every flow end-to-end — probe → classify → capabilities → manifest → supervisor reconcile — on all three tiers:**

| Tier | classifies → | identity | reconcile (running · refused) |
|---|---|---|---|
| **N100** (live native) | **edge-pro / n100** · cpu-model | TPM, sealed | **7 running** (napse·hydra·qsecbit·dnsxai·aegis-guard + napse-capture[sysext] + ovs[image-layer]) · refused: edge-ai (no NPU), inline-guard (no role) |
| **Pi4** (real facts) | **edge-lite / rpi4** · device-tree | software-PUF | **7 running** (incl. ovs — 3 NICs ⇒ openvswitch granted) · refused: edge-ai, inline-guard |
| **Cloud** (real facts) | **cloud / cloud** · virt:kvm | software | **6 running** · refused: edge-ai, inline-guard, **ovs (openvswitch absent — only 1 NIC)** |

**Thesis proven:** one OS, one prober, one pipeline — each board self-classifies to the right profile, grants exactly the capabilities its hardware supports (Pi4 & N100 get OVS/multi-WAN/Wi-Fi-AP; the cloud VM correctly does *not*), and the supervisor loads precisely the modules those grants allow — **with zero per-board code**.

### 8.2 — Software identity + manifest signing (no TPM) — built & validated

`crates/hookprobe-manifest/src/identity.rs` implements the **software-PUF** root of trust (the no-TPM path):
- a deterministic **Ed25519** key derived from a hardware PUF seed (board/SoC serial + storage serial + physical-NIC MACs — read-only, never stored, re-derived each boot, reimage-stable);
- the bootstrap **signs the manifest** (real Ed25519 over canonical `serde_json::Value` bytes — sorted keys, so the `capabilities` HashMap can't perturb the digest across processes);
- the supervisor **verifies the self-signature on load and refuses a tampered manifest**.

Validated live: N100 / Pi4 / cloud manifests all **sign → VERIFY**; a one-byte tamper (`memory_mb += 1`) is **rejected**. 14 lib tests (added a sign/verify/tamper roundtrip). Schema accepts `ed25519-puf`.

**Identity ladder** (`idevid.type`): `software` (this, everywhere) → upgrade to `dice` (OTP/eFuse) / `tpm` (discrete or **fTPM — the N100 already has Intel PTT**) by sealing the key in hardware. cosign **verification** of images/modules is independent (public keys, no TPM) and is the next supply-chain piece. Honest limit: software-PUF gives integrity + stable hardware-bound identity, **not** hardware tamper-resistance.

### 8.3 — Install-time robustness: self-test → heal → shed · commit-confirmed

`crates/hookprobe-manifest/src/health.rs` adds a post-reconcile health phase (the "*installed, self-tested, healed if failed, else start fresh*" behavior):
- **self-test** each loaded module; **bounded heal** (retry w/ backoff, default 3 attempts);
- **graceful shed** — a module that stays broken is dropped; the box keeps running the rest (degrade, never brick);
- **commit-confirmed** for data-plane modules (sysext/image-layer, or providing sdn/flows/inline/firewall/segmentation): after apply, verify the management path; if lost, **auto-revert** — a reconcile can't self-lockout;
- **reset discipline:** only ephemeral module state is shed; the **device identity + data partition are never touched** (only a deliberate factory reset wipes data; a bad OS *upgrade* is caught by the boot-health gate → `bootc rollback` — that OS-level gate still needs the real image).

Validated live on the N100 (3 new tests + CLI demo): `napse` flaky → **healed** (2 attempts); `qsecbit` persistent-fail → **shed**; `ovs` loses mgmt path → **reverted** → 5 running, 2 shed, box stays up. **17 lib tests green.**

### 8.4 — Module supply-chain verification ("trust nothing unsigned")

`crates/hookprobe-manifest/src/module_sig.rs` + a supervisor verify pass: before load, each module's detached signature (Ed25519 over its artifact digest) is verified against a baked-in **trust store** of release public keys. `signature: required` + (unsigned | unknown key | tampered) → **REFUSED**. Signing keys live OFF-device (ADR 0002); the device only verifies. (Reference signs the `module.yaml` digest; production swaps full sigstore/cosign over the OCI `.wasm`/container artifact — identical mechanism.)

Validated live on a temp module tree:
- **unsigned + empty trust → all 9 modules REFUSED** (trust-nothing-unsigned default — no trust/sigs ⇒ nothing runs);
- **dev release-sign → all `verified` → load**;
- **tamper one `module.yaml` → `INVALID` → refused**.

2 new tests (sign/verify/tamper roundtrip; `required`-unverified → refused) — **19 lib tests green**. **Image implication:** the bootc image must ship the trust store (`release.pub`) + signed modules, or nothing loads — the intended secure posture.

### 8.5 — Image-build pipeline scaffolded (`builder/`)

`builder/` turns the one signed bootc image into per-platform artifacts, driven by `base/profiles/*.yaml` `bib.variants` (so "add a platform = one profile file"):
- **`build.sh`** — podman build (`base/Containerfile`) → cosign → `bootc-image-builder` per variant (`.raw`/`.iso`/`.qcow2`/`.ami`). `--plan` prints the exact commands and **runs anywhere** (validated here).
- **`sign-release.sh`** — off-device module signing + trust-store emission to bake into the image (the §8.4 requirement).
- **`gen-matrix.sh`** — emits the CI image matrix from all profiles (closes the `build-os.yml` TODO): edge-pro→{arm64 `.raw`, amd64 `.iso`}, cloud→{amd64 `.raw`/`.ami`, arm64 `.raw`}, virtual→{`.qcow2`,`.vmdk`}, dev→`.qcow2`.

Validated on the dev box: `--plan` + matrix generation emit the correct per-platform commands. **Not runnable here:** the real build needs a build host (podman + bootc-image-builder + cosign) and a hardened Containerfile (it's CI-scaffold). This is the **graduation step** — everything upstream (probe → classify → sign → verify → reconcile → heal) is proven; this turns it into a flashable image.

### 8.6 — First-boot claim, fleet GitOps, seal-tier seam, build-host runbook

- **First-boot claim / enroll** (`crate::claim` + bootstrap `--claim-admin`/`--mode`/`--enroll-tenant`): sets a local admin (PUF-salted hash), `Unclaimed → Claimed` **standalone, no account**; optional `enroll` → `Claimed → Enrolled` + tenant (cloud-linked/self-hosted). Re-signs the manifest; the supervisor still verifies. Validated live on the N100 (claimed standalone; enrolled `acme-corp`).
- **Fleet GitOps** (`crate::fleet` + `fleet/` + supervisor `--fleet`): pull-based desired state (`hookprobe.yaml`: channel/mode/modules/ring) → a drift engine (module-start/stop, channel-mismatch) → the supervisor prints drift; `agent.sh` is the pull loop. Validated: desired vs live N100 → flags channel drift (`dev` → `stable` ⇒ `bootc upgrade`). Drift unit-tested.
- **Seal-tier seam** (`identity::SealTier` / `recommended_tier`): names the strongest available tier (tpm / dice / software-puf). The N100 reports "tpm-sealed available"; real TPM/DICE sealing is a clean drop-in (needs `tss-esapi`+root / OTP) — **deferred** (the planned CM5 has no TPM anyway → software-PUF).
- **Build-host runbook** (`builder/RUNBOOK.md`): provision host → build+sign → per-platform artifacts → qemu boot-test → flash / `bootc install` → `bootc upgrade`.

**21 lib tests green.**

### 8.7 — OS boot-health gate (greenboot → `bootc rollback`)

`base/greenboot/check/required.d/10-hookprobe-soc.sh` + supervisor `--health-gate`: on **every boot**, greenboot runs the device's full self-check (verify manifest sig → verify module sigs → reconcile → self-test/heal) and the gate emits one verdict — **healthy** (baseline SOC `napse`+`hydra` running) → exit 0, deployment confirmed; **unhealthy** → exit non-zero → greenboot rolls `bootc` back to the last-good deployment. Validated: healthy → `exit 0` "BOOT HEALTHY"; a broken SOC module (napse shed) → `exit 1` "BOOT UNHEALTHY → roll back". This is the OS-level "self-test → else go back" — a bad image/module update is auto-reverted in seconds; the immutable rootfs makes rollback cheap; identity + data partition untouched.

**Remaining for a true unattended first-boot on metal (all need infra/hardware not on this box):** an actual **build-host run** of `builder/build.sh` (+ a hardened Containerfile) for the first flashable image; **real hardware sealing** when a TPM device is on hand (the CM5 has none → software-PUF stays the floor); automated fleet ring promotion.

### 8.8 — WiFi station/AP role + stable naming (Pi / CM5)

Raised by the operator: on a Pi the **onboard radio must always default to STATION** and any **add-on radio to AP** — but `wlanN` names reorder across reboots (USB vs SDIO timing). Validated on the live **Pi 4**: onboard `brcmfmac`/SDIO (Pi OUI `dc:a6:32`) was **`wlan1`**, USB `rtl88XXau` was **`wlan0`**, with **no role-pinning rules** → a real swap risk. V1 (`guardian-wlan-setup.sh`) keyed AP off `wlan1` — fragile.

Fixed in two layers (built + tested, 23 lib tests):
- **Identity, not name:** the prober now records `bus` + an `onboard` flag (`brcmfmac` ∨ SDIO/MMC bus ∨ a Pi MAC OUI) per interface; `crate::net_roles::assign_wifi_roles` assigns **onboard → station, add-on → AP** — never `wlanN`. Unit-tested with the exact Pi4 case (onboard `wlan1` → station regardless of order). Holds for CM5/Pi5 (onboard always `brcmfmac`).
- **Stable names:** `base/network/*.link` rename by driver → **`wlan-sta`** (onboard, `wpa_supplicant`) / **`wlan-ap`** (add-on, `hostapd`), so daemons bind correctly across reboots, USB re-plugs, and SD→NVMe moves. No per-board code.

### 8.9 — Driver/firmware prerequisite (immutable image) + Ethernet role stability

**The constraint (operator):** a signed immutable image **can't ship every driver/firmware** — external components (N100 PCIe `ath12k` Wi-Fi, USB Wi-Fi dongles, 5G modems) **fail silently** if their driver isn't baked in. Fixed:
- **Detection (built):** the prober scans `/sys/bus/pci`+`/sys/bus/usb` for network-class devices **present but with NO driver bound** → `scan.unbound`; bootstrap prints a loud `WARNING`. Validated: correctly identifies the N100's `ath12k` PCIe Wi-Fi + 4 NICs (0 unbound when driven; flagged when the firmware is absent). Silent failure → loud prerequisite.
- **Firmware bundle (built):** edge profiles now include `firmware-{brcm80211,iwlwifi,atheros,realtek,misc-nonfree}` + `modemmanager`/`libqmi`/`libmbim` — covers the common in-tree case out of the box.
- **Strategy** (`docs/architecture/driver-strategy.md`): out-of-tree drivers → a **signed driver sysext** (added per-deploy, no base rebuild) or a **custom profile variant**; per-component guidance (PCIe Wi-Fi, USB dongles, 5G modems).
- **Ethernet role stability** (`base/network/`): onboard/PCIe NIC names are PCI-path-stable; USB Ethernet pinned by MAC; **WAN/LAN is a policy choice on stable identity** (default: lowest onboard port = WAN, operator-overridable). 23 lib tests.

### 8.10 — Storage / boot-media identity (stable across /dev reorder)

Same naming-instability class: `/dev/sda` ↔ `/dev/nvme0n1` ↔ `/dev/mmcblk0` reorder across reboots (worse with mixed SD + NVMe boot media). Fixed:
- **Data partition** already mounts by `/dev/disk/by-label/hookprobe-data` (stable; `bootc upgrade`/`rollback` never touches it) — confirmed.
- **Device fingerprint** now keys off the **disk serial/wwid** (fallback to the /dev name), sorted — so `device_id` no longer changes when /dev names shuffle. Unit-tested (fingerprint stable across a dev rename when the serial is unchanged).
- **Prober** records `serial` + `removable` per disk (validated on N100: `nvme0n1` serial `493744134832335`, removable=false). Schema extended (optional fields); all example manifests still validate. **24 lib tests.**

### 8.11 — One model for every edge add-on (data provisioning · cellular · PCIe AI)

Stress-tested the "single OS for all edges" thesis with concrete CM5 add-ons — each absorbed by the **same** pipeline (detect → driver → capability → module → one console):
- **First-boot data-partition provisioning** (`base/scripts/firstboot-provision-data.sh` + `hookprobe-firstboot-data.service`): idempotent grow/mkfs/label of `hookprobe-data` for SD-card/SBC flows where the installer can't pre-create it; the by-label mount then activates. Closes the `var-lib-hookprobe.mount` TODO. Validated (`--check` plan: `nvme0n1p4` + `mkfs -L hookprobe-data`).
- **Cellular (USB 5G modem)** (`base/scripts/cellular-connect.sh` + `cellular.example.yaml` + `hookprobe-cellular.service`): runtime APN/PIN via ModemManager; idempotent; waits for late USB enumeration. Validated `--check` (found the N100's real modem). The driver is a deploy prereq (base `modemmanager`+firmware, or a sysext).
- **PCIe AI accelerator** (Hailo/Coral/MediaTek/Helio): prober `npu()` now detects PCI class `0x12` + known vendor IDs (`present`+`driver_ready`); the `unbound` scan flags it as `ai-accelerator` if undriven. So CM5 + PCIe AI chip → `edge_ai` grants once driver-ready → `edge-ai-detector` (WASI-NN) loads → surfaces in **Detect**. Validated (N100: npu absent, 0 unbound — correct).

`docs/architecture/driver-strategy.md` §5 has the unified add-on table. **24 lib tests; scripts syntax-clean + `--check`-validated.**

### 8.12 — Unified "Get Online" uplink model (single pane for all WAN types)

`crate::net_roles::enumerate_uplinks` + bootstrap `--uplinks`: **one list of every WAN candidate** — each wired port, the onboard Wi-Fi in station mode, and the cellular modem — in default failover priority (wired > Wi-Fi-station > cellular). The Wi-Fi uplink is the onboard **station** (never the AP radio). Validated live on the N100: **4×2.5GbE wired + 1 Wi-Fi-station + 1 cellular** in one view. This is the data behind a single-pane Get Online — `multi_wan` picks and fails over between them; the operator can override the priority.

**Now first-class in the signed manifest:** `build_manifest` writes `network.uplinks[]` (`{name, kind, priority}`, schema-validated, `kind ∈ {wired, wifi-station, cellular}`) and it is covered by the `ed25519-puf` signature — so the console and the multi-WAN reconciler read the failover list from the *verified* manifest, not from a re-probe. Live N100 manifest: 4 wired + 1 wifi-station (`wlan_24ghz`) + 1 cellular (`wwan0`). **26 lib tests.**

### 8.13 — Multi-WAN reconciler: intent → generated artifact (the AEGIS loop)

`crate::multi_wan` + supervisor `--wan-plan` consumes `network.uplinks` and renders the failover routing as a **generated** systemd-networkd artifact — the AEGIS pattern proven end-to-end: the operator declares intent (`--wan-intent <yaml>`: `disable:` uplink names/kinds, `prefer:` priority overrides), the reconciler emits config; the drop-ins carry a *"do not edit — declare intent instead"* banner and are reproduced from the **signed** manifest every run (config is an artifact, never the interface).

- **Mechanism (no steady-state daemon):** each uplink's DHCP/RA default route gets a **strictly-increasing unique kernel metric** (lower = preferred); the kernel uses the lowest reachable default route and falls through on link-down. The de-collide step spreads same-band siblings (4 wired → metrics 10,11,12,13) so the kernel never sees two default routes at one metric.
- **Artifact:** `50-hookprobe-wan-<iface>.network.d/10-metric.conf` per uplink (`[DHCPv4]/[DHCPv6]/[IPv6AcceptRA] RouteMetric=`). `--wan-write <root>` lays them down; default prints them.
- **Validated live on the N100** (signed manifest → plan → files on disk): default = `enp1s0 > enp2s0 > enp3s0 > enp4s0 > wlan_24ghz > wwan0` at metrics 10/11/12/13/20/30; intent `disable:[cellular] prefer:{wlan_24ghz:5}` re-rendered to Wi-Fi-primary (metric 5) with cellular dropped. Empty survivor set → explicit **OFFLINE** summary, never a silent empty plan. **31 lib tests.**

### 8.14 — Data-partition picker: enforce removable-media policy (a third reboot trap)

`crate::storage::select_data_target` + supervisor `--data-plan` decides WHERE the persistent `hookprobe-data` partition is provisioned, from `hardware.storage`. The trap it closes: a data partition placed on a **removable** non-boot disk (a USB stick plugged in once) would vanish on the next boot and break the by-label mount. Policy (canonical + tested):

1. **Never** select a removable non-boot disk (transient USB/SD) — excluded with a reason.
2. Safe automatic action = grow free space on the **boot disk** (boot matched by **serial** so it survives `/dev` reorders).
3. A fixed non-boot spare is **recommended** for dedication but **never auto-claimed** (it may already hold data — operator action).
4. A removable boot medium (Pi SD card) is still grown (the OS lives there) but **warns** and points at attaching a fixed disk.

`base/scripts/firstboot-provision-data.sh` (the executor) mirrors this: it now resolves the boot disk through an LVM/dm tree (fallback walks `lsblk -s` to the physical `disk`) and **refuses** to provision on a removable non-boot disk.

- **Validated read-only across all three tiers:** N100 (LVM root → grow `nvme0n1`), Pi4 (SD boot → grow `mmcblk0`), cloud VM (kvm/virtio → grow `sda`) — each via the live `--check` and the picker.
- **Trap proven:** a Pi4 manifest with an added USB stick (`sda`, removable) → stick **excluded** as transient, `mmcblk0` grown. **36 lib tests.**

### 8.15 — Wi-Fi role → generated artifact (the same loop, second concern)

`crate::wifi_cfg` + supervisor `--wifi-plan` renders the radio config — station radios → `wpa_supplicant-<iface>.conf`, AP radios → `hostapd-<iface>.conf` — from intent (`--wifi-intent`: `station:{ssid,psk}`, `ap:{ssid,passphrase,channel,band,hidden}`, `country`). Same generated-artifact contract as multi-WAN: "do not edit" banner, reproduced from the **signed** manifest each run.

- **Role by stable identity, not name.** *Which* radio is station vs AP is baked into the manifest as `network.wifi_radios[]` at build time by `net_roles::assign_wifi_roles` (onboard `brcmfmac`/SDIO → station; add-on → AP). The reconciler never re-probes `onboard`, so a Pi's onboard radio stays the uplink and the USB dongle stays the AP **regardless of `wlanN` boot-order renaming**.
- **Idle-safe & open-net aware:** a radio with no matching intent emits no file (never half-configured); empty psk → station `key_mgmt=NONE`; empty passphrase → open AP (no WPA block); 5 GHz → `hw_mode=a`, 2.4 → `hw_mode=g`; hidden → `ignore_broadcast_ssid=1`.
- **Idle-safe & open-net aware:** a radio with no matching intent emits no file (never half-configured); empty psk → station `key_mgmt=NONE`; empty passphrase → open AP (no WPA block); hidden → `ignore_broadcast_ssid=1`.

> ⚠️ The role-assignment rule below was **corrected** in §8.16 — it is uplink-aware now (a router runs *both* radios as APs, not one station + one AP). The original "first/onboard radio = station" only holds when Wi-Fi is the *sole* uplink.

### 8.16 — Dual-radio Wi-Fi (2.4/5 GHz): investigation + uplink-aware, band-aware model

**Live investigation (N100, the dual-radio exemplar, read-only).** `iw dev` shows the N100 running **two single-band radios, BOTH `type AP`, same SSID `hookprobe`** — `phy0/wlan_24ghz` ch6 (Band 1, 2.4 GHz, HT40) and `phy1/wlan_5ghz` ch36 (Band 2, 5 GHz, VHT80) — i.e. a **band-steered dual-band AP**, one `hostapd` instance per radio (`hostapd-ovs`), bridged into OVS, with V1 extras `hostapd.vlan` (VLAN-per-SSID) and `deny.mac` (MAC ACL). Neither radio is a station: the uplink is wired/cellular.

This exposed two model bugs (both fixed):

1. **Role must be uplink-aware.** `net_roles::assign_wifi_roles(interfaces, has_nonwifi_uplink)`: if the device has any wired/cellular uplink → **every radio is an AP** (the router case); only a device with **no other way online** turns its onboard radio into a station. So `enumerate_uplinks` now lists Wi-Fi as a WAN candidate *only* on a Wi-Fi-only device. (N100 uplinks are correctly `wired×4 + cellular`, no Wi-Fi.)
2. **Band by stable identity.** The probe detects each radio's band from its **phy frequency capability** via `iw phy <phy> info` (graceful — `None` if `iw` absent), not the `wlanN`/`*_24ghz` name. Baked into `network.wifi_radios[].band` (`2.4`/`5`/`6`/combo). One `ap` intent then renders **band-steering**: the same SSID to every AP radio, each with its band-correct `hw_mode`+default channel (2.4→g/ch6, 5→a/ch36, 6→a/ch37); `channel`/`band` are optional per-radio overrides.

- **Validated live on the N100** (signed manifest → plan): `wifi_radios = [{wlan_24ghz, ap, 2.4}, {wlan_5ghz, ap, 5}]`; one `ap:{ssid:hookprobe}` intent → `hostapd-wlan_24ghz.conf` (g/ch6) + `hostapd-wlan_5ghz.conf` (a/ch36), same SSID — **matching the running config exactly**. Wi-Fi-only path still yields an onboard-station uplink (Pi4 onboard `wlan1`). **43 lib tests.**
- **Deferred to the network-fabric work (§OVS):** VLAN-per-SSID (`hostapd.vlan`) and the **MAC ACL** (`deny.mac`/accept) — the latter is the "MAC binding" thread; it joins the OVS/OpenFlow investigation.

### 8.17 — Network fabric: modular L2/L3 data plane + segmentation beyond MAC

`crate::fabric` + supervisor `--fabric-plan` is the modular data-plane reconciler — same intent→artifact loop. Grounded in a full read-only investigation of the live exemplars (N100 LAN: OVS `FTS` bridge + mirror taps; cloud: `vrf-hp-{public,mssp,ids}`) and the V1 code (`fortress` OpenFlow, `vlan_manager`, `setup-ids-mirror.sh`, `setup-vrf.sh`). Design docs: `docs/architecture/network-fabric.md`, **`docs/architecture/network-segmentation.md`**.

**Two complementary planes, topology- & capability-driven (`kind: auto` default):**
- **L2 switching (OVS)** — only when there are **≥2 LAN carriers** (something to switch). One bridge: LAN ports + AP radios as members, **WAN uplink left off the bridge**, per-segment VLAN internal ports, out-of-band `tc mirred` IDS taps. Where the `openvswitch` capability isn't granted → **Linux-bridge fallback** (the V1 `FTS` pattern, `vlan_filtering`), honestly flagged as lacking OpenFlow MAC binding.
- **L3 routing separation (VRF)** — a VRF + table per segment (routes split from the global table), cross-segment dropped by nftables; meaningful even on a single NIC (the cloud "firewall for a separate vnet / super-PoP"). 
- **Hybrid** renders both at once (switch the LAN *and* separate routing domains).

**Segmentation beyond MAC (the identity problem).** MAC binding is broken for modern clients (randomization sets the locally-administered bit → no OUI, stale `dl_src` flows, trivial spoofing). So `fabric` segments by **layered identity**:
- `mac_class()` detects randomized (locally-administered) MACs → bindings rendered with an `# UNSTABLE` banner + a `via: dot1x` recommendation; MAC binding retained **only** for stable-OUI IoT.
- **802.1X `via: dot1x` → RADIUS `Tunnel-Private-Group-Id`** (`fabric/62-<br>.radius`) — the durable path, keyed on a credential, survives MAC rotation.
- **Onboarding `unknown_segment`** catch-all (`priority=10 → onboarding VLAN`) — unknown/randomized devices land in a low-trust segment, **never a silent drop/quarantine**.
- Roadmap (in `network-segmentation.md`): behavioural fingerprint ingestion (Senzorium DHCP/mDNS/TLS), hostapd-EAP mode, microsegmentation (OVS conntrack/eBPF east-west), continuous-trust dynamic re-segmentation (QSECBIT/HYDRA posture).

- **Validated live:** N100 → `auto` resolves **ovs-bridge** (5 LAN members incl. both AP radios, `enp1s0` WAN off-bridge); fail-closed `cameras` → `fail_mode=secure`; stable IoT MAC → flow, randomized MAC → flagged, `alice@corp via:dot1x` → RADIUS, unknown → onboarding VLAN 99. Cloud → `auto` resolves **vrf-segmented** (`vrf-hp-public/mssp/ids`, tables 101/102/103, `ids` fail-closed → no egress). **52 lib tests.**

### 8.18 — Behavioural fingerprinting: MAC-independent identity ("who has what")

`crate::fingerprint` + supervisor `--classify <obs.json>` answers the question MAC filtering can't: it classifies a device from observed signals — DHCP hostname (opt 12), vendor class (opt 60), parameter-request list (opt 55), and mDNS service types — into a `DeviceClass` + a `suggested_segment`, **layered strongest-first** (mDNS > vendor-class > hostname > opt-55 > OUI). OUI is consulted **only for universal MACs**; a randomized (locally-administered) MAC is flagged so it is never used as durable identity. Output is an AEGIS-style recommendation that feeds `fabric`.

- **Validated on the REAL N100 LAN** (built from live `dnsmasq.leases`, read-only): 5 devices, **2 with randomized MACs** — `c2:…` **iPhone** → `phone`/byod and `9e:…` **Mac** → `computer`/byod, both correct **purely from hostname despite having no OUI**; `dc:a6:32` guardian → `sbc`/infra (hostname + Pi OUI); an unrecognised device → **`unknown`/onboarding** (honest, not misclassified). This is the exact failure mode of MAC/OUI filtering (randomized clients → quarantine churn) resolved by behavioural identity. **58 lib tests.**

### 8.19 — Closing the loop: hostapd-EAP + the AEGIS identity→segment bridge

Two halves that close identity-driven segmentation end-to-end:

- **hostapd-EAP (802.1X port config).** `wifi_cfg` AP intent gained `auth: eap` (+`radius_server`/`radius_secret`/`dynamic_vlan`): renders WPA2-Enterprise — `ieee8021x=1`, `wpa_key_mgmt=WPA-EAP`, `auth_server_addr/port/shared_secret`, `dynamic_vlan=1` + `vlan_file`. The client authenticates → RADIUS returns the VLAN → hostapd dynamic-VLAN assigns it. This is the **edge port** that pairs with `fabric/62-<br>.radius`; missing RADIUS config is flagged, not silent.
- **AEGIS bridge (`fingerprint::recommend` + supervisor `--auto-segment`).** Decides segment **and enforcement mechanism** from identity: stable-MAC identified device → `mac-flow`; **randomized-MAC identified device → `dot1x`** (a `dl_src` flow would churn); unidentified → `observe`/onboarding. Reads the live dnsmasq leases, classifies, and emits a ready `fabric` `mac_bindings` fragment (the plan-as-diff).

**Validated end-to-end on the live N100** (leases → fingerprint → AEGIS → fabric): the Pi (`dc:a6:32`, stable) → OpenFlow `dl_src` flow → VLAN 40 (infra); the **randomized iPhone & Mac → RADIUS `Tunnel-Private-Group-Id` = 60 (byod), via 802.1X — not a MAC flow**; the unidentified device → onboarding VLAN 99. The full chain `observe → identify → decide → generate → enforce` now runs on real hardware. **62 lib tests.**

**Cross-platform — the same loop on Pi4 and CM5** (it's manifest-driven + capability/topology-gated, never hardware-branched):
- **Pi4 (live, edge-lite):** `auto` → **ovs-bridge** switching its two Wi-Fi radios (`eth0` WAN off-bridge); hostapd-EAP renders on both radios; **AEGIS `--auto-segment` on the Pi4's OWN live `dnsmasq.leases`** — its `Watch` client (`ca:b2:08`, a randomized MAC) → `wearable` → `byod` via **dot1x** (not a churning MAC flow). The full loop on a *second* real device with its own clients.
- **CM5 (synthetic `raspberrypi,5-compute-module` profile — hardware not yet on hand):** classifies edge-pro (rpi5); with a 2-LAN carrier board + onboard Wi-Fi → `auto` resolves **ovs-bridge** switching `eth1`+`wlan0`, `eth0` left as the WAN route. The exact "CM5 + carrier board, 1–2 LAN ports" case — OVS L2 switching engages automatically from topology, no per-board code. (A `wearable` device class was added; the Pi4 `Watch` exercised it.)

### 8.20 — Live signal enrichment: from leases to mDNS + DHCP fingerprints

The leases feed (MAC+hostname) leaves some devices `unknown`. `crate::fingerprint` now enriches from richer live signals — **mDNS** (`parse_avahi_browse`: services + `md=`/`model=`/`am=` TXT model strings), **DHCP opt-60 vendor class** (`parse_dnsmasq_dhcp_log` from `log-dhcp`), and **DHCP opt-55** parameter-request signatures — merged by IP/hostname (`enrich`). The classifier gained a top-priority **model-string** layer (a TXT `md=HomePod` is ground truth) and the previously-missing **opt-55** layer. `--auto-segment … --mdns <avahi> --dhcp-log <dnsmasq>`.

- **Validated live on the N100 (before → after):** leases-only left `E1680422` **unknown** and mis-guessed `hooksound` as `sbc`. With mDNS + the DHCP log: `E1680422` → **computer** (DHCP `vendor class: MSFT 5.0`), `hooksound` → **voice-assistant** (mDNS `md=HomePod`/`model=AudioAccessory5,1`) — also correcting its segment infra→iot. **0 unknowns, every device correct.** **66 lib tests.**

### 8.21 — Microsegmentation: east-west isolation inside a segment

A VLAN is the coarse (north-south) boundary; `crate::microseg` + supervisor `--microseg-plan` adds the **east-west** control so devices *in the same segment* can't talk freely (a compromised camera can't reach another camera). Per-segment posture: `open` (no restriction), `client-isolation` (reach only the gateway + established return traffic; new lateral flows dropped — the IoT/guest default), `allowlist` (client-isolation + named exceptions, e.g. the NVR may reach cameras on RTSP 554). Rendered as **stateful OVS conntrack** OpenFlow (table 0 → `ct`, table 1 → policy: established/gateway/allowlist pass, new east-west drop) and an **nftables** `ct state` variant for the Linux-bridge/VRF path. Segment names resolve to VLANs via the fabric segment list; unresolved references are flagged. **71 lib tests.**

### 8.22 — Continuous trust: posture-driven dynamic re-segmentation

`crate::trust` + supervisor `--trust-eval <posture.json>` closes the loop between segmentation and the detection plane. A `PostureSignal {mac, current_segment, risk (0–100, QSECBIT-derived), threat (none/suspicious/malicious, HYDRA)}` is evaluated to `keep` / `step-up` (force re-auth, stay) / `quarantine`. Quarantine renders a **priority-250 override** `dl_src→quarantine-VLAN` OpenFlow rule — above the normal per-device binding (200) — so it takes effect immediately and **reverts cleanly when the override is removed** (no teardown of the underlying segmentation). Identity is no longer frozen at join time.

- **Validated** on simulated posture for the N100 devices: clean → `keep`; a device beaconing to C2 + scanning the cameras VLAN (risk 88, malicious) → **quarantine** (VLAN 666 override); unusual egress (risk 52, suspicious) → `step-up`.
- **Live feed + convergent reconcile.** `build_posture` reads the detection plane's own files — `arp-status.json` (presence) + `blocked_macs.json` (threat) — and `reconcile()` makes the loop *continuous*: it adds overrides for newly-quarantined devices and **emits `del-flows` for recovered ones (auto-revert when posture clears)**. Run on the live N100 (5 ARP entries); a simulated HYDRA block of the HomePod + a prior iPhone quarantine produced exactly one add (HomePod→666) and one release (iPhone). `--arp`/`--blocked`/`--prev-quarantined`. (V1's `blocked_macs` stores an MD5 of the MAC; plain-MAC matching is wired, hashed matching is a follow-up.) **78 lib tests.**

> **The segmentation arc is now structurally complete:** `observe (leases+mDNS+DHCP) → identify (multi-signal fingerprint) → decide (AEGIS: segment + mechanism) → generate (fabric: VLAN/flows/RADIUS/VRF + microseg east-west) → enforce (hostapd-EAP/RADIUS) → continuously re-evaluate (trust → dynamic quarantine)`. Every stage is manifest/intent-driven, capability-gated, and validated on real hardware (N100 + Pi4 live, CM5 synthetic).

### 8.23 — Segmentation polish: identity-driven defaults, hashed blocked_macs, autonomous loop

Three hardening items closing the loop:
- **Identity-driven microseg defaults** (`microseg::default_isolation_for_segment` / `default_policies`): segments derived from fingerprinting get sensible posture automatically — cameras/iot/onboarding/guest auto-isolated, byod/infra open — so `--microseg-plan` needs no hand-written policy.
- **MD5-hashed `blocked_macs` matching** (`crate::md5`, a 60-line pure-Rust MD5 — RFC-1321 test vectors pass; not security-bearing): `mac_is_blocked` matches a device whether the blocked entry is a plain MAC or the MD5 of any of four normalizations, so V1's hashed file actually resolves. (The current live entry is a historical device not presently on the LAN — confirmed by a forensic check.)
- **Autonomous on-device loop:** `--quarantine-state <file>` makes the trust cycle self-contained (reads the prev set, rewrites the new set); `base/scripts/trust-reconcile.sh` + `hookprobe-trust-reconcile.{service,timer}` run it **every 30 s**, capability-gated on `openvswitch`. Validated across two cycles: flag → quarantine (state persisted), clear → **auto-revert** `del-flows` (state empties). **81 lib tests.**

### 8.24 — AEGIS: one intent → reconcile the whole network in a single pass

`crate::aegis` + supervisor `--reconcile-network <hookprobe.yaml>` is the project's *"operated by intent, not configured"* core, realised. One declarative `network:` document (sub-sections `wan` / `wifi` / `fabric` / `microseg` / `trust`, each optional → safe default) is reconciled in **one pass** against the signed manifest into **every** generated artifact — multi-WAN networkd drop-ins, hostapd configs, the L2/L3 fabric plan + OpenFlow flows, and microsegmentation conntrack/nft. It returns a **plan-as-diff** (one line per domain) + the flat artifact set + warnings (missing capability, unresolved segment). `--network-write <dir>` lays them down; `base/units/hookprobe-network-reconcile.service` runs it on boot from `/etc/hookprobe/network.yaml` (example: `base/config/network.example.yaml`).

- **Validated live on the N100** with the shipped example intent: one file → **11 artifacts** across all five domains; the plan-as-diff reads `WAN · enp1s0>…>wwan0 · Wi-Fi 2 APs · Fabric ovs-bridge 5 members/6 segments · Microseg (identity-driven: cameras/iot/quarantine isolated, trusted/byod open) · Trust quarantine→666`. Empty intent still reconciles safely (auto fabric + manifest WAN order); no `openvswitch` → Linux-bridge fallback warned. **84 lib tests.**

> All the network reconcilers (`multi_wan`, `wifi_cfg`, `fabric`, `microseg`, `trust`) are now driven by a **single intent + single pass**, the way AEGIS is meant to work — and the whole thing is generated from the signed manifest, capability-gated, with config as a reproducible artifact.

## 9 — Backend gap discovery + hardening (multi-agent audit, 2026-06-30)

A multi-agent review (8 parallel reviewers across build/lint, reconciler logic, identity/crypto, probe/manifest, generated-config validity, shell/units, integration, consistency; each finding adversarially verified) surfaced **46 confirmed gaps (2 critical, 15 high, 19 medium, 10 low)**. The defining theme matched the prediction: the reconcilers generated good artifacts, but **packaging/wiring was broken** (nothing ran) and several **generated configs were subtly invalid**. Fixed (full-workspace tests 174 green, 0 clippy errors):

**Critical / packaging (the "nothing runs" cluster):** supervisor.service passed non-existent `--manifest/--schema` flags + was `Type=notify` with no `sd_notify` → fixed to positional arg + `Type=oneshot`; bootstrap.service `--schema` dropped; `/usr/bin/hookprobe-supervisor` symlinked (callers used it but binary was in `/usr/lib`); `base/scripts/*.sh`, `modules/ovs/units/`, and `base/greenboot/check/` now installed by the Containerfile; the new reconcile/trust/firstboot/cellular units enabled in the preset; `trust-reconcile.sh` no longer `eval`s (strict allowlist + argv exec).

**Generated-config validity:** multi-WAN drop-in → self-contained `.network` (was an orphan) and dropped the invalid `[DHCPv6] RouteMetric`; microseg cross-segment `reg0` dead-flows removed (match the segment VLAN; `tp_dst` gets a default proto); nft `meta tcp dport` corrected and the blanket `ct state new drop` (which blackholed all routing) removed; **client-isolation now allows north-south via the gateway MAC** (the `nw_dst=gateway-IP` match missed internet-bound traffic); VRF forward chain gained accept rules (was default-drop → blackhole) + cross-segment log-drop; VRF ifname clamped to IFNAMSIZ; 6 GHz AP gets HE bits + a WPA3 warning; hostapd passphrase length validated.

**Pipeline integration:** the **MAC-binding + microseg flow tables were unified** (table 0 classify+bind → `resubmit(,1)` → table 1 conntrack → table 2 policy) so a bound device is no longer exempt from isolation, and the onboarding catch-all (previously shadowed) actually fires; a new **`network-apply.sh` + `ExecStartPost`** installs the staged artifacts to their live locations (networkd/hostapd/OVS) — closing the "produces output nothing consumes" gap; fabric WAN-uplink selection now respects `WanIntent` (can't bridge the active WAN); `enumerate_uplinks` excludes IDS-tap/inline NICs.

**Identity/crypto:** module-signature verification is **fail-closed** (an unverified `signature: required` module is refused, not silently trusted); an **unsigned manifest is refused** by default (`--allow-unsigned` is an explicit dev opt-in) — a stripped signature is no longer a silent downgrade; weak-PUF-entropy is surfaced loudly; `device_id` no longer includes the unstable `memory_mb`.

**Lint/correctness:** the deny-by-default `never_loop` (a `for{return}`) → `.find()`; `RiskLevel::from_str` renamed to avoid shadowing `FromStr`; MAC matching, `auth` parsing, and unknown capability/segment tokens all hardened against silent mis-handling.

**Honestly still open (documented, not silently "done"):** the legacy `modules/ovs/ovs-bringup` retains its own bridge logic and hasn't been refactored to consume the fabric plan (two paths; `network-apply.sh` runs the fabric plan); the supervisor is a one-shot pass, not yet a real `sd_notify` loop; full Linux-bridge east-west isolation (nft VLAN-aware) and the software-PUF random-nonce fallback are follow-ups. These are tracked, not hidden.

## 10 — First image build + self-test (Gate 0 + Gate 2 passed, 2026-06-30)

Building the OS image for the first time surfaced that the founding premise had no footing — and then validated the rest. Key finding: **there is no pullable Debian/Ubuntu bootc base image anywhere** (`ghcr.io/bootcrew/debian-bootc` is fictional; only RPM-based bases exist). Decision (operator): **build our own Debian base**. The apt probe showed Debian trixie already ships everything *except* `bootc` + `composefs` (kernel/dracut/systemd-boot/ostree/ukify all present), so "build our own base" = assemble from apt + compile those two — and for proving the flow, **boot-first**: a plain immutable Debian image now, bootc layered after.

**Gate 0 — `podman build` (amd64, `FROM debian:trixie`, reusing all Layer A–F work).** Each failure was a real one-line gap (the build smoke test earning its keep): builder tag `rust:1-trixie-slim` → `rust:1-slim-trixie`; missing `xz-utils` (tar couldn't unpack wasmtime); flaky GitHub egress → `curl --retry` + a new **`SKIP_GITHUB_DL` offline-build** arg (also a genuine air-gap capability); and the inspection found the **network intent wasn't installed** (so `network-reconcile.service`'s `ConditionPathExists` could never fire) → now `COPY … /etc/hookprobe/network.yaml`. Result: **`hookprobe-os:debian-min`, 435 MB, all 38 steps**, full apt package set installs clean on Debian trixie.

**Gate 2 — first-boot self-test inside the image (`builder/smoketest.sh`, podman-only, `--net=host`).** **9/0 PASS:** binaries+symlinks present → `bootstrap` writes a **classified (edge-pro) + ed25519-puf-signed** manifest → `supervisor` **VERIFIES** the signature → AEGIS **reconcile → 11 artifacts** from the shipped intent → `network-apply --check` clean. The whole self-provisioning chain runs on a real Debian systemd userspace with the real packages.

**Gate 2.5 — systemd boot chain (in-podman, `--systemd=always`).** Booting the image with systemd as PID 1 validated the *unit* wiring: `hookprobe-bootstrap → supervisor → network-reconcile` are enabled and correctly ordered, `trust-reconcile.timer` is active, and the **network-reconcile *service* runs the AEGIS reconcile and stages all 11 artifacts** (the plan-as-diff appears in the journal). The hardware-gated units (`var-lib-hookprobe.mount`, `firstboot-data`, `cellular`) correctly fail in a diskless container — confirming the chain gates on the data partition. A real finding: `bootstrap.service` hard-`Requires=var-lib-hookprobe.mount`, so the *entire* first boot hinges on `firstboot-data` creating that partition — the critical path the VM (Gate 1) must exercise with a real disk.

### Gate 1 — real boot in qemu-kvm (`mkosi` + `qemu`, boot-first, 2026-06-30)

Built a **bootable Debian image with mkosi** (the Arch/mkosi way: `FROM` packages, our binaries/units/scripts overlaid via `mkosi.extra/`, boot delta = kernel + systemd-boot + dracut). Host tooling installed along the way (mkosi 20.2, qemu 8.2, OVMF, ukify, musl). Choices forced by the toolchain: **bookworm** (mkosi 20.2's hardcoded bootable-package list predates Debian trixie's `t64` renames) + **static-musl binaries** (`x86_64-unknown-linux-musl` — zero glibc coupling to the VM, the right call for a portable edge binary anyway). Harness: `builder/mkosi/{mkosi.conf,mkosi.postinst,build-vm.sh,boot-vm.sh}` + an on-boot self-test (`base/scripts/selftest-boot.sh` + `hookprobe-selftest.service`) that prints a PASS/FAIL verdict to the serial console.

**✅ GATE 1 PASSED — it boots AND self-provisions, verdict PASS.** On a real qemu-kvm UEFI boot, the full chain runs in **12 seconds**: OVMF → systemd-boot → UKI kernel → systemd → `firstboot-data` provisions the data partition → mounts it → `bootstrap` writes a **signed, classified (edge-pro) manifest** → `supervisor` **VERIFIES** the signature → `network-reconcile` stages artifacts → the on-boot **self-test prints PASS**. (`net reconcile: 4 artifacts` — fewer than the N100's 11 because the VM has only virtio-net, no Wi-Fi/OVS; correct for the hardware.) Getting there surfaced **a series of real bugs (all fixed)** that no container test could — the boot earned its keep:
1. `firstboot-data` couldn't provision a disk written smaller than its medium (VM-grown raw; a 1.4 GB image on a 32 GB SD) — the **GPT backup header sits mid-disk**, so `sgdisk` saw no free space. Fixed: `sgdisk --move-second-header` before partitioning (helps real hardware too).
2. The data mount could **hang the boot forever** (a `.device` unit has no timeout). Fixed: `nofail` + `x-systemd.device-timeout=30s` so a provisioning failure degrades, not hangs.
3. `bootstrap.service` pulled in the **deprecated `systemd-udev-settle`**, which hangs ~120 s. Fixed: order after `systemd-udev-trigger` instead, and only *want* (not require) the data mount.
4. Serial-capture: a second `console=tty0` stole `/dev/console`, hiding all userspace output. Fixed: serial-only console.

5. **The boot deadlocked** waiting on udev → which waited on `sysusers` → which waited on **`systemd-firstboot.service`** — and that ran `systemd-firstboot --prompt-locale --prompt-timezone --prompt-root-password`, **blocking on interactive input that never comes** (a headless appliance must never do this). *Diagnosed via `systemd.log_level=debug`*, which exposed the exact `held back, waiting for…` chain. Fixed: `systemd.firstboot=off` on the kernel cmdline.
6. `network-reconcile.service` ran **before** `bootstrap` wrote the manifest (skipped on its `ConditionPathExists`). Fixed: `After=hookprobe-bootstrap.service`.
7. `supervisor.service` **errored on a missing `modules/` dir** (fresh data partition). Fixed: the supervisor now treats an absent modules dir as zero modules.
8. `network-reconcile.service` failed `226/NAMESPACE` because its `ReadWritePaths=/etc/hostapd` doesn't exist on a minimal image. Fixed: optional-path prefix (`-/etc/hostapd`) + `network-apply.sh` creates its target dirs.

**Why this matters:** bugs 1, 5, and 6–8 are *real OS bugs that would have bricked a fresh Pi4 install*, not VM artifacts — the GPT-relocation (a small image on a big SD), the interactive-firstboot deadlock (any headless boot), and the first-boot chain ordering. Catching them in a 12-second VM loop instead of on an SD card is exactly the point of Gate 1.

### Gate 3 — arm64 / Pi 4 image (2026-06-30)

**Gate 3a — cross-build (PASSED).** The Rust workspace cross-compiles cleanly to
`aarch64-unknown-linux-musl` (linker `aarch64-linux-gnu-gcc`; crypto is pure-Rust so there's
no C-dependency cross-pain). Output is genuinely static aarch64 ELF and executes under
`qemu-aarch64-static`. Toolchain added: `qemu-user-static` + binfmt, `gcc-aarch64-linux-gnu`,
`qemu-system-aarch64`, AAVMF (arm64 UEFI).

**✅ GATE 3b PASSED — the arm64 image boots AND self-provisions, verdict PASS.** New
`builder/mkosi-arm64/` (mirrors the amd64 harness with `Architecture=arm64`, `linux-image-arm64`,
the non-free-firmware Wi-Fi bundle, `console=ttyAMA0`). Booted under `qemu-system-aarch64 -M virt`
+ AAVMF (TCG emulation — no cross-arch KVM) and ran the **identical first-boot chain to a green
self-test**:

```
  firstboot-data : ok
  data partition : mounted
  manifest       : signed, class=cloud
  supervisor     : ok
  net reconcile  : 4 artifacts
  >>> HOOKPROBE-SELFTEST: PASS
```

Two things worth noting: (a) wall-clock was **2 min 15 s** but that's *emulated* (kernel 11 s +
userspace 78 s are TCG-dilated; on real Pi 4 silicon this is ~10–15 s — the amd64 KVM run was
12 s). (b) The manifest self-classified as **`class=cloud` (`match=virt:qemu`)**, not edge-pro —
**correct behaviour**: the prober detected a virtualized aarch64 environment and picked the cloud
profile. On real Pi 4 hardware it will detect the Pi and classify as an edge profile. This proves
the "detect once, classify per-environment" invariant works on arm64, not just amd64.

**Net result: the OS now builds, self-tests in-container, and boots+self-provisions to a green
verdict on BOTH amd64 (KVM) and arm64 (emulated) — the same signed-manifest chain, two
architectures.**

**Gate 3c — Pi 4 boot substrate (PASSED) + dongle drivers (mechanism done, compile pending).**

*Pi 4 SD image — assembled + verified.* Operator chose the **Debian-native `raspi-firmware`**
boot path (config.txt loads the kernel directly; firmware from the Debian-signed package, not a
third-party GitHub binary — best supply-chain). `make-pi4-image.sh` takes the **byte-identical
Gate-3b rootfs** and re-lays it for the Pi 4: extracts the kernel (`vmlinuz` from the ESP), the
initrd (the `.initrd` section of the UKI, via `aarch64-linux-gnu-objcopy` — host x86 objcopy
can't parse the aarch64 PE), and the `bcm2711-rpi-4-b.dtb` (ships in the Debian kernel package);
fetches `start4.elf`/`fixup4.dat`/`bootcode.bin` from `raspi-firmware`; builds an SD image
(`hookprobe-os-pi4.img`: p1 vfat **bootfs** 256 M + p2 ext4 **hookprobe-root** 1.7 G) with a
generated `config.txt` (`arm_64bit=1`, `kernel=kernel8.img`, `initramfs8`, `device_tree=…`) and
`cmdline.txt` (`console=ttyAMA0` + `root=LABEL=hookprobe-root` + `systemd.firstboot=off`).
**Verified:** partition table, both filesystems, the HookProbe binaries + `/usr/bin` symlinks +
all units (firstboot-data/bootstrap/supervisor/network-reconcile/selftest…) + kernel modules,
`fstab`, and the boot-partition contents are all correct. **Not boot-tested in qemu** — this
qemu build has no `raspi4b` machine; the Pi 4 boot path validates on real hardware (Gate 4/5).

*USB-Wi-Fi dongle drivers — supply-chain + mechanism complete; per-driver compile is a port.*
Operator chose **vendor + pin**: `vendor-drivers.sh` cloned all 7 Realtek sources ONCE at
recorded commits into `base/drivers/` (SHAs in `base/drivers/SOURCES.md`); the build then
compiles **only from the local pinned trees** (no live external repos) in an emulated arm64
container against the image's exact kernel, stages `.ko` to `/usr/lib/modules/<ver>/updates/
hookprobe/`, and `hookprobe-depmod.service` regenerates `modules.dep` at first boot. The
**morrownr** trees (`AUTODETECT`) build cleanly; the **aircrack-ng/lwfinger/clnhub** trees
(`I386_PC=y`) get an arm64 platform fixup but then hit a kernel-6.1 `MODPOST … Can't read "-"`
quirk — a known out-of-tree-vs-modern-modpost incompatibility that needs a small per-driver
patch (best done against the real kernel, not in slow emulation). So: the *pipeline* is proven
and the *answer to "can we bake dongle drivers?" is yes*; finishing the compile of the
hardcoded-platform drivers is a bounded follow-up. `docs/architecture/driver-strategy.md` §6 carries the full
supported-Wi-Fi matrix. (Minor, separate: ensure `wireless-regdb`'s `regulatory.db` lands in
`/lib/firmware` — a cosmetic boot-log warning.)

**Still ahead — Gates 4–5:** flash `hookprobe-os-pi4.img` to the Pi 4 SD and fresh-install (back
up the live V1 SD first, per the operator's choice to wipe it). This needs the physical device.
`bootc`+`composefs` layer after boot-first is proven on hardware.



