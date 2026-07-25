# `base/` — the HookProbe OS bootc base image

> **Readme Pillar 1 / ADR 0019 D1: "the OS is a Containerfile."** This directory holds
> the single `Containerfile` that *is* HookProbe OS, the per-target build `profiles/`,
> the `systemd` `units/` that realize the boot-to-runtime spine, and the image
> `config/` (kargs, sysctls, cgroup slices, cosign policy, data-partition split). Build
> it with `podman build`, cosign-sign it, push to a registry, turn it into disk
> artifacts with `bootc-image-builder`. **Update mechanism is split by tier (ADR 0019
> D2/D3):** UEFI-tier devices run real `bootc upgrade` / `bootc rollback`; the
> rpi-native tier (today's shipping Pi4 image) has no bootc and updates via an
> OCI-derived A/B image-sync path instead (not yet shipped — Phase 3). See
> `docs/adr/0019-bootc-debian-substrate.md`.

---

## ⚠️ Honest scope — Phase 1 (ADR 0019): base is real, tooling is wired, egress is the wall

**Updated 2026-07-05.** The base image is no longer fictional: `ARG
BASE_IMAGE=docker.io/library/debian:trixie`, verified pullable
(`podman pull docker.io/library/debian:trixie` succeeds on this box). `bootc` +
`bootupd` are now compiled in a dedicated `bootc-tools` build stage (composefs-rs
rides in as bootc's own Cargo dependency, not a separate build — ADR 0019 F1/D2).

**This image still cannot be built end-to-end on the current dev box** — but for a
narrower, more precise reason than before. `podman` **is** available and registry
pulls work fine (`podman pull` succeeds); what's blocked is **build-time HTTP(S)
egress from inside a `podman build` RUN step** — confirmed empirically 2026-07-05:
`apt-get update` against `deb.debian.org` inside a `RUN` (a PRE-EXISTING layer,
not new) hangs/`Connection failed`, and `git clone` against `github.com` inside the
new `bootc-tools` stage is blocked the same way. This is the same class of
restriction the existing `SKIP_GITHUB_DL` escape hatch already worked around for
wasmtime/cosign — now confirmed broader (it's not github-specific) and reused for
the same purpose in the `bootc-tools` stage. So:

- The `Containerfile` is written to be **as correct and realistic as possible**, and
  the new `bootc-tools` stage **was verified to build cleanly** under
  `--build-arg SKIP_GITHUB_DL=1` (`podman build --target bootc-tools`), producing an
  honest stub binary that errors loudly (`exit 1`, clear message) rather than
  silently no-op'ing. Without `SKIP_GITHUB_DL`, the same stage was verified to
  correctly ATTEMPT the real fetch and hang/fail exactly at the network boundary —
  not from a Containerfile logic bug.
- Genuinely-uncertain specifics (`bootc-image-builder` filesystem-customization
  syntax, Pi bootloader handling, the exact bootc/bootupd build-dep apt list) are
  marked with explicit `# TODO:` rather than invented.
- Treat every version pin as **deliberately pinned, CI-reverifiable** (ADR 0019 D2 —
  "pin, don't float" for the experimental composefs-native backend), not a guarantee
  that a networked build will succeed unchanged forever.

What CI needs to actually build + sign it is in [CI requirements](#what-ci-needs) below.

---

## `FROM` rationale — what base image, and why (2026 research)

The load-bearing distro decision is **Debian/Ubuntu** (Readme TL;DR; OVS is a
first-class `apt` package, ARM SoCs are natively supported, no per-device
subscription). The open question is *which bootc base to build on*, because the
mature, production-grade bootc bases today are RHEL-family, not Debian.

What the ecosystem looks like in mid-2026:

- **There is no single canonical *official* Debian/Ubuntu bootc base image yet.** The
  proven, pre-built bases are RHEL-lineage: `quay.io/fedora/fedora-bootc`,
  `quay.io/centos-bootc/centos-bootc`, and AlmaLinux's experimental bootc images.
- **The Debian-aligned path is the Bootcrew effort.** Bootcrew packages and tests
  bootc's **composefs-native backend** (composefs-rs) across distros; the
  per-distro experiments (`bootcrew/debian-bootc`, `bootcrew/ubuntu-bootc`,
  `bootcrew/opensuse-bootc`, `bootcrew/arch-bootc`) were **consolidated into
  `bootcrew/mono`** and publish images to **ghcr.io**. The Debian experiment was
  active as recently as **2026-03**. It is explicitly experimental ("find out what's
  required to get a functional system and submit upstream").
- **bootc itself is distro-agnostic** (CNCF project, stable CLI) and **SteamOS ships
  on bootc**, so the substrate is proven even where the Debian base is young.
- **`bootc-image-builder`** (osbuild) turns a bootc container into disk images:
  `qcow2`, `raw`, `ami`, `vmdk`, and an `anaconda-iso` installer; `--type` is
  repeatable and `--target-arch aarch64` cross-builds for the Pi. **Raspberry Pi
  needs bootloader/firmware handling** (cf. `ondrejbudai/fedora-bootc-raspi` patching
  `bootupd`) — a real TODO for our SBC profiles.

**Decision, RESOLVED by ADR 0019 D2 (supersedes the original scaffold plan below):**
`ghcr.io/bootcrew/debian-bootc:trixie` was never actually pullable from any
registry (found at build Gate 0, 2026-06-30 — it does not exist as a published
image, only as source repos). Rather than depend on Bootcrew publishing a base we
don't control, **build our own**: `FROM` plain, real, verified-pullable
`docker.io/library/debian:trixie`, then add the bootc substrate ourselves —
apt (kernel-6.x, systemd-boot, ukify, ostree, dracut, grub-efi, skopeo — all
already in trixie's apt) + two compiled binaries (`bootc`, `bootupd` — composefs-rs
rides in as bootc's own Cargo dependency, not a third build). This is now the
build-arg:

```dockerfile
ARG BASE_IMAGE=docker.io/library/debian:trixie   # verified pullable, 2026-07-05
ARG BOOTC_VERSION=1.16.3      # pinned (ADR 0019 D2 — composefs-native is experimental)
ARG BOOTUPD_VERSION=0.2.35    # matched pair (bumped to bootc-internals v1.16.0)
```

`bootcrew/mono` remains a useful **reference** for what packages/build steps a
Debian-bootc system needs (that's where the apt package list + build-dep list
above came from), but this repo no longer depends on it existing as a pullable
registry image.

Residual risk, stated plainly: the composefs-native backend is **experimental**
("not yet suitable for production use" as of bootc v1.10.1, where it became
always-compiled-in — ADR 0019 F1). If it is not boot-stable for our targets, the
fallback ladder is (1) pin an older known-good bootc/composefs-rs combination,
(2) fall back to the ostree backend on Debian (less-trodden but real), or (3) —
only as an emergency, and at the cost of the Debian decision — temporarily base on
`quay.io/centos-bootc/centos-bootc`. Track composefs stabilization (ADR 0019
Phase 4) and re-pin deliberately, never float `latest`.

> Note: the `docs/Readme.md` Pillar-1 example uses `bookworm-bootc`. Debian **trixie**
> (13) is the current stable in 2026 and what Bootcrew tracks, so this scaffold uses
> `trixie`. That doc example should be updated to match (flagged here, not edited —
> this work is scoped to `base/**`).

Sources:
- [bootc-dev/bootc](https://github.com/bootc-dev/bootc) · [bootc.dev](https://bootc.dev/)
- [bootcrew/debian-bootc](https://github.com/bootcrew/debian-bootc) · [bootcrew org](https://github.com/bootcrew) · [bootcrew/ubuntu-bootc](https://github.com/bootcrew/ubuntu-bootc)
- [osbuild/bootc-image-builder](https://github.com/osbuild/bootc-image-builder) · [README](https://github.com/osbuild/bootc-image-builder/blob/main/README.md) · [osbuild bootc docs](https://osbuild.org/docs/bootc/)
- [ondrejbudai/fedora-bootc-raspi](https://github.com/ondrejbudai/fedora-bootc-raspi) (Pi bootloader handling)
- [AlmaLinux/bootc-images](https://github.com/AlmaLinux/bootc-images) · [Bootable Containers — projects](https://containers.github.io/bootable/projects.html)

---

## What's in the image (layer by layer)

The `Containerfile` is a two-stage build. Full per-layer comments live in the file;
the summary:

**Stage `build`** — cross-compiles the two **host-integral** Rust binaries
(`hookprobe-bootstrap`, `hookprobe-supervisor`) from the workspace. These are part of
the OS (run as root / privileged services), so unlike Wasm modules they are baked into
the immutable image. *(CI may instead inject pre-built, independently signed binaries —
TODO in the file.)*

**Stage `os`** — the bootc image:

| Layer | Provides | Why it's here |
|---|---|---|
| A — apt | `podman`+`crun`+rootless plumbing; `openvswitch-switch`; eBPF/XDP libs (`libbpf1`,`libxdp1`,`xdp-tools`,`bpftool`); one-shot probe deps (`lshw`,`dmidecode`,`iw`,`tpm2-tools`,…) | "you own every layer" — install OVS et al. directly; CO-RE loader libs for the NAPSE-capture sysext (no clang on-device) |
| A2 — bootc substrate (apt) | kernel-6.x, `systemd-boot`, `systemd-ukify`, `ostree`, `dracut`, `grub-efi-<arch>-bin`, `skopeo` | ADR 0019 D2 — everything the bootc/composefs-native model needs THAT Debian already packages; UEFI-tier (amd64/arm64) only, riscv64 skipped honestly (no bootc there — ADR 0019 F2) |
| B2 — bootc + bootupd (compiled) | `/usr/bin/bootc`, `/usr/bin/bootupd` | ADR 0019 D2 — the two binaries Debian's apt cannot provide, built in the dedicated `bootc-tools` stage (composefs-rs is bootc's own Cargo dependency, not a separate build); an HONEST STUB (loud error, never silent) ships instead of a real binary when `SKIP_GITHUB_DL` suppressed the compile |
| B — wasmtime | `runtime: wasm` module runtime (Pillar 2) | not in Debian apt → pinned upstream release |
| C — cosign | on-device **verification** of module + manifest signatures | ADR 0002 — devices only verify; signing keys never ship |
| D — binaries | `/usr/lib/hookprobe/{bootstrap,supervisor}` | the boot→runtime spine (Architecture C3–C11) |
| E — RO tables | `platforms/*.yaml` + manifest JSON Schema → `/usr/share/hookprobe/` | signed static `id→capability` tables (Architecture C1) |
| F — units+preset | `systemd` units + cgroup slices, enablement baked | realizes C3/C8/C15 + §4.3 |
| G — kargs+sysctl | cgroup v2 + PSI kargs; eBPF/capture/forwarding sysctls | budget model + out-of-band default |
| H — cosign policy | `containers/policy.json` signed-by (default reject) | "trust nothing unsigned" |
| I — data split | tmpfiles + `var-lib-hookprobe.mount` | persistent data partition vs immutable rootfs |
| J — rootless | `hookprobe` user + subuid/subgid | `runtime: container` modules run rootless |
| K — lint | `bootc container lint` | catch image-mode footguns (make it a hard CI gate) |

OVS and the (future) NAPSE-capture XDP objects are **image-layer / sysext**, per
`docs/runtime-engine-map.md` — host-integral dataplane, not Wasm modules.

---

## systemd units (`base/units/`) — the spine

| Unit | Role | Key directives (Architecture ref) |
|---|---|---|
| `hookprobe-bootstrap.service` | probe → signed manifest; re-probes on missing manifest **or** newer platform-rules | `ExecCondition=…hookprobe-bootstrap --check-rules-version`, `After=systemd-udev-trigger`, `Type=oneshot` (C3–C7) |
| `hookprobe-supervisor.service` | long-running reconciler + serves sockets | `Type=notify` + `WatchdogSec` + `Restart=on-failure` + `StartLimitBurst`, unit hardening, `Slice=hookprobe-live.slice` (C9–C11, C15, §4.4) |
| `hookprobe-manifest.socket` | **RO** manifest API (world-connectable) | `SocketMode=0666`, RO server-side (C8, ADR 0003) |
| `hookprobe-control.socket` | **RW** intent/control (admin-only) | `SocketMode=0600` (C9) — never `0.0.0.0` |
| `hookprobe.slice` / `-live` / `-background` | cgroup hierarchy: aggregate cap, high-prio live path, low-prio deferrable work | `CPUWeight` 800 vs 50, PSI-driven shed (§4.3, C11) |
| `var-lib-hookprobe.mount` | mounts the persistent data partition | label `hookprobe-data`, survives `bootc upgrade` (ADR 0003) |

A socket pair (world-readable manifest reads; admin-only writes) directly encodes the
"capabilities are public, mutation is privileged" contract.

---

## Build → sign → ship → image (the one pipeline)

```bash
# 1) Build the bootc image (from REPO ROOT; the build stage needs the Rust workspace).
podman build -f base/Containerfile \
  --build-arg PROFILE=edge-pro \
  --build-arg TARGETARCH=arm64 \
  -t ghcr.io/hookprobe/os:2026.6-edge-pro-arm64 .

# 2) Sign it (cosign). Signing keys live OFF-device, in the release HSM/pipeline
#    (ADR 0002 §5). Hybrid composite ML-DSA-65 + Ed25519 is the target; sigstore PQC
#    is still maturing, so dual/composite signing is the interim path.
cosign sign --key <hsm-or-kms-ref> ghcr.io/hookprobe/os:2026.6-edge-pro-arm64   # TODO: composite PQC

# 3) Push to the registry.
podman push ghcr.io/hookprobe/os:2026.6-edge-pro-arm64

# 4) Emit disk artifacts per profile (bib block in base/profiles/<profile>.yaml).
#    Example: RK3588 flashable image. --type repeatable; --target-arch cross-builds.
sudo podman run --rm -it --privileged \
  -v ./out:/output \
  -v /var/lib/containers/storage:/var/lib/containers/storage \
  quay.io/centos-bootc/bootc-image-builder:latest \      # TODO: pin bib version/digest
  --type raw --target-arch aarch64 \
  --config /config/edge-pro.toml \                        # generated from the profile bib: block
  ghcr.io/hookprobe/os:2026.6-edge-pro-arm64
# → out/.../disk.raw  → xz → hookprobe-edge-pro-arm64.img.xz
```

Per-profile outputs (from `base/profiles/*.yaml`): `.img.xz` (SBC), `.iso` (x86),
`.qcow2`/`.vmdk` (VM), `.raw`/`.ami` (cloud).

---

## The `bootc upgrade` / `rollback` model

**This section describes the UEFI tier only (ADR 0019 D2).** The rpi-native tier
(today's shipping Pi4 image, ADR 0019 F2) has no bootc, no second deployment slot,
and no rollback yet — see `base/greenboot/README.md` for what actually happens
there today and what the A/B image-sync path (ADR 0019 D3, Phase 3) will add.

Once a UEFI-tier device runs this image:

- **`bootc upgrade`** pulls the newest signed image from the registry (composefs
  dedupes + fsverity-checks blocks → cheap deltas), stages it as the *next* boot
  entry, and switches atomically on reboot. The previous entry is retained.
- **`bootc rollback`** flips back to the prior entry in seconds. Pair it with a
  boot-counting/greenboot-style health gate so a failed boot **auto-rolls-back**.
- A **tampered or unsigned image fails cosign verification and won't boot-switch**
  (Architecture C1, policy.json default-reject).
- **The persistent data partition (`/var/lib/hookprobe`) is never touched** by an
  upgrade or rollback — only the immutable rootfs swaps. The signed manifest, events,
  pcap, evidence, and TPM-sealed secrets survive (ADR 0003; Readme "Data & retention").
- **Re-seal on update:** PCR-sealing is brittle across OS updates — the update flow
  must re-seal the manifest, or readers fall back to cosign-only verification
  (ADR 0003 §lifecycle; open-Q).

This is the same atomic-update model whether it's one Pi or a national fleet; at scale
it's driven pull-based via GitOps (Readme "Fleet & scale", out of scope for `base/`).

---

## What CI needs

To turn this scaffold into a real, signed, bootable image, CI must provide:

1. **A builder host with `podman`** (rootful or rootless w/ privileges for buildkit
   cache mounts) on an **arm64 + amd64 matrix** (native runners or `qemu-user-static`).
2. **Real network egress from inside `podman build` RUN steps** — to `deb.debian.org`
   (apt, both the `build` stage's deps and the new Layer A2 bootc-substrate
   packages), `github.com` (wasmtime/cosign release assets AND, new as of ADR 0019
   Phase 1, `bootc-dev/bootc` + `coreos/bootupd` source clones in the `bootc-tools`
   stage) — with **checksum/signature verification** added for each download (TODOs
   in the Containerfile). **Verified 2026-07-05 that this dev box does NOT have
   this**: `podman pull` (registry) works, but `apt-get`/`git clone` inside a
   `podman build` RUN step do not reach either host — confirmed for both the
   pre-existing `build`-stage apt-get AND the new `bootc-tools` stage. This is why
   the image cannot be built end-to-end here; it is not a Containerfile defect.
3. **The Rust toolchain** for the `build` stage (or pre-built, signed binaries
   injected) — ALSO now needed for the `bootc-tools` stage (compiling `bootc` +
   `bootupd`; composefs-rs is bootc's own Cargo dependency, not separate).
4. **cosign signing identity** — ideally keyless (Fulcio/Rekor) or an HSM/KMS key;
   **never a private key in the repo or image** (ADR 0002 §5). Plus the public trust
   material injected into `/etc/pki/hookprobe/` for `policy.json`.
5. **`bootc-image-builder`** (pinned) run **privileged** to emit disk artifacts per
   profile, then `xz`-compress / AMI-register as the profile's `bib:` block specifies.
6. **SBOM + CBOM generation** per image (CycloneDX) attached as OCI artifacts
   (`security/`; ADR 0002 §4) — and `bootc container lint` promoted to a **hard gate**.
7. **A boot smoke-test** (boot the `.qcow2` in a VM, assert `hookprobe-bootstrap`
   writes a schema-valid manifest and `hookprobe-supervisor` comes up `notify`-ready)
   before publishing — the only way to catch what can't be checked statically here.

---

## Known TODBs / residual risks (consolidated)

- **composefs-native backend maturity** — experimental as of bootc v1.10.1+ ("not
  yet suitable for production use"); pinned (`BOOTC_VERSION=1.16.3`,
  `BOOTUPD_VERSION=0.2.35`) and tracked, not floated (ADR 0019 D2/Phase 4).
- **bootc/bootupd build-dep apt list is unverified in THIS environment** (Layer
  B2/`bootc-tools`) — written from upstream CONTRIBUTING notes (cargo, git,
  dracut, glibc, ostree headers), never actually exercised end-to-end here because
  build-time egress is unavailable (see "What CI needs" above). First networked CI
  run must re-verify it, honestly, rather than assume it's complete.
- **Pi bootloader/firmware** — rpi-native tier does NOT use bootc/bootupd at all
  (ADR 0019 F2 — no UEFI, no bootloader bootc can manage); pftf/EDK2-UEFI-on-Pi
  remains a tracked convergence (ADR 0019 D5), not the shipping path. The A/B
  image-sync agent (ADR 0019 D3) is the real Pi update mechanism, not yet built.
- **`bootc-image-builder` filesystem-customization syntax** — the separate labelled
  `hookprobe-data` partition (and ISO-installer partitioning) must be validated against
  the pinned bib version; the `bib:` blocks in `profiles/*.yaml` are the intent, not a
  verified config.toml.
- **wasmtime / cosign release-asset URLs + checksums** — verify and gate in CI.
- **cosign PQC** — composite ML-DSA signing in sigstore is still maturing; interim is
  dual/composite signing (ADR 0002 consequences).
- **Capability bounding sets** for `bootstrap` (needs broad hardware access) and the
  privileged host bridge for `supervisor` (OVS/Podman/mount) are stubbed — tighten once
  the real probe + OS-Agent IPC exist (Architecture §4.4).
