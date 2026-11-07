# Build-host runbook — from `git pull` to a flashable HookProbe OS image

The dev box can't build images (no privileged podman / bootc-image-builder). This is
the one-time setup + the commands to run on a **build host** (a Linux box or CI
runner you control). Once set up, producing all images is a single `build.sh` call
per profile.

## 0. Build host requirements

- Linux (Ubuntu 24.04 / Fedora 40+), x86_64 **and/or** arm64 (native build per arch;
  cross-build works via QEMU but native is faster).
- **podman** (rootful, or rootless + `--privileged`), **python3 + PyYAML**, **cosign**,
  and network access to pull the bootc base + `bootc-image-builder`.
- ~20 GB free for image artifacts.

```bash
# Ubuntu 24.04
sudo apt-get update && sudo apt-get install -y podman python3 python3-yaml qemu-user-static
# cosign (sigstore)
curl -fsSL -o /usr/local/bin/cosign https://github.com/sigstore/cosign/releases/latest/download/cosign-linux-amd64
chmod +x /usr/local/bin/cosign
# pre-pull bootc-image-builder
podman pull quay.io/centos-bootc/bootc-image-builder:latest
```

## 1. One-time keys (production = HSM; dev = local)

```bash
# Image-signing key (cosign). Production: keep in the release HSM, never on the host.
cosign generate-key-pair                      # → cosign.key / cosign.pub
# Module release key is created by sign-release.sh (builder/release.key, dev stand-in).
```

Bake the **public** keys into the image trust store (so devices verify, never sign):
`cosign.pub` → image-signing trust; `builder/trust/release.pub` → module trust at
`/usr/share/hookprobe/trust/` (add the `COPY builder/trust/ /usr/share/hookprobe/trust/`
line to `base/Containerfile`).

## 2. Build images (one command per profile)

```bash
cd hookprobe-os
# Preview anywhere (no podman):
builder/build.sh --profile edge-pro --plan

# Real build on the host:
COSIGN_KEY=cosign.key builder/build.sh --profile edge-pro     # arm64 .raw + amd64 .iso
COSIGN_KEY=cosign.key builder/build.sh --profile cloud        # .raw + .ami (+ arm64)
COSIGN_KEY=cosign.key builder/build.sh --profile virtual --type qcow2   # boot-test image
```

Artifacts land in `builder/out/` (`.raw`/`.iso`/`.qcow2`/`.ami`).
`build.sh` runs `sign-release.sh` first, so modules are signed + the trust store baked.

## 3. Boot-test before shipping (qemu, no hardware)

```bash
qemu-system-x86_64 -m 4096 -nographic \
  -drive file=builder/out/virtual-x86_64.qcow2,format=qcow2 \
  -bios /usr/share/OVMF/OVMF_CODE.fd
# Expected first boot: bootstrap probes hw → writes /var/lib/hookprobe/manifest.json
# (signed) → supervisor verifies sig → verifies module signatures → reconciles →
# self-test/heal. Confirm: `journalctl -u hookprobe-supervisor` shows "manifest
# signature: VERIFIED" + the reconcile/health report.
```

## 4. Flash / install on a device

- **Pi 5 / CM5 / RK3588** (`.img.xz`): `xz -d <img.xz>` then `dd`/`rpi-imager` to SD/NVMe.
- **x86 (N100)** (`.iso`): write to USB (`dd`), boot the installer.
- **Cloud** (`.ami`/`.raw`): import to the cloud provider.
- **Existing machine** (no reflash): `bootc install to-disk <dev>` / `to-existing-root`
  lays the immutable image down in place — the "run one command on any machine" path.

First boot is unattended: detect → sign → verify → reconcile → heal. Then **claim** it
(set local admin; no account needed — see §first-boot claim) and optionally enroll to a
fleet/tenant.

## 5. Updates (no re-flash)

```bash
# Push the signed image to a registry, then on the device:
bootc upgrade           # pulls the new signed image; health-gated; bootc rollback on failure
```

## 6. CI

`builder/gen-matrix.sh` emits the build matrix from `base/profiles/*.yaml` for the
GitHub Actions image job — adding a platform stays "one profile file":
```yaml
matrix: ${{ fromJson(needs.plan.outputs.matrix) }}   # plan step: builder/gen-matrix.sh
```

## 7. arm64 Raspberry Pi metal build → flash → validate (the mkosi-arm64 path)

The §2 `build.sh`/bootc-image-builder path is the target production pipeline. The
combined arm64 Pi image that has actually been booted on Pi4/CM5 metal is built via the
`builder/mkosi-arm64/` path. Sequence:

```bash
cd hookprobe-os
# (a) BUILD the arm64 binaries FIRST — see gotcha #1 below (this is not optional):
CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER=aarch64-linux-gnu-gcc \
  cargo build --release --target aarch64-unknown-linux-musl -p hookprobe-bootstrap
CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER=aarch64-linux-gnu-gcc \
  cargo build --release --target aarch64-unknown-linux-musl -p hookprobe-supervisor --features wasm
cargo build --release --target wasm32-wasip1 -p napse -p qsecbit -p dnsxai -p aegis-guard
# (plus any gnu-toolchain sysext/host crates the current gen-staging.sh --arch arm64 lists)

# (b) stage + build the fat-boot image (bakes the edge kernel, CONFIG_PTP_1588_CLOCK=y):
builder/mkosi-arm64/build-arm64.sh          # stages mkosi.extra (payload, units, tmpfiles.d)
builder/mkosi-arm64/make-pi-image.sh        # assembles the flashable pi image

# (c) flash — SD-reader wedge gotcha: if the uSD reader goes 0B / "Incompatible medium",
#     USB unbind/rebind the bus-id fixes it:
#       echo <bus-id> > /sys/bus/usb/drivers/usb/unbind ; echo <bus-id> > /sys/bus/usb/drivers/usb/bind

# (d) validate on metal: confirm `HOOKPROBE-SELFTEST: PASS`, every staged engine
#     systemctl-is-active, manifest classified (not `generic`), modules hybrid-verified
#     → running → healthy, and the separation matrix (attacker quarantined, mgmt/customer
#     never dropped). Debug images (HOOKPROBE_DEBUG_ACCESS=1) allow SSH for the pentest pass.
```

### Durable build gotchas (both bit us; both now guarded in-tree)

1. **Stale-musl-binary trap.** `build-arm64.sh` STAGES pre-built binaries from
   `target/aarch64-unknown-linux-{musl,gnu}/release/` — it only asserts they are
   `aarch64`, not that they are freshly rebuilt from current source
   (`builder/mkosi-arm64/build-arm64.sh:34,56`). So **any Rust change to the supervisor,
   `hookprobe-manifest`, or a host crate needs an explicit `cargo build --target
   aarch64-unknown-linux-musl -p <crate> [--features wasm]` FIRST**, or the image silently
   ships the previous binary (this session shipped a 4-day-stale supervisor until caught).
   Rule of thumb: touched Rust → rebuild the arm64 target → THEN `build-arm64.sh`.

2. **tmpfiles.d mkosi-path parity.** The mkosi arm64 path did NOT stage `tmpfiles.d` at
   all, so the Pi image was missing every tmpfiles entry — including the
   `z /var/lib/hookprobe/hydra-verdicts 0600 root root` perms line the HYDRA intel→trust
   bridge relies on. Fixed by mirroring `base/Containerfile`'s
   `COPY base/config/tmpfiles.d/ /usr/lib/tmpfiles.d/` into the mkosi.extra staging
   (`builder/mkosi-arm64/build-arm64.sh:159`). When adding host-integral state dirs,
   confirm BOTH build paths (Containerfile AND build-arm64.sh) stage the same tmpfiles.d.

See `builder/README.md` (pipeline) and `docs/architecture/OS-platform-report.md` (§6 sequence, §8.x).
