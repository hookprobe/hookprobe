#!/usr/bin/env bash
# build-vm.sh — populate mkosi.extra/ from the repo (release binaries + units + scripts +
# platforms/schema + intent), then build the bootable VM image with mkosi. Run mkosi itself
# with sudo (it needs loop devices / systemd-repart):
#
#   builder/mkosi/build-vm.sh            # populate only
#   (cd builder/mkosi && sudo mkosi --force build)   # then build
#
# ADR 0015 (registry-driven module inclusion) FIX: this script used to stage ONLY the two
# base binaries + base units — NONE of napse/qsecbit/dnsxai/aegis-guard/napse-capture/
# napse-quarantine/senzorium-flow/host-telemetry/evidence/ovs, even though the base preset
# unconditionally `enable`s most of their units. That was the "hollow bootc SOC" bug's VM
# leg (ADR 0015 context: "build-vm.sh is worse: it copies the preset and the base binaries
# but none of the native-services units or wasm modules"). It now calls the SAME generator +
# applier build-arm64.sh and base/Containerfile's `build` stage use, so the amd64 VM image
# stages the identical (by id) capability-gated module set as arm64/bootc — real SOC, not a
# blind box.
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
REPO=$(cd "$HERE/../.." && pwd)
EX="$HERE/mkosi.extra"

# Static-musl binaries (no glibc coupling to the VM/distro) + the x86_64-GNU binaries the
# `staging:` overrides need (bundled SQLite / vendored-libbpf — see each module.yaml's
# `staging.build[].toolchain`). Build with:
#   cargo build --release --target x86_64-unknown-linux-musl -p hookprobe-bootstrap -p hookprobe-supervisor --features wasm
BIN="$REPO/target/x86_64-unknown-linux-musl/release"
GNU_BIN="$REPO/target/x86_64-unknown-linux-gnu/release"
WASM="$REPO/target/wasm32-wasip1/release"
[ -x "$BIN/hookprobe-bootstrap" ] || { echo "build static binaries first: cargo build --release --target x86_64-unknown-linux-musl -p hookprobe-bootstrap -p hookprobe-supervisor"; exit 1; }

# --- pinned-glibc amd64 bpf-loader build (2026-07-07 fix) -----------------------------------
# host-telemetry/napse-quarantine/napse-l2guard's `--features bpf` loaders (libbpf-rs
# `vendored`) MUST be compiled inside builder/glibc-pin-amd64's Ubuntu-22.04/glibc-2.35
# container, never natively on whatever glibc this build host happens to run — a plain native
# build here silently picks up newer GLIBC symbols (GLIBC_2.38, confirmed empirically) that
# crash-loop on the shipped bookworm/glibc-2.36 image. This writes STRAIGHT into $GNU_BIN (the
# exact path `{gnu_bin}` in gen-staging.sh's staging plan already stages FROM), so no further
# change is needed below -- the same "no hand-staging" discipline builder/refresh-aot.sh
# established for the AOT cache. Needs podman (same requirement build.sh already has).
"$REPO/builder/build-glibc-pin-amd64.sh"

rm -rf "$EX"
mkdir -p \
  "$EX/usr/lib/hookprobe/ovs" \
  "$EX/usr/lib/systemd/system" \
  "$EX/usr/lib/systemd/system-preset" \
  "$EX/usr/share/hookprobe/platforms" \
  "$EX/usr/share/hookprobe/schema" \
  "$EX/usr/share/hookprobe/geoip" \
  "$EX/usr/share/hookprobe/trust" \
  "$EX/etc/hookprobe" \
  "$EX/etc/containers/registries.d" \
  "$EX/etc/update-motd.d"

install -m0755 "$BIN"/hookprobe-bootstrap "$BIN"/hookprobe-supervisor "$EX/usr/lib/hookprobe/"
install -m0755 "$REPO"/base/scripts/*.sh "$EX/usr/lib/hookprobe/"
# Pre-create the /usr/bin symlinks in the extra tree (mkosi copies these in while /usr is
# still writable — the final postinst runs with /usr READ-ONLY, so it can't make them).
mkdir -p "$EX/usr/bin"
ln -sf /usr/lib/hookprobe/hookprobe-supervisor "$EX/usr/bin/hookprobe-supervisor"
ln -sf /usr/lib/hookprobe/hookprobe-bootstrap  "$EX/usr/bin/hookprobe-bootstrap"
cp "$REPO"/base/units/* "$EX/usr/lib/systemd/system/" 2>/dev/null || true
# Resource-budget slice + baked security-hardening drop-ins (2026-07-07 audit: never staged before,
# so a clean `rm -rf mkosi.extra` rebuild dropped both). Slice: without it the 6 dataplane units'
# Slice= resolves to a default-weight implicit slice, silently dropping the capture/enforce priority.
install -m0644 "$REPO"/base/sysext/*.slice "$EX/usr/lib/systemd/system/" 2>/dev/null || true
mkdir -p "$EX/etc/systemd/resolved.conf.d"
install -m0644 "$REPO"/base/config/60-hookprobe-hardening.conf "$EX/etc/systemd/resolved.conf.d/" 2>/dev/null || true

# NAPSE IDS native break-glass fallback (parity with build-arm64.sh): a hand-staged EXTRA,
# deliberately OUTSIDE the module registry (ADR 0015 D0 scope) — no unit/preset ever enables
# it, so it can never trip the D3 orphan/hollow gates; kept only as an operator manual-recovery
# tool. Soft-fails (`|| true`) if this dev box hasn't cross/native-built the x86_64 `napse` CLI
# yet — never blocks the populate.
[ -x "$BIN/napse" ] && install -m0755 "$BIN/napse" "$EX/usr/lib/hookprobe/" || true

# Build-path parity fix (2026-07-07 divergence audit): three configs base/Containerfile already
# stages that this script silently dropped (an amd64-VM-only gap — build-arm64.sh already has
# all three). Each MATTERS at runtime, not just cosmetically:
#   - sysctl.d/90-hookprobe.conf: BPF JIT + unprivileged-BPF lockdown, capture-buffer sizing,
#     inotify limits, rootless-userns budget, ip_forward=0 default-off, AND the KSPP hardening
#     block (kptr_restrict/dmesg_restrict/ptrace_scope/kexec_load_disabled/perf_event_paranoid/
#     martian-logging/redirect-hardening). Without this the amd64 VM/generic image silently ran
#     with none of that — a real security-posture gap, not cosmetic.
#   - os-release/issue/issue.net/update-motd.d: "one system" identity (ADR 0006) — brands the
#     device as HookProbe OS (ID=hookprobe) to the operator, compliance scanners, and any
#     systemd-sysext extension-release matching; the dynamic Organism-Status MOTD. Plymouth is
#     intentionally NOT added here (no `plymouth` package on this headless VM/cloud path, unlike
#     build-arm64.sh's Pi image with a display) — that split is deliberate, not an oversight.
install -D -m0644 "$REPO"/base/config/sysctl.d/90-hookprobe.conf  "$EX/usr/lib/sysctl.d/90-hookprobe.conf"
install -D -m0644 "$REPO"/base/config/os-release                 "$EX/usr/lib/os-release"
install -D -m0644 "$REPO"/base/config/issue                      "$EX/etc/issue"
install -D -m0644 "$REPO"/base/config/issue                      "$EX/etc/issue.net"
install -D -m0755 "$REPO"/base/config/update-motd.d/10-hookprobe  "$EX/etc/update-motd.d/10-hookprobe"

# Container signature policy (parity fix — was Containerfile-only): "trust nothing unsigned"
# (Readme canon) must hold on every path that can run `runtime: container` Quadlet modules, not
# just the bootc tier. No module in the registry is `runtime: container` yet (verified
# 2026-07-07 — Layer J's podman/crun/etc are forward scaffolding, not yet exercised on any
# path), so this is currently inert on mkosi too; staged now so it's correct the moment one
# lands, rather than a second surprise gap to rediscover later.
cp "$REPO"/base/config/containers/policy.json          "$EX/etc/containers/policy.json"
cp "$REPO"/base/config/containers/registries.d/*        "$EX/etc/containers/registries.d/"

# --- ADR 0017 D3: refresh + re-sign the AOT (.cwasm) cache BEFORE staging (2026-07-05 fix —
# the "AOT drift" bug: this script used to stage whatever stale `.cwasm` happened to already sit
# in target/wasm32-wasip1/release/, which the running supervisor's CURRENT engine config
# (e.g. the consume_fuel(true) resource-budgets change) could no longer authenticate, so every
# module silently JIT-fell-back — only base/Containerfile's own `build` stage did this refresh).
# Precompile -> digest -> sign, in that order (ADR 0016/0017), THEN gen-staging.sh/stage-apply.sh
# below stage the byte-identical, freshly-signed result. SAME shared script build-arm64.sh calls
# for its own (arm64) leg — see builder/refresh-aot.sh's own header for the single-checkout
# ordering caveat when refreshing both arches from the same repo checkout.
"$REPO/builder/refresh-aot.sh" --arch amd64

# --- ADR 0015: registry-driven module staging — the fix for this script's hollow-SOC
# bug. SAME generator + applier as build-arm64.sh and base/Containerfile's `build` stage.
"$REPO/builder/gen-staging.sh" --arch amd64 \
  --out        "$REPO/builder/generated/staging-plan.json" \
  --preset-out "$REPO/builder/generated/85-hookprobe-modules.preset"
REPO="$REPO" WASM="$WASM" BIN="$BIN" GNU_BIN="$GNU_BIN" \
  "$REPO/builder/stage-apply.sh" "$REPO/builder/generated/staging-plan.json" "$EX" --relaxed

# Release trust store (security F2/F3 fix — unify the trust path) — same rationale and
# same canonical /usr/share/hookprobe/trust destination as build-arm64.sh: NOT a
# module.yaml artifact (the trust ANCHOR every module.sig verifies against), so it stays
# hand-staged; NEVER /var, and never colocated under modules/.
TRUST_SRC=""
if [ -d "$REPO/builder/trust" ] && ls "$REPO"/builder/trust/*.pub >/dev/null 2>&1; then
  TRUST_SRC="$REPO/builder/trust"
elif [ -d "$REPO/modules/.trust" ] && ls "$REPO"/modules/.trust/*.pub >/dev/null 2>&1; then
  TRUST_SRC="$REPO/modules/.trust"
  echo "note: builder/trust/ absent or empty — falling back to modules/.trust/ (DEV key, run builder/sign-release.sh for the real release flow)"
fi
if [ -n "$TRUST_SRC" ]; then
  cp "$TRUST_SRC"/*.pub "$EX/usr/share/hookprobe/trust/" 2>/dev/null || true
else
  echo "WARNING: no trust store found (builder/trust/ or modules/.trust/) — no trust store staged, EVERY signature:required module will be REFUSED."
fi

# Both preset files, applied together by `systemctl preset-all` (ADR 0015 D2/C4).
cp "$REPO"/base/config/presets/*             "$EX/usr/lib/systemd/system-preset/"
cp "$REPO"/builder/generated/85-hookprobe-modules.preset "$EX/usr/lib/systemd/system-preset/"
cp "$REPO"/platforms/*          "$EX/usr/share/hookprobe/platforms/"
cp -r "$REPO"/manifest/schema/. "$EX/usr/share/hookprobe/schema/"
# Embedded offline GeoIP country DB (ADR 0034 Feature 1) — parity with build-arm64.sh + Containerfile.
cp "$REPO"/base/data/ip-location-db/*.csv.gz "$EX/usr/share/hookprobe/geoip/"
cp "$REPO"/base/config/network.example.yaml  "$EX/etc/hookprobe/network.yaml"
cp "$REPO"/base/config/cellular.example.yaml "$EX/etc/hookprobe/cellular.yaml"

# ---- DEBUG console autologin (release security fix, 2026-07-07; mirrors mkosi-arm64's
# HOOKPROBE_DEBUG_ACCESS gate) ---------------------------------------------------------------
# mkosi.postinst can't stage this itself: its sandboxed script execution presents /usr as a
# READ-ONLY overlay (mkosi's own context.sandbox() ro-binds + overlay-mounts the package-manager
# cache tree's `usr` over /usr for build/postinst/finalize scripts), so a NEW unit file can't be
# created from there — the same reason the /usr/bin symlinks above are pre-baked here instead of
# in postinst. This drop-in is what mkosi's own (now-removed) `Autologin=yes` used to generate
# for serial-getty@ttyS0 (byte-identical content) — gated on the SAME HOOKPROBE_DEBUG_ACCESS
# env var mkosi.postinst reads for root's password, so the two decide the same thing from the
# same flag. `rm -rf "$EX"` above already guarantees a clean slate every populate — no leftover
# autologin unit can survive a release populate from a prior debug one.
if [ "${HOOKPROBE_DEBUG_ACCESS:-0}" = 1 ]; then
  mkdir -p "$EX/usr/lib/systemd/system/serial-getty@ttyS0.service.d"
  cat > "$EX/usr/lib/systemd/system/serial-getty@ttyS0.service.d/autologin.conf" <<'GETTY'
[Service]
ExecStart=
ExecStart=-agetty -o '-f -p -- \\u' --autologin root --keep-baud 115200,57600,38400,9600 - $TERM
StandardInput=tty
StandardOutput=tty
GETTY
  echo "DEBUG: staged serial-getty@ttyS0 console autologin (HOOKPROBE_DEBUG_ACCESS=1) — boot-vm.sh will get a root shell on ttyS0"
else
  echo "RELEASE (default): no console autologin staged — set HOOKPROBE_DEBUG_ACCESS=1 (for both this populate AND the mkosi build) for a debug build"
fi

echo "populated $EX"
find "$EX" -type f | wc -l | xargs echo "files staged:"
