#!/usr/bin/env bash
# build-arm64.sh — populate mkosi.extra/ from the repo for the arm64 / Pi 4 image, then you
# build with `sudo mkosi --force build`. Mirrors builder/mkosi/build-vm.sh with two deltas:
#   - arm64 static-musl/gnu binaries (target/aarch64-unknown-linux-{musl,gnu})
#   - optionally stages cross-built USB-Wi-Fi-dongle .ko modules from drivers-build/staged/
#     (produced by build-dongle-drivers.sh) into /usr/lib/modules/<ver>/updates/.
#
#   builder/mkosi-arm64/build-arm64.sh
#   (cd builder/mkosi-arm64 && sudo mkosi --force build)
#
# ADR 0015 (registry-driven module inclusion): module staging (napse/qsecbit/dnsxai/
# aegis-guard/napse-capture/napse-quarantine/senzorium-flow/host-telemetry/evidence/ovs)
# is now generated from modules/*/module.yaml by builder/gen-staging.sh and applied by
# builder/stage-apply.sh — this script no longer hand-lists a single module. Adding a
# module is "one file in modules/" (D5); this script does not change.
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
REPO=$(cd "$HERE/../.." && pwd)
EX="$HERE/mkosi.extra"

# Static-musl arm64 binaries (no glibc/distro coupling) + the aarch64-GNU binaries the
# `staging:` overrides need (bundled SQLite / vendored-libbpf modules — see each
# module.yaml's `staging.build[].toolchain`). Build with:
#   CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER=aarch64-linux-gnu-gcc \
#     cargo build --release --target aarch64-unknown-linux-musl -p hookprobe-bootstrap
#   CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER=aarch64-linux-gnu-gcc \
#     cargo build --release --target aarch64-unknown-linux-musl -p hookprobe-supervisor --features wasm
#   cargo build --release --target wasm32-wasip1 -p napse -p qsecbit -p dnsxai -p aegis-guard
# NOTE: the supervisor MUST be built --features wasm (it runs the SOC engines via `--run-wasm`; ADR 0009).
# builder/gen-staging.sh --arch arm64 (below) tells you the FULL current `build_targets` set,
# including the sysext/host crates (napse-loader/napse-quarantine/hookprobe-execsnoop/
# hookprobe-evidence) — build whichever of those you need; stage-apply.sh --relaxed (below)
# tolerates ones you haven't cross-built yet (prints a note, doesn't fail the dev populate).
BIN="$REPO/target/aarch64-unknown-linux-musl/release"
GNU_BIN="$REPO/target/aarch64-unknown-linux-gnu/release"
WASM="$REPO/target/wasm32-wasip1/release"
[ -x "$BIN/hookprobe-bootstrap" ] || { echo "build arm64 static binaries first (see header)"; exit 1; }
file "$BIN/hookprobe-bootstrap" | grep -q aarch64 || { echo "ERROR: $BIN/hookprobe-bootstrap is not aarch64"; exit 1; }

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
  "$EX/etc/systemd/resolved.conf.d" \
  "$EX/etc/containers/registries.d"
# resolved.conf.d must EXIST in the image so the reconcile unit's ReadWritePaths bind-mount binds
# it (the edge DNS drop-in is written there by network-apply under ProtectSystem=strict).

install -m0755 "$BIN"/hookprobe-bootstrap "$BIN"/hookprobe-supervisor "$EX/usr/lib/hookprobe/"
install -m0755 "$REPO"/base/scripts/*.sh "$EX/usr/lib/hookprobe/"
# Pre-create /usr/bin symlinks (mkosi copies these while /usr is writable; final postinst is RO).
mkdir -p "$EX/usr/bin"
ln -sf /usr/lib/hookprobe/hookprobe-supervisor "$EX/usr/bin/hookprobe-supervisor"
ln -sf /usr/lib/hookprobe/hookprobe-bootstrap  "$EX/usr/bin/hookprobe-bootstrap"
cp "$REPO"/base/units/* "$EX/usr/lib/systemd/system/" 2>/dev/null || true
# Resource-budget slice (base/sysext/) — WITHOUT this the 6 dataplane units' Slice= resolves to an
# implicitly-created slice with DEFAULT weights, silently dropping the capture/enforce path's
# priority. (2026-07-07 audit: was never staged — a clean rebuild dropped it.)
install -m0644 "$REPO"/base/sysext/*.slice "$EX/usr/lib/systemd/system/" 2>/dev/null || true
# Baked security-hardening drop-ins (base/config/) — resolved LLMNR/mDNS off. Canonical source
# staged here so a `rm -rf mkosi.extra` rebuild can't silently drop it.
install -m0644 "$REPO"/base/config/60-hookprobe-hardening.conf "$EX/etc/systemd/resolved.conf.d/" 2>/dev/null || true

# Container signature policy (build-path parity fix, 2026-07-07): was previously ONLY staged by
# base/Containerfile's Layer H — this Pi image (and build-vm.sh's amd64 leg) silently shipped
# WITHOUT it. "Trust nothing unsigned" (Readme canon) must hold on every path that can run
# `runtime: container` Quadlet modules, not just the bootc tier. No module in the registry is
# `runtime: container` yet (Layer J's podman/crun/etc are forward scaffolding), so this is
# currently inert here too — staged now so it's correct the moment one lands.
cp "$REPO"/base/config/containers/policy.json          "$EX/etc/containers/policy.json"
cp "$REPO"/base/config/containers/registries.d/*        "$EX/etc/containers/registries.d/"

# NAPSE IDS native break-glass fallback: a hand-staged EXTRA, deliberately OUTSIDE the
# module registry (ADR 0015 D0 scope) — no unit/preset ever enables it, so it can never
# trip the D3 orphan/hollow gates; kept only as an operator manual-recovery tool.
[ -x "$BIN/napse" ] && install -m0755 "$BIN/napse" "$EX/usr/lib/hookprobe/" || true

# --- ADR 0017 D3: refresh + re-sign the AOT (.cwasm) cache BEFORE staging (2026-07-05 fix —
# same "AOT drift" bug build-vm.sh's own comment documents). On this dev box this needs a
# cross-built aarch64-unknown-linux-gnu hookprobe-supervisor --features wasm + a qemu-user
# runner (see builder/refresh-aot.sh's own header — ARM64_QEMU/ARM64_SYSROOT); a real arm64 CI
# build host runs NATIVE instead (ADR 0017: no qemu needed there at all). Precompile -> digest
# -> sign (ADR 0016/0017), THEN gen-staging.sh/stage-apply.sh below stage the byte-identical,
# freshly-signed `.cwasm`. NOTE (single-checkout caveat, see refresh-aot.sh's header): running
# this arm64 leg after an amd64 leg in the SAME checkout is fine (each `role: aot` entry is
# arch-qualified and this call only ever touches its own arch's entry) but the two legs' staged
# `.cwasm` bytes share one physical file — finish this arm64 build (through stage-apply below)
# before starting an amd64 build again from the same tree.
"$REPO/builder/refresh-aot.sh" --arch arm64

# --- ADR 0015: registry-driven module staging (napse/qsecbit/dnsxai/aegis-guard/
# napse-capture/napse-quarantine/senzorium-flow/host-telemetry/evidence/ovs). ONE
# generator + ONE dumb applier, shared with build-vm.sh and base/Containerfile's
# `build` stage — this is the ONLY place module inclusion changes when a new
# modules/<id>/module.yaml lands (D5: "adding a module = one file").
"$REPO/builder/gen-staging.sh" --arch arm64 \
  --out        "$REPO/builder/generated/staging-plan.json" \
  --preset-out "$REPO/builder/generated/85-hookprobe-modules.preset"
REPO="$REPO" WASM="$WASM" BIN="$BIN" GNU_BIN="$GNU_BIN" \
  "$REPO/builder/stage-apply.sh" "$REPO/builder/generated/staging-plan.json" "$EX" --relaxed

# Release trust store (security F2/F3 fix — unify the trust path): ONE canonical RO
# location, /usr/share/hookprobe/trust (matches base/Containerfile Layer D2 + greenboot's
# 10-hookprobe-soc.sh + hookprobe-supervisor.service's --trust — NEVER /var, and never
# colocated under modules/ so it can't be mistaken for a module.yaml artifact; it's the
# trust ANCHOR every module.sig verifies against, not a module itself). Prefers
# builder/trust/release.pub (builder/sign-release.sh's output — the real release-signing
# step; see builder/RUNBOOK.md); falls back to the checked-in modules/.trust/release.pub
# DEV key for a standalone `build-arm64.sh` populate without running sign-release.sh first
# (same deterministic key either way in dev — see module_sig.rs's dev_sign_all). Production
# CI replaces builder/trust/release.pub with the real off-device release-HSM public key.
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

# Both preset files are applied together by `systemctl preset-all` (base = base units,
# generated = module units — ADR 0015 D2/C4).
cp "$REPO"/base/config/presets/*             "$EX/usr/lib/systemd/system-preset/"
cp "$REPO"/builder/generated/85-hookprobe-modules.preset "$EX/usr/lib/systemd/system-preset/"
# MASK the generic wpa_supplicant.service (2026-07-10, CM5 on-metal): it auto-started and scanned
# the AP radio, collapsing a stable VHT80 AP (351 Mbit/s) to ch140/20MHz. The preset `disable`
# (80-hookprobe.preset) handles WantedBy activation; this /dev/null symlink also blocks D-Bus
# activation. HookProbe drives station uplinks via the per-interface `wpa_supplicant@<iface>`
# TEMPLATE (unaffected by masking the generic instance). See docs/adr/0034 + the preset comment.
mkdir -p "$EX/etc/systemd/system"
ln -sf /dev/null "$EX/etc/systemd/system/wpa_supplicant.service"
cp "$REPO"/platforms/*          "$EX/usr/share/hookprobe/platforms/"
cp -r "$REPO"/manifest/schema/. "$EX/usr/share/hookprobe/schema/"
# Embedded offline GeoIP country DB (ADR 0034 Feature 1): the ODC-PDDL sapics user-country CSVs
# feed regdomain-apply.sh's offline Wi-Fi-regdomain HINT (public WAN IP → country, no network).
cp "$REPO"/base/data/ip-location-db/*.csv.gz "$EX/usr/share/hookprobe/geoip/"
# Brand the OS: HookProbe os-release overrides the base distro's /usr/lib/os-release (ID_LIKE=debian
# keeps apt/tooling working). Presents as HookProbe OS to the operator + systemd-sysext + scanners.
install -D -m0644 "$REPO"/base/config/os-release "$EX/usr/lib/os-release"
# Boot/login identity (ADR 0006): console banner (login), dynamic Organism-Status MOTD, Plymouth
# splash theme (display units), + KSPP-hardened sysctls.
install -D -m0644 "$REPO"/base/config/issue                       "$EX/etc/issue"
install -D -m0644 "$REPO"/base/config/issue                       "$EX/etc/issue.net"
install -D -m0755 "$REPO"/base/config/update-motd.d/10-hookprobe  "$EX/etc/update-motd.d/10-hookprobe"
install -D -m0644 "$REPO"/base/config/plymouthd.conf              "$EX/etc/plymouth/plymouthd.conf"
mkdir -p "$EX/usr/share/plymouth/themes/hookprobe"
cp "$REPO"/base/plymouth/hookprobe/*                              "$EX/usr/share/plymouth/themes/hookprobe/"
install -D -m0644 "$REPO"/base/config/sysctl.d/90-hookprobe.conf  "$EX/usr/lib/sysctl.d/90-hookprobe.conf"
# tmpfiles.d — build-path parity with base/Containerfile's `COPY base/config/tmpfiles.d/ /usr/lib/tmpfiles.d/`
# (2026-07-16: the mkosi arm64 path was NOT staging tmpfiles.d at all, so the Pi image was missing every
# tmpfiles entry — incl. the `z /var/lib/hookprobe/hydra-verdicts 0600 root root` re-assert perms line).
mkdir -p "$EX/usr/lib/tmpfiles.d"
for f in "$REPO"/base/config/tmpfiles.d/*.conf; do
  [ -e "$f" ] && install -D -m0644 "$f" "$EX/usr/lib/tmpfiles.d/$(basename "$f")"
done
cp "$REPO"/base/config/network.example.yaml  "$EX/etc/hookprobe/network.yaml"
cp "$REPO"/base/config/cellular.example.yaml "$EX/etc/hookprobe/cellular.yaml" 2>/dev/null || true

# Operator enforcement policy (systemd drop-in — keeps the shipped unit safe-by-default while THIS
# image auto-quarantines scanners). AEGIS reflex: napse-dpi rule-1000003 port-scan → nft drop with a
# 300s TTL auto-revert + the mgmt-path allowlist proven live (10.200.0.0/28 + gateway never dropped,
# so no self-lockout). Remove this drop-in to revert to plan-only (SCAN_RESPOND_APPLY=0).
install -d "$EX/etc/systemd/system/hookprobe-scan-responder.service.d"
cat > "$EX/etc/systemd/system/hookprobe-scan-responder.service.d/10-operator-enforce.conf" <<'EOF'
# Baked by builder/mkosi-arm64/build-arm64.sh — operator opted into active scan response.
[Service]
Environment=SCAN_RESPOND_APPLY=1
Environment=QUARANTINE_TTL_SECS=300
Environment=LAN_IFACE=wlan0
Environment=WAN_IFACE=end0
Environment=PROTECT_CIDRS=10.200.0.0/28
Environment=PROTECT_IPS=10.66.0.1
EOF

# Optional: stage cross-built USB-dongle drivers (run build-dongle-drivers.sh first).
STAGED="$HERE/drivers-build/staged"
if [ -d "$STAGED" ] && [ -n "$(ls -A "$STAGED" 2>/dev/null)" ]; then
  echo "staging cross-built dongle drivers from $STAGED"
  cp -r "$STAGED"/. "$EX/"
  find "$EX/usr/lib/modules" -name '*.ko' 2>/dev/null | sed 's#.*/##' | sort | sed 's/^/  driver: /'
else
  echo "note: no cross-built dongle drivers staged (run build-dongle-drivers.sh for Tier-2 USB Wi-Fi)"
fi

# --- completeness assertion (fail-closed) -----------------------------------------------------
# The Jul-2026 "006" field defect: this script aborted mid-staging (refresh-aot failed under
# `set -e`) leaving mkosi.extra with only the two pre-staging binaries; `mkosi build` was then run
# against the half-populated overlay and shipped an image whose /usr/share/hookprobe/platforms was
# EMPTY → bootstrap could not classify/fall back → supervisor manifest restart-loop. A `set -e`
# abort is invisible to a subsequent manual `mkosi build`, so we ALSO assert here that the overlay
# actually carries its load-bearing payload before declaring success. If this fails, DO NOT run
# mkosi against $EX — fix the staging first. (Belt; verify-image-payload.sh on the built image is
# the suspenders.)
INCOMPLETE=0
assert_present() { [ -e "$1" ] || { echo "  MISSING: $1"; INCOMPLETE=1; }; }
assert_nonempty_dir() { [ -d "$1" ] && [ -n "$(ls -A "$1" 2>/dev/null)" ] || { echo "  EMPTY/MISSING dir: $1"; INCOMPLETE=1; }; }
echo "=== asserting mkosi.extra staging completeness ==="
assert_present        "$EX/usr/lib/hookprobe/hookprobe-bootstrap"
assert_present        "$EX/usr/lib/hookprobe/hookprobe-supervisor"
assert_present        "$EX/usr/share/hookprobe/platforms/generic.yaml"
assert_present        "$EX/usr/share/hookprobe/schema/manifest.schema.json"
assert_present        "$EX/usr/share/hookprobe/geoip/user-country-ipv4.csv.gz"
assert_nonempty_dir   "$EX/usr/share/hookprobe/trust"
assert_nonempty_dir   "$EX/usr/lib/hookprobe/modules"
MODN=$(ls "$EX/usr/lib/hookprobe/modules" 2>/dev/null | wc -l)
[ "${MODN:-0}" -ge 6 ] || { echo "  UNDERFILLED: $EX/usr/lib/hookprobe/modules has $MODN (<6) module dirs"; INCOMPLETE=1; }
if [ "$INCOMPLETE" -ne 0 ]; then
  echo "FATAL: mkosi.extra staging is INCOMPLETE — do NOT run 'mkosi build' against it (that ships a boot-broken image, cf. field defect 006). Re-run build-arm64.sh and fix the failing staging step above." >&2
  exit 1
fi
echo "  staging complete: platforms + schema + trust + $MODN module dirs + core binaries all present"

# ADR 0030 D1: every staged aarch64 ELF must be >=16K LOAD-aligned or it EINVALs under the Pi5/CM5
# 16K-page kernel (boots fine on Pi4's 4K -- a silent cross-board trap). Enforce here, on the tree
# we just populated, so a mis-aligned binary can never reach the image. (Also Gate 1.8 in the ladder.)
if [ -x "$REPO/builder/verify-binary-alignment.sh" ]; then
  "$REPO/builder/verify-binary-alignment.sh" "$EX/usr/lib/hookprobe" || {
    echo "FATAL: a staged aarch64 binary is under-aligned for the 16K Pi5/CM5 kernel (ADR 0030 D1)." >&2; exit 1; }
fi
# glibc-skew guard: a gnu-leg binary built against newer glibc headers than the Pi's 2.36 runtime
# execs fine here but fails `GLIBC_2.3x not found` on metal. Enforce the pinned-toolchain lesson.
if [ -x "$REPO/builder/verify-arm64-toolchain.sh" ]; then
  "$REPO/builder/verify-arm64-toolchain.sh" "$EX" || {
    echo "FATAL: a staged aarch64-gnu binary needs newer glibc than the Pi (wrong cross-toolchain)." >&2; exit 1; }
fi

echo "populated $EX"
find "$EX" -type f | wc -l | xargs echo "files staged:"
