#!/usr/bin/env bash
# build-edge-kernel.sh — HookProbe "edge" kernel = the RaspberryPi DOWNSTREAM kernel
# RE-COMPILED with a minimal BTF config override. NOT a fork, NOT mainline: a re-compilation
# layer over the exact downstream source, changing ~2 config symbols.
#
# Why (ADR 0032): the network-vs-BTF deadlock.
#   * MAINLINE Linux has NO CM5 device tree (only bcm2712-rpi-5-b); the CM5 DTS lives only in
#     downstream raspberrypi/linux with downstream-only includes/pinctrl-macros/clock-topologies
#     that do NOT compile against vanilla dtc, plus the RP1 platform-vs-PCIe-MFD binding rift.
#     => a vanilla kernel cannot drive the CM5. (Verified 2026-07-08: mainline 6.18.32, torvalds
#        master, and linux-next all lack bcm2712-rpi-cm5*.dts.)
#   * The RPi Foundation's SHIPPED kernels are built CONFIG_DEBUG_INFO=n / DEBUG_INFO_BTF=n, and
#     their -dbg package carries no DWARF, so /sys/kernel/btf/vmlinux is absent at runtime and
#     pahole cannot sideload BTF from the shipped debug pkg. CO-RE eBPF (napse-quarantine/l2guard)
#     then crash-loops "kernel BTF is missing".
#
# The fix: build the downstream tree OURSELVES with CONFIG_DEBUG_INFO=y + CONFIG_DEBUG_INFO_BTF=y.
# We generate DWARF at build time, so pahole emits native BTF -> vmlinux carries a .BTF section
# -> /sys/kernel/btf/vmlinux present at boot -> CO-RE loads with NO sideload. Everything else
# (CM5 + full-family DTBs, RP1 platform drivers, built-in MMC/USB/NVMe, 16K pages) stays EXACTLY
# as the RPi Foundation ships it = production-vetted hardware parity. Fixes BTF for ALL RPi boards.
#
# Does NOT touch make-pi4-image.sh, the Pi4 validation image, or the shared rootfs. No commit/flash.
set -euo pipefail

# ---- knobs -------------------------------------------------------------------
RPI_BRANCH="${RPI_BRANCH:-rpi-6.12.y}"                 # matches shipped 6.12.9x+rpt; rpi-6.18.y fallback
RPI_COMMIT="${RPI_COMMIT:-a923c1dcd822385aaa82a4388c6a6ad92cbf9280}"  # pinned rpi-6.12.y @ v6.12.94 (2026-07-08)
FLAVOUR="${FLAVOUR:-2712}"                             # 2712 = Pi5/CM5 (16K); v8 = Pi4/CM4 (re-run w/ FLAVOUR=v8)
LOCALVERSION="${LOCALVERSION:--hookprobe-edge}"
ARCH=arm64
CROSS_COMPILE="${CROSS_COMPILE:-aarch64-linux-gnu-}"
JOBS="${JOBS:-$(nproc)}"
WORK="${WORK:-$(cd "$(dirname "$0")" && pwd)/kernel-build}"
CODELOAD="https://codeload.github.com/raspberrypi/linux/tar.gz"
TARBALL="linux-rpi-${RPI_COMMIT}.tar.gz"
SRC="${WORK}/linux-${RPI_COMMIT}"
OUT="${WORK}/out"
# ISOLATION (fix): each flavour builds OUT-OF-TREE into its own dir so 2712 and v8
# NEVER share .config/vmlinux/artifacts. This killed the shared-tree race where a
# second in-tree `make <defconfig>` clobbered the first flavour's vmlinux.
BUILDDIR="${WORK}/build-${FLAVOUR}"
case "$FLAVOUR" in
  2712) DEFCONFIG=bcm2712_defconfig; DTB=bcm2712-rpi-cm5-cm5io.dtb ;;   # the CM5 acid test
  v8)   DEFCONFIG=bcm2711_defconfig; DTB=bcm2711-rpi-4-b.dtb ;;
  *) echo "unknown FLAVOUR=$FLAVOUR (2712|v8)"; exit 2 ;;
esac
log(){ printf '\033[1;36m[edge-kernel]\033[0m %s\n' "$*"; }
die(){ printf '\033[1;31m[edge-kernel FATAL]\033[0m %s\n' "$*" >&2; exit 1; }

export ARCH CROSS_COMPILE
command -v pahole >/dev/null || die "pahole missing (needed for CONFIG_DEBUG_INFO_BTF)"
command -v "${CROSS_COMPILE}gcc" >/dev/null || die "${CROSS_COMPILE}gcc missing"
mkdir -p "$WORK" "$OUT"

# ---- 1. fetch (pinned commit) + extract -------------------------------------
if [ ! -d "$SRC" ]; then
  if [ ! -f "${WORK}/${TARBALL}" ]; then
    log "fetching ${CODELOAD}/${RPI_COMMIT}  (downstream raspberrypi/linux, pinned)"
    curl -fSL --retry 3 -o "${WORK}/${TARBALL}.part" "${CODELOAD}/${RPI_COMMIT}" || die "download failed (egress?)"
    mv "${WORK}/${TARBALL}.part" "${WORK}/${TARBALL}"
  fi
  SRC_SHA=$(sha256sum "${WORK}/${TARBALL}" | cut -d' ' -f1)
  log "tarball sha256=${SRC_SHA}  (branch=${RPI_BRANCH} commit=${RPI_COMMIT})"
  echo "${SRC_SHA}  ${TARBALL}  ${RPI_BRANCH}@${RPI_COMMIT}" > "${OUT}/tarball.sha256"
  log "extracting"
  tar -C "$WORK" -xf "${WORK}/${TARBALL}"
  # codeload names the dir linux-<commit>; normalise
  [ -d "$SRC" ] || mv "$WORK"/linux-* "$SRC" 2>/dev/null || true
fi
cd "$SRC"
KVER_STR="$(make -s kernelversion)"
log "downstream kernel version: ${KVER_STR}  flavour=${FLAVOUR}  defconfig=${DEFCONFIG}"

# The SHARED source tree MUST be pristine for O= out-of-tree builds. If a prior
# IN-TREE build left .config/vmlinux/*.o behind, O= refuses ("source tree is not
# clean"). mrproper the tree ONCE; thereafter every flavour writes only to its own
# $BUILDDIR, so 2712 and v8 can coexist and cannot clobber each other.
if [ -e "$SRC/.config" ] || [ -e "$SRC/vmlinux" ] || [ -e "$SRC/arch/arm64/boot/Image" ]; then
  log "shared source tree dirty from a prior in-tree build -> make mrproper (O= needs clean tree)"
  make -s mrproper
fi
rm -rf "$BUILDDIR"; mkdir -p "$BUILDDIR"
log "out-of-tree build dir (isolated per flavour): $BUILDDIR"

# ---- 2. base config = the RPi defconfig UNCHANGED ---------------------------
log "make O=\$BUILDDIR ${DEFCONFIG} (RaspberryPi downstream defconfig — hardware parity)"
make -s O="$BUILDDIR" "${DEFCONFIG}"

# ---- 3. the MINIMAL BTF override (the only change) --------------------------
FRAG="${WORK}/hookprobe-btf.fragment"
cat > "$FRAG" <<'EOF'
# Delta 1 vs the RPi defconfig: make the kernel self-describe with BTF.
CONFIG_DEBUG_INFO_DWARF_TOOLCHAIN_DEFAULT=y
CONFIG_DEBUG_INFO=y
CONFIG_DEBUG_INFO_BTF=y
CONFIG_DEBUG_INFO_BTF_MODULES=y
CONFIG_DEBUG_INFO_REDUCED=n
CONFIG_DEBUG_INFO_SPLIT=n
CONFIG_BPF_SYSCALL=y
CONFIG_BPF_JIT=y
# Delta 2 (2026-07-09 on-metal pentest finding): the RPi defconfig ships PSI OFF, so
# /proc/pressure/{cpu,memory,io} does not exist and AEGIS resource-shed's CPU/memory-pressure
# shedding is BLIND — it cannot react to a flood that saturates CPU via the mirror→DPI path,
# the exact mechanism that collaterally denied a legit LAN customer. Enable PSI (and leave it
# runtime-enabled, NOT default-disabled) so the reflex can read real pressure and shed the
# top-talker source before customer traffic is starved. Cheap: PSI overhead is negligible.
CONFIG_PSI=y
CONFIG_PSI_DEFAULT_DISABLED=n
# Delta 3 (2026-07-10 CM5 on-metal separation pentest): the RPi defconfig ships
# CONFIG_NF_CONNTRACK_PROCFS OFF, so /proc/net/nf_conntrack does not exist. senzorium-flow.service
# gates on `ConditionPathExists=/proc/net/nf_conntrack` → it is SKIPPED on the edge kernel, so ALL
# flow-based detection (SSH-brute 1000001, beaconing 1000040, lateral 1000041, exfil) is BLIND
# while packet-path detection (port scans) still works. Restore the procfs the flow engine reads.
# (Longer-term senzorium-flow should move to conntrack NETLINK — see task; this is the cheap fix.)
CONFIG_NF_CONNTRACK_PROCFS=y
# Delta 4 (2026-07-15 base-tier build ticket Phase 0): IEEE-1588 hardware timestamping.
# --- PTP / IEEE-1588 hardware timestamping (macb TSU behind RP1) — base-tier time-truth (ADR 0031 §B) ---
# The macb TSU driver (macb_ptp) compiles automatically once CONFIG_MACB=y (already in defconfig) AND
# CONFIG_PTP_1588_CLOCK=y — no separate macb symbol. Feeds Phase 3 ptp4l/phc2sys → NAPSE HW timestamps.
CONFIG_PTP_1588_CLOCK=y
CONFIG_NET_PTP_CLASSIFY=y     # auto-selected by PTP consumers; assert it lands
# Delta 5 (2026-07-16 box-hardening audit GAP-2): extend "trust nothing unsigned" to the kernel.
# Module signing (the kernel signs its OWN in-tree modules at modules_install via MODULE_SIG_ALL,
# embeds the public key in its keyring, and verifies on load) + the Lockdown LSM (the ENFORCEMENT:
# lockdown=integrity, set via kargs.d/cmdline, rejects unsigned-module load + kexec/hibernate/
# /dev/mem-write). The default image ships ONLY in-tree modules — all auto-signed — so this does not
# brick it. An OPTIONAL baked out-of-tree dongle .ko (drivers-build/staged, absent by default) must
# be signed with THIS build's certs/signing_key.pem (scripts/sign-file) or it won't load under
# lockdown — documented in the dongle build path. lockdown=INTEGRITY not confidentiality: integrity
# still permits the eBPF stack's bpf_probe_read kernel reads (execsnoop/TC), confidentiality breaks them.
CONFIG_MODULE_SIG=y
CONFIG_MODULE_SIG_ALL=y
CONFIG_MODULE_SIG_SHA256=y
CONFIG_MODULE_SIG_HASH="sha256"
CONFIG_MODULE_SIG_KEY="certs/signing_key.pem"
CONFIG_SECURITY_LOCKDOWN_LSM=y
CONFIG_SECURITY_LOCKDOWN_LSM_EARLY=y
CONFIG_LOCK_DOWN_KERNEL_FORCE_NONE=y
# CRITICAL (verified 2026-07-16): the RPi bcm2711/bcm2712 defconfig ships CONFIG_LSM="" — an EMPTY
# LSM list, so NO LSM initializes and `lockdown=integrity` would be SILENTLY INERT (and the existing
# kernel.yama.ptrace_scope sysctl was itself inert). Explicitly enrol the minor LSMs so lockdown is
# actually active. Kept minimal + permissive-by-default (yama = ptrace restriction we already want
# via sysctl; bpf = BPF LSM hooks, no policy = no-op). Deliberately NO loadpin (could block firmware/
# module loads from /usr) and NO SELinux/AppArmor (unused, enforcing would break the box).
CONFIG_SECURITY_YAMA=y
CONFIG_LSM="lockdown,yama,bpf"
CONFIG_STRICT_DEVMEM=y
CONFIG_IO_STRICT_DEVMEM=y
EOF
log "merging minimal BTF override (into \$BUILDDIR/.config)"
./scripts/kconfig/merge_config.sh -O "$BUILDDIR" -m "$BUILDDIR/.config" "$FRAG" >/dev/null
make -s O="$BUILDDIR" olddefconfig

# ---- 4. GUARD: BTF must be on; RP1/CM5 parity must be intact -----------------
# Grep the PER-FLAVOUR $BUILDDIR/.config (NOT the shared-tree .config, which no
# longer exists after mrproper). This proves the override survived olddefconfig
# for THIS defconfig, independently, before we spend an hour compiling.
require_y(){ grep -q "^$1=y" "$BUILDDIR/.config" || die "config guard FAILED: $1 not =y in $BUILDDIR/.config"; }
log "verifying config guard on $BUILDDIR/.config"
require_y CONFIG_DEBUG_INFO
require_y CONFIG_DEBUG_INFO_BTF
require_y CONFIG_BPF_SYSCALL
require_y CONFIG_PSI
grep -q '^CONFIG_PSI_DEFAULT_DISABLED=y' "$BUILDDIR/.config" && die "config guard FAILED: PSI is default-disabled — /proc/pressure would need psi=1 karg; want it always-on"
require_y CONFIG_NF_CONNTRACK_PROCFS
require_y CONFIG_PTP_1588_CLOCK
# NEGATIVE guard (base-tier ticket Phase 0, ADR 0031 §C): NO hugepages in the base kernel.
# CONFIG_TRANSPARENT_HUGEPAGE/hugetlb are MODULE-tier only (AF_XDP UMEM). A careless future merge
# must not sneak them into the base kernel — fail the build here, before the hour-long compile.
grep -q '^CONFIG_TRANSPARENT_HUGEPAGE=y' "$BUILDDIR/.config" && die "config guard FAILED: hugepages are module-tier (AF_XDP), not base (ADR 0031 §C)"
# a real DWARF choice must be active (NOT _NONE) or pahole has nothing to convert to BTF
grep -q '^CONFIG_DEBUG_INFO_NONE=y' "$BUILDDIR/.config" && die "config guard FAILED: DEBUG_INFO_NONE=y (no DWARF -> no BTF) after olddefconfig for ${DEFCONFIG}"
log "BTF/DWARF config AFTER olddefconfig (${DEFCONFIG}):"
grep -E '^(CONFIG_DEBUG_INFO|CONFIG_DEBUG_INFO_BTF|CONFIG_DEBUG_INFO_BTF_MODULES|CONFIG_DEBUG_INFO_DWARF_TOOLCHAIN_DEFAULT|CONFIG_DEBUG_INFO_DWARF[45]|CONFIG_BPF_SYSCALL|CONFIG_LOCALVERSION)\b' "$BUILDDIR/.config" | sed 's/^/    /'
# parity sanity (must stay as RPi ships): the target DTB must be in the source Makefile
grep -q "${DTB%.dtb}\.dtb" arch/arm64/boot/dts/broadcom/Makefile || die "target DTB ${DTB} not in downstream Makefile"
log "config guard PASS — DEBUG_INFO_BTF=y, real DWARF, BPF_SYSCALL=y, ${DTB} present in tree"

# ---- 5. build (LONG) --------------------------------------------------------
# Prefer bindeb-pkg; fall back to plain make + dpkg-deb when debhelper/libdw-dev absent (root-free).
DEB_METHOD="bindeb"
if ! dpkg -l debhelper 2>/dev/null | tail -1 | grep -q '^ii' || ! dpkg -l libdw-dev 2>/dev/null | tail -1 | grep -q '^ii'; then
  DEB_METHOD="manual"
  log "note: debhelper/libdw-dev absent -> plain-make + dpkg-deb fallback (no root needed)"
fi

DEB_LOG="${OUT}/build-${FLAVOUR}.log"
if [ "$DEB_METHOD" = "bindeb" ]; then
  log "building: make O=\$BUILDDIR -j${JOBS} bindeb-pkg LOCALVERSION=${LOCALVERSION}  (long compile)"
  make O="$BUILDDIR" -j"${JOBS}" bindeb-pkg LOCALVERSION="${LOCALVERSION}" 2>&1 | tee "${DEB_LOG}"
else
  log "building: make O=\$BUILDDIR -j${JOBS} Image modules dtbs LOCALVERSION=${LOCALVERSION}  (long compile)"
  make O="$BUILDDIR" -j"${JOBS}" Image modules dtbs LOCALVERSION="${LOCALVERSION}" 2>&1 | tee "${DEB_LOG}"
  KREL="$(make -s O="$BUILDDIR" kernelrelease LOCALVERSION="${LOCALVERSION}")"
  log "kernelrelease=${KREL}; installing modules + assembling .deb by hand"
  DEBROOT="${WORK}/debroot-${FLAVOUR}"; rm -rf "$DEBROOT"
  make O="$BUILDDIR" -j"${JOBS}" modules_install INSTALL_MOD_PATH="$DEBROOT" INSTALL_MOD_STRIP=1 LOCALVERSION="${LOCALVERSION}" >/dev/null
  rm -f "$DEBROOT/lib/modules/${KREL}/build" "$DEBROOT/lib/modules/${KREL}/source"
  mkdir -p "$DEBROOT/boot" "$DEBROOT/usr/lib/linux-image-${KREL}/broadcom" "$DEBROOT/DEBIAN"
  # All artifacts read from the PER-FLAVOUR $BUILDDIR (out-of-tree), never the shared $SRC.
  cp "$BUILDDIR/arch/arm64/boot/Image" "$DEBROOT/boot/vmlinuz-${KREL}"
  cp "$BUILDDIR/.config" "$DEBROOT/boot/config-${KREL}"
  cp "$BUILDDIR/System.map" "$DEBROOT/boot/System.map-${KREL}"
  # stage ALL downstream broadcom DTBs (incl. the full CM5 family) — RPi package layout
  cp "$BUILDDIR"/arch/arm64/boot/dts/broadcom/bcm27*.dtb "$DEBROOT/usr/lib/linux-image-${KREL}/broadcom/" 2>/dev/null || true
  [ -d "$BUILDDIR/arch/arm64/boot/dts/overlays" ] && { mkdir -p "$DEBROOT/usr/lib/linux-image-${KREL}/overlays"; cp "$BUILDDIR"/arch/arm64/boot/dts/overlays/*.dtbo "$DEBROOT/usr/lib/linux-image-${KREL}/overlays/" 2>/dev/null || true; }
  INST_SIZE=$(du -sk "$DEBROOT" | cut -f1)
  cat > "$DEBROOT/DEBIAN/control" <<CTL
Package: linux-image-${KREL}
Version: ${KVER_STR}-hookprobe1
Architecture: arm64
Maintainer: HookProbe OS <release@hookprobe.local>
Installed-Size: ${INST_SIZE}
Section: kernel
Priority: optional
Description: HookProbe edge kernel ${KREL} (RPi downstream ${RPI_BRANCH} + native BTF)
 RaspberryPi downstream kernel (${DEFCONFIG}) RE-COMPILED with CONFIG_DEBUG_INFO_BTF=y so
 /sys/kernel/btf/vmlinux is native (CO-RE eBPF, no sideload). All RPi hardware support
 (CM5 DTBs, RP1 platform drivers, storage/USB) unchanged. Built by build-edge-kernel.sh. ADR 0032.
CTL
  dpkg-deb --root-owner-group --build "$DEBROOT" \
    "${WORK}/linux-image-${KREL}_${KVER_STR}-hookprobe1_arm64.deb" | tail -1
fi

# ---- 6. PROVE (HARD GATE, per flavour, path-correct) ------------------------
# Three independent proofs, all against the PER-FLAVOUR $BUILDDIR:
#   (a) build-dir vmlinux carries a NON-EMPTY .BTF section (readelf),
#   (b) that .BTF is VALID BTF that CO-RE can consume (bpftool btf dump),
#   (c) BTF SURVIVED into the shippable artifact (BTF magic present in the raw
#       Image that becomes the .deb's vmlinuz).
log "=== PROOF (flavour=${FLAVOUR}) ==="
VMLINUX="$BUILDDIR/vmlinux"
[ -f "$VMLINUX" ] || die "vmlinux not found at $VMLINUX — build did not link the kernel"

# (a) non-empty .BTF section
BTF_LINE="$(readelf -S "$VMLINUX" | grep -E '\] \.BTF ' || true)"
[ -n "$BTF_LINE" ] || die "vmlinux has NO .BTF section — BTF generation did not happen for ${FLAVOUR}"
# size field is column 6 of readelf -S (hex). readelf prints size on the same or next line;
# use bpftool below as the authoritative non-empty proof.
log "(a) PROVEN: ${FLAVOUR} vmlinux carries a .BTF section:"
readelf -S "$VMLINUX" | grep -E '\.BTF' | sed 's/^/    /'

# (b) valid, consumable BTF — validated with pahole, NOT bpftool.
# FIX (2026-07-09): the original gate shelled out to the HOST's `bpftool btf dump`. On a build
# host whose running kernel has no matching linux-tools package (confirmed on THIS box:
# "WARNING: bpftool not found for kernel 6.12.62-061262" — a broken Debian per-kernel-version
# wrapper, not a real absence of bpftool functionality), that command silently decodes 0 types and
# the old check ("[ "${NTYPES:-0}" -gt 100 ] || die ...") FATALs the whole build even though the
# vmlinux's BTF is perfectly valid. This is exactly why run-both.sh reported BOTH flavours "FAILED"
# on 2026-07-09 while the .debs it produced were actually fine (verified independently: pahole reads
# 8564 structs from each, readelf shows a 5,105,845-byte non-stub .BTF section in each vmlinux).
# pahole reads DWARF/BTF directly out of the vmlinux ELF — no dependency on the host's running
# kernel version — so it is the correct tool for a build-time proof gate. Two independent checks,
# either sufficient to prove "populated", both run for defense-in-depth:
#   (b1) .BTF section SIZE via readelf -SW (a stub/empty section is a few bytes; a real one is MBs)
#   (b2) pahole struct count (>1000 = populated + CO-RE-consumable; proven 8564 on this exact build)
BTF_SIZE_HEX="$(readelf -SW "$VMLINUX" | awk '$2=="\.BTF"{print $6; exit}')"
BTF_SIZE_DEC=$((16#${BTF_SIZE_HEX:-0}))
[ "$BTF_SIZE_DEC" -gt 1048576 ] || die ".BTF section is only ${BTF_SIZE_DEC} bytes (need >1MiB) for ${FLAVOUR} vmlinux — not populated"
log "(b1) PROVEN: .BTF section size = ${BTF_SIZE_DEC} bytes (>1MiB) for ${FLAVOUR} vmlinux"

command -v pahole >/dev/null || die "pahole missing — cannot validate BTF content for ${FLAVOUR} (readelf size-only is not a sufficient hard gate on its own)"
NSTRUCTS="$(pahole "$VMLINUX" 2>/dev/null | grep -c '^struct ' || true)"
[ "${NSTRUCTS:-0}" -gt 1000 ] || die "pahole decoded only ${NSTRUCTS:-0} structs from ${FLAVOUR} vmlinux (need >1000) — .BTF present but not valid/populated"
log "(b2) PROVEN: pahole decoded ${NSTRUCTS} structs (CO-RE-consumable BTF) from ${FLAVOUR} vmlinux"

# (c) BTF survived into the shippable Image (BTF magic 0xeB9F -> bytes 9f eb 01 00)
IMG="$BUILDDIR/arch/arm64/boot/Image"
if [ -f "$IMG" ] && command -v python3 >/dev/null; then
  if python3 -c "import sys; d=open(sys.argv[1],'rb').read(); sys.exit(0 if b'\x9f\xeb\x01\x00' in d else 1)" "$IMG"; then
    log "(c) PROVEN: BTF magic present in the raw Image (the .deb's vmlinuz) — survived objcopy for ${FLAVOUR}"
  else
    die "BTF magic NOT found in shippable Image for ${FLAVOUR} — BTF did not survive into the artifact"
  fi
else
  log "(c) WARN: Image or python3 unavailable — skipping shippable-artifact magic check"
fi

# CM5 / target DTB proof (from $BUILDDIR)
CM5DTB="$BUILDDIR/arch/arm64/boot/dts/broadcom/${DTB}"
[ -f "$CM5DTB" ] || make O="$BUILDDIR" -j"${JOBS}" "broadcom/${DTB}" 2>/dev/null || true
if [ -f "$CM5DTB" ]; then
  log "PROVEN: target DTB compiled: $(du -h "$CM5DTB"|cut -f1)  ${DTB}"
  cp "$BUILDDIR"/arch/arm64/boot/dts/broadcom/bcm2712-rpi-cm5*.dtb "$OUT/" 2>/dev/null || true
  cp "$CM5DTB" "$OUT/" 2>/dev/null || true
else
  log "WARN: ${DTB} not built"
fi

# ---- 7. collect debs + hashes (append, never clobber the other flavour) -----
log "collecting .deb artifacts for flavour=${FLAVOUR}"
find "$WORK" -maxdepth 1 -name 'linux-image-*hookprobe*_arm64.deb' 2>/dev/null | while read -r d; do
  cp -u "$d" "$OUT/" 2>/dev/null || true
done
( cd "$OUT" && sha256sum *.deb *.dtb 2>/dev/null > SHA256SUMS || true )
log "artifacts + hashes in: $OUT"; ls -la "$OUT"
log "DONE (flavour=${FLAVOUR}). Pin the deb sha256 in base/drivers/SOURCES.md; substitute for the stock kernel in make-pi-image.sh (same DTBs/config.txt)."
