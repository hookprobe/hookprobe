#!/usr/bin/env bash
# s1-vm.sh — per-VM lifecycle for the S1 `qemu-itest` guest (G19 super-PoP interop) on the test host.
#
#   sudo S1_POP_IP=<ip> s1-vm.sh new <id>       per-VM dir, a fresh 32-byte KEK, a fixed-size data volume;
#                                               records the PoP address the sandbox may reach (no default)
#   sudo s1-vm.sh run      <id> <kernel.bin>    boot the guest sandboxed in netns hqs1 (s1-net.sh up first)
#   sudo s1-vm.sh stop     <id>
#   sudo s1-vm.sh evidence <id>                 write the interop evidence record (class E2 — NOT metal)
#   sudo s1-vm.sh destroy  <id>                 shred the KEK, delete the VM
#   sudo s1-vm.sh wrongkey <id> <other-id> <kernel.bin>   boot <id>'s volume with <other-id>'s KEK (must be refused)
#   sudo s1-vm.sh rotate   <id> <kernel.bin>    one boot with a fresh KEK offered as fw_cfg opt/hookprobe/kek-next
#   sudo s1-vm.sh rotate-commit <id>            after that boot re-wrapped the VEK: kek-next becomes kek, the old one is shredded
#
# Operator decisions 2026-11-22: a dedicated test identity, a unique per-VM VEK protected separately from the
# backing volume (the KEK lives in keys/, outside disk/, and reaches the guest only through read-only fw_cfg),
# CPU/memory/disk limits, no host-filesystem sharing, no device passthrough, no production secrets.
# Interfaces agreed with the heqk session: feature `qemu-itest`, virtio-rng-device (MMIO), fw_cfg
# `opt/hookprobe/kek`, one virtio-blk data volume, boot marker `[ITEST] device identity pk=<64 hex> fp=<16 hex>`.
set -euo pipefail

ROOT="${S1_ROOT:-/var/lib/hookprobe-s1}"
RUN_USER="${S1_USER:-hqs1}"                # a dedicated unprivileged system user (see README)
POP_IP="${S1_POP_IP:-}"                    # the PoP public IPv4; required by `new`, then read from vm.meta
DISK_MB="${S1_DISK_MB:-64}"
MAX_SEC="${S1_MAX_SEC:-7200}"              # hard wall-clock cap per run
NS_PATH=/run/netns/hqs1

die() { echo "s1-vm: $*" >&2; exit 2; }
[ "$(id -u)" = 0 ] || die "run as root (sudo)"
id_ok() { [[ "$1" =~ ^[a-z0-9][a-z0-9-]{0,30}$ ]] || die "bad VM id '$1' (a-z 0-9 -, max 31)"; }
vmdir() { echo "$ROOT/vms/$1"; }
unit() { echo "hqs1-vm-$1"; }

new() {
  id_ok "$1"; local d; d=$(vmdir "$1")
  [ -e "$d" ] && die "$d exists (destroy it first; keys are never reused)"
  [[ "$POP_IP" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || die "S1_POP_IP=<the PoP's public IPv4> required"
  id "$RUN_USER" >/dev/null 2>&1 || die "user $RUN_USER missing: useradd --system --no-create-home --shell /usr/sbin/nologin $RUN_USER"
  install -d -m 0755 "$ROOT" "$ROOT/vms"
  install -d -m 0700 -o "$RUN_USER" "$d"
  install -d -m 0700 -o "$RUN_USER" "$d/keys" "$d/disk" "$d/run"
  ( umask 077; head -c 32 /dev/urandom >"$d/keys/kek.bin" )
  [ "$(stat -c %s "$d/keys/kek.bin")" = 32 ] || die "KEK generation failed"
  local fp; fp=$(sha256sum "$d/keys/kek.bin" | cut -c1-16)
  # Never share a test key across VMs: refuse a (vanishingly unlikely) fingerprint collision.
  grep -rqs "kek_fp=$fp" "$ROOT"/vms/*/vm.meta && { shred -u "$d/keys/kek.bin"; rm -rf "$d"; die "KEK fingerprint collision — retry"; }
  chown "$RUN_USER" "$d/keys/kek.bin"; chmod 0400 "$d/keys/kek.bin"
  # heqk never writes LBA 0 ("gate 2: never the MBR"), so the HOST partitions: one 0xDA DataVolume from LBA 2048
  # (the keystore window LBA 2016-2047 stays below it). Unpartitioned → the guest prints [P-itest-vol] FAIL-CLOSED.
  truncate -s "${DISK_MB}M" "$d/disk/data.img"
  printf 'start=2048, type=da\n' | sfdisk --quiet --label dos "$d/disk/data.img"
  sfdisk -d "$d/disk/data.img" | grep -q 'start= *2048, .*type=da' || die "data volume partitioning failed"
  chown "$RUN_USER" "$d/disk/data.img"; chmod 0600 "$d/disk/data.img"
  printf 'id=%s\ncreated=%s\nkek_fp=%s\ndisk_mb=%s\npop=%s\n' "$1" "$(date -u +%FT%TZ)" "$fp" "$DISK_MB" "$POP_IP" >"$d/vm.meta"
  echo "s1-vm: created $d (KEK fp $fp, data volume ${DISK_MB} MiB)"
}

launch() { # <id> <kernel> <kek-file> <unit-name> [<kek-next-file>]
  local id="$1" kernel="$2" kek="$3" u="$4" next="${5:-}" d; d=$(vmdir "$id")
  local extra=(); [ -n "$next" ] && extra=(-fw_cfg "name=opt/hookprobe/kek-next,file=$next")
  [ -d "$d" ] || die "no VM $id (run 'new' first)"
  local pop; pop=$(sed -n 's/^pop=//p' "$d/vm.meta")
  [[ "$pop" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || die "no valid pop= in $d/vm.meta"
  [ -e "$NS_PATH" ] || die "netns hqs1 missing (s1-net.sh up)"
  [ -f "$kernel" ] || die "kernel image $kernel missing"
  # The guest may only see files inside its own VM dir: copy the kernel in (read-only to the guest).
  install -m 0444 -o "$RUN_USER" "$kernel" "$d/run/kernel.bin"
  sha256sum "$d/run/kernel.bin" | cut -d' ' -f1 >"$d/run/kernel.sha256"
  : >"$d/run/serial.log"; chown "$RUN_USER" "$d/run/serial.log"
  # No -semihosting: it gives the guest host file I/O (SYS_OPEN), i.e. host-filesystem sharing.
  # No hostfwd: nothing reaches the guest from outside; user-mode net inside the netns supplies DHCP.
  systemd-run --unit="$u" --collect --quiet \
    -p NetworkNamespacePath="$NS_PATH" \
    -p User="$RUN_USER" -p Group="$RUN_USER" \
    -p CPUQuota=100% -p MemoryMax=2G -p MemorySwapMax=0 -p TasksMax=64 \
    -p RuntimeMaxSec="$MAX_SEC" -p LimitFSIZE=256M \
    -p IPAddressDeny=any -p IPAddressAllow="$pop" \
    -p RestrictAddressFamilies="AF_INET AF_UNIX" \
    -p PrivateDevices=yes -p DevicePolicy=closed \
    -p ProtectSystem=strict -p ProtectHome=yes -p PrivateTmp=yes \
    -p ReadWritePaths="$d/disk $d/run" -p ReadOnlyPaths="$d/keys" \
    -p NoNewPrivileges=yes -p CapabilityBoundingSet= -p AmbientCapabilities= \
    -p ProtectKernelTunables=yes -p ProtectKernelModules=yes -p ProtectControlGroups=yes \
    -p RestrictSUIDSGID=yes -p LockPersonality=yes -p SystemCallArchitectures=native \
    qemu-system-aarch64 -M virt -cpu cortex-a72 -m 512M -nodefaults -display none -monitor none \
      -serial "file:$d/run/serial.log" \
      -global virtio-mmio.force-legacy=false \
      -object rng-random,id=rng0,filename=/dev/urandom -device virtio-rng-device,rng=rng0 \
      -fw_cfg "name=opt/hookprobe/kek,file=$kek" "${extra[@]}" \
      -netdev user,id=n0 -device virtio-net-device,netdev=n0 \
      -drive "file=$d/disk/data.img,format=raw,if=none,id=hd0" -device virtio-blk-device,drive=hd0 \
      -kernel "$d/run/kernel.bin"
  echo "s1-vm: $u started — serial: $d/run/serial.log  (stop: s1-vm.sh stop $id)"
}

run() { id_ok "$1"; [ -n "${2:-}" ] || die "usage: run <id> <kernel.bin>"; launch "$1" "$2" "$(vmdir "$1")/keys/kek.bin" "$(unit "$1")"; }

wrongkey() {
  id_ok "$1"; id_ok "$2"; [ "$1" != "$2" ] || die "wrongkey needs two different VMs"
  local other; other="$(vmdir "$2")/keys/kek.bin"; [ -f "$other" ] || die "no KEK for $2"
  # Copy the foreign KEK into this VM's keys dir under another name so the sandbox still sees only its own dir.
  install -m 0400 -o "$RUN_USER" "$other" "$(vmdir "$1")/keys/kek-foreign.bin"
  launch "$1" "$3" "$(vmdir "$1")/keys/kek-foreign.bin" "$(unit "$1")-wrongkey"
  echo "s1-vm: expect the guest to REFUSE the volume and generate no keys; then: shred -u $(vmdir "$1")/keys/kek-foreign.bin"
}

rotate() {
  id_ok "$1"; [ -n "${2:-}" ] || die "usage: rotate <id> <kernel.bin>"; local d; d=$(vmdir "$1")
  [ -f "$d/keys/kek.bin" ] || die "no KEK for $1"
  [ -e "$d/keys/kek-next.bin" ] && die "a rotation is already pending (rotate-commit or shred keys/kek-next.bin)"
  ( umask 077; head -c 32 /dev/urandom >"$d/keys/kek-next.bin" )
  cmp -s "$d/keys/kek.bin" "$d/keys/kek-next.bin" && { shred -u "$d/keys/kek-next.bin"; die "KEK collision — retry"; }
  chown "$RUN_USER" "$d/keys/kek-next.bin"; chmod 0400 "$d/keys/kek-next.bin"
  launch "$1" "$2" "$d/keys/kek.bin" "$(unit "$1")" "$d/keys/kek-next.bin"
  echo "s1-vm: rotation boot started; when the guest confirms the re-wrap, run: s1-vm.sh rotate-commit $1"
}

rotate_commit() {
  id_ok "$1"; local d; d=$(vmdir "$1"); [ -f "$d/keys/kek-next.bin" ] || die "no pending rotation for $1"
  systemctl is-active --quiet "$(unit "$1")" && die "stop the VM first (s1-vm.sh stop $1)"
  shred -u "$d/keys/kek.bin"; mv "$d/keys/kek-next.bin" "$d/keys/kek.bin"
  local fp; fp=$(sha256sum "$d/keys/kek.bin" | cut -c1-16)
  sed -i "s/^kek_fp=.*/kek_fp=$fp/" "$d/vm.meta"; echo "rotated=$(date -u +%FT%TZ)" >>"$d/vm.meta"
  echo "s1-vm: rotation committed for $1 (new KEK fp $fp; the old KEK is shredded)"
}

stop() { id_ok "$1"; systemctl stop "$(unit "$1")" "$(unit "$1")-wrongkey" 2>/dev/null || true; echo "s1-vm: stopped $1"; }

evidence() {
  id_ok "$1"; local d log out; d=$(vmdir "$1"); log="$d/run/serial.log"; out="$d/run/evidence-$(date -u +%Y%m%dT%H%M%SZ).txt"
  [ -f "$log" ] || die "no serial log for $1"
  {
    echo "# S1 evidence — CLASS E2: QEMU-to-real-PoP interoperability"
    echo "# This is NOT CM5 metal evidence and must not mark any metal gate (operator, 2026-11-22)."
    echo "vm=$1 host=$(hostname) date=$(date -u +%FT%TZ)"
    sed 's/^/meta: /' "$d/vm.meta"
    echo "kernel_sha256=$(cat "$d/run/kernel.sha256" 2>/dev/null || echo unknown)"
    echo "qemu=$(qemu-system-aarch64 --version | head -1)"
    echo "netns_allowlist=$(nft list table inet hqs1 >/dev/null 2>&1 && echo present || echo MISSING)"
    echo "--- markers"
    grep -aE '\[ITEST\]|\[P-itest|\[G19|g19|\[NETCP\]|HwTrng|TRNG|entropy|refus|PANIC' "$log" | head -200 || echo "(no markers)"
  } >"$out"
  echo "s1-vm: wrote $out"
}

destroy() {
  id_ok "$1"; local d; d=$(vmdir "$1"); [ -d "$d" ] || die "no VM $1"
  stop "$1" >/dev/null
  find "$d/keys" -type f -exec shred -u {} +
  rm -rf "$d"; echo "s1-vm: destroyed $1 (KEKs shredded)"
}

cmd="${1:-}"; shift || true
case "$cmd" in new) new "$@" ;; run) run "$@" ;; stop) stop "$@" ;; evidence) evidence "$@" ;;
  destroy) destroy "$@" ;; wrongkey) wrongkey "$@" ;; rotate) rotate "$@" ;; rotate-commit) rotate_commit "$@" ;;
  *) sed -n '2,12p' "$0"; exit 2 ;; esac
