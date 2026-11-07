#!/usr/bin/env bash
# =============================================================================
# firstboot-provision-data.sh — create the persistent data partition at first boot.
# =============================================================================
# For flows where the installer can't pre-create it (SD-card / raw-image SBC flows),
# this grows the boot disk's free space into ONE ext4 partition labelled
# `hookprobe-data`, so `var-lib-hookprobe.mount` (by-label) activates.
#
# IDEMPOTENT + SAFE:
#   - if /dev/disk/by-label/hookprobe-data already exists → no-op (exit 0);
#   - never touches the rootfs or an existing data partition;
#   - only creates a partition in UNALLOCATED free space.
# Runs once at first boot (the unit's ConditionPathExists gates it).
#
# `--check` prints the plan without changing anything (safe anywhere).
# Requires: util-linux (findmnt/lsblk/partprobe), gptfdisk (sgdisk), e2fsprogs (mkfs.ext4).
# =============================================================================
set -euo pipefail
LABEL="hookprobe-data"
PLAN=0; [ "${1:-}" = "--check" ] && PLAN=1
log() { echo "firstboot-data: $*"; }

# 0. Already provisioned? (idempotent — the common steady-state path). MUST NOT key off by-label alone:
#    once the data volume is ENCRYPTED (E1), the ext4 label lives inside the dm-crypt mapper, so
#    /dev/disk/by-label/$LABEL is ABSENT on every reboot until unlock-data opens it (which runs AFTER
#    this). Keying off by-label alone would re-provision on each boot → a new master key → orphaned
#    data. The persistent marker (written at the end, below) is the authoritative "provisioned" signal.
if [ -f /etc/hookprobe/.data-provisioned ] || [ -e "/dev/disk/by-label/$LABEL" ]; then
  log "already provisioned (marker or /dev/disk/by-label/$LABEL) — nothing to do"
  exit 0
fi

# 1. Find the disk holding the (real) root filesystem — the boot media.
#    bootc mounts the deployment at /sysroot; fall back to / for non-bootc.
root_src="$(findmnt -no SOURCE /sysroot 2>/dev/null || findmnt -no SOURCE / 2>/dev/null || true)"
disk="$(lsblk -no PKNAME "$root_src" 2>/dev/null | head -1 || true)"
# Fallback 1 (LVM/dm root): walk the root device's dependency tree down to its
# physical disk (the `lsblk -s` leaf→root chain ends at TYPE=disk). This is the boot
# disk even when PKNAME is empty — preferred over any global guess.
[ -n "$disk" ] || disk="$(lsblk -sno NAME,TYPE "$root_src" 2>/dev/null | awk '$2=="disk"{n=$1} END{gsub(/[^A-Za-z0-9_]/,"",n); print n}')"
# Fallback 2 (total detection miss): the first FIXED whole disk. SBC bootc images use
# direct partitions, so the PKNAME path is the norm; this is the last-resort net.
[ -n "$disk" ] || disk="$(lsblk -dno NAME,TYPE,RM 2>/dev/null | awk '$2=="disk" && $3=="0"{print $1; exit}')"
[ -n "$disk" ] || { log "ERROR: cannot determine boot disk from root='$root_src'"; exit 1; }
diskdev="/dev/$disk"

# SAFETY: never provision the persistent data partition on REMOVABLE non-boot media
# (a transient USB stick would vanish on reboot and break the by-label mount). The
# canonical, tested policy is `crate::storage::select_data_target`; this mirrors it.
rm_flag="$(lsblk -dno RM "$diskdev" 2>/dev/null | head -1 || echo 0)"
boot_disk="$(lsblk -no PKNAME "$root_src" 2>/dev/null | head -1 || true)"
if [ "$rm_flag" = "1" ] && [ "$disk" != "$boot_disk" ]; then
  log "ERROR: refusing to provision data on REMOVABLE non-boot disk $diskdev (transient media)"; exit 1
elif [ "$rm_flag" = "1" ]; then
  log "NOTE: boot medium $diskdev is removable (SD/USB) — growing it anyway (the OS lives here); attach a fixed disk for durable data"
fi
lastpart="$(lsblk -lno NAME "$diskdev" 2>/dev/null | grep -E "^${disk}p?[0-9]+$" | tail -1 || true)"
newnum="$(( $(echo "$lastpart" | grep -oE '[0-9]+$') + 1 ))"

if [ "$PLAN" = 1 ]; then
  log "PLAN (no changes): disk=$diskdev root=$root_src last=$lastpart"
  log "PLAN: sgdisk --new=${newnum}:0:0 (largest free) → partition ${newnum}, mkfs.ext4 -L $LABEL"
  exit 0
fi

# 2. New partition in the largest free block (rootfs typically leaves the rest free).
#    Partition-TABLE-AWARE: GPT (VM/cloud images) uses sgdisk; MBR/dos (the canonical Raspberry
#    Pi layout) uses sfdisk. The disk is almost always LARGER than the written image (a VM-grown
#    raw, or a 2 GB image flashed onto a 32 GB SD), so the trailing free space is what we claim.
pttype="$(lsblk -dno PTTYPE "$diskdev" 2>/dev/null | head -1)"
log "creating data partition on $diskdev (table=${pttype:-unknown}, partition $newnum, trailing free space)"
case "$pttype" in
  gpt)
    # The GPT BACKUP header sits mid-disk (at the old image end) when flashed to a bigger disk,
    # so sgdisk sees NO free space until it's relocated to the true end.
    sgdisk --move-second-header "$diskdev" 2>/dev/null \
      || sgdisk -e "$diskdev" 2>/dev/null \
      || log "WARNING: could not relocate GPT backup header (continuing)"
    partprobe "$diskdev" 2>/dev/null || true
    # Force the partition NUMBER (=$newnum) so it matches the node path built below.
    sgdisk --new="${newnum}:0:0" --change-name="${newnum}:$LABEL" --typecode="${newnum}:8300" "$diskdev"
    ;;
  dos|"")
    # MBR: append ONE Linux primary (type 83) filling the trailing free space. `--append` leaves
    # existing partitions untouched; ',,L' = default start (after the last part), default size
    # (rest of disk), type Linux. No backup-header dance (MBR has none). The by-label mount keys
    # off the ext4 FS label set by mkfs below, not a partition name (MBR has no partition names).
    echo ',,L' | sfdisk --append --force "$diskdev"
    ;;
  *) log "ERROR: unsupported partition table '$pttype' on $diskdev"; exit 1 ;;
esac
partprobe "$diskdev" 2>/dev/null || true
udevadm settle 2>/dev/null || sleep 1

# 3. Resolve the new partition node (nvme0n1p4 / mmcblk0p4 / sdb4) + ext4 + label.
case "$disk" in
  nvme*|mmcblk*) newpart="${diskdev}p${newnum}" ;;
  *)             newpart="${diskdev}${newnum}" ;;
esac
[ -b "$newpart" ] || { udevadm settle 2>/dev/null || true; sleep 1; }
[ -b "$newpart" ] || { log "ERROR: new partition $newpart did not appear"; exit 1; }

# 4. ENCRYPT the data volume — plain dm-crypt, NO header (ADR 0007 E1). The customer's crown jewels
#    (models, intel, certs, tokens, captures) live here; a cloned/stolen SD is unreadable without the
#    key. Plain mode: no on-disk metadata (looks like random data); cipher recipe is fixed, key is a
#    factory keyfile on the OS. On CM5 the OS+key are on the soldered eMMC and the DATA is on the
#    removable SD → clone the SD, get nothing. On Pi 4 (single SD) it's a weaker anchor (community
#    limitation). E3 hardens the anchor per platform (CM5 OTP / N100 TPM / customer passphrase).
KEYDIR=/etc/hookprobe/keys; MAP=hookprobe-data-crypt
install -d -m0700 "$KEYDIR"
# E3: generate a random master key, WRAP it with the platform's SELF-DETECTED best anchor
# (TPM / CM5-OTP / passphrase / Tang / software) via key-anchor.sh — one OS, any board. The plaintext
# key is piped to cryptsetup then shredded; it only persists for the weak `software` fallback.
MK=$(mktemp); ( umask 077; dd if=/dev/urandom of="$MK" bs=64 count=1 status=none )
/usr/lib/hookprobe/key-anchor.sh wrap "$MK"
modprobe dm_crypt 2>/dev/null || true
log "plain dm-crypt on $newpart (aes-xts-plain64, key-size 512) → /dev/mapper/$MAP (anchor=$(cat "$KEYDIR/anchor" 2>/dev/null))"
cryptsetup --type plain --cipher aes-xts-plain64 --key-size 512 --key-file "$MK" open "$newpart" "$MAP"
shred -u "$MK" 2>/dev/null || rm -f "$MK"
# Record the raw partition so the unlock service finds it every boot (encrypted → no ext4 label to key on).
blkid -s PARTUUID -o value "$newpart" > /etc/hookprobe/data-partuuid 2>/dev/null || true
[ -s /etc/hookprobe/data-partuuid ] || echo "$newpart" > /etc/hookprobe/data-partdev
log "mkfs.ext4 on the DECRYPTED mapper /dev/mapper/$MAP (label $LABEL)"
mkfs.ext4 -q -L "$LABEL" "/dev/mapper/$MAP"
cryptsetup close "$MAP"    # hookprobe-unlock-data.service re-opens it at boot, before the mount
# Authoritative "provisioned" marker (persistent on the root) — checked at step 0 so we NEVER
# re-provision on reboot (the encrypted volume has no visible by-label until unlock-data runs).
touch /etc/hookprobe/.data-provisioned
log "done — data volume ENCRYPTED; unlock service opens it, var-lib-hookprobe.mount mounts it"
