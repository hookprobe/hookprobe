#!/usr/bin/env bash
# Boot the heqk efiboot probe ONCE on a THROWAWAY Oracle Linux (or Ubuntu) OCI A1 instance,
# without replacing its OS image (keeps Oracle Linux pricing; no custom-image import).
#
#   oneshot-probe.sh <ssh-target> [efiboot.efi]
#
# What it does on the target (sudo): copies the probe to the EFI System Partition, adds a
# GRUB `chainloader` menu entry, and arms it for the NEXT boot only (grub2-reboot /
# grub-reboot), then reboots. The probe prints `[OCI-A1-model] PASS|FAIL` on the serial
# console and POWERS THE INSTANCE OFF. Start it again from the OCI console: GRUB's one-shot
# is consumed, so it boots the normal OS. Read the result in the OCI serial console
# connection (or console history).
#
# REFUSES the production host. Not idempotent-harmful: re-running replaces the same entry.
set -euo pipefail
TARGET=${1:?usage: oneshot-probe.sh <user@host> [efiboot.efi]}
HERE=$(cd "$(dirname "$0")" && pwd)
EFI=${2:-$HERE/../../target/oci-a1-probe/efiboot-probe/aarch64-unknown-uefi/release/efiboot.efi}
[ -f "$EFI" ] || { echo "no probe .efi at $EFI (run: PROBE_ONLY=1 BOOT=0 $HERE/boot-heqk.sh $HERE/../../target/oci-a1-probe)" >&2; exit 2; }

case "$TARGET" in
  *mesh.hookprobe.com*|*mssp.hookprobe.com*|*hookprobe.com|*130.61.174.233*)
    echo "REFUSED: $TARGET is the production instance (hookprobe.com/MSSP). Use a throwaway A1." >&2; exit 3;;
esac
SSH=(ssh -o BatchMode=yes -o ConnectTimeout=15)
# Second guard: the production box runs the hookprobe podman stack.
if "${SSH[@]}" "$TARGET" 'podman ps --format "{{.Names}}" 2>/dev/null | grep -q -E "hookprobe|keycloak|ids-"'; then
  echo "REFUSED: $TARGET runs hookprobe/keycloak/ids containers — looks like production." >&2; exit 3
fi

scp -q "$EFI" "$TARGET:/tmp/heqk-probe.efi"
"${SSH[@]}" "$TARGET" 'sudo bash -s' <<'REMOTE'
set -euo pipefail
ESP=/boot/efi
mountpoint -q "$ESP" || { echo "no ESP mounted at $ESP"; exit 1; }
install -D -m 0644 /tmp/heqk-probe.efi "$ESP/EFI/heqk/probe.efi"
ESP_UUID=$(findmnt -no UUID "$ESP")
cat > /etc/grub.d/45_heqk_probe <<EOF
#!/bin/sh
cat <<'MENU'
menuentry 'heqk-oci-probe' --id heqk-oci-probe {
    insmod part_gpt
    insmod fat
    insmod chain
    search --no-floppy --fs-uuid --set=root ${ESP_UUID}
    chainloader /EFI/heqk/probe.efi
}
MENU
EOF
chmod +x /etc/grub.d/45_heqk_probe
if command -v grub2-mkconfig >/dev/null; then
  # Oracle Linux / RHEL family: grub.cfg path differs by release; regenerate the live one.
  CFG=/boot/grub2/grub.cfg
  [ -f /boot/efi/EFI/redhat/grub.cfg ] && ! grep -q 'configfile' /boot/efi/EFI/redhat/grub.cfg && CFG=/boot/efi/EFI/redhat/grub.cfg
  grub2-mkconfig -o "$CFG" >/dev/null 2>&1
  grep -q heqk-oci-probe "$CFG" || { echo "menu entry missing from $CFG"; exit 1; }
  grub2-reboot heqk-oci-probe
else
  update-grub >/dev/null 2>&1
  grub-reboot heqk-oci-probe
fi
echo "armed one-shot boot of heqk-oci-probe; rebooting"
systemctl reboot
REMOTE
echo "Rebooted $TARGET into the probe. Watch the OCI serial console; the instance powers off when done."
echo "Then START it from the OCI console — it returns to the normal OS."
