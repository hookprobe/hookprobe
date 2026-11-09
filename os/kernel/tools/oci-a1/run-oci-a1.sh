#!/usr/bin/env bash
# QEMU model of the Oracle Cloud (OCI) Ampere A1.Flex guest — the heqk "arm64 cloud" target.
#
# Device model measured on the real A1 instance (mesh.hookprobe.com, 2026-11-09):
#   Neoverse-N1 · guest at EL1 (no EL2 / no nested virt: N1 is ARMv8.2, FEAT_NV needs v8.3+,
#   which is why the guest has no /dev/kvm — not a setting, the silicon can't nest)
#   UEFI (edk2/AAVMF) + ACPI only (MADT GTDT IORT MCFG SPCR DBG2 PPTT, no real DTB)
#   GICv3 · PL011 console (ttyAMA0) · virtio over PCIe (QEMU gpex host bridge 1b36:0008):
#   MODERN-ONLY virtio 1.0 — virtio-net 1af4:1041 (MSI-X), virtio-scsi 1af4:1048 boot volume
#   behind a PCIe root port (bus 0x18 on OCI), virtio-gpu 1af4:1050, qemu-xhci.
#
# Usage: run-oci-a1.sh <disk.img> [extra qemu args...]
#   env: OCI_SMP (4) OCI_MEM (2G; the real VM has 24G) OCI_SEMIHOST=1 (only for kernels built
#        WITHOUT `cloud`; a `cloud` kernel exits via PSCI and prints `[heqk-exit] code=N`)
#        OCI_TIMEOUT (seconds, 0 = none)
#   -no-reboot: a PSCI SYSTEM_RESET (heqk's fail-closed path) ends the run instead of looping.
set -euo pipefail
DISK=${1:?usage: run-oci-a1.sh <disk.img> [qemu args...]}; shift
FW_CODE=${OCI_FW_CODE:-/usr/share/AAVMF/AAVMF_CODE.no-secboot.fd}
FW_VARS_TMPL=${OCI_FW_VARS:-/usr/share/AAVMF/AAVMF_VARS.fd}
[ -r "$FW_CODE" ] || { echo "missing UEFI firmware $FW_CODE (apt install qemu-efi-aarch64)" >&2; exit 2; }
VARS=$(mktemp --suffix=.vars.fd)
trap 'rm -f "$VARS"' EXIT
cp "$FW_VARS_TMPL" "$VARS"

SEMI=()
[ "${OCI_SEMIHOST:-0}" = 1 ] && SEMI=(-semihosting)
TO=()
[ "${OCI_TIMEOUT:-0}" != 0 ] && TO=(timeout --foreground "$OCI_TIMEOUT")

# virtualization=off -> firmware + OS start at EL1, exactly like the OCI guest.
# acpi=on -> edk2 publishes ACPI tables; the payload must discover hardware from them.
"${TO[@]}" qemu-system-aarch64 \
  -M virt,gic-version=3,virtualization=off,secure=off,acpi=on,highmem=on \
  -cpu neoverse-n1 -smp "${OCI_SMP:-4}" -m "${OCI_MEM:-2G}" \
  -drive if=pflash,format=raw,readonly=on,file="$FW_CODE" \
  -drive if=pflash,format=raw,file="$VARS" \
  -device virtio-gpu-pci -device qemu-xhci \
  -device pcie-root-port,id=rp0,chassis=1,slot=1 \
  -device virtio-scsi-pci,id=scsi0,bus=rp0,disable-legacy=on,disable-modern=off \
  -drive if=none,id=bootvol,format=raw,file="$DISK" \
  -device scsi-hd,drive=bootvol,bus=scsi0.0,bootindex=0 \
  -netdev user,id=n0 \
  -device virtio-net-pci,netdev=n0,mac=02:00:17:00:00:01,disable-legacy=on,disable-modern=off \
  -display none -serial mon:stdio -nodefaults -no-reboot \
  "${SEMI[@]}" "$@"
