#!/usr/bin/env bash
# seal-luks-tpm.sh — bind the data-partition (LUKS2) key to the TPM 2.0, sealed to the boot-integrity
# PCRs, so the disk only unlocks when the boot chain is UNMODIFIED (a tampered kernel/UKI/SB policy →
# different PCRs → the TPM refuses to release the key = fail-closed at rest). H2 follow-on; UEFI/TPM
# platforms only (N100/appliances). The Pi has no TPM → its data partition uses a passphrase or stays
# plaintext behind dm-verity rootfs integrity (H3). See docs/adr/0006-os-hardening.md.
#
#   ./seal-luks-tpm.sh <luks-device>          # e.g. /dev/disk/by-partlabel/hookprobe-data
#
# PCR 7  = Secure Boot policy (which keys are enrolled + SB on/off)
# PCR 11 = systemd-stub's UKI measurement (kernel+initrd+cmdline+os-release)
# Binding to 7+11 means: re-signing with our key is fine (same PCR 7), but swapping the kernel/cmdline
# (PCR 11) or disabling SB (PCR 7) locks the data. Re-seal after an intended OS upgrade.
set -euo pipefail
DEV="${1:?usage: seal-luks-tpm.sh <luks-device>}"
PCRS="${HOOKPROBE_SEAL_PCRS:-7+11}"

[ -e /dev/tpmrm0 ] || { echo "seal-luks: no TPM (/dev/tpmrm0) — this platform uses H3 rootfs integrity instead"; exit 0; }
command -v systemd-cryptenroll >/dev/null || { echo "seal-luks: systemd-cryptenroll missing"; exit 1; }
cryptsetup isLuks "$DEV" 2>/dev/null || { echo "seal-luks: $DEV is not a LUKS device"; exit 1; }

echo "sealing $DEV LUKS key to TPM PCRs $PCRS (unlocks only on an unmodified boot chain)…"
systemd-cryptenroll "$DEV" --tpm2-device=auto --tpm2-pcrs="$PCRS"
echo "✓ sealed. Add to /etc/crypttab:  hookprobe-data  $DEV  -  tpm2-device=auto,tpm2-pcrs=$PCRS"
echo "  RE-SEAL after an intended kernel/UKI upgrade (PCR 11 changes) or key re-enroll (PCR 7)."
