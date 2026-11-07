#!/bin/sh
# measured-boot-report.sh — capture the device's boot-integrity posture at every boot into
# /var/lib/hookprobe/boot-attestation.json, for the Organism Status / QSECBIT score + (when enrolled)
# remote attestation to the PoP. CAPABILITY-GATED: reads the TPM 2.0 PCRs from sysfs where a TPM
# exists (N100/appliances/UEFI-arm64) — NO tpm2-tools dependency; degrades to software-attestation on
# the Pi (no TPM/no UEFI-SB). See docs/adr/0006-os-hardening.md (H2). Read-only; never fails the boot.
#
# PCR map (UEFI/systemd convention): 0=firmware · 4=bootloader/UKI · 7=SecureBoot policy state ·
# 11=systemd-stub's measurement of the UKI (kernel+initrd+cmdline+os-release). A stable 7 & 11 across
# boots = the boot chain didn't change; a delta = tamper or an (expected) upgrade.
set -u
OUT=/var/lib/hookprobe/boot-attestation.json
PCRDIR=/sys/class/tpm/tpm0/pcr-sha256
mkdir -p /var/lib/hookprobe 2>/dev/null || true

tpm=false; [ -d "$PCRDIR" ] && tpm=true

# Secure Boot state from the EFI variable (data byte after the 4-byte attr header = 1 → enabled).
sb=false
sbvar=$(ls /sys/firmware/efi/efivars/SecureBoot-* 2>/dev/null | head -1)
if [ -n "$sbvar" ]; then
  [ "$(od -An -t u1 "$sbvar" 2>/dev/null | tr -s ' ' | cut -d' ' -f6)" = "1" ] && sb=true
fi

pcr() { [ -f "$PCRDIR/$1" ] && tr 'A-F' 'a-f' < "$PCRDIR/$1" | tr -d '\n' || printf ''; }

# Posture verdict for the score: strongest = SB on + TPM measuring; weakest = neither (software only).
if $sb && $tpm; then posture="measured-secure"; score=100
elif $tpm;      then posture="measured";        score=70
elif [ -n "$sbvar" ] && $sb; then posture="secureboot";  score=60
else posture="software"; score=40; fi

# uki measurement (PCR 11) present ⇒ systemd-stub verified the kernel/initrd/cmdline at boot.
case "$(pcr 11)" in
  ""|0000000000000000000000000000000000000000000000000000000000000000) uki_measured=false ;;
  *) uki_measured=true ;;
esac

{
  printf '{\n'
  printf '  "schema": 1,\n'
  printf '  "tpm_present": %s,\n' "$tpm"
  printf '  "secure_boot": %s,\n' "$sb"
  printf '  "uki_measured": %s,\n' "$uki_measured"
  printf '  "posture": "%s",\n' "$posture"
  printf '  "integrity_score": %s,\n' "$score"
  printf '  "pcr": { "firmware": "%s", "bootloader": "%s", "secureboot_policy": "%s", "uki": "%s" }\n' \
         "$(pcr 0)" "$(pcr 4)" "$(pcr 7)" "$(pcr 11)"
  printf '}\n'
} > "$OUT.tmp" && mv "$OUT.tmp" "$OUT"

echo "measured-boot: posture=$posture tpm=$tpm secure_boot=$sb uki_measured=$uki_measured → $OUT"
