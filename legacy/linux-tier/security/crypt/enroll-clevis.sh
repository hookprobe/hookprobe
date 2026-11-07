#!/usr/bin/env bash
# enroll-clevis.sh — bind the LUKS2 data partition (/var/lib/hookprobe) to a CAPABILITY-DRIVEN Clevis
# unlock policy so it auto-unlocks at boot with no typed passphrase — WITHOUT ever depending solely on
# the network. Tang (network-bound) unlock is ADDITIVE, exactly like the cloud/account layer: a
# standalone/air-gapped device MUST still unlock on its own. See docs/adr/0006-os-hardening.md (H3c).
#
#   ./enroll-clevis.sh <luks-device> [tang-url ...]
#
# Policy chosen from what the device HAS (mirrors "capabilities, not branches"):
#   TPM + Tang   → sss t=1 {tpm2, tang}   unlock LOCALLY (standalone) OR via Tang (fleet). Best of both.
#   TPM, no Tang → tpm2                    local sealed unlock — fully standalone, confidential at rest.
#   Tang, no TPM → tang                    fleet auto-unlock; air-gapped falls back to the recovery slot.
#   neither      → SKIP (no auto-unlock secret) — the device stays INTEGRITY-only (dm-verity, H3); add a
#                  TPM/secure-element (or the future HookProbe silicon) for confidentiality-at-rest.
#
# A recovery passphrase LUKS keyslot is ALWAYS required first, so no policy can ever brick a device.
set -euo pipefail
DEV="${1:?usage: enroll-clevis.sh <luks-device> [tang-url ...]}"; shift || true
TANGS=("$@")
PCRS="${HOOKPROBE_CLEVIS_PCRS:-7,11}"

command -v clevis >/dev/null || { echo "clevis not installed (apt: clevis clevis-luks clevis-tpm2 clevis-initramfs)"; exit 1; }
cryptsetup isLuks "$DEV" 2>/dev/null || { echo "$DEV is not a LUKS device"; exit 1; }

# Guard: a recovery keyslot MUST exist (a Clevis pin failing must fall back to a human, never a brick).
slots=$(cryptsetup luksDump "$DEV" | grep -c '^\s*[0-9]*: luks2' || true)
[ "${slots:-0}" -ge 1 ] || { echo "REFUSING: add a recovery passphrase keyslot first (cryptsetup luksAddKey $DEV)"; exit 1; }

have_tpm=false; [ -e /dev/tpmrm0 ] && have_tpm=true
have_tang=false; [ "${#TANGS[@]}" -gt 0 ] && have_tang=true
tpm_cfg="{\"pcr_bank\":\"sha256\",\"pcr_ids\":\"$PCRS\"}"
tang_arr=""; for u in "${TANGS[@]:-}"; do [ -n "$u" ] && tang_arr+="${tang_arr:+,}{\"url\":\"$u\"}"; done

bind() { echo "clevis luks bind → $1"; clevis luks bind -d "$DEV" "$2" "$3"; }

if $have_tpm && $have_tang; then
  bind "sss t=1 {tpm2, tang}  (local OR network — standalone-safe)" sss \
       "{\"t\":1,\"pins\":{\"tpm2\":$tpm_cfg,\"tang\":[$tang_arr]}}"
elif $have_tpm; then
  bind "tpm2  (local sealed unlock — fully standalone)" tpm2 "$tpm_cfg"
elif $have_tang; then
  echo "NOTE: no TPM — Tang gives fleet auto-unlock, but air-gapped boots fall back to the recovery"
  echo "      passphrase. For headless standalone confidentiality, fit a TPM/secure-element."
  bind "tang  (network-bound; recovery passphrase is the standalone fallback)" tang \
       "{\"url\":\"${TANGS[0]}\"}"
else
  echo "no TPM and no Tang → SKIP Clevis. This device stays INTEGRITY-only (dm-verity rootfs, H3)."
  echo "Confidentiality-at-rest here needs a local root of trust (TPM/SE or HookProbe silicon)."
  exit 0
fi

echo "✓ enrolled. clevis-initramfs unlocks $DEV at boot. Verify: clevis luks list -d $DEV"
echo "  Tang is ADDITIVE — a local pin (tpm2) or the recovery slot always keeps standalone devices bootable."
