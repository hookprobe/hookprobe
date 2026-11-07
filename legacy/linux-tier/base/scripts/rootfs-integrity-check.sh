#!/bin/sh
# rootfs-integrity-check.sh — report the dm-verity rootfs posture into /var/lib/hookprobe/
# rootfs-integrity.json for the Organism Status / QSECBIT score. Two strengths:
#   enforced  — root is mounted through a dm-verity target ⇒ EVERY block read is hash-verified live,
#               fail-closed. This is the strong state (H3b, initramfs verity-boot).
#   verified  — verity metadata (root hash + hash tree) ships but root isn't yet verity-mounted; we ran
#               a one-shot `veritysetup verify` and it matched (detection, not live enforcement — H3a).
#   none      — no verity metadata (pre-H3 image / non-Pi platform using UEFI SB + TPM instead).
# Read-only; never fails the boot. See docs/adr/0006-os-hardening.md (H3).
set -u
OUT=/var/lib/hookprobe/rootfs-integrity.json
BOOT=/boot                              # p1 (FAT) — carries the verity anchor out-of-band from p2
RHFILE="$BOOT/verity.roothash"
HASHTREE="$BOOT/rootfs.verity"
mkdir -p /var/lib/hookprobe 2>/dev/null || true

posture=none; corruption=0; roothash=""
rootsrc=$(findmnt -no SOURCE / 2>/dev/null)

# 1) Strongest: is / served by an active dm-verity target? (dmsetup reports a corruption counter)
if command -v dmsetup >/dev/null 2>&1; then
  vstatus=$(dmsetup status --target verity 2>/dev/null)
  if [ -n "$vstatus" ] && { echo "$rootsrc" | grep -q '/dev/\(mapper\|dm-\)'; }; then
    posture=enforced
    # verity status line ends in V (valid) or C (corruption detected)
    echo "$vstatus" | grep -q ' C$' && corruption=1
  fi
fi

# 2) Fallback: verity metadata present but not verity-mounted → one-shot offline verify (detection).
if [ "$posture" = none ] && [ -f "$RHFILE" ] && [ -f "$HASHTREE" ] && [ -n "$rootsrc" ]; then
  roothash=$(cat "$RHFILE" 2>/dev/null)
  if command -v veritysetup >/dev/null 2>&1 && [ -n "$roothash" ]; then
    if veritysetup verify "$rootsrc" "$HASHTREE" "$roothash" >/dev/null 2>&1; then
      posture=verified
    else
      posture=tampered; corruption=1
    fi
  fi
fi

case "$posture" in
  enforced) score=100 ;; verified) score=80 ;; tampered) score=0 ;; *) score=40 ;;
esac

{
  printf '{ "schema": 1, "posture": "%s", "root_source": "%s", "corruption": %s, "integrity_score": %s' \
         "$posture" "${rootsrc:-unknown}" "$corruption" "$score"
  [ -n "$roothash" ] && printf ', "root_hash": "%s"' "$roothash"
  printf ' }\n'
} > "$OUT.tmp" && mv "$OUT.tmp" "$OUT"
echo "rootfs-integrity: posture=$posture corruption=$corruption → $OUT"
