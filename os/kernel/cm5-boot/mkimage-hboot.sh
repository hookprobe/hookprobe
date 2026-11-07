#!/usr/bin/env bash
# Combined HBoot image: hboot (padded to the payload slot) + hybrid-signed
# PayloadHeader + kernel. The EEPROM loads this flat image; HBoot measures
# (SHA-256) and VERIFIES the embedded kernel with BOTH an ed25519 and an
# SLH-DSA (FIPS 205) signature before launching it at EL1.
#   ./mkimage-hboot.sh <hboot.elf> <kernel.bin> <out.img>
# Env: SIGNER (default ~/heqk-sign/target/release/heqk-sign), KEYDIR
#      (default ~/heqk-sign/keys), SVN (default 1, anti-rollback version).
set -euo pipefail
HBOOT_ELF="${1:?hboot ELF}"; KERNEL_BIN="${2:?kernel flat binary}"; OUT="${3:?output image}"
OBJCOPY="${OBJCOPY:-llvm-objcopy}"
SIGNER="${SIGNER:-$HOME/heqk-sign/target/release/heqk-sign}"
KEYDIR="${KEYDIR:-$HOME/heqk-sign/keys}"
SVN="${SVN:-1}"
PAYLOAD_OFFSET=$((0x200000))    # HBOOT_PAYLOAD_OFFSET (boot-abi)
LOAD_PA=$((0x1000000))          # KERNEL_LOAD_PA
PAYLOAD_MAGIC=0x0033444c504b5148  # "HQKPLD3\0" (v3 hybrid + SVN)
SLHDSA_SIG_LEN=7856
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT

"$OBJCOPY" -O binary "$HBOOT_ELF" "$TMP/hboot.bin"
HBOOT_SIZE=$(stat -c %s "$TMP/hboot.bin")
[ "$HBOOT_SIZE" -le "$PAYLOAD_OFFSET" ] || { echo "ABORT: hboot $HBOOT_SIZE B > slot $PAYLOAD_OFFSET B" >&2; exit 1; }
KSIZE=$(stat -c %s "$KERNEL_BIN"); KHASH=$(sha256sum "$KERNEL_BIN" | cut -d' ' -f1)

# HYBRID SIGN — both signatures cover SHA-256( LE64(svn) || sha256(payload) ),
# binding the security version so anti-rollback cannot be bypassed by editing it.
"$SIGNER" sign "$KEYDIR" "$KERNEL_BIN" "$SVN" "$TMP/ed.sig" "$TMP/pq.sig"

cp "$TMP/hboot.bin" "$TMP/img"; truncate -s "$PAYLOAD_OFFSET" "$TMP/img"
python3 - "$KSIZE" "$LOAD_PA" "$KHASH" "$PAYLOAD_MAGIC" "$SLHDSA_SIG_LEN" "$SVN" \
         "$TMP/ed.sig" "$TMP/pq.sig" "$TMP/hdr" <<'PY'
import sys, struct, binascii
size, load, kh = int(sys.argv[1]), int(sys.argv[2]), binascii.unhexlify(sys.argv[3])
magic, slh_len, svn = int(sys.argv[4], 0), int(sys.argv[5]), int(sys.argv[6])
ed_sig = open(sys.argv[7], 'rb').read(); pq_sig = open(sys.argv[8], 'rb').read(); out = sys.argv[9]
assert len(ed_sig) == 64, len(ed_sig)
assert len(pq_sig) == slh_len, len(pq_sig)
hdr  = struct.pack('<QQQQQ', magic, size, 0, load, svn)  # magic/size/entry/load/svn
hdr += kh                                                # sha256[32]
hdr += ed_sig                                            # ed25519_sig[64]
hdr += pq_sig                                            # slhdsa_sig[7856]
assert len(hdr) == 40 + 32 + 64 + slh_len, len(hdr)
open(out, 'wb').write(hdr)
PY
cat "$TMP/hdr" "$KERNEL_BIN" >> "$TMP/img"; cp "$TMP/img" "$OUT"
echo "== $OUT: hboot ${HBOOT_SIZE}B | payload ${KSIZE}B @ $(printf 0x%x $LOAD_PA) | svn $SVN | sha $KHASH"
echo "   header $(stat -c %s "$TMP/hdr")B (ed25519+SLH-DSA+svn) | total $(stat -c %s "$OUT")B"

# BUILD-TIME guard (the same bound hboot enforces at boot, boot_abi::HBOOT_IMAGE_END_MAX): the
# EEPROM loads this whole file flat at 0x200000 and hboot's EL2 stack (1 MiB reserved) sits below
# 0x800000, so the file must end at or below 0x700000 → at most 5 MiB. Fail the BUILD, not the
# boot: a 2.06 MB kernel once passed every build check and was refused on metal.
IMG_SIZE=$(stat -c %s "$OUT")
MAX_IMG=$(( 0x700000 - 0x200000 ))
if [ "$IMG_SIZE" -gt "$MAX_IMG" ]; then
  echo "FATAL: $OUT is $IMG_SIZE bytes > $MAX_IMG — hboot would refuse it (payload under its stack). Shrink the kernel." >&2
  rm -f "$OUT"; exit 1
fi
echo "   image size $IMG_SIZE / $MAX_IMG bytes ($(( IMG_SIZE * 100 / MAX_IMG ))% of the hboot load window)"
