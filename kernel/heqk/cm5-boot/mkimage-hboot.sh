#!/usr/bin/env bash
# Combined HBoot image: hboot (padded to the payload slot) + hybrid-signed
# PayloadHeader + kernel. The EEPROM loads this flat image; HBoot measures
# (SHA-256) and VERIFIES the embedded kernel with BOTH an ed25519 and an
# SLH-DSA (FIPS 205) signature before launching it at EL1.
#   ./mkimage-hboot.sh <hboot.elf> <kernel.bin> <out.img>
# Env: SIGNER (default ~/heqk-sign/target/release/heqk-sign), KEYDIR
#      (default ~/heqk-sign/keys).
set -euo pipefail
HBOOT_ELF="${1:?hboot ELF}"; KERNEL_BIN="${2:?kernel flat binary}"; OUT="${3:?output image}"
OBJCOPY="${OBJCOPY:-llvm-objcopy}"
SIGNER="${SIGNER:-$HOME/heqk-sign/target/release/heqk-sign}"
KEYDIR="${KEYDIR:-$HOME/heqk-sign/keys}"
PAYLOAD_OFFSET=$((0x200000))    # HBOOT_PAYLOAD_OFFSET (boot-abi)
LOAD_PA=$((0x1000000))          # KERNEL_LOAD_PA
PAYLOAD_MAGIC=0x0032444c504b5148  # "HQKPLD2\0" (v2 hybrid)
SLHDSA_SIG_LEN=7856
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT

"$OBJCOPY" -O binary "$HBOOT_ELF" "$TMP/hboot.bin"
HBOOT_SIZE=$(stat -c %s "$TMP/hboot.bin")
[ "$HBOOT_SIZE" -le "$PAYLOAD_OFFSET" ] || { echo "ABORT: hboot $HBOOT_SIZE B > slot $PAYLOAD_OFFSET B" >&2; exit 1; }
KSIZE=$(stat -c %s "$KERNEL_BIN"); KHASH=$(sha256sum "$KERNEL_BIN" | cut -d' ' -f1)

# HYBRID SIGN the payload (both signatures are over sha256(payload)).
"$SIGNER" sign "$KEYDIR" "$KERNEL_BIN" "$TMP/ed.sig" "$TMP/pq.sig"

cp "$TMP/hboot.bin" "$TMP/img"; truncate -s "$PAYLOAD_OFFSET" "$TMP/img"
python3 - "$KSIZE" "$LOAD_PA" "$KHASH" "$PAYLOAD_MAGIC" "$SLHDSA_SIG_LEN" \
         "$TMP/ed.sig" "$TMP/pq.sig" "$TMP/hdr" <<'PY'
import sys, struct, binascii
size, load, kh = int(sys.argv[1]), int(sys.argv[2]), binascii.unhexlify(sys.argv[3])
magic, slh_len = int(sys.argv[4], 0), int(sys.argv[5])
ed_sig = open(sys.argv[6], 'rb').read(); pq_sig = open(sys.argv[7], 'rb').read(); out = sys.argv[8]
assert len(ed_sig) == 64, len(ed_sig)
assert len(pq_sig) == slh_len, len(pq_sig)
hdr  = struct.pack('<QQQQ', magic, size, 0, load)  # magic/size/entry_offset/load_pa
hdr += kh                                          # sha256[32]
hdr += ed_sig                                      # ed25519_sig[64]
hdr += pq_sig                                      # slhdsa_sig[7856]
assert len(hdr) == 32 + 32 + 64 + slh_len, len(hdr)
open(out, 'wb').write(hdr)
PY
cat "$TMP/hdr" "$KERNEL_BIN" >> "$TMP/img"; cp "$TMP/img" "$OUT"
echo "== $OUT: hboot ${HBOOT_SIZE}B | payload ${KSIZE}B @ $(printf 0x%x $LOAD_PA) | sha $KHASH"
echo "   header $(stat -c %s "$TMP/hdr")B (ed25519+SLH-DSA) | total $(stat -c %s "$OUT")B"
