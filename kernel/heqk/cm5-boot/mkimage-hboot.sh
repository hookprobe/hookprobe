#!/usr/bin/env bash
# Combined HBoot image: hboot (padded to 256 KiB) + PayloadHeader + kernel.
# The EEPROM loads this flat image; HBoot verifies+measures the embedded
# kernel (SHA-256) before launching it at EL1.
#   ./mkimage-hboot.sh <hboot.elf> <kernel.bin> <out.img>
set -euo pipefail
HBOOT_ELF="${1:?hboot ELF}"; KERNEL_BIN="${2:?kernel flat binary}"; OUT="${3:?output image}"
OBJCOPY="${OBJCOPY:-llvm-objcopy}"
PAYLOAD_OFFSET=$((0x40000)); LOAD_PA=$((0x1000000))
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT

"$OBJCOPY" -O binary "$HBOOT_ELF" "$TMP/hboot.bin"
HBOOT_SIZE=$(stat -c %s "$TMP/hboot.bin")
[ "$HBOOT_SIZE" -le "$PAYLOAD_OFFSET" ] || { echo "ABORT: hboot $HBOOT_SIZE B > slot $PAYLOAD_OFFSET B" >&2; exit 1; }
KSIZE=$(stat -c %s "$KERNEL_BIN"); KHASH=$(sha256sum "$KERNEL_BIN" | cut -d' ' -f1)

cp "$TMP/hboot.bin" "$TMP/img"; truncate -s "$PAYLOAD_OFFSET" "$TMP/img"
python3 - "$KSIZE" "$LOAD_PA" "$KHASH" "$TMP/hdr" <<'PY'
import sys, struct, binascii
size, load, h, out = int(sys.argv[1]), int(sys.argv[2]), binascii.unhexlify(sys.argv[3]), sys.argv[4]
data = struct.pack('<QQQQ', 0x0031444c504b5148, size, 0, load) + h + b'\x00'*64
assert len(data) == 128
open(out, 'wb').write(data)
PY
cat "$TMP/hdr" "$KERNEL_BIN" >> "$TMP/img"; cp "$TMP/img" "$OUT"
echo "== $OUT: hboot ${HBOOT_SIZE}B | payload ${KSIZE}B @ $(printf 0x%x $LOAD_PA) | sha $KHASH | total $(stat -c %s "$OUT")B"
