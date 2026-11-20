#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# fwfiles-fat-cases.sh <factory disk image> — ADR 0067 L0.1, the refusal cases against a REAL image layout, in QEMU.
#
# Boots the read-only QEMU check kernel (the same one the image factory boots) against copies of the image whose
# boot partition has a vendor file removed, truncated by one byte, extended by one byte, or changed in one byte, and
# expects the device's own MBR + FAT + pin code to say exactly why ([P-fwfiles-fat]). Nothing is written to the
# input image. This covers the file reader and the checks; what the chip does with the files is a metal question.
set -euo pipefail
IMG="${1:?usage: fwfiles-fat-cases.sh <disk.img>}"
HERE="$(cd "$(dirname "$0")/.." && pwd)"
for t in mcopy mdel qemu-system-aarch64 python3; do command -v $t >/dev/null || { echo "FATAL: missing $t"; exit 2; }; done
W="$(mktemp -d)"; trap 'rm -rf "$W"' EXIT
KDIR="${KDIR:-$HERE/target/factory-check}"
(cd "$HERE" && CARGO_TARGET_DIR="$KDIR" cargo build -q -p kernel --features netsvc,securechannel,securechannel-selftest) || { echo "FATAL: check kernel build"; exit 2; }
P1=$((8192 * 512))
ok=0; n=0
run() { # <name> <expected text> ; the mutated copy is $W/c.img
  timeout 180 qemu-system-aarch64 -M virt -cpu cortex-a72 -m 512M -nographic -serial mon:stdio -semihosting \
    -global virtio-mmio.force-legacy=false -netdev user,id=n0 -device virtio-net-device,netdev=n0 \
    -drive file="$W/c.img",format=raw,if=none,id=hd0 -device virtio-blk-device,drive=hd0 \
    -kernel "$KDIR/aarch64-unknown-none-softfloat/debug/kernel" >"$W/q.log" 2>&1 </dev/null || true
  local line; line="$(grep -aF "[P-fwfiles-fat]" "$W/q.log" | head -1 | cut -c1-260)"
  n=$((n + 1))
  if grep -qF "$2" <<<"$line"; then ok=$((ok + 1)); echo "ok  $1"; else echo "BAD $1 (wanted: $2)"; fi
  echo "      $line"
}
fresh() { cp "$IMG" "$W/c.img"; }
get() { mcopy -n -i "$W/c.img@@$P1" "::$1" "$W/f.bin"; }
put() { mdel -i "$W/c.img@@$P1" "::$1"; mcopy -i "$W/c.img@@$P1" "$W/f.bin" "::$1"; }
flip() { python3 -I - "$W/f.bin" <<'PY'
import sys
p = sys.argv[1]; d = bytearray(open(p, "rb").read()); d[len(d) // 2] ^= 0x01; open(p, "wb").write(d)
PY
}
fresh;                                                             run "untouched image: all three files accepted"            "PASS"
fresh; mdel -i "$W/c.img@@$P1" ::CYW43455.BIN;                      run "firmware absent -> Missing(0)"                         "would say: Err(Missing(0))"
fresh; get CYW43455.BIN; truncate -s -1 "$W/f.bin"; put CYW43455.BIN; run "firmware one byte short -> Size(0)"                   "would say: Err(Size(0))"
fresh; get CYW43455.BIN; printf 'x' >> "$W/f.bin"; put CYW43455.BIN;  run "firmware one byte long -> Size(0)"                    "would say: Err(Size(0))"
fresh; get CYW43455.BIN; flip; put CYW43455.BIN;                    run "firmware same length, one bit changed -> Digest(0)"   "would say: Err(Digest(0))"
fresh; mdel -i "$W/c.img@@$P1" ::CYW43455.NVR;                      run "NVRAM absent -> Missing(1)"                            "would say: Err(Missing(1))"
fresh; mdel -i "$W/c.img@@$P1" ::CYW43455.CLM;                      run "CLM absent -> Missing(2)"                              "would say: Err(Missing(2))"
fresh; get CYW43455.NVR; flip; put CYW43455.NVR;                    run "NVRAM one bit changed -> Digest(1)"                    "would say: Err(Digest(1))"
fresh; get CYW43455.CLM; flip; put CYW43455.CLM;                    run "CLM one bit changed -> Digest(2)"                      "would say: Err(Digest(2))"
echo "FWFILES-FAT-CASES: $([ $ok = $n ] && echo PASS || echo FAIL) ($ok/$n)"
[ $ok = $n ]
