#!/usr/bin/env bash
# REL-08: the in-RAM correction of the CYW43455 7.45.265 PMKID-cache expiry walk must be EXACTLY what
# tools/firmware/rel08/pmkid_walk.s assembles to, at 0x1c823c, 120 bytes, and (when the staged firmware is present) the
# bytes it replaces must be the original walk. Exit 0 = consistent; 1 = drift (refuse to ship).
set -eu
HERE=$(cd "$(dirname "$0")" && pwd); ROOT=$(cd "$HERE/../../.." && pwd)
SRC="$ROOT/os/kernel/arch-aarch64/src/cyw43.rs"; FW="$ROOT/os/kernel/firmware/brcm/cyw43455-sdio.bin"
T=$(mktemp -d); trap 'rm -rf "$T"' EXIT
LLD=${LLD:-$(command -v ld.lld || ls ~/.rustup/toolchains/*/lib/rustlib/*/bin/gcc-ld/ld.lld 2>/dev/null | head -1)}
llvm-mc -triple=thumbv7r-none-eabi -mcpu=cortex-r4 -filetype=obj "$HERE/pmkid_walk.s" -o "$T/w.o"
"$LLD" -T "$HERE/pmkid_walk.ld" "$T/w.o" -o "$T/w.elf" 2>/dev/null
llvm-objcopy -O binary -j .text "$T/w.elf" "$T/w.bin"
python3 -I - "$SRC" "$T/w.bin" "$FW" <<'PY'
import re, sys, os
src, built, fw = open(sys.argv[1]).read(), open(sys.argv[2], "rb").read(), sys.argv[3]
def arr(name):
    m = re.search(name + r": \[u8; 120\] = \[([^\]]*)\]", src)
    return bytes(int(x, 16) for x in m.group(1).replace("\n", " ").split(",") if x.strip())
fixed, orig = arr("WALK_FIXED"), arr("WALK_ORIG")
ok = True
if len(built) != 120 or built != fixed:
    print("REL-08 check: WALK_FIXED in cyw43.rs does not match pmkid_walk.s (%d B assembled)" % len(built)); ok = False
if os.path.exists(fw):
    d = open(fw, "rb").read(); off = 0x1c823c - 0x198000
    if d[off:off + 120] != orig:
        print("REL-08 check: the staged firmware does not carry the original walk at 0x1c823c — the patch would be skipped"); ok = False
    if b"Version: 7.45.265 (28bca26 CY) CRC: 68bafb8c" not in d:
        print("REL-08 check: the staged firmware is not 7.45.265 (28bca26) — re-derive the patch for the new image"); ok = False
else:
    print("REL-08 check: staged firmware not present (source-only check)")
print("REL-08 check: %s" % ("PASS" if ok else "FAIL")); sys.exit(0 if ok else 1)
PY
