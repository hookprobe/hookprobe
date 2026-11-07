#!/usr/bin/env bash
# verify-binary-alignment.sh -- ADR 0030 D1 page-size-alignment gate.
#
# WHY: the unified Pi fat-boot image (ADR 0029) runs ONE shared rootfs under a
# 4K-page kernel on Pi4/CM4 (linux-image-rpi-v8) but a 16K-page kernel on
# Pi5/CM5 (linux-image-rpi-2712). An ELF whose max-alignment LOAD segment is
# aligned to < the runtime page size fails to exec with EINVAL. A green Pi4 boot
# (4K) will NOT catch a binary that only breaks under the 16K Pi5/CM5 kernel.
# aarch64 LLVM/GCC default to 0x10000 (64K) alignment, so this is expected-green
# today -- this gate makes a silent single-flag drift a hard failure instead of a
# Pi5/CM5-that-cannot-exec-its-own-SOC.
#
# Checks every staged aarch64 ELF under the given tree has a max LOAD p_align of
# at least 0x4000 (16K). Exit 0=PASS, 1=FAIL, 2=SKIP (nothing to check).
set -euo pipefail

TREE="${1:-builder/mkosi-arm64/mkosi.extra/usr/lib/hookprobe}"
MIN_ALIGN_HEX="0x4000" # 16K -- the Pi5/CM5 page size
min_align=$((MIN_ALIGN_HEX))

if [ ! -d "$TREE" ]; then
  echo "verify-binary-alignment: no tree at $TREE -- nothing to check (SKIP)"
  exit 2
fi

command -v readelf >/dev/null 2>&1 || { echo "verify-binary-alignment: readelf not found (SKIP)"; exit 2; }

checked=0
fails=0
while IFS= read -r f; do
  # aarch64 ELF only -- the Pi tier is arm64; ignore scripts, data, other arches.
  file "$f" 2>/dev/null | grep -q "ELF.*aarch64" || continue
  # Only ET_EXEC / ET_DYN are exec'd directly and carry LOAD segments the kernel
  # page-aligns at mmap. ET_REL (relocatable) -- notably Wasmtime `.cwasm` AOT
  # blobs -- have NO LOAD segments: Wasmtime deserializes + maps them itself, so
  # ELF LOAD alignment is not the relevant property. Their 16K-page compatibility
  # is a Wasmtime *runtime* concern (deserialize succeeds on a 16K host, else the
  # loader's verified-JIT fallback kicks in -- ADR 0016/0017) and is validated on
  # Pi5/CM5 metal, not statically here. Skip them.
  etype=$(readelf -hW "$f" 2>/dev/null | awk -F': *' '/Type:/{print $2}')
  case "$etype" in *REL*) continue ;; esac
  checked=$((checked + 1))
  # Max LOAD-segment alignment (the exec-relevant one is the largest p_align).
  maxalign=$(readelf -lW "$f" 2>/dev/null \
    | awk '/LOAD/{print $NF}' \
    | while read -r a; do printf '%d\n' "$a" 2>/dev/null || true; done \
    | sort -n | tail -1)
  [ -n "${maxalign:-}" ] || maxalign=0
  if [ "$maxalign" -lt "$min_align" ]; then
    printf '  FAIL %s -- max LOAD align 0x%x < required %s (would EINVAL on the 16K Pi5/CM5 kernel)\n' \
      "$(basename "$f")" "$maxalign" "$MIN_ALIGN_HEX"
    fails=$((fails + 1))
  fi
done < <(find "$TREE" -type f 2>/dev/null)

if [ "$checked" -eq 0 ]; then
  echo "verify-binary-alignment: no aarch64 ELF binaries under $TREE (SKIP)"
  exit 2
fi

if [ "$fails" -gt 0 ]; then
  echo "verify-binary-alignment: $fails/$checked binaries under-aligned for the 16K Pi5/CM5 kernel -- FAIL"
  exit 1
fi

echo "verify-binary-alignment: all $checked aarch64 ELF binaries >= $MIN_ALIGN_HEX (Pi5/CM5 16K-page safe) -- PASS"
exit 0
