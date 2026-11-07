#!/usr/bin/env bash
# verify-arm64-toolchain.sh -- glibc-skew gate for staged aarch64-gnu ELFs (ADR 0021 companion).
#
# WHY (field lesson, 2026-07-09): cross-building the aarch64 GNU leg with Ubuntu 24.04's
# `aarch64-linux-gnu-gcc` links against glibc 2.39 HEADERS, but the Pi rootfs ships Debian 12
# glibc 2.36-9+deb12u14. A binary that references a NON-WEAK symbol versioned newer than the Pi's
# runtime glibc fails to exec on metal with `version 'GLIBC_2.3x' not found` -- and NO existing
# build gate inspected dynamic-symbol version requirements (build-arm64.sh only checks arch via
# `file`). This gate makes that silent "passes-build, fails-on-metal" class a hard failure. It is
# the enforcement of what modules/napse-quarantine/README.md §3 documents in prose but never gated.
# (The static-musl leg -- bootstrap/supervisor/napse-dpi -- is immune by construction; this only
# matters for the libbpf-linking GNU loaders that cannot be built musl.)
#
#   builder/verify-arm64-toolchain.sh [TREE] [MAX_GLIBC]
#     TREE       default: builder/mkosi-arm64/mkosi.extra   (scans recursively)
#     MAX_GLIBC  default: 2.36  (the Pi's runtime glibc; override if the base rootfs changes)
#
# Exit: 0=PASS, 1=FAIL (a binary needs newer glibc than the Pi has), 2=SKIP (no tree / no objdump).
set -euo pipefail
TREE="${1:-builder/mkosi-arm64/mkosi.extra}"
MAX_GLIBC="${2:-2.36}"

[ -d "$TREE" ] || { echo "verify-arm64-toolchain: no tree at $TREE (SKIP)"; exit 2; }
command -v objdump >/dev/null 2>&1 || { echo "verify-arm64-toolchain: objdump not found (SKIP)"; exit 2; }

# numeric compare "a.b" <= "c.d"
ver_le() { [ "$(printf '%s\n%s\n' "$1" "$2" | sort -V | head -1)" = "$1" ]; }

max_allowed="$MAX_GLIBC"
checked=0; fails=0
while IFS= read -r f; do
  file "$f" 2>/dev/null | grep -q "ELF.*aarch64" || continue
  # Skip static binaries (no dynamic glibc dep -- the musl leg). objdump -T errors on static.
  objdump -T "$f" >/dev/null 2>&1 || continue
  checked=$((checked+1))
  # objdump -T columns: <val> <flags(7)> <sect> <size> <version> <name>. A WEAK symbol has 'w' in
  # the flag field -- those are optional (glibc falls back), so they don't force a runtime version.
  # Take the max GLIBC_x.y among NON-weak entries only.
  worst=$(objdump -T "$f" 2>/dev/null \
      | awk '{ if (substr($0,26,1) != "w") print }' \
      | grep -oE 'GLIBC_[0-9]+\.[0-9]+' | sed 's/GLIBC_//' | sort -V | tail -1)
  [ -z "$worst" ] && continue
  if ver_le "$worst" "$max_allowed"; then
    :
  else
    echo "  FAIL $(basename "$f"): needs GLIBC_$worst > Pi runtime $max_allowed (wrong cross-toolchain -- use the pinned bookworm sysroot, see napse-quarantine/README.md §4)"
    fails=$((fails+1))
  fi
done < <(find "$TREE" -type f 2>/dev/null)

if [ "$fails" -gt 0 ]; then
  echo "verify-arm64-toolchain: $fails/$checked aarch64 binaries need newer glibc than the Pi ($max_allowed) -- FAIL"
  exit 1
fi
echo "verify-arm64-toolchain: all $checked aarch64 gnu binaries within Pi glibc $max_allowed -- PASS"
exit 0
