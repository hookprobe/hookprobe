#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# stage-licences.sh — build the LICENSES/ folder that every factory image carries on its FAT boot
# partition, so a unit that leaves the building has every licence text, notice and source its
# contents' licences ask for (os/build/licenses/, os/drivers/firmware/*/LICENSE.md).
#
#   os/build/licenses/stage-licences.sh <dest-dir> <git-rev> [--zero-linux]
#   os/build/licenses/stage-licences.sh --verify <image>@@<p1-byte-offset> <dest-dir>
#       reads every staged file back from the FAT partition (mtools) and compares its bytes
#
# Writes <dest-dir>/LICENSES/:
#   README.TXT              what is here, which file on the card each record covers, where the source is
#   HOOKPROBE-LICENSE.txt   HookProbe's own licence (AGPL-3.0-only), the repository's LICENSE
#   THIRD_PARTY_NOTICES.md  every third-party crate and browser package in the slot image (generated)
#   GPL-2.0.txt MIT.txt BSD-2-Clause.txt   licence texts the device-tree and NVRAM records refer to
#   WIFI-FIRMWARE.md        CYW43455.BIN/.CLM (Cypress licence, text included) and CYW43455.NVR (GPL-2)
#   DEVICETREE.md + DEVICETREE-SOURCE/   only with a .dtb (not --zero-linux): its licence record and
#                           its complete corresponding source (GPL-2.0 §3(a)), with SHA256SUMS
#
# Fails, rather than shipping an incomplete folder, if any input is missing or the device-tree source
# no longer matches its SHA256SUMS.
set -euo pipefail
if [ "${1:-}" = --verify ]; then
  [ $# = 3 ] || { echo "usage: $0 --verify <image>@@<offset> <dest-dir>" >&2; exit 2; }
  IMG="$2"; L="$3/LICENSES"; n=0
  [ -d "$L" ] || { echo "FATAL: nothing staged in $L" >&2; exit 1; }
  while IFS= read -r f; do
    rel="${f#"$L"/}"
    got="$(mcopy -n -i "$IMG" "::LICENSES/$rel" - | sha256sum | cut -d' ' -f1)"
    [ "$got" = "$(sha256sum <"$f" | cut -d' ' -f1)" ] || { echo "licences: LICENSES/$rel differs on the partition" >&2; exit 1; }
    n=$((n + 1))
  done < <(find "$L" -type f | sort)
  echo "licences: $n files read back from the partition, all identical"
  exit 0
fi
[ $# -ge 2 ] || { echo "usage: $0 <dest-dir> <git-rev> [--zero-linux]" >&2; exit 2; }
DEST="$1"; REV="$2"; ZERO_LINUX=0
[ "${3:-}" = --zero-linux ] && ZERO_LINUX=1
ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
FWD="$ROOT/os/drivers/firmware"
L="$DEST/LICENSES"

need() { [ -s "$1" ] || { echo "FATAL: licence input missing: ${1#"$ROOT"/}" >&2; exit 1; }; }
for f in "$ROOT/LICENSE" "$ROOT/os/build/licenses/THIRD_PARTY_NOTICES.md" "$FWD/LICENSES/GPL-2.0.txt" \
         "$FWD/LICENSES/MIT.txt" "$FWD/LICENSES/BSD-2-Clause.txt" "$FWD/brcm-firmware-rpt/LICENSE.md"; do
  need "$f"
done

rm -rf "$L"; mkdir -p "$L"
cp "$ROOT/LICENSE" "$L/HOOKPROBE-LICENSE.txt"
cp "$ROOT/os/build/licenses/THIRD_PARTY_NOTICES.md" "$L/THIRD_PARTY_NOTICES.md"
cp "$FWD/LICENSES/GPL-2.0.txt" "$FWD/LICENSES/MIT.txt" "$FWD/LICENSES/BSD-2-Clause.txt" "$L/"
cp "$FWD/brcm-firmware-rpt/LICENSE.md" "$L/WIFI-FIRMWARE.md"

if [ "$ZERO_LINUX" = 0 ]; then
  SRC="$FWD/rpi-dtb/source"
  need "$FWD/rpi-dtb/LICENSE.md"; need "$SRC/SHA256SUMS"
  ( cd "$SRC" && sha256sum --quiet -c SHA256SUMS ) || { echo "FATAL: device-tree source does not match its SHA256SUMS" >&2; exit 1; }
  cp "$FWD/rpi-dtb/LICENSE.md" "$L/DEVICETREE.md"
  cp -R "$SRC" "$L/DEVICETREE-SOURCE"
  DT_LINES="bcm2712-rpi-cm5-cm5io.dtb   GPL-2.0. Record: DEVICETREE.md. Complete corresponding source:
                            DEVICETREE-SOURCE/ (check it with: sha256sum -c SHA256SUMS);
                            rebuild commands in DEVICETREE.md. Licence text: GPL-2.0.txt."
else
  DT_LINES="(no devicetree: this image was built with --zero-linux)"
fi

cat >"$L/README.TXT" <<EOF
LICENCES FOR THE SOFTWARE ON THIS DEVICE

This boot partition holds HookProbe OS (heqk) and a few third-party files. Each one's licence,
notices and, where its licence asks for it, its source are in this folder.

File on the boot partition  Licence and where to find it
--------------------------  ----------------------------------------------------------------
heqk8-a.img, heqk8-b.img    HookProbe OS: AGPL-3.0-only (HOOKPROBE-LICENSE.txt), also available
                            under a commercial licence from HookProbe. It contains third-party
                            Rust crates and browser code, each listed with its licence text in
                            THIRD_PARTY_NOTICES.md (all MIT, Apache-2.0, BSD, ISC or similar).
CYW43455.BIN, CYW43455.CLM  Cypress Wi-Fi firmware, object code: Cypress licence, full text in
                            WIFI-FIRMWARE.md. For use with Cypress chips only.
CYW43455.NVR                Wi-Fi settings file, GPL-2 (its text is its own source).
                            Record: WIFI-FIRMWARE.md. Licence text: GPL-2.0.txt.
$DT_LINES
config.txt, tryboot.txt and the other .TXT, .SIG, .CRT files and RULES.BIN: device
configuration written by the image build or the device, not third-party software.

Source code of HookProbe OS: https://github.com/hookprobe/hookprobe
This image was built from commit $REV.
EOF
echo "licences: staged $(find "$L" -type f | wc -l | tr -d ' ') files in LICENSES/ ($([ "$ZERO_LINUX" = 1 ] && echo 'no devicetree' || echo 'with devicetree source'))"
