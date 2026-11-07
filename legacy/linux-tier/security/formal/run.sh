#!/bin/sh
# Run the HTP v2 ProVerif models. Requires `proverif` (>= 2.05) on PATH.
#
# If ProVerif is not installed:
#   Debian/Ubuntu (root):   sudo apt-get install -y proverif         # if packaged
#   OCaml/opam (preferred): opam install proverif
#   From source (no root):  download https://bblanche.gitlabpages.inria.fr/proverif/proverif2.05.tar.gz
#                           need an OCaml compiler (ocamlopt) + unix/str/threads libs, then:
#                             cd proverif2.05 && ./build -nointeract native
#                           (this produces ./proverif). See docs/architecture/htp-v2-formal-analysis.md SS"How it was run".
set -e
DIR="$(cd "$(dirname "$0")" && pwd)"
PV="${PROVERIF:-proverif}"
for f in htp_v2_ik htp_v2_ik_hidden htp_v2_ik_negctrl; do
  echo "================ $f.pv ================"
  "$PV" "$DIR/$f.pv" | sed -n '/Verification summary/,$p'
done
