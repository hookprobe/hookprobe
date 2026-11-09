#!/usr/bin/env bash
# Fetch NIST's FIPS 203 ACVP vectors (ML-KEM keyGen + encapDecap, internalProjection = inputs + expected).
#   os/build/kem-diff/fetch-acvp.sh [DIR]   (default ./acvp; gitignored)
set -euo pipefail
DIR="${1:-$(dirname "$0")/acvp}"
mkdir -p "$DIR"
for f in ML-KEM-keyGen-FIPS203 ML-KEM-encapDecap-FIPS203; do
  curl -sSf -m 180 -H "Accept: application/vnd.github.raw" -o "$DIR/$f.json" \
    "https://api.github.com/repos/usnistgov/ACVP-Server/contents/gen-val/json-files/$f/internalProjection.json"
  echo "$f: $(stat -c %s "$DIR/$f.json") bytes, sha256 $(sha256sum "$DIR/$f.json" | cut -c1-16)"
done
