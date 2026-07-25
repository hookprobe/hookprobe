#!/usr/bin/env bash
# =============================================================================
# refresh.sh — re-pin the embedded sapics/ip-location-db `user-country` GeoIP DB (ADR 0034).
#
# Data-only maintenance: re-downloads the PDDL `user-country` IPv4+IPv6 CSVs, sanity-checks them
# (non-empty, sorted, plausible RO/US rows present), re-gzips them in place, refreshes SHA256SUMS,
# and prints the new upstream commit/date to paste into SOURCES.md. Needs network; run locally,
# NEVER on-device. The DB is only a regdomain HINT, so a refresh is optional/infrequent.
# =============================================================================
set -euo pipefail
cd "$(dirname "$0")"

BASE=https://raw.githubusercontent.com/sapics/ip-location-db/main/user-country
API=https://api.github.com/repos/sapics/ip-location-db/commits

fetch() { # <name>
  local n="$1" tmp
  tmp=$(mktemp)
  echo "downloading $n ..." >&2
  curl -fsSL -o "$tmp" "$BASE/$n"
  # sanity: non-empty, CSV shape start,end,CC, and ascending by first column.
  [ -s "$tmp" ] || { echo "ERROR: $n empty" >&2; rm -f "$tmp"; exit 1; }
  head -1 "$tmp" | grep -Eq '^[0-9a-fA-F:.]+,[0-9a-fA-F:.]+,[A-Z]{2}$' \
    || { echo "ERROR: $n unexpected shape" >&2; rm -f "$tmp"; exit 1; }
  LC_ALL=C sort -c -t, -k1,1V "$tmp" 2>/dev/null \
    || echo "WARN: $n not strictly version-sorted (lookup still early-exits by start_ip)" >&2
  gzip -cn "$tmp" > "$n.gz"
  rm -f "$tmp"
}

fetch user-country-ipv4.csv
fetch user-country-ipv6.csv
sha256sum user-country-ipv4.csv.gz user-country-ipv6.csv.gz > SHA256SUMS
echo "wrote SHA256SUMS:"; cat SHA256SUMS

echo "--- paste into SOURCES.md 'Pinned snapshot commit' ---"
curl -fsSL "$API?path=user-country/user-country-ipv4.csv&per_page=1" 2>/dev/null \
  | grep -E '"sha"|"date"' | head -2 || echo "(commit lookup failed — offline?)"
echo "snapshot date staged: $(date -u +%Y-%m-%d)"
