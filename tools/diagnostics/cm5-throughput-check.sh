#!/usr/bin/env bash
# cm5-throughput-check — download throughput for a Wi-Fi client through the heqk AP (NAT + IDS + Shield on the
# path), from the bench Pi's AP-side interface. Reports each run and the median; FAIL below the floor.
#   tools/diagnostics/cm5-throughput-check.sh [pi] [iface] [floor-mbps] [runs]
# Baseline 2026-11-09 (cd624beb, bench Pi USB Wi-Fi): 73 / 120 / 135 Mbps, median 120.
set -u -o pipefail
PI="${1:-claude@10.200.0.4}"; IF="${2:-wlan1}"; FLOOR="${3:-60}"; RUNS="${4:-5}"
URL='https://speed.cloudflare.com/__down?bytes=60000000'
# the client must be on the AP with a default route through it first (after other suites it may be re-associating)
for _ in $(seq 1 30); do ssh -o BatchMode=yes -o ConnectTimeout=8 "$PI" "ip -4 addr show $IF | grep -q 'inet ' && curl --interface $IF -s -o /dev/null -m 5 https://example.com" && break; sleep 3; done
v=()
for _ in $(seq 1 "$RUNS"); do
  b=$(ssh -o BatchMode=yes -o ConnectTimeout=8 "$PI" "curl --interface $IF -s -o /dev/null -m 25 -w '%{speed_download}' '$URL'" 2>/dev/null || echo 0)
  m=$(awk -v b="$b" 'BEGIN{printf "%.1f", b*8/1e6}'); v+=("$m"); echo "  run: $m Mbps"
done
med=$(printf '%s\n' "${v[@]}" | sort -n | awk '{a[NR]=$1} END{print a[int((NR+1)/2)]}')
awk -v m="$med" -v f="$FLOOR" 'BEGIN{exit !(m>=f)}' && { echo "THROUGHPUT: PASS — median $med Mbps (floor $FLOOR)"; exit 0; }
echo "THROUGHPUT: FAIL — median $med Mbps (floor $FLOOR)"; exit 1
