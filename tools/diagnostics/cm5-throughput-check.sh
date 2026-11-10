#!/usr/bin/env bash
# cm5-throughput-check — download throughput for a Wi-Fi client through the heqk AP (NAT + IDS + Shield on the
# path), from the bench Pi's AP-side interface. Reports each run and the median; FAIL below the floor.
#   tools/diagnostics/cm5-throughput-check.sh [pi] [iface|auto] [floor-mbps] [runs]
# Baseline 2026-11-09 (cd624beb, bench Pi USB Wi-Fi): 73 / 120 / 135 Mbps, median 120.
set -u -o pipefail
PI="${1:-claude@10.200.0.4}"; IF="${2:-auto}"; FLOOR="${3:-60}"; RUNS="${4:-5}"
# The bench file server on the WAN VLAN (fortress-vlan-bench.sh setup starts it): deterministic, no internet
# rate limit (speed.cloudflare.com answered 403 after repeated runs, 2026-11-10). Override with HQ_SINK_URL.
URL="${HQ_SINK_URL:-http://10.100.0.1:8088/blob}"
"$(dirname "$0")/pi-ensure-ap.sh" "$PI" >/dev/null 2>&1 || true   # on the built-in radio, not the USB dongle
# auto: the Pi interface that routes to the AP (it may re-join on either adapter after a power cycle)
[ "$IF" = auto ] && for _ in $(seq 1 30); do IF=$(ssh -o BatchMode=yes -o ConnectTimeout=8 "$PI" "ip -4 route get 10.99.0.1 | sed -n 's/.* dev \\([^ ]*\\).*/\\1/p'" 2>/dev/null); [ -n "$IF" ] && [ "$IF" != auto ] && break; IF=auto; sleep 3; done
echo "  client interface: $IF"
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
