#!/usr/bin/env bash
# netns-e2e.sh — the REAL I/O path, unprivileged: a private user+network namespace (unshare -Urn)
# gives CAP_NET_ADMIN for a real TUN without touching the host. A device simulator completes the
# PQ-hybrid handshake over real UDP, gets an address, and pings a local address THROUGH the tunnel;
# the namespace's kernel answers, the PoP reads the reply from the TUN and seals it back.
#   tests/netns-e2e.sh [path/to/superpop]
set -euo pipefail
HERE=$(cd "$(dirname "$0")/.." && pwd)
BIN="${1:-$HERE/target/release/superpop}"
[ -x "$BIN" ] || { echo "build first: cargo build --release" >&2; exit 2; }
W=$(mktemp -d); trap 'rm -rf "$W"' EXIT

"$BIN" keygen --key-file "$W/pop.key" > "$W/pub.txt"
PUB=$(tail -1 "$W/pub.txt")
PK=$("$BIN" devsim --seed netns-test-device --print-pk)
printf 'netns-dev %s 100.64.0.2\n' "$PK" > "$W/devices"

unshare -Urn bash -s "$BIN" "$W" "$PUB" <<'NS'
set -euo pipefail
BIN=$1; W=$2; PUB=$3
ip link set lo up
ip addr add 192.0.2.1/32 dev lo            # the "internet host" the device pings
"$BIN" run --key-file "$W/pop.key" --devices "$W/devices" --bind 127.0.0.1 --tun hqpop0 --tenant 54454e41 > "$W/pop.log" 2>&1 &
POP=$!
for _ in $(seq 50); do ip link show hqpop0 >/dev/null 2>&1 && break; sleep 0.1; done
ip addr add 100.64.0.1/10 dev hqpop0
ip link set hqpop0 mtu 1380 up
rc=0
"$BIN" devsim --seed netns-test-device --pop 127.0.0.1 --pop-pub "$PUB" --ping 192.0.2.1 || rc=$?
# A device NOT on the allowlist must get no session.
if "$BIN" devsim --seed netns-rogue --pop 127.0.0.1 --pop-pub "$PUB" --ping 192.0.2.1 >"$W/rogue.log" 2>&1; then
  echo "FAIL: a rogue device got through"; rc=1
else
  echo "rogue device refused: $(tail -1 "$W/rogue.log")"
fi
kill $POP 2>/dev/null || true
[ $rc -eq 0 ] || { echo "--- PoP log ---"; cat "$W/pop.log"; }
exit $rc
NS
echo "netns-e2e: PASS"
