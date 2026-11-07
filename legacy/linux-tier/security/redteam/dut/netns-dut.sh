#!/usr/bin/env bash
# =============================================================================
# security/redteam/dut/netns-dut.sh — stands up a network-namespaced clone running HookProbe's REAL
# detection stack (napse-dpi capture -- the same binary `modules/napse-capture/loader` ships,
# already wired with the ADR 0020 Phase-1a defensive L1/L2 detectors: mac-flood, ARP guard,
# broadcast-storm, malformed-frame, plus the L4 port-scan + handshake-confirmation trackers),
# connected to the host by ONE veth pair -- so DESTRUCTIVE L1/L2 floods and L3/L4 probes run here,
# isolated, NEVER on a shared/mgmt segment (ADR 0020 D3 condition 6, the single largest residual
# risk the threat-model sign-off called out).
#
# This is the "safe DUT" the offensive probes (security/redteam/probes/) target -- it is NOT a
# shipped artifact (ADR 0020 D2: security/redteam/ never ships in an image) and it NEVER touches a
# real host interface (end0/wlan0/wan*/the mgmt path). Every command below operates ONLY on the
# `hookprobe-dut` netns and the `veth-dut`/`veth-dut-peer` pair it creates.
#
# Needs CAP_NET_ADMIN (root) to create the netns/veth pair, and CAP_NET_RAW inside the netns for
# napse-dpi's AF_PACKET socket. Both are SKIP-with-reason, never faked, when unavailable (see
# `builder/gate-ladder.sh`'s Gate R, which calls this script and honestly SKIPs if `id -u` != 0 and
# no working `sudo -n`).
#
# Usage:
#   netns-dut.sh up      [--events PATH] [--flows PATH]   # create netns+veth, start napse-dpi
#   netns-dut.sh status                                    # show link/route state (topology proof)
#   netns-dut.sh down                                      # stop napse-dpi, tear down netns+veth
# =============================================================================
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"

NETNS="${REDTEAM_DUT_NETNS:-hookprobe-dut}"
VETH_HOST="${REDTEAM_DUT_VETH_HOST:-veth-dut}"
VETH_PEER="${REDTEAM_DUT_VETH_PEER:-veth-dut-peer}"
HOST_CIDR="10.99.0.1/24"
DUT_CIDR="10.99.0.2/24"
MANIFEST="$HERE/manifest.dut.json"
PIDFILE="/run/redteam/napse-dpi.pid"
DEFAULT_EVENTS="/tmp/redteam-dut-events.jsonl"
DEFAULT_FLOWS="/tmp/redteam-dut-flows.jsonl"

# Locate the napse-dpi binary this repo already builds (debug preferred for a dev-box campaign;
# release if that's what's been built). Never falls back to fabricating a result if absent --
# `up` SKIPs starting napse-dpi (and says so loudly) so a benign netns-only topology test can still
# run without a built binary.
find_napse_dpi() {
  local repo
  repo="$(cd "$HERE/../../.." && pwd)"
  for c in "$repo/target/release/napse-dpi" "$repo/target/debug/napse-dpi"; do
    if [ -x "$c" ]; then echo "$c"; return 0; fi
  done
  return 1
}

need_root() {
  if [ "$(id -u)" -eq 0 ]; then return 0; fi
  if sudo -n true 2>/dev/null; then return 0; fi
  echo "netns-dut.sh: needs root/CAP_NET_ADMIN (id -u != 0 and no passwordless sudo) -- SKIP-with-reason, not faked" >&2
  return 1
}

as_root() {
  if [ "$(id -u)" -eq 0 ]; then "$@"; else sudo -n "$@"; fi
}

cmd_up() {
  local events="$DEFAULT_EVENTS" flows="$DEFAULT_FLOWS"
  while [ $# -gt 0 ]; do case "$1" in
    --events) events="$2"; shift 2;;
    --flows)  flows="$2"; shift 2;;
    *) echo "unknown arg: $1" >&2; exit 2;;
  esac; done

  need_root || exit 3

  if as_root ip netns list 2>/dev/null | awk '{print $1}' | grep -qx "$NETNS"; then
    echo "netns-dut.sh: netns $NETNS already exists -- reusing (run 'down' first for a clean slate)"
  else
    as_root ip netns add "$NETNS"
    echo "netns-dut.sh: created netns $NETNS"
  fi

  if ! as_root ip link show "$VETH_HOST" >/dev/null 2>&1; then
    as_root ip link add "$VETH_HOST" type veth peer name "$VETH_PEER"
    as_root ip link set "$VETH_PEER" netns "$NETNS"
    echo "netns-dut.sh: created veth pair $VETH_HOST <-> $VETH_PEER (peer moved into $NETNS)"
  else
    echo "netns-dut.sh: $VETH_HOST already exists -- reusing"
  fi

  as_root ip addr replace "$HOST_CIDR" dev "$VETH_HOST" 2>/dev/null || true
  as_root ip link set "$VETH_HOST" up
  as_root ip netns exec "$NETNS" ip addr replace "$DUT_CIDR" dev "$VETH_PEER" 2>/dev/null || true
  as_root ip netns exec "$NETNS" ip link set "$VETH_PEER" up
  as_root ip netns exec "$NETNS" ip link set lo up

  # DELIBERATELY no default route / no other route added inside $NETNS -- ADR 0020 D3 condition 2
  # requires the DUT netns to have no route off its own veth. Verify this holds (belt-and-braces,
  # the same check target_guard::topology::assert_l2_veth_topology performs independently):
  if as_root ip netns exec "$NETNS" ip route show default 2>/dev/null | grep -q default; then
    echo "netns-dut.sh: WARNING -- $NETNS unexpectedly has a default route (condition 2 violated); tearing down" >&2
    cmd_down
    exit 4
  fi

  local napse_dpi
  if napse_dpi="$(find_napse_dpi)"; then
    as_root mkdir -p "$(dirname "$PIDFILE")" "$(dirname "$events")" "$(dirname "$flows")"
    as_root rm -f "$events" "$flows"
    echo "netns-dut.sh: starting REAL napse-dpi ($napse_dpi) inside $NETNS on $VETH_PEER"
    as_root env MANIFEST="$MANIFEST" MIRROR_IFACE="$VETH_PEER" EVENTS="$events" FLOWS="$flows" \
      ip netns exec "$NETNS" "$napse_dpi" >/tmp/redteam-dut-napse-dpi.log 2>&1 &
    local pid=$!
    disown "$pid" 2>/dev/null || true
    as_root sh -c "echo $pid > '$PIDFILE'"
    sleep 0.3
    if as_root kill -0 "$pid" 2>/dev/null; then
      echo "netns-dut.sh: napse-dpi running (pid $pid); events -> $events"
    else
      echo "netns-dut.sh: napse-dpi exited immediately -- see /tmp/redteam-dut-napse-dpi.log (likely missing CAP_NET_RAW or manifest 'capture' not granted)" >&2
    fi
  else
    echo "netns-dut.sh: napse-dpi binary not built (target/{debug,release}/napse-dpi absent) -- topology-only DUT, no live detector. Build it first: cargo build -p napse-loader --bin napse-dpi --features bpf (or without --features bpf for the non-BPF parts)"
  fi

  echo "netns-dut.sh: DUT is up. iface=$VETH_HOST netns=$NETNS peer=$VETH_PEER events=$events flows=$flows"
}

cmd_status() {
  echo "=== $VETH_HOST (host side) ==="
  ip -d link show "$VETH_HOST" 2>&1 || echo "(absent)"
  echo "=== $NETNS netns links ==="
  as_root ip netns exec "$NETNS" ip -d link show 2>&1 || echo "(netns absent)"
  echo "=== $NETNS netns routes (MUST be empty of any 'default') ==="
  as_root ip netns exec "$NETNS" ip route show 2>&1 || true
  if [ -f "$PIDFILE" ]; then
    local pid; pid="$(cat "$PIDFILE" 2>/dev/null || true)"
    if [ -n "$pid" ] && as_root kill -0 "$pid" 2>/dev/null; then
      echo "napse-dpi: running (pid $pid)"
    else
      echo "napse-dpi: not running"
    fi
  else
    echo "napse-dpi: never started"
  fi
}

cmd_down() {
  if [ -f "$PIDFILE" ]; then
    local pid; pid="$(cat "$PIDFILE" 2>/dev/null || true)"
    [ -n "$pid" ] && as_root kill "$pid" 2>/dev/null || true
    as_root rm -f "$PIDFILE"
  fi
  as_root ip link del "$VETH_HOST" 2>/dev/null || true
  as_root ip netns del "$NETNS" 2>/dev/null || true
  echo "netns-dut.sh: torn down ($VETH_HOST/$VETH_PEER/$NETNS removed)"
}

case "${1:-}" in
  up)     shift; cmd_up "$@";;
  status) cmd_status;;
  down)   cmd_down;;
  *) echo "usage: $0 {up [--events PATH] [--flows PATH]|status|down}" >&2; exit 2;;
esac
