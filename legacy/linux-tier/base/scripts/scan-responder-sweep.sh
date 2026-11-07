#!/bin/sh
# =============================================================================
# scan-responder-sweep.sh — one continuous-trust-style TTL sweep for the scan-responder's nft
# quarantine (timer-driven, run from hookprobe-scan-responder-sweep.timer).
# =============================================================================
# scan-responder.sh's tail loop only re-evaluates TTL when a NEW alert line arrives — a scanner
# that goes quiet would never be released without this. This sweep reads the SAME state file,
# releases anything quiet for QUARANTINE_TTL_SECS (identical expiry logic — see
# `scan_responder::sweep_quarantine` in hookprobe-manifest), and appends a `revert` response line
# per release. Idempotent: a cycle with nothing expired prints/does nothing.
# =============================================================================
set -eu
SUP=${SUPERVISOR:-/usr/lib/hookprobe/hookprobe-supervisor}
MANIFEST=${MANIFEST:-/var/lib/hookprobe/manifest.json}
RESPONSES=${RESPONSES:-/var/lib/hookprobe/responses}
STATE=${QUARANTINE_STATE_FILE:-/var/lib/hookprobe/scan-quarantine.json}
TTL=${QUARANTINE_TTL_SECS:-300}
LAN_IFACE=${LAN_IFACE:-wlan0}
WAN_IFACE=${WAN_IFACE:-end0}
APPLY=${SCAN_RESPOND_APPLY:-0}
ALLOW_UNSIGNED=${ALLOW_UNSIGNED:-0}

[ -f "$STATE" ] || exit 0   # nothing has ever been quarantined yet — nothing to sweep

args="$MANIFEST --scan-respond-sweep --quarantine-ttl-secs $TTL --quarantine-state-file $STATE --lan-iface $LAN_IFACE --wan-iface $WAN_IFACE"
[ "$APPLY" = "1" ] && args="$args --apply"
[ "$ALLOW_UNSIGNED" = "1" ] && args="$args --allow-unsigned"

# shellcheck disable=SC2086
"$SUP" $args >> "$RESPONSES"
