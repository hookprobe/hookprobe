#!/bin/sh
# =============================================================================
# resource-shed-reconcile.sh — AEGIS reflex for RESOURCE-REALITY enforcement (2026-07-07).
# =============================================================================
# Timer-driven (hookprobe-resource-shed.timer), NOT alert-driven — there is no NAPSE detection
# stream to tail here: this reflex reacts to the box's OWN measured resource facts (conntrack
# table fill, /proc/pressure CPU+memory stall fractions), never a signature/identity verdict.
# Every cycle it:
#   1. Re-applies Layer 1's blanket, always-on per-source new-connection-rate cap (idempotent nft
#      bootstrap — safe every cycle; a legitimate source never approaches this ceiling).
#   2. Re-samples conntrack fill + PSI pressure and decides Layer 2/3's shed triggers
#      (hookprobe_manifest::scan_responder::evaluate_resource_reality) — either signal firing caps
#      the highest-volume source(s) via the SAME dynamic `shed_ips` nft set, self-reverting via TTL.
#   3. Appends a first-class response/revert JSON line per shed action to RESPONSES for
#      `hookprobe-evidence --responses` to ingest, exactly like scan-responder.sh's own records.
#
# SAFETY: nft commands are only EXECUTED when RESOURCE_SHED_APPLY=1 (default: print-only to
# stderr) — mirrors trust-reconcile.sh's/scan-responder.sh's never-`eval`, plan-first discipline.
# Keys ONLY on resource-reality signals (pps / conntrack-fill / PSI avg60) — NEVER on identity;
# see hookprobe_manifest::scan_responder's "RESOURCE-REALITY ENFORCEMENT" module doc.
# =============================================================================
set -eu
SUP=${SUPERVISOR:-/usr/lib/hookprobe/hookprobe-supervisor}
MANIFEST=${MANIFEST:-/var/lib/hookprobe/manifest.json}
RESPONSES=${RESPONSES:-/var/lib/hookprobe/responses}
STATE=${RESOURCE_SHED_STATE_FILE:-/var/lib/hookprobe/resource-shed.json}
TTL=${RESOURCE_SHED_TTL_SECS:-60}
LAN_IFACE=${LAN_IFACE:-wlan0}
WAN_IFACE=${WAN_IFACE:-end0}
NEW_CONN_PPS=${RESOURCE_SHED_NEW_CONN_PPS:-}
SHED_CAP_PPS=${RESOURCE_SHED_CAP_PPS:-}
CONNTRACK_SATURATION_PCT=${RESOURCE_SHED_CONNTRACK_SATURATION_PCT:-}
TOP_TALKER_MIN_ENTRIES=${RESOURCE_SHED_TOP_TALKER_MIN_ENTRIES:-}
CPU_AVG60_PCT=${RESOURCE_SHED_CPU_AVG60_PCT:-}
MEM_AVG60_PCT=${RESOURCE_SHED_MEM_AVG60_PCT:-}
APPLY=${RESOURCE_SHED_APPLY:-0}          # 1 = actually run nft; 0 = plan-only (safe default)
ALLOW_UNSIGNED=${ALLOW_UNSIGNED:-0}      # DEV ONLY — the shipping manifest is cosign-signed

args="$MANIFEST --resource-shed-reconcile --resource-shed-state-file $STATE --resource-shed-ttl-secs $TTL --lan-iface $LAN_IFACE --wan-iface $WAN_IFACE"
[ -n "$NEW_CONN_PPS" ] && args="$args --new-conn-pps $NEW_CONN_PPS"
[ -n "$SHED_CAP_PPS" ] && args="$args --shed-cap-pps $SHED_CAP_PPS"
[ -n "$CONNTRACK_SATURATION_PCT" ] && args="$args --conntrack-saturation-pct $CONNTRACK_SATURATION_PCT"
[ -n "$TOP_TALKER_MIN_ENTRIES" ] && args="$args --top-talker-min-entries $TOP_TALKER_MIN_ENTRIES"
[ -n "$CPU_AVG60_PCT" ] && args="$args --cpu-pressure-avg60-pct $CPU_AVG60_PCT"
[ -n "$MEM_AVG60_PCT" ] && args="$args --mem-pressure-avg60-pct $MEM_AVG60_PCT"
[ "$APPLY" = "1" ] && args="$args --apply"
[ "$ALLOW_UNSIGNED" = "1" ] && args="$args --allow-unsigned"

# shellcheck disable=SC2086 # $args is intentionally word-split — no argument value has spaces
"$SUP" $args >> "$RESPONSES"
