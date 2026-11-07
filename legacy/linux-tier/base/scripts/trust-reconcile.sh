#!/usr/bin/env bash
# =============================================================================
# trust-reconcile.sh — one continuous-trust cycle (run from a systemd timer).
# =============================================================================
# Reads the live detection plane (arp-status + blocked_macs), computes the trust
# decisions, and CONVERGES the OVS quarantine overrides: it adds a priority-250
# dl_src→quarantine-VLAN flow for newly-flagged devices and DELETES the override for
# any device whose posture has cleared (auto-revert). The quarantined set is persisted
# in a state file so each cycle is a diff against the last.
#
# Idempotent + safe: applies only the generated `ovs-ofctl add-flow/del-flows` lines;
# never touches forwarding bridges or ports. `--check` prints the plan, changes nothing.
# Gated by the `openvswitch` capability (quarantine override needs OpenFlow).
# =============================================================================
set -euo pipefail
SUP=${SUPERVISOR:-/usr/bin/hookprobe-supervisor}
MANIFEST=${MANIFEST:-/var/lib/hookprobe/manifest.json}
ARP=${ARP:-/var/lib/hookprobe/arp-status.json}
BLOCKED=${BLOCKED:-/var/lib/hookprobe/blocked_macs.json}
# ADR 0023 task #19 / ADR 0027 Layer-1: HYDRA's corroboration-gated intel verdicts (produced by
# hookprobe-hydra.service — see that unit's --verdicts-out). Optional/absent (e.g. before HYDRA's
# first run) — the supervisor treats a missing file as zero intel signals, never an error.
HYDRA_VERDICTS=${HYDRA_VERDICTS:-/var/lib/hookprobe/hydra-verdicts}
STATE=${STATE:-/var/lib/hookprobe/quarantined.json}
BRIDGE=${BRIDGE:-hp-br0}
PLAN=0; [ "${1:-}" = "--check" ] && PLAN=1
log() { echo "trust-reconcile: $*" >&2; }

granted() { [ "$(jq -r --arg t "$1" '.capabilities[$t].state // "absent"' "$MANIFEST" 2>/dev/null)" = "granted" ]; }
granted openvswitch || { log "openvswitch not granted → no OVS quarantine overrides; skipping"; exit 0; }

[ -f "$ARP" ] || { log "no arp-status ($ARP) yet — nothing to evaluate"; exit 0; }
args=( "$MANIFEST" --arp "$ARP" --bridge "$BRIDGE" --quarantine-state "$STATE" )
[ -f "$BLOCKED" ] && args+=( --blocked "$BLOCKED" )
[ -f "$HYDRA_VERDICTS" ] && args+=( --hydra-verdicts "$HYDRA_VERDICTS" )

# The supervisor prints the runnable `ovs-ofctl add-flow/del-flows` lines and rewrites
# the state file. We execute only those lines (comments are ignored by the shell).
plan="$("$SUP" "${args[@]}" 2>/dev/null | grep -E '^ovs-ofctl ' || true)"

if [ "$PLAN" = 1 ]; then
  log "PLAN (no changes):"
  [ -n "$plan" ] && printf '%s\n' "$plan" || log "  (no quarantine changes this cycle)"
  exit 0
fi

if [ -z "$plan" ]; then
  log "no quarantine changes this cycle"
  exit 0
fi
# SECURITY: never `eval` the supervisor output. Each line must match a STRICT allowlist
# (ovs-ofctl add-flow|del-flows <bridge> priority=250,dl_src=<mac>,…), then we word-split
# into argv and exec ovs-ofctl directly — no shell metacharacters can reach a shell.
flow_re='^ovs-ofctl (add-flow|del-flows) [A-Za-z0-9_-]+ priority=250,dl_src=[0-9a-fA-F:]{17}(,actions=mod_vlan_vid:[0-9]+,normal)?$'
while IFS= read -r cmd; do
  [ -n "$cmd" ] || continue
  if [[ ! "$cmd" =~ $flow_re ]]; then
    log "  REFUSED (not an allowlisted ovs-ofctl flow command): $cmd"
    continue
  fi
  read -r -a argv <<< "$cmd"     # safe: flowspec has no spaces → one argv element
  log "applying: ${argv[*]}"
  "${argv[@]}" || log "  WARNING: command failed (continuing): ${argv[*]}"
done <<< "$plan"
log "cycle complete"
