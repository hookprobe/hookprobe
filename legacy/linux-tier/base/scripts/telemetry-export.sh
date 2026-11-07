#!/bin/sh
# telemetry-export.sh — sample host metrics → the QSECBIT telemetry stream (ADR 0009 "light up qsecbit").
# One line per tick: `cpu,mem,net,disk,p_attack` — the first four are 0..1 utilization floats; the 5th
# is the tabular-ML attack probability (roadmap C, modules/napse/src/tabular.rs) merged in from NAPSE's
# alert stream (see the "p_attack merge" section below). Comma-separated — exactly the vector qsecbit's
# `main.rs` reads (its optional 5th CSV field). QSECBIT turns this into the composite resilience score
# (the Organism orb). Delta-based for net/disk (rate), so it needs a loop, not a oneshot. Pure /proc —
# no external tools (the p_attack merge below uses only `tail`/`awk`/`date`, already-available POSIX
# tools, same policy).
set -u
OUT="${1:-/var/lib/hookprobe/telemetry}"
INT="${2:-5}"
case "$INT" in ''|*[!0-9]*) INT=5 ;; esac   # positive integer only — else awk div-by-zero / sleep 0 spin
[ "$INT" -ge 1 ] 2>/dev/null || INT=5
# 3rd positional arg: NAPSE's alert stream (modules/napse/units/napse.service's own
# `>> /var/lib/hookprobe/events` redirect — this script does not invent a new path, it reads NAPSE's
# existing, already-wired output).
EVENTS="${3:-/var/lib/hookprobe/events}"
CORES="$(nproc 2>/dev/null || echo 1)"
mkdir -p "$(dirname "$OUT")" 2>/dev/null || true
pn=0; pd=0
while :; do
  # CPU: 1-min loadavg / cores, clamped to 1.0
  cpu="$(awk -v c="$CORES" '{v=$1/c; printf "%.4f", (v>1)?1:v}' /proc/loadavg)"
  # MEM: 1 - MemAvailable/MemTotal
  mem="$(awk '/^MemTotal/{t=$2} /^MemAvailable/{a=$2} END{if(t>0)printf "%.4f", 1-a/t; else print "0"}' /proc/meminfo)"
  # NET: total rx+tx bytes across ifaces, rate normalized to 100 MB/s
  n="$(awk 'NR>2{s+=$2+$10} END{print s+0}' /proc/net/dev)"; dn=$((n - pn)); pn="$n"
  net="$(awk -v d="$dn" -v i="$INT" 'BEGIN{v=d/i/1e8; printf "%.4f", (v>1)?1:((v<0)?0:v)}')"
  # DISK: total read+write completed I/Os, rate normalized to 1000 iops
  dd="$(awk '{s+=$4+$8} END{print s+0}' /proc/diskstats)"; dio=$((dd - pd)); pd="$dd"
  disk="$(awk -v d="$dio" -v i="$INT" 'BEGIN{v=d/i/1e3; printf "%.4f", (v>1)?1:((v<0)?0:v)}')"

  # p_attack merge (roadmap C — tabular-ML seam, closes audit GAP-2/GAP-4 minimally): read the most
  # recent `p_attack` value NAPSE wrote into its alert stream (modules/napse/src/lib.rs's
  # `NapseAlert.p_attack`, computed via `tabular::p_attack_for_qsecbit` and already `0.0` whenever
  # `ml_cpu` isn't granted — the gate is enforced upstream, not here).
  #
  # HONEST WINDOWING NOTE: NAPSE only appends a line PER ALERT (event-driven), not once per this
  # script's continuous 5 s tick — there is no design in ADR 0014/base-tier-build-ticket.md Phase 4
  # for a windowing/decay policy bridging that cadence mismatch (the same documented gap
  # `modules/dga-lm/src/lib.rs`'s "QSECBIT connector" doc block calls out on the dga-lm side). This
  # script's deliberate, minimal choice: read the newest alert's `p_attack` and trust it only if that
  # alert is fresh (within the last 2 ticks, i.e. `2*INT` seconds) — an older alert's score is NOT
  # replayed forever; it decays to the neutral `0.0` default instead. A real windowed/EWMA `p_attack`
  # across recent alerts is future work, not implemented here.
  p_attack="0.0000"
  if [ -r "$EVENTS" ]; then
    p_attack="$(tail -n 25 "$EVENTS" 2>/dev/null | awk -v now="$(date +%s)" -v win="$((INT * 2))" '
      {
        ts = ""; pa = "";
        if (match($0, /"ts":[0-9.]+/))       { ts = substr($0, RSTART + 5, RLENGTH - 5) }
        if (match($0, /"p_attack":[0-9.]+/)) { pa = substr($0, RSTART + 11, RLENGTH - 11) }
        if (ts != "" && pa != "") { last_ts = ts; last_pa = pa }
      }
      END {
        if (last_pa != "" && (now - last_ts) <= win && (now - last_ts) >= -2) {
          printf "%.4f", last_pa
        } else {
          print "0.0000"
        }
      }
    ')"
    # Defensive: a truncated tick (empty awk output on a read/race error) must never blank the field.
    [ -n "$p_attack" ] || p_attack="0.0000"
  fi

  echo "$cpu,$mem,$net,$disk,$p_attack" >> "$OUT"
  sleep "$INT"
done
