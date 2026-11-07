#!/bin/sh
# host-telemetry-export.sh — emit host PROCESS-exec events for the evidence graph's HOST layer (the
# process→spawned_by half of the Threat Graph). Light /proc-polling FALLBACK; the eBPF execsnoop loader
# (modules/host-telemetry) is the production producer (catches every exec, escapes via serde_json).
#
# Honest: /proc polling misses processes shorter-lived than the interval. This script emits ONE JSON
# object per line; comm/cmdline are ATTACKER-SETTABLE (prctl(PR_SET_NAME), argv[0]) so they are strictly
# escaped — a raw newline in a process name must not forge a second telemetry line.
set -u
OUT="${1:-/var/lib/hookprobe/host-events}"
INT="${2:-2}"
SELF="${HOOKPROBE_DEVICE_IP:-127.0.0.1}"
case "$INT" in ''|*[!0-9]*) INT=2 ;; esac   # positive integer only (guards sleep 0 / div-by-zero users)
[ "$INT" -ge 1 ] 2>/dev/null || INT=2
mkdir -p "$(dirname "$OUT")" 2>/dev/null || true

# JSON-escape for a "..." value: escape backslash + quote, then STRIP every control byte (<0x20,
# including newline/tab) — enough to make injection impossible without a full \uXXXX encoder.
json_str() {
  printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g' | tr -d '\000-\037'
}

prev=" "
while :; do
  ts="$(date +%s 2>/dev/null).0"    # one timestamp per TICK (was a fork per process)
  cur=""
  for p in /proc/[0-9]*; do
    pid="${p#/proc/}"
    cur="$cur $pid"
    case "$prev" in *" $pid "*) continue ;; esac      # seen last tick → skip
    name="$(cat "$p/comm" 2>/dev/null)" || continue    # process already gone
    cmd="$(tr '\0' ' ' < "$p/cmdline" 2>/dev/null)"
    # ppid: /proc/PID/stat is `pid (comm) state ppid ...`; comm may contain spaces/parens, so take
    # everything AFTER the last ')' (state ppid ...) and read field 2. Digits-only or fall back to 0.
    ppid="$(sed 's/^.*) //' "$p/stat" 2>/dev/null | cut -d' ' -f2)"
    case "$ppid" in ''|*[!0-9]*) ppid=0 ;; esac
    printf '{"type":"process","ts":%s,"device_ip":"%s","pid":%s,"name":"%s","cmdline":"%s","parent_pid":%s}\n' \
      "$ts" "$SELF" "$pid" "$(json_str "$name")" "$(json_str "$cmd")" "$ppid" >> "$OUT"
  done
  prev="$cur "
  sleep "$INT"
done
