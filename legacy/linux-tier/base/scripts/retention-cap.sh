#!/bin/sh
# retention-cap.sh — bound the SOC stream/output files so they can't fill the data partition (core
# invariant: local retention is capped by storage). Runs on a frequent timer. For each file over CAP,
# keep the last KEEP bytes IN PLACE — same inode, so the O_APPEND producers keep writing (no rename,
# which they'd never notice since they don't reopen on SIGHUP).
#
# TRADEOFF (honest): a consumer using `tail -F` re-reads a truncated file from the start. The evidence
# graph is idempotent (host-events re-ingest dedups on the edge PK); engine re-scoring on a cap event
# is a bounded, superseded burst whose output is itself capped here. Caps are large (50 MiB) so this is
# rare. The clean long-term fix is streaming over a message bus / journald (a larger change) — this is
# the storage-safety backstop, and specifically the backstop against an attacker inflating host-events.
set -u
DIR="${HOOKPROBE_DATA_DIR:-/var/lib/hookprobe}"
CAP="${HOOKPROBE_STREAM_CAP:-52428800}"    # 50 MiB — cap a file once it exceeds this
KEEP="${HOOKPROBE_STREAM_KEEP:-26214400}"  # 25 MiB — bytes to retain after a cap

for f in telemetry host-events flows events qsecbit-scores dns-verdicts aegis-verdicts responses; do
  p="$DIR/$f"
  [ -f "$p" ] || continue
  sz="$(stat -c %s "$p" 2>/dev/null || echo 0)"
  [ "$sz" -gt "$CAP" ] 2>/dev/null || continue
  # keep the last KEEP bytes; truncate IN PLACE (O_TRUNC on the same inode, not a rename). The first
  # retained line may be partial — the lossy/skip ingest + engine parsers drop it.
  if tail -c "$KEEP" "$p" > "$p.cap" 2>/dev/null; then
    cat "$p.cap" > "$p" 2>/dev/null || true
    rm -f "$p.cap"
  fi
done
