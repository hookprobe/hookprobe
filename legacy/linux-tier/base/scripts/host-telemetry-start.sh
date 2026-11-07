#!/bin/sh
# host-telemetry-start.sh — pick the host-telemetry producer at runtime: the eBPF execsnoop loader
# (production, catches every exec) if the CI-built loader + CO-RE object are present, else the
# /proc-polling fallback (works everywhere, no build). Both emit ingest_host_event JSON → host-events.
V=/var/lib/hookprobe
if [ -x /usr/lib/hookprobe/hookprobe-execsnoop ] && [ -f /usr/lib/hookprobe/bpf/execsnoop.bpf.o ]; then
  exec /usr/lib/hookprobe/hookprobe-execsnoop /usr/lib/hookprobe/bpf/execsnoop.bpf.o >> "$V/host-events"
else
  exec /usr/lib/hookprobe/host-telemetry-export.sh "$V/host-events" 2
fi
