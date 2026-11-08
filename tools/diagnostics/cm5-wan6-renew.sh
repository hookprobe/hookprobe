#!/usr/bin/env bash
# cm5-wan6-renew — G17.4: the delegated prefix is RENEWED at T1 on an Ethernet WAN (bench with V6_FAST=1:
# T1 = 60 s). Waits for the [P11-AP3 v6] beat line to show `pd renew ... ok=` rising after a boot.
#   tools/diagnostics/cm5-wan6-renew.sh --log SERIAL.log --since BYTES [--wait 200]
set -u -o pipefail
LOG=""; SINCE=0; WAIT=200
while [ $# -gt 0 ]; do case "$1" in --log) LOG="$2"; shift ;; --since) SINCE="$2"; shift ;; --wait) WAIT="$2"; shift ;; *) exit 2 ;; esac; shift; done
t0=$(date +%s)
while :; do
  L=$(tail -c +$((SINCE + 1)) "$LOG" | tr -d '\r\000' | grep -aE '\[P11-AP3 v6\] pd renew' | tail -1)
  okn=$(grep -oE 'pd renew tx=[0-9]+ ok=[0-9]+' <<<"$L" | grep -oE 'ok=[0-9]+' | cut -d= -f2)
  [ -n "$okn" ] && [ "$okn" -ge 1 ] && { echo "ok  $(grep -oE 'pd renew tx=[0-9]+ ok=[0-9]+ t1=[0-9]+s' <<<"$L")"; echo "WAN6-RENEW: PASS"; exit 0; }
  [ $(( $(date +%s) - t0 )) -ge "$WAIT" ] && { echo "BAD no renewal in ${WAIT}s: $(grep -oE 'pd renew tx=[0-9]+ ok=[0-9]+ t1=[0-9]+s' <<<"$L")"; echo "WAN6-RENEW: FAIL"; exit 1; }
  sleep 5
done
