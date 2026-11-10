#!/usr/bin/env bash
# cm5-dns-under-load — release gate NET-01: DNS through the heqk AP keeps working while a client saturates the
# Wi-Fi downlink (soak 2026-11-10: heqk lost 3/40 and p90 was 2.0 s under a download; fix = AP TX priority).
#   1. the bench Pi starts a continuous download from the local WAN-side sink (HQ_SINK_URL) on its AP interface;
#   2. 40 queries to the AP's DNS (10.99.0.1), one a second, each up to 10 s, unique names (no cache hits) mixed
#      with a cached one; the answer time of each is recorded;
#   3. acceptance (operator decision 2026-11-10): no worse than the path baseline — the same queries to a public
#      resolver through the same AP, same load, same run (lost <= baseline lost) — AND p90 < 500 ms. Also printed: the same 40 queries to 1.1.1.1 through the same AP
#      (the path baseline) and the device's prio counters from the serial heartbeat.
#   tools/diagnostics/cm5-dns-under-load.sh <serial-log> [pi]
set -u -o pipefail
LOG="${1:?serial log}"; PI="${2:-claude@10.200.0.4}"; HERE=$(cd "$(dirname "$0")" && pwd)
SINK="${HQ_SINK_URL:-http://10.100.0.1:8088/blob}"
pi() { ssh -o BatchMode=yes -o ConnectTimeout=8 "$PI" "$@"; }
"$HERE/pi-ensure-ap.sh" "$PI" >/dev/null 2>&1
IF=$(pi "ip -4 route get 10.99.0.1 | sed -n 's/.* dev \([^ ]*\).*/\1/p'")
probe() {   # -> 40 lines "<heqk ms|LOST> <baseline ms|LOST>": both resolvers each second, alternating which goes first,
            # so the two series see the same load at the same moments (the old back-to-back series did not)
  pi "for i in \$(seq 1 40); do n=\$( [ \$((i % 4)) = 0 ] && echo example.com || echo hq\$i-\$RANDOM.example.org ); \
      q() { t=\$(dig +time=10 +tries=1 @\$1 \$2 A 2>/dev/null | sed -n 's/^;; Query time: \\([0-9]*\\) msec.*/\\1/p'); echo \${t:-LOST}; }; \
      if [ \$((i % 2)) = 0 ]; then a=\$(q 10.99.0.1 \$n); b=\$(q 1.1.1.1 b\$n); else b=\$(q 1.1.1.1 b\$n); a=\$(q 10.99.0.1 \$n); fi; \
      echo \$a \$b; sleep 1; done"
}
stats() { awk '$1=="LOST"{l++; next} {a[n++]=$1} END{asort(a); p=a[int(n*0.9+0.5)]; if (n==0) p=99999; printf "%d %d %d\n", l+0, p+0, a[n]}' ; }
pi "nohup bash -c 'end=\$((SECONDS+300)); while [ \$SECONDS -lt \$end ]; do curl --interface $IF -s -o /dev/null -m 30 $SINK; done' >/dev/null 2>&1 &"
sleep 5
P=$(probe)
read -r lost p90 max < <(awk '{print $1}' <<<"$P" | stats)
read -r blost bp90 bmax < <(awk '{print $2}' <<<"$P" | stats)
pi "pkill -f 'curl --interface $IF -s -o /dev/null -m 30'" >/dev/null 2>&1 || true
echo "  heqk DNS (10.99.0.1) under load: lost $lost/40, p90 ${p90} ms, max ${max} ms"
echo "  path baseline (1.1.1.1 via the AP): lost $blost/40, p90 ${bp90} ms, max ${bmax} ms"
tail -c 300000 "$LOG" | tr -d '\r\000' | grep -a "P11-AP3 beat" | tail -1 | grep -o "prio direct=[0-9]* queued=[0-9]* dropped=[0-9]*" | sed 's/^/  /'
if [ "$lost" -le "$blost" ] && [ "$p90" -lt 500 ]; then echo "DNS-UNDER-LOAD: PASS (lost $lost <= baseline $blost, p90 ${p90} ms < 500)"; exit 0; fi
echo "DNS-UNDER-LOAD: FAIL (lost $lost vs baseline $blost, p90 ${p90} ms; need lost <= baseline and p90 < 500)"; exit 1
