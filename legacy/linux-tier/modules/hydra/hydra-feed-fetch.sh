#!/usr/bin/env bash
# hydra-feed-fetch — download the threat-intel CIDR feeds HYDRA drops on (V1 feed set). Writes one
# file per feed to FEEDS_DIR; hydra-feedsync parses them → the BPF blocklist map. Best-effort: a feed
# that 404s/times out is skipped (stale data > no data). No secrets; all public feeds.
set -uo pipefail
FEEDS_DIR=${FEEDS_DIR:-/var/lib/hookprobe/feeds}
mkdir -p "$FEEDS_DIR"
declare -A FEEDS=(
  [spamhaus-drop]="https://www.spamhaus.org/drop/drop.txt"
  [spamhaus-edrop]="https://www.spamhaus.org/drop/edrop.txt"
  [firehol-level1]="https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset"
  [emerging-threats]="https://rules.emergingthreats.net/blockrules/compromised-ips.txt"
  [feodo]="https://feodotracker.abuse.ch/downloads/ipblocklist.txt"
  [sslbl]="https://sslbl.abuse.ch/blacklist/sslipblocklist.txt"
)
n=0
for name in "${!FEEDS[@]}"; do
  if curl -fsS --max-time 20 -o "$FEEDS_DIR/$name.txt.new" "${FEEDS[$name]}" 2>/dev/null; then
    mv -f "$FEEDS_DIR/$name.txt.new" "$FEEDS_DIR/$name.txt"; n=$((n+1))
  else
    rm -f "$FEEDS_DIR/$name.txt.new"
    echo "hydra-feed-fetch: $name unavailable (keeping any prior copy)" >&2
  fi
done
echo "hydra-feed-fetch: refreshed $n/${#FEEDS[@]} feeds → $FEEDS_DIR" >&2
