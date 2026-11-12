#!/usr/bin/env bash
# home-capture — DET-01 household benign corpus (operator decision 2026-11-12: home LAN mirror via fortress,
# METADATA ONLY, stored locally on fortress001, never uploaded).
#   SUDO_PASS_FILE=<0600 file> tools/detbench/home-capture.sh <hours> [iface=FTS-mirror] [dir=~/heqk-corpus/home]
# One stripped pcap per hour: tcpdump streams into hdrstrip.py, which keeps headers only and zeroes every payload byte
# BEFORE anything reaches the disk. The directory is 0700. Nothing here sends data anywhere.
# Then: gunzip -k <hour>.pcap.gz ; tools/detbench/pcap2hqdb.py CORPUS.img benign:<hour>.pcap [attack:...] ; tools/detbench/run.sh CORPUS.img REPORT.md
set -u -o pipefail
H="${1:?hours}"; IF="${2:-FTS-mirror}"; D="${3:-$HOME/heqk-corpus/home}"
HERE=$(cd "$(dirname "$0")" && pwd)
[ -n "${SUDO_PASS_FILE:-}" ] && [ -f "$SUDO_PASS_FILE" ] || { echo "SUDO_PASS_FILE (0600) required: tcpdump needs root"; exit 2; }
ip link show "$IF" >/dev/null 2>&1 || { echo "no interface $IF"; exit 2; }
umask 077; mkdir -p "$D"; chmod 700 "$D"
echo "== DET-01 capture: $H h on $IF -> $D (headers only)"
for h in $(seq 1 "$H"); do
  out="$D/home-$(date +%Y%m%d-%H%M).pcap"
  # -s 160 is enough for every header hdrstrip keeps (Ethernet + 2 tags + IPv6 + ext headers + TCP options)
  sudo -S -p '' timeout 3600 tcpdump -i "$IF" -nn -s 160 -U -w - < "$SUDO_PASS_FILE" 2>/dev/null | python3 -I "$HERE/hdrstrip.py" "$out"
  gzip -1 "$out"   # the zero-padded payload compresses ~20x; gunzip before pcap2hqdb.py
  echo "   hour $h: $out.gz ($(stat -c %s "$out.gz") B)"
done
echo "== done: $(ls "$D"/home-*.pcap.gz | wc -l) file(s) in $D"
