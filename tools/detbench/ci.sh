#!/usr/bin/env bash
# detbench/ci.sh — detection regression gate (readiness 4.1): the deterministic synthetic attack corpus must
# be fully detected (incl. the evasive slow / jittered variants), without alert storms. Fails if any class gets no alert, or one rule raises > 30 alerts in one class.
set -u -o pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
D=$(mktemp -d); trap 'rm -rf "$D"' EXIT
python3 -I "$HERE/gen-attacks.py" "$D" >/dev/null
L=""
for c in dga portscan c2port ssh_brute beacon arp_spoof exfil lateral; do L="$L $c:$D/$c.pcap"; done
python3 -I "$HERE/gen-attacks.py" "$D/ev" --evasive >/dev/null
for c in slowscan jitterbeacon slowexfil dnstunnel slowbrute; do L="$L $c:$D/ev/$c.pcap"; done
python3 -I "$HERE/pcap2hqdb.py" "$D/attacks.img" --stagger 7200 $L >/dev/null
bash "$HERE/run.sh" "$D/attacks.img" "$D/report.md" > "$D/out" 2>&1 || { cat "$D/out"; exit 1; }
cat "$D/report.md"
python3 - "$D/report.md" <<'PY'
import re, sys
t = open(sys.argv[1]).read()
rows = [l for l in t.splitlines() if l.startswith("| ") and re.match(r"\| \d+ ", l)]
hdr = [l for l in t.splitlines() if l.startswith("| rule |")][0].strip("|").split("|")
labels = [h.strip() for h in hdr[1:]]
tot = {l: 0 for l in labels}
storms = []
for r in rows:
    cells = [x.strip() for x in r.strip().strip("|").split("|")]
    for l, v in zip(labels, cells[1:]):
        tot[l] += int(v)
        if int(v) > 30:  # one rule, one episode: the 60 s de-dup allows ~1/min, episodes run <= 2 h with gaps
            storms.append(f"{l}: {v} x '{cells[0]}' (storm)")
bad = [f"{l}: no alert" for l in labels if l != "dga" and tot[l] == 0] + storms
if tot.get("dga", 0) == 0:
    bad.append("dga: no alert")
print("DETBENCH-CI:", "FAIL — " + "; ".join(bad) if bad else "PASS — every attack class detected, no alert storm")
sys.exit(1 if bad else 0)
PY
