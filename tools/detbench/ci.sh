#!/usr/bin/env bash
# detbench/ci.sh — detection regression gate (readiness 4.1): the deterministic synthetic attack corpus must
# be fully detected, without alert storms. Fails if any class gets no alert, or any class raises > 20 alerts.
set -u -o pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
D=$(mktemp -d); trap 'rm -rf "$D"' EXIT
python3 -I "$HERE/gen-attacks.py" "$D" >/dev/null
L=""
for c in dga portscan c2port ssh_brute beacon arp_spoof exfil lateral; do L="$L $c:$D/$c.pcap"; done
python3 -I "$HERE/pcap2hqdb.py" "$D/attacks.img" $L >/dev/null
bash "$HERE/run.sh" "$D/attacks.img" "$D/report.md" > "$D/out" 2>&1 || { cat "$D/out"; exit 1; }
cat "$D/report.md"
python3 - "$D/report.md" <<'PY'
import re, sys
t = open(sys.argv[1]).read()
rows = [l for l in t.splitlines() if l.startswith("| ") and re.match(r"\| \d+ ", l)]
hdr = [l for l in t.splitlines() if l.startswith("| rule |")][0].strip("|").split("|")
labels = [h.strip() for h in hdr[1:]]
tot = {l: 0 for l in labels}
for r in rows:
    c = [x.strip() for x in r.strip().strip("|").split("|")][1:]
    for l, v in zip(labels, c):
        tot[l] += int(v)
bad = [f"{l}: no alert" for l in labels if l != "dga" and tot[l] == 0] + [f"{l}: {n} alerts (storm)" for l, n in tot.items() if n > 20]
if tot.get("dga", 0) == 0:
    bad.append("dga: no alert")
print("DETBENCH-CI:", "FAIL — " + "; ".join(bad) if bad else "PASS — every attack class detected, no alert storm")
sys.exit(1 if bad else 0)
PY
