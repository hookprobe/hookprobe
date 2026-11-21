#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Doc 24 dev table: hybrid mention (+ McNemar vs the first run), canary-safe over REAL injection cases,
hallucinated-entity rate, Romanian language, E fallback rate. Usage: guard_compare.py <cases> name=run.json ..."""
import json, os, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import t1_compare as tc  # noqa: E402
cases = {c["id"]: c for c in (json.loads(l) for l in open(sys.argv[1], encoding="utf-8") if l.strip())}
runs = []
for a in sys.argv[2:]:
    name, p = a.split("=", 1)
    raw = json.load(open(p)); raw = raw["results"] if isinstance(raw, dict) else raw
    runs.append((name, tc.hybrid(cases, p), raw))
ids = sorted(set.intersection(*[set(h) for _, h, _ in runs]))
real = [i for i in ids if cases[i]["task"] == "injection" and cases[i]["gold"].get("forbid_strings")]
ro = [i for i in ids if cases[i]["lang"] == "ro"]
print("| run | mention (n=%d) | McNemar vs %s | canary-safe real (n=%d) | halluc | RO (n=%d) | E fallback |" % (len(ids), runs[0][0], len(real), len(ro)))
print("|---|---|---|---|---|---|---|")
for name, h, raw in runs:
    p, x, y = tc.mcnemar(runs[0][1], h, ids)
    tr = [r for r in raw if cases[r["id"]]["task"] in ("triage", "injection")]
    hall = sum(float(r["score"].get("hallucinated_entities", 0)) for r in tr) / max(1, len(tr))
    fb = sum(1 for r in raw if r["outputs"][0].get("_guard_fallback")) / max(1, len(raw))
    print("| %s | %.3f | %s | %.3f | %.4f | %.3f | %.3f |" % (name, sum(h[i][0] for i in ids) / len(ids),
          "—" if h is runs[0][1] else "p=%.4f (%d vs %d)" % (p, y, x), sum(h[i][2] for i in real) / max(1, len(real)),
          hall, sum(h[i][1] for i in ro) / max(1, len(ro)), fb))
