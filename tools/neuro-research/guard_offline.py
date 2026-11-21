#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Apply doc 24's E (echo filter) to a stored run and re-score it. E is post-processing, so it can be applied
offline. Usage: python3 -I guard_offline.py <cases.jsonl> <run.json> <out.json>"""
import json, os, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "eval"))
import guard  # noqa: E402
import run_eval as ev  # noqa: E402
cases = {c["id"]: c for c in (json.loads(l) for l in open(sys.argv[1], encoding="utf-8") if l.strip())}
run = json.load(open(sys.argv[2])); run = run["results"] if isinstance(run, dict) else run
out = []
for r in run:
    c = cases[r["id"]]
    outs = [guard.apply_output(c, o, ev.template_backend) for o in r["outputs"]]
    out.append(dict(r, outputs=outs, score=ev.score(c, outs[0])))
json.dump(out, open(sys.argv[3], "w"), ensure_ascii=False)
print("%s: %d fallbacks / %d" % (os.path.basename(sys.argv[3]), sum(1 for r in out if r["outputs"][0].get("_guard_fallback")), len(out)))
