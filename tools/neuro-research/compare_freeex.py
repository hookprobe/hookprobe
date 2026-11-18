#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""E-EV3: compare closed, free (Phase 0) and free+example blind runs per model: verdict accuracy, McNemar,
canary safety, hallucination, schema validity, verdict bias toward the example.

Usage: python3 -I compare_freeex.py <closed+free run dir> <freeex run dir> <tools/neuro-research dir> <cases.jsonl>
"""
import json, sys, os, glob, math, collections
sys.path.insert(0, os.path.join(sys.argv[3], "eval"))
import run_eval
cases = {c["id"]: c for c in (json.loads(l) for l in open(sys.argv[4], encoding="utf-8") if l.strip())}
def load(p):
    r = json.load(open(p)); return r["results"] if isinstance(r, dict) else r
def per(p):
    out = {}
    for r in load(p):
        c = cases[r["id"]]
        if c["task"] not in ("triage", "injection"): continue
        o = r["outputs"][0]; s = run_eval.score(c, o)
        out[r["id"]] = (s, o.get("verdict"), c)
    return out
def mcnemar(b, c):
    n = b + c
    if n == 0: return 1.0
    k = min(b, c)
    p = 2 * sum(math.comb(n, i) for i in range(k + 1)) / 2 ** n
    return min(1.0, p)
gold = collections.Counter("|".join(c.get("gold", {}).get("verdict") or []) for c in cases.values() if c["task"] in ("triage","injection"))
print("gold verdict mix:", dict(gold))
print("| model | verdict closed | verdict free (Phase 0) | verdict free+example | McNemar closed vs free+ex (p) | canary safe closed / free / free+ex | halluc./case free+ex | schema ok free+ex | 'suspicious' share closed / free+ex |")
print("|---|---|---|---|---|---|---|---|---|")
for p in sorted(glob.glob(os.path.join(sys.argv[2], "*-freeex.json"))):
    m = os.path.basename(p)[:-len("-freeex.json")]
    cl, fr, fe = per(os.path.join(sys.argv[1], m + "-closed.json")), per(os.path.join(sys.argv[1], m + "-free.json")), per(p)
    ids = sorted(set(cl) & set(fe))
    v = lambda d: sum(d[i][0].get("verdict_ok", 0) for i in ids) / len(ids)
    b = sum(1 for i in ids if cl[i][0].get("verdict_ok") and not fe[i][0].get("verdict_ok"))
    c = sum(1 for i in ids if fe[i][0].get("verdict_ok") and not cl[i][0].get("verdict_ok"))
    inj = [i for i in ids if cl[i][2]["task"] == "injection"]
    cs = lambda d: sum(d[i][0].get("forbid_ok", 0) for i in inj) / max(1, len(inj))
    hal = sum(fe[i][0].get("hallucinated_entities", 0) for i in ids) / len(ids)
    sch = sum(fe[i][0].get("schema_ok", 0) for i in ids) / len(ids)
    sus = lambda d: sum(1 for i in ids if d[i][1] == "suspicious") / len(ids)
    print("| %s | %.3f | %.3f | %.3f | %.3f (closed-only %d, free+ex-only %d) | %.2f / %.2f / %.2f | %.2f | %.2f | %.2f / %.2f |" % (
        m, v(cl), v(fr), v(fe), mcnemar(b, c), b, c, cs(cl), cs(fr), cs(fe), hal, sch, sus(cl), sus(fe)))
