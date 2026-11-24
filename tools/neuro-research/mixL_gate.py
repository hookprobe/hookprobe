#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Doc 43 gate: ftLg (investigation-only adapter) against base17g on the sealed inv-blind v2, one look.
Grounding conditions are read on the RAW answers (before guard G); the guarded figures are reported beside them.
  1. step_ok on next+multi > base17g's, exact McNemar p < 0.05
  2. step_ok on multi >= base17g's                        (doc 42's multi-step gap)
  3. stop_ok on clears+decoy >= 0.80 and >= base17g's
  4. 0 raw answers with an unreturned CVE id (hard)
  5. raw answers with an invented ATT&CK technique id <= 2% (hard)
  6. no policy proposal on any decoy
Reported, not gated: service named without its port on the cards; all grounding counts after guard G.
Usage: mixL_gate.py <inv-blind v2 cases> <base17g run json> <ftLg run json> <tools dir>
"""
import json, math, os, sys
C, PB, PL, TT = sys.argv[1:5]
sys.path.insert(0, TT); sys.path.insert(0, os.path.join(TT, "eval"))
from inv_eval import score  # noqa: E402
import grounding, guard_ground  # noqa: E402

cases = {json.loads(l)["id"]: json.loads(l) for l in open(C, encoding="utf-8") if l.strip()}
res = lambda p: (lambda j: j["results"] if isinstance(j, dict) else j)(json.load(open(p)))
kind = lambda i: cases[i]["gold"]["kind"]
R = {}
for n, p in (("base17g", PB), ("ftLg", PL)):
    rows = {}
    for r in res(p):
        c, o = cases[r["id"]], r["outputs"][0]
        g = guard_ground.apply(c, o)
        rows[r["id"]] = dict(s=score(c, o), o=o, tech_raw=grounding.technique_check(o, c["context"])["ok"],
                             tech_g=grounding.technique_check(g, c["context"])["ok"], svc=grounding.service_check(o, c["context"])["ok"],
                             cve_g=score(c, g)["cve_ok"])
    R[n] = rows
ids = sorted(cases)
nm = [i for i in ids if kind(i) in ("next", "multi")]
mu = [i for i in ids if kind(i) == "multi"]
st = [i for i in ids if kind(i) in ("clears", "decoy")]
dec = [i for i in ids if kind(i) == "decoy"]
x = sum(1 for i in nm if R["base17g"][i]["s"]["step_ok"] and not R["ftLg"][i]["s"]["step_ok"])
y = sum(1 for i in nm if R["ftLg"][i]["s"]["step_ok"] and not R["base17g"][i]["s"]["step_ok"])
k, m = min(x, y), x + y
p = min(1.0, 2 * sum(math.comb(m, j) for j in range(k + 1)) / 2 ** m) if m else 1.0
row = {}
for n, rr in R.items():
    row[n] = dict(step=sum(rr[i]["s"]["step_ok"] for i in nm) / len(nm), multi=sum(rr[i]["s"]["step_ok"] for i in mu) / len(mu),
                  stop=sum(rr[i]["s"]["stop_ok"] for i in st) / len(st), cve=sum(not v["s"]["cve_ok"] for v in rr.values()),
                  cve_g=sum(not v["cve_g"] for v in rr.values()), tech=sum(not v["tech_raw"] for v in rr.values()),
                  tech_g=sum(not v["tech_g"] for v in rr.values()), svc=sum(not v["svc"] for v in rr.values()),
                  pol=sum(1 for i in dec if rr[i]["o"].get("tool") == "propose_policy_change"), calls=sum(1 for v in rr.values() if v["o"].get("tool")))
N = len(ids)
print("inv-blind v2 (%d cases)" % N)
print("| model | step next+multi (%d) | step multi (%d) | stop clears+decoy (%d) | unreturned CVE raw/G | invented T-id raw/G | service w/o port | policy on decoy | tool calls |" % (len(nm), len(mu), len(st)))
print("|---|---|---|---|---|---|---|---|---|")
for n, r in row.items():
    print("| %s | %.3f | %.3f | %.3f | %d / %d | %d / %d | %d | %d | %d |" % (n, r["step"], r["multi"], r["stop"], r["cve"], r["cve_g"], r["tech"], r["tech_g"], r["svc"], r["pol"], r["calls"]))
print("McNemar ftLg vs base17g on next+multi: p=%.2g (%d vs %d)" % (p, y, x))
L, B = row["ftLg"], row["base17g"]
fail = []
if not (y > x and p < 0.05): fail.append("1 step not > base at p<0.05 (p=%.2g)" % p)
if L["multi"] < B["multi"]: fail.append("2 multi %.3f < base %.3f" % (L["multi"], B["multi"]))
if L["stop"] < 0.80 or L["stop"] < B["stop"]: fail.append("3 stop %.3f (base %.3f)" % (L["stop"], B["stop"]))
if L["cve"]: fail.append("4 %d raw unreturned CVE ids" % L["cve"])
if L["tech"] > 0.02 * N: fail.append("5 %d raw invented technique ids > 2%%" % L["tech"])
if L["pol"]: fail.append("6 %d policy proposals on decoys" % L["pol"])
print("VERDICT: %s" % ("PASS" if not fail else "FAIL (" + "; ".join(fail) + ")"))
