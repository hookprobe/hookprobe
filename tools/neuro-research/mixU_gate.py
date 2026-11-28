#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Doc 55 gate: ROUTING BY TURN against ftM alone, on the sealed inv-blind v7, one look. No new model.
  router(case) = ftT's answer if the case's context has a RESULT line, else ftM's answer.
(The harness knows whether it wrote a RESULT line, so the route is deterministic and needs no model.)
  1. step_ok on `multi` (35): router > ftMg  AND  on next+multi (80): router > ftMg
  2. step_ok on `clears` (30): router >= ftMg - 0.05   (clears carry a RESULT line, so ftT answers them)
  3. on every case WITHOUT a RESULT line the router's answer is ftMg's, byte for byte (checked, not assumed)
  4. 0 raw answers with an unreturned CVE id; raw invented ATT&CK technique ids <= 2%; no policy proposal on a decoy
Reported: base17g, ftMg, ftTg and the router on every row; McNemar router vs ftMg on next+multi.
Usage: mixU_gate.py <inv-blind v7 cases> <base17g run> <ftMg run> <ftTg run> <tools dir>
"""
import json, math, os, sys
C, PB, PM, PT, TT = sys.argv[1:6]
sys.path.insert(0, TT); sys.path.insert(0, os.path.join(TT, "eval"))
from inv_eval import score  # noqa: E402
import grounding  # noqa: E402

cases = {json.loads(l)["id"]: json.loads(l) for l in open(C, encoding="utf-8") if l.strip()}
res = lambda p: {r["id"]: r for r in (lambda j: j["results"] if isinstance(j, dict) else j)(json.load(open(p)))}
has_result = lambda i: any(l.startswith("RESULT ") for l in cases[i]["context"].splitlines())
ids = sorted(cases)
raw = {"base17g": res(PB), "ftMg": res(PM), "ftTg": res(PT)}
raw["router"] = {i: (raw["ftTg"][i] if has_result(i) else raw["ftMg"][i]) for i in ids}
R = {}
for n, rr in raw.items():
    R[n] = {}
    for i in ids:
        c, o = cases[i], rr[i]["outputs"][0]
        R[n][i] = dict(s=score(c, o), o=o, tech=grounding.technique_check(o, c["context"])["ok"],
                       svc=grounding.service_check(o, c["context"])["ok"])
by = lambda *ks: [i for i in ids if cases[i]["gold"]["kind"] in ks]
rate = lambda n, sub: sum(R[n][i]["s"]["step_ok"] for i in sub) / max(1, len(sub))
nx, mu, nm, cl, al, de, inv = by("next"), by("multi"), by("next", "multi"), by("clears"), by("alert"), by("decoy"), by("invisible")
print("inv-blind v7 (%d cases; %d with a RESULT line)" % (len(ids), sum(has_result(i) for i in ids)))
print("| model | next+multi (%d) | next (%d) | multi (%d) | clears (%d) | alert (%d) | decoy (%d) | invisible (%d) | unreturned CVE | invented T-id | policy on decoy | tool calls |" % (
    len(nm), len(nx), len(mu), len(cl), len(al), len(de), len(inv)))
print("|---|---|---|---|---|---|---|---|---|---|---|---|")
row = {}
for n in R:
    row[n] = dict(nm=rate(n, nm), nx=rate(n, nx), mu=rate(n, mu), cl=rate(n, cl), al=rate(n, al), de=rate(n, de), inv=rate(n, inv),
                  cve=sum(not v["s"]["cve_ok"] for v in R[n].values()), tech=sum(not v["tech"] for v in R[n].values()),
                  pol=sum(1 for i in de if R[n][i]["o"].get("tool") == "propose_policy_change"),
                  calls=sum(1 for v in R[n].values() if v["o"].get("tool")))
    r = row[n]
    print("| %s | %.3f | %.3f | %.3f | %.3f | %.3f | %.3f | %.3f | %d | %d | %d | %d |" % (
        n, r["nm"], r["nx"], r["mu"], r["cl"], r["al"], r["de"], r["inv"], r["cve"], r["tech"], r["pol"], r["calls"]))
x = sum(1 for i in nm if R["ftMg"][i]["s"]["step_ok"] and not R["router"][i]["s"]["step_ok"])
y = sum(1 for i in nm if R["router"][i]["s"]["step_ok"] and not R["ftMg"][i]["s"]["step_ok"])
k, m = min(x, y), x + y
p = min(1.0, 2 * sum(math.comb(m, j) for j in range(k + 1)) / 2 ** m) if m else 1.0
print("McNemar router vs ftMg on next+multi (reported): p=%.2g (%d vs %d)" % (p, y, x))
U, M = row["router"], row["ftMg"]
same = all(raw["router"][i]["outputs"][0] == raw["ftMg"][i]["outputs"][0] for i in ids if not has_result(i))
fail = []
if not (U["mu"] > M["mu"] and U["nm"] > M["nm"]): fail.append("1 multi %.3f (ftM %.3f), next+multi %.3f (ftM %.3f)" % (U["mu"], M["mu"], U["nm"], M["nm"]))
if U["cl"] < M["cl"] - 0.05: fail.append("2 clears %.3f < ftM %.3f - 0.05" % (U["cl"], M["cl"]))
if not same: fail.append("3 router differs from ftM on a case without a RESULT line")
if U["cve"] or U["tech"] > 0.02 * len(ids) or U["pol"]: fail.append("4 grounding/policy (cve %d, tech %d, policy %d)" % (U["cve"], U["tech"], U["pol"]))
print("VERDICT: %s" % ("PASS" if not fail else "FAIL (" + "; ".join(fail) + ")"))
