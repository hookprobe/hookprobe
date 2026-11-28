#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Doc 56 gate: ROUTER + RULE P's STOP RULE against ftM alone, on the sealed inv-blind v8, one look. No new model.
  system(case) = no tool call   if any RESULT line's typed outcome is `clears`   (doc 52 Rule P, rule 1)
               = ftT's answer   else if the context has a RESULT line             (doc 55 router)
               = ftM's answer   otherwise
Typed outcomes come from the sealed outcomes file (inv_outcomes.py: labelled from each RESULT line alone).
  1. step_ok on `multi` (35): system > ftMg  AND  on next+multi (80): system > ftMg
  2. step_ok on `clears` (30): system >= ftMg - 0.05
  3. on every case WITHOUT a RESULT line the system's answer is ftMg's, and on every case with one and no `clears`
     outcome it is ftTg's, byte for byte (checked, not assumed)
  4. 0 raw answers with an unreturned CVE id; raw invented ATT&CK technique ids <= 2%; no policy proposal on a decoy
  5. the stop rule fires on at most 2 of the 35 `multi` cases
Reported: base17g, ftMg, ftTg, router (doc 55) and the system on every row; McNemar system vs ftMg on next+multi;
outcome labels by kind; where the stop rule fired.
Usage: mixV_gate.py <inv-blind v8 cases> <outcomes.json> <base17g run> <ftMg run> <ftTg run> <tools dir>
"""
import collections, json, math, os, sys
C, PO, PB, PM, PT, TT = sys.argv[1:7]
sys.path.insert(0, TT); sys.path.insert(0, os.path.join(TT, "eval"))
from inv_eval import score  # noqa: E402
import grounding  # noqa: E402

cases = {json.loads(l)["id"]: json.loads(l) for l in open(C, encoding="utf-8") if l.strip()}
outc = json.load(open(PO))
res = lambda p: {r["id"]: r for r in (lambda j: j["results"] if isinstance(j, dict) else j)(json.load(open(p)))}
has_result = lambda i: any(l.startswith("RESULT ") for l in cases[i]["context"].splitlines())
cleared = lambda i: "clears" in outc.get(i, [])
ids = sorted(cases)
assert all(has_result(i) == (i in outc) for i in ids), "outcomes file does not match the cases' RESULT lines"
STOP = {"tool": None, "args": {}}
raw = {"base17g": res(PB), "ftMg": res(PM), "ftTg": res(PT)}
raw["router"] = {i: (raw["ftTg"][i] if has_result(i) else raw["ftMg"][i]) for i in ids}
raw["system"] = {i: ({"outputs": [STOP]} if cleared(i) else raw["router"][i]) for i in ids}
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
print("inv-blind v8 (%d cases; %d with a RESULT line; stop rule fires on %d)" % (
    len(ids), sum(has_result(i) for i in ids), sum(cleared(i) for i in ids)))
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
x = sum(1 for i in nm if R["ftMg"][i]["s"]["step_ok"] and not R["system"][i]["s"]["step_ok"])
y = sum(1 for i in nm if R["system"][i]["s"]["step_ok"] and not R["ftMg"][i]["s"]["step_ok"])
k, m = min(x, y), x + y
p = min(1.0, 2 * sum(math.comb(m, j) for j in range(k + 1)) / 2 ** m) if m else 1.0
print("McNemar system vs ftMg on next+multi (reported): p=%.2g (%d vs %d)" % (p, y, x))
lab = collections.defaultdict(collections.Counter)
for i in outc:
    for o in outc[i]:
        lab[cases[i]["gold"]["kind"]][o] += 1
print("outcome labels by kind (reported): %s" % {kd: dict(v) for kd, v in sorted(lab.items())})
fired = collections.Counter(cases[i]["gold"]["kind"] for i in ids if cleared(i))
print("stop rule fired by kind (reported): %s" % dict(fired))
S, M = row["system"], row["ftMg"]
same = all(raw["system"][i]["outputs"][0] == raw["ftMg"][i]["outputs"][0] for i in ids if not has_result(i)) and \
    all(raw["system"][i]["outputs"][0] == raw["ftTg"][i]["outputs"][0] for i in ids if has_result(i) and not cleared(i))
fail = []
if not (S["mu"] > M["mu"] and S["nm"] > M["nm"]): fail.append("1 multi %.3f (ftM %.3f), next+multi %.3f (ftM %.3f)" % (S["mu"], M["mu"], S["nm"], M["nm"]))
if S["cl"] < M["cl"] - 0.05: fail.append("2 clears %.3f < ftM %.3f - 0.05" % (S["cl"], M["cl"]))
if not same: fail.append("3 system differs from its route (ftM without a RESULT line, ftT with one and no clears)")
if S["cve"] or S["tech"] > 0.02 * len(ids) or S["pol"]: fail.append("4 grounding/policy (cve %d, tech %d, policy %d)" % (S["cve"], S["tech"], S["pol"]))
if fired.get("multi", 0) > 2: fail.append("5 stop rule fired on %d multi cases (> 2)" % fired["multi"])
print("VERDICT: %s" % ("PASS" if not fail else "FAIL (" + "; ".join(fail) + ")"))
