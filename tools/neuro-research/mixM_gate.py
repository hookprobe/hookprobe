#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Doc 44 gate: ftMg (investigation adapter v2) against the incumbent ftLg and base17g on the sealed inv-blind v3, one
look. Grounding is read on the RAW answers (before guard G).
  1. step_ok on `alert` (the L1-alert card shape, 25) >= 0.60 AND > ftLg's
  2. step_ok on `decoy` (exact: no tool, 25) >= 0.60 AND > ftLg's
  3. step_ok on `invisible` (15) >= 0.80
  4. non-inferiority: step_ok on next+multi (80) >= ftLg's - 0.05
  5. 0 raw answers with an unreturned CVE id; raw invented ATT&CK technique ids <= 2%; no policy proposal on a decoy
Reported, not gated: base17g on every row; McNemar ftMg vs ftLg on next+multi; services named without their port.
Usage: mixM_gate.py <inv-blind v3 cases> <base17g run> <ftLg run> <ftMg run> <tools dir>
"""
import json, math, os, sys
C, PB, PL, PM, TT = sys.argv[1:6]
sys.path.insert(0, TT); sys.path.insert(0, os.path.join(TT, "eval"))
from inv_eval import score  # noqa: E402
import grounding  # noqa: E402

cases = {json.loads(l)["id"]: json.loads(l) for l in open(C, encoding="utf-8") if l.strip()}
res = lambda p: (lambda j: j["results"] if isinstance(j, dict) else j)(json.load(open(p)))
ids = sorted(cases)
by = lambda *ks: [i for i in ids if cases[i]["gold"]["kind"] in ks]
R = {}
for n, p in (("base17g", PB), ("ftLg", PL), ("ftMg", PM)):
    R[n] = {}
    for r in res(p):
        c, o = cases[r["id"]], r["outputs"][0]
        R[n][r["id"]] = dict(s=score(c, o), o=o, tech=grounding.technique_check(o, c["context"])["ok"],
                             svc=grounding.service_check(o, c["context"])["ok"])
rate = lambda n, sub: sum(R[n][i]["s"]["step_ok"] for i in sub) / max(1, len(sub))
nm, al, de, inv = by("next", "multi"), by("alert"), by("decoy"), by("invisible")
print("inv-blind v3 (%d cases)" % len(ids))
print("| model | next+multi (%d) | alert (%d) | decoy exact (%d) | invisible (%d) | unreturned CVE raw | invented T-id raw | service w/o port | policy on decoy | tool calls |" % (
    len(nm), len(al), len(de), len(inv)))
print("|---|---|---|---|---|---|---|---|---|---|")
row = {}
for n in R:
    row[n] = dict(nm=rate(n, nm), al=rate(n, al), de=rate(n, de), inv=rate(n, inv),
                  cve=sum(not v["s"]["cve_ok"] for v in R[n].values()), tech=sum(not v["tech"] for v in R[n].values()),
                  svc=sum(not v["svc"] for v in R[n].values()),
                  pol=sum(1 for i in de if R[n][i]["o"].get("tool") == "propose_policy_change"),
                  calls=sum(1 for v in R[n].values() if v["o"].get("tool")))
    r = row[n]
    print("| %s | %.3f | %.3f | %.3f | %.3f | %d | %d | %d | %d | %d |" % (n, r["nm"], r["al"], r["de"], r["inv"], r["cve"], r["tech"], r["svc"], r["pol"], r["calls"]))
x = sum(1 for i in nm if R["ftLg"][i]["s"]["step_ok"] and not R["ftMg"][i]["s"]["step_ok"])
y = sum(1 for i in nm if R["ftMg"][i]["s"]["step_ok"] and not R["ftLg"][i]["s"]["step_ok"])
k, m = min(x, y), x + y
p = min(1.0, 2 * sum(math.comb(m, j) for j in range(k + 1)) / 2 ** m) if m else 1.0
print("McNemar ftMg vs ftLg on next+multi (reported): p=%.2g (%d vs %d)" % (p, y, x))
M, L = row["ftMg"], row["ftLg"]
fail = []
if not (M["al"] >= 0.60 and M["al"] > L["al"]): fail.append("1 alert %.3f (ftL %.3f)" % (M["al"], L["al"]))
if not (M["de"] >= 0.60 and M["de"] > L["de"]): fail.append("2 decoy %.3f (ftL %.3f)" % (M["de"], L["de"]))
if M["inv"] < 0.80: fail.append("3 invisible %.3f" % M["inv"])
if M["nm"] < L["nm"] - 0.05: fail.append("4 next+multi %.3f < ftL %.3f - 0.05" % (M["nm"], L["nm"]))
if M["cve"] or M["tech"] > 0.02 * len(ids) or M["pol"]: fail.append("5 grounding/policy (cve %d, tech %d, policy %d)" % (M["cve"], M["tech"], M["pol"]))
print("VERDICT: %s" % ("PASS" if not fail else "FAIL (" + "; ".join(fail) + ")"))
