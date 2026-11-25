#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Doc 51 gate: ftSg (ftM's adapter trained further on ftM's own first-check rows plus gen v6 multi/clears rows with
varied RESULT wording) against the incumbent ftMg on the sealed inv-blind v5, one look. base17g is reported.
  1. step_ok on `multi` (35) > ftMg's AND on next+multi (80) > ftMg's
  2. step_ok on `next` (45) >= ftMg's - 0.05
  3. step_ok on `alert` (25) >= ftMg's - 0.05
  4. step_ok on `decoy` (exact: no tool, 25) >= ftMg's - 0.05
  5. step_ok on `invisible` (15) >= 0.80
  6. 0 raw answers with an unreturned CVE id; raw invented ATT&CK technique ids <= 2%; no policy proposal on a decoy
Reported, not gated: base17g on every row; McNemar ftSg vs ftMg on next+multi; services named without their port.
Usage: mixS_gate.py <inv-blind v5 cases> <base17g run> <ftMg run> <ftSg run> <tools dir>
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
for n, p in (("base17g", PB), ("ftMg", PL), ("ftSg", PM)):
    R[n] = {}
    for r in res(p):
        c, o = cases[r["id"]], r["outputs"][0]
        R[n][r["id"]] = dict(s=score(c, o), o=o, tech=grounding.technique_check(o, c["context"])["ok"],
                             svc=grounding.service_check(o, c["context"])["ok"])
rate = lambda n, sub: sum(R[n][i]["s"]["step_ok"] for i in sub) / max(1, len(sub))
nm, al, de, inv = by("next", "multi"), by("alert"), by("decoy"), by("invisible")
print("inv-blind v5 (%d cases)" % len(ids))
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
nx, mu = by("next"), by("multi")
for n in R:
    print("  %s: next %.3f (%d), multi %.3f (%d)" % (n, rate(n, nx), len(nx), rate(n, mu), len(mu)))
x = sum(1 for i in nm if R["ftMg"][i]["s"]["step_ok"] and not R["ftSg"][i]["s"]["step_ok"])
y = sum(1 for i in nm if R["ftSg"][i]["s"]["step_ok"] and not R["ftMg"][i]["s"]["step_ok"])
k, m = min(x, y), x + y
p = min(1.0, 2 * sum(math.comb(m, j) for j in range(k + 1)) / 2 ** m) if m else 1.0
print("McNemar ftSg vs ftMg on next+multi (reported): p=%.2g (%d vs %d)" % (p, y, x))
M, L = row["ftSg"], row["ftMg"]
fail = []
Mn, Ln, Mm, Lm = rate("ftSg", nx), rate("ftMg", nx), rate("ftSg", mu), rate("ftMg", mu)
if not (Mm > Lm and M["nm"] > L["nm"]): fail.append("1 multi %.3f (ftM %.3f), next+multi %.3f (ftM %.3f)" % (Mm, Lm, M["nm"], L["nm"]))
if Mn < Ln - 0.05: fail.append("2 next %.3f < ftM %.3f - 0.05" % (Mn, Ln))
if M["al"] < L["al"] - 0.05: fail.append("3 alert %.3f < ftM %.3f - 0.05" % (M["al"], L["al"]))
if M["de"] < L["de"] - 0.05: fail.append("4 decoy %.3f < ftM %.3f - 0.05" % (M["de"], L["de"]))
if M["inv"] < 0.80: fail.append("5 invisible %.3f" % M["inv"])
if M["cve"] or M["tech"] > 0.02 * len(ids) or M["pol"]: fail.append("6 grounding/policy (cve %d, tech %d, policy %d)" % (M["cve"], M["tech"], M["pol"]))
print("VERDICT: %s" % ("PASS" if not fail else "FAIL (" + "; ".join(fail) + ")"))
