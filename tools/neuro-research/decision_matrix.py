#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Gate 6 decision matrix: weighted value scoring of the candidate architectures + sensitivity analysis.

The scores are JUDGEMENTS (1-5) justified criterion by criterion in NEURO_ARCHITECTURE_COMPARISON.md;
this script only makes the arithmetic and the sensitivity analysis reproducible and auditable. Change a
score or a weight here and the document's tables can be regenerated.

Sensitivity analysis:
  1. one-at-a-time: each weight scaled x0.5 and x1.5 (others renormalised) -> does the winner change?
  2. named scenarios (efficiency-agnostic, UX-first, cost-first, research-first)
  3. Monte Carlo: 20,000 random weight vectors (Dirichlet around the stated weights) and +-1 score noise
     -> how often each architecture ranks first
  4. veto check: any architecture with a score of 1 on Feasibility or Reliability/Security is flagged,
     because a weighted average must not hide a critical weakness

Usage: python3 -I decision_matrix.py [--markdown]
"""
import random

CRITERIA = [  # (key, label, weight)
    ("value", "Practical intelligence & security value", 0.25),
    ("eff", "CM5 resource efficiency", 0.20),
    ("feas", "Technical feasibility & evidence", 0.15),
    ("rel", "Reliability & security", 0.15),
    ("ux", "User experience & autonomy", 0.10),
    ("cost", "Development & maintenance cost (5 = cheapest)", 0.10),
    ("ip", "Long-term differentiation / IP", 0.05),
]

ARCH = {
    "BASE  Conventional resident LLM": dict(value=2, eff=1, feas=2, rel=1, ux=3, cost=4, ip=1),
    "A     Extreme compact transformer": dict(value=3, eff=3, feas=2, rel=2, ux=3, cost=3, ip=3),
    "B     Recurrent edge intelligence": dict(value=2, eff=3, feas=1, rel=2, ux=2, cost=2, ip=3),
    "C     Hybrid adaptive (on-device L2)": dict(value=4, eff=4, feas=3, rel=4, ux=4, cost=2, ip=3),
    "D     Evidence-first, model-last": dict(value=4, eff=5, feas=4, rel=5, ux=3, cost=3, ip=3),
}


def total(s, w):
    return sum(s[k] * w[k] for k in w)


def norm(w):
    t = sum(w.values())
    return {k: v / t for k, v in w.items()}


def ranking(w, arch=ARCH):
    return sorted(((total(s, w), n) for n, s in arch.items()), reverse=True)


def main():
    w0 = {k: wt for k, _, wt in CRITERIA}
    print("## Weighted scores (1-5 scale; weights as specified)\n")
    print("| Architecture | " + " | ".join("%s (%d%%)" % (k, round(wt * 100)) for k, _, wt in CRITERIA) + " | **Weighted** | Veto flags |")
    print("|---" * (len(CRITERIA) + 3) + "|")
    for t, n in ranking(w0):
        s = ARCH[n]
        veto = [k for k in ("feas", "rel") if s[k] <= 1]
        print("| %s | %s | **%.2f** | %s |" % (n.split("  ")[0].strip() + " — " + n.split("  ", 1)[1].strip(),
                                              " | ".join(str(s[k]) for k, _, _ in CRITERIA), t,
                                              ", ".join("score 1 on " + v for v in veto) or "—"))
    print("\n## One-at-a-time weight sensitivity (each weight x0.5 / x1.5, renormalised)\n")
    print("| Weight changed | x0.5 winner (margin) | x1.5 winner (margin) |")
    print("|---|---|---|")
    for k, label, _ in CRITERIA:
        cells = []
        for f in (0.5, 1.5):
            w = dict(w0)
            w[k] *= f
            r = ranking(norm(w))
            cells.append("%s (+%.2f)" % (r[0][1].split()[0], r[0][0] - r[1][0]))
        print("| %s | %s | %s |" % (label, cells[0], cells[1]))
    print("\n## Scenarios\n")
    scen = {
        "Efficiency-agnostic (eff = 0)": dict(w0, eff=0.0),
        "UX-first (ux = 0.35)": dict(w0, ux=0.35),
        "Cost-first (cost = 0.35)": dict(w0, cost=0.35),
        "Research/IP-first (ip = 0.30)": dict(w0, ip=0.30),
        "Value only": {k: (1.0 if k == "value" else 0.0) for k in w0},
    }
    print("| Scenario | Ranking (weighted score) |")
    print("|---|---|")
    for name, w in scen.items():
        r = ranking(norm(w))
        print("| %s | %s |" % (name, " > ".join("%s %.2f" % (n.split()[0], t) for t, n in r)))
    print("\n## Monte Carlo robustness (20,000 draws: Dirichlet weights around the stated ones, +-1 score noise)\n")
    rnd = random.Random(42)
    wins = {n: 0 for n in ARCH}
    N = 20000
    for _ in range(N):
        g = {k: rnd.gammavariate(w0[k] * 20, 1.0) for k in w0}
        w = norm(g)
        noisy = {n: {k: min(5, max(1, v + rnd.choice((-1, 0, 0, 1)))) for k, v in s.items()} for n, s in ARCH.items()}
        wins[ranking(w, noisy)[0][1]] += 1
    print("| Architecture | Ranked first |")
    print("|---|---|")
    for n, c in sorted(wins.items(), key=lambda kv: -kv[1]):
        print("| %s | %.1f%% |" % (n.split()[0], 100.0 * c / N))


if __name__ == "__main__":
    main()
