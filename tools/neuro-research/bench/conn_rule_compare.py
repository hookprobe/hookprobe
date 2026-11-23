#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Doc 32 section 2: how far does the connection rule (Zeek-like 300/60 s vs the kernel's doc 20 rule) move DNA v1
features and the frozen M3 systems' home false-alert rate? Models and thresholds exactly as m3_run.py (trained on
the IoT-23 + CTU-13 dev windows, which only exist as Zeek logs). Descriptive; nothing is refitted.
Usage: conn_rule_compare.py --dev a,b --home-zeek z.jsonl --home-doc20 d.jsonl [--label second]
"""
import argparse, sys
import numpy as np
sys.path.insert(0, __file__.rsplit("/", 1)[0])
import bench as b, m3_run as m


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dev", required=True); ap.add_argument("--home-zeek", required=True); ap.add_argument("--home-doc20", required=True)
    ap.add_argument("--label", default="")
    a = ap.parse_args()
    _, Xd, yd, _ = b.load(a.dev.split(","))
    rz, Xz, _, gz = b.load([a.home_zeek]); rd, Xc, _, gc = b.load([a.home_doc20])
    N = m.NOCTX
    s1 = lambda X: b.logreg(Xd[:, N], yd, X[:, N])
    t1 = m.thr_at(s1(Xd), yd)
    a32 = lambda X: b.logreg(Xd, yd, X); ta = m.thr_at(a32(Xd), yd)
    print("UNSW %s: windows (>= 3 events) zeek %d, doc20 %d; devices %d / %d" % (a.label, len(Xz), len(Xc), len(set(gz)), len(set(gc))))
    print("\n| system | home FA/device-day, Zeek rule | home FA/device-day, doc 20 rule | worst device (doc 20) |")
    print("|---|---|---|---|")
    for name, f in [("S1 notify", lambda X: s1(X) > t1), ("S2 L0-gated", m.rules_gated),
                    ("S3 act", lambda X: m.rules_gated(X) & (s1(X) > t1)),
                    ("logreg 32", lambda X: a32(X) > ta), ("rules any (ungated)", lambda X: b.rules(Xd, yd, X) > 0)]:
        pz, pc = f(Xz), f(Xc)
        per = {d: 24 * pc[gc == d].mean() for d in set(gc)}; w = max(per, key=per.get)
        print("| %s | %.3f | %.3f | %s %.2f |" % (name, 24 * pz.mean(), 24 * pc.mean(), w.replace("UNSW-", ""), per[w]))
    # paired feature shift on window ids present in both
    iz = {r["window_id"]: i for i, r in enumerate(rz)}; pairs = [(iz[r["window_id"]], j) for j, r in enumerate(rd) if r["window_id"] in iz]
    A = Xz[[p[0] for p in pairs]]; B = Xc[[p[1] for p in pairs]]
    print("\npaired windows: %d. Feature shift doc20 - zeek (median, p90 |diff|), sorted by p90:" % len(pairs))
    print("| feature | median diff | p90 abs diff |")
    print("|---|---|---|")
    D = B - A
    rows = sorted(((n, float(np.median(D[:, i])), float(np.quantile(np.abs(D[:, i]), 0.9))) for n, i in b.F.items()), key=lambda x: -x[2])
    for n, med, p90 in rows[:12]:
        print("| %s | %+.3f | %.3f |" % (n, med, p90))


if __name__ == "__main__":
    main()
