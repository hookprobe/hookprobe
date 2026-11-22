#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Doc 31: the ONE M3 run. Frozen before any sealed data exists. Trains on IoT-23 + CTU-13 DEV windows only,
scores the sealed IoT-23 / CTU-13 TEST windows (recall, precision) and the UNSW second half (false alerts per
device-day). Systems S1 notify (logreg), S2 L0-gated (rules with gated beacon), S3 act (S2 AND S1); reported extras.
Usage: m3_run.py --dev a.jsonl,b.jsonl --test c.jsonl,d.jsonl --home e.jsonl
"""
import argparse, math, sys
import numpy as np
sys.path.insert(0, __file__.rsplit("/", 1)[0])
import bench as b

F = b.F
CONTEXT = [F[n] for n in ("warninglist_frac", "unrouted_frac", "log_countries", "log_asns")]
NOCTX = [i for i in range(len(F)) if i not in CONTEXT]   # S1 uses the 28 non-context features (doc 31)


def rules_gated(X):
    c = lambda n: X[:, F[n]]
    flows, remotes = np.expm1(c("log_flows")), np.expm1(c("log_remotes"))
    beacon = (c("periodic_cv") <= 0.15) & (flows >= 6) & (c("novel_pair_frac") > 0.5) & (c("warninglist_frac") < 0.5)
    return ((c("log_dst_ports") >= math.log1p(50)) | ((remotes >= 100) & (c("fail_ratio") > 0.5))
            | ((c("lan_peer_frac") * remotes >= 5) & ((c("ssh_frac") + c("smb_frac")) > 0.2)) | beacon
            | (c("log_bytes_out") >= math.log1p(50e6)) | ((c("ssh_frac") + c("telnet_frac")) * flows * c("fail_ratio") >= 20))


def thr_at(s_tr, y_tr):
    ben = np.sort(s_tr[y_tr == 0])
    return ben[min(len(ben) - 1, int(math.ceil(0.99 * len(ben))) - 1)]


def ci(k, n):
    """Exact (Clopper-Pearson) 95% interval via bisection on the binomial CDF."""
    from math import comb
    cdf = lambda x, p: sum(comb(n, i) * p ** i * (1 - p) ** (n - i) for i in range(x + 1))
    def solve(f):
        lo, hi = 0.0, 1.0
        for _ in range(60):
            mid = (lo + hi) / 2
            lo, hi = (mid, hi) if f(mid) else (lo, mid)
        return (lo + hi) / 2
    lower = 0.0 if k == 0 else solve(lambda p: 1 - cdf(k - 1, p) < 0.025)
    upper = 1.0 if k == n else solve(lambda p: cdf(k, p) > 0.025)
    return lower, upper


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dev", required=True); ap.add_argument("--test", required=True); ap.add_argument("--home", required=True)
    a = ap.parse_args()
    _, Xd, yd, gd = b.load(a.dev.split(","))
    _, Xt, yt, gt = b.load(a.test.split(","))
    _, Xh, yh, gh = b.load(a.home.split(","))
    assert yh.sum() == 0
    Xd28, Xt28, Xh28 = Xd[:, NOCTX], Xt[:, NOCTX], Xh[:, NOCTX]
    s1_tr, s1_t, s1_h = b.logreg(Xd28, yd, Xd28), b.logreg(Xd28, yd, Xt28), b.logreg(Xd28, yd, Xh28)
    t1 = thr_at(s1_tr, yd)
    systems = {"S1 notify": (s1_t > t1, s1_h > t1, (0.90, 0.14)),
               "S2 L0-gated": (rules_gated(Xt), rules_gated(Xh), (0.80, 0.14)),
               "S3 act": (rules_gated(Xt) & (s1_t > t1), rules_gated(Xh) & (s1_h > t1), (0.80, 0.02))}
    extras = {}
    a_tr, a_t, a_h = b.logreg(Xd, yd, Xd), b.logreg(Xd, yd, Xt), b.logreg(Xd, yd, Xh)
    ta = thr_at(a_tr, yd); extras["logreg (32 features, incl. context)"] = (a_t > ta, a_h > ta)
    for name, fn in [("rules any (ungated)", None), ("lightgbm", b.optional().get("lightgbm")), ("iforest", b.optional().get("iforest"))]:
        if name.startswith("rules"):
            extras[name] = (b.rules(Xd, yd, Xt) > 0, b.rules(Xd, yd, Xh) > 0)
        elif fn:
            tr, t_, h_ = fn(Xd, yd, Xd), fn(Xd, yd, Xt), fn(Xd, yd, Xh)
            th = thr_at(tr, yd); extras[name] = (t_ > th, h_ > th)
    print("M3 sealed run: dev windows %d | test windows %d (malicious %d, %d captures) | home windows %d (%d devices)\n" % (
        len(yd), len(yt), yt.sum(), len(set(gt)), len(yh), len(set(gh))))
    print("| system | recall [95% CI] | precision | home false alerts / device-day | worst device | criteria | PASS? |")
    print("|---|---|---|---|---|---|---|")
    for name, (Pt, Ph, (rmin, fmax)) in list(systems.items()) + [(k, (v[0], v[1], (None, None))) for k, v in extras.items()]:
        tp, fp = int((Pt & (yt == 1)).sum()), int((Pt & (yt == 0)).sum())
        rec = tp / max(1, yt.sum()); lo, hi = ci(tp, int(yt.sum()))
        per = {d: 24 * Ph[gh == d].mean() for d in set(gh)}; worst = max(per, key=per.get)
        home = 24 * Ph.mean()
        ok = "—" if rmin is None else ("PASS" if rec >= rmin and home <= fmax else "FAIL")
        print("| %s | %.3f [%.3f, %.3f] | %.3f | %.3f | %s %.2f | %s | %s |" % (name, rec, lo, hi, tp / max(1, tp + fp), home,
              worst.replace("UNSW-", ""), per[worst], "—" if rmin is None else "recall ≥ %.2f, ≤ %.2f/day" % (rmin, fmax), ok))
    print("\nper-capture recall (S1 / S2 / S3):")
    for c in sorted(set(gt)):
        m = (gt == c) & (yt == 1)
        if m.any():
            print("  %s: %s" % (c, " / ".join("%.2f" % systems[k][0][m].mean() for k in systems)))


if __name__ == "__main__":
    main()
