#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Doc 35 diagnosis on SPENT data (IoT-23 + CTU-13 dev and test, UNSW dev half). Descriptive; not a confirmation.
  loco     : the S1 recipe (28 features, logreg, 1% training-benign FPR) leave-one-capture-out over the pool;
             home false alerts of the full-pool model on the UNSW dev half
  features : CTU-13 malicious vs CTU-13 benign per-feature medians and AUC, with home and IoT-23 malicious medians
  iot      : doc 35 §1E (home = doc20-cut first half, plus the doc20-cut second half as the 7th argument)
Usage: m4_diag.py loco|features|iot <iot23_dev> <ctu13_dev> <iot23_test> <ctu13_test> <unsw_dev> [<unsw_second_doc20>]
"""
import sys
import numpy as np
sys.path.insert(0, __file__.rsplit("/", 1)[0])
import bench as b, m3_run as m


def auc(a, c):
    s = np.concatenate([a, c]); r = s.argsort().argsort() + 1
    return (r[:len(a)].sum() - len(a) * (len(a) + 1) / 2) / (len(a) * len(c))


def loco(pool, home):
    _, X, y, g = b.load(pool); _, Xh, _, _ = b.load([home]); N = m.NOCTX
    pred = np.zeros(len(y), bool)
    for c in sorted(set(g)):
        tr, te = g != c, g == c
        t = m.thr_at(b.logreg(X[tr][:, N], y[tr], X[tr][:, N]), y[tr])
        pred[te] = b.logreg(X[tr][:, N], y[tr], X[te][:, N]) > t
    gs = g.astype(str)
    for ds in ("CTU-13", "CTU-IoT", "CTU-Honeypot"):
        mm = np.char.startswith(gs, ds); k = mm & (y == 1)
        print("%s: recall %s (%d/%d), benign alerts %d/%d" % (ds, "%.3f" % pred[k].mean() if k.any() else "n/a", pred[k].sum(), k.sum(),
              pred[mm & (y == 0)].sum(), (mm & (y == 0)).sum()))
    for c in sorted(set(g)):
        k = (g == c) & (y == 1)
        if c.startswith("CTU-13") and k.any():
            print("  %s mal %d recall %.2f" % (c, k.sum(), pred[k].mean()))
    t = m.thr_at(b.logreg(X[:, N], y, X[:, N]), y)
    print("full-pool model: home FA/device-day %.3f" % (24 * (b.logreg(X[:, N], y, Xh[:, N]) > t).mean()))


def features(iot, ctu, home):
    _, X, y, _ = b.load(ctu); _, Xh, _, _ = b.load([home]); _, Xi, yi, _ = b.load(iot)
    M, Bn = X[y == 1], X[y == 0]
    print("| feature | CTU mal | CTU benign | home | IoT-23 mal | AUC mal vs CTU benign |\n|---|---|---|---|---|---|")
    res = [(abs(auc(M[:, i], Bn[:, i]) - .5), n, np.median(M[:, i]), np.median(Bn[:, i]), np.median(Xh[:, i]), np.median(Xi[yi == 1][:, i]),
            auc(M[:, i], Bn[:, i])) for n, i in b.F.items()]
    for r in sorted(res, reverse=True):
        print("| %s | %.3f | %.3f | %.3f | %.3f | %.3f |" % r[1:])




def iot(iot_paths, ctu_paths, home1_doc20, home2_doc20):
    """Doc 35 §1E: IoT-only refits with a home-quantile threshold; device-disjoint home groups (sha256 parity)."""
    import hashlib
    _, Xi, yi, gi = b.load(iot_paths); _, Xc, yc, _ = b.load(ctu_paths)
    _, X1, _, g1 = b.load([home1_doc20]); _, X2, _, g2 = b.load([home2_doc20])
    A = [d for d in sorted(set(g1)) if int(hashlib.sha256(d.encode()).hexdigest(), 16) % 2 == 0]
    drop = [b.F[n] for n in ("warninglist_frac", "unrouted_frac", "log_countries", "log_asns", "log_pkts_per_flow")]
    fi = [i for i in range(len(b.F)) if i not in drop]
    HA, HB, gB = X1[np.isin(g1, A)][:, fi], X2[~np.isin(g2, A)][:, fi], g2[~np.isin(g2, A)]
    print("| training | home quantile | LOCO IoT-23 recall | held-out home FA/dev-day | worst device |\n|---|---|---|---|---|")
    for lab, extra in (("IoT-23 + home A", []), ("IoT-23 + CTU-13 benign + home A", [(Xc[yc == 0][:, fi], yc[yc == 0])])):
        for q in (0.99, 0.995, 0.999):
            X = np.vstack([Xi[:, fi]] + [e[0] for e in extra] + [HA]); y = np.concatenate([yi] + [e[1] for e in extra] + [np.zeros(len(HA), int)])
            t = np.quantile(b.logreg(X, y, HA), q); pB = b.logreg(X, y, HB) > t
            per = {d: 24 * pB[gB == d].mean() for d in set(gB)}; w = max(per, key=per.get)
            pred = np.zeros(len(yi), bool)
            for c in sorted(set(gi)):
                tr = gi != c
                Xt = np.vstack([Xi[tr][:, fi]] + [e[0] for e in extra] + [HA]); yt = np.concatenate([yi[tr]] + [e[1] for e in extra] + [np.zeros(len(HA), int)])
                pred[gi == c] = b.logreg(Xt, yt, Xi[gi == c][:, fi]) > np.quantile(b.logreg(Xt, yt, HA), q)
            print("| %s | %.3f | %.3f | %.3f | %s %.2f |" % (lab, q, pred[yi == 1].mean(), 24 * pB.mean(), w.replace("UNSW-", ""), per[w]))


if __name__ == "__main__":
    mode, i_d, c_d, i_t, c_t, home = sys.argv[1:7]
    if mode == "loco":
        loco([i_d, c_d, i_t, c_t], home)
    elif mode == "iot":
        iot([i_d, i_t], [c_d, c_t], home, sys.argv[7])
    else:
        features([i_d, i_t], [c_d, c_t], home)
