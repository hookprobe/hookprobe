#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Behavioural protection benchmark on DNA v1 vectors (dev splits only; IoT-23 / CTU-13 test splits stay sealed).

Protocol (fixed before results):
- Leave-one-capture-out (LOCO): each fold holds out one whole capture/scenario, so test families are unseen and
  capture identity cannot leak. Windows of the same capture never appear on both sides.
- The threshold of every scoring method is set on the TRAINING folds only: the score at which training-benign FPR <= 1%.
- Pooled over folds: precision, recall, FPR, AUC (rank-based), plus per-capture recall and FPR.
- Window label: malicious if >= 50% of its labelled events are malicious (mal_frac recorded per window).
Methods: rules (an L0-style rule set, no training), logreg (numpy), maha (benign-only Mahalanobis anomaly),
plus lightgbm / iforest when those packages are installed.

Usage: python3 -I bench.py <features.jsonl> [<features.jsonl> ...]
"""
import json, math, sys
import numpy as np
sys.path.insert(0, __file__.rsplit("/", 1)[0])
from dna_features import FEATURES  # noqa: E402

F = {n: i for i, n in enumerate(FEATURES)}


def load(paths):
    rows = [json.loads(l) for p in paths for l in open(p)]
    rows = [r for r in rows if r["n_events"] >= 3]
    X = np.array([r["x"] for r in rows], dtype=np.float64)
    y = np.array([r["label"] for r in rows])
    g = np.array([r["capture"] for r in rows])
    return rows, X, y, g


def rules(Xtr, ytr, X):
    """Approximation of the KERNEL L0 behavioural thresholds (os/kernel/kernel/src/behavioral.rs, ratelimit.rs),
    applied per host-hour window (the kernel uses shorter sliding windows, so this is an approximation, not a
    measurement of heqk itself):
      scan: >= 50 distinct dst ports (rate-limit), >= 100 (confirm); horizontal: >= 100 peers with fails
      lateral: >= 5 LAN peers on 22/445/3389/5900/5985/5986 (proxy: lan_peer_frac*remotes with ssh/smb share)
      beacon: >= 6 connections to a peer with inter-arrival dispersion <= 15% (proxy: periodic_cv <= 0.15)
      exfil: >= 50 MB out in the window
      brute force: >= 20 failed connections on ssh/telnet (proxy: (ssh+telnet share) * flows * fail_ratio >= 20)
    Score = number of detectors hit (0..6)."""
    c = lambda n: X[:, F[n]]
    flows = np.expm1(c("log_flows")); remotes = np.expm1(c("log_remotes"))
    scan = c("log_dst_ports") >= math.log1p(50)
    hscan = (remotes >= 100) & (c("fail_ratio") > 0.5)
    lateral = (c("lan_peer_frac") * remotes >= 5) & ((c("ssh_frac") + c("smb_frac")) > 0.2)
    beacon = (c("periodic_cv") <= 0.15) & (flows >= 6)
    exfil = c("log_bytes_out") >= math.log1p(50e6)
    brute = (c("ssh_frac") + c("telnet_frac")) * flows * c("fail_ratio") >= 20
    return scan.astype(float) + hscan + lateral + beacon + exfil + brute


def standardize(Xtr, X):
    mu, sd = Xtr.mean(0), Xtr.std(0) + 1e-6
    return (Xtr - mu) / sd, (X - mu) / sd


def logreg(Xtr, ytr, X, l2=1.0, it=400, lr=0.5):
    A, B = standardize(Xtr, X)
    A = np.hstack([A, np.ones((len(A), 1))]); B = np.hstack([B, np.ones((len(B), 1))])
    w = np.zeros(A.shape[1]); pos = max(1, ytr.sum()); neg = max(1, len(ytr) - ytr.sum())
    sw = np.where(ytr == 1, 0.5 / pos, 0.5 / neg)            # class-balanced
    for _ in range(it):
        p = 1 / (1 + np.exp(-A @ w))
        w -= lr * (A.T @ ((p - ytr) * sw) + l2 * w / len(A))
    return B @ w


def maha(Xtr, ytr, X):
    """Unsupervised: fit on training BENIGN windows only; score = Mahalanobis distance."""
    A, B = standardize(Xtr[ytr == 0], X)
    cov = np.cov(A, rowvar=False) + 1e-3 * np.eye(A.shape[1])
    inv = np.linalg.pinv(cov)
    return np.einsum("ij,jk,ik->i", B, inv, B)


def robust(Xtr, ytr, X):
    """Arp et al.-style robust baseline: per-feature quantile score vs training-benign (no model). Score = max over
    features of how far above the benign 99th percentile a value sits, in benign IQR units."""
    B = Xtr[ytr == 0]
    q50, q75, q99 = np.percentile(B, 50, 0), np.percentile(B, 75, 0), np.percentile(B, 99, 0)
    iqr = np.maximum(q75 - np.percentile(B, 25, 0), 1e-3)
    return np.max((X - q99) / iqr, axis=1)


def optional():
    m = {}
    try:
        import lightgbm as lgb
        def f(Xtr, ytr, X):
            clf = lgb.LGBMClassifier(n_estimators=200, num_leaves=15, learning_rate=0.05, class_weight="balanced", verbose=-1)
            return clf.fit(Xtr, ytr).predict_proba(X)[:, 1]
        m["lightgbm"] = f
    except ImportError:
        pass
    try:
        from sklearn.ensemble import IsolationForest
        def h(Xtr, ytr, X):
            return -IsolationForest(n_estimators=200, random_state=0).fit(Xtr[ytr == 0]).score_samples(X)
        m["iforest"] = h
    except ImportError:
        pass
    return m


def auc(s, y):
    o = np.argsort(s, kind="mergesort"); r = np.empty(len(s)); r[o] = np.arange(1, len(s) + 1)
    p, n = y.sum(), len(y) - y.sum()
    return (r[y == 1].sum() - p * (p + 1) / 2) / (p * n) if p and n else float("nan")


def main():
    rows, X, y, g = load(sys.argv[1:])
    caps = sorted(set(g))
    print("windows %d (malicious %d) in %d captures: %s" % (len(y), y.sum(), len(caps),
          ", ".join("%s %d/%d" % (c.replace("CTU-IoT-Malware-Capture-", "IoT-").replace("CTU-13.Dataset-", "CTU13-"), y[g == c].sum(), (g == c).sum()) for c in caps)))
    methods = {"rules": rules, "robust": robust, "logreg": logreg, "maha": maha}
    methods.update(optional())
    if "lightgbm" in methods:                             # doc 29 §5 shape: a learned score only counts with an L0 detector
        lgbf = methods["lightgbm"]
        methods["rules AND lightgbm"] = lambda Xtr, ytr, X: lgbf(Xtr, ytr, X) * (rules(Xtr, ytr, X) > 0)
    print("\n| method | precision | recall | FPR | false alerts / device-day | AUC | folds with malicious: recall per held-out capture |")
    print("|---|---|---|---|---|---|---|")
    for name, fn in methods.items():
        S = np.zeros(len(y)); P = np.zeros(len(y), dtype=bool); per = []
        for c in caps:
            te, tr = g == c, g != c
            if y[tr].sum() == 0:
                continue
            s_tr, s_te = fn(X[tr], y[tr], X[tr]), fn(X[tr], y[tr], X[te])
            ben = np.sort(s_tr[y[tr] == 0])
            thr = ben[min(len(ben) - 1, int(math.ceil(0.99 * len(ben))) - 1)] if len(ben) else 0.0
            S[te], P[te] = s_te, s_te > thr
            if y[te].sum():
                per.append("%s %.2f" % (c[-6:], P[te][y[te] == 1].mean()))
        if name == "rules":                                   # the kernel alerts when ANY detector fires
            A = S > 0
            tpa, fpa = (A & (y == 1)).sum(), (A & (y == 0)).sum()
            print("| rules@any-detector (kernel behaviour) | %.3f | %.3f | %.4f | %.2f | — | operating point: score > 0 |" % (
                tpa / max(1, tpa + fpa), tpa / max(1, y.sum()), fpa / max(1, (y == 0).sum()), 24 * fpa / max(1, (y == 0).sum())))
        tp, fp = (P & (y == 1)).sum(), (P & (y == 0)).sum()
        fpr = fp / max(1, (y == 0).sum())
        print("| %s | %.3f | %.3f | %.4f | %.2f | %.3f | %s |" % (name, tp / max(1, tp + fp), tp / max(1, y.sum()),
              fpr, 24 * fpr, auc(S, y), "; ".join(per)))


if __name__ == "__main__":
    main()
