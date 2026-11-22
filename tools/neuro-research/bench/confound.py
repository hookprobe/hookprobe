#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Source-confound check (doc 28 protocol): can a classifier tell BENIGN windows of one pipeline/source from
another? Leave-one-capture-out LightGBM AUC; near 0.5 = indistinguishable, near 1.0 = a source shortcut exists and
supervised recall on mixed sources is not trustworthy. Usage: confound.py <source-A files,...> <source-B files,...>"""
import sys, numpy as np
sys.path.insert(0, __file__.rsplit("/", 1)[0])
import bench as b
from dna_features import FEATURES
import lightgbm as lgb
A, B = sys.argv[1].split(","), sys.argv[2].split(",")
ra, Xa, ya, ga = b.load(A); rb, Xb, yb, gb = b.load(B)
X = np.vstack([Xa[ya == 0], Xb[yb == 0]]); s = np.r_[np.zeros((ya == 0).sum()), np.ones((yb == 0).sum())].astype(int)
g = np.r_[ga[ya == 0], gb[yb == 0]]
S = np.zeros(len(s))
for c in sorted(set(g)):
    te = g == c
    if len(set(s[~te])) < 2:
        continue
    S[te] = lgb.LGBMClassifier(n_estimators=200, num_leaves=15, learning_rate=0.05, verbose=-1, class_weight="balanced").fit(X[~te], s[~te]).predict_proba(X[te])[:, 1]
print("benign windows: A %d, B %d; source-confound AUC (LOCO) %.3f" % ((s == 0).sum(), (s == 1).sum(), b.auc(S, s)))
clf = lgb.LGBMClassifier(n_estimators=200, num_leaves=15, learning_rate=0.05, verbose=-1, class_weight="balanced").fit(X, s)
print("most source-revealing:", [f for _, f in sorted(zip(clf.booster_.feature_importance("gain"), FEATURES), reverse=True)[:6]])
