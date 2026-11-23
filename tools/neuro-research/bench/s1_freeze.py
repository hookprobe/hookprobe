#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Freeze the M3 S1 model (doc 31) as a versioned artefact, so that M4 (doc 35) can pre-register exactly this model and
a Rust port can be checked against golden vectors.

S1 = bench.logreg (l2 1.0, 400 iterations, lr 0.5, class-balanced) on the 28 non-context DNA v1 features, trained on
the IoT-23 + CTU-13 DEV windows (>= 3 events); alert iff score > thr, thr = m3_run.thr_at (training-benign FPR 1%).

Writes <out>/s1_model.json:
  float   : feature names in order, mu, sd (+1e-6 as in bench), weights, bias, threshold; decision score > thr
  integer : per-feature lo/range for u8 quantisation q = clip(round(255*(x-lo)/range), 0, 255), i16 weights, i32 bias
            and threshold; decision acc > thr_q (acc = sum(wq*q) + bq, |acc| < 2^31 checked)
and <out>/s1_golden.jsonl: windows with x, q, float score, acc and both decisions.

Verifies that the float artefact reproduces m3_run's S1 decisions on every input given with --check, and counts the
integer artefact's differing decisions.
Usage: s1_freeze.py --dev iot23_dev.jsonl,ctu13_dev.jsonl --out DIR [--check a.jsonl,b.jsonl,...] [--golden-from x.jsonl,...]
"""
import argparse, hashlib, json, os, sys
import numpy as np
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import bench as b, m3_run as m


def fit(Xtr, ytr, l2=1.0, it=400, lr=0.5):
    mu, sd = Xtr.mean(0), Xtr.std(0) + 1e-6
    A = np.hstack([(Xtr - mu) / sd, np.ones((len(Xtr), 1))])
    w = np.zeros(A.shape[1]); pos, neg = max(1, ytr.sum()), max(1, len(ytr) - ytr.sum())
    sw = np.where(ytr == 1, 0.5 / pos, 0.5 / neg)
    for _ in range(it):
        p = 1 / (1 + np.exp(-A @ w))
        w -= lr * (A.T @ ((p - ytr) * sw) + l2 * w / len(A))
    return mu, sd, w


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dev", required=True); ap.add_argument("--out", required=True)
    ap.add_argument("--check", default=""); ap.add_argument("--golden-from", default="")
    a = ap.parse_args()
    dev = a.dev.split(",")
    _, Xd, yd, _ = b.load(dev)
    names = [n for n, i in sorted(b.F.items(), key=lambda kv: kv[1]) if i in m.NOCTX]
    X = Xd[:, m.NOCTX]
    mu, sd, w = fit(X, yd)
    sf = lambda Z: np.hstack([(Z - mu) / sd, np.ones((len(Z), 1))]) @ w
    assert np.array_equal(sf(X), b.logreg(X, yd, X)), "refit differs from bench.logreg"
    thr = float(m.thr_at(sf(X), yd))
    lo, hi = X.min(0), X.max(0); rng = np.where(hi > lo, hi - lo, 1.0)
    q = lambda Z: np.clip(np.rint(255 * (Z - lo) / rng), 0, 255).astype(np.int64)
    wf = w[:-1] / sd * rng / 255
    bf = w[-1] - (w[:-1] * mu / sd).sum() + (w[:-1] / sd * lo).sum()
    k = 32767 / np.abs(wf).max()
    wq = np.rint(wf * k).astype(np.int64); bq = int(round(bf * k)); tq = int(round(thr * k))
    si = lambda Z: q(Z) @ wq + bq
    acc_max = int(np.abs(wq).sum() * 255 + abs(bq))
    assert acc_max < 2 ** 31
    model = {"schema": "hookprobe.neuro.s1-model/1", "doc": "31 (M3 S1), frozen for doc 35 M4",
             "train": {"files": [os.path.basename(p) for p in dev], "sha256": [hashlib.sha256(open(p, "rb").read()).hexdigest() for p in dev],
                       "windows": int(len(yd)), "malicious": int(yd.sum()), "min_events": 3},
             "features": names,
             "float": {"mu": mu.tolist(), "sd": sd.tolist(), "w": w[:-1].tolist(), "b": float(w[-1]), "thr": thr, "decision": "score > thr"},
             "integer": {"lo": lo.tolist(), "range": rng.tolist(), "wq_i16": wq.tolist(), "bq_i32": bq, "thr_q_i32": tq, "scale": k,
                         "quantise": "q = clip(round(255*(x-lo)/range), 0, 255)", "decision": "sum(wq*q) + bq > thr_q", "max_abs_acc": acc_max}}
    os.makedirs(a.out, exist_ok=True)
    blob = json.dumps(model, indent=1)
    open(os.path.join(a.out, "s1_model.json"), "w").write(blob + "\n")
    print("s1_model.json sha256 %s" % hashlib.sha256((blob + "\n").encode()).hexdigest())
    for p in [p for p in a.check.split(",") if p]:
        _, Z, _, _ = b.load([p]); Z = Z[:, m.NOCTX]
        ref = b.logreg(X, yd, Z) > m.thr_at(b.logreg(X, yd, X), yd)
        df, di = sf(Z) > thr, si(Z) > tq
        print("%-26s n=%6d  m3_run alerts %5d  float artefact differs %d  integer alerts %5d  integer differs %d" % (
            os.path.basename(p), len(Z), ref.sum(), (df != ref).sum(), di.sum(), (di != ref).sum()))
    if a.golden_from:
        rows = []
        for p in a.golden_from.split(","):
            R, Z, _, _ = b.load([p]); Z = Z[:, m.NOCTX]
            idx = np.argsort(np.abs(sf(Z) - thr))[:16].tolist() + list(range(0, len(Z), max(1, len(Z) // 16)))[:16]
            for i in sorted(set(idx)):
                rows.append({"window_id": R[i]["window_id"], "x": Z[i].tolist(), "q": q(Z[i:i + 1])[0].tolist(), "score": float(sf(Z[i:i + 1])[0]),
                             "acc": int(si(Z[i:i + 1])[0]), "float_alert": bool(sf(Z[i:i + 1])[0] > thr), "int_alert": bool(si(Z[i:i + 1])[0] > tq)})
        open(os.path.join(a.out, "s1_golden.jsonl"), "w").write("".join(json.dumps(r) + "\n" for r in rows))
        print("golden vectors: %d (nearest the threshold + evenly spaced)" % len(rows))


if __name__ == "__main__":
    main()
