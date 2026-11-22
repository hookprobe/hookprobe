"""Dev-only: does an integer-only logistic regression (u8 features, i16 weights, i32 accumulator) make the same
decisions as the float S1 model? Uses IoT-23 + CTU-13 dev and the UNSW FIRST half only (never M3 sealed data).
Usage: python3 -I quant_check.py <bench dir> <work dir>"""
import sys, numpy as np
B, S = sys.argv[1], sys.argv[2]
sys.path.insert(0, B); import bench as b, m3_run as m
_, Xtr, ytr, _ = b.load([S + "/bench/iot23_dev.jsonl", S + "/bench/ctu13_dev.jsonl"])
_, Xh, _, gh = b.load([S + "/bench/unsw_dev_v3.jsonl"])
Xtr, Xh = Xtr[:, m.NOCTX], Xh[:, m.NOCTX]
# float S1 exactly as frozen: standardize + logreg; recover weights by fitting on identity trick
mu, sd = Xtr.mean(0), Xtr.std(0) + 1e-6
A = np.hstack([(Xtr - mu) / sd, np.ones((len(Xtr), 1))])
w = np.zeros(A.shape[1]); pos, neg = ytr.sum(), len(ytr) - ytr.sum(); sw = np.where(ytr == 1, 0.5 / pos, 0.5 / neg)
for _ in range(400):
    p = 1 / (1 + np.exp(-A @ w)); w -= 0.5 * (A.T @ ((p - ytr) * sw) + 1.0 * w / len(A))
sf = lambda X: np.hstack([(X - mu) / sd, np.ones((len(X), 1))]) @ w
assert np.allclose(sf(Xh), b.logreg(Xtr, ytr, Xh))
str_ = sf(Xtr); thr = np.quantile(str_[ytr == 0], 0.99)
# integer model: q = clip(round(255*(x-lo)/(hi-lo)),0,255); score = sum(wq*q) + bq  (i32)
lo, hi = Xtr.min(0), Xtr.max(0); rng = np.where(hi > lo, hi - lo, 1.0)
q = lambda X: np.clip(np.rint(255 * (X - lo) / rng), 0, 255).astype(np.int64)
wf = w[:-1] / sd * rng / 255                      # weight per quantum
bf = w[-1] - (w[:-1] * mu / sd).sum() + (w[:-1] / sd * lo).sum()
k = 32767 / np.abs(wf).max(); wq = np.rint(wf * k).astype(np.int64); bq = int(round(bf * k)); tq = int(round(thr * k))
si = lambda X: q(X) @ wq + bq
acc_max = int(np.abs(wq).sum() * 255 + abs(bq))
for name, X in (("train dev (IoT-23+CTU-13)", Xtr), ("UNSW home dev half", Xh)):
    df, di = sf(X) >= thr, si(X) >= tq
    print("%-28s n=%6d  float alerts %5d  int alerts %5d  decisions differ %d" % (name, len(X), df.sum(), di.sum(), (df != di).sum()))
print("recall on train malicious: float %.4f int %.4f" % ((sf(Xtr)[ytr == 1] >= thr).mean(), (si(Xtr)[ytr == 1] >= tq).mean()))
print("i32 headroom: max |acc| %d (limit 2147483647); model size %d B (28 x i16 + bias + thr + 28 x (lo,scale))" % (acc_max, 28 * 2 + 8 + 28 * 8))
