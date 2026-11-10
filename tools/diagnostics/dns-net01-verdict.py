#!/usr/bin/env python3
"""NET-01 verdict (operator decision 2026-11-10) over >= 3 interleaved cm5-dns-under-load.sh runs, >= 120 queries per
side pooled. PASS iff (1) p90 < 500 ms in EVERY run, (2) pooled heqk loss is not significantly worse than the
baseline (one-sided Fisher exact p > 0.05), (3) pooled heqk single-try loss <= 8 % (hard ceiling: at 120/side the
Fisher test alone has ~21 % power against a true 2x loss rate).
  dns-net01-verdict.py LOG [LOG ...]     (each LOG = one cm5-dns-under-load.sh output; 40 queries per side each)"""
import math, re, sys

def logc(n, k):
    return math.lgamma(n + 1) - math.lgamma(k + 1) - math.lgamma(n - k + 1)

def fisher_greater(a, n1, b, n2):
    """P(X >= a) for X ~ hypergeometric: heqk losses a of n1, baseline b of n2 (one-sided: heqk worse)."""
    K, N = a + b, n1 + n2
    return sum(math.exp(logc(n1, x) + logc(n2, K - x) - logc(N, K)) for x in range(a, min(K, n1) + 1))

PER = 40
runs = []
for path in sys.argv[1:]:
    t = open(path, errors="replace").read()
    h = re.search(r"heqk DNS \(10\.99\.0\.1\) under load: lost (\d+)/(\d+), p90 (\d+) ms", t)
    b = re.search(r"path baseline \([^)]*\): lost (\d+)/(\d+), p90 (\d+) ms", t)
    if h and b:
        runs.append((int(h[1]), int(h[2]), int(h[3]), int(b[1]), int(b[2]), int(b[3])))
if len(runs) < 3:
    print(f"DNS-UNDER-LOAD: INCOMPLETE ({len(runs)} runs; need >= 3)"); sys.exit(2)
a, n1 = sum(r[0] for r in runs), sum(r[1] for r in runs)
b, n2 = sum(r[3] for r in runs), sum(r[4] for r in runs)
p90_ok = all(r[2] < 500 for r in runs)
p = fisher_greater(a, n1, b, n2)
rate = a / n1
size_ok = n1 >= 120 and n2 >= 120
ok = p90_ok and p > 0.05 and rate <= 0.08 and size_ok
for i, r in enumerate(runs, 1):
    print(f"  run {i}: heqk lost {r[0]}/{r[1]} p90 {r[2]} ms | baseline lost {r[3]}/{r[4]} p90 {r[5]} ms")
print(f"  pooled: heqk {a}/{n1} ({rate:.1%}) vs baseline {b}/{n2} ({b/n2:.1%}); one-sided Fisher p = {p:.3f}; p90 < 500 ms every run: {p90_ok}")
print(f"DNS-UNDER-LOAD: {'PASS' if ok else 'FAIL'} (operator rule 2026-11-10: p90 < 500 every run, Fisher p > 0.05, pooled loss <= 8 %, >= 120/side)")
sys.exit(0 if ok else 1)
