# NET-01 evidence — DNS under a saturating download (operator rule 2026-11-10)

**Rule (operator decision, 2026-11-10).** PASS iff, over at least 3 interleaved runs with at least 120 queries per side:

1. p90 < 500 ms in EVERY run;
2. pooled heqk loss is not significantly worse than the baseline (one-sided Fisher exact p > 0.05);
3. pooled heqk single-try loss is at most 8 % (a hard ceiling).

Clause 3 exists because, at 120 queries per side, the Fisher test alone has only about 21 % power against a true 2× loss rate.

**Method.** The baseline is a public resolver (1.1.1.1) through the same AP, under the same load, in the same run. Each second queries both resolvers, alternating order (`tools/diagnostics/cm5-dns-under-load.sh`). The verdict is computed by `tools/diagnostics/dns-net01-verdict.py`.

## Batch 49 (image W9d, 2026-11-10)
```
  run 1: heqk lost 2/40 p90 207 ms | baseline lost 1/40 p90 395 ms
  run 2: heqk lost 3/40 p90 391 ms | baseline lost 1/40 p90 207 ms
  run 3: heqk lost 3/40 p90 275 ms | baseline lost 2/40 p90 283 ms
  pooled: heqk 8/120 (6.7%) vs baseline 4/120 (3.3%); one-sided Fisher p = 0.188; p90 < 500 ms every run: True
DNS-UNDER-LOAD: PASS (operator rule 2026-11-10: p90 < 500 every run, Fisher p > 0.05, pooled loss <= 8 %, >= 120/side)
```
