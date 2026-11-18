#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""E-SC2b: inter-connection gap statistics of IoT-23 DEV-split pairs (C&C/heartbeat vs benign).

Usage: python3 -I profile_gaps_iot23.py <iot23 dir> <this dir>
"""
import sys, os, glob, collections, random, statistics
sys.path.insert(0, sys.argv[2])
import replay_iot23 as rp
root = sys.argv[1]
files = sorted(glob.glob(os.path.join(root, "**", "conn.log.labeled"), recursive=True))
rnd = random.Random(7)
mal_stats, ben_stats = [], []
for path in files:
    name = path.split(os.sep)[-3]
    if rp.split_of(name) != "dev":
        continue
    rows = rp.read_conn(path, 1_500_000)
    if not rows: continue
    rows.sort(key=lambda r: r[0]); t0 = rows[0][0]
    b = collections.defaultdict(list)
    for r in rows: b[int((r[0]-t0)//3600)].append(r)
    mal = [k for k, v in b.items() if any(x[8].lower().startswith("malicious") for x in v)]
    ben = [k for k in b if k not in mal]
    pick = rnd.sample(mal, min(len(mal), 6)) + rnd.sample(ben, min(len(ben), 2))
    for k in pick:
        pairs = collections.defaultdict(list); lab = {}
        for r in b[k]:
            pairs[(r[1], r[2])].append(r[0])
            if r[8].lower().startswith("malicious"): lab[(r[1], r[2])] = rp.family(r[9])
        for p, ts in pairs.items():
            if len(ts) < 6: continue
            ts.sort(); g = [y-x for x, y in zip(ts, ts[1:])]
            med = statistics.median(g)
            if med <= 0: continue
            within = sum(1 for x in g if abs(x-med) <= 0.25*med)/len(g)
            cv = statistics.pstdev(g)/max(1e-9, statistics.mean(g))
            rec = (name[:28], lab.get(p, "benign"), len(ts), round(statistics.mean(g),1), round(med,1), round(cv,2), round(within,2))
            (mal_stats if p in lab else ben_stats).append(rec)
for r in sorted(mal_stats, key=lambda r: r[1]):
    if r[1] in ("c2", "heartbeat"): print("MAL", *r)
print("--- benign pairs n>=6:", len(ben_stats))
for r in sorted(ben_stats, key=lambda r: -r[6])[:25]: print("BEN", *r)
