#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Experiment E-BM2a: behavioural memory ("Neural DNA", behavioural_memory.DNA) on REAL IoT-23 traffic.

IoT-23 (Stratosphere Lab, CC BY 4.0, https://zenodo.org/records/4743746). Constraints of the data:
malware scenarios are infected from their first hour (no clean baseline per infected device) and the
labelled logs carry no DNS names. So the experiment has two honest parts:

  1. NUISANCE (real, benign): for each benign honeypot device (CTU-Honeypot-Capture-*), learn on the
     first half of its hours, score the second half -> alarm rate per device-day at fixed thresholds.
  2. ONSET (SEMI-SYNTHETIC): learn a benign device's baseline, then substitute k hours of a REAL
     infected device's behaviour (its peers, volume and fan-out, from a malware scenario) into the
     benign device's timeline -> is the change flagged? Both sides are real traffic; the join is
     artificial and labelled as such.

Same DNA code, same guarded update, same thresholds as E-BM1 -- no retuning on this data.

Usage: python3 -I replay_bm_iot23.py <iot23 dir> [--json out.json]
"""
import argparse
import collections
import glob
import json
import math
import os
import random
import statistics
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import behavioural_memory as bm  # noqa: E402
import replay_iot23 as rp  # noqa: E402

THRESHOLDS = [1.0, 2.0, 3.0]


def hourly(rows, host):
    """Per-hour observation tuples for one source host: (conns, peers, bytes_out, suffixes, nx)."""
    t0 = rows[0][0]
    hours = collections.defaultdict(lambda: [0, set(), 0])
    for ts, src, dst, dport, proto, ob, rb, state, label, det in rows:
        if src != host:
            continue
        h = int((ts - t0) // 3600)
        hours[h][0] += 1
        hours[h][1].add("%s:%d" % (dst, dport))
        hours[h][2] += ob
    if not hours:
        return []
    last = max(hours)
    return [(h, (hours[h][0], hours[h][1], hours[h][2], set(), 0.0)) for h in range(last + 1) if h in hours]


def main_host(rows):
    c = collections.Counter(r[1] for r in rows if r[1].startswith(("192.168.", "10.", "172.")))
    return c.most_common(1)[0][0] if c else None


def run(dna, series, t_offset=0):
    """Feed (hour, obs) in order; return scores for the scored part (after learning)."""
    out = []
    for i, (h, obs) in enumerate(series):
        hr = (h + t_offset) % 24
        s, parts = dna.score(hr, obs)
        out.append((s, parts))
        if s < bm.CALM:
            dna.update(hr, obs, admit_items=True)
        else:
            dna.admit_persistent({p for p in obs[1] if p not in dna.peers}, set(), k=bm.PERSIST_K)
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("root")
    ap.add_argument("--bloom", type=int, default=1024)
    ap.add_argument("--max-rows", type=int, default=1_500_000)
    ap.add_argument("--json")
    a = ap.parse_args()
    files = sorted(glob.glob(os.path.join(a.root, "**", "conn.log.labeled"), recursive=True))
    benign, infected = [], []
    for p in files:
        name = p.split(os.sep)[-3]
        rows = rp.read_conn(p, a.max_rows)
        if not rows:
            continue
        rows.sort(key=lambda r: r[0])
        host = main_host(rows)
        if not host:
            continue
        series = hourly(rows, host)
        if "Honeypot" in name:
            benign.append((name, host, series))
        else:
            mal_hours = [(h, o) for h, o in series]
            infected.append((name, host, mal_hours))
    res = {"benign_devices": [], "onset": []}
    print("E-BM2a on IoT-23 | bloom=%d bits | CALM=%.1f | PERSIST_K=%d" % (a.bloom, bm.CALM, bm.PERSIST_K))
    print("1) NUISANCE on real benign devices (learn first half, score second half)")
    for name, host, series in benign:
        if len(series) < 8:
            print("   %-34s too short (%d active hours)" % (name, len(series)))
            continue
        half = len(series) // 2
        dna = bm.DNA(a.bloom)
        for h, obs in series[:half]:
            dna.update(h % 24, obs)
        sc = [s for s, _ in run(dna, series[half:])]
        days = max(1.0, (series[-1][0] - series[half][0] + 1) / 24.0)
        rates = {t: sum(1 for s in sc if s > t) / days for t in THRESHOLDS}
        print("   %-34s hours=%-4d scored=%-4d alarms/day @1/2/3 = %s  state=%d B" % (
            name, len(series), len(sc), " / ".join("%.2f" % rates[t] for t in THRESHOLDS), dna.nbytes()))
        res["benign_devices"].append({"scenario": name, "active_hours": len(series), "scored_hours": len(sc),
                                      "alarms_per_day": rates, "state_bytes": dna.nbytes()})
    print("2) ONSET, SEMI-SYNTHETIC (benign baseline, then k real infected hours substituted)")
    rnd = random.Random(3)
    for bname, bhost, bseries in benign:
        if len(bseries) < 8:
            continue
        half = len(bseries) // 2
        for iname, ihost, iseries in infected:
            if len(iseries) < 3:
                continue
            dna = bm.DNA(a.bloom)
            for h, obs in bseries[:half]:
                dna.update(h % 24, obs)
            start = rnd.randrange(half, len(bseries))
            k = min(4, len(iseries))
            seg = rnd.randrange(0, len(iseries) - k + 1)
            spliced = [(bseries[start][0] + j, iseries[seg + j][1]) for j in range(k)]
            sc = run(dna, spliced)
            first = sc[0][0]
            hit = {t: any(s > t for s, _ in sc) for t in THRESHOLDS}
            drv = max(sc[0][1], key=sc[0][1].get)
            res["onset"].append({"benign": bname, "infected": iname, "first_hour_score": first, "flagged": hit, "driver": drv})
    by_t = {t: [o["flagged"][t] for o in res["onset"]] for t in THRESHOLDS}
    if res["onset"]:
        print("   pairs=%d  flagged within 4 h @1/2/3 = %s  first-hour drivers: %s" % (
            len(res["onset"]), " / ".join("%.2f" % (sum(v) / len(v)) for t, v in by_t.items()),
            dict(collections.Counter(o["driver"] for o in res["onset"]))))
    else:
        print("   no benign/infected pairs available yet")
    if a.json:
        with open(a.json, "w") as f:
            json.dump(res, f, indent=1)


if __name__ == "__main__":
    main()
