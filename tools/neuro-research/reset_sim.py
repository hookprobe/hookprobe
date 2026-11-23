#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""N0 after a server reset: how often does a relearning engine flag hours as deviant, compared with an engine that
never lost its memory, on the same hours? (heqk: a fault resets el0-neuro from its signed ELF; .bss is zeroed and
every device relearns; metal fault injection 2026-11-22.)

Engine = dna_fixed.DNAFixed (bit-exact with os/neuro/neuro-core), fed exactly as d1_analysis.make_agg. Per device
with >= MIN_DAYS active days: run once uninterrupted; run again with a reset at the first hour of active day
RESET_DAY (a fresh DNAFixed from then on). Deviant = score >= 1.0 (Q8 256), the doc 20 flag. Descriptive only.
Usage: python3 -I reset_sim.py <d1.jsonl> <devices.tsv> [--reset-day 14] [--out out.json]
"""
import argparse, json, os, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import d1_analysis as d1
import dna_fixed as fx

BUCKETS = [(0, 24), (24, 72), (72, 168), (168, 336), (336, 10 ** 9)]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("d1"); ap.add_argument("devices"); ap.add_argument("--reset-day", type=int, default=14)
    ap.add_argument("--min-days", type=int, default=28); ap.add_argument("--out")
    a = ap.parse_args()
    names, tl = d1.load(a.d1, a.devices)
    tot = {b: [0, 0, 0] for b in BUCKETS}          # hours, deviant uninterrupted, deviant after reset
    per_dev = {}
    for dev, hours in sorted(tl.items()):
        days = sorted({h // 24 for h, _ in hours})
        if len(days) < a.min_days:
            continue
        cut = days[a.reset_day]
        cont, rst = fx.DNAFixed(), fx.DNAFixed()
        t0 = None
        dd = {b: [0, 0, 0] for b in BUCKETS}
        for h, r in hours:
            sc, _ = cont.close_hour(h % 24, d1.make_agg(cont, r))
            if h // 24 < cut:
                rst.close_hour(h % 24, d1.make_agg(rst, r))
                continue
            if t0 is None:
                t0 = h; rst = fx.DNAFixed()              # the reset: memory lost, relearn from cold
            sr, _ = rst.close_hour(h % 24, d1.make_agg(rst, r))
            age = h - t0
            for b in BUCKETS:
                if b[0] <= age < b[1]:
                    dd[b][0] += 1; dd[b][1] += sc >= 256; dd[b][2] += sr >= 256
        for b in BUCKETS:
            for i in range(3):
                tot[b][i] += dd[b][i]
        per_dev[names[dev][1]] = {"%d-%s" % (b[0], "end" if b[1] > 10 ** 8 else b[1]): dd[b] for b in BUCKETS}
    print("reset at active day %d; devices with >= %d active days: %d" % (a.reset_day, a.min_days, len(per_dev)))
    print("| hours since reset | device-hours | deviant, never reset | deviant, after reset | ratio |")
    print("|---|---|---|---|---|")
    for b in BUCKETS:
        n, c, r = tot[b]
        lab = "%d–%s h" % (b[0], "end" if b[1] > 10 ** 8 else b[1])
        print("| %s | %d | %.3f (%d) | %.3f (%d) | %s |" % (lab, n, c / max(1, n), c, r / max(1, n), r, "%.2f" % (r / c) if c else "—"))
    if a.out:
        json.dump({"totals": {str(k): v for k, v in tot.items()}, "per_device": per_dev}, open(a.out, "w"), indent=1)


if __name__ == "__main__":
    main()
