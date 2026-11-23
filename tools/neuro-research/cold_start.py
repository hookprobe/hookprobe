#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""N0 cold start on real devices: share of a device's ACTIVE hours flagged deviant (score >= 1.0), by hours since the
device was first seen, with the bit-exact reference engine (dna_fixed.DNAFixed = neuro-core), fed as d1_analysis.
Answers heqk's 6 h CM5 observation (every early hour deviant) and sizes a warm-up policy for surfacing evidence
(the engine itself is unchanged; the host knows first-seen / last-reset time).
Usage: python3 -I cold_start.py <d1.jsonl> <devices.tsv>
"""
import argparse, os, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import d1_analysis as d1
import dna_fixed as fx

B = [(0, 6), (6, 24), (24, 72), (72, 168), (168, 336), (336, 672), (672, 10 ** 9)]


def main():
    ap = argparse.ArgumentParser(); ap.add_argument("d1"); ap.add_argument("devices"); a = ap.parse_args()
    names, tl = d1.load(a.d1, a.devices)
    tot = {b: [0, 0, 0] for b in B}            # active hours, deviant, deviant driven by novelty (novel parts > 0)
    first_dev = {}
    for dev, hours in sorted(tl.items()):
        dna = fx.DNAFixed(); t0 = hours[0][0]
        for h, r in hours:
            sc, parts = dna.close_hour(h % 24, d1.make_agg(dna, r))
            age = h - t0
            for b in B:
                if b[0] <= age < b[1]:
                    tot[b][0] += 1; tot[b][1] += sc >= 256
            if sc >= 256 and dev not in first_dev:
                first_dev[dev] = age
    print("devices %d (UNSW-IoTraffic, D1 records, engine = dna_fixed.DNAFixed)" % len(tl))
    print("| hours since first seen | active device-hours | deviant share |\n|---|---|---|")
    for b in B:
        n, d, _ = tot[b]
        print("| %d–%s | %d | %.3f |" % (b[0], "end" if b[1] > 10 ** 8 else b[1], n, d / max(1, n)))
    fd = sorted(first_dev.values())
    print("\nfirst deviant hour per device: median %d h, all within the first %d h: %d of %d devices" % (
        fd[len(fd) // 2], 6, sum(1 for v in fd if v < 6), len(tl)))


if __name__ == "__main__":
    main()
