#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Acceptance test for the windows export (agreed with the Neuro session, 2026-11-20).

For each scenario in a scenario-hour windows build (`heqk_data.py windows iot-23 --window scenario-hour
--splits dev`), renders every window with tools/neuro-research/semantic_compression.rendered_cards(events,
empty baseline, 512, Tok()) and compares with what gen_t0_iot23.py / replay_iot23.py produce from the raw
conn.log.labeled. Cards match "up to pseudonyms": every address and every interned alias (H1, R2, D3) is
masked before comparing, and lines are compared as multisets (rank ties between different addresses may
order differently once the addresses change).

Known difference (2026-11-20 run: 195 of 197 dev windows identical): normalised timestamps keep milliseconds,
gen_t0 keeps microseconds, so a flow within 1 ms of a window edge measured from the first flow can land in the
neighbouring window (2 flows in 2 windows of CTU-IoT-Malware-Capture-49-1). Host-hour windows start on whole
UTC hours, where millisecond truncation never moves a flow.

Usage: python3 -I neuro_acceptance.py <windows build dir> <iot23 extraction dir> [--budget 512]
Exit 0 when every window matches.
"""
import argparse
import collections
import glob
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "neuro-research"))
import replay_iot23 as rp  # noqa: E402
import semantic_compression as sc  # noqa: E402

ADDR = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b|\b[0-9a-f]{0,4}(?::[0-9a-f]{0,4}){2,7}\b", re.I)
ALIAS = re.compile(r"\b([HRD])\d+\b")


def mask(lines):
    return collections.Counter(ALIAS.sub(r"\1#", ADDR.sub("IP", l)) for l in lines)


def reference(path, max_rows, budget, tok):
    rows = rp.read_conn(path, max_rows)
    rows.sort(key=lambda x: x[0])
    t0 = rows[0][0]
    buckets = collections.defaultdict(list)
    for x in rows:
        buckets[int((x[0] - t0) // 3600)].append(x)
    return {k: sc.rendered_cards(rp.to_events(w, t0 + k * 3600), {"pairs": set(), "suffixes": set()}, budget, tok)[0]
            for k, w in buckets.items()}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("build")
    ap.add_argument("iot23")
    ap.add_argument("--budget", type=int, default=512)
    a = ap.parse_args()
    man = json.load(open(os.path.join(a.build, "manifest.json")))
    if man["window"] != "scenario-hour":
        sys.exit("needs a --window scenario-hour build")
    tok = sc.Tok()
    raw = {p.split(os.sep)[-3]: p for p in glob.glob(os.path.join(a.iot23, "**", "conn.log.labeled"), recursive=True)}
    total = same = 0
    report = {}
    for f in man["files"]:
        ref = reference(raw[f["scenario"]], man["max_rows"], a.budget, tok)
        got = {}
        with open(os.path.join(a.build, f["file"]), encoding="utf-8") as fh:
            for ln in fh:
                w = json.loads(ln)
                base = {"pairs": set(), "suffixes": set()}
                got[w["window_index"]] = sc.rendered_cards(w["events"], base, a.budget, tok)[0]
        keys = sorted(set(ref) | set(got))
        ok = [k for k in keys if k in ref and k in got and mask(ref[k]) == mask(got[k])]
        bad = [k for k in keys if k not in ok]
        total += len(keys)
        same += len(ok)
        report[f["scenario"]] = {"windows": len(keys), "match": len(ok), "mismatch": bad[:20]}
        print("%-34s windows=%-4d match=%-4d mismatch=%s" % (f["scenario"], len(keys), len(ok), bad[:10]))
        for k in bad[:2]:
            r, g = mask(ref.get(k, [])), mask(got.get(k, []))
            print("   window %d  only in reference: %s" % (k, list((r - g).elements())[:3]))
            print("   window %d  only in export:    %s" % (k, list((g - r).elements())[:3]))
    print("TOTAL windows=%d match=%d (%.4f)" % (total, same, same / max(1, total)))
    return 0 if same == total else 1


if __name__ == "__main__":
    sys.exit(main())
