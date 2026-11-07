#!/usr/bin/env python3
"""Fold gates.sh's per-gate JSONL into one gate-results.json (ADR 0048).

The single machine-readable record of a gate run: consumed by the heal loop
(tools/ci/heal/classify.py), the Cortex feed (tools/ci/cortex/ci_to_cortex.py)
and uploaded as a CI artifact. Stdlib only.
"""
import argparse
import datetime
import json
import os


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--in", dest="inp", required=True)
    ap.add_argument("--out", required=True)
    a = ap.parse_args()
    gates = []
    with open(a.inp) as f:
        for line in f:
            line = line.strip()
            if line:
                gates.append(json.loads(line))
    doc = {
        "schema": 1,
        "ts": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"),
        "run_id": os.environ.get("GITHUB_RUN_ID", "local"),
        "sha": os.environ.get("GITHUB_SHA", ""),
        "ref": os.environ.get("GITHUB_REF", ""),
        "workflow": os.environ.get("GITHUB_WORKFLOW", "local"),
        "overall": "fail" if any(g["status"] == "fail" for g in gates) else "pass",
        "gates": gates,
    }
    with open(a.out, "w") as f:
        json.dump(doc, f, indent=2)
    for g in gates:
        print(f"  {g['gate']:<4} {g['status'].upper():<5} {g['seconds']:>5}s  {g['desc']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
