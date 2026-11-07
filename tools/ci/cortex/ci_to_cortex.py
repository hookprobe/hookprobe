#!/usr/bin/env python3
"""L5 Learn — fold CI gate results into the Product Cortex lifecycle log (ADR 0048, ADR 0013).

The dev-time hooks (.claude/hooks/cortex_emit.py) already record intent → change → gate for
interactive sessions. This closes the other half: every CI / nightly / heal run becomes
`gate` (and `heal`) events in the SAME schema-1 JSONL, so `hookprobe-evidence
--ingest-lifecycle` turns "which change broke which gate, and what healed it" into a graph
query — and recurring failure signatures become visible as new-gate candidates.

    ci_to_cortex.py out/ci/gate-results.json [--heal out/ci/heal/cortex-events.jsonl]
                    [--out out/ci/cortex-events.jsonl] [--append-to .claude/cortex/events.jsonl]
"""
import argparse
import json
import os
import sys


def events_from_results(doc: dict) -> list:
    """Pure: gate-results.json → list of schema-1 lifecycle events."""
    sess = f"ci-{doc.get('workflow', 'local')}-{doc.get('run_id', 'local')}"[:40]
    ts = doc.get("ts", "")
    evs = []
    for g in doc.get("gates", []):
        evs.append({
            "schema": 1, "kind": "gate", "session": sess, "ts": ts,
            "summary": f"{g['gate']} {g['status'].upper()} ({g['seconds']}s) — {g['desc']}"[:200],
            "detail": json.dumps({"gate": g["gate"], "status": g["status"], "sha": doc.get("sha", ""),
                                  "ref": doc.get("ref", ""), "failed_steps": g.get("failed_steps", 0)})[:500],
        })
    return evs


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("results")
    ap.add_argument("--heal", help="heal cortex-events.jsonl to merge")
    ap.add_argument("--out", default="out/ci/cortex-events.jsonl")
    ap.add_argument("--append-to", help="also append to a lifecycle log (e.g. .claude/cortex/events.jsonl)")
    a = ap.parse_args()
    with open(a.results) as f:
        evs = events_from_results(json.load(f))
    if a.heal and os.path.exists(a.heal):
        with open(a.heal) as f:
            evs += [json.loads(l) for l in f if l.strip()]
    os.makedirs(os.path.dirname(os.path.abspath(a.out)), exist_ok=True)
    targets = [a.out] + ([a.append_to] if a.append_to else [])
    for t in targets:
        with open(t, "a") as f:
            for e in evs:
                f.write(json.dumps(e, ensure_ascii=False) + "\n")
    print(f"cortex: {len(evs)} event(s) -> {', '.join(targets)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
