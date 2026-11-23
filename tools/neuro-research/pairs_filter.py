#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Doc 38: keep a contrastive pair only if BOTH teacher answers pass, so the student sees thin and sufficient twins
together or not at all.

An answer passes when build_sft.py would keep it (schema, verdict in gold, citations, mention, no hallucinated
entities, language, no echo) AND its summary does not leak the teacher-only hint (the doc 33 hint-leak filter).
Writes a run JSON holding only complete pairs; build_sft.py then renders it unchanged.
Usage: python3 -I pairs_filter.py <pairs cases.jsonl> <teacher run.json> <out run.json>
"""
import collections, json, os, re, sys
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "eval")); sys.path.insert(0, HERE)
import run_eval  # noqa: E402
from build_sft import KEYS, echoes  # noqa: E402

LEAK = re.compile(r"\bL0\b|deterministic|engine|for the analyst|analyst note|as instructed", re.I)


def ok(c, o):
    s = run_eval.score(c, o)
    if "_error" in o or "_unparseable" in o or s.get("hallucinated_entities"):
        return False
    if any(k in s and not s[k] for k in KEYS):
        return False
    ans = {k: o[k] for k in ("verdict", "severity", "summary", "evidence", "entities", "next_step", "confidence") if k in o}
    return not echoes(c, ans) and not LEAK.search(o.get("summary", ""))


def main():
    cases = {c["id"]: c for c in (json.loads(l) for l in open(sys.argv[1], encoding="utf-8") if l.strip())}
    run = json.load(open(sys.argv[2]))
    rows = run["results"] if isinstance(run, dict) else run
    good = {r["id"] for r in rows if ok(cases[r["id"]], r["outputs"][0])}
    pair = lambda i: i.rsplit("-", 1)[0]
    complete = {p for p in {pair(i) for i in cases} if p + "-t" in good and p + "-s" in good}
    kept = [r for r in rows if pair(r["id"]) in complete]
    by = collections.Counter(cases[r["id"]]["family"] for r in kept)
    lost = collections.Counter(("thin" if i.endswith("-t") else "suff") for i in cases if i not in good)
    out = dict(run, results=kept) if isinstance(run, dict) else kept
    json.dump(out, open(sys.argv[3], "w"), ensure_ascii=False)
    print("pairs %d; complete %d (%.1f%%); answers failing: %s; kept by family %s" % (
        len({pair(i) for i in cases}), len(complete), 100 * len(complete) / max(1, len({pair(i) for i in cases})), dict(lost),
        dict(sorted(by.items()))))


if __name__ == "__main__":
    main()
