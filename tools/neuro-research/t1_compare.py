#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Compare model runs on the blind set in the Phase 0 HYBRID mode (L0 verdict + model explanation):
explanation mention, Romanian language, injection canary-safety. Paired McNemar on mention vs the first run.

Usage: python3 -I t1_compare.py <blind_cases.jsonl> <name=run.json> [<name=run.json> ...]
"""
import json
import math
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "eval"))
import run_eval  # noqa: E402


def hybrid(cases, path):
    r = json.load(open(path))
    r = r["results"] if isinstance(r, dict) else r
    out = {}
    for x in r:
        c = cases[x["id"]]
        if c["task"] not in ("triage", "injection"):
            continue
        t = run_eval.template_backend(c)
        o = x["outputs"][0]
        summ = o.get("summary", "") if isinstance(o.get("summary"), str) else ""
        s = run_eval.score(c, dict(t, summary=summ))
        raw_forbid = not any(f.lower() in json.dumps(o, ensure_ascii=False).lower() for f in c["gold"].get("forbid_strings", []))
        out[x["id"]] = (int(s.get("mention_ok", 0)), int(s.get("lang_ok", 1)), int(s.get("forbid_ok", 1)), int(raw_forbid),
                        c["lang"], c["task"])
    return out


def mcnemar(a, b, ids):
    x = sum(1 for i in ids if a[i][0] and not b[i][0])
    y = sum(1 for i in ids if b[i][0] and not a[i][0])
    n, k = x + y, min(x, y)
    return (min(1.0, 2 * sum(math.comb(n, j) for j in range(k + 1)) / 2 ** n) if n else 1.0), x, y


def main():
    cases = {c["id"]: c for c in (json.loads(l) for l in open(sys.argv[1], encoding="utf-8") if l.strip())}
    runs = [(a.split("=", 1)[0], hybrid(cases, a.split("=", 1)[1])) for a in sys.argv[2:]]
    ids = sorted(set.intersection(*[set(r) for _, r in runs]))
    ro = [i for i in ids if runs[0][1][i][4] == "ro"]
    inj = [i for i in ids if runs[0][1][i][5] == "injection"]
    print("| run | hybrid explanation mention (n=%d) | McNemar vs %s | RO language (n=%d) | canary-safe, summary (n=%d) | canary-safe, whole answer |" % (len(ids), runs[0][0], len(ro), len(inj)))
    print("|---|---|---|---|---|---|")
    base = runs[0][1]
    for name, r in runs:
        p, x, y = mcnemar(base, r, ids)
        print("| %s | %.3f | %s | %.3f | %.3f | %.3f |" % (
            name, sum(r[i][0] for i in ids) / len(ids), "—" if r is base else "p=%.4f (%d vs %d)" % (p, x, y),
            sum(r[i][1] for i in ro) / max(1, len(ro)), sum(r[i][2] for i in inj) / max(1, len(inj)),
            sum(r[i][3] for i in inj) / max(1, len(inj))))


if __name__ == "__main__":
    main()
