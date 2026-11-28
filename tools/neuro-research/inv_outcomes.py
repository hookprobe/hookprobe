#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Doc 56: typed tool outcomes (doc 53 R13) for a sealed investigation set, labelled from each RESULT line ALONE.

The labeller sees one RESULT line at a time (tool, alias, sentence), under a random key, shuffled. It never sees the
case id (which names the kind), the rest of the context, the question or the gold. That stands in for a tool that
returns a typed outcome about its own result. Prints ONLY counts and SHA-256 values, never case content.

Usage: inv_outcomes.py extract <cases> <labeller dir> <map.json>    writes <labeller dir>/results_only.jsonl
       inv_outcomes.py merge   <cases> <labeller dir> <map.json> <outcomes.json>
                                 reads <labeller dir>/labels.jsonl ({"key", "outcome"}), writes {case id: [outcome per
                                 RESULT line, in context order]}; fails unless every RESULT line has exactly one valid
                                 label
"""
import collections, hashlib, json, os, re, secrets, sys

RES = re.compile(r"^RESULT (\w+) ([HRD]\d+): (.+)$")
OUTCOMES = ("supports", "clears", "none")


def load(p):
    return [json.loads(l) for l in open(p, encoding="utf-8") if l.strip()]


def lines(case):
    return [m.groups() for m in (RES.match(l) for l in case["context"].splitlines()) if m]


def extract(cases, ldir, mpath):
    os.makedirs(ldir, exist_ok=True)
    rows, mp = [], {}
    for c in load(cases):
        for j, (tool, alias, text) in enumerate(lines(c)):
            k = secrets.token_hex(6)
            mp[k] = [c["id"], j]
            rows.append({"key": k, "tool": tool, "alias": alias, "text": text})
    rows.sort(key=lambda r: r["key"])                      # random keys: the order carries no case information
    with open(os.path.join(ldir, "results_only.jsonl"), "w", encoding="utf-8") as f:
        for r in rows:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")
    json.dump(mp, open(mpath, "w"), indent=0)
    print("extracted %d RESULT lines from %d cases" % (len(rows), len({v[0] for v in mp.values()})))


def merge(cases, ldir, mpath, out):
    mp = json.load(open(mpath))
    labs = load(os.path.join(ldir, "labels.jsonl"))
    got = collections.defaultdict(list)
    for L in labs:
        got[L.get("key")].append(L.get("outcome"))
    bad = [k for k in mp if len(got.get(k, [])) != 1 or got[k][0] not in OUTCOMES]
    extra = [k for k in got if k not in mp]
    if bad or extra:
        print("MERGE FAIL: %d lines without exactly one valid label, %d unknown keys" % (len(bad), len(extra)))
        sys.exit(2)
    res = {}
    for c in load(cases):
        n = len(lines(c))
        if n:
            res[c["id"]] = [None] * n
    for k, (cid, j) in mp.items():
        res[cid][j] = got[k][0]
    json.dump(res, open(out, "w"), indent=0, sort_keys=True)
    print("outcomes for %d cases, %d lines: %s" % (len(res), len(mp), dict(collections.Counter(o for v in res.values() for o in v))))
    print("sha256 %s" % hashlib.sha256(open(out, "rb").read()).hexdigest())


if __name__ == "__main__":
    if sys.argv[1] == "extract":
        extract(*sys.argv[2:5])
    elif sys.argv[1] == "merge":
        merge(*sys.argv[2:6])
    else:
        sys.exit(__doc__)
