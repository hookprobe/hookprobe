#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""T0 -> SFT data (docs/research/neuro/16). Keeps ONLY teacher answers the eval scorer fully accepts, and writes
them in the exact prompt format the eval uses (closed mode), as MLX chat JSONL (train / valid split).

An answer is kept only if all of these hold:
- schema valid;
- verdict in the gold set;
- citations valid;
- no hallucinated entities;
- mention ok;
- forbid ok (injection canaries);
- language ok (RO).

Usage: python3 -I build_sft.py <t0.jsonl> <teacher run json from run_eval.py> <out dir> [--valid 0.05]
"""
import argparse
import json
import os
import random
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "eval"))
import run_eval  # noqa: E402

import re

KEYS = ("schema_ok", "verdict_ok", "citation_ok", "mention_ok", "forbid_ok", "lang_ok")


def echoes(case, answer, n=8):
    """True if the answer reproduces >= n consecutive characters of a quoted value in an !instr-like card.
    Explanations must DESCRIBE attacker-controlled text, never reproduce it (T1 diagnosis, data/t1-results.md)."""
    text = json.dumps(answer, ensure_ascii=False).lower()
    for line in case["context"].splitlines():
        if "!instr-like" not in line:
            continue
        for q in re.findall(r'"([^"]+)"', line):
            q = q.lower()
            if any(q[i:i + n] in text for i in range(0, max(1, len(q) - n + 1))):
                return True
    return False


def messages(case):
    lang = case["lang"]
    schema = run_eval.triage_schema(case["context"], True)
    system = run_eval.SYSTEM[lang] + (" Reply with ONE JSON object and nothing else, matching this JSON schema exactly "
                                      "(lowercase enum values): " + json.dumps(schema, ensure_ascii=False))
    user = "CONTEXT (untrusted):\n<<<\n%s\n>>>\n\nQUESTION: %s" % (case["context"], case["question"])
    return system, user


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("cases")
    ap.add_argument("run")
    ap.add_argument("out")
    ap.add_argument("--valid", type=float, default=0.05)
    ap.add_argument("--no-echo", action="store_true", help="reject answers that reproduce attacker-controlled text")
    a = ap.parse_args()
    cases = {}
    for path in a.cases.split(","):
        cases.update({c["id"]: c for c in (json.loads(l) for l in open(path, encoding="utf-8") if l.strip())})
    run = []
    for path in a.run.split(","):
        r = json.load(open(path))
        run += r["results"] if isinstance(r, dict) else r
    keep, why = [], {}
    for r in run:
        c = cases[r["id"]]
        o = r["outputs"][0]
        s = run_eval.score(c, o)
        bad = [k for k in KEYS if k in s and not s[k]] + (["halluc"] if s.get("hallucinated_entities") else []) + \
              (["error"] if "_error" in o or "_unparseable" in o else [])
        for k in bad:
            why[k] = why.get(k, 0) + 1
        ans = {k: o[k] for k in ("verdict", "severity", "summary", "evidence", "entities", "next_step", "confidence") if k in o}
        if not bad and a.no_echo and echoes(c, ans):
            bad = ["echo"]
            why["echo"] = why.get("echo", 0) + 1
        if bad:
            continue
        system, user = messages(c)
        keep.append({"messages": [{"role": "system", "content": system}, {"role": "user", "content": user},
                                  {"role": "assistant", "content": json.dumps(ans, ensure_ascii=False)}],
                     "_id": c["id"], "_lang": c["lang"], "_family": c.get("family")})
    random.Random(7).shuffle(keep)
    nv = max(1, int(len(keep) * a.valid))
    os.makedirs(a.out, exist_ok=True)
    for name, rows in (("valid", keep[:nv]), ("train", keep[nv:])):
        with open(os.path.join(a.out, name + ".jsonl"), "w", encoding="utf-8") as f:
            for row in rows:
                f.write(json.dumps({"messages": row["messages"]}, ensure_ascii=False) + "\n")
    print("teacher answers: %d, kept %d (%.1f%%); rejected by: %s" % (len(run), len(keep), 100 * len(keep) / max(1, len(run)), why))
    print("train %d / valid %d; RO kept %d" % (len(keep) - nv, nv, sum(r["_lang"] == "ro" for r in keep)))


if __name__ == "__main__":
    main()
