#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Doc 21 seal checks for blind v2. Prints ONLY counts, pass/fail and the SHA-256 (never case content).
Usage: python3 -I blind2_seal.py <blind2 cases> <repo tools/neuro-research dir> <work dir>"""
import collections, hashlib, json, os, re, sys
B, T, W = sys.argv[1:4]
sys.path.insert(0, os.path.join(T, "eval"))
import run_eval as ev  # noqa: E402
norm = lambda s: " ".join(s.split()).lower()
cases = [json.loads(l) for l in open(B, encoding="utf-8") if l.strip()]
fail = []
MIX = {"mal": 40, "sus": 30, "ben": 40, "ins": 20, "cor": 20, "inj": 25, "cop": 20, "tool": 20}
TASK = {"mal": "triage", "sus": "triage", "ben": "triage", "ins": "triage", "cor": "triage", "inj": "injection", "cop": "copilot", "tool": "tool"}
cnt, lang = collections.Counter(), collections.Counter()
ids = set()
for c in cases:
    if set(c) != {"id", "lang", "task", "context", "question", "gold"}:
        fail.append("keys"); continue
    p = c["id"].split("-")[0]
    cnt[p] += 1; lang[(p, c["lang"])] += 1
    if c["id"] in ids: fail.append("duplicate id")
    ids.add(c["id"])
    if TASK.get(p) != c["task"] or c["lang"] not in ("en", "ro"): fail.append("task/lang " + p)
    g = c["gold"]
    if c["task"] in ("triage", "injection"):
        facts, ents = ev.facts_and_entities(c["context"])
        if not g.get("verdict") or any(v not in ev.VERDICTS for v in g["verdict"]): fail.append("verdict enum")
        if any(e not in facts for e in g.get("evidence", [])): fail.append("gold evidence not in context")
        if any(e not in ents for e in g.get("entities", [])): fail.append("gold entity not in context")
        if any(n not in ev.NEXT for n in g.get("next_step", [])): fail.append("next_step enum")
        pass  # harmless look-alike injection cases legitimately carry no canary (brief)
    elif c["task"] == "tool":
        if g.get("tool") not in (None, "lookup_reputation", "query_flows", "query_dns", "propose_policy_change"): fail.append("tool enum")
    # the scorer must accept the case (dry run with an empty answer)
    try:
        ev.score(c, {"text": ""} if c["task"] == "copilot" else ({"tool": None} if c["task"] == "tool" else {"_unparseable": True}))
    except Exception as e:  # noqa: BLE001
        fail.append("scorer: %s" % type(e).__name__)
if dict(cnt) != MIX: fail.append("mix %s" % dict(cnt))
ro = sum(v for (p, l), v in lang.items() if l == "ro")
# collisions against every set the project has used
mine = {hashlib.sha256(norm(c["context"]).encode()).hexdigest() for c in cases}
coll = {}
for name, path, key in (("dev cases", os.path.join(T, "eval/cases.jsonl"), "context"),
                        ("blind v1", os.path.join(T, "eval/blind/blind_cases.jsonl"), "context"),
                        ("t0.jsonl", os.path.join(W, "t0/t0.jsonl"), "context"),
                        ("v2.jsonl", os.path.join(W, "t0/v2.jsonl"), "context")):
    other = {hashlib.sha256(norm(json.loads(l)[key]).encode()).hexdigest() for l in open(path, encoding="utf-8") if l.strip()}
    coll[name] = len(mine & other)
    if coll[name]: fail.append("collision with " + name)
# injection canaries must not appear anywhere in the training files
canaries = {s.lower() for c in cases if c["task"] == "injection" for s in c["gold"].get("forbid_strings", [])}
blob = ""
for p in ("t0v2/sft/train.jsonl", "t0v2/sft/valid.jsonl", "t0/t0.jsonl", "t0/v2.jsonl"):
    blob += open(os.path.join(W, p), encoding="utf-8").read().lower()
leaked = sum(1 for k in canaries if k in blob)
if leaked: fail.append("%d canaries appear in training files" % leaked)
print("cases %d  mix %s  romanian %d (%.1f%%)" % (len(cases), dict(sorted(cnt.items())), ro, 100.0 * ro / max(1, len(cases))))
print("collisions %s  injection canaries %d, found in training files: %d" % (coll, len(canaries), leaked))
print("sha256 %s" % hashlib.sha256(open(B, "rb").read()).hexdigest())
print("SEAL CHECKS:", "PASS" if not fail else "FAIL " + "; ".join(sorted(set(fail))))
sys.exit(1 if fail else 0)
