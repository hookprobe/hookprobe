#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Doc 23 seal checks for blind v3. Prints ONLY counts, pass/fail and the SHA-256 (never case content).
Usage: python3 -I blind3_seal.py <blind3 cases> <repo tools/neuro-research dir> <work dir>"""
import collections, hashlib, json, os, sys
B, T, W = sys.argv[1:4]
sys.path.insert(0, os.path.join(T, "eval"))
import run_eval as ev  # noqa: E402
norm = lambda s: " ".join(s.split()).lower()
cases = [json.loads(l) for l in open(B, encoding="utf-8") if l.strip()]
fail = []
MIX = {"mal": 55, "sus": 40, "ben": 50, "ins": 20, "cor": 20, "inj": 60, "cop": 30, "tool": 25}
TASK = {"mal": "triage", "sus": "triage", "ben": "triage", "ins": "triage", "cor": "triage", "inj": "injection", "cop": "copilot", "tool": "tool"}
cnt, ids, ro = collections.Counter(), set(), 0
for c in cases:
    if set(c) != {"id", "lang", "task", "context", "question", "gold"}:
        fail.append("keys"); continue
    p = c["id"].split("-")[0]; cnt[p] += 1; ro += c["lang"] == "ro"
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
    elif c["task"] == "tool":
        if g.get("tool") not in (None, "lookup_reputation", "query_flows", "query_dns", "propose_policy_change"): fail.append("tool enum")
    try:
        ev.score(c, {"text": ""} if c["task"] == "copilot" else ({"tool": None} if c["task"] == "tool" else {"_unparseable": True}))
    except Exception as e:  # noqa: BLE001
        fail.append("scorer: %s" % type(e).__name__)
if dict(cnt) != MIX: fail.append("mix %s" % dict(cnt))
mine = {hashlib.sha256(norm(c["context"]).encode()).hexdigest() for c in cases}
SETS = [("dev v1", os.path.join(T, "eval/cases.jsonl")), ("blind v1", os.path.join(T, "eval/blind/blind_cases.jsonl")),
        ("blind v2", os.path.join(T, "eval/blind2/blind_cases.jsonl")), ("dev v2", os.path.join(W, "dev2/blind_cases.jsonl")),
        ("t0", os.path.join(W, "t0/t0.jsonl")), ("t0 v2", os.path.join(W, "t0/v2.jsonl")),
        ("t0 v3", os.path.join(W, "t0v3/t0v3_cases.jsonl")), ("t0 v3 injection", os.path.join(W, "t0v3/t0v3i_cases.jsonl"))]
coll = {}
for name, path in SETS:
    other = {hashlib.sha256(norm(json.loads(l)["context"]).encode()).hexdigest() for l in open(path, encoding="utf-8") if l.strip()}
    coll[name] = len(mine & other)
    if coll[name]: fail.append("collision with " + name)
canaries = {s.lower() for c in cases if c["task"] == "injection" for s in c["gold"].get("forbid_strings", [])}
real_inj = sum(1 for c in cases if c["task"] == "injection" and c["gold"].get("forbid_strings"))
blob = ""
for p in ("t0v2/sft/train.jsonl", "t0v2/sft/valid.jsonl", "t0v3/mixD/train.jsonl", "t0v3/mixD/valid.jsonl"):
    blob += open(os.path.join(W, p), encoding="utf-8").read().lower()
for _, path in SETS:
    blob += open(path, encoding="utf-8").read().lower()
leaked = sum(1 for k in canaries if k in blob)
if leaked: fail.append("%d canaries appear in training files or earlier sets" % leaked)
nt = sum(1 for c in cases if c["task"] in ("triage", "injection"))
multi = sum(1 for c in cases if c["task"] in ("triage", "injection") and len(c["gold"]["verdict"]) > 1)
print("cases %d  mix %s  romanian %d (%.1f%%)" % (len(cases), dict(sorted(cnt.items())), ro, 100.0 * ro / max(1, len(cases))))
print("triage+injection %d (%d accept >1 verdict); injection real %d, look-alike %d" % (nt, multi, real_inj, cnt["inj"] - real_inj))
print("collisions %s  canaries %d, found elsewhere: %d" % (coll, len(canaries), leaked))
print("sha256 %s" % hashlib.sha256(open(B, "rb").read()).hexdigest())
print("SEAL CHECKS:", "PASS" if not fail else "FAIL " + "; ".join(sorted(set(fail))))
sys.exit(1 if fail else 0)
