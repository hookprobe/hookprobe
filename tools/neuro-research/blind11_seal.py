#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Doc 47 seal checks for blind v11 (blind v9's rules and mix; blind v9 and v10 added to the collision sets). Prints ONLY counts,
pass/fail and the SHA-256 (never case content).
Usage: python3 -I blind11_seal.py <blind11 cases> <repo tools/neuro-research dir> <cache dir> <other case files...>"""
import collections, hashlib, json, os, sys
B, T, W = sys.argv[1:4]; OTHERS = sys.argv[4:]
sys.path.insert(0, os.path.join(T, "eval"))
import run_eval as ev  # noqa: E402
norm = lambda s: " ".join(s.split()).lower()
cases = [json.loads(l) for l in open(B, encoding="utf-8") if l.strip()]
fail = []
MIX = {"mal": 40, "sus": 25, "ben": 40, "ins": 20, "cor": 15, "inj": 40, "alm": 30, "alb": 30}
TASK = dict({p: "triage" for p in MIX}, inj="injection")
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
SETS = [(os.path.relpath(p, W) if p.startswith(W) else os.path.relpath(p, T), p) for p in
        [os.path.join(T, "eval/cases.jsonl")] + [os.path.join(T, "eval/blind%s/blind_cases.jsonl" % k) for k in ("", "2", "3", "4", "5", "6")]
        + [os.path.join(W, d, "blind_cases.jsonl") for d in ("blind7", "dev8", "blind9", "blind10", "invblind", "invblind2", "invblind3")]
        + [os.path.join(W, "t0/t0.jsonl"), os.path.join(W, "t0/v2-templ.jsonl")] + OTHERS]
coll = {}
for name, path in SETS:
    other = {hashlib.sha256(norm(json.loads(l)["context"]).encode()).hexdigest() for l in open(path, encoding="utf-8") if l.strip()}
    coll[name] = len(mine & other)
    if coll[name]: fail.append("collision with " + name)
canaries = {s.lower() for c in cases if c["task"] == "injection" for s in c["gold"].get("forbid_strings", [])}
real_inj = sum(1 for c in cases if c["task"] == "injection" and c["gold"].get("forbid_strings"))
blob = ""
for _, path in SETS:
    blob += open(path, encoding="utf-8").read().lower()
leaked = sum(1 for k in canaries if k in blob)
if leaked: fail.append("%d canaries appear in training files or earlier sets" % leaked)
import re as _re
sys.path.insert(0, T)
import semantic_compression as sc  # noqa: E402
bad_marker = 0
for c in cases:
    for m in _re.finditer(r'"([^"\n]*)"( !instr-like)?', c["context"]):
        if bool(sc.INSTRUCTION_LIKE.search(m.group(1))) != bool(m.group(2)):
            bad_marker += 1
if bad_marker: fail.append("%d quoted values break the marker rule" % bad_marker)
real_cases = [c for c in cases if c["task"] == "injection" and c["gold"].get("forbid_strings")]
unmarked = sum(1 for c in real_cases if not any(f.lower() in l.lower() and "!instr-like" in l for f in c["gold"]["forbid_strings"] for l in c["context"].splitlines()))
if len(real_cases) != 35: fail.append("real injection %d != 35" % len(real_cases))
if unmarked < 8: fail.append("marker-avoiding real injections %d < 8" % unmarked)
import service_labels as sl  # noqa: E402
L1 = "det=behaviour_change[-,sev2,alert, l1]"
svc_bad = sum(1 for c in cases if sl.label(_re.sub(r" svc=\S+", "", c["context"])) != c["context"])
alert_bad = sum(1 for c in cases if c["id"].split("-")[0] in ("alm", "alb") and L1 not in c["context"])
alert_other = sum(1 for c in cases if c["id"].split("-")[0] in ("alm", "alb") and _re.search(r"det=(?!behaviour_change\[-,sev2,alert, l1\])", c["context"]))
alm_v = sum(1 for c in cases if c["id"].startswith("alm-") and not set(c["gold"]["verdict"]) <= {"malicious", "suspicious"})
alb_v = sum(1 for c in cases if c["id"].startswith("alb-") and "malicious" in c["gold"]["verdict"])
print("svc label violations %d; alert cases without the exact L1 alert %d, with another det %d; alm gold outside mal/sus %d; alb gold incl. malicious %d" % (
    svc_bad, alert_bad, alert_other, alm_v, alb_v))
if svc_bad or alert_bad or alert_other or alm_v or alb_v: fail.append("doc 45-47 rules (svc/alert/gold)")
not_quoted = sum(1 for c in real_cases if not any(c["gold"]["forbid_strings"][0].lower() in v.lower() for v in _re.findall(r'"([^"\n]*)"', c["context"])))
in_owner = sum(1 for c in real_cases if any(c["gold"]["forbid_strings"][0].lower() in l.lower() for l in c["context"].splitlines() if l.startswith("CONTEXT owner")))
dup = len(cases) - len({" ".join(c["context"].split()).lower() for c in cases})
if not_quoted: fail.append("%d canaries not inside any quoted value" % not_quoted)
if in_owner: fail.append("%d canaries in owner notes" % in_owner)
if dup: fail.append("%d duplicate contexts within the set" % dup)
print("canaries not quoted %d, in owner notes %d; duplicate contexts within set %d" % (not_quoted, in_owner, dup))
print("marker rule violations %d; real injection %d, canary on an unmarked line %d" % (bad_marker, len(real_cases), unmarked))
nt = sum(1 for c in cases if c["task"] in ("triage", "injection"))
multi = sum(1 for c in cases if c["task"] in ("triage", "injection") and len(c["gold"]["verdict"]) > 1)
print("cases %d  mix %s  romanian %d (%.1f%%)" % (len(cases), dict(sorted(cnt.items())), ro, 100.0 * ro / max(1, len(cases))))
print("triage+injection %d (%d accept >1 verdict); injection real %d, look-alike %d" % (nt, multi, real_inj, cnt["inj"] - real_inj))
print("collisions %s  canaries %d, found elsewhere: %d" % (coll, len(canaries), leaked))
print("sha256 %s" % hashlib.sha256(open(B, "rb").read()).hexdigest())
print("SEAL CHECKS:", "PASS" if not fail else "FAIL " + "; ".join(sorted(set(fail))))
sys.exit(1 if fail else 0)
