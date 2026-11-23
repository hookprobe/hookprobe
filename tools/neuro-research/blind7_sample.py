#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Doc 36: a 25% stratified sample (80 cases) for the second annotator: context + question ONLY (no gold),
written to the annotator's own directory. Prints only counts. Then `agree` scores its labels against gold.
Usage: python3 -I blind7_sample.py sample <blind7 cases> <annotator dir>
       python3 -I blind7_sample.py agree <blind7 cases> <annotator dir> <repo tools/neuro-research dir>"""
import collections, hashlib, json, os, sys
PER = {"mal": 12, "sus": 9, "ben": 11, "ins": 10, "cor": 5, "inj": 21, "cop": 6, "tool": 6}   # 80
mode, B, A = sys.argv[1:4]
cases = [json.loads(l) for l in open(B, encoding="utf-8") if l.strip()]
by = collections.defaultdict(list)
for c in cases:
    by[c["id"].split("-")[0]].append(c)
pick = []
for p, n in PER.items():
    pick += sorted(by[p], key=lambda c: hashlib.sha256(("ann|" + c["id"]).encode()).hexdigest())[:n]
if mode == "sample":
    os.makedirs(A, exist_ok=True)
    with open(os.path.join(A, "sample.jsonl"), "w", encoding="utf-8") as f:
        for c in pick:
            f.write(json.dumps({k: c[k] for k in ("id", "lang", "task", "context", "question")}, ensure_ascii=False) + "\n")
    print("sample: %d cases %s" % (len(pick), {p: n for p, n in PER.items()}))
    sys.exit(0)
sys.path.insert(0, os.path.join(sys.argv[4], "eval"))
import run_eval as ev  # noqa: E402
lab = {json.loads(l)["id"]: json.loads(l) for l in open(os.path.join(A, "labels.jsonl"), encoding="utf-8") if l.strip()}
gold = {c["id"]: c for c in pick}
v_ok = v_n = 0; ns_ok = ns_n = 0; t_ok = t_n = 0; c_ok = c_n = 0; dis = []
for i, c in gold.items():
    L = lab.get(i)
    if L is None:
        dis.append((i, "missing")); continue
    if c["task"] in ("triage", "injection"):
        v_n += 1; ok = L.get("verdict") in c["gold"]["verdict"]; v_ok += ok
        if "next_step" in c["gold"]:
            ns_n += 1; ns_ok += L.get("next_step") in c["gold"]["next_step"]
        if not ok: dis.append((i, "verdict"))
    elif c["task"] == "tool":
        t_n += 1; ok = ev.score(c, {"tool": L.get("tool"), "args": L.get("args", {})})["tool_ok"]; t_ok += ok
        if not ok: dis.append((i, "tool"))
    else:
        c_n += 1; ok = ev.score(c, {"text": L.get("answer", "")})["mention_ok"]; c_ok += ok
        if not ok: dis.append((i, "copilot"))
print("agreement: verdict %d/%d = %.3f; next_step %d/%d; tool %d/%d; copilot facts %d/%d" % (
    v_ok, v_n, v_ok / max(1, v_n), ns_ok, ns_n, t_ok, t_n, c_ok, c_n))
json.dump({"verdict_agreement": v_ok / max(1, v_n), "next_step": [ns_ok, ns_n], "tool": [t_ok, t_n], "copilot": [c_ok, c_n],
           "disagreements": [{"id": i, "on": k, "annotator": lab.get(i)} for i, k in dis]},
          open(os.path.join(A, "agreement.json"), "w"), indent=1, ensure_ascii=False)
print("disagreements: %d (ids and the annotator's labels in agreement.json, for the author to adjudicate)" % len(dis))
