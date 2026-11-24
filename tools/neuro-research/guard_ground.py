#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Guard G (grounding): a deterministic output filter, applied after guard E and rule T. It can only DELETE.
  - a technique-like token that is not a real ATT&CK id (eval/grounding.py, data/attack-ids.json) is removed, with
    the brackets or quotes around it, e.g. "... Communication' (T12)." -> "... Communication'.";
  - a CVE id that does not appear in the case's context (i.e. was not returned by lookup_exposure) is removed the
    same way.
Only prose fields (summary, text) are touched; verdict, evidence, entities and tool calls never change. Each answer
that was edited carries `_guard_g` with what was removed.
It cannot fix a misread service (NTP on an SSH card): that stays a reported rate (grounding.service_check).
Usage (offline, on a run_eval JSON): python3 -I guard_ground.py <cases.jsonl> <run.json> <out.json>
"""
import json, os, re, sys
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "eval")); sys.path.insert(0, HERE)
import grounding  # noqa: E402

CVE = re.compile(r"CVE-\d{4}-\d{4,7}", re.I)


def _strip(text, bad):
    for tok in sorted(set(bad), key=len, reverse=True):
        t = re.escape(tok)
        text = re.sub(r"\s*[\(\[]\s*%s\s*[\)\]]" % t, "", text)                 # "(T12)" / "[T12]"
        text = re.sub(r"(?<![A-Za-z0-9])['\"]?%s['\"]?(?![A-Za-z0-9])" % t, "", text)
    text = re.sub(r"\s+([.,;:])", r"\1", text)
    text = re.sub(r"\(\s*\)|\[\s*\]", "", text)
    return re.sub(r"[ \t]{2,}", " ", text).strip()


def apply(case, out):
    if not isinstance(out, dict):
        return out
    ctx = case.get("context", "").upper()
    db = grounding.ids()
    o, removed = dict(out), []
    for k in ("summary", "text"):
        v = o.get(k)
        if not isinstance(v, str) or not v:
            continue
        bad = [x for x in grounding.TECH.findall(v) if x not in db]
        bad += [x for x in CVE.findall(v) if x.upper() not in ctx]
        if bad:
            o[k] = _strip(v, bad)
            removed += bad
    if removed:
        o["_guard_g"] = sorted(set(removed))
    return o


def main():
    cases = {c["id"]: c for c in (json.loads(l) for l in open(sys.argv[1], encoding="utf-8") if l.strip())}
    run = json.load(open(sys.argv[2])); rows = run["results"] if isinstance(run, dict) else run
    n = 0
    for r in rows:
        r["outputs"] = [apply(cases[r["id"]], o) for o in r["outputs"]]
        n += bool(r["outputs"][0].get("_guard_g"))
    json.dump(run, open(sys.argv[3], "w"), ensure_ascii=False)
    print("%s: guard G edited %d of %d answers" % (os.path.basename(sys.argv[3]), n, len(rows)))


if __name__ == "__main__":
    main()
