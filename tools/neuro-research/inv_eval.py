#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Doc 39 P3: the INVESTIGATION task. Reuses run_eval's model call unchanged (sent as its `tool` task) with one extra
read-only tool, lookup_exposure (exposure.py). run_eval.py itself is not modified, so every earlier score stands.

Case: {"id", "lang", "task": "investigate", "context": evidence cards [+ "RESULT <tool> <alias>: ..." lines from
earlier steps], "question", "gold": {"kind": next|multi|stop|clears|invisible, "tools": [acceptable tool names, null =
no call], "entities": [acceptable aliases], "policies": [acceptable policies, only for propose_policy_change]}}

Scores per answer:
  step_ok : the tool is one of gold.tools, and (if a tool was called) its entity is one of gold.entities, and (for
            propose_policy_change) its policy is one of gold.policies;
  stop_ok : for kind clears/decoy: no tool, or only a read-only look (never a policy change);
  cve_ok  : every CVE id anywhere in the answer appears in the case's context (i.e. came from lookup_exposure). HARD.
Usage: inv_eval.py --cases X.jsonl --url URL [--guard A] --json out.json        (model run)
       inv_eval.py --score X.jsonl run.json                                     (score a run)
"""
import argparse, collections, json, os, re, sys
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "eval")); sys.path.insert(0, HERE)
import run_eval  # noqa: E402

LOOKUP_TOOL = {"type": "function", "function": {
    "name": "lookup_exposure",
    "description": "Known-exploited weaknesses for a device's class (and product, when known): counts, usual entry technique, "
                   "and CVE ids that match the product. Read-only.",
    "parameters": {"type": "object", "properties": {"entity": {"type": "string"}}, "required": ["entity"]}}}
CVE = re.compile(r"CVE-\d{4}-\d{4,7}", re.I)
READ_ONLY = {"lookup_reputation", "query_flows", "query_dns", "lookup_exposure"}


def score(case, out):
    g = case["gold"]
    tool = out.get("tool")
    args = out.get("args") or {}
    ok = tool in g["tools"]
    if ok and tool is not None and g.get("entities"):
        ok = str(args.get("entity")) in g["entities"]
    if ok and tool == "propose_policy_change" and g.get("policies"):
        ok = args.get("policy") in g["policies"]
    s = {"step_ok": ok}
    if g["kind"] in ("stop", "clears", "decoy"):
        s["stop_ok"] = tool is None or tool in READ_ONLY
    blob = json.dumps(out, ensure_ascii=False)
    s["cve_ok"] = all(c.upper() in case["context"].upper() for c in CVE.findall(blob))
    return s


def run(a):
    import guard
    run_eval.TOOLS = run_eval.TOOLS + [LOOKUP_TOOL]           # this process only; run_eval.py is unchanged on disk
    cases = [json.loads(l) for l in open(a.cases, encoding="utf-8") if l.strip()]
    res = []
    for c in cases:
        seen = dict(c, task="tool", context=guard.redact_all(c["context"]) if a.guard == "A" else c["context"])
        try:
            o = run_eval.openai_backend(seen, a, a.temperature)
        except Exception as e:  # noqa: BLE001
            o = {"_error": str(e)[:200], "tool": None, "args": {}}
        res.append({"id": c["id"], "task": "investigate", "lang": c["lang"], "outputs": [o], "score": score(c, o)})
    json.dump({"results": res}, open(a.json, "w"), ensure_ascii=False)
    report(cases, res)


def report(cases, res):
    by = {c["id"]: c for c in cases}
    k = collections.defaultdict(lambda: collections.Counter())
    for r in res:
        c = by[r["id"]]; s = score(c, r["outputs"][0]); kd = c["gold"]["kind"]
        k[kd]["n"] += 1; k[kd]["step"] += s["step_ok"]; k[kd]["stop"] += s.get("stop_ok", 0); k["ALL"]["cve_bad"] += not s["cve_ok"]
        k["ALL"]["n"] += 1; k["ALL"]["step"] += s["step_ok"]
    for kd in sorted(k):
        x = k[kd]
        print("%-10s n=%d step_ok %.3f%s%s" % (kd, x["n"], x["step"] / max(1, x["n"]),
                                           "" if kd not in ("stop", "clears", "decoy") else "  stop_ok %.3f" % (x["stop"] / max(1, x["n"])),
                                           "" if kd != "ALL" else "  answers with an unreturned CVE id: %d" % x["cve_bad"]))


if __name__ == "__main__":
    if sys.argv[1] == "--score":
        cases = [json.loads(l) for l in open(sys.argv[2], encoding="utf-8") if l.strip()]
        j = json.load(open(sys.argv[3]))
        report(cases, j["results"] if isinstance(j, dict) else j)
        sys.exit(0)
    ap = argparse.ArgumentParser()
    ap.add_argument("--cases", required=True); ap.add_argument("--url", required=True); ap.add_argument("--json", required=True)
    ap.add_argument("--model", default="x"); ap.add_argument("--guard", choices=["none", "A"], default="A")
    ap.add_argument("--max-tokens", type=int, default=300); ap.add_argument("--temperature", type=float, default=0.0)
    ap.add_argument("--timeout", type=float, default=600)
    a = ap.parse_args()
    a.mode, a.system_extra, a.example = "closed", "", False
    run(a)
