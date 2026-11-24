#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Doc 41 §3: seal checks and the annotator sample for the investigation blind set. Prints ONLY counts, pass/fail and
the SHA-256, never case content.
Usage: inv_seal.py check  <cases> <other case files...>
       inv_seal.py sample <cases> <annotator dir>            (25% stratified: 38 cases, context + question only)
       inv_seal.py agree  <cases> <annotator dir>            (annotator labels.jsonl vs gold; writes agreement.json)
"""
import collections, hashlib, json, os, re, sys

MIX = {"next": 45, "multi": 35, "clears": 30, "decoy": 25, "invisible": 15}
PER = {"next": 11, "multi": 9, "clears": 8, "decoy": 6, "invisible": 4}            # 38 = 25%
TOOLS = {None, "lookup_reputation", "query_flows", "query_dns", "lookup_exposure", "propose_policy_change"}
POL = {"isolated", "internet_only", "lan_only", "full_access"}
RES = re.compile(r"^RESULT (\w+) ([HRD]\d+): .+$", re.M)
norm = lambda s: " ".join(s.split()).lower()


def load(p):
    return [json.loads(l) for l in open(p, encoding="utf-8") if l.strip()]


def check(path, others):
    cs, fail = load(path), []
    cnt, ro, ids = collections.Counter(), 0, set()
    for c in cs:
        if set(c) != {"id", "lang", "task", "context", "question", "gold"} or c["task"] != "investigate":
            fail.append("keys/task"); continue
        k = c["id"].split("-")[0]; cnt[k] += 1; ro += c["lang"] == "ro"
        if c["id"] in ids: fail.append("duplicate id")
        ids.add(c["id"])
        g = c["gold"]
        if g.get("kind") != k: fail.append("kind != id prefix")
        if not g.get("tools") or any(t not in TOOLS for t in g["tools"]): fail.append("tool enum")
        if "propose_policy_change" in g["tools"] and not set(g.get("policies") or []) <= POL: fail.append("policy enum")
        if "propose_policy_change" in g["tools"] and not g.get("policies"): fail.append("policy missing")
        if k in ("clears", "decoy") and g["tools"] != [None]: fail.append("clears/decoy gold not [null]")
        if k in ("next", "multi") and None in g["tools"]: fail.append("next/multi accepts null")
        for e in g.get("entities") or []:
            if not re.search(r"\b%s\b" % re.escape(e), c["context"]): fail.append("gold entity not in context")
        if re.search(r"CVE-\d", json.dumps(c), re.I): fail.append("CVE id present")
        for line in c["context"].splitlines():
            if line.startswith("RESULT") and (not RES.match(line) or RES.match(line).group(1) not in TOOLS - {None}):
                fail.append("RESULT line form")
        if not re.search(r"\b(192\.168|10\.|172\.(1[6-9]|2\d|3[01]))", c["context"]) and k != "invisible":
            pass
        for ip in re.findall(r"\b(\d+\.\d+\.\d+\.\d+)\b", c["context"]):
            a = list(map(int, ip.split(".")))
            ok = a[0] == 10 or (a[0] == 172 and 16 <= a[1] <= 31) or a[:2] == [192, 168] or a[:3] in ([192, 0, 2], [198, 51, 100], [203, 0, 113])
            if not ok: fail.append("address range")
        for d in re.findall(r"=([a-z0-9-]+(?:\.[a-z0-9-]+)+)\b", c["context"]):   # alias definitions: D1=name
            if not re.match(r"^[\d.]+$", d) and not d.endswith(".example"): fail.append("non-.example domain")
    hs = [hashlib.sha256(norm(c["context"]).encode()).hexdigest() for c in cs]
    if len(set(hs)) != len(hs): fail.append("duplicate contexts")
    coll = {}
    for p in others:
        if os.path.exists(p):
            oh = {hashlib.sha256(norm(json.loads(l)["context"]).encode()).hexdigest() for l in open(p, encoding="utf-8") if l.strip()}
            coll[os.path.basename(os.path.dirname(p)) + "/" + os.path.basename(p)] = len(set(hs) & oh)
        else:
            coll[p] = "MISSING"
    if any(v for v in coll.values() if v != 0): fail.append("collisions or missing comparison sets")
    if dict(cnt) != MIX: fail.append("mix %s" % dict(cnt))
    print("cases %d  mix %s  romanian %d (%.1f%%)" % (len(cs), dict(cnt), ro, 100 * ro / max(1, len(cs))))
    print("collisions %s" % coll)
    print("sha256 %s" % hashlib.sha256(open(path, "rb").read()).hexdigest())
    print("SEAL CHECKS: %s" % ("PASS" if not fail else "FAIL " + str(collections.Counter(fail))))


def pick(cs):
    by = collections.defaultdict(list)
    for c in cs:
        by[c["id"].split("-")[0]].append(c)
    out = []
    for k, n in PER.items():
        out += sorted(by[k], key=lambda c: hashlib.sha256(("ann|" + c["id"]).encode()).hexdigest())[:n]
    return out


if __name__ == "__main__":
    mode, path = sys.argv[1], sys.argv[2]
    if mode == "check":
        check(path, sys.argv[3:])
    elif mode == "sample":
        os.makedirs(sys.argv[3], exist_ok=True)
        with open(os.path.join(sys.argv[3], "sample.jsonl"), "w", encoding="utf-8") as f:
            for c in pick(load(path)):
                f.write(json.dumps({k: c[k] for k in ("id", "lang", "task", "context", "question")}, ensure_ascii=False) + "\n")
        print("sample: %d cases %s" % (sum(PER.values()), PER))
    else:
        sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
        from inv_eval import score
        lab = {json.loads(l)["id"]: json.loads(l) for l in open(os.path.join(sys.argv[3], "labels.jsonl"), encoding="utf-8") if l.strip()}
        ok, dis = 0, []
        sample = pick(load(path))
        for c in sample:
            L = lab.get(c["id"], {})
            s = score(c, {"tool": L.get("tool"), "args": L.get("args") or {}})
            ok += s["step_ok"]
            if not s["step_ok"]: dis.append({"id": c["id"], "annotator": L})
        print("agreement: %d/%d = %.3f" % (ok, len(sample), ok / len(sample)))
        json.dump({"agreement": ok / len(sample), "disagreements": dis}, open(os.path.join(sys.argv[3], "agreement.json"), "w"), indent=1)
        print("disagreements: %d (ids and the annotator's labels in agreement.json, for the author to adjudicate)" % len(dis))
