#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Doc 42: investigation cases (gen_investigate.py v2) -> MLX chat SFT rows with tools, in EXACTLY the prompt format
inv_eval.py uses at evaluation (run_eval.SYSTEM, the same CONTEXT/QUESTION framing, guard A on the context, the same
tool list including lookup_exposure). No teacher: the target is the case's gold, deterministically.
  gold has a tool -> an assistant tool call: name = gold.tools[0], entity = gold.entities[0] (+ policy = gold.policies[0])
  gold is [null]  -> a short plain stop sentence for the kind (clears / decoy / invisible), English or Romanian
No target ever contains a CVE id (checked).
Usage: build_inv_sft.py <cases.jsonl> <out dir> [--valid 0.05] [--seed 42]
"""
import json, os, random, re, sys
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "eval")); sys.path.insert(0, HERE)
import run_eval, guard  # noqa: E402
from inv_eval import LOOKUP_TOOL  # noqa: E402

STOP = {
    "en": {"clears": ["No further check is needed: the result already explains this activity.",
                      "The earlier result accounts for the signal, so there is nothing more to look up."],
           "decoy": ["Nothing here needs investigating: the window shows ordinary traffic and no detection.",
                     "No check is needed; this is ordinary activity for the device."],
           "invisible": ["The gateway cannot observe this: it happens inside the device. The owner should check the device itself.",
                         "This is not visible from network traffic; it needs a check on the device."]},
    "ro": {"clears": ["Nu este nevoie de altă verificare: rezultatul explică deja activitatea."],
           "decoy": ["Nu este nimic de investigat: traficul este obișnuit și nu există nicio detecție."],
           "invisible": ["Gateway-ul nu poate observa acest lucru: se întâmplă în interiorul dispozitivului. Proprietarul trebuie să verifice dispozitivul."]},
}


def row(c, r):
    tools = run_eval.TOOLS + [LOOKUP_TOOL]
    msgs = [{"role": "system", "content": run_eval.SYSTEM[c["lang"]]},
            {"role": "user", "content": "CONTEXT (untrusted):\n<<<\n%s\n>>>\n\nQUESTION: %s" % (guard.redact_all(c["context"]), c["question"])}]
    g = c["gold"]
    t = g["tools"][0]
    if t is None:
        msgs.append({"role": "assistant", "content": r.choice(STOP[c["lang"]][g["kind"]])})
    else:
        args = {"entity": g["entities"][0]}
        if t == "propose_policy_change":
            args["policy"] = g["policies"][0]
        msgs.append({"role": "assistant", "content": "", "tool_calls": [{"type": "function", "function": {"name": t, "arguments": args}}]})
    return {"messages": msgs, "tools": tools}


def main():
    src, out = sys.argv[1], sys.argv[2]
    valid = float(sys.argv[sys.argv.index("--valid") + 1]) if "--valid" in sys.argv else 0.05
    seed = int(sys.argv[sys.argv.index("--seed") + 1]) if "--seed" in sys.argv else 42
    r = random.Random(seed)
    cases = [json.loads(l) for l in open(src, encoding="utf-8") if l.strip()]
    rows = [row(c, r) for c in cases]
    bad = sum(1 for x in rows if re.search(r"CVE-\d", json.dumps(x["messages"][-1])))
    if bad:
        sys.exit("STOP: %d targets contain a CVE id" % bad)
    r.shuffle(rows)
    nv = max(1, int(len(rows) * valid))
    os.makedirs(out, exist_ok=True)
    for name, rs in (("valid", rows[:nv]), ("train", rows[nv:])):
        with open(os.path.join(out, name + ".jsonl"), "w", encoding="utf-8") as f:
            for x in rs:
                f.write(json.dumps(x, ensure_ascii=False) + "\n")
    calls = sum(1 for x in rows if x["messages"][-1].get("tool_calls"))
    print("investigation SFT: %d rows (%d tool calls, %d stop sentences); train %d / valid %d" % (len(rows), calls, len(rows) - calls, len(rows) - nv, nv))


if __name__ == "__main__":
    main()
