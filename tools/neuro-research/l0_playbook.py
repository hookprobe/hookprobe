#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Doc 52 Rule P, the reference: after a tool result, the next investigation step comes from the playbook, not the
model. The model keeps the first check and every explanation. Deterministic; reads data/playbooks.json only.

decide(playbook_id, done, aliases) -> {"tool": name, "args": {...}} | {"tool": None, "why": ...}
  done     list of (tool, outcome) already run, in order; outcome in {"supports", "clears", "none"}
  aliases  {"device": "H1", "remote": "R1", "name": "D1"} as far as the window defines them
Rules (doc 52 §3), in order:
  1. any result clears it                     -> stop ("cleared")
  2. two results support it, or the playbook's
     last check supported it                  -> propose_policy_change(device, first `close` with a contract policy);
                                                 no such entry -> stop ("owner_action")
  3. otherwise                                -> the first playbook step not yet run (matched by tool, in order);
                                                 its entity from `on` (TARGET below); unknown target -> stop
  4. nothing left                             -> stop ("exhausted")
Usage: l0_playbook.py check      (self-test on fixed scenarios; exits 1 on a failure)
"""
import json, os, sys
HERE = os.path.dirname(os.path.abspath(__file__))
PB = os.path.join(HERE, "..", "..", "docs", "research", "neuro", "data", "playbooks.json")
POLICIES = ("isolated", "internet_only", "lan_only", "full_access")   # run_eval.py propose_policy_change enum
# `on` wording in playbooks.json -> which alias it means. Anything not listed returns no step (the model decides).
TARGET = {
    "the device": "device", "the targeted device": "device", "the server": "device", "the source device": "device",
    "the inbound sources": "remote", "the remote peers": "remote", "the sources": "remote", "the peer": "remote",
    "the download peer": "remote", "those sources": "remote", "the destination": "remote",
    "the outside server": "remote", "the coordinating peer": "remote", "the source if it is a LAN device": "remote",
    "those domains and addresses": "name", "the name that resolved and its address": "name",
}


def load(path=PB):
    return {p["id"]: p for p in json.load(open(path))["playbooks"] if p["observable"]}


PLAYBOOKS = load()


def decide(pid, done, aliases, playbooks=PLAYBOOKS):
    p = playbooks[pid]
    steps = p["next"]
    if any(o == "clears" for _, o in done):
        return {"tool": None, "why": "cleared"}
    supports = sum(1 for _, o in done if o == "supports")
    ran = []                                               # playbook step indices matched to the tools run, in order
    for tool, _ in done:
        idx = next((i for i, s in enumerate(steps) if i not in ran and s["tool"] == tool), None)
        if idx is not None:
            ran.append(idx)
    last_supported = bool(done) and done[-1][1] == "supports" and ran and ran[-1] == len(steps) - 1
    if supports >= 2 or last_supported:
        pol = next((c["proposal"] for c in p["close"] if c["proposal"] in POLICIES), None)
        if pol is None or "device" not in aliases:
            return {"tool": None, "why": "owner_action"}
        return {"tool": "propose_policy_change", "args": {"entity": aliases["device"], "policy": pol}}
    for i, s in enumerate(steps):
        if i in ran:
            continue
        who = TARGET.get(s["on"])
        if who is None or who not in aliases:
            return {"tool": None, "why": "unknown target: %s" % s["on"]}
        return {"tool": s["tool"], "args": {"entity": aliases[who]}}
    return {"tool": None, "why": "exhausted"}


def check():
    A = {"device": "H1", "remote": "R1", "name": "D1"}
    cases = [  # (playbook, done, expected tool, expected entity or why)
        ("T1071", [("lookup_reputation", "clears")], None, "cleared"),
        ("T1071", [("lookup_reputation", "supports")], "query_dns", "H1"),
        ("T1071", [("lookup_reputation", "supports"), ("query_dns", "supports")], "propose_policy_change", ("H1", "isolated")),
        ("T1071", [("lookup_reputation", "none")], "query_dns", "H1"),
        ("T1105", [("lookup_reputation", "supports"), ("query_flows", "supports")], "propose_policy_change", ("H1", "isolated")),
        ("T1105", [("lookup_reputation", "none"), ("query_flows", "supports")], "propose_policy_change", ("H1", "isolated")),
        ("T1110", [("query_flows", "supports"), ("lookup_reputation", "supports")], None, "owner_action"),
        ("T1046", [("query_flows", "supports")], "query_flows", "H1"),
        ("T1572", [("query_dns", "supports")], "lookup_reputation", "R1"),
        ("T1203", [("query_dns", "supports")], "lookup_reputation", "D1"),
        ("T1498", [("query_flows", "none"), ("query_flows", "none")], None, "exhausted"),
        ("T1021", [("query_flows", "supports")], None, "unknown target: each reached host"),
    ]
    bad = 0
    for pid, done, tool, exp in cases:
        d = decide(pid, done, A)
        ok = d["tool"] == tool and (d.get("why") == exp if tool is None else
                                    (d["args"]["entity"], d["args"]["policy"]) == exp if tool == "propose_policy_change"
                                    else d["args"]["entity"] == exp)
        bad += not ok
        print("%s %-10s %-62s -> %s" % ("ok  " if ok else "FAIL", pid, done, d))
    unknown = sorted({s["on"] for p in PLAYBOOKS.values() for s in p["next"]} - set(TARGET))
    print("playbook targets without a mapping (the model decides there): %s" % unknown)
    print("%d/%d scenarios as specified" % (len(cases) - bad, len(cases)))
    return bad == 0


if __name__ == "__main__":
    sys.exit(0 if check() else 1)
