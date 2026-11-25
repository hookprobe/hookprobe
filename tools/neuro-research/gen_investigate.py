#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Doc 39 §3.3: investigation TRAINING cases from the playbooks (data/playbooks.json). Synthetic windows only (gen_t0
helpers: RFC 1918 / RFC 5737 addresses, .example names); no CVE id is ever written into a gold answer.

Per observable playbook, one card template (SIGN below) renders its "seen on the wire" sign. Case kinds:
  next      the sign alone -> gold = the playbook's FIRST step (tool + entity)
  multi     the sign + a RESULT line for step 1 -> gold = step 2
  clears    the sign + a RESULT line meeting the playbook's "clears" condition -> gold = stop (no call)
  invisible a window for a technique the gateway cannot see (T1003) -> gold = no call
  decoy     (v2, doc 42) an ordinary window with no detection that needs no investigation -> gold = no call
  v3 (doc 43, --version 3): multi = a DIFFERENT next tool after a supporting result, or a policy proposal once
            two results support it (doc 42 found v2 multi-step targets repeated step 1's tool)
  v5 (doc 49, --version 5): v4 plus v3's multi-step targets. v4 tested `version == 3` there, so its multi cases fell
            back to v2's (repeat a lookup; never a policy proposal).
  v4 (doc 44, --version 4): adds `alert` cases in the E2E L1-alert card shape (the card's shape decides the check:
            fan-out -> the device's flows; one remote -> its reputation), more decoy and invisible cases, and
            invisible gold = no tool only
Usage: gen_investigate.py --playbooks data/playbooks.json --n 600 --seed 39 --out inv.jsonl [--ro 0.10]
"""
import argparse, hashlib, json, os, random, sys
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import gen_t0 as g  # noqa: E402

Q_EN = ["What should be checked next?", "Which single step would you take now?", "Investigate: what is the next check?"]
Q_RO = ["Ce ar trebui verificat în continuare?", "Care este următorul pas al investigației?"]
ROLE = {"router": "router", "edge": "VPN gateway", "nas": "NAS", "camera": "IP camera", "printer": "printer",
        "server": "home server", "workstation": "work laptop", "phone": "phone", "media": "media box", "all": "smart TV"}


def sign(tid, w, r, H, R):
    """One card for the playbook's main observable sign. Returns the alias the first step should target."""
    h, rr = H.split("=")[0], R.split("=")[0]
    if tid == "T1190":
        w.card("%s->%s:443 n=%d novel inbound_sources=%d det=signature[T1190,sev2,PASS, observe]" % (R, H, r.randrange(40, 400), r.randrange(20, 90)))
        return h
    if tid == "T1133":
        w.card("%s->%s:%d n=%d novel det=behaviour_change[T1133,sev3,PASS, observe]" % (R, H, r.choice([1194, 51820, 443]), r.randrange(2, 9)))
        w.ctx_lines.append("CONTEXT the remote session came from a network never seen before")
        return h
    if tid == "T1110":
        w.card("%s->%s:%d n=%d fail=%d%% det=brute_force[T1110,sev2,PASS, ratelimit]" % (R, H, r.choice([22, 23, 3389]), r.randrange(200, 3000), r.randrange(90, 100)))
        return h
    if tid == "T1203":
        D = w.ref("D", "%s.example" % r.choice(["doc-share", "invoice-view", "free-codec"]))
        w.card("%s dns %s n=1 novel" % (H, D))
        w.card("%s->%s:443 n=%d periodic=%ds cv=0.0%d novel det=beaconing[T1071,sev3,PASS, observe]" % (h, R, r.randrange(60, 400), r.choice([60, 300]), r.randrange(1, 5)))
        return h
    if tid == "T1105":
        w.card("%s->%s:%d n=%d in=%dKB novel det=behaviour_change[T1105,sev2,PASS, observe]" % (H, R, r.choice([80, 8080, 4444]), r.randrange(1, 4), r.randrange(40, 900)))
        return rr
    if tid == "T1071":
        w.card("%s->%s:443 n=%d periodic=%ds cv=0.0%d novel det=beaconing[T1071,sev3,PASS, observe]" % (H, R, r.randrange(300, 2000), r.choice([60, 300, 600]), r.randrange(1, 4)))
        return rr
    if tid == "T1568.002":
        D = w.ref("D", "%s.example" % "".join(r.choice("qwxzkjvbn") for _ in range(12)))
        w.card("%s dns %s n=%d nxdomain=%d/%d distinct=%d label_entropy=3.%d det=dns_dga[T1568.002,sev2,PASS, observe]" % (
            H, D, r.randrange(150, 600), r.randrange(140, 150), 150, r.randrange(120, 300), r.randrange(6, 9)))
        return h
    if tid == "T1505.003":
        w.card("%s->%s:443 n=%d novel det=behaviour_change[T1505.003,sev2,PASS, observe]" % (R, H, r.randrange(5, 40)))
        w.ctx_lines.append("CONTEXT %s now also connects out to peers it never used" % h)
        return h
    if tid == "T1496":
        w.card("%s->%s:%d n=%d dur=%dh novel det=behaviour_change[T1496,sev3,PASS, observe]" % (H, R, r.choice([3333, 4444, 14444]), r.randrange(1, 4), r.randrange(4, 20)))
        return rr
    if tid == "T1046":
        w.card("%s->*:%d n=%d fanout_hosts=%d fail=%d%% novel det=port_scan[T1046,sev2,PASS, observe]" % (H, r.choice([23, 2323, 22]), r.randrange(500, 4000), r.randrange(200, 900), r.randrange(80, 99)))
        return h
    if tid == "T1498":
        w.card("%s->%s:%d n=%d out=%.1fGB novel det=behaviour_change[T1498,sev2,PASS, ratelimit]" % (H, R, r.choice([80, 53, 123]), r.randrange(20000, 90000), r.randrange(10, 60) / 10))
        return h
    if tid == "T1048":
        w.card("%s->%s:443 n=%d out=%.1fGB novel det=exfiltration[T1048,sev2,PASS, observe]" % (H, R, r.randrange(20, 200), r.randrange(10, 80) / 10))
        return rr
    if tid == "T1572":
        w.card("%s->%s:53 n=%d out=%dMB novel det=dns_bypass[T1572,sev3,PASS, observe]" % (H, R, r.randrange(500, 5000), r.randrange(20, 300)))
        return h
    if tid == "T1021":
        N = w.ref("H", g.ip_lan(r))
        w.card("%s->%s:445 n=%d novel det=lateral_movement[T1021,sev2,PASS, observe]" % (H, N, r.randrange(20, 300)))
        return h
    if tid == "T1090":
        w.card("%s->* n=%d remotes=%d countries=%d novel det=behaviour_change[T1090,sev3,PASS, observe]" % (H, r.randrange(2000, 9000), r.randrange(300, 2000), r.randrange(15, 60)))
        return h
    raise KeyError(tid)


RESULT = {  # (step-1 result that SUPPORTS going on, step-1 result that CLEARS)
    "lookup_reputation": ("listed on two threat feeds as malware infrastructure", "the device maker's own cloud service, not on any feed"),
    "query_flows": ("the device began new outbound connections right after this", "no change in the device's own outbound behaviour"),
    "query_dns": ("random-looking names, one resolved and was contacted", "names of a known content network, all resolved normally"),
    "lookup_exposure": ("class matches devices often attacked through this service", "class unknown; no exposure stated"),
}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--playbooks", required=True); ap.add_argument("--n", type=int, default=600); ap.add_argument("--seed", type=int, default=39)
    ap.add_argument("--ro", type=float, default=0.10); ap.add_argument("--out", required=True); ap.add_argument("--id-prefix", default="inv")
    ap.add_argument("--v1", action="store_true", help="doc 41 version: no decoy kind (reproduces the P3 output)")
    ap.add_argument("--version", type=int, choices=[2, 3, 4, 5], default=2,
                    help="2 = doc 42 (default, reproduces its output); 3 = doc 43: multi-step targets MOVE ON; "
                         "5 = doc 49: v4's mix with v3's multi-step targets")
    a = ap.parse_args()
    pbs = [p for p in json.load(open(a.playbooks))["playbooks"]]
    obs = [p for p in pbs if p["observable"]]
    blind = [p for p in pbs if not p["observable"]]
    r = random.Random(a.seed)
    out, seen = [], set()
    kinds = ["next"] * 4 + ["multi"] * 3 + ["clears"] * 2 + ["invisible"] + ([] if a.v1 else ["decoy"] * 2)
    if a.version >= 4:   # doc 44: the L1-alert card shape, and more decoy / invisible cases
        kinds = ["next"] * 4 + ["multi"] * 3 + ["clears"] * 2 + ["invisible"] * 2 + ["decoy"] * 3 + ["alert"] * 3
    while len(out) < a.n:
        kind = r.choice(kinds)
        ro = r.random() < a.ro
        w = g.Win(r)
        H, R = w.ref("H", g.ip_lan(r)), w.ref("R", g.ip_wan(r))
        if kind == "alert":
            # doc 44: the device's generic L1 alert, exactly as the E2E harness renders it (no category, no technique);
            # the card's SHAPE decides the check: fan-out -> the device's flows; one remote -> its reputation
            ALERT = "det=behaviour_change[-,sev2,alert, l1]"
            w.ctx_lines.append("CONTEXT %s is the %s" % (H.split("=")[0], r.choice(list(ROLE.values()))))
            shape = r.choice(["scan", "brute", "beacon", "upload", "proxy"])
            if shape == "scan":
                port = r.choice([23, 2323, 22, 445, 5555])
                w.card("%s->*:%d n=%d fanout_hosts=%d fail=%d%% %s" % (H, port, r.randrange(400, 4000), r.randrange(300, 3000), r.randrange(70, 98), ALERT))
                gold = {"kind": "alert", "tools": ["query_flows"], "entities": [H.split("=")[0]], "technique": "alert-scan"}
            elif shape == "brute":
                w.card("%s->%s:%d n=%d periodic=%ds cv=0.0%d novel %s" % (H, R, r.choice([22, 23, 3389]), r.randrange(200, 2000), r.choice([2, 4, 6, 10]), r.randrange(0, 5), ALERT))
                gold = {"kind": "alert", "tools": ["lookup_reputation"], "entities": [R.split("=")[0]], "technique": "alert-brute"}
            elif shape == "beacon":
                w.card("%s->%s:443 n=%d periodic=%ds cv=0.0%d novel %s" % (H, R, r.randrange(60, 900), r.choice([60, 300, 600]), r.randrange(1, 5), ALERT))
                gold = {"kind": "alert", "tools": ["lookup_reputation"], "entities": [R.split("=")[0]], "technique": "alert-beacon"}
            elif shape == "upload":
                w.card("%s->%s:443 n=%d out=%.1fGB novel %s" % (H, R, r.randrange(20, 300), r.randrange(5, 60) / 10, ALERT))
                gold = {"kind": "alert", "tools": ["lookup_reputation"], "entities": [R.split("=")[0]], "technique": "alert-upload"}
            else:
                w.card("%s->* n=%d remotes=%d countries=%d %s" % (H, r.randrange(2000, 9000), r.randrange(300, 2000), r.randrange(15, 60), ALERT))
                gold = {"kind": "alert", "tools": ["query_flows"], "entities": [H.split("=")[0]], "technique": "alert-proxy"}
            for _ in range(r.choice([0, 1, 2])):
                g.distractor(w)
        elif kind == "decoy":
            w.card("%s->%s:443 n=%d out=%dKB" % (H, R, r.randrange(3, 80), r.randrange(5, 400)))   # ordinary, no detection
            w.ctx_lines.append("CONTEXT %s is the %s" % (H.split("=")[0], r.choice(list(ROLE.values()))))
            for _ in range(r.choice([1, 2, 3])):
                g.distractor(w)
            gold = {"kind": "decoy", "tools": [None], "entities": [], "technique": "-"}
        elif kind == "invisible":
            p = r.choice(blind)
            w.card("%s->%s:445 n=%d" % (H, w.ref("H", g.ip_lan(r)), r.randrange(3, 30)))
            w.ctx_lines.append("CONTEXT owner: I think someone stole the passwords stored on %s" % H.split("=")[0])
            gold = {"kind": "invisible", "tools": [None] if a.version >= 4 else [None, "query_flows"], "entities": [H.split("=")[0]], "technique": p["id"]}
        else:
            p = r.choice(obs)
            cls = r.choice(p["classes"])
            w.ctx_lines.append("CONTEXT %s is the %s" % (H.split("=")[0], ROLE.get(cls, "device")))
            tgt = sign(p["id"], w, r, H, R)
            steps = p["next"]
            if kind == "next":
                st = steps[0]
                ents = [tgt] if st["tool"] != "lookup_exposure" else [H.split("=")[0]]
                gold = {"kind": "next", "tools": [st["tool"]], "entities": ents, "technique": p["id"]}
            else:
                st = steps[0]
                res = RESULT[st["tool"]][0 if kind == "multi" else 1]
                w.ctx_lines.append("RESULT %s %s: %s" % (st["tool"], tgt if st["tool"] != "lookup_exposure" else H.split("=")[0], res))
                if kind == "multi" and a.version in (3, 5):   # doc 49: v4 had dropped this branch (== 3 only)
                    # doc 43: after a supporting result the next check is a DIFFERENT tool; once two results support
                    # it, the case is conclusive and the step is a policy proposal (doc 42's multi-step template gap)
                    other = [x for x in steps[1:] if x["tool"] != st["tool"]]
                    if other and r.random() < 0.5:
                        gold = {"kind": "multi", "tools": [other[0]["tool"]], "entities": [tgt, H.split("=")[0]], "technique": p["id"]}
                    else:
                        if other:
                            t2 = other[0]["tool"]
                            w.ctx_lines.append("RESULT %s %s: %s" % (t2, tgt if t2 != "lookup_exposure" else H.split("=")[0], RESULT[t2][0]))
                        gold = {"kind": "multi", "tools": ["propose_policy_change"], "entities": [H.split("=")[0]],
                                "policies": ["isolated", "internet_only"], "technique": p["id"]}
                elif kind == "multi" and len(steps) > 1:
                    st2 = steps[1]
                    gold = {"kind": "multi", "tools": [st2["tool"]], "entities": [tgt, H.split("=")[0]], "technique": p["id"]}
                elif kind == "multi":
                    gold = {"kind": "multi", "tools": ["propose_policy_change"], "entities": [H.split("=")[0]],
                            "policies": ["isolated", "internet_only"], "technique": p["id"]}
                else:
                    gold = {"kind": "clears", "tools": [None], "entities": [], "technique": p["id"]}
        ctx = w.render()
        h = hashlib.sha256(" ".join(ctx.split()).lower().encode()).hexdigest()
        if h in seen:
            continue
        seen.add(h)
        out.append({"id": "%s-%05d" % (a.id_prefix, len(out)), "lang": "ro" if ro else "en", "task": "investigate", "context": ctx,
                    "question": r.choice(Q_RO if ro else Q_EN), "gold": gold})
    with open(a.out, "w", encoding="utf-8") as f:
        for c in out:
            f.write(json.dumps(c, ensure_ascii=False) + "\n")
    import collections
    print("wrote %d investigation cases; kinds %s; techniques %d" % (
        len(out), dict(collections.Counter(c["gold"]["kind"] for c in out)), len({c["gold"]["technique"] for c in out})))


if __name__ == "__main__":
    main()
