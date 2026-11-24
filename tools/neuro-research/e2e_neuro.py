#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Neuro end to end, on real captures: capture -> DNA -> S1 decision -> evidence cards -> explainer answer.
Operator rule (2026-11-24): every Neuro change is followed by this test, reporting cost per stage and output validity.

Stages (all timed; peak RSS of this process reported after each):
  A  capture -> device-hour DNA vectors: bench/pcap_to_dna.one (doc 20 rule, auto device MACs), unchanged. Its
     aggregator is wrapped so the SAME per-window flow events are kept for stage C.
  B  frozen S1 decision on every window with >= 3 events (bench/s1_apply.load_model, hash-checked).
  C  evidence cards: the device's compressor (semantic_compression.rendered_cards, 512-token budget) on every S1 alert
     plus a seeded sample of quiet windows. Flow events only: pcap_to_dna does not keep DNS questions.
  D  explainer: written as run_eval cases; the model run is done by e2e_neuro.sh (llama-server + run_eval, guard A),
     then guard E (guard_offline.py) and rule T (l0_thin.py) are applied and scored here (`--score`).
  E  lookup_exposure latency, if exposure.py is present (doc 39 P3).
Traffic is BENIGN (spent UNSW-IoTraffic); there is no unsealed malicious capture on this machine. So S1 alerts here
are false alerts, and the explainer's verdict on them is measured for calm wording, not for recall.
Usage: e2e_neuro.py build <out dir> <pcap>... [--sample 20] [--seed 7]
       e2e_neuro.py score <out dir> <run_eval AE json>
"""
import collections, json, os, random, re, resource, sys, time
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE); sys.path.insert(0, os.path.join(HERE, "bench")); sys.path.insert(0, os.path.join(HERE, "eval"))

LOOKUP = os.path.expanduser("~/.cache/hookprobe-intel-data/builds/lookup-1c5144faa881")


def rss_mb():
    r = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    return r / (1024 * 1024) if sys.platform == "darwin" else r / 1024


def build(out, pcaps, sample, seed):
    import pcap_to_dna as pd
    import unsw_to_d1 as u
    from dna_features import Agg
    import s1_apply, semantic_compression as sc
    os.makedirs(out, exist_ok=True)
    rep = collections.OrderedDict()
    kept = {}

    kept_host = {}

    class Rec(Agg):                        # same aggregator, plus a copy of the window's flow events for stage C
        def add(self, j):
            kept[self.meta["window_id"]] = (j["events"], [tuple(p) for p in j["baseline"]["pairs"]])
            kept_host[self.meta["window_id"]] = self.meta["host"]
            return Agg.add(self, j)
    pd.Agg = Rec

    # ---- A
    t = time.time(); frames = 0; vecs = []
    for p in pcaps:
        dev, exc, nf, lts = pd.find_devices(p)[1:]
        frames += nf
        for mac in dev:
            name, rows, err = pd.one((p, mac, LOOKUP, "doc20", None, "e2e"))
            if err:
                sys.exit("STOP: %s %s" % (name, err))
            vecs += rows
    tA = time.time() - t
    rep["A capture->DNA"] = dict(pcaps=len(pcaps), frames=frames, windows=len(vecs), seconds=round(tA, 2),
                                frames_per_s=round(frames / tA), ms_per_window=round(1000 * tA / max(1, len(vecs)), 2),
                                peak_rss_mb=round(rss_mb(), 1))
    # ---- B
    alert = s1_apply.load_model()
    scored = [v for v in vecs if v.get("n_events", 0) >= 3]
    t = time.time(); dec = {v["window_id"]: alert(v["x"]) for v in scored}; tB = time.time() - t
    devs = {v["window_id"].rsplit("|", 1)[0] for v in scored}
    n_al = sum(dec.values())
    rep["B S1 decision"] = dict(windows_scored=len(scored), devices=len(devs), alerts=n_al,
                                alerts_per_device_day=round(24 * n_al / max(1, len(scored)), 3),
                                us_per_window=round(1e6 * tB / max(1, len(scored)), 1), peak_rss_mb=round(rss_mb(), 1))
    json.dump(sorted(w for w, a in dec.items() if a), open(os.path.join(out, "alert_windows.json"), "w"))
    # ---- C
    r = random.Random(seed)
    quiet = sorted(w for w, a in dec.items() if not a)
    pick = sorted(w for w, a in dec.items() if a) + sorted(r.sample(quiet, min(sample, len(quiet))))
    tok = sc.Tok(); cases = []; toks = []
    t = time.time()
    for w in pick:
        evs, pairs = kept[w]
        # compressor states are est / rst / fin; only rst counts as a failure. No reply (S0) and reset (REJ) both fail.
        st = {"S0": "rst", "REJ": "rst", "SF": "fin"}
        ev2 = sorted((dict(e, state=st.get(e.get("conn_state"), "fin")) for e in evs), key=lambda e: e["ts"])
        if dec[w]:
            # the L1 alert reaches the explainer as a detection on the window, as it would on the device: attached to
            # the device's most-contacted peer and (dst_port 0) to its fan-out cards
            host = kept_host.get(w, "")
            import ipaddress
            pub = lambda x: (not u.is_local(ipaddress.ip_address(x).packed)) if re.match(r"^[\d.]+$", x or "") else False
            peers = collections.Counter(e["dst_ip"] for e in evs if e["src_ip"] == host and pub(e["dst_ip"]))
            ev2.append({"type": "detection", "id": "det:l1:%d" % len(cases), "ts": ev2[0]["ts"] if ev2 else "", "rule_id": 9100001,
                        "rule_msg": "L1 behaviour model alert (alert, l1)", "category": "behaviour_change", "severity": 2,
                        "mitre": None, "src_ip": host, "dst_ip": peers.most_common(1)[0][0] if peers else "", "dst_port": 0,
                        "confidence": 70})
        cards, residual, _ = sc.rep_cards(ev2, {"pairs": set(pairs), "suffixes": set()})
        lines, used = sc.fill(cards, 512, tok, residual)
        if len(lines) == len(cards):          # nothing dropped: still end with the REST line, as the device does
            lines = lines + [residual([])]
            used = tok.count("\n".join(lines))
        toks.append(used)
        cases.append({"id": ("alert-" if dec[w] else "quiet-") + str(len(cases)), "window": w, "lang": "en", "task": "triage",
                      "context": "\n".join(lines), "question": "Assess this window.",
                      "gold": {"verdict": ["malicious", "suspicious", "benign", "insufficient_evidence"], "evidence": [],
                               "entities": [], "must_mention_any": [], "next_step": ["observe", "investigate", "harden", "isolate_review"]}})
    tC = time.time() - t
    rep["C cards"] = dict(windows=len(cases), alerts=sum(c["id"].startswith("alert") for c in cases),
                          ms_per_window=round(1000 * tC / max(1, len(cases)), 1), tokens_mean=round(sum(toks) / max(1, len(toks)), 1),
                          tokens_max=max(toks) if toks else 0, tokenizer=tok.label(), peak_rss_mb=round(rss_mb(), 1))
    json.dump({c["id"]: c["window"] for c in cases}, open(os.path.join(out, "case_windows.json"), "w"))
    with open(os.path.join(out, "cases.jsonl"), "w") as f:
        for c in cases:
            f.write(json.dumps({k: v for k, v in c.items() if k != "window"}) + "\n")
    # ---- E
    try:
        import exposure
        t = time.time()
        for cl in ("router", "nas", "camera", "printer", "workstation", "phone") * 50:
            exposure.render("H1", exposure.lookup(cl, None))
        rep["E lookup_exposure"] = dict(calls=300, us_per_call=round(1e6 * (time.time() - t) / 300, 1))
    except ImportError:
        rep["E lookup_exposure"] = "not present on this branch (doc 39 P3)"
    json.dump(rep, open(os.path.join(out, "stages_ABCE.json"), "w"), indent=1)
    print(json.dumps(rep, indent=1))


def score(out, run_path):
    import run_eval, l0_thin
    cases = {json.loads(l)["id"]: json.loads(l) for l in open(os.path.join(out, "cases.jsonl"))}
    run = json.load(open(run_path)); rows = run["results"] if isinstance(run, dict) else run
    lat, pps, ppn, gen, ok = [], [], [], [], collections.Counter()
    verdict = collections.defaultdict(collections.Counter)
    for r in rows:
        c = cases[r["id"]]; o = r["outputs"][0]
        if o.get("_latency_s"): lat.append(o["_latency_s"])
        tm = o.get("_timings") or {}
        if tm.get("predicted_per_second"): gen.append(tm["predicted_per_second"])
        if tm.get("prompt_per_second"): pps.append(tm["prompt_per_second"])
        if tm.get("prompt_n"): ppn.append(tm["prompt_n"])
        s = run_eval.score(c, o)
        for k in ("schema_ok", "citation_ok"):
            ok[k] += bool(s.get(k))
        ok["hallucination_free"] += not s.get("hallucinated_entities")
        ok["fallback"] += bool(o.get("_guard_fallback"))
        o2 = l0_thin.compose(c, o)
        ok["rule_T_fired"] += bool(o2.get("_l0_thin"))
        verdict[c["id"].split("-")[0]][o2.get("verdict")] += 1
    n = len(rows)
    q = lambda xs, p: sorted(xs)[min(len(xs) - 1, int(p * len(xs)))] if xs else None
    rep = dict(answers=n, latency_s_median=round(q(lat, .5), 2), latency_s_p90=round(q(lat, .9), 2),
               prompt_tokens_median=q(ppn, .5), prompt_tok_per_s_median=round(q(pps, .5), 1) if pps else None,
               gen_tok_per_s_median=round(q(gen, .5), 1) if gen else None,
               valid={k: "%d/%d" % (v, n) for k, v in ok.items()},
               verdicts={k: dict(v) for k, v in verdict.items()})
    man = os.environ.get("E2E_MANIFEST")
    if man and os.path.exists(os.path.join(out, "case_windows.json")):   # injected attacks: what S1 and the explainer did per hour
        m = json.load(open(man)); mac = ":".join(m["device_mac"][i:i + 2] for i in range(0, 12, 2))
        cw = json.load(open(os.path.join(out, "case_windows.json")))
        al = set(json.load(open(os.path.join(out, "alert_windows.json"))))
        byw = {w: i for i, w in cw.items()}
        outs = {r["id"]: l0_thin.compose(cases[r["id"]], r["outputs"][0]) for r in rows}
        per = {}
        for h, kind in sorted(m["injected_hours"].items()):
            w = [x for x in al | set(cw.values()) if x.endswith("|%s|%s" % (mac, h))]
            w = w[0] if w else None
            o = outs.get(byw.get(w)) if w else None
            per[h] = dict(kind=kind, s1_alert=bool(w and w in al), explainer=(o or {}).get("verdict"),
                          summary=((o or {}).get("summary") or "")[:160])
        rep["injected"] = per
    json.dump(rep, open(os.path.join(out, "stage_D.json"), "w"), indent=1)
    print(json.dumps(rep, indent=1))


if __name__ == "__main__":
    if sys.argv[1] == "build":
        args = sys.argv[3:]
        smp = int(args[args.index("--sample") + 1]) if "--sample" in args else 20
        sd = int(args[args.index("--seed") + 1]) if "--seed" in args else 7
        pc = [x for x in args if x.endswith((".pcap", ".pcapng"))]
        build(sys.argv[2], pc, smp, sd)
    else:
        score(sys.argv[2], sys.argv[3])
