#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Experiment E-SC2: replay REAL labelled traffic (IoT-23) through the evidence compiler.

Dataset: IoT-23, Stratosphere Lab / Avast-AIC (Garcia, Parmisano, Erquiaga, 2020), CC BY 4.0,
https://zenodo.org/records/4743746 . Only the Zeek `conn.log.labeled` files are used. The data is NOT
committed to this repository; pass the extraction directory on the command line.

Method (fixed BEFORE looking at results):
  * Scenarios are split dev/test by a hash of the scenario name (about one third dev). The compressor
    may be changed only on evidence from DEV scenarios; reported numbers come from TEST scenarios.
  * A window = 60 minutes of one scenario. Up to --windows-per-scenario windows are sampled per
    scenario: those containing malicious flows, plus benign-only windows.
  * An incident = (window, source host, detailed-label family) with >= 1 malicious flow.
  * IoT-23 has no IDS detections and its labelled logs have no DNS names. Cards are therefore built
    from BEHAVIOUR ONLY (no `det=` merge, no DNS cards) -- a harder test than E-SC1.
  * Identity recall: the incident's source appears on one card line together with a behavioural flag
    (fan-out / periodic / volume / failure rate) or, for single-destination families, its destination.
    Evidence recall: the flag matches the family (scan -> fan-out, heartbeat -> periodic, DDoS ->
    count/volume).  Benign windows: count cards that carry any flag (false signals).

Usage: python3 -I replay_iot23.py <iot23 dir> [--split test|dev|all] [--budgets 256,512,1024]
"""
import argparse
import collections
import glob
import hashlib
import json
import os
import random
import re
import statistics
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import semantic_compression as sc  # noqa: E402

FAMILY = [  # (regex on detailed-label, family)
    (r"PortScan", "scan"),
    (r"HeartBeat", "heartbeat"),
    (r"DDoS|Attack", "flood"),
    (r"FileDownload", "download"),
    (r"C&C", "c2"),
    (r"Okiru|Mirai|Torii", "malware"),
]


def family(detailed):
    for rx, f in FAMILY:
        if re.search(rx, detailed):
            return f
    return "other"


def split_of(name):
    return "dev" if int(hashlib.sha256(name.encode()).hexdigest(), 16) % 3 == 0 else "test"


def read_conn(path, max_rows):
    """Zeek conn.log.labeled -> list of (ts, src, dst, dport, proto, ob, rb, state, label, detailed)."""
    fields, rows = None, []
    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            if line.startswith("#fields"):
                fields = line.rstrip("\n").split("\t")[1:]
                continue
            if line.startswith("#") or not fields:
                continue
            parts = line.rstrip("\n").split("\t")
            # the last Zeek column holds "tunnel_parents   label   detailed-label" separated by 3 spaces
            tail = re.split(r"\s{2,}", parts[-1].strip())
            label = tail[1] if len(tail) > 1 else "-"
            detailed = tail[2] if len(tail) > 2 else "-"
            d = dict(zip(fields, parts))
            try:
                ts = float(d["ts"])
                ob = int(d.get("orig_bytes", "0")) if d.get("orig_bytes", "-") not in ("-", "") else 0
                rb = int(d.get("resp_bytes", "0")) if d.get("resp_bytes", "-") not in ("-", "") else 0
            except (KeyError, ValueError):
                continue
            rows.append((ts, d.get("id.orig_h", ""), d.get("id.resp_h", ""), int(d.get("id.resp_p", "0") or 0),
                         d.get("proto", ""), ob, rb, d.get("conn_state", ""), label, detailed))
            if len(rows) >= max_rows:
                break
    return rows


def to_events(rows, t0):
    ev = []
    for ts, src, dst, dport, proto, ob, rb, state, label, det in rows:
        rel = ts - t0
        h, m, s = int(rel // 3600) % 24, int(rel // 60) % 60, rel % 60
        st = "rst" if state in ("REJ", "RSTO", "RSTR", "RSTOS0", "RSTRH", "S0", "SH") else "est"
        ev.append({"type": "flow", "ts": "2020-01-01T%02d:%02d:%06.3fZ" % (h, m, s), "src_ip": src, "dst_ip": dst,
                   "dst_port": dport, "proto": proto, "bytes_out": ob, "bytes_in": rb, "state": st})
    return ev


SIGNAL = {"scan": ["fanout_ports", "fanout_hosts"], "heartbeat": ["periodic"], "flood": ["fanout_hosts", "out=", "rst="],
          "download": [], "c2": ["periodic"], "malware": [], "other": []}
ANY_FLAG = ["fanout_ports", "fanout_hosts", "periodic", "out=", "rst="]


def expand(lines):
    legend = {}
    for l in lines:
        for a, v in re.findall(r"\b([HRD]\d+)=([0-9A-Za-z.\-:]+)", l):
            legend[a] = v
    out = []
    for l in lines:
        l = re.sub(r"\b([HRD]\d+)=([0-9A-Za-z.\-:]+)", r"\2", l)  # inline definition -> the address itself
        out.append(re.sub(r"\b([HRD]\d+)\b", lambda m: legend.get(m.group(1), m.group(1)), l))
    return out


def score_window(lines, incidents):
    exp = expand(lines)
    ident = evid = 0
    for (src, fam), dsts in incidents.items():
        hit_i = hit_e = False
        for l in exp:
            m = re.match(r"^F\d+ (\S+?)(->| dns )", l)
            if not m or m.group(1) != src:
                continue
            flagged = any(k in l for k in ANY_FLAG)
            single_dst = len(dsts) <= 3 and any(d in l for d in dsts)
            if flagged or single_dst:
                hit_i = True
                if not SIGNAL[fam] or any(k in l for k in SIGNAL[fam]):
                    hit_e = True
            if hit_e:
                break
        ident += hit_i
        evid += hit_e
    return ident, evid


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("root")
    ap.add_argument("--split", default="test", choices=["test", "dev", "all"])
    ap.add_argument("--budgets", default="256,512,1024,2048")
    ap.add_argument("--windows-per-scenario", type=int, default=6)
    ap.add_argument("--max-rows", type=int, default=1_500_000)
    ap.add_argument("--json")
    ap.add_argument("--show", type=int, default=0, help="print one rendered window at this budget")
    a = ap.parse_args()
    tok = sc.Tok()
    budgets = [int(x) for x in a.budgets.split(",")]
    files = sorted(glob.glob(os.path.join(a.root, "**", "conn.log.labeled"), recursive=True))
    agg = collections.defaultdict(lambda: [0, 0, 0])  # budget -> [incidents, identity hits, evidence hits]
    fam_agg = collections.defaultdict(lambda: [0, 0, 0])
    benign_flags = collections.defaultdict(list)
    raw_tokens, card_tokens, n_windows, scen_used, shown = [], [], 0, [], False
    rnd = random.Random(7)
    for path in files:
        name = path.split(os.sep)[-3] if len(path.split(os.sep)) >= 3 else path
        sp = split_of(name)
        if a.split != "all" and sp != a.split:
            continue
        rows = read_conn(path, a.max_rows)
        if not rows:
            continue
        rows.sort(key=lambda r: r[0])
        t0 = rows[0][0]
        buckets = collections.defaultdict(list)
        for r in rows:
            buckets[int((r[0] - t0) // 3600)].append(r)
        mal = [k for k, v in buckets.items() if any(x[8].lower().startswith("malicious") for x in v)]
        ben = [k for k, v in buckets.items() if k not in mal]
        pick = rnd.sample(mal, min(len(mal), a.windows_per_scenario)) + rnd.sample(ben, min(len(ben), 2))
        scen_used.append((name, sp, len(rows), len(mal), len(ben)))
        for k in pick:
            win = buckets[k]
            events = to_events(win, t0 + k * 3600)
            incidents = collections.defaultdict(set)
            for r in win:
                if r[8].lower().startswith("malicious"):
                    incidents[(r[1], family(r[9]))].add(r[2])
            base = {"pairs": set(), "suffixes": set()}  # no prior baseline in a replay (worst case for novelty)
            raw = sc.rep_raw(events)
            raw_tokens.append(tok.count("\n".join(raw[:4000])) * max(1, len(raw) / 4000.0))
            n_windows += 1
            for b in budgets:
                lines, used = sc.rendered_cards(events, base, b, tok)
                if b == budgets[-1]:
                    card_tokens.append(used)
                if a.show and b == a.show and incidents and not shown:
                    print("--- %s window %d (%d flows, %d incidents) @ %d ---" % (name, k, len(win), len(incidents), b))
                    print("\n".join(lines))
                    print("---")
                    shown = True
                if incidents:
                    i, e = score_window(lines, incidents)
                    agg[b][0] += len(incidents)
                    agg[b][1] += i
                    agg[b][2] += e
                    if b == 512:
                        for inc in incidents:
                            sub = {inc: incidents[inc]}
                            ii, ee = score_window(lines, sub)
                            fam_agg[inc[1]][0] += 1
                            fam_agg[inc[1]][1] += ii
                            fam_agg[inc[1]][2] += ee
                else:
                    benign_flags[b].append(sum(1 for l in lines if any(k in l for k in ANY_FLAG)))
    print("IoT-23 replay (CC BY 4.0) | split=%s | scenarios=%d | windows=%d | tokenizer: %s" % (
        a.split, len(scen_used), n_windows, tok.label()))
    for s in scen_used:
        print("  scenario %-40s %-4s flows=%-8d malicious_hours=%-4d benign_hours=%d" % s)
    if raw_tokens:
        print("raw window tokens (median, extrapolated past 4000 rows): %.0f" % statistics.median(raw_tokens))
    print("%7s %10s %10s %10s %22s" % ("budget", "incidents", "identity", "evidence", "flagged cards/benign win"))
    out = {"split": a.split, "scenarios": scen_used, "windows": n_windows, "rows": []}
    for b in budgets:
        n, i, e = agg[b]
        bf = benign_flags.get(b, [])
        print("%7d %10d %10.3f %10.3f %22s" % (b, n, i / max(1, n), e / max(1, n),
                                               ("%.1f (n=%d)" % (statistics.mean(bf), len(bf))) if bf else "-"))
        out["rows"].append({"budget": b, "incidents": n, "identity_recall": i / max(1, n), "evidence_recall": e / max(1, n),
                            "benign_windows": len(bf), "flagged_cards_per_benign_window": statistics.mean(bf) if bf else None})
    print("per family @512: " + "  ".join("%s %d/%d/%d" % (f, v[0], v[1], v[2]) for f, v in sorted(fam_agg.items())))
    out["per_family_512"] = {f: {"incidents": v[0], "identity": v[1], "evidence": v[2]} for f, v in fam_agg.items()}
    if a.json:
        with open(a.json, "w") as f:
            json.dump(out, f, indent=1)


if __name__ == "__main__":
    main()
