#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Reference fixture for neuro-l1: real (pseudonymised) dev windows -> per-connection records + the Python reference's
DNA v1 vector (tools/neuro-research/bench/dna_features.py, exactly as the benchmark computes it) -> the frozen S1
model's u8 quantisation, i32 accumulator and decision (tools/neuro-research/models/s1/s1_model.json).

Record lines (one per flow event, in file order):
  C t_us out peer lan port proto fail bytes_out bytes_in dur_us pkts novel
    t_us   : microseconds since the start of the UTC hour      out  : 1 if the host sent it (src_ip == host)
    peer   : u32 fingerprint of the peer address (sha256[:8])   lan  : 1 if the peer is a LAN address
    port   : destination port (65536 = none)                    proto: t/u/i/o
    fail   : 1 if conn_state is a failed state                  novel: 1 if (host, peer) is not in the 24 h baseline
Window lines: W <window_id> <n_events> <q0,...,q27> <acc> <alert 0/1>  (before its records)
  --stream writes the same line as "E ..." AFTER its records instead (one pass, constant memory; for huge windows)
Usage: python3 -I gen_fixture.py <out.txt> <windows build dir>... [--max-events N] [--per-build K] [--max-file-mb M] [--all]
"""
import argparse, hashlib, json, os, sys
HERE = os.path.dirname(os.path.abspath(__file__))
R = os.path.join(HERE, "..", "..", "..", "..", "tools", "neuro-research")
sys.path.insert(0, os.path.join(R, "bench"))
import dna_features as dna  # noqa: E402

M = json.load(open(os.path.join(R, "models", "s1", "s1_model.json")))
IDX = [dna.FEATURES.index(n) for n in M["features"]]
I = M["integer"]


def quantise(x):
    out = []
    for v, lo, rg in zip(x, I["lo"], I["range"]):
        q = round(255 * (v - lo) / rg)          # Python round = half-even, as numpy.rint in s1_freeze.py
        out.append(min(255, max(0, q)))
    return out


def fp(ip):
    return int(hashlib.sha256(ip.encode()).hexdigest()[:8], 16)


def t_us(ts):
    h, mi, s = int(ts[11:13]), int(ts[14:16]), ts[17:].rstrip("Z")
    whole, _, frac = s.partition(".")
    return (mi * 60 + int(whole)) * 1_000_000 + int((frac + "000000")[:6]), h


def records(host, baseline, events):
    out = []
    for e in events:
        if e.get("type") != "flow":
            continue
        o = e["src_ip"] == host
        peer = e["dst_ip"] if o else e["src_ip"]
        t, _ = t_us(e.get("ts", "T00:00:00"))
        port = e.get("dst_port") if o else None
        port = 65536 if port is None else int(port)
        pr = (e.get("proto") or "").lower()
        out.append("C %d %d %d %d %d %s %d %d %d %d %d %d" % (
            t, o, fp(peer), dna.lan(peer), port, {"tcp": "t", "udp": "u", "icmp": "i"}.get(pr, "o"),
            (e.get("conn_state") or "") in dna.FAIL, e.get("bytes_out") or 0, e.get("bytes_in") or 0,
            round((e.get("duration") or 0.0) * 1e6), e.get("orig_pkts") or 0, (o and (host, peer) not in baseline)))
    return out


def stream(a):
    nwin, done = 0, set()
    with open(a.out, "w") as o:
        for d in a.builds:
            files = sorted(x for x in os.listdir(d) if x.endswith(".jsonl") and os.path.getsize(os.path.join(d, x)) <= a.max_file_mb * 2 ** 20)
            for f in files:
                cur, ag, host, base, nflow = None, None, None, None, 0

                def flush():
                    nonlocal nwin
                    if cur is None:
                        return  # (an E line is written even for < 3 connections, so no record leaks into the next window)
                    x = [ag.vector()["x"][i] for i in IDX]
                    q = quantise(x)
                    acc = sum(wq * qq for wq, qq in zip(I["wq_i16"], q)) + I["bq_i32"]
                    o.write("E %s %d %s %d %d\n" % (cur.replace(" ", "_"), nflow, ",".join(map(str, q)), acc, acc > I["thr_q_i32"]))
                    nwin += 1
                for l in open(os.path.join(d, f), encoding="utf-8"):
                    j = json.loads(l)
                    if j["window_id"] != cur:
                        flush()
                        assert j["window_id"] not in done, "window chunks are not contiguous"
                        done.add(j["window_id"]); cur, host, nflow = j["window_id"], j["host"], 0
                        base = {tuple(p) for p in j.get("baseline", {}).get("pairs", [])}
                        ag = dna.Agg({"window_id": cur, "dataset": None, "capture": None, "host": host, "hour": None, "split": None})
                    ag.add({"events": j["events"], "baseline": {"pairs": [list(p) for p in base]}})
                    recs = records(host, base, j["events"]); nflow += len(recs)
                    if recs:
                        o.write("\n".join(recs) + "\n")
                flush()
    print("windows %d (stream)" % nwin)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("out"); ap.add_argument("builds", nargs="+")
    ap.add_argument("--max-events", type=int, default=2000); ap.add_argument("--per-build", type=int, default=80)
    ap.add_argument("--max-file-mb", type=float, default=1e9, help="skip capture files larger than this")
    ap.add_argument("--stream", action="store_true", help="every window, one pass, E line after the records")
    ap.add_argument("--all", action="store_true", help="every window with >= 3 events, no size cap (local check)")
    a = ap.parse_args()
    if a.stream:
        return stream(a)
    lines, nwin = [], 0
    for d in a.builds:
        files = sorted(x for x in os.listdir(d) if x.endswith(".jsonl") and os.path.getsize(os.path.join(d, x)) <= a.max_file_mb * 2 ** 20)
        # pass 1 (streaming, no events kept): flow count per window
        cnt = {}
        for f in files:
            for l in open(os.path.join(d, f), encoding="utf-8"):
                j = json.loads(l)
                cnt[j["window_id"]] = cnt.get(j["window_id"], 0) + sum(1 for e in j["events"] if e.get("type") == "flow")
        ok = [w for w, n in cnt.items() if n >= 3 and (a.all or n <= a.max_events)]
        ok.sort(key=lambda k: hashlib.sha256(k.encode()).hexdigest())
        chosen = set(ok if a.all else ok[:a.per_build])
        # pass 2: events of the chosen windows only
        wins = {}
        for f in files:
            for l in open(os.path.join(d, f), encoding="utf-8"):
                j = json.loads(l)
                if j["window_id"] not in chosen:
                    continue
                w = wins.setdefault(j["window_id"], {"host": j["host"], "baseline": None, "events": []})
                if w["baseline"] is None:
                    w["baseline"] = {tuple(p) for p in j.get("baseline", {}).get("pairs", [])}
                w["events"].extend(j["events"])
        for wid in sorted(wins, key=lambda k: hashlib.sha256(k.encode()).hexdigest()):
            w = wins[wid]
            nflow = sum(1 for e in w["events"] if e.get("type") == "flow")
            ag = dna.Agg({"window_id": wid, "dataset": None, "capture": None, "host": w["host"], "hour": None, "split": None})
            ag.add({"events": w["events"], "baseline": {"pairs": [list(p) for p in w["baseline"]]}})
            x = [ag.vector()["x"][i] for i in IDX]
            q = quantise(x)
            acc = sum(wq * qq for wq, qq in zip(I["wq_i16"], q)) + I["bq_i32"]
            lines.append("W %s %d %s %d %d" % (wid.replace(" ", "_"), nflow, ",".join(map(str, q)), acc, acc > I["thr_q_i32"]))
            lines += records(w["host"], w["baseline"], w["events"])
            nwin += 1
    open(a.out, "w").write("\n".join(lines) + "\n")
    print("windows %d, lines %d" % (nwin, len(lines)))


if __name__ == "__main__":
    main()
