#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Behavioural DNA v1 feature vector: one fixed-length vector per host-hour window, from flow events + remote
context. Streaming, numpy-only. The SAME vector is the benchmark input and the candidate on-device DNA record.

Usage: python3 -I dna_features.py <windows build dir> <out.jsonl> [--workers 8]
Output: one JSON line per window: {window_id, dataset, capture, host, hour, split, label, mal_frac, x: [..]}.
"""
import argparse, collections, json, math, os, sys
from multiprocessing import Pool

FEATURES = [
    "log_flows", "out_frac", "log_remotes", "log_dst_ports", "port_entropy", "top_port_share", "fail_ratio",
    "log_bytes_out", "log_bytes_in", "log_out_in_ratio", "log_mean_dur", "log_pkts_per_flow", "tcp_frac", "udp_frac",
    "icmp_frac", "wellknown_frac", "telnet_frac", "ssh_frac", "smb_frac", "web_frac", "dns_frac", "ntp_frac",
    "periodic_cv", "log_period_s", "log_max_per_min", "novel_pair_frac", "warninglist_frac", "unrouted_frac",
    "log_countries", "log_asns", "lan_peer_frac", "log_inbound_sources"]
FAIL = {"S0", "REJ", "RSTOS0", "SH", "SHR", "RSTRH", "OTH"}


def lan(ip):
    return ip.startswith(("10.", "192.168.", "172.16.", "172.17.", "172.18.", "172.19.", "172.2", "172.30.", "172.31.", "fe80", "fc", "fd"))


def ent(c):
    n = sum(c.values())
    return -sum(v / n * math.log2(v / n) for v in c.values()) if n else 0.0


def ts_s(t):
    h, m, s = t[11:13], t[14:16], t[17:]
    try:
        return int(h) * 3600 + int(m) * 60 + float(s.rstrip("Z"))
    except ValueError:
        return 0.0


class Agg:
    __slots__ = ("meta", "n", "out", "remotes", "ports", "fail", "bo", "bi", "dur", "pk", "proto", "inb", "times",
                 "per_min", "pairs", "novel", "ctx", "labs", "baseline")

    def __init__(self, meta):
        self.meta, self.n, self.out, self.fail, self.bo, self.bi, self.dur, self.pk = meta, 0, 0, 0, 0, 0, 0.0, 0
        self.remotes, self.ports, self.proto, self.inb = collections.Counter(), collections.Counter(), collections.Counter(), set()
        self.times, self.per_min, self.pairs, self.novel = collections.defaultdict(list), collections.Counter(), 0, 0
        self.ctx, self.labs, self.baseline = {}, collections.Counter(), None

    def add(self, j):
        host = self.meta["host"]
        if self.baseline is None:
            self.baseline = {tuple(p) for p in j.get("baseline", {}).get("pairs", [])}
        self.ctx.update(j.get("remote_context") or {})
        for k, v in (j.get("labels") or {}).items():
            self.labs["mal" if k.lower().startswith(("malicious", "botnet")) else "ben"] += v
        for e in j["events"]:
            if e.get("type") != "flow":
                continue
            self.n += 1
            out = e["src_ip"] == host
            peer = e["dst_ip"] if out else e["src_ip"]
            self.out += out
            self.remotes[peer] += 1
            if out:
                self.ports[e.get("dst_port")] += 1
                self.pairs += 1
                self.novel += (host, peer) not in self.baseline
            else:
                self.inb.add(peer)
            self.fail += (e.get("conn_state") or "") in FAIL
            self.bo += e.get("bytes_out") or 0
            self.bi += e.get("bytes_in") or 0
            self.dur += e.get("duration") or 0.0
            self.pk += (e.get("orig_pkts") or 0)
            self.proto[(e.get("proto") or "").lower()] += 1
            t = ts_s(e.get("ts", "T00:00:00"))
            if len(self.times[peer]) < 400:
                self.times[peer].append(t)
            self.per_min[int(t // 60)] += 1

    def vector(self):
        n = max(1, self.n)
        P = self.ports
        po = sum(P.values()) or 1
        cv, period = 1.0, 0.0
        for peer, _ in self.remotes.most_common(3):
            ts = sorted(self.times[peer])
            if len(ts) >= 6:
                d = [b - a for a, b in zip(ts, ts[1:]) if b > a]
                if len(d) >= 5:
                    m = sum(d) / len(d)
                    s = math.sqrt(sum((x - m) ** 2 for x in d) / len(d))
                    if m > 0 and s / m < cv:
                        cv, period = s / m, m
        rem = list(self.remotes)
        ctxv = [self.ctx.get(r) for r in rem if not lan(r)]
        ctxv = [c for c in ctxv if c]
        nc = max(1, len(ctxv))
        lg = lambda v: math.log1p(max(0.0, v))
        x = [lg(self.n), self.out / n, lg(len(rem)), lg(len(P)), ent(P), (P.most_common(1)[0][1] / po) if P else 0.0,
             self.fail / n, lg(self.bo), lg(self.bi), math.log((self.bo + 1) / (self.bi + 1)), lg(self.dur / n), lg(self.pk / n),
             self.proto["tcp"] / n, self.proto["udp"] / n, self.proto["icmp"] / n,
             sum(v for p, v in P.items() if isinstance(p, int) and p < 1024) / po,
             (P[23] + P[2323]) / po, P[22] / po, (P[445] + P[139]) / po, (P[80] + P[443] + P[8080]) / po, P[53] / po, P[123] / po,
             cv, lg(period), lg(max(self.per_min.values()) if self.per_min else 0), (self.novel / self.pairs) if self.pairs else 0.0,
             sum(1 for c in ctxv if c.get("warninglists")) / nc, sum(1 for c in ctxv if c.get("asn") is None) / nc,
             lg(len({c.get("country") for c in ctxv if c.get("country")})), lg(len({c.get("asn") for c in ctxv if c.get("asn")})),
             sum(1 for r in rem if lan(r)) / max(1, len(rem)), lg(len(self.inb))]
        tot = self.labs["mal"] + self.labs["ben"]
        mf = self.labs["mal"] / tot if tot else 0.0
        return dict(self.meta, label=int(mf >= 0.5), mal_frac=round(mf, 4), n_events=self.n, x=[round(v, 5) for v in x])


def one(path):
    cap = os.path.basename(path)[:-6]
    aggs = {}
    with open(path, encoding="utf-8") as f:
        for line in f:
            j = json.loads(line)
            wid = j["window_id"]
            a = aggs.get(wid)
            if a is None:
                a = aggs[wid] = Agg({"window_id": wid, "dataset": j.get("dataset"), "capture": cap, "host": j["host"],
                                     "hour": j["hour_utc"], "split": j.get("split")})
            a.add(j)
    return [a.vector() for a in aggs.values()]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("build"); ap.add_argument("out"); ap.add_argument("--workers", type=int, default=8)
    a = ap.parse_args()
    files = sorted((os.path.join(a.build, f) for f in os.listdir(a.build) if f.endswith(".jsonl")), key=os.path.getsize, reverse=True)
    with Pool(a.workers) as p, open(a.out, "w") as o:
        for rows in p.imap_unordered(one, files):
            for r in rows:
                o.write(json.dumps(r) + "\n")
            print("  %s: %d windows" % (rows[0]["capture"] if rows else "?", len(rows)), flush=True)
    assert len(FEATURES) == 32


if __name__ == "__main__":
    main()
