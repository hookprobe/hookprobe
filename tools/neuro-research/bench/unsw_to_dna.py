#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""UNSW-IoTraffic (CC0-1.0, verified in the intel-data registry 2026-11-22) -> DNA v1 vectors, benign home IoT.

One pcap per device (file name carries the MAC). Single streaming pass per device:
- Zeek-like CONNECTIONS (v2, after a source-confound check showed whole-hour 4-tuple flows were separable from
  Zeek exports at AUC 0.988): a new connection starts at a TCP SYN after FIN/RST, or after 300 s idle (TCP) /
  60 s idle (UDP) -- Zeek's default inactivity timeouts; each connection is assigned to the hour it STARTS;
  oriented by INITIATOR (TCP SYN sender / first UDP sender); conn_state S0 (no reply), REJ (responder RST without
  data), SF otherwise;
- remote context from the SAME verified lookup build used for the IoT-23/CTU-13 exports (iptoasn + MISP
  warninglist CIDRs), computed on real addresses LOCALLY; only aggregate features leave this script;
- baseline pairs = the device's peers in the previous 24 h (as the window exports);
- split: only the FIRST HALF of each device's active days is emitted ("dev"); the second half stays untouched for
  the sealed confirmation run (milestone M3, doc 30), as in the D1 history/test split.
Usage: python3 -I unsw_to_dna.py <pcap dir> <lookup build dir> <out.jsonl> [--workers 8]
"""
import argparse, bisect, collections, ipaddress, json, os, sys
from multiprocessing import Pool
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE); sys.path.insert(0, os.path.dirname(HERE))
import unsw_to_d1 as u  # noqa: E402
from dna_features import Agg  # noqa: E402

LOOK = {}


def load_lookup(d):
    starts, rows = [], []
    for line in open(os.path.join(d, "asn_ranges.tsv")):
        f = line.rstrip("\n").split("\t")
        if f[0] != "4":
            continue
        starts.append(int(f[1])); rows.append((int(f[2]), int(f[3]), f[4], f[5]))
    nets = []
    for line in open(os.path.join(d, "warninglists.jsonl")):
        j = json.loads(line)
        if j.get("not_for_captures"):
            continue
        for e in j.get("entries", []):
            try:
                n = ipaddress.ip_network(e, strict=False)
            except ValueError:
                continue
            if n.version == 4:
                nets.append((int(n.network_address), int(n.broadcast_address), j.get("id") or j.get("name")))
    nets.sort()
    LOOK.update(starts=starts, rows=rows, nets=nets, nstarts=[n[0] for n in nets], cache={})


def context(ip_bytes):
    c = LOOK["cache"].get(ip_bytes)
    if c is not None:
        return c
    v = int.from_bytes(ip_bytes, "big")
    i = bisect.bisect_right(LOOK["starts"], v) - 1
    asn = country = None
    if i >= 0 and v <= LOOK["rows"][i][0] and LOOK["rows"][i][1] != 0:
        asn, country = LOOK["rows"][i][1], LOOK["rows"][i][2]
    wl = []
    j = bisect.bisect_right(LOOK["nstarts"], v)
    for k in range(max(0, j - 64), j):                 # nets are sorted by start; check the nearby candidates
        s, e, name = LOOK["nets"][k]
        if s <= v <= e:
            wl.append(name)
    c = {"asn": asn, "country": country, "warninglists": wl}
    LOOK["cache"][ip_bytes] = c
    return c


def ipstr(b):
    return ".".join(str(x) for x in b) if len(b) == 4 else b.hex()


def one(args):
    path, lookup_dir, half = args
    if not LOOK:
        load_lookup(lookup_dir)
    name = os.path.basename(path).split(".")[0]
    mac = bytes.fromhex(name.rsplit("_", 1)[1])
    hours = {}                  # hour -> {flows, ip}
    out, prev_pairs = [], collections.deque(maxlen=24)

    def close(hr):
        w = hours.pop(hr)
        if not w["ip"] or not w["flows"]:
            prev_pairs.append(set()); return
        me = ipstr(w["ip"])
        base = set().union(*prev_pairs) if prev_pairs else set()
        a = Agg({"window_id": "%s|%d" % (name, hr), "dataset": "unsw-iotraffic", "capture": "UNSW-" + name.split("_")[0],
                 "host": me, "hour": "%d" % hr, "split": "dev"})
        evs, ctx, pairs = [], {}, set()
        for ((proto, peer, my_port, peer_port), _start), fl in w["flows"].items():
            t0, init_me, b_init, b_resp, p_init, syn, back, rst_resp, t1, _closed = fl
            src, dst = (me, ipstr(peer)) if init_me else (ipstr(peer), me)
            state = "S0" if not back else ("REJ" if rst_resp and b_resp == 0 else "SF")
            evs.append({"type": "flow", "ts": "1970-01-01T%02d:%02d:%06.3fZ" % ((t0 // 3600) % 24, (t0 // 60) % 60, t0 % 60),
                        "src_ip": src, "dst_ip": dst, "dst_port": peer_port if init_me else my_port,
                        "proto": {6: "tcp", 17: "udp", 1: "icmp"}[proto], "bytes_out": b_init if init_me else b_resp,
                        "bytes_in": b_resp if init_me else b_init, "conn_state": state, "orig_pkts": p_init,
                        "duration": max(0.0, t1 - t0)})
            if not u.is_local(peer):
                ctx[ipstr(peer)] = context(bytes(peer))
            if init_me:
                pairs.add((me, ipstr(peer)))
        a.add({"events": evs, "remote_context": ctx, "baseline": {"pairs": [list(p) for p in base]}, "labels": {"benign": len(evs)}})
        prev_pairs.append(pairs)
        v = a.vector(); v["hour_index"] = hr
        out.append(v)

    cur = None
    live = {}                   # 4-tuple -> open connection record [start_ts, init_me, b_init, b_resp, p_init, syn, back, rst_resp, last_ts, closed]

    def finish(k, c):
        hr0 = int(c[0] // 3600)
        w = hours.setdefault(hr0, {"flows": {}, "ip": None})
        if len(w["flows"]) < 20000:
            w["flows"][(k, c[0])] = c

    with open(path, "rb") as f:
        for ts, fr, lt in u.packets(f):
            p = u.parse(fr, lt)
            if p is None:
                continue
            smac, dmac, ver, src, dst, proto, sp, dp, flags, payload, ip_len = p
            if proto not in (1, 6, 17) or (smac != mac and dmac != mac):
                continue
            if proto == 1:                                # ICMP: no ports (Zeek keys ICMP by type/code; v1 uses 0)
                sp = dp = 0
            hr = int(ts // 3600)
            out_dir = smac == mac
            me, peer = (bytes(src), bytes(dst)) if out_dir else (bytes(dst), bytes(src))
            if u.is_bcast_mcast(peer):
                continue
            w = hours.setdefault(hr, {"flows": {}, "ip": None})
            if out_dir and len(me) == 4:
                w["ip"] = w["ip"] or me
            my_port, peer_port = (sp, dp) if out_dir else (dp, sp)
            k = (proto, peer, my_port, peer_port)
            syn = proto == 6 and flags & 0x02 and not flags & 0x10
            c = live.get(k)
            idle = 300 if proto == 6 else 60
            if c is not None and (ts - c[8] > idle or (proto == 6 and c[9] and syn)):
                finish(k, live.pop(k)); c = None
            if c is None:
                init_me = out_dir if (proto in (1, 17) or syn) else (peer_port < my_port)
                c = live[k] = [ts, init_me, 0, 0, 0, bool(syn), False, False, ts, False]
            if out_dir == c[1]:
                c[2] += ip_len; c[4] += 1
            else:
                c[3] += ip_len; c[6] = True
                if proto == 6 and flags & 0x04:
                    c[7] = True
            if proto == 6 and flags & 0x05:          # FIN or RST closes; a later SYN on the same tuple is a new connection
                c[9] = True
            c[8] = ts
            if cur is not None and hr != cur:        # hour boundary: retire idle connections, close finished hours
                for kk in [kk for kk, cc in live.items() if ts - cc[8] > (300 if kk[0] == 6 else 60)]:
                    finish(kk, live.pop(kk))
                oldest_open = min((int(cc[0] // 3600) for cc in live.values()), default=hr)
                for h in sorted(hours):
                    if h < min(hr, oldest_open):
                        close(h)
            cur = hr
    for kk in list(live):
        finish(kk, live.pop(kk))
    for h in sorted(hours):
        close(h)
    days = sorted({r["hour_index"] // 24 for r in out})
    cut = days[len(days) // 2] if days else 0
    keep = [r for r in out if (r["hour_index"] // 24 < cut) == (half == "first")]
    for r in keep:
        r["split"] = "dev" if half == "first" else "m3-sealed"
    return name, len(out), keep


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("pcaps"); ap.add_argument("lookup"); ap.add_argument("out"); ap.add_argument("--workers", type=int, default=8)
    ap.add_argument("--half", choices=["first", "second"], default="first",
                    help="first = dev half (default); second = the reserved half, ONLY for the pre-registered M3 run (doc 31)")
    a = ap.parse_args()
    files = sorted((os.path.join(a.pcaps, f) for f in os.listdir(a.pcaps) if ".pcap" in f), key=os.path.getsize, reverse=True)
    with Pool(a.workers) as p, open(a.out, "w") as o:
        for name, n, keep in p.imap_unordered(one, [(f, a.lookup, a.half) for f in files]):
            for r in keep:
                r.pop("hour_index", None)
                o.write(json.dumps(r) + "\n")
            print("  %s: %d hours, %d kept (%s half of active days)" % (name, n, len(keep), a.half), flush=True)


if __name__ == "__main__":
    main()
