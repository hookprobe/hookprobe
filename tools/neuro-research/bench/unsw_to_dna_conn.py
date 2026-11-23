#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""UNSW-IoTraffic -> DNA v1 with a selectable CONNECTION RULE (doc 32 section 2: re-measure under the doc 20 rule).

Same code as the frozen bench/unsw_to_dna.py (128b2520), generated from its one() with the connection rule
parameterised; the frozen file is not changed.
  --rule zeek   : the frozen behaviour (TCP: new at SYN after FIN/RST, or 300 s idle; UDP/ICMP: 60 s idle).
                  Must reproduce unsw_to_dna.py output exactly (checked by the caller as a sorted multiset).
  --rule doc20  : the kernel's N0 rule (doc 20, os/neuro/neuro-dp): TCP: every SYN without ACK starts a new connection,
                  no idle split (a 24 h guard only bounds memory); UDP (and ICMP, which doc 20 does not count):
                  120 s idle. Inbound SYNs also start connections (DNA v1 counts inbound sources; N0 counts only
                  device-sent SYNs) -- an approximation stated in the report.
Usage: unsw_to_dna_conn.py <pcap dir> <lookup dir> <out.jsonl> --rule zeek|doc20 --half first|second [--workers N]
"""
import argparse, collections, json, os, sys
from multiprocessing import Pool
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE); sys.path.insert(0, os.path.dirname(HERE))
import unsw_to_dna as m  # noqa: E402  (frozen helpers: lookup, context, ipstr)
import unsw_to_d1 as u  # noqa: E402
from dna_features import Agg  # noqa: E402

RULES = {"zeek": (300, 60, False), "doc20": (86400, 120, True)}


def one(args):
    path, lookup_dir, half, rule = args
    TCP_IDLE, UDP_IDLE, SYN_ALWAYS = RULES[rule]
    if not m.LOOK:
        m.load_lookup(lookup_dir)
    name = os.path.basename(path).split(".")[0]
    mac = bytes.fromhex(name.rsplit("_", 1)[1])
    hours = {}                  # hour -> {flows, ip}
    out, prev_pairs = [], collections.deque(maxlen=24)

    def close(hr):
        w = hours.pop(hr)
        if not w["ip"] or not w["flows"]:
            prev_pairs.append(set()); return
        me = m.ipstr(w["ip"])
        base = set().union(*prev_pairs) if prev_pairs else set()
        a = Agg({"window_id": "%s|%d" % (name, hr), "dataset": "unsw-iotraffic", "capture": "UNSW-" + name.split("_")[0],
                 "host": me, "hour": "%d" % hr, "split": "dev"})
        evs, ctx, pairs = [], {}, set()
        for ((proto, peer, my_port, peer_port), _start), fl in w["flows"].items():
            t0, init_me, b_init, b_resp, p_init, syn, back, rst_resp, t1, _closed = fl
            src, dst = (me, m.ipstr(peer)) if init_me else (m.ipstr(peer), me)
            state = "S0" if not back else ("REJ" if rst_resp and b_resp == 0 else "SF")
            evs.append({"type": "flow", "ts": "1970-01-01T%02d:%02d:%06.3fZ" % ((t0 // 3600) % 24, (t0 // 60) % 60, t0 % 60),
                        "src_ip": src, "dst_ip": dst, "dst_port": peer_port if init_me else my_port,
                        "proto": {6: "tcp", 17: "udp", 1: "icmp"}[proto], "bytes_out": b_init if init_me else b_resp,
                        "bytes_in": b_resp if init_me else b_init, "conn_state": state, "orig_pkts": p_init,
                        "duration": max(0.0, t1 - t0)})
            if not u.is_local(peer):
                ctx[m.ipstr(peer)] = m.context(bytes(peer))
            if init_me:
                pairs.add((me, m.ipstr(peer)))
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
            idle = TCP_IDLE if proto == 6 else UDP_IDLE
            if c is not None and (ts - c[8] > idle or (proto == 6 and (c[9] or SYN_ALWAYS) and syn)):
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
                for kk in [kk for kk, cc in live.items() if ts - cc[8] > (TCP_IDLE if kk[0] == 6 else UDP_IDLE)]:
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
    ap.add_argument("--rule", choices=sorted(RULES), required=True); ap.add_argument("--half", choices=["first", "second"], required=True)
    a = ap.parse_args()
    files = sorted((os.path.join(a.pcaps, f) for f in os.listdir(a.pcaps) if ".pcap" in f), key=os.path.getsize, reverse=True)
    with Pool(a.workers) as p, open(a.out, "w") as o:
        for name, n, keep in p.imap_unordered(one, [(f, a.lookup, a.half, a.rule) for f in files]):
            for r in keep:
                r.pop("hour_index", None)
                o.write(json.dumps(r) + "\n")
            print("  %s: %d hours, %d kept (%s half, rule %s)" % (name, n, len(keep), a.half, a.rule), flush=True)


if __name__ == "__main__":
    main()
