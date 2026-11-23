#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Spent UNSW-IoTraffic pcaps -> synthetic YAF-style biflow CSV, one file per device: the test bed for ipfix_to_dna.py.

The connection loop is unsw_to_dna_conn.py's one() (itself generated from the frozen unsw_to_dna.py) with two
additions that change nothing else: a responder packet count, and an ACTIVE timeout for --rule yaf.
  --rule zeek : the frozen cut. ipfix_to_dna.py on this output must reproduce unsw_to_dna_conn.py --rule zeek.
  --rule yaf  : YAF's defaults (300 s idle for every protocol, 1800 s active timeout, FIN/RST ends a TCP flow):
                how a real IPFIX export would cut the same traffic. Comparing the two measures the exporter effect.
Rows are written per hour in the frozen path's order; the frozen path's per-hour address (the device's first
outbound IPv4 in that hour) is the device address, and hours without one are dropped, exactly as frozen.
Usage: unsw_to_flows.py <pcap dir> <out dir> --rule zeek|yaf [--workers N]
"""
import argparse, csv, os, sys
from multiprocessing import Pool
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE); sys.path.insert(0, os.path.dirname(HERE))
import unsw_to_d1 as u  # noqa: E402

RULES = {"zeek": (300, 60, None), "yaf": (300, 300, 1800)}
COLS = ["device", "deviceAddress", "flowStartMilliseconds", "flowEndMilliseconds", "sourceIPv4Address", "destinationIPv4Address",
        "sourceTransportPort", "destinationTransportPort", "protocolIdentifier", "octetTotalCount", "reverseOctetTotalCount",
        "packetTotalCount", "reversePacketTotalCount", "reverseUnionTCPFlags"]


def ipstr(b):
    return ".".join(str(x) for x in b) if len(b) == 4 else b.hex()


def one(args):
    path, out_dir, rule = args
    TCP_IDLE, UDP_IDLE, ACTIVE = RULES[rule]
    name = os.path.basename(path).split(".")[0]
    mac = bytes.fromhex(name.rsplit("_", 1)[1])
    hours = {}
    f_out = open(os.path.join(out_dir, name + ".csv"), "w", newline="")
    wr = csv.writer(f_out); wr.writerow(COLS)
    rows = 0

    def close(hr):
        nonlocal rows
        w = hours.pop(hr)
        if not w["ip"] or not w["flows"]:
            return
        me = w["ip"]
        for ((proto, peer, my_port, peer_port), _start), fl in w["flows"].items():
            t0, init_me, b_init, b_resp, p_init, syn, back, rst_resp, t1, _closed, p_resp = fl
            s, d, sp, dp = (me, peer, my_port, peer_port) if init_me else (peer, me, peer_port, my_port)
            wr.writerow([name, ipstr(me), "%.3f" % (t0 * 1000), "%.3f" % (t1 * 1000), ipstr(s), ipstr(d), sp, dp, proto,
                         b_init, b_resp, p_init, p_resp, "R" if rst_resp else ""])
            rows += 1

    cur = None
    live = {}

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
            if proto == 1:
                sp = dp = 0
            hr = int(ts // 3600)
            out_dir_ = smac == mac
            me, peer = (bytes(src), bytes(dst)) if out_dir_ else (bytes(dst), bytes(src))
            if u.is_bcast_mcast(peer):
                continue
            w = hours.setdefault(hr, {"flows": {}, "ip": None})
            if out_dir_ and len(me) == 4:
                w["ip"] = w["ip"] or me
            my_port, peer_port = (sp, dp) if out_dir_ else (dp, sp)
            k = (proto, peer, my_port, peer_port)
            syn = proto == 6 and flags & 0x02 and not flags & 0x10
            c = live.get(k)
            idle = TCP_IDLE if proto == 6 else UDP_IDLE
            if c is not None and (ts - c[8] > idle or (proto == 6 and c[9] and syn) or (ACTIVE and ts - c[0] > ACTIVE)):
                finish(k, live.pop(k)); c = None
            if c is None:
                init_me = out_dir_ if (proto in (1, 17) or syn) else (peer_port < my_port)
                c = live[k] = [ts, init_me, 0, 0, 0, bool(syn), False, False, ts, False, 0]
            if out_dir_ == c[1]:
                c[2] += ip_len; c[4] += 1
            else:
                c[3] += ip_len; c[6] = True; c[10] += 1
                if proto == 6 and flags & 0x04:
                    c[7] = True
            if proto == 6 and flags & 0x05:
                c[9] = True
            c[8] = ts
            if cur is not None and hr != cur:
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
    f_out.close()
    return name, rows


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("pcaps"); ap.add_argument("out"); ap.add_argument("--rule", choices=sorted(RULES), required=True)
    ap.add_argument("--workers", type=int, default=6)
    a = ap.parse_args()
    os.makedirs(a.out, exist_ok=True)
    files = sorted((os.path.join(a.pcaps, f) for f in os.listdir(a.pcaps) if ".pcap" in f), key=os.path.getsize, reverse=True)
    with Pool(a.workers) as p:
        for name, rows in p.imap_unordered(one, [(f, a.out, a.rule) for f in files]):
            print("  %s: %d flows (rule %s)" % (name, rows, a.rule), flush=True)


if __name__ == "__main__":
    main()
