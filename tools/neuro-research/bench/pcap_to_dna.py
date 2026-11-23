#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Any Ethernet PCAP -> DNA v1 device-hour vectors, one device per LAN MAC (doc 37: the M4 L1-IoT malware side).

The UNSW path (bench/unsw_to_dna_conn.py) knows its device from the file name: one pcap per device. A lab capture
such as Kitsune's holds many devices in one file. This tool runs the SAME connection loop (copied from
unsw_to_dna_conn.py's one(), unchanged apart from the device MAC being a parameter, no halves, and per-packet labels)
once per device MAC.

Device MACs (--macs auto, the default):
  a MAC is a device if it sends at least one IPv4 packet from a local (RFC 1918 / link-local) address, and fewer than
  1% of the IPv4 packets it sends carry a NON-local source address (0.0.0.0, a DHCP client before its lease, counts as
  neither). The second rule drops routers and gateways,
  which forward remote traffic under their own MAC. Excluded MACs are printed with their counts.
--macs aa:bb:..,..  : exactly these MACs (the parity check uses this).

Labels (--labels, optional): a CSV with one row per frame of the pcap, in frame order, whose LAST column is 0 (benign)
or non-zero (attack); a header row is allowed. Every frame counts for alignment, parsed or not. A device-hour's
"attack_pkts_sent" is the number of attack-labelled IP frames (IPv4/IPv6, any protocol) that device SENT in that hour. The tool stops if the row count differs from
the frame count: the alignment is then unknown, and nothing is scored.

Connection rule: --rule doc20 (the kernel's N0 rule; the M4 default) or zeek (the frozen M3 cut), as in
unsw_to_dna_conn.py.
Usage: pcap_to_dna.py <out.jsonl> <pcap>... --lookup DIR [--rule doc20|zeek] [--macs auto|LIST] [--labels CSV]...
                      [--dataset NAME] [--workers N]
       (--labels is given once per pcap, in the same order, when used)
"""
import argparse, collections, csv, json, os, sys
from multiprocessing import Pool
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE); sys.path.insert(0, os.path.dirname(HERE))
import unsw_to_dna as m  # noqa: E402  (frozen helpers: lookup, context, ipstr)
import unsw_to_d1 as u  # noqa: E402
from dna_features import Agg  # noqa: E402

RULES = {"zeek": (300, 60, False), "doc20": (86400, 120, True)}
ROUTER_FRAC = 0.01


def mac_str(b):
    return ":".join("%02x" % x for x in b)


def find_devices(path):
    return (path,) + _find(path)


def _find(path):
    """-> (devices, excluded, frames, linktypes)."""
    local, nonlocal_, frames, lts = collections.Counter(), collections.Counter(), 0, collections.Counter()
    with open(path, "rb") as f:
        for ts, fr, lt in u.packets(f):
            frames += 1; lts[lt] += 1
            p = u.parse(fr, lt)
            if p is None or p[2] != 4 or bytes(p[3]) == bytes(4):    # 0.0.0.0 (DHCP before an address): neither
                continue
            (local if u.is_local(bytes(p[3])) else nonlocal_)[bytes(p[0])] += 1
    dev, exc = [], {}
    for mac in sorted(set(local) | set(nonlocal_)):
        tot = local[mac] + nonlocal_[mac]
        if local[mac] and nonlocal_[mac] < ROUTER_FRAC * tot:
            dev.append(mac)
        else:
            exc[mac_str(mac)] = (local[mac], nonlocal_[mac])
    return dev, exc, frames, dict(lts)


def read_labels(path):
    out = []
    with open(path, newline="") as f:
        for i, row in enumerate(csv.reader(f)):
            if not row:
                continue
            try:
                out.append(1 if float(row[-1]) != 0 else 0)
            except ValueError:
                if i == 0:
                    continue                      # header
                raise
    return out


def one(args):
    path, mac, lookup_dir, rule, labels_path, dataset = args
    TCP_IDLE, UDP_IDLE, SYN_ALWAYS = RULES[rule]
    if not m.LOOK:
        m.load_lookup(lookup_dir)
    lab = read_labels(labels_path) if labels_path else None
    cap = os.path.basename(path).split(".")[0]
    name = "%s|%s" % (cap, mac_str(mac))
    hours = {}                  # hour -> {flows, ip}
    atk = collections.Counter()  # hour -> attack-labelled IP frames this device sent (kept apart: no effect on hours)
    out, prev_pairs = [], collections.deque(maxlen=24)

    def close(hr):
        w = hours.pop(hr)
        if not w["ip"] or not w["flows"]:
            prev_pairs.append(set()); return
        me = m.ipstr(w["ip"])
        base = set().union(*prev_pairs) if prev_pairs else set()
        a = Agg({"window_id": "%s|%d" % (name, hr), "dataset": dataset, "capture": cap,
                 "host": me, "hour": "%d" % hr, "split": "eval"})
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
        v = a.vector(); v["hour_index"] = hr; v["device_mac"] = mac_str(mac)
        if lab is not None:
            v["attack_pkts_sent"] = atk[hr]
        out.append(v)

    cur = None
    live = {}

    def finish(k, c):
        hr0 = int(c[0] // 3600)
        w = hours.setdefault(hr0, {"flows": {}, "ip": None})
        if len(w["flows"]) < 20000:
            w["flows"][(k, c[0])] = c

    idx = -1
    with open(path, "rb") as f:
        for ts, fr, lt in u.packets(f):
            idx += 1
            p = u.parse(fr, lt)
            if p is None:
                continue
            smac, dmac, ver, src, dst, proto, sp, dp, flags, payload, ip_len = p
            if lab is not None and smac == mac and idx < len(lab) and lab[idx]:
                atk[int(ts // 3600)] += 1
            if proto not in (1, 6, 17) or (smac != mac and dmac != mac):
                continue
            if proto == 1:
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
    if lab is not None and idx + 1 != len(lab):
        return name, None, "labels: %d rows for %d frames" % (len(lab), idx + 1)
    for kk in list(live):
        finish(kk, live.pop(kk))
    for h in sorted(hours):
        close(h)
    return name, out, None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("out"); ap.add_argument("pcaps", nargs="+")
    ap.add_argument("--lookup", required=True); ap.add_argument("--rule", choices=sorted(RULES), default="doc20")
    ap.add_argument("--macs", default="auto"); ap.add_argument("--labels", action="append", default=[])
    ap.add_argument("--dataset", default="pcap"); ap.add_argument("--workers", type=int, default=6)
    a = ap.parse_args()
    if a.labels and len(a.labels) != len(a.pcaps):
        sys.exit("--labels must be given once per pcap")
    jobs = []
    if a.macs == "auto":
        found = {}
        with Pool(a.workers) as p:
            for path, dev, exc, frames, lts in p.imap_unordered(find_devices, a.pcaps):
                found[path] = dev
                print("%s: %d frames, linktypes %s, devices %d, excluded %s" % (os.path.basename(path), frames, lts, len(dev), exc),
                      flush=True)
    for i, path in enumerate(a.pcaps):
        dev = found[path] if a.macs == "auto" else [bytes.fromhex(x.replace(":", "")) for x in a.macs.split(",")]
        jobs += [(path, mac, a.lookup, a.rule, a.labels[i] if a.labels else None, a.dataset) for mac in dev]
    bad = 0
    with Pool(a.workers) as p, open(a.out, "w") as o:
        for name, out, err in p.imap_unordered(one, jobs):
            if err:
                print("  STOP %s: %s" % (name, err), flush=True); bad += 1; continue
            for r in out:
                r.pop("hour_index", None)
                o.write(json.dumps(r) + "\n")
            print("  %s: %d device-hours" % (name, len(out)), flush=True)
    if bad:
        sys.exit("label alignment failed for %d device jobs; output is not usable" % bad)


if __name__ == "__main__":
    main()
