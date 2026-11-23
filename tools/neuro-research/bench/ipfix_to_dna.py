#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""IPFIX / YAF biflow CSV -> DNA v1 host-hour vectors (doc 35 M4: a home-benign holdout that ships as flow records,
not PCAP). Same aggregation as the frozen UNSW path (bench/unsw_to_dna.py, bench/dna_features.py), on flow records.

What a record must carry (column names are YAF/IPFIX information elements; --map renames them):
  flowStartMilliseconds, flowEndMilliseconds      start / end, ms since the epoch (decimals allowed)
  sourceIPv4Address, destinationIPv4Address        source = the flow's INITIATOR (YAF biflow forward direction)
  sourceTransportPort, destinationTransportPort    0 for ICMP
  protocolIdentifier                               6 / 17 / 1 (others are skipped)
  octetTotalCount, reverseOctetTotalCount          IP-layer bytes, initiator / responder
  packetTotalCount, reversePacketTotalCount        packets, initiator / responder
  reverseUnionTCPFlags                             optional: responder TCP flags (int, 0x.. hex, or letters "R...")

Rules, identical to the frozen UNSW converter so home vectors are comparable with the M3 home set:
- device = every LOCAL endpoint of a flow (RFC 1918, link-local, ULA), unless --device-cols names a device column and
  its address column (the parity test uses this; real exports usually carry no device column);
- a flow belongs to the hour it STARTS; at most --max-per-hour flows per device-hour, in file order;
- conn_state: S0 if the responder sent nothing, REJ if it reset without sending bytes, else SF (as frozen; with
  IP-layer byte counts a reset packet has bytes, so REJ does not occur in either path);
- baseline pairs = the device's outbound peers in its previous 24 hours that had flows;
- remote context only with --lookup (the S1 model does not use context features).
Connection cutting is the EXPORTER's (YAF default: 300 s idle, 1800 s active timeout, FIN/RST ends a flow), not
Zeek's 300 s TCP / 60 s UDP. tools/neuro-research/bench/unsw_to_flows.py measures that difference on spent data.

Usage: ipfix_to_dna.py <out.jsonl> <csv>... [--dataset NAME] [--map col=IE,...] [--device-cols NAME_COL,ADDR_COL]
                       [--lookup DIR] [--max-per-hour 20000]
"""
import argparse, collections, csv, ipaddress, json, os, sys
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE); sys.path.insert(0, os.path.dirname(HERE))
from dna_features import Agg  # noqa: E402

IE = ["flowStartMilliseconds", "flowEndMilliseconds", "sourceIPv4Address", "destinationIPv4Address", "sourceTransportPort",
      "destinationTransportPort", "protocolIdentifier", "octetTotalCount", "reverseOctetTotalCount", "packetTotalCount",
      "reversePacketTotalCount", "reverseUnionTCPFlags"]
OPTIONAL = {"reverseUnionTCPFlags"}
PROTO = {6: "tcp", 17: "udp", 1: "icmp"}


def addr_bytes(s):
    """Dotted IPv4, any IPv6 text form, or 32 hex digits (the UNSW path's IPv6 spelling)."""
    s = s.strip()
    if len(s) == 32 and all(c in "0123456789abcdef" for c in s):
        return bytes.fromhex(s)
    return ipaddress.ip_address(s).packed


def is_local(b):
    if len(b) == 4:
        return b[0] in (10, 127) or (b[0] == 172 and 16 <= b[1] <= 31) or (b[0] == 192 and b[1] == 168) or (b[0] == 169 and b[1] == 254)
    return (b[0] & 0xFE) == 0xFC or (b[0] == 0xFE and b[1] & 0xC0 == 0x80) or b == bytes(15) + b"\x01"


def is_bcast_mcast(b):
    if len(b) == 4:
        return 224 <= b[0] <= 239 or b == b"\xff\xff\xff\xff" or (is_local(b) and b[3] == 255)
    return b[0] == 0xFF


def ipstr(b):
    return ".".join(str(x) for x in b) if len(b) == 4 else b.hex()


def rst(v):
    v = (v or "").strip()
    if not v:
        return False
    if v.isdigit():
        return bool(int(v) & 0x04)
    if v.lower().startswith("0x"):
        return bool(int(v, 16) & 0x04)
    return "R" in v.upper()


def ts_str(t):
    return "1970-01-01T%02d:%02d:%06.3fZ" % ((t // 3600) % 24, (t // 60) % 60, t % 60)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("out"); ap.add_argument("csv", nargs="+")
    ap.add_argument("--dataset", default="ipfix"); ap.add_argument("--map", default="")
    ap.add_argument("--device-cols", default=""); ap.add_argument("--lookup", default="")
    ap.add_argument("--max-per-hour", type=int, default=20000)
    a = ap.parse_args()
    ren = dict(kv.split("=", 1) for kv in a.map.split(",") if kv)      # export column -> IE name
    ctxf = None
    if a.lookup:
        import unsw_to_dna as m
        m.load_lookup(a.lookup)
        ctxf = m.context
    dcols = a.device_cols.split(",") if a.device_cols else None
    hours = collections.defaultdict(lambda: collections.defaultdict(list))   # device -> hour -> [(me, flow)]
    skipped = collections.Counter()
    for path in a.csv:
        with open(path, newline="", encoding="utf-8") as f:
            r = csv.DictReader(f)
            cols = {ren.get(c, c): c for c in r.fieldnames}
            miss = [k for k in IE if k not in cols and k not in OPTIONAL]
            if miss:
                sys.exit("%s: missing columns %s (use --map)" % (path, miss))
            g = lambda row, k: row.get(cols.get(k, ""), "")
            for row in r:
                proto = int(g(row, "protocolIdentifier") or 0)
                if proto not in PROTO:
                    skipped["proto"] += 1; continue
                src, dst = addr_bytes(g(row, "sourceIPv4Address")), addr_bytes(g(row, "destinationIPv4Address"))
                t0 = float(g(row, "flowStartMilliseconds")) / 1000.0; t1 = float(g(row, "flowEndMilliseconds")) / 1000.0
                sp, dp = int(g(row, "sourceTransportPort") or 0), int(g(row, "destinationTransportPort") or 0)
                if proto == 1:
                    sp = dp = 0
                fl = dict(t0=t0, t1=t1, src=src, dst=dst, sp=sp, dp=dp, proto=proto,
                          ob=int(g(row, "octetTotalCount") or 0), rb=int(g(row, "reverseOctetTotalCount") or 0),
                          op=int(g(row, "packetTotalCount") or 0), rp=int(g(row, "reversePacketTotalCount") or 0),
                          rrst=rst(g(row, "reverseUnionTCPFlags")))
                if dcols:
                    me = addr_bytes(row[dcols[1]])
                    targets = [(row[dcols[0]], me)] if me in (src, dst) else []
                else:
                    targets = [(ipstr(x), x) for x in (src, dst) if is_local(x)]
                    if src == dst:
                        targets = targets[:1]
                if not targets:
                    skipped["no_device"] += 1
                for dev, me in targets:
                    peer = dst if me == src else src
                    if is_bcast_mcast(peer):
                        skipped["bcast"] += 1; continue
                    h = hours[dev][int(t0 // 3600)]
                    if len(h) < a.max_per_hour:
                        h.append((me, peer, fl))
    n = 0
    with open(a.out, "w") as o:
        for dev in sorted(hours):
            prev = collections.deque(maxlen=24)
            for hr in sorted(hours[dev]):
                flows = hours[dev][hr]
                me = ipstr(flows[0][0])
                base = set().union(*prev) if prev else set()
                agg = Agg({"window_id": "%s|%d" % (dev, hr), "dataset": a.dataset, "capture": "%s-%s" % (a.dataset, dev),
                           "host": me, "hour": "%d" % hr, "split": "eval"})
                evs, ctx, pairs = [], {}, set()
                for _me, peer_b, fl in flows:
                    init_me = fl["src"] == _me
                    peer = ipstr(peer_b)
                    src, dst = (me, peer) if init_me else (peer, me)
                    back = fl["rp"] > 0 or fl["rb"] > 0
                    state = "S0" if not back else ("REJ" if fl["rrst"] and fl["rb"] == 0 else "SF")
                    evs.append({"type": "flow", "ts": ts_str(fl["t0"]), "src_ip": src, "dst_ip": dst, "dst_port": fl["dp"],
                                "proto": PROTO[fl["proto"]], "bytes_out": fl["ob"] if init_me else fl["rb"],
                                "bytes_in": fl["rb"] if init_me else fl["ob"], "conn_state": state, "orig_pkts": fl["op"],
                                "duration": max(0.0, fl["t1"] - fl["t0"])})
                    if ctxf and not is_local(peer_b):
                        ctx[peer] = ctxf(bytes(peer_b))
                    if init_me:
                        pairs.add((me, peer))
                agg.add({"events": evs, "remote_context": ctx, "baseline": {"pairs": [list(p) for p in base]},
                         "labels": {"benign": len(evs)}})
                prev.append(pairs)
                o.write(json.dumps(agg.vector()) + "\n"); n += 1
    print("devices %d, device-hours %d, skipped %s" % (len(hours), n, dict(skipped)))


if __name__ == "__main__":
    main()
