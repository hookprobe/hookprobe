#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Deterministic capture for the neuro-dp parity test (docs/research/neuro/20 §5.1).

Writes, next to this file:
  fixture.pcap        a synthetic classic pcap (us), ~3 UTC hours, 4 devices, every doc-20 rule exercised:
                      DNS queries (2- and 3-label registered domains, mixed case), responses with A/AAAA answers
                      (compressed names) -> named peers, NXDOMAIN, unanswered and duplicate queries, TCP SYN / SYN-ACK /
                      ACK, UDP flows with gaps under and over 120 s, NTP / multicast (class), local peers, IPv6, 802.1Q
  fixture.macs        the device list (index = line order)
  fixture.expect.txt  the reference converter's output on it (unsw_to_d1.py --peer-key v2-24 --name-table 4096),
                      one line per device-hour: dev hour conns bytes | sorted peers | sorted dns fp:nx
Regenerate: python3 -I os/neuro/neuro-dp/tests/gen_fixture.py
"""
import json
import os
import random
import struct
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", "..", "..", ".."))
CONV = os.path.join(ROOT, "tools", "neuro-research", "unsw_to_d1.py")

R = random.Random(20261122)
T0 = 1_795_000_000 // 3600 * 3600 + 1800  # half past an hour: the capture crosses two hour boundaries
DEVS = [bytes([0x3C, 0x22, 0xFB, 0, 0, i + 1]) for i in range(4)]
GW = bytes([0x02, 0x99, 0, 0, 0, 1])
DEV_IP = [bytes([192, 168, 7, 10 + i]) for i in range(4)]
DEV_IP6 = [bytes.fromhex("fd00000000000000000000000000%04x" % (0x10 + i)) for i in range(4)]
DNS_IP = bytes([192, 168, 7, 1])
NAMES = ["api.Example.com", "cdn.example.com", "telemetry.vendor.co.uk", "img.svc.io", "a.b.c.d.example.org",
         "updates.thing.net", "time.cloud.com", "x.y.co.jp", "NoSuch-Host.invalid.tld", "dga-qwkjhe.biz"]


def eth(src, dst, et, body, vlan=None):
    if vlan is not None:
        return dst + src + struct.pack("!HHH", 0x8100, vlan, et) + body
    return dst + src + struct.pack("!H", et) + body


def ipv4(src, dst, proto, l4):
    return struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(l4), 0, 0, 64, proto, 0, src, dst) + l4


def ipv6(src, dst, proto, l4):
    return struct.pack("!IHBB16s16s", 0x60000000, len(l4), proto, 64, src, dst) + l4


def tcp(sp, dp, flags, payload=b""):
    return struct.pack("!HHIIBBHHH", sp, dp, 0, 0, 5 << 4, flags, 0, 0, 0) + payload


def udp(sp, dp, payload):
    return struct.pack("!HHHH", sp, dp, 8 + len(payload), 0) + payload


def qname(name):
    return b"".join(bytes([len(l)]) + l.encode() for l in name.split(".")) + b"\0"


def dns_query(txid, name):
    return struct.pack("!HHHHHH", txid, 0x0100, 1, 0, 0, 0) + qname(name) + struct.pack("!HH", 1, 1)


def dns_response(txid, name, rcode=0, answers=()):
    body = struct.pack("!HHHHHH", txid, 0x8180 | rcode, 1, len(answers), 0, 0) + qname(name) + struct.pack("!HH", 1, 1)
    for a in answers:
        typ = 1 if len(a) == 4 else 28
        body += struct.pack("!HHHIH", 0xC00C, typ, 1, 300, len(a)) + a  # name = pointer to the question
    return body


def pub4():
    return bytes([R.choice([8, 23, 34, 52, 104, 142, 151, 172 + 1]), R.randrange(256), R.randrange(256), R.randrange(1, 255)])


def main():
    pkts = []  # (ts, frame)
    resolved = {d: [] for d in range(4)}
    t = float(T0)
    end = T0 + 3 * 3600
    udp_flows = {d: [] for d in range(4)}
    while t < end:
        t += R.expovariate(1 / 6.0)
        d = R.randrange(4)
        mac, ip = DEVS[d], DEV_IP[d]
        vlan = 7 if d == 3 else None
        r = R.random()
        if r < 0.25:  # DNS query (+ response most of the time)
            name = R.choice(NAMES)
            txid = R.randrange(65536)
            pkts.append((t, eth(mac, GW, 0x0800, ipv4(ip, DNS_IP, 17, udp(40000 + d, 53, dns_query(txid, name))), vlan)))
            if R.random() < 0.08:  # a duplicate query, same txid and name
                pkts.append((t + 0.2, eth(mac, GW, 0x0800, ipv4(ip, DNS_IP, 17, udp(40000 + d, 53, dns_query(txid, name.upper()))), vlan)))
            if "invalid" in name or "dga" in name:
                pkts.append((t + 0.03, eth(GW, mac, 0x0800, ipv4(DNS_IP, ip, 17, udp(53, 40000 + d, dns_response(txid, name, 3))), vlan)))
            elif R.random() < 0.9:
                ans = [pub4() for _ in range(R.randrange(1, 4))]
                if R.random() < 0.3:
                    ans.append(bytes.fromhex("2606470000000000000000000000%04x" % R.randrange(65536)))
                resolved[d].extend(ans)
                pkts.append((t + 0.03, eth(GW, mac, 0x0800, ipv4(DNS_IP, ip, 17, udp(53, 40000 + d, dns_response(txid, name, 0, ans))), vlan)))
        elif r < 0.55:  # TCP connection: SYN, SYN-ACK back, a data packet
            if resolved[d] and R.random() < 0.6:
                dst = R.choice(resolved[d])
            elif R.random() < 0.15:
                dst = bytes([192, 168, 7, R.randrange(100, 120)])
            else:
                dst = pub4()
            port = R.choice([443, 443, 80, 8883, 5228])
            sp = R.randrange(32768, 61000)
            if len(dst) == 16:
                pkts.append((t, eth(mac, GW, 0x86DD, ipv6(DEV_IP6[d], dst, 6, tcp(sp, port, 0x02)), vlan)))
                pkts.append((t + 0.02, eth(GW, mac, 0x86DD, ipv6(dst, DEV_IP6[d], 6, tcp(port, sp, 0x12)), vlan)))
            else:
                pkts.append((t, eth(mac, GW, 0x0800, ipv4(ip, dst, 6, tcp(sp, port, 0x02)), vlan)))
                pkts.append((t + 0.02, eth(GW, mac, 0x0800, ipv4(dst, ip, 6, tcp(port, sp, 0x12)), vlan)))
                pkts.append((t + 0.04, eth(mac, GW, 0x0800, ipv4(ip, dst, 6, tcp(sp, port, 0x18, b"x" * R.randrange(40, 900))), vlan)))
        elif r < 0.85:  # UDP: reuse a flow (gap under/over 120 s) or start one
            if udp_flows[d] and R.random() < 0.7:
                dst, dport, sp = R.choice(udp_flows[d])
            else:
                kind = R.random()
                if kind < 0.2:
                    dst, dport = pub4(), 123  # NTP: class
                elif kind < 0.35:
                    dst, dport = bytes([239, 255, 255, 250]), 1900  # multicast: class
                elif kind < 0.5:
                    dst, dport = bytes([192, 168, 7, 1]), 5000  # local
                else:
                    dst, dport = (R.choice(resolved[d]) if resolved[d] and R.random() < 0.5 else pub4()), 443
                if len(dst) == 16:
                    dst = pub4()
                sp = R.randrange(32768, 61000)
                udp_flows[d].append((dst, dport, sp))
            pkts.append((t, eth(mac, GW, 0x0800, ipv4(ip, dst, 17, udp(sp, dport, b"q" * R.randrange(20, 300))), vlan)))
        else:  # inbound traffic to the device, and other protocols (bytes only)
            if R.random() < 0.5:
                pkts.append((t, eth(GW, mac, 0x0800, ipv4(pub4(), ip, 6, tcp(443, 50000, 0x10, b"y" * 500)), vlan)))
            else:
                pkts.append((t, eth(mac, GW, 0x0800, ipv4(ip, pub4(), 1, b"\x08\x00" + b"p" * 54), vlan)))
        if R.random() < 0.01:  # a long quiet spell: UDP flows go idle past 120 s
            t += R.uniform(130, 400)
    pkts.sort(key=lambda p: p[0])

    with open(os.path.join(HERE, "fixture.pcap"), "wb") as f:
        f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for ts, fr in pkts:
            s = int(ts)
            us = int(round((ts - s) * 1e6))
            if us >= 1_000_000:
                s, us = s + 1, us - 1_000_000
            f.write(struct.pack("<IIII", s, us, len(fr), len(fr)) + fr)
    with open(os.path.join(HERE, "fixture.macs"), "w") as f:
        for i, m in enumerate(DEVS):
            f.write("%s dev%d\n" % (":".join("%02x" % b for b in m), i))

    with tempfile.TemporaryDirectory() as td:
        out, devs = os.path.join(td, "d1.jsonl"), os.path.join(td, "devices.tsv")
        subprocess.run([sys.executable, "-I", CONV, os.path.join(HERE, "fixture.pcap"), "--out", out, "--devices", devs,
                        "--macs", os.path.join(HERE, "fixture.macs"), "--peer-key", "v2-24", "--name-table", "4096"],
                       check=True, stdout=subprocess.DEVNULL)
        lines = []
        for line in open(out):
            r = json.loads(line)
            peers = " ".join("%08x" % p for p in sorted(r["peers"]))
            dns = " ".join("%08x:%d" % (fp, nx) for fp, nx in sorted(map(tuple, r["dns"])))
            lines.append("%d %d %d %d | %s | %s" % (r["dev"], r["hour"], r["conns"], r["bytes"], peers, dns))
    with open(os.path.join(HERE, "fixture.expect.txt"), "w") as f:
        f.write("\n".join(lines) + "\n")
    print("%d packets, %d device-hours" % (len(pkts), len(lines)))


if __name__ == "__main__":
    main()
