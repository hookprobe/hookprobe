#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Doc 48 / doc 53 R10: the S1 alert's top-3 feature deviations (`dev=` token), defined in INTEGER arithmetic on the
u8 features the S1 integer twin already has (os/neuro/neuro-l1), so Python and Rust agree bit for bit.

From s1_model.json: q = round(255 * (x - lo) / range), and S1's float model standardises z = (x - mu) / sd. On the
dequantised x = lo + q * range / 255 this is exactly linear in q:
    z = A + B * q,   A = (lo - mu) / sd,   B = range / (255 * sd)
The contract fixes A and B as Q16 integers (round half to even, once, here) and everything after that is integer:
    z_q16[i] = A_Q16[i] + B_Q16[i] * q[i]                     (|z_q16| < 2^31, checked)
    top 3 by |z_q16| descending, ties -> the lower feature index
    tenths   = (|z_q16| * 10 + 32768) >> 16                   (round half up on the magnitude)
    token    = "<name><+|-><tenths // 10>.<tenths % 10>" joined by ",";  sign "+" iff z_q16 >= 0
It DESCRIBES an S1 decision; it never changes one.

Usage: dev_token.py vectors <fixture.txt> <out.txt>   (id + token per W/E line of neuro-l1's parity fixture)
       dev_token.py q <comma-separated 28 u8>          (prints the token)
"""
import json, os, sys
HERE = os.path.dirname(os.path.abspath(__file__))
MODEL = os.path.join(HERE, "models", "s1", "s1_model.json")
NAMES = ["flows", "out", "remotes", "dst_ports", "port_entropy", "top_port", "fail", "bytes_out", "bytes_in", "out_in",
         "mean_dur", "pkts_per_flow", "tcp", "udp", "icmp", "wellknown", "telnet", "ssh", "smb", "web", "dns", "ntp",
         "periodic_cv", "period", "max_per_min", "novel_pair", "lan_peer", "inbound_sources"]


def tables(path=MODEL):
    m = json.load(open(path))
    assert len(m["features"]) == 28 == len(NAMES)
    I, F = m["integer"], m["float"]
    a = [round((lo - mu) / sd * 65536) for lo, mu, sd in zip(I["lo"], F["mu"], F["sd"])]
    b = [round(rg / (255 * sd) * 65536) for rg, sd in zip(I["range"], F["sd"])]
    for ai, bi in zip(a, b):
        assert max(abs(ai), abs(ai + 255 * bi)) < 2 ** 31
    return a, b


A_Q16, B_Q16 = tables()


def z_q16(q):
    return [a + b * v for a, b, v in zip(A_Q16, B_Q16, q)]


def deviations(q):
    z = z_q16(q)
    order = sorted(range(28), key=lambda i: (-abs(z[i]), i))[:3]
    return [(i, z[i]) for i in order]


def token(q):
    out = []
    for i, z in deviations(q):
        t = (abs(z) * 10 + 32768) >> 16
        out.append("%s%s%d.%d" % (NAMES[i], "+" if z >= 0 else "-", t // 10, t % 10))
    return ",".join(out)


def main():
    if sys.argv[1] == "q":
        print(token([int(v) for v in sys.argv[2].split(",")]))
        return
    src, dst = sys.argv[2], sys.argv[3]
    n = 0
    with open(dst, "w") as f:
        for line in open(src):
            p = line.split(" ")
            if p[0] in ("W", "E"):
                f.write("%s %s\n" % (p[1], token([int(v) for v in p[3].split(",")])))
                n += 1
    print("wrote %d tokens to %s" % (n, dst))


if __name__ == "__main__":
    main()
