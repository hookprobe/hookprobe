#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Golden vectors for neuro_core::peerkey (docs/research/neuro/20) from the Python reference in unsw_to_d1.py.

Line formats (hex without 0x; '-' = none):
  P <mode> <proto> <ip hex> <port> <named state|-> <fp> <rule>     mode: exact | v1-24 | v1-16 | v2-24 | v2-16
                                                                    proto: tcp | udp | any
  I <dev> <ip hex> <state> <ts>                                     NameTable<64>::insert
  L <dev> <ip hex> <now> <state|->                                  NameTable<64>::lookup, expected result
Usage: python3 -I gen_peerkey_golden.py <out path>
"""
import os
import random
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import unsw_to_d1 as u  # noqa: E402

PROTO = {6: "tcp", 17: "udp", None: "any"}


def addr(r):
    k = r.random()
    if k < 0.08:
        return bytes([r.choice([224, 239]), r.randrange(256), r.randrange(256), r.randrange(256)])
    if k < 0.12:
        return bytes([192, 168, r.randrange(256), 255])
    if k < 0.30:
        return bytes(r.choice([[10, r.randrange(256)], [192, 168], [172, r.randrange(16, 32)], [169, 254], [127, 0]])) + \
            bytes([r.randrange(256), r.randrange(256)])
    if k < 0.42:
        pre = r.choice([b"\xfd", b"\xfe\x80", b"\xff\x02", b"\x20\x01\x0d\xb8"])
        return pre + bytes(r.randrange(256) for _ in range(16 - len(pre)))
    return bytes(r.randrange(256) for _ in range(4))


def main():
    r = random.Random(20)
    out = []
    ports = [123, 3478, 3479, 5349, 19302, 67, 68, 546, 547, 5353, 1900, 5355, 137, 138, 443, 80, 8883, 53, 0, 65535]
    for _ in range(600):
        ip = addr(r)
        port = r.choice(ports) if r.random() < 0.6 else r.randrange(65536)
        proto = r.choice([6, 17, None])
        state = u.svc_state(r.choice(["vendor.com", "example.co.uk", "a.org", "x" * 40 + ".net"])) if r.random() < 0.5 else None
        for mode in u.PEER_MODES:
            fp = u.service_peer_fp_state(mode, ip, port, proto, state)
            rule = u.peer_kind(mode, ip, port, proto, state)
            out.append("P %s %s %s %d %s %08x %s" % (mode, PROTO[proto], ip.hex(), port, "%016x" % state if state else "-", fp, rule))
    t = u.SetAssocNames(64)          # small: forces evictions
    ips = [addr(r) for _ in range(60)]
    now = 1_000_000
    for _ in range(4000):
        now += r.randrange(0, 120)
        dev = r.randrange(5)
        ip = r.choice(ips)
        if r.random() < 0.45:
            st = u.svc_state(r.choice(["a.com", "b.com", "c.net"]))
            ts = now - r.randrange(0, 3)
            t.insert(dev, ip, st, ts)
            out.append("I %d %s %016x %d" % (dev, ip.hex(), st, ts))
        else:
            res = t.lookup(dev, ip, now)
            out.append("L %d %s %d %s" % (dev, ip.hex(), now, "%016x" % res if res is not None else "-"))
    open(sys.argv[1], "w").write("\n".join(out) + "\n")
    print("wrote %d vectors (%d named-table ops)" % (len(out), 4000))


if __name__ == "__main__":
    main()
