#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""End-to-end ATTACK path: synthetic attack traffic merged into a spent BENIGN capture, so the whole Neuro chain
(e2e_neuro.sh) sees real alerts. The attacks are written here, by us: they test the pipeline's mechanics and cost on
alerts, NOT real-world recall (that is the blind sets' and M4's job).

Injected, each in its own hours on the capture's device (its MAC and LAN address), via its real gateway MAC:
  scan     Mirai-like: 1 hour of TCP SYNs to port 23/2323 on ~3,000 random remote addresses, mostly unanswered, some RST
  beacon   C2: 6 hours, one remote on 443, a small request/response every 60 s +- 2 s
  exfil    1 hour, 150 connections each uploading ~1 MB to one new remote on 443
  brute    1 hour of outbound SSH attempts to one remote: 600 connections, the remote resets each one
Remote addresses are synthetic (RFC 5737 plus random high octets); no real host is contacted. Output: a classic pcap
(microsecond timestamps, Ethernet) with every frame in time order, plus a manifest of injected device-hours.
Usage: e2e_inject.py <benign pcap> <device mac hex> <out.pcap> [--start-hour 240] [--seed 11]
"""
import json, os, random, struct, sys
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import unsw_to_d1 as u  # noqa: E402


def csum(b):
    if len(b) % 2:
        b += b"\0"
    s = sum(struct.unpack("!%dH" % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return ~s & 0xFFFF


def frame(smac, dmac, src, dst, sport, dport, flags, payload=b"", proto=6):
    if proto == 6:
        l4 = struct.pack("!HHIIBBHHH", sport, dport, 0, 0, 5 << 4, flags, 65535, 0, 0) + payload
    else:
        l4 = struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(l4), 0, 0x4000, 64, proto, 0, src, dst)
    ip = ip[:10] + struct.pack("!H", csum(ip)) + ip[12:]
    return dmac + smac + b"\x08\x00" + ip + l4


def main():
    src_p, mac_hex, out = sys.argv[1], sys.argv[2], sys.argv[3]
    start_h = int(sys.argv[sys.argv.index("--start-hour") + 1]) if "--start-hour" in sys.argv else 240
    r = random.Random(int(sys.argv[sys.argv.index("--seed") + 1]) if "--seed" in sys.argv else 11)
    dev = bytes.fromhex(mac_hex)
    gw = ip = None; first = None
    with open(src_p, "rb") as f:                      # pass 1: the device's LAN address and its gateway MAC
        for ts, fr, lt in u.packets(f):
            first = first if first is not None else ts
            p = u.parse(fr, lt)
            if p and bytes(p[0]) == dev and p[2] == 4 and not u.is_local(bytes(p[4])):
                ip, gw = bytes(p[3]), bytes(p[1])
                break
    if ip is None:
        sys.exit("device sends no internet traffic in this capture")
    base = (int(first // 3600) + start_h) * 3600
    inj, manifest = [], {}
    pub = lambda: bytes([r.choice([45, 77, 91, 103, 185, 193, 212]), r.randrange(256), r.randrange(256), r.randrange(1, 255)])

    def mark(h, kind):
        manifest[str(int(base // 3600) + h)] = kind

    # scan: hour 0
    mark(0, "scan")
    for i in range(3000):
        t = base + r.uniform(5, 3590); d = pub(); dp = r.choice([23, 23, 23, 2323])
        sp = r.randrange(30000, 60000)
        inj.append((t, frame(dev, gw, ip, d, sp, dp, 0x02)))
        if r.random() < 0.15:
            inj.append((t + 0.08, frame(gw, dev, d, ip, dp, sp, 0x14)))      # RST,ACK
    # beacon: hours 24..29 (a day later)
    C2 = bytes([203, 0, 113, r.randrange(1, 255)])
    mark_hours = range(24, 30)
    for h in mark_hours:
        mark(h, "beacon")
    t = base + 24 * 3600 + 10
    while t < base + 30 * 3600:
        sp = r.randrange(30000, 60000)
        inj += [(t, frame(dev, gw, ip, C2, sp, 443, 0x02)), (t + 0.04, frame(gw, dev, C2, ip, 443, sp, 0x12)),
                (t + 0.05, frame(dev, gw, ip, C2, sp, 443, 0x18, os.urandom(180))), (t + 0.11, frame(gw, dev, C2, ip, 443, sp, 0x18, os.urandom(90))),
                (t + 0.12, frame(dev, gw, ip, C2, sp, 443, 0x11))]
        t += 60 + r.uniform(-2, 2)
    # exfil: hour 48
    mark(48, "exfil")
    X = bytes([198, 51, 100, r.randrange(1, 255)])
    for i in range(150):
        t = base + 48 * 3600 + 20 + i * 23; sp = r.randrange(30000, 60000)
        inj += [(t, frame(dev, gw, ip, X, sp, 443, 0x02)), (t + 0.03, frame(gw, dev, X, ip, 443, sp, 0x12))]
        for k in range(700):                                               # ~1 MB in 1,400-byte segments
            inj.append((t + 0.05 + k * 0.002, frame(dev, gw, ip, X, sp, 443, 0x18, b"\0" * 1400)))
        inj.append((t + 1.6, frame(gw, dev, X, ip, 443, sp, 0x10)))
    # brute: hour 72
    mark(72, "brute")
    B = bytes([192, 0, 2, r.randrange(1, 255)])
    for i in range(600):
        t = base + 72 * 3600 + 5 + i * 5.9; sp = r.randrange(30000, 60000)
        inj += [(t, frame(dev, gw, ip, B, sp, 22, 0x02)), (t + 0.03, frame(gw, dev, B, ip, 22, sp, 0x12)),
                (t + 0.05, frame(dev, gw, ip, B, sp, 22, 0x18, os.urandom(120))), (t + 0.3, frame(gw, dev, B, ip, 22, sp, 0x04))]
    inj.sort(key=lambda x: x[0])
    n_in = n_out = 0
    with open(src_p, "rb") as f, open(out, "wb") as o:
        o.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 262144, 1))
        def w(ts, fr):
            o.write(struct.pack("<IIII", int(ts), int(round((ts % 1) * 1e6)) % 1000000, len(fr), len(fr)) + fr)
        j = 0
        for ts, fr, lt in u.packets(f):
            while j < len(inj) and inj[j][0] <= ts:
                w(*inj[j]); j += 1; n_in += 1
            w(ts, fr); n_out += 1
        for k in range(j, len(inj)):
            w(*inj[k]); n_in += 1
    json.dump({"source": os.path.basename(src_p), "device_mac": mac_hex, "device_ip": ".".join(map(str, ip)),
               "injected_hours": manifest, "injected_frames": n_in}, open(out + ".manifest.json", "w"), indent=1)
    print("wrote %s: %d original + %d injected frames; injected device-hours %s" % (out, n_out, n_in, manifest))


if __name__ == "__main__":
    main()
