#!/usr/bin/env python3
"""gen-attacks — synthetic, labelled attack pcaps for the detection benchmark (pure Python, no scapy).

  gen-attacks.py OUTDIR      -> OUTDIR/<class>.pcap for every class below

Each class is a small, realistic-shaped episode from one LAN attacker (10.99.0.66) with the replies a real
target would send (the scan tier only counts scans with server evidence, ADR 0049 D3). They are meant to be
mixed over a benign background capture by pcap2hqdb.py.
"""
import os, random, struct, sys

ATT_MAC, VIC_MAC, GW_MAC = bytes.fromhex("02aa00000066"), bytes.fromhex("02aa00000020"), bytes.fromhex("020000000001")
ATT, VIC, GW = bytes([10, 99, 0, 66]), bytes([10, 99, 0, 20]), bytes([10, 99, 0, 1])

def csum(b):
    if len(b) % 2:
        b += b"\0"
    s = sum(struct.unpack("!%dH" % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return (~s) & 0xFFFF

def ip4(src, dst, proto, l4, ident=0):
    h = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(l4), ident & 0xFFFF, 0x4000, 64, proto, 0, src, dst)
    h = h[:10] + struct.pack("!H", csum(h)) + h[12:]
    return h + l4

def l4sum(src, dst, proto, seg):
    return csum(src + dst + struct.pack("!BBH", 0, proto, len(seg)) + seg)

def tcp(src, dst, sp, dp, flags, seq=0, ack=0, data=b""):
    seg = struct.pack("!HHIIBBHHH", sp, dp, seq, ack, 0x50, flags, 64240, 0, 0) + data
    seg = seg[:16] + struct.pack("!H", l4sum(src, dst, 6, seg)) + seg[18:]
    return ip4(src, dst, 6, seg)

def udp(src, dst, sp, dp, data):
    seg = struct.pack("!HHHH", sp, dp, 8 + len(data), 0) + data
    seg = seg[:6] + struct.pack("!H", l4sum(src, dst, 17, seg)) + seg[8:]
    return ip4(src, dst, 17, seg)

def eth(dmac, smac, typ, payload):
    return dmac + smac + struct.pack("!H", typ) + payload

def arp(op, smac, sip, tmac, tip):
    return eth(b"\xff" * 6 if op == 1 else tmac, smac, 0x0806, struct.pack("!HHBBH6s4s6s4s", 1, 0x0800, 6, 4, op, smac, sip, tmac, tip))

def write_pcap(path, frames):
    with open(path, "wb") as f:
        f.write(struct.pack("<IHHiIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        for t, fr in frames:
            f.write(struct.pack("<IIII", int(t), int((t % 1) * 1e6), len(fr), len(fr)) + fr)

def conv(frames, t, cli_mac, srv_mac, cli, srv, sp, dp, up=b"", down=b"", fin=True):
    """One full TCP conversation (handshake, one request + answer, close)."""
    a = lambda *x: frames.append((t[0], eth(srv_mac, cli_mac, 0x0800, tcp(cli, srv, *x))))
    b = lambda *x: frames.append((t[0], eth(cli_mac, srv_mac, 0x0800, tcp(srv, cli, *x))))
    a(sp, dp, 0x02, 1000); t[0] += 0.002
    b(dp, sp, 0x12, 5000, 1001); t[0] += 0.002
    a(sp, dp, 0x10, 1001, 5001); t[0] += 0.001
    if up:
        a(sp, dp, 0x18, 1001, 5001, up); t[0] += 0.01
    if down:
        b(dp, sp, 0x18, 5001, 1001 + len(up), down); t[0] += 0.01
    if fin:
        a(sp, dp, 0x11, 1001 + len(up), 5001 + len(down)); t[0] += 0.002
        b(dp, sp, 0x11, 5001 + len(down), 1002 + len(up)); t[0] += 0.002

def main():
    out = sys.argv[1] if len(sys.argv) > 1 else "."
    os.makedirs(out, exist_ok=True)
    rnd = random.Random(7)
    T0 = 1_762_000_000.0
    C = {}
    # LAN port scan with closed-port RSTs + a few open ports
    f, t = [], T0
    for p in range(1, 1025):
        f.append((t, eth(VIC_MAC, ATT_MAC, 0x0800, tcp(ATT, VIC, 40000 + p % 500, p, 0x02, p))))
        flags = 0x12 if p in (22, 80, 443) else 0x14
        f.append((t + 0.0005, eth(ATT_MAC, VIC_MAC, 0x0800, tcp(VIC, ATT, p, 40000 + p % 500, flags, 0, p + 1))))
        t += 0.004
    C["portscan"] = f
    # known C2 port + backdoor + telnet
    f, t = [], [T0]
    for dp in (4444, 31337, 23):
        conv(f, t, ATT_MAC, GW_MAC, ATT, bytes([203, 0, 113, 9]), 45000 + dp % 1000, dp, b"hello", b"ok")
        t[0] += 5
    C["c2port"] = f
    # SSH brute force: 40 short sessions in 80 s
    f, t = [], [T0]
    for i in range(40):
        conv(f, t, ATT_MAC, VIC_MAC, ATT, VIC, 50000 + i, 22, b"SSH-2.0-OpenSSH_9.6\r\n" + b"x" * 300, b"SSH-2.0-OpenSSH_9.2\r\n" + b"y" * 400)
        t[0] += 2
    C["ssh_brute"] = f
    # C2 beacon: every 60 s (+-1 s) to one host for 20 min
    f, t = [], [T0]
    for i in range(20):
        conv(f, t, ATT_MAC, GW_MAC, ATT, bytes([203, 0, 113, 50]), 51000 + i, 443, b"\x16\x03\x01" + b"b" * 120, b"\x16\x03\x03" + b"r" * 200)
        t[0] = T0 + (i + 1) * 60 + rnd.uniform(-1, 1)
    C["beacon"] = f
    # DGA-style DNS lookups
    f, t = [], T0
    for i in range(60):
        name = "".join(rnd.choice("bcdfghjklmnpqrstvwxz") for _ in range(14)) + ".com"
        q = struct.pack("!HHHHHH", 0x1000 + i, 0x0100, 1, 0, 0, 0) + b"".join(bytes([len(x)]) + x.encode() for x in name.split(".")) + b"\0\0\1\0\1"
        f.append((t, eth(GW_MAC, ATT_MAC, 0x0800, udp(ATT, GW, 33000 + i, 53, q))))
        t += 2
    C["dga"] = f
    # ARP spoofing the gateway
    f, t = [], T0
    for i in range(5):  # the real gateway first (the detector learns IP -> MAC), then the attacker's claims
        f.append((t, arp(2, GW_MAC, GW, VIC_MAC, VIC)))
        t += 2
    for i in range(20):
        f.append((t, arp(2, ATT_MAC, GW, VIC_MAC, VIC)))
        t += 1.5
    C["arp_spoof"] = f
    # exfil: 80 MB to one internet host in ~60 s (the detector's bar is 50 MB / minute)
    f, t = [], T0
    dst = bytes([192, 0, 2, 200])
    tt = [t]
    conv(f, tt, ATT_MAC, GW_MAC, ATT, dst, 52000, 443, fin=False)
    t = tt[0]
    for i in range(57000):  # a real upload (80 MB in ~60 s): the server ACKs every other segment
        f.append((t, eth(GW_MAC, ATT_MAC, 0x0800, tcp(ATT, dst, 52000, 443, 0x18, 1001 + i * 1400, 5001, b"e" * 1400))))
        if i % 2:
            f.append((t + 0.0005, eth(ATT_MAC, GW_MAC, 0x0800, tcp(dst, ATT, 443, 52000, 0x10, 5001, 1001 + (i + 1) * 1400))))
        t += 0.00105
    C["exfil"] = f
    # lateral movement: SMB/RDP to many LAN hosts
    f, t = [], [T0]
    for h in range(2, 60):
        hip, hmac = bytes([10, 99, 0, h]), bytes([2, 0xbb, 0, 0, 0, h])
        for dp in (445, 3389):
            conv(f, t, ATT_MAC, hmac, ATT, hip, 53000 + h, dp, b"\x00" * 64, b"\x00" * 64)
            t[0] += 0.2
    C["lateral"] = f
    for k, fr in C.items():
        write_pcap(os.path.join(out, k + ".pcap"), fr)
        print(f"{k}: {len(fr)} frames")

if __name__ == "__main__":
    main()
