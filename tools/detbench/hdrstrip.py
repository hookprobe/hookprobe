#!/usr/bin/env python3
"""hdrstrip — DET-01 privacy filter for the household benign corpus (operator decision 2026-11-12: home LAN mirror,
METADATA ONLY, stored locally, never uploaded).

  tcpdump -i FTS-mirror -s 160 -U -w - | hdrstrip.py OUT.pcap

Reads a classic pcap stream on stdin and writes one where every frame keeps only its headers — Ethernet (+ up to two
802.1Q tags), ARP, IPv4 / IPv6 (+ hop-by-hop / routing / fragment / destination-options), TCP / UDP / ICMP / ICMPv6 —
and every byte after the last header is ZERO, padded to the frame's original length (so length- and rate-based rules
see the real sizes, and pcap2hqdb.py keeps the frame: incl == orig). No payload byte is ever written: frames whose
headers cannot be parsed are reduced to the Ethernet header + zeros. Frames over 1518 B (host GRO artefacts) are
dropped, as pcap2hqdb.py would. Summary (frames in / out / unparsed) on stderr.
Content rules (DNS names / Shield, TLS ClientHello / JA4, rules 125 / 126) get no FP figure from this corpus.
"""
import struct, sys

def l4_end(f):
    """Byte offset where the headers end (everything after is payload), or 14 if unknown."""
    o, et = 12, None
    if len(f) < 14:
        return len(f)
    et = struct.unpack(">H", f[12:14])[0]; o = 14
    for _ in range(2):
        if et in (0x8100, 0x88A8) and len(f) >= o + 4:
            et = struct.unpack(">H", f[o + 2:o + 4])[0]; o += 4
    if et == 0x0806:
        return min(len(f), o + 28)
    proto = None
    if et == 0x0800 and len(f) >= o + 20:
        ihl = (f[o] & 0x0F) * 4
        if ihl < 20:
            return o
        frag = struct.unpack(">H", f[o + 6:o + 8])[0]
        proto = f[o + 9]; o += ihl
        if frag & 0x1FFF:  # a non-first fragment carries no L4 header
            return min(len(f), o)
    elif et == 0x86DD and len(f) >= o + 40:
        proto = f[o + 6]; o += 40
        for _ in range(4):
            if proto in (0, 43, 60) and len(f) >= o + 2:
                proto, o = f[o], o + (f[o + 1] + 1) * 8
            elif proto == 44 and len(f) >= o + 8:
                nxt, off = f[o], struct.unpack(">H", f[o + 2:o + 4])[0] >> 3
                o += 8; proto = nxt
                if off:
                    return min(len(f), o)
            else:
                break
    else:
        return 14
    if proto == 6 and len(f) >= o + 20:
        return min(len(f), o + max(20, (f[o + 12] >> 4) * 4))
    if proto == 17:
        return min(len(f), o + 8)
    if proto in (1, 58):
        return min(len(f), o + 8)
    return min(len(f), o)

def main():
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    r = sys.stdin.buffer
    g = r.read(24)
    if len(g) < 24:
        sys.exit("hdrstrip: no pcap header on stdin")
    magic = struct.unpack("<I", g[:4])[0]
    e = "<" if magic in (0xa1b2c3d4, 0xa1b23c4d) else ">" if magic in (0xd4c3b2a1, 0x4d3cb2a1) else None
    if e is None or struct.unpack(e + "I", g[20:24])[0] != 1:
        sys.exit("hdrstrip: need a classic Ethernet pcap stream")
    n_in = n_out = n_unk = 0
    with open(sys.argv[1], "wb") as w:
        nano = magic in (0xa1b23c4d, 0x4d3cb2a1)
        w.write(struct.pack("<IHHiIII", 0xa1b23c4d if nano else 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        while True:
            h = r.read(16)
            if len(h) < 16:
                break
            s, frac, incl, orig = struct.unpack(e + "IIII", h)
            f = r.read(incl)
            if len(f) < incl:
                break
            n_in += 1
            if orig > 1518:
                continue
            k = min(l4_end(f), len(f))
            if k <= 14:
                n_unk += 1
            out = f[:k] + bytes(orig - k)
            w.write(struct.pack("<IIII", s, frac, orig, orig) + out)
            n_out += 1
            if n_out % 1000 == 0:
                w.flush()
    print(f"hdrstrip: {n_in} frames in, {n_out} out (headers only, payload zeroed), {n_unk} reduced to Ethernet", file=sys.stderr)

if __name__ == "__main__":
    main()
