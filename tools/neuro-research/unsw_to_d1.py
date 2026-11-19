#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""D1 converter (docs/research/neuro/17): packet captures -> the temporal engine's own inputs, per device-hour.

Output JSONL, one line per active device-hour, and NOTHING identifying:
  {"dev": <device index>, "hour": <UTC epoch hour>, "conns": n, "bytes": b,
   "peers": [peer fingerprint, ...],             # one per new connection (duplicates allowed)
   "dns": [[suffix fingerprint, nx 0|1], ...]}   # one per query the device sent
A separate devices.tsv maps the device index to the MAC address and name given by the dataset.
No IP address, domain name or payload is ever written.

Fingerprints are exactly those of tools/neuro-research/dna_fixed.py and os/neuro/neuro-core:
  IPv4 peer : fingerprint(peer_key(ipv4, port))
  IPv6 peer : fingerprint(fnv1a64(16 address bytes + 2 port bytes, big-endian))
  DNS       : fingerprint(fnv1a64(registered domain)), where the registered domain is the last two labels,
              or the last three when the second-to-last label has <= 3 characters (pinned rule, doc 17).
New connection: a TCP SYN without ACK sent by the device; or a UDP 5-tuple from the device that was idle
for >= 120 s. DNS (UDP/53) queries are DNS events, not peers. NXDOMAIN = a response to the device with
rcode 3, matched to its query by (transaction id, question name).

Pure standard library: classic pcap (us/ns, both byte orders) and pcapng (EPB/SPB), Ethernet II with
802.1Q/QinQ, IPv4, IPv6 (no extension-header walking beyond the fixed header), TCP, UDP.
Usage:
  python3 -I unsw_to_d1.py --selftest
  python3 -I unsw_to_d1.py <pcap dir or file> --out d1.jsonl --devices devices.tsv [--macs mac_list.csv]
"""
import argparse
import glob
import json
import os
import struct
import sys
import zipfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import dna_fixed as fx  # noqa: E402

UDP_IDLE = 120.0


def registered_domain(name):
    labels = [l for l in name.lower().rstrip(".").split(".") if l]
    if len(labels) <= 2:
        return ".".join(labels)
    k = 3 if len(labels[-2]) <= 3 else 2
    return ".".join(labels[-k:])


def dns_fp(name):
    return fx.fingerprint(fx.fnv1a64(registered_domain(name).encode()))


def peer_fp(ip, port):
    if len(ip) == 4:
        return fx.fingerprint(fx.peer_key(int.from_bytes(ip, "big"), port))
    return fx.fingerprint(fx.fnv1a64(ip + port.to_bytes(2, "big")))


# ------------------------------------------------------------------------------------------------ pcap readers
def packets(f):
    """Yield (ts seconds, frame bytes, linktype) from a classic pcap or pcapng stream."""
    head = f.read(4)
    if len(head) < 4:
        return
    if head == b"\x0a\x0d\x0d\x0a":
        yield from _pcapng(f, head)
        return
    magic = struct.unpack("<I", head)[0]
    if magic in (0xA1B2C3D4, 0xA1B23C4D):
        e = "<"
    elif magic in (0xD4C3B2A1, 0x4D3CB2A1):
        e = ">"
    else:
        raise ValueError("not a pcap/pcapng file")
    ns = magic in (0xA1B23C4D, 0x4D3CB2A1)
    rest = f.read(20)
    linktype = struct.unpack(e + "I", rest[16:20])[0] & 0x0FFFFFFF
    div = 1e9 if ns else 1e6
    while True:
        h = f.read(16)
        if len(h) < 16:
            return
        sec, frac, incl, _ = struct.unpack(e + "IIII", h)
        data = f.read(incl)
        if len(data) < incl:
            return
        yield sec + frac / div, data, linktype


def _pcapng(f, first):
    e = "<"
    links, res = [], []
    buf = first
    while True:
        h = buf + f.read(8 - len(buf)) if buf else f.read(8)
        buf = b""
        if len(h) < 8:
            return
        btype = struct.unpack(e + "I", h[:4])[0]
        if btype == 0x0A0D0D0A:  # section header: byte order from the BOM
            bom = f.read(4)
            e = "<" if bom == b"\x4d\x3c\x2b\x1a" else ">"
            blen = struct.unpack(e + "I", h[4:8])[0]
            f.read(blen - 12)
            links, res = [], []
            continue
        blen = struct.unpack(e + "I", h[4:8])[0]
        body = f.read(blen - 8)
        if len(body) < blen - 8:
            return
        if btype == 1:  # interface description
            links.append(struct.unpack(e + "H", body[:2])[0])
            tsres = 6
            opts = body[8:-4]
            i = 0
            while i + 4 <= len(opts):
                code, ln = struct.unpack(e + "HH", opts[i:i + 4])
                if code == 0:
                    break
                if code == 9 and ln >= 1:
                    tsres = opts[i + 4]
                i += 4 + ((ln + 3) & ~3)
            res.append(10 ** (tsres & 0x7F) if not tsres & 0x80 else 2 ** (tsres & 0x7F))
        elif btype == 6:  # enhanced packet
            iface, th, tl, cap = struct.unpack(e + "IIII", body[:16])
            ts = ((th << 32) | tl) / (res[iface] if iface < len(res) else 1e6)
            yield ts, body[20:20 + cap], links[iface] if iface < len(links) else 1
        elif btype == 3:  # simple packet
            orig = struct.unpack(e + "I", body[:4])[0]
            yield 0.0, body[4:4 + orig], links[0] if links else 1


# ------------------------------------------------------------------------------------------------ parsing
def parse(frame, linktype):
    """-> (src_mac, dst_mac, ip_ver, src_ip, dst_ip, proto, sport, dport, flags, payload, ip_len) or None."""
    if linktype != 1 or len(frame) < 14:
        return None
    dst_mac, src_mac = frame[0:6], frame[6:12]
    et = struct.unpack("!H", frame[12:14])[0]
    off = 14
    while et in (0x8100, 0x88A8) and len(frame) >= off + 4:
        et = struct.unpack("!H", frame[off + 2:off + 4])[0]
        off += 4
    if et == 0x0800 and len(frame) >= off + 20:
        ihl = (frame[off] & 0x0F) * 4
        ip_len = struct.unpack("!H", frame[off + 2:off + 4])[0]
        proto = frame[off + 9]
        src, dst = frame[off + 12:off + 16], frame[off + 16:off + 20]
        l4 = off + ihl
        ver = 4
    elif et == 0x86DD and len(frame) >= off + 40:
        ip_len = struct.unpack("!H", frame[off + 4:off + 6])[0] + 40
        proto = frame[off + 6]
        src, dst = frame[off + 8:off + 24], frame[off + 24:off + 40]
        l4 = off + 40
        ver = 6
    else:
        return None
    if proto == 6 and len(frame) >= l4 + 14:
        sp, dp = struct.unpack("!HH", frame[l4:l4 + 4])
        doff = (frame[l4 + 12] >> 4) * 4
        return src_mac, dst_mac, ver, src, dst, 6, sp, dp, frame[l4 + 13], frame[l4 + doff:], ip_len
    if proto == 17 and len(frame) >= l4 + 8:
        sp, dp = struct.unpack("!HH", frame[l4:l4 + 4])
        return src_mac, dst_mac, ver, src, dst, 17, sp, dp, 0, frame[l4 + 8:], ip_len
    return src_mac, dst_mac, ver, src, dst, proto, 0, 0, 0, b"", ip_len


def dns_question(p):
    """-> (txid, rcode, is_response, qname) or None. Uncompressed question name only (as in real queries)."""
    if len(p) < 12:
        return None
    txid, flags, qd = struct.unpack("!HHH", p[:6])
    if qd < 1:
        return None
    i, labels = 12, []
    while i < len(p):
        ln = p[i]
        if ln == 0:
            break
        if ln & 0xC0 or i + 1 + ln > len(p):
            return None
        labels.append(p[i + 1:i + 1 + ln].decode("ascii", "replace"))
        i += 1 + ln
    if not labels:
        return None
    return txid, flags & 0x0F, bool(flags & 0x8000), ".".join(labels)


# ------------------------------------------------------------------------------------------------ conversion
class Converter:
    def __init__(self, device_macs=None):
        self.dev_of_mac = {}                     # mac bytes -> index
        self.names = {}                          # index -> (mac str, name)
        if device_macs:
            for mac, name in device_macs:
                self._dev(mac, name)
        self.fixed = bool(device_macs)
        self.hours = {}                          # (dev, hour) -> agg
        self.udp_last = {}                       # (dev, 5-tuple) -> last ts
        self.pending = {}                        # (dev, txid, qname) -> (dev, hour, index in dns list)

    def _dev(self, mac, name=""):
        if mac not in self.dev_of_mac:
            i = len(self.dev_of_mac)
            self.dev_of_mac[mac] = i
            self.names[i] = (":".join("%02x" % b for b in mac), name)
        return self.dev_of_mac[mac]

    def _agg(self, dev, ts):
        k = (dev, int(ts // 3600))
        a = self.hours.get(k)
        if a is None:
            a = self.hours[k] = {"conns": 0, "bytes": 0, "peers": [], "dns": []}
        return a

    def packet(self, ts, frame, linktype):
        p = parse(frame, linktype)
        if p is None:
            return
        smac, dmac, ver, src, dst, proto, sp, dp, flags, payload, ip_len = p
        if smac in self.dev_of_mac or (not self.fixed and smac[0] & 0x02 == 0 and dmac != b"\xff" * 6):
            dev = self._dev(smac) if not self.fixed else self.dev_of_mac[smac]
            a = self._agg(dev, ts)
            a["bytes"] += ip_len
            if proto == 17 and dp == 53:
                q = dns_question(payload)
                if q and not q[2]:
                    a["dns"].append([dns_fp(q[3]), 0])
                    self.pending[(dev, q[0], q[3].lower())] = a["dns"][-1]
                return
            if proto == 6 and flags & 0x02 and not flags & 0x10:
                a["conns"] += 1
                a["peers"].append(peer_fp(dst, dp))
            elif proto == 17:
                key = (dev, src, dst, sp, dp)
                last = self.udp_last.get(key)
                if last is None or ts - last >= UDP_IDLE:
                    a["conns"] += 1
                    a["peers"].append(peer_fp(dst, dp))
                self.udp_last[key] = ts
        if dmac in self.dev_of_mac and proto == 17 and sp == 53:
            q = dns_question(payload)
            if q and q[2]:
                ev = self.pending.pop((self.dev_of_mac[dmac], q[0], q[3].lower()), None)
                if ev is not None and q[1] == 3:
                    ev[1] = 1

    def write(self, out_path, dev_path):
        with open(out_path, "w") as f:
            for (dev, hour), a in sorted(self.hours.items()):
                f.write(json.dumps({"dev": dev, "hour": hour, **a}, separators=(",", ":")) + "\n")
        with open(dev_path, "w") as f:
            for i, (mac, name) in sorted(self.names.items()):
                f.write("%d\t%s\t%s\n" % (i, mac, name))


def iter_sources(path):
    """Yield readable binary streams: pcap files, or pcap members inside zip archives."""
    if os.path.isfile(path) and path.endswith(".zip"):
        with zipfile.ZipFile(path) as z:
            for n in sorted(z.namelist()):
                if n.endswith((".pcap", ".pcapng", ".cap")):
                    with z.open(n) as f:
                        yield n, f
        return
    files = [path] if os.path.isfile(path) else sorted(
        glob.glob(os.path.join(path, "**", "*.pcap*"), recursive=True) + glob.glob(os.path.join(path, "**", "*.zip"), recursive=True))
    for p in files:
        if p.endswith(".zip"):
            yield from iter_sources(p)
        else:
            with open(p, "rb") as f:
                yield p, f


# ------------------------------------------------------------------------------------------------ self-test
def _eth(src, dst, et, body):
    return dst + src + struct.pack("!H", et) + body


def _ipv4(src, dst, proto, l4):
    h = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(l4), 0, 0, 64, proto, 0, src, dst)
    return h + l4


def _tcp(sp, dp, flags):
    return struct.pack("!HHIIBBHHH", sp, dp, 0, 0, 5 << 4, flags, 0, 0, 0)


def _udp(sp, dp, payload):
    return struct.pack("!HHHH", sp, dp, 8 + len(payload), 0) + payload


def _dnsmsg(txid, name, resp=False, rcode=0):
    q = b"".join(bytes([len(l)]) + l.encode() for l in name.split(".")) + b"\0" + struct.pack("!HH", 1, 1)
    return struct.pack("!HHHHHH", txid, (0x8000 if resp else 0) | rcode, 1, 0, 0, 0) + q


def selftest():
    dev, gw = bytes.fromhex("aabbcc000001"), bytes.fromhex("aabbcc0000fe")
    me, out1, dnss = bytes([192, 168, 1, 10]), bytes([203, 0, 113, 7]), bytes([192, 168, 1, 1])
    frames = [
        (1000.0, _eth(dev, gw, 0x0800, _ipv4(me, out1, 6, _tcp(40000, 443, 0x02)))),              # SYN -> conn
        (1000.1, _eth(dev, gw, 0x0800, _ipv4(me, out1, 6, _tcp(40000, 443, 0x10)))),              # ACK -> no conn
        (1001.0, _eth(dev, gw, 0x0800, _ipv4(me, out1, 17, _udp(5000, 123, b"x" * 48)))),         # UDP -> conn
        (1050.0, _eth(dev, gw, 0x0800, _ipv4(me, out1, 17, _udp(5000, 123, b"x" * 48)))),         # same, <120 s
        (1200.0, _eth(dev, gw, 0x0800, _ipv4(me, out1, 17, _udp(5000, 123, b"x" * 48)))),         # idle >= 120 s
        (1300.0, _eth(dev, gw, 0x0800, _ipv4(me, dnss, 17, _udp(5353, 53, _dnsmsg(7, "a.b.example.co.uk"))))),
        (1300.1, _eth(gw, dev, 0x0800, _ipv4(dnss, me, 17, _udp(53, 5353, _dnsmsg(7, "a.b.example.co.uk", True, 3))))),
        (1301.0, _eth(dev, gw, 0x0800, _ipv4(me, dnss, 17, _udp(5354, 53, _dnsmsg(8, "time.vendor.com"))))),
        (1301.1, _eth(gw, dev, 0x0800, _ipv4(dnss, me, 17, _udp(53, 5354, _dnsmsg(8, "time.vendor.com", True, 0))))),
        (5000.0, _eth(dev, gw, 0x0800, _ipv4(me, out1, 6, _tcp(40001, 443, 0x02)))),              # next hour
    ]
    c = Converter([(dev, "test-device")])
    for ts, fr in frames:
        c.packet(ts, fr, 1)
    h0, h1 = c.hours[(0, 0)], c.hours[(0, 1)]
    want_peer = fx.fingerprint(fx.peer_key(0xCB007107, 443))
    checks = {
        "hour0 conns = 3 (SYN + 2 UDP idle-separated)": h0["conns"] == 3,
        "ACK and short-gap UDP not counted": len(h0["peers"]) == 3,
        "peer fingerprint = engine's": h0["peers"][0] == want_peer,
        "DNS events not peers, 2 queries": len(h0["dns"]) == 2,
        "registered domain of a.b.example.co.uk = example.co.uk": registered_domain("a.b.example.co.uk") == "example.co.uk",
        "NXDOMAIN matched by txid+qname": h0["dns"][0] == [dns_fp("example.co.uk"), 1],
        "NOERROR stays 0": h0["dns"][1][1] == 0,
        "next hour separate": h1["conns"] == 1,
        "bytes counted from IP length": h0["bytes"] > 0,
    }
    import tempfile
    with tempfile.TemporaryDirectory() as d:  # a classic pcap round trip through the reader
        p = os.path.join(d, "t.pcap")
        with open(p, "wb") as f:
            f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
            for ts, fr in frames:
                f.write(struct.pack("<IIII", int(ts), int((ts % 1) * 1e6), len(fr), len(fr)) + fr)
        c2 = Converter([(dev, "test-device")])
        for _, src in iter_sources(p):
            for ts, fr, lt in packets(src):
                c2.packet(ts, fr, lt)
        checks["pcap reader round trip"] = c2.hours == c.hours
    for k, v in checks.items():
        print("  %-60s %s" % (k, "PASS" if v else "FAIL"))
    ok = all(checks.values())
    print("selftest:", "PASS" if ok else "FAIL")
    return ok


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("src", nargs="?")
    ap.add_argument("--out")
    ap.add_argument("--devices")
    ap.add_argument("--macs", help="CSV/TSV with a MAC address and a device name per line (the dataset's device list)")
    ap.add_argument("--selftest", action="store_true")
    a = ap.parse_args()
    if a.selftest:
        sys.exit(0 if selftest() else 1)
    macs = []
    if a.macs:
        import re
        for line in open(a.macs, encoding="utf-8", errors="replace"):
            m = re.search(r"([0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5})", line)
            if m:
                name = line.replace(m.group(1), "").strip(" ,\t\r\n")
                macs.append((bytes.fromhex(m.group(1).replace(":", "")), name))
    c = Converter(macs or None)
    n = 0
    for name, f in iter_sources(a.src):
        for ts, fr, lt in packets(f):
            c.packet(ts, fr, lt)
            n += 1
        print("  %s: %d packets so far, %d device-hours" % (name, n, len(c.hours)), flush=True)
    c.write(a.out, a.devices)
    print("done: %d packets, %d devices, %d device-hours" % (n, len(c.names), len(c.hours)))


if __name__ == "__main__":
    main()
