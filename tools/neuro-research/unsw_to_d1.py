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
import collections
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


def _skip_name(p, i):
    while i < len(p):
        ln = p[i]
        if ln == 0:
            return i + 1
        if ln & 0xC0 == 0xC0:
            return i + 2
        i += 1 + ln
    return None


def dns_answers(p):
    """A/AAAA addresses in a DNS response's answer section (name compression handled). -> [addr bytes]."""
    if len(p) < 12:
        return []
    qd, an = struct.unpack("!HH", p[4:8])
    i = 12
    for _ in range(qd):
        i = _skip_name(p, i)
        if i is None:
            return []
        i += 4
    out = []
    for _ in range(an):
        i = _skip_name(p, i)
        if i is None or i + 10 > len(p):
            break
        typ, _cls, _ttl, rdlen = struct.unpack("!HHIH", p[i:i + 10])
        i += 10
        if i + rdlen > len(p):
            break
        if (typ == 1 and rdlen == 4) or (typ == 28 and rdlen == 16):
            out.append(bytes(p[i:i + rdlen]))
        i += rdlen
    return out


# ------------------------------------------------------------------------------------------------ D1b peer keys (doc 18)
PEER_MODES = ("exact", "v1-24", "v1-16", "v2-24", "v2-16")
NAME_WINDOW = 86400.0
NAME_CAP = 4096
INFRA = {123: ("ntp", "u"), 3478: ("stun", "ut"), 3479: ("stun", "ut"), 5349: ("stun", "ut"), 19302: ("stun", "ut"),
         67: ("dhcp", "u"), 68: ("dhcp", "u"), 546: ("dhcp", "u"), 547: ("dhcp", "u"),
         5353: ("lan-discovery", "u"), 1900: ("lan-discovery", "u"), 5355: ("lan-discovery", "u"),
         137: ("lan-discovery", "u"), 138: ("lan-discovery", "u")}


def is_local(ip):
    if len(ip) == 4:
        a, b = ip[0], ip[1]
        return a == 10 or a == 127 or (a == 172 and 16 <= b <= 31) or (a == 192 and b == 168) or (a == 169 and b == 254)
    return (ip[0] & 0xFE) == 0xFC or (ip[0] == 0xFE and ip[1] & 0xC0 == 0x80) or ip == bytes(15) + b"\x01"


def is_bcast_mcast(ip):
    if len(ip) == 4:
        return 224 <= ip[0] <= 239 or ip == b"\xff\xff\xff\xff" or (is_local(ip) and ip[3] == 255)
    return ip[0] == 0xFF


def _key(s):
    return fx.fingerprint(fx.fnv1a64(s.encode()))


def infra_class(ip, port, proto):
    """proto: 6, 17 or None (port-only match, used for overlays without a transport)."""
    if is_bcast_mcast(ip):
        return "broadcast-multicast"
    c = INFRA.get(port)
    if c and (proto is None or ("u" in c[1] and proto == 17) or ("t" in c[1] and proto == 6)):
        return c[0]
    return None


def service_peer_fp(mode, ip, port, proto=None, name=None):
    """The doc-18 rule order: infrastructure class (V2) > local exact > named service > prefix."""
    if mode == "exact":
        return peer_fp(ip, port)
    variant, plen = mode.split("-")
    if variant == "v2":
        c = infra_class(ip, port, proto)
        if c:
            return _key("cls:" + c)
    if is_local(ip):
        return peer_fp(ip, port)
    if name:
        return _key("svc:%s:%d" % (name, port))
    if len(ip) == 4:
        pre = "%d.%d.%d.0/24" % tuple(ip[:3]) if plen == "24" else "%d.%d.0.0/16" % tuple(ip[:2])
    else:
        pre = ip[:6].hex() + "/48"
    return _key("net:%s:%d" % (pre, port))


class Fnv:
    """Streaming FNV-1a 64: the kernel-side form of _key() (no strings on the device, only a running state)."""
    __slots__ = ("h",)

    def __init__(self, h=0xCBF29CE484222325):
        self.h = h

    def bytes(self, b):
        h = self.h
        for c in b:
            h = ((h ^ c) * 0x100000001B3) & 0xFFFFFFFFFFFFFFFF
        return Fnv(h)

    def dec(self, v):
        return self.bytes(str(int(v)).encode())

    def fp(self):
        return fx.fingerprint(self.h)


def svc_state(domain):
    """FNV state after 'svc:<registered domain>:' -- what the name table stores (8 bytes, no string)."""
    return Fnv().bytes(b"svc:").bytes(domain.encode()).bytes(b":").h


class SetAssocNames:
    """doc 20: the kernel-shaped name table. ONE table for all devices, N entries in 4-way sets, keyed by
    (device, address); a set evicts its entry with the oldest timestamp (lowest index on ties). Stores the
    svc FNV state, never the name. Bit-exact with neuro_core::peerkey::NameTable."""
    WAYS = 4

    def __init__(self, n=4096):
        assert n % self.WAYS == 0 and (n // self.WAYS) & (n // self.WAYS - 1) == 0
        self.sets = n // self.WAYS
        self.e = [None] * n          # (dev, ip16, state, ts)

    @staticmethod
    def ip16(ip):
        return bytes(10) + b"\xff\xff" + bytes(ip) if len(ip) == 4 else bytes(ip)

    def _base(self, dev, ip16):
        h = fx.splitmix64(fx.fnv1a64(dev.to_bytes(2, "little") + ip16))
        return (h % self.sets) * self.WAYS

    def insert(self, dev, ip, state, ts):
        k = self.ip16(ip)
        b = self._base(dev, k)
        victim = None
        for j in range(b, b + self.WAYS):
            x = self.e[j]
            if x is not None and x[0] == dev and x[1] == k:
                victim = j
                break
        if victim is None:
            empty = [j for j in range(b, b + self.WAYS) if self.e[j] is None]
            victim = empty[0] if empty else min(range(b, b + self.WAYS), key=lambda j: (self.e[j][3], j))
        self.e[victim] = (dev, k, state, ts)

    def lookup(self, dev, ip, now):
        k = self.ip16(ip)
        b = self._base(dev, k)
        for j in range(b, b + self.WAYS):
            x = self.e[j]
            if x is not None and x[0] == dev and x[1] == k:
                return x[2] if 0 <= now - x[3] <= NAME_WINDOW else None
        return None


def service_peer_fp_state(mode, ip, port, proto, state):
    """As service_peer_fp, but the named rule takes the stored FNV state (kernel form). Same result."""
    if state is None or mode == "exact":
        return service_peer_fp(mode, ip, port, proto, None)
    variant = mode.split("-")[0]
    if variant == "v2" and infra_class(ip, port, proto):
        return service_peer_fp(mode, ip, port, proto, None)
    if is_local(ip):
        return peer_fp(ip, port)
    return Fnv(state).dec(port).fp()


def peer_kind(mode, ip, port, proto, name):
    if mode == "exact":
        return "exact"
    if mode.startswith("v2") and infra_class(ip, port, proto):
        return "class"
    return "local" if is_local(ip) else "named" if name else "prefix"


# ------------------------------------------------------------------------------------------------ conversion
class Converter:
    def __init__(self, device_macs=None, peer_mode="exact", name_table=None):
        self.peer_mode = peer_mode
        self.ntab = SetAssocNames(name_table) if name_table else None   # doc 20 kernel-shaped table
        self.amap = {}                           # dev -> OrderedDict(addr -> (registered domain, ts)), doc 18
        self.kinds = {}                          # peer-key rule -> count (reported)
        self.amap_max = 0
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
                a["peers"].append(self._peer(dev, ts, dst, dp, 6))
            elif proto == 17:
                key = (dev, src, dst, sp, dp)
                last = self.udp_last.get(key)
                if last is None or ts - last >= UDP_IDLE:
                    a["conns"] += 1
                    a["peers"].append(self._peer(dev, ts, dst, dp, 17))
                self.udp_last[key] = ts
        if dmac in self.dev_of_mac and proto == 17 and sp == 53:
            q = dns_question(payload)
            if q and q[2] and self.peer_mode != "exact":
                self._learn_names(self.dev_of_mac[dmac], ts, q[3], payload)
            if q and q[2]:
                ev = self.pending.pop((self.dev_of_mac[dmac], q[0], q[3].lower()), None)
                if ev is not None and q[1] == 3:
                    ev[1] = 1

    def _learn_names(self, dev, ts, qname, payload):
        if self.ntab is not None:
            st = svc_state(registered_domain(qname))
            for addr in dns_answers(payload):
                self.ntab.insert(dev, addr, st, int(ts))
            return
        m = self.amap.setdefault(dev, collections.OrderedDict())
        dom = registered_domain(qname)
        for addr in dns_answers(payload):
            m[addr] = (dom, ts)
            m.move_to_end(addr)
            while len(m) > NAME_CAP:
                m.popitem(last=False)
        self.amap_max = max(self.amap_max, len(m))

    def _peer(self, dev, ts, dst, dp, proto):
        if self.ntab is not None and self.peer_mode != "exact":
            st = self.ntab.lookup(dev, bytes(dst), int(ts))
            k = peer_kind(self.peer_mode, dst, dp, proto, st)
            self.kinds[k] = self.kinds.get(k, 0) + 1
            return service_peer_fp_state(self.peer_mode, bytes(dst), dp, proto, st)
        name = None
        if self.peer_mode != "exact":
            e = self.amap.get(dev, {}).get(bytes(dst))
            if e and 0 <= ts - e[1] <= NAME_WINDOW:
                name = e[0]
        k = peer_kind(self.peer_mode, dst, dp, proto, name)
        self.kinds[k] = self.kinds.get(k, 0) + 1
        return service_peer_fp(self.peer_mode, bytes(dst), dp, proto, name)

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
    checks.update(selftest_d1b(dev, gw, me, dnss))
    for k, v in checks.items():
        print("  %-60s %s" % (k, "PASS" if v else "FAIL"))
    ok = all(checks.values())
    print("selftest:", "PASS" if ok else "FAIL")
    return ok


def _dnsresp_a(txid, name, addrs):
    """A response with a compressed answer name (pointer to the question at offset 12)."""
    q = b"".join(bytes([len(l)]) + l.encode() for l in name.split(".")) + b"\0" + struct.pack("!HH", 1, 1)
    ans = b"".join(b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 60, 4) + a for a in addrs)
    return struct.pack("!HHHHHH", txid, 0x8180, 1, len(addrs), 0, 0) + q + ans


def selftest_d1b(dev, gw, me, dnss):
    cdn1, cdn2, other = bytes([52, 1, 2, 3]), bytes([52, 1, 9, 9]), bytes([198, 51, 100, 7])
    lan, ntp, mc = bytes([192, 168, 1, 20]), bytes([162, 159, 200, 1]), bytes([239, 255, 255, 250])
    def run(mode):
        c = Converter([(dev, "t")], mode)
        frames = [
            (10.0, _eth(gw, dev, 0x0800, _ipv4(dnss, me, 17, _udp(53, 5000, _dnsresp_a(9, "eu.api.vendor.com", [cdn1, cdn2]))))),
            (11.0, _eth(dev, gw, 0x0800, _ipv4(me, cdn1, 6, _tcp(40000, 443, 0x02)))),     # named
            (12.0, _eth(dev, gw, 0x0800, _ipv4(me, cdn2, 6, _tcp(40001, 443, 0x02)))),     # named, other address
            (13.0, _eth(dev, gw, 0x0800, _ipv4(me, other, 6, _tcp(40002, 443, 0x02)))),    # unnamed -> prefix
            (14.0, _eth(dev, gw, 0x0800, _ipv4(me, lan, 6, _tcp(40003, 22, 0x02)))),       # LAN exact
            (15.0, _eth(dev, gw, 0x0800, _ipv4(me, ntp, 17, _udp(123, 123, b"n" * 48)))),   # NTP
            (16.0, _eth(dev, gw, 0x0800, _ipv4(me, mc, 17, _udp(1900, 1900, b"m" * 20)))),  # SSDP multicast
            (10.0 + 86401, _eth(dev, gw, 0x0800, _ipv4(me, cdn1, 6, _tcp(40004, 443, 0x02)))),  # name expired
        ]
        for ts, fr in frames:
            c.packet(ts, fr, 1)
        return [x for (d, h), a in sorted(c.hours.items()) for x in a["peers"]], c
    ex, _ = run("exact")
    v1, c1 = run("v1-24")
    v2, _ = run("v2-24")
    v16, _ = run("v1-16")
    svc = fx.fingerprint(fx.fnv1a64(b"svc:vendor.com:443"))
    return {
        "D1b: exact mode unchanged (6 addresses -> 6 keys)": len(set(ex)) == 6 and ex[0] == ex[6],
        "D1b: two CDN addresses of one name -> one service key": v1[0] == v1[1] == svc,
        "D1b: unnamed public peer -> /24 prefix key": v1[2] == fx.fingerprint(fx.fnv1a64(b"net:198.51.100.0/24:443")),
        "D1b: /16 prefix variant": v16[2] == fx.fingerprint(fx.fnv1a64(b"net:198.51.0.0/16:443")),
        "D1b: LAN peer keeps the exact D1 key": v1[3] == ex[3] == v2[3],
        "D1b: V1 has no classes (NTP -> prefix key)": v1[4] == fx.fingerprint(fx.fnv1a64(b"net:162.159.200.0/24:123")),
        "D1b: V2 NTP -> class key": v2[4] == fx.fingerprint(fx.fnv1a64(b"cls:ntp")),
        "D1b: V2 multicast -> class key": v2[5] == fx.fingerprint(fx.fnv1a64(b"cls:broadcast-multicast")),
        "D1b: name older than 24 h -> prefix key": v1[6] == fx.fingerprint(fx.fnv1a64(b"net:52.1.2.0/24:443")),
        "D1b: rule counts reported": c1.kinds == {"named": 2, "prefix": 4, "local": 1},
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("src", nargs="?")
    ap.add_argument("--out")
    ap.add_argument("--devices")
    ap.add_argument("--macs", help="CSV/TSV with a MAC address and a device name per line (the dataset's device list)")
    ap.add_argument("--peer-key", choices=PEER_MODES, default="exact", help="doc 18 peer identity (default: D1's exact key)")
    ap.add_argument("--name-table", type=int, help="doc 20: use the kernel-shaped set-associative table of N entries")
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
    c = Converter(macs or None, a.peer_key, a.name_table)
    n = 0
    for name, f in iter_sources(a.src):
        for ts, fr, lt in packets(f):
            c.packet(ts, fr, lt)
            n += 1
        print("  %s: %d packets so far, %d device-hours" % (name, n, len(c.hours)), flush=True)
    c.write(a.out, a.devices)
    print("done: %d packets, %d devices, %d device-hours" % (n, len(c.names), len(c.hours)))
    print("peer key %s: rule counts %s; name table max %d entries/device" % (a.peer_key, c.kinds, c.amap_max))


if __name__ == "__main__":
    main()
