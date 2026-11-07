#!/usr/bin/env python3
"""Separation-matrix frame generator for the heqk M2 metal gate.

Emits the exact stimulus for individual matrix rows as raw Ethernet frames on an
isolated DUT link. Every kind is a named matrix row so a result can be attributed to a
row rather than to "some traffic".

Canon: docs/design/heqk-detection-parity.md §1a (legit, must NEVER wire-drop),
§1b (attacker, must reach the correct tri-state action), §1c (raw-frame predicates).

Usage: gen2.py <iface> <kind> <count>
"""
import socket, struct, sys

SRC_IP = "10.99.0.1"
DST_IP = "10.99.0.2"


def pad(f, n=60):
    return f + b"\x00" * max(0, n - len(f))


def eth(dst, src, ethertype, payload=b"", minlen=60):
    return pad(dst + src + struct.pack("!H", ethertype) + payload, minlen)


def ipv4(proto, body, src=SRC_IP, dst=DST_IP):
    total = 20 + len(body)
    h = struct.pack("!BBHHHBBH4s4s", 0x45, 0, total, 0x1234, 0, 64, proto, 0,
                    socket.inet_aton(src), socket.inet_aton(dst))
    s = sum(struct.unpack("!10H", h))
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return h[:10] + struct.pack("!H", ~s & 0xFFFF) + h[12:] + body


def udp(sport, dport, body=b"heqk"):
    return ipv4(17, struct.pack("!HHHH", sport, dport, 8 + len(body), 0) + body)


def tcp(sport, dport, flags, dst=DST_IP):
    # seq, ack, data-offset(5)<<4, flags, window, csum, urg
    t = struct.pack("!HHIIBBHHH", sport, dport, 1, 0, 0x50, flags, 8192, 0, 0)
    return ipv4(6, t, dst=dst)


def arp(eth_src, sender_mac, sender_ip=SRC_IP, target_ip=DST_IP, minlen=60):
    """ARP request. `sender_mac` deliberately separable from `eth_src` — that
    divergence is exactly what bpf::ARP_SPOOF keys on (matrix rows L3 / F10)."""
    body = (struct.pack("!HHBBH", 1, 0x0800, 6, 4, 1) + sender_mac +
            socket.inet_aton(sender_ip) + b"\x00" * 6 + socket.inet_aton(target_ip))
    return eth(b"\xff" * 6, eth_src, 0x0806, body, minlen)


def build(kind, src, i):
    bcast = b"\xff" * 6
    uni = b"\x00\x11\x22\x33\x44\x55"  # unicast dst: L3/L4 rows must NOT feed the bcast-storm counter (post-A3 it DROPs bcast floods, masking L4)
    # ---- §1a LEGIT — these must NEVER be wire-dropped -------------------------
    if kind == "L3_arp_flipflop":
        # Gratuitous / proxy-ARP style rebind: eth-src != ARP sender-mac. A legit NAT
        # rebind or proxy-ARP looks exactly like this. Required: Observe, NEVER FrameDrop.
        return arp(src, bytes([0x02, 0xAA, 0xBB, 0xCC, 0xDD, i & 0xFF]))
    if kind == "L7_cdn_443":
        # CDN fan-out: many connections all to ONE port. Must NOT trip a port-scan
        # detector (which counts DISTINCT ports, not connections).
        return eth(uni, src, 0x0800, tcp(40000 + i, 443, 0x02))
    if kind == "L8_ntp_beacon":
        # Beacon-SHAPED but port 123. FP-guard #4 exempts NTP.
        return eth(uni, src, 0x0800, udp(40000 + i, 123))
    if kind == "L10_newconn_burst":
        # Legit ~100 new-conns/s burst — under the DEFAULT_NEW_CONN_PPS=400 blanket cap.
        return eth(uni, src, 0x0800, tcp(41000 + i, 443, 0x02))
    if kind == "F1_iphone_arp42":
        # 42-byte UNPADDED ARP (the real iPhone frame that a 60-byte runt floor
        # false-dropped on Linux). heqk's floor is the complete-ARP 42 check.
        return arp(src, src, minlen=42)
    if kind == "F2_bare_ack54":
        # Bare 54-byte TCP ACK — a legitimate minimal frame, never anomalous.
        return eth(uni, src, 0x0800, tcp(40000 + i, 443, 0x10), minlen=54)
    if kind == "L11_ioc_hit":
        # SRC IP inside the signed blocklist (192.0.2.0/24, blocklist.rs). Required:
        # OBSERVE (rule 302), NEVER a wire-drop — a legit customer touching one IOC.
        body = struct.pack("!HHIIBBHHH", 40000 + i, 443, 1, 0, 0x50, 0x02, 8192, 0, 0)
        return eth(uni, src, 0x0800, ipv4(6, body, src="192.0.2.5"))
    if kind == "F3_local_admin_mac":
        # Locally-administered UNICAST src MAC (0x02: bit1 set, bit0/mcast clear) — must
        # NOT trip the multicast/broadcast-source structural check (rule 110).
        return eth(uni, b"\x02\xaa\xbb\xcc\xdd\xee", 0x0800, udp(40000 + i, 443))
    if kind == "F8_double_vlan":
        # Two stacked 802.1Q tags — structural anomaly, must be flagged (rule 110).
        inner = (struct.pack("!H", 100) + struct.pack("!H", 0x8100) +
                 struct.pack("!H", 200) + struct.pack("!H", 0x0800) + udp(40000 + i, 443))
        return eth(uni, src, 0x8100, inner)
    # ---- §1b ATTACKER — must reach the correct action ------------------------
    if kind == "A4_synscan_ports":
        # SYN to MANY DISTINCT dst ports from one source: the distinct-port scan tier.
        return eth(uni, src, 0x0800, tcp(40000, 1000 + i, 0x02))
    if kind == "A6_fin_scan":
        return eth(uni, src, 0x0800, tcp(40000 + i, 80, 0x01))       # FIN only
    if kind == "A6_null_scan":
        return eth(uni, src, 0x0800, tcp(40000 + i, 80, 0x00))       # no flags
    if kind == "A6_xmas_scan":
        return eth(uni, src, 0x0800, tcp(40000 + i, 80, 0x29))       # FIN|PSH|URG
    if kind == "threat_4444":
        return eth(uni, src, 0x0800, udp(40000 + i, 4444))
    # ---- §1c RAW-FRAME PREDICATES -------------------------------------------
    if kind == "F4_runt":
        return b"\xff" * 6 + src + b"\x08"                  # shorter than an eth header
    if kind == "F6_mcast_src":
        # Multicast/broadcast SOURCE MAC — structurally illegal, must be flagged.
        return eth(uni, b"\x01\x00\x5e\x00\x00\x01", 0x0800, udp(40000 + i, 443))
    if kind == "F7_oversize":
        return eth(uni, src, 0x0800, udp(40000 + i, 443, b"A" * 1600), minlen=1600)
    if kind == "F9_arp_malformed":
        bad = struct.pack("!HHBBH", 1, 0x0800, 99, 99, 1) + b"\x00" * 20   # bad hlen/plen
        return eth(bcast, src, 0x0806, bad)
    if kind == "A3_bcast_storm":
        # A benign-looking BROADCAST flood (dst=ff:ff:ff:ff:ff:ff, non-exempt): a raw
        # resource-exhaustion storm. Post-A3 this must RateLimit(DROP) on ANY port role
        # (rule 112 -> FloodRate), where pre-A3 an Uplink saw it as L2Flood -> Observe(PASS).
        return eth(bcast, src, 0x0800, udp(40000 + i, 443))
    if kind == "A10_lateral":
        # Lateral movement: one src -> many distinct internal peers on SMB(445). >5 distinct
        # peers in-window => rule 117 fires, but Behavioral is OBSERVE-ONLY (verdict=PASS):
        # detected + logged, NEVER a wire drop. Vary the IPv4 dst per frame. Unicast eth dst
        # so the lateral SYNs reach L4 (a bcast dst would feed the bcast-storm counter and mask it).
        return eth(uni, src, 0x0800, tcp(40000 + i, 445, 0x02, dst=f"10.99.0.{20 + i}"))
    if kind == "bench":
        return eth(bcast, src, 0x88B5, b"heqk-bench")
    raise SystemExit(f"unknown kind {kind!r}")


def main():
    if len(sys.argv) < 4:
        print(__doc__)
        return 2
    iface, kind, count = sys.argv[1], sys.argv[2], int(sys.argv[3])
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
    s.bind((iface, 0))
    src = s.getsockname()[4][:6]
    sent = 0
    for i in range(count):
        try:
            s.send(build(kind, src, i))
            sent += 1
        except OSError as e:
            print(f"send failed at {i}: {e}")
            break
    print(f"{kind}: sent={sent}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
