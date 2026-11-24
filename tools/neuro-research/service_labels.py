#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Doc 45: service labels on evidence cards. One shared function for the training generator (gen_t0_v3.py
--service-labels) and the real compressor path (semantic_compression / the E2E harness), so both write the same token.

A flow card's destination port list gets a separate `svc=` token right after it:
    F1 H1=192.168.1.165->R1=192.0.2.127:22 n=600 ...   ->   F1 H1=...->R1=192.0.2.127:22 svc=ssh n=600 ...
    F5 H1->H2:53,5000 n=44                            ->   F5 H1->H2:53,5000 svc=dns n=44
Only IANA-registered well-known/registered ports in the table below are named; unknown ports get nothing (never a
guess). The port itself stays untouched, so every existing card parser (run_eval template rows, grounding
ports_on_cards) reads the line as before. A label is a fact about the port number only, not about the traffic:
SSH-looking traffic on port 22 is labelled ssh whatever it really is (the explainer must still read the shape).
"""
import re

SERVICES = {
    20: "ftp-data", 21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 67: "dhcp", 68: "dhcp", 69: "tftp",
    80: "http", 110: "pop3", 123: "ntp", 137: "netbios", 138: "netbios", 139: "netbios", 143: "imap", 161: "snmp",
    389: "ldap", 443: "https", 445: "smb", 465: "smtps", 500: "ike", 514: "syslog", 554: "rtsp", 587: "smtp",
    636: "ldaps", 853: "dns-over-tls", 993: "imaps", 995: "pop3s", 1194: "openvpn", 1433: "mssql", 1883: "mqtt",
    1900: "ssdp", 2323: "telnet-alt", 3306: "mysql", 3389: "rdp", 3478: "stun", 5060: "sip", 5353: "mdns",
    5432: "postgresql", 5900: "vnc", 6667: "irc", 8080: "http-alt", 8443: "https-alt", 8883: "mqtt-tls",
    51820: "wireguard",
}
# a flow card: "<src>-><dst>:<ports> " where <ports> is a comma list. A range "a-b" and the count form "<N> ports"
# (e.g. ":25 ports", a port COUNT, not port 25) are left unlabelled.
FLOW = re.compile(r"^(F\d+ \S+->\S+?:)((?:\d+,)*\d+)( )(?!ports\b)", re.M)


def label(card_text):
    """Insert ` svc=<name>[,<name>]` after the port list of every flow card that has at least one named port."""
    def sub(m):
        names = []
        for p in m.group(2).split(","):
            n = SERVICES.get(int(p))
            if n and n not in names:
                names.append(n)
        return m.group(1) + m.group(2) + (" svc=" + ",".join(names) if names else "") + m.group(3)
    return FLOW.sub(sub, card_text)


if __name__ == "__main__":
    import sys
    sys.stdout.write(label(sys.stdin.read()))
