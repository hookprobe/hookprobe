#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Doc 37 amendment B §9.3: the attacking devices in each CICIoT2023 Mirai capture. Counts only; nothing is scored.

Rule (fixed in doc 37 before any count existed): an attacker is one of the ten Raspberry Pi MACs listed in the
paper's Table 1 that sends at least 10% of the capture's IPv4 frames. Its IPv4 source addresses in that capture
become the capture's `--labels infected:` value for pcap_to_dna.py. A capture where no Pi qualifies prints NONE;
intake converts it with an empty `--labels infected:`, so all its windows carry attack_pkts_sent = 0: it is reported
and contributes nothing to the gated recall.
An attacker that SPOOFS non-local source addresses (>= 1% of its frames) would be dropped by pcap_to_dna.py's router
rule; the non-local share is printed so intake can pass such a MAC explicitly with --macs (a plumbing step, doc 37
§6.5), never by looking at scores.
Prints one line per capture: <pcap>\t<infected:IP,...|NONE>\t<per-Pi frame shares>.
Usage: python3 -I cic_attackers.py <pcap>...
"""
import collections, os, sys
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE); sys.path.insert(0, os.path.dirname(HERE))
import unsw_to_d1 as u  # noqa: E402

PI_MACS = ["DC:A6:32:C9:E6:F4", "DC:A6:32:C9:E4:C6", "DC:A6:32:C9:E5:02", "E4:5F:01:55:90:C4", "DC:A6:32:C9:E4:D5",
           "DC:A6:32:DC:27:D5", "DC:A6:32:C9:E5:EF", "DC:A6:32:C9:E4:AB", "DC:A6:32:C9:E4:90", "DC:A6:32:C9:E5:A4"]
PI = {bytes.fromhex(m.replace(":", "")) for m in PI_MACS}
SHARE = 0.10


def one(path):
    n, by, nl, ips = 0, collections.Counter(), collections.Counter(), collections.defaultdict(set)
    with open(path, "rb") as f:
        for ts, fr, lt in u.packets(f):
            p = u.parse(fr, lt)
            if p is None or p[2] != 4:
                continue
            n += 1
            mac = bytes(p[0])
            if mac in PI:
                by[mac] += 1
                nl[mac] += not u.is_local(bytes(p[3]))
                if bytes(p[3]) != bytes(4):
                    ips[mac].add(".".join(str(x) for x in p[3]))
    att = [m for m in by if n and by[m] >= SHARE * n]
    addrs = sorted({ip for m in att for ip in ips[m]})
    shares = ", ".join("%s %.1f%% (non-local source %.1f%%)" % (":".join("%02x" % x for x in m), 100 * by[m] / n, 100 * nl[m] / by[m])
                       for m in sorted(by)) or "no Pi frames"
    return "%s\t%s\t%d IPv4 frames; Pi shares: %s" % (path, ("infected:" + ",".join(addrs)) if addrs else "NONE", n, shares)


if __name__ == "__main__":
    assert len(PI) == 10
    for p in sys.argv[1:]:
        print(one(p), flush=True)
