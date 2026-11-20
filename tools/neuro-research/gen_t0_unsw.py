#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""T0 v3: TRAINING windows from REAL benign device traffic (UNSW-IoTraffic, CC0), rendered as evidence cards by
the device's own compressor (semantic_compression.rendered_cards, 512-token budget).

- Only each device's HISTORY period (the D1 split: first 50% of active days) is used.
- Addresses and names are ANONYMISED into the reserved ranges the evaluation sets use:
  - the device becomes 192.168.10.<20+i>;
  - other LAN hosts become 192.168.10.x;
  - public peers become 198.51.100.x (stable per address);
  - domains become <hash>.<vendor-hash>.example.
- The baseline ("novel" flags) is what the same device talked to in the 24 h before the window.
- Flows are oriented by their INITIATOR (TCP SYN sender / first UDP sender), so a device answering many
  client ports is not mistaken for a port scan. Every window ends with the compressor's REST line, so quiet
  hours render as "nothing notable" exactly as on the device.
- Every window is benign. The gold is benign / insufficient_evidence, as for IoT-23 benign windows.

Usage: python3 -I gen_t0_unsw.py <pcap dir> <macs.tsv> <d1.jsonl> --n 400 --out t0_unsw.jsonl [--seed 5]
"""
import argparse
import collections
import hashlib
import json
import os
import random
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import semantic_compression as sc  # noqa: E402
import unsw_to_d1 as u  # noqa: E402

Q_EN = ["Assess this window.", "What is happening on this network?", "Explain what this device is doing.",
        "Summarise the evidence for the owner."]
Q_RO = ["Evaluează această fereastră și explică pe scurt, în română.", "Ce se întâmplă în rețea? Răspunde în română.",
        "Rezumă dovezile pentru proprietar, în română."]
MAX_FLOWS = 4000


def h8(b):
    return int(hashlib.sha256(b).hexdigest()[:8], 16)


class Anon:
    def __init__(self):
        self.lan, self.wan = {}, {}

    def ip(self, b, dev_ip_bytes, dev_idx):
        if b == dev_ip_bytes:
            return "192.168.10.%d" % (20 + dev_idx)
        if u.is_local(b):
            return self.lan.setdefault(b, "192.168.10.%d" % (60 + len(self.lan) % 190))
        return self.wan.setdefault(b, "198.51.100.%d" % (1 + h8(b) % 254))

    @staticmethod
    def name(q):
        reg = u.registered_domain(q)
        sub = q.lower().rstrip(".")[: -len(reg)].rstrip(".") if q.lower().rstrip(".").endswith(reg) else ""
        host = ("h%04x." % (h8(sub.encode()) % 65536)) if sub else ""
        return "%sv%04x.example" % (host, h8(reg.encode()) % 65536)


def ts_of(t):
    s = int(t)
    return "2026-11-17T%02d:%02d:%02d.%03dZ" % ((s // 3600) % 24, (s // 60) % 60, s % 60, int((t % 1) * 1000))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("pcaps")
    ap.add_argument("macs")
    ap.add_argument("d1")
    ap.add_argument("--n", type=int, default=400)
    ap.add_argument("--seed", type=int, default=5)
    ap.add_argument("--out", required=True)
    a = ap.parse_args()
    r = random.Random(a.seed)
    macs = []
    for line in open(a.macs):
        m, name = line.split()
        macs.append((bytes.fromhex(m.replace(":", "")), name))
    # history hours per device (the D1 split), then sample windows
    hours = collections.defaultdict(list)
    for line in open(a.d1):
        x = json.loads(line)
        if x["hour"] >= 1472688000 // 3600:
            hours[x["dev"]].append(x["hour"])
    pick = set()
    for d, hs in hours.items():
        days = sorted({h // 24 for h in hs})
        cut = days[len(days) // 2] if days else 0
        hist = [h for h in hs if h // 24 < cut]
        k = min(len(hist), max(3, a.n // max(1, len(hours)) + 2))
        pick |= {(d, h) for h in r.sample(hist, k)}
    pick = set(r.sample(sorted(pick), min(a.n * 2, len(pick))))      # oversample: some windows render empty
    want_base = {(d, h - k) for d, h in pick for k in range(1, 25)}
    dev_of = {m: i for i, (m, _) in enumerate(macs)}
    win = collections.defaultdict(lambda: {"flows": {}, "dns": {}, "ip": None})
    base = collections.defaultdict(lambda: {"pairs": set(), "suffixes": set()})
    for path in sorted(os.path.join(a.pcaps, f) for f in os.listdir(a.pcaps) if ".pcap" in f):
        with open(path, "rb") as f:
            for ts, fr, lt in u.packets(f):
                p = u.parse(fr, lt)
                if p is None:
                    continue
                smac, dmac, ver, src, dst, proto, sp, dp, flags, payload, ip_len = p
                out = smac in dev_of
                dev = dev_of.get(smac if out else dmac)
                if dev is None:
                    continue
                hr = int(ts // 3600)
                key = (dev, hr)
                inwin, inbase = key in pick, key in want_base
                if not (inwin or inbase):
                    continue
                me, peer, pport = (bytes(src), bytes(dst), dp) if out else (bytes(dst), bytes(src), sp)
                if proto == 17 and (dp == 53 or sp == 53):
                    q = u.dns_question(payload)
                    if not q:
                        continue
                    if inbase and out and not q[2]:
                        base[key]["suffixes"].add(sc._suffix(Anon.name(q[3])))
                    if inwin:
                        w = win[key]
                        if out and not q[2]:
                            w["dns"].setdefault((q[0], q[3].lower()), [ts, q[3], "NOERROR", me])
                        elif not out and q[2] and (q[0], q[3].lower()) in w["dns"] and q[1] == 3:
                            w["dns"][(q[0], q[3].lower())][2] = "NXDOMAIN"
                    continue
                if proto not in (6, 17):
                    continue
                if inbase and out:
                    base[key]["pairs"].add((me, peer))
                if not inwin:
                    continue
                w = win[key]
                if out:
                    w["ip"] = w["ip"] or me
                my_port, peer_port = (sp, dp) if out else (dp, sp)
                fk = (proto, peer, my_port, peer_port)          # same key for both directions
                fl = w["flows"].get(fk)
                if fl is None:
                    if len(w["flows"]) >= MAX_FLOWS:
                        continue
                    syn = proto == 6 and flags & 0x02 and not flags & 0x10
                    if proto == 17 or syn:
                        dev_init = out                          # the first UDP sender / the SYN sender initiated
                    else:                                       # joined mid-connection: the lower port is the service
                        dev_init = peer_port < my_port
                    # [first ts, peer, service port, proto, initiator->responder bytes, back bytes, state, me, dev_init]
                    fl = w["flows"][fk] = [ts, peer, peer_port if dev_init else my_port, proto, 0, 0, "est", me, dev_init]
                fl[4 if out == fl[8] else 5] += ip_len
                if proto == 6 and flags & 0x04:
                    fl[6] = "rst"
                elif proto == 6 and flags & 0x01:
                    fl[6] = "fin"
        print("  read %s" % os.path.basename(path), flush=True)
    tok = sc.Tok()
    out_cases, seen = [], set()
    for (dev, hr) in sorted(win, key=lambda k: h8(("%d|%d|%d" % (k[0], k[1], a.seed)).encode())):
        if len(out_cases) >= a.n:
            break
        w = win[(dev, hr)]
        if not w["ip"]:
            continue
        an = Anon()
        ev = []
        for fl in w["flows"].values():
            a_, b_ = (fl[7], fl[1]) if fl[8] else (fl[1], fl[7])     # initiator -> responder
            ev.append({"type": "flow", "ts": ts_of(fl[0]), "src_ip": an.ip(a_, w["ip"], dev), "dst_ip": an.ip(b_, w["ip"], dev),
                       "dst_port": fl[2], "proto": "tcp" if fl[3] == 6 else "udp", "bytes_out": fl[4], "bytes_in": fl[5],
                       "state": fl[6]})
        for t, q, rc, me in w["dns"].values():
            ev.append({"type": "dns", "ts": ts_of(t), "src_ip": an.ip(me, w["ip"], dev), "qname": Anon.name(q), "rcode": rc,
                       "shield": "allow"})
        ev.sort(key=lambda e: e["ts"])
        bl = {"pairs": set(), "suffixes": set()}
        for k in range(1, 25):
            b = base.get((dev, hr - k))
            if b:
                bl["pairs"] |= {(an.ip(x, w["ip"], dev), an.ip(y, w["ip"], dev)) for x, y in b["pairs"]}
                bl["suffixes"] |= b["suffixes"]
        cards, residual, _ = sc.rep_cards(ev, bl)
        lines, _ = sc.fill(cards, 512, tok, residual)
        if len(lines) == len(cards):                  # nothing dropped: still end with the REST line, as the device does
            lines = lines + [residual([])]
        if not lines:
            continue
        ctx = "\n".join(lines)
        hsh = hashlib.sha256(" ".join(ctx.split()).lower().encode()).hexdigest()
        if hsh in seen:
            continue
        seen.add(hsh)
        ro = r.random() < 0.3
        gold = {"verdict": ["benign", "insufficient_evidence"], "evidence": [], "entities": [],
                "must_mention_any": (["normal", "obișnuit", "benign", "nu", "insuficient"] if ro else
                                     ["normal", "benign", "no ", "routine", "expected", "insufficient"]),
                "next_step": ["observe"]}
        out_cases.append({"id": "t0u-%05d" % len(out_cases), "lang": "ro" if ro else "en", "task": "triage", "context": ctx,
                          "question": r.choice(Q_RO if ro else Q_EN), "gold": gold, "family": "unsw-benign",
                          "source": macs[dev][1]})
    with open(a.out, "w", encoding="utf-8") as f:
        for c in out_cases:
            f.write(json.dumps(c, ensure_ascii=False) + "\n")
    print("wrote %d real benign windows from %d devices" % (len(out_cases), len({c["source"] for c in out_cases})))


if __name__ == "__main__":
    main()
