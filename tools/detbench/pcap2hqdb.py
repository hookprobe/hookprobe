#!/usr/bin/env python3
"""pcap2hqdb — build the detection-benchmark corpus disk (HQDB1) from labelled pcaps.

  pcap2hqdb.py OUT.img [--stagger SECONDS] LABEL:FILE.pcap [LABEL:FILE.pcap ...]

The FIRST label is the benign class (its alerts are false positives). Records from all files are merged by
timestamp; each file's timeline is shifted to start at the same moment unless --keep-time is given (attacks
then overlap the benign background, as they would on a real network). With --stagger S (default 1200), the
k-th attack file starts S*k seconds in, so episodes never overlap EACH OTHER (an alert is attributable to one
class) while all of them overlap the benign background. Classic pcap, Ethernet link type.
"""
import struct, sys

SKIPPED = [0]

def read_pcap(path):
    with open(path, "rb") as f:
        d = f.read()
    magic = struct.unpack("<I", d[:4])[0]
    if magic in (0xa1b2c3d4, 0xa1b23c4d):
        e = "<"
    elif magic in (0xd4c3b2a1, 0x4d3cb2a1):
        e = ">"
    else:
        sys.exit(f"{path}: not a classic pcap (convert pcapng with: tcpdump -r in.pcapng -w out.pcap)")
    nano = magic in (0xa1b23c4d, 0x4d3cb2a1)
    link = struct.unpack(e + "I", d[20:24])[0]
    if link != 1:
        sys.exit(f"{path}: link type {link}, need Ethernet (1)")
    o, out = 24, []
    while o + 16 <= len(d):
        s, frac, incl, orig = struct.unpack(e + "IIII", d[o:o + 16])
        o += 16
        # > 1518 B = a host capture's GRO/TSO super-frame (never on a real wire) or a truncated capture: skip
        if orig <= 1518 and incl == orig:
            out.append((s * 1_000_000 + (frac // 1000 if nano else frac), d[o:o + incl]))
        else:
            SKIPPED[0] += 1
        o += incl
    return out

def main():
    a = sys.argv[1:]
    keep = "--keep-time" in a
    a = [x for x in a if x != "--keep-time"]
    stagger = 1200
    if "--stagger" in a:
        i = a.index("--stagger")
        stagger = int(a[i + 1])
        del a[i:i + 2]
    if len(a) < 2:
        sys.exit(__doc__)
    out, specs = a[0], a[1:]
    labels, recs = [], []
    for k, sp in enumerate(specs):
        lab, path = sp.split(":", 1)
        if lab not in labels:
            labels.append(lab)
        li = labels.index(lab)
        frames = read_pcap(path)
        if not frames:
            continue
        base = 0 if keep else frames[0][0]
        shift = 0 if (keep or li == 0) else k * stagger * 1_000_000
        for ts, fr in frames:
            if 14 <= len(fr) <= 2048:
                recs.append((ts - base + 1_000_000 + shift, li, fr))
    if len(labels) > 15:
        sys.exit("at most 15 labels")
    recs.sort(key=lambda r: r[0])
    body = bytearray()
    for ts, li, fr in recs:
        body += struct.pack("<QBBH", ts, li, 0, len(fr)) + fr
    hdr = bytearray(512)
    hdr[:8] = b"HQDB1\0\0\0"
    hdr[8:16] = struct.pack("<Q", len(recs))
    hdr[16] = len(labels)
    for i, l in enumerate(labels):
        n = l.encode()[:15]
        hdr[64 + i * 16:64 + i * 16 + len(n)] = n
    body += bytes(-len(body) % 512)
    with open(out, "wb") as f:
        f.write(hdr + body)
        f.write(bytes(1 << 20))  # tail padding (virtio sizes)
    print(f"{out}: {len(recs)} frames, labels {labels}" + (f" ({SKIPPED[0]} offload super-frames / truncated captures skipped)" if SKIPPED[0] else ""))

if __name__ == "__main__":
    main()
