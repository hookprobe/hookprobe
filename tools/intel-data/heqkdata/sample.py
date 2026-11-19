# SPDX-License-Identifier: AGPL-3.0-only
"""Sample-at-registration for captures too big to normalise whole (IoT-23 has 0.5-11 GB conn logs).

zeek_per_label() streams a Zeek conn.log once and keeps, per (label, detailed-label) pair, a
reservoir of at most `per_label` data lines. Rare classes (benign flows inside a flood capture,
C&C heartbeats) survive; the flood class is cut down. Header lines are kept as they are. Lines keep
their original order. The seed is fixed and the reservoir uses a seeded PRNG, so the same input gives
byte-identical output, and the stored sample has a stable content hash.

What it returns goes into acquisition.json as `derived_from`: the original file's sha256, size,
line count and per-label counts (measured here, not taken from the dataset's documentation), so a
build can say exactly what fraction of each class it saw.
"""
import hashlib
import random

from .safeio import MAX_LINE, UnsafeContent

SEED = "heqk-v1"


def _d(b):
    return b.decode("utf-8", "replace")


def _label_key(line, cols=None):
    """(label, detailed-label) of one data line. `cols` = (label index, detailed-label index) when the
    #fields header has them as their own tab columns (the CTU / later IoT-23 layout); otherwise the
    IoT-23 layout, where the last tab field is "<tunnel_parents>   <label>   <detailed-label>"."""
    parts = line.rstrip(b"\r\n").split(b"\t")
    if cols is not None:
        li, di = cols
        if li < len(parts):
            lab = parts[li].strip() or b"-"
            det = parts[di].strip() if di is not None and di < len(parts) else b"-"
            if b"  " not in parts[-1]:
                return (_d(lab), _d(det or b"-"))
    tail = parts[-1].split()
    if len(tail) >= 3:
        return (_d(tail[1]), _d(tail[2]))
    if len(tail) == 2:
        return (_d(tail[1]), "-")
    return ("-", "-")


def _label_cols(header_line):
    """From a '#fields' line: (label index, detailed-label index or None) if label is its own column."""
    names = [_d(x).strip() for x in header_line.rstrip(b"\r\n").split(b"\t")[1:]]
    if "label" not in names:
        return None
    return (names.index("label"), names.index("detailed-label") if "detailed-label" in names else None)


def _bounded(f, limit):
    while True:
        line = f.readline(limit + 1)
        if not line:
            return
        if len(line) > limit:
            raise UnsafeContent(f"line longer than {limit} bytes")
        yield line


def zeek_per_label(src, dst, per_label, seed=SEED, name=""):
    if per_label < 1:
        raise ValueError("per_label must be >= 1")
    rng = random.Random(f"{seed}:{name}")
    h = hashlib.sha256()
    headers, res, seen = [], {}, {}
    n_bytes = n_lines = 0
    cols = None
    with open(src, "rb") as f:
        for i, line in enumerate(_bounded(f, MAX_LINE)):
            h.update(line)
            n_bytes += len(line)
            n_lines += 1
            if line.startswith(b"#"):
                if line.startswith(b"#fields"):
                    cols = _label_cols(line)
                headers.append((i, line))
                continue
            if not line.strip():
                continue
            k = _label_key(line, cols)
            c = seen.get(k, 0) + 1
            seen[k] = c
            r = res.setdefault(k, [])
            if c <= per_label:
                r.append((i, line))
            else:
                j = rng.randrange(c)
                if j < per_label:
                    r[j] = (i, line)
    # header lines before the data, the '#close' trailer after it, data in original order
    data = sorted(x for r in res.values() for x in r)
    first_data = data[0][0] if data else float("inf")
    with open(dst, "wb") as out:
        for i, line in headers:
            if i < first_data:
                out.write(line)
        for _, line in data:
            out.write(line)
        for i, line in headers:
            if i > first_data:
                out.write(line)
    counts = {f"{a}/{b}": seen[(a, b)] for a, b in sorted(seen)}
    kept = {f"{a}/{b}": len(res[(a, b)]) for a, b in sorted(res)}
    return {"sha256": h.hexdigest(), "bytes": n_bytes, "lines": n_lines, "label_counts": counts,
            "sample": {"method": "zeek_per_label_reservoir", "per_label": per_label, "seed": seed,
                       "kept": kept}}
