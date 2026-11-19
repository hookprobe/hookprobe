# SPDX-License-Identifier: AGPL-3.0-only
"""Bit-exact Python reference of heqk's DGA / lookalike / tunnelling scorer (os/kernel/kernel/src/dga.rs).

Integer arithmetic only, mirroring the Rust line by line, so scores computed here on a benchmark are the
scores the device would produce. The kernel's own self-test corpus is reproduced in tests/test_dga_ref.py;
if dga.rs changes, that test (which parses the Rust source's lists) fails until this port follows.

This is tier A (deterministic) evaluation tooling: it measures the shipped scorer's false-positive rate
on benign baselines and its recall on DGA / tunnelling sets. It is not a model.
"""
DGA_THRESHOLD = 600

SUFFIX2 = (b"co.uk", b"org.uk", b"ac.uk", b"com.au", b"net.au", b"co.jp", b"com.br", b"co.in", b"com.cn", b"co.nz",
           b"com.tr", b"co.za", b"com.mx", b"com.ro")
SUS_TLD = (b"xyz", b"top", b"tk", b"ml", b"ga", b"cf", b"gq", b"pw", b"click", b"loan", b"work", b"zip", b"mov",
           b"cyou", b"rest", b"buzz")
BRANDS = (b"google", b"paypal", b"microsoft", b"apple", b"amazon", b"facebook", b"netflix", b"instagram",
          b"whatsapp", b"outlook", b"office", b"icloud", b"binance", b"coinbase", b"linkedin", b"dropbox")
PHISH = (b"secure", b"login", b"signin", b"verify", b"account", b"update", b"support", b"wallet", b"billing")
VOWELS = b"aeiouy"
U32 = 0xFFFFFFFF


def log2_q8(x):
    if x == 0:
        return 0
    msb = x.bit_length() - 1
    frac = ((x >> (msb - 8)) & 0xFF) if msb >= 8 else ((x << (8 - msb)) & 0xFF)
    return (msb << 8) + frac


def entropy_q8(s):
    n = len(s)
    if n == 0:
        return 0
    c = [0] * 256
    for b in s:
        c[b] = (c[b] + 1) & 0xFFFF  # u16 counters, as in Rust (labels are <= 255 bytes, so no wrap)
    total = 0
    for k in c:
        if k > 0:
            total += k * log2_q8(k)
    return max(0, log2_q8(n) - (total // n))  # saturating_sub


def split(name):
    if name.endswith(b"."):
        name = name[:-1]
    last = name.rfind(b".")
    if last < 0:
        return None
    tld = name[last + 1:]
    end = last
    for s in SUFFIX2:
        if len(name) > len(s) and name.endswith(s) and name[len(name) - len(s) - 1] == ord("."):
            end = len(name) - len(s) - 1
    p = name[:end].rfind(b".")
    start = 0 if p < 0 else p + 1
    sub = name[:start - 1] if start > 0 else b""
    return name[start:end], sub, tld


def _leet(c):
    return {ord("0"): ord("o"), ord("1"): ord("l"), ord("3"): ord("e"), ord("4"): ord("a"), ord("5"): ord("s"),
            ord("7"): ord("t"), ord("@"): ord("a")}.get(c, c)


def lookalike(label):
    n = min(len(label), 64)
    lower = bytes(b + 32 if 65 <= b <= 90 else b for b in label[:n])
    has_digit = any(48 <= b <= 57 for b in label[:n])
    norm = bytes(_leet(b) for b in lower)
    for br in BRANDS:
        if label == br:
            return False
        if has_digit and br in norm and br not in lower:
            return True
        if br in label and any(p in label for p in PHISH):
            return True
    return False


def score(name):
    if isinstance(name, str):
        name = name.encode("ascii", "replace")
    sp = split(name)
    if sp is None:
        return 0
    label, sub, tld = sp
    s = 0
    if lookalike(label):
        s += 650
    ln = len(label)
    if ln >= 4:
        e = entropy_q8(label)
        if e >= 4 * 256:
            s += 300
        elif e > 3 * 256 + 128:
            s += 150
        letters = sum(1 for c in label if (65 <= c <= 90) or (97 <= c <= 122))
        vowels = sum(1 for c in label if (c | 0x20 if 65 <= c <= 90 else c) in VOWELS)
        if letters > 0:
            vr = vowels * 100 // ln
            if vr < 10:
                s += 250
            elif vr < 20:
                s += 150
        run, cluster = 0, False
        for c in label:
            lc = c | 0x20 if 65 <= c <= 90 else c
            if (97 <= lc <= 122) and lc not in VOWELS:
                run += 1
                cluster |= run >= 5
            else:
                run = 0
        if cluster:
            s += 200
        if ln >= 20:
            s += 150
        elif ln >= 15:
            s += 80
        digits = sum(1 for c in label if 48 <= c <= 57)
        dr = digits * 100 // ln
        if dr > 40:
            s += 150
        elif dr > 25:
            s += 80
        if any(tld.lower() == t for t in SUS_TLD):
            s += 100
    maxl, maxe = 0, 0
    for part in sub.split(b"."):
        if len(part) > maxl:
            maxl = len(part)
            maxe = entropy_q8(part)
    if maxl > 30 and maxe > 4 * 256 + 32:
        s += 650
    elif maxl > 30:
        s += 250
    elif maxl > 15 and maxe >= 4 * 256:
        s += 150
    return min(s, 1000)


def detects(name):
    return score(name) >= DGA_THRESHOLD
