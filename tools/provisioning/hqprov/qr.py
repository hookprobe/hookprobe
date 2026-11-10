"""Minimal pure-Python QR Code encoder (ISO/IEC 18004): byte mode, error-correction level M, versions 1-6.

Enough for the Wi-Fi label payload (`WIFI:T:WPA;S:<ssid>;P:<pass>;;`, 57 bytes -> version 4). Used only when
`qrencode` is absent. Structure follows the public reference algorithm (Nayuki's QR-Code-generator).
Capacity (byte mode, level M): v1 14, v2 26, v3 42, v4 62, v5 84, v6 106 bytes.
"""

# version -> (EC codewords per block, number of blocks, data codewords per block); level M, equal-size blocks only
_ECC_M = {1: (10, 1, 16), 2: (16, 1, 28), 3: (26, 1, 44), 4: (18, 2, 32), 5: (24, 2, 43), 6: (16, 4, 27)}
_ALIGN = {1: [], 2: [6, 18], 3: [6, 22], 4: [6, 26], 5: [6, 30], 6: [6, 34]}
_FMT_M = 0  # the 2-bit error-correction level indicator for M


def _gf_tables():
    exp, log = [0] * 512, [0] * 256
    x = 1
    for i in range(255):
        exp[i], log[x] = x, i
        x <<= 1
        if x & 0x100:
            x ^= 0x11D
    for i in range(255, 512):
        exp[i] = exp[i - 255]
    return exp, log


_EXP, _LOG = _gf_tables()


def gmul(a, b):
    return 0 if a == 0 or b == 0 else _EXP[_LOG[a] + _LOG[b]]


def rs_generator(n):
    g = [1]
    for i in range(n):
        nxt = [0] * (len(g) + 1)
        for j, c in enumerate(g):
            nxt[j] ^= c
            nxt[j + 1] ^= gmul(c, _EXP[i])
        g = nxt
    return g  # highest degree first


def rs_remainder(data, n):
    """Reed-Solomon parity (n bytes) of `data`."""
    g = rs_generator(n)
    rem = list(data) + [0] * n
    for i in range(len(data)):
        c = rem[i]
        if c:
            for j in range(1, len(g)):
                rem[i + j] ^= gmul(g[j], c)
    return rem[len(data):]


def _fits(n, version):
    ec, nb, dc = _ECC_M[version]
    return (4 + 8 + 8 * n + 7) // 8 <= nb * dc


def pick_version(n):
    for v in sorted(_ECC_M):
        if _fits(n, v):
            return v
    raise ValueError(f"payload of {n} bytes exceeds the built-in QR encoder (max 106 bytes); install qrencode")


def _data_codewords(payload, version):
    ec, nb, dc = _ECC_M[version]
    total = nb * dc
    bits = [0, 1, 0, 0]
    bits += [(len(payload) >> i) & 1 for i in range(7, -1, -1)]
    for b in payload:
        bits += [(b >> i) & 1 for i in range(7, -1, -1)]
    bits += [0] * min(4, total * 8 - len(bits))
    bits += [0] * (-len(bits) % 8)
    cw = [int("".join(map(str, bits[i:i + 8])), 2) for i in range(0, len(bits), 8)]
    pad = 0xEC
    while len(cw) < total:
        cw.append(pad)
        pad ^= 0xEC ^ 0x11
    return cw


def interleave(cw, version):
    ec, nb, dc = _ECC_M[version]
    blocks = [cw[i * dc:(i + 1) * dc] for i in range(nb)]
    eccs = [rs_remainder(b, ec) for b in blocks]
    out = []
    for i in range(dc):
        out += [b[i] for b in blocks]
    for i in range(ec):
        out += [e[i] for e in eccs]
    return out


def function_mask(version):
    """(size, is_function[y][x]): the modules that are not data."""
    size = version * 4 + 17
    fn = [[False] * size for _ in range(size)]

    def mark(x, y):
        if 0 <= x < size and 0 <= y < size:
            fn[y][x] = True
    for i in range(size):
        mark(6, i)
        mark(i, 6)
    for cx, cy in ((3, 3), (size - 4, 3), (3, size - 4)):
        for dy in range(-4, 5):
            for dx in range(-4, 5):
                mark(cx + dx, cy + dy)
    pos = _ALIGN[version]
    for i, px in enumerate(pos):
        for j, py in enumerate(pos):
            if (i == 0 and j == 0) or (i == 0 and j == len(pos) - 1) or (i == len(pos) - 1 and j == 0):
                continue
            for dy in range(-2, 3):
                for dx in range(-2, 3):
                    mark(px + dx, py + dy)
    for i in range(9):          # format info areas (+ separators)
        mark(8, i)
        mark(i, 8)
    for i in range(8):
        mark(size - 1 - i, 8)
        mark(8, size - 1 - i)
    return size, fn


def format_bits(mask):
    data = (_FMT_M << 3) | mask
    rem = data
    for _ in range(10):
        rem = (rem << 1) ^ ((rem >> 9) * 0x537)
    return ((data << 10) | rem) ^ 0x5412


def mask_fn(m):
    return [lambda x, y: (x + y) % 2 == 0, lambda x, y: y % 2 == 0, lambda x, y: x % 3 == 0,
            lambda x, y: (x + y) % 3 == 0, lambda x, y: (x // 3 + y // 2) % 2 == 0,
            lambda x, y: x * y % 2 + x * y % 3 == 0, lambda x, y: (x * y % 2 + x * y % 3) % 2 == 0,
            lambda x, y: ((x + y) % 2 + x * y % 3) % 2 == 0][m]


def _penalty(mod):
    n = len(mod)
    score = 0
    for grid in (mod, [list(r) for r in zip(*mod)]):          # rows, then columns
        for row in grid:
            run = 1
            for i in range(1, n):
                if row[i] == row[i - 1]:
                    run += 1
                else:
                    if run >= 5:
                        score += 3 + run - 5
                    run = 1
            if run >= 5:
                score += 3 + run - 5
            s = "".join("1" if c else "0" for c in row)
            for pat in ("10111010000", "00001011101"):
                i = s.find(pat)
                while i != -1:
                    score += 40
                    i = s.find(pat, i + 1)
    for y in range(n - 1):
        for x in range(n - 1):
            if mod[y][x] == mod[y][x + 1] == mod[y + 1][x] == mod[y + 1][x + 1]:
                score += 3
    dark = sum(sum(1 for c in r if c) for r in mod)
    total = n * n
    k = (abs(dark * 20 - total * 10) + total - 1) // total - 1
    return score + max(k, 0) * 10


def encode(payload, version=None):
    """Return the module matrix (rows of bool, True = dark), without the quiet zone."""
    if isinstance(payload, str):
        payload = payload.encode("utf-8")
    version = version or pick_version(len(payload))
    if not _fits(len(payload), version):
        raise ValueError("payload too long for the requested version")
    size, fn = function_mask(version)
    cw = interleave(_data_codewords(payload, version), version)
    base = [[False] * size for _ in range(size)]
    for i in range(size):
        base[i][6] = i % 2 == 0
        base[6][i] = i % 2 == 0
    for cx, cy in ((3, 3), (size - 4, 3), (3, size - 4)):
        for dy in range(-4, 5):
            for dx in range(-4, 5):
                x, y = cx + dx, cy + dy
                if 0 <= x < size and 0 <= y < size:
                    base[y][x] = max(abs(dx), abs(dy)) not in (2, 4)
    pos = _ALIGN[version]
    for i, px in enumerate(pos):
        for j, py in enumerate(pos):
            if (i == 0 and j == 0) or (i == 0 and j == len(pos) - 1) or (i == len(pos) - 1 and j == 0):
                continue
            for dy in range(-2, 3):
                for dx in range(-2, 3):
                    base[py + dy][px + dx] = max(abs(dx), abs(dy)) != 1
    k = 0                                                  # zigzag data placement
    right = size - 1
    while right >= 1:
        if right == 6:
            right = 5
        for vert in range(size):
            for j in range(2):
                x = right - j
                upward = ((right + 1) & 2) == 0
                y = size - 1 - vert if upward else vert
                if not fn[y][x] and k < len(cw) * 8:
                    base[y][x] = bool((cw[k >> 3] >> (7 - (k & 7))) & 1)
                    k += 1
        right -= 2

    def finish(m):
        mod = [row[:] for row in base]
        f = mask_fn(m)
        for y in range(size):
            for x in range(size):
                if not fn[y][x] and f(x, y):
                    mod[y][x] = not mod[y][x]
        bits = format_bits(m)

        def b(i):
            return bool((bits >> i) & 1)
        for i in range(6):
            mod[i][8] = b(i)
        mod[7][8] = b(6)
        mod[8][8] = b(7)
        mod[8][7] = b(8)
        for i in range(9, 15):
            mod[8][14 - i] = b(i)
        for i in range(8):
            mod[8][size - 1 - i] = b(i)
        for i in range(8, 15):
            mod[size - 15 + i][8] = b(i)
        mod[size - 8][8] = True                            # the dark module
        return mod
    return min((finish(m) for m in range(8)), key=_penalty)


def to_svg_path(mod, quiet=4):
    """One SVG path of dark runs (+ quiet zone) and the side length in modules."""
    d = []
    for y, row in enumerate(mod):
        x = 0
        while x < len(row):
            if row[x]:
                s = x
                while x < len(row) and row[x]:
                    x += 1
                d.append(f"M{s + quiet},{y + quiet}h{x - s}v1h-{x - s}z")
            else:
                x += 1
    return "".join(d), len(mod) + 2 * quiet
