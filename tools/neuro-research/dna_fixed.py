#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Stage 1 (E-N0): the INTEGER-ONLY, STREAMING reference of the Neural DNA (behavioural_memory.DNA).

This file is the specification the no_std Rust engine (`os/neuro/neuro-core`) must match BIT FOR BIT:
- integers only: Q8 fixed point (x256) for log-domain values, Q16 for shares and EWMA rates;
- arithmetic shifts floor; every division has a non-negative numerator and a positive denominator,
  so Python `//` and Rust `/` agree;
- 64-bit intermediates for products (Rust: i64);
- hashing: SplitMix64 on a 32-bit fingerprint; Bloom indices by double hashing; no strings on device.

Streaming: the device sees one flow or DNS event at a time, not hourly sets. Per device and hour it keeps
a `HourAgg`:
- counters (conns, bytes, DNS queries, NXDOMAINs);
- a CANDIDATE Bloom per kind, which deduplicates (distinct counts) and holds the hour's items;
- a short list of NOVEL items (not in long-term memory) for the persistence rule.

At the end of the hour, `close_hour` scores it and applies the guarded update (same policy as the float
DNA and the Phase 0b cold-start fix):
- calm hour: learn statistics and OR the candidate Blooms into long-term memory;
- alarming hour: learn statistics only while the slot is cold; novel items count toward persistence.

Float reference: behavioural_memory.py. Differences are deliberate and measured in dna_fixed_eval.py:
- integer rounding;
- Bloom-estimated distinct counts;
- a bounded pending table (8 entries per device instead of an unbounded dict).
"""

M64 = (1 << 64) - 1

# ---- parameters (mirror behavioural_memory.py) ---------------------------------------------------------
BLOOM_BITS = 1024           # per filter; two kinds (peers, dns) x two generations (cur, old)
BLOOM_K = 3
ALPHA_Q16 = 9830            # 0.15
CALM_Q8 = 256               # 1.0
SLOT_MIN = 3
COLD_WIDEN_Q8 = 256         # 1.0 (log2 units)
PERSIST_K = 6
PENDING_SLOTS = 8
NOVEL_LIST = 16
ROTATE_HOURS = 168
DEV_INIT_Q8 = 256           # bdev/fdev start at 1.0
NOVDEV_INIT_Q8 = 128        # 0.5
HALF_Q8 = 128               # +0.5 in score denominators
NOV_EPS_Q8 = 77             # +0.3
ACT_MARGIN_Q8 = 384         # 1.5
U16 = 65535


def splitmix64(x):
    x = (x + 0x9E3779B97F4A7C15) & M64
    z = x
    z = ((z ^ (z >> 30)) * 0xBF58476D1CE4E5B9) & M64
    z = ((z ^ (z >> 27)) * 0x94D049BB133111EB) & M64
    return z ^ (z >> 31)


def fingerprint(key64):
    """Item identity on the device: 32-bit fingerprint of a 64-bit key."""
    return splitmix64(key64 & M64) >> 32


def peer_key(ip_u32, port):
    return ((ip_u32 & 0xFFFFFFFF) << 16) | (port & 0xFFFF)


def fnv1a64(b):
    h = 0xCBF29CE484222325
    for c in b:
        h = ((h ^ c) * 0x100000001B3) & M64
    return h


def ip_to_u32(s):
    a = s.split(".")
    if len(a) != 4:
        return fnv1a64(s.encode()) & 0xFFFFFFFF
    try:
        return (int(a[0]) << 24) | (int(a[1]) << 16) | (int(a[2]) << 8) | int(a[3])
    except ValueError:
        return fnv1a64(s.encode()) & 0xFFFFFFFF


def peer_fp_from_str(s):
    """'a.b.c.d:port' -> fingerprint (used by the simulators and the IoT-23 replay)."""
    ip, _, port = s.rpartition(":")
    return fingerprint(peer_key(ip_to_u32(ip), int(port or 0)))


def dns_fp_from_str(s):
    return fingerprint(fnv1a64(s.encode()))


# log2(1 + i/256) in Q8, for the mantissa table
LOG2_LUT = []
for _i in range(256):
    import math as _m
    LOG2_LUT.append(int(round(_m.log2(1 + _i / 256.0) * 256)))


def log2_q8(x):
    """round-ish log2(x) in Q8 for x >= 1 (0 for x <= 0). Integer only: msb + table on the next 8 bits."""
    if x <= 0:
        return 0
    n = x.bit_length() - 1
    frac8 = ((x << 8) >> n) & 0xFF if n < 64 else 0
    return n * 256 + LOG2_LUT[frac8]


def ewma(v, x, a_q16):
    return v + (((x - v) * a_q16) >> 16)


def clamp16(v):
    return 0 if v < 0 else (U16 if v > U16 else v)


class Bloom:
    __slots__ = ("bits",)

    def __init__(self):
        self.bits = bytearray(BLOOM_BITS // 8)

    @staticmethod
    def idx(fp):
        h = splitmix64(fp)
        h1, h2 = h & 0xFFFFFFFF, (h >> 32) | 1
        return [((h1 + i * h2) & 0xFFFFFFFF) % BLOOM_BITS for i in range(BLOOM_K)]

    def test(self, fp):
        return all(self.bits[i >> 3] >> (i & 7) & 1 for i in self.idx(fp))

    def set(self, fp):
        """Returns True if the item was NOT already present (all bits were not set)."""
        new = False
        for i in self.idx(fp):
            if not (self.bits[i >> 3] >> (i & 7) & 1):
                new = True
                self.bits[i >> 3] |= 1 << (i & 7)
        return new

    def merge(self, other):
        for j in range(len(self.bits)):
            self.bits[j] |= other.bits[j]

    def clear(self):
        for j in range(len(self.bits)):
            self.bits[j] = 0


class AgingBloom:
    __slots__ = ("cur", "old")

    def __init__(self):
        self.cur, self.old = Bloom(), Bloom()

    def test(self, fp):
        return self.cur.test(fp) or self.old.test(fp)

    def rotate(self):
        self.old, self.cur = self.cur, Bloom()


class HourAgg:
    """Per device, per hour. Fed one event at a time."""
    __slots__ = ("conns", "bytes_out", "peers", "n_peers", "novel_peers", "dns", "n_dns", "novel_dns",
                 "q_total", "q_nx", "novel_list")

    def __init__(self):
        self.reset()

    def reset(self):
        self.conns = 0
        self.bytes_out = 0
        self.peers = Bloom()
        self.dns = Bloom()
        self.n_peers = self.novel_peers = self.n_dns = self.novel_dns = 0
        self.q_total = self.q_nx = 0
        self.novel_list = []   # fingerprints, tagged: (kind 0=peer 1=dns, fp); at most NOVEL_LIST

    def add_flow(self, mem, fp, bytes_out, conns=1):
        self.conns += conns
        self.bytes_out += bytes_out
        if fp is None:
            return
        if self.peers.set(fp):
            self.n_peers += 1
            if not mem.peers.test(fp):
                self.novel_peers += 1
                if len(self.novel_list) < NOVEL_LIST:
                    self.novel_list.append((0, fp))

    def add_dns(self, mem, fp, nx):
        self.q_total += 1
        self.q_nx += 1 if nx else 0
        if self.dns.set(fp):
            self.n_dns += 1
            if not mem.dns.test(fp):
                self.novel_dns += 1
                if len(self.novel_list) < NOVEL_LIST:
                    self.novel_list.append((1, fp))

    def nx_q16(self):
        return (self.q_nx * 65536) // self.q_total if self.q_total else 0


class DNAFixed:
    def __init__(self):
        self.act = [0] * 24
        self.bmu = [0] * 24
        self.bdev = [DEV_INIT_Q8] * 24
        self.fmu = [0] * 24
        self.fdev = [DEV_INIT_Q8] * 24
        self.n = [0] * 24
        self.n_all = 0
        self.p = [0, 0, DEV_INIT_Q8, 0, DEV_INIT_Q8]  # act, bmu, bdev, fmu, fdev (pooled)
        self.nx = 0                                    # Q16
        self.nov_mu, self.nov_dev = 0, NOVDEV_INIT_Q8  # Q8
        self.peers, self.dns = AgingBloom(), AgingBloom()
        self.pending = []                              # [kind, fp, count], at most PENDING_SLOTS
        self.hours = 0

    @staticmethod
    def nbytes():
        # profile 5x24 u16 + n[24] u8 + n_all u16 + pooled 5 u16 + nx u16 + nov 2 u16 + hours u32
        prof = 5 * 24 * 2 + 24 + 2 + 10 + 2 + 4 + 4
        blooms = 2 * 2 * BLOOM_BITS // 8
        pending = PENDING_SLOTS * (4 + 1 + 1)
        agg = 2 * BLOOM_BITS // 8 + 4 * 8 + NOVEL_LIST * 5
        return prof + blooms + pending + agg

    # ---- scoring (pure) ----
    def _base(self, hr):
        slot = (self.act[hr], self.bmu[hr], self.bdev[hr], self.fmu[hr], self.fdev[hr])
        if self.n[hr] >= SLOT_MIN or self.n_all == 0:
            return slot
        w = self.n[hr]
        m = [(w * a + (SLOT_MIN - w) * b) // SLOT_MIN for a, b in zip(slot, self.p)]
        widen = (SLOT_MIN - w) * COLD_WIDEN_Q8 // SLOT_MIN
        return m[0] + widen, m[1], m[2] + widen, m[3], m[4] + widen

    def score(self, hr, agg):
        b_act, b_mu, b_dev, f_mu, f_dev = self._base(hr)
        lb = log2_q8(1 + agg.bytes_out)
        num = lb - b_mu
        vol = (num * 256) // (b_dev + HALF_Q8) if num > 0 else 0
        lf = log2_q8(1 + agg.n_peers)
        num = lf - f_mu
        fan = (num * 256) // (f_dev + HALF_Q8) if num > 0 else 0
        num = agg.novel_peers * 256 - self.nov_mu
        nov = (num * 256) // (self.nov_dev + NOV_EPS_Q8) if num > 0 else 0
        frac = (agg.novel_dns * 256) // max(1, agg.n_dns)
        m = min(256, (agg.novel_dns * 256) // 5)
        d_nx = agg.nx_q16() - self.nx
        dns = ((frac * m) >> 8) * 4 + ((d_nx * 8) >> 8 if d_nx > 0 else 0)
        num = log2_q8(1 + agg.conns) - b_act - ACT_MARGIN_Q8
        act = num if num > 0 else 0
        parts = {"vol": vol, "fan": fan, "novel": nov, "dns": dns, "act": act}
        return max(parts.values()), parts

    # ---- learning ----
    def update(self, hr, agg, admit_items=True):
        self.n[hr] = min(255, self.n[hr] + 1)
        self.n_all = min(65535, self.n_all + 1)
        a = max(ALPHA_Q16, 65536 // self.n[hr])
        ap = max(ALPHA_Q16, 65536 // self.n_all)
        lb = log2_q8(1 + agg.bytes_out)
        lf = log2_q8(1 + agg.n_peers)
        lc = log2_q8(1 + agg.conns)
        # pooled profile (dev first, against the old mean; first sample keeps the default dev)
        pa, pbm, pbd, pfm, pfd = self.p
        pbd = clamp16(ewma(pbd, abs(lb - pbm), ap)) if self.n_all > 1 else DEV_INIT_Q8
        pbm = clamp16(ewma(pbm, lb, ap))
        pfd = clamp16(ewma(pfd, abs(lf - pfm), ap)) if self.n_all > 1 else DEV_INIT_Q8
        pfm = clamp16(ewma(pfm, lf, ap))
        pa = clamp16(ewma(pa, lc, ap))
        self.p = [pa, pbm, pbd, pfm, pfd]
        # novelty rate (counts in Q8)
        nn = agg.novel_peers * 256
        self.nov_dev = clamp16(ewma(self.nov_dev, abs(nn - self.nov_mu), a))
        self.nov_mu = clamp16(ewma(self.nov_mu, nn, a))
        # slot profile
        first = self.n[hr] == 1
        self.act[hr] = clamp16(ewma(self.act[hr], lc, a))
        d = abs(lb - self.bmu[hr])
        self.bmu[hr] = clamp16(ewma(self.bmu[hr], lb, a))
        if not first:
            self.bdev[hr] = clamp16(ewma(self.bdev[hr], d, a))
        d = abs(lf - self.fmu[hr])
        self.fmu[hr] = clamp16(ewma(self.fmu[hr], lf, a))
        if not first:
            self.fdev[hr] = clamp16(ewma(self.fdev[hr], d, a))
        self.nx = clamp16(ewma(self.nx, agg.nx_q16(), a))
        if admit_items:
            self.peers.cur.merge(agg.peers)
            self.dns.cur.merge(agg.dns)

    def admit_persistent(self, agg):
        """Alarming hour: each novel item counts once; at PERSIST_K it becomes normal."""
        for kind, fp in agg.novel_list:
            mem = self.peers if kind == 0 else self.dns
            if mem.test(fp):
                continue
            hit = next((e for e in self.pending if e[0] == kind and e[1] == fp), None)
            if hit is None:
                if len(self.pending) < PENDING_SLOTS:
                    hit = [kind, fp, 0]
                    self.pending.append(hit)
                else:  # replace the entry with the lowest count (first such), deterministic
                    j = min(range(len(self.pending)), key=lambda q: (self.pending[q][2], q))
                    hit = self.pending[j] = [kind, fp, 0]
            hit[2] += 1
            if hit[2] >= PERSIST_K:
                mem.cur.set(fp)
                self.pending.remove(hit)

    def cold(self, hr):
        return self.n[hr] < SLOT_MIN

    def close_hour(self, hr, agg):
        """Score, then the guarded update. Returns (score_q8, parts). The caller resets agg."""
        s, parts = self.score(hr, agg)
        if s < CALM_Q8:
            self.update(hr, agg, admit_items=True)
        else:
            if self.cold(hr):
                self.update(hr, agg, admit_items=False)
            self.admit_persistent(agg)
        self.hours += 1
        if self.hours % ROTATE_HOURS == 0:
            self.peers.rotate()
            self.dns.rotate()
        return s, parts
