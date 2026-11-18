#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Experiment E-BM1: "Neural DNA" -- compact, fixed-size behavioural memory per device.

Question: can a device's normal behaviour be held in a few hundred bytes of state (instead of days of
raw events), updated incrementally, and still separate injected behaviour changes from normal hours?

This is the NON-NEURAL baseline the Neuro Engine's learned variant must beat (Kitsune-style damped
incremental statistics + set-membership sketches). If a learned recurrent state cannot beat this at
the same byte budget, the learned variant is rejected (NEURO_EXPERIMENT_DESIGN.md, E-BM2).

Per-device state ("DNA"), fixed size, parameterised by the Bloom filter width:
  activity[24]      u8   log2 connection-count EWMA per hour of day          24 B
  bytes_mu/var[24]  u8   log2 bytes-out EWMA mean / mean-abs-dev per hour     48 B
  fanout_mu/var     f16  distinct-destination EWMA                             4 B
  nx_rate           f16  NXDOMAIN-share EWMA                                   2 B
  peers bloom x2    bits (dst, port) seen; two generations, rotated weekly    2*M/8 B  ("aging bloom")
  dns  bloom x2     bits registered DNS suffixes seen; two generations        2*M/8 B
Updates are GUARDED: an hour that scores anomalous does not update the state (poisoning resistance);
a benign drift is admitted only after it persists (K consecutive hours), so new normal is learned.

Simulation (synthetic, seeded): 14 days at hourly resolution for N devices of six kinds; days 1-10
learn, days 11-14 are scored. Injected on days 11-14: new_service, exfil, beacon_new_dst, scan, dga.
Also injected: a BENIGN drift (a laptop adopts a new SaaS app) to measure false alarms on change.

Outputs: hour-level ROC AUC, detection rate at a 1% false-positive rate per anomaly kind, alerts
caused by the benign drift, and state bytes vs the bytes of the raw history the state replaces.
Synthetic data: this measures the mechanism, not field efficacy.

Usage: python3 -I behavioural_memory.py [--devices 60 --seeds 1,2,3] [--json out.json]
"""
import argparse
import hashlib
import json
import math
import random
import statistics

KINDS = {
    # kind: (peak hours, base conns/hour, n usual remote peers, bytes_out per conn, dns suffixes)
    "camera": (range(0, 24), 30, 2, 40_000, 2),
    "tv": (range(18, 24), 60, 12, 3_000, 10),
    "laptop": (range(8, 19), 120, 60, 8_000, 40),
    "phone": (range(7, 24), 50, 30, 4_000, 25),
    "plug": (range(0, 24), 4, 1, 500, 1),
    "printer": (range(9, 17), 3, 1, 2_000, 1),
}


def h64(s, salt):
    return int.from_bytes(hashlib.blake2b(("%d|%s" % (salt, s)).encode(), digest_size=8).digest(), "big")


class AgingBloom:
    def __init__(self, m_bits, k=3):
        self.m, self.k = m_bits, k
        self.cur = bytearray(m_bits // 8)
        self.old = bytearray(m_bits // 8)

    def _idx(self, item):
        return [h64(item, i) % self.m for i in range(self.k)]

    def add(self, item):
        for i in self._idx(item):
            self.cur[i >> 3] |= 1 << (i & 7)

    def __contains__(self, item):
        ix = self._idx(item)
        return all(self.cur[i >> 3] >> (i & 7) & 1 for i in ix) or all(self.old[i >> 3] >> (i & 7) & 1 for i in ix)

    def rotate(self):
        self.old, self.cur = self.cur, bytearray(self.m // 8)
        # keep membership continuous: anything in old is still "known" until the next rotation

    def nbytes(self):
        return 2 * len(self.cur)


CALM = 1.0       # score below which an hour may teach the state
SLOT_MIN = 3     # cold start: an hour-of-day slot is trusted fully only after this many updates
COLD_WIDEN = 1.0  # extra tolerance (log2 units, i.e. 2x) while a slot leans on the pooled profile
COLD_FALLBACK = True  # Phase 0b fix; False reproduces the Phase 0 behaviour
COLD_LEARN = True     # a still-cold slot learns its volume/activity statistics even on an alarming hour
                      # (never new peers or DNS: those still need PERSIST_K hours) -- else it can never warm
PERSIST_K = 6    # alarming new items become normal only after this many alarming hours (drift vs poisoning)


class DNA:
    ALPHA = 0.15

    def __init__(self, m_bits):
        self.act = [0.0] * 24
        self.bmu = [0.0] * 24
        self.bdev = [1.0] * 24
        self.fmu = [0.0] * 24   # log2 distinct-peer EWMA per hour of day (fan-out is diurnal too)
        self.fdev = [1.0] * 24
        self.nx = 0.0
        # cold-start fallback (Phase 0b): per-slot update counts + an all-hours pooled profile. A slot
        # with little history is scored against the pooled profile, widened, instead of against zero.
        self.n = [0] * 24
        self.n_all = 0
        self.p_act, self.p_bmu, self.p_bdev, self.p_fmu, self.p_fdev = 0.0, 0.0, 1.0, 0.0, 1.0
        self.nov_mu, self.nov_dev = 0.0, 0.5   # the device's OWN normal rate of new peers per hour
        self.peers = AgingBloom(m_bits)
        self.dns = AgingBloom(m_bits)
        self.pending = {}  # candidate new-normal items -> consecutive-hour count (bounded, see admit)

    def nbytes(self):
        cold = (24 + 10) if COLD_FALLBACK else 0  # u8 counts per slot + 5 pooled f16
        return 24 + 48 + 48 + 2 + 4 + cold + self.peers.nbytes() + self.dns.nbytes()

    def _base(self, hr):
        """(act, bmu, bdev, fmu, fdev) to score hour-of-day slot hr against."""
        slot = (self.act[hr], self.bmu[hr], self.bdev[hr], self.fmu[hr], self.fdev[hr])
        if not COLD_FALLBACK or self.n[hr] >= SLOT_MIN:
            return slot
        if self.n_all == 0:
            return slot
        w = self.n[hr] / SLOT_MIN
        pool = (self.p_act, self.p_bmu, self.p_bdev, self.p_fmu, self.p_fdev)
        m = [w * a + (1 - w) * b for a, b in zip(slot, pool)]
        widen = (1 - w) * COLD_WIDEN
        return m[0] + widen, m[1], m[2] + widen, m[3], m[4] + widen

    def score(self, hr, obs):
        conns, peers, bytes_out, suffixes, nx_share = obs
        b_act, b_mu, b_dev, f_mu, f_dev = self._base(hr)
        lb = math.log2(1 + bytes_out)
        vol = max(0.0, (lb - b_mu) / (b_dev + 0.5))
        lf = math.log2(1 + len(peers))
        fan = max(0.0, (lf - f_mu) / (f_dev + 0.5))
        novel_peers = [p for p in peers if p not in self.peers]
        # surprise relative to THIS device's learned novelty rate: one new peer is loud for a camera
        # (rate ~0) and quiet for a laptop (rate > 0). Same rule, no per-kind branches.
        nov = max(0.0, (len(novel_peers) - self.nov_mu) / (self.nov_dev + 0.3))
        novel_dns = [s for s in suffixes if s not in self.dns]
        dns = (len(novel_dns) / max(1, len(suffixes))) * min(1.0, len(novel_dns) / 5.0) * 4 + max(0.0, nx_share - self.nx) * 8
        act = max(0.0, math.log2(1 + conns) - b_act - 1.5)
        return max(vol, fan, nov, dns, act), {"vol": vol, "fan": fan, "novel": nov, "dns": dns, "act": act}

    def update(self, hr, obs, admit_items=True):
        conns, peers, bytes_out, suffixes, nx_share = obs
        a = self.ALPHA
        if COLD_FALLBACK:
            # warm-up: a running mean until 1/n < ALPHA, so a slot's first sample initialises it
            # instead of being shrunk toward zero (the Phase 0 EWMA started every slot at 0)
            self.n[hr] = min(255, self.n[hr] + 1)
            self.n_all = min(65535, self.n_all + 1)
            a = max(self.ALPHA, 1.0 / self.n[hr])
            ap = max(self.ALPHA, 1.0 / self.n_all)
            lb0, lf0, lc0 = math.log2(1 + bytes_out), math.log2(1 + len(peers)), math.log2(1 + conns)
            self.p_bdev = (1 - ap) * self.p_bdev + ap * abs(lb0 - self.p_bmu) if self.n_all > 1 else 1.0
            self.p_bmu = (1 - ap) * self.p_bmu + ap * lb0
            self.p_fdev = (1 - ap) * self.p_fdev + ap * abs(lf0 - self.p_fmu) if self.n_all > 1 else 1.0
            self.p_fmu = (1 - ap) * self.p_fmu + ap * lf0
            self.p_act = (1 - ap) * self.p_act + ap * lc0
        n_new = sum(1 for p in peers if p not in self.peers)
        self.nov_dev = (1 - a) * self.nov_dev + a * abs(n_new - self.nov_mu)
        self.nov_mu = (1 - a) * self.nov_mu + a * n_new
        self.act[hr] = (1 - a) * self.act[hr] + a * math.log2(1 + conns)
        lb = math.log2(1 + bytes_out)
        first = COLD_FALLBACK and self.n[hr] == 1
        d = abs(lb - self.bmu[hr])
        self.bmu[hr] = (1 - a) * self.bmu[hr] + a * lb
        self.bdev[hr] = self.bdev[hr] if first else (1 - a) * self.bdev[hr] + a * d
        lf = math.log2(1 + len(peers))
        self.fdev[hr] = self.fdev[hr] if first else (1 - a) * self.fdev[hr] + a * abs(lf - self.fmu[hr])
        self.fmu[hr] = (1 - a) * self.fmu[hr] + a * lf
        self.nx = (1 - a) * self.nx + a * nx_share
        if admit_items:
            for p in peers:
                self.peers.add(p)
            for s in suffixes:
                self.dns.add(s)

    def cold(self, hr):
        return COLD_FALLBACK and COLD_LEARN and self.n[hr] < SLOT_MIN

    def admit_persistent(self, peers, suffixes, k=3):
        """A NEW item that keeps appearing for k scored hours becomes normal (drift adaptation)."""
        for item in list(peers) + ["dns:" + s for s in suffixes]:
            self.pending[item] = self.pending.get(item, 0) + 1
            if self.pending[item] >= k:
                if item.startswith("dns:"):
                    self.dns.add(item[4:])
                else:
                    self.peers.add(item)
        if len(self.pending) > 256:  # bounded: the pending table is part of the budget, never unbounded
            self.pending = dict(sorted(self.pending.items(), key=lambda kv: -kv[1])[:128])


def simulate(seed, n_devices, m_bits, threshold_q=0.99, learn_hours=240):
    r = random.Random(seed)
    devs = []
    kinds = list(KINDS)
    for i in range(n_devices):
        k = kinds[i % len(kinds)]
        peak, base, npeers, bpc, nsuf = KINDS[k]
        peers = ["198.51.100.%d:%d" % (r.randrange(1, 250), r.choice([443, 443, 80, 8883, 123])) for _ in range(npeers)]
        sufs = ["svc%d.vendor%d.example" % (j, r.randrange(1000)) for j in range(nsuf)]
        devs.append({"kind": k, "peak": set(peak), "base": base, "peers": peers, "bpc": bpc, "sufs": sufs})

    # injections on the scored days (11..14): (device index, kind, start hour offset, duration hours)
    inj = {}
    anomaly_kinds = ["new_service", "exfil", "beacon_new_dst", "scan", "dga"]
    victims = r.sample(range(n_devices), min(n_devices, 15))
    for j, v in enumerate(victims):
        kind = anomaly_kinds[j % len(anomaly_kinds)]
        start = 24 * 10 + r.randrange(0, 24 * 4 - 6)
        dur = 1 if kind in ("exfil", "scan") else 4
        for h in range(start, start + dur):
            inj[(v, h)] = kind
    laptops = [i for i, d in enumerate(devs) if d["kind"] == "laptop" and i not in victims]
    drift_dev = laptops[0] if laptops else None
    drift_start = 24 * 11 + 9
    drift_peers = ["198.51.100.%d:443" % (200 + q) for q in range(5)]

    def observe(i, h):
        d = devs[i]
        hr = h % 24
        on = hr in d["peak"]
        rate = d["base"] * (1.0 if on else 0.15) * r.uniform(0.6, 1.4)
        conns = max(0, int(rate))
        k_peers = min(len(d["peers"]), max(1, int(math.sqrt(conns + 1))))
        peers = set(r.sample(d["peers"], k_peers)) if conns else set()
        bytes_out = int(conns * d["bpc"] * r.uniform(0.5, 1.5))
        sufs = set(r.sample(d["sufs"], min(len(d["sufs"]), max(1, conns // 10)))) if conns else set()
        nx = r.uniform(0.0, 0.03)
        if drift_dev == i and h >= drift_start and on:
            peers |= set(drift_peers)
            conns += 20
        a = inj.get((i, h))
        if a == "new_service":
            peers.add("203.0.113.%d:4444" % (i % 50 + 1))
            conns += 15
        elif a == "exfil":
            bytes_out += 2_000_000_000
        elif a == "beacon_new_dst":
            peers.add("203.0.113.%d:8443" % (i % 50 + 100))
            conns += 1
        elif a == "scan":
            peers |= {"192.168.10.%d:%d" % (q, p) for q in range(1, 60) for p in (22, 445)}
            conns += 118
        elif a == "dga":
            sufs |= {"x%08x.bad.test" % r.getrandbits(32) for _ in range(150)}
            nx = 0.9
        return a, (conns, peers, bytes_out, sufs, nx)

    dnas = [DNA(m_bits) for _ in range(n_devices)]
    rows = []  # (score, label, kind, device, hour, drift)
    for h in range(24 * 14):
        if h and h % (24 * 7) == 0:
            for dn in dnas:
                dn.peers.rotate()
                dn.dns.rotate()
        for i in range(n_devices):
            a, obs = observe(i, h)
            hr = h % 24
            if h < 24 * 10:
                if h >= 24 * 10 - learn_hours:  # learn_hours < 240 simulates a device that was just installed
                    dnas[i].update(hr, obs)
                continue
            s, parts = dnas[i].score(hr, obs)
            drift = (drift_dev == i and h >= drift_start and hr in devs[i]["peak"])
            rows.append((s, 1 if a else 0, a, i, h, drift))
            # GUARDED update -- the policy sees only the score, never the label:
            #   calm hour      -> learn statistics and admit new items
            #   alarming hour  -> learn nothing; new items only count toward persistence (k hours)
            if s < CALM:
                dnas[i].update(hr, obs, admit_items=True)
            else:
                if dnas[i].cold(hr):
                    dnas[i].update(hr, obs, admit_items=False)
                dnas[i].admit_persistent({p for p in obs[1] if p not in dnas[i].peers},
                                         {x for x in obs[3] if x not in dnas[i].dns}, k=PERSIST_K)
    return rows, dnas[0].nbytes(), devs, drift_dev


def auc(rows):
    pos = [s for s, l, *_ in rows if l]
    neg = [s for s, l, *_ in rows if not l]
    if not pos or not neg:
        return float("nan")
    allv = sorted([(s, 1) for s in pos] + [(s, 0) for s in neg])
    rank_sum, i = 0.0, 0
    while i < len(allv):
        j = i
        while j < len(allv) and allv[j][0] == allv[i][0]:
            j += 1
        avg = (i + j + 1) / 2.0
        rank_sum += avg * sum(1 for x in allv[i:j] if x[1])
        i = j
    return (rank_sum - len(pos) * (len(pos) + 1) / 2) / (len(pos) * len(neg))


def evaluate(rows, fpr=0.01):
    neg = sorted((s for s, l, *_ in rows if not l), reverse=True)
    thr = neg[max(0, int(len(neg) * fpr) - 1)] if neg else 0
    det = {}
    for s, l, a, *_ in rows:
        if l:
            det.setdefault(a, []).append(s > thr)
    drift_alerts = sum(1 for s, l, a, i, h, dr in rows if dr and not l and s > thr)
    drift_hours = sum(1 for *_, dr in rows if dr)
    inc = {}
    for s, l, a, i, h, dr in rows:
        if l:
            inc.setdefault((a, i), False)
            inc[(a, i)] = inc[(a, i)] or s > thr
    inc_rate = {}
    for (a, i), hit in inc.items():
        inc_rate.setdefault(a, []).append(hit)
    return thr, {k: sum(v) / len(v) for k, v in det.items()}, drift_alerts, drift_hours, \
        {k: sum(v) / len(v) for k, v in inc_rate.items()}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--devices", type=int, default=60)
    ap.add_argument("--seeds", default="1,2,3,4,5")
    ap.add_argument("--json")
    ap.add_argument("--persist-k", type=int, default=PERSIST_K)
    ap.add_argument("--blooms", default="256,1024,4096,16384")
    ap.add_argument("--learn-hours", type=int, default=240, help="history before scoring (cold start if < 24)")
    ap.add_argument("--no-cold-fallback", action="store_true", help="reproduce the Phase 0 DNA")
    ap.add_argument("--no-cold-learn", action="store_true")
    a = ap.parse_args()
    globals()["PERSIST_K"] = a.persist_k
    globals()["COLD_FALLBACK"] = not a.no_cold_fallback
    globals()["COLD_LEARN"] = not a.no_cold_learn
    out = []
    print("synthetic: %d devices x 14 days hourly; learn days 1-10, score days 11-14" % a.devices)
    print("%8s %8s %7s %8s %-62s %s" % ("bloom_m", "state_B", "AUC", "thr@1%", "detect @1% FPR: hour-level/incident-level",
                                         "benign-drift alerts"))
    print("persistence k = %d alarming hours before a new item becomes normal | learn_hours=%d | cold fallback=%s" % (
        PERSIST_K, a.learn_hours, COLD_FALLBACK))
    for m in [int(x) for x in a.blooms.split(",")]:
        aucs, per, dr_a, dr_h, thrs, sb, inc, fa = [], {}, 0, 0, [], 0, {}, []
        for s in [int(x) for x in a.seeds.split(",")]:
            rows, sb, devs, _ = simulate(s, a.devices, m, learn_hours=a.learn_hours)
            aucs.append(auc(rows))
            # absolute nuisance at a FIXED score threshold (2.0, as in replay_bm_iot23): alarms/device/day
            fa.append(sum(1 for r in rows if not r[1] and r[0] > 2.0) / (a.devices * 4.0))
            thr, d, da, dh, ir = evaluate(rows)
            for k, v in ir.items():
                inc.setdefault(k, []).append(v)
            thrs.append(thr)
            dr_a += da
            dr_h += dh
            for k, v in d.items():
                per.setdefault(k, []).append(v)
        pk = " ".join("%s=%.2f/%.2f" % (k, statistics.mean(per[k]), statistics.mean(inc[k])) for k in sorted(per))
        print("%8d %8d %7.3f %8.2f %-62s %d/%d hours  benign alarms/dev/day@2.0=%.2f" % (
            m, sb, statistics.mean(aucs), statistics.mean(thrs), pk, dr_a, dr_h, statistics.mean(fa)))
        out.append({"bloom_bits": m, "state_bytes": sb, "auc_mean": statistics.mean(aucs),
                    "auc_min": min(aucs), "detect_at_1pct_fpr": {k: statistics.mean(v) for k, v in per.items()},
                    "incident_detect_at_1pct_fpr": {k: statistics.mean(v) for k, v in inc.items()},
                    "drift_alerts": dr_a, "drift_hours": dr_h, "benign_alarms_per_device_day_at_2": statistics.mean(fa)})
    # what the state replaces: 10 days of raw per-device rows (flow + dns summaries at ~110 B/row as JSON)
    rows_per_dev_day = statistics.mean(KINDS[k][1] * (len(KINDS[k][0]) + 0.15 * (24 - len(KINDS[k][0])))
                                       for k in KINDS) * 1.5
    raw_bytes = rows_per_dev_day * 10 * 110
    print("raw history replaced (10 days, ~110 B/row JSON, flows+dns): ~%.1f MB per device (ESTIMATE)" % (raw_bytes / 1e6))
    if a.json:
        with open(a.json, "w") as f:
            json.dump({"devices": a.devices, "seeds": a.seeds, "results": out,
                       "raw_history_bytes_per_device_estimate": raw_bytes}, f, indent=1)


if __name__ == "__main__":
    main()
