#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""P2 (preliminary, IoT-23): learned diagonal state-space cell vs the integer statistical DNA.

Implements docs/research/neuro/15_P2_PREREGISTRATION.md exactly. Requires NumPy (an isolated venv).
  --phase dev   : build dev episodes, fit B's readout on dev benign hours, choose the ridge penalty,
                  calibrate thresholds (1 alarm / device / week), print dev metrics.
  --phase test  : freeze everything from dev, compute the test metrics ONCE.
Usage: <venv>/bin/python -I p2_learned_vs_dna.py <iot23 dir> --phase dev|test [--json out.json]
"""
import argparse
import collections
import glob
import hashlib
import json
import math
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import numpy as np  # noqa: E402
import replay_iot23 as rp  # noqa: E402
import dna_fixed as fx  # noqa: E402
import dna_fixed_eval as fe  # noqa: E402
import behavioural_memory as bm  # noqa: E402

LAMBDAS = (0.5, 0.8, 0.95, 0.99)
NF = 6                         # features: bytes, conns, peers, novel, sin(h), cos(h)
NT = 4                         # targets: the first four features of the next hour
K_SPLICE = 4
MIN_HOURS = 12
FPR_WEEK = 1.0 / (24 * 7)      # 1 alarm per device per week
RIDGES = (0.1, 1.0, 10.0, 100.0)


# ---------------------------------------------------------------- data
def series(rows, host, t0, want):
    """Hourly obs for `host`: want='benign' keeps benign-labelled flows only, 'all' keeps all."""
    hours = collections.defaultdict(lambda: [0, set(), 0])
    mal = set()
    for ts, src, dst, dport, proto, ob, rb, state, label, det in rows:
        if src != host:
            continue
        h = int((ts - t0) // 3600)
        bad = label.lower().startswith("malicious")
        if bad:
            mal.add(h)
        if want == "benign" and bad:
            continue
        hours[h][0] += 1
        hours[h][1].add("%s:%d" % (dst, dport))
        hours[h][2] += ob
    out = [(h, (v[0], v[1], v[2], set(), 0.0)) for h, v in sorted(hours.items())]
    return out, sorted(mal)


def load(root, split):
    benign, infected = [], []
    for p in sorted(glob.glob(os.path.join(root, "**", "conn.log.labeled"), recursive=True)):
        name = p.split(os.sep)[-3]
        if rp.split_of(name) != split:
            continue
        rows = rp.read_conn(p, 1_500_000)
        if not rows:
            continue
        rows.sort(key=lambda r: r[0])
        c = collections.Counter(r[1] for r in rows if r[1].startswith(("192.168.", "10.", "172.")))
        if not c:
            continue
        host, t0 = c.most_common(1)[0][0], rows[0][0]
        b, _ = series(rows, host, t0, "benign")
        if len(b) >= MIN_HOURS:
            benign.append((name, b))
        full, mal = series(rows, host, t0, "all")
        seg = [(h, o) for h, o in full if h in set(mal)]
        if len(seg) >= 1:
            infected.append((name, seg))
    return benign, infected


def episodes(benign, infected):
    """(benign name, infected name, learn part, scored list of (h, obs, label))."""
    eps = []
    for bname, b in benign:
        half = len(b) // 2
        learn, rest = b[:half], b[half:]
        for iname, seg in infected:
            r = int(hashlib.sha256((bname + "|" + iname).encode()).hexdigest(), 16)
            k = min(K_SPLICE, len(seg))
            s0 = r % (len(seg) - k + 1)
            at = (r >> 32) % len(rest)
            base_h = rest[at][0]
            spliced = [(base_h + j, seg[s0 + j][1], 1) for j in range(k)]
            scored = [(h, o, 0) for h, o in rest[:at]] + spliced + [(h + k, o, 0) for h, o in rest[at:]]
            eps.append((bname, iname, learn, scored))
    return eps


# ---------------------------------------------------------------- engines
def feats(obs, novel, hr):
    conns, peers, bytes_out, _s, _n = obs
    a = 2 * math.pi * (hr % 24) / 24.0
    return np.array([math.log2(1 + bytes_out), math.log2(1 + conns), math.log2(1 + len(peers)),
                     math.log2(1 + novel), math.sin(a), math.cos(a)])


class Novelty:
    """The same aging Bloom + per-hour candidate as the integer DNA (fingerprints, 1,024 bits)."""

    def __init__(self):
        self.mem = fx.AgingBloom()
        self.hours = 0

    def count(self, peers):
        cand, n_new = fx.Bloom(), 0
        for p in sorted(peers):
            fp = fx.peer_fp_from_str(p)
            if cand.set(fp) and not self.mem.test(fp):
                n_new += 1
        return n_new, cand

    def admit(self, cand):
        self.mem.cur.merge(cand)

    def tick(self):
        self.hours += 1
        if self.hours % fx.ROTATE_HOURS == 0:
            self.mem.rotate()


class SSM:
    """Candidate B: fixed multi-timescale diagonal state + learned linear readout + per-device error scale."""

    def __init__(self, W, scale0, admit_q):
        self.W, self.admit_q = W, admit_q
        self.s = np.zeros((len(LAMBDAS), NF))
        self.scale = scale0.copy()
        self.nov = Novelty()
        self.primed = False

    def z(self, hr_next):
        a = 2 * math.pi * (hr_next % 24) / 24.0
        return np.concatenate([self.s.ravel(), [math.sin(a), math.cos(a), 1.0]])

    def score(self, hr, obs):
        n_new, cand = self.nov.count(obs[1])
        x = feats(obs, n_new, hr)
        if not self.primed:
            return 0.0, x, cand
        err = np.abs(x[:NT] - self.z(hr) @ self.W)
        return float(np.sum(err / self.scale)), x, cand

    def update(self, x, cand, score, learn):
        lam = np.array(LAMBDAS)[:, None]
        if self.primed:
            err = np.abs(x[:NT] - self.z(int(round(math.atan2(x[4], x[5]) / (2 * math.pi) * 24)) % 24) @ self.W)
            if learn or score < self.admit_q:
                self.scale = 0.9 * self.scale + 0.1 * np.minimum(err, 3 * self.scale) + 1e-6
        self.s = lam * self.s + (1 - lam) * x if self.primed else np.repeat(x[None, :], len(LAMBDAS), 0)
        self.primed = True
        if learn or score < self.admit_q:
            self.nov.admit(cand)
        self.nov.tick()

    @staticmethod
    def nbytes():
        return len(LAMBDAS) * NF * 2 + NT * 2 + 4 * fx.BLOOM_BITS // 8 // 2 + 2 * fx.BLOOM_BITS // 8  # state+scales+bloom(cur,old)+candidate


def fit_readout(benign, ridge):
    """Ridge regression of next-hour targets on the state, over dev benign timelines (all hours)."""
    Z, Y = [], []
    lam = np.array(LAMBDAS)[:, None]
    for _, b in benign:
        nov, s, primed = Novelty(), np.zeros((len(LAMBDAS), NF)), False
        for h, obs in b:
            n_new, cand = nov.count(obs[1])
            x = feats(obs, n_new, h % 24)
            if primed:
                a = 2 * math.pi * (h % 24) / 24.0
                Z.append(np.concatenate([s.ravel(), [math.sin(a), math.cos(a), 1.0]]))
                Y.append(x[:NT])
            s = lam * s + (1 - lam) * x if primed else np.repeat(x[None, :], len(LAMBDAS), 0)
            primed = True
            nov.admit(cand)
            nov.tick()
    Z, Y = np.array(Z), np.array(Y)
    W = np.linalg.solve(Z.T @ Z + ridge * np.eye(Z.shape[1]), Z.T @ Y)
    mae = np.mean(np.abs(Y - Z @ W), axis=0) + 1e-6
    return W, mae, len(Z)


def run_episode(ep, W, mae, admit_q):
    """Returns per scored hour: (labelA, scoreA, scoreB)."""
    bname, iname, learn, scored = ep
    dna = fe.FixedAdapter()
    for h, obs in learn:
        dna.update(h % 24, obs)
    ssm = SSM(W, mae, admit_q)
    for h, obs in learn:
        _, x, cand = ssm.score(h % 24, obs)
        ssm.update(x, cand, 0.0, learn=True)
    out = []
    for h, obs, lab in scored:
        hr = h % 24
        sa, _ = dna.score(hr, obs)
        if sa < bm.CALM:
            dna.update(hr, obs, admit_items=True)
        else:
            if dna.cold(hr):
                dna.update(hr, obs, admit_items=False)
            dna.admit_persistent({p for p in obs[1] if p not in dna.peers}, set(), k=bm.PERSIST_K)
        sb, x, cand = ssm.score(hr, obs)
        ssm.update(x, cand, sb, learn=False)
        out.append((lab, sa, sb))
    return out


# ---------------------------------------------------------------- metrics
def auc(pos, neg):
    if not pos or not neg:
        return float("nan")
    allv = sorted([(s, 1) for s in pos] + [(s, 0) for s in neg])
    rank, i = 0.0, 0
    while i < len(allv):
        j = i
        while j < len(allv) and allv[j][0] == allv[i][0]:
            j += 1
        rank += (i + j + 1) / 2.0 * sum(1 for x in allv[i:j] if x[1])
        i = j
    return (rank - len(pos) * (len(pos) + 1) / 2) / (len(pos) * len(neg))


def thr_at(neg, fpr):
    s = sorted(neg, reverse=True)
    return s[max(0, int(len(s) * fpr) - 1)] if s else 0.0


def evaluate(results, thr):
    """results: list per episode of [(lab, a, b, c)]; thr: dict cand -> threshold."""
    m = {}
    for ci, cand in enumerate(("A", "B", "C")):
        pos = [r[1 + ci] for ep in results for r in ep if r[0]]
        neg = [r[1 + ci] for ep in results for r in ep if not r[0]]
        det = [any(r[1 + ci] > thr[cand] for r in ep if r[0]) for ep in results]
        neg_hours = len(neg)
        alarms = sum(1 for s in neg if s > thr[cand])
        m[cand] = {"auc": auc(pos, neg), "incident_detect": sum(det) / max(1, len(det)),
                   "benign_alarms_per_device_day": alarms / max(1.0, neg_hours / 24.0),
                   "pos_hours": len(pos), "neg_hours": neg_hours}
    return m


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("root")
    ap.add_argument("--phase", choices=["dev", "test"], required=True)
    ap.add_argument("--json")
    ap.add_argument("--frozen", help="dev JSON with the frozen ridge, W, mae, thresholds (required for test)")
    a = ap.parse_args()
    dev_b, dev_i = load(a.root, "dev")
    print("dev: %d benign timelines, %d infected scenarios" % (len(dev_b), len(dev_i)))
    if a.phase == "dev":
        best = None
        for ridge in RIDGES:
            W, mae, n = fit_readout(dev_b, ridge)
            res0 = [run_episode(ep, W, mae, float("inf")) for ep in episodes(dev_b, dev_i)]
            negB = [r[2] for ep in res0 for r in ep if not r[0]]
            admit_q = float(np.quantile(negB, 0.95)) if negB else float("inf")
            res = [run_episode(ep, W, mae, admit_q) for ep in episodes(dev_b, dev_i)]
            posB = [r[2] for ep in res for r in ep if r[0]]
            negB = [r[2] for ep in res for r in ep if not r[0]]
            aB = auc(posB, negB)
            print("  ridge=%-6g train pairs=%d  dev AUC(B)=%.4f" % (ridge, n, aB))
            if best is None or aB > best[0]:
                best = (aB, ridge, W, mae, admit_q, res)
        aB, ridge, W, mae, admit_q, res = best
        negA = [r[1] for ep in res for r in ep if not r[0]]
        negB = [r[2] for ep in res for r in ep if not r[0]]
        tA, tB = thr_at(negA, FPR_WEEK), thr_at(negB, FPR_WEEK)
        resc = [[(lab, sa, sb, max(sa / max(tA, 1e-9), sb / max(tB, 1e-9))) for lab, sa, sb in ep] for ep in res]
        negC = [r[3] for ep in resc for r in ep if not r[0]]
        thr = {"A": tA, "B": tB, "C": thr_at(negC, FPR_WEEK)}
        m = evaluate(resc, thr)
        frozen = {"ridge": ridge, "W": W.tolist(), "mae": mae.tolist(), "admit_q": admit_q, "thr": thr,
                  "tA": tA, "tB": tB}
    else:
        fz = json.load(open(a.frozen))["frozen"]
        W, mae, admit_q, thr = np.array(fz["W"]), np.array(fz["mae"]), fz["admit_q"], fz["thr"]
        tA, tB = fz["tA"], fz["tB"]
        test_b, test_i = load(a.root, "test")
        print("test: %d benign timelines, %d infected scenarios (frozen from dev: ridge=%g)" % (len(test_b), len(test_i), fz["ridge"]))
        res = [run_episode(ep, W, mae, admit_q) for ep in episodes(test_b, test_i)]
        resc = [[(lab, sa, sb, max(sa / max(tA, 1e-9), sb / max(tB, 1e-9))) for lab, sa, sb in ep] for ep in res]
        m = evaluate(resc, thr)
        frozen = fz
    bytes_ = {"A": fx.DNAFixed.nbytes(), "B": SSM.nbytes(), "C": fx.DNAFixed.nbytes() + SSM.nbytes()}
    print("phase=%s episodes=%d" % (a.phase, len(resc)))
    print("%-4s %8s %18s %26s %10s" % ("cand", "AUC", "incident det @1/wk", "benign alarms/dev/day", "bytes/dev"))
    for c in ("A", "B", "C"):
        print("%-4s %8.4f %18.3f %26.3f %10d" % (c, m[c]["auc"], m[c]["incident_detect"], m[c]["benign_alarms_per_device_day"], bytes_[c]))
    if a.json:
        json.dump({"phase": a.phase, "metrics": m, "bytes": bytes_, "frozen": frozen, "episodes": len(resc)},
                  open(a.json, "w"), indent=1)


if __name__ == "__main__":
    main()
