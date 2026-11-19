#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""D1: the integer temporal engine on months of real device traffic (UNSW-IoTraffic).

Implements docs/research/neuro/17_D1_PREREGISTRATION.md, including its analysis addendum.
  --phase dev  : Q2 (choose q_min), Q4 (choose the ridge), dev nuisance. Writes the frozen choices.
  --phase test : frozen choices only; Q1, Q2, Q3, Q4 on the test portion, ONCE.

Engine = dna_fixed.DNAFixed (bit-exact with os/neuro/el0-neuro), fed event by event via HourAgg, closing
only the hours in which the device had traffic (el0-neuro closes active devices only). Alarm = score >= 1.0.

Usage: <venv>/bin/python -I d1_analysis.py <d1.jsonl> <devices.tsv> <iot23 dir> --phase dev|test --json out.json
       [--frozen dev.json]   (required for test)
"""
import argparse
import collections
import copy
import hashlib
import json
import math
import os
import random
import statistics
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import numpy as np  # noqa: E402
import dna_fixed as fx  # noqa: E402
import p2_learned_vs_dna as p2  # noqa: E402
import unsw_to_d1 as conv  # noqa: E402
import ipaddress  # noqa: E402

PEER_MODE = "exact"             # doc 18: the overlays use the same peer key as the converted data


def ov_fp(s):
    """'ip:port' of an overlay peer -> its fingerprint under PEER_MODE (no transport: port-only class match)."""
    ip, _, port = s.rpartition(":")
    return conv.service_peer_fp(PEER_MODE, ipaddress.ip_address(ip.strip("[]")).packed, int(port or 0))

Q_MINS = (3, 5, 10, 20)
ONSETS = 8                      # attack onsets per device, per kind, per period
KINDS = ("dga", "scan", "exfil", "iot23")
DUR = {"dga": 4, "scan": 1, "exfil": 1, "iot23": 4}
CALM = fx.CALM_Q8
HOURS_WEEK = 24 * 7
CLOCK_CUT = 1472688000 // 3600  # 2016-09-01 UTC: earlier timestamps are capture clock errors (addendum A2)
MIN_DAYS = 7                    # medians use devices with >= 7 active days in the period (addendum A6)


# ---------------------------------------------------------------- data
def load(d1, devs_tsv):
    names = {}
    for l in open(devs_tsv):
        i, mac, name = l.rstrip("\n").split("\t")
        names[int(i)] = (mac, name)
    tl = collections.defaultdict(list)
    for l in open(d1):
        r = json.loads(l)
        if r["hour"] >= CLOCK_CUT:
            tl[r["dev"]].append((r["hour"], r))
    for v in tl.values():
        v.sort(key=lambda x: x[0])
    return names, tl


def held_out(mac):
    """Pre-registered: sha256(device id) % 27 < 5, device id = the converter's MAC string (aa:bb:..)."""
    return int(hashlib.sha256(mac.encode()).hexdigest(), 16) % 27 < 5


def split(hours, mode="d1"):
    """Per device. d1: first 50% of ACTIVE DAYS = history, next 25% = dev, last 25% = test.
    half (doc 18 confirmation): first 50% = history (learning, unscored), last 50% = test (scored)."""
    days = sorted({h // 24 for h, _ in hours})
    n = len(days)
    if mode == "half":
        a = days[n // 2] if n else 0
        out = {"history": [], "dev": [], "test": []}
        for h, r in hours:
            out["history" if h // 24 < a else "test"].append((h, r))
        return out, {"history": n // 2, "dev": 0, "test": n - n // 2}
    a, b = days[n // 2] if n else 0, days[(3 * n) // 4] if n else 0
    out = {"history": [], "dev": [], "test": []}
    for h, r in hours:
        d = h // 24
        out["history" if d < a else "dev" if d < b else "test"].append((h, r))
    return out, {"history": n // 2, "dev": (3 * n) // 4 - n // 2, "test": n - (3 * n) // 4}


# ---------------------------------------------------------------- engine with the Q2 rule
class DNAQ(fx.DNAFixed):
    """DNAFixed, but the NX term counts only when the hour has >= q_min DNS queries (q_min=0: unchanged)."""

    def __init__(self, q_min=0):
        super().__init__()
        self.q_min = q_min

    def score(self, hr, agg):
        if self.q_min and agg.q_total < self.q_min:
            x = agg.q_nx
            agg.q_nx = 0          # hour NX share 0 -> d_nx <= 0 -> NX term 0; the novel-DNS term is unchanged
            try:
                return super().score(hr, agg)
            finally:
                agg.q_nx = x      # learning (update) still sees the true NX share
        return super().score(hr, agg)


def make_agg(mem, r, extra=None):
    agg = fx.HourAgg()
    for fp in r["peers"]:
        agg.add_flow(mem, fp, 0, conns=0)
    for fp, nx in r["dns"]:
        agg.add_dns(mem, fp, nx)
    agg.conns, agg.bytes_out = r["conns"], r["bytes"]
    if extra:
        for fp in extra.get("peers", ()):
            agg.add_flow(mem, fp, 0, conns=0)
        for fp, nx in extra.get("dns", ()):
            agg.add_dns(mem, fp, nx)
        agg.conns += extra.get("conns", 0)
        agg.bytes_out += extra.get("bytes", 0)
    return agg


# ---------------------------------------------------------------- attacks (overlaid on real hours)
def attack_hours(kind, seed, iot_segs):
    """List (len DUR[kind]) of overlays {peers, dns, conns, bytes} for one onset."""
    r = random.Random(seed)
    if kind == "dga":   # 150 NX queries per hour to random REGISTERED domains (the pinned eTLD rule would
        out = []        # collapse random subdomains of one parent to a single fingerprint)
        for _ in range(DUR[kind]):
            names = ["%s.%s" % ("".join(r.choice("abcdefghijklmnopqrstuvwxyz0123456789") for _ in range(r.randint(10, 18))),
                                r.choice(("com", "net", "org", "info"))) for _ in range(150)]
            out.append({"dns": [(fx.dns_fp_from_str(n), 1) for n in names], "conns": 0, "bytes": 150 * 70})
        return out
    if kind == "scan":  # 59 LAN hosts x {22, 445}, as behavioural_memory.py
        peers = [ov_fp("192.168.10.%d:%d" % (q, p)) for q in range(1, 60) for p in (22, 445)]
        return [{"peers": peers, "conns": 118, "bytes": 118 * 60}]
    if kind == "exfil":  # +2 GB to one new external peer, as behavioural_memory.py
        return [{"peers": [ov_fp("203.0.113.%d:443" % r.randrange(1, 250))], "conns": 1,
                 "bytes": 2_000_000_000}]
    name, seg = iot_segs[seed % len(iot_segs)]      # IoT-23 malicious hours of an infected host
    k = min(DUR[kind], len(seg))
    s0 = (seed >> 8) % (len(seg) - k + 1)
    out = []
    for _, (conns, peers, bytes_out, _s, _n) in seg[s0:s0 + k]:
        out.append({"peers": [ov_fp(p) for p in sorted(peers)], "conns": conns, "bytes": bytes_out})
    return out


def onsets(mac, kind, n_hours):
    """Deterministic onset indices within the period (not in its first 24 hours when possible)."""
    lo = min(24, max(0, n_hours - 8))
    hi = max(lo + 1, n_hours - DUR[kind])
    return sorted({lo + int(hashlib.sha256(("%s|%s|%d" % (mac, kind, j)).encode()).hexdigest(), 16) % (hi - lo)
                   for j in range(ONSETS)})


# ---------------------------------------------------------------- the learned cell (P2 candidate B, on fingerprints)
class NoveltyFP(p2.Novelty):
    def count(self, peers):
        cand, n_new = fx.Bloom(), 0
        for fp in peers:
            if cand.set(fp) and not self.mem.test(fp):
                n_new += 1
        return n_new, cand


def obs_of(r, extra=None):
    peers = list(r["peers"]) + list((extra or {}).get("peers", ()))
    return (r["conns"] + (extra or {}).get("conns", 0), peers, r["bytes"] + (extra or {}).get("bytes", 0), set(), 0.0)


def feats_fp(obs, novel, hr):
    conns, peers, bytes_out, _s, _n = obs
    a = 2 * math.pi * (hr % 24) / 24.0
    return np.array([math.log2(1 + bytes_out), math.log2(1 + conns), math.log2(1 + len(set(peers))),
                     math.log2(1 + novel), math.sin(a), math.cos(a)])


class SSMFP(p2.SSM):
    def __init__(self, W, scale0, admit_q):
        super().__init__(W, scale0, admit_q)
        self.nov = NoveltyFP()

    def score(self, hr, obs):
        n_new, cand = self.nov.count(obs[1])
        x = feats_fp(obs, n_new, hr)
        if not self.primed:
            return 0.0, x, cand
        err = np.abs(x[:p2.NT] - self.z(hr) @ self.W)
        return float(np.sum(err / self.scale)), x, cand


def fit_readout(timelines, ridge):
    Z, Y = [], []
    lam = np.array(p2.LAMBDAS)[:, None]
    for tl in timelines:
        nov, s, primed = NoveltyFP(), np.zeros((len(p2.LAMBDAS), p2.NF)), False
        for h, r in tl:
            obs = obs_of(r)
            n_new, cand = nov.count(obs[1])
            x = feats_fp(obs, n_new, h % 24)
            if primed:
                a = 2 * math.pi * (h % 24) / 24.0
                Z.append(np.concatenate([s.ravel(), [math.sin(a), math.cos(a), 1.0]]))
                Y.append(x[:p2.NT])
            s = lam * s + (1 - lam) * x if primed else np.repeat(x[None, :], len(p2.LAMBDAS), 0)
            primed = True
            nov.admit(cand)
            nov.tick()
    Z, Y = np.array(Z), np.array(Y)
    W = np.linalg.solve(Z.T @ Z + ridge * np.eye(Z.shape[1]), Z.T @ Y)
    return W, np.mean(np.abs(Y - Z @ W), axis=0) + 1e-6, len(Z)


# ---------------------------------------------------------------- one device, one period
def run_device(mac, parts, period, q_min, iot_segs, ssm=None):
    """Streams history (+dev when period=test) unscored, then the period scored.
    Returns benign scores [(h, sA, sB)] and attack results {kind: [(scoresA, scoresB)]}."""
    dna = DNAQ(q_min)
    warm = parts["history"] + (parts["dev"] if period == "test" else [])
    for h, r in warm:
        dna.close_hour(h % 24, make_agg(dna, r))
    b = None
    if ssm is not None:
        W, mae, admit_q = ssm
        b = SSMFP(W, mae, admit_q)
        for h, r in warm:
            _, x, cand = b.score(h % 24, obs_of(r))
            b.update(x, cand, 0.0, learn=True)
    hours = parts[period]
    starts = {k: set(onsets(mac, k, len(hours))) for k in KINDS}
    benign, attacks = [], {k: [] for k in KINDS}
    for i, (h, r) in enumerate(hours):
        for k in KINDS:
            if i in starts[k] and (k != "iot23" or iot_segs):
                seed = int(hashlib.sha256(("%s|%s|%d|%s" % (mac, k, i, period)).encode()).hexdigest()[:12], 16)
                ov = attack_hours(k, seed, iot_segs)
                dA, dB = copy.deepcopy(dna), copy.deepcopy(b) if b is not None else None
                sa, sb = [], []
                for j, extra in enumerate(ov):
                    if i + j >= len(hours):
                        break
                    hh, rr = hours[i + j]
                    s, _ = dA.close_hour(hh % 24, make_agg(dA, rr, extra))
                    sa.append(s / 256.0)
                    if dB is not None:
                        v, x, cand = dB.score(hh % 24, obs_of(rr, extra))
                        dB.update(x, cand, v, learn=False)
                        sb.append(v)
                attacks[k].append((sa, sb))
        s, _ = dna.close_hour(h % 24, make_agg(dna, r))
        v = None
        if b is not None:
            v, x, cand = b.score(h % 24, obs_of(r))
            b.update(x, cand, v, learn=False)
        benign.append((h, s / 256.0, v))
    return benign, attacks


def run_all(devs, period, q_min, iot_segs, ssm=None):
    out = {}
    for d, (mac, name, parts, ndays) in devs.items():
        if parts[period]:
            out[d] = run_device(mac, parts, period, q_min, iot_segs, ssm)
    return out


# ---------------------------------------------------------------- metrics
def nuisance(res, devs, period, col=1, thr=1.0):
    per, days = {}, {}
    for d, (benign, _) in res.items():
        nd = devs[d][3][period]
        weeks = max(nd, 1) / 7.0
        per[devs[d][1]] = sum(1 for x in benign if x[col] is not None and x[col] >= thr) / weeks
        days[devs[d][1]] = nd
    vals = sorted(v for k, v in per.items() if days[k] >= MIN_DAYS)
    return {"median": statistics.median(vals) if vals else float("nan"), "max": max(vals) if vals else float("nan"),
            "devices_over_1": sum(1 for v in vals if v > 1.0), "devices": len(vals), "per_device": per,
            "period_days": days, "min_days": MIN_DAYS}


def detection(res, col=0, thr=1.0, kinds=KINDS, only=None):
    det, n, pos = collections.Counter(), collections.Counter(), []
    for d, (_, attacks) in res.items():
        if only is not None and d not in only:
            continue
        for k in kinds:
            for sc in attacks[k]:
                s = sc[col]
                if not s:
                    continue
                n[k] += 1
                det[k] += any(v >= thr for v in s)
                pos.extend(s)
    rate = {k: det[k] / n[k] if n[k] else float("nan") for k in kinds}
    tot = sum(n.values())
    rate["all"] = sum(det.values()) / tot if tot else float("nan")
    return rate, pos, dict(n)


def neg_scores(res, col, only=None):
    return [x[col] for d, (b, _) in res.items() if only is None or d in only for x in b if x[col] is not None]


# ---------------------------------------------------------------- main
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("d1")
    ap.add_argument("devices")
    ap.add_argument("iot23")
    ap.add_argument("--phase", choices=["dev", "test", "dna"], required=True,
                    help="dev/test: doc 17. dna: doc 18, the DNA alone on --period, with the overlays")
    ap.add_argument("--period", choices=["dev", "test"], default="dev")
    ap.add_argument("--split", choices=["d1", "half"], default="d1")
    ap.add_argument("--peer-key", choices=conv.PEER_MODES, default="exact")
    ap.add_argument("--json", required=True)
    ap.add_argument("--frozen")
    a = ap.parse_args()
    global PEER_MODE
    PEER_MODE = a.peer_key
    names, tl = load(a.d1, a.devices)
    devs = {}
    for d, hours in sorted(tl.items()):
        parts, ndays = split(hours, a.split)
        mac, name = names[d]
        devs[d] = (mac, name, parts, ndays)
    held = {d for d, v in devs.items() if held_out(v[0])}
    print("devices with traffic: %d / %d listed; held out: %s" % (len(devs), len(names), sorted(devs[d][1] for d in held)))
    for d, (mac, name, parts, nd) in devs.items():
        print("  %-24s days h/d/t %3d/%3d/%3d  hours h/d/t %5d/%5d/%5d%s" % (
            name, nd["history"], nd["dev"], nd["test"], len(parts["history"]), len(parts["dev"]), len(parts["test"]),
            "  HELD-OUT" if d in held else ""))
    iot_split = "dev" if (a.phase == "dev" or (a.phase == "dna" and a.period == "dev")) else "test"
    _, iot_segs = p2.load(a.iot23, iot_split)
    print("IoT-23 %s split: %d infected scenarios for splicing" % (iot_split, len(iot_segs)))
    report = {"phase": a.phase, "held_out": sorted(devs[d][1] for d in held),
              "days": {devs[d][1]: devs[d][3] for d in devs}}

    if a.phase == "dna":
        res = run_all(devs, a.period, 0, iot_segs)
        nu = nuisance(res, devs, a.period)
        rate, posA, n = detection(res, col=0)
        rate_ho, _, _ = detection(res, col=0, only=held)
        aA = p2.auc(posA, neg_scores(res, 1))
        drivers = collections.Counter()
        ok = nu["median"] <= 1.0 and all(rate[k] >= 0.9 for k in KINDS if n.get(k))
        print("DNA peer-key=%s period=%s split=%s: alarms/dev/week median %.3f max %.2f (devices >1: %d/%d)  AUC %.4f" % (
            a.peer_key, a.period, a.split, nu["median"], nu["max"], nu["devices_over_1"], nu["devices"], aA))
        print("  detection %s  held-out %.3f  onsets %s  -> criteria %s" % (
            {k: round(v, 3) for k, v in rate.items()}, rate_ho["all"], n, "MET" if ok else "NOT MET"))
        report.update({"peer_key": a.peer_key, "period": a.period, "split": a.split, "nuisance": nu, "detect": rate,
                       "detect_held_out": rate_ho, "auc": aA, "onsets": n, "criteria_met": ok})
    elif a.phase == "dev":
        # Q2: q_min on dev
        q2 = {}
        for q in (0,) + Q_MINS:
            res = run_all(devs, "dev", q, iot_segs)
            nu = nuisance(res, devs, "dev")
            rate, _, n = detection(res, kinds=("dga",))
            q2[q] = {"nuisance": nu, "dga_detect": rate["dga"], "dga_onsets": n.get("dga", 0)}
            print("dev q_min=%-2d  alarms/dev/week median %.3f max %.2f (devices >1: %d/%d)  DGA onset detect %.3f" % (
                q, nu["median"], nu["max"], nu["devices_over_1"], nu["devices"], rate["dga"]))
        ok = [q for q in Q_MINS if q2[q]["nuisance"]["median"] <= 1.0 and q2[q]["dga_detect"] >= 0.9]
        q_min = min(ok) if ok else None
        print("Q2 choice on dev: q_min = %s" % q_min)
        # Q4: ridge on dev (history hours of non-held-out devices train the readout)
        train = [devs[d][2]["history"] for d in devs if d not in held and len(devs[d][2]["history"]) > 1]
        best = None
        for ridge in p2.RIDGES:
            W, mae, npairs = fit_readout(train, ridge)
            res0 = run_all(devs, "dev", q_min or 0, iot_segs, (W, mae, float("inf")))
            nb = neg_scores(res0, 2)
            admit_q = float(np.quantile(nb, 0.95)) if nb else float("inf")
            res = run_all(devs, "dev", q_min or 0, iot_segs, (W, mae, admit_q))
            _, posB, _ = detection(res, col=1)
            aB = p2.auc(posB, neg_scores(res, 2))
            print("  ridge=%-6g pairs=%d dev AUC(B)=%.4f" % (ridge, npairs, aB))
            if best is None or aB > best[0]:
                best = (aB, ridge, W, mae, admit_q, res)
        aB, ridge, W, mae, admit_q, res = best
        tB = p2.thr_at(neg_scores(res, 2), 1.0 / HOURS_WEEK)
        _, posA, _ = detection(res, col=0)
        aA = p2.auc(posA, neg_scores(res, 1))
        print("dev AUC: A(DNA%s) %.4f  B %.4f (ridge %g)  B threshold @1/week %.4f" % (
            "+q%d" % q_min if q_min else "", aA, aB, ridge, tB))
        report.update({"q2": {str(k): v for k, v in q2.items()}, "dev_auc": {"A": aA, "B": aB},
                       "frozen": {"q_min": q_min, "ridge": ridge, "W": W.tolist(), "mae": mae.tolist(),
                                  "admit_q": admit_q, "tB": tB}})
    else:
        fz = json.load(open(a.frozen))["frozen"]
        q_min, W, mae, admit_q, tB = fz["q_min"], np.array(fz["W"]), np.array(fz["mae"]), fz["admit_q"], fz["tB"]
        print("frozen from dev: q_min=%s ridge=%g tB=%.4f" % (q_min, fz["ridge"], tB))
        base = run_all(devs, "test", 0, iot_segs, (W, mae, admit_q))
        fixd = run_all(devs, "test", q_min, iot_segs, (W, mae, admit_q)) if q_min else None
        out = {}
        for label, res in (("dna", base), ("dna+q%s" % q_min, fixd)):
            if res is None:
                continue
            nu = nuisance(res, devs, "test")
            rate, posA, n = detection(res, col=0)
            rate_ho, _, _ = detection(res, col=0, only=held)
            aA = p2.auc(posA, neg_scores(res, 1))
            out[label] = {"nuisance": nu, "detect": rate, "detect_held_out": rate_ho, "auc": aA, "onsets": n}
            print("TEST %-9s alarms/dev/week median %.3f max %.2f (devices >1: %d/%d)  AUC %.4f  detect %s  held-out %s" % (
                label, nu["median"], nu["max"], nu["devices_over_1"], nu["devices"], aA,
                {k: round(v, 3) for k, v in rate.items()}, round(rate_ho["all"], 3)))
        ref = fixd or base
        nuB = nuisance(ref, devs, "test", col=2, thr=tB)
        rateB, posB, _ = detection(ref, col=1, thr=tB)
        aB = p2.auc(posB, neg_scores(ref, 2))
        out["learned_B"] = {"nuisance": nuB, "detect": rateB, "auc": aB}
        aA_ref = out["dna+q%s" % q_min if q_min else "dna"]["auc"]
        q4 = aB >= aA_ref + 0.02 and p2.SSM.nbytes() <= fx.DNAFixed.nbytes() and \
            nuB["median"] <= out["dna+q%s" % q_min if q_min else "dna"]["nuisance"]["median"]
        print("TEST learned B: AUC %.4f (DNA %.4f)  alarms/dev/week median %.3f  detect %.3f  -> Q4 %s" % (
            aB, aA_ref, nuB["median"], rateB["all"], "B WINS" if q4 else "DNA stays"))
        report.update({"test": out, "q4_b_wins": q4, "frozen": fz,
                       "bytes": {"A": fx.DNAFixed.nbytes(), "B": p2.SSM.nbytes()}})
    json.dump(report, open(a.json, "w"), indent=1, default=float)


if __name__ == "__main__":
    main()
