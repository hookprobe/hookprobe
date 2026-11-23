#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Doc 37: the M4 L1-IoT gate. Applies the FROZEN S1 model (s1_apply.load_model, hash-checked) once to the two sealed
sets and prints the verdict. Nothing is fitted, tuned or re-thresholded.

Inputs (both produced by the pinned converters; see doc 37):
  malware.jsonl : pcap_to_dna.py --rule doc20 --labels ... on the Kitsune captures (dataset "kitsune", per-frame label
                  files) and the Stratosphere MCFP captures (dataset "mcfp", --labels infected:<documented host IPs>),
                  concatenated. Each window carries attack_pkts_sent (attack frames the device sent in that hour).
  homes.jsonl   : ipfix_to_dna.py on the unsw-iot-homes-ipfix CSVs (the exporter's own YAF cut).

Rules (all fixed in doc 37 before either set is acquired):
  - a window is scored only with >= 3 events (bench.load's rule, as M3);
  - malicious window: attack_pkts_sent >= 1. GATED recall pools (a) the Kitsune captures whose name contains "mirai"
    (the infected IoT devices) and (b) every MCFP capture (each is an infected IoT device). The other Kitsune captures'
    attacker hosts are reported, not gated (an attacking laptop is out of L1-IoT's scope). Recall is also reported per
    source, not gated;
  - benign windows in the malware captures (attack_pkts_sent == 0) are reported, not gated (a lab, not a home);
  - home false alerts per device-day = 24 * alerts / scored windows, over every home device (as M3);
  - PASS iff pooled IoT-malware recall >= 0.90 with >= 20 scored malicious windows AND home FA <= 0.14 with >= 2,400 scored windows
    (100 device-days). Below either minimum the verdict is INCONCLUSIVE (underpowered), never PASS.
Usage: m4_gate.py <malware.jsonl> <homes.jsonl>            the one look
       m4_gate.py --counts <malware.jsonl> <homes.jsonl>   intake: window counts only; the model is never loaded
"""
import collections, json, math, os, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from s1_apply import load_model, SHA  # noqa: E402

RECALL_MIN, FA_MAX, N_MAL_MIN, N_HOME_MIN = 0.90, 0.14, 20, 2400


def source(r):
    """-> 'kitsune-mirai', 'mcfp', or None (reported only)."""
    if r.get("dataset") == "mcfp":
        return "mcfp"
    if r.get("dataset") == "kitsune" and "mirai" in r["capture"].lower():
        return "kitsune-mirai"
    return None


def wilson(k, n, z=1.96):
    if n == 0:
        return (0.0, 0.0)
    p = k / n; d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d; h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return (max(0.0, c - h), min(1.0, c + h))


def rows(path):
    for l in open(path):
        yield json.loads(l)


def counts(mal_path, home_path):
    c = collections.Counter()
    for r in rows(mal_path):
        if "attack_pkts_sent" not in r:
            sys.exit("malware vectors carry no labels: run pcap_to_dna.py with --labels")
        c[(source(r) or "-", r["capture"], "mal" if r["attack_pkts_sent"] >= 1 else "ben", r.get("n_events", 0) >= 3)] += 1
    for (src, cap, lab, ok), n in sorted(c.items()):
        print("malware set: [%s] %s %s %s: %d" % (src, cap, lab, "scored" if ok else "< 3 events", n))
    per = collections.Counter()
    for (src, cap, lab, ok), n in c.items():
        if src != "-" and lab == "mal" and ok:
            per[src] += n
    n_m = sum(per.values())
    print("gated malicious scored windows by source: %s" % dict(per))
    h = collections.Counter()
    for r in rows(home_path):
        if r.get("n_events", 0) >= 3:
            h[r["window_id"].rsplit("|", 1)[0]] += 1
    print("homes: %d scored windows, %d devices" % (sum(h.values()), len(h)))
    print("power: gated malicious scored windows %d (need >= %d); home scored windows %d (need >= %d)" % (
        n_m, N_MAL_MIN, sum(h.values()), N_HOME_MIN))


def main():
    if sys.argv[1] == "--counts":
        return counts(sys.argv[2], sys.argv[3])
    mal_path, home_path = sys.argv[1], sys.argv[2]
    alert = load_model()
    print("S1 model sha256 %s (frozen, checked)" % SHA)
    cap = collections.defaultdict(lambda: collections.Counter())
    gated = collections.defaultdict(lambda: [0, 0])     # source -> [malicious windows, detected]
    skipped_mal = 0
    for r in rows(mal_path):
        is_mal = r.get("attack_pkts_sent", 0) >= 1
        if "attack_pkts_sent" not in r:
            sys.exit("malware vectors carry no labels: run pcap_to_dna.py with --labels")
        if r.get("n_events", 0) < 3:
            skipped_mal += is_mal; continue
        a = alert(r["x"]); c = cap[r["capture"]]
        c["mal" if is_mal else "ben"] += 1
        c["mal_hit" if is_mal else "ben_alert"] += a
        if is_mal and source(r):
            g = gated[source(r)]; g[0] += 1; g[1] += a
    print("\n| capture | malicious windows | detected | recall | benign windows | alerts on benign |")
    print("|---|---|---|---|---|---|")
    for k in sorted(cap):
        c = cap[k]
        print("| %s | %d | %d | %s | %d | %d |" % (k, c["mal"], c["mal_hit"], "%.3f" % (c["mal_hit"] / c["mal"]) if c["mal"] else "—",
                                               c["ben"], c["ben_alert"]))
    print("malicious windows skipped (< 3 events): %d" % skipped_mal)
    for src in sorted(gated):
        n, k = gated[src]
        print("recall by source (not gated): %s %d / %d = %.3f" % (src, k, n, k / n))
    n_m = sum(g[0] for g in gated.values()); k_m = sum(g[1] for g in gated.values())
    rec = k_m / n_m if n_m else None
    lo, hi = wilson(k_m, n_m)

    per_dev = collections.defaultdict(lambda: [0, 0])
    n_h = k_h = 0
    for r in rows(home_path):
        if r.get("n_events", 0) < 3:
            continue
        a = alert(r["x"]); n_h += 1; k_h += a
        d = per_dev[r["window_id"].rsplit("|", 1)[0]]; d[0] += 1; d[1] += a
    fa = 24 * k_h / n_h if n_h else None
    worst = sorted(((24 * a / n, dev, a, n) for dev, (n, a) in per_dev.items() if n), reverse=True)[:5]

    print("\nGATED")
    print("  pooled IoT-malware recall: %d / %d = %s (Wilson 95%% %.3f-%.3f); need >= %.2f with >= %d windows" % (
        k_m, n_m, "%.3f" % rec if rec is not None else "—", lo, hi, RECALL_MIN, N_MAL_MIN))
    print("  home false alerts: %d on %d windows (%d devices) = %s per device-day; need <= %.2f with >= %d windows" % (
        k_h, n_h, len(per_dev), "%.3f" % fa if fa is not None else "—", FA_MAX, N_HOME_MIN))
    print("  worst home devices: %s" % ", ".join("%s %.2f (%d/%d)" % (d, f, a, n) for f, d, a, n in worst))
    under = [s for s, bad in (("gated malware windows %d < %d" % (n_m, N_MAL_MIN), n_m < N_MAL_MIN),
                              ("home windows %d < %d" % (n_h, N_HOME_MIN), n_h < N_HOME_MIN)) if bad]
    fail = []                                     # an empty side cannot fail; it is underpowered
    if rec is not None and rec < RECALL_MIN:
        fail.append("recall %.3f < %.2f" % (rec, RECALL_MIN))
    if fa is not None and fa > FA_MAX:
        fail.append("home FA %.3f > %.2f" % (fa, FA_MAX))
    if fail:
        print("VERDICT: FAIL (%s)%s" % ("; ".join(fail), " [also underpowered: %s]" % "; ".join(under) if under else ""))
    elif under:
        print("VERDICT: INCONCLUSIVE, underpowered (%s)" % "; ".join(under))
    else:
        print("VERDICT: PASS")


if __name__ == "__main__":
    main()
