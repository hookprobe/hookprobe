#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Apply the FROZEN S1 model (models/s1/s1_model.json, float form) to DNA v1 vectors. Nothing is fitted.
Windows with fewer than 3 events are skipped (bench.load's rule). Prints alerts per device-day; with two files, also
paired decision differences by window id (one alert per window id; duplicate ids are counted once).
Usage: s1_apply.py <vectors.jsonl> [<vectors_b.jsonl>]
"""
import hashlib, json, math, os, sys
FEATS32 = ["log_flows", "out_frac", "log_remotes", "log_dst_ports", "port_entropy", "top_port_share", "fail_ratio",
           "log_bytes_out", "log_bytes_in", "log_out_in_ratio", "log_mean_dur", "log_pkts_per_flow", "tcp_frac", "udp_frac",
           "icmp_frac", "wellknown_frac", "telnet_frac", "ssh_frac", "smb_frac", "web_frac", "dns_frac", "ntp_frac",
           "periodic_cv", "log_period_s", "log_max_per_min", "novel_pair_frac", "warninglist_frac", "unrouted_frac",
           "log_countries", "log_asns", "lan_peer_frac", "log_inbound_sources"]
P = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "models", "s1", "s1_model.json")
SHA = "20f38f337863a934d825fd0cfecf57609865779a60cfd702063ff41a32c81df5"


def load_model():
    raw = open(P, "rb").read()
    assert hashlib.sha256(raw).hexdigest() == SHA, "s1_model.json is not the frozen file"
    m = json.loads(raw)
    idx = [FEATS32.index(f) for f in m["features"]]
    f = m["float"]
    return lambda x: sum(w * (x[i] - mu) / sd for w, i, mu, sd in zip(f["w"], idx, f["mu"], f["sd"])) + f["b"] > f["thr"]


def run(path, alert):
    dec, hours = {}, 0
    for l in open(path):
        r = json.loads(l)
        if r.get("n_events", 0) < 3:
            continue
        hours += 1
        dec[r["window_id"]] = dec.get(r["window_id"], False) or alert(r["x"])
    return dec, hours


def main():
    alert = load_model()
    out = [run(p, alert) for p in sys.argv[1:]]
    for p, (d, h) in zip(sys.argv[1:], out):
        n = sum(d.values())
        print("%s: windows (>= 3 events) %d, S1 alerts %d, %.3f per device-day" % (os.path.basename(p), h, n, 24 * n / max(1, h)))
    if len(out) == 2:
        a, b = out[0][0], out[1][0]
        both = set(a) & set(b)
        print("paired window ids %d; S1 decisions differing %d (a only %d, b only %d); ids only in a %d, only in b %d" % (
            len(both), sum(a[k] != b[k] for k in both), sum(a[k] and not b[k] for k in both), sum(b[k] and not a[k] for k in both),
            len(set(a) - set(b)), len(set(b) - set(a))))


if __name__ == "__main__":
    main()
