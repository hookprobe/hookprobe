#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""T0 v2: TRAINING windows from REAL traffic. IoT-23 dev-split hours are rendered as evidence cards by the
same compressor the device uses (semantic_compression.rendered_cards, behaviour-only, 512-token budget).

Only the DEV split (sha256(name) % 3 == 0) is used; the IoT-23 test split stays untouched for P2.
Labels come from IoT-23's own flow labels. A window with malicious flows gets the primary incident's family,
the card ids of the incident's source as evidence, and its alias as an entity. A benign window gets
benign / insufficient_evidence.

Usage: python3 -I gen_t0_iot23.py <iot23 dir> --n 600 --out t0_iot23.jsonl [--seed 3]
"""
import argparse
import collections
import glob
import hashlib
import json
import os
import random
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import replay_iot23 as rp  # noqa: E402
import semantic_compression as sc  # noqa: E402

MENTION = {
    "scan": (["scan", "port"], ["scan", "scanare", "porturi"]),
    "heartbeat": (["periodic", "beacon", "heartbeat", "command"], ["periodic", "comandă", "control", "beacon"]),
    "c2": (["command", "control", "c2", "beacon", "periodic"], ["comandă", "control", "c2", "periodic"]),
    "flood": (["flood", "ddos", "traffic", "volume"], ["inundare", "ddos", "trafic", "volum"]),
    "download": (["download", "malware", "file"], ["descărc", "malware", "fișier"]),
    "malware": (["malware", "infect", "bot", "suspicious"], ["malware", "infect", "bot", "suspect"]),
    "other": (["suspicious", "malicious"], ["suspect", "malițios"]),
}
Q_EN = ["Assess this window.", "What is happening on this network?", "Explain what this device is doing.",
        "Summarise the evidence for the owner."]
Q_RO = ["Evaluează această fereastră și explică pe scurt, în română.", "Ce se întâmplă în rețea? Răspunde în română.",
        "Rezumă dovezile pentru proprietar, în română."]


def norm(s):
    return " ".join(s.split()).lower()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("root")
    ap.add_argument("--n", type=int, default=600)
    ap.add_argument("--seed", type=int, default=3)
    ap.add_argument("--out", required=True)
    a = ap.parse_args()
    here = os.path.dirname(os.path.abspath(__file__))
    banned = set()
    for f in ("eval/cases.jsonl", "eval/blind/blind_cases.jsonl"):
        for l in open(os.path.join(here, f), encoding="utf-8"):
            if l.strip():
                banned.add(hashlib.sha256(norm(json.loads(l)["context"]).encode()).hexdigest())
    tok = sc.Tok()
    r = random.Random(a.seed)
    windows = []
    for p in sorted(glob.glob(os.path.join(a.root, "**", "conn.log.labeled"), recursive=True)):
        name = p.split(os.sep)[-3]
        if rp.split_of(name) != "dev":
            continue
        rows = rp.read_conn(p, 1_500_000)
        if not rows:
            continue
        rows.sort(key=lambda x: x[0])
        t0 = rows[0][0]
        buckets = collections.defaultdict(list)
        for x in rows:
            buckets[int((x[0] - t0) // 3600)].append(x)
        for k, win in buckets.items():
            windows.append((name, k, t0, win))
    r.shuffle(windows)
    out, seen = [], set()
    for name, k, t0, win in windows:
        if len(out) >= a.n:
            break
        events = rp.to_events(win, t0 + k * 3600)
        lines, _ = sc.rendered_cards(events, {"pairs": set(), "suffixes": set()}, 512, tok)
        if not lines:
            continue
        ctx = "\n".join(lines)
        h = hashlib.sha256(norm(ctx).encode()).hexdigest()
        if h in banned or h in seen:
            continue
        seen.add(h)
        exp = rp.expand(lines)
        legend = {}
        for l in lines:
            for al, v in re.findall(r"\b([HRD]\d+)=([0-9A-Za-z.\-:]+)", l):
                legend[v.rstrip("-")] = al  # "H1=1.2.3.4->R1" captures "1.2.3.4-": drop the arrow's dash
        inc = collections.Counter()
        for x in win:
            if x[8].lower().startswith("malicious"):
                inc[(x[1], rp.family(x[9]))] += 1
        ro = r.random() < 0.3
        if inc:
            (src, fam), _ = inc.most_common(1)[0]
            ev = [m.group(1) for l in exp for m in [re.match(r"^(F\d+) (\S+?)(->| dns )", l)] if m and m.group(2) == src]
            if not ev or src not in legend:
                continue  # the incident's source did not make it into the window: not a usable label
            gold = {"verdict": ["malicious", "suspicious"], "evidence": ev[:3], "entities": [legend[src]],
                    "must_mention_any": MENTION.get(fam, MENTION["other"])[1 if ro else 0],
                    "next_step": ["investigate", "isolate_review", "observe"]}
            fam_tag = "iot23-" + fam
        else:
            gold = {"verdict": ["benign", "insufficient_evidence"], "evidence": [], "entities": [],
                    "must_mention_any": (["normal", "obișnuit", "benign", "nu", "insuficient"] if ro else
                                         ["normal", "benign", "no ", "routine", "expected", "insufficient"]),
                    "next_step": ["observe"]}
            fam_tag = "iot23-benign"
        out.append({"id": "t0i-%05d" % len(out), "lang": "ro" if ro else "en", "task": "triage", "context": ctx,
                    "question": r.choice(Q_RO if ro else Q_EN), "gold": gold, "family": fam_tag, "source": name})
    with open(a.out, "w", encoding="utf-8") as f:
        for c in out:
            f.write(json.dumps(c, ensure_ascii=False) + "\n")
    print("wrote %d IoT-23 dev-split windows: %s" % (len(out), dict(collections.Counter(c["family"] for c in out))))


if __name__ == "__main__":
    main()
