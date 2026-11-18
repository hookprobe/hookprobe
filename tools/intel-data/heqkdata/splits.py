# SPDX-License-Identifier: AGPL-3.0-only
"""Leak-free splits and the contamination check.

group_hash   every example with the same group_key goes to the same split, chosen by
             sha256(seed, group_key) — stable across rebuilds and independent of record order.
time         groups ordered by their earliest observed_at; the latest groups form test, the ones before
             them dev (temporal-shift evaluation: train on the past, test on the future).
source_holdout  one named source is entirely test (distribution-shift evaluation).

check_contamination() fails a build when any content hash, group_key, or evidence record appears in
two different splits.
"""
from . import canon


def _frac(seed, key):
    return int(canon.sha256_obj([seed, key])[:12], 16) / float(1 << 48)


def assign(examples, fractions, strategy="group_hash", seed="heqk-v1", holdout_source=None):
    tr, dv = fractions["train"], fractions["dev"]
    if strategy == "group_hash":
        for e in examples:
            x = _frac(seed, e["split"]["group_key"])
            e["split"]["name"] = "train" if x < tr else ("dev" if x < tr + dv else "test")
            e["split"]["strategy"] = strategy
    elif strategy == "group_stratified":
        _stratified(examples, fractions, seed)
    elif strategy == "time":
        first = {}
        for e in examples:
            t = min((r["observed_at"] or "9999") for r in e["input"]["records"])
            g = e["split"]["group_key"]
            first[g] = min(first.get(g, "9999"), t)
        order = sorted(first, key=lambda g: (first[g], g))
        n = len(order)
        cut_tr, cut_dv = int(n * tr), int(n * (tr + dv))
        rank = {g: i for i, g in enumerate(order)}
        for e in examples:
            i = rank[e["split"]["group_key"]]
            e["split"]["name"] = "train" if i < cut_tr else ("dev" if i < cut_dv else "test")
            e["split"]["strategy"] = strategy
    elif strategy == "source_holdout":
        if not holdout_source:
            raise ValueError("source_holdout needs holdout_source")
        for e in examples:
            if holdout_source in e["provenance"]["source_ids"]:
                e["split"]["name"] = "test"
            else:
                x = _frac(seed, e["split"]["group_key"])
                e["split"]["name"] = "train" if x < tr / (tr + dv) else "dev"
            e["split"]["strategy"] = strategy
    else:
        raise ValueError(f"unknown split strategy {strategy!r}")
    return examples


FEW_GROUPS = 100


def _stratified(examples, fractions, seed):
    """Whole groups, label-balanced: groups (largest first, ties by hash) go to the split whose per-label
    targets they overshoot least. Deterministic. Used when a collection has too few groups for hashing to
    balance labels (IoT-23 has 23 scenarios; a hash split once put 7,824 benign vs 48 malicious in test)."""
    groups = {}
    for e in examples:
        groups.setdefault(e["split"]["group_key"], []).append(e)
    labels = sorted({str(e["target"]["label"]) for e in examples})
    total = {lab: sum(1 for e in examples if str(e["target"]["label"]) == lab) for lab in labels}
    names = ("train", "dev", "test")
    target = {s: {lab: fractions[s] * total[lab] for lab in labels} for s in names}
    have = {s: {lab: 0 for lab in labels} for s in names}
    order = sorted(groups, key=lambda g: (-len(groups[g]), _frac(seed, g)))
    for g in order:
        cnt = {lab: sum(1 for e in groups[g] if str(e["target"]["label"]) == lab) for lab in labels}

        def cost(s):
            c = 0.0
            for lab in labels:
                if target[s][lab] <= 0:
                    c += cnt[lab] * 10.0
                else:
                    c += max(0.0, have[s][lab] + cnt[lab] - target[s][lab]) / target[s][lab] - \
                        min(cnt[lab], max(0.0, target[s][lab] - have[s][lab])) / target[s][lab]
            return c

        best = min(names, key=lambda s: (cost(s), names.index(s)))
        for lab in labels:
            have[best][lab] += cnt[lab]
        for e in groups[g]:
            e["split"]["name"] = best
            e["split"]["strategy"] = "group_stratified"


def check_contamination(examples):
    """Problems (empty = clean): the same content / group / evidence record in more than one split."""
    seen = {"content": {}, "group": {}, "record": {}}
    problems = []
    for e in examples:
        s = e["split"]["name"]
        keys = [("content", e["content_sha256"]), ("group", f"{e['collection']}|{e['split']['group_key']}")]
        keys += [("record", r["record_id"]) for r in e["input"]["records"]]
        for kind, k in keys:
            prev = seen[kind].setdefault(k, s)
            if prev != s:
                problems.append(f"{kind} {k} in both {prev} and {s} (example {e['id']})")
    return problems


def dedupe(examples):
    """Drop exact duplicates (same content_sha256), keeping the first by id. Returns (kept, n_dropped)."""
    seen, kept = set(), []
    for e in sorted(examples, key=lambda x: x["id"]):
        if e["content_sha256"] in seen:
            continue
        seen.add(e["content_sha256"])
        kept.append(e)
    return kept, len(examples) - len(kept)
