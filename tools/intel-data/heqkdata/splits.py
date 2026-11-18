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
