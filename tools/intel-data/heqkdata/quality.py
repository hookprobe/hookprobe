# SPDX-License-Identifier: AGPL-3.0-only
"""Data-quality report for a build: everything a reviewer needs to decide whether an export is fit to
train on. Numbers are computed, never estimated. Label ACCURACY cannot be computed from the data itself;
the report states the label-quality grade each source was given and the share of human-verified examples.
"""
import collections

from . import dga_ref


def report(examples, normalized_counts=None, excluded=None, contamination=None, stats=None):
    by = collections.defaultdict(lambda: collections.Counter())
    split_label = collections.defaultdict(collections.Counter)
    missing = collections.Counter()
    sources, licences = collections.Counter(), collections.Counter()
    years = collections.Counter()
    gt_types, quality = collections.Counter(), collections.Counter()
    verified = synthetic = 0
    prov_ok = lic_ok = 0
    for e in examples:
        c = e["collection"]
        by[c]["examples"] += 1
        by[c][f"label:{e['target']['label']}"] += 1
        split_label[(c, e["split"]["name"])][e["target"]["label"]] += 1
        for s in e["provenance"]["source_ids"]:
            sources[s] += 1
        for lic in e["provenance"]["license_ids"]:
            licences[lic] += 1
        gt_types[e["ground_truth"]["type"]] += 1
        quality[e["ground_truth"]["label_quality"]] += 1
        verified += e["ground_truth"]["verified"]
        synthetic += e["ground_truth"]["type"] == "synthetic"
        recs = e["input"]["records"]
        if all(r["provenance"]["acquisition_id"] and r["provenance"]["license_id"] for r in recs):
            prov_ok += 1
        if e["provenance"]["license_ids"]:
            lic_ok += 1
        for r in recs:
            if r["observed_at"]:
                years[r["observed_at"][:4]] += 1
            else:
                missing["record.observed_at"] += 1
            for k, v in r["body"].items():
                if v is None:
                    missing[f"{r['kind']}.{k}"] += 1
        for k in ("confidence", "severity", "reasoning", "recommended_action"):
            if e["target"][k] is None:
                missing[f"target.{k}"] += 1
    n = len(examples) or 1
    imbalance = {}
    for c, cnt in by.items():
        labs = {k[6:]: v for k, v in cnt.items() if k.startswith("label:")}
        if len(labs) > 1:
            imbalance[c] = round(max(labs.values()) / max(1, min(labs.values())), 2)
    return {
        "examples": len(examples),
        "by_collection": {c: dict(v) for c, v in sorted(by.items())},
        "by_split_and_label": {f"{c}/{s}": dict(v) for (c, s), v in sorted(split_label.items(), key=str)},
        "class_imbalance_ratio": imbalance,
        "source_diversity": {"sources": len(sources), "examples_per_source": dict(sources.most_common())},
        "licences": dict(licences),
        "ground_truth_types": dict(gt_types),
        "label_quality_grades": dict(quality),
        "human_verified_share": round(verified / n, 4),
        "synthetic_share": round(synthetic / n, 4),
        "provenance_completeness": round(prov_ok / n, 4),
        "licence_completeness": round(lic_ok / n, 4),
        "temporal_coverage_by_year": dict(sorted(years.items())),
        "missing_fields": dict(missing.most_common(25)),
        "normalized_counts": normalized_counts or {},
        "excluded": excluded or {},
        "contamination_problems": contamination or [],
        "build_stats": stats or {},
    }


def dga_benchmark(examples):
    """Tier-A baseline: heqk's shipped dga.rs scorer (bit-exact port) on the DNS collection's test split.
    Reports per-source FP and TP rates. Feed-listed hosts are mostly NOT DGA names (compromised sites,
    phishing kits), so low recall on them is expected and is not a scorer defect by itself."""
    res = collections.defaultdict(lambda: {"n": 0, "flagged": 0, "examples_flagged": []})
    for e in examples:
        if e["collection"] != "dns_intelligence" or e["split"]["name"] != "test":
            continue
        r = e["input"]["records"][0]
        q = r["body"]["qname"]
        key = f"{e['target']['label']}@{r['provenance']['source_id']}"
        res[key]["n"] += 1
        if dga_ref.detects(q):
            res[key]["flagged"] += 1
            if len(res[key]["examples_flagged"]) < 10:
                res[key]["examples_flagged"].append(q)
    out = {}
    for k, v in sorted(res.items()):
        v["rate"] = round(v["flagged"] / v["n"], 4) if v["n"] else None
        out[k] = v
    return out


def markdown(rep, bench=None, title="Data quality report"):
    L = [f"# {title}", "", f"Examples: **{rep['examples']}**. Human-verified share: {rep['human_verified_share']}. "
         f"Synthetic share: {rep['synthetic_share']}. Provenance completeness: {rep['provenance_completeness']}. "
         f"Licence completeness: {rep['licence_completeness']}.", ""]
    L += ["## By collection and split", "", "| collection/split | labels |", "|---|---|"]
    for k, v in rep["by_split_and_label"].items():
        L.append(f"| {k} | {', '.join(f'{a}: {b}' for a, b in sorted(v.items(), key=str))} |")
    L += ["", "## Sources and licences", "", "| source | examples |", "|---|---|"]
    L += [f"| {s} | {n} |" for s, n in rep["source_diversity"]["examples_per_source"].items()]
    L += ["", "Licences: " + ", ".join(f"{k} ({v})" for k, v in rep["licences"].items()), ""]
    L += ["## Labels", "", "Ground-truth types: " + ", ".join(f"{k} {v}" for k, v in rep["ground_truth_types"].items()),
          "", "Label-quality grades: " + ", ".join(f"{k} {v}" for k, v in rep["label_quality_grades"].items()), "",
          "Class imbalance (max/min label count): " + (", ".join(f"{k} {v}" for k, v in rep["class_imbalance_ratio"].items()) or "n/a"), ""]
    L += ["## Exclusions and contamination", ""]
    L += [f"- excluded {k}: {v}" for k, v in rep["excluded"].items()] or ["- none"]
    L += [f"- build: {k} = {v}" for k, v in rep["build_stats"].items()]
    L += ["", f"Contamination problems: **{len(rep['contamination_problems'])}**", ""]
    L += [f"- {p}" for p in rep["contamination_problems"][:20]]
    L += ["", "## Missing fields (top)", "", "| field | null count |", "|---|---|"]
    L += [f"| {k} | {v} |" for k, v in rep["missing_fields"].items()]
    L += ["", "## Temporal coverage (records by year)", "", ", ".join(f"{y}: {n}" for y, n in rep["temporal_coverage_by_year"].items()) or "n/a"]
    if bench:
        L += ["", "## Tier-A baseline: heqk dga.rs on the DNS test split", "",
              "| label@source | n | flagged (score ≥ 600) | rate |", "|---|---|---|---|"]
        L += [f"| {k} | {v['n']} | {v['flagged']} | {v['rate']} |" for k, v in bench.items()]
        fp = [(k, v) for k, v in bench.items() if k.startswith("benign@")]
        for k, v in fp:
            if v["examples_flagged"]:
                L += ["", f"Benign names flagged ({k}): " + ", ".join(f"`{x}`" for x in v["examples_flagged"])]
    return "\n".join(L) + "\n"
