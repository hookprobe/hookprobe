#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""heqk_data — HEQK Security Intelligence data foundation CLI.

  python3 -I heqk_data.py check                         registry + schema self-consistency
  python3 -I heqk_data.py sources [--class OPEN] [--collection dns_intelligence]
  python3 -I heqk_data.py gate <source_id> <purpose>    what the licence gate says, and why
  python3 -I heqk_data.py fetch <source_id> --purpose P  download a registry source (licence-gated)
  python3 -I heqk_data.py register <source_id> FILE --purpose P   add a manually obtained file
  python3 -I heqk_data.py normalize [<source_id>]       raw -> validated normalised records
  python3 -I heqk_data.py build --purpose P [--cap N] [--collections a,b]
  python3 -I heqk_data.py validate FILE.jsonl --schema training-example
  python3 -I heqk_data.py dga NAME [NAME ...]           score names with the heqk dga.rs reference

Purposes: commercial_training | evaluation | research | live_intel.
Data lives in $HEQK_INTEL_DATA (default ~/.cache/hookprobe-intel-data), never in the repository.
"""
import argparse
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from heqkdata import SCHEMA_IDS, dga_ref, licensing, normalize, registry, schema  # noqa: E402
from heqkdata import export as exportmod  # noqa: E402
from heqkdata.store import Store  # noqa: E402


def cmd_check(a):
    probs = schema.check_schema_files()
    reg = registry.Registry()
    probs += reg.check()
    for s in sorted(SCHEMA_IDS.values()):
        if not os.path.exists(os.path.join(schema.SCHEMA_DIR, s)):
            probs.append(f"missing schema file {s}")
    for p in probs:
        print("FAIL", p)
    by = {}
    for s in reg.sources.values():
        by[s["license_class"]] = by.get(s["license_class"], 0) + 1
    print(f"{len(reg.sources)} sources {by}, {len(reg.licenses)} licences, {len(reg.collections)} collections: "
          + ("OK" if not probs else f"{len(probs)} problem(s)"))
    return 1 if probs else 0


def cmd_sources(a):
    reg = registry.Registry()
    for s in sorted(reg.sources.values(), key=lambda x: (-x["priority"], x["id"])):
        if a.cls and s["license_class"] != a.cls:
            continue
        if a.collection and a.collection not in s["collections"]:
            continue
        auto = "auto" if s["acquisition"] else "-"
        print(f"{s['priority']} {s['license_class']:10} {auto:4} {s['id']:40} {s['name']}")
    return 0


def cmd_gate(a):
    reg = registry.Registry()
    ok, why = licensing.decide(reg.license_of(a.source), a.purpose)
    print(("ALLOW " if ok else "DENY  ") + why)
    return 0 if ok else 2


def cmd_fetch(a):
    import urllib.error
    st, reg = Store(), registry.Registry()
    try:
        acq = st.fetch(reg, a.source, a.purpose)
    except licensing.LicenseDenied as e:
        print(f"DENIED by licence gate: {e}", file=sys.stderr)
        return 2
    except (urllib.error.URLError, OSError, RuntimeError) as e:
        print(f"fetch failed for {a.source}: {e}", file=sys.stderr)
        return 3
    print(json.dumps({k: acq[k] for k in ("acquisition_id", "source_id", "bytes", "fetched_at")}))
    return 0


def cmd_register(a):
    st, reg = Store(), registry.Registry()
    acq = st.register(reg, a.source, a.file, a.purpose, a.url, a.sample_per_label)
    print(json.dumps({k: acq[k] for k in ("acquisition_id", "source_id", "bytes", "fetched_at")}))
    return 0


def cmd_normalize(a):
    st, reg = Store(), registry.Registry()
    rc = 0
    for acq in st.acquisitions(a.source):
        n, rej = normalize.normalize(st, reg, acq, a.adapter)
        print(f"{acq['source_id']} {acq['acquisition_id'][:12]}: {n} records, {len(rej)} rejects")
        for r in rej[:5]:
            print("   reject:", r["reason"])
    return rc


def cmd_build(a):
    st, reg = Store(), registry.Registry()
    cols = a.collections.split(",") if a.collections else None
    out, man, rep = exportmod.build(st, reg, a.purpose, collections=cols, cap_per_source=a.cap)
    print(f"built {man['dataset_version']} -> {out}")
    print(f"  examples {rep['examples']} {man['counts']}  excluded {man['excluded']}")
    print(f"  contamination problems: {len(rep['contamination_problems'])}")
    return 1 if rep["contamination_problems"] else 0


def cmd_validate(a):
    v = schema.default()
    name = SCHEMA_IDS.get(a.schema, a.schema)
    bad = 0
    with open(a.file, "r", encoding="utf-8") as f:
        for n, line in enumerate(f, 1):
            if not line.strip():
                continue
            errs = v.errors(json.loads(line), name)
            if errs:
                bad += 1
                if bad <= 10:
                    print(f"line {n}: " + "; ".join(errs[:3]))
    print(f"{a.file}: {'OK' if not bad else f'{bad} invalid line(s)'}")
    return 1 if bad else 0


def cmd_catalog(a):
    """Render the registry as the human catalogue (docs/research/intel-data/CATALOGUE.md)."""
    reg = registry.Registry()
    L = ["# HEQK intelligence source catalogue", "",
         "> GENERATED by `python3 -I tools/intel-data/heqk_data.py catalog` from `tools/intel-data/registry/`. Do not edit by hand.",
         "> Classes: OPEN = open licence granting commercial use + redistribution (training rights are listed separately);",
         "> RESEARCH = research/non-commercial; COMMERCIAL = paid licence; RESTRICTED = agreement/membership; UNKNOWN = not verified.",
         "> Gate columns are `licensing.decide()` for each purpose: ✅ allowed, — denied.", ""]
    by_cls = {}
    for s in reg.sources.values():
        by_cls[s["license_class"]] = by_cls.get(s["license_class"], 0) + 1
    L.append("Sources: " + ", ".join(f"{k} {v}" for k, v in sorted(by_cls.items())) + f" — total {len(reg.sources)}.")
    L.append("")
    cats = sorted({s["category"] for s in reg.sources.values()})
    for cat in cats:
        L += [f"## {cat}", "", "| id | name | org / country | class | train | eval | ship | access | P | verified |", "|---|---|---|---|---|---|---|---|---|---|"]
        for s in sorted((x for x in reg.sources.values() if x["category"] == cat), key=lambda x: (-x["priority"], x["id"])):
            lic = reg.licenses[s["license_id"]]
            g = lambda p: "✅" if licensing.decide(lic, p)[0] else "—"  # noqa: E731
            name = s["name"].replace("|", "/")
            L.append(f"| `{s['id']}` | [{name}]({s['source_url']}) | {s['organisation'].replace('|', '/')[:40]} / {s['country'] or '-'} | "
                     f"{s['license_class']} | {g('commercial_training')} | {g('evaluation')} | {g('live_intel')} | {s['access']} | "
                     f"{s['priority']} | {s['verification_status']} |")
        L.append("")
    L += ["## Licence decisions", "", "| licence | class | commercial | training | redistribution | share-alike | notes |", "|---|---|---|---|---|---|---|"]
    for lic in sorted(reg.licenses.values(), key=lambda x: x["id"]):
        L.append(f"| `{lic['id']}` | {lic['class']} | {lic['commercial_use']} | {lic['training_use']} | {lic['redistribution']} | "
                 f"{'yes' if lic['share_alike'] else 'no'} | {(lic['notes'] or '').replace('|', '/')[:160]} |")
    text = "\n".join(L) + "\n"
    if a.out:
        with open(a.out, "w", encoding="utf-8") as f:
            f.write(text)
    else:
        sys.stdout.write(text)
    return 0


def cmd_dga_eval(a):
    """Threshold sweep of the shipped dga.rs scorer over all labelled DNS records in the store."""
    from heqkdata import quality
    st, reg = Store(), registry.Registry()
    recs = (r for r in st.records() if licensing.decide(reg.licenses[r["provenance"]["license_id"]], "evaluation")[0])
    res = quality.dga_sweep(recs)
    if a.json:
        print(json.dumps(res, indent=1, sort_keys=True))
        return 0
    T = res["thresholds"]
    print(f"benign  n={res['benign']['n']:7d}  FP     " + "  ".join(f"@{t}={res['benign']['fp_rate'].get(str(t), 0):.4f}" for t in T))
    print(f"DGA     n={res['dga_all']['n']:7d}  recall " + "  ".join(f"@{t}={res['dga_all']['recall'].get(str(t), 0):.3f}" for t in T))
    for k, v in res["other_malicious"].items():
        print(f"{k[:20]:20} n={v['n']:7d} flagged " + "  ".join(f"@{t}={v['flag_rate'].get(str(t), 0):.3f}" for t in T))
    print(f"families with zero recall at {dga_ref.DGA_THRESHOLD}: {res['families_zero_recall_at_device_threshold']} of {len(res['families'])}")
    for k, v in sorted(res["families"].items(), key=lambda kv: kv[1]["recall"].get(str(dga_ref.DGA_THRESHOLD), 0)):
        print(f"  {k:18} n={v['n']:5d} " + "  ".join(f"@{t}={v['recall'].get(str(t), 0):.2f}" for t in T))
    return 0


def cmd_dga(a):
    for n in a.names:
        s = dga_ref.score(n)
        print(f"{s:5d} {'DETECT' if s >= dga_ref.DGA_THRESHOLD else 'pass  '} {n}")
    return 0


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("check").set_defaults(fn=cmd_check)
    s = sub.add_parser("sources")
    s.add_argument("--class", dest="cls")
    s.add_argument("--collection")
    s.set_defaults(fn=cmd_sources)
    s = sub.add_parser("gate")
    s.add_argument("source")
    s.add_argument("purpose", choices=licensing.PURPOSES)
    s.set_defaults(fn=cmd_gate)
    s = sub.add_parser("fetch")
    s.add_argument("source")
    s.add_argument("--purpose", required=True, choices=licensing.PURPOSES)
    s.set_defaults(fn=cmd_fetch)
    s = sub.add_parser("register")
    s.add_argument("source")
    s.add_argument("file")
    s.add_argument("--purpose", required=True, choices=licensing.PURPOSES)
    s.add_argument("--url")
    s.add_argument("--sample-per-label", type=int, metavar="N",
                   help="Zeek conn logs: keep at most N lines per (label, detailed-label); records the original's hash")
    s.set_defaults(fn=cmd_register)
    s = sub.add_parser("normalize")
    s.add_argument("source", nargs="?")
    s.add_argument("--adapter")
    s.set_defaults(fn=cmd_normalize)
    s = sub.add_parser("build")
    s.add_argument("--purpose", required=True, choices=licensing.PURPOSES)
    s.add_argument("--cap", type=int, default=None, help="max records per source per collection (deterministic sample)")
    s.add_argument("--collections")
    s.set_defaults(fn=cmd_build)
    s = sub.add_parser("validate")
    s.add_argument("file")
    s.add_argument("--schema", default="training-example")
    s.set_defaults(fn=cmd_validate)
    s = sub.add_parser("catalog")
    s.add_argument("--out")
    s.set_defaults(fn=cmd_catalog)
    s = sub.add_parser("dga-eval")
    s.add_argument("--json", action="store_true")
    s.set_defaults(fn=cmd_dga_eval)
    s = sub.add_parser("dga")
    s.add_argument("names", nargs="+")
    s.set_defaults(fn=cmd_dga)
    a = p.parse_args(argv)
    return a.fn(a)


if __name__ == "__main__":
    sys.exit(main())
