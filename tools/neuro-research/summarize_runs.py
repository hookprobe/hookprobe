#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Summarise eval_models.sh runs: quality per model and mode, token counts per incident, and a
PROJECTED CM5 time per incident / incidents-per-minute capacity.

Quality and token counts are hardware-independent (same weights, same prompts). The CM5 times are a
PROJECTION, never a measurement:
  decode tok/s  = 11.8 GB/s (Arm LP Pi 5 measured bandwidth) / model file bytes        (E-RF1 method)
  prefill tok/s = 290 tok/s x (0.494 B / params B)   (Arm LP: Qwen2.5-0.5B Q4_0 pp512, 4 threads, Pi 5)
The decode projection under-predicted published Pi 5 decode by 11-21% (E-RF1 calibration) -> conservative.

Usage: python3 -I summarize_runs.py <run dir> [--models-dir DIR] [--markdown]
"""
import argparse
import collections
import glob
import json
import os
import statistics
import sys

PARAMS_B = {"granite-4.0-h-350m": 0.34, "Qwen3-0.6B": 0.596, "Qwen3.5-0.8B": 0.8, "granite-4.0-h-1b": 1.5,
            "Qwen3-1.7B": 2.03, "Qwen3.5-2B": 2.0}
BW = 11.8e9
PP_REF = (290.0, 0.494)


def params_for(name):
    for k, v in PARAMS_B.items():
        if name.lower().startswith(k.lower()):
            return v
    return None


def load(path):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("run")
    ap.add_argument("--models-dir")
    ap.add_argument("--cases", help="re-score saved outputs with the CURRENT scorer (consistent across runs)")
    a = ap.parse_args()
    rows = []
    for p in sorted(glob.glob(os.path.join(a.run, "*-closed.json")) + glob.glob(os.path.join(a.run, "*-free.json"))):
        base = os.path.basename(p)[:-5]
        model, mode = base.rsplit("-", 1)
        res = load(p)
        if a.cases:
            sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "eval"))
            import run_eval  # noqa: E402
            cases = {c["id"]: c for c in (json.loads(l) for l in open(a.cases, encoding="utf-8") if l.strip())}
            for r in res:
                c = cases[r["id"]]
                sc_ = [run_eval.score(c, o) for o in r["outputs"]]
                first = sc_[0]
                if len(r["outputs"]) > 1 and c["task"] in ("triage", "injection"):
                    vs = [o.get("verdict") for o in r["outputs"]]
                    first["consistency"] = max(collections.Counter(vs).values()) / len(vs)
                r["score"] = first
        m = collections.defaultdict(list)
        pn, dn, lat, cn = [], [], [], []
        for r in res:
            for k, v in r["score"].items():
                key = ("inj_" + k) if r["task"] == "injection" else k
                m[key].append(float(v))
                if r["lang"] == "ro" and k in ("verdict_ok", "lang_ok"):
                    m["ro_" + k].append(float(v))
            o = r["outputs"][0]
            if "_error" in o:
                m["errors"].append(1.0)
            t = o.get("_timings") or {}
            if r["task"] in ("triage", "injection") and t.get("prompt_n") is not None:
                pn.append(t["prompt_n"])            # tokens actually prefilled (prefix cache warm)
                cn.append(t.get("cache_n") or 0)    # tokens reused from the cached system-prompt prefix
                dn.append(t.get("predicted_n", 0))
                lat.append(o.get("_latency_s", 0))
        rows.append((model, mode, m, pn, dn, lat, cn))
    print("| model | mode | verdict | citation | halluc. entities/case | injection canary safe | injection verdict | explanation mention | RO verdict | RO language | insufficient-evidence calibrated | tool | copilot facts | errors |")
    print("|---|---|---|---|---|---|---|---|---|---|---|---|---|---|")
    g = lambda m, k: ("%.2f" % statistics.mean(m[k])) if m.get(k) else "-"
    for model, mode, m, *_ in rows:
        cop = m.get("mention_ok")
        print("| %s | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s | %d |" % (
            model, mode, g(m, "verdict_ok"), g(m, "citation_ok"), g(m, "hallucinated_entities"), g(m, "inj_forbid_ok"),
            g(m, "inj_verdict_ok"), g(m, "mention_ok"), g(m, "ro_verdict_ok"), g(m, "ro_lang_ok"), g(m, "calibrated_ok"),
            g(m, "tool_ok"), "see json", len(m.get("errors", []))))
    if a.cases:
        # Architecture D in miniature: the DETERMINISTIC (L0) verdict, next_step, evidence and entities,
        # with the MODEL's natural-language summary. Scored with the same scorer on the same cases.
        sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "eval"))
        import run_eval  # noqa: E402
        cases = {c["id"]: c for c in (json.loads(l) for l in open(a.cases, encoding="utf-8") if l.strip())}
        print("\n| L0 verdict + model explanation (closed) | verdict | citation | halluc. | explanation mention | RO language | injection canary safe |")
        print("|---|---|---|---|---|---|---|")
        for p in sorted(glob.glob(os.path.join(a.run, "*-closed.json"))):
            model = os.path.basename(p)[:-len("-closed.json")]
            m = collections.defaultdict(list)
            for r in load(p):
                c = cases[r["id"]]
                if c["task"] not in ("triage", "injection"):
                    continue
                t = run_eval.template_backend(c)
                o = r["outputs"][0]
                hyb = dict(t, summary=o.get("summary", "") if isinstance(o.get("summary"), str) else "")
                sc_ = run_eval.score(c, hyb)
                for k, v in sc_.items():
                    m[k].append(float(v))
                if c["lang"] == "ro" and "lang_ok" in sc_:
                    m["ro_lang"].append(float(sc_["lang_ok"]))
                if c["task"] == "injection":
                    m["inj_forbid"].append(float(sc_["forbid_ok"]))
            print("| %s | %s | %s | %s | %s | %s | %s |" % (model, g(m, "verdict_ok"), g(m, "citation_ok"),
                  g(m, "hallucinated_entities"), g(m, "mention_ok"), g(m, "ro_lang"), g(m, "inj_forbid")))
        mt = collections.defaultdict(list)
        for c in cases.values():
            if c["task"] in ("triage", "injection"):
                for k, v in run_eval.score(c, run_eval.template_backend(c)).items():
                    mt[k].append(float(v))
        print("| (L0 template alone) | %s | %s | %s | %s | - | - |" % (g(mt, "verdict_ok"), g(mt, "citation_ok"),
              g(mt, "hallucinated_entities"), g(mt, "mention_ok")))
    print("\n| model | cached prefix tokens (median) | new prompt tokens / incident (median) | answer tokens / incident (median) | PROJECTED CM5 prefill tok/s | PROJECTED CM5 decode tok/s | PROJECTED s / incident | PROJECTED incidents / min (one stream) |")
    print("|---|---|---|---|---|---|---|---|")
    seen = set()
    for model, mode, m, pn, dn, lat, cn in rows:
        if mode != "closed" or model in seen or not pn:
            continue
        seen.add(model)
        pb = params_for(model)
        size = None
        if a.models_dir:
            f = os.path.join(a.models_dir, model + ".gguf")
            if os.path.exists(f):
                size = os.path.getsize(f)
        if not pb or not size:
            continue
        pp = PP_REF[0] * PP_REF[1] / pb
        tg = BW / size
        P, D = statistics.median(pn), statistics.median(dn)
        s = P / pp + D / tg
        print("| %s | %.0f | %.0f | %.0f | %.0f | %.1f | %.1f | %.1f |" % (model, statistics.median(cn), P, D, pp, tg, s, 60.0 / s))


if __name__ == "__main__":
    main()
