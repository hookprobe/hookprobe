#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Evidence-card contract vectors on SYNTHETIC windows, for the device card builder that now runs in the
Conductor's harness (doc 53 R12, operator decision 2026-11-28). They cover what the E2E fixture vectors
(card_contract_export.py) do not: DNS events, named detections (verbatim cards included) and "behaviour" records
(the el0-neuro result, doc 20). Synthetic addresses only (RFC 1918 / RFC 5737, .test/.example names), so the file can
live in the repository.

Per window: events (synth_events, all incidents, plus behaviour records drawn here), the baseline (pairs AND
suffixes), and for each budget the card text that the device path produces: rep_cards -> fill(budget, bytes/4
estimate) -> the E2E REST rule (append residual([]) iff nothing was dropped and the last line is not already a REST
line; e2e_neuro.py after #1618).

Usage: card_contract_synth.py <out.json> [--windows 16]
"""
import hashlib, json, os, random, re, sys
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
os.environ.pop("NEURO_LLAMA_TOKENIZE", None); os.environ.pop("NEURO_VOCAB", None)
import semantic_compression as sc  # noqa: E402
import synth_events  # noqa: E402

BUDGETS = [64, 128, 256, 512]
DRIVERS = ["volume", "fan-out", "novel-peers", "dns", "activity"]   # hal::neuroabi::DRIVERS
OK_IP = re.compile(r"^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|192\.0\.2\.|198\.51\.100\.|203\.0\.113\.)")


def window(i):
    r = random.Random(5300 + i)
    w = synth_events.Window(5300 + i, r.choice([10, 20, 30])).build(r.choice([2, 4, 8]), synth_events.ALL_INCIDENTS)
    ev = [{k: v for k, v in e.items() if k != "_t"} for e in w["events"]]
    hosts = sorted({e["src_ip"] for e in ev if e.get("src_ip", "").startswith(("10.", "192.168.", "172."))})
    for _ in range(r.choice([0, 1, 2, 3])):          # el0-neuro result records; some below 1.0 (must be skipped)
        ev.append({"type": "behaviour", "ts": ev[0]["ts"], "src_ip": r.choice(hosts), "hour": r.randrange(24),
                   "driver": r.choice(DRIVERS), "score_q8": r.choice([128, 255, 256, 300, 512, 777, 1024, 4000])})
    base = sc.baseline_from(5300 + i, 20, 4)
    return ev, base


def context(ev, base, budget, tok):
    cards, residual, _ = sc.rep_cards(ev, base)
    lines, _ = sc.fill(cards, budget, tok, residual)
    if len(lines) == len(cards) and not (lines and lines[-1].startswith("REST ")):
        lines = lines + [residual([])]
    return "\n".join(lines)


def main():
    out = sys.argv[1]
    n = int(sys.argv[sys.argv.index("--windows") + 1]) if "--windows" in sys.argv else 16
    tok = sc.Tok()
    assert tok.label() == "ESTIMATE (bytes/4)", tok.label()
    vs = []
    for i in range(n):
        ev, base = window(i)
        bad = [v for e in ev for k, v in e.items() if k.endswith("_ip") and v and not OK_IP.match(v)]
        if bad:
            sys.exit("STOP: non-synthetic address %s" % bad[0])
        ctx = {str(b): context(ev, base, b, tok) for b in BUDGETS}
        vs.append({"id": "synth-%02d" % i, "events": ev,
                   "baseline": {"pairs": sorted([list(p) for p in base["pairs"]]), "suffixes": sorted(base["suffixes"])},
                   "contexts": ctx})
    kinds = {}
    for v in vs:
        for c in v["contexts"].values():
            for l in c.splitlines():
                k = "behaviour" if " behaviour hour=" in l else "dns" if re.match(r"^[FDR]\d+ \S+ dns ", l) else \
                    "verbatim-det" if re.match(r"^[FD]\d+ \S+->\S+:\d+ det=", l) else l.split()[0][0]
                kinds[k] = kinds.get(k, 0) + 1
    src = {f: hashlib.sha256(open(os.path.join(HERE, f), "rb").read()).hexdigest()
           for f in ("semantic_compression.py", "synth_events.py", "card_contract_synth.py")}
    res = {"contract": "neuro evidence cards v1, synthetic windows (flows, dns, detections, behaviour)",
           "source_sha256": src, "budgets": BUDGETS, "tokenizer": tok.label(),
           "rest_rule": "append residual([]) iff len(lines) == len(cards) and the last line is not a REST line",
           "line_kinds": kinds, "vectors": vs}
    with open(out, "w", encoding="utf-8") as f:
        json.dump(res, f, ensure_ascii=False, separators=(",", ":")); f.write("\n")
    print("wrote %s: %d windows x %d budgets; line kinds %s; %d bytes" % (out, len(vs), len(BUDGETS), kinds, os.path.getsize(out)))


if __name__ == "__main__":
    main()
