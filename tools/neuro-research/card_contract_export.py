#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Export the EVIDENCE-CARD contract as test vectors: the exact input and output of Neuro's card builder
(semantic_compression.rep_cards -> fill(..., 512) -> REST line) on the E2E attack fixture, so a device-side builder
mirror (the Conductor's neuro-contract) can drift-gate against it, as it does for the request contract and guards.

It runs e2e_neuro.py's `build` unchanged and records, per window, what `build` passes to `rep_cards` and what ends in
the card text. Nothing in the builder is re-implemented here.

Vector fields:
  events          the window's events exactly as passed to rep_cards. These are flow and DNS events with the
                  compressor state already mapped (S0/REJ -> rst, SF -> fin, other -> fin), plus for an S1 alert the
                  appended L1 detection event.
  baseline_pairs  the device baseline's (src, dst) pairs, as passed to rep_cards
  budget          512 (tokens)
  tokenizer       how fill counted tokens: "ESTIMATE (bytes/4)" unless NEURO_LLAMA_TOKENIZE/NEURO_VOCAB are set
  context         the final card text sent to the explainer (no svc= labels; e2e adds those only when asked)
Order rules the text follows: F<n> cards in builder order, then the REST line last. E2E has no CONTEXT lines (the
device knows no role/owner note yet). The generator's order, when they exist: F cards, CONTEXT lines, RESULT lines,
REST.

Usage: card_contract_export.py <out.json> <pcap> [<manifest.json>]     (E2E_MANIFEST is set from the 3rd argument)
"""
import hashlib, json, os, sys
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path[:0] = [HERE, os.path.join(HERE, "bench"), os.path.join(HERE, "eval")]


def main():
    out, pcap = sys.argv[1], sys.argv[2]
    if len(sys.argv) > 3:
        os.environ["E2E_MANIFEST"] = sys.argv[3]
    os.environ.pop("NEURO_SVC_LABELS", None)
    import semantic_compression as sc
    import e2e_neuro
    calls, real_rep, real_fill = [], sc.rep_cards, sc.fill

    def rep_cards(events, baseline, *a, **k):
        calls.append({"events": json.loads(json.dumps(events, default=str)),
                      "baseline_pairs": sorted([list(p) for p in baseline["pairs"]])})
        return real_rep(events, baseline, *a, **k)

    def fill(lines, budget, tok, residual=None):
        calls[-1]["budget"], calls[-1]["tokenizer"] = budget, tok.label()
        return real_fill(lines, budget, tok, residual)

    sc.rep_cards, sc.fill = rep_cards, fill
    import tempfile
    with tempfile.TemporaryDirectory() as d:
        import contextlib, io
        with contextlib.redirect_stdout(io.StringIO()):
            e2e_neuro.build(d, [pcap], 20, 7)
        cases = [json.loads(l) for l in open(os.path.join(d, "cases.jsonl"))]
        wins = json.load(open(os.path.join(d, "case_windows.json")))
    if len(cases) != len(calls):
        sys.exit("STOP: %d cases but %d builder calls" % (len(cases), len(calls)))
    vs = []
    for c, k in zip(cases, calls):
        vs.append(dict(id=c["id"], window=wins[c["id"]], alert=c["id"].startswith("alert"), **k, context=c["context"],
                       context_sha256=hashlib.sha256(c["context"].encode()).hexdigest()))
    src = {f: hashlib.sha256(open(os.path.join(HERE, f), "rb").read()).hexdigest()
           for f in ("semantic_compression.py", "e2e_neuro.py", "card_contract_export.py")}
    res = {"contract": "neuro evidence cards v1 (rep_cards + fill(512) + REST; E2E attack fixture)",
           "source_sha256": src, "pcap_sha256": hashlib.sha256(open(pcap, "rb").read()).hexdigest(),
           "sample": "e2e_neuro build: every S1 alert + 20 quiet windows (seed 7)",
           "vectors": vs}
    with open(out, "w", encoding="utf-8") as f:
        json.dump(res, f, ensure_ascii=False, separators=(",", ":")); f.write("\n")
    print("wrote %s: %d vectors (%d alerts, %d without a fact card)" % (
        out, len(vs), sum(v["alert"] for v in vs), sum(1 for v in vs if not v["context"].startswith(("F",)))))


if __name__ == "__main__":
    main()
