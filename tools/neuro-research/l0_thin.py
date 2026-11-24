#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Doc 40: a deterministic thin-evidence rule (L0) that decides `insufficient_evidence`; the explainer only words it.

Three data-mix attempts (docs 33, 36, 38) taught the student WHEN to hedge and each moved the same trade-off: more
thin acknowledgement, more hedging on real evidence. Here the decision leaves the model.

RULE T (fixed in doc 40). A window is THIN iff all hold:
  1. it has exactly one evidence card (an `F<n>` line);
  2. no quoted value anywhere in the context (attacker-controlled text is itself a signal; injections stay with the model);
  3. the card's count `n=` is at most 5 (absent counts as 0);
  4. the card carries no detection, OR its only detection was blocked on the wire (`DROP`).
When T fires: verdict = insufficient_evidence, severity low, next_step observe, confidence <= 40, and a fixed sentence
leads the summary. The model's own summary follows it, and its evidence and entities are kept.
When T does not fire, the model's answer is unchanged.

Usage (offline, on a run_eval JSON):  python3 -I l0_thin.py <cases.jsonl> <model run.json> <out run.json>
"""
import json, re, sys

LEAD = {"en": "Not enough evidence to conclude: a single weak signal with nothing corroborating it.",
        "ro": "Nu sunt suficiente dovezi pentru o concluzie: un singur semnal slab, necoroborat (insuficient)."}
CARD = re.compile(r"^F\d+ ", re.M)


def fires(context):
    cards = [l for l in context.splitlines() if CARD.match(l)]
    if len(cards) != 1 or '"' in context:
        return False
    c = cards[0]
    n = re.findall(r"\bn=(\d+)", c)
    if (int(n[0]) if n else 0) > 5:
        return False
    if "det=" not in c:
        return True
    dets = re.findall(r"det=\w+\[[^\]]*\]", c)
    return len(dets) == 1 and "DROP" in dets[0]


def compose(case, out):
    """The deployed behaviour: T decides; the model's answer is kept otherwise."""
    if case["task"] not in ("triage", "injection") or not fires(case["context"]):
        return out
    o = dict(out)
    o["verdict"], o["severity"], o["next_step"] = "insufficient_evidence", "low", "observe"
    o["confidence"] = min(int(o.get("confidence") or 40), 40)
    s = o.get("summary") if isinstance(o.get("summary"), str) else ""
    o["summary"] = (LEAD[case.get("lang", "en")] + " " + s).strip()
    o["_l0_thin"] = True
    return o


def main():
    cases = {c["id"]: c for c in (json.loads(l) for l in open(sys.argv[1], encoding="utf-8") if l.strip())}
    run = json.load(open(sys.argv[2]))
    rows = run["results"] if isinstance(run, dict) else run
    n = 0
    for r in rows:
        new = compose(cases[r["id"]], r["outputs"][0])
        n += new is not r["outputs"][0]
        r["outputs"] = [new] + r["outputs"][1:]
    json.dump(run, open(sys.argv[3], "w"), ensure_ascii=False)
    print("rule T fired on %d of %d answers" % (n, len(rows)))


if __name__ == "__main__":
    main()
