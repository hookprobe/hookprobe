#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Experiment E-SC1: semantic compression of a security-event window before any model sees it.

Question: can thousands of raw events be reduced to a few hundred tokens WITHOUT losing the facts an
analyst (or a model) needs?  Four representations are compared at several token budgets:

  RAW         the event rows as JSON lines, newest-last, truncated to the budget (what a naive
              "paste the logs into the prompt" pipeline does)
  DETECTIONS  only heqk's detection rows, de-duplicated (what the device already has, rulecat.rs)
  TOPK        groups by (type, src, dst, port), ranked by COUNT (frequency-only aggregation)
  CARDS       proposed: evidence cards -- per-entity behavioural aggregates (fan-out, periodicity,
              plus, when given, the temporal engine's per-device-hour deviations ("behaviour" events,
              docs/research/neuro/20) as evidence-only cards,
              volume, NXDOMAIN ratio, label entropy) merged with the detections that reference them,
              ranked by severity + novelty against a behavioural baseline, entity-interned (H1, R3
              aliases defined inline on first use), untrusted strings quoted and flagged, budget-filled, and the tail
              folded into one residual line so nothing is silently dropped

Two recalls are scored against the generator's ground truth:
  identity  the incident's source (and destination, if any) appear on ONE line with a signal for
            its kind (a category keyword or a derived behaviour flag)
  evidence  that line ALSO carries the explanatory magnitude (scan breadth, beacon period, exfil
            volume, NXDOMAIN burst) -- what turns "an alert" into "an explanation"

Token counts are REAL tokenizer counts when NEURO_LLAMA_TOKENIZE + NEURO_VOCAB point at
llama.cpp's `llama-tokenize` and a vocab-only GGUF; otherwise they are bytes/4 ESTIMATES and the
output says so.  Data is synthetic (synth_events.py): this measures the mechanism, not field efficacy.

Usage: python3 -I semantic_compression.py --seed 7 [--minutes 60 --benign-rate 40] [--json out.json]
"""
import argparse
import collections
import json
import math
import os
import re
import statistics
import subprocess
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import synth_events  # noqa: E402

BUDGETS = [128, 256, 512, 1024, 2048, 4096]
SEV_WEIGHT = {1: 8.0, 2: 6.0, 3: 3.0, 4: 1.0, 5: 0.2}


# --------------------------------------------------------------------------------------------
# token counting
class Tok:
    calls = 0

    def __init__(self):
        self.bin = os.environ.get("NEURO_LLAMA_TOKENIZE")
        self.vocab = os.environ.get("NEURO_VOCAB")
        self.real = bool(self.bin and self.vocab and os.path.exists(self.bin) and os.path.exists(self.vocab))
        self.cache = {}

    def label(self):
        return ("real (%s)" % os.path.basename(self.vocab)) if self.real else "ESTIMATE (bytes/4)"

    def count(self, text):
        if not text:
            return 0
        if text in self.cache:
            return self.cache[text]
        if not self.real:
            n = max(1, len(text.encode()) // 4)
        else:
            Tok.calls += 1
            with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as f:
                f.write(text)
                p = f.name
            try:
                out = subprocess.run([self.bin, "-m", self.vocab, "-f", p, "--ids", "--log-disable",
                                      "--no-bos"], capture_output=True, text=True, timeout=120).stdout
                ids = out.strip().splitlines()[-1] if out.strip() else "[]"
                n = len(json.loads(ids))
            finally:
                os.unlink(p)
        self.cache[text] = n
        return n

    def ratio(self, lines):
        """Tokens per byte for this kind of text, from ONE exact call on a sample (cached per sample)."""
        sample = "\n".join(lines[:600])
        if not sample:
            return 0.25
        return self.count(sample) / max(1, len(sample.encode()))



# Jitter-tolerant periodicity (Phase 0b): REJECTED on the IoT-23 dev split -- C&C evidence 0/7 -> 1/7,
# heartbeat 0/5 -> 0/5, flagged cards per benign window 1.3 -> 2.0. Off by default; set JITTER = 0.25 to
# reproduce. Real benign polling is far more regular than real C&C, so regularity alone is not the signal.
JITTER = 0.0              # a gap counts if within JITTER x (k x median gap), k = 1..3
PERIODIC_MIN_SHARE = 0.6  # ...and at least this share of gaps must count

def fill(lines, budget, tok, residual=None):
    """Select a prefix of `lines` that fits `budget` tokens when joined with newlines, and return the EXACT
    token count of the joined prompt text. Selection uses a per-kind tokens-per-byte ratio measured on the
    real tokenizer; the final text is then counted exactly and trimmed until it truly fits."""
    r = tok.ratio(lines)
    kept, est = [], 0.0
    for l in lines:
        c = len(l.encode()) * r + 1
        if est + c > budget:
            break
        kept.append(l)
        est += c

    def render(k):
        out = list(k)
        if residual is not None and len(k) < len(lines):
            out.append(residual(lines[len(k):]))
        return out

    out = render(kept)
    n = tok.count("\n".join(out))
    while n > budget and kept:
        kept.pop()
        out = render(kept)
        n = tok.count("\n".join(out))
    if n > budget:  # even the residual alone does not fit
        out, n = [], 0
    return out, n


# --------------------------------------------------------------------------------------------
# representations
def rep_raw(events):
    # newest-last: a budget truncation keeps the MOST RECENT rows (tail), as a rolling log would
    lines = [json.dumps(e, separators=(",", ":")) for e in events]
    return list(reversed(lines))  # filled newest-first, so truncation drops the oldest


def rep_detections(events):
    seen, out = set(), []
    for e in events:
        if e["type"] != "detection":
            continue
        k = (e["rule_id"], e["src_ip"], e["dst_ip"], e["dst_port"])
        if k in seen:
            continue
        seen.add(k)
        out.append("%s %s %s->%s:%s %s sev=%d" % (e["ts"][11:19], e["rule_msg"], e["src_ip"], e["dst_ip"] or "-",
                                                  e["dst_port"], e["mitre"] or "-", e["severity"]))
    out.sort(key=lambda l: int(l.rsplit("sev=", 1)[1]))
    return out


def rep_topk(events):
    g = collections.Counter()
    for e in events:
        if e["type"] == "flow":
            g[("flow", e["src_ip"], e["dst_ip"], e["dst_port"])] += 1
        elif e["type"] == "dns":
            g[("dns", e["src_ip"], e["qname"], "")] += 1
        else:
            g[("det:" + e["category"], e["src_ip"], e["dst_ip"], e["dst_port"])] += 1
    return ["%s %s->%s:%s n=%d" % (k[0], k[1], k[2], k[3], n) for k, n in g.most_common()]


def _suffix(q):
    parts = q.rstrip(".").split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else q


def _entropy(s):
    c = collections.Counter(s)
    n = len(s)
    return -sum(v / n * math.log2(v / n) for v in c.values()) if n else 0.0


INSTRUCTION_LIKE = re.compile(r"(ignore|disregard|previous|instruction|system prompt|classify|you are|assistant)",
                              re.I)


def quote_untrusted(s, cap=64):
    s = s[:cap] + ("~" if len(s) > cap else "")
    flag = " !instr-like" if INSTRUCTION_LIKE.search(s) else ""
    return json.dumps(s) + flag


class Interner:
    """Entity interning with INLINE first-use definitions: the first time an entity appears in the
    rendered (ranked) prompt it is written `H1=192.168.10.18`; every later mention is just `H1`.
    Digits cost one token each in common BPE vocabularies (a dotted quad is ~13 tokens), so a repeated
    entity saves ~11 tokens per repeat, and a single-use entity costs only ~3 extra tokens -- unlike a
    separate legend block, which restates every entity and loses at small budgets (measured, E-SC1).
    Aliases also give the decoder a CLOSED vocabulary of entities (see NEURO_INNOVATION_PROPOSALS: P2)."""

    PH = re.compile(r"\x01([HRD])\x02([^\x03]*)\x03")

    def __init__(self, on):
        self.on = on

    def __call__(self, ent, kind):
        return "\x01%s\x02%s\x03" % (kind, ent) if ent else "-"

    def materialize(self, lines):
        seen, counters, out = {}, collections.Counter(), []
        for l in lines:
            def sub(m):
                kind, ent = m.group(1), m.group(2)
                if not self.on:
                    return ent
                if ent in seen:
                    return seen[ent]
                counters[kind] += 1
                seen[ent] = "%s%d" % (kind, counters[kind])
                return "%s=%s" % (seen[ent], ent)
            out.append(self.PH.sub(sub, l))
        return out


def kind_of(ip):
    """H = an address inside the site (RFC 1918), R = remote. Never inferred from the event's direction."""
    if ip.startswith(("10.", "192.168.")) or re.match(r"172\.(1[6-9]|2\d|3[01])\.", ip):
        return "H"
    return "R"


def rep_cards(events, baseline, intern=True):
    flows = collections.defaultdict(list)          # (src,dst) -> [(t,port,out,in,state)]
    dns = collections.defaultdict(list)            # (src,suffix) -> [(t,qname,rcode,shield)]
    dets = collections.defaultdict(list)           # src -> [det]
    behav = []                                     # el0-neuro result records (doc 20): evidence, never alerts
    t_of = lambda ts: int(ts[11:13]) * 3600 + int(ts[14:16]) * 60 + float(ts[17:23])
    for e in events:
        if e["type"] == "behaviour":
            behav.append(e)
            continue
        if e["type"] == "flow":
            flows[(e["src_ip"], e["dst_ip"])].append((t_of(e["ts"]), e["dst_port"], e["bytes_out"], e["bytes_in"],
                                                      e["state"]))
        elif e["type"] == "dns":
            dns[(e["src_ip"], _suffix(e["qname"]))].append((t_of(e["ts"]), e["qname"], e["rcode"], e["shield"]))
        else:
            dets[e["src_ip"]].append(e)

    I = Interner(intern)
    cards = []  # (score, text)

    def det_note(src, dst, port):
        # a flow card claims only detections naming ITS destination; a DNS card (dst "") claims only
        # destination-less detections. (A looser match attached one DGA alert to every flow of the host.)
        hits = [d for d in dets.get(src, []) if d["dst_ip"] == dst]
        if port is not None:
            hits = [d for d in hits if d["dst_port"] in (0, port, 53)]
        if not hits:
            return "", 0.0, []
        best = min(hits, key=lambda d: d["severity"])
        w = SEV_WEIGHT.get(best["severity"], 1.0)
        return (" det=%s[%s,sev%d,%s]" % (best["category"], best["mitre"] or "-", best["severity"],
                                          best["rule_msg"].split("(")[-1].rstrip(")"))), w, hits

    used_dets = set()
    # horizontal fan-out: one source, one destination port, many destination HOSTS (Mirai-style scans,
    # worm propagation, floods spread over targets). Per-pair cards cannot see this pattern.
    by_sport = collections.defaultdict(set)
    fail_sport = collections.Counter()
    tot_sport = collections.Counter()
    for (src, dst), rows in flows.items():
        for r in rows:
            by_sport[(src, r[1])].add(dst)
            tot_sport[(src, r[1])] += 1
            fail_sport[(src, r[1])] += r[4] == "rst"
    fanned = set()
    for (src, port), dsts in by_sport.items():
        if len(dsts) >= 50:
            n = tot_sport[(src, port)]
            fail = 100 * fail_sport[(src, port)] // max(1, n)
            hits = [d for d in dets.get(src, []) if d["dst_port"] in (0, port)]
            note, dw = "", 0.0
            if hits:
                best = min(hits, key=lambda d: d["severity"])
                note = " det=%s[%s,sev%d,%s]" % (best["category"], best["mitre"] or "-", best["severity"],
                                                  best["rule_msg"].split("(")[-1].rstrip(")"))
                dw = SEV_WEIGHT.get(best["severity"], 1.0)
                for h in hits:
                    used_dets.add(h["id"])
            cards.append((4.0 + dw + min(3.0, len(dsts) / 500.0),
                          "%s->*:%d n=%d fanout_hosts=%d fail=%d%%%s" % (I(src, kind_of(src)), port, n, len(dsts), fail, note),
                          None))
            fanned.add((src, port))
    for (src, dst), rows in flows.items():
        if all((src, r[1]) in fanned for r in rows):
            cards.append((0.0, None, ("flow", src, dst, len(rows), sum(r[2] for r in rows))))
            continue
        rows.sort()
        n = len(rows)
        ports = {r[1] for r in rows}
        out_b = sum(r[2] for r in rows)
        flags, w = [], 0.0
        if len(ports) >= 50:
            flags.append("fanout_ports=%d" % len(ports))
            w += 4
        if n >= 8:
            gaps = [b[0] - a[0] for a, b in zip(rows, rows[1:])]
            mu = statistics.mean(gaps)
            med = statistics.median(gaps)
            if mu >= 5:  # beacons are seconds-to-hours apart; sub-5s regularity is a burst, not a beacon
                cv = statistics.pstdev(gaps) / mu
                if cv < 0.1:
                    flags.append("periodic=%ds cv=%.2f" % (round(mu), cv))
                    w += 3
            if JITTER and not any(f.startswith("periodic") for f in flags) and med >= 5:
                # jitter-tolerant (Phase 0b): most gaps near the median, or near a whole multiple of it
                # (a missed beat). Weaker evidence than the strict rule, so a lower weight.
                near = sum(1 for g in gaps if min(abs(g - k * med) for k in (1, 2, 3)) <= JITTER * med)
                if near >= PERIODIC_MIN_SHARE * len(gaps):
                    flags.append("periodic~%ds jit=%d%%" % (round(med), round(100 * JITTER)))
                    w += 1.5
        if out_b >= 100_000_000:
            flags.append("out=%.1fGB" % (out_b / 1e9))
            w += 4
        rst = sum(1 for r in rows if r[4] == "rst")
        if rst > n / 2 and n > 20:
            flags.append("rst=%d%%" % (100 * rst // n))
        novel = (src, dst) not in baseline["pairs"]
        note, dw, hits = det_note(src, dst, None if len(ports) > 3 else next(iter(ports)))
        for h in hits:
            used_dets.add(h["id"])
        w += dw + (1.0 if novel else 0.0)
        if not flags and not note and n < 30:
            # an ordinary, small, non-alerting pair: not a card, goes to the residual summary
            cards.append((0.0, None, ("flow", src, dst, n, out_b)))
            continue
        port_s = ("%d ports" % len(ports)) if len(ports) > 3 else ",".join(str(p) for p in sorted(ports))
        text = "%s->%s:%s n=%d %s%s%s" % (I(src, kind_of(src)), I(dst, kind_of(dst)), port_s, n,
                                          " ".join(flags), " novel" if novel else "", note)
        cards.append((w, text, None))

    for (src, suf), rows in dns.items():
        n = len(rows)
        nx = sum(1 for r in rows if r[2] == "NXDOMAIN")
        names = {r[1] for r in rows}
        ent = statistics.mean(_entropy(q.split(".")[0]) for q in names)
        flags, w = [], 0.0
        if n >= 20 and nx / n > 0.5:
            flags.append("nxdomain=%d/%d" % (nx, n))
            w += 3
        if len(names) >= 20 and ent > 3.3:
            flags.append("distinct=%d label_entropy=%.1f" % (len(names), ent))
            w += 2
        odd = [q for q in names if INSTRUCTION_LIKE.search(q)]
        if odd:
            flags.append("qname=%s" % quote_untrusted(odd[0]))
            w += 3.0  # instruction-like text in telemetry is itself a signal: someone is aiming at the AI
        novel = suf not in baseline["suffixes"]
        note, dw, hits = det_note(src, "", 53)
        if note and ("dns" not in note):
            note, dw = "", 0.0
        for h in hits:
            if h["category"].startswith("dns"):
                used_dets.add(h["id"])
        w += dw + (0.5 if novel else 0.0)
        if not flags and not note:
            cards.append((0.0, None, ("dns", src, suf, n, 0)))
            continue
        text = "%s dns %s n=%d %s%s%s" % (I(src, kind_of(src)), I(suf, "D"), n, " ".join(flags), " novel" if novel else "", note)
        cards.append((w, text, None))

    # temporal-engine deviations (docs/research/neuro/20): one card per deviating device-hour, worded as
    # evidence. The score ranks hours (AUC 0.995 on real traffic) but is NOT an alarm (D1: 72 benign
    # deviations per device-week), so it ranks below detections and never says "alert".
    for b in behav:
        sc = b["score_q8"] / 256.0
        if sc < 1.0:
            continue
        cards.append((1.0 + min(3.0, sc / 4.0),
                      "%s behaviour hour=%02d driver=%s score=%.1f (deviation from its own history; evidence, not an alert)" % (
                          I(b["src_ip"], kind_of(b["src_ip"])), b["hour"], b["driver"], sc), None))

    # detections that no aggregate claimed (e.g. a single IOC hit) are kept VERBATIM: rare + severe
    for src, ds in dets.items():
        for d in ds:
            if d["id"] in used_dets:
                continue
            used_dets.add(d["id"])
            w = SEV_WEIGHT.get(d["severity"], 1.0) + (2.0 if d["category"] == "ioc_match" else 0.0)
            text = "%s->%s:%s det=%s[%s,sev%d,%s]" % (I(src, kind_of(src)), I(d["dst_ip"], kind_of(d["dst_ip"])) if d["dst_ip"] else "-",
                                                      d["dst_port"], d["category"], d["mitre"] or "-", d["severity"],
                                                      d["rule_msg"].split("(")[-1].rstrip(")"))
            cards.append((w, text, None))

    ranked = [c for c in sorted(cards, key=lambda c: -c[0]) if c[1]]
    residual_items = [c[2] for c in cards if c[1] is None]
    lines = I.materialize(["F%d %s" % (i + 1, c[1]) for i, c in enumerate(ranked)])

    def residual(dropped_lines):
        nf = sum(1 for r in residual_items if r[0] == "flow")
        nd = sum(1 for r in residual_items if r[0] == "dns")
        cats = collections.Counter(m for l in dropped_lines for m in re.findall(r"det=(\w+)", l))
        dets_s = ("; omitted cards carry detections: " + ", ".join("%s x%d" % kv for kv in cats.most_common())) \
            if cats else "; omitted cards carry no detections"
        return "REST %d more cards omitted%s; plus %d ordinary flow pairs and %d ordinary dns groups with no detections" % (
            len(dropped_lines), dets_s, nf, nd)

    return lines, residual, I


def rendered_cards(events, baseline, budget, tok, intern=True):
    """Ranked, entity-interned cards, counted EXACTLY as one joined prompt (no separate legend)."""
    lines, residual, _ = rep_cards(events, baseline, intern)
    return fill(lines, budget, tok, residual)


# --------------------------------------------------------------------------------------------
# scoring
SIGNALS = {
    "port_scan": (["port_scan", "fanout_ports", "Port scan"], r"fanout_ports=(\d+)|(\d+) ports", 300),
    "brute_force": (["brute_force", "Brute force"], r"n=(\d+)", 100),
    "beaconing": (["beaconing", "periodic", "Beaconing"], r"periodic=(\d+)s", None),
    "dns_dga": (["dns_dga", "nxdomain", "DNS tunneling"], r"nxdomain=(\d+)", 100),
    "exfiltration": (["exfiltration", "out=", "Bulk exfiltration"], r"out=([\d.]+)GB", 0.5),
    "ioc_single": (["ioc_match", "Blocklisted"], None, None),
    "prompt_injection_carrier": (["!instr-like", "ignore-previous"], None, None),
}


def score(lines, truth):
    text_lines = lines
    legend = {}
    for l in lines:
        for a, v in re.findall(r"\b([HRD]\d+)=([0-9A-Za-z.\-]+)", l):
            legend[a] = v
    def expand(l):
        return re.sub(r"\b([HRD]\d+)\b", lambda m: legend.get(m.group(1), m.group(1)), l)
    exp = [expand(l) for l in text_lines]
    ident = evid = 0
    detail = []
    for t in truth:
        f = t["facts"]
        kws, mag_re, mag_min = SIGNALS[t["kind"]]
        need = [f["src_ip"]] + ([f["dst_ip"]] if f.get("dst_ip") else [])
        if t["kind"] == "dns_dga":
            need.append(f["domain_suffix"])
        hit_i = hit_e = False
        for l in exp:
            if all(x in l for x in need) and any(k in l for k in kws):
                hit_i = True
                if mag_re is None:
                    hit_e = True
                else:
                    m = re.search(mag_re, l)
                    if m:
                        v = float(next(g for g in m.groups() if g))
                        hit_e = (mag_min is None) or v >= mag_min
                        if t["kind"] == "beaconing":
                            hit_e = abs(v - f["period_s"]) <= 3
                if hit_e:
                    break
        ident += hit_i
        evid += hit_e
        detail.append((t["kind"], hit_i, hit_e))
    n = len(truth) or 1
    return ident / n, evid / n, detail


def baseline_from(seed, minutes, rate):
    """A benign-only window from an earlier period: the device's learned 'normal' (see behavioural_memory.py)."""
    w = synth_events.Window(seed + 10_000, minutes).build(rate, [])
    pairs = {(e["src_ip"], e["dst_ip"]) for e in w["events"] if e["type"] == "flow"}
    sufs = {_suffix(e["qname"]) for e in w["events"] if e["type"] == "dns"}
    return {"pairs": pairs, "suffixes": sufs}


def run(seed, minutes, rate, tok):
    w = synth_events.Window(seed, minutes).build(rate, synth_events.ALL_INCIDENTS)
    events = w["events"]
    for e in events:
        e.pop("_t", None)
    base = baseline_from(seed, minutes, rate)
    raw_all = rep_raw(events)
    full_raw_tokens = tok.count("\n".join(raw_all))
    res = {"seed": seed, "events": len(events), "incidents": len(w["truth"]), "raw_bytes":
           sum(len(l) + 1 for l in raw_all), "raw_tokens_full": full_raw_tokens, "rows": []}
    reps = {
        "RAW": lambda b: fill(raw_all, b, tok),
        "DETECTIONS": lambda b: fill(rep_detections(events), b, tok),
        "TOPK": lambda b: fill(rep_topk(events), b, tok),
        "CARDS": lambda b: rendered_cards(events, base, b, tok, True),
        "CARDS-noalias": lambda b: rendered_cards(events, base, b, tok, False),
    }
    for b in BUDGETS:
        for name, fn in reps.items():
            lines, used = fn(b)
            i, e, det = score(lines, w["truth"])
            res["rows"].append({"rep": name, "budget": b, "tokens": used, "identity_recall": round(i, 3),
                                "evidence_recall": round(e, 3), "detail": det})
    return res, w


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--seeds", default="1,2,3,4,5")
    ap.add_argument("--minutes", type=int, default=60)
    ap.add_argument("--benign-rate", type=int, default=40)
    ap.add_argument("--json")
    ap.add_argument("--show-cards", type=int, default=0, help="print the CARDS rendering at this budget for seed 1")
    a = ap.parse_args()
    tok = Tok()
    allres = []
    for s in [int(x) for x in a.seeds.split(",")]:
        r, w = run(s, a.minutes, a.benign_rate, tok)
        allres.append(r)
        if a.show_cards and s == int(a.seeds.split(",")[0]):
            evs = w["events"]
            lines, used = rendered_cards(evs, baseline_from(s, a.minutes, a.benign_rate), a.show_cards, tok)
            print("--- CARDS @ budget %d (%d tokens) seed %d ---" % (a.show_cards, used, s))
            print("\n".join(lines))
            print("---")
    # aggregate across seeds
    print("tokenizer: %s | synthetic windows: %d x %d min @ %d benign rows/min" % (
        tok.label(), len(allres), a.minutes, a.benign_rate))
    print("raw window: mean %d events, %.0f KB, full RAW tokens: %s" % (
        statistics.mean(r["events"] for r in allres), statistics.mean(r["raw_bytes"] for r in allres) / 1024,
        ", ".join(str(r["raw_tokens_full"]) for r in allres)))
    print("%-14s %6s %8s %10s %10s" % ("rep", "budget", "tokens", "identity", "evidence"))
    agg = collections.defaultdict(list)
    for r in allres:
        for row in r["rows"]:
            agg[(row["rep"], row["budget"])].append(row)
    for b in BUDGETS:
        for name in ["RAW", "DETECTIONS", "TOPK", "CARDS-noalias", "CARDS"]:
            rows = agg[(name, b)]
            print("%-14s %6d %8.0f %10.2f %10.2f" % (name, b, statistics.mean(x["tokens"] for x in rows),
                                                     statistics.mean(x["identity_recall"] for x in rows),
                                                     statistics.mean(x["evidence_recall"] for x in rows)))
    if a.json:
        with open(a.json, "w") as f:
            json.dump({"tokenizer": tok.label(), "runs": allres}, f, indent=1)


if __name__ == "__main__":
    main()
