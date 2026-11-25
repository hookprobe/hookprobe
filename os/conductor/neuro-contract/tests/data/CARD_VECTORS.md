# Card vectors: how `card_vectors.rs` was made

`card_vectors.rs` holds the contexts Neuro's own functions produce for 120 generated windows (seed 20261125) and one
hand-built window:
- `tools/neuro-research/semantic_compression.py`: `rep_cards`, then `fill` with the estimate token counter
  (`Tok` without a real tokenizer, bytes / 4);
- the rule of `tools/neuro-research/e2e_neuro.py` that the `REST` line is appended when `fill` returned as many
  lines as there are cards and the last of them is not already a `REST` line (Neuro d65431e5c; before it, dropping
  exactly one card gave two `REST` lines).

`tests/cards.rs` checks `neuro_contract::cards::build_context` against them. Nothing in `os/conductor` runs Python:
the generator below ran once on the build host and is kept here as documentation only.

The windows are synthetic: RFC 1918 and RFC 5737 addresses (plus `172.15/172.32` and `100.64` to exercise the site
rule), flows and detections only. They are built to sit on the thresholds: 49, 50 and 51 hosts or ports, 7, 8 and 9
flows, mean gaps of 4.99, 5.00 and 5.01 s, 20 and 21 flows with half resets, byte totals on both sides of 100 MB
and on `%.1f` half-way values, pairs with 2 to 4 ports, detections of every severity with and without a
destination, repeated detection ids, and budgets from 24 to 512.

## What was checked beyond the committed file

On the Neuro host (2026-11-25), all equal byte for byte:
- 6,400 windows from the same generator without `small` (seeds 1, 2, 3 at 2,000 windows and the default seed at
  400), with scans of up to 700 hosts;
- Neuro's own `card_contract.json`: 22 windows of the E2E attack fixture (both S1 alerts, 20 quiet windows, 3 with
  no fact card). That file holds the fixture's real addresses and is not in the repository. Run it with
  `NEURO_CARD_CONTRACT=<path> cargo test -p neuro-contract --test cards`.

The first run of the 6,400 found one difference: a pair with a mean gap of exactly 5 s, where Python's float mean
is just under 5. The module now computes that mean as the double Python holds; see `src/cards.rs`. Neuro then
compared it rounded to ms (d65431e5c), and switched the 2-3 port match to `min(ports)` and the REST rule above.
The vectors were regenerated with that code on 2026-11-25: one of the 120 committed windows changed (a pair on
ports 23 and 2323, whose detection is now matched on 23), and the 6,400 extra windows (seeds 1, 2, 3 at 2,000 and
the default seed at 400, without `small`) are again equal byte for byte.

## To regenerate

1. Save the script below as `gen_card_vectors.py` outside the repository.
2. Run `python3 -I gen_card_vectors.py <repo root> <out.txt> 120 20261125 small`.
3. Put the lines into the `VECTORS` constant, followed by the hand-built window (kept at the end of the file).

For a larger local check, run it without `small` and with other seeds, and point `NEURO_CARD_VECTORS` at the
outputs (colon-separated).

```python
# Generates evidence-card vectors from Neuro's own functions (semantic_compression.rep_cards + fill, and the
# E2E rule that a context always ends with the REST line). Synthetic windows only: RFC 1918 / RFC 5737 addresses.
# Run: python3 -I gen_card_vectors.py <repo root> <out.txt> [n] [seed] [small]
# "small" keeps scans near the 50-host threshold, for a file small enough to commit.
# Line format: "V <budget> <context hex>", then "b <src> <dst>" baseline pairs, "f <t_ms> <src> <dst> <port> <bytes_out> <rst 0|1>"
# flows in event order, "d <id> <src> <dst or -> <port> <category> <mitre or -> <severity> <rule_msg hex>" detections.
import sys, os, random
root = sys.argv[1]
sys.path.insert(0, os.path.join(root, "tools/neuro-research"))
import semantic_compression as sc
N = int(sys.argv[3]) if len(sys.argv) > 3 else 400
r = random.Random(int(sys.argv[4]) if len(sys.argv) > 4 else 20261125)
SMALL = len(sys.argv) > 5
LAN = ["192.168.1.%d" % i for i in (10, 20, 30, 165)] + ["10.0.0.5", "172.16.4.9", "172.31.0.2"]
WAN = ["198.51.100.%d" % i for i in range(1, 9)] + ["203.0.113.7", "172.32.0.1", "172.15.9.9", "100.64.0.1"]
CATS = ["behaviour_change", "port_scan", "beaconing", "ioc_match", "brute_force", "exfiltration"]
MSGS = ["L1 behaviour model alert (alert, l1)", "ET SCAN probe (PASS, observe)", "plain rule without paren", "Nested (a) rule (DROP)", "x ()"]

def ts(ms):
    ms %= 86400000
    return "1970-01-01T%02d:%02d:%02d.%03dZ" % (ms // 3600000, ms // 60000 % 60, ms // 1000 % 60, ms % 1000)

def window():
    ev, t0 = [], r.randrange(0, 80000000)
    def flow(ms, s, d, p, out=None, rst=None):
        ev.append({"type": "flow", "ts": ts(t0 + ms), "src_ip": s, "dst_ip": d, "dst_port": p, "bytes_out": r.randrange(40, 5000) if out is None else out,
                   "bytes_in": r.randrange(0, 5000), "state": ("rst" if r.random() < 0.2 else r.choice(["fin", "est"])) if rst is None else ("rst" if rst else "fin")})
    for _ in range(r.choice([0, 1, 1, 2, 3, 5, 8])):
        kind = r.choice(["scan", "beacon", "bulk", "rst", "ports", "small", "small", "busy", "near5"])
        s = r.choice(LAN + WAN[:2]); d = r.choice(WAN + LAN)
        if kind == "scan":
            for p in r.sample([23, 2323, 22, 445, 80], r.choice([1, 1, 2])):
                for i in range(r.choice([49, 50, 51, 55] if SMALL else [49, 50, 51, 120, 500, 700])):
                    for _ in range(r.choice([1, 1, 2])):
                        flow(r.randrange(0, 3000000), s, "203.0.%d.%d" % (113 + i // 250, i % 250), p, rst=r.random() < 0.8)
        elif kind in ("beacon", "near5"):
            gap = r.choice([4990, 5000, 5010, 6000]) if kind == "near5" else r.choice([2000, 5000, 6000, 30000, 300000, 1024000])
            jit = r.choice([0, 0, 3, 50, gap // 10, gap // 4]); p = r.choice([443, 22, 8883])
            for i in range(r.choice([7, 8, 9, 30, 60])):
                flow(i * gap + (r.randrange(-jit, jit + 1) if jit else 0) + jit, s, d, p)
        elif kind == "bulk":
            tot = r.choice([99999999, 100000000, 150000000, 250000000, 949999999, 950000000, 1050000000, 3210000000]); k = r.choice([1, 3, 10])
            for i in range(k):
                flow(r.randrange(0, 3000000), s, d, 443, out=tot // k + (tot % k if i == 0 else 0))
        elif kind == "rst":
            n = r.choice([20, 21, 40]); m = r.choice([n // 2, n // 2 + 1, n])
            for i in range(n):
                flow(r.randrange(0, 3000000), s, d, 50184, rst=i < m)
        elif kind == "ports":
            ports = r.sample(range(1, 65536), r.choice([2, 3, 4, 49, 50, 51] if SMALL else [2, 3, 4, 49, 50, 60]))
            for p in ports:
                for _ in range(r.choice([1, 2])):
                    flow(r.randrange(0, 3000000), s, d, p)
        elif kind == "busy":
            for i in range(r.choice([29, 30, 31, 45])):
                flow(r.randrange(0, 3000000), s, d, r.choice([53, 5000, 8080][:r.choice([1, 2, 3])]))
        else:
            for i in range(r.randrange(1, 12)):
                flow(r.randrange(0, 3000000), s, d, r.choice([53, 123, 443, 8008]))
    if r.random() < 0.5:
        r.shuffle(ev)
    else:
        ev.sort(key=lambda e: e["ts"])
    pairs = list(dict.fromkeys((e["src_ip"], e["dst_ip"]) for e in ev))
    base = [p for p in pairs if r.random() < 0.5]
    for i in range(r.choice([0, 0, 1, 1, 2, 4])):
        f = r.choice(ev) if ev and r.random() < 0.8 else None
        ev.append({"type": "detection", "id": "det:%d" % (i if r.random() < 0.9 else 0), "ts": "", "rule_id": 1, "rule_msg": r.choice(MSGS),
                   "category": r.choice(CATS), "severity": r.choice([1, 2, 2, 3, 4, 5, 6]), "mitre": r.choice([None, "T1071", "T1046", ""]),
                   "src_ip": f["src_ip"] if f else r.choice(LAN), "dst_ip": (f["dst_ip"] if r.random() < 0.7 else "") if f else r.choice(WAN + [""]),
                   "dst_port": r.choice([0, 0, 53, f["dst_port"] if f else 443, 9999]), "confidence": 70})
    return ev, base

out = open(sys.argv[2], "w")
tok = sc.Tok()
assert tok.label() == "ESTIMATE (bytes/4)"
for _ in range(N):
    ev, base = window()
    budget = r.choice([512, 512, 512, 256, 128, 64, 24])
    cards, residual, _ = sc.rep_cards([dict(e) for e in ev], {"pairs": set(base), "suffixes": set()})
    lines, used = sc.fill(cards, budget, tok, residual)
    if len(lines) == len(cards) and not (lines and lines[-1].startswith("REST ")):
        lines = lines + [residual([])]
    out.write("V %d %s\n" % (budget, "\n".join(lines).encode().hex()))
    for s, d in base:
        out.write("b %s %s\n" % (s, d))
    for e in ev:
        if e["type"] == "flow":
            t = e["ts"]; ms = int(t[11:13]) * 3600000 + int(t[14:16]) * 60000 + int(t[17:19]) * 1000 + int(t[20:23])
            out.write("f %d %s %s %d %d %d\n" % (ms, e["src_ip"], e["dst_ip"], e["dst_port"], e["bytes_out"], e["state"] == "rst"))
        else:
            out.write("d %s %s %s %d %s %s %d %s\n" % (e["id"], e["src_ip"], e["dst_ip"] or "-", e["dst_port"], e["category"], e["mitre"] or "-", e["severity"], e["rule_msg"].encode().hex()))
```

The hand-built window: two pairs of 31 flows each and one severity-5 detection with a 150-character rule text, at
the smallest budget where `fill` drops exactly that one card.
