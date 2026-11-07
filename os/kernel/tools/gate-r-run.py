#!/usr/bin/env python3
"""gate-r-run.py — unified Gate-R (M2 enforcement-separation matrix) readiness parser.

The 33-row matrix is DRIVEN two ways: frame-drivable rows by tools/gate-r-matrix.sh
(raw frames at a real DUT), and the non-frame-drivable rows by on-metal sepdiag
self-tests at sensor bring-up. Until now nothing produced ONE per-row PASS/FAIL
table + a single verdict line: gate-r-matrix.sh prints its `===ROW===` markers to
its OWN stdout (a different stream from the CM5 serial console where the device's
`[SEPDIAG] rule=N verdict=V` heartbeat drain and the boot `[SEPDIAG-*] => PASS`
self-tests appear), so the two were never correlated.

This tool closes that: give it a CM5 serial capture (a gate-r-matrix.sh metal run
AND/OR a sepdiag boot log) and it aggregates the `rule=N verdict=V` observations +
the `[SEPDIAG-*]` self-tests, maps them to the 33 rows, and emits a per-row table
plus one `GATE-R: PASS/INCOMPLETE` line. Pure host tooling — no board needed to
run it (test it against an archived ~/heqk-metal-logs capture).

Usage: gate-r-run.py <serial-capture.log> [more.log ...]
Verdict semantics: a LEGIT row (L*) is PASS if its rule is observed and NEVER
wire-drops that legit source; an ATTACKER row (A*) is PASS if its rule is observed
producing the expected DROP/RateLimit at least once; a FRAME row (F*) is PASS if
its structural rule DROPs/flags. sepdiag-selftest rows PASS on `[SEPDIAG-X] PASS`.
L5/L6 are OFF-DEVICE (ADR 0044 D3 NAC) and reported as such, not failed.
"""
import re
import sys

# row id -> (class, human, how-proven, detail)
#   how-proven: ("rule", rule_id, want)  want in {DROP, PASS, RATE}
#               ("sepdiag", TAG)         boot self-test [SEPDIAG-TAG] => PASS
#               ("offdev", note)         off-device, not a heqk datapath row
ROWS = {
    # --- legit (must PASS / never wire-drop the legit source) ---
    "L1":  ("legit", "mDNS/SSDP mcast burst -> no storm alert",     ("sepdiag", "STRUCT")),
    "L2":  ("legit", "busy uplink many MACs -> Observe",            ("sepdiag", "A1A2")),
    "L3":  ("legit", "ARP flip-flop -> Observe, never FrameDrop",   ("rule", 102, "PASS")),
    "L4":  ("legit", "downstream RA on uplink -> observed+accepted",("sepdiag", "RAGUARD")),
    "L5":  ("legit", "new device -> OnboardingGrace",               ("offdev", "NAC state machine (ADR 0044 D3)")),
    "L6":  ("legit", "stale device -> InternetOnly",                ("offdev", "NAC state machine (ADR 0044 D3)")),
    "L7":  ("legit", "CDN fan-out 100 conns:443 -> no scan alert",  ("rule", 113, "PASS")),
    "L8":  ("legit", "NTP beacon-shape :123 -> allowlisted",        ("rule", 116, "PASS")),
    "L9":  ("legit", "heavy legit src, low PSI -> no shed",         ("sepdiag", "SHED")),
    "L10": ("legit", "~100 new-conn/s under 400/s cap -> allow",    ("rule", 114, "PASS")),
    "L11": ("legit", "customer touches one IOC -> never quarantine",("rule", 302, "PASS")),
    # --- attacker (must reach the correct tri-state) ---
    "A1":  ("attacker", "access-port mac-flood >=20 -> RateLimit",  ("sepdiag", "A1A2")),
    "A2":  ("attacker", "uplink 300+-MAC flood -> Observe",         ("sepdiag", "A1A2")),
    "A3":  ("attacker", "non-exempt bcast flood -> RateLimit",      ("rule", 112, "DROP")),
    "A4":  ("attacker", "unconfirmed SYN scan -> RateLimit",        ("rule", 113, "DROP")),
    "A5":  ("attacker", "confirmed SYN scan -> Quarantine",         ("rule", 113, "DROP")),
    "A6":  ("attacker", "FIN/NULL/XMAS stealth scan -> observe/rate",("sepdiag", "SCAN")),
    "A7":  ("attacker", "conntrack saturation -> shed source",      ("sepdiag", "SHED")),
    "A8":  ("attacker", "sustained PSI top-talker -> shed",         ("sepdiag", "SHED")),
    "A9":  ("attacker", "rogue RA on access port -> FrameDrop",     ("sepdiag", "RAGUARD")),
    "A10": ("attacker", "lateral/C2 beacon -> detected, not enforced",("rule", 117, "PASS")),
    "A11": ("attacker", "corroborated IOC -> Observe + CRIT sev",   ("sepdiag", "CORR")),
    # --- frame-structural ---
    "F1":  ("frame", "iPhone 42B unpadded ARP -> not anomalous",    ("sepdiag", "STRUCT")),
    "F2":  ("frame", "bare 54B TCP ACK -> not anomalous",           ("sepdiag", "STRUCT")),
    "F3":  ("frame", "locally-admin unicast MAC -> no mcast trip",  ("sepdiag", "STRUCT")),
    "F4":  ("frame", "frame < eth header -> flagged",               ("sepdiag", "STRUCT")),
    "F5":  ("frame", "ARP truncated <42B -> flagged",               ("rule", 101, "DROP")),
    "F6":  ("frame", "mcast/bcast source MAC -> flagged",           ("rule", 110, "DROP")),
    "F7":  ("frame", "oversize >1522B -> flagged",                  ("sepdiag", "STRUCT")),
    "F8":  ("frame", "double-VLAN -> flagged",                      ("rule", 110, "DROP")),
    "F9":  ("frame", "malformed ARP header -> flagged",             ("rule", 101, "DROP")),
    "F10": ("frame", "ARP sender/eth-src mismatch -> flagged(obs)", ("rule", 102, "PASS")),
    "F11": ("frame", "FIN/NULL/XMAS shapes -> recognized",          ("rule", 201, "PASS")),
}

RULE_LINE = re.compile(r"rule=(\d+)\s+verdict=([A-Z]+)")
SEPDIAG = re.compile(r"\[SEPDIAG-([A-Z0-9]+)\].*?\b(PASS|FAIL)\b")


def parse(paths):
    # rule_id -> {verdict: count}
    rules = {}
    seldiag = {}  # TAG -> PASS/FAIL (last seen)
    for p in paths:
        try:
            data = open(p, "rb").read().decode("utf-8", "replace")
        except OSError as e:
            print(f"  ! cannot read {p}: {e}", file=sys.stderr)
            continue
        for m in RULE_LINE.finditer(data):
            rid, v = int(m.group(1)), m.group(2)
            rules.setdefault(rid, {}).setdefault(v, 0)
            rules[rid][v] += 1
        for m in SEPDIAG.finditer(data):
            seldiag[m.group(1)] = m.group(2)
    return rules, seldiag


# Rule ids an ATTACKER/FRAME row expects to DROP/RateLimit — a legit row that shares
# one of these cannot be verified from aggregate counts (the DROPs are the attacker
# sibling's; isolating the legit source needs a per-row ===ROW=== window).
def _shared_drop_rules():
    s = set()
    for klass, _human, how in ROWS.values():
        if how[0] == "rule" and how[2] in ("DROP", "RATE") and klass in ("attacker", "frame"):
            s.add(how[1])
    return s


def row_status(rid, how, rules, seldiag, shared):
    kind = how[0]
    if kind == "offdev":
        return "OFF-DEVICE", how[1]
    if kind == "sepdiag":
        tag = how[1]
        st = seldiag.get(tag)
        if st == "PASS":
            return "PASS", f"[SEPDIAG-{tag}] PASS"
        if st == "FAIL":
            return "FAIL", f"[SEPDIAG-{tag}] FAIL"
        return "MISSING", f"[SEPDIAG-{tag}] not in log"
    if kind == "rule":
        _, ruleid, want = how
        seen = rules.get(ruleid)
        if not seen:
            return "MISSING", f"rule {ruleid} not observed"
        drops = seen.get("DROP", 0) + seen.get("RATE", 0)
        passes = seen.get("PASS", 0)
        dist = " ".join(f"{v}x{c}" for v, c in sorted(seen.items()))
        if want in ("DROP", "RATE"):
            return ("PASS" if drops > 0 else "FAIL", f"rule {ruleid} [{dist}]")
        # want PASS (legit / observe-only): PASS iff observed and NOT wire-dropped.
        if passes > 0 and drops == 0:
            return "PASS", f"rule {ruleid} [{dist}]"
        # If the rule is one an attacker row drops, the DROPs here can't be
        # attributed to this legit source without a per-row window: indeterminate.
        if ruleid in shared:
            return "SHARED", f"rule {ruleid} [{dist}] (shared w/ attacker row; needs ===ROW=== window)"
        return "FAIL", f"rule {ruleid} [{dist}]"
    return "MISSING", "?"


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(2)
    rules, seldiag = parse(sys.argv[1:])
    shared = _shared_drop_rules()
    print(f"== Gate-R matrix readiness from {len(sys.argv)-1} log(s) ==")
    print(f"   observed rules: {', '.join(str(r) for r in sorted(rules))}")
    print(f"   sepdiag self-tests: {', '.join(f'{k}={v}' for k, v in sorted(seldiag.items())) or '(none)'}")
    print()
    counts = {"PASS": 0, "FAIL": 0, "MISSING": 0, "SHARED": 0, "OFF-DEVICE": 0}
    for rid in sorted(ROWS, key=lambda x: (x[0], int(x[1:]))):
        klass, human, how = ROWS[rid]
        st, why = row_status(rid, how, rules, seldiag, shared)
        counts[st] += 1
        print(f"  {rid:<4} {klass:<8} {st:<10} {human:<44} {why}")
    print()
    total = len(ROWS)
    owned = total - counts["OFF-DEVICE"]  # rows heqk-the-sensor owns
    proven = counts["PASS"]
    fails = counts["FAIL"]
    unproven = counts["MISSING"] + counts["SHARED"]
    print(f"  rows: {total} total | {counts['OFF-DEVICE']} off-device | {owned} heqk-owned")
    print(f"        {proven} PASS | {fails} FAIL | {counts['MISSING']} MISSING | {counts['SHARED']} SHARED-indeterminate")
    if fails == 0 and unproven == 0 and proven == owned:
        print(f"\nGATE-R: PASS ({proven}/{owned} heqk-owned rows proven; {counts['OFF-DEVICE']} off-device: L5/L6)")
        sys.exit(0)
    verdict = "FAIL" if fails else "INCOMPLETE"
    print(f"\nGATE-R: {verdict} ({proven}/{owned} proven, {fails} fail, {unproven} not observed in these logs)")
    sys.exit(1 if fails else 2)


if __name__ == "__main__":
    main()
