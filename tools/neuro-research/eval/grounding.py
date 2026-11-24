#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Grounding checks the alias-based hallucination score misses (E2E attack path, 2026-11-24): an explainer that
invents a technique id, or names a service the cards do not show, is wrong even when every alias it cites exists.

technique_check(answer, context) -> {"ids": [...], "unknown": [...], "stale": [...], "off_category": [...], "ok": bool}
  - every technique-looking token (T + digits, optionally .digits) in the answer must be a real ATT&CK id
    (data/attack-ids.json, built from intel-data's raw STIX). Malformed tokens ("T1", "T12") count as unknown;
  - stale = revoked or deprecated ids (reported, not failing);
  - off_category = real ids that fit none of the card's detection categories and are not cited on the cards
    (reported, not failing: an analyst may legitimately name a related technique);
  - ok = no unknown id.
service_check(answer_text, context) -> {"named": [...], "absent": [...], "ok": bool}
  - a service the answer names (SSH, Telnet, RDP, NTP, DNS, SMB, SMTP, HTTP/HTTPS, MQTT, SNMP, FTP, SSDP/UPnP)
    must have one of its ports on the cards; ok = none named without its port.
Both read only the answer's prose fields (summary, text), never the evidence ids.
Usage: grounding.py <cases.jsonl> <run_eval json>      (reports rates over triage/injection/copilot answers)
"""
import json, os, re, sys

HERE = os.path.dirname(os.path.abspath(__file__))
IDS_PATH = os.path.join(HERE, "..", "..", "..", "docs", "research", "neuro", "data", "attack-ids.json")
_IDS = {}
TECH = re.compile(r"(?<![A-Za-z0-9])T\d{1,5}(?:\.\d{1,3})?(?![A-Za-z0-9])")
CATEGORY = {"port_scan": {"T1046", "T1595"}, "brute_force": {"T1110"}, "beaconing": {"T1071", "T1573", "T1102", "T1008"},
            "exfiltration": {"T1048", "T1041", "T1567", "T1030"}, "dns_dga": {"T1568", "T1071"},
            "lateral_movement": {"T1021", "T1570", "T1210"}, "dns_bypass": {"T1572", "T1071"},
            "ioc_match": set(), "signature": set(), "behaviour_change": set(), "exfil_volume": {"T1048", "T1041"},
            "lateral_smb": {"T1021"}}
SERVICE = {"ssh": {22}, "telnet": {23, 2323}, "rdp": {3389}, "ntp": {123}, "dns": {53, 853}, "smb": {445, 139},
           "smtp": {25, 465, 587}, "http": {80, 8080, 8000}, "https": {443, 8443}, "mqtt": {1883, 8883}, "snmp": {161, 162},
           "ftp": {20, 21}, "ssdp": {1900}, "upnp": {1900}}


def ids():
    if not _IDS:
        _IDS.update(json.load(open(IDS_PATH))["ids"])
    return _IDS


def prose(answer):
    if isinstance(answer, str):
        return answer
    return " ".join(str(answer.get(k) or "") for k in ("summary", "text"))


def technique_check(answer, context):
    t = prose(answer)
    found = sorted(set(TECH.findall(t)))
    db = ids()
    unknown = [x for x in found if x not in db]
    stale = [x for x in found if x in db and (db[x]["revoked"] or db[x]["deprecated"])]
    cats = set(re.findall(r"det=(\w+)\[", context))
    on_cards = set(TECH.findall(context))
    allowed = set().union(*[CATEGORY.get(c, set()) for c in cats]) if cats else set()
    off = [x for x in found if x in db and cats and x.split(".")[0] not in allowed and x not in on_cards
           and x.split(".")[0] not in {y.split(".")[0] for y in on_cards}]
    return {"ids": found, "unknown": unknown, "stale": stale, "off_category": off, "ok": not unknown}


def ports_on_cards(context):
    ps = set()
    for m in re.finditer(r":((?:\d+,)*\d+)(?:-(\d+))?", context):
        if m.group(2):
            lo, hi = int(m.group(1).split(",")[-1]), int(m.group(2))
            if hi - lo < 70000:
                ps |= {p for p in range(lo, hi + 1)} if hi - lo < 2000 else {lo, hi}
        ps |= {int(x) for x in m.group(1).split(",")}
    return ps


def service_check(answer, context):
    t = prose(answer).lower()
    named = sorted({s for s in SERVICE if re.search(r"(?<![a-z])%s(?![a-z])" % s, t)})
    ps = ports_on_cards(context)
    ctx = context.lower()
    absent = [s for s in named if not (SERVICE[s] & ps) and not re.search(r"(?<![a-z])%s(?![a-z])" % s, ctx)
              and not (s == "dns" and " dns " in ctx)]
    return {"named": named, "absent": absent, "ok": not absent}


def main():
    cases = {json.loads(l)["id"]: json.loads(l) for l in open(sys.argv[1], encoding="utf-8") if l.strip()}
    run = json.load(open(sys.argv[2])); rows = run["results"] if isinstance(run, dict) else run
    n = tu = ts = so = sa = 0
    bad = []
    for r in rows:
        c = cases.get(r["id"])
        if not c or c["task"] not in ("triage", "injection", "copilot"):
            continue
        o = r["outputs"][0]; n += 1
        t, s = technique_check(o, c["context"]), service_check(o, c["context"])
        tu += not t["ok"]; ts += bool(t["off_category"]); so += bool(s["named"]); sa += not s["ok"]
        if not t["ok"] or not s["ok"]:
            bad.append((r["id"], t["unknown"], s["absent"]))
    print("answers %d | invented technique id: %d (%.1f%%) | off-category technique: %d | names a service: %d | service without its port on the cards: %d (%.1f%%)" % (
        n, tu, 100 * tu / max(1, n), ts, so, sa, 100 * sa / max(1, n)))
    for b in bad[:12]:
        print("  %s unknown=%s service_absent=%s" % b)


if __name__ == "__main__":
    main()
