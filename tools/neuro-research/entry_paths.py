#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Doc 39 §3.1: the entry-path graph. Which ATT&CK techniques attackers actually use to get into each device class a
home/SMB gateway sees, weighted by CISA KEV, and whether the gateway can observe them. Deterministic; no model.

Inputs are intel-data's raw files (read-only, located by source id under ~/.cache/hookprobe-intel-data/raw):
  cisa-kev, nist-nvd-api2 (yearly CVE 2.0 feeds), ctid-mappings-explorer (KEV -> ATT&CK), mitre-capec, mitre-attack-stix.

Per KEV entry:
  1. device class: CLASS_RULES below, first match on "vendor product" (hand-written, reviewed in the output);
  2. reach: NVD CVSS attackVector (v3.1, then v3.0, then v2 accessVector); NETWORK / ADJACENT_NETWORK = reachable;
     no NVD metric -> "unknown" (kept, counted apart);
  3. entry technique: CTID `exploitation_technique` if mapped (source "ctid"); else the CWEs' CAPEC patterns' ATT&CK
     mappings (source "capec", only if they name <= CAPEC_MAX techniques; CAPEC_MAX = 0 turns it off, see below); else a default by class and reach (source "default": network-reachable servers and
     appliances -> T1190, client software -> T1203, local -> T1068);
  4. follow-on: CTID primary/secondary impact techniques (what the attacker does next), counted apart.
Observability: a technique is GATEWAY-VISIBLE if any ATT&CK v18 analytic of a detection strategy that detects it (or
its parent) reads Network Traffic Flow, Network Traffic Content or Network Connection Creation.
Writes <out>.json (full graph) and <out>.md (review tables). No CVE text is copied into the outputs beyond ids.
Usage: python3 -I entry_paths.py <out prefix> [--raw ~/.cache/hookprobe-intel-data/raw]
"""
import argparse, collections, glob, gzip, hashlib, json, os, re

CLASS_RULES = [  # (class, regex on "vendor product", lower case). Order matters: first match wins.
    ("ics", r"siemens|schneider|rockwell|openplc|mitsubishi electric|advantech|unitronics|ge digital|moxa"),
    ("camera", r"hikvision|dahua|reolink|geovision|nuuo|ptzoptics|avtech|axis communications|vivotek|uniview|tbk|"
               r"\bnvr\b|\bdvr\b|ip camera|\bcamera|d-link.*dcs-|\bdcs-\d|\bdnr-"),
    ("nas", r"synology|qnap|western digital|wd my cloud|my cloud|buffalo|asustor|terramaster|seagate.*nas|\bnas\b|"
            r"zyxel.*nas|unraid|storage device|\bdns-3\d\d"),
    ("printer", r"papercut|printer|xerox|ricoh|kyocera|lexmark|hp.*laserjet|konica"),
    ("media", r"plex|roku|smart tv|webos|tizen|kodi|chromecast"),
    ("edge", r"fortinet|fortigate|fortios|sonicwall|palo alto|check point|sophos|watchguard|ivanti.*(connect|pulse|"
             r"policy secure|gateway)|pulse secure|citrix.*(adc|gateway|netscaler)|netscaler|f5 big-ip|f5\b|"
             r"zyxel.*(firewall|usg|atp|vpn)|array networks|barracuda|aviatrix|versa|juniper|cisco.*(asa|firepower|ios|ftd|adaptive security|"
             r"secure firewall|anyconnect|smart licensing|ise|meraki)|arista|zscaler|cyberoam"),
    ("router", r"d-link|zyxel|netgear|tp-link|mikrotik|draytek|tenda|ubiquiti|linksys|totolink|arcadyan|realtek|"
               r"four-faith|cisco small business|cisco.*rv\d|asus.*router|asus.*rt-|asus\b|digiever|edimax|"
               r"zte|huawei.*router|netis|wavlink|optilink|billion|tenda|gpon|\brouters?\b"),
    ("phone", r"whatsapp|\bios\b|ipados|android|pixel|qualcomm|arm mali|mali gpu|samsung mobile|samsung.*(galaxy|exynos)|"
              r"mediatek|unisoc|apple.*(iphone|multiple products)|imagination"),
    ("workstation", r"microsoft.*(windows|office|outlook|\bword\b|excel|internet explorer|edge|defender|\.net|silverlight|"
                    r"win32k|mshtml|wordpad|skype|teams|directx|visual studio|powerpoint|graphics device|xml core|"
                    r"cryptographic|smbv1)|apple.*os x|gigabyte|chrom|firefox|mozilla|safari|webkit|"
                    r"macos|adobe (acrobat|reader|flash)|acrobat|flash player|winrar|unrar|rarlab|7-zip|java se|"
                    r"\bjre\b|wps office|onlyoffice|apex one|officescan|linux.*kernel|sudo|polkit|glibc|xz utils|"
                    r"windows"),
]
SERVER = "server"   # everything else: self-hosted web apps, mail, management, CMS, enterprise software
CLIENT = {"workstation", "phone"}
CAPEC_MAX = 0   # OFF. Reviewed 2026-11-23: even <= 3-technique CWE->CAPEC->ATT&CK chains gave the same spurious trio
                # (T1027.006 HTML Smuggling, T1027.009, T1564.009) for server/router RCEs. Too coarse for entry paths.
VISIBLE_DC = {"Network Traffic Flow", "Network Traffic Content", "Network Connection Creation"}


def one(raw, src, pat):
    m = sorted(glob.glob(os.path.join(raw, src, "*", pat)))
    if not m:
        raise SystemExit("missing %s/%s" % (src, pat))
    return m


def sha(p):
    return hashlib.sha256(open(p, "rb").read()).hexdigest()


def klass(vendor, product):
    s = ("%s %s" % (vendor, product)).lower()
    for c, rx in CLASS_RULES:
        if re.search(rx, s):
            return c
    return SERVER


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("out"); ap.add_argument("--raw", default=os.path.expanduser("~/.cache/hookprobe-intel-data/raw"))
    a = ap.parse_args()
    inputs = {}
    kev_p = one(a.raw, "cisa-kev", "known_exploited_vulnerabilities.json")[-1]
    kev = json.load(open(kev_p))["vulnerabilities"]; inputs["cisa-kev"] = [sha(kev_p)]
    want = {k["cveID"] for k in kev}
    reach = {}
    nvd_ps = one(a.raw, "nist-nvd-api2", "*.json.gz"); inputs["nist-nvd-api2"] = [sha(p) for p in nvd_ps]
    for p in nvd_ps:
        for v in json.load(gzip.open(p))["vulnerabilities"]:
            c = v["cve"]
            if c["id"] not in want:
                continue
            m = c.get("metrics", {})
            av = None
            for key in ("cvssMetricV31", "cvssMetricV30"):
                for x in m.get(key, []):
                    av = av or x["cvssData"].get("attackVector")
            for x in m.get("cvssMetricV2", []):
                av = av or x["cvssData"].get("accessVector")
            reach[c["id"]] = av
    ctid_ps = one(a.raw, "ctid-mappings-explorer", "*enterprise.json"); inputs["ctid-mappings-explorer"] = [sha(p) for p in ctid_ps]
    ctid_entry, ctid_impact = collections.defaultdict(set), collections.defaultdict(set)
    for p in ctid_ps:
        for m in json.load(open(p))["mapping_objects"]:
            if not m.get("attack_object_id"):
                continue
            (ctid_entry if m["mapping_type"] == "exploitation_technique" else ctid_impact)[m["capability_id"]].add(m["attack_object_id"])
    cap_p = one(a.raw, "mitre-capec", "capec.ndjson")[-1]; inputs["mitre-capec"] = [sha(cap_p)]
    cwe2t = collections.defaultdict(set)
    for l in open(cap_p):
        c = json.loads(l)
        tm = c.get("Taxonomy_Mappings") or {}
        tm = tm.get("Taxonomy_Mapping", [])
        tm = tm if isinstance(tm, list) else [tm]
        tids = {"T" + t["Entry_ID"] for t in tm if t.get("@Taxonomy_Name") == "ATTACK" and t.get("Entry_ID")}
        rw = (c.get("Related_Weaknesses") or {}).get("Related_Weakness", [])
        rw = rw if isinstance(rw, list) else [rw]
        for w in rw:
            cwe2t["CWE-" + w["@CWE_ID"]] |= tids
    att_p = one(a.raw, "mitre-attack-stix", "enterprise-attack.json")[-1]; inputs["mitre-attack-stix"] = [sha(att_p)]
    objs = json.load(open(att_p))["objects"]
    by = {o["id"]: o for o in objs}
    tech = {}
    for o in objs:
        if o["type"] == "attack-pattern" and not o.get("revoked") and not o.get("x_mitre_deprecated"):
            tid = [e["external_id"] for e in o["external_references"] if e.get("source_name") == "mitre-attack"][0]
            tech[tid] = {"name": o["name"], "id": o["id"], "tactics": sorted(p["phase_name"] for p in o.get("kill_chain_phases", []))}
    sid2tid = {v["id"]: k for k, v in tech.items()}
    dcs = collections.defaultdict(set)
    for o in objs:
        if o["type"] == "relationship" and o["relationship_type"] == "detects" and o["source_ref"].startswith("x-mitre-detection-strategy") \
                and o["target_ref"] in sid2tid:
            ds = by.get(o["source_ref"], {})
            for an in ds.get("x_mitre_analytic_refs", []):
                for ls in by.get(an, {}).get("x_mitre_log_source_references", []):
                    dc = by.get(ls.get("x_mitre_data_component_ref"), {}).get("name")
                    if dc:
                        dcs[sid2tid[o["target_ref"]]].add(dc)

    def visible(t):
        return bool((dcs.get(t, set()) | dcs.get(t.split(".")[0], set())) & VISIBLE_DC)

    rows = []
    for k in kev:
        cid, cls = k["cveID"], klass(k["vendorProject"], k["product"])
        av = reach.get(cid)
        net = av in ("NETWORK", "ADJACENT_NETWORK")
        if cid in ctid_entry:
            ts, srcm = ctid_entry[cid], "ctid"
        else:
            ts = set().union(*[cwe2t.get(w, set()) for w in k.get("cwes") or []]) if k.get("cwes") else set()
            ts = {t for t in ts if t in tech or t.split(".")[0] in tech}
            srcm = "capec"
            if len(ts) > CAPEC_MAX:          # a generic weakness (e.g. CWE-20) fans out to many patterns: no signal
                ts = set()
            if not ts:
                ts = {"T1203" if cls in CLIENT else ("T1068" if av == "LOCAL" else "T1190")}
                srcm = "default"
        rows.append({"cve": cid, "vendor": k["vendorProject"], "product": k["product"], "class": cls, "reach": av or "unknown",
                     "date_added": k["dateAdded"], "ransomware": k.get("knownRansomwareCampaignUse") == "Known",
                     "entry": sorted(ts), "entry_source": srcm, "impact": sorted(ctid_impact.get(cid, set()))})
    newest = max(r["date_added"] for r in rows)
    recent = lambda d: d >= "%04d%s" % (int(newest[:4]) - 2, newest[4:])
    graph = collections.defaultdict(lambda: collections.defaultdict(lambda: collections.Counter()))
    for r in rows:
        if r["reach"] not in ("NETWORK", "ADJACENT_NETWORK", "unknown"):
            continue
        for t in r["entry"]:
            g = graph[r["class"]][t]
            g["kev"] += 1; g["recent"] += recent(r["date_added"]); g["ransomware"] += r["ransomware"]; g[r["entry_source"]] += 1
            g["reach_unknown"] += r["reach"] == "unknown"
    out = {"schema": "hookprobe.neuro.entry-paths/1", "doc": "39 §3.1", "inputs_sha256": inputs, "kev_newest": newest,
           "class_rules": CLASS_RULES, "visible_components": sorted(VISIBLE_DC), "kev_rows": rows,
           "graph": {c: {t: dict(n, name=(tech.get(t) or tech.get(t.split(".")[0]) or {}).get("name", "?"),
                                 tactics=(tech.get(t) or tech.get(t.split(".")[0]) or {}).get("tactics", []),
                                 gateway_visible=visible(t))
                         for t, n in ts.items()} for c, ts in graph.items()}}
    json.dump(out, open(a.out + ".json", "w"), indent=1, sort_keys=True)
    cls_n = collections.Counter(r["class"] for r in rows)
    reach_n = collections.Counter(r["reach"] for r in rows)
    src_n = collections.Counter(r["entry_source"] for r in rows)
    follow = collections.defaultdict(collections.Counter)
    for r in rows:
        for t in r["impact"]:
            follow[r["class"]][t] += 1
    out["follow_on"] = {c: dict(n) for c, n in follow.items()}
    json.dump(out, open(a.out + ".json", "w"), indent=1, sort_keys=True)
    with open(a.out + ".md", "w") as f:
        f.write("# Entry-path graph (doc 39 §3.1), generated by `tools/neuro-research/entry_paths.py`\n\n")
        f.write("KEV entries %d (newest %s); by class %s; reach %s; entry mapping %s.\n\n" % (
            len(rows), newest, dict(cls_n.most_common()), dict(reach_n.most_common()), dict(src_n.most_common())))
        f.write("Only network-reachable (or unknown-reach) entries enter the graph. `recent` = added in the last 2 years of the "
                "catalogue. `visible` = an ATT&CK analytic for the technique reads network flow, content or connection data.\n")
        for c in sorted(graph, key=lambda c: -cls_n[c]):
            f.write("\n## %s (%d KEV entries)\n\n| technique | name | KEV | recent | ransomware | mapped by ctid / capec / default | gateway-visible |\n|---|---|---|---|---|---|---|\n" % (c, cls_n[c]))
            for t, n in sorted(graph[c].items(), key=lambda x: -x[1]["kev"])[:15]:
                nm = (tech.get(t) or tech.get(t.split(".")[0]) or {}).get("name", "?")
                f.write("| %s | %s | %d | %d | %d | %d / %d / %d | %s |\n" % (t, nm, n["kev"], n["recent"], n["ransomware"], n["ctid"], n["capec"], n["default"],
                                                                         "yes" if visible(t) else "no"))
        f.write("\n## What attackers did next (CTID primary/secondary impact, mapped KEV entries only)\n\n| class | top follow-on techniques (count) |\n|---|---|\n")
        for c in sorted(follow, key=lambda c: -cls_n[c]):
            f.write("| %s | %s |\n" % (c, "; ".join("%s %s (%d)" % (t, (tech.get(t) or tech.get(t.split(".")[0]) or {}).get("name", "?"), n)
                                                for t, n in follow[c].most_common(8))))
        f.write("\n## Products per class (for review of CLASS_RULES)\n")
        per = collections.defaultdict(collections.Counter)
        for r in rows:
            per[r["class"]]["%s %s" % (r["vendor"], r["product"])] += 1
        for c in sorted(per):
            f.write("\n**%s** (%d products): %s\n" % (c, len(per[c]), "; ".join("%s (%d)" % kv for kv in per[c].most_common(40))))
    print("KEV %d; classes %s; reach %s; mapping %s" % (len(rows), dict(cls_n.most_common()), dict(reach_n.most_common()), dict(src_n.most_common())))
    print("graph: %s" % {c: len(t) for c, t in graph.items()})


if __name__ == "__main__":
    main()
