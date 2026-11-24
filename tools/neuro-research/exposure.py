#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Doc 39 §3.4: `lookup_exposure`, a read-only, deterministic tool. It is the ONLY way CVE facts reach an answer: the
model never memorises CVE ids (doc 39 §1), it cites what this tool returned.

Source: data/entry-paths.json (KEV rows with device class, network reach, entry technique; built by entry_paths.py from
intel-data's raw files). Network-reachable entries only (NVD attack vector NETWORK / ADJACENT_NETWORK or unknown).

lookup(device_class, product=None) ->
  {"class", "entries", "recent", "ransomware", "top_entry": [(technique, count)], "product_match": [cve ids, <= 5],
   "caveat"}
render(alias, result) -> one context line, as the tool's RESULT would appear to the model:
  RESULT lookup_exposure H1: class nas; 22 known-exploited weaknesses reachable from the network (1 added in the last 2
  years, 11 used by ransomware); usual entry T1190 (22). Product matches: none known. Caveat: ...
The caveat is always present: firmware versions are rarely known at the gateway, so a match means "devices like this
are often hit by", never "this device is vulnerable".
Usage: python3 -I exposure.py <entry-paths.json> <class> [product words...]
"""
import collections, json, os, sys

HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT = os.path.join(HERE, "..", "..", "docs", "research", "neuro", "data", "entry-paths.json")
CAVEAT = ("firmware versions are rarely known at the gateway, so this says which weaknesses devices like this are often "
          "attacked through, not that this device is vulnerable")
CLASSES = {"router", "edge", "nas", "camera", "printer", "media", "phone", "workstation", "server", "ics"}
_DB = {}


def load(path=DEFAULT):
    if path not in _DB:
        d = json.load(open(path))
        newest = d["kev_newest"]
        cut = "%04d%s" % (int(newest[:4]) - 2, newest[4:])
        rows = [r for r in d["kev_rows"] if r["reach"] in ("NETWORK", "ADJACENT_NETWORK", "unknown")]
        _DB[path] = (rows, cut)
    return _DB[path]


def lookup(device_class, product=None, path=DEFAULT):
    rows, cut = load(path)
    if device_class not in CLASSES:   # never guess a class: an unknown device gets no exposure claim
        return {"class": "unknown", "entries": 0, "recent": 0, "ransomware": 0, "top_entry": [], "product_match": [],
                "caveat": "the device class is unknown, so no exposure can be stated"}
    c = device_class
    rs = [r for r in rows if r["class"] == c]
    top = collections.Counter(t for r in rs for t in r["entry"]).most_common(3)
    match = []
    if product:
        words = [w.lower() for w in product.split() if len(w) > 2]
        hits = [r for r in rs if words and all(w in ("%s %s" % (r["vendor"], r["product"])).lower() for w in words)]
        match = [r["cve"] for r in sorted(hits, key=lambda r: r["date_added"], reverse=True)[:5]]
    return {"class": c, "entries": len(rs), "recent": sum(r["date_added"] >= cut for r in rs),
            "ransomware": sum(r["ransomware"] for r in rs), "top_entry": top, "product_match": match, "caveat": CAVEAT}


def render(alias, res):
    if res["class"] == "unknown":
        return "RESULT lookup_exposure %s: device class unknown; no exposure can be stated." % alias
    top = ", ".join("%s (%d)" % (t, n) for t, n in res["top_entry"]) or "none"
    pm = ", ".join(res["product_match"]) if res["product_match"] else "none known"
    return ("RESULT lookup_exposure %s: class %s; %d known-exploited weaknesses reachable from the network (%d added in the last "
            "2 years, %d used by ransomware); usual entry %s. Product matches: %s. Caveat: %s." % (
                alias, res["class"], res["entries"], res["recent"], res["ransomware"], top, pm, res["caveat"]))


if __name__ == "__main__":
    p, cls = sys.argv[1], sys.argv[2]
    print(render("H1", lookup(cls, " ".join(sys.argv[3:]) or None, p)))
