# SPDX-License-Identifier: AGPL-3.0-only
"""Read-only lookup tables for Neuro's L0 CONTEXT line (agreed with the Neuro session, 2026-11-21).

Not training text: a 1.7B explainer should look CVE and ATT&CK facts up, not memorise them. Two tables,
record facts only, from the newest normalised acquisition of each source that the licence gate allows
for `purpose`:

  cve.jsonl     {"cve": "CVE-2021-44228", "cwe": ["CWE-502"], "cvss": {"version": "3.1", "score": 10.0,
                 "band": "critical"} | null, "vendor": "...", "product": "...", "kev": true|false,
                 "src": ["cve-list-v5", ...]}
  attack.jsonl  {"id": "T1110", "name": "Brute Force", "tactics": ["credential-access"],
                 "domains": ["enterprise"]}
  cwe.jsonl     {"id": "CWE-79", "name": ..., "abstraction": "Base", "status": "Stable", "parents": ["CWE-74"],
                 "capec": ["CAPEC-209", ...], "likelihood": "High"}
  capec.jsonl   {"id": "CAPEC-66", "name": "SQL Injection", "parents": [...], "cwe": ["CWE-89", ...],
                 "attack": ["T1190"?], "severity": "High", "likelihood": "High", ...}

Field rules:
- CVE fields come from the CVE Program record first; the GitHub Advisory Database fills a field only where
  the CVE record has none (vendor/product there are the package ecosystem and name). `src` lists the
  sources that contributed.
- band is the CVSS v3/v4 qualitative rating; v2 scores keep band null (v2 has no 'critical').
- kev is true when the CVE is in the CISA KEV catalogue acquisition used, or the CVE record's CISA-ADP
  container carries the KEV marker; false means "not in that catalogue snapshot", dated in the manifest.
- CWE / CAPEC: Weakness entries and attack patterns that are not Deprecated or Obsolete; links and the
  CAPEC -> ATT&CK mapping are MITRE's own (mitre_weakness_json).
- ATT&CK: active techniques only (deprecated and revoked are left out); domains lists which of the
  enterprise / mobile / ICS bundles carry the id.
The output directory is immutable (id = hash of inputs + code); files are 0444 and the manifest, with every
file's SHA-256, is renamed into place last.
"""
import hashlib
import json
import os

from . import VERSION, canon, context, cvss, licensing

CVE_SOURCES = ("cve-list-v5", "github-advisory-db", "cisa-kev")
ATTACK_SOURCES = {"mitre-attack-stix": "enterprise", "mitre-attack-mobile": "mobile", "mitre-attack-ics": "ics"}
WEAKNESS_SOURCES = ("mitre-cwe", "mitre-capec")
INACTIVE = {"Deprecated", "Obsolete"}
CONTEXT_SOURCES = ("iptoasn", "misp-warninglists")
# 1 = cve + attack; 2 = + cwe + capec; 3 = + asn_ranges.tsv + warninglists.jsonl (the windows' remote_context
# tables, so L0 at inference matches what training saw); 4 = + warninglist_phrases.jsonl, more third-party lists dropped
FORMAT = 4


def _newest(store, source_id):
    acqs = [a for a in store.acquisitions(source_id) if not a.get("derived_from")]
    return acqs[-1] if acqs else None  # acquisitions() is ordered by fetched_at


def _records(store, acq):
    p = os.path.join(store.norm_dir(acq["source_id"], acq["acquisition_id"]), "records.jsonl")
    if not os.path.exists(p):
        return
    with open(p, "r", encoding="utf-8") as f:
        for line in f:
            yield json.loads(line)


def build(store, registry, purpose, out_root=None, cve_sources=CVE_SOURCES, attack_sources=None, kev_source="cisa-kev",
          weakness_sources=WEAKNESS_SOURCES, context_sources=CONTEXT_SOURCES):
    """cve_sources in precedence order; kev_source is the KEV catalogue (sources are parameters for tests)."""
    attack_sources = attack_sources or ATTACK_SOURCES
    used, refused, caveats = {}, {}, {}
    for sid in tuple(cve_sources) + tuple(attack_sources) + tuple(weakness_sources) + tuple(context_sources):
        ok, why = licensing.decide(registry.license_of(sid), purpose)
        acq = _newest(store, sid)
        if not ok:
            refused[sid] = why
        elif acq is None:
            refused[sid] = "no acquisition"
        else:
            used[sid] = acq
            if why == licensing.EVALUATION_UNCLEAR:
                caveats[sid] = why
    version = "lookup-" + canon.sha256_obj([FORMAT, VERSION, purpose, _code_digest(),
                                            sorted((s, a["acquisition_id"], _norm(store, a)) for s, a in used.items())])[:12]
    out = os.path.join(out_root or os.path.join(store.root, "builds"), version)
    if os.path.exists(os.path.join(out, "manifest.json")):
        raise RuntimeError(f"{out} is a finished lookup build and is never rewritten")
    os.makedirs(out, exist_ok=True)

    cve = {}
    kev = set()
    for sid in cve_sources:
        if sid not in used:
            continue
        for r in _records(store, used[sid]):
            if r["kind"] != "vulnerability":
                continue
            b = r["body"]
            if sid == kev_source or b["known_exploited"]:
                kev.add(b["cve_id"])
            if sid == kev_source:
                continue
            e = cve.setdefault(b["cve_id"], {"cve": b["cve_id"], "cwe": [], "cvss": None, "vendor": None,
                                             "product": None, "src": []})
            took = False
            if not e["cwe"] and b["cwe_ids"]:
                e["cwe"], took = list(b["cwe_ids"]), True
            if e["cvss"] is None and b["cvss"]:
                c = b["cvss"]
                band = cvss.severity(c["base_score"]) if c["version"] != "2.0" else None
                e["cvss"], took = {"version": c["version"], "score": c["base_score"], "band": band}, True
            if e["vendor"] is None and e["product"] is None and (b["vendor"] or b["product"]):
                e["vendor"], e["product"], took = b["vendor"], b["product"], True
            if took and sid not in e["src"]:
                e["src"].append(sid)
    for c in kev:  # a KEV entry missing from both CVE sources still gets a row (kev only)
        cve.setdefault(c, {"cve": c, "cwe": [], "cvss": None, "vendor": None, "product": None, "src": []})
    for c, e in cve.items():
        e["kev"] = c in kev
        if c in kev and kev_source in used and kev_source not in e["src"]:
            e["src"].append(kev_source)

    attack = {}
    for sid, domain in attack_sources.items():
        if sid not in used:
            continue
        for r in _records(store, used[sid]):
            if r["kind"] != "attack_technique":
                continue
            b = r["body"]
            if b["deprecated"] or b["revoked"]:
                continue
            e = attack.setdefault(b["technique_id"], {"id": b["technique_id"], "name": b["name"], "tactics": [],
                                                      "domains": []})
            e["tactics"] = sorted(set(e["tactics"]) | set(b["tactics"]))
            if domain not in e["domains"]:
                e["domains"].append(domain)

    cwe, capec = {}, {}
    for sid in weakness_sources:
        if sid not in used:
            continue
        for r in _records(store, used[sid]):
            if r["kind"] != "weakness":
                continue
            b = r["body"]
            if b["status"] in INACTIVE:
                continue
            if b["catalog"] == "CWE":
                cwe[b["entry_id"]] = {"id": b["entry_id"], "name": b["name"], "abstraction": b["abstraction"],
                                      "status": b["status"], "parents": b["parents"], "capec": b["related_capec"],
                                      "likelihood": b["likelihood"]}
            else:
                capec[b["entry_id"]] = {"id": b["entry_id"], "name": b["name"], "abstraction": b["abstraction"],
                                        "status": b["status"], "parents": b["parents"], "cwe": b["related_cwe"],
                                        "attack": b["attack_mapping"]["techniques"], "severity": b["typical_severity"],
                                        "likelihood": b["likelihood"]}

    files = []
    ctx_sources = [s for s in context_sources if s in used]
    tables = context.load(store, registry, purpose, ctx_sources) if ctx_sources else {}
    for sid, (tab, _) in tables.items():
        if isinstance(tab, context.ASN):
            p = os.path.join(out, "asn_ranges.tsv")
            with open(p + ".partial", "w", encoding="utf-8") as f:
                f.write("family\tstart\tend\tasn\tcountry\tas_name\n")
                for fam, s, e, asn, cc, name in tab.rows():
                    f.write(f"{fam}\t{s}\t{e}\t{asn}\t{cc or ''}\t{(name or '').replace(chr(9), ' ')}\n")
            nrows = sum(1 for _ in tab.rows())
            fname = "asn_ranges.tsv"
        else:
            p = os.path.join(out, "warninglists.jsonl")
            with open(p + ".partial", "w", encoding="utf-8") as f:
                for k in sorted(tab.lists):
                    l = tab.lists[k]
                    f.write(json.dumps({"id": k, "name": l["name"], "type": l["type"], "category": l["category"],
                                        "version": l["version"], "not_for_captures": k in context.NOT_FOR_CAPTURES,
                                        "entries": l["entries"]}, separators=(",", ":"), sort_keys=True) + "\n")
            nrows, fname = len(tab.lists), "warninglists.jsonl"
            os.chmod(p + ".partial", 0o444)
            os.replace(p + ".partial", p)
            files.append({"file": fname, "rows": nrows, "sha256": _sha(p)})
            # one hand-written phrase per kept list, so L0 and training render identical CONTEXT phrases
            ph = context.phrases()
            unmapped = sorted(k for k in tab.lists if k not in ph)
            if unmapped:
                raise RuntimeError(f"warninglists without a hand-written phrase: {unmapped}")
            p = os.path.join(out, "warninglist_phrases.jsonl")
            with open(p + ".partial", "w", encoding="utf-8") as f:
                for k in sorted(tab.lists):
                    f.write(json.dumps({"id": k, "phrase": ph[k]}, separators=(",", ":"), sort_keys=True) + "\n")
            nrows, fname = len(tab.lists), "warninglist_phrases.jsonl"
        os.chmod(p + ".partial", 0o444)
        os.replace(p + ".partial", p)
        files.append({"file": fname, "rows": nrows, "sha256": _sha(p)})
    for name, rows, key in (("cve.jsonl", cve, _cve_key), ("attack.jsonl", attack, _attack_key),
                            ("cwe.jsonl", cwe, _num_key), ("capec.jsonl", capec, _num_key)):
        p = os.path.join(out, name)
        with open(p + ".partial", "w", encoding="utf-8") as f:
            for k in sorted(rows, key=key):
                f.write(json.dumps(rows[k], separators=(",", ":"), sort_keys=True) + "\n")
        os.chmod(p + ".partial", 0o444)
        os.replace(p + ".partial", p)
        files.append({"file": name, "rows": len(rows), "sha256": _sha(p)})
    manifest = {
        "schema": "heqk.lookup-manifest/1", "version": version, "tool_version": VERSION, "format": FORMAT,
        "purpose": purpose, "files": files,
        "sources": {s: {"acquisition_id": a["acquisition_id"], "fetched_at": a["fetched_at"], "normalized_by": _norm(store, a),
                        "license_id": a["license_id"],
                        "attribution": registry.source(s).get("attribution")} for s, a in sorted(used.items())},
        "refused": refused,
        "context": context.manifest_entry(tables) if tables else {},
        "phrases_note": "warninglist_phrases.jsonl is hand-written (registry/warninglist_phrases.json): no inferred facts; "
                        "null = address space or non-network data, never a CONTEXT phrase.",
        "notes": "Record facts only. kev=false means 'not in the CISA KEV snapshot fetched at "
                 + (used[kev_source]["fetched_at"] if kev_source in used else "n/a") + "'.",
    }
    if caveats:  # admitted only for evaluation: never ship these tables to a device
        manifest["licence_caveats"] = caveats
    mp = os.path.join(out, "manifest.json")
    with open(mp + ".partial", "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=1, sort_keys=True)
    os.chmod(mp + ".partial", 0o444)
    os.replace(mp + ".partial", mp)
    store.audit("lookup", version=version, purpose=purpose, sources=sorted(used))
    return out, manifest


def _norm(store, acq):
    """(adapter, adapter_version) of the acquisition's current normalisation: a re-parse changes the id."""
    row = store.db.execute("SELECT adapter, adapter_version FROM normalizations WHERE acquisition_id = ? "
                           "ORDER BY created_at DESC LIMIT 1",
                           (acq["acquisition_id"],)).fetchone()
    return list(row) if row else None


def _cve_key(c):
    y, n = c[4:].split("-")
    return (int(y), int(n))


def _num_key(i):
    return int(i.rsplit("-", 1)[1])


def _attack_key(t):
    main, _, sub = t[1:].partition(".")
    return (int(main), int(sub or 0))


def _code_digest():
    with open(__file__, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()


def _sha(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for b in iter(lambda: f.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()
