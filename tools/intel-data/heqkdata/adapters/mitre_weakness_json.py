# SPDX-License-Identifier: AGPL-3.0-only
"""MITRE CWE and CAPEC, one entry per line (CIRCL Vulnerability-Lookup's cwec.ndjson / capec.ndjson dumps,
which are MITRE's XML catalogues converted to JSON) -> weakness.

The dump is xmltodict-style: a single child is an object, several are a list, and text may be wrapped
in xhtml elements; _list() and _text() normalise both. A CWE line carries 'entry_type' (Weakness,
Grouping, View): only Weakness entries are kept, the others are rejected with that reason. Deprecated
and obsolete entries are kept with their status (the lookup table leaves them out).

What is read: id, name, abstraction, status, description, likelihood of exploit / attack, CAPEC typical
severity, ChildOf parents, CWE <-> CAPEC links and CAPEC's ATT&CK taxonomy mappings ("1574.010" ->
T1574.010, mapping_source "source": MITRE asserts it). Content_History (submitter names) and the dump's
'vulnerability-lookup:*' keys are ignored.
"""
import re

from .. import canon, safeio

VERSION = "1.0.0"
ATT = re.compile(r"^T?([0-9]{4}(?:\.[0-9]{3})?)$")


def _list(v):
    if v is None:
        return []
    return v if isinstance(v, list) else [v]


def _text(v):
    if v is None:
        return ""
    if isinstance(v, str):
        return v
    if isinstance(v, list):
        return " ".join(t for t in (_text(x) for x in v) if t)
    if isinstance(v, dict):
        return " ".join(t for t in (_text(x) for k, x in v.items() if not k.startswith("@")) if t)
    return str(v)


def _clean(s, n):
    s = re.sub(r"\s+", " ", s).strip()
    return s[:n] or None


def parse(path, ctx):
    from . import Reject
    with safeio.open_text(path, max_bytes=ctx.acq.get("bytes") or safeio.MAX_TOTAL) as f:
        for n, e, why in safeio.ndjson(f):
            if e is None:
                yield Reject(n, why)
                continue
            num = str(e.get("@ID") or "").strip()
            if not num.isdigit():
                yield Reject(n, f"bad @ID {num[:20]!r}")
                continue
            cwe = "entry_type" in e
            if cwe and e.get("entry_type") != "Weakness":
                yield Reject(n, f"CWE-{num} entry_type {e.get('entry_type')!r}")
                continue
            cat = "CWE" if cwe else "CAPEC"
            eid = f"{cat}-{num}"
            name = _clean(_text(e.get("@Name")), 512)
            if not name:
                yield Reject(n, f"{eid} has no name")
                continue
            rel_w = [r for r in _list((e.get("Related_Weaknesses") or {}).get("Related_Weakness")) if isinstance(r, dict)]
            rel_p = [r for r in _list((e.get("Related_Attack_Patterns") or {}).get("Related_Attack_Pattern")) if isinstance(r, dict)]
            if cwe:
                parents = {f"CWE-{r['@CWE_ID']}" for r in rel_w if r.get("@Nature") == "ChildOf" and str(r.get("@CWE_ID", "")).isdigit()}
                related_cwe = {f"CWE-{r['@CWE_ID']}" for r in rel_w if str(r.get("@CWE_ID", "")).isdigit()} - parents
                related_capec = {f"CAPEC-{r['@CAPEC_ID']}" for r in rel_p if str(r.get("@CAPEC_ID", "")).isdigit()}
            else:
                parents = {f"CAPEC-{r['@CAPEC_ID']}" for r in rel_p if r.get("@Nature") == "ChildOf" and str(r.get("@CAPEC_ID", "")).isdigit()}
                related_cwe = {f"CWE-{r['@CWE_ID']}" for r in rel_w if str(r.get("@CWE_ID", "")).isdigit()}
                related_capec = set()
            techniques = set()
            for m in _list((e.get("Taxonomy_Mappings") or {}).get("Taxonomy_Mapping")):
                if isinstance(m, dict) and m.get("@Taxonomy_Name") == "ATTACK":
                    mm = ATT.match(str(m.get("Entry_ID") or "").strip())
                    if mm:
                        techniques.add("T" + mm.group(1))
            body = {
                "schema": "heqk.weakness/1", "catalog": cat, "entry_id": eid, "name": name,
                "abstraction": _clean(_text(e.get("@Abstraction")), 64), "status": _clean(_text(e.get("@Status")), 64),
                "description": _clean(_text(e.get("Description")), 8192),
                "likelihood": _clean(_text(e.get("Likelihood_Of_Exploit") or e.get("Likelihood_Of_Attack")), 32),
                "typical_severity": _clean(_text(e.get("Typical_Severity")), 32),
                "parents": sorted(parents), "related_cwe": sorted(related_cwe), "related_capec": sorted(related_capec),
                "attack_mapping": {"framework": "MITRE ATT&CK", "version": None, "techniques": sorted(techniques),
                                   "tactics": [], "mapping_source": "source" if techniques else "none"},
            }
            own = {k: v for k, v in e.items() if not k.startswith("vulnerability-lookup:") and k != "Content_History"}
            yield ctx.record("weakness", body, source_record_id=eid, raw_bytes=canon.canonical_json(own).encode(),
                             label=None, label_source="knowledge_base", original_label=body["status"],
                             techniques=sorted(techniques), mapping_source="source" if techniques else "none",
                             sensor_type="knowledge_base")
