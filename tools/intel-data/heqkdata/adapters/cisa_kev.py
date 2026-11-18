# SPDX-License-Identifier: AGPL-3.0-only
"""CISA Known Exploited Vulnerabilities catalogue (JSON feed) -> vulnerability.

KEV carries no CVSS and no ATT&CK mapping; those stay null/empty here and are joined later from NVD
(a separate, separately licensed source). Every KEV entry is, by definition, known_exploited = true.
"""
import re

from .. import canon, safeio

VERSION = "1.0.0"


def parse(path, ctx):
    from . import Reject
    doc = safeio.load_json(path)
    vulns = doc.get("vulnerabilities")
    if not isinstance(vulns, list):
        yield Reject(0, "no 'vulnerabilities' array")
        return
    for i, v in enumerate(vulns):
        cve = (v.get("cveID") or "").strip()
        if not re.fullmatch(r"CVE-[0-9]{4}-[0-9]{4,}", cve):
            yield Reject(i, f"bad cveID {cve!r}")
            continue
        cwes = sorted({c for c in (v.get("cwes") or []) if re.fullmatch(r"CWE-[0-9]+", str(c))})
        ransom = v.get("knownRansomwareCampaignUse")
        body = {
            "schema": "heqk.vulnerability/1",
            "cve_id": cve,
            "vendor": v.get("vendorProject") or None,
            "product": v.get("product") or None,
            "description": (v.get("shortDescription") or None),
            "cwe_ids": cwes,
            "cvss": None,
            "known_exploited": True,
            "kev_date_added": canon.date(v.get("dateAdded")),
            "kev_due_date": canon.date(v.get("dueDate")),
            "ransomware_use": ransom if ransom in ("Known", "Unknown") else None,
            "required_action": v.get("requiredAction") or None,
            "published": None,
            "attack_mapping": {"framework": "MITRE ATT&CK", "version": None, "techniques": [], "tactics": [], "mapping_source": "none"},
        }
        yield ctx.record(
            "vulnerability", body, source_record_id=cve, raw_bytes=canon.canonical_json(v).encode(),
            observed_at=canon.ts(v.get("dateAdded")), label=None, label_source="knowledge_base",
            original_label="known_exploited", sensor_type="knowledge_base",
        )
