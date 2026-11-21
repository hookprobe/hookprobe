# SPDX-License-Identifier: AGPL-3.0-only
"""OSV advisories, one per line (CIRCL Vulnerability-Lookup's github.ndjson dump of the GitHub Advisory
Database, CC BY 4.0) -> vulnerability, one record per CVE alias.

heqk.vulnerability/1 is keyed on a CVE id, so an advisory with no CVE alias (many GHSA-only and malicious
package advisories) is rejected with that reason. Withdrawn advisories are rejected. The package is
recorded as vendor = OSV ecosystem (npm, PyPI, Maven, ...) and product = package name. OSV gives a CVSS
vector without a score; v3 scores are computed from the vector with the FIRST formula (heqkdata.cvss), and
v4-only advisories keep cvss null. The 'vulnerability-lookup:*' keys added by the dump are ignored.
"""
import re

from .. import canon, cvss, safeio

VERSION = "1.0.0"
CVE_RE = re.compile(r"CVE-[0-9]{4}-[0-9]{4,}")
CWE_RE = re.compile(r"CWE-[0-9]+")


def _cvss(adv):
    for s in adv.get("severity") or []:
        if isinstance(s, dict) and s.get("type") == "CVSS_V3":
            score = cvss.base_score_v3(s.get("score"))
            if score is not None:
                return {"version": s["score"].strip()[5:8], "vector": s["score"].strip()[:256], "base_score": score}
    return None


def parse(path, ctx):
    from . import Reject
    with safeio.open_text(path, max_bytes=ctx.acq.get("bytes") or safeio.MAX_TOTAL) as f:
        for n, adv, why in safeio.ndjson(f):
            if adv is None:
                yield Reject(n, why)
                continue
            gid = str(adv.get("id") or "")[:64]
            if adv.get("withdrawn"):
                yield Reject(n, f"{gid} withdrawn")
                continue
            cves = sorted({a.strip().upper() for a in adv.get("aliases") or [] if isinstance(a, str)
                           and CVE_RE.fullmatch(a.strip().upper())})
            if not cves:
                yield Reject(n, f"{gid} has no CVE alias")
                continue
            summary = adv.get("summary") if isinstance(adv.get("summary"), str) else ""
            details = adv.get("details") if isinstance(adv.get("details"), str) else ""
            desc = "\n\n".join(x.strip() for x in (summary, details) if x and x.strip())[:8192] or None
            pkg = next((a.get("package") for a in adv.get("affected") or []
                        if isinstance(a, dict) and isinstance(a.get("package"), dict)), {}) or {}
            ds = adv.get("database_specific") if isinstance(adv.get("database_specific"), dict) else {}
            cwes = sorted({c for c in ds.get("cwe_ids") or [] if isinstance(c, str) and CWE_RE.fullmatch(c)})
            reviewed = ds.get("github_reviewed")
            for cve in cves:
                body = {
                    "schema": "heqk.vulnerability/1",
                    "cve_id": cve,
                    "vendor": (pkg.get("ecosystem") or None) and str(pkg["ecosystem"])[:256],
                    "product": (pkg.get("name") or None) and str(pkg["name"])[:256],
                    "description": desc,
                    "cwe_ids": cwes,
                    "cvss": _cvss(adv),
                    "known_exploited": None,
                    "kev_date_added": None,
                    "kev_due_date": None,
                    "ransomware_use": None,
                    "required_action": None,
                    "published": canon.date(adv.get("published")),
                    "attack_mapping": {"framework": "MITRE ATT&CK", "version": None, "techniques": [],
                                       "tactics": [], "mapping_source": "none"},
                }
                own = {k: v for k, v in adv.items() if not k.startswith("vulnerability-lookup:")}
                yield ctx.record(
                    "vulnerability", body, source_record_id=f"{gid}:{cve}",
                    raw_bytes=canon.canonical_json(own).encode(), observed_at=canon.ts(adv.get("published")),
                    label=None, label_source="knowledge_base",
                    original_label="github_reviewed" if reviewed is True else "unreviewed",
                    sensor_type="knowledge_base",
                )
