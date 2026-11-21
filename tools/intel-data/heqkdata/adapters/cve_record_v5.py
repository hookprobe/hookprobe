# SPDX-License-Identifier: AGPL-3.0-only
"""CVE JSON 5 records, one per line (CIRCL Vulnerability-Lookup's cvelistv5.ndjson dump) -> vulnerability.

Reads only the CVE record itself: cveMetadata, the CNA container, and the CISA-ADP (Vulnrichment, CC0)
container. The dump adds a 'vulnerability-lookup:meta' block (EPSS, NVD configurations, other feeds); it
is IGNORED, because those values come from other sources under their own terms (FIRST EPSS terms are
unclear in the registry). REJECTED and RESERVED records are rejected.

Field precedence: the CNA's own values first, CISA-ADP only where the CNA gave none. known_exploited is
true only when the CISA-ADP container carries a 'kev' metric; otherwise null (unknown), never false.
"""
import re

from .. import canon, safeio

VERSION = "1.0.0"
CVE_RE = re.compile(r"CVE-[0-9]{4}-[0-9]{4,}")
CWE_RE = re.compile(r"\bCWE-[0-9]+\b")
CVSS_KEYS = (("cvssV4_0", "4.0"), ("cvssV3_1", "3.1"), ("cvssV3_0", "3.0"), ("cvssV2_0", "2.0"))


def _na(v):
    v = (v or "").strip() if isinstance(v, str) else ""
    return None if not v or v.lower() in ("n/a", "unknown", "-", "*") else v[:256]


def _description(cna):
    descs = [d for d in cna.get("descriptions") or [] if isinstance(d, dict) and isinstance(d.get("value"), str)]
    for d in descs:
        if str(d.get("lang", "")).lower().startswith("en"):
            return d["value"].strip()[:8192] or None
    return None


def _vendor_product(container):
    for a in container.get("affected") or []:
        if isinstance(a, dict):
            v, p = _na(a.get("vendor")), _na(a.get("product"))
            if v or p:
                return v, p
    return None, None


def _cwes(container):
    out = set()
    for pt in container.get("problemTypes") or []:
        for d in (pt or {}).get("descriptions") or []:
            if not isinstance(d, dict):
                continue
            for v in (d.get("cweId"), d.get("description")):
                if isinstance(v, str):
                    out.update(CWE_RE.findall(v))
    return out


def _cvss(container):
    metrics = [m for m in container.get("metrics") or [] if isinstance(m, dict)]
    for key, ver in CVSS_KEYS:
        for m in metrics:
            c = m.get(key)
            if isinstance(c, dict) and isinstance(c.get("vectorString"), str):
                s = c.get("baseScore")
                if isinstance(s, (int, float)) and not isinstance(s, bool) and 0 <= s <= 10:
                    return {"version": ver, "vector": c["vectorString"][:256], "base_score": float(s)}
    return None


def _kev(container):
    for m in container.get("metrics") or []:
        o = (m or {}).get("other") if isinstance(m, dict) else None
        if isinstance(o, dict) and o.get("type") == "kev":
            c = o.get("content") if isinstance(o.get("content"), dict) else {}
            return True, canon.date(c.get("dateAdded"))
    return None, None


def parse(path, ctx):
    from . import Reject
    with safeio.open_text(path, max_bytes=ctx.acq.get("bytes") or safeio.MAX_TOTAL) as f:
        for n, rec, why in safeio.ndjson(f):
            if rec is None:
                yield Reject(n, why)
                continue
            meta = rec.get("cveMetadata") if isinstance(rec.get("cveMetadata"), dict) else {}
            cve = str(meta.get("cveId") or "").strip().upper()
            if not CVE_RE.fullmatch(cve):
                yield Reject(n, f"bad cveId {cve[:40]!r}")
                continue
            if meta.get("state") != "PUBLISHED":
                yield Reject(n, f"{cve} state {meta.get('state')!r}")
                continue
            cont = rec.get("containers") if isinstance(rec.get("containers"), dict) else {}
            cna = cont.get("cna") if isinstance(cont.get("cna"), dict) else {}
            adp = next((a for a in cont.get("adp") or [] if isinstance(a, dict)
                        and (a.get("providerMetadata") or {}).get("shortName") == "CISA-ADP"), {})
            desc = _description(cna)
            if not desc:
                yield Reject(n, f"{cve} has no English CNA description")
                continue
            vendor, product = _vendor_product(cna)
            if not (vendor or product):
                vendor, product = _vendor_product(adp)
            cwes = _cwes(cna) or _cwes(adp)
            kev, kev_added = _kev(adp)
            body = {
                "schema": "heqk.vulnerability/1",
                "cve_id": cve,
                "vendor": vendor,
                "product": product,
                "description": desc,
                "cwe_ids": sorted(cwes),
                "cvss": _cvss(cna) or _cvss(adp),
                "known_exploited": kev,
                "kev_date_added": kev_added,
                "kev_due_date": None,
                "ransomware_use": None,
                "required_action": None,
                "published": canon.date(meta.get("datePublished")),
                "attack_mapping": {"framework": "MITRE ATT&CK", "version": None, "techniques": [], "tactics": [],
                                   "mapping_source": "none"},
            }
            own = {"cveMetadata": meta, "containers": {"cna": cna, "adp": [adp] if adp else []}}
            yield ctx.record(
                "vulnerability", body, source_record_id=cve, raw_bytes=canon.canonical_json(own).encode(),
                observed_at=canon.ts(meta.get("datePublished")), label=None, label_source="knowledge_base",
                original_label=meta.get("assignerShortName") or None, sensor_type="knowledge_base",
            )
