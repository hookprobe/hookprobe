# SPDX-License-Identifier: AGPL-3.0-only
"""hookprobe-ioc-v1 feed (ADR 0027 D1; the snapshots lived in legacy/linux-tier/security/threat-intel/, removed in #1396) -> indicator.

The in-repo snapshot mixes real Feodo entries with HookProbe canary indicators (RFC 5737/2606 values,
EICAR). Canaries are kept but tagged 'canary' and labelled null: they test plumbing, they are not
threat intelligence and must never become training positives.
"""
from .. import canon, safeio

VERSION = "1.0.0"
TYPES = {"ip", "cidr", "domain", "url", "sha256", "sha1", "md5", "ja3", "ja4", "ja4s"}


# The public EICAR anti-malware test file (eicar.org): a test string, never threat intelligence.
EICAR_DIGESTS = {
    "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",  # sha256
    "3395856ce81f2b7382dee72602f798b642f14140",                          # sha1
    "44d88612fea8a8f36de82e1278abb02f",                                  # md5
}


def _is_canary(ind):
    v = str(ind.get("value", ""))
    src = str(ind.get("source", "")).lower()
    fam = str(ind.get("family") or "").lower()
    return ("canary" in src or "hookprobe" in src or "canary" in fam or "eicar" in src or "eicar" in fam
            or v.lower() in EICAR_DIGESTS
            or v.endswith((".example", ".test", ".invalid")) or v.startswith(("192.0.2.", "198.51.100.", "203.0.113.")))


def parse(path, ctx):
    from . import Reject
    doc = safeio.load_json(path)
    if doc.get("format") != "hookprobe-ioc-v1":
        yield Reject(0, f"format {doc.get('format')!r} != hookprobe-ioc-v1")
        return
    for i, ind in enumerate(doc.get("indicators", [])):
        t = ind.get("ioc_type")
        if t not in TYPES:
            yield Reject(i, f"unsupported ioc_type {t!r}")
            continue
        v = str(ind.get("value", ""))
        if t == "ip":
            v = canon.ip(v)
        elif t == "domain":
            v = canon.domain(v)
        if not v:
            yield Reject(i, "invalid value", str(ind.get("value")))
            continue
        canary = _is_canary(ind)
        mitre = ind.get("mitre") or ""
        techs = [mitre] if mitre and mitre[0] == "T" else []
        conf = ind.get("confidence")
        body = {
            "schema": "heqk.indicator/1",
            "value": v,
            "ioc_type": t,
            "family": ind.get("family") or None,
            "threat_type": None if canary else "botnet_cc",
            "confidence": conf if isinstance(conf, (int, float)) and 0 <= conf <= 1 else None,
            "first_seen": canon.ts(ind.get("first_seen")),
            "last_seen": None,
            "expires": None,
            "active": ind.get("active") if isinstance(ind.get("active"), bool) else None,
            "tlp": ind.get("tlp") if ind.get("tlp") in ("clear", "green", "amber", "amber+strict", "red") else "clear",
            "attack_mapping": {"framework": "MITRE ATT&CK", "version": None, "techniques": techs, "tactics": [],
                               "mapping_source": "source" if techs else "none"},
            "tags": ["canary"] if canary else [],
        }
        yield ctx.record(
            "indicator", body, source_record_id=f"{t}:{v}", raw_bytes=canon.canonical_json(ind).encode(),
            observed_at=body["first_seen"], label=None if canary else "malicious", family=body["family"],
            label_source="none" if canary else "feed", original_label="canary" if canary else ind.get("source"),
            techniques=techs, mapping_source="source", sensor_type="feed",
        )
