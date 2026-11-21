# SPDX-License-Identifier: AGPL-3.0-only
"""MITRE ATT&CK Enterprise STIX 2.1 bundle (github.com/mitre-attack/attack-stix-data) -> attack_technique.

Keeps deprecated and revoked techniques (flagged), because older dataset labels still cite them; the
training builder skips them. Tactic ids are not in attack-pattern objects (only phase names), so the
TA-ids come from the bundle's x-mitre-tactic objects.
"""
from .. import canon, safeio

VERSION = "1.1.0"
# enterprise, mobile and ICS bundles name their kill chains differently (1.0.0 read enterprise only, so
# mobile / ICS techniques came out with no tactics)
KILL_CHAINS = {"mitre-attack", "mitre-mobile-attack", "mitre-ics-attack"}


def _ext_id(obj):
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack" and ref.get("external_id"):
            return ref["external_id"]
    return None


def parse(path, ctx):
    from . import Reject
    bundle = safeio.load_json(path)
    if bundle.get("type") != "bundle":
        yield Reject(0, "not a STIX bundle")
        return
    objs = bundle.get("objects", [])
    version = None
    tactic_ids = {}
    for o in objs:
        if o.get("type") == "x-mitre-collection":
            version = o.get("x_mitre_version") or version
        if o.get("type") == "x-mitre-tactic" and o.get("x_mitre_shortname"):
            tactic_ids[o["x_mitre_shortname"]] = _ext_id(o)
    for i, o in enumerate(objs):
        if o.get("type") != "attack-pattern":
            continue
        tid = _ext_id(o)
        if not tid or not tid.startswith("T"):
            yield Reject(i, "attack-pattern without a mitre-attack external_id", o.get("id"))
            continue
        phases = sorted({p["phase_name"] for p in o.get("kill_chain_phases", []) if p.get("kill_chain_name") in KILL_CHAINS})
        body = {
            "schema": "heqk.attack-technique/1",
            "technique_id": tid,
            "stix_id": o["id"],
            "name": o.get("name", ""),
            "tactics": phases,
            "platforms": sorted(set(o.get("x_mitre_platforms", []))),
            "description": (o.get("description") or "")[:32768],
            "detection": (o.get("x_mitre_detection") or None),
            "data_sources": list(o.get("x_mitre_data_sources", [])),
            "is_subtechnique": bool(o.get("x_mitre_is_subtechnique", False)),
            "deprecated": bool(o.get("x_mitre_deprecated", False)),
            "revoked": bool(o.get("revoked", False)),
            "attack_version": version,
            "modified": canon.ts(o.get("modified")),
        }
        tactics = sorted({tactic_ids[p] for p in phases if tactic_ids.get(p)})
        yield ctx.record(
            "attack_technique", body, source_record_id=o["id"], raw_bytes=canon.canonical_json(o).encode(),
            observed_at=canon.ts(o.get("modified")), label=None, label_source="knowledge_base",
            techniques=[tid], tactics=tactics, mapping_source="source", sensor_type="knowledge_base",
            attack_version=version,
        )
