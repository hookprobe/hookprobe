# SPDX-License-Identifier: AGPL-3.0-only
"""The source, licence and collection registries (registry/*.json) and their consistency rules.

The registries are JSON, not YAML: the tooling is stdlib-only (tools/neuro-research convention), and the
files are reviewed in pull requests like code. Each file is {"schema": ..., "entries": [...]}, sorted by id.
"""
import json
import os

from . import REGISTRY_DIR
from . import schema as schemamod

FILES = {"sources": "sources.json", "licenses": "licenses.json", "collections": "collections.json"}
SCHEMA_FOR = {"sources": "source.schema.json", "licenses": "license.schema.json", "collections": "collection.schema.json"}


class Registry:
    def __init__(self, root=REGISTRY_DIR):
        self.root = root
        self.sources = self._load("sources")
        self.licenses = self._load("licenses")
        self.collections = self._load("collections")

    def _load(self, kind):
        with open(os.path.join(self.root, FILES[kind]), "r", encoding="utf-8") as f:
            doc = json.load(f)
        return {e["id"]: e for e in doc["entries"]}

    def source(self, sid):
        if sid not in self.sources:
            raise KeyError(f"unknown source {sid!r} (not in registry/sources.json)")
        return self.sources[sid]

    def license_of(self, sid):
        return self.licenses[self.source(sid)["license_id"]]

    def collection_sources(self, cid):
        """Sources that may feed collection `cid`: those the collection lists plus those whose own
        `collections` field names it (the two lists are maintained separately; either is a declaration)."""
        listed = set(self.collections[cid]["sources"])
        return listed | {sid for sid, s in self.sources.items() if cid in (s.get("collections") or [])}

    def check(self, validator=None):
        """List of problems; empty means the registry is internally consistent."""
        v = validator or schemamod.default()
        problems = []
        for kind in FILES:
            with open(os.path.join(self.root, FILES[kind]), "r", encoding="utf-8") as f:
                doc = json.load(f)
            ids = [e.get("id") for e in doc["entries"]]
            if ids != sorted(ids):
                problems.append(f"{FILES[kind]}: entries not sorted by id")
            if len(ids) != len(set(ids)):
                problems.append(f"{FILES[kind]}: duplicate ids")
            for e in doc["entries"]:
                for err in v.errors(e, SCHEMA_FOR[kind]):
                    problems.append(f"{FILES[kind]} {e.get('id')}: {err}")
        for lid, lic in self.licenses.items():
            # OPEN = an open licence granting commercial use and redistribution. Training rights are recorded
            # separately (training_use) because several open feeds carry an AI-training carve-out.
            if lic["class"] == "OPEN" and not (lic["commercial_use"] == lic["redistribution"] == "yes"):
                problems.append(f"licence {lid}: OPEN requires commercial_use and redistribution = yes")
        for sid, s in self.sources.items():
            lic = self.licenses.get(s["license_id"])
            if lic is None:
                problems.append(f"source {sid}: licence {s['license_id']!r} not in licenses.json")
                continue
            if s["license_class"] != lic["class"]:
                problems.append(f"source {sid}: license_class {s['license_class']} != licence {lic['id']} class {lic['class']}")
            for k in ("commercial_use", "training_use", "redistribution"):
                if s[k] != lic[k]:
                    problems.append(f"source {sid}: {k}={s[k]} disagrees with licence {lic['id']} ({lic[k]})")
            if s["verification_status"] == "verified" and not s["evidence"]:
                problems.append(f"source {sid}: verified without evidence URLs")
            if s["acquisition"] and s["access"] not in ("public_download",):
                problems.append(f"source {sid}: automated acquisition declared but access={s['access']}")
            if s["acquisition"] and s["sensitivity"] == "high":
                problems.append(f"source {sid}: high-sensitivity sources are never fetched automatically")
        for cid, c in self.collections.items():
            for sid in c["sources"]:
                if sid not in self.sources:
                    problems.append(f"collection {cid}: unknown source {sid}")
        return problems
