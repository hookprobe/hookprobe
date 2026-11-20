# SPDX-License-Identifier: AGPL-3.0-only
"""Test helpers: a throwaway data root and a small test registry, independent of the real catalogue."""
import json
import os
import shutil
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
TOOL = os.path.dirname(HERE)
FIX = os.path.join(HERE, "fixtures")
sys.path.insert(0, TOOL)

from heqkdata import REGISTRY_DIR  # noqa: E402


def lic(lid, cls, commercial, training, redistribution, share_alike=False):
    return {"id": lid, "name": lid, "spdx": None, "url": "https://example.org/licence", "class": cls,
            "commercial_use": commercial, "training_use": training, "redistribution": redistribution,
            "derivatives": training, "share_alike": share_alike, "attribution_required": True, "notes": None,
            "verified_on": "2026-11-18"}


LICENSES = [
    lic("t-open", "OPEN", "yes", "yes", "yes"),
    lic("t-research", "RESEARCH", "no", "unclear", "no"),
    lic("t-cc-by-sa", "OPEN", "yes", "yes", "yes", share_alike=True),
    lic("agpl-3.0-only", "OPEN", "yes", "yes", "yes"),
]


def src(sid, licence, adapter=None, collections=("dns_intelligence",)):
    l = next(x for x in LICENSES if x["id"] == licence)
    return {
        "id": sid, "name": sid, "organisation": "fixture", "country": None, "geographic_coverage": None,
        "source_url": "https://example.org/", "download_url": None, "api_endpoint": None, "description": "fixture",
        "category": "threat_intel", "subcategories": [], "data_format": ["csv"], "machine_readable": True,
        "records": None, "collection_period": None, "publication_date": None, "last_update": None,
        "update_frequency": None, "labels_available": True, "label_quality": None, "known_limitations": None,
        "license_id": licence, "license_class": l["class"], "commercial_use": l["commercial_use"],
        "training_use": l["training_use"], "redistribution": l["redistribution"], "attribution": None,
        "personal_data": "none", "sensitivity": "low", "access": "public_download", "collaboration_route": None,
        "recommended_use": "fixture", "collections": list(collections), "priority": 3,
        "acquisition": None if adapter is None else {"url": "https://example.org/x", "adapter": adapter,
                                                     "max_bytes": 1 << 20, "compression": None},
        "verified_on": "2026-11-18", "verification_status": "unverified", "evidence": [], "notes": None,
    }


SOURCES = [
    src("f-attack", "t-open", "mitre_attack_stix", ("attack_intelligence",)),
    src("f-kev", "t-open", "cisa_kev", ("vulnerability_intelligence",)),
    src("f-urlhaus", "t-open", "abusech_urlhaus_csv"),
    src("f-feodo", "t-open", "abusech_feodo_json", ("live_intel",)),
    src("f-tranco", "t-open", "tranco_csv"),
    src("f-iot23", "t-open", "zeek_conn_labeled", ("network_intelligence",)),
    src("f-cic", "t-research", "cicflowmeter_csv", ("network_intelligence",)),
    src("f-iocv1", "t-cc-by-sa", "hookprobe_ioc_v1", ("live_intel",)),
    src("f-dga", "t-open", "domain_list"),
    src("f-phiusiil", "t-open", "phiusiil_csv"),
    src("f-umudga", "t-open", "domain_list"),
    src("hookprobe-synthetic-soc", "agpl-3.0-only", None, ("soc_reasoning",)),
]

FIXTURE_FILES = {
    "f-attack": "stix_bundle.json", "f-kev": "kev.json", "f-urlhaus": "urlhaus.csv", "f-feodo": "feodo.json",
    "f-tranco": "tranco.csv", "f-iot23": "zeek/CTU-IoT-Fixture-1-1/conn.log.labeled", "f-cic": "cic.csv",
    "f-iocv1": "ioc-v1.json", "f-dga": "dga/necurs.txt",
    "f-phiusiil": "phiusiil.csv", "f-umudga": "umudga/gozi_gpl/1000.txt",
}


class Sandbox:
    """A temp data root + a temp registry dir (collections copied from the real registry)."""

    def __init__(self):
        self.dir = tempfile.mkdtemp(prefix="heqk-intel-test-")
        self.data = os.path.join(self.dir, "data")
        self.reg = os.path.join(self.dir, "registry")
        os.makedirs(self.reg)
        with open(os.path.join(REGISTRY_DIR, "collections.json"), encoding="utf-8") as f:
            cols = json.load(f)
        for c in cols["entries"]:
            # the fixture sources replace the real ones; membership must agree both ways (Registry.check)
            c["sources"] = sorted(s["id"] for s in SOURCES if c["id"] in (s.get("collections") or []))
        self._dump("collections.json", cols)
        self._dump("sources.json", {"schema": "heqk.source/1", "entries": sorted(SOURCES, key=lambda x: x["id"])})
        self._dump("licenses.json", {"schema": "heqk.license/1", "entries": sorted(LICENSES, key=lambda x: x["id"])})

    def _dump(self, name, doc):
        with open(os.path.join(self.reg, name), "w", encoding="utf-8") as f:
            json.dump(doc, f, indent=1)

    def close(self):
        for root, dirs, files in os.walk(self.dir):
            for n in dirs + files:
                try:
                    os.chmod(os.path.join(root, n), 0o755)
                except OSError:
                    pass
        shutil.rmtree(self.dir, ignore_errors=True)
