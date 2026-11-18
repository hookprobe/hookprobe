# SPDX-License-Identifier: AGPL-3.0-only
"""Source adapters: raw acquisition -> heqk.security-event/1 records.

An adapter is a generator `parse(path, ctx) -> Iterator[Record | Reject]`. It reads only with the
safeio parsers, keeps the source's own identifiers (source_record_id) and raw label (original_label),
and never guesses a label the source did not give. Bumping an adapter's VERSION changes every
record_id it produces, so changed parsing never silently mixes with old output.
"""
import importlib

from .. import canon

# adapter name -> module (each module defines VERSION and parse)
NAMES = (
    "mitre_attack_stix",
    "cisa_kev",
    "abusech_urlhaus_csv",
    "abusech_feodo_json",
    "tranco_csv",
    "zeek_conn_labeled",
    "cicflowmeter_csv",
    "hookprobe_ioc_v1",
    "domain_list",
)


def get(name):
    if name not in NAMES:
        raise KeyError(f"unknown adapter {name!r}")
    return importlib.import_module(f"{__name__}.{name}")


class Reject:
    __slots__ = ("line", "reason", "raw")

    def __init__(self, line, reason, raw=None):
        self.line, self.reason, self.raw = line, reason, (raw[:300] if isinstance(raw, str) else None)


class Ctx:
    """What an adapter needs to stamp provenance on its records."""

    def __init__(self, source, acquisition, adapter_name, adapter_version, pseudonym_key):
        self.source = source
        self.acq = acquisition
        self.adapter = adapter_name
        self.version = adapter_version
        self.key = pseudonym_key
        # Deterministic: the acquisition time, not the wall clock, so re-normalising the same raw file
        # with the same adapter version reproduces byte-identical records.
        self.created_at = acquisition["fetched_at"]

    def record(self, kind, body, *, source_record_id=None, raw_bytes=None, observed_at=None, label=None,
               family=None, label_source="none", original_label=None, techniques=(), tactics=(),
               mapping_source="none", sensor_type="dataset", attack_version=None):
        raw_sha = canon.sha256_bytes(raw_bytes) if raw_bytes is not None else None
        key = source_record_id if source_record_id is not None else raw_sha
        if key is None:
            raise ValueError("a record needs a source_record_id or its raw bytes")
        rid = canon.sha256_obj([self.source["id"], str(key), self.adapter, self.version])[:24]
        return {
            "schema": "heqk.security-event/1",
            "record_id": f"{kind}:{rid}",
            "kind": kind,
            "observed_at": observed_at,
            "sensor": {"type": sensor_type, "name": self.source["id"]},
            "body": body,
            "labels": {
                "label": label,
                "family": family,
                "label_source": label_source,
                "original_label": original_label,
                "attack_mapping": {
                    "framework": "MITRE ATT&CK",
                    "version": attack_version,
                    "techniques": sorted(set(techniques)),
                    "tactics": sorted(set(tactics)),
                    "mapping_source": mapping_source if (techniques or tactics) else "none",
                },
            },
            "provenance": {
                "source_id": self.source["id"],
                "source_record_id": None if source_record_id is None else str(source_record_id)[:512],
                "acquisition_id": self.acq["acquisition_id"],
                "raw_sha256": raw_sha,
                "license_id": self.acq["license_id"],
                "transform": {"name": self.adapter.replace("_", "-"), "version": self.version},
                "created_at": self.created_at,
            },
        }


def empty_mapping():
    return {"framework": "MITRE ATT&CK", "version": None, "techniques": [], "tactics": [], "mapping_source": "none"}
