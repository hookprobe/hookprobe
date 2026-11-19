# SPDX-License-Identifier: AGPL-3.0-only
"""heqkdata — the HEQK Security Intelligence data foundation (tools/intel-data).

Standard library only, run with ``python3 -I`` (the convention of tools/neuro-research and tools/ci).
Nothing here trains a model, touches a device, or executes downloaded content.
"""
import os

VERSION = "0.1.0"

PKG_DIR = os.path.dirname(os.path.abspath(__file__))
TOOL_DIR = os.path.dirname(PKG_DIR)
SCHEMA_DIR = os.path.join(TOOL_DIR, "schemas")
REGISTRY_DIR = os.path.join(TOOL_DIR, "registry")
SAMPLES_DIR = os.path.join(TOOL_DIR, "samples")

SCHEMA_IDS = {
    "common": "common.schema.json",
    "dns-event": "dns-event.schema.json",
    "network-flow": "network-flow.schema.json",
    "indicator": "indicator.schema.json",
    "vulnerability": "vulnerability.schema.json",
    "attack-technique": "attack-technique.schema.json",
    "security-event": "security-event.schema.json",
    "training-example": "training-example.schema.json",
    "source": "source.schema.json",
    "license": "license.schema.json",
    "collection": "collection.schema.json",
    "manifest": "manifest.schema.json",
}


def data_root():
    """Where acquired (raw) and derived data live. NEVER inside the repository: real data is not committed."""
    root = os.environ.get("HEQK_INTEL_DATA") or os.path.join(os.path.expanduser("~"), ".cache", "hookprobe-intel-data")
    return os.path.abspath(root)
