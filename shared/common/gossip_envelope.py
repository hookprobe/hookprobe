"""Canonical HMAC gossip envelope — single source of truth for the on-wire
authentication envelope shared by DSM gossip and Mesh consciousness.

Both subsystems independently produced the *byte-identical* envelope

    json.dumps({"body": <utf-8 body>, "mac": <hmac-sha256 hexdigest of body>})

and a comment in consciousness.py even asserted it was "DSM-compatible" — but
the two copies were hand-synced and could silently drift, breaking cross-tier
gossip. This module makes the format authoritative; the verify *policy* (raise
vs. lenient, accept-unsigned vs. reject) stays with each caller because they
legitimately differ.

Pure stdlib so it is safe to vendor into Sentinel / the DSM container.
"""
from __future__ import annotations

import hashlib
import hmac
import json
from dataclasses import dataclass
from typing import Optional

__all__ = ["sign_envelope", "open_envelope", "OpenedEnvelope"]


def sign_envelope(key: bytes, body: bytes) -> bytes:
    """Wrap ``body`` in the canonical HMAC-SHA256 envelope.

    Produces exactly ``{"body": <body-as-utf8-str>, "mac": <hexdigest>}`` so it
    is byte-compatible with both prior implementations. ``body`` must be valid
    UTF-8 (it always is in practice: callers pass JSON).
    """
    mac = hmac.new(key, body, hashlib.sha256).hexdigest()
    return json.dumps({"body": body.decode("utf-8"), "mac": mac}).encode("utf-8")


@dataclass
class OpenedEnvelope:
    """Result of :func:`open_envelope`.

    is_envelope: ``raw`` parsed as JSON with both ``body`` and ``mac`` present.
    verified:    MAC matched (only meaningful when ``is_envelope`` is True).
    body:        the inner body bytes when ``is_envelope`` else ``None``.
    raw:         the original input, unchanged.

    Callers apply their own policy: DSM raises on ``not is_envelope`` / ``not
    verified``; Mesh returns the body when verified, ``None`` on a bad MAC, and
    falls back to ``raw`` for non-envelope (unsigned) input.
    """

    is_envelope: bool
    verified: bool
    body: Optional[bytes]
    raw: bytes


def open_envelope(key: bytes, raw: bytes) -> OpenedEnvelope:
    """Parse and authenticate ``raw``; never raises. See :class:`OpenedEnvelope`."""
    try:
        obj = json.loads(raw.decode("utf-8"))
    except Exception:
        return OpenedEnvelope(is_envelope=False, verified=False, body=None, raw=raw)
    if isinstance(obj, dict) and "mac" in obj and "body" in obj:
        body = obj["body"].encode("utf-8")
        expected = hmac.new(key, body, hashlib.sha256).hexdigest()
        verified = hmac.compare_digest(str(obj["mac"]), expected)
        return OpenedEnvelope(is_envelope=True, verified=verified, body=body, raw=raw)
    return OpenedEnvelope(is_envelope=False, verified=False, body=None, raw=raw)
