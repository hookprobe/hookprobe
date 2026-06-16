"""Canonical ClickHouse HTTP client for HookProbe core subsystems.

Consolidates the ~28 per-module `_ch_post` / `_ch_query` copies that had
divergent timeouts, auth styles, and (worst of all) error handling — some
swallowed failures silently, which is how cno_emotion_log went 10 days stale
while the container reported "healthy".

Conventions (uniform for every caller):
  - Auth via X-ClickHouse-* headers, never in the URL/query string, so the
    password never lands in logs.
  - The SQL is sent in the POST body (GET is read-only in ClickHouse).
  - Connection comes from CLICKHOUSE_* env vars (same defaults every module
    already used).
  - Failures are logged at WARNING with the first 200 chars of the query and,
    for HTTP errors, the server's response body (schema mismatches, etc.).

Two entry points:
  - ch_query(sql)  -> Optional[str]   # SELECTs; response text, None on failure
  - ch_post(sql)   -> bool            # INSERT/DDL/command; True on HTTP 200
"""

from __future__ import annotations

import logging
import os
from typing import Optional
from urllib.error import HTTPError
from urllib.request import Request, urlopen

logger = logging.getLogger("hookprobe.clickhouse")

CH_HOST = os.environ.get("CLICKHOUSE_HOST", "127.0.0.1")
CH_PORT = os.environ.get("CLICKHOUSE_PORT", "8123")
CH_DB = os.environ.get("CLICKHOUSE_DB", "hookprobe_ids")
CH_USER = os.environ.get("CLICKHOUSE_USER", "ids")
CH_PASSWORD = os.environ.get("CLICKHOUSE_PASSWORD", "")

DEFAULT_TIMEOUT_S = int(os.environ.get("CLICKHOUSE_TIMEOUT_S", "10"))


def _build_request(sql: str, database: Optional[str]) -> Request:
    req = Request(f"http://{CH_HOST}:{CH_PORT}/", data=sql.encode("utf-8"))
    req.add_header("X-ClickHouse-User", CH_USER)
    req.add_header("X-ClickHouse-Key", CH_PASSWORD)
    req.add_header("X-ClickHouse-Database", database or CH_DB)
    req.add_header("Content-Type", "text/plain")
    return req


def ch_query(
    sql: str,
    timeout: int = DEFAULT_TIMEOUT_S,
    database: Optional[str] = None,
) -> Optional[str]:
    """Run a query (typically SELECT) and return the response text.

    Returns None on any failure (logged at WARNING).
    """
    try:
        with urlopen(_build_request(sql, database), timeout=timeout) as resp:
            return resp.read().decode("utf-8")
    except HTTPError as e:
        body = ""
        try:
            body = e.read(500).decode("utf-8", errors="replace")
        except Exception:
            pass
        logger.warning(
            "ClickHouse query rejected: status=%s body=%r query=%r",
            e.code, body, sql[:200],
        )
        return None
    except Exception as e:
        logger.warning("ClickHouse query failed: %s | query=%r", e, sql[:200])
        return None


def ch_post(
    sql: str,
    timeout: int = DEFAULT_TIMEOUT_S,
    database: Optional[str] = None,
) -> bool:
    """Run an INSERT / DDL / command. Returns True on HTTP 200, else False.

    Failures (network, auth, schema mismatch) are logged at WARNING with the
    server's response body so they are diagnosable from container logs.
    """
    try:
        with urlopen(_build_request(sql, database), timeout=timeout) as resp:
            if resp.status == 200:
                return True
            body = resp.read(500).decode("utf-8", errors="replace")
            logger.warning(
                "ClickHouse rejected write: status=%d body=%r query=%r",
                resp.status, body, sql[:200],
            )
            return False
    except HTTPError as e:
        body = ""
        try:
            body = e.read(500).decode("utf-8", errors="replace")
        except Exception:
            pass
        logger.warning(
            "ClickHouse rejected write: status=%s body=%r query=%r",
            e.code, body, sql[:200],
        )
        return False
    except Exception as e:
        logger.warning("ClickHouse POST failed: %s | query=%r", e, sql[:200])
        return False
