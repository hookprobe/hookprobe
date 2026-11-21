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
from urllib.parse import urlencode
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


# ---------------------------------------------------------------------------
# HYDRA-style helpers: query goes in the URL (?query=...), data/VALUES in the
# POST body. ClickHouse treats GET as read-only and silently downgrades
# oversized URL-encoded queries to GET (Error 164), so the body is used for
# bulk VALUES. These reproduce the behavior the core/hydra modules relied on.
# ---------------------------------------------------------------------------

def _url_request(query: str, body: bytes, database: Optional[str]) -> Request:
    full_url = f"http://{CH_HOST}:{CH_PORT}/?{urlencode({'query': query})}"
    req = Request(full_url, data=body)
    req.add_header("X-ClickHouse-User", CH_USER)
    req.add_header("X-ClickHouse-Key", CH_PASSWORD)
    req.add_header("X-ClickHouse-Database", database or CH_DB)
    if body:
        req.add_header("Content-Type", "text/plain")
    return req


def ch_select(query: str, fmt: str = "JSONEachRow",
              timeout: int = 30, database: Optional[str] = None) -> Optional[str]:
    """Run a SELECT (query in URL, optional FORMAT appended); return text or None."""
    if not CH_PASSWORD:
        return None
    full_query = query + (f" FORMAT {fmt}" if fmt else "")
    try:
        with urlopen(_url_request(full_query, b"", database), timeout=timeout) as resp:
            return resp.read().decode("utf-8")
    except HTTPError as e:
        body = ""
        try:
            body = e.read(500).decode("utf-8", errors="replace")
        except Exception:
            pass
        logger.warning("ClickHouse select rejected: status=%s body=%r query=%r",
                       e.code, body, query[:200])
        return None
    except Exception as e:
        logger.warning("ClickHouse select failed: %s | query=%r", e, query[:200])
        return None


def ch_query_with_body(query: str, data: str = "",
                       timeout: int = 10, database: Optional[str] = None) -> Optional[str]:
    """Run a query with the SQL in the URL and optional data in the POST body."""
    if not CH_PASSWORD:
        return None
    try:
        with urlopen(_url_request(query, data.encode("utf-8") if data else b"", database),
                     timeout=timeout) as resp:
            return resp.read().decode("utf-8")
    except Exception as e:
        logger.warning("ClickHouse query failed: %s | query=%r", e, query[:200])
        return None


def ch_insert(query: str, data: str = "",
              timeout: int = 30, database: Optional[str] = None) -> bool:
    """Run an INSERT. Splits 'INSERT ... VALUES <rows>' so the rows go in the
    POST body (avoids the URL-size GET downgrade). Returns True on success."""
    if not CH_PASSWORD:
        return False
    if data:
        # Caller passed the row tuples separately, e.g.
        #   ch_insert("INSERT INTO t (cols)", "('a'),('b')")
        # ClickHouse needs the VALUES keyword between the column list and the
        # body rows; without it the body parses as a syntax error at the first
        # '('. Append " VALUES" unless the caller already supplied it. (This was
        # the 2026-04 refactor regression that broke every engine INSERT.)
        head = query.rstrip()
        url_query = head if head.upper().endswith("VALUES") else head + " VALUES"
        body = data
    elif " VALUES " in query:
        # Single-string form: "INSERT ... VALUES <rows>" — split so the rows go
        # in the POST body (avoids the URL-size GET downgrade).
        head, _, rows = query.partition(" VALUES ")
        url_query, body = head + " VALUES", rows
    else:
        # DDL / command with no rows (ALTER, OPTIMIZE, TRUNCATE, ...).
        url_query, body = query, data
    try:
        with urlopen(_url_request(url_query, body.encode("utf-8") if body else b"", database),
                     timeout=timeout) as resp:
            resp.read()
        return True
    except HTTPError as e:
        body_err = ""
        try:
            body_err = e.read(500).decode("utf-8", errors="replace")
        except Exception:
            pass
        logger.warning("ClickHouse insert rejected: status=%s body=%r query=%r",
                       e.code, body_err, query[:200])
        return False
    except Exception as e:
        logger.warning("ClickHouse insert failed: %s | query=%r", e, query[:200])
        return False
