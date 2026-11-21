"""Shared /healthz readiness helper for HYDRA / CNO / AEGIS / NAPSE services.

Ch 22 §6.2 non-negotiable: every service must expose readiness that tells
the difference between "process is alive" and "pipeline stage is ingesting".
This module provides that in a single ~150-line drop-in.

Usage:
    from core.common.health import HealthReporter, start_health_server

    reporter = HealthReporter(service="hydra-anomaly")
    start_health_server(reporter, port=9301)

    # as the service runs:
    reporter.model_loaded = True          # after successful load
    reporter.bump_ingest()                 # on every processed record
    reporter.backlog_size = queue.qsize()  # where applicable

Response shape on GET /healthz:
    200 OK if model_loaded AND (now - last_ingest_ts) < stale_threshold_s
    503 Service Unavailable otherwise (with reason in JSON body)

    {
      "service":        "hydra-anomaly",
      "status":         "ok" | "unhealthy",
      "reason":         "...",                      // unhealthy only
      "model_loaded":   true,
      "last_ingest_ts": "2026-04-18T13:22:17.234Z",
      "last_ingest_age_s": 0.9,
      "backlog_size":   0,
      "uptime_s":       123.4,
      "version":        1
    }

A second endpoint GET /metrics emits a minimal Prometheus line-format
representation of the same data. Enough for alerting, without pulling in
a full prometheus_client dependency.
"""
from __future__ import annotations

import http.server
import json
import logging
import os
import socketserver
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional


log = logging.getLogger("core.common.health")


DEFAULT_STALE_THRESHOLD_S = float(os.environ.get("HP_HEALTH_STALE_S", "300"))


@dataclass
class HealthReporter:
    """Thread-safe state bag services write into; the HTTP handler reads."""
    service: str = "unknown"
    model_loaded: bool = False
    last_ingest_ts: float = 0.0           # epoch seconds; 0 = never
    backlog_size: int = 0
    stale_threshold_s: float = DEFAULT_STALE_THRESHOLD_S
    start_time: float = field(default_factory=time.time)
    extra: dict = field(default_factory=dict)
    _lock: threading.Lock = field(default_factory=threading.Lock)

    def bump_ingest(self, n: int = 1) -> None:
        """Call on every successful record processed."""
        with self._lock:
            self.last_ingest_ts = time.time()

    def set_model_loaded(self, loaded: bool = True) -> None:
        with self._lock:
            self.model_loaded = loaded

    def set_backlog(self, size: int) -> None:
        with self._lock:
            self.backlog_size = int(size)

    def snapshot(self) -> dict:
        now = time.time()
        with self._lock:
            last = self.last_ingest_ts
            model = self.model_loaded
            backlog = self.backlog_size
            extra = dict(self.extra)
        age_s = (now - last) if last > 0 else None
        healthy = True
        reason = ""
        if not model:
            healthy = False
            reason = "model_not_loaded"
        elif last > 0 and age_s is not None and age_s > self.stale_threshold_s:
            healthy = False
            reason = f"no_ingest_for_{int(age_s)}s"
        elif last == 0:
            # Still warming up — don't fail readiness yet, but mark as such
            healthy = True
            reason = "warming_up"
        body = {
            "service": self.service,
            "status": "ok" if healthy else "unhealthy",
            "model_loaded": model,
            "last_ingest_ts": (
                datetime.fromtimestamp(last, tz=timezone.utc)
                .isoformat(timespec="milliseconds")
                if last > 0 else None
            ),
            "last_ingest_age_s": round(age_s, 2) if age_s is not None else None,
            "backlog_size": backlog,
            "uptime_s": round(now - self.start_time, 2),
            "version": 1,
        }
        if reason:
            body["reason"] = reason
        if extra:
            body["extra"] = extra
        return body

    def prometheus_lines(self) -> list[str]:
        snap = self.snapshot()
        svc = snap["service"]
        lines = [
            f'# HELP hp_service_up Service readiness (1=ok, 0=unhealthy)',
            f'# TYPE hp_service_up gauge',
            f'hp_service_up{{service="{svc}"}} {1 if snap["status"] == "ok" else 0}',
            f'# HELP hp_model_loaded Model artifact loaded (1/0)',
            f'# TYPE hp_model_loaded gauge',
            f'hp_model_loaded{{service="{svc}"}} {1 if snap["model_loaded"] else 0}',
            f'# HELP hp_last_ingest_age_seconds Seconds since last processed record',
            f'# TYPE hp_last_ingest_age_seconds gauge',
            f'hp_last_ingest_age_seconds{{service="{svc}"}} '
            f'{snap["last_ingest_age_s"] if snap["last_ingest_age_s"] is not None else -1}',
            f'# HELP hp_backlog_size Pending work items in this service',
            f'# TYPE hp_backlog_size gauge',
            f'hp_backlog_size{{service="{svc}"}} {snap["backlog_size"]}',
            f'# HELP hp_uptime_seconds Process uptime',
            f'# TYPE hp_uptime_seconds gauge',
            f'hp_uptime_seconds{{service="{svc}"}} {snap["uptime_s"]}',
        ]
        return lines


class _Handler(http.server.BaseHTTPRequestHandler):
    reporter: Optional[HealthReporter] = None  # set per-server instance below

    def log_message(self, fmt, *args):  # quiet the access log
        log.debug("health http: " + fmt, *args)

    def do_GET(self):  # noqa: N802 (stdlib naming)
        if self.path == "/healthz":
            snap = self.reporter.snapshot() if self.reporter else {"status": "no_reporter"}
            status_code = 200 if snap.get("status") == "ok" else 503
            body = json.dumps(snap).encode("utf-8")
            self.send_response(status_code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        if self.path == "/metrics":
            lines = self.reporter.prometheus_lines() if self.reporter else []
            body = ("\n".join(lines) + "\n").encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; version=0.0.4")
            self.end_headers()
            self.wfile.write(body)
            return
        self.send_response(404)
        self.end_headers()


class _ThreadingServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = True


def start_health_server(reporter: HealthReporter, port: int,
                         bind: str = "0.0.0.0") -> None:
    """Start the HTTP server on a background daemon thread. Never raises
    on port bind failure — logs and continues (so a duplicate port in a
    dev setup doesn't wedge the whole service)."""
    handler_cls = type("BoundHandler", (_Handler,), {"reporter": reporter})
    try:
        server = _ThreadingServer((bind, port), handler_cls)
    except OSError as e:
        log.warning("health: cannot bind %s:%d: %s — skipping", bind, port, e)
        return

    def _run():
        try:
            log.info("health: serving on %s:%d for service=%s",
                     bind, port, reporter.service)
            server.serve_forever(poll_interval=1.0)
        except Exception as e:
            log.warning("health server loop exited: %s", e)

    t = threading.Thread(target=_run, name=f"health-{reporter.service}",
                          daemon=True)
    t.start()
