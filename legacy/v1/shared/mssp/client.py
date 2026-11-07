"""
HookProbe MSSP Client — Single-contract piggyback architecture.

PROPRIETARY AND CONFIDENTIAL
Copyright (c) 2024-2026 HookProbe Technologies

Architecture:
    Everything goes through POST /api/nodes/heartbeat:
    - UP:   telemetry + findings + feedback
    - DOWN: next interval + signed recommendations

    Auth: X-API-Key header with hp_ prefixed key (issued during claim)
    Signing: HMAC-SHA256 derived from API key (domain-separated)
    Config: /etc/hookprobe/node.conf (MSSP_URL + API_KEY)
"""

import hashlib
import hmac
import json
import logging
import os
import threading
import time
from pathlib import Path
from typing import Callable, Optional

from .types import Feedback, Finding, Recommendation

logger = logging.getLogger(__name__)


class MSSPClient:
    """Unified MSSP client for all HookProbe edge nodes.

    Usage:
        mssp = MSSPClient()  # reads /etc/hookprobe/node.conf
        mssp.on_recommendation(handle_rec)
        mssp.start(collect_telemetry=my_telemetry_fn)
    """

    VERSION = '3.0.0'

    def __init__(self, api_key: str = None, mssp_url: str = None):
        self._api_key = api_key or self._load_config('API_KEY', '')
        self._url = mssp_url or self._load_config('MSSP_URL', 'https://mssp.hookprobe.com')

        # Derive signing key for recommendation verification (domain separation)
        self._signing_key = hmac.new(
            self._api_key.encode(), b'hookprobe-rec-v1', hashlib.sha256
        ).digest() if self._api_key else b''

        # Heartbeat state
        self._interval = 60
        self._backoff = 60
        self._consecutive_failures = 0
        self._running = False
        self._thread: Optional[threading.Thread] = None

        # Pending intelligence data (thread-safe)
        self._pending_findings: list[Finding] = []
        self._pending_feedback: list[Feedback] = []
        self._lock = threading.Lock()

        # Recommendation callback
        self._on_recommendation: Optional[Callable[[Recommendation], None]] = None

        # Gateway endpoint (discovered via heartbeat response)
        self.gateway_endpoint: str = ""

        if self._api_key:
            logger.info("MSSP client initialized: %s", self._url)
        else:
            logger.warning("MSSP client has no API key — heartbeats will fail")

    @staticmethod
    def _load_config(key: str, default: str) -> str:
        """Load config value from environment or /etc/hookprobe/node.conf."""
        val = os.environ.get(key)
        if val:
            return val

        conf = Path('/etc/hookprobe/node.conf')
        if conf.exists():
            try:
                for line in conf.read_text().splitlines():
                    stripped = line.strip()
                    if stripped.startswith(f'{key}='):
                        return stripped.split('=', 1)[1].strip().strip('"\'')
            except Exception as e:
                logger.debug("Could not read config %s: %s", key, e)

        return default

    # =========================================================================
    # Intelligence Queue
    # =========================================================================

    def queue_finding(self, finding: Finding) -> None:
        """Queue a threat finding for submission on next heartbeat."""
        with self._lock:
            self._pending_findings.append(finding)

    def queue_feedback(self, feedback: Feedback) -> None:
        """Queue execution feedback for submission on next heartbeat."""
        with self._lock:
            self._pending_feedback.append(feedback)

    def on_recommendation(self, callback: Callable[[Recommendation], None]) -> None:
        """Register a callback for verified recommendations."""
        self._on_recommendation = callback

    # =========================================================================
    # Heartbeat (the single communication endpoint)
    # =========================================================================

    def heartbeat(self, telemetry: dict) -> list[Recommendation]:
        """Single round trip: telemetry+findings+feedback up, recommendations down.

        Returns list of verified recommendations.
        """
        # Drain pending queues (thread-safe, batch up to 50)
        with self._lock:
            findings = self._pending_findings[:50]
            feedback = self._pending_feedback[:50]
            self._pending_findings = self._pending_findings[50:]
            self._pending_feedback = self._pending_feedback[50:]

        payload = {
            **telemetry,
            'findings': [f.to_dict() for f in findings] if findings else [],
            'feedback': [f.to_dict() for f in feedback] if feedback else [],
        }

        resp = self._post('/api/nodes/heartbeat', payload)
        if resp is None:
            # Re-queue on failure
            with self._lock:
                self._pending_findings = findings + self._pending_findings
                self._pending_feedback = feedback + self._pending_feedback
            return []

        # Success — reset backoff
        data = resp.get('data', {})
        self._interval = data.get('nextHeartbeat', 60)
        self._consecutive_failures = 0
        self._backoff = 60

        # Track gateway endpoint for VPN connections
        gw = data.get('gatewayEndpoint')
        if gw and isinstance(gw, str):
            self.gateway_endpoint = gw

        # Process recommendations
        recs = []
        for r in data.get('recommendations', []):
            try:
                rec = Recommendation.from_dict(r)
                if self._verify_sig(rec):
                    recs.append(rec)
                    if self._on_recommendation:
                        try:
                            self._on_recommendation(rec)
                        except Exception as e:
                            logger.error("Recommendation callback error: %s", e)
                else:
                    logger.warning("Invalid signature on recommendation %s — discarding", rec.id)
            except Exception as e:
                logger.warning("Failed to parse recommendation: %s", e)

        if recs:
            logger.info("Received %d verified recommendation(s)", len(recs))

        return recs

    # =========================================================================
    # Background Heartbeat Loop
    # =========================================================================

    def start(self, collect_telemetry: Callable[[], dict]) -> None:
        """Start background heartbeat loop.

        Args:
            collect_telemetry: Callable returning HeartbeatV2Request-compatible dict
        """
        if self._running:
            return
        self._running = True
        self._thread = threading.Thread(
            target=self._loop, args=(collect_telemetry,), daemon=True
        )
        self._thread.start()
        logger.info("Background heartbeat started (interval: %ds)", self._interval)

    def stop(self) -> None:
        """Stop background heartbeat loop."""
        self._running = False
        if self._thread:
            self._thread.join(timeout=5)

    def _loop(self, collect_telemetry: Callable[[], dict]) -> None:
        while self._running:
            try:
                telemetry = collect_telemetry()
                self.heartbeat(telemetry)
            except Exception as e:
                logger.error("Heartbeat error: %s", e)
                self._consecutive_failures += 1

                if self._consecutive_failures >= 10:
                    logger.critical(
                        "10 consecutive heartbeat failures — stopping. Check API_KEY and MSSP_URL."
                    )
                    self._running = False
                    return

                # Exponential backoff: 60s → 120s → 240s → ... → max 1h
                self._backoff = min(self._backoff * 2, 3600)

            sleep_time = self._backoff if self._consecutive_failures > 0 else self._interval
            time.sleep(sleep_time)

    # =========================================================================
    # HTTP Transport
    # =========================================================================

    def _post(self, path: str, payload: dict) -> Optional[dict]:
        import urllib.error
        import urllib.request

        url = f"{self._url.rstrip('/')}{path}"
        data = json.dumps(payload).encode('utf-8')

        req = urllib.request.Request(url, data=data, method='POST', headers={
            'Content-Type': 'application/json',
            'X-API-Key': self._api_key,
            'User-Agent': f'HookProbe/{self.VERSION}',
        })

        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                if resp.status in (200, 201):
                    return json.loads(resp.read().decode('utf-8'))
                else:
                    logger.warning("MSSP returned %d for %s", resp.status, path)
                    return None
        except urllib.error.HTTPError as e:
            if e.code in (401, 403):
                logger.error("MSSP auth failed (HTTP %d) — check API_KEY in /etc/hookprobe/node.conf", e.code)
            else:
                logger.warning("MSSP HTTP %d for %s", e.code, path)
            return None
        except urllib.error.URLError as e:
            logger.debug("MSSP connection error: %s", e.reason)
            return None
        except Exception as e:
            logger.debug("MSSP request error: %s", e)
            return None

    # =========================================================================
    # Signature Verification
    # =========================================================================

    def _verify_sig(self, rec: Recommendation) -> bool:
        """Verify HMAC-SHA256 signature on a recommendation.

        The signing key is derived from the API key:
            signing_key = HMAC-SHA256(api_key, "hookprobe-rec-v1")
        The signature covers all fields except 'sig', canonicalized as sorted JSON.
        """
        if not rec.sig or not self._signing_key:
            return False

        payload = json.dumps(
            {k: v for k, v in rec.to_dict().items() if k != 'sig'},
            sort_keys=True
        )
        expected = hmac.new(
            self._signing_key, payload.encode('utf-8'), hashlib.sha256
        ).hexdigest()

        return hmac.compare_digest(expected, rec.sig)

    # =========================================================================
    # Health & Stats
    # =========================================================================

    @property
    def is_running(self) -> bool:
        return self._running

    @property
    def pending_count(self) -> int:
        with self._lock:
            return len(self._pending_findings) + len(self._pending_feedback)
