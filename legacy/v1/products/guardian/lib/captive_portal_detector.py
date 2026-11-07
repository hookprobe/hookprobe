#!/usr/bin/env python3
"""
HookProbe Guardian - Captive Portal Detector

Detects hotel/airport/cafe captive portals by probing well-known
connectivity check URLs and comparing responses to expected values.

Usage:
    from products.guardian.lib.captive_portal_detector import CaptivePortalDetector

    detector = CaptivePortalDetector()
    result = detector.check()
    if result.is_captive:
        print(f"Captive portal detected: {result.portal_type}")
        print(f"Redirect URL: {result.redirect_url}")
"""

import logging
import time
from dataclasses import dataclass, field
from typing import Optional, List
from urllib.request import urlopen, Request
from urllib.error import URLError, HTTPError

logger = logging.getLogger(__name__)

# Connectivity check endpoints used by major OS vendors
# Each has a known expected response when internet is available
PROBES = [
    {
        'name': 'apple',
        'url': 'http://captive.apple.com/hotspot-detect.html',
        'expected_status': 200,
        'expected_body': '<HTML><HEAD><TITLE>Success</TITLE></HEAD><BODY>Success</BODY></HTML>',
    },
    {
        'name': 'google',
        'url': 'http://connectivitycheck.gstatic.com/generate_204',
        'expected_status': 204,
        'expected_body': None,
    },
    {
        'name': 'microsoft',
        'url': 'http://www.msftconnecttest.com/connecttest.txt',
        'expected_status': 200,
        'expected_body': 'Microsoft Connect Test',
    },
]

PROBE_TIMEOUT = 5  # seconds per probe


@dataclass
class CaptivePortalResult:
    """Result of a captive portal detection check."""
    is_captive: bool = False
    redirect_url: Optional[str] = None
    portal_type: str = 'none'  # none, hotel, airport, generic
    confidence: float = 0.0
    probes_run: int = 0
    probes_captive: int = 0
    probes_failed: int = 0
    latency_ms: float = 0.0
    details: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            'is_captive': self.is_captive,
            'redirect_url': self.redirect_url,
            'portal_type': self.portal_type,
            'confidence': round(self.confidence, 2),
            'probes_run': self.probes_run,
            'probes_captive': self.probes_captive,
            'probes_failed': self.probes_failed,
            'latency_ms': round(self.latency_ms, 1),
        }


class CaptivePortalDetector:
    """Detects captive portals by probing OS connectivity check URLs.

    When a captive portal is active, HTTP requests to known endpoints
    are redirected (302/307) to the portal login page, or return
    unexpected content (HTML login form instead of expected response).
    """

    def __init__(self, timeout: int = PROBE_TIMEOUT):
        self.timeout = timeout

    def check(self) -> CaptivePortalResult:
        """Run all probes and return detection result.

        Returns CaptivePortalResult with is_captive=True if any probe
        detects a captive portal redirect or unexpected response.
        """
        result = CaptivePortalResult()
        start = time.monotonic()
        redirect_urls = []

        for probe in PROBES:
            result.probes_run += 1
            try:
                probe_result = self._run_probe(probe)
                if probe_result == 'captive':
                    result.probes_captive += 1
                elif probe_result == 'failed':
                    result.probes_failed += 1
                # probe_result is redirect URL if captive via redirect
                if isinstance(probe_result, str) and probe_result.startswith('http'):
                    result.probes_captive += 1
                    redirect_urls.append(probe_result)
            except Exception as e:
                logger.debug("Probe %s error: %s", probe['name'], e)
                result.probes_failed += 1

        result.latency_ms = (time.monotonic() - start) * 1000

        # Determine if captive portal is present
        if result.probes_captive > 0:
            result.is_captive = True
            result.confidence = result.probes_captive / max(1, result.probes_run - result.probes_failed)
            if redirect_urls:
                result.redirect_url = redirect_urls[0]
                result.portal_type = self._classify_portal(redirect_urls[0])
            else:
                result.portal_type = 'generic'

        logger.info(
            "Captive portal check: captive=%s confidence=%.0f%% probes=%d/%d",
            result.is_captive, result.confidence * 100,
            result.probes_captive, result.probes_run
        )
        return result

    def _run_probe(self, probe: dict) -> str:
        """Run a single connectivity probe.

        Returns:
            'ok' - Internet is working normally
            'captive' - Captive portal detected (unexpected response)
            'failed' - Probe failed (network down)
            URL string - Redirect URL (captive portal redirect)
        """
        req = Request(probe['url'], headers={'User-Agent': 'CaptiveNetworkSupport/1.0'})

        try:
            response = urlopen(req, timeout=self.timeout)
        except HTTPError as e:
            # 3xx redirects may raise HTTPError with redirect info
            if 300 <= e.code < 400:
                redirect_url = e.headers.get('Location', '')
                if redirect_url:
                    logger.debug("Probe %s: redirect to %s", probe['name'], redirect_url)
                    return redirect_url
            logger.debug("Probe %s: HTTP %d", probe['name'], e.code)
            return 'captive'
        except URLError as e:
            logger.debug("Probe %s: network error: %s", probe['name'], e.reason)
            return 'failed'

        status = response.status
        body = response.read().decode('utf-8', errors='replace').strip()

        # Check for redirect via response URL differing from request URL
        final_url = response.url
        if final_url and final_url != probe['url']:
            # Followed a redirect - captive portal
            logger.debug("Probe %s: redirected to %s", probe['name'], final_url)
            return final_url

        # Check status code
        if status != probe['expected_status']:
            logger.debug("Probe %s: expected %d got %d", probe['name'], probe['expected_status'], status)
            return 'captive'

        # Check body content
        if probe['expected_body'] and probe['expected_body'] not in body:
            logger.debug("Probe %s: unexpected body (len=%d)", probe['name'], len(body))
            return 'captive'

        return 'ok'

    def _classify_portal(self, url: str) -> str:
        """Classify the portal type from the redirect URL."""
        url_lower = url.lower()

        hotel_keywords = ['hotel', 'hilton', 'marriott', 'hyatt', 'inn', 'lodge', 'resort']
        airport_keywords = ['airport', 'airline', 'terminal', 'boingo', 'gogo', 'inflight']
        cafe_keywords = ['starbucks', 'coffee', 'cafe', 'mcdonalds']

        for kw in hotel_keywords:
            if kw in url_lower:
                return 'hotel'
        for kw in airport_keywords:
            if kw in url_lower:
                return 'airport'
        for kw in cafe_keywords:
            if kw in url_lower:
                return 'cafe'

        return 'generic'
