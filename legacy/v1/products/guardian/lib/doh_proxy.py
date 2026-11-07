#!/usr/bin/env python3
"""
Guardian DNS-over-HTTPS Proxy

Lightweight DoH proxy that receives plain DNS queries from dnsmasq on
127.0.0.1:5053 and forwards them encrypted over HTTPS to privacy-focused
DoH resolvers (Cloudflare, Quad9, Google).

This prevents hotel/airport/cafe WiFi operators from inspecting DNS queries,
which is a primary vector for:
- Traffic surveillance (seeing which sites you visit)
- DNS hijacking (redirecting you to fake login pages)
- Censorship (blocking specific domains)

Architecture:
    dnsmasq (127.0.0.1:53) → DoH Proxy (127.0.0.1:5053) → HTTPS → Resolver

Author: HookProbe Team
Version: 5.5.0
License: AGPL-3.0
"""

import base64
import logging
import os
import signal
import socket
import struct
import sys
import threading
import time
from typing import List, Optional
from urllib.request import Request, urlopen
from urllib.error import URLError

logger = logging.getLogger(__name__)

# DoH resolver endpoints (privacy-focused, tried in order)
# IMPORTANT: Use IP addresses, NOT hostnames, to avoid circular DNS dependency
# (system resolv.conf -> dnsmasq -> this proxy -> needs DNS to resolve hostname)
DOH_RESOLVERS = [
    'https://1.1.1.1/dns-query',              # Cloudflare (fastest)
    'https://9.9.9.9/dns-query',              # Quad9 (threat-blocking)
    'https://8.8.8.8/dns-query',              # Google (fallback)
]

# Configuration
LISTEN_HOST = '127.0.0.1'
LISTEN_PORT = 5053
DOH_TIMEOUT = 5  # seconds
MAX_DNS_SIZE = 4096
CACHE_SIZE = 5000
CACHE_MIN_TTL = 60  # seconds
CACHE_MAX_TTL = 3600  # 1 hour


class DNSCache:
    """Simple TTL-based DNS response cache."""

    def __init__(self, max_size: int = CACHE_SIZE):
        self._cache = {}
        self._lock = threading.Lock()
        self._max_size = max_size

    def get(self, query: bytes) -> Optional[bytes]:
        """Get cached response for a DNS query."""
        key = self._cache_key(query)
        with self._lock:
            entry = self._cache.get(key)
            if entry is None:
                return None
            response, expiry = entry
            if time.time() > expiry:
                del self._cache[key]
                return None
            return response

    def put(self, query: bytes, response: bytes):
        """Cache a DNS response with TTL from the response."""
        key = self._cache_key(query)
        ttl = self._extract_ttl(response)
        ttl = max(CACHE_MIN_TTL, min(ttl, CACHE_MAX_TTL))

        with self._lock:
            if len(self._cache) >= self._max_size:
                # Evict oldest entries
                now = time.time()
                expired = [k for k, (_, exp) in self._cache.items() if now > exp]
                for k in expired[:100]:
                    del self._cache[k]
                # If still full, evict random
                if len(self._cache) >= self._max_size:
                    keys = list(self._cache.keys())[:100]
                    for k in keys:
                        del self._cache[k]

            self._cache[key] = (response, time.time() + ttl)

    @staticmethod
    def _cache_key(query: bytes) -> bytes:
        """Extract cache key from DNS query (skip ID and flags)."""
        if len(query) > 4:
            return query[4:]  # Skip transaction ID (2) + flags (2)
        return query

    @staticmethod
    def _extract_ttl(response: bytes) -> int:
        """Extract minimum TTL from DNS response."""
        try:
            if len(response) < 12:
                return CACHE_MIN_TTL

            # Parse header
            qdcount = struct.unpack('>H', response[4:6])[0]
            ancount = struct.unpack('>H', response[6:8])[0]

            if ancount == 0:
                return CACHE_MIN_TTL

            # Skip questions
            offset = 12
            for _ in range(qdcount):
                while offset < len(response):
                    length = response[offset]
                    if length == 0:
                        offset += 5  # null + type(2) + class(2)
                        break
                    if length >= 0xC0:  # Pointer
                        offset += 6
                        break
                    offset += 1 + length

            # Parse answers for TTL
            min_ttl = CACHE_MAX_TTL
            for _ in range(min(ancount, 10)):
                if offset + 12 > len(response):
                    break
                # Skip name
                if response[offset] >= 0xC0:
                    offset += 2
                else:
                    while offset < len(response) and response[offset] != 0:
                        offset += 1 + response[offset]
                    offset += 1

                if offset + 10 > len(response):
                    break
                # type(2) + class(2) + ttl(4) + rdlength(2)
                ttl = struct.unpack('>I', response[offset + 4:offset + 8])[0]
                rdlength = struct.unpack('>H', response[offset + 8:offset + 10])[0]
                min_ttl = min(min_ttl, ttl)
                offset += 10 + rdlength

            return max(min_ttl, CACHE_MIN_TTL)
        except Exception:
            return CACHE_MIN_TTL


class DoHProxy:
    """DNS-over-HTTPS proxy server."""

    def __init__(
        self,
        listen_host: str = LISTEN_HOST,
        listen_port: int = LISTEN_PORT,
        resolvers: Optional[List[str]] = None,
    ):
        self.listen_host = listen_host
        self.listen_port = listen_port
        self.resolvers = resolvers or DOH_RESOLVERS
        self.cache = DNSCache()
        self._socket: Optional[socket.socket] = None
        self._running = False

        # Stats
        self.queries_total = 0
        self.queries_cached = 0
        self.queries_forwarded = 0
        self.queries_failed = 0

    def _forward_doh(self, dns_query: bytes) -> Optional[bytes]:
        """Forward DNS query to DoH resolver over HTTPS."""
        # RFC 8484: DNS query via HTTP GET with base64url encoding
        b64_query = base64.urlsafe_b64encode(dns_query).rstrip(b'=').decode()

        for resolver_url in self.resolvers:
            try:
                url = f"{resolver_url}?dns={b64_query}"
                req = Request(url, headers={
                    'Accept': 'application/dns-message',
                    'User-Agent': 'HookProbe-Guardian/5.5',
                })
                with urlopen(req, timeout=DOH_TIMEOUT) as resp:
                    if resp.status == 200:
                        return resp.read()
            except URLError:
                continue
            except Exception:
                continue

        return None

    def _handle_query(self, data: bytes, addr: tuple):
        """Handle a single DNS query."""
        self.queries_total += 1

        # Check cache first
        cached = self.cache.get(data)
        if cached:
            # Fix transaction ID in cached response
            response = data[:2] + cached[2:]
            self._socket.sendto(response, addr)
            self.queries_cached += 1
            return

        # Forward via DoH
        response = self._forward_doh(data)
        if response:
            self.cache.put(data, response)
            self._socket.sendto(response, addr)
            self.queries_forwarded += 1
        else:
            # Return SERVFAIL
            if len(data) >= 2:
                servfail = data[:2] + b'\x81\x82' + data[4:] if len(data) > 4 else data[:2] + b'\x81\x82'
                self._socket.sendto(servfail, addr)
            self.queries_failed += 1

    def start(self):
        """Start the DoH proxy server."""
        self._socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._socket.bind((self.listen_host, self.listen_port))
        self._socket.settimeout(1.0)
        self._running = True

        logger.info("DoH proxy listening on %s:%d -> %s",
                     self.listen_host, self.listen_port, self.resolvers[0])

        while self._running:
            try:
                data, addr = self._socket.recvfrom(MAX_DNS_SIZE)
                if data:
                    # Handle in thread to not block
                    threading.Thread(
                        target=self._handle_query,
                        args=(data, addr),
                        daemon=True
                    ).start()
            except socket.timeout:
                continue
            except Exception as e:
                if self._running:
                    logger.warning("DoH proxy error: %s", e)

    def stop(self):
        """Stop the proxy server."""
        self._running = False
        if self._socket:
            try:
                self._socket.close()
            except Exception:
                pass
        logger.info("DoH proxy stopped (total=%d, cached=%d, forwarded=%d, failed=%d)",
                     self.queries_total, self.queries_cached,
                     self.queries_forwarded, self.queries_failed)

    def get_stats(self) -> dict:
        """Get proxy statistics."""
        return {
            'running': self._running,
            'listen': f'{self.listen_host}:{self.listen_port}',
            'resolvers': self.resolvers,
            'queries_total': self.queries_total,
            'queries_cached': self.queries_cached,
            'queries_forwarded': self.queries_forwarded,
            'queries_failed': self.queries_failed,
            'cache_hit_rate': (
                f"{self.queries_cached / self.queries_total * 100:.1f}%"
                if self.queries_total > 0 else "0%"
            ),
        }


def main():
    """Run DoH proxy as standalone daemon."""
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s [%(name)s] %(levelname)s: %(message)s'
    )

    proxy = DoHProxy()

    def shutdown(sig, frame):
        logger.info("Shutting down (signal %d)", sig)
        proxy.stop()
        sys.exit(0)

    signal.signal(signal.SIGTERM, shutdown)
    signal.signal(signal.SIGINT, shutdown)

    proxy.start()


if __name__ == '__main__':
    main()
