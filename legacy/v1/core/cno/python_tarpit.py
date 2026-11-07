"""
Userspace TCP Tarpit — delays data on attacked connections.

Phase 9: Replaces the log-only tarpit stub in adaptive_camouflage.py.
Attacker opens connection → we accept → send SSH-like banner at 1 byte
per 5 seconds. Wastes attacker time and scanning tool resources.

Runs in a daemon thread. Activated by emotion level ≥ 4 (FEARFUL).
Deactivated when emotion drops below 3.

Ports: 23 (telnet), 445 (SMB), 3389 (RDP) — common attack targets.
"""

import asyncio
import logging
import socket
import threading
import time
from typing import Set, Optional

logger = logging.getLogger(__name__)

TARPIT_BANNER = b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.7\r\n"
DEFAULT_PORTS = [23, 445, 3389, 5900]
DEFAULT_DELAY_S = 5.0  # Seconds between bytes


class PythonTarpit:
    """Async tarpit that slows attacker connections."""

    def __init__(self, ports: Optional[list] = None, delay_s: float = DEFAULT_DELAY_S):
        self.ports = ports or DEFAULT_PORTS
        self.delay_s = delay_s
        self.active_ips: Set[str] = set()
        self._running = False
        self._loop: Optional[asyncio.AbstractEventLoop] = None
        self._thread: Optional[threading.Thread] = None
        self._stats = {
            'connections_total': 0,
            'connections_active': 0,
            'bytes_sent': 0,
            'ips_tarpitted': set(),
        }

    def start(self) -> None:
        """Start tarpit in a daemon thread."""
        if self._running:
            return
        self._running = True
        self._thread = threading.Thread(
            target=self._run_loop, daemon=True, name="cno-tarpit",
        )
        self._thread.start()
        logger.info("TARPIT: started on ports %s (%.1fs delay/byte)",
                     self.ports, self.delay_s)

    def stop(self) -> None:
        """Stop tarpit."""
        self._running = False
        if self._loop:
            self._loop.call_soon_threadsafe(self._loop.stop)
        self.active_ips.clear()
        logger.info("TARPIT: stopped (%d total connections served)",
                     self._stats['connections_total'])

    def get_stats(self) -> dict:
        return {
            'connections_total': self._stats['connections_total'],
            'connections_active': len(self.active_ips),
            'bytes_sent': self._stats['bytes_sent'],
            'unique_ips': len(self._stats['ips_tarpitted']),
            'ports': self.ports,
            'running': self._running,
        }

    def _run_loop(self) -> None:
        """Thread entry: create event loop and start servers."""
        self._loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self._loop)
        try:
            self._loop.run_until_complete(self._serve())
        except Exception as e:
            logger.error("TARPIT loop error: %s", e)
        finally:
            self._loop.close()

    async def _serve(self) -> None:
        """Start listening on all tarpit ports."""
        servers = []
        for port in self.ports:
            try:
                srv = await asyncio.start_server(
                    self._handle, '0.0.0.0', port,
                    reuse_address=True,
                )
                servers.append(srv)
            except OSError as e:
                # Port may be in use — skip it
                logger.warning("TARPIT: cannot bind port %d: %s", port, e)

        if not servers:
            logger.error("TARPIT: no ports available")
            return

        # Run until stopped
        while self._running:
            await asyncio.sleep(1.0)

        for srv in servers:
            srv.close()

    async def _handle(self, reader: asyncio.StreamReader,
                      writer: asyncio.StreamWriter) -> None:
        """Handle a single tarpit connection — send banner at 1 byte/delay."""
        peername = writer.get_extra_info('peername')
        client_ip = peername[0] if peername else 'unknown'

        self.active_ips.add(client_ip)
        self._stats['connections_total'] += 1
        self._stats['ips_tarpitted'].add(client_ip)
        logger.info("TARPIT: %s connected (active: %d)", client_ip, len(self.active_ips))

        try:
            # Drip-feed the banner one byte at a time
            for byte in TARPIT_BANNER:
                if not self._running:
                    break
                writer.write(bytes([byte]))
                await writer.drain()
                self._stats['bytes_sent'] += 1
                await asyncio.sleep(self.delay_s)

            # After banner, hold connection open indefinitely
            while self._running:
                try:
                    data = await asyncio.wait_for(reader.read(1), timeout=30)
                    if not data:
                        break
                except asyncio.TimeoutError:
                    # Send a single keepalive byte every 30s
                    writer.write(b'\n')
                    await writer.drain()
                    self._stats['bytes_sent'] += 1
        except (ConnectionResetError, BrokenPipeError):
            pass
        finally:
            self.active_ips.discard(client_ip)
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
            logger.info("TARPIT: %s disconnected (active: %d)",
                        client_ip, len(self.active_ips))
