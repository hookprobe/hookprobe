#!/usr/bin/env python3
"""
Efficiency Engine - Central coordinator for AI Autopilot.

This is the brain of the event-driven architecture. It coordinates:
- DHCP Sentinel (new device triggers)
- OVS MAC Watcher (unknown device detection)
- On-Demand Probe (burst capture)
- IPFIX Collector (D2D relationships)
- Ecosystem Bubble (automatic assignment)
- n8n Webhooks (workflow automation)

The engine implements the "Sleep-and-Wake" pattern:
- Idle State: <1% CPU, sentinels watching
- Active State: 10% CPU burst for 60s, then return to idle

Dashboard Integration:
- Shows "Network Activity Light":
  - 🟢 Green: Idle (saving power)
  - 🔵 Blue Pulse: Identifying new device
  - 🛡️ Gold Shield: Bubble protection active

Copyright (c) 2024-2026 HookProbe Security
"""

import os
import sys
import json
import asyncio
import logging
from pathlib import Path
from enum import Enum
from datetime import datetime, timedelta
from dataclasses import dataclass, field
from typing import Optional, List, Dict, Any, Callable
from threading import Thread, Lock
import time

# Local imports
from .dhcp_sentinel import (
    DHCPSentinel, DHCPEvent, DHCPEventType,
    get_dhcp_sentinel,
)
from .mac_watcher import (
    OVSMACWatcher, MACEvent, MACEventType,
    get_mac_watcher,
)
from .probe_service import (
    OnDemandProbe, ProbeResult, ProbeConfig,
    get_probe_service,
)
from .ipfix_collector import (
    IPFIXCollector, D2DFlow,
    get_ipfix_collector,
)

# Configuration
CONFIG_FILE = Path(os.getenv('FORTRESS_CONFIG', '/etc/hookprobe/fortress.conf'))
LOG_FILE = Path('/var/log/fortress/efficiency-engine.log')
STATE_FILE = Path('/run/fortress/autopilot-state.json')

# N8N webhook URLs
N8N_DEVICE_WEBHOOK = os.getenv('N8N_DEVICE_WEBHOOK', 'http://localhost:5678/webhook/device-event')
N8N_BUBBLE_WEBHOOK = os.getenv('N8N_BUBBLE_WEBHOOK', 'http://localhost:5678/webhook/bubble-event')

logger = logging.getLogger('efficiency_engine')


class AutopilotState(Enum):
    """Autopilot operational states."""
    SLEEPING = 'sleeping'           # Idle, sentinels watching (green light)
    IDENTIFYING = 'identifying'     # Processing new device (blue pulse)
    PROTECTED = 'protected'         # All devices in bubbles (gold shield)
    ANALYZING = 'analyzing'         # D2D relationship analysis
    ERROR = 'error'                 # Error state


@dataclass
class AutopilotConfig:
    """Configuration for the Efficiency Engine."""
    # Probe settings
    probe_duration: int = 60        # Seconds for burst capture
    probe_cooldown: int = 300       # Minimum seconds between probes for same MAC

    # Watcher settings
    mac_poll_interval: int = 5      # Seconds between MAC table checks
    dhcp_enabled: bool = True
    mac_watcher_enabled: bool = True

    # IPFIX settings
    ipfix_enabled: bool = True
    ipfix_port: int = 4739
    ipfix_flush_interval: int = 30

    # Integration settings
    n8n_enabled: bool = True
    clickhouse_enabled: bool = True

    # Auto-bubble settings
    auto_bubble_enabled: bool = True
    auto_bubble_confidence: float = 0.7  # Minimum confidence for auto-assignment
    guest_bubble_default: bool = True    # Put unknown devices in guest bubble

    @classmethod
    def from_file(cls, path: Path = CONFIG_FILE) -> 'AutopilotConfig':
        """Load configuration from file."""
        config = cls()

        if path.exists():
            try:
                with open(path) as f:
                    for line in f:
                        line = line.strip()
                        if '=' in line and not line.startswith('#'):
                            key, value = line.split('=', 1)
                            key = key.strip().lower()
                            value = value.strip().strip('"\'')

                            if key == 'probe_duration':
                                config.probe_duration = int(value)
                            elif key == 'probe_cooldown':
                                config.probe_cooldown = int(value)
                            elif key == 'auto_bubble_enabled':
                                config.auto_bubble_enabled = value.lower() == 'true'
                            elif key == 'n8n_enabled':
                                config.n8n_enabled = value.lower() == 'true'
                            elif key == 'ipfix_enabled':
                                config.ipfix_enabled = value.lower() == 'true'

            except Exception as e:
                logger.warning(f"Config load error: {e}")

        return config


@dataclass
class DeviceIdentification:
    """Result of device identification process."""
    mac: str
    timestamp: datetime = field(default_factory=datetime.now)

    # From DHCP
    ip: Optional[str] = None
    hostname: Optional[str] = None
    os_fingerprint: Optional[str] = None

    # From Probe
    ecosystem: Optional[str] = None
    device_type: Optional[str] = None
    services: List[str] = field(default_factory=list)
    d2d_targets: List[str] = field(default_factory=list)

    # Bubble assignment
    bubble_id: Optional[str] = None
    bubble_confidence: float = 0.0
    auto_assigned: bool = False

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'mac': self.mac,
            'timestamp': self.timestamp.isoformat(),
            'ip': self.ip,
            'hostname': self.hostname,
            'os_fingerprint': self.os_fingerprint,
            'ecosystem': self.ecosystem,
            'device_type': self.device_type,
            'services': self.services,
            'd2d_targets': self.d2d_targets,
            'bubble_id': self.bubble_id,
            'bubble_confidence': self.bubble_confidence,
            'auto_assigned': self.auto_assigned,
        }


class EfficiencyEngine:
    """
    Central coordinator for the AI Autopilot event-driven architecture.

    Orchestrates all sentinels and manages the device identification workflow.
    """

    def __init__(self, config: Optional[AutopilotConfig] = None):
        self.config = config or AutopilotConfig.from_file()
        self._state = AutopilotState.SLEEPING
        self._running = False
        self._lock = Lock()

        # Recent probes (for cooldown)
        self._recent_probes: Dict[str, datetime] = {}

        # Pending identifications
        self._pending: Dict[str, DeviceIdentification] = {}
        self._completed: List[DeviceIdentification] = []

        # Statistics
        self._stats = {
            'devices_identified': 0,
            'auto_assignments': 0,
            'probes_triggered': 0,
            'uptime_start': None,
            'state_changes': 0,
        }

        # Components (lazy loaded)
        self._dhcp_sentinel: Optional[DHCPSentinel] = None
        self._mac_watcher: Optional[OVSMACWatcher] = None
        self._probe_service: Optional[OnDemandProbe] = None
        self._ipfix_collector: Optional[IPFIXCollector] = None

        # Callbacks
        self._on_device_identified: List[Callable[[DeviceIdentification], None]] = []
        self._on_state_change: List[Callable[[AutopilotState], None]] = []

        self._init_logging()

    def _init_logging(self):
        """Initialize logging."""
        LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
        handler = logging.FileHandler(LOG_FILE)
        handler.setFormatter(logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        ))
        logger.addHandler(handler)
        logger.setLevel(logging.INFO)

    @property
    def state(self) -> AutopilotState:
        """Get current state."""
        return self._state

    def _set_state(self, new_state: AutopilotState):
        """Update state and notify callbacks."""
        if new_state != self._state:
            old_state = self._state
            self._state = new_state
            self._stats['state_changes'] += 1

            logger.info(f"State: {old_state.value} -> {new_state.value}")
            self._save_state()

            for callback in self._on_state_change:
                try:
                    callback(new_state)
                except Exception as e:
                    logger.error(f"State callback error: {e}")

    def _save_state(self):
        """Save current state to file for dashboard."""
        STATE_FILE.parent.mkdir(parents=True, exist_ok=True)

        state_data = {
            'state': self._state.value,
            'timestamp': datetime.now().isoformat(),
            'pending_count': len(self._pending),
            'recent_identifications': len(self._completed),
        }

        try:
            with open(STATE_FILE, 'w') as f:
                json.dump(state_data, f)
        except Exception as e:
            logger.warning(f"State save error: {e}")

    def _can_probe(self, mac: str) -> bool:
        """Check if MAC can be probed (respects cooldown)."""
        mac = mac.upper()
        last_probe = self._recent_probes.get(mac)

        if last_probe is None:
            return True

        cooldown = timedelta(seconds=self.config.probe_cooldown)
        return datetime.now() - last_probe > cooldown

    async def _handle_new_device(self, mac: str, ip: Optional[str] = None,
                                  hostname: Optional[str] = None,
                                  os_fingerprint: Optional[str] = None):
        """
        Handle new device detection.

        This is the main workflow for device identification:
        1. Create identification record
        2. Trigger probe capture
        3. Analyze results
        4. Assign to bubble
        5. Update SDN rules
        """
        mac = mac.upper()

        # Check cooldown
        if not self._can_probe(mac):
            logger.debug(f"Probe cooldown active for {mac}")
            return

        # Create identification record
        ident = DeviceIdentification(
            mac=mac,
            ip=ip,
            hostname=hostname,
            os_fingerprint=os_fingerprint,
        )

        with self._lock:
            self._pending[mac] = ident

        self._set_state(AutopilotState.IDENTIFYING)
        self._recent_probes[mac] = datetime.now()
        self._stats['probes_triggered'] += 1

        try:
            # Run probe
            if self._probe_service is None:
                self._probe_service = get_probe_service()

            config = ProbeConfig(
                mac=mac,
                duration=self.config.probe_duration,
            )

            logger.info(f"Starting probe for {mac}")
            result = await self._probe_service.capture_async(config)

            # Update identification with probe results
            ident.ecosystem = result.ecosystem
            ident.device_type = result.device_type
            ident.services = result.services
            ident.d2d_targets = result.d2d_targets

            if result.hostname:
                ident.hostname = result.hostname

            # Try to assign bubble
            await self._assign_bubble(ident, result)

            # Complete identification
            with self._lock:
                self._pending.pop(mac, None)
                self._completed.append(ident)
                if len(self._completed) > 100:
                    self._completed = self._completed[-100:]

            self._stats['devices_identified'] += 1

            # Notify callbacks
            for callback in self._on_device_identified:
                try:
                    callback(ident)
                except Exception as e:
                    logger.error(f"Identification callback error: {e}")

            # Send to n8n
            if self.config.n8n_enabled:
                await self._send_n8n_event('device_identified', ident.to_dict())

            logger.info(f"Device identified: {mac} -> {ident.ecosystem or 'unknown'}, "
                       f"bubble={ident.bubble_id}")

        except Exception as e:
            logger.error(f"Device handling error for {mac}: {e}")
        finally:
            # Update state
            with self._lock:
                if not self._pending:
                    self._set_state(AutopilotState.PROTECTED)

    async def _assign_bubble(self, ident: DeviceIdentification, probe_result: ProbeResult):
        """Assign device to a bubble based on probe results."""
        if not self.config.auto_bubble_enabled:
            return

        confidence = probe_result.confidence

        # Try to find matching bubble based on D2D targets
        if probe_result.d2d_targets:
            # Check if any D2D targets are already in a bubble
            try:
                # Use unified module from shared/aiochi/bubble
                try:
                    from shared.aiochi.bubble import get_bubble_manager
                except ImportError:
                    # Fallback to deprecated local module
                    from ..ecosystem_bubble import get_bubble_manager

                manager = get_bubble_manager()

                for target_mac in probe_result.d2d_targets:
                    target_bubble = manager.get_device_bubble(target_mac)
                    if target_bubble:
                        # Device communicates with something in a bubble
                        ident.bubble_id = target_bubble.bubble_id
                        ident.bubble_confidence = min(confidence + 0.2, 1.0)
                        ident.auto_assigned = True
                        self._stats['auto_assignments'] += 1

                        # Actually move the device
                        manager.add_device_to_bubble(ident.mac, target_bubble.bubble_id)
                        return

            except ImportError:
                logger.debug("Bubble manager not available")

        # Check ecosystem-based assignment
        if probe_result.ecosystem and confidence >= self.config.auto_bubble_confidence:
            try:
                # Use unified module from shared/aiochi/bubble
                try:
                    from shared.aiochi.bubble import get_bubble_manager, BubbleType
                except ImportError:
                    from ..ecosystem_bubble import get_bubble_manager, BubbleType

                manager = get_bubble_manager()

                # Find or create bubble for ecosystem
                bubbles = manager.get_bubbles_by_ecosystem(probe_result.ecosystem)
                if bubbles:
                    bubble = bubbles[0]
                    ident.bubble_id = bubble.bubble_id
                    ident.bubble_confidence = confidence
                    ident.auto_assigned = True
                    self._stats['auto_assignments'] += 1

                    manager.add_device_to_bubble(ident.mac, bubble.bubble_id)
                    return

            except ImportError:
                pass

        # Default to guest bubble if configured
        if self.config.guest_bubble_default and not ident.bubble_id:
            try:
                # Use unified module from shared/aiochi/bubble
                try:
                    from shared.aiochi.bubble import get_bubble_manager, BubbleType
                except ImportError:
                    from ..ecosystem_bubble import get_bubble_manager, BubbleType

                manager = get_bubble_manager()
                guest_bubbles = manager.get_bubbles_by_type(BubbleType.GUEST)

                if guest_bubbles:
                    ident.bubble_id = guest_bubbles[0].bubble_id
                    ident.bubble_confidence = 0.5
                    ident.auto_assigned = True

                    manager.add_device_to_bubble(ident.mac, guest_bubbles[0].bubble_id)

            except ImportError:
                pass

    async def _send_n8n_event(self, event_type: str, data: Dict[str, Any]):
        """Send event to n8n webhook."""
        try:
            import aiohttp

            payload = {
                'event': event_type,
                'source': 'efficiency_engine',
                'timestamp': datetime.now().isoformat(),
                'data': data,
            }

            async with aiohttp.ClientSession() as session:
                async with session.post(
                    N8N_DEVICE_WEBHOOK,
                    json=payload,
                    timeout=aiohttp.ClientTimeout(total=5),
                ) as resp:
                    if resp.status != 200:
                        logger.warning(f"n8n webhook failed: {resp.status}")

        except ImportError:
            # Fall back to requests
            self._send_n8n_sync(event_type, data)
        except Exception as e:
            logger.debug(f"n8n webhook error: {e}")

    def _send_n8n_sync(self, event_type: str, data: Dict[str, Any]):
        """Synchronous n8n webhook (fallback)."""
        try:
            import requests

            payload = {
                'event': event_type,
                'source': 'efficiency_engine',
                'timestamp': datetime.now().isoformat(),
                'data': data,
            }

            requests.post(
                N8N_DEVICE_WEBHOOK,
                json=payload,
                timeout=5,
            )
        except Exception as e:
            logger.debug(f"n8n sync webhook error: {e}")

    def _on_dhcp_event(self, event: DHCPEvent):
        """Handle DHCP event from sentinel."""
        if event.is_new_device:
            self._schedule_async_task(self._handle_new_device(
                mac=event.mac,
                ip=event.ip,
                hostname=event.hostname,
                os_fingerprint=event.os_fingerprint,
            ))

    def _on_unknown_mac(self, event: MACEvent):
        """Handle unknown MAC from watcher."""
        if event.is_unknown:
            self._schedule_async_task(self._handle_new_device(mac=event.mac))

    def _schedule_async_task(self, coro):
        """Schedule an async task from sync context.

        Handles the case where we're called from a sync callback
        but need to run an async coroutine.
        """
        try:
            loop = asyncio.get_running_loop()
            loop.create_task(coro)
        except RuntimeError:
            # No running loop - run in a new thread with its own loop
            def run_coro():
                asyncio.run(coro)
            thread = Thread(target=run_coro, daemon=True)
            thread.start()

    async def run_async(self):
        """Main async run loop."""
        self._running = True
        self._stats['uptime_start'] = datetime.now().isoformat()
        self._set_state(AutopilotState.SLEEPING)

        logger.info("Efficiency Engine starting")

        # Start components
        tasks = []

        # DHCP Sentinel
        if self.config.dhcp_enabled:
            self._dhcp_sentinel = get_dhcp_sentinel()
            self._dhcp_sentinel.on_new_device(self._on_dhcp_event)
            logger.info("DHCP Sentinel enabled")

        # MAC Watcher
        if self.config.mac_watcher_enabled:
            self._mac_watcher = get_mac_watcher()
            self._mac_watcher.on_unknown_mac(self._on_unknown_mac)
            tasks.append(asyncio.create_task(self._mac_watcher.watch_async()))
            logger.info("MAC Watcher enabled")

        # IPFIX Collector
        if self.config.ipfix_enabled:
            self._ipfix_collector = get_ipfix_collector()
            tasks.append(asyncio.create_task(self._ipfix_collector.listen_async()))
            logger.info("IPFIX Collector enabled")

        # Probe service (lazy loaded)
        self._probe_service = get_probe_service()

        self._set_state(AutopilotState.PROTECTED)

        try:
            # Keep running until stopped
            while self._running:
                await asyncio.sleep(1)

        finally:
            # Stop all tasks
            for task in tasks:
                task.cancel()
                try:
                    await task
                except asyncio.CancelledError:
                    pass

            logger.info("Efficiency Engine stopped")

    def run(self):
        """Blocking run."""
        asyncio.run(self.run_async())

    def start(self):
        """Start in background thread."""
        thread = Thread(target=self.run, daemon=True, name='efficiency-engine')
        thread.start()
        return thread

    def stop(self):
        """Stop the engine."""
        self._running = False
        if self._mac_watcher:
            self._mac_watcher.stop()
        if self._ipfix_collector:
            self._ipfix_collector.stop()

    def on_device_identified(self, callback: Callable[[DeviceIdentification], None]):
        """Register callback for device identification."""
        self._on_device_identified.append(callback)

    def on_state_change(self, callback: Callable[[AutopilotState], None]):
        """Register callback for state changes."""
        self._on_state_change.append(callback)

    def get_stats(self) -> Dict[str, Any]:
        """Get engine statistics."""
        return {
            'state': self._state.value,
            'running': self._running,
            'config': {
                'probe_duration': self.config.probe_duration,
                'auto_bubble_enabled': self.config.auto_bubble_enabled,
                'n8n_enabled': self.config.n8n_enabled,
            },
            'stats': self._stats,
            'pending_count': len(self._pending),
            'recent_identifications': len(self._completed),
            'components': {
                'dhcp_sentinel': self._dhcp_sentinel is not None,
                'mac_watcher': self._mac_watcher is not None,
                'ipfix_collector': self._ipfix_collector is not None,
                'probe_service': self._probe_service is not None,
            },
        }

    def get_recent_identifications(self, limit: int = 10) -> List[Dict[str, Any]]:
        """Get recent device identifications."""
        with self._lock:
            return [i.to_dict() for i in self._completed[-limit:]]


# Singleton instance
_engine_instance: Optional[EfficiencyEngine] = None
_engine_lock = Lock()


def get_efficiency_engine() -> EfficiencyEngine:
    """Get singleton Efficiency Engine instance."""
    global _engine_instance
    with _engine_lock:
        if _engine_instance is None:
            _engine_instance = EfficiencyEngine()
        return _engine_instance


def main():
    """CLI entry point."""
    import argparse

    parser = argparse.ArgumentParser(description='Efficiency Engine - AI Autopilot')
    parser.add_argument('--stats', action='store_true', help='Show statistics')
    parser.add_argument('--recent', type=int, help='Show recent identifications')
    parser.add_argument('--test-probe', help='Test probe for MAC address')
    parser.add_argument('--debug', action='store_true')

    args = parser.parse_args()

    if args.debug:
        logging.basicConfig(level=logging.DEBUG)
    else:
        logging.basicConfig(level=logging.INFO)

    engine = get_efficiency_engine()

    if args.stats:
        print(json.dumps(engine.get_stats(), indent=2))
        return

    if args.recent:
        idents = engine.get_recent_identifications(args.recent)
        print(json.dumps(idents, indent=2))
        return

    if args.test_probe:
        async def test():
            await engine._handle_new_device(args.test_probe)
            idents = engine.get_recent_identifications(1)
            print(json.dumps(idents, indent=2))

        asyncio.run(test())
        return

    # Run engine
    print("Starting Efficiency Engine...")
    print("State indicators:")
    print("  🟢 SLEEPING - Idle, sentinels watching")
    print("  🔵 IDENTIFYING - Processing new device")
    print("  🛡️ PROTECTED - All devices in bubbles")
    print()

    engine.run()


if __name__ == '__main__':
    main()
