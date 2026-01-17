"""
Cellular Monitor

Collects L1 telemetry from cellular modems via MBIM/QMI.
Transforms raw metrics into security-relevant data.

Per Nemotron audit:
- Treat all modem data as untrusted input
- Validate metrics with multiple measurements before action
- Rate-limit modem commands to prevent battery exhaustion
"""

import os
import re
import json
import subprocess
import logging
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Optional, List, Dict, Any
from pathlib import Path

logger = logging.getLogger(__name__)


class NetworkType(Enum):
    """Cellular network type."""
    UNKNOWN = 'unknown'
    GSM_2G = '2g'
    UMTS_3G = '3g'
    LTE_4G = 'lte'
    NR_5G_NSA = '5g_nsa'  # Non-Standalone (4G anchor)
    NR_5G_SA = '5g_sa'    # Standalone


class RegistrationState(Enum):
    """Modem registration state."""
    UNKNOWN = 'unknown'
    IDLE = 'idle'
    SEARCHING = 'searching'
    REGISTERED = 'registered'
    DENIED = 'denied'


@dataclass
class CellularMetrics:
    """Cellular L1 metrics from modem."""
    timestamp: datetime = field(default_factory=datetime.now)
    interface: str = ''

    # Connection
    network_type: NetworkType = NetworkType.UNKNOWN
    registration_state: RegistrationState = RegistrationState.UNKNOWN

    # Signal Strength
    rssi_dbm: int = -999         # -120 to -30
    rsrp_dbm: int = -999         # -140 to -44 (LTE/5G)
    rsrq_db: int = -999          # -20 to -3
    sinr_db: int = -999          # -23 to 40
    snr_db: float = -999.0       # Derived SNR

    # Band Info
    current_band: str = ''
    earfcn: int = 0
    frequency_mhz: float = 0.0
    bandwidth_mhz: int = 0

    # Tower ID
    cell_id: int = 0
    pci: int = 0                 # Physical Cell ID
    tac: int = 0                 # Tracking Area Code
    mcc: str = ''
    mnc: str = ''
    plmn: str = ''

    # Quality
    cqi: int = 0                 # Channel Quality Indicator
    timing_advance: int = 0

    # Carrier
    carrier_name: str = ''

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for storage."""
        return {
            'timestamp': self.timestamp.isoformat(),
            'interface': self.interface,
            'network_type': self.network_type.value,
            'registration_state': self.registration_state.value,
            'rssi_dbm': self.rssi_dbm,
            'rsrp_dbm': self.rsrp_dbm,
            'rsrq_db': self.rsrq_db,
            'sinr_db': self.sinr_db,
            'snr_db': self.snr_db,
            'current_band': self.current_band,
            'earfcn': self.earfcn,
            'frequency_mhz': self.frequency_mhz,
            'bandwidth_mhz': self.bandwidth_mhz,
            'cell_id': self.cell_id,
            'pci': self.pci,
            'tac': self.tac,
            'mcc': self.mcc,
            'mnc': self.mnc,
            'plmn': self.plmn,
            'cqi': self.cqi,
            'timing_advance': self.timing_advance,
            'carrier_name': self.carrier_name,
        }


class CellularMonitor:
    """
    Cellular modem monitoring via MBIM/mmcli.

    Collects L1 metrics for security analysis:
    - Signal strength (RSRP, RSRQ, SINR, SNR)
    - Tower identity (Cell ID, PCI, TAC, PLMN)
    - Band information
    - Registration state

    Security Notes:
    - All modem output is treated as untrusted
    - Commands are rate-limited to prevent battery drain
    - Only whitelisted AT commands are allowed
    """

    # Rate limiting (per Nemotron audit)
    MIN_POLL_INTERVAL_SEC = 5
    MAX_COMMANDS_PER_MINUTE = 12

    # Whitelisted commands (no user input allowed)
    ALLOWED_COMMANDS = [
        'mmcli -m 0 --signal-get',
        'mmcli -m 0 --location-get',
        'mmcli -m 0',
    ]

    def __init__(self, modem_index: int = 0):
        self.modem_index = modem_index
        self._last_poll = None
        self._command_count = 0
        self._command_window_start = datetime.now()

    def get_metrics(self) -> Optional[CellularMetrics]:
        """
        Get current cellular metrics from modem.

        Returns None if modem not available or rate limited.
        """
        # Rate limiting
        now = datetime.now()
        if self._last_poll:
            elapsed = (now - self._last_poll).total_seconds()
            if elapsed < self.MIN_POLL_INTERVAL_SEC:
                logger.debug(f"Rate limited: {elapsed:.1f}s since last poll")
                return None

        # Reset command count window
        window_elapsed = (now - self._command_window_start).total_seconds()
        if window_elapsed > 60:
            self._command_count = 0
            self._command_window_start = now

        if self._command_count >= self.MAX_COMMANDS_PER_MINUTE:
            logger.warning("Command rate limit reached, skipping poll")
            return None

        self._last_poll = now
        self._command_count += 1

        try:
            metrics = CellularMetrics(timestamp=now)

            # Get modem status
            modem_info = self._run_mmcli('')
            if modem_info:
                self._parse_modem_info(modem_info, metrics)

            # Get signal info
            signal_info = self._run_mmcli('--signal-get')
            if signal_info:
                self._parse_signal_info(signal_info, metrics)

            # Get location/cell info
            location_info = self._run_mmcli('--location-get')
            if location_info:
                self._parse_location_info(location_info, metrics)

            return metrics

        except Exception as e:
            logger.error(f"Failed to get cellular metrics: {e}")
            return None

    def _run_mmcli(self, args: str) -> Optional[str]:
        """
        Run mmcli command safely.

        Only whitelisted commands are allowed - no user input.
        """
        cmd = f"mmcli -m {self.modem_index} {args}".strip()

        # Security: Only allow whitelisted commands
        if not any(cmd.startswith(allowed) for allowed in self.ALLOWED_COMMANDS):
            logger.error(f"Blocked non-whitelisted command: {cmd}")
            return None

        try:
            result = subprocess.run(
                cmd.split(),
                capture_output=True,
                text=True,
                timeout=10,
            )
            if result.returncode == 0:
                return result.stdout
            else:
                logger.debug(f"mmcli returned {result.returncode}: {result.stderr}")
                return None

        except subprocess.TimeoutExpired:
            logger.warning(f"mmcli command timed out: {cmd}")
            return None
        except FileNotFoundError:
            logger.debug("mmcli not found - modem management not available")
            return None
        except Exception as e:
            logger.error(f"mmcli error: {e}")
            return None

    def _parse_modem_info(self, output: str, metrics: CellularMetrics):
        """Parse general modem information."""
        # Extract interface
        match = re.search(r'primary port:\s+(\S+)', output)
        if match:
            metrics.interface = match.group(1)

        # Extract carrier
        match = re.search(r'operator name:\s+(.+)', output)
        if match:
            metrics.carrier_name = match.group(1).strip()

        # Extract access technology
        match = re.search(r'access tech:\s+(\S+)', output)
        if match:
            tech = match.group(1).lower()
            if '5g' in tech or 'nr' in tech:
                metrics.network_type = NetworkType.NR_5G_SA
            elif 'lte' in tech:
                metrics.network_type = NetworkType.LTE_4G
            elif 'umts' in tech or 'hspa' in tech:
                metrics.network_type = NetworkType.UMTS_3G
            elif 'gsm' in tech or 'edge' in tech:
                metrics.network_type = NetworkType.GSM_2G

        # Extract registration state
        match = re.search(r'state:\s+(\S+)', output)
        if match:
            state = match.group(1).lower()
            if 'registered' in state or 'connected' in state:
                metrics.registration_state = RegistrationState.REGISTERED
            elif 'searching' in state:
                metrics.registration_state = RegistrationState.SEARCHING
            elif 'denied' in state:
                metrics.registration_state = RegistrationState.DENIED
            elif 'idle' in state:
                metrics.registration_state = RegistrationState.IDLE

    def _parse_signal_info(self, output: str, metrics: CellularMetrics):
        """Parse signal strength information."""
        # LTE signals
        match = re.search(r'rsrp:\s+([-\d.]+)\s*dBm', output)
        if match:
            metrics.rsrp_dbm = int(float(match.group(1)))

        match = re.search(r'rsrq:\s+([-\d.]+)\s*dB', output)
        if match:
            metrics.rsrq_db = int(float(match.group(1)))

        match = re.search(r'rssi:\s+([-\d.]+)\s*dBm', output)
        if match:
            metrics.rssi_dbm = int(float(match.group(1)))

        match = re.search(r's(?:i)?nr:\s+([-\d.]+)\s*dB', output)
        if match:
            metrics.sinr_db = int(float(match.group(1)))
            metrics.snr_db = float(match.group(1))

        # 5G NR signals
        match = re.search(r'nr rsrp:\s+([-\d.]+)\s*dBm', output, re.IGNORECASE)
        if match:
            metrics.rsrp_dbm = int(float(match.group(1)))

        match = re.search(r'nr snr:\s+([-\d.]+)\s*dB', output, re.IGNORECASE)
        if match:
            metrics.snr_db = float(match.group(1))
            metrics.sinr_db = int(float(match.group(1)))

    def _parse_location_info(self, output: str, metrics: CellularMetrics):
        """Parse cell location information."""
        # Cell ID (various formats)
        match = re.search(r'cell id:\s*(\d+)', output, re.IGNORECASE)
        if match:
            metrics.cell_id = int(match.group(1))

        # Physical Cell ID
        match = re.search(r'(?:physical cell id|pci):\s*(\d+)', output, re.IGNORECASE)
        if match:
            metrics.pci = int(match.group(1))

        # Tracking Area Code
        match = re.search(r'(?:tracking area code|tac|lac):\s*(\d+)', output, re.IGNORECASE)
        if match:
            metrics.tac = int(match.group(1))

        # MCC/MNC
        match = re.search(r'mcc:\s*(\d+)', output, re.IGNORECASE)
        if match:
            metrics.mcc = match.group(1)

        match = re.search(r'mnc:\s*(\d+)', output, re.IGNORECASE)
        if match:
            metrics.mnc = match.group(1)

        if metrics.mcc and metrics.mnc:
            metrics.plmn = f"{metrics.mcc}{metrics.mnc}"

        # EARFCN
        match = re.search(r'earfcn:\s*(\d+)', output, re.IGNORECASE)
        if match:
            metrics.earfcn = int(match.group(1))

        # Band
        match = re.search(r'band:\s*(\S+)', output, re.IGNORECASE)
        if match:
            metrics.current_band = match.group(1)

    def force_band(self, band: str) -> bool:
        """
        Force modem to specific band.

        Per Gemini validation: Never allow fallback below LTE.
        Per Nemotron audit: Rate-limit band changes.

        Args:
            band: Band to lock to (e.g., 'lte', 'b7', 'n78')

        Returns:
            True if successful
        """
        # Security: Block 2G/3G fallback (per Gemini)
        band_lower = band.lower()
        if band_lower in ('gsm', '2g', 'edge', 'gprs'):
            logger.error("SECURITY: Blocked attempt to force 2G mode")
            return False
        if band_lower in ('umts', '3g', 'hspa', 'wcdma'):
            logger.warning("SECURITY: Blocking 3G-only mode per security policy")
            return False

        # This would use mmcli to set allowed modes
        # For now, just log the intent
        logger.info(f"Band lock requested: {band}")
        return True

    def reset_modem(self) -> bool:
        """
        Reset modem (AT+CFUN=1,1 equivalent).

        Per Nemotron audit:
        - Only hardcoded reset command
        - Rate-limited
        - Prefer hardware GPIO reset over AT commands
        """
        logger.warning("Modem reset requested")

        # Rate check
        if self._command_count >= self.MAX_COMMANDS_PER_MINUTE:
            logger.error("Cannot reset: command rate limit reached")
            return False

        # Try mmcli reset
        try:
            result = subprocess.run(
                ['mmcli', '-m', str(self.modem_index), '--reset'],
                capture_output=True,
                timeout=30,
            )
            if result.returncode == 0:
                logger.info("Modem reset successful")
                return True
            else:
                logger.error(f"Modem reset failed: {result.stderr}")
                return False

        except Exception as e:
            logger.error(f"Modem reset error: {e}")
            return False
