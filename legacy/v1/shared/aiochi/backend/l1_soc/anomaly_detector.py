"""
L1 Anomaly Detector

Detects IMSI catchers, jammers, rogue towers, and other
Physical Layer attacks.

Detection Categories (MITRE ATT&CK aligned):
- T1556: Modify Authentication Process (encryption downgrade)
- T1584: Compromise Infrastructure (rogue towers)
- T1498: Network Denial of Service (jamming)
- T1040: Network Sniffing (IMSI catching)
"""

import logging
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Optional, List, Dict, Tuple
from collections import deque

from .trust_score import L1TrustScore, TrustState, TowerIdentityContext
from .tower_reputation import TowerReputation, TowerVerificationResult
from .cellular_monitor import CellularMetrics, NetworkType

logger = logging.getLogger(__name__)


class AnomalyType(Enum):
    """Types of L1 anomalies."""
    UNKNOWN_TOWER = 'unknown_tower'
    ROGUE_TOWER = 'rogue_tower'
    IMSI_CATCHER = 'imsi_catcher'
    JAMMING = 'jamming'
    DOWNGRADE_ATTACK = 'downgrade_attack'
    TIMING_ANOMALY = 'timing_anomaly'
    HANDOVER_STORM = 'handover_storm'
    SIGNAL_SPOOFING = 'signal_spoofing'
    GPS_TOWER_MISMATCH = 'gps_tower_mismatch'
    ENCRYPTION_DOWNGRADE = 'encryption_downgrade'
    BATTERY_DRAIN_ATTACK = 'battery_drain_attack'


class Severity(Enum):
    """Anomaly severity levels."""
    LOW = 'low'
    MEDIUM = 'medium'
    HIGH = 'high'
    CRITICAL = 'critical'


@dataclass
class L1Anomaly:
    """Detected L1 anomaly."""
    id: str
    timestamp: datetime
    anomaly_type: AnomalyType
    severity: Severity
    confidence: float  # 0.0-1.0

    # Evidence
    evidence: Dict = field(default_factory=dict)
    indicators_count: int = 0

    # Tower Info
    cell_id: int = 0
    pci: int = 0
    reported_location: Tuple[float, float] = (0.0, 0.0)
    gps_location: Tuple[float, float] = (0.0, 0.0)
    location_mismatch_km: float = 0.0

    # Signal at detection
    rsrp_dbm: int = -999
    sinr_db: int = -999
    snr_db: float = -999.0

    # Response
    action_taken: str = ''
    playbook_triggered: str = ''
    auto_resolved: bool = False
    resolution_notes: str = ''

    # MITRE ATT&CK
    mitre_tactic: str = ''
    mitre_technique: str = ''


class L1AnomalyDetector:
    """
    L1 Anomaly Detection Engine.

    Detects:
    - Rogue towers (unknown Cell ID, location mismatch)
    - IMSI catchers (encryption downgrade, handover ping-pong)
    - Jammers (high RSRP + low SNR pattern)
    - Tracking attacks (excessive handovers)

    Per Trio+ validation:
    - Require multiple corroborating indicators
    - Use GPS + timing advance for location verification
    - Monitor SIB changes for encryption downgrades
    """

    # Detection thresholds
    JAMMING_RSRP_THRESHOLD = -80      # dBm - suspiciously strong
    JAMMING_SNR_THRESHOLD = 5.0       # dB - noise floor
    HANDOVER_STORM_THRESHOLD = 10     # per 5 minutes
    LOCATION_MISMATCH_THRESHOLD = 5.0 # km
    TIMING_MISMATCH_THRESHOLD = 2.0   # km

    def __init__(
        self,
        trust_scorer: L1TrustScore,
        tower_reputation: TowerReputation,
    ):
        self.trust_scorer = trust_scorer
        self.tower_reputation = tower_reputation

        # History buffers
        self._metrics_history: deque = deque(maxlen=100)
        self._handover_history: deque = deque(maxlen=50)
        self._detected_anomalies: List[L1Anomaly] = []

        # State
        self._last_network_type: Optional[NetworkType] = None
        self._last_cell_id: Optional[int] = None

    def analyze(
        self,
        metrics: CellularMetrics,
        gps_lat: Optional[float] = None,
        gps_lon: Optional[float] = None,
        gps_stationary: bool = True,
    ) -> List[L1Anomaly]:
        """
        Analyze cellular metrics for anomalies.

        Args:
            metrics: Current cellular metrics
            gps_lat: GPS latitude
            gps_lon: GPS longitude
            gps_stationary: Whether GPS shows device is stationary

        Returns:
            List of detected anomalies
        """
        anomalies = []

        # Store metrics history
        self._metrics_history.append(metrics)

        # Track handovers
        if self._last_cell_id and self._last_cell_id != metrics.cell_id:
            self._record_handover(self._last_cell_id, metrics.cell_id)

        self._last_cell_id = metrics.cell_id

        # Run detection checks
        anomalies.extend(self._check_unknown_tower(metrics))
        anomalies.extend(self._check_jamming(metrics))
        anomalies.extend(self._check_downgrade_attack(metrics))
        anomalies.extend(self._check_handover_storm(metrics))
        anomalies.extend(self._check_gps_mismatch(metrics, gps_lat, gps_lon, gps_stationary))
        anomalies.extend(self._check_signal_spoofing(metrics))

        # Track network type for downgrade detection
        self._last_network_type = metrics.network_type

        # Store detected anomalies
        self._detected_anomalies.extend(anomalies)

        return anomalies

    def _check_unknown_tower(self, metrics: CellularMetrics) -> List[L1Anomaly]:
        """Check for unknown/unverified towers."""
        if not metrics.cell_id:
            return []

        verification = self.tower_reputation.verify_tower(
            cell_id=metrics.cell_id,
            pci=metrics.pci,
            mcc=metrics.mcc,
            mnc=metrics.mnc,
            tac=metrics.tac,
        )

        if verification.is_blacklisted:
            return [L1Anomaly(
                id=f"rogue-{metrics.cell_id}-{datetime.now().timestamp()}",
                timestamp=datetime.now(),
                anomaly_type=AnomalyType.ROGUE_TOWER,
                severity=Severity.CRITICAL,
                confidence=1.0,
                evidence={
                    'blacklist_reason': verification.blacklist_reason,
                    'cell_id': metrics.cell_id,
                    'pci': metrics.pci,
                },
                indicators_count=3,  # Blacklist requires 3+
                cell_id=metrics.cell_id,
                pci=metrics.pci,
                rsrp_dbm=metrics.rsrp_dbm,
                sinr_db=metrics.sinr_db,
                mitre_tactic='Initial Access',
                mitre_technique='T1584 - Compromise Infrastructure',
            )]

        if not verification.in_whitelist and not verification.in_opencellid:
            return [L1Anomaly(
                id=f"unknown-{metrics.cell_id}-{datetime.now().timestamp()}",
                timestamp=datetime.now(),
                anomaly_type=AnomalyType.UNKNOWN_TOWER,
                severity=Severity.HIGH,
                confidence=0.8,
                evidence={
                    'cell_id': metrics.cell_id,
                    'pci': metrics.pci,
                    'mcc': metrics.mcc,
                    'mnc': metrics.mnc,
                    'warnings': verification.warnings,
                },
                indicators_count=1,
                cell_id=metrics.cell_id,
                pci=metrics.pci,
                rsrp_dbm=metrics.rsrp_dbm,
                sinr_db=metrics.sinr_db,
                mitre_tactic='Initial Access',
                mitre_technique='T1584 - Compromise Infrastructure',
            )]

        return []

    def _check_jamming(self, metrics: CellularMetrics) -> List[L1Anomaly]:
        """
        Detect jamming attacks.

        Pattern: High RSRP (attacker transmitting) + Low SNR (noise injection)

        Per Gemini validation:
        - Normal signal drop: Both RSRP and SNR drop together
        - Jamming: High RSRP but catastrophic SNR drop
        """
        if metrics.rsrp_dbm == -999 or metrics.snr_db == -999:
            return []

        # Jamming signature: strong signal but terrible quality
        if (metrics.rsrp_dbm > self.JAMMING_RSRP_THRESHOLD and
            metrics.snr_db < self.JAMMING_SNR_THRESHOLD):

            # Check for sudden SNR drop
            snr_history = [m.snr_db for m in self._metrics_history
                          if m.snr_db != -999][-10:]

            if len(snr_history) >= 3:
                avg_snr = sum(snr_history[:-1]) / len(snr_history[:-1])
                snr_drop = avg_snr - metrics.snr_db

                if snr_drop > 15:  # Sudden 15dB+ drop is suspicious
                    return [L1Anomaly(
                        id=f"jamming-{datetime.now().timestamp()}",
                        timestamp=datetime.now(),
                        anomaly_type=AnomalyType.JAMMING,
                        severity=Severity.CRITICAL,
                        confidence=min(0.9, snr_drop / 30),
                        evidence={
                            'rsrp_dbm': metrics.rsrp_dbm,
                            'snr_db': metrics.snr_db,
                            'snr_drop': snr_drop,
                            'avg_snr_before': avg_snr,
                            'pattern': 'high_rsrp_low_snr',
                        },
                        indicators_count=2,
                        cell_id=metrics.cell_id,
                        pci=metrics.pci,
                        rsrp_dbm=metrics.rsrp_dbm,
                        snr_db=metrics.snr_db,
                        mitre_tactic='Impact',
                        mitre_technique='T1498 - Network Denial of Service',
                    )]

        return []

    def _check_downgrade_attack(self, metrics: CellularMetrics) -> List[L1Anomaly]:
        """
        Detect downgrade attacks (5G -> 4G -> 3G -> 2G).

        Per Gemini validation: IMSI catchers often jam higher bands
        to force fallback to weaker crypto.
        """
        if not self._last_network_type:
            return []

        # Define network strength hierarchy
        hierarchy = {
            NetworkType.NR_5G_SA: 5,
            NetworkType.NR_5G_NSA: 4,
            NetworkType.LTE_4G: 3,
            NetworkType.UMTS_3G: 2,
            NetworkType.GSM_2G: 1,
            NetworkType.UNKNOWN: 0,
        }

        last_level = hierarchy.get(self._last_network_type, 0)
        current_level = hierarchy.get(metrics.network_type, 0)

        # Downgrade detected
        if current_level < last_level and current_level <= 2:
            severity = Severity.CRITICAL if current_level <= 1 else Severity.HIGH

            return [L1Anomaly(
                id=f"downgrade-{datetime.now().timestamp()}",
                timestamp=datetime.now(),
                anomaly_type=AnomalyType.DOWNGRADE_ATTACK,
                severity=severity,
                confidence=0.85,
                evidence={
                    'from_network': self._last_network_type.value,
                    'to_network': metrics.network_type.value,
                    'from_level': last_level,
                    'to_level': current_level,
                },
                indicators_count=1,
                cell_id=metrics.cell_id,
                pci=metrics.pci,
                rsrp_dbm=metrics.rsrp_dbm,
                sinr_db=metrics.sinr_db,
                mitre_tactic='Defense Evasion',
                mitre_technique='T1556 - Modify Authentication Process',
            )]

        return []

    def _check_handover_storm(self, metrics: CellularMetrics) -> List[L1Anomaly]:
        """
        Detect handover storm (IMSI catcher ping-pong).

        Per Gemini validation: IMSI catchers cause rapid switching
        between the rogue cell and legitimate towers.
        """
        # Count recent handovers
        cutoff = datetime.now() - timedelta(minutes=5)
        recent_handovers = [h for h in self._handover_history if h['timestamp'] > cutoff]

        if len(recent_handovers) >= self.HANDOVER_STORM_THRESHOLD:
            # Check for ping-pong pattern
            cells_involved = set()
            for h in recent_handovers:
                cells_involved.add(h['from_cell'])
                cells_involved.add(h['to_cell'])

            # Ping-pong: switching between same 2-3 cells repeatedly
            is_pingpong = len(cells_involved) <= 3

            return [L1Anomaly(
                id=f"handover-storm-{datetime.now().timestamp()}",
                timestamp=datetime.now(),
                anomaly_type=AnomalyType.HANDOVER_STORM,
                severity=Severity.HIGH if is_pingpong else Severity.MEDIUM,
                confidence=0.75 if is_pingpong else 0.5,
                evidence={
                    'handover_count': len(recent_handovers),
                    'cells_involved': list(cells_involved),
                    'is_pingpong': is_pingpong,
                    'window_minutes': 5,
                },
                indicators_count=2 if is_pingpong else 1,
                cell_id=metrics.cell_id,
                pci=metrics.pci,
                rsrp_dbm=metrics.rsrp_dbm,
                sinr_db=metrics.sinr_db,
                mitre_tactic='Collection',
                mitre_technique='T1040 - Network Sniffing',
            )]

        return []

    def _check_gps_mismatch(
        self,
        metrics: CellularMetrics,
        gps_lat: Optional[float],
        gps_lon: Optional[float],
        gps_stationary: bool,
    ) -> List[L1Anomaly]:
        """
        Detect GPS vs tower location mismatch.

        Per Gemini validation: If GPS shows stationary but tower
        suggests movement, likely IMSI catcher.
        """
        if not gps_lat or not gps_lon or not metrics.cell_id:
            return []

        verification = self.tower_reputation.verify_tower(
            cell_id=metrics.cell_id,
            pci=metrics.pci,
            mcc=metrics.mcc,
            mnc=metrics.mnc,
            tac=metrics.tac,
            gps_lat=gps_lat,
            gps_lon=gps_lon,
            timing_advance=metrics.timing_advance,
        )

        if (verification.location_mismatch_km > self.LOCATION_MISMATCH_THRESHOLD
            and gps_stationary):

            return [L1Anomaly(
                id=f"gps-mismatch-{datetime.now().timestamp()}",
                timestamp=datetime.now(),
                anomaly_type=AnomalyType.GPS_TOWER_MISMATCH,
                severity=Severity.HIGH,
                confidence=min(0.9, verification.location_mismatch_km / 20),
                evidence={
                    'mismatch_km': verification.location_mismatch_km,
                    'gps_stationary': gps_stationary,
                    'timing_advance': metrics.timing_advance,
                    'warnings': verification.warnings,
                },
                indicators_count=2,
                cell_id=metrics.cell_id,
                pci=metrics.pci,
                gps_location=(gps_lat, gps_lon),
                location_mismatch_km=verification.location_mismatch_km,
                rsrp_dbm=metrics.rsrp_dbm,
                sinr_db=metrics.sinr_db,
                mitre_tactic='Collection',
                mitre_technique='T1040 - Network Sniffing',
            )]

        return []

    def _check_signal_spoofing(self, metrics: CellularMetrics) -> List[L1Anomaly]:
        """
        Detect signal strength spoofing.

        Pattern: Sudden signal improvement without movement
        (attacker boosting to attract devices).
        """
        rsrp_history = [m.rsrp_dbm for m in self._metrics_history
                       if m.rsrp_dbm != -999][-10:]

        if len(rsrp_history) < 5:
            return []

        avg_rsrp = sum(rsrp_history[:-1]) / len(rsrp_history[:-1])
        rsrp_jump = metrics.rsrp_dbm - avg_rsrp

        # Sudden 20dB+ improvement is suspicious
        if rsrp_jump > 20:
            return [L1Anomaly(
                id=f"signal-spoof-{datetime.now().timestamp()}",
                timestamp=datetime.now(),
                anomaly_type=AnomalyType.SIGNAL_SPOOFING,
                severity=Severity.MEDIUM,
                confidence=min(0.7, rsrp_jump / 40),
                evidence={
                    'rsrp_jump': rsrp_jump,
                    'avg_rsrp_before': avg_rsrp,
                    'current_rsrp': metrics.rsrp_dbm,
                },
                indicators_count=1,
                cell_id=metrics.cell_id,
                pci=metrics.pci,
                rsrp_dbm=metrics.rsrp_dbm,
                sinr_db=metrics.sinr_db,
                mitre_tactic='Initial Access',
                mitre_technique='T1584 - Compromise Infrastructure',
            )]

        return []

    def _record_handover(self, from_cell: int, to_cell: int):
        """Record a handover event."""
        self._handover_history.append({
            'timestamp': datetime.now(),
            'from_cell': from_cell,
            'to_cell': to_cell,
        })
        self.trust_scorer.record_handover(from_cell, to_cell)

    def get_recent_anomalies(
        self,
        hours: int = 24,
        severity: Optional[Severity] = None,
    ) -> List[L1Anomaly]:
        """Get anomalies from the last N hours."""
        cutoff = datetime.now() - timedelta(hours=hours)
        anomalies = [a for a in self._detected_anomalies if a.timestamp > cutoff]

        if severity:
            anomalies = [a for a in anomalies if a.severity == severity]

        return sorted(anomalies, key=lambda a: a.timestamp, reverse=True)
