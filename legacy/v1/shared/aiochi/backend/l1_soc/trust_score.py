"""
L1 Trust Score Algorithm

Validated by Trio+:
- Devstral: Weight adjustments (Identity 0.35, SNR 0.20)
- Nemotron: Hard thresholds for unknown towers
- Gemini 3 Flash: Edge case handling

The L1 Trust Score treats the Physical Layer as a Security Sensor,
not just a connectivity indicator.

Formula:
    L1_Trust_Score = (
        W_stability * Signal_Stability +
        W_snr * SNR_Score +
        W_identity * Tower_Identity_Score +
        W_temporal * Temporal_Consistency +
        W_handover * Handover_Score +
        W_pairs * Unexpected_Pairs_Score
    ) * 100

Hard Thresholds (Nemotron security audit):
- Unknown tower (Identity=0) -> Force score to 0
- SNR < 0.3 -> Cap at 30%
- Handover > 20/hour -> Cap at 40%
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional, Dict, List, Tuple
from datetime import datetime, timedelta
import math
import logging

logger = logging.getLogger(__name__)


class TrustState(Enum):
    """L1 Trust states for dashboard visualization."""
    TRUSTED = 'trusted'        # Score >= 70%
    SUSPICIOUS = 'suspicious'  # Score 30-70%
    HOSTILE = 'hostile'        # Score < 30%
    UNKNOWN = 'unknown'        # Cannot calculate


@dataclass
class L1Weights:
    """
    Algorithm weights - validated by Devstral.

    Security-focused weights (not connectivity-focused):
    - Tower identity is most important (rogue tower = primary threat)
    - SNR is secondary (jamming indicator)
    - Stability/temporal/handover are supporting indicators
    """
    stability: float = 0.15      # Signal stability (reduced per Devstral)
    snr: float = 0.20            # SNR score (reduced, can be spoofed)
    identity: float = 0.35       # Tower identity (increased for security)
    temporal: float = 0.15       # Temporal consistency
    handover: float = 0.10       # Handover frequency
    unexpected_pairs: float = 0.05  # New: unexpected tower pairs

    def validate(self) -> bool:
        """Ensure weights sum to 1.0."""
        total = (self.stability + self.snr + self.identity +
                 self.temporal + self.handover + self.unexpected_pairs)
        return abs(total - 1.0) < 0.001


@dataclass
class TowerIdentityContext:
    """Context for tower identity scoring."""
    cell_id: int
    pci: int
    mcc: str
    mnc: str
    tac: int

    # Location verification
    tower_lat: Optional[float] = None
    tower_lon: Optional[float] = None
    gps_lat: Optional[float] = None
    gps_lon: Optional[float] = None

    # Verification status
    in_whitelist: bool = False
    in_opencellid: bool = False
    location_verified: bool = False
    expected_neighbors: List[int] = field(default_factory=list)
    actual_neighbors: List[int] = field(default_factory=list)


@dataclass
class L1TrustResult:
    """Result of L1 Trust Score calculation."""
    score: float                    # 0.0-100.0
    state: TrustState
    timestamp: datetime

    # Component scores (0.0-1.0)
    signal_stability: float
    snr_score: float
    tower_identity: float
    temporal_consistency: float
    handover_score: float
    unexpected_pairs: float

    # Hard threshold flags
    forced_zero: bool = False       # Unknown tower forced to 0
    capped_score: Optional[float] = None
    cap_reason: Optional[str] = None

    # Context
    cell_id: int = 0
    pci: int = 0
    rsrp_variance: float = 0.0
    handover_count_hour: int = 0


class L1TrustScore:
    """
    L1 Trust Score Calculator.

    Treats Physical Layer metrics as security indicators:
    - Signal stability -> Attack detection (sudden changes)
    - SNR -> Jamming detection (noise injection)
    - Tower identity -> Rogue tower detection
    - Temporal consistency -> IMSI catcher detection (ping-pong)
    - Handover frequency -> Tracking attack detection
    """

    # Normalization constants
    RSRP_MIN = -140.0  # dBm
    RSRP_MAX = -44.0   # dBm
    RSRP_MAX_VARIANCE = 100.0  # dBm^2 for worst-case variance

    SNR_MIN = -10.0    # dB
    SNR_MAX = 30.0     # dB

    MAX_HANDOVERS_HOUR = 20  # Per Devstral: >20/hour is suspicious

    # Hard thresholds (Nemotron security audit)
    SNR_CRITICAL_THRESHOLD = 0.3   # SNR score below this caps total
    HANDOVER_CRITICAL_COUNT = 20   # Handovers above this caps total
    SNR_CAP = 30.0                 # Cap score at 30% if SNR critical
    HANDOVER_CAP = 40.0            # Cap score at 40% if handover critical

    def __init__(self, weights: Optional[L1Weights] = None):
        self.weights = weights or L1Weights()
        if not self.weights.validate():
            raise ValueError("Weights must sum to 1.0")

        # History for variance calculations
        self._rsrp_history: List[Tuple[datetime, float]] = []
        self._handover_history: List[datetime] = []
        self._tower_pairs_history: List[Tuple[datetime, int, int]] = []

        # Configuration
        self.history_window = timedelta(hours=1)

    def calculate(
        self,
        rsrp_dbm: float,
        sinr_db: float,
        snr_db: Optional[float] = None,
        tower_context: Optional[TowerIdentityContext] = None,
        gps_stationary: bool = True,
    ) -> L1TrustResult:
        """
        Calculate L1 Trust Score.

        Args:
            rsrp_dbm: Current RSRP in dBm
            sinr_db: Current SINR in dB
            snr_db: Current SNR in dB (if available, else use SINR)
            tower_context: Tower identity information
            gps_stationary: Whether GPS shows device is stationary

        Returns:
            L1TrustResult with score and component breakdown
        """
        now = datetime.now()
        snr = snr_db if snr_db is not None else sinr_db

        # Update history
        self._update_history(rsrp_dbm, tower_context, now)

        # Calculate component scores (0.0-1.0)
        stability = self._calc_signal_stability(rsrp_dbm)
        snr_score = self._calc_snr_score(snr)
        identity = self._calc_tower_identity(tower_context, gps_stationary)
        temporal = self._calc_temporal_consistency()
        handover = self._calc_handover_score()
        pairs = self._calc_unexpected_pairs(tower_context)

        # Weighted sum
        raw_score = (
            self.weights.stability * stability +
            self.weights.snr * snr_score +
            self.weights.identity * identity +
            self.weights.temporal * temporal +
            self.weights.handover * handover +
            self.weights.unexpected_pairs * pairs
        ) * 100

        # Apply hard thresholds (Nemotron security audit)
        final_score, forced_zero, capped, cap_reason = self._apply_hard_thresholds(
            raw_score, identity, snr_score, handover
        )

        # Determine state
        state = self._determine_state(final_score, forced_zero)

        return L1TrustResult(
            score=final_score,
            state=state,
            timestamp=now,
            signal_stability=stability,
            snr_score=snr_score,
            tower_identity=identity,
            temporal_consistency=temporal,
            handover_score=handover,
            unexpected_pairs=pairs,
            forced_zero=forced_zero,
            capped_score=capped,
            cap_reason=cap_reason,
            cell_id=tower_context.cell_id if tower_context else 0,
            pci=tower_context.pci if tower_context else 0,
            rsrp_variance=self._calc_rsrp_variance(),
            handover_count_hour=len(self._handover_history),
        )

    def _calc_signal_stability(self, rsrp_dbm: float) -> float:
        """
        Calculate signal stability score.

        Stability = 1 - (RSRP_variance / max_variance)

        Sudden signal changes (high variance) indicate potential attack:
        - Jamming often causes erratic signal
        - IMSI catchers cause abrupt changes during handover
        """
        variance = self._calc_rsrp_variance()
        stability = 1.0 - min(variance / self.RSRP_MAX_VARIANCE, 1.0)
        return max(0.0, min(1.0, stability))

    def _calc_snr_score(self, snr_db: float) -> float:
        """
        Calculate SNR score (normalized).

        Key jamming indicator:
        - High RSRP + Low SNR = Likely jamming
        - Normal SNR degradation shows correlated RSRP drop
        """
        normalized = (snr_db - self.SNR_MIN) / (self.SNR_MAX - self.SNR_MIN)
        return max(0.0, min(1.0, normalized))

    def _calc_tower_identity(
        self,
        context: Optional[TowerIdentityContext],
        gps_stationary: bool,
    ) -> float:
        """
        Calculate tower identity score.

        Per Devstral-validated breakdown:
        - 1.0: Whitelist + GPS location match
        - 0.5: Whitelist + GPS mismatch (reduced from 0.7)
        - 0.2: OpenCellID only (reduced from 0.3)
        - 0.0: Unknown tower

        Additional penalty for GPS mismatch when stationary (IMSI catcher indicator).
        """
        if not context:
            return 0.0

        # Unknown tower = maximum risk
        if not context.in_whitelist and not context.in_opencellid:
            return 0.0

        # Whitelist + location verified
        if context.in_whitelist and context.location_verified:
            return 1.0

        # Whitelist but location mismatch
        if context.in_whitelist and not context.location_verified:
            # Extra penalty if GPS shows stationary but tower suggests movement
            if gps_stationary and self._has_location_mismatch(context):
                return 0.3  # Severe penalty for "virtual movement"
            return 0.5  # Reduced from 0.7 per Devstral

        # OpenCellID only (not whitelisted)
        if context.in_opencellid:
            return 0.2  # Reduced from 0.3 per Devstral

        return 0.0

    def _calc_temporal_consistency(self) -> float:
        """
        Calculate temporal consistency score.

        Consistency = 1 - (handover_frequency / max_expected)

        Rapid handovers indicate:
        - IMSI catcher causing ping-pong
        - Tracking attack
        - Location Area spoofing
        """
        if not self._handover_history:
            return 1.0

        # Count handovers in the last hour
        now = datetime.now()
        recent = [t for t in self._handover_history
                  if now - t < self.history_window]

        frequency = len(recent) / self.MAX_HANDOVERS_HOUR
        consistency = 1.0 - min(frequency, 1.0)
        return max(0.0, min(1.0, consistency))

    def _calc_handover_score(self) -> float:
        """
        Calculate handover score.

        Per Devstral:
        - 1.0 if < 2 handovers/hour
        - Decreasing to 0.1 if > 20 handovers/hour
        """
        count = len(self._handover_history)

        if count < 2:
            return 1.0
        elif count >= self.MAX_HANDOVERS_HOUR:
            return 0.1
        else:
            # Linear interpolation
            return 1.0 - (0.9 * (count - 2) / (self.MAX_HANDOVERS_HOUR - 2))

    def _calc_unexpected_pairs(
        self,
        context: Optional[TowerIdentityContext],
    ) -> float:
        """
        Calculate unexpected tower pairs score.

        Per Devstral: Penalize when device hands over between
        towers that should never be neighbors.

        This catches sophisticated IMSI catchers that clone tower IDs
        but don't know the legitimate neighbor relationships.
        """
        if not context or not context.expected_neighbors:
            return 1.0  # No data, assume OK

        if not context.actual_neighbors:
            return 1.0  # No neighbors seen yet

        # Check if actual neighbors are in expected list
        expected_set = set(context.expected_neighbors)
        actual_set = set(context.actual_neighbors)

        if not actual_set:
            return 1.0

        # Calculate overlap ratio
        overlap = len(actual_set & expected_set)
        overlap_ratio = overlap / len(actual_set)

        return overlap_ratio

    def _apply_hard_thresholds(
        self,
        raw_score: float,
        identity: float,
        snr_score: float,
        handover_score: float,
    ) -> Tuple[float, bool, Optional[float], Optional[str]]:
        """
        Apply hard security thresholds.

        Per Nemotron security audit:
        - Unknown tower (identity=0) MUST force score to 0
        - Critical SNR (< 0.3) caps score at 30%
        - Critical handover (score < 0.2) caps score at 40%
        """
        forced_zero = False
        capped = None
        cap_reason = None

        # Hard rule: Unknown tower = zero trust
        if identity == 0.0:
            logger.warning("L1 Trust: Unknown tower detected, forcing score to 0")
            return 0.0, True, None, None

        final = raw_score

        # Cap for critical SNR
        if snr_score < self.SNR_CRITICAL_THRESHOLD:
            if final > self.SNR_CAP:
                capped = self.SNR_CAP
                cap_reason = f"SNR critical ({snr_score:.2f} < {self.SNR_CRITICAL_THRESHOLD})"
                final = self.SNR_CAP
                logger.warning(f"L1 Trust: {cap_reason}, capping at {self.SNR_CAP}%")

        # Cap for critical handover
        if handover_score < 0.2:
            if final > self.HANDOVER_CAP:
                capped = self.HANDOVER_CAP
                cap_reason = f"Handover storm detected (score={handover_score:.2f})"
                final = self.HANDOVER_CAP
                logger.warning(f"L1 Trust: {cap_reason}, capping at {self.HANDOVER_CAP}%")

        return final, forced_zero, capped, cap_reason

    def _determine_state(self, score: float, forced_zero: bool) -> TrustState:
        """Determine trust state from score."""
        if forced_zero:
            return TrustState.HOSTILE

        if score >= 70:
            return TrustState.TRUSTED
        elif score >= 30:
            return TrustState.SUSPICIOUS
        else:
            return TrustState.HOSTILE

    def _update_history(
        self,
        rsrp_dbm: float,
        context: Optional[TowerIdentityContext],
        now: datetime,
    ):
        """Update history buffers and prune old entries."""
        # Add RSRP
        self._rsrp_history.append((now, rsrp_dbm))

        # Prune old RSRP entries
        cutoff = now - self.history_window
        self._rsrp_history = [
            (t, v) for t, v in self._rsrp_history if t > cutoff
        ]

        # Prune old handover entries
        self._handover_history = [
            t for t in self._handover_history if t > cutoff
        ]

        # Prune old tower pairs
        self._tower_pairs_history = [
            (t, c1, c2) for t, c1, c2 in self._tower_pairs_history if t > cutoff
        ]

    def record_handover(self, from_cell: int, to_cell: int):
        """Record a handover event."""
        now = datetime.now()
        self._handover_history.append(now)
        self._tower_pairs_history.append((now, from_cell, to_cell))
        logger.debug(f"L1 Trust: Recorded handover {from_cell} -> {to_cell}")

    def _calc_rsrp_variance(self) -> float:
        """Calculate RSRP variance from history."""
        if len(self._rsrp_history) < 2:
            return 0.0

        values = [v for _, v in self._rsrp_history]
        mean = sum(values) / len(values)
        variance = sum((v - mean) ** 2 for v in values) / len(values)
        return variance

    def _has_location_mismatch(self, context: TowerIdentityContext) -> bool:
        """Check if tower location mismatches GPS."""
        if (context.tower_lat is None or context.tower_lon is None or
            context.gps_lat is None or context.gps_lon is None):
            return False

        # Calculate distance using Haversine formula
        distance_km = self._haversine(
            context.tower_lat, context.tower_lon,
            context.gps_lat, context.gps_lon
        )

        # More than 10km mismatch is suspicious
        return distance_km > 10.0

    @staticmethod
    def _haversine(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
        """Calculate distance between two points in km."""
        R = 6371  # Earth radius in km

        lat1_rad = math.radians(lat1)
        lat2_rad = math.radians(lat2)
        dlat = math.radians(lat2 - lat1)
        dlon = math.radians(lon2 - lon1)

        a = (math.sin(dlat/2)**2 +
             math.cos(lat1_rad) * math.cos(lat2_rad) * math.sin(dlon/2)**2)
        c = 2 * math.atan2(math.sqrt(a), math.sqrt(1-a))

        return R * c
