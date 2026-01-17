"""
Tower Reputation System

Integrates with OpenCellID and maintains local whitelist for
tower verification and rogue tower detection.

Per Gemini 3 Flash validation:
- Use OpenCellID for LOCATION verification, not identity
- Attackers can clone Cell IDs from the database
- Cross-validate with GPS and timing advance

Per Nemotron security audit:
- Require multiple indicators before blacklisting
- Implement time decay on blacklist entries
- Don't trust crowdsourced data as "source of truth"
"""

import os
import csv
import json
import logging
import sqlite3
import requests
from pathlib import Path
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Optional, List, Dict, Tuple
import math

logger = logging.getLogger(__name__)


class TowerSource(Enum):
    """Source of tower information."""
    WHITELIST = 'whitelist'          # Manually verified/carrier-provided
    OPENCELLID = 'opencellid'        # Crowdsourced database
    CARRIER = 'carrier'              # Direct from carrier API
    USER_REPORTED = 'user_reported'  # User submission
    AUTO_LEARNED = 'auto_learned'    # Learned from stable connections


class TowerType(Enum):
    """Type of cell tower."""
    MACRO = 'macro'           # Large tower
    SMALL_CELL = 'small_cell' # Urban densification
    FEMTO = 'femto'           # Indoor/home
    UNKNOWN = 'unknown'


@dataclass
class TowerInfo:
    """Information about a cell tower."""
    cell_id: int
    pci: int                          # Physical Cell ID
    mcc: str
    mnc: str
    tac: int                          # Tracking Area Code

    # Location
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    location_accuracy_m: int = 0

    # Metadata
    carrier_name: str = ''
    tower_type: TowerType = TowerType.UNKNOWN
    expected_bands: List[str] = field(default_factory=list)
    expected_neighbors: List[int] = field(default_factory=list)

    # Trust
    source: TowerSource = TowerSource.UNKNOWN
    reputation_score: float = 0.5     # 0.0-1.0
    first_seen: datetime = field(default_factory=datetime.now)
    last_seen: datetime = field(default_factory=datetime.now)
    observation_count: int = 1

    # Blacklist
    is_blacklisted: bool = False
    blacklist_reason: str = ''
    blacklist_timestamp: Optional[datetime] = None
    blacklist_indicators: int = 0     # Must be >= 3 per Nemotron


@dataclass
class TowerVerificationResult:
    """Result of tower verification."""
    tower: Optional[TowerInfo]
    in_whitelist: bool = False
    in_opencellid: bool = False
    location_verified: bool = False
    location_mismatch_km: float = 0.0
    is_blacklisted: bool = False
    blacklist_reason: str = ''
    confidence: float = 0.0           # Overall confidence 0.0-1.0
    warnings: List[str] = field(default_factory=list)


class TowerReputation:
    """
    Tower Reputation System.

    Manages tower whitelist and integrates with OpenCellID
    for rogue tower detection.

    Security Notes (per Trio+ audit):
    - OpenCellID is for LOCATION verification only
    - Never trust Cell ID alone (can be cloned)
    - Require timing advance + GPS correlation
    - Blacklist requires >= 3 indicators
    """

    # OpenCellID API
    OPENCELLID_API = "https://opencellid.org/cell/get"
    OPENCELLID_BULK = "https://opencellid.org/downloads"

    # Blacklist settings (per Nemotron)
    MIN_BLACKLIST_INDICATORS = 3
    BLACKLIST_DECAY_DAYS = 7          # Remove from blacklist after 7 days
    MAX_LOCATION_MISMATCH_KM = 5.0    # GPS vs tower location threshold

    def __init__(
        self,
        db_path: str = "/var/lib/aiochi/tower_reputation.db",
        opencellid_token: Optional[str] = None,
    ):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)

        self.opencellid_token = opencellid_token or os.environ.get('OPENCELLID_TOKEN')

        self._init_db()

    def _init_db(self):
        """Initialize SQLite database for tower reputation."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        # Whitelist table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS tower_whitelist (
                cell_id INTEGER,
                pci INTEGER,
                mcc TEXT,
                mnc TEXT,
                tac INTEGER,
                latitude REAL,
                longitude REAL,
                location_accuracy_m INTEGER DEFAULT 0,
                carrier_name TEXT,
                tower_type TEXT DEFAULT 'unknown',
                expected_bands TEXT,
                expected_neighbors TEXT,
                source TEXT DEFAULT 'auto_learned',
                reputation_score REAL DEFAULT 0.5,
                first_seen TEXT,
                last_seen TEXT,
                observation_count INTEGER DEFAULT 1,
                is_blacklisted INTEGER DEFAULT 0,
                blacklist_reason TEXT,
                blacklist_timestamp TEXT,
                blacklist_indicators INTEGER DEFAULT 0,
                PRIMARY KEY (mcc, mnc, cell_id, pci)
            )
        ''')

        # OpenCellID cache
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS opencellid_cache (
                mcc TEXT,
                mnc TEXT,
                cell_id INTEGER,
                latitude REAL,
                longitude REAL,
                accuracy_m INTEGER,
                cached_at TEXT,
                PRIMARY KEY (mcc, mnc, cell_id)
            )
        ''')

        # Anomaly indicators (for blacklist decisions)
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS tower_anomalies (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                cell_id INTEGER,
                pci INTEGER,
                mcc TEXT,
                mnc TEXT,
                indicator_type TEXT,
                details TEXT,
                timestamp TEXT,
                resolved INTEGER DEFAULT 0
            )
        ''')

        conn.commit()
        conn.close()

    def verify_tower(
        self,
        cell_id: int,
        pci: int,
        mcc: str,
        mnc: str,
        tac: int,
        gps_lat: Optional[float] = None,
        gps_lon: Optional[float] = None,
        timing_advance: Optional[int] = None,
    ) -> TowerVerificationResult:
        """
        Verify a cell tower.

        Checks:
        1. Is tower in whitelist?
        2. Is tower in OpenCellID?
        3. Does location match GPS?
        4. Is tower blacklisted?

        Returns verification result with confidence score.
        """
        warnings = []

        # Check whitelist first
        whitelist_tower = self._get_from_whitelist(cell_id, pci, mcc, mnc)

        # Check OpenCellID
        opencellid_info = self._get_from_opencellid(cell_id, mcc, mnc)

        # Check blacklist
        is_blacklisted, blacklist_reason = self._check_blacklist(cell_id, pci, mcc, mnc)

        if is_blacklisted:
            return TowerVerificationResult(
                tower=whitelist_tower,
                in_whitelist=whitelist_tower is not None,
                in_opencellid=opencellid_info is not None,
                is_blacklisted=True,
                blacklist_reason=blacklist_reason,
                confidence=0.0,
                warnings=["Tower is blacklisted: " + blacklist_reason],
            )

        # Determine tower info (prefer whitelist)
        tower = whitelist_tower
        if not tower and opencellid_info:
            tower = TowerInfo(
                cell_id=cell_id,
                pci=pci,
                mcc=mcc,
                mnc=mnc,
                tac=tac,
                latitude=opencellid_info.get('lat'),
                longitude=opencellid_info.get('lon'),
                location_accuracy_m=opencellid_info.get('accuracy', 0),
                source=TowerSource.OPENCELLID,
            )

        # Location verification
        location_verified = False
        location_mismatch_km = 0.0

        if tower and tower.latitude and tower.longitude and gps_lat and gps_lon:
            location_mismatch_km = self._haversine(
                tower.latitude, tower.longitude,
                gps_lat, gps_lon
            )

            if location_mismatch_km <= self.MAX_LOCATION_MISMATCH_KM:
                location_verified = True
            else:
                warnings.append(
                    f"Location mismatch: tower claims {location_mismatch_km:.1f}km from GPS"
                )

            # Timing advance validation (per Gemini)
            if timing_advance is not None and tower.latitude and tower.longitude:
                ta_distance_km = timing_advance * 0.078  # ~78m per TA unit
                if abs(ta_distance_km - location_mismatch_km) > 2.0:
                    warnings.append(
                        f"Timing advance mismatch: TA suggests {ta_distance_km:.1f}km, "
                        f"GPS shows {location_mismatch_km:.1f}km"
                    )

        # Calculate confidence
        confidence = self._calc_confidence(
            in_whitelist=whitelist_tower is not None,
            in_opencellid=opencellid_info is not None,
            location_verified=location_verified,
            location_mismatch_km=location_mismatch_km,
        )

        return TowerVerificationResult(
            tower=tower,
            in_whitelist=whitelist_tower is not None,
            in_opencellid=opencellid_info is not None,
            location_verified=location_verified,
            location_mismatch_km=location_mismatch_km,
            is_blacklisted=False,
            confidence=confidence,
            warnings=warnings,
        )

    def add_to_whitelist(
        self,
        cell_id: int,
        pci: int,
        mcc: str,
        mnc: str,
        tac: int,
        latitude: Optional[float] = None,
        longitude: Optional[float] = None,
        carrier_name: str = '',
        source: TowerSource = TowerSource.USER_REPORTED,
        expected_neighbors: Optional[List[int]] = None,
    ):
        """Add or update a tower in the whitelist."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        now = datetime.now().isoformat()

        cursor.execute('''
            INSERT INTO tower_whitelist (
                cell_id, pci, mcc, mnc, tac, latitude, longitude,
                carrier_name, source, expected_neighbors,
                first_seen, last_seen, observation_count, reputation_score
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, 0.8)
            ON CONFLICT(mcc, mnc, cell_id, pci) DO UPDATE SET
                last_seen = ?,
                observation_count = observation_count + 1,
                reputation_score = MIN(1.0, reputation_score + 0.01)
        ''', (
            cell_id, pci, mcc, mnc, tac, latitude, longitude,
            carrier_name, source.value,
            json.dumps(expected_neighbors or []),
            now, now, now
        ))

        conn.commit()
        conn.close()
        logger.info(f"Added tower to whitelist: {mcc}-{mnc}-{cell_id}")

    def report_anomaly(
        self,
        cell_id: int,
        pci: int,
        mcc: str,
        mnc: str,
        indicator_type: str,
        details: str,
    ):
        """
        Report an anomaly indicator for a tower.

        Per Nemotron: Must have >= 3 indicators before blacklisting.

        Indicator types:
        - location_mismatch: GPS doesn't match tower location
        - timing_anomaly: Timing advance inconsistent
        - encryption_downgrade: Tower disabled encryption
        - handover_storm: Excessive handovers involving this tower
        - signal_anomaly: RSRP/SNR pattern suspicious
        - neighbor_mismatch: Doesn't list expected neighbors
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        now = datetime.now().isoformat()

        cursor.execute('''
            INSERT INTO tower_anomalies (
                cell_id, pci, mcc, mnc, indicator_type, details, timestamp
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (cell_id, pci, mcc, mnc, indicator_type, details, now))

        # Count unresolved indicators
        cursor.execute('''
            SELECT COUNT(*) FROM tower_anomalies
            WHERE cell_id = ? AND pci = ? AND mcc = ? AND mnc = ?
            AND resolved = 0
        ''', (cell_id, pci, mcc, mnc))

        indicator_count = cursor.fetchone()[0]

        # Auto-blacklist if threshold reached
        if indicator_count >= self.MIN_BLACKLIST_INDICATORS:
            logger.warning(
                f"Tower {mcc}-{mnc}-{cell_id} reached {indicator_count} anomaly indicators, "
                f"blacklisting..."
            )
            self._blacklist_tower(
                conn, cell_id, pci, mcc, mnc,
                reason=f"Multiple anomalies detected ({indicator_count} indicators)",
                indicators=indicator_count
            )

        conn.commit()
        conn.close()

    def _blacklist_tower(
        self,
        conn: sqlite3.Connection,
        cell_id: int,
        pci: int,
        mcc: str,
        mnc: str,
        reason: str,
        indicators: int,
    ):
        """Internal: Blacklist a tower."""
        cursor = conn.cursor()
        now = datetime.now().isoformat()

        cursor.execute('''
            INSERT INTO tower_whitelist (
                cell_id, pci, mcc, mnc, tac, source,
                is_blacklisted, blacklist_reason, blacklist_timestamp,
                blacklist_indicators, first_seen, last_seen
            ) VALUES (?, ?, ?, ?, 0, 'auto_learned', 1, ?, ?, ?, ?, ?)
            ON CONFLICT(mcc, mnc, cell_id, pci) DO UPDATE SET
                is_blacklisted = 1,
                blacklist_reason = ?,
                blacklist_timestamp = ?,
                blacklist_indicators = ?
        ''', (
            cell_id, pci, mcc, mnc, reason, now, indicators, now, now,
            reason, now, indicators
        ))

        logger.warning(f"Blacklisted tower: {mcc}-{mnc}-{cell_id} - {reason}")

    def cleanup_blacklist(self):
        """
        Clean up expired blacklist entries.

        Per Nemotron: Implement time decay to prevent DoS via
        permanent blacklisting of legitimate towers.
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cutoff = (datetime.now() - timedelta(days=self.BLACKLIST_DECAY_DAYS)).isoformat()

        cursor.execute('''
            UPDATE tower_whitelist
            SET is_blacklisted = 0, blacklist_reason = '', blacklist_timestamp = NULL
            WHERE is_blacklisted = 1 AND blacklist_timestamp < ?
        ''', (cutoff,))

        affected = cursor.rowcount
        if affected > 0:
            logger.info(f"Removed {affected} towers from blacklist (time decay)")

        # Also resolve old anomalies
        cursor.execute('''
            UPDATE tower_anomalies
            SET resolved = 1
            WHERE resolved = 0 AND timestamp < ?
        ''', (cutoff,))

        conn.commit()
        conn.close()

    def _get_from_whitelist(
        self,
        cell_id: int,
        pci: int,
        mcc: str,
        mnc: str,
    ) -> Optional[TowerInfo]:
        """Get tower from whitelist."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute('''
            SELECT * FROM tower_whitelist
            WHERE cell_id = ? AND pci = ? AND mcc = ? AND mnc = ?
            AND is_blacklisted = 0
        ''', (cell_id, pci, mcc, mnc))

        row = cursor.fetchone()
        conn.close()

        if not row:
            return None

        return TowerInfo(
            cell_id=row[0],
            pci=row[1],
            mcc=row[2],
            mnc=row[3],
            tac=row[4],
            latitude=row[5],
            longitude=row[6],
            location_accuracy_m=row[7] or 0,
            carrier_name=row[8] or '',
            tower_type=TowerType(row[9]) if row[9] else TowerType.UNKNOWN,
            expected_bands=json.loads(row[10]) if row[10] else [],
            expected_neighbors=json.loads(row[11]) if row[11] else [],
            source=TowerSource(row[12]) if row[12] else TowerSource.AUTO_LEARNED,
            reputation_score=row[13] or 0.5,
            first_seen=datetime.fromisoformat(row[14]) if row[14] else datetime.now(),
            last_seen=datetime.fromisoformat(row[15]) if row[15] else datetime.now(),
            observation_count=row[16] or 1,
        )

    def _get_from_opencellid(
        self,
        cell_id: int,
        mcc: str,
        mnc: str,
    ) -> Optional[Dict]:
        """
        Get tower info from OpenCellID.

        Uses cache to minimize API calls.
        """
        # Check cache first
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute('''
            SELECT latitude, longitude, accuracy_m FROM opencellid_cache
            WHERE mcc = ? AND mnc = ? AND cell_id = ?
        ''', (mcc, mnc, cell_id))

        cached = cursor.fetchone()
        if cached:
            conn.close()
            return {'lat': cached[0], 'lon': cached[1], 'accuracy': cached[2]}

        conn.close()

        # Query API if token available
        if not self.opencellid_token:
            logger.debug("No OpenCellID token, skipping API lookup")
            return None

        try:
            response = requests.get(
                self.OPENCELLID_API,
                params={
                    'key': self.opencellid_token,
                    'mcc': mcc,
                    'mnc': mnc,
                    'cellid': cell_id,
                    'format': 'json',
                },
                timeout=5,
            )

            if response.status_code == 200:
                data = response.json()
                if 'lat' in data and 'lon' in data:
                    # Cache result
                    self._cache_opencellid(
                        mcc, mnc, cell_id,
                        data['lat'], data['lon'],
                        data.get('accuracy', 0)
                    )
                    return data

        except Exception as e:
            logger.warning(f"OpenCellID lookup failed: {e}")

        return None

    def _cache_opencellid(
        self,
        mcc: str,
        mnc: str,
        cell_id: int,
        lat: float,
        lon: float,
        accuracy: int,
    ):
        """Cache OpenCellID result."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute('''
            INSERT OR REPLACE INTO opencellid_cache
            (mcc, mnc, cell_id, latitude, longitude, accuracy_m, cached_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (mcc, mnc, cell_id, lat, lon, accuracy, datetime.now().isoformat()))

        conn.commit()
        conn.close()

    def _check_blacklist(
        self,
        cell_id: int,
        pci: int,
        mcc: str,
        mnc: str,
    ) -> Tuple[bool, str]:
        """Check if tower is blacklisted."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute('''
            SELECT is_blacklisted, blacklist_reason FROM tower_whitelist
            WHERE cell_id = ? AND pci = ? AND mcc = ? AND mnc = ?
        ''', (cell_id, pci, mcc, mnc))

        row = cursor.fetchone()
        conn.close()

        if row and row[0]:
            return True, row[1] or 'Unknown reason'

        return False, ''

    def _calc_confidence(
        self,
        in_whitelist: bool,
        in_opencellid: bool,
        location_verified: bool,
        location_mismatch_km: float,
    ) -> float:
        """
        Calculate confidence score for tower verification.

        Per Devstral-validated breakdown:
        - Whitelist + GPS match: 1.0
        - Whitelist + GPS mismatch: 0.5
        - OpenCellID only: 0.2
        - Unknown: 0.0
        """
        if in_whitelist and location_verified:
            return 1.0
        elif in_whitelist and not location_verified:
            # Penalty based on mismatch distance
            if location_mismatch_km > 10:
                return 0.3
            return 0.5
        elif in_opencellid:
            return 0.2
        else:
            return 0.0

    @staticmethod
    def _haversine(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
        """Calculate distance between two points in km."""
        R = 6371
        lat1_rad = math.radians(lat1)
        lat2_rad = math.radians(lat2)
        dlat = math.radians(lat2 - lat1)
        dlon = math.radians(lon2 - lon1)

        a = (math.sin(dlat/2)**2 +
             math.cos(lat1_rad) * math.cos(lat2_rad) * math.sin(dlon/2)**2)
        c = 2 * math.atan2(math.sqrt(a), math.sqrt(1-a))

        return R * c
