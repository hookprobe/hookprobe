"""
Clock Drift PUF — PUF from CPU clock timing variations.

Measures the drift between the CPU's Time Stamp Counter (TSC) and the
Real-Time Clock (RTC). Manufacturing variations in crystal oscillators
and CPU clock circuits produce unique, measurable timing signatures.

Works on any hardware including VMs (unlike SRAM PUF which needs
/dev/mem access). Uses time.perf_counter_ns() as TSC proxy and
time.time_ns() as RTC proxy.

Author: HookProbe Team
License: Proprietary
Version: 1.0.0
"""

import hashlib
import logging
import struct
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

# Constants
DEFAULT_MEASUREMENTS = 64        # Number of drift measurements
MEASUREMENT_DELAY_US = 100       # Microsecond delay between measurements
RESPONSE_BITS = 256              # Output response size (256 bits = 32 bytes)
MIN_HAMMING_DISTANCE = 0.15      # Minimum inter-device Hamming distance


@dataclass
class ClockMeasurement:
    """A single clock drift measurement."""
    tsc_delta: int       # TSC (perf_counter) elapsed nanoseconds
    rtc_delta: int       # RTC (time) elapsed nanoseconds
    drift_ns: int        # Difference: tsc_delta - rtc_delta
    iteration: int = 0


@dataclass
class DriftProfile:
    """Statistical profile of clock drift measurements."""
    measurements: List[ClockMeasurement]
    mean_drift_ns: float = 0.0
    std_drift_ns: float = 0.0
    response: bytes = b""        # 32-byte PUF response
    raw_drifts: List[int] = field(default_factory=list)

    def hamming_distance(self, other: "DriftProfile") -> float:
        """Calculate normalized Hamming distance to another profile."""
        if not self.response or not other.response:
            return 0.0

        distance = 0
        total_bits = min(len(self.response), len(other.response)) * 8

        for i in range(min(len(self.response), len(other.response))):
            xor = self.response[i] ^ other.response[i]
            distance += bin(xor).count("1")

        return distance / total_bits if total_bits > 0 else 0.0


class ClockDriftPuf:
    """Clock Drift PUF — works on any hardware including VMs.

    Measures subtle timing differences between high-resolution timers
    to extract a device-unique response.

    Usage:
        puf = ClockDriftPuf()
        profile = puf.measure()
        response = profile.response  # 32-byte unique response
    """

    def __init__(
        self,
        num_measurements: int = DEFAULT_MEASUREMENTS,
        measurement_delay_us: int = MEASUREMENT_DELAY_US,
    ):
        self._num_measurements = num_measurements
        self._measurement_delay_us = measurement_delay_us
        self._last_profile: Optional[DriftProfile] = None

        logger.info(
            "ClockDriftPuf initialized: measurements=%d, delay=%d us",
            num_measurements, measurement_delay_us,
        )

    def measure(self) -> DriftProfile:
        """Perform clock drift measurement and generate PUF response.

        Returns DriftProfile with 32-byte response.
        """
        measurements = []
        raw_drifts = []

        for i in range(self._num_measurements):
            m = self._single_measurement(i)
            measurements.append(m)
            raw_drifts.append(m.drift_ns)

            # Brief busy-wait between measurements
            self._busy_wait_us(self._measurement_delay_us)

        # Calculate statistics
        mean_drift = sum(raw_drifts) / len(raw_drifts) if raw_drifts else 0.0
        variance = sum((d - mean_drift) ** 2 for d in raw_drifts) / len(raw_drifts) if raw_drifts else 0.0
        std_drift = variance ** 0.5

        # Generate response from drift pattern
        response = self._drifts_to_response(raw_drifts, mean_drift)

        profile = DriftProfile(
            measurements=measurements,
            mean_drift_ns=mean_drift,
            std_drift_ns=std_drift,
            response=response,
            raw_drifts=raw_drifts,
        )

        self._last_profile = profile
        return profile

    def get_response(self) -> bytes:
        """Get 32-byte PUF response (measures if not done yet)."""
        if not self._last_profile:
            self.measure()
        return self._last_profile.response

    def verify_consistency(self, num_trials: int = 5) -> Dict:
        """Verify PUF response consistency across multiple measurements.

        Returns dict with consistency metrics.
        """
        responses = []
        for _ in range(num_trials):
            profile = self.measure()
            responses.append(profile.response)

        if len(responses) < 2:
            return {"consistent": False, "trials": 0}

        # Calculate intra-device Hamming distances
        distances = []
        for i in range(len(responses)):
            for j in range(i + 1, len(responses)):
                dist = self._hamming_distance(responses[i], responses[j])
                distances.append(dist)

        mean_distance = sum(distances) / len(distances) if distances else 0.0

        return {
            "consistent": mean_distance < 0.15,
            "trials": num_trials,
            "mean_hamming_distance": round(mean_distance, 4),
            "max_hamming_distance": round(max(distances), 4) if distances else 0.0,
            "min_hamming_distance": round(min(distances), 4) if distances else 0.0,
        }

    def get_stats(self) -> Dict:
        """Get PUF statistics."""
        result = {
            "num_measurements": self._num_measurements,
            "measurement_delay_us": self._measurement_delay_us,
            "has_profile": self._last_profile is not None,
        }
        if self._last_profile:
            result.update({
                "mean_drift_ns": round(self._last_profile.mean_drift_ns, 2),
                "std_drift_ns": round(self._last_profile.std_drift_ns, 2),
                "response_hex": self._last_profile.response[:8].hex() + "...",
            })
        return result

    # ------------------------------------------------------------------
    # Internal Methods
    # ------------------------------------------------------------------

    def _single_measurement(self, iteration: int) -> ClockMeasurement:
        """Perform a single clock drift measurement."""
        # Measure TSC (high-resolution monotonic)
        tsc_start = time.perf_counter_ns()
        rtc_start = time.time_ns()

        # Small workload to amplify drift
        _ = hashlib.sha256(struct.pack("!QI", tsc_start, iteration)).digest()

        tsc_end = time.perf_counter_ns()
        rtc_end = time.time_ns()

        tsc_delta = tsc_end - tsc_start
        rtc_delta = rtc_end - rtc_start
        drift = tsc_delta - rtc_delta

        return ClockMeasurement(
            tsc_delta=tsc_delta,
            rtc_delta=rtc_delta,
            drift_ns=drift,
            iteration=iteration,
        )

    def _drifts_to_response(
        self,
        drifts: List[int],
        mean_drift: float,
    ) -> bytes:
        """Convert drift measurements to a deterministic PUF response.

        Uses comparison-based bit extraction:
        - Compare pairs of adjacent measurements
        - If drift[i] > drift[i+1], output 1; else output 0
        - Hash the result for uniform distribution

        Also uses absolute drift magnitude relative to mean for
        additional entropy bits.
        """
        # Phase 1: Comparison-based bits
        comparison_bits = bytearray()
        for i in range(0, len(drifts) - 1, 2):
            bit = 1 if drifts[i] > drifts[i + 1] else 0
            comparison_bits.append(bit)

        # Phase 2: Above/below mean bits
        magnitude_bits = bytearray()
        for d in drifts:
            bit = 1 if d > mean_drift else 0
            magnitude_bits.append(bit)

        # Phase 3: Quantile bits (quartile of each measurement)
        sorted_drifts = sorted(drifts)
        q1_idx = len(sorted_drifts) // 4
        q3_idx = 3 * len(sorted_drifts) // 4
        q1 = sorted_drifts[q1_idx] if q1_idx < len(sorted_drifts) else 0
        q3 = sorted_drifts[q3_idx] if q3_idx < len(sorted_drifts) else 0

        quantile_bits = bytearray()
        for d in drifts:
            if d < q1:
                quantile_bits.extend([0, 0])
            elif d < mean_drift:
                quantile_bits.extend([0, 1])
            elif d < q3:
                quantile_bits.extend([1, 0])
            else:
                quantile_bits.extend([1, 1])

        # Combine all sources and hash to 32 bytes
        combined = (
            bytes(comparison_bits)
            + bytes(magnitude_bits)
            + bytes(quantile_bits)
            + struct.pack("!d", mean_drift)
        )

        return hashlib.sha256(combined).digest()

    def _busy_wait_us(self, microseconds: int) -> None:
        """Busy-wait for specified microseconds (more precise than sleep)."""
        end = time.perf_counter_ns() + microseconds * 1000
        while time.perf_counter_ns() < end:
            pass

    def _hamming_distance(self, a: bytes, b: bytes) -> float:
        """Calculate normalized Hamming distance between two byte sequences."""
        distance = 0
        total_bits = min(len(a), len(b)) * 8
        for i in range(min(len(a), len(b))):
            xor = a[i] ^ b[i]
            distance += bin(xor).count("1")
        return distance / total_bits if total_bits > 0 else 0.0
