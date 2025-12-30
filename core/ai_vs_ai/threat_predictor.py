"""
Threat Predictor

Interface with LSTM threat detection model for attack sequence prediction.
Provides unified API for both Fortress (lite) and Nexus (advanced) deployments.

Author: HookProbe Team
Version: 1.0.0
License: AGPL-3.0
"""

import json
import time
from pathlib import Path
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Tuple
from collections import deque

# NumPy is optional for lite mode
try:
    import numpy as np
    NUMPY_AVAILABLE = True
except ImportError:
    NUMPY_AVAILABLE = False

from .models import (
    ThreatPrediction,
    ComputeTask,
    ComputeTier,
)


# Attack categories (must match LSTM model)
ATTACK_CATEGORIES = [
    "unknown",
    "port_scan",
    "address_scan",
    "syn_flood",
    "udp_flood",
    "icmp_flood",
    "brute_force",
    "sql_injection",
    "xss",
    "dns_tunneling",
    "malware_c2",
    "data_exfiltration",
    "privilege_escalation",
    "lateral_movement",
    "dos_attack",
    "reconnaissance"
]

CATEGORY_TO_IDX = {cat: idx for idx, cat in enumerate(ATTACK_CATEGORIES)}
IDX_TO_CATEGORY = {idx: cat for idx, cat in enumerate(ATTACK_CATEGORIES)}

# Model paths
MODEL_DIR = Path("/opt/hookprobe/fortress/data/ml-models/trained")
DEFAULT_MODEL_PATH = MODEL_DIR / "threat_lstm.pt"


class ThreatPredictor:
    """
    Unified threat prediction interface.

    Supports:
    - Fortress Lite: Statistical fallback (no PyTorch)
    - Fortress Standard: LSTM model inference
    - Nexus Advanced: Full LSTM with ensemble models
    """

    def __init__(
        self,
        model_path: Optional[Path] = None,
        max_sequence_length: int = 20,
        compute_tier: ComputeTier = ComputeTier.FORTRESS_LITE
    ):
        self.model_path = model_path or DEFAULT_MODEL_PATH
        self.max_sequence_length = max_sequence_length
        self.compute_tier = compute_tier

        # Event sequence buffer
        self._sequence_buffer: deque = deque(maxlen=max_sequence_length)
        self._timestamps: deque = deque(maxlen=max_sequence_length)

        # Model state
        self._model = None
        self._model_loaded = False
        self._model_version = "1.0"

        # Statistical fallback (always available)
        self._transition_counts: Dict[str, Dict[str, int]] = {}
        self._category_counts: Dict[str, int] = {}

        # Performance tracking
        self._prediction_count = 0
        self._total_latency_ms = 0

        # Try to load LSTM model if not in lite mode
        if compute_tier != ComputeTier.FORTRESS_LITE:
            self._load_model()

    def _load_model(self) -> bool:
        """Load LSTM model if available"""
        try:
            import torch
            from products.fortress.lib.lstm_threat_detector import ThreatLSTM

            if self.model_path.exists():
                self._model = ThreatLSTM()
                # Use weights_only=True to prevent arbitrary code execution
                # during deserialization (CWE-502)
                self._model.load_state_dict(
                    torch.load(self.model_path, weights_only=True)
                )
                self._model.eval()
                self._model_loaded = True
                print(f"LSTM model loaded from {self.model_path}")
                return True
        except ImportError:
            print("PyTorch not available, using statistical fallback")
        except Exception as e:
            print(f"Could not load LSTM model: {e}")

        return False

    def add_event(
        self,
        attack_category: str,
        timestamp: Optional[datetime] = None
    ):
        """
        Add attack event to sequence buffer.

        Args:
            attack_category: Type of attack detected
            timestamp: Event timestamp (defaults to now)
        """
        if timestamp is None:
            timestamp = datetime.now()

        # Normalize category
        category = attack_category.lower().replace(" ", "_").replace("-", "_")
        if category not in CATEGORY_TO_IDX:
            category = "unknown"

        self._sequence_buffer.append(category)
        self._timestamps.append(timestamp)

        # Update statistical model
        self._update_statistics(category)

    def predict(self) -> ThreatPrediction:
        """
        Predict next attack type based on current sequence.

        Returns:
            ThreatPrediction with predicted attack and confidence
        """
        start_time = time.time()

        if len(self._sequence_buffer) < 2:
            return self._empty_prediction()

        # Get current sequence
        sequence = list(self._sequence_buffer)

        # Choose prediction method based on tier
        if self._model_loaded and self.compute_tier != ComputeTier.FORTRESS_LITE:
            prediction = self._lstm_predict(sequence)
        else:
            prediction = self._statistical_predict(sequence)

        # Calculate temporal features
        prediction = self._add_temporal_features(prediction)

        # Track performance
        latency_ms = (time.time() - start_time) * 1000
        self._prediction_count += 1
        self._total_latency_ms += latency_ms

        return prediction

    def _lstm_predict(self, sequence: List[str]) -> ThreatPrediction:
        """LSTM model prediction"""
        try:
            import torch

            # Encode sequence
            features = self._encode_sequence(sequence)
            X = torch.FloatTensor(features).unsqueeze(0)

            with torch.no_grad():
                outputs = self._model(X)
                probs = torch.softmax(outputs, dim=1)
                confidence, predicted_idx = torch.max(probs, 1)

                predicted_category = IDX_TO_CATEGORY.get(
                    predicted_idx.item(), "unknown"
                )

                # Build probability distribution
                prob_dist = {
                    IDX_TO_CATEGORY[i]: probs[0][i].item()
                    for i in range(len(ATTACK_CATEGORIES))
                }

            return ThreatPrediction(
                predicted_attack=predicted_category,
                confidence=confidence.item(),
                attack_probabilities=prob_dist,
                input_sequence=sequence.copy(),
                sequence_length=len(sequence),
                anomaly_score=1.0 - confidence.item(),
                is_anomalous=confidence.item() < 0.5,
                model_version=self._model_version,
            )

        except Exception as e:
            print(f"LSTM prediction error: {e}")
            return self._statistical_predict(sequence)

    def _statistical_predict(self, sequence: List[str]) -> ThreatPrediction:
        """Statistical fallback prediction (Markov chain)"""
        if not sequence:
            return self._empty_prediction()

        current_state = sequence[-1]

        # Get transition probabilities
        transitions = self._transition_counts.get(current_state, {})
        total = sum(transitions.values()) if transitions else 0

        if total == 0:
            # Fall back to global distribution
            total = sum(self._category_counts.values())
            if total == 0:
                return self._empty_prediction()

            prob_dist = {
                cat: count / total
                for cat, count in self._category_counts.items()
            }
        else:
            prob_dist = {
                cat: count / total
                for cat, count in transitions.items()
            }

        # Get top prediction
        if prob_dist:
            predicted = max(prob_dist.items(), key=lambda x: x[1])
            predicted_category = predicted[0]
            confidence = predicted[1]
        else:
            predicted_category = "unknown"
            confidence = 0.5

        # Build full probability distribution
        full_prob_dist = {cat: 0.0 for cat in ATTACK_CATEGORIES}
        full_prob_dist.update(prob_dist)

        return ThreatPrediction(
            predicted_attack=predicted_category,
            confidence=min(confidence, 0.9),  # Cap statistical confidence
            attack_probabilities=full_prob_dist,
            input_sequence=sequence.copy(),
            sequence_length=len(sequence),
            anomaly_score=self._calculate_anomaly_score(sequence),
            is_anomalous=self._is_sequence_anomalous(sequence),
            model_version="statistical",
        )

    def _add_temporal_features(
        self,
        prediction: ThreatPrediction
    ) -> ThreatPrediction:
        """Add temporal analysis to prediction"""
        if len(self._timestamps) < 2:
            return prediction

        timestamps = list(self._timestamps)

        # Calculate attack intensity (events per minute)
        time_span = (timestamps[-1] - timestamps[0]).total_seconds()
        if time_span > 0:
            prediction.attack_intensity = (len(timestamps) / time_span) * 60
        else:
            prediction.attack_intensity = 0

        # Calculate trend
        if len(timestamps) >= 5:
            # Compare first half vs second half intensity
            mid = len(timestamps) // 2
            first_half_span = (timestamps[mid] - timestamps[0]).total_seconds()
            second_half_span = (timestamps[-1] - timestamps[mid]).total_seconds()

            if first_half_span > 0 and second_half_span > 0:
                first_intensity = mid / first_half_span
                second_intensity = (len(timestamps) - mid) / second_half_span

                if second_intensity > first_intensity * 1.2:
                    prediction.trend = "increasing"
                elif second_intensity < first_intensity * 0.8:
                    prediction.trend = "decreasing"
                else:
                    prediction.trend = "stable"

        # Estimate time to next attack
        if len(timestamps) >= 3:
            intervals = [
                (timestamps[i+1] - timestamps[i]).total_seconds()
                for i in range(len(timestamps) - 1)
            ]
            if intervals:
                # Use weighted average (recent intervals weighted more)
                weights = [i + 1 for i in range(len(intervals))]
                weighted_avg = sum(w * i for w, i in zip(weights, intervals)) / sum(weights)
                prediction.time_to_next_attack = weighted_avg

        return prediction

    def _encode_sequence(self, sequence: List[str]):
        """Encode sequence for LSTM input"""
        # One-hot encode categories
        encoded = []
        for cat in sequence[-self.max_sequence_length:]:
            idx = CATEGORY_TO_IDX.get(cat, 0)
            encoded.append(idx)

        # Pad to max length
        while len(encoded) < self.max_sequence_length:
            encoded.insert(0, 0)  # Pad at beginning

        if NUMPY_AVAILABLE:
            return np.array(encoded, dtype=np.float32)
        return encoded

    def _update_statistics(self, category: str):
        """Update statistical model with new event"""
        self._category_counts[category] = self._category_counts.get(category, 0) + 1

        if len(self._sequence_buffer) >= 2:
            prev_category = list(self._sequence_buffer)[-2]
            if prev_category not in self._transition_counts:
                self._transition_counts[prev_category] = {}
            self._transition_counts[prev_category][category] = \
                self._transition_counts[prev_category].get(category, 0) + 1

    def _calculate_anomaly_score(self, sequence: List[str]) -> float:
        """Calculate anomaly score for sequence"""
        if len(sequence) < 2:
            return 0.0

        # Count unexpected transitions
        unexpected = 0
        for i in range(len(sequence) - 1):
            current = sequence[i]
            next_cat = sequence[i + 1]

            transitions = self._transition_counts.get(current, {})
            if transitions:
                total = sum(transitions.values())
                prob = transitions.get(next_cat, 0) / total
                if prob < 0.1:  # Less than 10% expected
                    unexpected += 1

        if len(sequence) > 1:
            return unexpected / (len(sequence) - 1)
        return 0.0

    def _is_sequence_anomalous(self, sequence: List[str]) -> bool:
        """Check if sequence is anomalous"""
        return self._calculate_anomaly_score(sequence) > 0.5

    def _empty_prediction(self) -> ThreatPrediction:
        """Return empty prediction"""
        return ThreatPrediction(
            predicted_attack="unknown",
            confidence=0.0,
            attack_probabilities={cat: 0.0 for cat in ATTACK_CATEGORIES},
            input_sequence=[],
            sequence_length=0,
        )

    def get_compute_task(self) -> ComputeTask:
        """Get compute task description for routing"""
        if self._model_loaded:
            return ComputeTask(
                task_type="lstm_prediction",
                estimated_memory_mb=256,
                estimated_cpu_cores=0.5,
                estimated_gpu_required=False,
                estimated_duration_sec=1,
                priority=7,
            )
        else:
            return ComputeTask(
                task_type="statistical_prediction",
                estimated_memory_mb=64,
                estimated_cpu_cores=0.1,
                estimated_gpu_required=False,
                estimated_duration_sec=0.1,
                priority=5,
            )

    def get_stats(self) -> Dict[str, Any]:
        """Get predictor statistics"""
        avg_latency = (
            self._total_latency_ms / self._prediction_count
            if self._prediction_count > 0 else 0
        )

        return {
            "model_loaded": self._model_loaded,
            "model_version": self._model_version,
            "compute_tier": self.compute_tier.value,
            "sequence_length": len(self._sequence_buffer),
            "prediction_count": self._prediction_count,
            "avg_latency_ms": avg_latency,
            "unique_categories_seen": len(self._category_counts),
            "total_events": sum(self._category_counts.values()),
        }

    def clear_sequence(self):
        """Clear the sequence buffer"""
        self._sequence_buffer.clear()
        self._timestamps.clear()

    def save_statistics(self, path: Optional[Path] = None):
        """Save statistical model for persistence"""
        if path is None:
            path = MODEL_DIR / "threat_statistics.json"

        path.parent.mkdir(parents=True, exist_ok=True)

        data = {
            "transition_counts": self._transition_counts,
            "category_counts": self._category_counts,
            "timestamp": datetime.now().isoformat(),
        }

        with open(path, 'w') as f:
            json.dump(data, f, indent=2)

    def load_statistics(self, path: Optional[Path] = None):
        """Load statistical model"""
        if path is None:
            path = MODEL_DIR / "threat_statistics.json"

        if path.exists():
            with open(path, 'r') as f:
                data = json.load(f)
                self._transition_counts = data.get("transition_counts", {})
                self._category_counts = data.get("category_counts", {})


def create_predictor_for_tier(tier: ComputeTier) -> ThreatPredictor:
    """
    Factory function to create predictor for compute tier.

    Args:
        tier: Target compute tier

    Returns:
        Configured ThreatPredictor
    """
    return ThreatPredictor(compute_tier=tier)
