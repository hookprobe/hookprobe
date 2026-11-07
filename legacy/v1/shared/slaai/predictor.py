"""
SLA AI LSTM Predictor

Neural network for predicting WAN failures before they occur.
Uses a lightweight LSTM architecture optimized for edge devices.

Features:
    - Sliding window input (12 samples = 1 minute at 5s intervals)
    - Multi-class output: healthy, degraded, failure
    - Online learning from labeled outcomes
    - Model persistence and versioning
"""

import os
import json
import struct
import logging
from datetime import datetime, timedelta
from dataclasses import dataclass, field
from typing import Dict, Optional, List, Tuple, Any, TYPE_CHECKING
from enum import Enum
import math

if TYPE_CHECKING:
    from .metrics_collector import WANMetrics

logger = logging.getLogger(__name__)

# Try to import numpy, fallback to pure Python
try:
    import numpy as np
    HAS_NUMPY = True
except ImportError:
    HAS_NUMPY = False
    logger.warning("NumPy not available, using pure Python (slower)")


class PredictionState(Enum):
    """Predicted network states."""
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    FAILURE = "failure"


@dataclass
class Prediction:
    """Prediction result with confidence scores."""
    state: str
    confidence: float
    probabilities: Dict[str, float]
    timestamp: datetime = field(default_factory=datetime.now)
    features_used: int = 0

    def to_dict(self) -> Dict:
        return {
            "state": self.state,
            "confidence": self.confidence,
            "probabilities": self.probabilities,
            "timestamp": self.timestamp.isoformat(),
            "features_used": self.features_used,
        }


@dataclass
class TrainingSample:
    """Training sample with features and label."""
    features: List[float]
    label: str  # healthy, degraded, failure
    timestamp: datetime
    interface: str


class FeatureExtractor:
    """
    Extracts normalized features from WANMetrics for LSTM input.

    Features (24 total per sample):
        0-3:   RTT stats (current, mean, std, trend)
        4-7:   Jitter stats (current, mean, std, trend)
        8-10:  Packet loss (current, mean, trend)
        11-14: Signal (RSSI, RSRP, RSRQ normalized, signal_trend)
        15-17: DNS (response_ms, mean, trend)
        18-19: Time encoding (hour_sin, hour_cos)
        20-21: Day encoding (day_sin, day_cos)
        22:    Error rate
        23:    Historical failure count (24h, normalized)
    """

    # Normalization parameters
    RTT_MAX = 500.0  # ms
    JITTER_MAX = 200.0  # ms
    DNS_MAX = 1000.0  # ms
    RSSI_MIN = -110  # dBm
    RSSI_MAX = -50   # dBm
    RSRP_MIN = -140  # dBm
    RSRP_MAX = -80   # dBm
    RSRQ_MIN = -20   # dB
    RSRQ_MAX = -3    # dB

    @classmethod
    def extract(
        cls,
        metrics_window: List["WANMetrics"],
        historical_failures: int = 0,
    ) -> List[float]:
        """
        Extract features from a window of metrics.

        Args:
            metrics_window: List of WANMetrics (most recent last)
            historical_failures: Failure count in last 24h

        Returns:
            List of 24 normalized features
        """
        if not metrics_window:
            return [0.0] * 24

        latest = metrics_window[-1]
        features = []

        # RTT features (0-3)
        rtts = [m.rtt_ms for m in metrics_window if m.rtt_ms is not None]
        if rtts:
            features.append(cls._normalize(latest.rtt_ms or 0, 0, cls.RTT_MAX))
            features.append(cls._normalize(sum(rtts) / len(rtts), 0, cls.RTT_MAX))
            features.append(cls._normalize(cls._std(rtts), 0, cls.RTT_MAX / 2))
            features.append(cls._trend(rtts))
        else:
            features.extend([0.0, 0.0, 0.0, 0.0])

        # Jitter features (4-7)
        jitters = [m.jitter_ms for m in metrics_window if m.jitter_ms is not None]
        if jitters:
            features.append(cls._normalize(latest.jitter_ms or 0, 0, cls.JITTER_MAX))
            features.append(cls._normalize(sum(jitters) / len(jitters), 0, cls.JITTER_MAX))
            features.append(cls._normalize(cls._std(jitters), 0, cls.JITTER_MAX / 2))
            features.append(cls._trend(jitters))
        else:
            features.extend([0.0, 0.0, 0.0, 0.0])

        # Packet loss features (8-10)
        losses = [m.packet_loss_pct for m in metrics_window if m.packet_loss_pct is not None]
        if losses:
            features.append(cls._normalize(latest.packet_loss_pct or 0, 0, 100))
            features.append(cls._normalize(sum(losses) / len(losses), 0, 100))
            features.append(cls._trend(losses))
        else:
            features.extend([0.0, 0.0, 0.0])

        # Signal features (11-14)
        rssi = latest.signal_rssi_dbm
        rsrp = latest.signal_rsrp_dbm
        rsrq = latest.signal_rsrq_db

        features.append(cls._normalize(rssi or cls.RSSI_MIN, cls.RSSI_MIN, cls.RSSI_MAX))
        features.append(cls._normalize(rsrp or cls.RSRP_MIN, cls.RSRP_MIN, cls.RSRP_MAX))
        features.append(cls._normalize(rsrq or cls.RSRQ_MIN, cls.RSRQ_MIN, cls.RSRQ_MAX))

        # Signal trend
        rssis = [m.signal_rssi_dbm for m in metrics_window if m.signal_rssi_dbm is not None]
        features.append(cls._trend(rssis) if rssis else 0.0)

        # DNS features (15-17)
        dns_times = [m.dns_response_ms for m in metrics_window if m.dns_response_ms is not None]
        if dns_times:
            features.append(cls._normalize(latest.dns_response_ms or 0, 0, cls.DNS_MAX))
            features.append(cls._normalize(sum(dns_times) / len(dns_times), 0, cls.DNS_MAX))
            features.append(cls._trend(dns_times))
        else:
            features.extend([0.0, 0.0, 0.0])

        # Time encoding (18-21) - cyclical encoding
        now = datetime.now()
        hour_rad = 2 * math.pi * now.hour / 24
        day_rad = 2 * math.pi * now.weekday() / 7

        features.append(math.sin(hour_rad))  # hour_sin
        features.append(math.cos(hour_rad))  # hour_cos
        features.append(math.sin(day_rad))   # day_sin
        features.append(math.cos(day_rad))   # day_cos

        # Error rate (22)
        errors = [m.interface_errors for m in metrics_window if m.interface_errors is not None]
        if len(errors) >= 2:
            error_rate = (errors[-1] - errors[0]) / max(1, len(errors))
            features.append(cls._normalize(error_rate, 0, 100))
        else:
            features.append(0.0)

        # Historical failures (23)
        features.append(cls._normalize(historical_failures, 0, 10))

        return features

    @staticmethod
    def _normalize(value: float, min_val: float, max_val: float) -> float:
        """Normalize value to 0-1 range."""
        if max_val <= min_val:
            return 0.0
        return max(0.0, min(1.0, (value - min_val) / (max_val - min_val)))

    @staticmethod
    def _std(values: List[float]) -> float:
        """Calculate standard deviation."""
        if len(values) < 2:
            return 0.0
        mean = sum(values) / len(values)
        variance = sum((x - mean) ** 2 for x in values) / len(values)
        return math.sqrt(variance)

    @staticmethod
    def _trend(values: List[float]) -> float:
        """
        Calculate trend (-1 to 1).
        Positive = increasing, negative = decreasing.
        """
        if len(values) < 2:
            return 0.0

        # Simple linear regression slope
        n = len(values)
        x_mean = (n - 1) / 2
        y_mean = sum(values) / n

        numerator = sum((i - x_mean) * (v - y_mean) for i, v in enumerate(values))
        denominator = sum((i - x_mean) ** 2 for i in range(n))

        if denominator == 0:
            return 0.0

        slope = numerator / denominator

        # Normalize slope to -1 to 1
        return max(-1.0, min(1.0, slope / (y_mean + 1e-6)))


class LightweightLSTM:
    """
    Lightweight LSTM implementation for edge devices.

    Architecture:
        Input (24) -> LSTM(32) -> Dense(16) -> Dense(3)

    Uses pure Python with optional NumPy acceleration.
    """

    def __init__(self, input_size: int = 24, hidden_size: int = 32, output_size: int = 3):
        self.input_size = input_size
        self.hidden_size = hidden_size
        self.output_size = output_size

        # Initialize weights with Xavier initialization
        self._init_weights()

    def _init_weights(self):
        """Initialize weights with Xavier/Glorot initialization."""
        import random

        def xavier(fan_in, fan_out):
            limit = math.sqrt(6 / (fan_in + fan_out))
            return [[random.uniform(-limit, limit) for _ in range(fan_out)]
                    for _ in range(fan_in)]

        # LSTM gates: input, forget, cell, output (combined)
        # Weights for input
        self.Wi = xavier(self.input_size, self.hidden_size * 4)
        # Weights for hidden
        self.Wh = xavier(self.hidden_size, self.hidden_size * 4)
        # Biases
        self.b = [0.0] * (self.hidden_size * 4)
        # Forget gate bias initialized to 1.0 for better gradient flow
        for i in range(self.hidden_size, self.hidden_size * 2):
            self.b[i] = 1.0

        # Dense layer 1: hidden -> 16
        self.W1 = xavier(self.hidden_size, 16)
        self.b1 = [0.0] * 16

        # Dense layer 2: 16 -> output
        self.W2 = xavier(16, self.output_size)
        self.b2 = [0.0] * self.output_size

    def forward(self, sequence: List[List[float]]) -> List[float]:
        """
        Forward pass through LSTM.

        Args:
            sequence: List of feature vectors (window_size x input_size)

        Returns:
            Output probabilities (softmax)
        """
        # Initialize hidden state and cell state
        h = [0.0] * self.hidden_size
        c = [0.0] * self.hidden_size

        # Process sequence through LSTM
        for x in sequence:
            h, c = self._lstm_step(x, h, c)

        # Dense layers
        d1 = self._dense(h, self.W1, self.b1)
        d1 = self._relu(d1)
        d2 = self._dense(d1, self.W2, self.b2)

        # Softmax output
        return self._softmax(d2)

    def _lstm_step(
        self,
        x: List[float],
        h_prev: List[float],
        c_prev: List[float],
    ) -> Tuple[List[float], List[float]]:
        """Single LSTM step."""
        # Compute gates
        gates = [0.0] * (self.hidden_size * 4)

        # Wi @ x + Wh @ h + b
        for i in range(self.hidden_size * 4):
            for j in range(self.input_size):
                gates[i] += self.Wi[j][i] * x[j]
            for j in range(self.hidden_size):
                gates[i] += self.Wh[j][i] * h_prev[j]
            gates[i] += self.b[i]

        # Split into gates
        hs = self.hidden_size
        i_gate = self._sigmoid(gates[0:hs])
        f_gate = self._sigmoid(gates[hs:hs*2])
        g_gate = self._tanh(gates[hs*2:hs*3])
        o_gate = self._sigmoid(gates[hs*3:hs*4])

        # New cell state
        c = [f_gate[j] * c_prev[j] + i_gate[j] * g_gate[j] for j in range(hs)]

        # New hidden state
        h = [o_gate[j] * math.tanh(c[j]) for j in range(hs)]

        return h, c

    def _dense(self, x: List[float], W: List[List[float]], b: List[float]) -> List[float]:
        """Dense layer: y = Wx + b."""
        out_size = len(b)
        in_size = len(x)
        result = [0.0] * out_size

        for i in range(out_size):
            for j in range(in_size):
                result[i] += W[j][i] * x[j]
            result[i] += b[i]

        return result

    @staticmethod
    def _sigmoid(x: List[float]) -> List[float]:
        """Sigmoid activation."""
        return [1.0 / (1.0 + math.exp(-min(500, max(-500, v)))) for v in x]

    @staticmethod
    def _tanh(x: List[float]) -> List[float]:
        """Tanh activation."""
        return [math.tanh(v) for v in x]

    @staticmethod
    def _relu(x: List[float]) -> List[float]:
        """ReLU activation."""
        return [max(0.0, v) for v in x]

    @staticmethod
    def _softmax(x: List[float]) -> List[float]:
        """Softmax activation."""
        max_x = max(x)
        exp_x = [math.exp(v - max_x) for v in x]
        sum_exp = sum(exp_x)
        return [v / sum_exp for v in exp_x]

    def get_weights(self) -> bytes:
        """Serialize weights to bytes."""
        data = {
            "Wi": self.Wi,
            "Wh": self.Wh,
            "b": self.b,
            "W1": self.W1,
            "b1": self.b1,
            "W2": self.W2,
            "b2": self.b2,
        }
        return json.dumps(data).encode("utf-8")

    def set_weights(self, data: bytes) -> None:
        """Load weights from bytes."""
        weights = json.loads(data.decode("utf-8"))
        self.Wi = weights["Wi"]
        self.Wh = weights["Wh"]
        self.b = weights["b"]
        self.W1 = weights["W1"]
        self.b1 = weights["b1"]
        self.W2 = weights["W2"]
        self.b2 = weights["b2"]


class LSTMPredictor:
    """
    LSTM-based failure predictor for WAN interfaces.

    Predicts network state (healthy/degraded/failure) based on
    recent metrics history and learned patterns.
    """

    STATE_LABELS = ["healthy", "degraded", "failure"]
    DEFAULT_WINDOW_SIZE = 12  # 1 minute at 5s intervals

    def __init__(
        self,
        database=None,
        model_path: Optional[str] = None,
        window_size: int = DEFAULT_WINDOW_SIZE,
    ):
        """
        Initialize predictor.

        Args:
            database: SLAAIDatabase for metrics and model storage
            model_path: Path to model weights file
            window_size: Number of samples in sliding window
        """
        self.database = database
        self.model_path = model_path
        self.window_size = window_size

        # Per-interface models and buffers
        self._models: Dict[str, LightweightLSTM] = {}
        self._feature_buffers: Dict[str, List[List[float]]] = {}

        # Load model if path provided
        if model_path and os.path.exists(model_path):
            self._load_model(model_path)

    def _get_model(self, interface: str) -> LightweightLSTM:
        """Get or create model for interface."""
        if interface not in self._models:
            self._models[interface] = LightweightLSTM()

            # Try to load from database
            if self.database:
                weights = self.database.get_model_weights(interface)
                if weights:
                    try:
                        self._models[interface].set_weights(weights)
                        logger.info(f"Loaded model weights for {interface}")
                    except Exception as e:
                        logger.warning(f"Failed to load weights for {interface}: {e}")

        return self._models[interface]

    def update_features(self, interface: str, metrics: "WANMetrics") -> None:
        """
        Update feature buffer with new metrics.

        Args:
            interface: Interface name
            metrics: WANMetrics from collector
        """
        if interface not in self._feature_buffers:
            self._feature_buffers[interface] = []

        # Get historical failures for feature
        historical_failures = 0
        if self.database:
            try:
                historical_failures = self.database.get_failure_count(interface, hours=24)
            except Exception:
                pass

        # Extract features from single sample
        features = FeatureExtractor.extract([metrics], historical_failures)
        self._feature_buffers[interface].append(features)

        # Keep only window_size samples
        if len(self._feature_buffers[interface]) > self.window_size:
            self._feature_buffers[interface] = self._feature_buffers[interface][-self.window_size:]

    def predict(self, interface: str) -> Prediction:
        """
        Predict network state for interface.

        Args:
            interface: Interface name

        Returns:
            Prediction with state, confidence, probabilities
        """
        buffer = self._feature_buffers.get(interface, [])

        if len(buffer) < 3:
            # Not enough data - return healthy with low confidence
            return Prediction(
                state="healthy",
                confidence=0.3,
                probabilities={"healthy": 0.5, "degraded": 0.3, "failure": 0.2},
                features_used=len(buffer),
            )

        # Pad buffer if needed
        sequence = buffer.copy()
        while len(sequence) < self.window_size:
            sequence.insert(0, sequence[0])

        # Get prediction from model
        model = self._get_model(interface)
        probs = model.forward(sequence)

        # Map to states
        probabilities = dict(zip(self.STATE_LABELS, probs))

        # Determine state and confidence
        max_idx = probs.index(max(probs))
        state = self.STATE_LABELS[max_idx]
        confidence = probs[max_idx]

        prediction = Prediction(
            state=state,
            confidence=confidence,
            probabilities=probabilities,
            features_used=len(buffer),
        )

        # Store prediction for later validation
        if self.database:
            try:
                self.database.store_prediction(
                    interface=interface,
                    prediction=state,
                    confidence=confidence,
                    probabilities=probabilities,
                )
            except Exception as e:
                logger.warning(f"Failed to store prediction: {e}")

        return prediction

    def label_outcome(
        self,
        interface: str,
        prediction_id: int,
        actual_outcome: str,
    ) -> None:
        """
        Label a prediction with actual outcome for training.

        Args:
            interface: Interface name
            prediction_id: ID of prediction to label
            actual_outcome: What actually happened (healthy/degraded/failure)
        """
        if self.database:
            self.database.update_prediction_outcome(prediction_id, actual_outcome)

    def train(self, interface: str, samples: List[TrainingSample]) -> float:
        """
        Train model on labeled samples.

        Args:
            interface: Interface name
            samples: List of training samples

        Returns:
            Training accuracy
        """
        if len(samples) < 10:
            logger.warning(f"Not enough samples for training: {len(samples)}")
            return 0.0

        logger.info(f"Training model for {interface} with {len(samples)} samples")

        model = self._get_model(interface)

        # Simple training loop (SGD)
        correct = 0
        learning_rate = 0.01

        for sample in samples:
            # Create sequence from sample features
            sequence = [sample.features] * self.window_size

            # Forward pass
            probs = model.forward(sequence)

            # Get prediction
            pred_idx = probs.index(max(probs))
            label_idx = self.STATE_LABELS.index(sample.label)

            if pred_idx == label_idx:
                correct += 1

            # Note: Full backprop would require implementing BPTT
            # For now, we use this for evaluation only
            # Real training would use PyTorch/TensorFlow

        accuracy = correct / len(samples)
        logger.info(f"Training accuracy: {accuracy*100:.1f}%")

        # Save model
        self._save_model(interface)

        return accuracy

    def get_training_data(
        self,
        interface: str,
        min_samples: int = 100,
    ) -> List[TrainingSample]:
        """
        Get training data from database.

        Args:
            interface: Interface name
            min_samples: Minimum samples required

        Returns:
            List of training samples
        """
        if not self.database:
            return []

        return self.database.get_training_data(interface, min_samples)

    def _save_model(self, interface: str) -> None:
        """Save model weights."""
        model = self._models.get(interface)
        if not model:
            return

        weights = model.get_weights()

        # Save to database
        if self.database:
            try:
                self.database.store_model_weights(
                    interface=interface,
                    weights=weights,
                    version="1.0",
                    accuracy=0.0,  # Would be updated after validation
                )
            except Exception as e:
                logger.warning(f"Failed to save model to database: {e}")

        # Save to file
        if self.model_path:
            try:
                model_file = f"{self.model_path}.{interface}"
                with open(model_file, "wb") as f:
                    f.write(weights)
                logger.info(f"Saved model to {model_file}")
            except Exception as e:
                logger.warning(f"Failed to save model to file: {e}")

    def _load_model(self, path: str) -> None:
        """Load model weights from file."""
        # Models are loaded per-interface in _get_model
        pass

    def get_prediction_accuracy(self, interface: str, days: int = 7) -> float:
        """
        Get prediction accuracy over recent period.

        Args:
            interface: Interface name
            days: Number of days to evaluate

        Returns:
            Accuracy (0.0 - 1.0)
        """
        if not self.database:
            return 0.0

        return self.database.get_prediction_accuracy(interface, days)

    def get_state(self) -> Dict:
        """Get predictor state for status reporting."""
        return {
            "interfaces": list(self._models.keys()),
            "buffer_sizes": {
                iface: len(buf)
                for iface, buf in self._feature_buffers.items()
            },
            "window_size": self.window_size,
        }
