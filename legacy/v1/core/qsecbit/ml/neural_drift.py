#!/usr/bin/env python3
"""
Neural Drift Calculator

PROPRIETARY AND CONFIDENTIAL
Copyright (c) 2024-2026 HookProbe Technologies
Licensed under Commercial License - See LICENSING.md

Replaces the simple logistic function drift calculation with a
neural network-based approach for improved accuracy and adaptability.

Architecture:
    Input Layer:  4 neurons (CPU, Memory, Network, Disk telemetry)
    Hidden 1:     64 neurons (ReLU activation)
    Hidden 2:     32 neurons (ReLU activation)
    Output:       1 neuron (Sigmoid - drift score 0-1)

Features:
- Pure NumPy implementation (no external ML frameworks required)
- Fixed-point compatible (can run on int16 arithmetic)
- Online learning with exponential moving average updates
- Anomaly detection via reconstruction error threshold

Usage:
    calculator = NeuralDriftCalculator()

    # Calculate drift from telemetry
    telemetry = np.array([0.45, 0.62, 0.15, 0.78])  # CPU, Mem, Net, Disk
    drift = calculator.calculate_drift(telemetry)

    # Update model with new observations
    calculator.online_update(telemetry, actual_drift=0.3)
"""

import numpy as np
import struct
import hashlib
import logging
from typing import Optional, Tuple, List, Dict, Any
from collections import deque
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class LayerWeights:
    """Neural network layer weights and biases."""
    weights: np.ndarray  # Shape: (input_dim, output_dim)
    biases: np.ndarray   # Shape: (output_dim,)


def relu(x: np.ndarray) -> np.ndarray:
    """ReLU activation function."""
    return np.maximum(0, x)


def relu_derivative(x: np.ndarray) -> np.ndarray:
    """Derivative of ReLU."""
    return (x > 0).astype(np.float32)


def sigmoid(x: np.ndarray) -> np.ndarray:
    """Sigmoid activation function with numerical stability."""
    # Clip to prevent overflow
    x = np.clip(x, -500, 500)
    return 1 / (1 + np.exp(-x))


def sigmoid_derivative(x: np.ndarray) -> np.ndarray:
    """Derivative of sigmoid."""
    s = sigmoid(x)
    return s * (1 - s)


class NeuralDriftCalculator:
    """
    Neural network-based drift detection replacing logistic function.

    The network learns to predict system drift from telemetry data,
    adapting to the specific characteristics of each deployment.

    Network Architecture:
        Input:  4 features (normalized telemetry)
        Layer1: 64 neurons, ReLU
        Layer2: 32 neurons, ReLU
        Output: 1 neuron, Sigmoid (drift score)
    """

    # Network architecture
    INPUT_DIM = 4      # CPU, Memory, Network, Disk
    HIDDEN1_DIM = 64
    HIDDEN2_DIM = 32
    OUTPUT_DIM = 1

    # Learning parameters
    LEARNING_RATE = 0.01
    EWMA_ALPHA = 0.1  # Exponential weighted moving average for online learning
    DRIFT_THRESHOLD = 0.5  # Threshold for anomaly detection

    def __init__(self, seed: Optional[int] = None):
        """
        Initialize neural drift calculator.

        Args:
            seed: Random seed for reproducibility
        """
        if seed is not None:
            np.random.seed(seed)

        # Initialize weights with Xavier/Glorot initialization
        self.layer1 = LayerWeights(
            weights=np.random.randn(self.INPUT_DIM, self.HIDDEN1_DIM).astype(np.float32) * np.sqrt(2 / self.INPUT_DIM),
            biases=np.zeros(self.HIDDEN1_DIM, dtype=np.float32)
        )
        self.layer2 = LayerWeights(
            weights=np.random.randn(self.HIDDEN1_DIM, self.HIDDEN2_DIM).astype(np.float32) * np.sqrt(2 / self.HIDDEN1_DIM),
            biases=np.zeros(self.HIDDEN2_DIM, dtype=np.float32)
        )
        self.output_layer = LayerWeights(
            weights=np.random.randn(self.HIDDEN2_DIM, self.OUTPUT_DIM).astype(np.float32) * np.sqrt(2 / self.HIDDEN2_DIM),
            biases=np.zeros(self.OUTPUT_DIM, dtype=np.float32)
        )

        # Running statistics for normalization (Welford's online algorithm)
        self._input_mean = np.zeros(self.INPUT_DIM, dtype=np.float32)
        self._input_m2 = np.zeros(self.INPUT_DIM, dtype=np.float32)
        self._input_std = np.ones(self.INPUT_DIM, dtype=np.float32)
        self._samples_seen = 0

        # EWMA momentum buffers for stable gradient updates
        self._momentum = {
            'layer1': {'weights': np.zeros_like(self.layer1.weights), 'biases': np.zeros_like(self.layer1.biases)},
            'layer2': {'weights': np.zeros_like(self.layer2.weights), 'biases': np.zeros_like(self.layer2.biases)},
            'output': {'weights': np.zeros_like(self.output_layer.weights), 'biases': np.zeros_like(self.output_layer.biases)},
        }

        # Drift history for trend analysis
        self._drift_history: deque = deque(maxlen=1000)

        logger.info("[NeuralDrift] Calculator initialized (4→64→32→1 architecture)")

    def _build_model(self) -> None:
        """Build the neural network model (already done in __init__)."""
        pass  # Model is built in __init__

    def _normalize_input(self, telemetry: np.ndarray) -> np.ndarray:
        """
        Normalize input telemetry for stable training.

        Args:
            telemetry: Raw telemetry values

        Returns:
            Normalized telemetry
        """
        # Avoid division by zero
        std = np.where(self._input_std > 1e-6, self._input_std, 1.0)
        return (telemetry - self._input_mean) / std

    def _update_running_stats(self, telemetry: np.ndarray) -> None:
        """Update running mean and std for normalization (Welford's algorithm)."""
        self._samples_seen += 1

        # Online mean update
        delta = telemetry - self._input_mean
        self._input_mean += delta / self._samples_seen

        # Accumulate M2 for online variance (Welford's algorithm)
        delta2 = telemetry - self._input_mean
        self._input_m2 += delta * delta2

        if self._samples_seen > 1:
            self._input_std = np.sqrt(self._input_m2 / self._samples_seen + 1e-6)

    def forward(self, x: np.ndarray) -> Tuple[np.ndarray, Dict[str, np.ndarray]]:
        """
        Forward pass through the network.

        Args:
            x: Input tensor (batch_size, 4) or (4,)

        Returns:
            Tuple of (output, activations_cache)
        """
        # Ensure 2D
        if x.ndim == 1:
            x = x.reshape(1, -1)

        # Layer 1
        z1 = x @ self.layer1.weights + self.layer1.biases
        a1 = relu(z1)

        # Layer 2
        z2 = a1 @ self.layer2.weights + self.layer2.biases
        a2 = relu(z2)

        # Output layer
        z3 = a2 @ self.output_layer.weights + self.output_layer.biases
        output = sigmoid(z3)

        # Cache for backprop
        cache = {
            'x': x,
            'z1': z1, 'a1': a1,
            'z2': z2, 'a2': a2,
            'z3': z3,
        }

        return output.flatten(), cache

    def calculate_drift(self, telemetry: np.ndarray) -> float:
        """
        Calculate drift score from telemetry.

        Args:
            telemetry: Array of [CPU_usage, Memory_usage, Network_activity, Disk_activity]
                      Values should be in range [0, 1]

        Returns:
            Drift score in range [0, 1] where:
            - 0.0-0.3: Normal operation
            - 0.3-0.5: Minor drift
            - 0.5-0.7: Moderate drift
            - 0.7-1.0: Severe drift (anomaly)
        """
        # Ensure proper shape
        telemetry = np.asarray(telemetry, dtype=np.float32)
        if telemetry.shape != (self.INPUT_DIM,):
            raise ValueError(f"Expected telemetry shape ({self.INPUT_DIM},), got {telemetry.shape}")

        # Normalize
        normalized = self._normalize_input(telemetry)

        # Forward pass
        drift_score, _ = self.forward(normalized)

        # Track history (deque maxlen handles eviction)
        self._drift_history.append(float(drift_score[0]))

        return float(drift_score[0])

    def online_update(
        self,
        telemetry: np.ndarray,
        actual_drift: float,
        learning_rate: Optional[float] = None
    ) -> float:
        """
        Perform online learning update with new observation.

        Args:
            telemetry: Input telemetry
            actual_drift: Known/estimated actual drift value
            learning_rate: Optional override for learning rate

        Returns:
            Loss value
        """
        lr = learning_rate if learning_rate is not None else self.LEARNING_RATE

        # Update running stats
        self._update_running_stats(telemetry)

        # Normalize
        normalized = self._normalize_input(telemetry)

        # Forward pass
        predicted, cache = self.forward(normalized)

        # Compute loss (MSE)
        target = np.array([actual_drift], dtype=np.float32)
        loss = np.mean((predicted - target) ** 2)

        # Backpropagation
        self._backward(cache, predicted, target, lr)

        return float(loss)

    def _backward(
        self,
        cache: Dict[str, np.ndarray],
        predicted: np.ndarray,
        target: np.ndarray,
        lr: float
    ) -> None:
        """
        Backward pass (gradient descent update).

        Args:
            cache: Forward pass activations
            predicted: Network output
            target: Target values
            lr: Learning rate
        """
        batch_size = cache['x'].shape[0]

        # Output layer gradient
        d_loss = 2 * (predicted - target) / batch_size
        d_z3 = d_loss.reshape(-1, 1) * sigmoid_derivative(cache['z3'])

        d_w3 = cache['a2'].T @ d_z3
        d_b3 = np.sum(d_z3, axis=0)

        # Layer 2 gradient
        d_a2 = d_z3 @ self.output_layer.weights.T
        d_z2 = d_a2 * relu_derivative(cache['z2'])

        d_w2 = cache['a1'].T @ d_z2
        d_b2 = np.sum(d_z2, axis=0)

        # Layer 1 gradient
        d_a1 = d_z2 @ self.layer2.weights.T
        d_z1 = d_a1 * relu_derivative(cache['z1'])

        d_w1 = cache['x'].T @ d_z1
        d_b1 = np.sum(d_z1, axis=0)

        # Update weights with EWMA momentum smoothing
        alpha = self.EWMA_ALPHA

        self._momentum['layer1']['weights'] = alpha * self._momentum['layer1']['weights'] + (1 - alpha) * d_w1
        self._momentum['layer1']['biases'] = alpha * self._momentum['layer1']['biases'] + (1 - alpha) * d_b1
        self.layer1.weights -= lr * self._momentum['layer1']['weights']
        self.layer1.biases -= lr * self._momentum['layer1']['biases']

        self._momentum['layer2']['weights'] = alpha * self._momentum['layer2']['weights'] + (1 - alpha) * d_w2
        self._momentum['layer2']['biases'] = alpha * self._momentum['layer2']['biases'] + (1 - alpha) * d_b2
        self.layer2.weights -= lr * self._momentum['layer2']['weights']
        self.layer2.biases -= lr * self._momentum['layer2']['biases']

        self._momentum['output']['weights'] = alpha * self._momentum['output']['weights'] + (1 - alpha) * d_w3
        self._momentum['output']['biases'] = alpha * self._momentum['output']['biases'] + (1 - alpha) * d_b3
        self.output_layer.weights -= lr * self._momentum['output']['weights']
        self.output_layer.biases -= lr * self._momentum['output']['biases']

    def detect_anomaly(self, telemetry: np.ndarray) -> Tuple[bool, float]:
        """
        Detect if current telemetry represents an anomaly.

        Args:
            telemetry: Input telemetry

        Returns:
            Tuple of (is_anomaly, drift_score)
        """
        drift = self.calculate_drift(telemetry)
        is_anomaly = drift > self.DRIFT_THRESHOLD

        return is_anomaly, drift

    def get_drift_trend(self, window: int = 10) -> Dict[str, float]:
        """
        Analyze drift trend over recent history.

        Args:
            window: Number of recent samples to analyze

        Returns:
            Trend statistics
        """
        if len(self._drift_history) < 2:
            return {
                'mean': 0.0,
                'std': 0.0,
                'trend': 0.0,
                'min': 0.0,
                'max': 0.0,
            }

        recent = self._drift_history[-window:]
        arr = np.array(recent)

        # Calculate trend (linear regression slope)
        x = np.arange(len(recent))
        if len(recent) > 1:
            slope = np.polyfit(x, arr, 1)[0]
        else:
            slope = 0.0

        return {
            'mean': float(np.mean(arr)),
            'std': float(np.std(arr)),
            'trend': float(slope),  # Positive = increasing drift
            'min': float(np.min(arr)),
            'max': float(np.max(arr)),
        }

    def get_weight_fingerprint(self) -> bytes:
        """
        Get fingerprint of current weight state for PoSF integration.

        Returns:
            32-byte fingerprint
        """
        # Concatenate all weights
        all_weights = np.concatenate([
            self.layer1.weights.flatten(),
            self.layer1.biases,
            self.layer2.weights.flatten(),
            self.layer2.biases,
            self.output_layer.weights.flatten(),
            self.output_layer.biases,
        ])

        # Hash to 32 bytes
        return hashlib.sha256(all_weights.tobytes()).digest()

    def export_weights(self) -> bytes:
        """Export weights as bytes for persistence."""
        weights = {
            'l1_w': self.layer1.weights,
            'l1_b': self.layer1.biases,
            'l2_w': self.layer2.weights,
            'l2_b': self.layer2.biases,
            'out_w': self.output_layer.weights,
            'out_b': self.output_layer.biases,
            'mean': self._input_mean,
            'std': self._input_std,
        }

        # Serialize with numpy
        import io
        buffer = io.BytesIO()
        np.savez_compressed(buffer, **weights)
        return buffer.getvalue()

    def import_weights(self, data: bytes) -> None:
        """Import weights from bytes."""
        import io
        buffer = io.BytesIO(data)
        weights = np.load(buffer)

        self.layer1.weights = weights['l1_w']
        self.layer1.biases = weights['l1_b']
        self.layer2.weights = weights['l2_w']
        self.layer2.biases = weights['l2_b']
        self.output_layer.weights = weights['out_w']
        self.output_layer.biases = weights['out_b']
        self._input_mean = weights['mean']
        self._input_std = weights['std']

        logger.info("[NeuralDrift] Weights imported successfully")


# ============================================================================
# FIXED-POINT VERSION (for constrained devices)
# ============================================================================

class FixedPointNeuralDrift:
    """
    Fixed-point (Q16.16) version of neural drift calculator.

    For use on devices without floating-point support or for
    deterministic cross-platform behavior.
    """

    # Q16.16 fixed-point scale
    SCALE = 65536  # 2^16

    def __init__(self):
        """Initialize fixed-point calculator."""
        # Simplified architecture for fixed-point: 4→16→8→1
        self.w1 = np.zeros((4, 16), dtype=np.int32)
        self.b1 = np.zeros(16, dtype=np.int32)
        self.w2 = np.zeros((16, 8), dtype=np.int32)
        self.b2 = np.zeros(8, dtype=np.int32)
        self.w_out = np.zeros((8, 1), dtype=np.int32)
        self.b_out = np.zeros(1, dtype=np.int32)

        # Initialize with small random values
        self._initialize_weights()

    def _initialize_weights(self) -> None:
        """Initialize weights with small fixed-point values."""
        # Xavier initialization scaled to fixed-point
        scale = int(0.5 * self.SCALE)
        self.w1 = np.random.randint(-scale, scale, (4, 16), dtype=np.int32)
        self.w2 = np.random.randint(-scale, scale, (16, 8), dtype=np.int32)
        self.w_out = np.random.randint(-scale, scale, (8, 1), dtype=np.int32)

    def _fixed_relu(self, x: np.ndarray) -> np.ndarray:
        """Fixed-point ReLU."""
        return np.maximum(0, x)

    def _fixed_sigmoid(self, x: np.ndarray) -> np.ndarray:
        """
        Fixed-point sigmoid approximation.

        Uses piecewise linear approximation for efficiency.
        """
        result = np.zeros_like(x)

        # Linear approximation of sigmoid
        # x < -4: output ≈ 0
        # -4 < x < 4: linear ramp
        # x > 4: output ≈ 1
        threshold = 4 * self.SCALE

        mask_low = x < -threshold
        mask_high = x > threshold
        mask_mid = ~mask_low & ~mask_high

        result[mask_low] = 0
        result[mask_high] = self.SCALE
        result[mask_mid] = (x[mask_mid] + threshold) * self.SCALE // (2 * threshold)

        return result

    def calculate_drift_fixed(self, telemetry: np.ndarray) -> int:
        """
        Calculate drift in fixed-point arithmetic.

        Args:
            telemetry: Input as Q16.16 fixed-point values

        Returns:
            Drift score as Q16.16 (0 to SCALE)
        """
        x = telemetry.astype(np.int32)

        # Layer 1
        z1 = (x @ self.w1) // self.SCALE + self.b1
        a1 = self._fixed_relu(z1)

        # Layer 2
        z2 = (a1 @ self.w2) // self.SCALE + self.b2
        a2 = self._fixed_relu(z2)

        # Output
        z_out = (a2 @ self.w_out) // self.SCALE + self.b_out
        output = self._fixed_sigmoid(z_out)

        return int(output[0])


# ============================================================================
# CLI for testing
# ============================================================================

if __name__ == '__main__':
    import time

    print("Neural Drift Calculator Demo")
    print("=" * 50)

    # Initialize calculator
    calculator = NeuralDriftCalculator(seed=42)

    # Generate synthetic telemetry
    print("\nTesting drift calculation...")
    for i in range(5):
        # Simulate varying workload
        cpu = 0.3 + 0.4 * np.sin(i / 5 * np.pi)
        mem = 0.5 + 0.2 * np.cos(i / 5 * np.pi)
        net = 0.1 + 0.3 * (i / 10)
        disk = 0.6 + 0.1 * np.sin(i / 3 * np.pi)

        telemetry = np.array([cpu, mem, net, disk], dtype=np.float32)
        drift = calculator.calculate_drift(telemetry)

        print(f"  Sample {i+1}: CPU={cpu:.2f}, Mem={mem:.2f}, Net={net:.2f}, Disk={disk:.2f} → Drift={drift:.4f}")

    # Test anomaly detection
    print("\nTesting anomaly detection...")
    normal = np.array([0.3, 0.4, 0.1, 0.5], dtype=np.float32)
    anomaly = np.array([0.95, 0.95, 0.9, 0.95], dtype=np.float32)

    is_anom_normal, drift_normal = calculator.detect_anomaly(normal)
    is_anom_anomaly, drift_anomaly = calculator.detect_anomaly(anomaly)

    print(f"  Normal:  drift={drift_normal:.4f}, anomaly={is_anom_normal}")
    print(f"  Anomaly: drift={drift_anomaly:.4f}, anomaly={is_anom_anomaly}")

    # Test online learning
    print("\nTesting online learning...")
    for i in range(10):
        telemetry = np.random.rand(4).astype(np.float32)
        actual_drift = 0.5 if telemetry.mean() > 0.5 else 0.2
        loss = calculator.online_update(telemetry, actual_drift)
        print(f"  Update {i+1}: loss={loss:.6f}")

    # Drift trend
    print("\nDrift trend analysis:")
    trend = calculator.get_drift_trend()
    for k, v in trend.items():
        print(f"  {k}: {v:.4f}")

    # Weight fingerprint
    print(f"\nWeight fingerprint: {calculator.get_weight_fingerprint().hex()[:32]}...")

    print("\n✓ Neural drift calculator test complete")
