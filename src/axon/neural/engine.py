"""
Deterministic Neural Network Engine

Fixed-point forward pass for PoSF signature generation.
Must produce bit-for-bit identical results across all platforms.
"""

import hashlib
import numpy as np
from typing import Optional
from .fixedpoint import (
    FixedPoint, FixedPointArray,
    fp_relu, fp_sigmoid, fp_matrix_vector_mult
)


class WeightState:
    """
    Neural network weight state representation.

    Stores all weights in Q16.16 fixed-point format for deterministic evolution.
    """

    def __init__(self, architecture: dict):
        """
        Initialize weights from architecture specification.

        Args:
            architecture: Layer sizes dict, e.g.:
                {
                    'input': 64,
                    'hidden_1': 128,
                    'hidden_2': 64,
                    'output': 32
                }
        """
        self.architecture = architecture
        self.weights = {}
        self.biases = {}

        # Initialize weights (deterministic seed required)
        self._initialize_weights()

    def _initialize_weights(self):
        """
        Initialize weights with deterministic Xavier/He initialization.
        Uses fixed-point arithmetic for determinism.
        """
        layers = list(self.architecture.items())

        for i in range(len(layers) - 1):
            layer_name, layer_size = layers[i]
            next_layer_name, next_layer_size = layers[i + 1]

            # Xavier initialization: scale = sqrt(2 / (fan_in + fan_out))
            fan_in = layer_size
            fan_out = next_layer_size
            scale = np.sqrt(2.0 / (fan_in + fan_out))

            # Generate deterministic random weights (fixed seed)
            np.random.seed(42 + i)  # Deterministic seed
            W = np.random.randn(next_layer_size, fan_in) * scale

            # Convert to fixed-point
            W_fp = FixedPointArray(W.flatten())

            # Store as matrix (list of rows)
            W_matrix = []
            for row_idx in range(next_layer_size):
                row_data = np.zeros(fan_in, dtype=np.int32)
                for col_idx in range(fan_in):
                    row_data[col_idx] = W_fp.data[row_idx * fan_in + col_idx]
                W_matrix.append(FixedPointArray(row_data))

            self.weights[f"{layer_name}_to_{next_layer_name}"] = W_matrix

            # Initialize biases to zero
            b = FixedPointArray([0.0] * next_layer_size)
            self.biases[next_layer_name] = b

    def fingerprint(self) -> bytes:
        """
        Generate 64-byte fingerprint of weight state via SHA512.

        This fingerprint is used for:
        1. Key derivation (HKDF input)
        2. Weight verification (cloud checks edge weights)
        """
        # Concatenate all weights and biases in deterministic order
        weight_bytes = b''

        for key in sorted(self.weights.keys()):
            for row in self.weights[key]:
                weight_bytes += row.to_bytes()

        for key in sorted(self.biases.keys()):
            weight_bytes += self.biases[key].to_bytes()

        # SHA512 hash
        return hashlib.sha512(weight_bytes).digest()

    def to_bytes(self) -> bytes:
        """Serialize complete weight state to bytes."""
        data = b''

        for key in sorted(self.weights.keys()):
            for row in self.weights[key]:
                data += row.to_bytes()

        for key in sorted(self.biases.keys()):
            data += self.biases[key].to_bytes()

        return data

    @classmethod
    def from_bytes(cls, data: bytes, architecture: dict) -> 'WeightState':
        """Deserialize weight state from bytes."""
        ws = cls(architecture)

        offset = 0

        # Restore weights
        for key in sorted(ws.weights.keys()):
            num_rows = len(ws.weights[key])
            row_size = len(ws.weights[key][0])
            bytes_per_row = row_size * 4  # 4 bytes per int32

            for row_idx in range(num_rows):
                row_bytes = data[offset:offset + bytes_per_row]
                ws.weights[key][row_idx] = FixedPointArray.from_bytes(row_bytes)
                offset += bytes_per_row

        # Restore biases
        for key in sorted(ws.biases.keys()):
            bias_size = len(ws.biases[key])
            bytes_size = bias_size * 4

            bias_bytes = data[offset:offset + bytes_size]
            ws.biases[key] = FixedPointArray.from_bytes(bias_bytes)
            offset += bytes_size

        return ws

    def copy(self) -> 'WeightState':
        """Create deep copy of weight state."""
        return WeightState.from_bytes(self.to_bytes(), self.architecture)


class NeuralEngine:
    """
    Deterministic neural network forward pass engine.

    Uses fixed-point arithmetic for bit-for-bit reproducibility.
    """

    def __init__(self, weight_state: WeightState):
        """
        Args:
            weight_state: Initial neural network weights
        """
        self.W = weight_state
        self.architecture = weight_state.architecture

    def forward(self, input_vector: FixedPointArray, output_layer: Optional[str] = None) -> FixedPointArray:
        """
        Forward pass through neural network.

        Args:
            input_vector: Input layer activations (fixed-point)
            output_layer: If specified, return activations from this layer

        Returns:
            Output layer activations (fixed-point)
        """
        layers = list(self.architecture.keys())

        # Start with input
        activations = input_vector

        for i in range(len(layers) - 1):
            layer_name = layers[i]
            next_layer_name = layers[i + 1]

            # Get weights and biases
            W = self.W.weights[f"{layer_name}_to_{next_layer_name}"]
            b = self.W.biases[next_layer_name]

            # Linear transformation: z = W × a + b
            z = fp_matrix_vector_mult(W, activations)

            # Add bias
            for j in range(len(z)):
                z[j] = FixedPoint(0)
                z[j].raw = z.data[j] + b.data[j]

            # Apply activation function
            if next_layer_name == 'output' or next_layer_name.endswith('_SIG_07'):
                # Sigmoid activation for output/signing layer
                activations_data = []
                for j in range(len(z)):
                    a = fp_sigmoid(z[j])
                    activations_data.append(a.raw)
                activations = FixedPointArray(np.array(activations_data, dtype=np.int32))
            else:
                # ReLU activation for hidden layers
                activations_data = []
                for j in range(len(z)):
                    a = fp_relu(z[j])
                    activations_data.append(a.raw)
                activations = FixedPointArray(np.array(activations_data, dtype=np.int32))

            # Return early if this is the requested layer
            if output_layer and next_layer_name == output_layer:
                return activations

        return activations

    def gradient_descent_step(self, ter_bytes: bytes, learning_rate: FixedPoint, integrity_coeff: FixedPoint):
        """
        Perform one step of gradient descent driven by TER.

        This is where weight evolution happens!

        Args:
            ter_bytes: 64-byte TER
            learning_rate: η_mod (time-decayed learning rate)
            integrity_coeff: C_integral × Σ_threat
        """
        # Convert TER to input vector
        input_vector = self._ter_to_input_vector(ter_bytes)

        # Forward pass to get predictions
        predictions = self.forward(input_vector)

        # Calculate loss (simplified: mean squared error from target of 0.5)
        target = FixedPoint(0.5)
        loss_base = FixedPoint(0.0)
        for i in range(len(predictions)):
            error = predictions[i] - target
            loss_base = loss_base + (error * error)

        # Modified loss with integrity penalty
        loss_new = loss_base + integrity_coeff

        # Simplified gradient update (full backprop in production)
        # For now, we'll do a simple perturbation-based update
        # TODO: Implement full fixed-point backpropagation

        # Update weights (placeholder - deterministic update based on loss)
        layers = list(self.architecture.keys())
        for i in range(len(layers) - 1):
            layer_name = layers[i]
            next_layer_name = layers[i + 1]

            W = self.W.weights[f"{layer_name}_to_{next_layer_name}"]

            # Simple update: W -= learning_rate × sign(loss_new) × small_constant
            update_direction = FixedPoint(-0.01) if loss_new.raw > 0 else FixedPoint(0.01)

            for row_idx in range(len(W)):
                for col_idx in range(len(W[row_idx])):
                    gradient = learning_rate * update_direction
                    W[row_idx][col_idx] = W[row_idx][col_idx] - gradient

    def _ter_to_input_vector(self, ter_bytes: bytes) -> FixedPointArray:
        """
        Convert 64-byte TER to fixed-point input vector.

        Normalizes bytes to [0.0, 1.0] range.
        """
        ter_array = np.frombuffer(ter_bytes, dtype=np.uint8)

        # Normalize to [0, 1]
        normalized = ter_array.astype(np.float64) / 255.0

        # Convert to fixed-point
        input_fp = FixedPointArray(normalized)

        return input_fp


# Default HookProbe Axon-Z architecture
AXON_Z_ARCHITECTURE = {
    'input': 64,       # TER size
    'hidden_1': 128,   # First hidden layer
    'hidden_2': 64,    # Second hidden layer
    'L_X_SIG_07': 32   # PoSF signing layer (output)
}


def create_initial_weights(seed: int = 42) -> WeightState:
    """
    Create initial weight state with deterministic seed.

    This should be run once during provisioning and shared between edge and cloud.

    Args:
        seed: Random seed for deterministic initialization

    Returns:
        WeightState instance
    """
    np.random.seed(seed)
    return WeightState(AXON_Z_ARCHITECTURE)


if __name__ == '__main__':
    # Test deterministic forward pass
    print("=== Testing Deterministic Neural Engine ===\n")

    # Create initial weights
    W0 = create_initial_weights(seed=42)
    print(f"Weight fingerprint: {W0.fingerprint().hex()[:32]}...")

    # Create engine
    engine = NeuralEngine(W0)

    # Test input (64 bytes of zeros)
    test_input = FixedPointArray([0.0] * 64)

    # Forward pass
    output = engine.forward(test_input, output_layer='L_X_SIG_07')

    print(f"\nOutput from L_X_SIG_07 layer:")
    print(f"  Size: {len(output)}")
    print(f"  First 8 values: {output.to_numpy()[:8]}")

    # Verify determinism - run twice
    output2 = engine.forward(test_input, output_layer='L_X_SIG_07')
    if np.array_equal(output.data, output2.data):
        print("\n✓ Determinism verified: Same input → Same output")
    else:
        print("\n❌ Determinism broken: Same input → Different output")

    # Test weight serialization
    W_bytes = W0.to_bytes()
    W_restored = WeightState.from_bytes(W_bytes, AXON_Z_ARCHITECTURE)

    if W0.fingerprint() == W_restored.fingerprint():
        print("✓ Weight serialization verified")
    else:
        print("❌ Weight serialization broken")
