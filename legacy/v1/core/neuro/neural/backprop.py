#!/usr/bin/env python3
"""
Fixed-Point Backpropagation

PROPRIETARY AND CONFIDENTIAL
Copyright (c) 2024-2026 HookProbe Technologies
Licensed under Commercial License - See LICENSING.md

Full backpropagation implementation in Q16.16 fixed-point arithmetic
for deterministic neural network training across all platforms.

Key Features:
- Bit-for-bit identical results across x86, ARM, and RISC-V
- Gradient computation via chain rule in fixed-point
- Overflow-safe intermediate calculations using 64-bit arithmetic
- Weight updates with configurable learning rate

Usage:
    backprop = FixedPointBackprop(learning_rate=0.01)

    # Forward pass (done elsewhere)
    loss = compute_loss(output, target)

    # Backward pass
    gradients = backprop.backward(loss, layers)

    # Update weights
    backprop.update_weights(weights, gradients)
"""

import numpy as np
from typing import Dict, List, Tuple, Optional, Any
from dataclasses import dataclass
import hashlib
import logging

from .fixedpoint import (
    FixedPoint, FixedPointArray, FP_SHIFT, FP_ONE,
    fp_sigmoid, fp_relu, fp_exp, fp_dot_product
)

logger = logging.getLogger(__name__)


@dataclass
class LayerCache:
    """Cached values from forward pass for backpropagation."""
    input: FixedPointArray
    pre_activation: FixedPointArray  # Before activation (z)
    output: FixedPointArray          # After activation (a)
    activation_type: str             # 'relu', 'sigmoid', 'tanh', 'linear'


@dataclass
class LayerGradients:
    """Gradients for a single layer."""
    d_weights: List[FixedPointArray]  # Shape: [output_dim][input_dim]
    d_biases: FixedPointArray         # Shape: [output_dim]


class FixedPointBackprop:
    """
    Full backpropagation in Q16.16 fixed-point arithmetic.

    Implements the standard backpropagation algorithm using only
    fixed-point operations for complete determinism.

    Algorithm:
        1. Forward pass computes activations and caches them
        2. Output layer: δ = ∂L/∂a * f'(z)
        3. Hidden layers: δ = (W^T · δ_next) * f'(z)
        4. Gradients: ∂L/∂W = δ · a^T, ∂L/∂b = δ
        5. Update: W = W - η * ∂L/∂W
    """

    # Default learning rate in fixed-point (0.01 * 65536)
    DEFAULT_LR_RAW = 655  # ~0.01

    # Gradient clipping threshold to prevent overflow
    GRADIENT_CLIP_RAW = 32767 * FP_ONE  # Max positive int16 in Q16.16

    def __init__(self, learning_rate: float = 0.01):
        """
        Initialize fixed-point backpropagation.

        Args:
            learning_rate: Learning rate (will be converted to fixed-point)
        """
        self.lr = FixedPoint(learning_rate)
        self._layer_caches: List[LayerCache] = []

        logger.debug(f"[FixedPointBackprop] Initialized with lr={learning_rate} (raw={self.lr.raw})")

    def cache_layer(
        self,
        layer_input: FixedPointArray,
        pre_activation: FixedPointArray,
        output: FixedPointArray,
        activation_type: str = 'relu'
    ) -> None:
        """
        Cache layer values during forward pass for backpropagation.

        Args:
            layer_input: Input to the layer
            pre_activation: Linear combination before activation (z = Wx + b)
            output: Output after activation (a = f(z))
            activation_type: Type of activation function
        """
        self._layer_caches.append(LayerCache(
            input=layer_input,
            pre_activation=pre_activation,
            output=output,
            activation_type=activation_type,
        ))

    def clear_cache(self) -> None:
        """Clear cached layer values."""
        self._layer_caches.clear()

    def activation_derivative(self, z: FixedPoint, activation_type: str) -> FixedPoint:
        """
        Compute activation function derivative in fixed-point.

        Args:
            z: Pre-activation value
            activation_type: Type of activation

        Returns:
            f'(z) in fixed-point
        """
        zero = FixedPoint(0.0)
        one = FixedPoint(1.0)

        if activation_type == 'relu':
            # ReLU': 1 if z > 0, else 0
            return one if z > zero else zero

        elif activation_type == 'sigmoid':
            # sigmoid'(z) = sigmoid(z) * (1 - sigmoid(z))
            sig = fp_sigmoid(z)
            return sig * (one - sig)

        elif activation_type == 'tanh':
            # tanh'(z) = 1 - tanh(z)^2
            two = FixedPoint(2.0)
            exp_2z = fp_exp(two * z)
            tanh_z = (exp_2z - one) / (exp_2z + one)
            return one - (tanh_z * tanh_z)

        elif activation_type == 'linear':
            # Linear: derivative is 1
            return one

        else:
            raise ValueError(f"Unknown activation type: {activation_type}")

    def activation_derivative_array(
        self,
        z_array: FixedPointArray,
        activation_type: str
    ) -> FixedPointArray:
        """
        Compute activation derivative for entire array.

        Args:
            z_array: Array of pre-activation values
            activation_type: Type of activation

        Returns:
            Array of derivatives
        """
        result_data = []
        for i in range(len(z_array)):
            deriv = self.activation_derivative(z_array[i], activation_type)
            result_data.append(deriv.raw)

        return FixedPointArray(np.array(result_data, dtype=np.int32))

    def compute_output_delta(
        self,
        predicted: FixedPointArray,
        target: FixedPointArray,
        pre_activation: FixedPointArray,
        activation_type: str,
        loss_type: str = 'mse'
    ) -> FixedPointArray:
        """
        Compute delta for output layer.

        δ = ∂L/∂a * f'(z)

        For MSE loss: ∂L/∂a = 2(a - y)/n
        For cross-entropy + sigmoid: δ = a - y (simplified form)

        Args:
            predicted: Network output (a)
            target: Target values (y)
            pre_activation: Pre-activation values (z)
            activation_type: Output activation type
            loss_type: Loss function type ('mse' or 'cross_entropy')

        Returns:
            Output layer delta
        """
        n = len(predicted)
        delta_data = []

        for i in range(n):
            a = predicted[i]
            y = target[i]
            z = pre_activation[i]

            if loss_type == 'cross_entropy' and activation_type == 'sigmoid':
                # Simplified gradient for cross-entropy + sigmoid
                delta = a - y
            else:
                # MSE gradient: 2(a - y) * f'(z)
                two = FixedPoint(2.0)
                n_fp = FixedPoint(float(n))
                grad_loss = (two * (a - y)) / n_fp

                # Multiply by activation derivative
                f_prime = self.activation_derivative(z, activation_type)
                delta = grad_loss * f_prime

            # Clip to prevent overflow
            if delta.raw > self.GRADIENT_CLIP_RAW:
                delta.raw = np.int32(self.GRADIENT_CLIP_RAW)
            elif delta.raw < -self.GRADIENT_CLIP_RAW:
                delta.raw = np.int32(-self.GRADIENT_CLIP_RAW)

            delta_data.append(delta.raw)

        return FixedPointArray(np.array(delta_data, dtype=np.int32))

    def compute_hidden_delta(
        self,
        delta_next: FixedPointArray,
        weights_next: List[FixedPointArray],
        pre_activation: FixedPointArray,
        activation_type: str
    ) -> FixedPointArray:
        """
        Compute delta for hidden layer via backpropagation.

        δ = (W_next^T · δ_next) * f'(z)

        Args:
            delta_next: Delta from next layer (closer to output)
            weights_next: Weights of next layer (shape: [next_dim][this_dim])
            pre_activation: Pre-activation values for this layer
            activation_type: Activation type for this layer

        Returns:
            Hidden layer delta
        """
        # Compute W^T · δ using fixed-point operations
        # W is [next_dim][this_dim], so W^T is [this_dim][next_dim]
        this_dim = len(pre_activation)
        next_dim = len(delta_next)

        delta_data = []

        for i in range(this_dim):
            # Sum over next layer: Σ(W_ji * δ_j)
            sum_val = FixedPoint(0.0)
            for j in range(next_dim):
                w_ji = weights_next[j][i]  # Weight from this[i] to next[j]
                d_j = delta_next[j]
                sum_val = sum_val + (w_ji * d_j)

            # Multiply by activation derivative
            f_prime = self.activation_derivative(pre_activation[i], activation_type)
            delta = sum_val * f_prime

            # Clip
            if delta.raw > self.GRADIENT_CLIP_RAW:
                delta.raw = np.int32(self.GRADIENT_CLIP_RAW)
            elif delta.raw < -self.GRADIENT_CLIP_RAW:
                delta.raw = np.int32(-self.GRADIENT_CLIP_RAW)

            delta_data.append(delta.raw)

        return FixedPointArray(np.array(delta_data, dtype=np.int32))

    def compute_weight_gradients(
        self,
        delta: FixedPointArray,
        layer_input: FixedPointArray
    ) -> Tuple[List[FixedPointArray], FixedPointArray]:
        """
        Compute gradients for weights and biases.

        ∂L/∂W = δ · a^T (outer product)
        ∂L/∂b = δ

        Args:
            delta: Layer delta
            layer_input: Input to the layer (activations from previous layer)

        Returns:
            (weight_gradients, bias_gradients)
        """
        output_dim = len(delta)
        input_dim = len(layer_input)

        # Weight gradients: outer product δ ⊗ a
        d_weights = []
        for i in range(output_dim):
            row_data = []
            for j in range(input_dim):
                grad = delta[i] * layer_input[j]

                # Clip
                if grad.raw > self.GRADIENT_CLIP_RAW:
                    grad.raw = np.int32(self.GRADIENT_CLIP_RAW)
                elif grad.raw < -self.GRADIENT_CLIP_RAW:
                    grad.raw = np.int32(-self.GRADIENT_CLIP_RAW)

                row_data.append(grad.raw)

            d_weights.append(FixedPointArray(np.array(row_data, dtype=np.int32)))

        # Bias gradients: δ directly
        d_biases = delta  # Copy by reference is fine since we won't modify

        return d_weights, d_biases

    def backward(
        self,
        loss: FixedPoint,
        layers: List[Dict[str, Any]]
    ) -> Dict[str, LayerGradients]:
        """
        Full backward pass through the network.

        Args:
            loss: Computed loss value
            layers: List of layer specifications with weights

        Returns:
            Dictionary mapping layer names to their gradients
        """
        if not self._layer_caches:
            raise RuntimeError("No layer caches available. Did you run forward pass?")

        gradients = {}
        num_layers = len(self._layer_caches)

        # Start from output layer
        delta = None

        for layer_idx in range(num_layers - 1, -1, -1):
            cache = self._layer_caches[layer_idx]
            layer_spec = layers[layer_idx]
            layer_name = layer_spec.get('name', f'layer_{layer_idx}')

            if layer_idx == num_layers - 1:
                # Output layer
                target = layer_spec.get('target')
                if target is None:
                    raise ValueError("Target required for output layer gradient")

                delta = self.compute_output_delta(
                    predicted=cache.output,
                    target=target,
                    pre_activation=cache.pre_activation,
                    activation_type=cache.activation_type,
                    loss_type=layer_spec.get('loss_type', 'mse')
                )
            else:
                # Hidden layer
                weights_next = layers[layer_idx + 1].get('weights')
                if weights_next is None:
                    raise ValueError(f"Weights required for layer {layer_idx + 1}")

                delta = self.compute_hidden_delta(
                    delta_next=delta,
                    weights_next=weights_next,
                    pre_activation=cache.pre_activation,
                    activation_type=cache.activation_type
                )

            # Compute gradients for this layer
            d_weights, d_biases = self.compute_weight_gradients(delta, cache.input)

            gradients[layer_name] = LayerGradients(
                d_weights=d_weights,
                d_biases=d_biases
            )

        return gradients

    def update_weights(
        self,
        weights: Dict[str, List[FixedPointArray]],
        biases: Dict[str, FixedPointArray],
        gradients: Dict[str, LayerGradients],
        learning_rate: Optional[FixedPoint] = None
    ) -> None:
        """
        Apply gradient descent step to weights.

        W = W - η * ∂L/∂W
        b = b - η * ∂L/∂b

        Args:
            weights: Dictionary of layer weights
            biases: Dictionary of layer biases
            gradients: Computed gradients
            learning_rate: Optional learning rate override
        """
        lr = learning_rate if learning_rate is not None else self.lr

        for layer_name, layer_grads in gradients.items():
            if layer_name not in weights:
                logger.warning(f"No weights found for layer {layer_name}")
                continue

            layer_weights = weights[layer_name]
            layer_biases = biases[layer_name]

            # Update weights
            for i in range(len(layer_weights)):
                for j in range(len(layer_weights[i])):
                    grad = layer_grads.d_weights[i][j]
                    update = lr * grad

                    # W_ij -= lr * grad
                    old_val = layer_weights[i][j]
                    new_val = old_val - update
                    layer_weights[i][j] = new_val

            # Update biases
            for i in range(len(layer_biases)):
                grad = layer_grads.d_biases[i]
                update = lr * grad

                old_val = layer_biases[i]
                new_val = old_val - update
                layer_biases[i] = new_val

    def get_gradient_norm(self, gradients: Dict[str, LayerGradients]) -> float:
        """
        Compute L2 norm of all gradients (for debugging/monitoring).

        Args:
            gradients: Computed gradients

        Returns:
            L2 norm as float
        """
        total_sq = 0.0

        for layer_name, layer_grads in gradients.items():
            # Weight gradients
            for row in layer_grads.d_weights:
                for i in range(len(row)):
                    val = row[i].to_float()
                    total_sq += val * val

            # Bias gradients
            for i in range(len(layer_grads.d_biases)):
                val = layer_grads.d_biases[i].to_float()
                total_sq += val * val

        return np.sqrt(total_sq)


class FixedPointNetwork:
    """
    Simple fixed-point neural network for training demonstration.
    """

    def __init__(self, layer_dims: List[int], learning_rate: float = 0.01):
        """
        Initialize network.

        Args:
            layer_dims: List of layer dimensions [input, hidden1, hidden2, ..., output]
            learning_rate: Learning rate
        """
        self.layer_dims = layer_dims
        self.backprop = FixedPointBackprop(learning_rate)

        # Initialize weights with small random values
        self.weights: Dict[str, List[FixedPointArray]] = {}
        self.biases: Dict[str, FixedPointArray] = {}

        np.random.seed(42)  # For reproducibility

        for i in range(len(layer_dims) - 1):
            layer_name = f'layer_{i}'
            input_dim = layer_dims[i]
            output_dim = layer_dims[i + 1]

            # Xavier initialization scaled to fixed-point
            scale = np.sqrt(2.0 / input_dim)
            weight_data = []
            for _ in range(output_dim):
                row = np.random.randn(input_dim) * scale
                row_fp = FixedPointArray([float(v) for v in row])
                weight_data.append(row_fp)

            self.weights[layer_name] = weight_data
            self.biases[layer_name] = FixedPointArray([0.0] * output_dim)

    def forward(self, x: FixedPointArray) -> FixedPointArray:
        """
        Forward pass through network.

        Args:
            x: Input

        Returns:
            Output
        """
        self.backprop.clear_cache()

        current = x
        num_layers = len(self.layer_dims) - 1

        for i in range(num_layers):
            layer_name = f'layer_{i}'
            weights = self.weights[layer_name]
            biases = self.biases[layer_name]

            # Linear: z = Wx + b
            z_data = []
            for j in range(len(weights)):
                dot = fp_dot_product(weights[j], current)
                z = dot + biases[j]
                z_data.append(z.raw)

            z = FixedPointArray(np.array(z_data, dtype=np.int32))

            # Activation
            activation_type = 'sigmoid' if i == num_layers - 1 else 'relu'
            a_data = []
            for j in range(len(z)):
                if activation_type == 'relu':
                    a_data.append(fp_relu(z[j]).raw)
                else:
                    a_data.append(fp_sigmoid(z[j]).raw)

            a = FixedPointArray(np.array(a_data, dtype=np.int32))

            # Cache for backprop
            self.backprop.cache_layer(current, z, a, activation_type)

            current = a

        return current

    def train_step(self, x: FixedPointArray, target: FixedPointArray) -> float:
        """
        Single training step.

        Args:
            x: Input
            target: Target output

        Returns:
            Loss value
        """
        # Forward
        output = self.forward(x)

        # Compute loss (MSE)
        loss_sum = FixedPoint(0.0)
        n = len(output)
        for i in range(n):
            diff = output[i] - target[i]
            loss_sum = loss_sum + (diff * diff)
        loss = loss_sum / FixedPoint(float(n))

        # Build layer specs for backward
        num_layers = len(self.layer_dims) - 1
        layer_specs = []

        for i in range(num_layers):
            layer_name = f'layer_{i}'
            spec = {
                'name': layer_name,
                'weights': self.weights[layer_name],
            }

            if i == num_layers - 1:
                spec['target'] = target
                spec['loss_type'] = 'mse'

            layer_specs.append(spec)

        # Backward
        gradients = self.backprop.backward(loss, layer_specs)

        # Update weights
        self.backprop.update_weights(self.weights, self.biases, gradients)

        return loss.to_float()

    def get_weight_fingerprint(self) -> bytes:
        """Get fingerprint of current weights."""
        all_weights = []
        for layer_name in sorted(self.weights.keys()):
            for row in self.weights[layer_name]:
                all_weights.append(row.to_bytes())
            all_weights.append(self.biases[layer_name].to_bytes())

        return hashlib.sha256(b''.join(all_weights)).digest()


# ============================================================================
# CLI for testing
# ============================================================================

if __name__ == '__main__':
    print("Fixed-Point Backpropagation Demo")
    print("=" * 50)

    # Create simple network: 4 → 8 → 4 → 1
    net = FixedPointNetwork([4, 8, 4, 1], learning_rate=0.1)

    print(f"Network: {net.layer_dims}")
    print(f"Initial fingerprint: {net.get_weight_fingerprint().hex()[:32]}...")

    # Generate synthetic data
    print("\nTraining on XOR-like pattern...")

    training_data = [
        ([0.0, 0.0, 0.0, 0.0], [0.0]),
        ([1.0, 0.0, 0.0, 0.0], [1.0]),
        ([0.0, 1.0, 0.0, 0.0], [1.0]),
        ([1.0, 1.0, 0.0, 0.0], [0.0]),
        ([0.0, 0.0, 1.0, 0.0], [1.0]),
        ([0.0, 0.0, 0.0, 1.0], [1.0]),
    ]

    # Train for a few epochs
    for epoch in range(5):
        total_loss = 0
        for x_data, y_data in training_data:
            x = FixedPointArray(x_data)
            y = FixedPointArray(y_data)
            loss = net.train_step(x, y)
            total_loss += loss

        avg_loss = total_loss / len(training_data)
        print(f"  Epoch {epoch + 1}: avg_loss = {avg_loss:.6f}")

    # Test inference
    print("\nTesting inference:")
    for x_data, y_data in training_data[:3]:
        x = FixedPointArray(x_data)
        output = net.forward(x)
        print(f"  Input: {x_data} → Output: {output[0].to_float():.4f} (target: {y_data[0]})")

    print(f"\nFinal fingerprint: {net.get_weight_fingerprint().hex()[:32]}...")
    print("\n✓ Fixed-point backpropagation test complete")
