#!/usr/bin/env python3
"""
Variational Autoencoder (VAE) Anomaly Detection

PROPRIETARY AND CONFIDENTIAL
Copyright (c) 2024-2026 HookProbe Technologies
Licensed under Commercial License - See LICENSING.md

Replaces quantum drift entropy analysis with a Variational Autoencoder
for system entropy anomaly detection. The VAE learns the normal distribution
of system entropy and detects anomalies via reconstruction error.

Architecture:
    Encoder: input_dim → 64 → 32 → latent_dim (mean, log_var)
    Decoder: latent_dim → 32 → 64 → input_dim

Anomaly Detection:
    - Reconstruction error > threshold → anomaly
    - KL divergence spike → distribution shift
    - Latent space distance → novelty detection

Usage:
    detector = VAEAnomalyDetector(latent_dim=16)

    # Train on normal data
    for batch in normal_entropy_data:
        loss = detector.train_step(batch)

    # Detect anomalies
    anomaly_score = detector.detect_anomaly(new_sample)
    if anomaly_score > threshold:
        raise AnomalyDetected()
"""

import numpy as np
import hashlib
import logging
from typing import Optional, Tuple, List, Dict, Any
from dataclasses import dataclass

logger = logging.getLogger(__name__)


def softplus(x: np.ndarray) -> np.ndarray:
    """Softplus activation: log(1 + exp(x)) with numerical stability."""
    return np.where(x > 20, x, np.log1p(np.exp(np.clip(x, -20, 20))))


def relu(x: np.ndarray) -> np.ndarray:
    """ReLU activation function."""
    return np.maximum(0, x)


def relu_derivative(x: np.ndarray) -> np.ndarray:
    """Derivative of ReLU."""
    return (x > 0).astype(np.float32)


def sigmoid(x: np.ndarray) -> np.ndarray:
    """Sigmoid activation with numerical stability."""
    x = np.clip(x, -500, 500)
    return 1 / (1 + np.exp(-x))


@dataclass
class VAELayerWeights:
    """VAE layer weights."""
    weights: np.ndarray
    biases: np.ndarray


class VAEEncoder:
    """VAE Encoder network."""

    def __init__(self, input_dim: int, hidden_dims: List[int], latent_dim: int):
        """
        Initialize encoder.

        Args:
            input_dim: Input dimension
            hidden_dims: Hidden layer dimensions
            latent_dim: Latent space dimension
        """
        self.input_dim = input_dim
        self.hidden_dims = hidden_dims
        self.latent_dim = latent_dim

        # Build layers
        dims = [input_dim] + hidden_dims
        self.layers = []

        for i in range(len(dims) - 1):
            self.layers.append(VAELayerWeights(
                weights=np.random.randn(dims[i], dims[i+1]).astype(np.float32) * np.sqrt(2 / dims[i]),
                biases=np.zeros(dims[i+1], dtype=np.float32)
            ))

        # Mean and log variance layers
        final_hidden = hidden_dims[-1]
        self.mean_layer = VAELayerWeights(
            weights=np.random.randn(final_hidden, latent_dim).astype(np.float32) * np.sqrt(2 / final_hidden),
            biases=np.zeros(latent_dim, dtype=np.float32)
        )
        self.logvar_layer = VAELayerWeights(
            weights=np.random.randn(final_hidden, latent_dim).astype(np.float32) * np.sqrt(2 / final_hidden),
            biases=np.zeros(latent_dim, dtype=np.float32)
        )

    def forward(self, x: np.ndarray) -> Tuple[np.ndarray, np.ndarray, Dict]:
        """
        Forward pass through encoder.

        Args:
            x: Input tensor

        Returns:
            (mean, log_variance, activations_cache)
        """
        if x.ndim == 1:
            x = x.reshape(1, -1)

        cache = {'input': x, 'activations': [], 'pre_activations': []}

        # Hidden layers with ReLU
        h = x
        for layer in self.layers:
            z = h @ layer.weights + layer.biases
            cache['pre_activations'].append(z)
            h = relu(z)
            cache['activations'].append(h)

        # Mean and log variance
        mean = h @ self.mean_layer.weights + self.mean_layer.biases
        logvar = h @ self.logvar_layer.weights + self.logvar_layer.biases

        # Clamp log variance for stability
        logvar = np.clip(logvar, -20, 20)

        cache['final_hidden'] = h

        return mean, logvar, cache


class VAEDecoder:
    """VAE Decoder network."""

    def __init__(self, latent_dim: int, hidden_dims: List[int], output_dim: int):
        """
        Initialize decoder.

        Args:
            latent_dim: Latent space dimension
            hidden_dims: Hidden layer dimensions (reversed from encoder)
            output_dim: Output dimension (same as encoder input)
        """
        self.latent_dim = latent_dim
        self.hidden_dims = hidden_dims
        self.output_dim = output_dim

        # Build layers
        dims = [latent_dim] + hidden_dims + [output_dim]
        self.layers = []

        for i in range(len(dims) - 1):
            self.layers.append(VAELayerWeights(
                weights=np.random.randn(dims[i], dims[i+1]).astype(np.float32) * np.sqrt(2 / dims[i]),
                biases=np.zeros(dims[i+1], dtype=np.float32)
            ))

    def forward(self, z: np.ndarray) -> Tuple[np.ndarray, Dict]:
        """
        Forward pass through decoder.

        Args:
            z: Latent space sample

        Returns:
            (reconstruction, activations_cache)
        """
        if z.ndim == 1:
            z = z.reshape(1, -1)

        cache = {'input': z, 'activations': [], 'pre_activations': []}

        h = z
        for i, layer in enumerate(self.layers):
            z_layer = h @ layer.weights + layer.biases
            cache['pre_activations'].append(z_layer)

            # ReLU for hidden, sigmoid for output
            if i < len(self.layers) - 1:
                h = relu(z_layer)
            else:
                h = sigmoid(z_layer)  # Output in [0, 1]

            cache['activations'].append(h)

        return h, cache


class VAEAnomalyDetector:
    """
    Variational Autoencoder for system entropy anomaly detection.

    The VAE learns a probabilistic model of normal system entropy
    patterns. Anomalies are detected via:
    1. Reconstruction error (MSE between input and output)
    2. KL divergence from prior
    3. Distance in latent space from normal cluster

    Architecture:
        Encoder: input_dim → 64 → 32 → latent_dim (mean, logvar)
        Decoder: latent_dim → 32 → 64 → input_dim
    """

    # Default architecture
    DEFAULT_HIDDEN_DIMS = [64, 32]
    DEFAULT_LATENT_DIM = 16

    # Training parameters
    LEARNING_RATE = 0.001
    KL_WEIGHT = 0.1  # Weight of KL divergence in loss

    # Anomaly detection thresholds
    RECONSTRUCTION_THRESHOLD = 0.1
    KL_THRESHOLD = 2.0
    LATENT_DISTANCE_THRESHOLD = 3.0  # Standard deviations

    def __init__(
        self,
        input_dim: int = 32,
        latent_dim: int = DEFAULT_LATENT_DIM,
        hidden_dims: Optional[List[int]] = None,
        seed: Optional[int] = None
    ):
        """
        Initialize VAE anomaly detector.

        Args:
            input_dim: Dimension of input entropy vector
            latent_dim: Dimension of latent space
            hidden_dims: Hidden layer dimensions (default: [64, 32])
            seed: Random seed for reproducibility
        """
        if seed is not None:
            np.random.seed(seed)

        self.input_dim = input_dim
        self.latent_dim = latent_dim
        self.hidden_dims = hidden_dims or self.DEFAULT_HIDDEN_DIMS

        # Build encoder and decoder
        self.encoder = VAEEncoder(input_dim, self.hidden_dims, latent_dim)
        self.decoder = VAEDecoder(latent_dim, list(reversed(self.hidden_dims)), input_dim)

        # Running statistics for latent space
        self._latent_mean = np.zeros(latent_dim, dtype=np.float32)
        self._latent_var = np.ones(latent_dim, dtype=np.float32)
        self._samples_seen = 0

        # Training history
        self._loss_history: List[float] = []
        self._recon_loss_history: List[float] = []
        self._kl_loss_history: List[float] = []

        logger.info(f"[VAE] Anomaly detector initialized ({input_dim}→{self.hidden_dims}→{latent_dim}→{list(reversed(self.hidden_dims))}→{input_dim})")

    def _reparameterize(self, mean: np.ndarray, logvar: np.ndarray) -> np.ndarray:
        """
        Reparameterization trick for sampling from latent distribution.

        z = mean + std * epsilon, where epsilon ~ N(0, I)

        Args:
            mean: Mean of latent distribution
            logvar: Log variance of latent distribution

        Returns:
            Sampled latent vector
        """
        std = np.exp(0.5 * logvar)
        epsilon = np.random.randn(*mean.shape).astype(np.float32)
        return mean + std * epsilon

    def forward(self, x: np.ndarray) -> Tuple[np.ndarray, np.ndarray, np.ndarray, np.ndarray]:
        """
        Full forward pass through VAE.

        Args:
            x: Input entropy vector

        Returns:
            (reconstruction, mean, logvar, z)
        """
        # Encode
        mean, logvar, enc_cache = self.encoder.forward(x)

        # Sample from latent distribution
        z = self._reparameterize(mean, logvar)

        # Decode
        reconstruction, dec_cache = self.decoder.forward(z)

        # Cache activations for backprop (avoids O(n²) recomputation)
        self._last_enc_cache = enc_cache
        self._last_dec_cache = dec_cache

        return reconstruction, mean, logvar, z

    def compute_loss(
        self,
        x: np.ndarray,
        reconstruction: np.ndarray,
        mean: np.ndarray,
        logvar: np.ndarray
    ) -> Tuple[float, float, float]:
        """
        Compute VAE loss (reconstruction + KL divergence).

        Args:
            x: Original input
            reconstruction: Reconstructed output
            mean: Latent mean
            logvar: Latent log variance

        Returns:
            (total_loss, reconstruction_loss, kl_loss)
        """
        # Reconstruction loss (MSE)
        recon_loss = np.mean((x - reconstruction) ** 2)

        # KL divergence: -0.5 * sum(1 + log(sigma^2) - mu^2 - sigma^2)
        kl_loss = -0.5 * np.mean(1 + logvar - mean**2 - np.exp(logvar))

        # Total loss
        total_loss = recon_loss + self.KL_WEIGHT * kl_loss

        return float(total_loss), float(recon_loss), float(kl_loss)

    def train_step(self, x: np.ndarray, learning_rate: Optional[float] = None) -> Dict[str, float]:
        """
        Single training step.

        Args:
            x: Input batch
            learning_rate: Optional learning rate override

        Returns:
            Loss dictionary
        """
        lr = learning_rate if learning_rate is not None else self.LEARNING_RATE

        if x.ndim == 1:
            x = x.reshape(1, -1)

        # Forward pass
        reconstruction, mean, logvar, z = self.forward(x)

        # Compute loss
        total_loss, recon_loss, kl_loss = self.compute_loss(x, reconstruction, mean, logvar)

        # Simple gradient descent update (without full backprop for simplicity)
        # In practice, use autograd framework
        self._update_weights_simple(x, reconstruction, mean, logvar, z, lr)

        # Update latent statistics
        self._update_latent_stats(mean)

        # Track history
        self._loss_history.append(total_loss)
        self._recon_loss_history.append(recon_loss)
        self._kl_loss_history.append(kl_loss)

        return {
            'total_loss': total_loss,
            'recon_loss': recon_loss,
            'kl_loss': kl_loss,
        }

    def _update_weights_simple(
        self,
        x: np.ndarray,
        reconstruction: np.ndarray,
        mean: np.ndarray,
        logvar: np.ndarray,
        z: np.ndarray,
        lr: float
    ) -> None:
        """
        Full backpropagation through encoder and decoder.

        Uses cached activations from forward() to avoid O(n²) recomputation.
        Computes gradients for reconstruction loss (MSE) and KL divergence,
        propagating through all layers.
        """
        batch_size = x.shape[0]
        dec_cache = self._last_dec_cache
        enc_cache = self._last_enc_cache

        # ---- Decoder backward pass ----
        # Output gradient (dL/d_reconstruction)
        d_out = (reconstruction - x) * 2.0 / batch_size

        # Backprop through decoder layers (reverse order) using cached activations
        d_h = d_out
        decoder_grads = []
        for i in reversed(range(len(self.decoder.layers))):
            # Use cached pre-activations for correct derivatives
            pre_act = dec_cache['pre_activations'][i]
            if i == len(self.decoder.layers) - 1:
                # Sigmoid output layer
                act = dec_cache['activations'][i]
                d_z = d_h * act * (1 - act)
            else:
                # ReLU hidden layers
                d_z = d_h * relu_derivative(pre_act)

            # Get input to this layer from cache (O(1) instead of O(n) re-forward)
            if i == 0:
                layer_input = dec_cache['input']  # z
            else:
                layer_input = dec_cache['activations'][i - 1]

            grad_w = layer_input.T @ d_z
            grad_b = np.sum(d_z, axis=0)
            decoder_grads.append((grad_w, grad_b))

            # Propagate gradient to previous layer
            d_h = d_z @ self.decoder.layers[i].weights.T

        # Apply decoder gradients
        for i, (gw, gb) in enumerate(reversed(decoder_grads)):
            self.decoder.layers[i].weights -= lr * gw
            self.decoder.layers[i].biases -= lr * gb

        # ---- Encoder backward pass ----
        # Gradient through z → mean and logvar (reparameterization)
        kl_grad_mean = self.KL_WEIGHT * mean / batch_size
        d_mean = d_h + kl_grad_mean

        kl_grad_logvar = self.KL_WEIGHT * 0.5 * (np.exp(logvar) - 1) / batch_size

        # Use cached final hidden activation (O(1) instead of re-forward)
        enc_final_h = enc_cache['final_hidden']

        # Mean layer gradients
        self.encoder.mean_layer.weights -= lr * (enc_final_h.T @ d_mean)
        self.encoder.mean_layer.biases -= lr * np.sum(d_mean, axis=0)

        # Logvar layer gradients
        self.encoder.logvar_layer.weights -= lr * (enc_final_h.T @ kl_grad_logvar)
        self.encoder.logvar_layer.biases -= lr * np.sum(kl_grad_logvar, axis=0)

        # Backprop through encoder hidden layers using cached activations
        d_h_enc = d_mean @ self.encoder.mean_layer.weights.T + kl_grad_logvar @ self.encoder.logvar_layer.weights.T
        for i in reversed(range(len(self.encoder.layers))):
            # Use cached pre-activations
            pre_act = enc_cache['pre_activations'][i]
            d_z = d_h_enc * relu_derivative(pre_act)

            # Use cached input (O(1) instead of O(n) re-forward)
            if i == 0:
                layer_input = enc_cache['input']  # x
            else:
                layer_input = enc_cache['activations'][i - 1]

            self.encoder.layers[i].weights -= lr * (layer_input.T @ d_z)
            self.encoder.layers[i].biases -= lr * np.sum(d_z, axis=0)

            d_h_enc = d_z @ self.encoder.layers[i].weights.T

    def _update_latent_stats(self, mean: np.ndarray) -> None:
        """Update running latent space statistics."""
        batch_mean = np.mean(mean, axis=0)
        self._samples_seen += mean.shape[0]

        # Online mean update
        alpha = min(0.1, 1.0 / self._samples_seen)
        self._latent_mean = (1 - alpha) * self._latent_mean + alpha * batch_mean

        # Online variance update (simplified)
        batch_var = np.var(mean, axis=0)
        self._latent_var = (1 - alpha) * self._latent_var + alpha * batch_var

    def detect_anomaly(self, entropy_vector: np.ndarray) -> float:
        """
        Detect anomaly based on reconstruction error.

        Args:
            entropy_vector: System entropy vector

        Returns:
            Anomaly score (0 = normal, higher = more anomalous)
        """
        if entropy_vector.ndim == 1:
            entropy_vector = entropy_vector.reshape(1, -1)

        # Forward pass
        reconstruction, mean, logvar, z = self.forward(entropy_vector)

        # Reconstruction error
        recon_error = np.mean((entropy_vector - reconstruction) ** 2)

        # KL divergence
        kl_div = -0.5 * np.mean(1 + logvar - mean**2 - np.exp(logvar))

        # Latent space distance from normal distribution
        latent_distance = np.sqrt(np.sum((mean - self._latent_mean)**2 / (self._latent_var + 1e-6)))

        # Combined anomaly score
        anomaly_score = (
            recon_error / self.RECONSTRUCTION_THRESHOLD +
            kl_div / self.KL_THRESHOLD +
            latent_distance / self.LATENT_DISTANCE_THRESHOLD
        ) / 3.0

        return float(anomaly_score)

    def is_anomaly(self, entropy_vector: np.ndarray, threshold: float = 1.0) -> Tuple[bool, float]:
        """
        Check if entropy vector is anomalous.

        Args:
            entropy_vector: Input entropy
            threshold: Anomaly threshold (default 1.0)

        Returns:
            (is_anomaly, anomaly_score)
        """
        score = self.detect_anomaly(entropy_vector)
        return score > threshold, score

    def get_latent_representation(self, x: np.ndarray) -> np.ndarray:
        """
        Get latent space representation of input.

        Args:
            x: Input entropy vector

        Returns:
            Latent space vector (mean)
        """
        mean, _, _ = self.encoder.forward(x)
        return mean.flatten()

    def reconstruct(self, x: np.ndarray) -> np.ndarray:
        """
        Reconstruct input through VAE.

        Args:
            x: Input entropy vector

        Returns:
            Reconstructed vector
        """
        reconstruction, _, _, _ = self.forward(x)
        return reconstruction.flatten()

    def get_training_stats(self) -> Dict[str, Any]:
        """Get training statistics."""
        return {
            'samples_seen': self._samples_seen,
            'total_loss': self._loss_history[-1] if self._loss_history else 0,
            'recon_loss': self._recon_loss_history[-1] if self._recon_loss_history else 0,
            'kl_loss': self._kl_loss_history[-1] if self._kl_loss_history else 0,
            'latent_mean': self._latent_mean.tolist(),
            'latent_var': self._latent_var.tolist(),
        }

    def get_weight_fingerprint(self) -> bytes:
        """Get fingerprint of VAE weights."""
        # Concatenate all weights
        all_weights = []
        for layer in self.encoder.layers:
            all_weights.extend([layer.weights.flatten(), layer.biases])
        all_weights.extend([
            self.encoder.mean_layer.weights.flatten(),
            self.encoder.mean_layer.biases,
            self.encoder.logvar_layer.weights.flatten(),
            self.encoder.logvar_layer.biases,
        ])
        for layer in self.decoder.layers:
            all_weights.extend([layer.weights.flatten(), layer.biases])

        concatenated = np.concatenate(all_weights)
        return hashlib.sha256(concatenated.tobytes()).digest()


# ============================================================================
# CLI for testing
# ============================================================================

if __name__ == '__main__':
    print("VAE Anomaly Detector Demo")
    print("=" * 50)

    # Initialize detector
    np.random.seed(42)
    detector = VAEAnomalyDetector(input_dim=32, latent_dim=8, seed=42)

    # Generate synthetic normal data
    print("\nGenerating synthetic normal entropy data...")
    normal_mean = np.random.rand(32).astype(np.float32) * 0.5
    normal_data = np.clip(
        normal_mean + np.random.randn(100, 32).astype(np.float32) * 0.1,
        0, 1
    )

    # Train on normal data
    print("\nTraining VAE on normal data...")
    for epoch in range(10):
        total_loss = 0
        for i in range(0, len(normal_data), 10):
            batch = normal_data[i:i+10]
            losses = detector.train_step(batch)
            total_loss += losses['total_loss']
        print(f"  Epoch {epoch+1}: loss={total_loss/10:.6f}")

    # Test anomaly detection
    print("\nTesting anomaly detection...")

    # Normal sample
    normal_sample = normal_mean + np.random.randn(32).astype(np.float32) * 0.1
    normal_sample = np.clip(normal_sample, 0, 1)
    is_anom_normal, score_normal = detector.is_anomaly(normal_sample)
    print(f"  Normal sample:  score={score_normal:.4f}, anomaly={is_anom_normal}")

    # Anomalous sample (shifted distribution)
    anomaly_sample = np.random.rand(32).astype(np.float32)
    is_anom_anomaly, score_anomaly = detector.is_anomaly(anomaly_sample)
    print(f"  Anomaly sample: score={score_anomaly:.4f}, anomaly={is_anom_anomaly}")

    # Latent representation
    print("\nLatent space analysis:")
    normal_latent = detector.get_latent_representation(normal_sample)
    anomaly_latent = detector.get_latent_representation(anomaly_sample)
    print(f"  Normal latent:  {normal_latent[:4]}...")
    print(f"  Anomaly latent: {anomaly_latent[:4]}...")

    # Reconstruction test
    print("\nReconstruction test:")
    recon_normal = detector.reconstruct(normal_sample)
    recon_error = np.mean((normal_sample - recon_normal) ** 2)
    print(f"  Normal reconstruction error: {recon_error:.6f}")

    recon_anomaly = detector.reconstruct(anomaly_sample)
    recon_error_anom = np.mean((anomaly_sample - recon_anomaly) ** 2)
    print(f"  Anomaly reconstruction error: {recon_error_anom:.6f}")

    # Weight fingerprint
    print(f"\nWeight fingerprint: {detector.get_weight_fingerprint().hex()[:32]}...")

    print("\n✓ VAE anomaly detector test complete")
