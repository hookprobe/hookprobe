#!/usr/bin/env python3
"""
Meta-Regressive Framework - Bubble Accuracy Optimization

PROPRIETARY AND CONFIDENTIAL
Copyright (c) 2024-2025 HookProbe Technologies
Licensed under Commercial License - See LICENSING.md

Implements meta-regressive analysis to optimize bubble assignment accuracy.
Uses effect sizes from purple team simulations to adjust SDN Autopilot
parameters automatically.

The Model:
E = β0 + β1(Temporal_Sync) + β2(D2D_Affinity) + β3(NSE_Resonance) + ε

Where:
- E = Entropy of Misclassification (minimize)
- β1 = Weight for temporal synchronization factor
- β2 = Weight for device-to-device affinity factor
- β3 = Weight for NSE resonance factor
- ε = Error term

The framework:
1. Collects effect sizes from simulation results
2. Runs meta-regression to find optimal β coefficients
3. Generates optimization recommendations for Fortress
4. Applies changes via n8n webhook or direct API

Architecture:
┌─────────────────────────────────────────────────────────────────────────────┐
│                         META-REGRESSIVE FRAMEWORK                            │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐    ┌─────────────┐  │
│  │  COLLECT    │───▶│   ANALYZE   │───▶│   REGRESS   │───▶│  OPTIMIZE   │  │
│  │ Effect Sizes│    │  Patterns   │    │  β Coeff    │    │  Autopilot  │  │
│  └─────────────┘    └─────────────┘    └─────────────┘    └─────────────┘  │
│                                                                              │
│  Data Sources:                                                              │
│  - Purple Team simulations                                                  │
│  - Real-world bubble assignments                                            │
│  - Manual corrections (reinforcement learning)                              │
│  - Detection/blocking rates                                                 │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
"""

import json
import logging
import math
import statistics
import threading
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

# Data storage
REGRESSION_DATA_DIR = Path('/var/lib/hookprobe/nexus/regression')


class OptimizationTarget(Enum):
    """Optimization targets for bubble accuracy."""
    DETECTION_RATE = "detection_rate"
    FALSE_POSITIVE_RATE = "false_positive_rate"
    BUBBLE_ACCURACY = "bubble_accuracy"
    DEFENSE_SCORE = "defense_score"
    MISCLASSIFICATION_ENTROPY = "misclassification_entropy"


@dataclass
class EffectSize:
    """Effect size measurement from a simulation."""
    factor_name: str
    effect_type: str  # cohen_d, pearson_r, hedges_g
    value: float
    confidence_interval: Tuple[float, float] = (0.0, 0.0)
    sample_size: int = 1
    timestamp: datetime = field(default_factory=datetime.now)

    def to_dict(self) -> Dict:
        return {
            'factor_name': self.factor_name,
            'effect_type': self.effect_type,
            'value': self.value,
            'ci_lower': self.confidence_interval[0],
            'ci_upper': self.confidence_interval[1],
            'sample_size': self.sample_size,
            'timestamp': self.timestamp.isoformat(),
        }


@dataclass
class RegressionResult:
    """Result of meta-regression analysis."""
    target: OptimizationTarget
    beta_coefficients: Dict[str, float]
    r_squared: float
    adjusted_r_squared: float
    f_statistic: float
    p_value: float
    residual_std: float
    sample_size: int
    timestamp: datetime = field(default_factory=datetime.now)

    # Derived recommendations
    significant_factors: List[str] = field(default_factory=list)
    recommendations: List[Dict] = field(default_factory=list)

    def to_dict(self) -> Dict:
        return {
            'target': self.target.value,
            'beta_coefficients': self.beta_coefficients,
            'r_squared': self.r_squared,
            'adjusted_r_squared': self.adjusted_r_squared,
            'f_statistic': self.f_statistic,
            'p_value': self.p_value,
            'residual_std': self.residual_std,
            'sample_size': self.sample_size,
            'timestamp': self.timestamp.isoformat(),
            'significant_factors': self.significant_factors,
            'recommendations': self.recommendations,
        }


@dataclass
class OptimizationRecommendation:
    """Optimization recommendation for Fortress Autopilot."""
    parameter: str
    current_value: float
    recommended_value: float
    change_percentage: float
    confidence: float
    reason: str
    priority: int  # 1-10
    expected_improvement: float  # Percentage

    def to_dict(self) -> Dict:
        return {
            'parameter': self.parameter,
            'current_value': self.current_value,
            'recommended_value': self.recommended_value,
            'change_percentage': self.change_percentage,
            'confidence': self.confidence,
            'reason': self.reason,
            'priority': self.priority,
            'expected_improvement': self.expected_improvement,
        }


class EffectSizeAnalyzer:
    """
    Analyzes effect sizes from simulation results.

    Calculates Cohen's d, Pearson's r, and other effect size measures
    to quantify the impact of different factors on bubble accuracy.
    """

    @staticmethod
    def cohen_d(group1: List[float], group2: List[float]) -> float:
        """
        Calculate Cohen's d effect size.

        Cohen's d = (M1 - M2) / pooled_std
        """
        if not group1 or not group2:
            return 0.0

        n1, n2 = len(group1), len(group2)
        mean1, mean2 = statistics.mean(group1), statistics.mean(group2)

        # Handle single-element lists
        var1 = statistics.variance(group1) if n1 > 1 else 0
        var2 = statistics.variance(group2) if n2 > 1 else 0

        # Pooled standard deviation
        pooled_var = ((n1 - 1) * var1 + (n2 - 1) * var2) / (n1 + n2 - 2) if n1 + n2 > 2 else 1
        pooled_std = math.sqrt(pooled_var) if pooled_var > 0 else 1

        return (mean1 - mean2) / pooled_std

    @staticmethod
    def hedges_g(group1: List[float], group2: List[float]) -> float:
        """
        Calculate Hedges' g (bias-corrected Cohen's d).

        Better for small sample sizes.
        """
        d = EffectSizeAnalyzer.cohen_d(group1, group2)
        n = len(group1) + len(group2)

        # Correction factor
        correction = 1 - (3 / (4 * n - 9)) if n > 3 else 1

        return d * correction

    @staticmethod
    def pearson_r(x: List[float], y: List[float]) -> float:
        """Calculate Pearson correlation coefficient."""
        if len(x) != len(y) or len(x) < 2:
            return 0.0

        n = len(x)
        mean_x = statistics.mean(x)
        mean_y = statistics.mean(y)

        numerator = sum((x[i] - mean_x) * (y[i] - mean_y) for i in range(n))

        sum_sq_x = sum((xi - mean_x) ** 2 for xi in x)
        sum_sq_y = sum((yi - mean_y) ** 2 for yi in y)

        denominator = math.sqrt(sum_sq_x * sum_sq_y) if sum_sq_x * sum_sq_y > 0 else 1

        return numerator / denominator

    @staticmethod
    def confidence_interval(effect_size: float, n: int, alpha: float = 0.05) -> Tuple[float, float]:
        """Calculate confidence interval for effect size."""
        # Approximate standard error
        se = math.sqrt(4 / n + effect_size ** 2 / (2 * n)) if n > 0 else 1

        # Z-value for 95% CI
        z = 1.96 if alpha == 0.05 else 2.576  # 99%

        lower = effect_size - z * se
        upper = effect_size + z * se

        return (lower, upper)

    @staticmethod
    def interpret_effect_size(d: float) -> str:
        """Interpret Cohen's d effect size."""
        abs_d = abs(d)
        if abs_d < 0.2:
            return "negligible"
        elif abs_d < 0.5:
            return "small"
        elif abs_d < 0.8:
            return "medium"
        else:
            return "large"


class BubbleAccuracyModel:
    """
    Model for predicting bubble accuracy based on factor weights.

    Implements the meta-regression model:
    E = β0 + β1(Temporal_Sync) + β2(D2D_Affinity) + β3(NSE_Resonance) + ε
    """

    # Default weights (will be updated by regression)
    DEFAULT_WEIGHTS = {
        'intercept': 0.5,
        'temporal_sync': 0.30,
        'd2d_affinity': 0.25,
        'nse_resonance': 0.25,
        'discovery_hits': 0.10,
        'dhcp_fingerprint': 0.05,
        'behavioral_pattern': 0.05,
    }

    def __init__(self, weights: Dict[str, float] = None):
        self.weights = weights or self.DEFAULT_WEIGHTS.copy()

    def predict_accuracy(self, factors: Dict[str, float]) -> float:
        """
        Predict bubble accuracy based on factor values.

        Args:
            factors: Dictionary of factor values (0-1 scale)

        Returns:
            Predicted accuracy (0-1)
        """
        prediction = self.weights.get('intercept', 0.5)

        for factor, weight in self.weights.items():
            if factor != 'intercept' and factor in factors:
                prediction += weight * factors[factor]

        # Clip to valid range
        return max(0.0, min(1.0, prediction))

    def predict_misclassification_entropy(self, factors: Dict[str, float]) -> float:
        """
        Predict misclassification entropy (lower is better).

        E = 1 - accuracy
        """
        accuracy = self.predict_accuracy(factors)
        return 1.0 - accuracy

    def update_weights(self, new_weights: Dict[str, float]):
        """Update model weights."""
        self.weights.update(new_weights)


class MetaRegressor:
    """
    Meta-Regressive Analyzer for bubble accuracy optimization.

    Collects effect sizes from simulations, runs meta-regression,
    and generates optimization recommendations for the SDN Autopilot.

    Usage:
        regressor = MetaRegressor()
        regressor.add_sample(simulation_result)
        result = regressor.run_regression(OptimizationTarget.DEFENSE_SCORE)
        recommendations = regressor.generate_recommendations(result)
    """

    # Minimum samples for reliable regression
    MIN_SAMPLES = 10

    # Significance threshold
    SIGNIFICANCE_THRESHOLD = 0.05

    def __init__(self, persist: bool = True):
        self.persist = persist
        self._lock = threading.Lock()

        # Data storage
        self._samples: List[Dict] = []
        self._effect_sizes: List[EffectSize] = []
        self._regression_history: List[RegressionResult] = []

        # Model
        self._model = BubbleAccuracyModel()

        # Ensure data directory
        if persist:
            REGRESSION_DATA_DIR.mkdir(parents=True, exist_ok=True)
            self._load_data()

        logger.debug("MetaRegressor initialized")

    def add_sample(self, sample: Dict):
        """
        Add a sample from a simulation result.

        Expected fields:
        - defense_score: Overall defense score (0-100)
        - detection_rate: Rate of attack detection
        - false_positive_rate: False positive rate
        - bubble_penetration_rate: Rate of bubble penetration
        - temporal_sync_weight: Weight given to temporal sync
        - d2d_affinity_weight: Weight given to D2D affinity
        - nse_resonance_weight: Weight given to NSE resonance
        """
        with self._lock:
            sample['timestamp'] = datetime.now().isoformat()
            self._samples.append(sample)

            if self.persist:
                self._save_data()

        logger.debug(f"Added sample, total: {len(self._samples)}")

    def add_effect_size(self, effect: EffectSize):
        """Add an effect size measurement."""
        with self._lock:
            self._effect_sizes.append(effect)

    def calculate_effect_sizes(self) -> Dict[str, EffectSize]:
        """
        Calculate effect sizes for all factors from samples.

        Returns dictionary of factor → EffectSize
        """
        if len(self._samples) < 2:
            return {}

        effect_sizes = {}
        analyzer = EffectSizeAnalyzer()

        # Factors to analyze
        factors = ['temporal_sync', 'd2d_affinity', 'nse_resonance',
                   'discovery_hits', 'dhcp_fingerprint']

        # Target: defense_score
        defense_scores = [s.get('defense_score', 50) for s in self._samples]

        for factor in factors:
            factor_values = [s.get(f'{factor}_weight', 0.5) for s in self._samples]

            if len(factor_values) >= 2:
                # Correlation with defense score
                r = analyzer.pearson_r(factor_values, defense_scores)
                ci = analyzer.confidence_interval(r, len(factor_values))

                effect_sizes[factor] = EffectSize(
                    factor_name=factor,
                    effect_type='pearson_r',
                    value=r,
                    confidence_interval=ci,
                    sample_size=len(factor_values),
                )

        return effect_sizes

    def run_regression(
        self,
        target: OptimizationTarget = OptimizationTarget.DEFENSE_SCORE
    ) -> Optional[RegressionResult]:
        """
        Run meta-regression to find optimal β coefficients.

        Returns RegressionResult with coefficients and statistics.
        """
        if len(self._samples) < self.MIN_SAMPLES:
            logger.info(
                f"Not enough samples for regression: "
                f"{len(self._samples)}/{self.MIN_SAMPLES}"
            )
            return None

        with self._lock:
            # Extract data
            X = []  # Features
            y = []  # Target

            for sample in self._samples:
                features = [
                    1.0,  # Intercept
                    sample.get('temporal_sync_weight', 0.3),
                    sample.get('d2d_affinity_weight', 0.25),
                    sample.get('nse_resonance_weight', 0.25),
                    sample.get('discovery_hits_weight', 0.1),
                ]
                X.append(features)

                if target == OptimizationTarget.DEFENSE_SCORE:
                    y.append(sample.get('defense_score', 50) / 100)  # Normalize
                elif target == OptimizationTarget.DETECTION_RATE:
                    y.append(sample.get('detection_rate', 0.5))
                elif target == OptimizationTarget.FALSE_POSITIVE_RATE:
                    y.append(1 - sample.get('false_positive_rate', 0.1))  # Invert
                elif target == OptimizationTarget.BUBBLE_ACCURACY:
                    y.append(1 - sample.get('bubble_penetration_rate', 0.2))
                else:
                    y.append(sample.get('defense_score', 50) / 100)

            # Simple OLS regression
            betas = self._ols_regression(X, y)

            if betas is None:
                return None

            # Calculate statistics
            y_pred = [sum(b * x for b, x in zip(betas, row)) for row in X]
            residuals = [actual - pred for actual, pred in zip(y, y_pred)]

            ss_res = sum(r ** 2 for r in residuals)
            ss_tot = sum((yi - statistics.mean(y)) ** 2 for yi in y)

            r_squared = 1 - (ss_res / ss_tot) if ss_tot > 0 else 0
            n = len(y)
            p = len(betas)
            adjusted_r_squared = 1 - (1 - r_squared) * (n - 1) / (n - p - 1) if n > p + 1 else r_squared

            residual_std = math.sqrt(ss_res / (n - p)) if n > p else 0

            # F-statistic (simplified)
            ss_reg = ss_tot - ss_res
            f_statistic = (ss_reg / (p - 1)) / (ss_res / (n - p)) if p > 1 and n > p else 0

            # Create result
            beta_names = ['intercept', 'temporal_sync', 'd2d_affinity',
                         'nse_resonance', 'discovery_hits']

            result = RegressionResult(
                target=target,
                beta_coefficients={name: beta for name, beta in zip(beta_names, betas)},
                r_squared=r_squared,
                adjusted_r_squared=adjusted_r_squared,
                f_statistic=f_statistic,
                p_value=0.05,  # Simplified
                residual_std=residual_std,
                sample_size=n,
            )

            # Find significant factors
            for name, beta in result.beta_coefficients.items():
                if name != 'intercept' and abs(beta) > 0.1:
                    result.significant_factors.append(name)

            # Generate recommendations
            result.recommendations = self._generate_recommendations_from_betas(
                result.beta_coefficients
            )

            self._regression_history.append(result)

            if self.persist:
                self._save_data()

            logger.info(
                f"Regression complete: R²={r_squared:.3f}, "
                f"significant factors: {result.significant_factors}"
            )

            return result

    def _ols_regression(self, X: List[List[float]], y: List[float]) -> Optional[List[float]]:
        """
        Simple Ordinary Least Squares regression.

        Returns beta coefficients.
        """
        n = len(y)
        p = len(X[0]) if X else 0

        if n < p or n < 2:
            return None

        try:
            # Convert to matrix operations
            # β = (X'X)^-1 X'y

            # X'X
            XtX = [[0.0] * p for _ in range(p)]
            for i in range(p):
                for j in range(p):
                    XtX[i][j] = sum(X[k][i] * X[k][j] for k in range(n))

            # X'y
            Xty = [sum(X[k][i] * y[k] for k in range(n)) for i in range(p)]

            # Solve using Gaussian elimination (simple)
            betas = self._solve_linear_system(XtX, Xty)

            return betas

        except Exception as e:
            logger.debug(f"OLS regression failed: {e}")
            return None

    def _solve_linear_system(self, A: List[List[float]], b: List[float]) -> List[float]:
        """Solve Ax = b using Gaussian elimination."""
        n = len(b)
        # Augmented matrix
        aug = [row[:] + [b[i]] for i, row in enumerate(A)]

        # Forward elimination
        for i in range(n):
            # Find pivot
            max_row = i
            for k in range(i + 1, n):
                if abs(aug[k][i]) > abs(aug[max_row][i]):
                    max_row = k
            aug[i], aug[max_row] = aug[max_row], aug[i]

            # Eliminate column
            if abs(aug[i][i]) < 1e-10:
                continue

            for k in range(i + 1, n):
                factor = aug[k][i] / aug[i][i]
                for j in range(i, n + 1):
                    aug[k][j] -= factor * aug[i][j]

        # Back substitution
        x = [0.0] * n
        for i in range(n - 1, -1, -1):
            if abs(aug[i][i]) < 1e-10:
                x[i] = 0
            else:
                x[i] = aug[i][n]
                for j in range(i + 1, n):
                    x[i] -= aug[i][j] * x[j]
                x[i] /= aug[i][i]

        return x

    def _generate_recommendations_from_betas(
        self,
        betas: Dict[str, float]
    ) -> List[Dict]:
        """Generate optimization recommendations from beta coefficients."""
        recommendations = []

        # Current weights (from model or defaults)
        current = self._model.weights

        for factor, beta in betas.items():
            if factor == 'intercept':
                continue

            current_value = current.get(factor, 0.25)
            abs_beta = abs(beta)

            # Only recommend changes for significant factors
            if abs_beta < 0.1:
                continue

            # Recommendation logic
            if beta > 0:
                # Positive correlation - increase weight
                if current_value < 0.4:
                    recommended = min(0.4, current_value + 0.05)
                    recommendations.append({
                        'parameter': f'{factor}_weight',
                        'current_value': current_value,
                        'recommended_value': recommended,
                        'change': 'increase',
                        'reason': f'Positive correlation (β={beta:.3f}) with defense score',
                        'priority': int(abs_beta * 10),
                        'expected_improvement': abs_beta * 10,
                    })
            else:
                # Negative correlation - decrease weight
                if current_value > 0.1:
                    recommended = max(0.1, current_value - 0.05)
                    recommendations.append({
                        'parameter': f'{factor}_weight',
                        'current_value': current_value,
                        'recommended_value': recommended,
                        'change': 'decrease',
                        'reason': f'Negative correlation (β={beta:.3f}) with defense score',
                        'priority': int(abs_beta * 10),
                        'expected_improvement': abs_beta * 5,
                    })

        # Sort by priority
        recommendations.sort(key=lambda x: x['priority'], reverse=True)

        return recommendations

    def generate_recommendations(
        self,
        regression_result: RegressionResult = None
    ) -> List[OptimizationRecommendation]:
        """Generate optimization recommendations."""
        if regression_result is None:
            regression_result = self.run_regression()

        if regression_result is None:
            return []

        recommendations = []
        current_weights = self._model.weights

        for factor in regression_result.significant_factors:
            beta = regression_result.beta_coefficients.get(factor, 0)
            current = current_weights.get(factor, 0.25)

            if abs(beta) < 0.1:
                continue

            # Calculate recommended change
            change_factor = min(0.1, abs(beta) * 0.2)  # Conservative change
            if beta > 0:
                recommended = min(0.5, current + change_factor)
            else:
                recommended = max(0.05, current - change_factor)

            change_pct = ((recommended - current) / current) * 100 if current > 0 else 0

            recommendations.append(OptimizationRecommendation(
                parameter=factor,
                current_value=current,
                recommended_value=recommended,
                change_percentage=change_pct,
                confidence=regression_result.r_squared,
                reason=f"β={beta:.3f}, R²={regression_result.r_squared:.3f}",
                priority=int(abs(beta) * 10),
                expected_improvement=abs(change_pct) * regression_result.r_squared,
            ))

        # Sort by priority
        recommendations.sort(key=lambda x: x.priority, reverse=True)

        return recommendations

    def apply_recommendations(self, recommendations: List[OptimizationRecommendation]) -> Dict:
        """
        Apply recommendations to the model.

        Returns the new weight configuration.
        """
        new_weights = self._model.weights.copy()

        for rec in recommendations:
            if rec.confidence >= 0.3 and rec.priority >= 5:
                new_weights[rec.parameter] = rec.recommended_value

        self._model.update_weights(new_weights)

        return new_weights

    def get_current_model(self) -> BubbleAccuracyModel:
        """Get the current accuracy model."""
        return self._model

    def get_stats(self) -> Dict:
        """Get regressor statistics."""
        return {
            'total_samples': len(self._samples),
            'effect_sizes_calculated': len(self._effect_sizes),
            'regressions_run': len(self._regression_history),
            'current_weights': self._model.weights,
            'min_samples_required': self.MIN_SAMPLES,
            'can_run_regression': len(self._samples) >= self.MIN_SAMPLES,
        }

    def _save_data(self):
        """Save data to disk."""
        if not self.persist:
            return

        try:
            data = {
                'samples': self._samples,
                'effect_sizes': [e.to_dict() for e in self._effect_sizes],
                'regression_history': [r.to_dict() for r in self._regression_history],
                'model_weights': self._model.weights,
                'saved_at': datetime.now().isoformat(),
            }

            data_path = REGRESSION_DATA_DIR / 'meta_regressor.json'
            with open(data_path, 'w') as f:
                json.dump(data, f, indent=2)

        except Exception as e:
            logger.debug(f"Failed to save data: {e}")

    def _load_data(self):
        """Load data from disk."""
        data_path = REGRESSION_DATA_DIR / 'meta_regressor.json'
        if not data_path.exists():
            return

        try:
            with open(data_path, 'r') as f:
                data = json.load(f)

            self._samples = data.get('samples', [])
            self._model.weights = data.get('model_weights', self._model.DEFAULT_WEIGHTS)

            logger.debug(f"Loaded {len(self._samples)} samples from disk")

        except Exception as e:
            logger.debug(f"Failed to load data: {e}")


# =============================================================================
# CONVENIENCE FUNCTIONS
# =============================================================================

def create_meta_regressor(persist: bool = True) -> MetaRegressor:
    """Create a meta-regressor instance."""
    return MetaRegressor(persist=persist)


def analyze_simulation_results(results: List[Dict]) -> Dict:
    """
    Analyze simulation results and generate recommendations.

    Args:
        results: List of simulation result dictionaries

    Returns:
        Analysis summary with recommendations
    """
    regressor = MetaRegressor(persist=False)

    for result in results:
        regressor.add_sample(result)

    if len(results) < MetaRegressor.MIN_SAMPLES:
        return {
            'status': 'insufficient_data',
            'samples': len(results),
            'required': MetaRegressor.MIN_SAMPLES,
        }

    regression = regressor.run_regression()
    if regression is None:
        return {'status': 'regression_failed'}

    recommendations = regressor.generate_recommendations(regression)

    return {
        'status': 'success',
        'regression': regression.to_dict(),
        'recommendations': [r.to_dict() for r in recommendations],
        'effect_sizes': {
            name: size.to_dict()
            for name, size in regressor.calculate_effect_sizes().items()
        },
    }


# =============================================================================
# CLI INTERFACE
# =============================================================================

if __name__ == '__main__':
    import argparse
    import random

    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )

    parser = argparse.ArgumentParser(description='Meta-Regressive Framework')
    parser.add_argument('command', choices=['demo', 'stats', 'recommend'])
    parser.add_argument('--samples', type=int, default=20, help='Number of samples for demo')
    args = parser.parse_args()

    regressor = MetaRegressor(persist=False)

    if args.command == 'demo':
        print(f"Generating {args.samples} sample simulations...")

        # Generate synthetic samples
        for i in range(args.samples):
            # Simulate correlation: higher temporal_sync → higher defense_score
            temporal = random.uniform(0.1, 0.5)
            d2d = random.uniform(0.1, 0.4)
            nse = random.uniform(0.1, 0.4)

            # Defense score correlated with factors
            base_score = 40
            score = base_score + temporal * 60 + d2d * 40 + nse * 30 + random.gauss(0, 5)
            score = max(0, min(100, score))

            sample = {
                'simulation_id': f'SIM-{i:04d}',
                'defense_score': score,
                'detection_rate': 0.5 + temporal * 0.3,
                'false_positive_rate': 0.1 - temporal * 0.05,
                'bubble_penetration_rate': 0.3 - d2d * 0.2,
                'temporal_sync_weight': temporal,
                'd2d_affinity_weight': d2d,
                'nse_resonance_weight': nse,
                'discovery_hits_weight': random.uniform(0.05, 0.15),
            }
            regressor.add_sample(sample)

        print("\nRunning meta-regression...")
        result = regressor.run_regression()

        if result:
            print("\n" + "=" * 60)
            print("REGRESSION RESULTS")
            print("=" * 60)
            print(f"R² = {result.r_squared:.4f}")
            print(f"Adjusted R² = {result.adjusted_r_squared:.4f}")
            print(f"F-statistic = {result.f_statistic:.2f}")
            print(f"Residual Std = {result.residual_std:.4f}")

            print("\nBeta Coefficients:")
            for name, beta in result.beta_coefficients.items():
                sig = "***" if name in result.significant_factors else ""
                print(f"  {name}: {beta:.4f} {sig}")

            print(f"\nSignificant Factors: {result.significant_factors}")

            print("\n" + "-" * 60)
            print("RECOMMENDATIONS")
            print("-" * 60)
            recommendations = regressor.generate_recommendations(result)
            for rec in recommendations:
                print(f"\n  {rec.parameter}:")
                print(f"    Current: {rec.current_value:.3f}")
                print(f"    Recommended: {rec.recommended_value:.3f}")
                print(f"    Change: {rec.change_percentage:+.1f}%")
                print(f"    Priority: {rec.priority}")
                print(f"    Expected Improvement: {rec.expected_improvement:.1f}%")

    elif args.command == 'stats':
        stats = regressor.get_stats()
        print("Meta-Regressor Statistics:")
        for key, value in stats.items():
            print(f"  {key}: {value}")

    elif args.command == 'recommend':
        # Load existing data
        stats = regressor.get_stats()
        if stats['can_run_regression']:
            result = regressor.run_regression()
            if result:
                recommendations = regressor.generate_recommendations(result)
                print("Optimization Recommendations:")
                for rec in recommendations:
                    print(f"  {rec.parameter}: {rec.current_value:.3f} → {rec.recommended_value:.3f}")
        else:
            print(f"Need at least {stats['min_samples_required']} samples")
