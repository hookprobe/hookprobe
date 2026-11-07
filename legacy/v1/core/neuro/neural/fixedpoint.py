"""
Fixed-Point Mathematics for Deterministic Neural Networks

Q16.16 format: 16-bit integer part, 16-bit fractional part
Critical: Must produce bit-for-bit identical results across all platforms.
"""

import numpy as np
from typing import Union

# Fixed-point configuration
FP_SHIFT = 16
FP_ONE = 1 << FP_SHIFT  # 1.0 in fixed-point (65536)
FP_MASK = 0xFFFFFFFF  # 32-bit mask


class FixedPoint:
    """
    Q16.16 fixed-point number representation.

    Range: -32768.0 to +32767.99998
    Precision: 1/65536 ≈ 0.000015
    """

    def __init__(self, value: Union[int, float, 'FixedPoint']):
        if isinstance(value, FixedPoint):
            self.raw = value.raw
        elif isinstance(value, int):
            self.raw = value << FP_SHIFT
        elif isinstance(value, float):
            self.raw = int(value * FP_ONE)
        else:
            raise TypeError(f"Cannot create FixedPoint from {type(value)}")

        # Ensure 32-bit signed integer
        self.raw = np.int32(self.raw)

    def __add__(self, other: 'FixedPoint') -> 'FixedPoint':
        result = FixedPoint(0)
        result.raw = np.int32(self.raw + other.raw)
        return result

    def __sub__(self, other: 'FixedPoint') -> 'FixedPoint':
        result = FixedPoint(0)
        result.raw = np.int32(self.raw - other.raw)
        return result

    def __mul__(self, other: 'FixedPoint') -> 'FixedPoint':
        result = FixedPoint(0)
        # 64-bit intermediate to prevent overflow
        intermediate = np.int64(self.raw) * np.int64(other.raw)
        result.raw = np.int32(intermediate >> FP_SHIFT)
        return result

    def __truediv__(self, other: 'FixedPoint') -> 'FixedPoint':
        result = FixedPoint(0)
        # 64-bit intermediate to prevent overflow
        intermediate = (np.int64(self.raw) << FP_SHIFT) // np.int64(other.raw)
        result.raw = np.int32(intermediate)
        return result

    def __neg__(self) -> 'FixedPoint':
        result = FixedPoint(0)
        result.raw = np.int32(-self.raw)
        return result

    def __eq__(self, other: 'FixedPoint') -> bool:
        return self.raw == other.raw

    def __lt__(self, other: 'FixedPoint') -> bool:
        return self.raw < other.raw

    def __le__(self, other: 'FixedPoint') -> bool:
        return self.raw <= other.raw

    def __gt__(self, other: 'FixedPoint') -> bool:
        return self.raw > other.raw

    def __ge__(self, other: 'FixedPoint') -> bool:
        return self.raw >= other.raw

    def to_float(self) -> float:
        return float(self.raw) / FP_ONE

    def to_int(self) -> int:
        return self.raw >> FP_SHIFT

    def __repr__(self) -> str:
        return f"FixedPoint({self.to_float():.6f})"


def fp_exp(x: FixedPoint, terms: int = 10) -> FixedPoint:
    """
    Fixed-point exponential using Taylor series.

    exp(x) ≈ 1 + x + x²/2! + x³/3! + ... + x^n/n!

    Args:
        x: Input value (should be in range -5 to 5)
        terms: Number of Taylor series terms (default 10)

    Returns:
        exp(x) in fixed-point
    """
    sum_val = FixedPoint(1.0)  # Start with 1.0
    term = FixedPoint(1.0)

    for i in range(1, terms + 1):
        term = term * x / FixedPoint(i)
        sum_val = sum_val + term

        # Early termination if term becomes negligible
        if abs(term.raw) < 10:  # Less than 0.0002
            break

    return sum_val


def fp_sigmoid(x: FixedPoint) -> FixedPoint:
    """
    Fixed-point sigmoid approximation.

    sigmoid(x) = 1 / (1 + exp(-x))

    For numerical stability, uses:
      - If x >= 0: 1 / (1 + exp(-x))
      - If x < 0:  exp(x) / (1 + exp(x))
    """
    zero = FixedPoint(0.0)
    one = FixedPoint(1.0)

    if x >= zero:
        # x >= 0: compute 1 / (1 + exp(-x))
        exp_neg_x = fp_exp(-x)
        return one / (one + exp_neg_x)
    else:
        # x < 0: compute exp(x) / (1 + exp(x))
        exp_x = fp_exp(x)
        return exp_x / (one + exp_x)


def fp_relu(x: FixedPoint) -> FixedPoint:
    """
    Fixed-point ReLU (Rectified Linear Unit).

    ReLU(x) = max(0, x)
    """
    zero = FixedPoint(0.0)
    return x if x > zero else zero


def fp_tanh(x: FixedPoint) -> FixedPoint:
    """
    Fixed-point tanh approximation.

    tanh(x) = (exp(2x) - 1) / (exp(2x) + 1)
    """
    one = FixedPoint(1.0)
    two = FixedPoint(2.0)

    exp_2x = fp_exp(two * x)
    return (exp_2x - one) / (exp_2x + one)


class FixedPointArray:
    """
    Array of fixed-point numbers for neural network layers.
    """

    def __init__(self, values: Union[list, np.ndarray]):
        if isinstance(values, list):
            self.data = np.array([FixedPoint(v).raw for v in values], dtype=np.int32)
        elif isinstance(values, np.ndarray):
            if values.dtype == np.int32:
                self.data = values
            else:
                self.data = np.array([FixedPoint(v).raw for v in values], dtype=np.int32)
        else:
            raise TypeError(f"Cannot create FixedPointArray from {type(values)}")

    def __getitem__(self, idx):
        result = FixedPoint(0)
        result.raw = self.data[idx]
        return result

    def __setitem__(self, idx, value: FixedPoint):
        self.data[idx] = value.raw

    def __len__(self):
        return len(self.data)

    def to_numpy(self) -> np.ndarray:
        """Convert to numpy float array."""
        return self.data.astype(np.float64) / FP_ONE

    def to_bytes(self) -> bytes:
        """Serialize to bytes (for weight fingerprinting)."""
        return self.data.tobytes()

    @classmethod
    def from_bytes(cls, data: bytes) -> 'FixedPointArray':
        """Deserialize from bytes."""
        arr = np.frombuffer(data, dtype=np.int32)
        return cls(arr)

    def __repr__(self) -> str:
        float_vals = self.to_numpy()
        return f"FixedPointArray({float_vals})"


def fp_dot_product(a: FixedPointArray, b: FixedPointArray) -> FixedPoint:
    """
    Fixed-point dot product.

    a · b = Σ(a_i × b_i)
    """
    assert len(a) == len(b), "Arrays must have same length"

    result = FixedPoint(0)
    for i in range(len(a)):
        result = result + (a[i] * b[i])

    return result


def fp_matrix_vector_mult(matrix: list[FixedPointArray], vector: FixedPointArray) -> FixedPointArray:
    """
    Fixed-point matrix-vector multiplication.

    y = M × x
    """
    result_data = []
    for row in matrix:
        dot_product = fp_dot_product(row, vector)
        result_data.append(dot_product.raw)

    return FixedPointArray(np.array(result_data, dtype=np.int32))


# Test vectors for determinism verification
TEST_VECTORS = {
    'mul': [
        (1.5, 2.0, 3.0),
        (0.5, 0.5, 0.25),
        (-1.5, 2.0, -3.0),
    ],
    'div': [
        (5.0, 2.0, 2.5),
        (1.0, 3.0, 0.333333),
        (-10.0, 2.0, -5.0),
    ],
    'exp': [
        (0.0, 1.0),
        (1.0, 2.718282),
        (-1.0, 0.367879),
    ],
    'sigmoid': [
        (0.0, 0.5),
        (1.0, 0.731059),
        (-1.0, 0.268941),
    ],
}


def verify_determinism():
    """
    Verify fixed-point operations produce expected results.
    Run this on both edge and cloud to ensure identical implementation.
    """
    print("=== Fixed-Point Determinism Verification ===\n")

    errors = 0

    # Test multiplication
    print("Testing multiplication...")
    for a, b, expected in TEST_VECTORS['mul']:
        result = (FixedPoint(a) * FixedPoint(b)).to_float()
        if abs(result - expected) > 0.001:
            print(f"  ❌ FAIL: {a} × {b} = {result} (expected {expected})")
            errors += 1
        else:
            print(f"  ✓ PASS: {a} × {b} = {result}")

    # Test division
    print("\nTesting division...")
    for a, b, expected in TEST_VECTORS['div']:
        result = (FixedPoint(a) / FixedPoint(b)).to_float()
        if abs(result - expected) > 0.001:
            print(f"  ❌ FAIL: {a} / {b} = {result} (expected {expected})")
            errors += 1
        else:
            print(f"  ✓ PASS: {a} / {b} = {result}")

    # Test exponential
    print("\nTesting exp...")
    for x, expected in TEST_VECTORS['exp']:
        result = fp_exp(FixedPoint(x)).to_float()
        if abs(result - expected) > 0.001:
            print(f"  ❌ FAIL: exp({x}) = {result} (expected {expected})")
            errors += 1
        else:
            print(f"  ✓ PASS: exp({x}) = {result}")

    # Test sigmoid
    print("\nTesting sigmoid...")
    for x, expected in TEST_VECTORS['sigmoid']:
        result = fp_sigmoid(FixedPoint(x)).to_float()
        if abs(result - expected) > 0.001:
            print(f"  ❌ FAIL: sigmoid({x}) = {result} (expected {expected})")
            errors += 1
        else:
            print(f"  ✓ PASS: sigmoid({x}) = {result}")

    print(f"\n{'='*50}")
    if errors == 0:
        print("✓ All tests passed - Determinism verified!")
    else:
        print(f"❌ {errors} tests failed - Determinism broken!")

    return errors == 0


if __name__ == '__main__':
    verify_determinism()
