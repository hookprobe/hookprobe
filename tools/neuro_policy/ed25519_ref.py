# SPDX-License-Identifier: AGPL-3.0-only
"""RFC 8032 Ed25519, pure-Python reference (Section 6 algorithm). FOR GOLDEN VECTORS AND TESTS ONLY: slow and not
constant-time. Production signing uses the vetted Rust implementation already in heqk / the companion tier."""
import hashlib

p = 2 ** 255 - 19
L = 2 ** 252 + 27742317777372353535851937790883648493
d = -121665 * pow(121666, p - 2, p) % p
SQRT_M1 = pow(2, (p - 1) // 4, p)
G_Y = 4 * pow(5, p - 2, p) % p


def sha512(b):
    return hashlib.sha512(b).digest()


def add(P, Q):
    A, B = (P[1] - P[0]) * (Q[1] - Q[0]) % p, (P[1] + P[0]) * (Q[1] + Q[0]) % p
    C, D = 2 * P[3] * Q[3] * d % p, 2 * P[2] * Q[2] % p
    E, F, G, H = B - A, D - C, D + C, B + A
    return (E * F % p, G * H % p, F * G % p, E * H % p)


def mul(s, P):
    Q = (0, 1, 1, 0)
    while s > 0:
        if s & 1:
            Q = add(Q, P)
        P = add(P, P)
        s >>= 1
    return Q


def equal(P, Q):
    return (P[0] * Q[2] - Q[0] * P[2]) % p == 0 and (P[1] * Q[2] - Q[1] * P[2]) % p == 0


def recover_x(y, sign):
    if y >= p:
        return None
    x2 = (y * y - 1) * pow(d * y * y + 1, p - 2, p)
    if x2 == 0:
        return None if sign else 0
    x = pow(x2, (p + 3) // 8, p)
    if (x * x - x2) % p != 0:
        x = x * SQRT_M1 % p
    if (x * x - x2) % p != 0:
        return None
    if (x & 1) != sign:
        x = p - x
    return x


G_X = recover_x(G_Y, 0)
G = (G_X, G_Y, 1, G_X * G_Y % p)


def compress(P):
    zinv = pow(P[2], p - 2, p)
    x, y = P[0] * zinv % p, P[1] * zinv % p
    return int.to_bytes(y | ((x & 1) << 255), 32, "little")


def decompress(s):
    if len(s) != 32:
        return None
    y = int.from_bytes(s, "little")
    sign = y >> 255
    y &= (1 << 255) - 1
    x = recover_x(y, sign)
    return None if x is None else (x, y, 1, x * y % p)


def secret_expand(secret):
    h = sha512(secret)
    a = int.from_bytes(h[:32], "little")
    a &= (1 << 254) - 8
    a |= 1 << 254
    return a, h[32:]


def public_key(secret):
    a, _ = secret_expand(secret)
    return compress(mul(a, G))


def sign(secret, msg):
    a, prefix = secret_expand(secret)
    A = compress(mul(a, G))
    r = int.from_bytes(sha512(prefix + msg), "little") % L
    R = compress(mul(r, G))
    h = int.from_bytes(sha512(R + A + msg), "little") % L
    return R + int.to_bytes((r + h * a) % L, 32, "little")


def verify(public, msg, signature):
    if len(public) != 32 or len(signature) != 64:
        return False
    A, R = decompress(public), decompress(signature[:32])
    if A is None or R is None:
        return False
    s = int.from_bytes(signature[32:], "little")
    if s >= L:
        return False
    h = int.from_bytes(sha512(signature[:32] + public + msg), "little") % L
    return equal(mul(s, G), add(R, mul(h, A)))
