#!/usr/bin/env python3
"""Independent reference for os/kernel/hal/src/drbg.rs: NIST SP 800-90A Rev. 1 §10.1.2 HMAC_DRBG with SHA-256, written
from the standard with Python's hmac/hashlib only. Prints the test vectors drbg.rs asserts (REF_A, REF_B, REF_C)."""
import hashlib
import hmac


class HmacDrbg:
    def __init__(self, entropy: bytes, nonce: bytes, pers: bytes):
        self.k = b"\x00" * 32
        self.v = b"\x01" * 32
        self._update(entropy + nonce + pers)
        self.ctr = 1

    def _h(self, key: bytes, msg: bytes) -> bytes:
        return hmac.new(key, msg, hashlib.sha256).digest()

    def _update(self, data: bytes):
        self.k = self._h(self.k, self.v + b"\x00" + data)
        self.v = self._h(self.k, self.v)
        if data:
            self.k = self._h(self.k, self.v + b"\x01" + data)
            self.v = self._h(self.k, self.v)

    def reseed(self, entropy: bytes, addl: bytes = b""):
        self._update(entropy + addl)
        self.ctr = 1

    def generate(self, n: int, addl: bytes = b"") -> bytes:
        if addl:
            self._update(addl)
        out = b""
        while len(out) < n:
            self.v = self._h(self.k, self.v)
            out += self.v
        self._update(addl)
        self.ctr += 1
        return out[:n]


d = HmacDrbg(bytes(range(32)), bytes(range(0x20, 0x28)), b"")
print("REF_A", d.generate(32).hex())
print("REF_B", d.generate(32).hex())
d.reseed(b"\x5a" * 32, b"addl")
print("REF_C", d.generate(32, b"more").hex())
