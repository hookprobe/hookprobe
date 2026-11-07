#!/usr/bin/env python3
"""policy-sign — the OPERATOR's signature over POLICY.TXT (ADR 0049 D1).

  policy-sign.py keygen KEYFILE              # new Ed25519 operator key (mode 600); prints the public key hex
  policy-sign.py pubkey KEYFILE              # public key hex (-> HEQK_POLICY_PUBKEY for the image factory)
  policy-sign.py sign KEYFILE POLICY.TXT GEN OUT.SIG   # POLICY.TXT = the exact 4096-byte staged file

POLICY.SIG (512 B): "HQPSIG1\\0" | gen u64 LE | sha256(POLICY.TXT) | Ed25519(key, "HQPOL1"|gen LE|sha256) | 0-pad.
The device verifies it with the operator key compiled into its boot-signed image, before parsing the policy,
and refuses a generation below the image's floor. Keep KEYFILE off the device (it is the operator's authority).
"""
import hashlib, os, struct, sys
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization as ser


def load(path):
    return ser.load_pem_private_key(open(path, "rb").read(), password=None)


def pubhex(k):
    return k.public_key().public_bytes(ser.Encoding.Raw, ser.PublicFormat.Raw).hex()


def main():
    a = sys.argv[1:]
    if a[:1] == ["keygen"] and len(a) == 2:
        k = Ed25519PrivateKey.generate()
        old = os.umask(0o077)
        try:
            open(a[1], "wb").write(k.private_bytes(ser.Encoding.PEM, ser.PrivateFormat.PKCS8, ser.NoEncryption()))
        finally:
            os.umask(old)
        print(pubhex(k))
    elif a[:1] == ["pubkey"] and len(a) == 2:
        print(pubhex(load(a[1])))
    elif a[:1] == ["sign"] and len(a) == 5:
        k, pol, gen, out = load(a[1]), open(a[2], "rb").read(), int(a[3]), a[4]
        if len(pol) != 4096 or not pol.startswith(b"HQPOL1"):
            sys.exit("POLICY.TXT must be the exact 4096-byte staged file starting with HQPOL1")
        d = hashlib.sha256(pol).digest()
        sig = k.sign(b"HQPOL1" + struct.pack("<Q", gen) + d)
        open(out, "wb").write((b"HQPSIG1\0" + struct.pack("<Q", gen) + d + sig).ljust(512, b"\0"))
        print(f"POLICY.SIG written (generation {gen})")
    else:
        sys.exit(__doc__)


if __name__ == "__main__":
    main()
