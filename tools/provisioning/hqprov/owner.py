"""Owner key (ADR 0037 D3 (retired 2026-11-12; see in part 0051 / 0054 / 0058 / 0059)) and the in-place boot-partition patches (OWNER.TXT, MCTLS.CRT).

The mechanism is the one the image factory already defines (os/build/make-cm5-heqk-disk.sh:155-173, 335-364;
kernel/src/mcauth.rs): the device stores only a salted verifier `sha256(salt || token)` in a FIXED 128-byte
OWNER.TXT (`HQOWN1 <salt:32hex> <verifier:64hex>`, space-padded to 127 + '\\n'); the factory image ships the
`HQOWN0 unclaimed` placeholder and its manifest `<image>.json` records the byte offsets of OWNER.TXT (128 B) and
MCTLS.CRT (4096 B) so a flasher can patch them in place. A per-unit factory run does exactly that, AFTER the first
boot (the SRK-derived TLS key and Wi-Fi credential are only knowable from the device).
"""
import hashlib
import json
import os
import re
import secrets
import stat
import string

OWNER_FILE_LEN = 128
MCTLS_FILE_LEN = 4096
# The owner-token character set (make-cm5-heqk-disk.sh:159): A-Z and 0-9 without the look-alikes 0/O/1/I,
# 32 symbols = 5 bits each. Built from the stdlib sets so the exclusions are explicit.
_TOKEN_ALPHABET = "".join(c for c in string.ascii_uppercase + string.digits if c not in "0O1I")
assert len(_TOKEN_ALPHABET) == 32
TOKEN_RE = re.compile(r"^[A-HJ-NP-Z2-9]{4}(?:-[A-HJ-NP-Z2-9]{4}){5}$")


class PatchError(Exception):
    pass


def mint_token():
    """24 chars x 5 bits = 120 bits, grouped 'XXXX-XXXX-...' (same format as the image factory's `auto`)."""
    raw = "".join(secrets.choice(_TOKEN_ALPHABET) for _ in range(24))
    return "-".join(raw[i:i + 4] for i in range(0, 24, 4))


def owner_file_bytes(token, salt=None):
    salt = salt if salt is not None else os.urandom(16)
    line = f"HQOWN1 {salt.hex()} {hashlib.sha256(salt + token.encode()).hexdigest()}"
    b = (line.ljust(127) + "\n").encode()
    assert len(b) == OWNER_FILE_LEN
    return b


def parse_owner_file(b):
    """-> None (unclaimed/placeholder) or (salt, verifier)."""
    parts = b.split()
    if len(parts) == 3 and parts[0] == b"HQOWN1":
        try:
            return bytes.fromhex(parts[1].decode()), bytes.fromhex(parts[2].decode())
        except ValueError:
            return None
    return None


def token_matches(owner_bytes, token):
    p = parse_owner_file(owner_bytes)
    return bool(p) and secrets.compare_digest(hashlib.sha256(p[0] + token.encode()).digest(), p[1])


def load_manifest(path):
    with open(path) as f:
        m = json.load(f)
    for k, ln in (("owner_file", OWNER_FILE_LEN), ("mctls_file", MCTLS_FILE_LEN)):
        e = m.get(k) or {}
        if not e.get("offset") or e.get("length") != ln:
            raise PatchError(f"image manifest {path}: {k} offset/length missing or wrong (want length {ln})")
    return m


_SAFE_DEV = re.compile(r"^/dev/disk/by-id/usb-.*(Raspberry_Pi|RPi).*MSD.*$|^/dev/disk/by-id/usb-.*Raspberry_Pi.*$")


def check_target(path):
    """A regular file (an image, for dry runs/tests) or the rpiboot mass-storage disk by-id: never a host disk."""
    st = os.stat(path)
    if stat.S_ISREG(st.st_mode):
        return
    if stat.S_ISBLK(st.st_mode):
        if _SAFE_DEV.match(path) and "-part" not in path:
            return
        raise PatchError(f"refusing block device {path}: only a /dev/disk/by-id/usb-*Raspberry_Pi* mass-storage "
                         "disk (the CM5 in rpiboot mode) is an acceptable patch target")
    raise PatchError(f"{path} is neither a regular file nor a block device")


def _pread(fd, off, n):
    return os.pread(fd, n, off)


def patch_boot_files(target, manifest, owner_bytes, mctls_bytes):
    """Idempotently patch OWNER.TXT and MCTLS.CRT in place; read back and verify. Returns what was done.

    Refuses to overwrite a claim that is not ours (a different verifier) or a foreign certificate: re-provisioning
    an already-claimed unit needs a re-flash of the factory image (unclaimed), never a silent overwrite.
    """
    if len(owner_bytes) != OWNER_FILE_LEN:
        raise PatchError("OWNER.TXT payload must be exactly 128 bytes")
    if len(mctls_bytes) != MCTLS_FILE_LEN or not mctls_bytes.startswith(b"HQCRT1"):
        raise PatchError("MCTLS.CRT payload must be a 4096-byte HQCRT1 file (os/kernel/tools/mctls-provision.py)")
    check_target(target)
    oo, mo = manifest["owner_file"]["offset"], manifest["mctls_file"]["offset"]
    done = {}
    fd = os.open(target, os.O_RDWR)
    try:
        cur_o = _pread(fd, oo, OWNER_FILE_LEN)
        cur_m = _pread(fd, mo, MCTLS_FILE_LEN)
        if cur_o == owner_bytes:
            done["owner"] = "already-set"
        elif cur_o.startswith(b"HQOWN0"):
            os.pwrite(fd, owner_bytes, oo)
            done["owner"] = "written"
        else:
            raise PatchError("OWNER.TXT on the unit is not the unclaimed placeholder and not ours: re-flash the "
                             "factory image first (never overwrite a claim)")
        if cur_m == mctls_bytes:
            done["mctls"] = "already-set"
        elif cur_m.strip(b"\0") == b"":
            os.pwrite(fd, mctls_bytes, mo)
            done["mctls"] = "written"
        else:
            raise PatchError("MCTLS.CRT on the unit is neither empty nor ours: re-flash the factory image first")
        os.fsync(fd)
        if _pread(fd, oo, OWNER_FILE_LEN) != owner_bytes or _pread(fd, mo, MCTLS_FILE_LEN) != mctls_bytes:
            raise PatchError("read-back verification FAILED after patching")
    finally:
        os.close(fd)
    return done
