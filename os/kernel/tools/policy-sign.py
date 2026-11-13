#!/usr/bin/env python3
"""policy-sign — the OPERATOR's signature over POLICY.TXT (ADR 0049 D1).

  policy-sign.py keygen KEYFILE              # new Ed25519 operator key (mode 600); prints the public key hex
  policy-sign.py pubkey KEYFILE              # public key hex (-> HEQK_POLICY_PUBKEY for the image factory)
  policy-sign.py sign KEYFILE POLICY.TXT GEN OUT.SIG   # POLICY.TXT = the exact 4096-byte staged file
  policy-sign.py sign-blocklist KEYFILE BLOCK.TXT GEN OUT.SIG   # Shield blocklist (<= 16 MiB; ADR 0052)
  policy-sign.py sign-allowlist KEYFILE ALLOW.TXT GEN OUT.SIG   # Shield allowlist (<= 16 MiB)
  policy-sign.py sign-ioc KEYFILE IOC.TXT GEN OUT.SIG           # threat-intel IOC pack (<= 16 MiB)
  policy-sign.py sign-devices KEYFILE DEVICES.TXT GEN OUT.SIG   # per-device policy (<= 16 KiB)
  policy-sign.py sign-wifi KEYFILE WIFI.TXT GEN OUT.SIG         # AP SSID / PSK / channel (<= 1 KiB)
  policy-sign.py sign-rules KEYFILE RULES.BIN GEN OUT.SIG       # compiled rule pack (tools/rulepack.py, <= 64 KiB)
  policy-sign.py sign-oui KEYFILE OUI.TXT GEN OUT.SIG           # IEEE OUI vendor registry (<= 4 MiB; os/build/fpgen/gen_oui.py)
  policy-sign.py sign-wan KEYFILE WAN.TXT GEN OUT.SIG           # WAN mode / VLANs / mgmt_floor (<= 512 B; audit finding 11)
  policy-sign.py enroll-proof OWNERKEY                          # ADR 0058 D3: public_key + proof for POST /api/anchor/enroll
  policy-sign.py rotate OLDKEY NEWKEY GEN                       # ADR 0058 D3: public_key + proof + signature for /api/anchor/rotate
  policy-sign.py mgmt-sign OWNERKEY --device-id HEX --epoch HEX --seq N
                 --msg confirm|rollback|stage|activate|pack-rollback|factory-reset|rotate|wifi-heal-test  [per-message binding,
                 see mgmt_args: --generation --digest --bundle --arg --type --current-key --new-key]
                                                                # R6 = D: an HQMGMT1 command envelope (312 hex)

HQMGMT1 envelope (156 B, R6 = D): "HQMGMT1\\0" | version u16 = 1 | msg u16 (20 confirm, 21 rollback, 22 stage,
23 activate, 24 pack-rollback, 32 factory-reset, 33 rotate; 40 wifi-heal-test = BENCH builds only) |
device_id[16] | epoch[8] | seq u64 | arg u64 | generation u64 | digest[32] | Ed25519(K_own, "HQMGMT1-SIG" || bytes 0..92),
all little-endian. device_id / epoch / next sequence / generation / digest come from GET /api/config ("envelope")
or the hsh command `owner challenge`; confirm / rollback bind the bundle in force (digest = sha256 of the HQCFG1
bundle file, --bundle computes it). The device verifies with the enrolled owner public key; K_own never leaves you.
POLICY.SIG (512 B): "HQPSIG1\\0" | gen u64 LE | sha256(POLICY.TXT) | Ed25519(key, "HQPOL1"|gen LE|sha256) | 0-pad.
The device verifies it with the operator key compiled into its boot-signed image, before parsing the policy,
and refuses a generation below the image's floor.
BLOCK.SIG / ALLOW.SIG (512 B): "HQBSIG1\\0"/"HQASIG1\\0" | gen u64 LE | len u64 LE | sha256(list) |
Ed25519(key, "HQBLK1"/"HQALW1" | gen | len | sha256) | 0-pad. Distinct tags: a BLOCK signature never verifies as ALLOW. Keep KEYFILE off the device (it is the operator's authority).
"""
import hashlib, os, struct, sys
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization as ser


def load(path):
    """Plain PKCS#8 PEM, or an encrypted one ("BEGIN ENCRYPTED PRIVATE KEY" — Mission Control's
    passphrase-wrapped backup): the passphrase comes from HQ_KEY_PASSPHRASE or an interactive prompt."""
    data = open(path, "rb").read()
    password = None
    if b"ENCRYPTED PRIVATE KEY" in data:
        pw = os.environ.get("HQ_KEY_PASSPHRASE")
        if pw is None:
            import getpass
            pw = getpass.getpass(f"passphrase for {path}: ")
        password = pw.encode()
    return ser.load_pem_private_key(data, password=password)


def pubhex(k):
    return k.public_key().public_bytes(ser.Encoding.Raw, ser.PublicFormat.Raw).hex()


MGMT_MSG = {"confirm": 20, "rollback": 21, "stage": 22, "activate": 23, "pack-rollback": 24, "factory-reset": 32, "rotate": 33,
            "wifi-heal-test": 40}
# BENCH ONLY (kernel feature wifiheal-bench): the `arg` of a wifi-heal-test envelope = the hsh word's op code
HEAL_TEST_OP = {"freeze": 1, "freeze-once": 2, "fwhalt": 3, "clear": 4}
# artifact type codes (kernel artstore::Ty; os_image 0xfe) — the `arg` of activate / pack-rollback envelopes
TYPE_CODE = {"shield_block": 0, "shield_allow": 1, "ioc": 2, "rules": 3, "oui": 4, "devices": 5, "wan": 6, "wifi": 7,
             "policy": 8, "config": 9, "os_image": 0xFE}


def fp8(pk):
    """An owner key's fingerprint as rotate envelopes carry it in `arg`: SHA-256(public key)[..8], little-endian."""
    return struct.unpack("<Q", hashlib.sha256(pk).digest()[:8])[0]


def mgmt_args(rest):
    """--device-id HEX --epoch HEX --seq N --msg NAME, then per message:
       confirm / rollback   --generation N --digest HEX | --bundle FILE      (the bundle in force)
       stage                --arg UPLOAD_ID
       activate             --type NAME --generation N --digest HEX | --file PACK   (as /api/upload/finish reports)
       pack-rollback        --type NAME --generation N                       (the generation it rolls back TO)
       factory-reset        (nothing else)
       rotate               --current-key HEX --new-key HEX --generation N   (public keys; N = rotation generation)
       wifi-heal-test       --arg freeze|freeze-once|fwhalt|clear            (BENCH builds only: wifi heal-test …)"""
    kv = {}
    it = iter(rest)
    for k in it:
        if not k.startswith("--"):
            sys.exit(f"unexpected argument {k}")
        kv[k[2:].replace("-", "_")] = next(it, None)
    if kv.get("bundle"):
        kv["digest"] = hashlib.sha256(open(kv.pop("bundle"), "rb").read()).hexdigest()
    msg = kv.get("msg")
    need = {"confirm": ("generation", "digest"), "rollback": ("generation", "digest"), "activate": ("type", "generation"),
            "pack-rollback": ("type", "generation"), "rotate": ("current_key", "new_key", "generation")}.get(msg, ())
    missing = [n for n in need if kv.get(n) is None]
    if missing:
        sys.exit(f"mgmt-sign --msg {msg}: missing --{' --'.join(m.replace('_', '-') for m in missing)} (see policy-sign.py mgmt-sign)")
    if msg in ("activate", "pack-rollback"):
        if kv["type"] not in TYPE_CODE:
            sys.exit(f"--type must be one of {', '.join(TYPE_CODE)}")
        kv["arg"] = str(TYPE_CODE[kv["type"]])
    if msg == "activate" and kv.get("digest") is None:
        sys.exit("activate binds the staged content: --digest (as /api/upload/finish reports it)")
    if msg == "wifi-heal-test":
        if kv.get("arg") not in HEAL_TEST_OP:
            sys.exit(f"wifi-heal-test: --arg must be one of {', '.join(HEAL_TEST_OP)}")
        kv["arg"] = str(HEAL_TEST_OP[kv["arg"]])
    if msg == "rotate":
        kv["arg"] = str(fp8(bytes.fromhex(kv["current_key"])))
        kv["digest"] = hashlib.sha256(bytes.fromhex(kv["new_key"])).hexdigest()
    try:
        return dict(device_id=bytes.fromhex(kv["device_id"]), epoch=bytes.fromhex(kv["epoch"]), seq=int(kv["seq"]),
                    msg=kv["msg"], arg=int(kv.get("arg") or "0", 0), generation=int(kv.get("generation") or 0),
                    digest=bytes.fromhex(kv.get("digest") or "00" * 32))
    except (KeyError, TypeError, ValueError) as e:
        sys.exit(f"mgmt-sign: {e!r} (needs --device-id --epoch --seq --msg)")


def mgmt_envelope(k, device_id, epoch, seq, msg, arg=0, generation=0, digest=b"\0" * 32):
    """The HQMGMT1 envelope bytes (156) signed by the owner key k (R6 = D)."""
    if msg not in MGMT_MSG:
        sys.exit(f"--msg must be one of {', '.join(MGMT_MSG)}")
    if len(device_id) != 16 or len(epoch) != 8 or len(digest) != 32:
        sys.exit("device_id is 16 bytes, epoch 8, digest 32 (hex as /api/config 'envelope' shows them)")
    body = (b"HQMGMT1\0" + struct.pack("<HH", 1, MGMT_MSG[msg]) + device_id + epoch
            + struct.pack("<QQQ", seq, arg, generation) + digest)
    assert len(body) == 92
    return body + k.sign(b"HQMGMT1-SIG" + body)


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
    elif a[:1] in (["sign-blocklist"], ["sign-allowlist"], ["sign-ioc"], ["sign-devices"], ["sign-wifi"], ["sign-rules"], ["sign-oui"], ["sign-wan"]) and len(a) == 5:
        k, body, gen, out = load(a[1]), open(a[2], "rb").read(), int(a[3]), a[4]
        tag, magic, cap = {
            "sign-blocklist": (b"HQBLK1", b"HQBSIG1\0", 16 << 20),
            "sign-allowlist": (b"HQALW1", b"HQASIG1\0", 16 << 20),
            "sign-ioc": (b"HQIOC1", b"HQISIG1\0", 16 << 20),
            "sign-devices": (b"HQDEV1", b"HQDSIG1\0", 16 << 10),
            "sign-wifi": (b"HQWIF1", b"HQWSIG1\0", 1 << 10),
            "sign-rules": (b"HQRUL1", b"HQRSIG1\0", 64 << 10),
            "sign-oui": (b"HQOUI1", b"HQOSIG1\0", 4 << 20),
            "sign-wan": (b"HQWAN1", b"HQNSIG1\0", 512),
        }[a[0]]
        if len(body) > cap:
            sys.exit(f"file larger than {cap} bytes")
        d = hashlib.sha256(body).digest()
        meta = struct.pack("<QQ", gen, len(body))
        sig = k.sign(tag + meta + d)
        open(out, "wb").write((magic + meta + d + sig).ljust(512, b"\0"))
        print(f"{a[0][5:].upper()} signature written (generation {gen}, {len(body)} bytes)")
    elif a[:1] == ["enroll-proof"] and len(a) == 2:
        k = load(a[1])
        pk = bytes.fromhex(pubhex(k))
        print(f"public_key={pk.hex()}\nproof={k.sign(b'HQENR1' + pk).hex()}")
    elif a[:1] == ["rotate"] and len(a) == 4:
        old, new, gen = load(a[1]), load(a[2]), int(a[3])
        pk = bytes.fromhex(pubhex(new))
        print(f"public_key={pk.hex()}\nproof={new.sign(b'HQENR1' + pk).hex()}\ngeneration={gen}\nsignature={old.sign(b'HQROT1' + pk + struct.pack('<Q', gen)).hex()}")
    elif a[:1] == ["mgmt-sign"] and len(a) >= 2:
        print(mgmt_envelope(load(a[1]), **mgmt_args(a[2:])).hex())
    else:
        sys.exit(__doc__)


if __name__ == "__main__":
    main()
