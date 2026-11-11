#!/usr/bin/env python3
"""hqcfg — the HQCFG1 configuration bundle + HQCSIG1 signature (ADR 0059 Step 2; assessment §B.4).

  hqcfg.py bundle KEYFILE GEN OUT.BIN OUT.SIG [--wan WAN.TXT] [--wifi WIFI.TXT] [--policy POLICY.TXT] [--device-id HEX32]
        Build one bundle from the legacy per-file forms (their "HQWAN1"/"HQPOL1" header lines and the
        POLICY 4096-byte newline padding are dropped; the sections hold canonical text only), then sign it.
  hqcfg.py verify PUBHEX BUNDLE.BIN BUNDLE.SIG [FLOOR [DEVICE_ID_HEX32]]   # verify like the device
  hqcfg.py vectors OUTDIR                          # deterministic test vectors (fixed RFC 8032 test key)

Byte layout (all integers little-endian). Points marked [A] are this tool's reading of §B.4 where it is
silent; they are agreed with the kernel verifier (cfgbundle.rs) through the shared vectors:

  bundle   "HQCFG1\\0\\0" | schema u16 [A: (major<<8)|minor, 1.0 = 0x0100] | flags u16 (bit0 device-bound)
           | generation u64 | device_id[16] (zero = any device) | signer_key_id[8] = sha256(pk)[:8]
           | section_count u8 | reserved[3]=0 | count x {kind u8, rsv u8=0, len u16} | bodies, no padding
           kinds 1 wan 2 link 3 lan 4 wifi 5 policy 6 mgmt 7 tunnel 8 secrets; [A] each kind at most once,
           strictly ascending
  schema 1.0 carries only wan(1), wifi(4), policy(5); any other kind is refused (2/6 reserved).
  sig      512 B: "HQCSIG1\\0" | alg u8 (1 = Ed25519) | total_len u32 (= the received length exactly) | sha256(bundle)
           | Ed25519(key, b"HQCFG1-SIG" || sha256) | zero pad

Canonical section text (refused otherwise): ASCII 0x20-0x7E + LF; every line ends in LF; no blank lines, no
trailing whitespace; wan/wifi: one key=value per line, each key once; policy: each statement once, no
repeated (list, seq), second default, interface binding or route (dst, from, via).
The PPPoE password and Wi-Fi PSK travel inside the signed region in clear: they are NOT protected at rest
until the secrets section (kind 8) ships.
Keys: plain PKCS#8 PEM or Mission Control's encrypted backup (HQ_KEY_PASSPHRASE or a prompt).
"""
import hashlib, json, os, re, struct, sys
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives import serialization as ser

MAGIC, SIG_MAGIC, SIG_TAG = b"HQCFG1\0\0", b"HQCSIG1\0", b"HQCFG1-SIG"
SCHEMA = 0x0100
MAX_BUNDLE = 16 << 10
KINDS = {"wan": 1, "link": 2, "lan": 3, "wifi": 4, "policy": 5, "mgmt": 6, "tunnel": 7, "secrets": 8}
LINE = re.compile(rb"^[\x20-\x7e]*$")
V1_KINDS = {"wan", "wifi", "policy"}   # schema 1.0: link(2)/mgmt(6) reserved, lan/tunnel/secrets not defined yet -> refused


def load(path):
    data = open(path, "rb").read()
    password = None
    if b"ENCRYPTED PRIVATE KEY" in data:
        pw = os.environ.get("HQ_KEY_PASSPHRASE")
        if pw is None:
            import getpass
            pw = getpass.getpass(f"passphrase for {path}: ")
        password = pw.encode()
    return ser.load_pem_private_key(data, password=password)


def raw_pk(k):
    return k.public_key().public_bytes(ser.Encoding.Raw, ser.PublicFormat.Raw)


def canonical(kind, body):
    """Raise ValueError unless `body` is canonical section text for `kind`."""
    if not body or not body.endswith(b"\n"):
        raise ValueError(f"{kind}: empty or missing final LF")
    lines = body[:-1].split(b"\n")
    seen = set()
    for ln in lines:
        if not ln:
            raise ValueError(f"{kind}: blank line")
        if not LINE.match(ln) or ln != ln.rstrip(b" "):
            raise ValueError(f"{kind}: non-canonical byte or trailing space in {ln[:40]!r}")
        if kind == "policy":
            w = ln.split(b" ")
            if w[0] in (b"acl", b"prefix-list") and len(w) > 3 and w[2] == b"seq":
                key = (w[0], w[1], b"seq", w[3])
            elif w[0] == b"acl" and len(w) > 2 and w[2] == b"default":
                key = (b"acl", w[1], b"default")
            elif w[0] == b"interface" and len(w) >= 4:
                key = tuple(w[:4])
            elif w[0] == b"route" and len(w) > 1:
                # (dst, from|any, via): metric-ordered failover through different interfaces is legitimate;
                # a repeat through the same interface (only the metric differs) is a duplicate.
                via = w[w.index(b"via") + 1] if b"via" in w[:-1] else b""
                key = (b"route", w[1], w[3] if len(w) > 3 and w[2] == b"from" else b"any", via)
            else:
                key = tuple(w)
        else:
            if b"=" not in ln:
                raise ValueError(f"{kind}: not key=value: {ln[:40]!r}")
            key = ln.split(b"=", 1)[0]
        if key in seen:
            raise ValueError(f"{kind}: repeated {key!r}")
        seen.add(key)


def from_legacy(kind, data):
    """Legacy per-file form -> canonical section body."""
    if kind == "policy":
        data = data.rstrip(b"\n") + b"\n"           # drop the 4096-byte newline padding
        if data.startswith(b"HQPOL1\n"):
            data = data[len(b"HQPOL1\n"):]
    if kind == "wan" and data.startswith(b"HQWAN1\n"):
        data = data[len(b"HQWAN1\n"):]
    canonical(kind, data)
    return data


def build(sections, generation, pk, device_id=b"\0" * 16, schema=SCHEMA):
    """sections: list of (kind name, canonical body). Returns the bundle bytes."""
    order = sorted(sections, key=lambda s: KINDS[s[0]])
    if any(k not in V1_KINDS for k, _ in order):
        raise ValueError("schema 1.0 carries only wan, wifi and policy sections")
    if len({k for k, _ in order}) != len(order):
        raise ValueError("a section kind appears twice")
    for k, b in order:
        canonical(k, b)
        if len(b) > 0xFFFF:
            raise ValueError(f"{k}: section longer than 65535 bytes")
    flags = 1 if any(device_id) else 0
    head = MAGIC + struct.pack("<HHQ", schema, flags, generation) + device_id + hashlib.sha256(pk).digest()[:8]
    head += struct.pack("<B3x", len(order))
    table = b"".join(struct.pack("<BBH", KINDS[k], 0, len(b)) for k, b in order)
    out = head + table + b"".join(b for _, b in order)
    if len(out) > MAX_BUNDLE:
        raise ValueError("bundle larger than 16 KiB")
    return out


def sign(key, bundle):
    d = hashlib.sha256(bundle).digest()
    s = SIG_MAGIC + struct.pack("<BI", 1, len(bundle)) + d + key.sign(SIG_TAG + d)
    return s + b"\0" * (512 - len(s))


def verify(pk, buf, sig, device_id=b"\0" * 16, floor=0):
    """Verify like the device. Returns (header dict, [(kind, body)]). Raises ValueError with the reason."""
    if len(sig) != 512 or sig[:8] != SIG_MAGIC:
        raise ValueError("sig: bad magic or size")
    alg, total = struct.unpack_from("<BI", sig, 8)
    if alg != 1:
        raise ValueError("sig: unknown alg")
    if any(sig[109:]):
        raise ValueError("sig: non-zero padding")
    if total > MAX_BUNDLE or total < 48:
        raise ValueError("sig: total_len out of range")
    if total != len(buf):
        raise ValueError("sig: total_len differs from the received length")
    bundle = buf
    d = hashlib.sha256(bundle).digest()
    if d != sig[13:45]:
        raise ValueError("digest mismatch")
    try:
        Ed25519PublicKey.from_public_bytes(pk).verify(sig[45:109], SIG_TAG + d)
    except Exception:
        raise ValueError("bad signature")
    if bundle[:8] != MAGIC:
        raise ValueError("bundle: bad magic")
    schema, flags, gen = struct.unpack_from("<HHQ", bundle, 8)
    if schema >> 8 != SCHEMA >> 8:
        raise ValueError("bundle: unknown major schema")
    dev, kid = bundle[20:36], bundle[36:44]
    if gen <= floor:
        raise ValueError(f"bundle: generation {gen} not newer than {floor}")
    if kid != hashlib.sha256(pk).digest()[:8]:
        raise ValueError("bundle: unknown signer key id")
    if flags & 1 and dev != device_id:
        raise ValueError("bundle: bound to another device")
    if flags & ~1:
        raise ValueError("bundle: unknown flag")
    count = bundle[44]
    if any(bundle[45:48]):
        raise ValueError("bundle: reserved bytes set")
    off, out, last = 48 + 4 * count, [], 0
    if off > total:
        raise ValueError("bundle: section table overruns")
    names = {v: k for k, v in KINDS.items()}
    for i in range(count):
        kind, rsv, ln = struct.unpack_from("<BBH", bundle, 48 + 4 * i)
        if kind not in names or names[kind] not in V1_KINDS or rsv:
            raise ValueError(f"bundle: unknown section kind {kind}")
        if kind <= last:
            raise ValueError("bundle: sections out of order or repeated")
        last = kind
        if off + ln > total:
            raise ValueError("bundle: section overruns")
        body = bundle[off:off + ln]
        canonical(names[kind], body)
        out.append((names[kind], body))
        off += ln
    if off != total:
        raise ValueError("bundle: bytes after the last section")
    return {"schema": schema, "flags": flags, "generation": gen, "device_id": dev.hex(), "signer_key_id": kid.hex()}, out


# RFC 8032 §7.1 TEST 1 secret key: public, deterministic — for vectors only, never a real key.
TEST_SEED = bytes.fromhex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")


def vectors(outdir):
    key = Ed25519PrivateKey.from_private_bytes(TEST_SEED)
    pk = raw_pk(key)
    wan = b"mode=pppoe\npppoe_user=user@isp\npppoe_pass=s3cret\nvlan=6\n"
    wifi = b"ssid=Popescu-Home\npsk=correct horse battery\nsecurity=wpa3-transition\n"
    pol = b"acl LAN_IN seq 10 block any 10.66.0.0/24 10.66.0.0/24\nacl LAN_IN seq 20 allow any any any\ninterface lan acl in LAN_IN\n"
    cases = {}
    full = build([("wan", wan), ("wifi", wifi), ("policy", pol)], 7, pk)
    good = [("valid-wan-wifi-policy", full), ("valid-wifi-only", build([("wifi", wifi)], 8, pk))]
    for name, b in good:
        cases[name] = {"bundle": b.hex(), "sig": sign(key, b).hex(), "expect": "ok", "floor": 0}
    s = bytes(sign(key, full))
    def case(b, sg, why, floor=0):
        return {"bundle": b.hex(), "sig": sg.hex(), "expect": why, "floor": floor}
    def forged(raw, why, floor=0):  # correctly signed but wrong: refused after the signature passes
        return case(raw, sign(key, raw), why, floor)
    cases["flip-header-byte"] = case(full[:10] + bytes([full[10] ^ 1]) + full[11:], s, "digest mismatch")
    cases["flip-body-byte"] = case(full[:-2] + bytes([full[-2] ^ 1]) + full[-1:], s, "digest mismatch")
    cases["trailing-byte"] = case(full + b"X", s, "sig: total_len differs from the received length")
    cases["truncated"] = case(full[:-1], s, "sig: total_len differs from the received length")
    cases["sig-nonzero-pad"] = case(full, s[:-1] + b"\x01", "sig: non-zero padding")
    cases["older-generation"] = case(full, s, "bundle: generation 7 not newer than 7", floor=7)
    cases["newer-than-floor"] = case(full, s, "ok", floor=6)
    hdr = bytearray(full[:48]); hdr[44] = 2
    two = bytes(hdr) + struct.pack("<BBH", 1, 0, len(wan)) * 2 + wan + wan
    cases["sections-repeated"] = forged(two, "bundle: sections out of order or repeated")
    ooo = bytes(hdr) + struct.pack("<BBH", 4, 0, len(wifi)) + struct.pack("<BBH", 1, 0, len(wan)) + wifi + wan
    cases["sections-out-of-order"] = forged(ooo, "bundle: sections out of order or repeated")
    major2 = bytearray(full); major2[8:10] = struct.pack("<H", 0x0200)
    cases["schema-major-2"] = forged(bytes(major2), "bundle: unknown major schema")
    minor = bytearray(full); minor[8:10] = struct.pack("<H", 0x0101)
    cases["schema-minor-1"] = forged(bytes(minor), "ok")
    fl = bytearray(full); fl[10:12] = struct.pack("<H", 2)
    cases["unknown-flag"] = forged(bytes(fl), "bundle: unknown flag")
    kid = bytearray(full); kid[36] ^= 0xFF
    cases["unknown-signer-key-id"] = forged(bytes(kid), "bundle: unknown signer key id")
    bound = bytearray(full); bound[10:12] = struct.pack("<H", 1); bound[20:36] = b"\x11" * 16
    cases["bound-to-other-device"] = forged(bytes(bound), "bundle: bound to another device")
    for k in (2, 6, 9):
        unk = bytearray(full); unk[48] = k
        cases[f"kind-{k}-refused"] = forged(bytes(unk), f"bundle: unknown section kind {k}")
    over = bytearray(full); over[50:52] = struct.pack("<H", 0xFFF0)
    cases["len-overflow"] = forged(bytes(over), "bundle: section overruns")
    cases["bytes-after-last-section"] = forged(full + b"Z", "bundle: bytes after the last section")
    wdup = full.replace(b"vlan=6\n", b"mode=x\n")  # same length; 'mode' twice in wan
    cases["duplicate-key-in-wan"] = forged(wdup, "wan: repeated b'mode'")
    wf = build([("wifi", b"ssid=a\npsk=xxxxxxxx\n")], 9, pk).replace(b"psk=xxxxxxxx\n", b"ssid=bbbbbbb\n")
    cases["duplicate-key-in-wifi"] = forged(wf, "wifi: repeated b'ssid'")
    crlf = full.replace(b"mode=pppoe\n", b"mode=pppo\r\n")  # same length; CR inside the wan section
    cases["cr-in-wan"] = forged(crlf, "wan: non-canonical byte or trailing space in b'mode=pppo\\r'")
    fo = b"route 0.0.0.0/0 via wan metric 10\nroute 0.0.0.0/0 via mgmt gw 192.168.200.1 metric 100\n"
    fob = build([("policy", fo)], 10, pk)
    cases["two-default-routes-wan-mgmt"] = {"bundle": fob.hex(), "sig": sign(key, fob).hex(), "expect": "ok", "floor": 0}
    same = build([("policy", b"route 0.0.0.0/0 via wan metric 10\nroute 10.9.0.0/16 via wan metric 99\n")], 11, pk)
    same = same.replace(b"route 10.9.0.0/16 via wan metric 99\n", b"route 0.0.0.0/0 via wan metric 9999\n")  # same length
    cases["duplicate-route-same-via"] = forged(same, "policy: repeated (b'route', b'0.0.0.0/0', b'any', b'wan')")
    # section byte ranges of the valid full bundle (offset from the start of the bundle)
    off, ranges = 48 + 4 * 3, []
    for k, b in sorted([("wan", wan), ("wifi", wifi), ("policy", pol)], key=lambda x: KINDS[x[0]]):
        ranges.append({"kind": k, "id": KINDS[k], "offset": off, "len": len(b)}); off += len(b)
    cases["valid-wan-wifi-policy"]["sections"] = ranges
    cases["valid-wan-wifi-policy"]["total_len"] = len(full)
    os.makedirs(outdir, exist_ok=True)
    for c in cases.values():
        c["accept"] = c["expect"] == "ok"   # the contract; "expect" strings are hqcfg.py's wording only
    doc = {"about": "HQCFG1/HQCSIG1 vectors (ADR 0059 §B.4) from os/kernel/tools/hqcfg.py; RFC 8032 TEST 1 key. "
                    "accept = the verifier must accept; floor = the stored generation floor (accept only generation > floor); "
                    "device_id = this device's id for the case (absent = all-zero).",
           "public_key": pk.hex(), "generation_full": 7, "sections_full": {"wan": wan.decode(), "wifi": wifi.decode(), "policy": pol.decode()},
           "cases": cases}
    with open(os.path.join(outdir, "hqcfg-vectors.json"), "w") as f:
        json.dump(doc, f, indent=1, sort_keys=True)
    # self-check
    for name, c in cases.items():
        try:
            verify(pk, bytes.fromhex(c["bundle"]), bytes.fromhex(c["sig"]), floor=c.get("floor", 0), device_id=bytes.fromhex(c.get("device_id", "00" * 16)))
            got = "ok"
        except ValueError as e:
            got = str(e)
        if got != c["expect"]:
            sys.exit(f"vector {name}: expected {c['expect']!r}, got {got!r}")
    print(f"{len(cases)} vectors -> {os.path.join(outdir, 'hqcfg-vectors.json')} (self-verified)")


def main():
    a = sys.argv[1:]
    if len(a) >= 5 and a[0] == "bundle":
        key, gen, out_b, out_s = load(a[1]), int(a[2]), a[3], a[4]
        secs, rest, dev = [], a[5:], b"\0" * 16
        while rest:
            flag, path = rest[0], rest[1]
            if flag == "--device-id":
                dev = bytes.fromhex(path); assert len(dev) == 16, "device id is 32 hex digits"
                rest = rest[2:]; continue
            kind = {"--wan": "wan", "--wifi": "wifi", "--policy": "policy"}[flag]
            secs.append((kind, from_legacy(kind, open(path, "rb").read())))
            rest = rest[2:]
        b = build(secs, gen, raw_pk(key), device_id=dev)
        open(out_b, "wb").write(b)
        open(out_s, "wb").write(sign(key, b))
        print(f"HQCFG1 generation {gen}: {len(b)} bytes, sections {[k for k, _ in sorted(secs, key=lambda s: KINDS[s[0]])]}")
    elif len(a) in (4, 5, 6) and a[0] == "verify":
        hdr, secs = verify(bytes.fromhex(a[1]), open(a[2], "rb").read(), open(a[3], "rb").read(),
                           floor=int(a[4]) if len(a) >= 5 else 0, device_id=bytes.fromhex(a[5]) if len(a) == 6 else b"\0" * 16)
        print(json.dumps(hdr))
        for k, b in secs:
            print(f"--- {k} ({len(b)} B)\n{b.decode()}", end="")
    elif len(a) == 2 and a[0] == "vectors":
        vectors(a[1])
    else:
        sys.exit(__doc__)


if __name__ == "__main__":
    main()
