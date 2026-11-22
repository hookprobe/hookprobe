# SPDX-License-Identifier: AGPL-3.0-only
"""Doc 29 HQPROP1: the deterministic Neuro policy compiler (userspace reference) and its proposal codec.

compile(evidence, rules, inventory, now) -> proposal dict | None   (pure; no ML, no free text)
encode(proposal) -> canonical ASCII bytes;  sign(...) / verify(...) with Ed25519 (tag "HQPROP1-SIG").
The compiler NEVER applies anything: authority comes only from the owner key on HEQK's existing signed paths.
"""
import hashlib, re
try:
    import tomllib
except ImportError:  # pragma: no cover
    tomllib = None
from . import ed25519_ref as ed

COMPILER_VER = 1
ACTIONS = {"hold_ip": "session", "isolate_device": "session", "restrict_lan_only": "durable",
           "restrict_internet_only": "durable", "block_domain": "durable", "shield_profile_strict": "durable"}
LOOSENING = {"allow_domain", "full_access", "shield_off", "unquarantine"}     # never producible
SESSION_TTL = (60, 86400)
FIELDS = ["magic", "prop_id", "compiler_ver", "rules_ver", "device_id", "target", "action", "scope", "ttl_s",
          "confidence", "evidence", "reason_code", "expires_at", "nonce", "issued_at", "revokes"]
SAFE = re.compile(r"^[A-Za-z0-9._:\-]*$")


def load_rules(path):
    with open(path, "rb") as f:
        r = tomllib.load(f)
    for rule in r["rule"]:
        assert rule["action"] in ACTIONS and rule["action"] not in LOOSENING, rule
        assert rule["scope"] == ACTIONS[rule["action"]] or rule["action"] == "isolate_device"
        lo, hi = SESSION_TTL if rule["scope"] == "session" else (60, r["durable_ttl_max_s"])
        assert lo <= rule["ttl_s"] <= hi, rule
    return r


def _ref(x):
    """Evidence references must be identifiers, never content: anything else is rejected."""
    x = str(x)
    if not SAFE.match(x) or len(x) > 64:
        raise ValueError("evidence reference is not an identifier")
    return x


def compile(evidence, rules, inventory, now):
    """evidence: {gateway, target:{kind,id,mac?}, l0:[{category, confirmed, incident}], cls:{high, run, model},
    dna:{novel_dest, record}}. Unknown fields (and any free text) are ignored by construction."""
    t = evidence.get("target") or {}
    kind = t.get("kind")
    if kind not in ("device", "ip"):
        return None
    if kind == "device" and t.get("id") not in inventory:
        return None
    if kind == "ip" and not t.get("mac"):           # identity-keyed action needs the (IP, MAC) anti-spoof pair
        return None
    cats = {e.get("category") for e in evidence.get("l0", [])}
    confirmed = any(e.get("confirmed") for e in evidence.get("l0", []))
    cls_high = bool((evidence.get("cls") or {}).get("high"))
    novel = bool((evidence.get("dna") or {}).get("novel_dest"))
    for rule in rules["rule"]:                       # first match wins; table order is part of rules_ver
        q = rule["requires"]
        if not set(q.get("l0", [])) <= cats:
            continue
        if q.get("l0_confirmed") and not confirmed:
            continue
        if q.get("cls_high") and not cls_high:
            continue
        if q.get("dna_novel") and not novel:
            continue
        refs = sorted({_ref(e["incident"]) for e in evidence.get("l0", []) if e.get("incident")})
        if evidence.get("cls"):
            refs += ["cls:" + _ref(evidence["cls"].get("run", "")), "model:" + _ref(evidence["cls"].get("model", ""))]
        if evidence.get("dna", {}).get("record"):
            refs.append("dna:" + _ref(evidence["dna"]["record"]))
        target = "%s:%s" % (kind, _ref(t["id"])) + ("@" + _ref(t["mac"]) if kind == "ip" else "")
        seed = "|".join([_ref(evidence["gateway"]), target, rule["reason_code"], str(now)] + refs).encode()
        h = hashlib.sha256(seed).hexdigest()
        return {"magic": "HQPROP1", "prop_id": h[:32], "compiler_ver": COMPILER_VER, "rules_ver": rules["rules_ver"],
                "device_id": _ref(evidence["gateway"]), "target": target, "action": rule["action"], "scope": rule["scope"],
                "ttl_s": rule["ttl_s"], "confidence": rule["confidence"], "evidence": refs, "reason_code": rule["reason_code"],
                "expires_at": now + rules["proposal_validity_s"], "nonce": h[32:64], "issued_at": now, "revokes": ""}
    return None                                      # classifier-only or DNA-only evidence never yields an action


def encode(prop):
    lines = []
    for k in FIELDS:
        v = prop[k]
        v = ",".join(v) if isinstance(v, list) else str(v)
        if not SAFE.match(v.replace(",", "").replace("+", "")):
            raise ValueError("non-canonical value in %s" % k)
        lines.append("%s=%s" % (k, v))
    return ("\n".join(lines) + "\n").encode("ascii")


def sign(prop, secret):
    body = encode(prop)
    return body + b"sig=" + ed.sign(secret, b"HQPROP1-SIG" + hashlib.sha256(body).digest()).hex().encode() + b"\n"


def verify(blob, public, now, seen_nonces, gateway):
    """Device-side acceptance check (reference): signature, binding, expiry, replay, mapping, TTL."""
    body, _, sig = blob.rpartition(b"sig=")
    if not ed.verify(public, b"HQPROP1-SIG" + hashlib.sha256(body).digest(), bytes.fromhex(sig.strip().decode())):
        return False, "bad signature"
    kv = dict(l.split("=", 1) for l in body.decode("ascii").splitlines())
    if kv["magic"] != "HQPROP1" or kv["device_id"] != gateway:
        return False, "wrong device"
    if now > int(kv["expires_at"]):
        return False, "expired"
    if kv["nonce"] in seen_nonces:
        return False, "replay"
    if kv["action"] in LOOSENING or kv["action"] not in ACTIONS:
        return False, "action not allowed"
    ttl = int(kv["ttl_s"])
    if kv["scope"] == "session" and not (SESSION_TTL[0] <= ttl <= SESSION_TTL[1]):
        return False, "ttl out of range"
    seen_nonces.add(kv["nonce"])
    return True, "ok"
