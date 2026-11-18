# SPDX-License-Identifier: AGPL-3.0-only
"""Canonical representations. Every normalised record goes through these, so two sources describing
the same observable produce byte-identical values (the precondition for deduplication and for the
train/test contamination check).

  timestamps  RFC 3339, UTC, millisecond precision, 'Z'           2026-11-18T09:30:00.000Z
  IPs         Python ipaddress compressed form; IPv4-mapped IPv6 -> IPv4
  domains     lowercase IDNA A-labels, no trailing dot, RFC 1035 length limits
  JSON        sorted keys, no whitespace, UTF-8 (canonical_json)
"""
import datetime
import hashlib
import hmac
import ipaddress
import json
import math
import re

_LABEL = re.compile(r"^(?!-)[a-z0-9_-]{1,63}(?<!-)$")

# Two-label public suffixes the heqk DGA scorer knows (os/kernel/kernel/src/dga.rs SUFFIX2). Used for
# split grouping only; a full Public Suffix List is a later, licence-checked addition (PSL is MPL-2.0).
SUFFIX2 = ("co.uk", "org.uk", "ac.uk", "com.au", "net.au", "co.jp", "com.br", "co.in", "com.cn", "co.nz",
           "com.tr", "co.za", "com.mx", "com.ro")


def ts(value):
    """Canonical timestamp from a datetime, an epoch number (s), or an ISO-8601 string. None -> None."""
    if value is None or value == "" or value == "-":
        return None
    if isinstance(value, datetime.datetime):
        dt = value
    elif isinstance(value, (int, float)) and not isinstance(value, bool):
        if not math.isfinite(value):
            return None
        dt = datetime.datetime.fromtimestamp(float(value), tz=datetime.timezone.utc)
    elif isinstance(value, str):
        s = value.strip()
        if re.fullmatch(r"[0-9]+(\.[0-9]+)?", s):
            return ts(float(s))
        s = s.replace(" UTC", "Z").replace(" ", "T", 1)
        if s.endswith("Z"):
            s = s[:-1] + "+00:00"
        try:
            dt = datetime.datetime.fromisoformat(s)
        except ValueError:
            return None
    else:
        raise TypeError(f"cannot make a timestamp from {type(value).__name__}")
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=datetime.timezone.utc)  # sources without a zone are documented as UTC
    dt = dt.astimezone(datetime.timezone.utc)
    return dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{dt.microsecond // 1000:03d}Z"


def now():
    return ts(datetime.datetime.now(datetime.timezone.utc))


def date(value):
    """YYYY-MM-DD from an ISO date/datetime string, or None."""
    if not value:
        return None
    m = re.match(r"^\s*([0-9]{4}-[0-9]{2}-[0-9]{2})", str(value))
    return m.group(1) if m else None


def ip(value):
    """Canonical IP string, or None if `value` is not an IP address."""
    if value is None:
        return None
    try:
        a = ipaddress.ip_address(str(value).strip().strip("[]"))
    except ValueError:
        return None
    if isinstance(a, ipaddress.IPv6Address) and a.ipv4_mapped:
        a = a.ipv4_mapped
    return a.compressed


def cidr(value):
    try:
        return ipaddress.ip_network(str(value).strip(), strict=False).compressed
    except ValueError:
        return None


def domain(value):
    """Canonical domain (lowercase A-label, no trailing dot) or None when the name is not a valid DNS name.

    Underscore labels are allowed (service names like _dmarc). IP literals are rejected (use ip()).
    """
    if value is None:
        return None
    s = str(value).strip().rstrip(".").lower()
    if not s or len(s) > 253 or ip(s) is not None:
        return None
    try:
        if any(ord(c) > 127 for c in s):
            s = s.encode("idna").decode("ascii")
    except UnicodeError:
        return None
    labels = s.split(".")
    if len(labels) < 2 or not all(_LABEL.match(lb) for lb in labels):
        return None
    if labels[-1].isdigit():
        return None
    return s


def registrable(name):
    """The registrable domain (label + public suffix) by the same rule as dga.rs `split`."""
    d = domain(name)
    if d is None:
        return None
    labels = d.split(".")
    for suf in SUFFIX2:
        if d.endswith("." + suf) and len(labels) >= 3:
            return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def url_host(url):
    m = re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://(?:[^/@]*@)?(\[[^\]]+\]|[^/:?#]+)", url.strip())
    return m.group(1).strip("[]") if m else None


def canonical_json(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)


def sha256_bytes(b):
    return hashlib.sha256(b).hexdigest()


def sha256_obj(obj):
    return sha256_bytes(canonical_json(obj).encode("utf-8"))


def pseudonym(key, value, prefix="c:"):
    """Keyed pseudonym (HMAC-SHA256, 64 bits). The key is per dataset build and is never exported, so the
    mapping cannot be reversed from the output (GDPR art. 4(5) pseudonymisation; see governance doc)."""
    if value is None:
        return None
    return prefix + hmac.new(key, str(value).encode("utf-8"), hashlib.sha256).hexdigest()[:16]


SEVERITY_BY_NUMBER = {1: "critical", 2: "high", 3: "medium", 4: "low", 5: "info"}
