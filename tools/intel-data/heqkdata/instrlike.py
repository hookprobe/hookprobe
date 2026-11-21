# SPDX-License-Identifier: AGPL-3.0-only
"""The `!instr-like` flag on attacker-controlled strings in exports (Neuro doc 24 addendum, #1450).

The rule is Neuro's reference detector, imported from tools/neuro-research/semantic_compression.py so there is
one source of truth: INSTRUCTION_LIKE.search() on the FULL value, before any truncation. An exported value
becomes {"value": "...", "instr_like": bool}; the card renderer appends ` !instr-like` iff true.

Known limitation (measured by Neuro): the keyword rule misses English injections without those words and all
Romanian ones. Do not change the rule here; a detector change is its own pre-registered step on Neuro's side.

Today's windows exports (IoT-23 conn.log, CTU-13 binetflow) carry no attacker-controlled strings (service,
history and conn_state are the sensor's own vocabulary), so wrapping them is a no-op and their output is
unchanged. The field list is ready for sources that do carry them (DNS, HTTP, TLS, DHCP/mDNS, mail, files).
"""
import importlib.util
import os

from . import TOOL_DIR

DETECTOR = os.path.join(os.path.dirname(TOOL_DIR), "neuro-research", "semantic_compression.py")

# exported field name -> attacker-controlled string (DNS qname, HTTP host/UA/referer/URL, TLS SNI and cert
# CN/SAN, file names, DHCP/mDNS hostnames, mail subject)
ATTACKER_FIELDS = frozenset({
    "query", "qname", "dns_query",
    "http_host", "host_header", "user_agent", "referrer", "referer", "uri", "url",
    "server_name", "sni", "cert_cn", "cert_subject", "cert_san", "san",
    "filename", "file_name",
    "dhcp_hostname", "mdns_name", "hostname",
    "mail_subject", "subject",
})

_regex = None


def pattern():
    """The reference detector's compiled regex (loaded once, from Neuro's file)."""
    global _regex
    if _regex is None:
        spec = importlib.util.spec_from_file_location("_neuro_semantic_compression", DETECTOR)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        _regex = mod.INSTRUCTION_LIKE
    return _regex


def flag(value):
    """{"value", "instr_like"} for one attacker-controlled string, tested on the full value."""
    return {"value": value, "instr_like": bool(pattern().search(value))}


def wrap(event):
    """Replace every attacker-controlled string value of one exported event dict with its flagged form."""
    for k in ATTACKER_FIELDS.intersection(event):
        v = event[k]
        if isinstance(v, str):
            event[k] = flag(v)
        elif isinstance(v, list):  # e.g. several SANs
            event[k] = [flag(x) if isinstance(x, str) else x for x in v]
    return event
