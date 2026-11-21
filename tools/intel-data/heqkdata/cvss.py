# SPDX-License-Identifier: AGPL-3.0-only
"""CVSS v3.0 / v3.1 base score from a vector string (FIRST CVSS v3.1 specification, section 7.1 and
Appendix A rounding). Used where a source gives the vector but not the score (OSV advisories). Returns
None for anything that is not a complete, valid v3 base vector; v2 and v4 vectors are not scored here."""
import math

W = {
    "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2},
    "AC": {"L": 0.77, "H": 0.44},
    "UI": {"N": 0.85, "R": 0.62},
    "C": {"H": 0.56, "L": 0.22, "N": 0.0},
    "I": {"H": 0.56, "L": 0.22, "N": 0.0},
    "A": {"H": 0.56, "L": 0.22, "N": 0.0},
}
PR = {"U": {"N": 0.85, "L": 0.62, "H": 0.27}, "C": {"N": 0.85, "L": 0.68, "H": 0.5}}
BASE = ("AV", "AC", "PR", "UI", "S", "C", "I", "A")


def roundup(x):
    """Appendix A: the smallest number, to one decimal place, that is >= x (float-safe)."""
    i = int(round(x * 100000))
    return i / 100000.0 if i % 10000 == 0 else (math.floor(i / 10000) + 1) / 10.0


def parse_v3(vector):
    if not isinstance(vector, str):
        return None
    parts = vector.strip().split("/")
    if not parts or parts[0] not in ("CVSS:3.0", "CVSS:3.1"):
        return None
    m = {}
    for p in parts[1:]:
        k, _, v = p.partition(":")
        if not k or not v or k in m:
            return None
        m[k] = v
    if any(k not in m for k in BASE) or m["S"] not in ("U", "C"):
        return None
    for k in ("AV", "AC", "UI", "C", "I", "A"):
        if m[k] not in W[k]:
            return None
    if m["PR"] not in PR["U"]:
        return None
    return parts[0][5:], m


def base_score_v3(vector):
    p = parse_v3(vector)
    if p is None:
        return None
    _, m = p
    iss = 1 - (1 - W["C"][m["C"]]) * (1 - W["I"][m["I"]]) * (1 - W["A"][m["A"]])
    if m["S"] == "U":
        impact = 6.42 * iss
    else:
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
    expl = 8.22 * W["AV"][m["AV"]] * W["AC"][m["AC"]] * PR[m["S"]][m["PR"]] * W["UI"][m["UI"]]
    if impact <= 0:
        return 0.0
    if m["S"] == "U":
        return roundup(min(impact + expl, 10))
    return roundup(min(1.08 * (impact + expl), 10))


def severity(score):
    """CVSS v3 qualitative rating (spec table 14) on the heqk scale; 0.0 ('None') maps to info."""
    if score is None:
        return None
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    if score >= 0.1:
        return "low"
    return "info"
