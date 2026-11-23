#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Doc 36: thin-evidence ACKNOWLEDGEMENT, frozen before blind v7 exists.

A thin-evidence case (`ins-`) is acknowledged when the answer's verdict is `insufficient_evidence`, OR its summary
says the evidence is too thin (LEX below, English and Romanian, with and without diacritics).

LEX was written on 2026-11-23 after reading six ftGg summaries on SPENT blind v6 cases (doc 36 says so). It is
frozen here, by SHA-256 in doc 36, before blind v7 is authored, so blind v7 tests it honestly.
"""
import re

LEX = re.compile(
    r"insufficient|too thin|not enough|cannot (be )?(confirm|determine|conclude)|can't (confirm|determine)|inconclusive"
    r"|no (additional|further|other) (evidence|context|signal|corroborat)|lack of (additional |further )?(evidence|context|corroborat)"
    r"|more (data|evidence|context) (is )?(needed|required)|difficult to (classify|determine|conclude)"
    r"|dovezi insuficiente|nu exist[aă] (suficiente )?dovezi|nu sunt (suficiente|disponibile)|insuficient|neconcludent",
    re.I)


def acknowledged(output):
    """output = run_eval's parsed answer dict (outputs[0])."""
    return output.get("verdict") == "insufficient_evidence" or bool(LEX.search(output.get("summary") or ""))
