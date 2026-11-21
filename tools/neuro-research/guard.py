# SPDX-License-Identifier: AGPL-3.0-only
"""Doc 24 injection guard (model-independent), the Python reference.

R: render-side redaction. On every context line carrying `!instr-like`, each quoted value becomes
   "<instruction-like text, N chars, withheld>". The carrier field name and the marker stay; unmarked lines are
   untouched.
E: output echo filter. If a triage/injection `summary` (or a copilot `text`) contains any 8+ character substring
   of any quoted value in the ORIGINAL context (case-insensitive), it is replaced by the deterministic template
   explanation. The verdict, evidence, entities and next step are kept, and `_guard_fallback` is set.
"""
import re

QUOTED = re.compile(r'"([^"\n]*)"')
N = 8


def redact(context):
    out = []
    for line in context.split("\n"):
        if "!instr-like" in line:
            line = QUOTED.sub(lambda m: '"<instruction-like text, %d chars, withheld>"' % len(m.group(1)), line)
        out.append(line)
    return "\n".join(out)


def quoted_values(context):
    return [v.lower() for v in QUOTED.findall(context) if len(v) >= N]


def echoes(context, text, n=N):
    t = (text or "").lower()
    for v in quoted_values(context):
        for i in range(0, len(v) - n + 1):
            if v[i:i + n] in t:
                return True
    return False


def apply_output(case, out, template):
    """E. `template` is run_eval.template_backend; `case` is the ORIGINAL (unredacted) case."""
    if not isinstance(out, dict) or "_error" in out or "_unparseable" in out:
        return out
    if case["task"] in ("triage", "injection") and isinstance(out.get("summary"), str):
        if echoes(case["context"], out["summary"]):
            out = dict(out, summary=template(case)["summary"], _guard_fallback=True)
    elif case["task"] == "copilot" and isinstance(out.get("text"), str):
        if echoes(case["context"], out["text"]):
            out = dict(out, text=template(case)["text"], _guard_fallback=True)
    return out
