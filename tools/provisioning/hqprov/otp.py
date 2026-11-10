"""OTP secret programming: IRREVERSIBLE and separately approved. This module is a GATE, not a programmer.

It refuses unless BOTH are present:
  1. the explicit flag  --i-understand-otp-is-irreversible
  2. an operator approval file (--otp-approval-file): a regular, non-world-writable JSON file with
     `approved_by`, `approval_ref`, `approved_at` (non-empty strings) and `valid_until` (ISO-8601, in the future).

Even when both are present there is NO programming backend wired in this tool: `program()` raises
OtpBackendNotWired. The step exists so the factory flow has one auditable place where the burn must pass the
gate; wiring a real backend (and its approval record) is a separate, human-approved change. The normal
`run` flow never calls this module.
"""
import datetime
import json
import os
import stat

FLAG = "--i-understand-otp-is-irreversible"


class OtpRefused(Exception):
    pass


class OtpBackendNotWired(Exception):
    pass


def check_gate(flag_given, approval_path, now=None):
    """Return the approval dict, or raise OtpRefused with the reason. Never touches hardware."""
    if not flag_given:
        raise OtpRefused(f"refused: OTP programming is irreversible; pass {FLAG} (and an approval file)")
    if not approval_path:
        raise OtpRefused("refused: no operator approval file (--otp-approval-file)")
    try:
        st = os.stat(approval_path)
    except OSError:
        raise OtpRefused(f"refused: approval file {approval_path} does not exist")
    if not stat.S_ISREG(st.st_mode):
        raise OtpRefused("refused: approval file must be a regular file")
    if st.st_mode & stat.S_IWOTH:
        raise OtpRefused("refused: approval file is world-writable")
    try:
        with open(approval_path) as f:
            a = json.load(f)
    except (OSError, ValueError):
        raise OtpRefused("refused: approval file is not valid JSON")
    if not isinstance(a, dict):
        raise OtpRefused("refused: approval file must be a JSON object")
    for k in ("approved_by", "approval_ref", "approved_at", "valid_until"):
        if not isinstance(a.get(k), str) or not a[k].strip():
            raise OtpRefused(f"refused: approval file field {k!r} missing or empty")
    try:
        until = datetime.datetime.fromisoformat(a["valid_until"].replace("Z", "+00:00"))
    except ValueError:
        raise OtpRefused("refused: approval valid_until is not ISO-8601")
    if until.tzinfo is None:
        until = until.replace(tzinfo=datetime.timezone.utc)
    now = now or datetime.datetime.now(datetime.timezone.utc)
    if until <= now:
        raise OtpRefused("refused: approval has expired")
    return a


def program(flag_given, approval_path, now=None):
    """Gate, then (intentionally) stop: no backend is wired."""
    check_gate(flag_given, approval_path, now)
    raise OtpBackendNotWired("gate passed, but no OTP programming backend is wired in this tool (by design: "
                             "needs a separately approved change); nothing was written")
