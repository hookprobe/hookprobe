"""OTP programming: REFUSAL PATH ONLY. Nothing here (or anywhere in this tool) can program OTP."""
import contextlib
import datetime
import io
import json
import os
import stat
import tempfile
import unittest

from common import load_cli, Quiet
from hqprov import otp


def approval(d, **over):
    a = {"approved_by": "ops lead", "approval_ref": "CHG-1", "approved_at": "2026-11-10T00:00:00Z",
         "valid_until": "2099-01-01T00:00:00Z"}
    a.update(over)
    p = os.path.join(d, "approval.json")
    json.dump(a, open(p, "w"))
    os.chmod(p, 0o600)
    return p


class OtpRefusalTest(Quiet):
    def test_refuses_without_flag(self):
        with tempfile.TemporaryDirectory() as d:
            with self.assertRaises(otp.OtpRefused) as cm:
                otp.program(False, approval(d))
            self.assertIn("irreversible", str(cm.exception))

    def test_refuses_without_approval_file(self):
        with self.assertRaises(otp.OtpRefused):
            otp.program(True, None)
        with self.assertRaises(otp.OtpRefused):
            otp.program(True, "/nonexistent/approval.json")

    def test_refuses_bad_approvals(self):
        with tempfile.TemporaryDirectory() as d:
            for over in ({"approved_by": ""}, {"approval_ref": 5}, {"valid_until": "2001-01-01T00:00:00Z"},
                         {"valid_until": "not a date"}):
                with self.assertRaises(otp.OtpRefused, msg=str(over)):
                    otp.program(True, approval(d, **over))
            p = approval(d)
            os.chmod(p, 0o666)
            with self.assertRaises(otp.OtpRefused):
                otp.program(True, p)
            open(p, "w").write("[1]")
            os.chmod(p, 0o600)
            with self.assertRaises(otp.OtpRefused):
                otp.program(True, p)

    def test_even_with_both_gates_nothing_is_programmed(self):
        with tempfile.TemporaryDirectory() as d:
            with self.assertRaises(otp.OtpBackendNotWired):
                otp.program(True, approval(d))

    def test_cli_exit_codes_and_no_flag_on_run(self):
        cli = load_cli()
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            self.assertEqual(cli.main(["otp"]), 3)
        self.assertIn("refused", err.getvalue())
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            cli.main(["run", "--image", "x", "--out", "y", "--ca-dir", "z", otp.FLAG])   # run has no such flag


if __name__ == "__main__":
    unittest.main()
