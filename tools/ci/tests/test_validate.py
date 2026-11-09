"""Regression tests for the heqk validation script's build-failure reporting."""
import os
import subprocess
import tempfile
import unittest

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))


class ValidateBuildDiagnostics(unittest.TestCase):
    def test_build_failure_includes_nested_cargo_output(self):
        with tempfile.TemporaryDirectory() as td:
            bindir = os.path.join(td, "bin")
            os.makedirs(bindir)
            cargo = os.path.join(bindir, "cargo")
            with open(cargo, "w") as f:
                f.write("#!/bin/sh\nprintf '%s\\n' 'error: nested build diagnostic' >&2\nexit 101\n")
            os.chmod(cargo, 0o755)
            flock = os.path.join(bindir, "flock")
            with open(flock, "w") as f:
                f.write("#!/bin/sh\nexit 0\n")
            os.chmod(flock, 0o755)

            env = os.environ.copy()
            env["HOME"] = td
            env["PATH"] = bindir + os.pathsep + env["PATH"]
            env["CARGO_TARGET_DIR"] = os.path.join(td, "target")
            result = subprocess.run(
                ["bash", os.path.join(ROOT, "os", "kernel", "validate.sh")],
                cwd=os.path.join(ROOT, "os", "kernel"),
                env=env,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                check=False,
            )

        self.assertEqual(result.returncode, 2)
        self.assertIn("error: nested build diagnostic", result.stdout)
        self.assertIn("GAP: build broken", result.stdout)


if __name__ == "__main__":
    unittest.main()
