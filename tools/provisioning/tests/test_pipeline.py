"""End-to-end station flow replayed from recorded serial logs (no hardware, no flasher, no relay)."""
import contextlib
import io
import json
import os
import shutil
import stat
import subprocess
import tempfile
import unittest

from common import MAC, PSK, QR, SSID, UNIT, fixture, load_cli, make_image, Quiet
from hqprov import owner, pipeline

HAVE_OPENSSL = shutil.which("openssl") is not None


def quiet(fn, *a):
    with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
        return fn(*a)


class Station(Quiet):
    def setUp(self):
        super().setUp()
        self.tmp = tempfile.TemporaryDirectory()
        self.d = self.tmp.name
        self.cli = load_cli()
        self.img = make_image(self.d)
        self.target = os.path.join(self.d, "emmc.img")          # stands in for the rpiboot-exposed eMMC
        shutil.copy(self.img, self.target)
        self.out = os.path.join(self.d, "out")
        self.unit_dir = os.path.join(self.out, UNIT)

    def tearDown(self):
        self.tmp.cleanup()

    def args(self, *extra, boot1=True, boot2=True):
        a = ["run", "--image", self.img, "--out", self.out, "--skip-flash", "--ca-dir", os.path.join(self.d, "ca"),
             "--patch-target", self.target, "--operator", "tester", "--model", "HookProbe test"]
        if boot1:
            a += ["--serial-log", fixture("boot1.log")]
        if boot2:
            a += ["--verify-serial-log", fixture("boot2.log")]
        return a + list(extra)

    def read_target(self, off, n):
        with open(self.target, "rb") as f:
            f.seek(off)
            return f.read(n)

    def run_ok(self, *extra, **kw):
        return quiet(self.cli.main, self.args(*extra, **kw))

    # ------------------------------------------------------------------------------------------
    @unittest.skipUnless(HAVE_OPENSSL, "openssl CLI needed for the MC TLS step")
    def test_full_flow_outputs(self):
        self.assertEqual(self.run_ok(), 0)
        names = set(os.listdir(self.unit_dir))
        for n in ("state.json", "identity.json", "secrets.json", "label.svg", "owner-card.svg", "MCTLS.CRT",
                  "record.json", "selftest.json", "provision.log", "boot-1.redacted.log", "boot-2.redacted.log"):
            self.assertIn(n, names)
        rec = json.load(open(os.path.join(self.unit_dir, "record.json")))
        self.assertTrue(rec["shippable"])
        self.assertEqual(rec["unit_id"], UNIT)
        self.assertEqual(rec["identity"]["wifi_mac"], MAC)
        self.assertEqual(rec["identity"]["setup_ssid"], SSID)
        self.assertIn("tool_git_commit", rec)
        self.assertEqual(len(rec["image"]["sha256"]), 64)
        self.assertEqual(rec["operator"], "tester")
        sec = json.load(open(os.path.join(self.unit_dir, "secrets.json")))
        self.assertEqual(sec["setup_psk"], PSK)
        self.assertRegex(sec["owner_token"], owner.TOKEN_RE)
        # the unit's eMMC got a claimed OWNER.TXT matching the minted token + the certificate
        ob = self.read_target(0x1000, 128)
        self.assertTrue(owner.token_matches(ob, sec["owner_token"]))
        self.assertEqual(self.read_target(0x2000, 6), b"HQCRT1")
        self.assertEqual(self.read_target(0, 16), b"\0" * 16)    # nothing else touched
        # label carries the wifi QR and passphrase
        lab = open(os.path.join(self.unit_dir, "label.svg")).read()
        self.assertIn(PSK, lab)
        self.assertIn(SSID, lab)

    @unittest.skipUnless(HAVE_OPENSSL, "openssl CLI needed")
    def test_secrets_absent_from_general_outputs(self):
        self.assertEqual(self.run_ok(), 0)
        sec = json.load(open(os.path.join(self.unit_dir, "secrets.json")))
        needles = [PSK, QR, sec["owner_token"], sec["owner_file_hex"]]
        allowed = {"secrets.json", "label.svg", "label.png", "owner-card.svg", "owner-card.png"}
        checked = 0
        for root, _dirs, files in os.walk(self.out):
            for f in files:
                if f in allowed:
                    st = os.stat(os.path.join(root, f))
                    self.assertEqual(stat.S_IMODE(st.st_mode), 0o600, f)       # secret-bearing files are 0600
                    continue
                data = open(os.path.join(root, f), "rb").read()
                for n in needles:
                    self.assertNotIn(n.encode(), data, f"secret leaked into {f}")
                checked += 1
        self.assertGreater(checked, 6)
        # the redacted boot log kept its structure
        redacted = open(os.path.join(self.unit_dir, "boot-1.redacted.log")).read()
        self.assertIn("<redacted>", redacted)
        self.assertIn("per-device MAC " + MAC, redacted)

    @unittest.skipUnless(HAVE_OPENSSL, "openssl CLI needed")
    def test_stdout_never_shows_secrets(self):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            self.cli.main(self.args())
        sec = json.load(open(os.path.join(self.unit_dir, "secrets.json")))
        for n in (PSK, sec["owner_token"]):
            self.assertNotIn(n, out.getvalue() + err.getvalue())

    @unittest.skipUnless(HAVE_OPENSSL, "openssl CLI needed")
    def test_resume_and_idempotence(self):
        # interrupted: boot 2 is unavailable (no console, no log) -> fails after the patch, work dir kept
        self.assertEqual(self.run_ok(boot2=False), 2)
        st = json.load(open(os.path.join(self.unit_dir, "state.json")))["steps"]
        self.assertEqual(st["patch"]["status"], "ok")
        self.assertNotIn("capture2", st)
        sec1 = open(os.path.join(self.unit_dir, "secrets.json")).read()
        patched = self.read_target(0x1000, 128)
        # resume: no boot-1 log needed, owner key is NOT re-minted, patch is not repeated
        a = ["run", "--image", self.img, "--out", self.out, "--ca-dir", os.path.join(self.d, "ca"),
             "--patch-target", self.target, "--resume-unit", UNIT, "--verify-serial-log", fixture("boot2.log")]
        self.assertEqual(quiet(self.cli.main, a), 0)
        self.assertEqual(open(os.path.join(self.unit_dir, "secrets.json")).read(), sec1)
        self.assertEqual(self.read_target(0x1000, 128), patched)
        # a third run (everything done) is a no-op that still reports shippable and does not change secrets
        self.assertEqual(quiet(self.cli.main, a), 0)
        self.assertEqual(open(os.path.join(self.unit_dir, "secrets.json")).read(), sec1)

    @unittest.skipUnless(HAVE_OPENSSL, "openssl CLI needed")
    def test_reprovision_after_reflash_starts_clean(self):
        self.assertEqual(self.run_ok(), 0)
        tok1 = json.load(open(os.path.join(self.unit_dir, "secrets.json")))["owner_token"]
        shutil.copy(self.img, self.target)                    # "re-flash": unclaimed placeholder again
        self.assertEqual(self.run_ok(), 0)
        tok2 = json.load(open(os.path.join(self.unit_dir, "secrets.json")))["owner_token"]
        self.assertNotEqual(tok1, tok2)                       # a fresh claim, not a skipped patch
        self.assertTrue(owner.token_matches(self.read_target(0x1000, 128), tok2))
        prev = [d for d in os.listdir(self.out) if d.startswith(UNIT + ".prev-")]
        self.assertEqual(len(prev), 1)

    @unittest.skipUnless(HAVE_OPENSSL, "openssl CLI needed")
    def test_record_signature_verifies(self):
        key = os.path.join(self.d, "k.pem")
        subprocess.run(["openssl", "genpkey", "-algorithm", "ed25519", "-out", key], check=True, capture_output=True)
        pub = os.path.join(self.d, "k.pub")
        subprocess.run(["openssl", "pkey", "-in", key, "-pubout", "-out", pub], check=True, capture_output=True)
        self.assertEqual(self.run_ok("--sign-key", key), 0)
        rec = os.path.join(self.unit_dir, "record.json")
        r = subprocess.run(["openssl", "pkeyutl", "-verify", "-pubin", "-inkey", pub, "-rawin", "-in", rec,
                            "-sigfile", rec + ".sig"], capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr)

    def test_patch_is_idempotent_and_refuses_foreign_claim(self):
        m = owner.load_manifest(self.img + ".json")
        ob = owner.owner_file_bytes("AAAA-BBBB-CCCC-DDDD-EEEE-FFFF")
        mb = b"HQCRT1\0\0".ljust(4096, b"\0")
        self.assertEqual(owner.patch_boot_files(self.target, m, ob, mb), {"owner": "written", "mctls": "written"})
        self.assertEqual(owner.patch_boot_files(self.target, m, ob, mb), {"owner": "already-set", "mctls": "already-set"})
        other = owner.owner_file_bytes("GGGG-HHHH-JJJJ-KKKK-LLLL-MMMM")
        with self.assertRaises(owner.PatchError):
            owner.patch_boot_files(self.target, m, other, mb)
        self.assertEqual(self.read_target(0x1000, 128), ob)           # the existing claim was not overwritten

    def test_patch_refuses_host_block_device_and_odd_files(self):
        m = owner.load_manifest(self.img + ".json")
        with self.assertRaises(owner.PatchError):
            owner.check_target("/dev/null")                            # char device
        if os.path.exists("/dev/loop0"):
            with self.assertRaises(owner.PatchError):
                owner.check_target("/dev/loop0")                       # any non-rpiboot block device
        with self.assertRaises(owner.PatchError):
            owner.patch_boot_files(self.target, m, b"short", b"HQCRT1" * 683)

    def test_no_srk_unit_fails_closed(self):
        a = self.args(boot1=False) + ["--serial-log", fixture("boot_nosrk.log"), "--skip-tls"]
        self.assertEqual(quiet(self.cli.main, a), 2)
        self.assertFalse(os.path.exists(self.unit_dir))                # no unit dir, no secrets, nothing to ship

    def test_wifitxt_image_rejected(self):
        a = self.args(boot1=False) + ["--serial-log", fixture("boot_wifitxt.log"), "--skip-tls"]
        self.assertEqual(quiet(self.cli.main, a), 2)

    def test_missing_openssl_is_a_clear_error(self):
        import hqprov.pipeline as p
        real = shutil.which
        p.shutil.which = lambda n, *a, **k: None if n == "openssl" else real(n, *a, **k)
        try:
            err = io.StringIO()
            with contextlib.redirect_stderr(err), contextlib.redirect_stdout(io.StringIO()):
                rc = self.cli.main(self.args())
            self.assertEqual(rc, 2)
            self.assertIn("openssl", err.getvalue())
        finally:
            p.shutil.which = real

    @unittest.skipUnless(HAVE_OPENSSL, "openssl CLI needed")
    def test_selftest_detects_a_changed_credential(self):
        bad = os.path.join(self.d, "boot2-changed.log")
        open(bad, "w").write(open(fixture("boot2.log"), newline="").read().replace(PSK, "zzzz-zzzz-zzzz-zzzz"))
        a = self.args(boot2=False) + ["--verify-serial-log", bad]
        self.assertEqual(quiet(self.cli.main, a), 1)
        res = json.load(open(os.path.join(self.unit_dir, "selftest.json")))
        failed = [r["name"] for r in res["results"] if not r["ok"]]
        self.assertIn("setup credential identical across reboot", failed)
        rec = json.load(open(os.path.join(self.unit_dir, "record.json")))
        self.assertFalse(rec["shippable"])

    @unittest.skipUnless(HAVE_OPENSSL, "openssl CLI needed")
    def test_delete_input_logs(self):
        b1 = os.path.join(self.d, "b1.log")
        b2 = os.path.join(self.d, "b2.log")
        shutil.copy(fixture("boot1.log"), b1)
        shutil.copy(fixture("boot2.log"), b2)
        a = self.args(boot1=False, boot2=False) + ["--serial-log", b1, "--verify-serial-log", b2, "--delete-input-logs"]
        self.assertEqual(quiet(self.cli.main, a), 0)
        self.assertFalse(os.path.exists(b1) or os.path.exists(b2))

    # ------------------------------------------------------------------------------------------
    @unittest.skipUnless(HAVE_OPENSSL, "openssl CLI needed")
    def test_reset_verify(self):
        self.assertEqual(self.run_ok(), 0)
        # a second, different unit in the work area (to prove uniqueness is checked)
        other = os.path.join(self.out, "02aaaaaaaaaa")
        os.makedirs(other)
        json.dump({"setup_psk": "aaaa-aaaa-aaaa-aaaa"}, open(os.path.join(other, "secrets.json"), "w"))
        r = ["reset-verify", "--out", self.out, "--resume-unit", UNIT, "--verify-serial-log", fixture("boot_reset.log")]
        self.assertEqual(quiet(self.cli.main, r), 0)
        res = json.load(open(os.path.join(self.unit_dir, "reset-verify.json")))
        self.assertTrue(res["ok"])
        self.assertEqual(res["owner_state"], "UNCLAIMED")
        # a different credential after "reset" (e.g. a random/universal one) must fail
        r2 = ["reset-verify", "--out", self.out, "--resume-unit", UNIT,
              "--verify-serial-log", fixture("boot_reset_changed.log")]
        self.assertEqual(quiet(self.cli.main, r2), 1)
        # the reset check never writes the passphrase anywhere general either
        for f in ("reset-verify.json", "boot-reset.redacted.log", "provision.log"):
            self.assertNotIn(PSK.encode(), open(os.path.join(self.unit_dir, f), "rb").read(), f)

    @unittest.skipUnless(HAVE_OPENSSL, "openssl CLI needed")
    def test_reset_verify_flags_shared_passphrase(self):
        self.assertEqual(self.run_ok(), 0)
        other = os.path.join(self.out, "02bbbbbbbbbb")
        os.makedirs(other)
        json.dump({"setup_psk": PSK}, open(os.path.join(other, "secrets.json"), "w"))     # same label value elsewhere
        r = ["reset-verify", "--out", self.out, "--resume-unit", UNIT, "--verify-serial-log", fixture("boot_reset.log")]
        self.assertEqual(quiet(self.cli.main, r), 1)


if __name__ == "__main__":
    unittest.main()
