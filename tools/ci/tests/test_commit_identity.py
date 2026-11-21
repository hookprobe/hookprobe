#!/usr/bin/env python3
"""tools/ci/commit_identity.py — commit identities expose no personal or contact email."""
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import commit_identity as c  # noqa: E402

H = "3350272+homepods@users.noreply.github.com"
T = "355515004+hookprobes@users.noreply.github.com"


def rec(ae=H, ce=H, body="subject\n"):
    return ("a" * 40, "n", ae, "n", ce, body)


class Identity(unittest.TestCase):
    def test_noreply_identities_pass(self):
        self.assertEqual(c.problems([rec(), rec(ae=T, ce="noreply@github.com"),
                                     rec(ae="49699333+dependabot[bot]@users.noreply.github.com"),
                                     rec(ae="homepods@users.noreply.github.com")]), [])

    def test_contact_email_as_author_or_committer_fails(self):
        self.assertEqual(len(c.problems([rec(ae="qsecbit@hookprobe.com")])), 1)       # the 2026-11-21 leak
        self.assertEqual(len(c.problems([rec(ce="hookprobe@hookprobe.com")])), 1)
        self.assertEqual(len(c.problems([rec(ae="someone@gmail.com", ce="someone@gmail.com")])), 2)

    def test_coauthor_trailers(self):
        leak = rec(body="subject\n\nCo-authored-by: homepods <qsecbit@hookprobe.com>\n")
        self.assertEqual(len(c.problems([leak])), 1)
        role = rec(body="subject\n\nCo-authored-by: Claude Opus 5.5 <noreply@anthropic.com>\n")
        self.assertEqual(c.problems([role]), [])          # a role noreply exposes nobody
        mention = rec(body="docs: the security contact is qsecbit@hookprobe.com\n")
        self.assertEqual(c.problems([mention]), [])       # the contact address in prose is not an identity

    def test_lookalike_domain_rejected(self):
        self.assertEqual(len(c.problems([rec(ae="x@users.noreply.github.com.evil.example")])), 1)


if __name__ == "__main__":
    unittest.main()
