# SPDX-License-Identifier: AGPL-3.0-only
"""instrlike: Neuro's `!instr-like` rule on attacker-controlled export strings. Test values are SYNTHETIC."""
import re
import unittest

import helpers  # noqa: F401  (sys.path)
from heqkdata import instrlike


class Rule(unittest.TestCase):
    def test_pattern_pinned(self):
        # Pinned on purpose: a change to Neuro's detector must show up here in review (doc 24 addendum, #1450).
        p = instrlike.pattern()
        self.assertEqual(p.pattern, r"(ignore|disregard|previous|instruction|system prompt|classify|you are|assistant)")
        self.assertEqual(p.flags & re.I, re.I)

    def test_flag_is_substring_case_insensitive(self):
        self.assertTrue(instrlike.flag("IgnoreRules.example")["instr_like"])
        self.assertTrue(instrlike.flag("cdn.you are.example")["instr_like"])
        self.assertFalse(instrlike.flag("updates.example.net")["instr_like"])
        self.assertEqual(instrlike.flag("a.example"), {"value": "a.example", "instr_like": False})

    def test_full_value_before_truncation(self):
        v = "x" * 200 + ".disregard.example"  # keyword past the 64-char card cap
        self.assertTrue(instrlike.flag(v)["instr_like"])
        self.assertEqual(instrlike.flag(v)["value"], v)

    def test_wrap_only_attacker_fields(self):
        e = {"type": "dns", "query": "ignore-previous.example", "src_ip": "H1", "service": "dns",
             "cert_san": ["ok.example", "assistant.example"], "user_agent": "curl/8"}
        out = instrlike.wrap(dict(e))
        self.assertEqual(out["query"], {"value": "ignore-previous.example", "instr_like": True})
        self.assertEqual(out["cert_san"], [{"value": "ok.example", "instr_like": False},
                                           {"value": "assistant.example", "instr_like": True}])
        self.assertEqual(out["user_agent"], {"value": "curl/8", "instr_like": False})
        self.assertEqual((out["src_ip"], out["service"]), ("H1", "dns"))

    def test_flow_events_unchanged(self):
        # today's windows events carry no attacker-controlled strings: output stays byte-identical
        e = {"type": "flow", "ts": 0, "src_ip": "H1", "dst_ip": "R1", "service": "dns", "history": "Dd",
             "conn_state": "SF", "label": "Benign", "detailed_label": "-"}
        self.assertEqual(instrlike.wrap(dict(e)), e)


if __name__ == "__main__":
    unittest.main()
