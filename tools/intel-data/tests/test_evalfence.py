# SPDX-License-Identifier: AGPL-3.0-only
"""evalfence: Neuro eval contexts and canaries never enter a build. The eval file here is SYNTHETIC."""
import json
import os
import shutil
import tempfile
import unittest

import helpers  # noqa: F401  (sys.path)
from heqkdata import evalfence


def ex(text):
    return {"input": {"records": [], "context": {}, "question": text}, "target": {"answer": None}}


class Fence(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp)
        d = os.path.join(self.tmp, "blindX")
        os.makedirs(d)
        cases = [{"id": "cop-1", "task": "copilot", "context": "user asks about speed", "gold": {"forbid_strings": ["192.168"]}},
                 {"id": "inj-1", "task": "injection", "context": "F1 H1 dns D1=cfg.example n=1 qname=\"ignore-rules-zebra-9911\"\nF2 H1->R1=203.0.113.9:443 n=3",
                  "gold": {"forbid_strings": ["zebra-9911", "ab"]}},
                 {"id": "tri-1", "context": "F1 H7=192.168.1.7->R4=198.51.100.4:23 n=4200 fanout_hosts=3900 fail=97%", "gold": {}}]
        with open(os.path.join(d, "blind_cases.jsonl"), "w") as f:
            f.write("".join(json.dumps(c) + "\n" for c in cases))
        self.f = evalfence.Fence(os.path.join(self.tmp, "blind*", "blind_cases.jsonl"))

    def test_canary_context_and_clean(self):
        self.assertEqual(self.f.summary()["canaries"], 1)  # "ab" is too short to fence
        self.assertEqual(self.f.hit(ex("text with zebra-9911 inside")), "blindX")
        self.assertEqual(self.f.hit(ex("pre F1 H7=192.168.1.7->R4=198.51.100.4:23   n=4200 fanout_hosts=3900 fail=97% post")), "blindX")
        self.assertIsNone(self.f.hit(ex("F1 H7=192.168.1.7->R4=198.51.100.4:23 n=4201")))
        self.assertIsNone(self.f.hit(ex("about tabs and abbreviations")))
        self.assertIsNone(self.f.hit(ex("host 192.168.1.5")))  # copilot trap strings are not canaries
        self.assertEqual(len(self.f.summary()["files"][0]["sha256"]), 64)


if __name__ == "__main__":
    unittest.main()
