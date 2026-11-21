# SPDX-License-Identifier: AGPL-3.0-only
"""Eval fence: nothing from Neuro's evaluation sets may enter a build (Neuro session, 2026-11-21).

Loads every tools/neuro-research/eval/blind*/blind_cases.jsonl in the repository (blind, blind2, blind3 ...;
published once spent, still never training data) and reports any build example that contains
  * a canary: an injection case's gold.forbid_strings value (the tokens a model must never echo), or
  * a whole eval context: a case's context text, whitespace-normalised.
Matching examples are excluded from the build and counted per eval set in the manifest. The fenced files
and their SHA-256 are recorded, so a build states which eval sets it was checked against.
"""
import ast
import glob
import hashlib
import json
import os
import re

from . import TOOL_DIR

EVAL_GLOB = os.path.join(os.path.dirname(TOOL_DIR), "neuro-research", "eval", "blind*", "blind_cases.jsonl")
MIN_CANARY = 6  # shorter strings would match ordinary text
PREFIX = 40


def _norm(s):
    return re.sub(r"\s+", " ", s).strip()


class Fence:
    def __init__(self, pattern=EVAL_GLOB):
        self.files, self.canary, self.contexts = [], {}, {}
        for path in sorted(glob.glob(pattern)):
            name = os.path.basename(os.path.dirname(path))
            with open(path, "rb") as f:
                raw = f.read()
            self.files.append({"set": name, "path": os.path.relpath(path, os.path.dirname(os.path.dirname(TOOL_DIR))),
                               "sha256": hashlib.sha256(raw).hexdigest()})
            for line in raw.decode("utf-8").splitlines():
                if not line.strip():
                    continue
                case = json.loads(line)
                gold = case.get("gold")
                if isinstance(gold, str):  # blind v1 stores gold as a Python-literal string
                    try:
                        gold = ast.literal_eval(gold)
                    except (ValueError, SyntaxError):
                        gold = {}
                gold = gold if isinstance(gold, dict) else {}
                # canaries are the injection cases' forbid_strings; other tasks' forbid_strings are
                # hallucination traps ("192.168", "Mbps") that ordinary text contains
                for c in (gold.get("forbid_strings") or []) if case.get("task") == "injection" else []:
                    if isinstance(c, str) and len(c) >= MIN_CANARY:
                        self.canary[c] = name
                ctx = case.get("context")
                if isinstance(ctx, str) and _norm(ctx):
                    self.contexts[_norm(ctx)] = name
        alts = sorted(self.canary, key=len, reverse=True)
        self._re = re.compile("|".join(re.escape(c) for c in alts)) if alts else None
        # contexts: one regex over each context's opening (PREFIX chars), full containment checked on a hit
        self._heads = {}
        for ctx in self.contexts:
            self._heads.setdefault(ctx[:PREFIX], []).append(ctx)
        heads = sorted(self._heads, key=len, reverse=True)
        self._ctx_re = re.compile("|".join(re.escape(h) for h in heads)) if heads else None

    def hit(self, example):
        """The eval set an example collides with, or None."""
        text = json.dumps({"input": example["input"], "target": example["target"]}, ensure_ascii=False)
        if self._re:
            m = self._re.search(text)
            if m:
                return self.canary[m.group(0)]
        if self._ctx_re:
            flat = _norm(text.replace("\\n", "\n"))
            for m in self._ctx_re.finditer(flat):
                for ctx in self._heads[m.group(0)]:
                    if flat.startswith(ctx, m.start()):
                        return self.contexts[ctx]
        return None

    def summary(self):
        return {"files": self.files, "canaries": len(self.canary), "contexts": len(self.contexts)}
