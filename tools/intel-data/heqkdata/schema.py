# SPDX-License-Identifier: AGPL-3.0-only
"""A small, strict JSON Schema (2020-12 subset) validator — stdlib only.

Supported keywords: type, enum, const, properties, required, additionalProperties (bool or schema),
items, minItems, maxItems, uniqueItems, minLength, maxLength, pattern, minimum, maximum, format,
$ref (local '#/$defs/x' and sibling files 'name.schema.json#/…'), allOf, anyOf, oneOf, if/then/else.
An unsupported keyword in a schema is an ERROR (fail closed), so a schema can never silently assert
more than this validator checks. Annotation keywords ($schema, $id, title, description, $defs,
default, examples, $comment) are ignored.

Formats: uri (scheme + netloc), ip-canonical, domain-canonical (both from canon.py: the value must
already be in canonical form).
"""
import json
import os
import re
from urllib.parse import urlparse

from . import SCHEMA_DIR
from . import canon

ANNOTATIONS = {"$schema", "$id", "title", "description", "$defs", "default", "examples", "$comment"}
SUPPORTED = {
    "type", "enum", "const", "properties", "required", "additionalProperties", "items", "minItems", "maxItems",
    "uniqueItems", "minLength", "maxLength", "pattern", "minimum", "maximum", "format", "$ref", "allOf", "anyOf",
    "oneOf", "if", "then", "else",
} | ANNOTATIONS

_TYPES = {
    "object": lambda v: isinstance(v, dict),
    "array": lambda v: isinstance(v, list),
    "string": lambda v: isinstance(v, str),
    "integer": lambda v: isinstance(v, int) and not isinstance(v, bool),
    "number": lambda v: isinstance(v, (int, float)) and not isinstance(v, bool),
    "boolean": lambda v: isinstance(v, bool),
    "null": lambda v: v is None,
}


class SchemaError(Exception):
    """The schema itself is malformed or uses an unsupported keyword."""


def _check_uri(v):
    p = urlparse(v)
    return p.scheme in ("http", "https") and bool(p.netloc)


FORMATS = {
    "uri": _check_uri,
    "ip-canonical": lambda v: canon.ip(v) == v,
    "domain-canonical": lambda v: canon.domain(v) == v,
}


class Validator:
    def __init__(self, schema_dir=SCHEMA_DIR):
        self.schema_dir = schema_dir
        self._docs = {}
        self._re = {}

    def load(self, name):
        if name not in self._docs:
            path = os.path.join(self.schema_dir, name)
            with open(path, "r", encoding="utf-8") as f:
                self._docs[name] = json.load(f)
        return self._docs[name]

    def _resolve(self, ref, doc_name):
        file_part, _, frag = ref.partition("#")
        name = file_part or doc_name
        node = self.load(name)
        if frag:
            for tok in frag.lstrip("/").split("/"):
                tok = tok.replace("~1", "/").replace("~0", "~")
                if not isinstance(node, dict) or tok not in node:
                    raise SchemaError(f"unresolvable $ref {ref!r} in {doc_name}")
                node = node[tok]
        return node, name

    def errors(self, instance, name):
        """All validation errors of `instance` against schema file `name` (empty list = valid)."""
        out = []
        self._v(instance, self.load(name), name, "$", out)
        return out

    def is_valid(self, instance, name):
        return not self.errors(instance, name)

    def _v(self, x, s, doc, path, out):
        if s is True or s == {}:
            return
        if s is False:
            out.append(f"{path}: no value allowed")
            return
        unknown = set(s) - SUPPORTED
        if unknown:
            raise SchemaError(f"{doc}: unsupported keyword(s) {sorted(unknown)} at {path}")
        if "$ref" in s:
            target, tdoc = self._resolve(s["$ref"], doc)
            self._v(x, target, tdoc, path, out)
        if "type" in s:
            ts = s["type"] if isinstance(s["type"], list) else [s["type"]]
            if not any(_TYPES[t](x) for t in ts):
                out.append(f"{path}: expected {'/'.join(ts)}, got {type(x).__name__}")
                return
        if "const" in s and x != s["const"]:
            out.append(f"{path}: must equal {s['const']!r}")
        if "enum" in s and x not in s["enum"]:
            out.append(f"{path}: {x!r} not in {s['enum']}")
        if isinstance(x, str):
            if "minLength" in s and len(x) < s["minLength"]:
                out.append(f"{path}: shorter than {s['minLength']}")
            if "maxLength" in s and len(x) > s["maxLength"]:
                out.append(f"{path}: longer than {s['maxLength']}")
            if "pattern" in s:
                rx = self._re.get(s["pattern"]) or self._re.setdefault(s["pattern"], re.compile(s["pattern"]))
                if not rx.search(x):
                    out.append(f"{path}: {x[:80]!r} does not match {s['pattern']}")
            if "format" in s:
                fn = FORMATS.get(s["format"])
                if fn is None:
                    raise SchemaError(f"{doc}: unsupported format {s['format']!r}")
                if not fn(x):
                    out.append(f"{path}: {x[:80]!r} is not a valid {s['format']}")
        if isinstance(x, (int, float)) and not isinstance(x, bool):
            if "minimum" in s and x < s["minimum"]:
                out.append(f"{path}: {x} < minimum {s['minimum']}")
            if "maximum" in s and x > s["maximum"]:
                out.append(f"{path}: {x} > maximum {s['maximum']}")
        if isinstance(x, list):
            if "minItems" in s and len(x) < s["minItems"]:
                out.append(f"{path}: fewer than {s['minItems']} items")
            if "maxItems" in s and len(x) > s["maxItems"]:
                out.append(f"{path}: more than {s['maxItems']} items")
            if s.get("uniqueItems"):
                seen = set()
                for item in x:
                    k = json.dumps(item, sort_keys=True)
                    if k in seen:
                        out.append(f"{path}: duplicate item {item!r}")
                        break
                    seen.add(k)
            if "items" in s:
                for i, item in enumerate(x):
                    self._v(item, s["items"], doc, f"{path}[{i}]", out)
        if isinstance(x, dict):
            for r in s.get("required", []):
                if r not in x:
                    out.append(f"{path}: missing required field {r!r}")
            props = s.get("properties", {})
            for k, v in x.items():
                if k in props:
                    self._v(v, props[k], doc, f"{path}.{k}", out)
                elif "additionalProperties" in s:
                    ap = s["additionalProperties"]
                    if ap is False:
                        out.append(f"{path}: unexpected field {k!r}")
                    elif isinstance(ap, dict):
                        self._v(v, ap, doc, f"{path}.{k}", out)
        for sub in s.get("allOf", []):
            self._v(x, sub, doc, path, out)
        if "anyOf" in s:
            if not any(self._ok(x, sub, doc) for sub in s["anyOf"]):
                # report the closest branch's errors to keep messages useful
                best = min((self._errs(x, sub, doc, path) for sub in s["anyOf"]), key=len)
                out.append(f"{path}: matches no anyOf branch ({'; '.join(best[:3])})")
        if "oneOf" in s:
            n = sum(self._ok(x, sub, doc) for sub in s["oneOf"])
            if n != 1:
                out.append(f"{path}: matches {n} oneOf branches, need exactly 1")
        if "if" in s:
            if self._ok(x, s["if"], doc):
                if "then" in s:
                    self._v(x, s["then"], doc, path, out)
            elif "else" in s:
                self._v(x, s["else"], doc, path, out)

    def _errs(self, x, s, doc, path):
        e = []
        self._v(x, s, doc, path, e)
        return e

    def _ok(self, x, s, doc):
        return not self._errs(x, s, doc, "$")


_DEFAULT = None


def default():
    global _DEFAULT
    if _DEFAULT is None:
        _DEFAULT = Validator()
    return _DEFAULT


def check_schema_files(schema_dir=SCHEMA_DIR):
    """Walk every schema file and make sure each keyword is supported and every $ref resolves."""
    v = Validator(schema_dir)
    problems = []

    def walk(node, doc, path):
        if isinstance(node, dict):
            if "$ref" in node:
                try:
                    v._resolve(node["$ref"], doc)
                except (SchemaError, OSError) as e:
                    problems.append(f"{doc} {path}: {e}")
            looks_like_schema = any(k in node for k in ("type", "$ref", "properties", "anyOf", "allOf", "const", "enum"))
            if looks_like_schema:
                bad = set(node) - SUPPORTED
                if bad:
                    problems.append(f"{doc} {path}: unsupported keyword(s) {sorted(bad)}")
            for k, val in node.items():
                if k in ("properties", "$defs"):
                    for pk, pv in val.items():
                        walk(pv, doc, f"{path}/{k}/{pk}")
                elif k in ("enum", "const", "required", "examples", "default"):
                    continue
                else:
                    walk(val, doc, f"{path}/{k}")
        elif isinstance(node, list):
            for i, item in enumerate(node):
                walk(item, doc, f"{path}/{i}")

    for name in sorted(os.listdir(schema_dir)):
        if name.endswith(".schema.json"):
            walk(v.load(name), name, "#")
    return problems
