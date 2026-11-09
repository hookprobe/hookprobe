#!/usr/bin/env python3
"""rulepack — compile a readable rule file into heqk's RULES.BIN (parity gap G6).

  rulepack.py compile RULES.TXT RULES.BIN      # then: policy-sign.py sign-rules KEY RULES.BIN GEN RULES.SIG
  rulepack.py dump RULES.BIN                   # list what a pack contains

RULES.TXT, one rule per line (`#` comments):
  rule <id> <template> <arg> [class <c>] [sev <1..7>] name "<text>"
templates (R1 = the tier's header; same RFC 9669 encoding as os/kernel/kernel/src/bpf.rs):
  dport <port>          L4 tier: TCP or UDP destination port ==
  sport <port>          L4 tier: source port ==
  dport-range <a>-<b>   L4 tier: a <= destination port <= b
  tcp-flags <hex>       TCP tier: flags byte == value
classes: signature (may drop — reserve for confirmed-bad), scan_shape, malformed, reputation, spoof,
         behavioral (DEFAULT: observe-only, ADR 0023 — a port is not proof of an attack).
ids: 1000..1999 (the dynamic band; never collide with the built-in catalogue).
The device verifies the pack signature, then runs each program through the same verifier + JIT as the
built-in corpus; a rule that fails is skipped and counted, never armed.
"""
import re
import shlex
import struct
import sys

CLASSES = {"signature": 0, "scan_shape": 1, "malformed": 2, "reputation": 3, "spoof": 4, "behavioral": 5}
TIERS = {"dport": 0, "sport": 0, "dport-range": 0, "tcp-flags": 2}


def insn(op, dst, src, off, imm):
    return (op & 0xff) | ((dst & 0xf) << 8) | ((src & 0xf) << 12) | ((off & 0xffff) << 16) | ((imm & 0xffffffff) << 32)


def port_load(base):  # R2 = big-endian u16 at R1+base
    return [insn(0x71, 2, 1, base, 0), insn(0x67, 2, 0, 0, 8), insn(0x71, 3, 1, base + 1, 0), insn(0x4f, 2, 3, 0, 0)]


def eq_rule(base, value):  # identical to bpf.rs port_block_rule when base == 2
    return port_load(base) + [insn(0x55, 2, 0, 2, value), insn(0xb7, 0, 0, 0, 2), insn(0x95, 0, 0, 0, 0),
                              insn(0xb7, 0, 0, 0, 1), insn(0x95, 0, 0, 0, 0)]


def range_rule(a, b):
    # only verifier-supported jumps (JGT_K 0x25, JGE_K 0x35): if R2 > b -> PASS; if R2 >= a -> DROP; else PASS
    return port_load(2) + [insn(0x25, 2, 0, 1, b), insn(0x35, 2, 0, 2, a), insn(0xb7, 0, 0, 0, 1), insn(0x95, 0, 0, 0, 0),
                           insn(0xb7, 0, 0, 0, 2), insn(0x95, 0, 0, 0, 0)]


def flags_rule(v):  # identical to bpf.rs tcp_flag_eq_rule
    return [insn(0x71, 2, 1, 13, 0), insn(0xb7, 0, 0, 0, 1), insn(0x55, 2, 0, 1, v), insn(0xb7, 0, 0, 0, 2), insn(0x95, 0, 0, 0, 0)]


def program(tmpl, arg):
    if tmpl == "dport":
        return eq_rule(2, port(arg))
    if tmpl == "sport":
        return eq_rule(0, port(arg))
    if tmpl == "dport-range":
        a, b = (port(x) for x in arg.split("-", 1))
        if a > b:
            raise ValueError("range a > b")
        return range_rule(a, b)
    if tmpl == "tcp-flags":
        v = int(arg, 16)
        if not 0 <= v <= 0xff:
            raise ValueError("flags byte")
        return flags_rule(v)
    raise ValueError(f"unknown template {tmpl}")


def port(s):
    v = int(s)
    if not 0 < v < 65536:
        raise ValueError(f"port {s}")
    return v


def compile_rules(text):
    out, seen = [], set()
    for ln, line in enumerate(text.splitlines(), 1):
        line = line.split("#", 1)[0].strip()
        if not line:
            continue
        t = shlex.split(line)
        try:
            if t[0] != "rule":
                raise ValueError("expected 'rule'")
            rid, tmpl, arg = int(t[1]), t[2], t[3]
            if not 1000 <= rid <= 1999 or rid in seen:
                raise ValueError("id must be unique in 1000..1999")
            opts = dict(zip(t[4::2], t[5::2]))
            cls = CLASSES[opts.get("class", "behavioral")]
            sev = int(opts.get("sev", "3"))
            name = opts.get("name", f"rule {rid}")
            if not 1 <= sev <= 7 or not re.fullmatch(r"[ -~]{1,60}", name):
                raise ValueError("sev 1..7, printable name <= 60")
            prog = program(tmpl, arg)
        except (IndexError, KeyError, ValueError) as e:
            sys.exit(f"RULES.TXT line {ln}: {e}")
        seen.add(rid)
        nb = name.encode()
        out.append(struct.pack("<HBBBBH", rid, TIERS[tmpl], cls, sev, len(nb), len(prog)) + nb + b"".join(struct.pack("<Q", i) for i in prog))
    return b"HQRULES1" + struct.pack("<HH", len(out), 0) + b"".join(out)


def dump(blob):
    assert blob[:8] == b"HQRULES1", "not a rule pack"
    n = struct.unpack_from("<H", blob, 8)[0]
    p = 12
    inv = {v: k for k, v in CLASSES.items()}
    for _ in range(n):
        rid, tier, cls, sev, nl, ni = struct.unpack_from("<HBBBBH", blob, p)
        name = blob[p + 8:p + 8 + nl].decode()
        print(f"{rid} tier={tier} class={inv.get(cls, cls)} sev={sev} insns={ni} {name!r}")
        p += 8 + nl + 8 * ni


def main():
    a = sys.argv[1:]
    if a[:1] == ["compile"] and len(a) == 3:
        blob = compile_rules(open(a[1]).read())
        if len(blob) > 65536:
            sys.exit("pack larger than 64 KiB")
        open(a[2], "wb").write(blob)
        print(f"RULES.BIN written ({struct.unpack_from('<H', blob, 8)[0]} rules, {len(blob)} bytes)")
    elif a[:1] == ["dump"] and len(a) == 2:
        dump(open(a[1], "rb").read())
    else:
        sys.exit(__doc__)


if __name__ == "__main__":
    main()
