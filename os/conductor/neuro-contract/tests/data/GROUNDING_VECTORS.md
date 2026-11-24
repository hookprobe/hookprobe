# Grounding vectors: how `grounding_vectors.rs` was made

`grounding_vectors.rs` holds the outputs of Neuro's own functions on 1,518 cases (18 hand-written edge cases plus
1,500 random ones, seed 20261124):
- `tools/neuro-research/guard_ground.py` `apply`;
- `tools/neuro-research/eval/grounding.py` `technique_check` and `service_check`.

`tests/grounding.rs` checks `neuro_contract::grounding` against them. Nothing in `os/conductor` runs Python: the
generator below ran once on the build host, from the repository root, and is kept here as documentation only.

**One deliberate difference from Neuro's code.** `_strip` orders equal-length tokens with
`sorted(set(bad), key=len, reverse=True)`, so ties come out in set order. That order changes with
`PYTHONHASHSEED`, and the output changes with it (for example `"T1[T9]http"` keeps or loses `T1`). The device breaks
ties lexicographically. The generator applies exactly that one change to Neuro's function, and the same one-line
fix is proposed to Neuro (`os/conductor/NEURO_ALIGNMENT.md`). The output was checked to be identical under two
different hash seeds.

To regenerate:
1. Save the script below as `gen_vectors.py` outside the repository.
2. Run `python3 -I gen_vectors.py <repo root> <out.txt>`.
3. Convert the lines to the `VECTORS` constant (tab-separated hex fields, one case per line).

```python
# Generates neuro-contract/tests/data/grounding_vectors.txt from Neuro's own functions (guard_ground.apply,
# grounding.technique_check, grounding.service_check). Run: python3 -I gen_vectors.py <repo root> <out>
import sys, os, random, re
root = sys.argv[1]
sys.path.insert(0, os.path.join(root, "tools/neuro-research/eval")); sys.path.insert(0, os.path.join(root, "tools/neuro-research"))
import grounding, guard_ground, inspect
# Neuro's _strip orders equal-length tokens by set iteration order, which depends on PYTHONHASHSEED (the output
# changes between runs). The device fixes the tie-break lexicographically; this applies exactly that one change.
_src = inspect.getsource(guard_ground._strip)
assert "sorted(set(bad), key=len, reverse=True)" in _src
exec(_src.replace("sorted(set(bad), key=len, reverse=True)", "sorted(set(bad), key=lambda s: (-len(s), s))"), guard_ground.__dict__)
CVE = guard_ground.CVE
fixed = [
 ("Lateral movement via SMB (T1021.002) and scanning (T1046).", "F1 det=lateral_smb[H1,sev3] :445"),
 ("Uses 'T12' and \"T99999\" techniques (T1059.999) [T1].", "F1 :22"),
 ("Exploit CVE-2024-3400 and CVE-2023-12345 seen.", "F2 RESULT lookup_exposure R1: CVE-2024-3400"),
 ("cve-2024-3400 lowercase, CVE-2021-44228 not returned.", "RESULT lookup_exposure: CVE-2024-3400"),
 ("Technique T1059.001.5 and T1059.0012 and xT1059 and T1059x.", ""),
 ("SSH brute force on :22 and NTP traffic.", "F1 det=brute_force[H1] R1:22 tcp"),
 ("DNS tunnelling and HTTP beacons, MQTT and telnet.", "F1 R2:1883,8883 F3 :8000-8090"),
 ("RDP and SMB and FTP and SNMP and SSDP/UPnP.", "F1 :3389 :139,445 :20-21 :161-162 :1900"),
 ("Range edge (T0000) ( T1 ) [ T2 ] ' T3 '.", " :1-70000 :100-5000"),
 ("   leading and trailing T0 , ; : spaces   ", ""),
 ("Deprecated T1002 and revoked ids.", ""),
 ("Nested ((T9999)) and [[T8888]] and (T7777].", ""),
 ("Quoted 'CVE-2020-1234567' and CVE-2020-12345678.", ""),
 ("The dns resolver and DNS logs.", "F1 uses dns over udp"),
 ("telnet on 2323 only https", "F1 :2323 :443"),
 ("Tab\tseparated\t\tT0\t\twords .", ""),
 ("Mixed T1071 (T1071) [T1071] 'T1071'.", ""),
 ("Port list :22, and :80,,", "R1:22, R2:80,,443"),
]
frag = ["T1059", "T1059.001", "T12", "T99999", "T1", "T0001", "T1059.999", "(T1046)", "[T9]", "'T8'", "\"T7\"",
        "CVE-2024-3400", "CVE-2021-44228", "cve-2019-0708", "CVE-2020-1234567", " ", "  ", "\t", ",", ".", ";", ":",
        "(", ")", "[", "]", "'", "\"", "ssh", "SSH", "ntp", "dns", "http", "https", "smb", "rdp", "telnet", "mqtt",
        "upnp", "ssdp", "ftp", "snmp", "smtp", "x", "T", "-", "word", "Port 22", "T1071.001", "T1002", "T1021"]
cfrag = [" :22", " :80,443", " :8000-8090", " :1-5000", " R1:1883", " dns ", " ssh", " CVE-2024-3400", " cve-2021-44228",
         " F1", " det=port_scan[H1]", " :445,", " :3389-3390", " :123", " :20,21-25", ""]
rng = random.Random(20261124)
cases = list(fixed)
for _ in range(1500):
    t = "".join(rng.choice(frag) + (" " if rng.random() < 0.5 else "") for _ in range(rng.randint(1, 14)))
    c = "".join(rng.choice(cfrag) for _ in range(rng.randint(0, 5)))
    cases.append((t, c))
out = open(sys.argv[2], "w", encoding="utf-8")
src = open(__file__, encoding="utf-8").read()
for l in src.splitlines():
    out.write("# " + l + "\n")
for t, c in cases:
    o = guard_ground.apply({"context": c}, {"summary": t})
    g = o["summary"]
    tc = grounding.technique_check(g, c)
    st = sum(1 for x in tc["ids"] if x in tc["stale"])
    # counts over the FILTERED text, as the verifier sees it, plus over the raw text
    tr = grounding.technique_check(t, c)
    raw_cve = sum(1 for x in CVE.findall(t) if x.upper() not in c.upper())
    sv = len(grounding.service_check(t, c)["absent"])
    rem = len(o.get("_guard_g", []))
    out.write("\t".join([t.encode().hex(), c.encode().hex(), g.encode().hex(), str(rem), str(len(tr["unknown"])), str(len(tr["stale"])), str(raw_cve), str(sv), str(len(tc["unknown"]))]) + "\n")
```
