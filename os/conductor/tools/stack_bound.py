# SPDX-License-Identifier: AGPL-3.0-only
# Static worst-case stack bound for an aarch64 EL0 server: frame sizes from the prologues, call edges from
# bl/b, deepest path from _start. Valid only when the binary has no indirect calls (reported) and no
# register-based sp adjustment (check separately). Usage: llvm-objdump -d --no-show-raw-insn ELF > x.dis;
# python3 -I stack_bound.py x.dis
import re,sys,functools
fn=None; frame={}; calls={}; indirect=0
for line in open(sys.argv[1]):
    m=re.match(r'^([0-9a-f]+) <(.+)>:',line)
    if m: fn=m.group(2); frame[fn]=0; calls[fn]=set(); continue
    if fn is None: continue
    # pre-index pushes: stp x29, x30, [sp, #-N]!  and sub sp, sp, #N
    for mm in re.finditer(r'\[sp, #-(0x[0-9a-f]+|\d+)\]!',line): frame[fn]+=int(mm.group(1),0)
    mm=re.search(r'\bsub\s+sp, sp, #(0x[0-9a-f]+|\d+)(, lsl #12)?',line)
    if mm:
        v=int(mm.group(1),0); v<<=12 if mm.group(2) else 0
        frame[fn]+=v
    mm=re.search(r'\s(?:bl|b)\s+0x[0-9a-f]+ <([^+>]+)>',line)
    if mm: calls[fn].add(mm.group(1).split('+')[0])
    if re.search(r'\bblr\s',line): indirect+=1
sys.setrecursionlimit(10000)
@functools.lru_cache(None)
def depth(f, stack=()):
    return frame.get(f,0)+max([depth(c) for c in calls.get(f,()) if c!=f] or [0])
print("indirect calls (blr):", indirect)
print("max stack from _start (bytes):", depth('_start'))
path=['_start']
while True:
    f=path[-1]; cs=[c for c in calls.get(f,()) if c!=f]
    if not cs: break
    path.append(max(cs,key=depth))
for f in path: print(f"  {frame.get(f,0):6d}  {f[:110]}")
