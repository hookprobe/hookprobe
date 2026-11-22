#!/usr/bin/env bash
# negative.sh — prove the X1 checks can FAIL (a check that cannot fail proves nothing).
#   1. no RDSEED (-cpu …,-rdseed)            → must stop at "[X1-rng] FAIL-CLOSED", QEMU exit 35, no "[X1] PASS"
#   2. mutant: kernel identity map user-accessible (U bit set on the kernel PDPT + PD entries, SMEP/SMAP off)
#                                            → the ring-3 read check must report "NOT refused", exit 35
#   3. mutant: user stack page executable (NX bit dropped)
#                                            → the NX-execute check must report "NOT refused", exit 35
#   4. no virtio devices on the PCIe bus     → the X2 PCIe stage must FAIL (exit 35), not pass vacuously
# Mutants are built from a temp COPY of the crate; the source tree is never modified.
set -uo pipefail
HERE="$(cd "$(dirname "$0")/.." && pwd)"
RUN="$HERE/run-qemu.sh"
pass=0 fail=0
ok()  { echo "ok   $*"; pass=$((pass+1)); }
bad() { echo "FAIL $*"; fail=$((fail+1)); }

expect_fail() { # <label> <grep pattern> -- env…
  local label="$1" pat="$2"; shift 3
  local out; out=$(env "$@" "$RUN" 2>&1)
  # Judged on the overall verdict: exit 35, the specific failure message, and no "X1+X2 PASS" (an X2 failure may
  # legitimately follow an "[X1] PASS" line).
  if grep -q "qemu-exit=35" <<<"$out" && grep -aq "$pat" <<<"$out" && ! grep -aq 'run-qemu: X1+X2 PASS' <<<"$out"; then
    ok "$label"
  else
    bad "$label"; echo "$out" | tail -5 | sed 's/^/     /'
  fi
}

[ -r /dev/kvm ] && [ -w /dev/kvm ] && BASECPU=host || BASECPU=max
expect_fail "no RDSEED → entropy FAIL-CLOSED" '\[X1-rng\] FAIL-CLOSED' -- X1_CPU="$BASECPU,-rdseed"

mutant() { # <name> <python replace: old> <new>
  local d; d=$(mktemp -d); cp -r "$HERE/." "$d/"; rm -rf "$d/target"
  python3 -I -c "import sys; p=sys.argv[1]; s=open(p).read(); assert sys.argv[2] in s; open(p,'w').write(s.replace(sys.argv[2], sys.argv[3]))" \
    "$d/src/paging.rs" "$2" "$3" || { bad "$1: mutation did not apply"; return 1; }
  echo "$d"
}

if D=$(mutant "U-bit" \
    "(*(&raw mut PDPT)).0[g as usize] = (&raw const (*pd_k)[g as usize]) as u64 | P | RW;" \
    "(*(&raw mut PDPT)).0[g as usize] = (&raw const (*pd_k)[g as usize]) as u64 | P | RW | US;"); then
  # Also turn SMEP/SMAP off: with SMEP on, user-accessible kernel CODE faults on every fetch and the machine
  # triple-faults before the check runs (also a refusal, but not the one this control is meant to exercise).
  python3 -I -c "
import sys; p=sys.argv[1]; s=open(p).read()
for o, n in (('pa | P | RW | PS | mmio;', 'pa | P | RW | PS | mmio | US;'), ('if f.smep {', 'if false {'), ('if f.smap {', 'if false {')):
    assert o in s, o; s = s.replace(o, n)
open(p, 'w').write(s)" "$D/src/paging.rs"
  expect_fail "mutant: kernel map user-accessible (SMEP/SMAP off) → isolation check fails" 'ring-3 read of kernel memory was NOT refused' -- X1_CRATE="$D"
  rm -rf "$D"
fi

if D=$(mutant "NX-drop" "| P | RW | US | nx; // RW, never executable" "| P | RW | US; // MUTANT: executable"); then
  expect_fail "mutant: executable user stack → NX check fails" 'execute from the NX stack was NOT refused' -- X1_CRATE="$D"
  rm -rf "$D"
fi

expect_fail "no virtio devices → X2 PCIe stage fails (not vacuous)" 'PCIe scan did not find' -- X1_NODEV=1

echo "negative: $pass passed, $fail failed"
[ "$fail" = 0 ]
