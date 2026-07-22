#!/usr/bin/env bash
# HookProbe kernel agent validator — the always-on V&V harness.
#
# Builds the kernel, boots it under QEMU, checks every phase gate by its PASS
# marker, and prints a product-lifecycle-aligned report (see LIFECYCLE.md).
# Reports gaps (regressions in built phases, or not-yet-built phases) and exits
# non-zero if any IMPLEMENTED phase fails — so CI / the kernel-validator agent
# can heal it. Run: ./validate.sh
set -u
cd "$(dirname "$0")"
[ -f "$HOME/.cargo/env" ] && . "$HOME/.cargo/env"

KERNEL=target/aarch64-unknown-none-softfloat/debug/kernel
LOG="$(mktemp)"
# virtio-net (v2) attached for P5b: the kernel ARPs the gateway and RXes the reply.
QEMU="qemu-system-aarch64 -M virt -cpu cortex-a72 -m 512M -nographic -serial mon:stdio -semihosting \
  -global virtio-mmio.force-legacy=false -netdev user,id=n0 -device virtio-net-device,netdev=n0 -kernel"

# phase|marker (fixed string)|status(impl|plan)|lifecycle stage|what it proves
PHASES=(
  "P0|[P0] PASS|impl|Implementation+Verification|boot chain: EL2->EL1, PL011, exception vectors"
  "P1|[P1] PASS|impl|Implementation+Verification|preemptive scheduler + context switch"
  "P1b|[P1b] PASS|impl|Implementation+Verification|MMU stage-1 + physical frame allocator"
  "P2|[P2] PASS|impl|Implementation+Verification|capabilities: untyped/retype/CDT/revoke"
  "P3|[P3] PASS|impl|Implementation+Verification|EL0 userspace + SVC syscall boundary + fault containment"
  "P4|[P4] PASS|impl|Implementation+Verification|synchronous IPC rendezvous over an Endpoint (block/unblock)"
  "P5|[P5] PASS|impl|Validation|Packet Engine: zero-copy ring + in-place verdict (synthetic pkts)"
  "P5b|[P5b] PASS|impl|Validation|real wire: virtio-net ARP round-trip -> ring -> verdict"
  "P6|[P6] PASS|impl|Validation|AI Runtime: RFC 9669 BPF VM (interpreter) verdict + bounds sandbox"
  "P6b|[P6b] PASS|impl|Validation|BPF verifier + JIT (W^X) + self-heal supervisor + telemetry/QSecBit"
  "DRV|[DRV] PASS|impl|Validation|driver isolation: EL0 driver server drives NIC MMIO via a capability"
  "P8|[P8] PASS|impl|Validation|PREVAIL verifier: statically proves rule memory-safety, rejects unsafe 3rd-party rules"
  "P8p|[P8-plane] PASS|impl|Validation|detection plane: general BPF JIT (branches) + rule registry (parity) + live QSecBit scoring"
  "P7|[P7] PASS|plan|Validation|CM5/RP1 metal bring-up"
)

echo "==================================================================="
echo " HEQK Core — Kernel Agent Validator (Hardened Edge Quantum-safe Kernel)"
echo "==================================================================="

# --- Stage 1: build -------------------------------------------------------
echo -n "[build] cargo build ... "
if ! cargo build >/tmp/hp_build.log 2>&1; then
  echo "FAIL"; echo "  --- build errors ---"; grep -E '^error' /tmp/hp_build.log | head;
  echo "GAP: build broken — cannot validate. Fix compile errors first."; exit 2
fi
echo "ok"

# --- Stage 2: boot + capture ---------------------------------------------
echo -n "[boot]  qemu virt ... "
timeout 45 $QEMU "$KERNEL" >"$LOG" 2>&1
RC=$?
if grep -q "\[ALL\]" "$LOG"; then echo "clean exit"; else echo "rc=$RC (no ALL marker; possible hang/regression)"; fi

# --- Stage 3: phase gate report ------------------------------------------
printf "\n %-4s %-8s %-30s %s\n" "PH" "STATUS" "LIFECYCLE STAGE" "GATE"
printf " %-4s %-8s %-30s %s\n" "----" "------" "------------------------------" "----------------------------------------"
FAILS=0; GAPS=0; FIRST_FAIL=""
for row in "${PHASES[@]}"; do
  IFS='|' read -r ph marker kind stage what <<< "$row"
  if grep -qF "$marker" "$LOG"; then
    st="PASS"
  elif [ "$kind" = "plan" ]; then
    st="PLANNED"; GAPS=$((GAPS+1))
  else
    st="FAIL"; FAILS=$((FAILS+1))
    [ -z "$FIRST_FAIL" ] && FIRST_FAIL="$ph|$marker|$what"
  fi
  printf " %-4s %-8s %-30s %s\n" "$ph" "$st" "$stage" "$what"
done

# --- Stage 4: verdict + auto-diagnostics (heal fast) ----------------------
echo ""
echo " built phases failing : $FAILS"
echo " gaps (not yet built) : $GAPS   (next: first PLANNED phase above)"
if [ "$FAILS" -gt 0 ]; then
  IFS='|' read -r ff_ph ff_marker ff_what <<< "$FIRST_FAIL"
  echo ""
  echo " ┌─ HEAL: first failing gate = $ff_ph ($ff_what)"
  echo " │  missing marker: '$ff_marker'"
  if grep -qE 'EXCEPTION|PANIC' "$LOG"; then
    echo " │  fault detected — dumping the exception/panic:"
    grep -E 'EXCEPTION|PANIC|ESR_EL1|ELR_EL1|FAR_EL1' "$LOG" | sed 's/^/ │    /'
  elif ! grep -q "\[ALL\]" "$LOG"; then
    echo " │  no clean exit (hang or early abort) — last 12 console lines:"
    grep -v '^\s*$' "$LOG" | tail -12 | sed 's/^/ │    /'
  fi
  echo " └─ next: the kernel-validator agent diagnoses at $ff_ph's code and re-runs ./validate.sh"
  rm -f "$LOG"
  echo " VERDICT: REGRESSION — heal required (diagnostics above)."
  exit 1
fi
rm -f "$LOG"
echo " VERDICT: all implemented phases GREEN. Kernel is healthy."
echo " (continuous V&V + runtime self-heal (P6b); see LIFECYCLE.md + the kernel-validator agent.)"
exit 0
