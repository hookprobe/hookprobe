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
  "P2iso|[P2-iso] PASS|impl|Implementation+Verification|CORE-2 per-TCB CSpaces: distinct capability spaces + rights-narrowing cross-CSpace delegation (child holds only the delegated Frame, read-only; Endpoint absent) — the P12 authority primitive"
  "P2gen|[P2-gen] PASS|impl|Implementation+Verification|CORE-9 generation-tagged CDT: parent link = (slot, generation); a freed+reused slot bumps its generation so a stale child (old-gen link) is orphaned — revoke of the new occupant spares it, never re-attaches"
  "PH7caps|[PH7-caps] PASS|impl|Implementation+Verification|PH7/XC-15 capability-invariant property sweep (dual-backend: runs on the QEMU AND CM5 MMU backends): mint narrows rights to exactly requested&source and never amplifies across all 8 combos, type-tag safety (Frame!=Endpoint), revoke severs a child subtree + bumps its generation, and mint-without-Grant is refused"
  "P2unmap|[P2-unmap] PASS|impl|Implementation+Verification|CORE-1 cap-gated Frame mapping + revoke-unmaps: map_frame_cap routes an EL0 grant through a has_rights-gated capability invocation (RW cap => AP RW, RO cap => AP RO, W-on-RO-cap denied) and RECORDS the VA; revoke then SEVERS authority by INVALIDATING the L3 entry + tlbi (present -> revoke -> invalid), closing the confused-deputy gap where revoke only cleared the CSpace slot"
  "P3|[P3] PASS|impl|Implementation+Verification|EL0 userspace + SVC syscall boundary + fault containment"
  "P4|[P4] PASS|impl|Implementation+Verification|synchronous IPC rendezvous over an Endpoint (block/unblock)"
  "P5|[P5] PASS|impl|Validation|Packet Engine: zero-copy ring + in-place verdict (synthetic pkts)"
  "P5b|[P5b] PASS|impl|Validation|real wire: virtio-net ARP round-trip -> ring -> verdict"
  "P6|[P6] PASS|impl|Validation|AI Runtime: RFC 9669 BPF VM (interpreter) verdict + bounds sandbox"
  "P6b|[P6b] PASS|impl|Validation|BPF verifier + JIT (W^X) + self-heal supervisor + telemetry/QSecBit"
  "DRV|[DRV] PASS|impl|Validation|driver isolation: EL0 driver server drives NIC MMIO via a capability"
  "P8|[P8] PASS|impl|Validation|PREVAIL verifier: statically proves rule memory-safety, rejects unsafe 3rd-party rules"
  "P8p|[P8-plane] PASS|impl|Validation|detection plane: general BPF JIT (branches) + rule registry (parity) + live QSecBit scoring"
  "P8diff|[P8-diff] PASS|impl|Validation|DET-6: JIT<->interpreter differential over ALL live JIT'd rules (L4 port + L2 ARP + TCP-scan), not just THREAT_RULE — native codegen proven == verified interpreter on a match-constant-stressed input set; FLOW/CALL rules interp-only, excluded"
  "P8vlan|[P8-vlan] PASS|impl|Validation|AUD-NET-1: strip_vlan reconstructs the canonical untagged frame for 1-tag and QinQ (guards the VLAN-normalization off-by-2 that re-opened the DET-4 L2/FLOW IDS bypass)"
  "P8n|[P8-napi] PASS|impl|Validation|adaptive NAPI: poll-budget grows under load, idles+re-arms when quiet (spin-poll retired)"
  "P8l|[P8-l2] PASS|impl|Validation|L2 guard: napse-l2guard parity — malformed-ARP FrameDropped; eth-src mismatch DETECTED but OBSERVED (ADR 0023 tri-state: a legit gratuitous/proxy ARP passes, no fabricated FrameDrop)"
  "P8t|[P8-tcp] PASS|impl|Validation|TCP scan detection: NULL/FIN/Xmas/SYN-FIN anomalous-flag scans DETECTED but OBSERVED (observe-by-default — no legit segment dropped), normal SYN/ACK fire nothing (ADR 0023)"
  "P8s|[P8-syn] PASS|impl|Validation|SYN-flood rate-limit: first stateful rule (BPF CALL helper + windowed rate limiter)"
  "P8ss|[P8-synsrc] PASS|impl|Validation|per-source SYN-flood: live rule keyed by IP source — flood one host, others unaffected"
  "P8b|[P8-block] PASS|impl|Validation|threat-feed blocklist: helper #2 (keyed CIDR lookup) — a feed IOC hit is DETECTED but OBSERVED (ADR 0023 matrix L11: a customer touching one IOC is never quarantined on a single hit), clean sources pass"
  "P8sep|[P8-sep] PASS|impl|Validation|DET-SEP / M2 keystone: tri-state decide()/decide_l2 seam ports ADR 0023 onto heqk — observe-by-default (a fired detector defaults to Observe/PASS), blocklist+ARP-spoof OBSERVED (legit customer always passes), Allowlisted mgmt floor never enforced (never self-lock-out), while malformed-frame + operator signature still FrameDrop (the suspicion-free confirmed drops)"
  "P8soar|[P8-soar] PASS|impl|Validation|SOAR event-ring: async non-blocking telemetry exfiltration (verdict engine -> SPSC ring -> EL0 exporter)"
  "P8l7|[P8-l7] PASS|impl|Validation|L7 deep-packet signature: helper #3 payload_match — MQTT CONNECT flagged in the verified fast-path before EL0 services"
  "P12|[P12] PASS|impl|Implementation+Verification|notification objects + capability pub-sub: seL4 Signal/Poll (OR-coalescing), topics-as-caps authority (ungranted subscribe REFUSED via has_rights), blocking WAIT syscall woken by Signal under the scheduler; badge-from-cap; MAX_THREADS->16; DSN-6 fixed"
  "P17|[P17] PASS|impl|Validation|overlay convergence: net-class queue + dual-direction IPS gate (ingress DROP before ring + egress DROP before wire); EL0 monotonic counter; smoltcp EL0 service deferred"
  "PHprod|[PHprod] PASS|impl|Validation|PH1 production datapath: the running-sensor enforce decision (verdict-per-frame -> PASS FORWARDED / threat DROPPED) over a mixed benign+threat batch; the cm5 prod build wraps this loop around a real EL0-driven NIC (self-healing, never halts)"
  "PH6net|[PH6-net] PASS|impl|Validation|PH6 smoltcp net-service stack integration: the smoltcp TCP/IP stack runs ABOVE the P17 rule plane (ingress admits only verdict-PASS frames, egress emits only verdict-PASS frames) and correctly answers an ARP for its own IP; the EL0-isolated netq service + TRNG seed + PCR3 measure is the metal follow-up"
  "P11|[P11] PASS|impl|Validation|device-class transport (sDDF borrow): hardened SPSC (H1 kernel-private cap, H2 ownership table, H3 copy-then-validate, csdb, no-RMW) REJECTS+COUNTS a hostile driver's forged descriptors (V2 index/V4 offset+len+flags/V5 not-owned); LoopDev + honest path pass; metal GemDev/RtlDev deferred"
  "P16sha|[P16-sha] PASS|impl|Validation|crypto primitive: incremental SHA-256 Hasher == one-shot digest across all lengths/chunkings (guards the metal-found short-tail HMAC auth bug)"
  "P15|[P15-seal] PASS|impl|Validation|sealed storage: Encrypt-then-MAC seal/unseal (SHA256 HMAC/HKDF/CTR), tamper+wrong-measurement refused, MBR write-guard (RamDisk); eMMC driver read-only (writes behind p15-write)"
  "AB|[HBoot-AB] PASS|impl|Validation|A/B trial boot: kernel confirms health (hvc #1 disarms HBoot's EL2 watchdog) or firmware falls back to the known-good slot"
  "P7|[P7] PASS|plan|Validation|CM5/RP1 metal bring-up"
)

echo "==================================================================="
echo " HEQK Core — Kernel Agent Validator (Hardened Edge Quantum-safe Kernel)"
echo "==================================================================="

# --- Stage 1: build -------------------------------------------------------
echo -n "[build] cargo build ... "
if ! cargo build --features netsvc >/tmp/hp_build.log 2>&1; then
  echo "FAIL"; echo "  --- build errors ---"; grep -E '^error' /tmp/hp_build.log | head;
  echo "GAP: build broken — cannot validate. Fix compile errors first."; exit 2
fi
echo "ok"

# --- Stage 1b: verifier soundness harness (P16, host-side) ----------------
# Compile the REAL abstract operators (kernel/src/absdom.rs) for the host and
# check each over-approximates the concrete semantics (Agni-style). A control
# injects a deliberately-unsound operator the harness must catch.
echo -n "[P16]   verifier soundness harness ... "
VH="$(mktemp)"
if rustc --edition 2021 -O tools/verifier-harness.rs -o "$VH" >/tmp/hp_vh_build.log 2>&1; then
  if "$VH" >/tmp/hp_vh.log 2>&1; then
    echo "PASS (operators PROVEN SOUND exhaustively over reduced width + sampled on reachable domain; injected unsoundness caught)"
  else
    echo "FAIL — verifier operator UNSOUND:"; sed 's/^/    /' /tmp/hp_vh.log
    rm -f "$VH"; exit 2
  fi
  rm -f "$VH"
else
  echo "skip (rustc host build unavailable)"
fi

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
