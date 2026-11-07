# HookProbe-OS — The BPF Threat Plane (RFC 9669 VM · JIT · Verifier)

**The detection logic itself: a clean, standards-pure BPF virtual machine, JIT-compiled and sandbox-verified, living entirely inside the unprivileged IDS sidecar — the microkernel never sees a packet or a rule.**

Status: design document · Companion to `ZEROCOPY_IPC_RING.md`, `CAPABILITY_MODEL.md`. Validates the drafted VM/JIT/verifier design against the research and against the sibling HookProbe FreeBSD track, and flags the two places where honesty matters most (verifier soundness, and build-vs-adopt for the JIT).

---

## 0. Why this is the right move — and it's already the HookProbe standard

Targeting the **IETF-standardized BPF ISA (RFC 9669)** rather than Linux eBPF is correct, and it is *already the committed HookProbe portability contract.* The sibling FreeBSD track's ADR-008 freezes exactly three cross-substrate contracts — **event schema, BPF ISA (RFC 9669), WASI** — precisely so detection logic never touches OS-specific machinery. This document is the microkernel realization of that same contract. The payoff compounds across all three tracks (Linux teaser, FreeBSD, now microkernel): **the same clang-compiled BPF bytecode threat rules run on all of them**, because none of them depend on Linux eBPF's kernel entanglement (maps, kfuncs, kernel helpers, the in-kernel verifier).

- **Linux eBPF is a trap for a microkernel:** it is fused to Linux internal state, giant map infrastructure, and hundreds of kernel-specific helpers. Reimplementing it would mean emulating half of Linux inside your TCB — the opposite of a lean, provable system.
- **RFC 9669 BPF is a clean 64-bit RISC-like VM:** input a packet, run pure logic, return a verdict. No OS state. Decoupled. Embeddable in userspace. ([RFC 9669 standardizes the BPF ISA independently of Linux — confirmed; the research brief notes seL4 has no IDS-on-microkernel prior art, so this is novel ground.])

**Architectural placement (correct as drafted):** because the datapath is a zero-copy capability ring, the BPF VM does **not** belong in the kernel. It is embedded in the IDS sidecar. The core runtime stays blind to packet logic — Layer-1 (capability/hardware) isolation bounds the whole engine to the ring; Layer-2 (verifier) bounds each rule to the packet buffer. Two independent walls.

---

## 1. The three tiers of the plane

```
   clang/LLVM (offline, authoring)  ──▶  RFC 9669 BPF bytecode (.bpf) + signature
                                              │  loaded into the IDS sidecar
                                              ▼
   ┌───────────────────────────────────────────────────────────────────────┐
   │  IDS SIDECAR  (unprivileged, capability-bounded to the ring only)       │
   │                                                                         │
   │   ① VERIFIER  ── proves bounds-safety + termination BEFORE any exec     │
   │        │  (or, v1: signature check on HookProbe-authored rules)         │
   │        ▼                                                                │
   │   ② JIT      ── RFC 9669 bytecode → native x86-64/arm64, W^X-locked     │
   │        │                                                                │
   │        ▼                                                                │
   │   ③ EXEC     ── verdict = prog(packet_ptr)  on the zero-copy ring       │
   └───────────────────────────────────────────────────────────────────────┘
```

Order is load-bearing: **verify → JIT → lock W^X → execute.** A rule that fails the verifier is never JIT-ed; JIT-ed code is never executed until its page is flipped from RW to RX.

---

## 2. Tier ①: the verifier — the hardest, most safety-critical component

The drafted verifier design — **CFG/DAG construction, abstract interpretation with dual-domain (interval + tri-state `tnum`) register tracking, branch-splitting on conditionals to prove `PTR_TO_PACKET` bounds, state-pruning/memoization, and a bounded-instruction ceiling for termination** — is **exactly how a real BPF verifier works.** It matches Linux's verifier and, more importantly, the academic reference:

- **PREVAIL** (Gershuni et al., **PLDI 2019**) is the standalone, abstract-interpretation-based eBPF verifier built precisely to be *decoupled from Linux* — the closest existing thing to what HookProbe needs. `tnum` (tri-state number) tracking, interval domains, and branch-split range refinement are its core. **Adopt/study PREVAIL rather than inventing the abstract domains from scratch.** The drafted `RegisterState{type, smin, smax, umin, umax, tnum}` is essentially Linux's `bpf_reg_state` / PREVAIL's abstract value — correct.

**The honest risk (this is the one to internalize):** *a verifier is a proof engine, and a bug in it is a sandbox escape.* Linux's eBPF verifier is one of the most CVE-dense components in the kernel despite years of expert attention; range-tracking and speculative-path bugs have repeatedly produced privilege escalations. Writing a *sound* verifier is a research-grade undertaking, not a sprint.

**Therefore the HookProbe sequencing (borrowed directly from the FreeBSD track's ADR-007) is:**
- **v1 — signed-programs-only, NO full verifier.** HookProbe authors *all* the threat rules. Ship them **signed** (the `mac_veriexec`/secpol analog); the sidecar runs only rules whose signature verifies. This removes the entire verifier attack surface for v1 and still gives a working detection plane. Layer-1 capability isolation already bounds the engine; a signed first-party rule that misbehaves crashes only the (HAM/-restartable) sidecar, not the system.
- **v2 — add the PREVAIL-style verifier only when opening the plane to third-party/customer rules.** That is the moment the verifier's cost is justified, and by then it can be built/audited deliberately. This is the single biggest de-risking decision in the whole plane.

Termination: the **strict-DAG (forbid backward jumps)** option is the safe v1 default; **bounded loops via induction-variable tracking + a state-complexity ceiling** is the v2 upgrade for variable-length parsing (IP options, TLV). Both are as drafted.

---

## 3. Tier ②: the JIT — lean, but a real attack surface

Interpreting bytecode at 100 Gbps is too slow (the ~20-cycle/packet budget forbids an interpreter loop), so a JIT is required. The drafted design is correct and complete:
- **Fixed BPF→native register map** (R0→RAX return, R1→RDI packet ptr per SysV ABI, callee-saved R6–R9→RBX/R13–R15, R10→RBP) — avoids stack spills. Correct.
- **Two-pass emit** (pass 1: emit native + record byte offsets; pass 2: patch relative branch targets) — the standard JIT structure. Correct.
- **W^X discipline** via capabilities: allocate the code Frame **RW**, emit, then invoke a capability op to remap it **RX** (never RWX). This is the capability-model realization of W^X and it is *stronger* than mprotect on Linux because the executable-vs-writable authority is a kernel-checked capability right, not a page flag a bug can flip. Correct and elegant.
- **Hardening — both drafted mitigations are real and necessary:**
  - **Constant blinding** (XOR immediates with a per-compile random key, un-XOR right before use) defeats JIT-spraying / ROP-gadget planting via attacker-known immediates. This is exactly why Linux added `bpf_jit_harden`. Correct.
  - **Retpolines** on any indirect branch (tail calls) to defeat Spectre-v2 branch-target injection. Correct — and note that a security appliance is a *high-value* Spectre target, so this is not optional.

**Build-vs-adopt (the honest call):** a from-scratch Zig JIT is a clean, ownable, ~fit-for-purpose choice and the drafted design is sound. **But two permissively-licensed RFC-9669 JITs already exist and are the HookProbe-sanctioned bases** (per the FreeBSD track's ADR-007): **uBPF** (Apache-2.0, C, x86-64 + arm64 JIT) and **rbpf** (MIT, Rust). Extending one of these gives you a working, tested JIT immediately and keeps full ownership (permissive license → relicense freely, matching ADR-000). Recommendation: **start from uBPF/rbpf to reach a running plane fast; a from-scratch Zig JIT is a legitimate later "own-it-fully" refinement, not a prerequisite.** Don't let JIT authoring block detection — the moat is the *rules and integration*, not the translator.

---

## 4. Tier ③: execution on the ring (zero crossings)

Once verified and RX-locked, the rule is a native function in RAM. In the sidecar's poll loop (from `ZEROCOPY_IPC_RING.md`):
```zig
const BpfProgram = *const fn (ctx: *const PacketFrame) callconv(.C) u32; // R1=ctx→RDI, verdict→RAX
const rule = @as(BpfProgram, @ptrCast(rx_locked_code));
while (ring.available()) |desc| {
    const frame = pool.frame(desc.frame_idx);      // pointer into Region C — no copy
    const verdict = rule(frame);                    // CPU jumps into JIT-ed native code
    switch (verdict) { DROP => recycle(desc), PASS => forward(desc), else => alert(desc, verdict) }
}
```
- **No context switch, no kernel crossing, no copy.** The packet pointer handed to the rule is the physical frame the NIC DMA-ed into (Region C), mapped into the sidecar's VSpace as Read-only (IDS) or RW (IPS). The verifier (or the signature, in v1) has already proven the rule only reads within `[ctx, ctx+len)`.
- **Verdict codes** align with the ring descriptor's `verdict` field: PASS/DROP/REDIRECT/ALERT. IPS enforcement is the same ring write already specified.

---

## 5. The double-layer security model (why this is provable and lean)

| Layer | Mechanism | Guarantees | Proven by |
|---|---|---|---|
| **1 — Spatial / hardware** | microkernel capabilities + IOMMU | the IDS engine can address *only* the packet ring; a full compromise of the engine cannot touch the host runtime, FS, USB, or other tenants | capability model (`CAPABILITY_MODEL.md`); on seL4, machine-checked |
| **2 — Logic / software** | BPF verifier (v2) or signature (v1) + W^X + constant-blinding + retpolines | a threat rule cannot read OOB, cannot loop forever, cannot be sprayed into a gadget, cannot leak via Spectre | PREVAIL-style abstract interpretation; JIT hardening |

The two layers are **independent** — a defeat of the software sandbox (a verifier bug) is still contained by the hardware sandbox (the engine can't address anything but the ring), and vice-versa. That independence is the entire security argument, and it is why this design is genuinely stronger than eBPF-in-a-monolithic-kernel, where a verifier bug is a *kernel* compromise.

---

## 6. Cross-track consistency (the compounding payoff)

Because the plane targets RFC 9669 + a userspace runtime + WASI (for higher-level detectors), a threat rule authored once runs on:
- the **Linux teaser** (loads into kernel eBPF, or the same userspace runtime),
- the **FreeBSD track** (HSP userspace uBPF/rbpf over netmap),
- the **QNX track** (same runtime over a capture resource manager),
- **this microkernel** (same runtime over the capability ring).

One rule artifact, four substrates. That is ADR-008 delivering for the fourth time, and it is the reason the detection moat is portable across every base HookProbe ever evaluates.

---

*Honest bottom line: the drafted VM/JIT/verifier design is correct and matches the state of the art (PREVAIL, uBPF/rbpf, Linux JIT hardening). The two decisions that keep it shippable and safe: (1) v1 = signed-first-party rules, defer the full verifier to v2/third-party; (2) start the JIT from permissive uBPF/rbpf, treat a from-scratch Zig JIT as a later ownership refinement. Both are lifted straight from the FreeBSD track's ADR-007 — the same discipline, applied to the microkernel.*
