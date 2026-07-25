export const meta = {
  name: 'base-tier-build',
  description: 'Implement + T1-validate the 6-phase base-tier (bcm2712) build ticket; sequential with per-phase verify/fix, final T1 gate + adversarial refill review',
  phases: [
    { title: 'P0-kernel' },
    { title: 'P1-tuning' },
    { title: 'P2-shed-v2' },
    { title: 'P3-ptp' },
    { title: 'P4-aot-dga' },
    { title: 'T1-gate' },
  ],
}

const TICKET = 'docs/base-tier-build-ticket.md'

const IMPL_SCHEMA = { type:'object', additionalProperties:false,
  required:['phase','files_changed','summary','open_gaps','needs_operator'],
  properties:{
    phase:{type:'string'},
    files_changed:{type:'array', items:{type:'string'}},
    summary:{type:'string'},
    open_gaps:{type:'array', items:{type:'string'}},
    needs_operator:{type:'array', items:{type:'string'}},
  } }

const VERIFY_SCHEMA = { type:'object', additionalProperties:false,
  required:['phase','pass','failures','notes'],
  properties:{
    phase:{type:'string'},
    pass:{type:'boolean'},
    failures:{type:'array', items:{type:'string'}},
    notes:{type:'string'},
  } }

const phases = [
  {
    key:'P0-kernel', agentType:'os-architect',
    task:`Implement PHASE 0 (Edge kernel PTP) from ${TICKET}. Read that file's "Phase 0" section and builder/build-edge-kernel.sh. Make exactly these edits: (1) add CONFIG_PTP_1588_CLOCK=y and CONFIG_NET_PTP_CLASSIFY=y to the inline kernel-config heredoc (near the NF_CONNTRACK_PROCFS block); (2) add a "require_y CONFIG_PTP_1588_CLOCK" line to the config-guard block; (3) add the negative hugepage guard from the ticket so a stray CONFIG_TRANSPARENT_HUGEPAGE=y fails the build (base tier = no hugepages, ADR 0031 §C). Update the script header comment if it enumerates the config deltas. DO NOT run the kernel compile — it takes hours; record the exact run-both.sh / FLAVOUR commands in needs_operator. Re-read the file and confirm the guard block is internally consistent and shell-valid. Return JSON per schema.`,
    verify:`Verify PHASE 0 in builder/build-edge-kernel.sh: confirm CONFIG_PTP_1588_CLOCK=y is in the config heredoc, "require_y CONFIG_PTP_1588_CLOCK" is in the guard, and the negative hugepage guard exists. Run "bash -n builder/build-edge-kernel.sh" to confirm shell validity. Do NOT compile the kernel. Return pass/fail per schema.`,
  },
  {
    key:'P1-tuning', agentType:'code-developer',
    task:`Implement PHASE 1 (base tuning profile) from ${TICKET} "Phase 1". Create base/units/hookprobe-tune-bcm2712.service (oneshot, manifest-keyed, runs only where the profile matches / tc_bpf granted) applying: threaded NAPI on (/sys/class/net/<if>/threaded=1), macb IRQ smp_affinity -> core 0, detection slice AllowedCPUs=2-3, RPS DEFAULT OFF (opt-in core-1-only via a dataplane_tuning manifest flag), GRO on, rk3588 big.LITTLE pinning (NAPI+detection on A76, housekeeping on A55). NO isolcpus/nohz_full. Add a dataplane_tuning block to platforms/rpi5.yaml and platforms/rk3588.yaml. Match existing conventions in base/units/ and platforms/. Return JSON per schema.`,
    verify:`Verify PHASE 1: the new unit is syntactically valid (systemd-analyze verify if available, else static lint / builder/lint-units.sh if present), platforms/rpi5.yaml + platforms/rk3588.yaml are valid YAML, RPS defaults OFF, no isolcpus present. Return pass/fail.`,
  },
  {
    key:'P2-shed-v2', agentType:'code-developer',
    task:`Implement PHASE 2 (DDoS resource-shed v2) from ${TICKET} "Phase 2" and the MUST-FIX #1 box. Read modules/napse-capture/bpf/napse_detect.bpf.c and its loader first. Build: (a) userspace hookprobe-psid (housekeeping slice, hard CPUQuota) that registers PSI trigger FDs on /proc/pressure/{cpu,memory}, blocks in poll(2), writes tier 0..3 + r_base_pps + heartbeat_ns into a pinned BPF_MAP_TYPE_ARRAY at /sys/fs/bpf/hookprobe/shed_ctrl, with 5s step-down hysteresis and the tier table from spec §3.2; (b) in napse_detect.bpf.c add the token-bucket fast loop AFTER the conntrack-established fast-pass and BEFORE the per-source SYN window, backed by a new shed_bucket LRU_HASH (65536). CRITICAL (must-fix #1): the refill MUST be fixed-point INTEGER (scaled milli-tokens or a fractional-remainder field) — eBPF has NO floating point; "rate*dt/1e9" truncates to 0 per-packet and would drop every legit new flow under tier>=1. Add a test proving a legit new-flow burst passes at line rate while tier>=1. Fail-open on stale (>30s) heartbeat or map-read error (treat as tier 0). Tier 0 = mechanism fully bypassed. Add the flat resource_shed_v2 capability token. Demote the nft hookprobe_resource_shed table to fallback (keep its L2 conntrack-saturation guard). Add a SHED_V2 ringbuf event type. Match existing crate/module layout. Return JSON per schema.`,
    verify:`Verify PHASE 2: (1) compile modules/napse-capture/bpf/napse_detect.bpf.c with clang -target bpf CO-RE against the repo vmlinux BTF — must build clean; (2) grep the .bpf.c for any floating-point (float/double/1e9/1.0 literals) — MUST be none; (3) cargo build the hookprobe-psid binary; (4) run the legit-passes-under-flood test if present and report result; (5) confirm the tier-0-bypass and fail-open-on-stale-heartbeat code paths exist. Return pass/fail with specifics.`,
  },
  {
    key:'P3-ptp', agentType:'code-developer',
    task:`Implement PHASE 3 (PTP userspace wiring) from ${TICKET} "Phase 3". Add ptp4l + phc2sys to the housekeeping slice (systemd units/config), discipline the PHC, and expose PHC-disciplined timestamps into the telemetry pipeline (NAPSE event timestamps). Add the flat ptp_hw capability token, granted only where the manifest records macb hardware timestamping (ethtool -T style fact). Document the mesh-domain caveat in comments: HW timestamps are locally precise; cross-node absolute alignment needs a PTP domain with a master (no GNSS grandmaster on a base box). Return JSON per schema.`,
    verify:`Verify PHASE 3: units parse, ptp_hw token wired into the capability mapper, the mesh caveat is documented. Return pass/fail.`,
  },
  {
    key:'P4-aot-dga', agentType:'code-developer',
    task:`Implement PHASE 4 (A76 AOT dotprod + dga-lm unstub) from ${TICKET} "Phase 4" and MUST-FIX #2. Read builder/refresh-aot.sh and modules/qsecbit first. Do: (1) extend the --with-a76 precompile (builder/refresh-aot.sh) to target +dotprod +fp16 and enable Wasmtime relaxed_simd for the a76 blob ONLY (a72 baseline unchanged; still exactly two ARM blobs); (2) create modules/dga-lm/ — an int8 char-level DGA classifier Wasm module using the EXPLICIT core::arch::wasm32 relaxed-dot intrinsic (i32x4_relaxed_dot_i8x16_i7x16_add), NOT plain core::simd, with an A72 NEON widening-multiply fallback, a SEED/BASELINE int8 model (<=256KB) + model card (real training is off-device per ADR 0014 — note this in open_gaps), and a CI quantization stage; (3) implement the two-stage SDOT gate as a script: verify the emitted .wat contains the relaxed-dot opcode, THEN verify the .a76.cwasm disassembly contains an SDOT instruction — if the disasm check fails, still ship but DROP the throughput claim (record which happened in open_gaps); (4) wire QSECBIT p_attack to the dga-lm score, budget-gated so if the A72 path misses the 50ms epoch, ml_cpu is NOT granted there and p_attack stays 0.0 (scoped, per ADR 0014 D6); (5) add the flat ml_cpu capability token. dga-lm is advisory/observe-only (C9). Return JSON per schema.`,
    verify:`Verify PHASE 4: (1) modules/dga-lm builds to wasm (cargo build --target wasm32-wasip1 or the repo's wasm target); (2) confirm the emitted .wat contains the relaxed-dot opcode; (3) run the SDOT two-stage gate script and REPORT whether SDOT actually appears in the a76 disassembly or the claim was dropped; (4) QSECBIT builds and the p_attack wiring compiles; (5) ml_cpu token added; (6) cargo test the affected crates. Return pass/fail with the SDOT outcome in notes.`,
  },
]

const results = []
for (const p of phases) {
  phase(p.key)
  const impl = await agent(p.task, { label:`impl:${p.key}`, phase:p.key, agentType:p.agentType, schema:IMPL_SCHEMA })
  let verify = await agent(p.verify, { label:`verify:${p.key}`, phase:p.key, agentType:'verification-engineer', schema:VERIFY_SCHEMA })
  if (verify && verify.pass === false) {
    log(`${p.key} verify FAILED: ${(verify.failures||[]).join('; ')} — running one fix round`)
    await agent(`In phase ${p.key} of ${TICKET}, a verification pass reported these failures: ${JSON.stringify(verify.failures)}. Fix them at the source (do not paper over), preserving the phase's must-fix invariants. Then re-run the phase's own checks. Return JSON per the implementation schema.`, { label:`fix:${p.key}`, phase:p.key, agentType:p.agentType, schema:IMPL_SCHEMA })
    verify = await agent(`Re-verify phase ${p.key} after the fix round. ${p.verify}`, { label:`reverify:${p.key}`, phase:p.key, agentType:'verification-engineer', schema:VERIFY_SCHEMA })
  }
  results.push({ phase:p.key, impl, verify })
  log(`${p.key} done — verify pass=${verify ? verify.pass : 'null'}`)
}

phase('T1-gate')
const t1 = await agent(`Run the FULL T1 gate for the base-tier build described in ${TICKET}. Execute: cargo test --workspace (add --features hookprobe-supervisor/wasm if that is how the repo enables wasm), cargo clippy --workspace --all-targets, compile EVERY eBPF *.bpf.c under modules/*/bpf with clang -target bpf CO-RE against the repo vmlinux BTF, and run builder/lint-units.sh if present. Report exact pass/fail counts and every failure. DO NOT run the multi-hour kernel compile and DO NOT flash any hardware. Return pass/fail per schema with counts in notes.`, { label:'t1:full', phase:'T1-gate', agentType:'verification-engineer', schema:VERIFY_SCHEMA })

const sec = await agent(`Adversarially review the Phase-2 shed-v2 token-bucket refill in modules/napse-capture/bpf/napse_detect.bpf.c (must-fix #1). Prove or refute: (a) the refill is fixed-point INTEGER with no floating point; (b) a legitimate new-flow burst at line rate STILL PASSES under pressure tier>=1 (i.e. tokens actually accumulate and do not truncate to 0); (c) fail-open holds on stale (>30s) heartbeat and on map-read error; (d) tier 0 fully bypasses the mechanism (observe-by-default). Default to pass=false if any of (a)-(d) is not clearly satisfied. Return {phase:'sec-refill', pass, failures, notes}.`, { label:'sec:refill', phase:'T1-gate', agentType:'security-auditor', schema:VERIFY_SCHEMA })

log(`build complete — T1 pass=${t1 ? t1.pass : 'null'}, refill-review pass=${sec ? sec.pass : 'null'}`)
return { results, t1, sec }