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
  "Pwx|[P-wx] PASS|impl|Implementation+Verification|MULTI-BLOCK W^X: build_wx_ram_range L3-maps EVERY 2 MiB block overlapping [__text_start,__text_end) as per-page RO+X code / RW+PXN data, all other RAM blocks RW+PXN — removes the old single-2-MiB-block ceiling (code past the first block used to land in a PXN block and instruction-abort: the metal-driver / bigger-catalogue / wasmi-host case). Proof builds a SYNTHETIC executable range spanning THREE 2 MiB blocks into an unused L1 slot and reads the REAL page descriptors back through the P7b walker: code RO+X in the 2nd AND last text block, data RW+NX before/after/beyond text, and a strict sweep confirming NO page is ever both writable and EL1-executable (SCTLR.WXN backstop on top)"
  "P2|[P2] PASS|impl|Implementation+Verification|capabilities: untyped/retype/CDT/revoke"
  "P2iso|[P2-iso] PASS|impl|Implementation+Verification|CORE-2 per-TCB CSpaces: distinct capability spaces + rights-narrowing cross-CSpace delegation (child holds only the delegated Frame, read-only; Endpoint absent) — the P12 authority primitive"
  "P2teardown|[P2-teardown] PASS|impl|Implementation+Verification|CORE-2 CSpace KILL-CLEAR (A1a): a thread's CSpace is DROPPED on its final exit so a REUSED scheduler slot (tid) cannot inherit the dead task's caps — the confused-deputy where current_cspace() would resolve a previous occupant's authority for a new occupant. clear_cspace is now wired into p12_task_exit (clean exit + scheduled-TCB SYS_EXIT_USER) AND the fault-kill path (restart budget exhausted); the proof shows install->cap-resolves, clear_cspace->slot-resolves-nothing, reuse-with-own-empty-CSpace->old-cap-NOT-inherited"
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
  "P8scan|[P8-scan] PASS|impl|Validation|TCP-flag scan tier fires SYMMETRICALLY (M2 A6 settled): a lone FIN (0x01) fires rule 202 exactly as NULL (0x00) fires 201 and Xmas (0x29) fires 203 — the three are byte-eq on the same TCP flags offset — while a legit SYN (0x02) fires none. Proves the metal 'FIN-scan doesn't fire' observation was a harness run-ordering/attribution artifact, not a code asymmetry"
  "P8diff|[P8-diff] PASS|impl|Validation|DET-6: JIT<->interpreter differential over ALL live JIT'd rules (L4 port + L2 ARP + TCP-scan), not just THREAT_RULE — native codegen proven == verified interpreter on a match-constant-stressed input set; FLOW/CALL rules interp-only, excluded"
  "P8vlan|[P8-vlan] PASS|impl|Validation|AUD-NET-1: strip_vlan reconstructs the canonical untagged frame for 1-tag and QinQ (guards the VLAN-normalization off-by-2 that re-opened the DET-4 L2/FLOW IDS bypass)"
  "P8n|[P8-napi] PASS|impl|Validation|adaptive NAPI: poll-budget grows under load, idles+re-arms when quiet (spin-poll retired)"
  "P8l|[P8-l2] PASS|impl|Validation|L2 guard: napse-l2guard parity — malformed-ARP FrameDropped; eth-src mismatch DETECTED but OBSERVED (ADR 0023 tri-state: a legit gratuitous/proxy ARP passes, no fabricated FrameDrop)"
  "P8t|[P8-tcp] PASS|impl|Validation|TCP scan detection: NULL/FIN/Xmas/SYN-FIN anomalous-flag scans DETECTED but OBSERVED (observe-by-default — no legit segment dropped), normal SYN/ACK fire nothing (ADR 0023)"
  "P8s|[P8-syn] PASS|impl|Validation|SYN-flood rate-limit: first stateful rule (BPF CALL helper + windowed rate limiter)"
  "P8ss|[P8-synsrc] PASS|impl|Validation|per-source SYN-flood: live rule keyed by IP source — flood one host, others unaffected"
  "P8b|[P8-block] PASS|impl|Validation|threat-feed blocklist: helper #2 (keyed CIDR lookup) — a feed IOC hit is DETECTED but OBSERVED (ADR 0023 matrix L11: a customer touching one IOC is never quarantined on a single hit), clean sources pass"
  "P8sep|[P8-sep] PASS|impl|Validation|DET-SEP / M2 keystone: tri-state decide()/decide_l2 seam ports ADR 0023 onto heqk — observe-by-default (a fired detector defaults to Observe/PASS), blocklist+ARP-spoof OBSERVED (legit customer always passes), Allowlisted mgmt floor never enforced (never self-lock-out), while malformed-frame + operator signature still FrameDrop (the suspicion-free confirmed drops)"
  "P8l2struct|[P8-l2struct] PASS|impl|Validation|M2.1 L2 structural + flood parity: F6 multicast-src / F7 oversize / F8 double-tag VLAN -> FrameDrop; mac-flood is PORT-ROLE-aware — Access->RateLimit(drop) but Uplink/AP->Observe (a legit AP radio's many client MACs are NEVER wire-dropped, ADR 0023 D12); broadcast-storm fires on a raw flood but mDNS/SSDP/LLMNR is exempt (D13); all via the decide_l2() seam"
  "P8flow|[P8-flow] PASS|impl|Validation|M2.2 flow-state (conntrack-equivalent): per-source distinct-dst-port scan counter (rule 1000003) → tri-state via decide() — an UNCONFIRMED sweep RateLimits (bounded, self-reverting DROP), a CONFIRMED sweep (>=CONFIRM distinct SYN-only ports, ZERO establishment) Quarantines (durable DROP); the load-bearing legit-safety proof: a busy source with 150 ESTABLISHED flows and a 100/s new-conn burst NEVER RateLimit/Quarantine (establishment ⇒ not a scan), and the A7/L9 flow-table saturation signal maps 40%-full→no-shed / 85%-full→shed (ADR 0018 anti-spoof + ADR 0023 observe-by-default)"
  "P8shed|[P8-shed] PASS|impl|Validation|M2.3 resource-shed (ADR 0023's 4th suspicion-free inline drop): SELF-REVERTING drops keyed on MEASURED RESOURCE REALITY, never identity — L1 blanket per-source new-conn cap (400/s) DROPs over-cap then PASSes next window (self-revert proof, synthetic clock); L2 conntrack-saturation sheds the top-talker only (un-saturated L9 / small legit source NEVER shed); L3 heqk-native PSI-equivalent (runqueue-depth-derived, synthetic-injected for QEMU; REAL pressure = Gate-R metal) sheds under pressure, not when clear; A8 top-talker sheds first; a legit busy-but-normal source is NEVER shed and the mgmt Allowlisted floor is NEVER shed however hot (routed through decide(), floor short-circuits — never self-lock-out)"
  "P8raflood|[P8-raflood] PASS|impl|Validation|A9-3/A9-5/A9-7 (security-auditor A9 ruling 2026-09-11, heqk-detection-parity.md §5) — the ONE RA-guard arm approved to arm now: an ICMPv6 Router-Advertisement FLOOD from one source MAC on one port (> RA_FLOOD_THRESH=10 per 10 s; a legit router paces to ~4/10 s per RFC 4861) is a RATE wall crossed → FloodRate → bounded, self-reverting RateLimit (wire DROP) on ANY port role, identity-blind. Proven: (a) L4 continuity — a single RA on an Uplink port stays Observe/PASS; (b) the first 10 RAs from a flooder PASS, every RA past the threshold DROPs (no premature drop); (c) per-(port,MAC) isolation — a legit router beside the flooder on the SAME port keeps PASSing mid-flood; (d) SELF-REVERT via the injected clock — the next window's RA PASSes again; (e) A9-5 attribution — rule 121/122 events carry the source-MAC hash (non-zero) instead of the IPv4 src=0 an IPv6 frame can't have; (f) A9-7 evasion visibility — an IPv6 frame with a 9-deep Hop-by-Hop chain (past MAX_V6_EXT) is neither an RA nor dropped but IS surfaced as rule 123 Observe. The Access-port first-sight FrameDrop arm stays EMBARGOED (unreachable live: DEFAULT_PORT_ROLE=Uplink) pending A9-1/2/4/6"
  "P8soar|[P8-soar] PASS|impl|Validation|SOAR event-ring: async non-blocking telemetry exfiltration (verdict engine -> SPSC ring -> EL0 exporter)"
  "P8l7|[P8-l7] PASS|impl|Validation|L7 deep-packet signature: helper #3 payload_match — MQTT CONNECT flagged in the verified fast-path before EL0 services"
  "P8l7o|[P8-l7oracle] PASS|impl|Validation|XC-11/DET-1 helper-arg kernel-read oracle CLOSED: (a) the verifier REFUSES a rule passing a SCALAR (attacker address) to payload_match — arg1 must be a packet pointer; (b) runtime backstop — a verifier-admissible no-touch-load rule (payload_match(pkt+0), min_len=4) run on a 2-byte packet returns INVALID (the interpreter bounds R1 to the packet at the CALL, no OOB read) while a full MQTT packet still DROPs — makes the verifier-folded min_len a per-call runtime reality, independent of a rule's touch-load structure (the prereq before any dynamic/untrusted rule loading)"
  "P8det2|[P8-det2] PASS|impl|Validation|DET-2 per-rule AUTHENTICITY GATE — the SECOND prerequisite (with A4's [P8-l7oracle] kernel-read-oracle close) for any DYNAMIC/untrusted rule source (HYDRA-synced field updates from storage/network, not the image-signed static corpus). rules::rule_sig_ok verifies an Ed25519 signature over the rule BYTECODE against the PINNED rule-signing root (never a caller-supplied key). Proven: (a) an AUTHENTIC signed rule passes the gate AND verify_prevail (memory-safe); (b) FAIL-CLOSED — a rule with one bytecode byte flipped is REFUSED at the gate BEFORE verify_prevail (provenance broken even if still valid BPF); (c) a WRONG signature is refused likewise. An unsigned/tampered dynamic rule never reaches the verifier or the live datapath. Foundation for field-updatable signed detection; the dynamic-load wiring itself (storage/HYDRA transport + a dynamic RState table) is the follow-on"
  "P8l7b|[P8-l7b] PASS|impl|Validation|M2.4 L7/behavioral observe-only parity: C2 beacon (rule 1000040/A10) periodicity, east-west lateral fan-out (1000041/A10), bulk exfil (1000025), DNS tunneling/DGA (1000002/1000021/1000011) — ALL detect (SOC sees them) but route decide(Behavioral)->Observe->wire PASS, NEVER a drop (zero legit-drop risk, observe-only by construction); NTP(:123) beacon EXEMPT (L8 FP-guard #4); beacon jitter/retry-storm + lateral 1-peer/internal->external FP guards hold; host-EDR (1000100-115) correctly EXCLUDED (architecturally N/A on heqk — no process model, routed off-device per ADR 0044 D3)"
  "P12|[P12] PASS|impl|Implementation+Verification|notification objects + capability pub-sub: seL4 Signal/Poll (OR-coalescing), topics-as-caps authority (ungranted subscribe REFUSED via has_rights), blocking WAIT syscall woken by Signal under the scheduler; badge-from-cap; MAX_THREADS->24; DSN-6 fixed"
  "Pr1ipc|[P-r1-ipc] PASS|impl|Implementation+Verification|M5.0 R1 IPC beachhead — the inert Endpoint cap becomes an ENFORCED synchronous-IPC mechanism (seL4-style SYS_CALL/SYS_EP_RECV/SYS_REPLY, ADR 0044 D4 #1 gate). (a) LIVE EL0 rendezvous: a client EL0 TCB SYS_CALLs and a server EL0 TCB SYS_EP_RECVs+SYS_REPLYs through the real syscall path — the Endpoint cap is resolved from each caller's OWN per-TCB CSpace (CORE-2), the message is delivered and the reply returned; (b) FAIL CLOSED: a CALL without the cap / with an R-only cap (CALL needs W) / against a wrong object type / on a stale object is REFUSED (RC_DENIED/RC_BADARG) with no rendezvous; (c) REVOKE SEVERS: minting a CHILD endpoint cap from a PARENT and revoking the PARENT deletes the child + fires the IPC-sever hook (mirrors CORE-1's Frame-unmap-on-revoke) — a TCB parked on it is woken RC_DENIED (not hung), the object generation is bumped, and the kept parent cap fails closed. NOT the app-host/ELF-loader/Wasm runtime (ADR 0044 D5) — the foundation M5.1/M5.2 inherit"
  "Pelf|[P-elf] PASS|impl|Implementation+Verification|M5.1 ELF-loader beachhead — the userspace-server substrate step: a MINIMAL bounds-safe ELF64/aarch64 STATIC loader replaces the hand-asm-stub EL0 task path with parse->map->run, INHERITING the M5.0 enforced Endpoint cap. (a) LIVE: a client LOADED FROM AN ELF (build.rs fixture, parsed + validated) has its PT_LOAD segments mapped into a fresh per-TCB VSpace through the ENFORCED CORE-1 map_frame_cap path (R+X code / RW data, W^X), then runs at EL0 and drives the REAL cap-gated SYS_CALL over an Endpoint{W} resolved from its OWN CSpace — rendezvousing with an asm server(Endpoint{R}), which replies; the loaded client stores the reply into its RW ELF data segment (kernel reads it back). (b) BOUNDS-SAFETY / FAIL-CLOSED: the parser REFUSES truncated / bad-magic / non-ELF64 / wrong-machine / phdrs-out-of-bounds / file-range-out-of-bounds / memsz<filesz / oversize / unaligned / overlapping images for the EXACT right reason, never OOB, never partial-map. (c) W^X: a segment requesting WRITE+EXECUTE is REJECTED (WxViolation) at parse AND at map_frame_cap_in. NOT a dynamic loader / relocations / shared libs / Wasm host (M5.2) / signed catalogue (M5.3) — the multi-year road (ADR 0044 D5); QEMU-green kernel primitive, not a running SOC"
  "Pwasm|[P-wasm] PASS|impl|Implementation+Verification|M5.2 Wasm-host BEACHHEAD — the FIRST minimal sliver of the multi-year Wasm-host road (ADR 0044 D4 #2): verify-then-run ONE signed .wasm module on heqk. (a) a memoryless detection-shaped module classify(port)->{0,1} (returns 1 iff port==4444, rule-1 'block-port-4444'), hand-assembled + Ed25519-SIGNED in build.rs, is Ed25519-VERIFIED (the classical leg of heqk's REAL per-artifact hybrid Ed25519+SLH-DSA — NOT ML-DSA-65, which is not on heqk; the kernel's ALWAYS-ON ed25519-compact primitive, base TCB untouched) then EXECUTED by a BESPOKE MINIMAL no_std interpreter (dependency-free; decodes the MVP subset type/function/export/code + local.get/i32.const/i32.add/i32.eq/end), returning classify(4444)==1 and classify(443)==0 against the known vector, EL1 in-kernel. FEASIBILITY (reported): wasmi 0.32 DOES build no_std for aarch64-unknown-none-softfloat under build-std with alloc only (zero std leakage/no getrandom, ~7 KiB heap) — but folding it in adds ~2 MiB .text (~15 crates) AND overran the QEMU MMU single-2-MiB-block W^X map (build_wx_ram), so the bespoke interpreter ships and wasmi is deferred to the full host. (b) FAIL-CLOSED: a TAMPERED module (one code byte flipped — still valid wasm wasmi would run to a WRONG verdict) is REFUSED at the signature gate and PROVABLY never reaches the interpreter (an INTERPRETED tripwire stays clear); (b') a bad/unsigned signature is refused likewise. NOT the production WASI host / WASI 0.2 components / wasm32-wasip1 shim / signed catalogue (napse-dpi/aegis-guard/qsecbit/dnsxai) / EL0-hosted-at-detection-parity / metal — those are the genuine multi-year build + Gate R (ADR 0044 D5). ~one module of a catalogue; the CONCEPT proven, not the host"
  "Pwasmel0|[P-wasm-el0] PASS|impl|Implementation+Verification|M5.2b Wasm-host AS AN EL0 SERVER (ADR 0044 D4 #2 shape @ minimal scale) — the M5.2 bespoke 5-opcode interpreter's EXECUTION ENGINE (exec_expr) is relocated OUT of the kernel into an ISOLATED EL0 task (its own ASID/TTBR0, own per-TCB CSpace). (a) LIVE: the kernel (TRUST ROOT) Ed25519-verifies the signed fixture and locates classify()'s code expression (bounds-safe EL1 decode) BEFORE any hand-off, then the EL0 host interprets classify(4444) AT EL0 with the bespoke engine (arch-aarch64 wasmhost_stub) and SYS_CALLs the verdict over an Endpoint{W} resolved from its OWN CSpace — an asm server (ipc_server_stub, Endpoint{R}) RECVs it into a result page the kernel reads back (== 1, == the in-kernel reference) and REPLYs: an EL0-isolated module's verdict reaches the kernel through a CAP-GATED path, not a raw kernel call. (b) FAIL-CLOSED: a TAMPERED module yields no verified expression, so the EL0 host is NEVER spawned for it (the sig gate is the kernel's, checked before EL0). (c) ISOLATION: a SECOND EL0 host handed a fault-inducing expression (out-of-range local.get) faults at EL0 and is CONTAINED + restarted + killed by the R1 fault-restart — the kernel survives and the good host's verdict stays intact. NOT the production wasmi/WASI host / wasm32-wasip1 / signed catalogue at detection parity / metal — those are the multi-year road + Gate R + the wasmi-TCB decision (ADR 0044 D5)"
  "Pwasmiel0|[P-wasmi-el0] PASS|impl|Implementation+Verification|M5.3 the REAL wasmi runtime in an EL0 SERVER (ADR 0044 D4 #2 beachhead) — ONE signed .wasm module run through a genuine wasmi 0.32 interpreter that lives in an ISOLATED EL0 binary (el0-wasmhost), NOT the kernel. KEY: the Wasm host is an EL0 server, so wasmi's ~326 KiB .text is loaded via the M5.1 ELF loader into an EL0 task (own ASID/TTBR0, own bump-heap over a kernel-mapped 256 KiB window, own #[global_allocator]) — the kernel TCB gains only the include_bytes! of that image (kernel .text printed to PROVE no +2.3 MB bloat). Build: the EL0 host is a detached-workspace crate compiled to an aarch64 ELF by a NESTED cargo build in build.rs (clean env, own target dir); loader caps raised 64 KiB->2 MiB / 4->8 segments (all bounds/W^X/overflow/overlap checks KEPT). (a) LIVE: the kernel (TRUST ROOT) Ed25519-verifies the module BEFORE hand-off, then the EL0 wasmi host runs classify(4444) AND classify(443) THROUGH wasmi and packs the two verdicts (0x0001_0000 = 1<<16|0 — proving the predicate genuinely COMPUTES, not a constant), returned over the enforced Endpoint{W} cap-gated SYS_CALL -> asm server(Endpoint{R}) -> result page the kernel reads back. (b) FAIL-CLOSED: a TAMPERED module fails verify -> verified_module None -> no EL0 host spawned. (c) ISOLATION: a SECOND EL0 host runs a SIGNED module whose classify is 'unreachable' -> wasmi TRAP -> the host returns the FAIL sentinel (0xFFFF_FFFF) over IPC — a wasm trap is CONTAINED by wasmi AT EL0, host A's verdict stays intact, the kernel survives. Feasibility measured: wasmi builds no_std aarch64-none under build-std alloc, .text ~326 KiB (opt-z+LTO), heap high-water ~9.5 KiB. NOT the full signed catalogue (napse-dpi/aegis-guard/qsecbit/dnsxai) at detection parity, NOT WASI 0.2/wasm32-wasip1 (no host imports are reachable — memoryless predicate only), NOT metal — the multi-year road + Gate R (ADR 0044 D5). ONE real module via a real engine; the production D4 #2 host beachhead, wasmi isolated in EL0"
  "Pwasmparity|[P-wasm-parity] PASS|impl|Implementation+Verification|M5.4 DETECTION AT PARITY (ADR 0044 D4 #4, small scale) — a SIGNED detection-shaped .wasm module with LINEAR MEMORY + a BESPOKE MINIMAL host-import shim (hp_input(ptr,cap)->len reads the input L4 header into linear memory; hp_emit(verdict) emits the alert) run through the REAL wasmi 0.32 interpreter in the ISOLATED EL0 host, whose per-input verdict MATCHES the in-kernel rules::run_l4 case-for-case. The module does REAL detection: reads the big-endian dst-port from mem[2..4] (mirrors THREAT_RULE R1+2/R1+3), LOOPS the blocked-port corpus {4444,23,31337} held in linear memory (== rules.rs RULES, all FindingClass::Signature), emits DROP(2) on a match else PASS(1). (a) PARITY: over an 8-header vector {4444,23,31337,80,443,22,0,65535} the EL0-wasmi packed verdicts EQUAL the kernel's INDEPENDENT rules::run_l4 packing byte-for-byte (non-trivial: >=1 DROP + >=1 PASS), returned over the enforced Endpoint-cap IPC; (b) FAIL-CLOSED: a TAMPERED detection module fails Ed25519 verify -> no EL0 host spawned (kernel trust root); (c) ISOLATION: a malformed 2-byte header makes the module defensively TRAP (unreachable) -> wasmi CONTAINS it at EL0 -> 0xF fail nibble, the parity host's result + the kernel survive. Bespoke 2-import ABI, NOT WASI 0.2/wasm32-wasip1 — the REAL modules (napse/dnsxai/qsecbit) are wasm32-wasip1 stdin/stdout binaries whose imports are a SUPERSET, unreachable here; ONE detection module at parity, NOT the full signed catalogue, NOT metal — the continuing road + Gate R (ADR 0044 D5)"
  "Pwasip1|[P-wasip1] PASS|impl|Implementation+Verification|M5.5 REAL WASI preview1 host (ADR 0044 D4 #4) — TWO signed wasm32-wasip1 STD modules (stdin/stdout, the PRODUCTION module shape: napse-dpi/dnsxai/qsecbit ARE wasm32-wasip1 binaries) run through REAL wasmi 0.32 in ISOLATED EL0 hosts over the genuine WASI preview1 ABI (fd_read/fd_write/environ_sizes_get/environ_get/proc_exit) — NOT the bespoke hp_input/hp_emit shim. Each host reads a 16-B L4 header from STDIN (fd_read pulls the kernel-staged bytes into the module's linear memory), classifies the big-endian dst-port, and writes a 1-B verdict to STDOUT (fd_write); the verdict returns over the enforced Endpoint-cap IPC. (a) COMPUTES: dst-port 4444 -> DROP(2) AND dst-port 443 -> PASS(1) (a single pair proves the predicate runs over real WASI stdin, not a constant); (b) FAIL-CLOSED: a bad-signature module is REFUSED before any EL0 hand-off (kernel trust root). The std module needs a MiB-scale heap window + its own 64-KiB module window (too big for the work page); wasmi's .text stays OUT of the kernel TCB (in the EL0 image). QEMU-proven; metal = a future cm5 concern (the GB5 2-MiB window is too small for a MiB heap)"
  "Pwasip1cat|[P-wasip1-cat] PASS|impl|Implementation+Verification|A2+ (M5.5 catalogue) — the wasip1 host runs a 2-MODULE signed CATALOGUE, not one hardwired predicate: a SECOND, DISTINCT signed wasm32-wasip1 module (a DNS-RPZ sinkhole detector, same WASI stdin/stdout ABI) is run through the SAME EL0 host over two inputs — a blocklisted SUBDOMAIN 'host.malware.example' -> DROP(2) and a benign 'good.example.com' -> PASS(1) — and its verdicts EQUAL the in-kernel dnssink::rpz_blocked reference case-for-case (exact-or-label-boundary-subdomain match on the RPZ corpus malware.example/ads.tracker/c2.evil.test). Same signed-verify-before-EL0 trust root (pinned TRUSTED_MODULE_PK). Together with [P-wasip1] (the port-signature module == rules::run_l4) this is the portable-signed-rule catalogue on heqk: distinct rules as signed wasip1 modules, each at parity with a distinct in-kernel detector. NOT the full production catalogue (napse-dpi/qsecbit are heavier WASI-0.2 components); QEMU-proven"
  "P17|[P17] PASS|impl|Validation|overlay convergence: net-class queue + dual-direction IPS gate (ingress DROP before ring + egress DROP before wire); EL0 monotonic counter; smoltcp EL0 service deferred"
  "PHprod|[PHprod] PASS|impl|Validation|PH1 production datapath: the running-sensor enforce decision (verdict-per-frame -> PASS FORWARDED / threat DROPPED) over a mixed benign+threat batch; the cm5 prod build wraps this loop around a real EL0-driven NIC (self-healing, never halts)"
  "PH6net|[PH6-net] PASS|impl|Validation|PH6 smoltcp net-service stack integration: the smoltcp TCP/IP stack runs ABOVE the P17 rule plane (ingress admits only verdict-PASS frames, egress emits only verdict-PASS frames) and correctly answers an ARP for its own IP; the EL0-isolated netq service + TRNG seed + PCR3 measure is the metal follow-up"
  "PH6mb|[PH6-metalbridge] PASS|impl|Validation|M4 GEM<->smoltcp bridge FIRST-LIGHT (the SAME MetalBridge the cm5 prod drain loop runs, exercised in QEMU): (1) wants()+step() answer an ARP for heqk's control-plane IP through the dual verdict gate (the metal-PROVEN capability — host arping 10.200.0.2 -> heqk smoltcp ARP reply on the real RP1 wire); (2) the broadened is_for_heqk demux CLAIMS a unicast ICMP-echo-for-us and that frame PASSes the rule plane, so it is admitted + TERMINATES at heqk (never hairpin-forwarded) — the actual echo REPLY needs an ICMP/raw socket (smoltcp 0.13 does not auto-answer echo) and is DEFERRED, not faked; (3) the demux rejects a broadcast threat frame. netmetal image, Gate R"
  "P18netcfg|[P18-netcfg] PASS|impl|Validation|M4.1 network CONFIG clients over smoltcp (the first time heqk drives smoltcp UDP, not just ARP): (a) smoltcp dhcpv4 socket EMITS a well-formed DISCOVER (UDP 68->67 broadcast) through the EGRESS verdict gate; (b) DNS query builder + response parser and SNTP request builder + response parser round-trip fail-closed (truncated/wrong-id/wrong-mode -> None); (c) the config INGRESS gate ADMITS benign DHCP/DNS/NTP and REFUSES a threat (UDP:4444); (d) the SACRED air-gap invariant — no server -> resolve_or_fallback returns a static/last-known config and a bounded DHCP attempt TERMINATES (never a boot-block), local SOC unaffected, no account. Real SLIRP lease (10.0.2.15) + DNS via 10.0.2.3 over virtio-net is a reported bonus; the real RP1 GEM/RTL8111 datapath, real DHCP/DNS servers, and a real NTP server (SLIRP has none) are metal (Gate R)"
  "P19pqc|[P19-pqc-kat] PASS|impl|Validation|M4.2a PQC secure-channel crypto PRIMITIVES + KATs (framing-agnostic: the identical KEX+AEAD both the ADR-0002 rustls-hybrid path AND the ADR-0004 Noise path need — brought in ONCE, NO handshake here (that is M4.2b)): (1) ML-KEM-768 / FIPS 203 (RustCrypto ml-kem, no_std) encaps/decaps round-trip + a pinned deterministic KAT shared-secret; (2) X25519 / RFC 7748 §5.2 known-answer vector (x25519-dalek, serial backend on aarch64 softfloat); (3) ChaCha20-Poly1305 / RFC 8439 §2.8.2 AEAD vector + authenticated round-trip + forged-tag REJECT (no AES-NI dependence — right for a softfloat edge); (4) hybrid KEX combiner — HKDF-combine (the EXISTING boot_abi::kdf) the ML-KEM ss WITH the X25519 ss into ONE hybrid secret, Alice==Bob. ALL DETERMINISTIC (fixed seeds/scalars/key-nonce, no RNG) so it is QEMU-reproducible; the real TRNG-fed keygen entropy is metal (Gate R, like the M3.3 VEK note); the handshake + rustls-vs-Noise framing + crypto review are M4.2b"
  "P19noise|[P19-noise] PASS|impl|Validation|M4.2b PQ-HYBRID secure-channel HANDSHAKE over the M4.2a primitives — Noise (ADR 0004 HTP-v2, NOT rustls; the device<->control-plane channel is between two of OUR endpoints). Pattern = an IK-analog Noise_HTP2hybrid_25519+MLKEM768_ChaChaPoly_SHA256: initiator=DEVICE, responder=control-plane whose static keys the device knows from enrollment; each es/ee is a HYBRID {X25519 DH + ML-KEM-768 encapsulation} folded via the M4.2a hybrid_combine before a single Noise MixKey. Noise rev-34 SymmetricState/CipherState/Split implemented to spec (MixHash/MixKey/EncryptAndHash; §12.3 nonce = 4 zero bytes || LE64(counter)); KEM-in-Noise per PQNoise (ePrint 2022/539); device auth = an Ed25519 (PUF-anchored, attest_svc key model) transcript signature over h. PROVES (loopback, deterministic seeded ephemerals): (A) full handshake -> MATCHING crossed transport keys (i.send==r.recv, i.recv==r.send), send!=recv, transcript-hash agree; (B) a transport record round-trips (confidentiality+integrity) and a REPLAY is rejected (advanced nonce counter, separate send/recv CipherStates); (C) a TAMPERED handshake byte -> AEAD auth fails -> ABORT; (D) a WRONG/unenrolled responder static key -> es key diverges -> ABORT; (E) an UNENROLLED device identity -> ABORT; (F) the hybrid combiner binds BOTH the ML-KEM & X25519 legs (transport key secure if either holds) + fresh ephemerals derive a new key (forward secrecy). Real HW-TRNG ephemerals + software-PUF device identity + responder PKI + the real network transport (with an anti-replay WINDOW for reordering) = metal/M4.3 (Gate R); ML-DSA-65 PQ co-signature auth leg = ADR 0002/0004 roadmap"
  "P19segpol|[P19-seg-policy] PASS|impl|Validation|M4.5 SEGMENTATION AUTHORITY — an operator-signed REACH-POLICY delivered over the enrolled Noise channel ARMS segment.rs's per-device reach plane. TRUST SEPARATION (security-auditor C9): the channel authenticates the PIPE, the policy carries its OWN Ed25519 signature by a DEDICATED operator key (distinct from the Noise static), verified on-device before ANY table mutation — so a compromised always-online MSSP can only relay/withhold/replay operator-signed policies, never forge a customer-traffic-dropping one. PROVES (deterministic loopback + fake MSSP + operator key): (1) fail-CLOSED serde (bad magic/version/short/count>64/unknown-reach-code all reject the whole record); (2) fetch over the AEAD counter-advanced transport; (3) signed apply → plane ARMED + the reach matrix holds (Quarantine/InternetOnly LAN-deny, WAN allow, C2 infra gateway allow, C3 mgmt floor allow) provisioned via the policy not set directly; (4) a TAMPERED signature → BadSignature, nothing armed/mutated (fail-open all-allow); (5) WRONG operator key → BadSignature; (6) STALE generation (<=floor) → StaleGeneration, no re-strand; (7) TENANT mismatch → rejected; (8) monotonic gen-advance applies. Plane restored DISARMED (C7/C13). Persisted gen-floor (M3 sealed store) + operator-key TOFU-pinning + metal reconcile-over-the-GEM-bridge = the p15-write/Noise-over-bridge follow-up (Gate R)"
  "P20dnssink|[P20-dns-sink] PASS|impl|Validation|M4 DNS-sinkhole / RPZ — 'refuse a NAME, never a PACKET' (ADR 0023 applied to DNS). A query for a policy-blocked domain (and its subdomains, matched on a label boundary) gets a SINKHOLE A answer (walled-garden IP) crafted from the query; a benign name is NOT blocked (the packet path is never dropped); a query qname carrying a compression pointer (0xC0 — illegal in a query, RFC 1035) is rejected fail-closed. Bounds-safe no_std parse_qname + rpz_blocked + build_sinkhole_response, unit-proven; the inline datapath interception rides the control-plane transport (metal)"
  "P20reconcile|[P20-reconcile] PASS|impl|Validation|M4.5 G2 — the segmentation-ARMING orchestrator (reconcile_reach_policy) end-to-end over the enrolled Noise channel (p15-write two-boot). Composes the shipped+proven primitives: read persisted floor (C12 no-floor⇒no-arm) → TOFU-pin/read the operator key (C10) → fetch_reach_policy over the Session → apply_reach_policy (verify operator sig + tenant + monotonic gen against the floor) → arm segment.rs → best-effort persist the floor. PROVES: a gen=F+5 signed reach policy FETCHED over the channel is applied + ARMS the plane (Quarantine LAN-deny holds) + the floor advances to F+5; a REPLAYED gen=F+2 policy (≤ the new floor) is REFUSED (StaleGeneration — no re-strand); plane restored DISARMED. This is the QEMU half of the U2b gate; metal arming on the wire (via the ControlPlane live Session + host MSSP-sim) is the metal follow-up"
  "P19cp|[P19-controlplane] PASS|impl|Validation|M4.5 control-plane INITIATOR — the on-device half of the full PQ-hybrid Noise handshake over a SMOLTCP-FREE, hand-framed UDP transport that rides the sensor's SINGLE GEM drain (RX tee) + single gem::tx_frame path (the Linux-macb single-ring-owner discipline). No persistent smoltcp socket — InitiatorPending/Session own every field by value, zero no_std lifetime hazard. PROVES (deterministic, in-kernel responder, no hardware): the ControlPlane state machine tick()->start builds msg1, chunks it into BROADCAST UDP datagrams (avoids ARP; responder replies unicast to our MAC, caught by is_for_heqk), the responder reassembles + authenticates the device + writes msg2, ingress() reassembles the msg2 datagrams -> initiator_read_msg2 -> Established with crossed transport keys MATCHING the responder's (send==recv, recv==send). The metal half is the host MSSP-sim replying on the real wire (Increment B, deferred)"
  "P19noiseudp|[P19-noise-over-udp] PASS|impl|Validation|M4.5 Noise-over-UDP DATAGRAM FRAMING — the PQ-hybrid handshake msg1 (~2480 B: ML-KEM-768 encaps key 1184 B + ciphertext 1088 B) EXCEEDS one UDP datagram at the 1514 MTU, so it is split into <=1024-B datagrams prefixed [total_len][offset]. PROVES: (1) a >MTU buffer chunks into 3 datagrams and REASSEMBLES byte-identical; (2) the reassembler is FAIL-CLOSED — 8 malformed datagrams (total>MAX, unaligned offset, off>total, chunk>CHUNK, short non-final chunk, offset+chunk overflow, inconsistent total across datagrams, short header) are each REJECTED (no OOB write, no unbounded state — a reassembly-DoS surface closed); (3) the FULL initiator<->responder PQ-hybrid handshake completes with EVERY message routed through the chunker+reassembler, yielding matching crossed transport keys (a record round-trips). The framing sits BELOW Noise — Noise AEAD still authenticates the reassembled bytes. The real smoltcp-UDP-over-GEM carriage (GemPhy + bounded cm5_enroll_bringup emitting real-TRNG-ephemeral msg1 on the wire) is the metal first-light (Gate R)"
  "P19segpolp|[P19-seg-policy-persist] PASS|impl|Validation|M4.5 segmentation-authority PERSISTENCE across reboot (p15-write two-boot over one virtio-blk backing): the TOFU-pinned operator key (C10) + the monotonic anti-rollback generation floor (C11) SURVIVE reboot in the M3 sealed-store fslog. BOOT1 pins the operator key + applies a gen=5 policy + persists floor=5; BOOT2 reads floor=5 back, REFUSES a replayed gen=3 policy (no re-strand across reboot), applies a gen=7 advance, and REFUSES a DIFFERENT operator key (no silent swap, C10). Plane restored DISARMED. The metal reconcile orchestrator over the GEM bridge = the Noise-over-bridge follow-up"
  "P19enroll|[P19-enroll] PASS|impl|Validation|M4.3 MSSP ENROLLMENT + AUTHENTICATED UPDATE FETCH over the M4.2b PQ-hybrid Noise channel (ties the channel=TRANSPORT to M3.4 OTA=TRUST-ROOT to the M3.2/M3.3 sealed store=PERSISTENCE): (a) ENTROPY #6 — the production MetalEntropy<HwTrng> FAILS CLOSED (boot-health-assert Err on the no-TRNG QEMU target; an ABSENT TRNG → fill Err; a STUCK TRNG → health_check rejects), while a healthy simulated-HW TRNG drives a full handshake through the PRODUCTION from_entropy path; NO seeded path can reach metal (a compile_error refuses securechannel-selftest+cm5, and the ephemeral fields are private with from_entropy the only production constructor); (b) FIXED BUFFERS #7 — repeated handshakes + transport records grow the bump heap by 0 bytes (the handshake/transport alloc::Vec is gone, replaced by in-place fixed buffers); (c) ENROLLMENT over Noise — mutual auth (device Ed25519 transcript signature + the enrolled MSSP static key; a rogue MSSP is rejected), and the enrollment binding SURVIVES REBOOT via the sealed record store (two boots, one virtio-blk backing); (d) AIR-GAP invariant — UNENROLLED is a VALID non-blocking steady state (no MSSP ⇒ full local SOC, enrollment is additive, never a boot precondition); (e) AUTHENTICATED FETCH — a signed candidate fetched over the enrolled transport is handed to ota::stage which VERIFIES it (shared hboot ed25519+SLH-DSA + SVN floor) and stages it, while a TAMPERED or BELOW-FLOOR candidate — delivered just as faithfully by the channel — is REJECTED by ota::verify (the channel is transport only, the boot signature+SVN is the trust root; a compromised MSSP still cannot ship an image hboot would reject); #8 CipherState::key_for_test is gated behind securechannel-selftest (out of the metal profile). DETERMINISTIC loopback + in-process fake MSSP; real mssp.hookprobe.com PKI + real HW-TRNG + real network = metal (Gate R). Deferred (M4.4): anti-replay sliding window + msg1-replay DoS (#9/N1); CBOM kem-0.3.0-pre entry (#4); ML-DSA-65 co-signature (#10)"
  "P19edge|[P19-edge] PASS|impl|Validation|M4.4 SECURE-EDGE ENVELOPE (ADR 0004 crown jewel) on heqk's native stack — closes the last two deferred Noise-transport conditions + lands the WAN-egress kill-switch: (1) ANTI-REPLAY #9 — an RFC 6479 (IPsec anti-replay without bit-shifting; the WireGuard construction) sliding BITMAP window on the Noise transport RECEIVER (AntiReplayRx): in-order records ACCEPTED, in-window OUT-OF-ORDER reorder ACCEPTED, exact REPLAY REJECTED, BELOW-WINDOW (stale) REJECTED, and a forged/tampered record fails the AEAD and NEVER advances the window (RFC 4303 §3.4.3 order — verify integrity BEFORE touching the window, so a forgery can't shadow a genuine record); (2) msg1-replay DoS N1 — a WireGuard/DTLS-1.3 (RFC 9147 §5.1) load-triggered STATELESS COOKIE + token-bucket guard BEFORE the expensive ML-KEM decap/keygen/encap + Ed25519-verify path: a 256-deep forged/replayed msg1 flood is rejected PRE-crypto (ZERO reach responder_read_msg1; the only work forced is one keyed HMAC) while a cookie-vouched legit peer (return-routability proven) reaches AND completes the real handshake, and a wrong cookie is refused; (3) KILL-SWITCH (ADR 0004, fail-closed) riding the M2 netq egress gate (packet::verdict): an ENROLLED device whose secure tunnel is DOWN/COMPROMISED has WAN-bound egress CUT (no plaintext leak) while LAN + local SOC + the PoP-reconnect carve-out stay UP — and a NEVER-ENROLLED / standalone / air-gapped device NEVER arms it (local SOC + LAN up, WAN per local policy: the CLAUDE.md air-gap invariant, never bricked); armed only when Enrolled && tunnel!=Up, disarmed by default = zero datapath change. Also #3 defense-in-depth: ResponderStatic::from_seeds is now securechannel-selftest-only (a metal device is always the initiator, never builds a responder static). QEMU-provable DECISION logic; the full PBR/NAT/encrypted-TUN SASE dataplane at line rate + the real super-PoP tunnel = a larger follow-on + metal (Gate R), scoped not faked (docs/design/heqk-control-plane.md §M4.4). Remaining tracked: dalek-zeroize (#3, partial), CBOM kem-0.3.0-pre (#4), ML-DSA-65 co-signature (#10)"
  "Pm6export|[P-m6-export] PASS|impl|Validation|M6 (ADR 0044 D3 B2) on-device evidence/telemetry EXPORT — the CM5 is a PURE heqk sensor/enforcer; Mission Control + HYDRA + the heavy tokio services are OFF-DEVICE (the existing hookprobe-os cloud stack, ADR 0009), NOT heqk, NOT built here. This is the on-device SENSOR-EXPORT half of B2: (a) a REAL M2 SOAR verdict (rules::run_l4 threat drop -> events ring) is PERSISTED as an RT_EVIDENCE record to the M3 crash-safe store, read back, and EXPORTED — with the QSecBit score — over the M4 enrolled PQ-hybrid Noise channel (enroll_over_noise transport) to a FAKE in-process off-device MC that DECRYPTS (AEAD) + AUTHENTICATES it against the device fingerprint + tenant id (the device is the source of truth, the MC is consumer-only); (b) AIR-GAP invariant (sacred) — UNENROLLED is a valid steady state: should_export=false so NO export is attempted/blocking, yet evidence still PERSISTS locally (M3) and the local SOC (detection/enforcement) is unaffected, never boot-blocking; export is ADDITIVE; (c) ENROLLED-ONLY — the frame is sealed with the enrolled session key, so a rogue/unenrolled consumer lacking the M4 mutual-auth transport key FAILS the AEAD (ChannelReject, never sees the evidence) while the legit MC accepts the same frame; fixed-buffer (no per-export heap). DETERMINISTIC loopback + fake MC in QEMU; the full (a) M3-DISK-persist leg rides the p15-write two-boot. NOT the MC UI, NOT the full evidence graph, NOT metal — real mssp PKI + HW-TRNG + network + real MC/HYDRA cloud = Gate R (ADR 0044 D5)"
  "Psnap|[P-snapshot] PASS|impl|Validation|M3 evidence SNAPSHOT v2 (the sealed ring prod-full persists across reboots): a WRAPPED ring restores IN ORDER across persist/restore (v1 restored the cursor as nev%64 = 0 after a wrap, so the first post-reboot event overwrote an arbitrary record), the next push keeps order, eviction at capacity + SOAR overruns are COUNTED (bounded & honest retention), a legacy v1 blob still restores, and a corrupt cursor is refused. Pure ring/codec logic (snapshot.rs); sealing + the eMMC write stay in prodfull.rs (metal)"
  "P11|[P11] PASS|impl|Validation|device-class transport (sDDF borrow): hardened SPSC (H1 kernel-private cap, H2 ownership table, H3 copy-then-validate, csdb, no-RMW) REJECTS+COUNTS a hostile driver's forged descriptors (V2 index/V4 offset+len+flags/V5 not-owned); LoopDev + honest path pass; metal GemDev/RtlDev deferred"
  "P16sha|[P16-sha] PASS|impl|Validation|crypto primitive: incremental SHA-256 Hasher == one-shot digest across all lengths/chunkings (guards the metal-found short-tail HMAC auth bug)"
  "P15|[P15-seal] PASS|impl|Validation|sealed storage: Encrypt-then-MAC seal/unseal (SHA256 HMAC/HKDF/CTR), tamper+wrong-measurement refused, MBR write-guard (RamDisk); eMMC driver read-only (writes behind p15-write)"
  "P15g|[P15-guard2] PASS|impl|Validation|M3.0 multi-region write-guard (brick-safety): the write allowlist REFUSES LBA 0/MBR + the ACTIVE boot slot + unregistered gaps + past-capacity, ALLOWS keystore+data-volume+inactive-slot, and rejects a bad region registration (LBA-0 inclusion / keystore overlap / past capacity) fail-closed — runs every boot, no device needed"
  "P15p|[P15-persist] PASS|impl|Validation|M3.1 cross-restart persistence: over a FILE-BACKED virtio-blk device (behind hal::BlockDev, the identical trait the metal eMMC slots into), boot-1 seals a cookie + writes a data-volume marker through the M3.0 guard and boot-2 (same backing file) reads them back + unseals — seal->persist->reboot->unseal SURVIVES restart (a volatile RamDisk cannot prove this); real eMMC write on brcm,bcm2712-sdhci is metal (Gate R)"
  "P15fs|[P15-fs] PASS|impl|Validation|M3.2 crash-safe log-structured record store on the DataVolume region: (a) N records survive reboot IN ORDER, (b) an injected torn-tail record is DROPPED on recovery while every intact record survives + the store stays writable, (c) a bounded ring evicts oldest-first at capacity and never writes outside the guard, (d) a real evidence Event + QSecBit history record round-trip across reboot; keyless digest integrity (per-record seal.rs encryption is M3.3); QEMU/virtio-blk-proven, real eMMC = metal (Gate R)"
  "P15sf|[P15-sealfs] PASS|impl|Validation|M3.3 sealed data-volume (encryption at rest): record payloads are sealed with HQKSEAL1 (Encrypt-then-MAC) under a Volume Encryption Key that is itself SEALED in the keystore — (b) CONFIDENTIALITY: a raw block read of a slot holding a known Event is ciphertext (ts 0xDEADBEEF / src IP / the 16-B Event image ABSENT on disk, HQKSEAL1 magic present), (c) INTEGRITY: a ciphertext byte flipped on disk WITH the forgeable keyless framing digest recomputed is still MAC-REJECTED at mount_sealed (the seal MAC, not the digest, is the guard) while intact records survive fail-closed, (a)+(d) CROSS-RESTART: the sealed VEK survives reboot (boot-2 loads it) and decrypts the evidence Event + QSecBit history field-for-field; QEMU/virtio-blk-proven, real eMMC write + OTP-bound SRK = metal (Gate R)"
  "P15ota|[P15-ota] PASS|impl|Validation|M3.4 on-device A/B OTA orchestrator + state machine over file-backed virtio-blk: (a) a VALID hybrid-signed candidate is verified by the SHARED boot_abi::verify (HBoot's EXACT verifier + trust root — no 2nd trust root) → staged to the INACTIVE slot only → state=Staged, persisted; (b) an INVALID candidate (bad ed25519 sig) is REJECTED verify-before-flip — NO inactive-slot write, active slot + tryboot flag untouched; (c) flip→Trying→simulated healthy trial→Committed (new slot active); (d) simulated failed trial→RolledBack (old slot stays active) + a below-floor (svn<floor) DOWNGRADE is refused (SVN floor); (e) OTA state + staged candidate SURVIVE reboot (persisted, driven by the two boots); (f) brick-safety — the candidate write only ever lands in RegionKind::InactiveSlot, LBA 0/MBR + the active slot are guard-REFUSED. QEMU-proven; the REAL firmware one-shot flip + PM-watchdog trial reset + power cycle are hboot/metal (Gate R)"
  "P15otafat|[P15-otafat] PASS|impl|Validation|B2 OTA DELIVERY — locate the inactive A/B slot inside the SHARED FAT32 boot partition + stage a candidate into its REAL sectors (genuine mkfs.vfat image over virtio-blk): the read-only fat.rs locator parses the MBR → the FAT32 BPB → walks the root directory to HEQK8-B.IMG → follows its cluster chain to a CONTIGUOUS LBA run (fail-closed if fragmented/absent), registers that run as RegionKind::InactiveSlot, and writes a candidate marker through the brick-safety LBA guard (LBA 0 + the active slot + FAT/dir metadata all WriteRefused), read back byte-identical — FAT metadata never mutated (same-size in-place overwrite). QEMU-proven on a real FAT32 fs; the metal eMMC InactiveSlot write arming (emmc.rs clamp) is a separate Gate-R item"
  "AB|[HBoot-AB] PASS|impl|Validation|A/B trial boot: kernel confirms health (hvc #1 disarms HBoot's EL2 watchdog) or firmware falls back to the known-good slot"
  "P7|[P7] PASS|plan|Validation|CM5/RP1 metal bring-up"
)

echo "==================================================================="
echo " HEQK Core — Kernel Agent Validator (Hardened Edge Quantum-safe Kernel)"
echo "==================================================================="

# --- Stage 1: build -------------------------------------------------------
echo -n "[build] cargo build ... "
if ! cargo build --features netsvc,securechannel,securechannel-selftest,wasmhost >/tmp/hp_build.log 2>&1; then
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

# --- Stage 1c: WiFi/WPA crypto KAT harness (P-wifi-crypto, host-side) ------
# aes.rs + wpa.rs are #[cfg(feature="cm5")] so they are ABSENT from the qemu-virt
# kernel — their KATs (aes_selftest/wpa_pmk_selftest) would otherwise never run.
# Compile the REAL source (#[path], no drift) and run FIPS-197 + RFC-3394 wrap/
# unwrap/tamper + PBKDF2 PMK + PTK/MIC self-consistency vectors on the host.
echo -n "[P-wifi-crypto] WiFi/WPA crypto KAT ... "
WCK="$(mktemp)"
if rustc --edition 2021 -O tools/wifi-crypto-kat.rs -o "$WCK" >/tmp/hp_wck_build.log 2>&1; then
  if "$WCK" >/tmp/hp_wck.log 2>&1; then
    echo "PASS (AES-128/RFC3394 wrap+tamper, PBKDF2 PMK, PRF PTK, HMAC-SHA1 MIC)"
  else
    echo "FAIL — WiFi crypto KAT:"; sed 's/^/    /' /tmp/hp_wck.log
    rm -f "$WCK"; exit 2
  fi
  rm -f "$WCK"
else
  echo "skip (rustc host build unavailable)"
fi

# --- Stage 1d: design-doc canon references must resolve --------------------
# Source files, tools and readiness docs cite docs/design/<name>.md as canon. A
# dangling reference (three were found missing on 2026-09-10/11 and reconstructed)
# silently breaks traceability, so fail if any cited design doc is absent.
echo -n "[docs]  design-doc canon refs ... "
DOC_MISSING=0
for d in $(grep -rhoE 'docs/design/heqk-[a-z0-9-]+\.md' --include='*.rs' --include='*.md' --include='*.py' --include='*.sh' . 2>/dev/null | sort -u); do
  if [ ! -f "$d" ]; then echo; echo "  MISSING: $d"; DOC_MISSING=1; fi
done
if [ "$DOC_MISSING" -eq 0 ]; then
  echo "PASS (every cited docs/design/*.md exists)"
else
  echo "FAIL — a cited design doc is missing (dangling canon reference)"; exit 2
fi

# --- Stage 2: boot + capture ---------------------------------------------
# TCG emulation of the PQC self-tests is CPU-bound: the old fixed 45 s budget expired
# mid-boot on a loaded host (load 9 on 4 cores, 2026-10-08) and reported 29 phantom
# phase FAILs. QEMU exits via semihosting as soon as the boot completes, so a larger
# budget costs nothing on a pass — only a genuine hang waits it out.
QEMU_TIMEOUT="${HEQK_QEMU_TIMEOUT:-150}"
echo -n "[boot]  qemu virt ... "
timeout "$QEMU_TIMEOUT" $QEMU "$KERNEL" >"$LOG" 2>&1
RC=$?
if grep -q "\[ALL\]" "$LOG"; then echo "clean exit"
elif [ "$RC" = 124 ]; then echo "TIMEOUT after ${QEMU_TIMEOUT}s (load: $(cut -d' ' -f1 /proc/loadavg 2>/dev/null)) — missing markers below may be phantom; rerun on an idle host or raise HEQK_QEMU_TIMEOUT"
else echo "rc=$RC (no ALL marker; possible hang/regression)"; fi

# --- Stage 2b: M3.1 cross-restart persistence (file-backed virtio-blk) -----
# The volatile RamDisk (P15 above) proves the write-window LOGIC but cannot prove
# "survives reboot". A file-backed virtio-blk device — the SAME hal::BlockDev the
# metal eMMC slots into — can: boot twice against ONE backing file and confirm the
# sealed cookie + data-volume marker persisted. Needs the p15-write build (the
# store WRITE path); the eMMC write driver stays cfg(cm5) = NOT built here.
echo -n "[P15-persist] two-boot persistence (virtio-blk, p15-write) ... "
if command -v dd >/dev/null 2>&1 && cargo build --features netsvc,securechannel,securechannel-selftest,p15-write >/tmp/hp_build_p15w.log 2>&1; then
  DISK="$(mktemp)"; B1="$(mktemp)"; B2="$(mktemp)"
  # Factory step: a 64 MiB image with a valid MBR (p1 FAT @ LBA 2048, 129024
  # sectors). The running kernel is FORBIDDEN to write LBA 0 (brick-safety), so
  # the image tool lays the partition table down — exactly as on a real device.
  dd if=/dev/zero of="$DISK" bs=1M count=64 status=none
  printf '\x0c'             | dd of="$DISK" bs=1 seek=450 conv=notrunc status=none  # part type 0x0c (FAT)
  printf '\x00\x08\x00\x00' | dd of="$DISK" bs=1 seek=454 conv=notrunc status=none  # LBA start = 2048
  printf '\x00\xf8\x01\x00' | dd of="$DISK" bs=1 seek=458 conv=notrunc status=none  # sector count = 129024
  printf '\x55\xaa'         | dd of="$DISK" bs=1 seek=510 conv=notrunc status=none  # 0x55AA boot signature
  QEMU_BLK="qemu-system-aarch64 -M virt -cpu cortex-a72 -m 512M -nographic -serial mon:stdio -semihosting \
    -global virtio-mmio.force-legacy=false -netdev user,id=n0 -device virtio-net-device,netdev=n0 \
    -drive file=$DISK,format=raw,if=none,id=hd0 -device virtio-blk-device,drive=hd0 -kernel"
  # 75s cap (was 45s): the p15-write two-boot now also runs the M4.3 securechannel
  # + enrollment gates, whose debug-mode ML-KEM-768 handshakes add real wall time.
  timeout "$QEMU_TIMEOUT" $QEMU_BLK "$KERNEL" >"$B1" 2>&1   # boot 1: write cookie+marker through the guard
  timeout "$QEMU_TIMEOUT" $QEMU_BLK "$KERNEL" >"$B2" 2>&1   # boot 2: SAME disk -> read back + unseal
  cat "$B1" "$B2" >> "$LOG"                     # feed both boots' markers into the report
  if grep -qF "[P15-persist] PASS" "$B2"; then
    echo "PASS (cookie+marker survived restart)"
  else
    echo "FAIL/see report"; echo "  --- boot1 tail ---"; grep -F "[P15-persist]" "$B1" | sed 's/^/    /'
    echo "  --- boot2 tail ---"; grep -F "[P15-persist]" "$B2" | sed 's/^/    /'
  fi
  rm -f "$DISK" "$B1" "$B2"
else
  echo "skip (no dd, or p15-write build failed — see /tmp/hp_build_p15w.log)"
fi

# --- Stage 2c: B2 (M3.4) OTA DELIVERY — locate the inactive A/B slot inside the
# SHARED FAT32 boot partition and stage a candidate into its REAL sectors. Builds a
# genuine mkfs.vfat FAT32 image (heqk8.img + heqk8-b.img copied in), boots heqk against
# it as virtio-blk, and the kernel parses the BPB + walks the root dir + follows the
# cluster chain to HEQK8-B.IMG, registers that run as InactiveSlot, and writes a
# candidate through the brick-safety guard. Needs the p15-write kernel from Stage 2b.
echo -n "[P15-otafat] FAT32 locate + guarded slot-B candidate write ... "
if command -v mkfs.vfat >/dev/null 2>&1 && command -v mcopy >/dev/null 2>&1 \
   && command -v dd >/dev/null 2>&1 && [ -f "$KERNEL" ]; then
  FATDISK="$(mktemp)"; PART="$(mktemp)"; CAND="$(mktemp)"; BO="$(mktemp)"
  # A 63 MiB FAT32 partition image (>= FAT32 min clusters), 512-B clusters.
  dd if=/dev/zero of="$PART" bs=512 count=129024 status=none
  mkfs.vfat -F 32 -s 1 "$PART" >/dev/null 2>&1
  # A 256 KiB candidate; copy it as BOTH slots (fresh FS => each contiguous). HEQK8-B.IMG
  # is the INACTIVE target the kernel must locate; HEQK8.IMG is the active slot (never written).
  dd if=/dev/urandom of="$CAND" bs=1K count=256 status=none
  mcopy -i "$PART" "$CAND" ::HEQK8.IMG   >/dev/null 2>&1
  mcopy -i "$PART" "$CAND" ::HEQK8-B.IMG >/dev/null 2>&1
  # A 64 MiB disk with an MBR: FAT partition @ LBA 2048 (129024 sectors); the running
  # kernel is FORBIDDEN LBA 0, so the tool lays the table + copies the FS in (as on metal).
  dd if=/dev/zero of="$FATDISK" bs=1M count=64 status=none
  printf '\x0c'             | dd of="$FATDISK" bs=1 seek=450 conv=notrunc status=none  # type 0x0c (FAT)
  printf '\x00\x08\x00\x00' | dd of="$FATDISK" bs=1 seek=454 conv=notrunc status=none  # LBA start 2048
  printf '\x00\xf8\x01\x00' | dd of="$FATDISK" bs=1 seek=458 conv=notrunc status=none  # count 129024
  printf '\x55\xaa'         | dd of="$FATDISK" bs=1 seek=510 conv=notrunc status=none  # 0x55AA sig
  dd if="$PART" of="$FATDISK" bs=512 seek=2048 conv=notrunc status=none
  QEMU_FAT="qemu-system-aarch64 -M virt -cpu cortex-a72 -m 512M -nographic -serial mon:stdio -semihosting \
    -global virtio-mmio.force-legacy=false -netdev user,id=n0 -device virtio-net-device,netdev=n0 \
    -drive file=$FATDISK,format=raw,if=none,id=hd0 -device virtio-blk-device,drive=hd0 -kernel"
  timeout "$QEMU_TIMEOUT" $QEMU_FAT "$KERNEL" >"$BO" 2>&1
  cat "$BO" >> "$LOG"
  if grep -qF "[P15-otafat] PASS" "$BO"; then
    echo "PASS (located HEQK8-B.IMG in FAT32 + staged candidate through the guard)"
  else
    echo "FAIL/see report"; grep -F "[P15-otafat]" "$BO" | sed 's/^/    /'
  fi
  rm -f "$FATDISK" "$PART" "$CAND" "$BO"
else
  echo "skip (no mkfs.vfat/mcopy/dd, or no p15-write kernel)"
fi

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
