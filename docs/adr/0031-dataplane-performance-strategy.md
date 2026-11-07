# ADR 0031 — Data-plane performance strategy + per-platform tuning seam

**Status:** 🟢 Accepted (implemented, metal-validated 2026-07-16). Validates a four-frontier "wire-speed
kernel-path optimization" proposal against the *actual* HookProbe data plane and the edge/soft-real-time
reality. Records which frontiers are already banked, which are a real win at OUR packet rates
(1.5–3.7 Mpps at 1–2.5 GbE small packets — real, but not hyperscale 100 GbE), which are premature,
and where the one manifest-driven per-platform tuning seam belongs. Every speedup claim is flagged
for a real benchmark (telemetry-analyst) rather than asserted.
**On-metal (2026-07-16, Pi4 + CM5):** the `macb`→TC-BPF floor + the PSI/conntrack resource-shed are
live and metal-proven under flood; both edge kernels ship `CONFIG_PTP_1588_CLOCK=y` (kernel present,
confirmed). **PTP is an HONEST PARTIAL, not done:** the Cadence GEM (`macb`) TSU is NOT exposed via
`ethtool -T` on Pi4/CM5, so hardware time-sync is not usable and the **`ptp_hw` capability is NOT
granted (not faked)** — the §B "zero-BOM PTP differentiator" is de-scoped pending a real macb-TSU
enablement fact. Shed-v2 (PSI-triggered eBPF token bucket, §E) remains ⬜ not built.
**Deciders:** os-architect (author), verification-engineer (owns the benchmarks that must confirm any
adopted change before an SLA), telemetry-analyst (per-platform pps/latency measurement),
security-auditor (fail-open discipline on any new veto path; the PERCPU stats change touches no drop
decision), product-steward (Cortex traceability — Amber change carries this ADR).
**Relates to:** [ADR 0005](0005-unified-ebpf-detection.md) (the unified XDP/TC detection core these
frontiers optimize), [ADR 0009](0009-soc-brain-edge-cloud.md) / [ADR 0018](0018-inline-quarantine-safety.md)
(the quarantine enforcement layer whose stats maps move to PERCPU), [ADR 0017](0017-authenticated-aot-cache.md)
+ [ADR 0021](0021-multiarch-native-artifact-digests.md) (the `.cwasm` AOT + A72/A76 microarch tiering —
frontier 3.5 is *already* this), [ADR 0023](0023-enforcement-separation.md) (observe-by-default; a
bloom veto that mis-vetoed would have to fail OPEN to respect it — one reason it does not fit our
LPM/CIDR blocklist), [ADR 0003](0003-platform-manifest-schema.md) (the manifest the per-platform
dataplane-tuning block extends).

## Context — the actual data plane (ground truth, not assumed)

Three in-kernel BPF programs carry the hot path; one host EDR program is out of data-plane scope.
The per-packet detection decision is **100 % in-kernel eBPF** — it never touches userspace or Wasm.

| Program | Attach | Per-packet work | Maps |
|---|---|---|---|
| `napse_detect.bpf.c` | **XDP-native** where the driver allows (igc/igb/stmmac/virtio/mlx5…), **TC-clsact** otherwise (all Wi-Fi, bcmgenet) — one core, two thin wrappers (ADR 0005) | parse L2/L3/L4 → `allowlist` LPM (daddr, saddr) → `blocklist` LPM (saddr, daddr) → `nf_conntrack` kfunc (established fast-pass) → `syn_rate` window on SYN | `LPM_TRIE` blocklist (1 M), `LPM_TRIE` allowlist (64 K), `LRU_HASH` syn_rate (256 K), `HASH` role_by_ifindex (64), `ARRAY` cfg (4), **`RINGBUF`** events (1 MB) |
| `quarantine.bpf.c` | **TC-clsact ingress only** (no XDP — Wi-Fi + bcmgenet copy-mode; ADR 0018) | src-MAC exact `HASH` → src-IP exact `HASH`, both ifindex-scoped | `HASH` quarantine_ips (8192), `HASH` quarantine_macs (8192), **`ARRAY`** quarantine_stats |
| `l2guard.bpf.c` | **TC-clsact ingress only** | stateless structural frame check (runt/oversize/QinQ/malformed-ARP) | **`ARRAY`** l2guard_stats only (no per-flow state) |
| `execsnoop.bpf.c` (host EDR, not data plane) | tracepoint | exec record | `RINGBUF`, `LRU_HASH`, `PERCPU_ARRAY` (scratch) |

**Telemetry to userland:** `RINGBUF` everywhere. No legacy `PERF_EVENT_ARRAY` anywhere in the tree.
The userspace loader drains it with `rb.poll(200 ms)` and converts the 32-byte POD `napse_event` to a
JSON line only at the userspace boundary. The ringbuf carries **escalations only** (new-flow, drops),
a small fraction of packets — not line rate.

**Control plane:** the supervisor↔Wasm boundary is a WASI command reading JSON-lines on stdin / writing
JSON on stdout. Wasm runs policy/enrichment/scoring on **escalated events**, never per packet. AOT
(`.cwasm`, ADR 0017) is done and digest-pinned; microarch tiering (baseline Cortex-A72 vs Cortex-A76,
ADR 0021) is done and selected from the signed manifest `hardware.cpu.tier`, fail-closed to baseline.

**Edge reality:** Pi 4 = Cortex-A72 ×4, single-queue bcmgenet, 1 GbE, no LSE. CM5/Pi 5 = A76 ×4. N100 =
x86 ×4, multiqueue **igc** 2.5 GbE (`inline_ips` known-good). The box runs the **whole SOC**, not a
dedicated router — hot path is in-kernel eBPF/TC/XDP, **not** a DPDK poll loop (`crates/hookprobe-manifest/src/xdp.rs`).
Posture is soft-real-time, observe-by-default (ADR 0023).

## Decision — per-frontier verdict

### 1. Probabilistic fast-veto (Bloom filter in XDP) — **SKIP**
A `BPF_MAP_TYPE_BLOOM_FILTER` stores **exact** keys; the blocklist is a **CIDR LPM trie** (you cannot
query a /32 against a bloom of /24s). Type-incompatible with the map it would front. The one exact-match
per-packet map (`quarantine_ips`, /32) *could* be bloom-fronted, but it is tiny (≤8192, usually near
empty — only actively quarantined sources) so its `HASH` lookup is already a single-cache-line O(1); a
bloom adds a lookup and saves nothing. Revisit **only** if a future exact-`/32` mega-feed (millions,
per-packet, mostly-miss) replaces the CIDR blocklist. A bloom veto would also have to **fail open**
(ADR 0023) — moot since we skip. The adjacent *real* question is lookup **ordering** (see Consequences).

### 2. Lockless / zero-copy in-kernel (PERCPU + RINGBUF) — **RINGBUF already done; PERCPU stats = ADOPT**
`RINGBUF` is already universal — bank it, no work. The stats maps (`quarantine_stats`, `l2guard_stats`)
are **global `ARRAY` with `__sync_fetch_and_add` on the PASS path — i.e. an atomic RMW to one shared
cache line on every forwarded packet across all cores.** That is the textbook contended-atomic /
false-sharing hotspot. Move both to `BPF_MAP_TYPE_PERCPU_ARRAY`; the loader sums across CPUs on
`--status` read (rare). Microarch-neutral (the in-kernel BPF JIT already emits A72-vs-A76-correct code).
Highest ROI, lowest risk, touches **no drop decision**. Separate note (not a PERCPU win): `syn_rate`'s
`++w->count` is a **non-atomic** increment on a shared `LRU_HASH` value — a correctness race
(under-counts a flood), not a perf item; it cannot become PERCPU without breaking the shared window
semantics. Make it `__sync_fetch_and_add` for honesty; leave the map type.

### 3. Zero-copy control plane (rkyv/bytemuck) — **AOT already banked; rkyv/bytemuck = SKIP**
AOT (`.cwasm`) already eliminates per-load JIT (seconds → ms cold start), digest-pinned and
arch/microarch-qualified — the real control-plane win is banked. The Wasm boundary is JSON, but it is
**cold**: Wasm sees escalated events (hundreds–thousands/s), not 3.7 Mpps, and the kernel→userspace hop
is already zero-copy (POD `napse_event` read straight from the ringbuf, JSON only at the boundary).
rkyv/bytemuck there optimizes a non-bottleneck. If evidence-WRITE volume to SQLite ever shows as CPU on
Pi 4 (benchmark), that is a storage/IO format question, not a wire-speed one.

### 3.5 A72 vs A76 — **already correct; guard the invariant**
`.cwasm` AOT is the *only* microarch-sensitive artifact; the eBPF objects are JIT'd by the **kernel** at
load, which already targets the running CPU (LSE atomics on A76, none on A72) — so frontier #2's PERCPU
change needs no tiering. The standing hazard (an A76-LSE native blob crash-looping on an A72) is why
selection **fails closed to baseline**; nothing here adds native codegen, so nothing reopens it.

### 4. IRQ affinity + CPU isolation — **ADAPT (per-platform, manifest-driven); full isolation = reject**
Nothing is done today (no `CPUAffinity`, `isolcpus`, `irqbalance` control, RPS/XPS). Full core isolation
is **wrong** for us: a 4-core box running the whole SOC cannot spare 2 cores without starving the
evidence DB / Wasm / UI. But a lighter, **platform-specific** tuning is a real win and belongs in the
manifest, not a hardcode:
- **Multiqueue NICs (igc/ixgbe/mlx5 — already tracked as `known_good_nic_drivers`):** spread RX IRQs
  (RSS/MSI-X) and keep them off the supervisor core; pin `irqbalance` away from migrating them. Real on
  N100 @ 2.5 GbE.
- **Single-queue SoC NICs (bcmgenet):** one RX queue → IRQ affinity is nearly moot; optional RPS only,
  marginal on a 4-core Pi and can hurt cache locality — default off.

## Consequences

- **Adopt now (code owner, not this ADR):** PERCPU stats maps in `quarantine.bpf.c` + `l2guard.bpf.c`;
  atomic `syn_rate` increment. Small, in-kernel, no ABI/drop-path change.
- **New manifest seam:** a per-platform `dataplane_tuning` block (RX-queue steering / irqbalance policy),
  gated on NIC-driver capability the manifest already carries, applied by the reconciler — the same
  pattern the `hookprobe-dataplane.slice` TODO ("derive from manifest per profile") already anticipated.
  One file per platform in `platforms/*.yaml`; no code branch (preserves the one-file invariant).
- **Benchmark before any SLA (telemetry-analyst / verification-engineer):** (a) PERCPU vs global-atomic
  stats bump at line-rate small packets on A72 (Pi 4) + N100 — pps/CPU delta; (b) the LPM-walk ordering
  finding: today every *established* packet pays 4 LPM walks (2 allow, 2 block) **before** the ct
  fast-pass at step 3 — measure whether that is material at 1.5–3.7 Mpps with a large blocklist, and
  whether a policy-safe reorder (ct fast-pass earlier + periodic blocklist re-check) helps without
  weakening "a mid-session flow to a newly-blocklisted IP still drops"; (c) igc RX-steering on N100
  @ 2.5 GbE — pps + p99. No speedup is claimed here that a benchmark has not confirmed.
- **Residual risk:** PERCPU read is slightly costlier for the loader's `--status` (sum-across-CPUs) — a
  cold path, acceptable. The ordering reorder (if pursued) trades a small drop-latency window on a
  freshly-blocklisted established flow for per-packet cost — a policy call, not taken without data.

## Ranking (highest ROI first)
1. **PERCPU stats maps** (frontier 2) — real 4-core contention, low risk, microarch-neutral.
2. **LPM-walk ordering** (adjacent to frontier 1, *not* bloom) — the single biggest per-packet cost;
   benchmark-gated.
3. **Per-platform IRQ/RX-steering** (frontier 4) — real on N100, marginal on Pi 4; manifest seam.
4. **A72/A76 tiering** (3.5) — already done; guard the fail-closed-to-baseline invariant.
5. **rkyv/bytemuck at the Wasm boundary** (3) — SKIP (cold path; AOT already banked).
6. **Bloom veto** (1) — SKIP (type mismatch with LPM/CIDR; quarantine map too small).

---

## Amendment (2026-07-15) — the $50 stock-silicon base tier: tuning recipe, PTP time-truth, RP1 role, BOM-as-capability-tiers, and shed-v2

**Status:** 🟡 Proposed (extends the parent, still Proposed). Records the outcome of a
hardware-acceleration review whose conclusion is: **the base product competes on stock BCM2712 silicon;
every BOM-adding accelerator is an *optional capability tier*, never a base dependency** — which the
manifest/capability-token architecture already handles for free (the base manifest never names hardware
it doesn't have, so the $50 claim stays intact). No code change; every speedup flagged for benchmark
(telemetry-analyst) as in the parent. **Deciders:** os-architect (author), telemetry-analyst
(per-platform pps/latency), verification-engineer, security-auditor (fail-open on shed-v2; trust-boundary
on the NPU sidecar), release-engineer (BOM/tier framing), product-steward (Cortex traceability —
Amber change carries this ADR). **Relates to:** [ADR 0018](0018-inline-quarantine-safety.md) /
[ADR 0023](0023-enforcement-separation.md) (the resource-shed invariant shed-v2 preserves),
[ADR 0021](0021-multiarch-native-artifact-digests.md) D7 (the A76 SDOT compute tier this base-tier
story leans on), [ADR 0014](0014-continuous-improvement-detection-lifecycle.md) (`dga-lm` on the CPU
path), [ADR 0003](0003-platform-manifest-schema.md) (the `dataplane_tuning`/capability tokens added
here), [ADR 0032](0032-custom-edge-kernel-btf-mainline-rp1.md) (the edge kernel the new config lands in).

### A. The RP1 is not a dataplane accelerator — reposition it

The BCM2712 southbridge (RP1: dual Cortex-M3, 64 KB SRAM, DMA, 4-lane PCIe2 to the SoC) cannot do
line-rate packet work: DMA handshakes cost ~70 bus cycles each (sample loss above ~20 Mbit), the M3
cores are **deliberately closed** by Raspberry Pi (no sanctioned code path — the firmware-mailbox route
is ≥10 µs/op; the unofficial firmware-patch route is unfit for a signed/attested OS), and the GbE MAC
behind it is **Cadence GEM (`macb`) with no XDP support in mainline**. This *confirms* the existing
tiering decision (`macb` → TC-BPF floor, `crates/hookprobe-manifest/src/xdp.rs`) is **permanent, not a
gap to close** — do not carry "native XDP on Pi onboard Ethernet" as a roadmap item. RP1's legitimate
roles: (1) **PTP HW timestamping** on the Cadence GEM (§B); (2) an **out-of-band health/tamper channel**
(ADC temp sensor + PIO tamper GPIO) independent of the A76 cores — a watchdog surviving a
CPU-exhaustion attack, feeding the Organism Status story. Marketing posture: not NP7-pps parity —
**detection-intelligence-per-dollar, observe-first** (we already avoid the inline bottleneck ASICs
exist to solve).

### B. PTP hardware timestamping — zero-BOM differentiator

Enable the Cadence GEM's IEEE 1588 HW timestamping (`macb_ptp` + `ptp4l`; kernel config only).
Nanosecond-class flow timestamps sharpen NAPSE kill-chain sequencing and cross-node mesh correlation —
detection-quality most cheap boxes fake in software. New **`ptp_hw`** capability token, manifest-gated
(granted where the MAC + kernel support it). Fortinet's desktop line doesn't market time-truth.

### C. Base-tier ($50 stock Pi5/CM5) single-queue dataplane recipe

`macb` is single-queue → TC-BPF forever; tune for that reality. All userspace/systemd/manifest, one new
kernel config (hugepages); **benchmark before any SLA**:

- **Threaded NAPI** (`/sys/class/net/<if>/threaded=1`) — the load-bearing one: RX softirq work becomes
  schedulable kthreads the **cgroup-v2 budget model can actually govern**. Closes the real accounting
  hole the parent flagged (softirq storms are invisible to `CPUQuota`) — a **DDoS-era
  resource-accounting fix**, not just a perf tweak, and philosophically native to our cgroup-v2-only
  bounding.
- **Static IRQ affinity + cpuset:** NIC RX IRQ → core 0; detection Wasm workers cpuset → cores 2–3; no
  `irqbalance` (not shipped anyway). GRO on.
- **RPS** only on single-queue `macb` (fan RX to cores 1–2) — measure the IPI cost on A76 first;
  **default off, opt-in** (can hurt cache locality on a 4-core Pi).
- **big.LITTLE (RK3588):** pin XDP/NAPI threads **and** Wasm detection workers to the **A76** cores,
  telemetry/housekeeping to A55 — an unpinned scheduler will put the 50 ms-epoch QSECBIT tick on an A55
  and blow the budget. (Scheduling fix, not codegen — cross-ref ADR 0021 D7 residual.)
- **hugepages — deferred to the accelerated tier, NOT base** (reconciled with base-tier consensus
  spec §6, 2026-07-15). `CONFIG_TRANSPARENT_HUGEPAGE` + a hugetlb reservation are needed *only* to
  back **AF_XDP UMEM**, which is a module-tier (igc) concern (§D). The stock macb/TC-BPF base tier has
  no AF_XDP and no use for them, so they ship with the i226 module, **not** the base edge kernel — the
  earlier "cheap on the base tier, add it now" note was wrong and is withdrawn.

Ship as manifest-keyed **`dataplane_tuning`** profiles per platform (the seam the parent's Consequences
already named; one file per `platforms/*.yaml`, no code branch — preserves the one-file invariant).

### D. BOM-bearing acceleration = optional capability tiers (modular-router track), never base

Same OS image; tokens flip. The base $50 manifest grants none of these.

- **i226 NIC module** (igc: native XDP + AF_XDP zero-copy + RSS/MSI-X + 2.5 GbE + PTP) → grants
  **`xdp_native`** + **`xdp_zerocopy`**. igc is **already** in `NATIVE_XDP_DRIVERS` and is the
  known-good NIC behind `inline_ips` on N100 — so the code already anticipates it; the CM5-tier addition
  is validation + a manifest capability, **not a fork** (`napse_detect` already tiers by attach point).
  AF_XDP zero-copy matters specifically for **DPI-under-flood** (userspace reads NIC DMA buffers vs the
  kernel copying every escalated packet through the ringbuf — the difference between DPI surviving a
  flood and DPI being the thing that gets shed). **This tier is where the hugepages deferred from §C
  land** — the AF_XDP UMEM is hugetlb-backed here, and nowhere else. Manifest/validation caveats: validate igc on the
  `rpi-6.12.y` edge kernel (historic Pi 5 probe `-13`/`IGC_ERR_SWFW_SYNC` needing `config.txt` PCIe
  workarounds — pin the fix); some i226 boards negotiate only 1 GbE on Pi 5 (even at 1 GbE the
  native-XDP+zero-copy is the win); pin **i226, exclude i225** (2.5 G errata); and for the **attested**
  tier spec the reference at **supported PCIe Gen2** (~4 Gbps), treating Gen3 forcing as an opt-in
  overclock manifest flag — consistency with the same "no unsanctioned path" stance that kills the
  RP1-M3 idea (§A).
- **NPU module** (Hailo-8L/8/10H via M.2/PCIe, or the RK3588 built-in 6-TOPS NPU) → grants
  **`wasi-nn: npu`** (the token `edge-ai-detector` already declares). **Trust-boundary decision:**
  HailoRT / librknnrt are **proprietary vendor runtimes — they must NOT be host-integral.** Run the
  inference runtime as a **rootless Podman/Quadlet sidecar**, digest-pinned, tight seccomp, exposed to
  Wasm only through a host-function shim behind `wasi-nn: npu` (mirror the WASI-NN WIT signatures so the
  module-facing interface is stable if Wasmtime ever grows a native rknn/HailoRT backend — it has
  **none** today, and swapping to WasmEdge would torch the Cranelift AOT pipeline, ADR 0017). NPU
  inference stays **observe-only** (feeds Detect/alerts, never the inline drop plane) — keeps it
  **C9-clean**. Model conversion (RKNN-Toolkit2 / Hailo Dataflow Compiler) is **x86-only → belongs in CI
  next to AOT precompilation**; verify every op against the support list (unsupported ops silently fall
  back to CPU, 5×+ latency).
- **PCIe arbitration:** Pi 5 has **one** FPC PCIe connector → i226 **or** Hailo, not both. CM5 carriers
  can host a PCIe switch (ASM1182e/ASM2806 class) to run both — an "i226 module" + "NPU module" snap-on
  tier, capability-gated exactly as designed.
- **VideoCore VII (Phase-2 experiment, `gpu_compute` token):** v3dv (mainline Mesa Vulkan, **no blob**)
  + ncnn's Vulkan backend is the only untapped on-die compute — but **"no blob" ≠ "no surface"** (adds
  the Mesa/Vulkan compute stack to a signed image; v3dv's compute path is less battle-tested than
  graphics), and on a tiny DGA-class model the **A76 SDOT path (ADR 0021 D7) may beat VC7 once
  dispatch/queue-submit overhead is counted.** Experiment-behind-token; **measure A76-SDOT vs
  VC7-Vulkan before any roadmap commitment.**

### E. Shed-v2 — PSI-triggered eBPF token bucket (reaction 10 s → ~1 s, invariant unchanged)

The current resource-shed (per-source new-conn cap + conntrack-saturation guard + PSI pressure) is an
**nft reconciler on a 10 s timer** (`base/scripts/resource-shed-reconcile.sh`, `scan_responder.rs`,
ADR 0018/0023). Its only weakness is **reaction latency**, and it drops at nft cost precisely when under
flood. Two-loop redesign, **no invariant change**:

- **Slow loop (userspace, event-driven):** a trivial PSI watcher using `poll(2)` on
  `/proc/pressure/{cpu,memory}` **trigger FDs** (fire in ms on threshold-cross — better than polling
  avg60) writes a single scalar **"pressure tier" (0–3)** into a pinned `BPF_MAP_TYPE_ARRAY`. (PSI
  cannot be read from eBPF directly — hence the scalar bridge.)
- **Fast loop (in `napse_detect`, per-packet):** a per-source **token bucket** *extending the existing
  `syn_rate` `LRU_HASH`* (tokens + last-refill-ts per entry, refill computed inline from
  `bpf_ktime_get_ns`, no timers) whose rate parameter is selected by the pressure tier. **Tier 0 =
  bucket disabled entirely** (observe-by-default holds, ADR 0023); tiers 1–3 tighten the per-source
  new-connection rate.
- **Self-reversion is structural, unchanged:** pressure drops → tier scalar drops → buckets stop biting;
  LRU entries age out; no offense counter, no persisted reputation — the **same properties** as the nft
  layer, engaging within ~1 s and dropping at XDP/TC cost. Keep the nft layer as the **fallback tier for
  software-floor platforms.** EDT (`skb->tstamp`) is **rejected** — it's egress pacing; the problem is
  ingress shedding. **security-auditor:** the bucket must **fail OPEN** on map-read error (tier defaults
  to 0), never fail closed.
- **Threat-model honesty:** this is a $50 edge box protecting itself, not a scrubbing center —
  **sub-second self-reverting self-protection** is the defensible claim at this price, not µs ASIC
  parity.

### Ranking delta (folds into the parent's ranking)

The two **zero-BOM software** items ship first — **(C)** threaded NAPI + pinning + hugepages and
**(E)** the shed-v2 PSI token bucket — both validatable on existing Pi 4 / CM5 metal and both hardening
the base tier under flood. Then **(B)** PTP (config-only differentiator). Then the **capability-tier
hardware (D)** as the modular-router track lands. Every perf number remains benchmark-gated
(telemetry-analyst) per the parent's discipline. The competitive sentence this supports: **ASICs make
packets cheap; we make detection cheap** — ML-backed detection + sub-second self-protection + hardware
time-truth at a price where the incumbent entry box costs 6–8× more before licensing.

---

## heqk migration — see [ADR 0043](0043-heqk-microkernel-substrate.md)

**Coupling: HARD.** Every frontier here (PERCPU eBPF maps, LPM-walk ordering, threaded NAPI, AF_XDP UMEM/hugepages, PSI shed) is a Linux-kernel dataplane primitive and is re-decided from scratch: heqk provides its own per-packet fast path (zero-copy SPSC ring), resource accounting, and NIC IRQ model. The perf *targets* carry over as heqk benchmark goals. → **Phase M2**.
