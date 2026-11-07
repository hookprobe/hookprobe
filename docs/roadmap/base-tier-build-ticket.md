# Build Ticket — Base tier `hookprobe-bcm2712` ($50 stock Pi 5 / CM5)

**Status:** 🟡 Ready to build (v1, 2026-07-15). Phased. Derived from the base-tier consensus spec v0.1.
**Scope (in):** BCM2712 (4× Cortex-A76 @ 2.4 GHz), macb/GEM GbE behind RP1, `rpi-6.12.y` edge kernel
(2712/16K + v8/4K), **zero-BOM** — no add-on PCIe hardware.
**Scope (out — module tiers, separate doc):** i226 / `xdp_native` / AF_XDP zero-copy / hugepages, NPU /
`wasi-nn: npu`, CM5 PCIe-switch carrier.
**Canon:** ADR 0031 (base-tier amendment) · ADR 0014 D6 · ADR 0021 D7 · ADR 0003 (token vocabulary) ·
ADR 0018/0023 (shed invariant) · ADR 0005 (eBPF detection) · ADR 0032 (edge kernel) · ADR 0020 (pentest
harness) · ADR 0015/0016/0017 (registry, signing, AOT).

---

## ⛔ Two must-fix bugs — bake these into the acceptance criteria of their phase, do not "fix later"

1. **Phase 2 — eBPF token-bucket refill must be fixed-point integer, never float.** eBPF has no FP; the
   spec's `rate * dt_ns / 1e9` truncates to **0** at sub-second (per-packet) `dt`, so tokens stick at 0
   and **every new flow drops under tier ≥ 1 — including legitimate ones**, violating "a legitimate
   customer always passes" exactly when it matters. Store tokens **scaled** (milli-tokens) or carry a
   fractional remainder. Acceptance test: a legit new-flow burst at line rate passes while tier ≥ 1.
2. **Phase 4 — SDOT needs the explicit `core::arch::wasm32` relaxed-dot intrinsic + a two-stage gate.**
   Plain `core::simd` does **not** emit `i32x4.relaxed_dot_i8x16_i7x16_add_s`; the feature flag alone
   changes nothing. Gate: (a) the `.wat` contains the relaxed-dot opcode (Rust→Wasm did its job), **then**
   (b) the `.a76.cwasm` disassembly contains an `SDOT` instruction (Cranelift did its job). If (b) fails,
   the feature still ships but the "full SDOT throughput" claim is **dropped** until the lowering lands.

## Cross-cutting invariants (release-blocking, apply to every phase)

- **Legit customer traffic always passes** — no phase may add a drop keyed on identity/suspicion; only
  proven attack / resource-reality (ADR 0023).
- **Fail-open by default** — any map-read / clock / parse failure → PASS.
- **Observe by default** — tier 0 / MONITOR mode is a no-op drop-wise (ADR 0023).
- **Everything signed** — cosign + ML-DSA-65/Ed25519 hybrid; SBOM/CBOM per image (ADR 0016/0002).
- **Capability-gated, not hardware-branched** — code asks for a flat token (ADR 0003 Principle 5), never
  board identity.
- **Benchmark before claim** — no speedup asserted that telemetry-analyst hasn't measured (ADR 0031).

## Phase dependency graph

```
P0 (kernel: +PTP, rebuild) ──┬─► P1 (tuning profile) ──┐
                             ├─► P2 (shed-v2 eBPF) ─────┼─► P5 (image + metal validation)
                             ├─► P3 (PTP userspace) ────┤
                             └─► P4 (AOT dotprod + DGA) ─┘
```
P0 gates everything (it's the kernel). P1–P4 are independent of each other and can proceed in parallel
once P0's kernel is in hand; P5 integrates. Recommended serial order by ROI: **P0 → P2 → P1 → P3 → P4 →
P5** (shed-v2 and the tuning profile are the two zero-BOM flood-hardening wins; do them first).

---

## Phase 0 — Edge kernel: add PTP, rebuild both flavours, gate

**Goal.** Produce a new `rpi-6.12.y` edge kernel that adds IEEE-1588 HW timestamping to the existing
BTF/PSI/conntrack edge deltas, for both `2712` (Pi5/CM5, 16K) and `v8` (Pi4/CM4, 4K) flavours. This is
the only phase that touches the kernel.

**Changes.**
- `builder/build-edge-kernel.sh` — in the inline config heredoc (currently ends at the
  `CONFIG_NF_CONNTRACK_PROCFS=y` block ~L116) add:
  ```
  # --- PTP / IEEE-1588 hardware timestamping (macb TSU behind RP1) — base-tier time-truth (ADR 0031 §B) ---
  CONFIG_PTP_1588_CLOCK=y
  CONFIG_NET_PTP_CLASSIFY=y     # auto-selected by PTP consumers; assert it lands
  ```
  The macb TSU driver (`macb_ptp`) compiles automatically once `CONFIG_MACB=y` (already present) **and**
  `CONFIG_PTP_1588_CLOCK=y` — no separate macb symbol.
- Same file, config guard block (the `require_y` list ~L126–140) — add:
  ```
  require_y CONFIG_PTP_1588_CLOCK
  ```
- **Explicit NON-goal (assert, don't add): NO hugepages.** Per ADR 0031 §C reconciliation,
  `CONFIG_TRANSPARENT_HUGEPAGE`/hugetlb are module-tier (AF_XDP UMEM) only. Add a negative guard so a
  future careless merge can't sneak them into the base kernel:
  ```
  grep -q '^CONFIG_TRANSPARENT_HUGEPAGE=y' "$BUILDDIR/.config" && die "config guard FAILED: hugepages are module-tier (AF_XDP), not base (ADR 0031 §C)"
  ```

**Build.** `builder/kernel-build/run-both.sh` (or `FLAVOUR=2712` then `FLAVOUR=v8`) → two
`linux-image-6.12.94-*-hookprobe-edge_*.deb`. Bump the `-hookprobe1` package revision so the image
picks up the new build.

**Acceptance gates.**
| Gate | Check |
|---|---|
| Config guard | `config guard PASS` including the new `CONFIG_PTP_1588_CLOCK`; negative hugepage guard passes; BTF/PSI/conntrack guards unchanged-green. |
| Both flavours | 2712 (16K, `bcm2712-rpi-cm5-cm5io.dtb`) **and** v8 (4K, `bcm2711-rpi-4-b.dtb`) `.deb` built. |
| Boot (QEMU/metal) | `/sys/class/ptp/ptp0` present; native `/sys/kernel/btf/vmlinux` present; `/proc/pressure/*` present. |
| **§5 metal gate — test, don't assume** | On a real Pi 5/CM5 on `rpi-6.12.y`: `ethtool -T <macb-if>` reports **hardware** rx/tx timestamping + a PHC index. If the GEM instance behind RP1 does *not* expose the TSU, PTP (Phase 3) is de-scoped and `ptp_hw` stays ungranted — record the finding, don't fake it. |

**Definition of done.** New signed-nothing-yet kernel `.deb`s exist for both flavours, boot to a shell,
and the macb PHC is confirmed real on metal (or PTP is explicitly de-scoped with evidence).

---

## Phase 1 — Base tuning profile `hookprobe-tune-bcm2712` (zero-BOM, config-only)

**Goal.** A manifest-keyed systemd oneshot that tunes the single-queue macb dataplane for the A76, inside
the cgroup-v2 budget model (no `isolcpus`).

**Changes.**
- New unit `base/units/hookprobe-tune-bcm2712.service` (oneshot, `After=network-pre.target`, keyed off
  the Platform Manifest — runs only where the profile matches / `tc_bpf` granted).
- `platforms/rpi5.yaml` + `platforms/rk3588.yaml` — add a `dataplane_tuning` block (the seam ADR 0031
  named; one file per platform, no code branch).
- Settings applied:
  - **Threaded NAPI ON** — `/sys/class/net/<if>/threaded=1` (the load-bearing change: softirq RX becomes
    a cgroup-accountable kthread; closes the CPUQuota-blind-to-softirq hole).
  - **cpusets** — macb IRQ `smp_affinity` → core 0; detection slice `AllowedCPUs=2-3` (QSECBIT/NAPSE
    epochs). No `isolcpus`/`nohz_full`.
  - **RPS — DEFAULT OFF** (reconciled: ADR 0031 says default-off; the draft's default-on is not adopted).
    Opt-in only via a `dataplane_tuning.rps` manifest flag, and when enabled **mask = core 1 only** so
    stack processing never shares a core with the detection cpuset (2–3). Rationale: at 1 GbE a single
    A76 core handles RX softirq; RPS adds IPI + cache-bounce and can be a net loss.
  - **GRO ON** (global) — TC-BPF runs post-GRO; disabling GRO taxes the legit pass-through path.
  - **big.LITTLE (rk3588 only)** — pin NAPI + detection workers to A76 cores, housekeeping to A55.

**Acceptance gates (spec §2.3 — none may be waived).**
| Gate | Threshold |
|---|---|
| **l2guard vs post-GRO skb** (the sharp one) | `l2guard.bpf.c` runt/length/bounds logic is **correct for GRO-coalesced skbs up to 64 KB** on the TC-ingress path (clsact runs *after* GRO). **Do not ship until verified.** Fix options if it mis-fires: make l2guard `gso_size`-aware (validate the segment, not the coalesced length), or disable GRO on the monitored iface only. |
| iperf3 pass-through | throughput with profile on vs off: **no regression > 3%**. |
| Flood (SYN+UDP at line rate) | detection epoch-deadline misses **< 1%** with profile on. |
| RPS IPI (only if enabled) | `perf stat` IPI delta **< 5% of a core** at line rate, else keep RPS off. |

**Definition of done.** Profile applies at boot on Pi5/CM5, all four gates green, epoch budget holds
under flood.

---

## Phase 2 — DDoS resource-shed v2 (eBPF PSI pressure valve)

**Goal.** Move the primary shed mechanism from the 10 s nft reconciler into an eBPF token bucket driven
by a PSI watcher — reaction 10 s → ~1 s, dropping at TC/XDP cost — **preserving every v1 invariant**.

**Changes.**
- New userspace `hookprobe-psid` (housekeeping slice, hard `CPUQuota`) — registers PSI **trigger FDs**
  on `/proc/pressure/{cpu,memory}`, blocks in `poll(2)`, writes tier `0..3` + `r_base_pps` +
  `heartbeat_ns` into a pinned `BPF_MAP_TYPE_ARRAY` (`/sys/fs/bpf/hookprobe/shed_ctrl`). Hysteresis:
  step down one tier only after 5 s below the lower trigger. Tier table per spec §3.2.
- `modules/napse-capture/bpf/napse_detect.bpf.c` — add the fast-loop token bucket **after** the
  conntrack-established fast-pass, **before** the per-source SYN window (established flows are never
  shed). New `shed_bucket` `LRU_HASH` (65536). Refill inline from `bpf_ktime_get_ns`, no bpf_timers.
- Demote the nft `hookprobe_resource_shed` table to **fallback** (software-floor platforms) + defence-in-
  depth; keep its Layer-2 conntrack-saturation guard unchanged.
- New flat capability token **`resource_shed_v2`** (ADR 0003 table).
- Telemetry: `SHED_V2` event type on the existing 1 MiB ringbuf (tier, effective rate, disposition).

**Must-fix (#1) baked into acceptance.** Fixed-point integer refill (scaled milli-tokens / fractional
remainder). **No float anywhere in the BPF program.**

**Acceptance gates.**
| Gate | Check |
|---|---|
| Verifier | program loads on the Phase-0 kernel (BTF/CO-RE), no verifier rejection. |
| **Tier 0 = fully disabled** | below all triggers, the bucket is bypassed — observe-by-default intact. |
| **Fail-open** | stale heartbeat (> 30 s) or map-read error ⇒ treated as tier 0 (PASS), never "hold last tier". |
| **Legit-passes-under-flood** (#1 regression) | at line rate with tier ≥ 1, a legitimate new-flow burst still passes — proves the refill accumulates, not truncates. |
| Self-revert | pressure drops ⇒ tier drops ⇒ buckets stop biting ⇒ LRU ages out; no persisted state. |
| Reaction latency | PSI trigger → tier write → first shed within ~1 s (vs ≤ 10 s nft). |
| Harness | ADR 0020 netns-DUT: flood engages shed, self-reverts; `0.7-separation-matrix` gate green. |

**Definition of done.** Under a real flood on the netns DUT, shed-v2 engages sub-second, drops the flood
at TC cost, self-reverts, and a concurrent legit client is never dropped.

---

## Phase 3 — PTP time-truth wiring (userspace)

**Goal.** Turn the Phase-0 macb PHC into disciplined nanosecond timestamps feeding NAPSE.

**Changes.**
- Ship `ptp4l` + `phc2sys` in the housekeeping slice; discipline the system/PHC clock.
- Expose PHC-disciplined timestamps into the telemetry pipeline (NAPSE kill-chain sequencing, mesh
  correlation).
- New flat token **`ptp_hw`**, granted only where the Phase-0 §5 metal gate passed.

**Acceptance gates.**
| Gate | Check |
|---|---|
| PHC disciplined | `phc2sys` offset converges; `ptp4l` locks to the PHC. |
| Event ordering | NAPSE events carry HW timestamps; sub-microsecond intra-node ordering demonstrable. |
| **Mesh honesty** | Documented: HW timestamps are *locally* precise; cross-node absolute alignment needs a PTP **domain with a master** (no GNSS grandmaster on a base box). Marketing claim is "hardware time-truth per node, disciplined across a mesh domain" — not free cross-node ns alignment. |

**Definition of done.** NAPSE consumes HW timestamps; the mesh caveat is written down, not implied.

---

## Phase 4 — Detection acceleration (A76 AOT dotprod + DGA unstub)

**Goal.** Give the A76 AOT blob `+dotprod`/`+fp16`, and ship the `dga-lm` int8 char-level DGA classifier
as a **pure-CPU** signed Wasm module — no NPU — so QSECBIT's `p_attack` stops returning 0.0 on the
flagship.

**Changes.**
- `builder/refresh-aot.sh` — the `--with-a76` precompile (`-cpu cortex-a76`, already LSE-on) additionally
  targets `+dotprod +fp16`; enable `Config::relaxed_simd` in the Wasmtime config **for the a76 blob
  only**. The a72 baseline is unchanged (still exactly two ARM blobs; signing surface unchanged).
- New module `modules/dga-lm/` — int8 char-level CNN, using the explicit `core::arch::wasm32` relaxed-dot
  intrinsic. CI quantization/model-card stage next to AOT precompile (x86 CI, signed OCI model artifact).
- A72 / no-dotprod fallback: same module recompiled with widening NEON (SMULL/SADALP semantics),
  int8 weights L2-resident.
- Wire QSECBIT `p_attack` to the `dga-lm` score. New flat token **`ml_cpu`**.

**Must-fix (#2) baked into acceptance.** Two-stage SDOT gate (see top).

**Acceptance gates.**
| Gate | Check |
|---|---|
| **SDOT two-stage (#2)** | `.wat` has `relaxed_dot`; `.a76.cwasm` disasm has `SDOT`. If (b) fails: ship without the throughput claim. |
| A76 budget | `dga-lm` ≤ 5 ms per epoch batch, model ≤ 256 KB (L2-resident), within the 50 ms QSECBIT epoch. |
| **A72 budget-gate** (ADR 0014 D6) | if the A72 NEON path misses the epoch, `ml_cpu` is **not granted** there (`present_unsafe`/`absent`) and `p_attack` stays 0.0 — scoped, not global. Do not force it. |
| Determinism | `dga-lm` is advisory/observe-only (C9) → relaxed-SIMD OK per ADR 0021 D7; any persisted training label is re-scored off-device, never taken from the device's fast-path number. |
| Score | QSECBIT composite exceeds the ~AMBER (0.50) ceiling on a genuine DGA input on the flagship. |
| Signing | `dga-lm` cosign + ML-DSA signed, model-carded (SBOM), digest-pinned. |

**Definition of done.** On a Pi 5/CM5, a DGA domain drives `p_attack > 0` and lifts the QSECBIT score; on
Pi 4 the term is honestly scoped-out if it misses budget.

---

## Phase 5 — Integration: new signed image + on-metal validation

**Goal.** Fold P1–P4 onto the P0 kernel, produce a signed base-tier image, and prove it on real silicon.

**Changes.**
- Register the new units/modules (`hookprobe-tune-bcm2712`, `hookprobe-psid`, shed-v2 maps, `ptp4l`/
  `phc2sys`, `dga-lm`) via the registry (ADR 0015); stage per platform.
- Rebuild the image (2712 + v8), sign (ADR 0016/0017/0021 — per-arch/per-microarch digests incl. the new
  a76-dotprod `.cwasm` and `dga-lm`).

**Acceptance gates (gate ladder T1→T4).**
| Tier | Check |
|---|---|
| T1 tests | workspace tests + clippy green (incl. the #1 refill regression + #2 SDOT-disasm check). |
| T2 qemu-user | per-arch smoke. |
| T3 arm64 system VM | boots, self-provisions, manifest classifies `edge-*`/`bcm2712`. |
| **T4 metal (Pi 5/CM5)** | SELFTEST PASS; **tokens granted exactly**: `tc_bpf`, `resource_shed_v2`, `ml_cpu`, `ptp_hw` **granted**; `xdp_native`/`xdp_zerocopy`/NPU **absent** (base tier). Pentest matrix (attack caught + legit passes, both directions). Shed-v2 engages under flood + self-reverts + legit passes. macb HW timestamps live. QSECBIT `p_attack` live. Mirror-liveness selftest green. |

**Definition of done.** A signed base-tier image boots on stock Pi 5/CM5, grants exactly the base-tier
tokens, catches the attack matrix while never dropping a legit client, sheds a flood sub-second, and runs
CPU-native ML detection — zero add-on hardware.

---

## Token summary (flat, ADR 0003 Principle 5)

| Token | Base tier | Introduced by phase |
|---|---|---|
| `tc_bpf` | granted | (existing; the floor/ceiling on macb) |
| `resource_shed_v2` | granted | P2 |
| `ml_cpu` | granted (A76) / budget-gated (A72) | P4 |
| `ptp_hw` | granted (if P0 §5 gate passed) | P0/P3 |
| `gpu_compute` | `policy_denied` (experimental, Phase-2 investigation) | — |
| `xdp_native` / `xdp_zerocopy` / NPU (`edge_ai`) | **not granted** (module tier) | — |

## Traceability

This ticket implements ADR 0031 (base-tier amendment), ADR 0014 D6, and ADR 0021 D7. On acceptance of
each phase, `product-steward` records the gate evidence in `docs/roadmap/BuildPlan.md` (Change Log +
requirement↔ADR↔code↔test↔gate row). Cortex governance: all code/ADR work is **Amber** (operator
reviews); commits/releases/flashing are **Red** (never autonomous).
