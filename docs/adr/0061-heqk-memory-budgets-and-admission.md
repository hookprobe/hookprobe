# ADR 0061: heqk memory discovery, budgets and admission

**Status:** 🟡 Proposed (2026-11-11). Needs operator review.

**Scope:** hboot, os/kernel (MMU, frame allocator, caps/Untyped, cfgd admission, telemetry).

**Related:**
- ADR 0060 (cores and the MG memory reserve);
- ADR 0062 (assurance);
- `docs/design/heqk-wan-routing-architecture-2026-11-11.md`.

## Context

| # | Gap | Status | Evidence |
|---|---|---|---|
| M1 | The CM5 boot map covers 4 × 1 GiB; RAM above 4 GiB is unmapped | PARTIAL | `arch-aarch64/src/mmu_cm5.rs:5-6, 33` |
| M2 | The firmware DTB is passed in `BootInfo.dtb_pa`, but `/memory` and `/reserved-memory` are never parsed | NOT IMPLEMENTED | `hboot/src/boot.s:26`; `boot-abi/src/lib.rs:155`; `kernel/src/main.rs:538` |
| M3 | CM5 frame pool is 768–896 MiB, bump-allocated, with no free | PARTIAL | `mmu_cm5.rs:405-425` |
| M4 | The QEMU frame allocator has a free list | IMPLEMENTED (QEMU) | `arch-aarch64/src/mmu.rs:164, 254` |
| M5 | The kernel heap is a 1 MiB bump allocator | IMPLEMENTED (by design) | `kernel/src/heap.rs:1-10` |
| M6 | Capacities are compile-time constants (routes 16, NAT 4096, IPv6 flows 256, …) | IMPLEMENTED (defaults) | `hal/src/policy.rs:35-41`; `arch-aarch64/src/nat.rs:18`; `ip6lan.rs:17-22` |
| M7 | Untyped/retype/revoke exist, QEMU-backed | PARTIAL | `kernel/src/caps.rs:1-31` |
| M8 | The manifest carries no RAM or CPU facts | NOT IMPLEMENTED | `kernel/src/capabilities.rs:1-25` |
| M9 | No memory-pressure signal | NOT IMPLEMENTED | — |
| M10 | CM5 RAM variants | UNKNOWN in the repo | Read the real value from the DTB at boot |

## Decision

**D1. Discover RAM once.** hboot parses the DTB (or ACPI/UEFI on cloud and x86) for usable and
reserved regions. They are measured into the boot record and passed in BootInfo. The kernel maps
all usable RAM and records `ram_usable` in the Platform Manifest's hardware section.

**D2. Partition all memory into budgets.** Every byte belongs to a budget backed by Untyped, or to
the unassigned reserve:
- kernel fixed (page tables, stacks, per-core packet pools);
- the kernel data plane (FIB node pools per address family, NAT/conntrack shards, SA tables, IPv6
  tables);
- one hard Untyped grant per EL0 service;
- telemetry and evidence rings (bounded, honest retention);
- the **MG reserve, ≥ 64 MiB** (ADR 0060 D9), never offered to tenants;
- the headroom reserve (a profile percentage).

**D3. Frame allocator:** free lists with per-core caches, and an ABA-safe pop (ADR 0060 D3). The
kernel heap stays a bump allocator for boot-time objects only.

**D4. Admission.** Creating a VRF, tenant, peer or tunnel, or raising a max-prefix, **reserves**
its budget out of the reserve when the configuration is staged. If the reserve can't cover it,
cfgd refuses with a reason. There is no optimistic allocation and no overcommit.

**D5. Pressure handling:**
- **The kernel never allocates at runtime outside its reserved pools.**
- **Per-budget watermarks** trigger shedding inside the service's own protocol: bgpd refuses new
  paths and enforces max-prefix on the offending peer; ribd moves a VRF to semantics-safe
  selective FIB download; telemetry drops the oldest records and counts the drops.
- **A data-plane pool exhausted** takes the ADR 0023 self-reverting resource-shed path, keyed on
  resource facts.
- **Inspection overload** follows the per-interface fail-open/fail-closed policy; confirmed-attack
  drops continue in both modes.

**D6. Scaling.** Each capacity = budget bytes ÷ measured per-unit cost, bounded by its CPU share
(ADR 0060). More RAM raises the capacity that admission can grant; it never raises the default
allocation.

**D7. Safety boundaries vs defaults:**
- **Safety boundaries (independent of RAM):**
  - recursion depth ≤ 4;
  - an ECMP width ceiling;
  - label stack ≤ 3;
  - parser bounds;
  - mandatory per-peer max-prefix;
  - punt pps caps;
  - every service has a budget;
  - every byte is budgeted;
  - the headroom reserve.
- **Implementation defaults to be replaced by budget-derived values:** `ROUTE_MAX`, NAT 4096, IPv6
  64/256, `MAX_THREADS` 36, the 1 MiB heap, the 128 MiB pool, the 4 GiB map, the 16 KiB HQCFG1
  size (handled by policy objects), and the tunnel split limit of 8.

## Consequences

- A manifest schema change: a hardware section (cores/topology, RAM regions, crypto extensions,
  NIC queues and offloads, PMU) and a budget map. Runtime pressure is telemetry and is never
  written into the manifest.
- The qualification harness (routing design doc §7) measures the cost coefficients that feed D6.
