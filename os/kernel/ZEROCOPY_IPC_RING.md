# HookProbe-OS — Zero-Copy IPC Packet Ring: Structural Map

**The single most performance-critical structure in the whole OS: how a NIC driver hands 100 Gbps of packets to an IDS/IPS engine in another address space without a copy, without a syscall per packet, and without the kernel touching the data at all.**

Status: design document · Companion to `ARCHITECTURE_BLUEPRINT.md`. This is the "notify-and-pull shared-memory ring" from the blueprint, fully specified. Design is grounded in the proven layouts of DPDK `rte_ring`/mbuf, AF_XDP UMEM, virtio packed/split virtqueues, and VPP `memif` (see `RESEARCH_LANDSCAPE.md` for citations); it adapts them to a **capability-secured seL4-class microkernel**.

---

## 0. The one idea

The microkernel is **not on the data path.** It sets up the ring *once* (maps shared memory into two address spaces, hands out one notification capability) and then gets out of the way. After setup, a packet's journey is: **NIC DMA → hugepage buffer → descriptor index published → IDS reads in place → verdict.** No `memcpy`. No `MsgSend`. No ring-0 transition per packet. The kernel's only runtime role is delivering an occasional wake-up when a core has parked itself to save power. This is what makes microkernel IPC fast enough for line rate — you stop using IPC for the bulk data and use it only for rare control signals.

The trap the design avoids (the QNX lesson): **synchronous message-passing IPC per packet is fatal.** A `MsgSend`/`MsgReceive` round-trip is hundreds of cycles; at 100 Gbps the per-64B-packet budget is **~6.7 ns ≈ ~20 cycles** on a 3 GHz core. You cannot afford a kernel entry per packet. The ring makes the common case *zero* kernel entries.

---

## 1. The three memory regions (what actually lives in shared memory)

A ring is not one array — it is **three regions with different access patterns**, deliberately separated so the cache lines that bounce between cores are as small and few as possible.

```
 SHARED DATASPACE  (one seL4 capability, mapped into NIC-driver VSpace + IDS VSpace)
 ┌──────────────────────────────────────────────────────────────────────────────┐
 │  REGION A — CONTROL BLOCK  (2 cache lines, the ONLY lines that ping-pong)       │
 │  ┌───────────────────────────────┐  ┌───────────────────────────────┐          │
 │  │ cacheline 0  (producer-owned) │  │ cacheline 1  (consumer-owned) │          │
 │  │  prod_head (u32)              │  │  cons_tail (u32)              │          │
 │  │  prod_needs_wakeup (u32)      │  │  cons_needs_wakeup (u32)      │          │
 │  │  <pad to 64 B>                │  │  <pad to 64 B>                │          │
 │  └───────────────────────────────┘  └───────────────────────────────┘          │
 │      ▲ written by producer only          ▲ written by consumer only            │
 │      (false-sharing eliminated: the two hot indices never share a line)         │
 ├──────────────────────────────────────────────────────────────────────────────┤
 │  REGION B — DESCRIPTOR RING  (array[RING_SIZE] of 32-byte descriptors)           │
 │  fixed size, power-of-two count. Holds INDICES + metadata, never payload.        │
 │  desc[0] desc[1] desc[2] ... desc[RING_SIZE-1]   (RING_SIZE e.g. 4096)           │
 ├──────────────────────────────────────────────────────────────────────────────┤
 │  REGION C — PAYLOAD POOL  (array[POOL_SIZE] of fixed 2 KiB frames, hugepage-backed) │
 │  the NIC DMAs packet bytes DIRECTLY here. Descriptors point at frames by index.  │
 │  frame[0] frame[1] frame[2] ... frame[POOL_SIZE-1]                                │
 │  (2 MiB / 1 GiB hugepages → few TLB entries cover the whole pool)                │
 └──────────────────────────────────────────────────────────────────────────────┘
```

**Why the split (descriptor ring ≠ payload).** If you copied packets *into* the ring, every enqueue is a `memcpy` and the ring cache lines carry payload — ruinous. Instead the ring carries only a **descriptor** (which frame, how long, metadata). The payload sits still in Region C from the moment the NIC DMAs it until the IDS is done — **the bytes are never moved.** This is exactly how DPDK (`rte_mbuf` + `rte_mempool`), virtio (descriptor table + buffer pool), and AF_XDP (descriptor rings + UMEM) all do it. `VERIFY` exact sizes against the datapath research; the *structure* is universal.

---

## 2. The descriptor (Region B element)

```c
// 32 bytes — half a cache line, so two descriptors per line, power-of-two friendly.
struct hzr_desc {
    uint32_t frame_idx;    // index into Region C payload pool (which 2 KiB frame)
    uint16_t len;          // packet length in bytes
    uint16_t off;          // start offset within the frame (headroom for encap/rewrite)
    uint32_t rss_hash;     // NIC-computed flow hash (RSS) — steer to the right IDS core
    uint64_t rx_tstamp;    // NIC/PMD hardware timestamp — for latency SLAs & ordering
    uint16_t port_id;      // ingress port
    uint16_t flags;        // HZR_F_EOP, checksum-ok, VLAN-present, ...
    uint16_t verdict;      // IPS: 0=undecided 1=PASS 2=DROP 3=REDIRECT  (written by IDS)
    uint16_t _pad;         // -> 32 bytes total
};
```

`verdict` is the field that makes this an **IPS** ring, not just an IDS tap: the consumer writes its decision back into the same descriptor, and the TX/forward path reads it. Inline enforcement with zero extra copies.

---

## 3. The ring topology: 2 rings (IDS tap) or 4 rings (inline IPS)

A single ring only expresses "producer→consumer." Real packet flow needs to express **buffer ownership** — who is allowed to touch a given frame right now. The proven answer (AF_XDP's model) is **paired rings that pass ownership of frames in a cycle.**

### 3.1 IDS mode (passive tap) — 2 rings
```
  NIC PMD  ──RX ring──▶  IDS engine        (filled frames: driver → IDS)
  NIC PMD  ◀─FILL ring─  IDS engine        (empty frames: IDS returns for reuse)
```
- **FILL ring**: IDS puts indices of *free* frames here; the NIC is allowed to DMA into exactly those.
- **RX ring**: NIC puts indices of *filled* frames here; the IDS consumes them.
- A frame is always owned by exactly one side; ownership moves around the FILL→(NIC DMA)→RX→(IDS reads)→FILL loop. **No allocation on the data path** — the frame set is fixed and recycled.

### 3.2 IPS mode (inline, can drop/forward) — 4 rings
```
  NIC-RX PMD ──RX ring──▶ IDS/IPS ──TX ring──▶ NIC-TX PMD     (forward path)
  NIC-RX PMD ◀FILL ring─ IDS/IPS                              (RX frame recycle)
  IDS/IPS   ◀COMPLETION─ NIC-TX PMD                           (TX frame recycle)
```
- Same FILL/RX pair for ingress. After the IDS sets `verdict`, PASS/REDIRECT frames go on the **TX ring**; DROP frames go straight back on FILL (never transmitted). The NIC-TX driver posts finished transmits on the **COMPLETION ring** so their frames return to the pool. This is the full AF_XDP four-ring model, adapted.

---

## 4. The lock-free protocol (SPSC, one producer + one consumer per ring)

Every ring is **single-producer / single-consumer** — the fastest, simplest correct lock-free structure. Multi-core scaling comes from **many independent SPSC rings** (one per RSS queue / per IDS core), *not* from making one ring multi-producer. This mirrors DPDK's per-core queues and eliminates all cross-core contention on the hot path.

### 4.1 Indices
- `prod_head` — next slot the producer will write. Written by producer, read by consumer.
- `cons_tail` — next slot the consumer will read. Written by consumer, read by producer.
- Ring is **empty** when `prod_head == cons_tail`; **full** when `prod_head - cons_tail == RING_SIZE`. (Use free-running `uint32_t` counters and mask with `RING_SIZE-1` to index — the difference gives occupancy without an ambiguous full/empty state, so you use the whole ring.)

### 4.2 The memory-ordering rule (the part that is subtle and mandatory)
```
PRODUCER (enqueue N descriptors):
  1. read cons_tail  (load-acquire)                 // how much free space
  2. if space < N: apply backpressure policy (§6)
  3. write descriptors into slots [prod_head .. prod_head+N)   // plain stores
  4. STORE-RELEASE prod_head += N                   // <-- publishes the data
     // the release barrier guarantees: no consumer can observe the new
     // prod_head before it can observe the descriptor writes in step 3.

CONSUMER (dequeue):
  1. read prod_head  (load-acquire)                 // <-- sees data iff it sees index
  2. process slots [cons_tail .. prod_head)         // read descriptor + payload in place
  3. STORE-RELEASE cons_tail += processed           // frees the slots
```
- **Producer publishes with store-release; consumer observes with load-acquire.** That single acquire/release pair is the entire correctness argument. Without it, a weakly-ordered CPU can reorder the index update ahead of the payload write and the consumer reads garbage.
- **x86-64 (TSO):** stores are already ordered; the release is essentially a compiler barrier (cheap). **aarch64 (weak):** you need a real barrier (`STLR`/`DMB ISH`) on the release and `LDAR` on the acquire. `VERIFY` exact instructions per arch from the ring-engineering research. **This is why the ring must be arch-aware even though the layout is portable.**
- The **NIC-DMA case adds one rule:** the descriptor's data is written by the *device*, not the CPU. The producer (PMD) must ensure the DMA completion is visible (read the NIC's own "descriptor done" bit, which the NIC orders after the DMA) *before* publishing `prod_head`. The IOMMU/SMMU and the NIC's descriptor semantics provide this; the PMD just respects it.

### 4.3 Batching (amortize the one expensive line)
The only cache line that moves between cores is the index being published. So **publish once per batch, not per packet:** the producer writes 32 descriptors, then does *one* `store-release prod_head += 32`. The consumer likewise advances `cons_tail` once per drained batch. This turns 32 cache-coherency events into 1 — the difference between choking and line rate. Batch size is a tunable (16/32/64); larger = more throughput, more latency.

---

## 5. Notification: poll when hot, sleep when idle (never both wrong)

Pure polling burns a full core even at 0 pps; pure interrupts add latency and syscalls at line rate. The answer is a **signal-and-poll hybrid**, identical in spirit to virtio `EVENT_IDX` and AF_XDP `need_wakeup`:

```
CONSUMER hot loop:
  spin: dequeue; if got work -> process, continue spinning
  if empty for K iterations:
      set cons_needs_wakeup = 1   (store, then a barrier)
      re-check ring once more (avoid lost-wakeup race)
      if still empty: BLOCK on the seL4 Notification capability (kernel entry — rare)

PRODUCER after publishing:
  if (cons_needs_wakeup):
      cons_needs_wakeup = 0
      seL4_Signal(consumer_notification_cap)   // the ONLY data-path kernel call, only when idle
```
- **At line rate:** `cons_needs_wakeup` is never set, so the producer never signals — **zero kernel entries.** The consumer spins and drains. Pure user-space, pure shared memory.
- **At idle:** the consumer parks on the Notification object; the next packet's producer wakes it with one `seL4_Signal`. One core is freed instead of spinning at 100%.
- The re-check-after-arming step closes the classic lost-wakeup race (producer published between "empty" and "arm").
- On seL4 the wake primitive is a **Notification object capability**; on a from-scratch kernel it's your async-IPC/`futex`-equivalent. Either way it is a *control-plane* primitive used only on the busy↔idle transition.

---

## 6. Backpressure (an IPS must define what "full" means)

When the producer finds the ring full, it has exactly two honest choices, and for a security appliance the choice is policy, not accident:
- **DROP (tail-drop):** the NIC's frames have nowhere to go → drop at ingress and bump a counter. Correct for an **IDS** (you'd rather lose visibility than stall the wire) and for DoS resilience (a flood cannot make you consume unbounded memory).
- **BLOCK/PAUSE:** stop pulling from the NIC (let its hardware ring fill and eventually assert flow control). Correct only where **guaranteed inspection** matters more than availability — and dangerous, because an attacker who can fill the ring can now stall your link. **Default = DROP + count + emit a "detector overloaded" event** (the overload is itself security telemetry). This is the enforcement-separation invariant from the HookProbe FreeBSD/QNX tracks, applied at the ring: *never let the inspection layer's saturation silently blind you.*

The `prod_needs_wakeup`/`cons_needs_wakeup` fields also drive the symmetric case (consumer waits when *it* is starved), so both sides degrade gracefully.

---

## 7. Where capabilities make this safe (the microkernel's actual job)

This is what a capability microkernel adds over "just DPDK on Linux": **the ring is unforgeable and minimally shared.**
- The shared dataspace (Regions A/B/C) is a **memory capability** the root task grants to **exactly two** components — the NIC driver and the IDS engine. Nothing else in the system can map it. A compromised USB stack, filesystem server, or app-tier container **cannot even name** the packet buffers.
- The **notification** is a single capability shared by the same two. No ambient authority to signal anyone else.
- The NIC's **DMA is itself capability/IOMMU-gated:** the SMMU/IOMMU is programmed so the NIC can DMA *only* into Region C. A malicious or buggy NIC (or firmware) **cannot DMA over kernel memory or another component's frames** — the classic DMA attack is structurally impossible, not merely unlikely. This is the seL4 + IOMMU story and it is the strongest reason to build the datapath on a capability kernel rather than a monolith.
- Result: the fast path is *both* zero-copy *and* least-privilege. Speed and isolation stop being a trade-off.

---

## 8. Multi-core scale-out (how one ring becomes N)

```
        NIC (RSS spreads flows by hash across H hardware queues)
          │        │        │        │
        HWq0     HWq1     HWq2     HWq3         (H = number of hardware queues)
          │        │        │        │
      [SPSC set][SPSC set][SPSC set][SPSC set]  (one FILL/RX(/TX/CMPL) set per queue)
          │        │        │        │
      IDScore0  IDScore1  IDScore2  IDScore3    (each pinned to a dedicated core)
```
- **One SPSC ring set per (hardware queue ↔ IDS core) pair.** No ring is ever shared by two cores, so there is *no lock and no contention anywhere on the data path* — scaling is linear until you run out of PCIe/NIC bandwidth.
- **RSS** (the NIC's flow hash, carried in `desc.rss_hash`) keeps each flow pinned to one core, preserving per-flow state locality and ordering.
- Each IDS core is **pinned** (scheduler affinity) and its ring + payload pool are **NUMA-local** to that core and to the NIC's PCIe root — remote-NUMA access would double memory latency and wreck the cycle budget.
- **Hugepages**: Regions B/C for each core come from 2 MiB/1 GiB pages so the whole working set is covered by a handful of TLB entries — no TLB thrash during inspection. This is the VMM "hugepages granted to the datapath" hook from the blueprint.

---

## 9. Parameters (the tuning surface, one place)

| Parameter | Typical | Trades |
|---|---|---|
| `RING_SIZE` (descriptors) | 2048–4096 (power of 2) | depth vs cache footprint |
| Frame size (Region C slot) | 2048 B (jumbo: 4096/9216) | headroom vs memory |
| `POOL_SIZE` (frames) | ≥ RING_SIZE × (rings sharing it) + in-flight | never starve FILL |
| Batch size | 32 | throughput vs latency |
| Poll-to-park threshold `K` | ~thousands of empty spins | idle-power vs wake latency |
| Hugepage size | 2 MiB (1 GiB for huge pools) | TLB reach vs granularity |
| Rings per core | 1 set | keep it SPSC, scale by cores |
| Backpressure policy | DROP+count (IDS) / configurable (IPS) | availability vs guaranteed inspection |

---

## 10. Data-path summary (one packet, start to finish, zero copies)

1. IDS core has pre-posted free frame indices on the **FILL ring**; the IOMMU permits the NIC to DMA only into those Region-C frames.
2. Packet arrives → **NIC DMAs bytes straight into a Region-C frame** (copy #0 — the only "move", and it's the unavoidable wire→RAM DMA every system does).
3. PMD (producer) writes one **descriptor** (frame idx, len, hash, tstamp) into the **RX ring**, **store-releases** `prod_head` once per batch of 32.
4. IDS core (consumer), spinning, **load-acquires** `prod_head`, reads the descriptor, and **inspects the payload in place** in Region C — signatures, the userspace BPF/XDP-style programs, QSecBit scoring. **No copy.**
5. IDS writes `verdict` into the descriptor. IDS mode: recycle frame via **FILL**. IPS mode: PASS→**TX ring**, DROP→**FILL** (never sent).
6. Kernel involvement across the whole path at line rate: **none**, except a rare `seL4_Signal` if a core had parked.

That is the structure. Everything else in HookProbe-OS — the capability model, the PMD sidecars, the VFS, the VM/container tier — exists to protect and feed this ring.

---

## 11. One optimization to not forget: thread-local cached indices

The design above bounces exactly one shared cache line (the published index) per batch. There is a further, well-measured win: **each side keeps a private cached copy of the *other* side's index** and only re-reads the shared one when its cache says the ring looks full/empty. Rigtorp's SPSC benchmark shows this cutting cache misses ~300M→15M and lifting throughput ~5.5M→112M items/s over 100M ops. Concretely: the producer keeps `cons_tail_cached` and only re-loads the real `cons_tail` when `prod_head - cons_tail_cached == RING_SIZE` (looks full); symmetric on the consumer. Combined with batch-32 publishing, this turns cross-core coherency traffic from per-op into roughly per-ring-drain. Use `memory_order_relaxed` for the cached copies; the release/acquire pair stays only on the real published indices.

## 12. Reconciliation with the HookProbe Zig implementation

The drafted Zig structs (`RingBuffer` with `head`/`tail` as `std.atomic.Value(u32) align(64)`, `PacketBuffer{ data:[2048]u8 align(64), len, flags }`) are the correct realization of this design. Two refinements to fold in:
- **Keep the `head`/`tail` `align(CacheLine)` split exactly as drafted** — that is Region A's two-cache-line control block, and it is the single most important layout decision. Add the `*_needs_wakeup` fields (§5) into those same padded lines.
- **Prefer the descriptor/payload split (Region B vs C) over an array of full `PacketBuffer`s in the ring.** The drafted `buffers: [*]PacketBuffer` embeds the 2 KiB payload inline in the ring stride, which fattens the descriptor cache footprint. Instead let the ring hold 32-byte `hzr_desc` entries (§2) that index into a separate hugepage `PacketBuffer` pool — this is what DPDK mbuf, virtio, and AF_XDP UMEM all do, and it keeps many descriptors per cache line. The Zig types map cleanly: `desc: [RING_SIZE]HzrDesc align(64)` in Region B, `pool: [*]PacketBuffer` in Region C.

## 13. Sources (proven systems this design mirrors)

- **AF_XDP** four-ring UMEM model (FILL/RX/TX/COMPLETION), `need_wakeup` — [kernel docs](https://docs.kernel.org/networking/af_xdp.html)
- **DPDK** `rte_ring` (separate-cache-line index couples, power-of-two, masked free-running indices) + `rte_mbuf`/mempool descriptor/payload split — [ring_lib](https://doc.dpdk.org/guides/prog_guide/ring_lib.html), [mbuf_lib](https://doc.dpdk.org/guides/prog_guide/mbuf_lib.html)
- **virtio** split/packed virtqueue (the canonical shared-memory ring layout, `EVENT_IDX` notification suppression) — [virtio spec](https://github.com/oasis-tcs/virtio-spec)
- **netmap** slot/buffer-index rings — [netmap(4)](https://man.freebsd.org/cgi/man.cgi?netmap%284%29)
- **Rigtorp SPSC** (cache-line isolation + local cached indices) — [rigtorp.se/ringbuffer](https://rigtorp.se/ringbuffer/); **MCRingBuffer** (batch index publish) — [CUHK](https://www.cse.cuhk.edu.hk/~pclee/www/pubs/ancs09poster.pdf)
- **AArch64 memory ordering** (STLR/LDAR vs x86 TSO) — [MSFT oldnewthing](https://devblogs.microsoft.com/oldnewthing/20220812-00/?p=106968)
- **seL4** shared Frame + Notification zero-copy channel — [Notifications tutorial](https://docs.sel4.systems/Tutorials/notifications.html)

*Cross-references: the capability/IOMMU setup is in `ARCHITECTURE_BLUEPRINT.md` §Zone-1/2; the BPF plane that consumes each packet is in `BPF_THREAT_PLANE.md`; the build sequencing is in `buildPlan.md`; the full research grounding is in `RESEARCH_LANDSCAPE.md`.*
