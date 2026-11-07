# HookProbe-OS — The Object-Capability Model

**Authority as spatial structure: if a compromised packet-inspection sidecar doesn't hold the token for a resource, that resource does not exist in its universe.**

Status: design document · Companion to `ZEROCOPY_IPC_RING.md` and `ARCHITECTURE_BLUEPRINT.md`. This document specifies the capability model and then does something important: it **validates that design against seL4**, because the research finding here is decisive for the whole project.

---

## 0. The finding you need to hear first

**The object-capability model drafted for HookProbe-OS — 128-bit unforgeable tokens, untyped memory retyped into typed objects, capabilities stored in kernel CNodes and invoked by CSpace index, badges for IPC sender identification, a Grant right for delegation, and a capability-derivation tree for recursive revocation — is, point for point, the seL4 capability model.** That is not a criticism; it is the strongest possible validation. You independently converged on the design that a team of formal-methods researchers spent ~15 years proving mathematically correct. The research is unambiguous on this:

| Your drafted design | seL4's actual mechanism | Source |
|---|---|---|
| 128-bit capability, kernel-only mutation | seL4 caps are 2 machine words, kernel-managed, unforgeable | seL4 Reference Manual 12.1.0 |
| Untyped → Frame/TCB/Endpoint via Retype | `seL4_Untyped_Retype` — the *sole* memory-allocation primitive; no in-kernel malloc | Untyped tutorial |
| "purpose is locked once retyped" | typed objects cannot be reinterpreted; type safety is proven | verification project |
| Caps in CNodes, invoked by CSpace index | CNodes = capability storage; threads invoke by CPtr (CSpace slot index) | Reference Manual |
| `badge` stamps IPC sender identity | Endpoint badges: kernel stamps the receiver's message with the sender badge | IPC tutorial |
| Grant right delegates caps over IPC | seL4 `Grant` right; caps transferred over Endpoints | Reference Manual |
| Radix/derivation tree for recursive revoke | the **CDT** (Capability Derivation Tree); `seL4_CNode_Revoke` sweeps derived caps | Reference Manual |
| IRQs, I/O ports, BARs as capabilities | `IRQControl`→`IRQHandler` caps; x86 I/O-port caps; device MMIO frames | Reference Manual |
| Fast-path IPC = direct context switch | hand-optimized register-only Call/ReplyRecv fastpath (~600 cycles x64) | arXiv 2210.04328 |

**The engineering consequence (developed fully in `buildPlan.md`):** for a *security* product, the capability microkernel is the one component where writing your own is strictly worse than adopting seL4 — because seL4's value *is* the machine-checked proof that this exact model has no implementation bug, and a from-scratch reimplementation throws that proof away. seL4's kernel is GPLv2, but **the GPL boundary stops at the kernel/user line** — every HookProbe driver, sidecar, the IDS/IPS engine, the VMM, and the boot chain above it stays proprietary and fully yours. So "everything is HookProbe" is achievable *on top of* the verified core; you do not have to choose between owning the product and having a trustworthy TCB.

The rest of this document specifies the model as HookProbe uses it — written so it maps 1:1 onto seL4 primitives (recommended path) but is also a complete spec if the from-scratch "HookProbe Kernel" track is pursued (`buildPlan.md`, Track B).

---

## 1. Anatomy of a capability

```zig
// HookProbe capability — 128 bits, register-friendly, kernel-only mutation.
// (Maps to seL4's 2-word cap; field split is HookProbe's, semantics are seL4's.)
const Capability = packed struct {
    obj_type:    u8,   // Untyped | Endpoint | Notification | TCB | CNode | Frame | PageTable | IRQHandler | IOPort
    rights:      u8,   // Read | Write | Grant | GrantReply  (bitmask)
    badge:       u16,  // sender identity for IPC routing (0 = unbadged)
    guard:       u32,  // CSpace guard bits / derivation metadata
    object_ref:  u64,  // kernel-internal object reference (NOT user-visible, NOT forgeable)
};
```

- **`object_ref` is never exposed to user space.** The user only ever names a capability by its **CSpace slot index** (a CPtr). The kernel resolves index → CNode slot → capability → object. User space cannot read or write the 128-bit structure; it lives in the kernel. This is what makes the token unforgeable — a user thread cannot fabricate an `object_ref` because it never sees one.
- **`rights`** are checked in O(1) at invocation: the kernel confirms the cap is the right type and carries the right permission for the requested operation, then acts or faults the thread. No ACL, no list walk.
- **`badge`** is the decentralized-identity mechanism: when many sidecars send to one server (e.g. the VFS or the event bus), the kernel stamps each delivered message with the sender's badge. The server authenticates origin by badge value — no handshake, no crypto, no lookup table.

---

## 2. Untyped memory: the base material

At boot the kernel reserves its own image and hands **all remaining physical RAM to the root task as Untyped capabilities.** Every kernel object thereafter is carved from untyped by **Retype**:

```
Untyped ──Retype──▶ Frame        (RAM to hold data: the zero-copy packet rings, payload pools)
Untyped ──Retype──▶ TCB          (a thread of execution)
Untyped ──Retype──▶ Endpoint     (synchronous IPC portal — control plane)
Untyped ──Retype──▶ Notification (async signal object — the ring's idle-wakeup primitive)
Untyped ──Retype──▶ CNode        (capability storage table)
Untyped ──Retype──▶ PageTable    (VSpace paging structure)
```

- **Type safety is absolute and, on seL4, proven:** once RAM is retyped as an Endpoint it can never be read as a Frame. This mathematically eliminates the type-confusion / memory-overlap vulnerability class — the attacker cannot alias a control object as data or vice-versa.
- **No in-kernel allocator.** All allocation policy lives in user space (the root task and its delegates decide how to carve untyped). The kernel has no `malloc`, so it has no allocator bugs and no allocator DoS surface. This is also why the kernel's memory use is bounded and analyzable — essential for the real-time and mission-critical claims.

---

## 3. CSpaces and the O(1) invocation path

A thread's authority is exactly the set of capabilities reachable in its **CSpace** (a tree of CNodes). Invocation:

```
1. SYSCALL          thread executes syscall with (CPtr slot, operation, args) in registers
2. CSPACE LOOKUP    kernel resolves CPtr → CNode slot → 128-bit cap  (radix walk, O(depth))
3. TYPE+RIGHTS      O(1): correct obj_type? required right present?   (fault instantly if not)
4. EXECUTE          kernel dereferences object_ref and performs the op (e.g. IPC transfer)
```

- **Presence is authorization.** There is no "who is asking" question — the kernel never identifies the caller against a policy list. Holding the cap in your CSpace *is* the permission. This is the property that makes authority checks cheap enough for a 100 Gbps appliance.
- The IDS sidecar sending a verdict does not invoke a pointer; it invokes **slot N** of its CSpace. If slot N doesn't hold an Endpoint cap with Write, the thread faults — it cannot even name the target otherwise.

---

## 4. Delegation (Grant) and the confused-deputy elimination

Decentralization requires threads to share authority without a central broker. The **Grant** right enables it:

- If thread A holds a cap with `Grant`, it may send a **copy** of that cap to thread B over an Endpoint. B now holds independent authority to the object; A can later revoke it (§5).
- **Worked HookProbe example (the NIC bring-up):**
  1. The **PCI enumeration server** scans the bus, finds the NIC.
  2. It retypes untyped into an **IRQHandler** cap for the NIC's interrupt and **Frame** caps mapping the NIC's BARs (MMIO registers).
  3. It **Grants** those caps over IPC to the freshly-spawned **NIC PMD sidecar**, plus the shared-ring Frame caps and one Notification cap.
  4. The NIC driver now has *exactly* the authority to poll its hardware and drive its ring — and **no authority to touch the filesystem, USB, the IDS engine's other memory, or the kernel.** A total compromise of the NIC driver is contained to the NIC driver.
- **Confused deputy is structurally impossible:** because authority travels *with* the capability (not as an ambient identity the kernel looks up), a component cannot be tricked into exercising authority it was merely *near*. It can only act through caps it actually holds. This is the POLA (Principle of Least Authority) property that ambient-authority systems (Unix root, Linux capabilities-as-flags) cannot provide.

---

## 5. Deterministic destruction (revocation without GC)

When a container/sidecar is torn down, its authority must vanish **completely and immediately** — no lingering caps, no GC pause (a GC pause is unacceptable in a real-time datapath).

- Capabilities derived from a common untyped are linked in a **Capability Derivation Tree (CDT)** — the radix/derivation tree the draft calls for.
- `Revoke` on the parent cap walks the CDT subtree and deletes every derived capability **synchronously and in bounded time.** When the last cap to an object is deleted, the object's untyped becomes reclaimable.
- Result: **tearing down a compromised IDS container instantly severs every handle it ever delegated** — its ring frames, its NIC caps, its IPC endpoints — with no garbage-collection pause and no dangling authority. This is the mechanism behind the "self-heal / HAM-style restart" story from the FreeBSD/QNX tracks, done at the authority layer: kill, revoke subtree, respawn clean.

---

## 6. Implementation rules for line-rate security

1. **No ACLs, ever.** Authority is the cap's presence in the CSpace. The kernel never iterates a subject list.
2. **Fast-path IPC = direct switch.** For a short register-only control message to a waiting receiver, jump straight from sender to receiver context, bypassing the scheduler run-queue (seL4 fastpath ≈600 cycles x64; the slow path >1100). Data-plane packets never use this — they use the shared ring (`ZEROCOPY_IPC_RING.md`); IPC is for control only.
3. **Deterministic, GC-free destruction** via the CDT (§5).
4. **The datapath's safety rests here.** The zero-copy ring is safe *because* its shared dataspace is a Frame cap granted to exactly two components and the NIC's DMA is confined by an IOMMU/SMMU cap — both are capability facts, not conventions. The capability model and the ring are one design.

---

## 7. Why this is the right base for mission-critical IDS/IPS

- **Breach containment is spatial:** an attacker who owns the packet-inspection sidecar cannot address the host runtime's memory, the filesystem, or another tenant's rings — those objects are not in its CSpace.
- **The TCB is tiny and (on seL4) proven:** the whole authority mechanism is ~10k LOC of kernel with a machine-checked correctness + integrity proof. Nothing else in security software offers that.
- **It composes with the VM/container tier:** each guest VM and each container is just a CSpace-bounded protection domain holding exactly the caps it was granted — the same model scales from a single sidecar to a multi-tenant SOC appliance (see `ARCHITECTURE_BLUEPRINT.md`).

---

*Recommended realization: seL4 via the seL4 Microkit (Protection Domains, channels, memory regions), with all HookProbe components in proprietary user space above the GPLv2 kernel boundary. The from-scratch alternative — the "HookProbe Kernel" implementing this same spec unverified — is Track B in `buildPlan.md`, presented with an honest assurance/cost comparison. Citations for every seL4 claim are in `RESEARCH_LANDSCAPE.md`.*
