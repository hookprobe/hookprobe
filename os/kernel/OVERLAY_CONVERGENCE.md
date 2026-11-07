# P17 — Overlay convergence: a smoltcp IP service at EL0 — frozen design

Status: **DESIGNED, not yet implemented.** Researched against smoltcp 0.13 and
validated against the existing HEQK EL0 machinery.

## The decisive finding

smoltcp **needs no heap**. `alloc` is an optional feature, off by default; all
state lives in caller-supplied `&mut [..]` slices and fixed-capacity vectors:

```rust
let mut storage = [SocketStorage::EMPTY; 4];
let mut sockets = SocketSet::new(&mut storage[..]);
```

This matters because **EL0 tasks on HEQK have no heap at all** (the kernel's bump
allocator is `AP_RW_EL1`, and there is no `brk`/mmap syscall) — and P17 must not
introduce one. Build with `default-features = false`, features
`medium-ethernet, proto-ipv4, socket-{udp,icmp,tcp}` only.

The `phy::Device` trait's **token** design maps one-to-one onto HEQK's existing
"inspect in place, never copy through the ring" doctrine: `receive()` only reserves
a slot; the frame is read in place inside `RxToken::consume`. And `receive()`
returns an RxToken *paired* with a TxToken precisely so a reply can be generated
with no allocation — exactly the ARP-reply / ICMP-echo path the gate needs.

## Architecture — and why the IPS stays authoritative

```
EL0 (own ASID, NO MMIO grant):  smoltcp Interface + SocketSet -- HeqkNetDevice
        rxq (kernel->svc)  Normal-NC        txq (svc->kernel)  Normal-NC
====================== trust boundary ======================
EL1/TCB:  rx_publish()                      tx_drain()
            +- packet::classify  <-- SAME signed rule plane -->  classify
               PASS -> enqueue                   PASS -> gem::tx_frame
               DROP -> dropped, telemetry        DROP -> NEVER on the wire
```

The single most important design rule: **the IPS enforcement point stays in the
TCB, on BOTH sides of the queue.** The userspace stack is a *client* of it, never a
bypass of it.

- **Ingress**: a frame the rules DROP never enters the ring, so smoltcp cannot even
  observe it — a smoltcp parser bug is unreachable by traffic the rules rejected.
  This is strictly stronger than a Linux/eBPF tap.
- **Egress**: every frame the service publishes is re-classified before
  `gem::tx_frame`. So a **fully compromised IP stack still cannot put a frame on
  the wire that the signed rule plane rejects** — no C2 beacon, no spoofed ARP, no
  scan pattern. In Linux+eBPF a compromised userspace stack sits *above* the filter;
  here it sits below.

## Queue ABI — per-slot ownership, not head/tail

Deliberately **no EL0-writable index**. With head/tail, a compromised service
writes `head = 0xFFFF_FFFF` and the kernel indexes out of bounds. With per-slot
`state` flags the kernel iterates its own `0..NETQ_SLOTS` and treats the
EL0-written state as a single validated boolean and `len` as a value it clamps
itself. Same lesson as audit finding M-7.

Both sides map the ring **Normal-NC** (kernel via `NC_ALIAS_VA`, EL0 via
`map_user_nc`) so acquire/release pairs suffice with zero cache maintenance — EL0
cannot execute `dc` anyway (SCTLR_EL1.UCI=0 traps it).

## Grants — the service gets *less* than the existing P7c driver

| pages | what | attrs |
|---|---|---|
| ~32 | smoltcp .text/.rodata | RO+X, PXN |
| ~16 | .data/.bss + stack | RW, PXN\|UXN |
| 20 | rxq + txq | RW, Normal-NC |
| **0** | **MMIO** | **none — no GEM regs, no descriptor rings, no PCIe, no SDHCI** |

That is a deliberate downgrade from the P7c EL0 GEM driver (which is granted the
GEM register page — audit finding H-2). The queue is the only interface. Blast
radius of a smoltcp parsing bug: ~48 EL0 pages of one ASID. It cannot reach kernel
RAM, cannot program DMA, cannot execute anything writable.

## Two prerequisites this exposes

1. **EL0 code is currently a single 4 KiB page** of hand-written asm. smoltcp is
   ~60-90 KiB of `.text`, so P17 needs a multi-page image loader + a validated
   range mapper (which is also where audit finding L-14 must be honoured). Build
   the service as a separate crate linked at a fixed VA, `objcopy -O binary`,
   `include_bytes!` — no general ELF loader, preserving the static architecture.
2. **`CNTKCTL_EL1` is never programmed**, so EL0 counter access is trapped at
   reset. smoltcp needs a monotonic `Instant`. One-line fix
   (`CNTKCTL_EL1.EL0PCTEN = 1`, granting a counter *only* — no compare regs, no
   event stream), plus a kernel-published `time_us` fallback in the ring header.
   Record the timing-side-channel implication in SECURITY.md.

Also: `M-8` (per-TCB restart params) must land first — P17 adds a second EL0
service, and the restart record is currently global, so a fault would restart the
wrong TCB in the wrong ASID with another's kernel stack.

## Gate — no external infrastructure

Kernel synthesizes an ARP request and an ICMP echo, pushes them through the
**ingress** IPS gate, runs the service once, and drains the **egress** gate
checking for the ARP reply and ICMP echo reply. Tier D is the important one: the
service is asked to emit UDP to a threat port and the egress gate **must** drop it
— proving the IPS is authoritative over the userspace stack. Live-wire traffic is
opportunistic and silence is not a failure.

Hang-proofing: the poll loop is bounded by a constant compiled into the service
binary (verifiable by disassembly); a fault is contained by `handle_lower_sync`.
Once green, move the service to a **scheduled EL0 TCB** so even an infinite loop is
preempted — structurally hang-proof rather than bound-by-convention.

## Residual risks to record

smoltcp is a third-party crate in a security product: pin the exact version and
checksum, and **measure the service binary into PCR3** so the attested boot chain
covers it. `random_seed` must come from the hboot TRNG nonce, not `cntpct`, or TCP
ISN prediction is trivial.
