# P12 — Notification objects + capability pub-sub — frozen design

Status: **DESIGNED, not yet implemented.** This document is the implementable spec.
Researched against seL4 and validated against the existing HEQK code.

## Why

`kernel/src/events.rs` already says it verbatim: the EL0 exporter's wakeup *should*
be "a batched P12 Notification". Today there is no async signal primitive that EL0
can use — `ipc.rs` is a synchronous single-word rendezvous for EL1 threads only.

## seL4 semantics to copy exactly

A Notification is one **badge word** + a queue of waiting TCBs. Three states:

| State | `Signal(badge)` | `Wait` | `Poll` |
|---|---|---|---|
| Idle (word 0, no waiters) | word <- badge -> Active | block, enqueue -> Waiting | 0 |
| Active (word != 0) | word **\|=** badge | return word, word <- 0 -> Idle | same as Wait |
| Waiting (>=1 waiter) | dequeue head, deliver badge directly | join queue | 0 |

Invariant: **`nwait > 0 => word == 0`**. This is what makes Signal/Wait
ordering-independent and makes lost wakeups structurally impossible.

Three properties that are *security* properties here:
1. **The badge comes from the capability, never from a syscall argument.**
   `seL4_Signal` takes only a CPtr. Badges are stamped at mint time. Badge forgery
   is therefore impossible by construction, not by checking.
2. **OR-coalescing, not a queue.** Lossy in count, lossless in identity — an array
   of binary semaphores. Cannot overflow, cannot be exhausted.
3. **Signal never blocks the signaller.** A malicious subscriber cannot stall a
   publisher.

## Pub-sub: topics ARE capabilities

`Topic{W}` = may publish. `Topic{R}` = may subscribe/receive. No ACL, no broker
identity check (CAPABILITY_MODEL rule 1: "No ACLs, ever"). "Ungranted subscribe is
refused" falls straight out of `has_rights`.

Delivery is deliberately split into three layers:

| Layer | Semantics | Why |
|---|---|---|
| Signal (notification word) | lossy, OR-coalescing, O(1) | seL4-exact; cannot overflow or block |
| Event metadata (per-subscription queue) | bounded, drop-newest + counter | a slow subscriber loses **its own** events only; `seq` gaps make loss auditable |
| Bulk payload | zero-copy, kernel never touches it | `payload` is a P11 ring descriptor; kernel copies 24 B of metadata, never data |

`publish` is strictly non-blocking and O(subscribers) — that is the anti-DoS property.

## Prerequisite this exposes

**There is exactly one CSpace in the system today** (`static mut ROOT`), shared by
every EL0 task. P12 cannot express "publisher may not subscribe" without
**per-task CSpaces** — that is the largest structural change P12 requires.
Also `scheduler::MAX_THREADS = 8` is *exactly full* on the QEMU path; P12 needs 16.

## The blocking-syscall mechanism (no new assembly needed)

`lower_sync_entry` and `irq_entry` have **byte-identical epilogues** (restore 34
words, `eret`). So a thread that blocks inside a syscall can be resumed later by
the timer IRQ path. To block: enqueue tid, `scheduler::block_current()`,
`on_tick()`, `enter_current_addr_space()`, return the next SP. To wake: write the
badge **directly into the blocked thread's saved `x0`** in its trap frame, then
`unblock`. That is the whole implementation.

Exception entry masks `PSTATE.{D,A,I,F}` in hardware and nothing re-enables it, so
check-then-block is atomic for free on this single core (add a debug assert so the
contract is checked, not assumed).

## Latent bug this found (fix regardless of P12)

`main.rs`: `SYS_EXIT_USER` **unconditionally** calls `resume_kernel()`, which
long-jumps into the `KRESUME` context saved by the last `enter_user`. For a
*scheduled* EL0 TCB that context is stale -> jump into a dead kernel stack. Must be
gated on `!EL0_SCHED_MODE`, with a scheduler-aware `SYS_TASK_EXIT` for scheduled tasks.

## Syscall ABI (block 16..23; 8..15 reserved for P11)

`16 SIGNAL`, `17 WAIT`(blocking), `18 POLL`, `19 PUBLISH`, `20 RECV`,
`21 SUBSCRIBE`, `22 TASK_EXIT`, `23 CAP_BADGE`. Return codes `RC_OK`,
`RC_DENIED`, `RC_EMPTY`, `RC_REVOKED`, `RC_NORESOURCE`, `RC_BADARG` in `abi/`.
**Only WAIT blocks, and only the caller** — no syscall can block another task.

## Security checklist (condensed)

Objects are `(index, generation)`, never pointers — `destroy()` bumps the
generation so stale caps fail with `RC_REVOKED`, and every blocked waiter is woken
with `RC_REVOKED` rather than left parked forever. `detach_tcb(tid)` must be called
on **all three** death paths (fault restart, restart-budget kill, task exit) — else
a signal writes a badge into a dead/reused thread's frame. Wake paths bounds-check
the tid and verify `blocked_on[tid]` matches this object+generation. Tables are
fixed-size with a per-task subscription quota; object *creation* is not an EL0
syscall at all (static, Microkit-style). Syscalls never return physical addresses,
object indices, tids or frame pointers. A missing CSpace fails **closed**.

Also: every path returning a *different* thread's SP must call
`enter_current_addr_space()` first — factor it into one `switch_to(next)` helper so
it cannot be forgotten (omitting it runs a thread under the wrong TTBR0).

## Why it matters for the smart-farm target

A sensor driver holds `Topic{W}` on `sensors/soil-moisture`; the rule engine holds
`Topic{R}` on that and `Topic{W}` on `actuators/valve`. **A compromised sensor
driver cannot actuate a valve** — that authority is simply not in its CSpace. P12
is the primitive that makes that expressible.

## Sources

seL4 notifications tutorial + manual `notifications.tex`, seL4 API reference,
Microkit manual, sDDF design doc (signalling protocol, model-checked),
LionsOS (arXiv:2501.06234), and in-repo `CAPABILITY_MODEL.md`,
`ZEROCOPY_IPC_RING.md`, `buildPlan.md` (the P12 gate text).
