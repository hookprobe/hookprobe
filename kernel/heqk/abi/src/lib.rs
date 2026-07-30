#![no_std]
//! Shared kernel<->userspace ABI: syscall numbers, trap-frame layout, cap structs.
//!
//! P0 placeholder — the real surface lands at P3 (SVC syscall boundary) and
//! P4 (IPC). Kept in the workspace now so the ring-0/ring-3 contract has a home
//! from the start and both sides depend on exactly one crate for it.

/// Syscall numbers (passed in x8 by convention on aarch64).
#[repr(u64)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Syscall {
    Yield = 0,
    // P3/P4: IpcCall, IpcReplyRecv, CapCopy, CapRevoke, UntypedRetype, ...
}

// --- P12 syscall ABI: notification objects + capability pub-sub ---------------
// Numbers 8..15 are RESERVED for P11 (automation underlay). P12 owns 16..23.
// Every one is invoked on a CAPABILITY (a CPtr in x0) — the badge is stamped in
// the cap at mint time and is NEVER a syscall argument, so badge forgery is
// impossible by construction (see NOTIFICATIONS_PUBSUB.md). Only WAIT blocks, and
// only the caller — no syscall can block another task.
pub const SYS_SIGNAL: u64 = 16; // Signal(CPtr{W}): OR the cap's badge; never blocks
pub const SYS_WAIT: u64 = 17; // Wait(CPtr{R}): block until signalled; returns+clears the word
pub const SYS_POLL: u64 = 18; // Poll(CPtr{R}): non-blocking; returns+clears the word (0 = empty)
pub const SYS_PUBLISH: u64 = 19; // Publish(TopicCPtr{W}): non-blocking, O(subscribers)
pub const SYS_RECV: u64 = 20; // Recv(TopicCPtr{R}, sub_id): pop one bounded event
pub const SYS_SUBSCRIBE: u64 = 21; // Subscribe(TopicCPtr{R}): requires the R right (else refused)
pub const SYS_TASK_EXIT: u64 = 22; // scheduler-aware clean exit of the current scheduled TCB
pub const SYS_CAP_BADGE: u64 = 23; // reserved: read a cap's badge (kept for symmetry)

// --- R1 sync-IPC ABI (M5.0): cap-gated SYNCHRONOUS rendezvous over an Endpoint ------
// seL4-style Call/Recv/Reply. The Endpoint cap is a CPtr in x0, resolved from the
// CALLER's OWN per-TCB CSpace (CORE-2); CALL requires the W (send) right, RECV/REPLY
// require the R (receive) right. A missing / wrong-type / insufficient-rights cap fails
// CLOSED with RC_DENIED before any rendezvous. `SYS_EP_RECV` is named distinctly from
// the P12 topic `SYS_RECV = 20` (a different object) to avoid the number/name collision;
// it is the endpoint-object receive of the synchronous IPC path.
pub const SYS_CALL: u64 = 24; // Call(EpCPtr{W}, msg=x1): send msg + BLOCK until a REPLY; reply in x0
pub const SYS_EP_RECV: u64 = 25; // Recv(EpCPtr{R}): block until a CALL rendezvous; returns msg in x0
pub const SYS_REPLY: u64 = 26; // Reply(EpCPtr{R}, word=x1): wake the served caller with word; never blocks

// --- P12 return codes (in x0). RC_OK = 0 so a bare `0` return stays "success". --
pub const RC_OK: u64 = 0;
pub const RC_DENIED: u64 = 1; // authority absent (ungranted subscribe/signal) — fail CLOSED
pub const RC_EMPTY: u64 = 2; // nothing to receive (bounded queue empty / word 0)
pub const RC_REVOKED: u64 = 3; // stale (index,generation) — object was destroyed
pub const RC_NORESOURCE: u64 = 4; // table/quota exhausted, or a second concurrent waiter
pub const RC_BADARG: u64 = 5; // wrong object type / malformed CPtr
