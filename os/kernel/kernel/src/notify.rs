//! P12 — Notification objects + capability pub-sub (topics as caps).
//!
//! seL4-exact async signalling for `#![no_std]`, single core. See
//! `NOTIFICATIONS_PUBSUB.md` (the frozen design). Two primitives:
//!
//!  * **Notification** — one **badge word** + a waiter. Three states:
//!    Idle (word 0, no waiter) · Active (word != 0) · Waiting (a blocked TCB).
//!    `Signal` ORs the badge in (OR-coalescing, never blocks the signaller);
//!    `Wait` blocks and returns+clears the word; `Poll` is the non-blocking read.
//!    Invariant **`waiter.is_some() => word == 0`** — makes lost wakeups structurally
//!    impossible and Signal/Wait ordering-independent.
//!
//!  * **Topic** — a pub-sub channel expressed as a capability. `Topic{W}` may
//!    `publish`, `Topic{R}` may `subscribe`/`recv` — so "ungranted subscribe is
//!    refused" falls straight out of `CapSpace::has_rights`, no ACL. `publish` is
//!    strictly non-blocking and O(subscribers). Delivery is split: a lossy,
//!    OR-coalescing notification word PLUS a bounded per-subscription event queue
//!    (drop-NEWEST + a counter; `seq` gaps make loss auditable). The kernel copies
//!    only ~24 B of metadata, never bulk payload (that is a P11 ring descriptor).
//!
//! Objects are `(index, generation)`, NEVER pointers. `destroy()` bumps the
//! generation, so a stale cap fails `RC_REVOKED` and any parked waiter is woken with
//! `RC_REVOKED` rather than left forever. Object CREATION is static (kernel-side,
//! Microkit-style) — there is no "create" EL0 syscall. The badge comes from the
//! CAPABILITY (`caps::Cap::badge`), never from a syscall argument, so it cannot be
//! forged. Signal/wake paths run in the exception epilogue (IRQs masked) so
//! check-then-block and deliver-then-unblock are atomic on this single core.

use crate::scheduler;
use abi::{RC_BADARG, RC_DENIED, RC_EMPTY, RC_NORESOURCE, RC_OK, RC_REVOKED};
use core::ptr::addr_of_mut;

// ---------------------------------------------------------------------------
// Notification objects
// ---------------------------------------------------------------------------

pub const MAX_NOTIFY: usize = 16;
/// Per-task quota: a compromised task cannot exhaust the shared table.
pub const NOTIFY_QUOTA_PER_TASK: usize = 8;

#[derive(Clone, Copy)]
struct Notif {
    used: bool,
    generation: u32, // bumped on destroy() so stale caps fail RC_REVOKED
    owner: usize,    // tid that created it (quota accounting)
    word: u64,       // OR-coalesced badge accumulator; Active iff != 0
    waiter: Option<usize>, // tid blocked in WAIT; Waiting iff Some (single waiter)
}
const EMPTY_NOTIF: Notif = Notif { used: false, generation: 0, owner: 0, word: 0, waiter: None };
static mut NOTIFY: [Notif; MAX_NOTIFY] = [EMPTY_NOTIF; MAX_NOTIFY];

/// An opaque object handle: `(index, generation)`. Kernel-internal — this is what a
/// cap stores (`base`=index, `watermark`=generation); it is NEVER returned to EL0.
#[derive(Clone, Copy)]
pub struct Handle {
    pub index: usize,
    pub generation: u32,
}

/// Outcome of preparing a WAIT (the syscall layer turns this into block/return).
pub enum WaitOut {
    Ready(u64), // Active: return this word immediately (already cleared)
    Block,      // Idle/Waiting: caller must block the current TCB
    Rc(u64),    // an error code (revoked / busy)
}

#[inline]
fn notify_slot(index: usize, generation: u32) -> Option<&'static mut Notif> {
    if index >= MAX_NOTIFY {
        return None;
    }
    let n = unsafe { &mut (*addr_of_mut!(NOTIFY))[index] };
    if n.used && n.generation == generation {
        Some(n)
    } else {
        None // fail CLOSED: unused slot or stale generation
    }
}

/// Statically create a Notification owned by `owner` (a tid). Quota-checked; returns
/// `None` if the table is full or the owner is over quota. NOT reachable from EL0.
pub fn create(owner: usize) -> Option<Handle> {
    unsafe {
        let tbl = &mut *addr_of_mut!(NOTIFY);
        let held = tbl.iter().filter(|n| n.used && n.owner == owner).count();
        if held >= NOTIFY_QUOTA_PER_TASK {
            return None;
        }
        for i in 0..MAX_NOTIFY {
            if !tbl[i].used {
                tbl[i].used = true;
                tbl[i].owner = owner;
                tbl[i].word = 0;
                tbl[i].waiter = None;
                // generation is NOT reset — it only ever increases, so a cap minted
                // over a previous tenant of this slot can never alias this object.
                return Some(Handle { index: i, generation: tbl[i].generation });
            }
        }
        None
    }
}

/// Destroy a Notification: wake any waiter with `RC_REVOKED`, then bump the
/// generation so every outstanding cap over this slot fails closed.
pub fn destroy(h: Handle) {
    if let Some(n) = notify_slot(h.index, h.generation) {
        if let Some(w) = n.waiter.take() {
            scheduler::deliver_wake(w, RC_REVOKED);
            scheduler::unblock(w);
        }
        n.used = false;
        n.word = 0;
        n.generation = n.generation.wrapping_add(1);
    }
}

/// `Signal(badge)`. NEVER blocks the signaller. Waiting -> deliver the badge directly
/// to the parked waiter; Idle/Active -> OR the badge into the word. `badge` comes from
/// the signaller's CAP, not a syscall argument. Returns RC_OK, or RC_REVOKED if stale.
pub fn signal(index: usize, generation: u32, badge: u64) -> u64 {
    match notify_slot(index, generation) {
        None => RC_REVOKED,
        Some(n) => {
            if let Some(w) = n.waiter.take() {
                // Waiting: hand the badge straight to the waiter's saved x0 (word stays
                // 0, preserving the invariant), then make it runnable.
                scheduler::deliver_wake(w, badge);
                scheduler::unblock(w);
            } else {
                n.word |= badge; // Idle->Active, or Active stays Active (coalesce)
            }
            RC_OK
        }
    }
}

/// Prepare a `Wait`. Active -> `Ready(word)` (cleared, no block). Idle/Waiting ->
/// `Block` (this TCB is enqueued as the waiter). A SECOND concurrent waiter is refused
/// (`RC_NORESOURCE`) rather than clobbering the slot — the single-core, single-waiter
/// analogue of the P4 endpoint's "refuse a second receiver".
pub fn wait_prepare(index: usize, generation: u32, tid: usize) -> WaitOut {
    match notify_slot(index, generation) {
        None => WaitOut::Rc(RC_REVOKED),
        Some(n) => {
            if n.word != 0 {
                let w = n.word;
                n.word = 0; // Active -> return + clear -> Idle
                WaitOut::Ready(w)
            } else if n.waiter.is_some() {
                WaitOut::Rc(RC_NORESOURCE)
            } else {
                n.waiter = Some(tid); // Idle/Waiting -> enqueue + block
                WaitOut::Block
            }
        }
    }
}

/// `Poll`: non-blocking. Returns+clears the word (0 = nothing pending).
pub fn poll(index: usize, generation: u32) -> u64 {
    match notify_slot(index, generation) {
        None => 0,
        Some(n) => {
            let w = n.word;
            n.word = 0;
            w
        }
    }
}

// ---------------------------------------------------------------------------
// Topics (pub-sub) — `Topic{W}` publishes, `Topic{R}` subscribes/receives.
// ---------------------------------------------------------------------------

pub const MAX_TOPICS: usize = 4;
pub const MAX_SUBS_PER_TOPIC: usize = 4;
pub const SUB_QUEUE_LEN: usize = 4;

/// ~24 B of event METADATA. The kernel copies this, never the bulk payload (which is
/// a P11 zero-copy ring descriptor named by `payload`). `seq`/`payload` are delivered
/// to a subscriber via `recv`; the self-test asserts on `kind` only.
#[allow(dead_code)]
#[derive(Clone, Copy)]
pub struct EventMeta {
    pub seq: u64,     // monotonic per-subscription; gaps == dropped events (auditable)
    pub kind: u32,    // event class
    pub payload: u64, // opaque ring-descriptor handle (kernel never dereferences it)
}
const EMPTY_META: EventMeta = EventMeta { seq: 0, kind: 0, payload: 0 };

#[derive(Clone, Copy)]
struct Sub {
    used: bool,
    subscriber: usize, // tid
    word: u64,         // per-subscription notification word (lossy, OR-coalescing)
    waiter: Option<usize>,
    q: [EventMeta; SUB_QUEUE_LEN],
    head: usize,
    len: usize,
    next_seq: u64,
    dropped: u64, // drop-NEWEST counter
}
const EMPTY_SUB: Sub = Sub {
    used: false,
    subscriber: 0,
    word: 0,
    waiter: None,
    q: [EMPTY_META; SUB_QUEUE_LEN],
    head: 0,
    len: 0,
    next_seq: 0,
    dropped: 0,
};

#[derive(Clone, Copy)]
struct Topic {
    used: bool,
    generation: u32,
    subs: [Sub; MAX_SUBS_PER_TOPIC],
}
const EMPTY_TOPIC: Topic = Topic { used: false, generation: 0, subs: [EMPTY_SUB; MAX_SUBS_PER_TOPIC] };
static mut TOPICS: [Topic; MAX_TOPICS] = [EMPTY_TOPIC; MAX_TOPICS];

#[inline]
fn topic_slot(index: usize, generation: u32) -> Option<&'static mut Topic> {
    if index >= MAX_TOPICS {
        return None;
    }
    let t = unsafe { &mut (*addr_of_mut!(TOPICS))[index] };
    if t.used && t.generation == generation {
        Some(t)
    } else {
        None
    }
}

/// Statically create a Topic (kernel-side; not an EL0 syscall). Returns its handle.
pub fn topic_create() -> Option<Handle> {
    unsafe {
        let tbl = &mut *addr_of_mut!(TOPICS);
        for i in 0..MAX_TOPICS {
            if !tbl[i].used {
                tbl[i].used = true;
                tbl[i].subs = [EMPTY_SUB; MAX_SUBS_PER_TOPIC];
                return Some(Handle { index: i, generation: tbl[i].generation });
            }
        }
        None
    }
}

/// Destroy a Topic: wake every subscription's waiter with RC_REVOKED, bump generation.
pub fn topic_destroy(h: Handle) {
    if let Some(t) = topic_slot(h.index, h.generation) {
        for s in t.subs.iter_mut() {
            if let Some(w) = s.waiter.take() {
                scheduler::deliver_wake(w, RC_REVOKED);
                scheduler::unblock(w);
            }
        }
        t.used = false;
        t.generation = t.generation.wrapping_add(1);
        t.subs = [EMPTY_SUB; MAX_SUBS_PER_TOPIC];
    }
}

/// Subscribe `tid` to a topic — the caller MUST already hold `Topic{R}` (the rights
/// gate lives in the syscall/demo layer via `has_rights`; an ungranted subscribe is
/// refused BEFORE reaching here). Returns a subscription id (a small per-topic index,
/// never a pointer), or an RC error.
pub fn subscribe(index: usize, generation: u32, tid: usize) -> Result<usize, u64> {
    match topic_slot(index, generation) {
        None => Err(RC_REVOKED),
        Some(t) => {
            // AUD-CAP-3: one subscription per (tid, topic). A tid that already holds a
            // subscription gets the SAME id back (idempotent) rather than consuming a
            // second slot — so a single Topic{R} holder cannot re-subscribe in a loop to
            // exhaust MAX_SUBS_PER_TOPIC and starve other legitimate subscribers.
            for i in 0..MAX_SUBS_PER_TOPIC {
                if t.subs[i].used && t.subs[i].subscriber == tid {
                    return Ok(i);
                }
            }
            for i in 0..MAX_SUBS_PER_TOPIC {
                if !t.subs[i].used {
                    t.subs[i] = EMPTY_SUB;
                    t.subs[i].used = true;
                    t.subs[i].subscriber = tid;
                    return Ok(i);
                }
            }
            Err(RC_NORESOURCE)
        }
    }
}

/// Publish an event: strictly non-blocking, O(subscribers). For each subscription: OR
/// the `badge` into its word (waking a parked waiter directly), then enqueue the
/// metadata (drop-NEWEST if the bounded queue is full — `seq` still advances so the
/// gap is auditable). `badge` comes from the publisher's `Topic{W}` cap.
pub fn publish(index: usize, generation: u32, badge: u64, kind: u32, payload: u64) -> u64 {
    match topic_slot(index, generation) {
        None => RC_REVOKED,
        Some(t) => {
            for s in t.subs.iter_mut() {
                if !s.used {
                    continue;
                }
                // (1) lossy notification word.
                if let Some(w) = s.waiter.take() {
                    scheduler::deliver_wake(w, badge);
                    scheduler::unblock(w);
                } else {
                    s.word |= badge;
                }
                // (2) bounded event queue (drop-newest + counter).
                let seq = s.next_seq;
                s.next_seq += 1;
                if s.len >= SUB_QUEUE_LEN {
                    s.dropped += 1; // newest dropped; `seq` consumed -> auditable gap
                } else {
                    let slot = (s.head + s.len) % SUB_QUEUE_LEN;
                    s.q[slot] = EventMeta { seq, kind, payload };
                    s.len += 1;
                }
            }
            RC_OK
        }
    }
}

/// Receive one event from `tid`'s subscription. `RC_EMPTY` if the queue is drained.
/// Verifies the subscription belongs to `tid` (a task cannot read another's queue).
pub fn recv(index: usize, generation: u32, sub_id: usize, tid: usize) -> Result<EventMeta, u64> {
    match topic_slot(index, generation) {
        None => Err(RC_REVOKED),
        Some(t) => {
            let s = t.subs.get_mut(sub_id).ok_or(RC_BADARG)?;
            if !s.used || s.subscriber != tid {
                return Err(RC_DENIED);
            }
            if s.len == 0 {
                return Err(RC_EMPTY);
            }
            let m = s.q[s.head];
            s.head = (s.head + 1) % SUB_QUEUE_LEN;
            s.len -= 1;
            Ok(m)
        }
    }
}

/// Number of events dropped-newest on `tid`'s subscription (the auditable counter).
/// Part of the pub-sub API surface (a slow subscriber loses only its OWN events, and
/// the count + `seq` gaps make that loss auditable) even though the current self-test
/// exercises the never-full path.
#[allow(dead_code)]
pub fn dropped(index: usize, generation: u32, sub_id: usize) -> u64 {
    match topic_slot(index, generation) {
        None => 0,
        Some(t) => t.subs.get(sub_id).map(|s| s.dropped).unwrap_or(0),
    }
}

// ---------------------------------------------------------------------------
// Death-path teardown — MUST be called on EVERY way a TCB dies.
// ---------------------------------------------------------------------------

/// Detach `tid` from every object it waits on. Called on all three death paths (fault
/// restart, restart-budget kill, task exit) so a later Signal can NEVER write a badge
/// into a dead/reused thread's frame. Bounds-safe; idempotent.
pub fn detach_tcb(tid: usize) {
    unsafe {
        for n in (*addr_of_mut!(NOTIFY)).iter_mut() {
            // AUD-CAP-4: reclaim Notification objects OWNED by the dead task so their
            // slots (and the owner-keyed create quota) don't leak permanently — a reused
            // tid would otherwise inherit a dead owner's quota. Owner-death ends the
            // object, matching the create(owner) model and mirroring the subscription
            // reclaim below. A FOREIGN task parked on it is woken RC_REVOKED (never left
            // blocked forever); the generation bump makes any surviving cap fail closed.
            if n.used && n.owner == tid {
                if let Some(w) = n.waiter.take() {
                    if w != tid {
                        scheduler::deliver_wake(w, RC_REVOKED);
                        scheduler::unblock(w);
                    }
                }
                n.used = false;
                n.word = 0;
                n.generation = n.generation.wrapping_add(1);
                continue;
            }
            // Not owned by tid: just detach tid if it is parked here as a foreign waiter.
            if n.waiter == Some(tid) {
                n.waiter = None;
            }
        }
        for t in (*addr_of_mut!(TOPICS)).iter_mut() {
            for s in t.subs.iter_mut() {
                if s.waiter == Some(tid) {
                    s.waiter = None;
                }
                // Free this task's subscriptions so a reused tid can't inherit them.
                if s.used && s.subscriber == tid {
                    *s = EMPTY_SUB;
                }
            }
        }
    }
}

