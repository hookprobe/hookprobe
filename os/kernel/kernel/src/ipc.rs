//! P4 — synchronous IPC over an Endpoint (register-passed message word).
//!
//! The rendezvous: whichever side arrives first blocks (via the scheduler); the
//! second side finds the waiter, hands over the message, and unblocks it. Single
//! endpoint for the demo (conceptually the Endpoint cap in the root CSpace);
//! multi-endpoint keyed by CPtr is the generalization. Critical sections mask
//! IRQs (single core) so the check-and-block is atomic against preemption.

use crate::scheduler;
use abi::{RC_DENIED, RC_NORESOURCE, RC_OK, RC_REVOKED};
use core::ptr::{addr_of, addr_of_mut};

static mut RECV_WAITER: Option<usize> = None;
static mut SEND_WAITER: Option<usize> = None;
// Two distinct slots, not one shared `MSG`: `SEND_MSG` is the word a *waiting
// sender* parked; `DELIVERED` is the word handed to a *woken receiver*. Sharing
// one slot let a second sender (taking the no-receiver branch after the first
// delivery cleared RECV_WAITER) overwrite a message the woken receiver had not
// yet read. Separating them makes delivery a private handoff.
static mut SEND_MSG: u64 = 0;
static mut DELIVERED: Option<u64> = None;

#[inline]
fn wait_until_runnable() {
    let me = scheduler::current_tid();
    while scheduler::is_blocked(me) {
        unsafe { core::arch::asm!("wfe") };
    }
}

/// Receive a message word (blocks until a sender rendezvous). CORE-11: returns
/// `Some(word)` on a real delivery, `None` when the endpoint is busy (a second
/// concurrent receiver is refused) — the old `0` was ambiguous with a genuine
/// 0-word message.
pub fn recv() -> Option<u64> {
    arch_aarch64::disable_irqs();
    if let Some(sender) = unsafe { addr_of!(SEND_WAITER).read() } {
        // A sender is already waiting: take its parked message, wake it.
        let m = unsafe { addr_of!(SEND_MSG).read() };
        unsafe { addr_of_mut!(SEND_WAITER).write(None) };
        scheduler::unblock(sender);
        arch_aarch64::enable_irqs();
        Some(m)
    } else {
        // No sender yet: register as receiver and block. Refuse a second
        // concurrent receiver rather than overwrite the waiter slot.
        if unsafe { addr_of!(RECV_WAITER).read() }.is_some() {
            arch_aarch64::enable_irqs();
            return None; // endpoint busy
        }
        unsafe { addr_of_mut!(RECV_WAITER).write(Some(scheduler::current_tid())) };
        scheduler::block_current();
        arch_aarch64::enable_irqs();
        wait_until_runnable();
        // Woken by a sender that handed us a private DELIVERED word.
        arch_aarch64::disable_irqs();
        let m = unsafe { addr_of!(DELIVERED).read() };
        unsafe {
            addr_of_mut!(DELIVERED).write(None);
            addr_of_mut!(RECV_WAITER).write(None);
        }
        arch_aarch64::enable_irqs();
        m
    }
}

/// Send a message word (rendezvous with a receiver; blocks if none waiting).
/// CORE-11: returns `false` when the endpoint is busy (a second concurrent sender
/// is refused rather than clobbering the parked message), `true` otherwise.
pub fn send(msg: u64) -> bool {
    arch_aarch64::disable_irqs();
    if let Some(receiver) = unsafe { addr_of!(RECV_WAITER).read() } {
        // A receiver is waiting: deliver, CLEAR the waiter at the moment of
        // delivery (so a second sender can't re-deliver to an already-woken
        // receiver and clobber this message), and wake it.
        unsafe {
            addr_of_mut!(DELIVERED).write(Some(msg));
            addr_of_mut!(RECV_WAITER).write(None);
        }
        scheduler::unblock(receiver);
        arch_aarch64::enable_irqs();
        true
    } else {
        // No receiver yet: park the message and block until one takes it. This
        // single-endpoint rendezvous supports one waiter per side; refuse a
        // second concurrent sender rather than silently overwrite (lost wakeup).
        // A multi-waiter queue is the generalization (keyed by Endpoint cap).
        if unsafe { addr_of!(SEND_WAITER).read() }.is_some() {
            arch_aarch64::enable_irqs();
            return false; // endpoint busy: drop rather than corrupt the waiter slot
        }
        unsafe {
            addr_of_mut!(SEND_MSG).write(msg);
            addr_of_mut!(SEND_WAITER).write(Some(scheduler::current_tid()));
        }
        scheduler::block_current();
        arch_aarch64::enable_irqs();
        wait_until_runnable();
        true
    }
}

// ===========================================================================
// R1 (M5.0) — cap-gated SYNCHRONOUS IPC: seL4-style Call / Recv / Reply.
// ===========================================================================
//
// The P4 rendezvous above is a single GLOBAL endpoint (a pre-capability demo). R1
// makes the Endpoint a real, capability-named kernel OBJECT: an EL0 task may Call /
// Recv / Reply ONLY through an Endpoint cap resolved from its OWN per-TCB CSpace
// (CORE-2, `resolve_ep_cap` in main.rs). A missing / wrong-type / insufficient-rights
// cap fails CLOSED with `RC_DENIED` BEFORE any rendezvous. Objects are named by
// `(index, generation)` — NEVER a pointer; a stale cap fails `RC_REVOKED`, and a TCB
// parked on an endpoint is woken `RC_DENIED` (never left hung) when the cap is revoked
// (the sever hook `caps::revoke` fires — the exact analogue of CORE-1's Frame-unmap).
//
// This is the R1 IPC beachhead: the Endpoint cap is now a real ENFORCED mechanism the
// ELF loader (M5.1) and Wasm host (M5.2) inherit. It is NOT the app-host / ELF loader /
// Wasm runtime (the multi-year road; ADR 0044 D5).
//
// Payload: a single fixed message word (x1) each way (no heap). The rendezvous is
// single-outstanding per endpoint for the beachhead — a second concurrent caller or
// receiver is refused `RC_NORESOURCE` rather than clobbering the slot (the P4
// single-waiter discipline, generalized to a capability-named object).

/// How many synchronous-IPC endpoint OBJECTS the kernel can hold. Kept tiny — the R1
/// beachhead needs a handful; the full seL4 waiter-queue endpoint is a later step.
pub const MAX_ENDPOINTS: usize = 16; // M5.5:+2 wasip1; A2+:+2 wasip1-dnsrpz catalogue hosts (was 8/12)

/// The outcome of a `call`/`recv_ep` the syscall layer turns into block / return / error.
pub enum IpcOut {
    /// Return this word to the caller NOW, no block (a `Recv` that found a parked call).
    Ready(u64),
    /// The caller must BLOCK the current TCB (a rendezvous is pending; it is woken later).
    Block,
    /// An error code (revoked / busy) — return it now, no block, FAIL CLOSED.
    Rc(u64),
}

#[derive(Clone, Copy)]
struct Endpoint {
    used: bool,
    generation: u32,            // bumped on sever/destroy so a stale cap fails closed
    recv_waiter: Option<usize>, // a server BLOCKED in RECV awaiting a CALL
    call_waiter: Option<usize>, // a client BLOCKED in CALL, msg parked, not yet received
    call_msg: u64,              // the message word parked by `call_waiter`
    reply_to: Option<usize>,    // the client being served — BLOCKED awaiting REPLY
    server: Option<usize>,      // the TCB currently SERVING (received the call, not yet replied)
}
const EMPTY_EP: Endpoint = Endpoint {
    used: false,
    generation: 0,
    recv_waiter: None,
    call_waiter: None,
    call_msg: 0,
    reply_to: None,
    server: None,
};
static mut ENDPOINTS: [Endpoint; MAX_ENDPOINTS] = [EMPTY_EP; MAX_ENDPOINTS];

/// An opaque endpoint-object handle: `(index, generation)`. This is what an Endpoint
/// cap stores (`Cap::base` = index, `Cap::watermark` = generation); NEVER returned to EL0.
#[derive(Clone, Copy)]
pub struct EpHandle {
    pub index: usize,
    pub generation: u32,
}

#[inline]
fn ep_slot(index: usize, generation: u32) -> Option<&'static mut Endpoint> {
    if index >= MAX_ENDPOINTS {
        return None; // fail CLOSED: out-of-range index is never a live object
    }
    let e = unsafe { &mut (*addr_of_mut!(ENDPOINTS))[index] };
    if e.used && e.generation == generation {
        Some(e)
    } else {
        None // fail CLOSED: unused slot or stale generation
    }
}

/// Statically create an Endpoint object (kernel-side, Microkit-style; NOT an EL0
/// syscall). Returns its `(index, generation)` to stamp into an Endpoint cap via
/// `CapSpace::install_object`. Generation is NEVER reset on reuse (monotonic), so a cap
/// minted over a previous tenant of a slot can never alias a fresh object. Fails-closed
/// `None` if the table is full.
#[allow(dead_code)]
pub fn ep_create() -> Option<EpHandle> {
    unsafe {
        let tbl = &mut *addr_of_mut!(ENDPOINTS);
        for i in 0..MAX_ENDPOINTS {
            if !tbl[i].used {
                let g = tbl[i].generation; // preserve the monotonic generation across reuse
                tbl[i] = EMPTY_EP;
                tbl[i].used = true;
                tbl[i].generation = g;
                return Some(EpHandle { index: i, generation: g });
            }
        }
        None
    }
}

/// `Call`: send `msg` and BLOCK until a `Reply`. If a server is already parked in RECV,
/// hand it the message directly (via its saved x0) and record this caller as the one
/// awaiting reply; otherwise park the message and block until a server RECVs it. The
/// caller ALWAYS blocks (Call = send + wait-for-reply). A SECOND outstanding call on the
/// same endpoint is refused `RC_NORESOURCE` — single-outstanding rendezvous for R1.
/// Returns `Rc(RC_REVOKED)` (fail closed) if the object is stale/absent.
pub fn call(index: usize, generation: u32, msg: u64, caller: usize) -> IpcOut {
    match ep_slot(index, generation) {
        None => IpcOut::Rc(RC_REVOKED),
        Some(e) => {
            if e.call_waiter.is_some() || e.reply_to.is_some() {
                return IpcOut::Rc(RC_NORESOURCE); // one call in flight per endpoint
            }
            if let Some(server) = e.recv_waiter.take() {
                // Server waiting: deliver the message straight into its RECV return
                // (frame word 0 = x0), record this caller as awaiting reply, wake it.
                // Track the serving TCB so its death (before REPLY) can be recovered.
                e.reply_to = Some(caller);
                e.server = Some(server);
                scheduler::deliver_wake(server, msg);
                scheduler::unblock(server);
            } else {
                // No server yet: park the message; a later RECV picks it up.
                e.call_waiter = Some(caller);
                e.call_msg = msg;
            }
            IpcOut::Block // the caller blocks until REPLY either way (Call semantics)
        }
    }
}

/// `Recv`: BLOCK until a `Call` rendezvous. If a caller has already parked a message,
/// take it (moving that caller to await-reply) and return it WITHOUT blocking; else
/// register as the receiver and block. A SECOND concurrent receiver — or a RECV while a
/// prior call still awaits its reply — is refused `RC_NORESOURCE`. Fail-closed
/// `Rc(RC_REVOKED)` on a stale/absent object.
pub fn recv_ep(index: usize, generation: u32, server: usize) -> IpcOut {
    match ep_slot(index, generation) {
        None => IpcOut::Rc(RC_REVOKED),
        Some(e) => {
            if e.reply_to.is_some() {
                return IpcOut::Rc(RC_NORESOURCE); // must REPLY the current call first
            }
            if let Some(caller) = e.call_waiter.take() {
                let m = e.call_msg;
                e.call_msg = 0;
                e.reply_to = Some(caller); // the caller stays blocked until REPLY
                e.server = Some(server); // this RECVer is now serving until it REPLYs
                IpcOut::Ready(m)
            } else if e.recv_waiter.is_some() {
                IpcOut::Rc(RC_NORESOURCE) // one server per endpoint
            } else {
                e.recv_waiter = Some(server);
                IpcOut::Block
            }
        }
    }
}

/// `Reply`: wake the caller currently being served with `word` (into its saved x0).
/// NEVER blocks the replier. `RC_OK` on delivery; `RC_NORESOURCE` if no call is
/// outstanding; `RC_REVOKED` (fail closed) if the object is stale/absent.
pub fn reply(index: usize, generation: u32, word: u64) -> u64 {
    match ep_slot(index, generation) {
        None => RC_REVOKED,
        Some(e) => match e.reply_to.take() {
            Some(caller) => {
                e.server = None; // serving complete — endpoint free for a new rendezvous
                scheduler::deliver_wake(caller, word);
                scheduler::unblock(caller);
                RC_OK
            }
            None => RC_NORESOURCE,
        },
    }
}

/// The IPC-sever hook `caps::revoke` fires when it DELETES an Endpoint cap — the exact
/// analogue of CORE-1's Frame-unmap-on-revoke. Revoking authority to an endpoint tears
/// its rendezvous down FAIL-CLOSED: every TCB parked on the object (a blocked caller,
/// server, or served caller) is woken with `RC_DENIED` (never left hung), and the
/// object's generation is bumped + the slot freed so ALL caps naming it — including a
/// KEPT parent whose subtree was revoked — now fail closed (`RC_REVOKED`) on next use.
/// Safe no-op if `index/generation` names no LIVE object (e.g. a retyped-Endpoint cap
/// whose `base` is a nominal physical address, not a small object index — the P2 caps
/// self-tests). Returns the count of parked TCBs woken (for the R1 (c) self-test).
pub fn on_endpoint_cap_deleted(index: usize, generation: u32) -> usize {
    match ep_slot(index, generation) {
        None => 0,
        Some(e) => {
            let mut woken = 0usize;
            for w in [e.recv_waiter.take(), e.call_waiter.take(), e.reply_to.take()] {
                if let Some(tid) = w {
                    scheduler::deliver_wake(tid, RC_DENIED); // severed authority -> DENIED
                    scheduler::unblock(tid); // never leave a parked TCB hung
                    woken += 1;
                }
            }
            e.server = None;
            e.used = false;
            e.call_msg = 0;
            e.generation = e.generation.wrapping_add(1); // stale every cap -> fail closed
            woken
        }
    }
}

/// Detach `tid` from every endpoint it is parked on (a death path). Mirrors
/// `notify::detach_tcb` — called on ALL TCB death paths so a later reply/sever can never
/// write a word into a dead / reused thread's trap frame. Bounds-safe; idempotent.
///
/// LIVENESS (server-death recovery): a server that RECVs a call and then dies/faults
/// BEFORE `reply` would otherwise strand its client forever — `reply_to` holds the
/// CLIENT, so clearing only `reply_to==tid` (the client-death case) never matched a
/// dying SERVER, leaving the endpoint permanently `reply_to=Some` → every future
/// `call`/`recv_ep` on it returns `RC_NORESOURCE` (a shared IPC channel bricked by one
/// compromised EL0 module). Here, if the dying `tid` is the serving TCB, we wake its
/// stranded client `RC_DENIED` and reset the rendezvous so the endpoint recovers.
pub fn detach_tcb(tid: usize) {
    unsafe {
        for e in (*addr_of_mut!(ENDPOINTS)).iter_mut() {
            if e.recv_waiter == Some(tid) {
                e.recv_waiter = None;
            }
            if e.call_waiter == Some(tid) {
                e.call_waiter = None;
                e.call_msg = 0;
            }
            // Serving TCB died before REPLY: recover the endpoint, don't strand the client.
            if e.server == Some(tid) {
                e.server = None;
                if let Some(client) = e.reply_to.take() {
                    scheduler::deliver_wake(client, RC_DENIED);
                    scheduler::unblock(client); // never leave the client hung
                }
            }
            if e.reply_to == Some(tid) {
                e.reply_to = None;
            }
        }
    }
}

/// Test-only: does a live endpoint object exist for `(index, generation)`?
#[cfg(not(feature = "cm5"))]
pub fn ep_exists(index: usize, generation: u32) -> bool {
    ep_slot(index, generation).is_some()
}

/// Test-only: park `tid` as the RECV waiter on an endpoint WITHOUT going through the
/// scheduler block path, so the R1 (c) self-test can then revoke the cap and OBSERVE
/// the sever hook wake it. Fail-closed no-op on a stale/absent object.
#[cfg(not(feature = "cm5"))]
pub fn park_recv_for_test(index: usize, generation: u32, tid: usize) {
    if let Some(e) = ep_slot(index, generation) {
        e.recv_waiter = Some(tid);
    }
}
