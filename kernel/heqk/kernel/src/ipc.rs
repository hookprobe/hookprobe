//! P4 — synchronous IPC over an Endpoint (register-passed message word).
//!
//! The rendezvous: whichever side arrives first blocks (via the scheduler); the
//! second side finds the waiter, hands over the message, and unblocks it. Single
//! endpoint for the demo (conceptually the Endpoint cap in the root CSpace);
//! multi-endpoint keyed by CPtr is the generalization. Critical sections mask
//! IRQs (single core) so the check-and-block is atomic against preemption.

use crate::scheduler;
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
