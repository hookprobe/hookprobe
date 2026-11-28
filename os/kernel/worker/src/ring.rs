// SPDX-License-Identifier: AGPL-3.0-only
//! Single-producer/single-consumer ring between two cores (the discipline of `ZEROCOPY_IPC_RING.md`:
//! the producer owns `head`, the consumer owns `tail`; a slot is published by a release store of
//! `head` and freed by a release store of `tail`).
//!
//! SPSC is enforced structurally, not by convention: the only way to push is a [`Producer`] and the
//! only way to pop is a [`Consumer`], and [`Ring::split`] hands out the pair exactly once.

use core::cell::UnsafeCell;
use core::mem::MaybeUninit;
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

/// Slots per ring (a power of two).
pub const SLOTS: usize = 64;

#[repr(C, align(64))]
struct Line(AtomicU32);

/// `head` and `tail` sit on separate cache lines so the two cores do not false-share.
#[repr(C)]
pub struct Ring<T: Copy> {
    head: Line,
    tail: Line,
    split: AtomicBool,
    slots: [UnsafeCell<MaybeUninit<T>>; SLOTS],
}

// SAFETY: slots are only written by the unique Producer before a release store of `head`, and only
// read by the unique Consumer after an acquire load of that `head`; the ring is shared, the slots
// are never accessed by both sides at once.
unsafe impl<T: Copy + Send> Sync for Ring<T> {}

impl<T: Copy> Ring<T> {
    pub const fn new() -> Self {
        Self {
            head: Line(AtomicU32::new(0)),
            tail: Line(AtomicU32::new(0)),
            split: AtomicBool::new(false),
            slots: [const { UnsafeCell::new(MaybeUninit::uninit()) }; SLOTS],
        }
    }

    /// The two endpoints, once. A second call returns `None`.
    pub fn split(&'static self) -> Option<(Producer<T>, Consumer<T>)> {
        if self.split.swap(true, Ordering::AcqRel) {
            return None;
        }
        Some((Producer { r: self }, Consumer { r: self }))
    }

    /// Entries currently queued (a snapshot; exact only from one of the two endpoints).
    pub fn len(&self) -> usize {
        self.head.0.load(Ordering::Acquire).wrapping_sub(self.tail.0.load(Ordering::Acquire)) as usize
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl<T: Copy> Default for Ring<T> {
    fn default() -> Self {
        Self::new()
    }
}

/// The unique push side.
pub struct Producer<T: Copy + 'static> {
    r: &'static Ring<T>,
}

/// The unique pop side.
pub struct Consumer<T: Copy + 'static> {
    r: &'static Ring<T>,
}

// The endpoints move to the core that uses them (core 0 hands the worker its ends at start).
unsafe impl<T: Copy + Send> Send for Producer<T> {}
unsafe impl<T: Copy + Send> Send for Consumer<T> {}

impl<T: Copy> Producer<T> {
    /// Queue `v`; `false` if the ring is full.
    pub fn push(&mut self, v: T) -> bool {
        let h = self.r.head.0.load(Ordering::Relaxed);
        let t = self.r.tail.0.load(Ordering::Acquire);
        if h.wrapping_sub(t) as usize >= SLOTS {
            return false;
        }
        let slot = &self.r.slots[(h as usize) & (SLOTS - 1)];
        // SAFETY: slot h is not visible to the consumer until the release store below, and the
        // consumer has released it (tail moved past it) per the acquire load above.
        unsafe { (*slot.get()).write(v) };
        self.r.head.0.store(h.wrapping_add(1), Ordering::Release);
        true
    }
}

impl<T: Copy> Consumer<T> {
    pub fn pop(&mut self) -> Option<T> {
        let t = self.r.tail.0.load(Ordering::Relaxed);
        let h = self.r.head.0.load(Ordering::Acquire);
        if h == t {
            return None;
        }
        let slot = &self.r.slots[(t as usize) & (SLOTS - 1)];
        // SAFETY: the acquire load of head made the producer's write of slot t visible, and the
        // producer will not reuse it until the release store of tail below.
        let v = unsafe { (*slot.get()).assume_init_read() };
        self.r.tail.0.store(t.wrapping_add(1), Ordering::Release);
        Some(v)
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;

    #[test]
    fn split_once_fifo_and_full() {
        static R: Ring<u64> = Ring::new();
        let (mut p, mut c) = R.split().unwrap();
        assert!(R.split().is_none());
        assert_eq!(c.pop(), None);
        for i in 0..SLOTS as u64 {
            assert!(p.push(i));
        }
        assert!(!p.push(999), "full");
        for i in 0..SLOTS as u64 {
            assert_eq!(c.pop(), Some(i));
        }
        assert_eq!(c.pop(), None);
    }

    #[test]
    fn two_threads_in_order() {
        static R: Ring<u64> = Ring::new();
        let (mut p, mut c) = R.split().unwrap();
        const N: u64 = 2_000_000;
        let t = std::thread::spawn(move || {
            let mut i = 0;
            while i < N {
                if p.push(i) {
                    i += 1;
                }
            }
        });
        let mut want = 0;
        while want < N {
            if let Some(v) = c.pop() {
                assert_eq!(v, want);
                want += 1;
            }
        }
        t.join().unwrap();
    }
}
