//! Minimal kernel heap: a bump allocator over a static region. No reclaim —
//! adequate for P1 (a few long-lived allocations). A real allocator arrives
//! with the physical frame allocator + MMU at P1b/P2. Zero external deps.

use core::alloc::{GlobalAlloc, Layout};
use core::cell::UnsafeCell;
use core::ptr::null_mut;
use core::sync::atomic::{AtomicUsize, Ordering};

const HEAP_SIZE: usize = 1 << 20; // 1 MiB

#[repr(align(16))]
struct Region(UnsafeCell<[u8; HEAP_SIZE]>);
unsafe impl Sync for Region {}

static REGION: Region = Region(UnsafeCell::new([0; HEAP_SIZE]));

pub struct Bump {
    off: AtomicUsize,
}

#[global_allocator]
static ALLOCATOR: Bump = Bump {
    off: AtomicUsize::new(0),
};

unsafe impl GlobalAlloc for Bump {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let base = REGION.0.get() as *mut u8 as usize;
        let mut cur = self.off.load(Ordering::Relaxed);
        loop {
            let start = (base + cur + layout.align() - 1) & !(layout.align() - 1);
            let new_off = start - base + layout.size();
            if new_off > HEAP_SIZE {
                return null_mut();
            }
            match self.off.compare_exchange_weak(
                cur,
                new_off,
                Ordering::SeqCst,
                Ordering::Relaxed,
            ) {
                Ok(_) => return start as *mut u8,
                Err(actual) => cur = actual,
            }
        }
    }

    unsafe fn dealloc(&self, _ptr: *mut u8, _layout: Layout) {
        // bump allocator: no reclaim
    }
}

/// Bytes handed out so far (for diagnostics).
pub fn used() -> usize {
    ALLOCATOR.off.load(Ordering::Relaxed)
}
