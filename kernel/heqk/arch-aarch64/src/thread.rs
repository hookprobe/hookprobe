//! Thread context = a trap frame on the thread's stack, laid out to match the
//! save/restore in `vectors.s` (irq_entry). 34 u64 slots (272 bytes):
//!   [0..=30] = x0..x30   [31] = ELR_EL1   [32] = SPSR_EL1   [33] = pad
//! The scheduler treats a thread's context as an opaque `sp: usize`.

pub const FRAME_WORDS: usize = 34;
pub const FRAME_BYTES: usize = FRAME_WORDS * 8; // 272

/// Build the initial context for a new thread so that the first switch into it
/// `eret`s to `entry` (running at EL1h with IRQs enabled) on stack `stack_top`.
/// Returns the initial stack pointer to hand to the scheduler.
pub fn make_thread(stack_top: usize, entry: usize, arg: usize) -> usize {
    debug_assert!(stack_top % 16 == 0);
    let sp = (stack_top - FRAME_BYTES) as *mut u64;
    unsafe {
        for i in 0..FRAME_WORDS {
            core::ptr::write(sp.add(i), 0);
        }
        core::ptr::write(sp.add(0), arg as u64); // x0 = first argument
        core::ptr::write(sp.add(31), entry as u64); // ELR_EL1 = entry point
        core::ptr::write(sp.add(32), 0x5); // SPSR = EL1h, DAIF clear (IRQs on)
    }
    sp as usize
}
