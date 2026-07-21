//! Thread context = a trap frame on the thread's KERNEL stack, laid out to match
//! the save/restore in `vectors.s` (irq_entry). 34 u64 slots (272 bytes):
//!   [0..=30] = x0..x30   [31] = ELR_EL1   [32] = SPSR_EL1   [33] = SP_EL0
//! The scheduler treats a thread's context as an opaque `sp: usize` (its kernel
//! stack pointer). A thread may run at EL1 (SPSR=EL1h, SP_EL0 unused) or EL0
//! (SPSR=EL0t, SP_EL0 = its user stack) — the same frame + `eret` handles both,
//! so EL0 tasks are preemptible scheduler TCBs, not a cooperative side-path (P7c).

pub const FRAME_WORDS: usize = 34;
pub const FRAME_BYTES: usize = FRAME_WORDS * 8; // 272

/// Build the initial context for a new EL1 kernel thread so the first switch into
/// it `eret`s to `entry` (EL1h, IRQs enabled) on stack `stack_top`.
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
        // slot 33 SP_EL0 = 0 (unused at EL1)
    }
    sp as usize
}

/// Build the initial context for a new **EL0** thread (a preemptible scheduler
/// TCB). `kstack_top` = its kernel stack (where its trap frames live), `entry` =
/// EL0 program counter, `user_sp` = its EL0 stack, `arg` = x0. The first switch
/// into it `eret`s to EL0 at `entry` with IRQs **enabled** — so the timer
/// preempts it like any thread (closes B-6). Returns the initial kernel sp.
pub fn make_el0_thread(kstack_top: usize, entry: usize, user_sp: usize, arg: usize) -> usize {
    debug_assert!(kstack_top % 16 == 0);
    let sp = (kstack_top - FRAME_BYTES) as *mut u64;
    unsafe {
        for i in 0..FRAME_WORDS {
            core::ptr::write(sp.add(i), 0);
        }
        core::ptr::write(sp.add(0), arg as u64); // x0 = first argument
        core::ptr::write(sp.add(31), entry as u64); // ELR_EL1 = EL0 entry
        core::ptr::write(sp.add(32), 0x0); // SPSR = EL0t, DAIF clear (IRQs ON → preemptible)
        core::ptr::write(sp.add(33), user_sp as u64); // SP_EL0 = user stack
    }
    sp as usize
}
