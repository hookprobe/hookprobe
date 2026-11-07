//! P3 — EL0 entry / kernel-resume glue (asm in `syscall.s`).

// Saved kernel context for the enter_user/resume_kernel longjmp:
// x19..x30 (12) + SP = 13 words. Referenced by name from `syscall.s`.
#[used]
#[no_mangle]
static mut KRESUME: [u64; 13] = [0; 13];

extern "C" {
    /// Drop to EL0 at `entry` on `user_sp`; returns (to enter_user's caller)
    /// only when the handler calls `resume_kernel`.
    pub fn enter_user(entry: usize, user_sp: usize);
    /// `enter_user` with IRQs UNMASKED at EL0 (SPSR = EL0t, D/A/F masked, I clear) — only for a
    /// BOUNDED excursion: the kernel arms the watchdog timer first, so a spinning EL0 service is
    /// preempted and returned from (ADR 0050 D5) instead of wedging an IRQs-off kernel loop.
    pub fn enter_user_irq(entry: usize, user_sp: usize);
    /// Restore the kernel context saved by `enter_user` and return into its
    /// caller. Called from the syscall/fault handler; never returns to it.
    pub fn resume_kernel() -> !;
}
