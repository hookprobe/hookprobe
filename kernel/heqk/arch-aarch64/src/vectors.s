// HookProbe microkernel — EL1 exception vector table (P0 + P1 IRQ path).
// AArch64 layout: 2 KiB-aligned base, 16 entries, each 0x80 (128) bytes apart,
// in 4 groups of 4 (Sync, IRQ, FIQ, SError) x (SP0, SPx, LowerA64, LowerA32).
// IRQ-from-current-EL (slot 5) does a full context save/switch/restore for the
// preemptive scheduler; every other slot reports and exits (P0 policy).

.section .text

.macro VTENTRY idx
    .align 7                 // 0x80-byte slot
    mov     x0, #\idx
    b       __exception_common
.endm

    .align 11                // 2 KiB alignment for VBAR_EL1
.global __vectors
__vectors:
    VTENTRY 0                // Sync   / Current EL, SP0
    VTENTRY 1                // IRQ    / Current EL, SP0
    VTENTRY 2                // FIQ    / Current EL, SP0
    VTENTRY 3                // SError / Current EL, SP0
    // ---- Sync / Current EL, SPx (slot 4) ----
    .align 7
    mov     x0, #4
    b       __exception_common
    // ---- IRQ / Current EL, SPx (slot 5): the scheduler tick path ----
    .align 7
    b       irq_entry
    VTENTRY 6                // FIQ    / Current EL, SPx
    VTENTRY 7                // SError / Current EL, SPx
    // ---- Sync / Lower EL AArch64 (slot 8): EL0 syscalls + fault containment ----
    .align 7
    b       lower_sync_entry
    // ---- IRQ / Lower EL AArch64 (slot 9): EL0 preemption -> scheduler ----
    .align 7
    b       irq_entry                // timer IRQ while at EL0 -> save frame + reschedule
    VTENTRY 10               // FIQ    / Lower EL, AArch64
    VTENTRY 11               // SError / Lower EL, AArch64
    VTENTRY 12               // Sync   / Lower EL, AArch32
    VTENTRY 13               // IRQ    / Lower EL, AArch32
    VTENTRY 14               // FIQ    / Lower EL, AArch32
    VTENTRY 15               // SError / Lower EL, AArch32

// ---------------------------------------------------------------------------
// IRQ entry: save the full trap frame (34 words) on the current stack, call
// handle_irq(sp)->new_sp (defined in the kernel crate), switch to new_sp,
// restore, and eret. Frame layout matches arch-aarch64/src/thread.rs.
// ---------------------------------------------------------------------------
irq_entry:
    sub     sp,  sp,  #272
    stp     x0,  x1,  [sp, #0]
    stp     x2,  x3,  [sp, #16]
    stp     x4,  x5,  [sp, #32]
    stp     x6,  x7,  [sp, #48]
    stp     x8,  x9,  [sp, #64]
    stp     x10, x11, [sp, #80]
    stp     x12, x13, [sp, #96]
    stp     x14, x15, [sp, #112]
    stp     x16, x17, [sp, #128]
    stp     x18, x19, [sp, #144]
    stp     x20, x21, [sp, #160]
    stp     x22, x23, [sp, #176]
    stp     x24, x25, [sp, #192]
    stp     x26, x27, [sp, #208]
    stp     x28, x29, [sp, #224]
    mrs     x9,  elr_el1
    mrs     x10, spsr_el1
    stp     x30, x9,  [sp, #240]     // x30, ELR_EL1
    str     x10,      [sp, #256]     // SPSR_EL1
    mrs     x11, sp_el0
    str     x11,      [sp, #264]     // SP_EL0 (EL0 threads; harmless for EL1)

    mov     x0,  sp
    bl      handle_irq               // returns next thread's sp in x0
    mov     sp,  x0

    ldr     x11,      [sp, #264]
    msr     sp_el0,   x11            // SP_EL0 of the thread we're resuming
    ldr     x10,      [sp, #256]
    ldp     x30, x9,  [sp, #240]
    msr     elr_el1,  x9
    msr     spsr_el1, x10
    ldp     x0,  x1,  [sp, #0]
    ldp     x2,  x3,  [sp, #16]
    ldp     x4,  x5,  [sp, #32]
    ldp     x6,  x7,  [sp, #48]
    ldp     x8,  x9,  [sp, #64]
    ldp     x10, x11, [sp, #80]
    ldp     x12, x13, [sp, #96]
    ldp     x14, x15, [sp, #112]
    ldp     x16, x17, [sp, #128]
    ldp     x18, x19, [sp, #144]
    ldp     x20, x21, [sp, #160]
    ldp     x22, x23, [sp, #176]
    ldp     x24, x25, [sp, #192]
    ldp     x26, x27, [sp, #208]
    ldp     x28, x29, [sp, #224]
    add     sp,  sp,  #272
    eret

// ---------------------------------------------------------------------------
// Sync from EL0: save the trap frame, call handle_lower_sync(frame). For an SVC
// it services the syscall and returns here -> restore + eret back to EL0. For a
// fault it calls resume_kernel() (never returns), containing the user fault.
// ---------------------------------------------------------------------------
lower_sync_entry:
    sub     sp,  sp,  #272
    stp     x0,  x1,  [sp, #0]
    stp     x2,  x3,  [sp, #16]
    stp     x4,  x5,  [sp, #32]
    stp     x6,  x7,  [sp, #48]
    stp     x8,  x9,  [sp, #64]
    stp     x10, x11, [sp, #80]
    stp     x12, x13, [sp, #96]
    stp     x14, x15, [sp, #112]
    stp     x16, x17, [sp, #128]
    stp     x18, x19, [sp, #144]
    stp     x20, x21, [sp, #160]
    stp     x22, x23, [sp, #176]
    stp     x24, x25, [sp, #192]
    stp     x26, x27, [sp, #208]
    stp     x28, x29, [sp, #224]
    mrs     x9,  elr_el1
    mrs     x10, spsr_el1
    stp     x30, x9,  [sp, #240]
    str     x10,      [sp, #256]

    mov     x0,  sp
    bl      handle_lower_sync        // SVC: services + returns; fault: resume_kernel (no return)

    ldr     x10,      [sp, #256]
    ldp     x30, x9,  [sp, #240]
    msr     elr_el1,  x9
    msr     spsr_el1, x10
    ldp     x0,  x1,  [sp, #0]
    ldp     x2,  x3,  [sp, #16]
    ldp     x4,  x5,  [sp, #32]
    ldp     x6,  x7,  [sp, #48]
    ldp     x8,  x9,  [sp, #64]
    ldp     x10, x11, [sp, #80]
    ldp     x12, x13, [sp, #96]
    ldp     x14, x15, [sp, #112]
    ldp     x16, x17, [sp, #128]
    ldp     x18, x19, [sp, #144]
    ldp     x20, x21, [sp, #160]
    ldp     x22, x23, [sp, #176]
    ldp     x24, x25, [sp, #192]
    ldp     x26, x27, [sp, #208]
    ldp     x28, x29, [sp, #224]
    add     sp,  sp,  #272
    eret

__exception_common:
    // x0 already holds the vector index. Pass syndrome/fault registers.
    mrs     x1, esr_el1
    mrs     x2, elr_el1
    mrs     x3, far_el1
    bl      rust_exception
0:  wfe
    b       0b
