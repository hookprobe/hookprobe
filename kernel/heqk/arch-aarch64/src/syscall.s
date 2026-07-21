// HookProbe microkernel — P3 EL0 entry + kernel resume (setjmp/longjmp style).
//
// enter_user(entry, user_sp): save the kernel's callee-saved context + SP + LR
// into KRESUME, then ERET into EL0 at `entry` on `user_sp`. resume_kernel():
// restore that context and RET — i.e. make enter_user() "return" to its caller.
// The syscall/fault handler calls resume_kernel() to bring control back to the
// kernel from EL0 (on the user's exit syscall or a contained fault).

.section .text

.global enter_user
enter_user:                          // x0 = entry, x1 = user_sp
    adrp    x2, KRESUME
    add     x2, x2, #:lo12:KRESUME
    stp     x19, x20, [x2, #0]
    stp     x21, x22, [x2, #16]
    stp     x23, x24, [x2, #32]
    stp     x25, x26, [x2, #48]
    stp     x27, x28, [x2, #64]
    stp     x29, x30, [x2, #80]
    mov     x3, sp
    str     x3, [x2, #96]
    msr     sp_el0, x1               // user stack
    msr     elr_el1, x0              // user entry
    mov     x3, #0x80                // SPSR = EL0t, IRQ masked
    msr     spsr_el1, x3
    eret

// -------- P3 user program: position-independent, copied into an EL0 page ------
// Does 3 syscalls (hello, getval, printval) then triggers a contained fault.
.global user_stub
.global user_stub_end
user_stub:
    mov     x8, #3                  // SYS_HELLO
    svc     #0
    mov     x8, #2                  // SYS_GETVAL -> x0
    svc     #0
    mov     x8, #4                  // SYS_PRINTVAL (a0 = x0 = returned value)
    svc     #0
    mov     x0, #3                  // CPtr 3 (a Frame in the root task's CSpace)
    mov     x8, #5                  // SYS_CAP_IDENTIFY: invoke a capability
    svc     #0
    movz    x9, #0xE000, lsl #16    // x9 = 0xE000_0000 (unmapped)
    str     x0, [x9]                // EL0 data abort -> kernel contains it
1:  b       1b
user_stub_end:

// -------- Driver-isolation demo: an EL0 driver server ------------------------
// Runs at EL0 with ONLY a granted device-MMIO window (0xE200_0000 -> the NIC's
// virtio-mmio page). Reads the NIC DeviceID register, reports it via syscall,
// and exits. It has no kernel access — a compromised driver is contained here.
.global driver_stub
.global driver_stub_end
driver_stub:
    movz    x10, #0xE200, lsl #16   // x10 = 0xE200_0000 (granted device window)
    movk    x10, #0x0e08            // x10 = 0xE200_0e08 (virtio-net DeviceID reg)
    ldr     w0, [x10]               // read the NIC register via the capability
    mov     x8, #7                  // SYS_DRIVER_REPORT (a0 = DeviceID)
    svc     #0
    mov     x8, #6                  // SYS_EXIT_USER
    svc     #0
1:  b       1b
driver_stub_end:

.global resume_kernel
resume_kernel:
    adrp    x2, KRESUME
    add     x2, x2, #:lo12:KRESUME
    ldp     x19, x20, [x2, #0]
    ldp     x21, x22, [x2, #16]
    ldp     x23, x24, [x2, #32]
    ldp     x25, x26, [x2, #48]
    ldp     x27, x28, [x2, #64]
    ldp     x29, x30, [x2, #80]
    ldr     x3, [x2, #96]
    mov     sp, x3
    ret                              // returns into enter_user()'s caller
