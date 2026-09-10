// HBoot — HEQK boot manager, aarch64 entry stub (CM5/BCM2712).
// Carries the console doctrine proven during kernel bring-up (2026-07-21):
//   mask DAIF -> vectors (with resident hvc-reboot gate) -> own the console
//   (clk_uart from xosc, pinmux, PL011, READ-BACK after every programming
//   step — posted-PCIe-write races killed consoles without them) -> Rust.
// HBoot runs and STAYS at EL2: the kernel is launched at EL1 and reaches the
// PM reset only through `hvc #0` into our vector table.

.section .text.boot

// ---- ARM64 Linux Image header, byte-mimic of what the EEPROM boots -------
.global _image_header
_image_header:
    .long   0xfa405a4d          // "MZ" (harmless ccmp)
    b       _start
    .quad   0                   // text_offset
    .quad   0x400000            // image_size (HBoot slot + payload window)
    .quad   0xc                 // LE | 16K pages | anywhere
    .quad   0
    .quad   0
    .quad   0
    .long   0x644d5241          // "ARM\x64"
    .long   0

.global _start
_start:
    mov     x21, x0             // firmware DTB PA — stash before ANY clobber
    mrs     x2, mpidr_el1
    and     x2, x2, #0xff
    cbnz    x2, park

    msr     daifset, #0xf

    adr     x0, __hboot_vectors
    msr     vbar_el2, x0
    isb

    // ---- console bring-up with read-back discipline ----------------------
    movz    x8, #0x8000             // RP1 clocks @0x1C00018000
    movk    x8, #0x0001, lsl #16
    movk    x8, #0x001c, lsl #32
    mov     w10, #1
    str     w10, [x8, #0x58]        // CLK_UART_DIV_INT = 1
    ldr     w10, [x8, #0x58]        // read-back (posted-write fence)
    movz    w10, #0x0840            // ENABLE | AUXSRC=2 (xosc 50 MHz)
    str     w10, [x8, #0x54]
    ldr     w10, [x8, #0x54]

    movz    x8, #0x0074             // IO_BANK0 GPIO14_CTRL
    movk    x8, #0x000d, lsl #16
    movk    x8, #0x001c, lsl #32
    mov     w10, #4
    str     w10, [x8]
    ldr     w10, [x8]
    mov     w10, #4
    str     w10, [x8, #8]
    ldr     w10, [x8, #8]
    movz    x8, #0x003c             // PADS_BANK0 GPIO14
    movk    x8, #0x000f, lsl #16
    movk    x8, #0x001c, lsl #32
    ldr     w10, [x8]
    bic     w10, w10, #0x80
    orr     w10, w10, #0x40
    str     w10, [x8]
    ldr     w10, [x8]
    ldr     w10, [x8, #4]
    bic     w10, w10, #0x80
    orr     w10, w10, #0x40
    str     w10, [x8, #4]
    ldr     w10, [x8, #4]

    movz    x20, #0x0000            // PL011 @0x1C00030000
    movk    x20, #0x0003, lsl #16
    movk    x20, #0x001c, lsl #32
    str     wzr, [x20, #0x30]
    ldr     w10, [x20, #0x30]
    str     wzr, [x20, #0x2c]
    ldr     w10, [x20, #0x2c]
    mov     w10, #0x7ff
    str     w10, [x20, #0x44]
    mov     w10, #27
    str     w10, [x20, #0x24]
    ldr     w10, [x20, #0x24]
    mov     w10, #8
    str     w10, [x20, #0x28]
    ldr     w10, [x20, #0x28]
    mov     w10, #0x70
    str     w10, [x20, #0x2c]
    ldr     w10, [x20, #0x2c]
    mov     w10, #0x301
    str     w10, [x20, #0x30]
    ldr     w10, [x20, #0x30]

    // stack + bss, then Rust (still at EL2)
    adrp    x0, __stack_top
    add     x0, x0, #:lo12:__stack_top
    mov     sp, x0

    adrp    x0, __bss_start
    add     x0, x0, #:lo12:__bss_start
    adrp    x1, __bss_end
    add     x1, x1, #:lo12:__bss_end
1:  cmp     x0, x1
    b.hs    2f
    str     xzr, [x0], #8
    b       1b
2:
    mov     x0, x21                 // DTB PA (transitional; see stash note)
    bl      hboot_main
    b       park                    // hboot_main must not return

// Launch the verified kernel at EL1. x0 = entry PA, x1 = BootInfo PA.
// Exact register recipe proven by the kernel's own EL2->EL1 drop.
.global hboot_launch_el1
hboot_launch_el1:
    mov     x4, x0                  // entry
    mov     x5, x1                  // bootinfo
    mov     x0, #(1 << 31)          // HCR_EL2.RW = EL1 is AArch64
    orr     x0, x0, #(1 << 0)       // HCR_EL2.VM = enable stage-2 for EL1&0 (P7e)
    msr     hcr_el2, x0
    isb                             // stage-2 now active for lower ELs
    // Let EL1 use the physical counter + timer without trapping to EL2:
    // CNTHCTL_EL2.EL1PCTEN(bit0) | EL1PCEN(bit1). Without this the kernel's
    // CNTP_* access (P7b timer) traps to EL2 and stalls.
    mrs     x0, cnthctl_el2
    orr     x0, x0, #0b11
    msr     cnthctl_el2, x0
    msr     cntvoff_el2, xzr        // zero virtual offset
    mov     x0, #0x3c5              // EL1h, DAIF masked
    msr     spsr_el2, x0
    movz    x0, #0xff00, lsl #16    // temp EL1 stack @0x00FF0000 (kernel
    msr     sp_el1, x0              // installs its own immediately)
    msr     elr_el2, x4
    mov     x0, x5                  // BootInfo -> kernel x0
    movz    x1, #0x4248             // HBOOT_ENTRY_MAGIC "HBOT" -> kernel x1
    movk    x1, #0x544f, lsl #16
    ic      iallu                   // fresh I-cache for relocated payload
    dsb     sy
    isb
    eret

// Clean full-SoC reset via the PM block @0x107D200000 (works from EL2).
.global reset_platform
reset_platform:
    movz    x9, #0x0000
    movk    x9, #0x7d20, lsl #16
    movk    x9, #0x0010, lsl #32
    movz    w12, #0x5a00, lsl #16
    ldr     w10, [x9, #0x20]
    movz    w11, #0x0555
    bic     w10, w10, w11
    orr     w10, w10, w12
    str     w10, [x9, #0x20]
    movz    w10, #10
    orr     w10, w10, w12
    str     w10, [x9, #0x24]
    ldr     w10, [x9, #0x1c]
    bic     w10, w10, #0x30
    orr     w10, w10, #0x20
    orr     w10, w10, w12
    str     w10, [x9, #0x1c]
1:  wfe
    b       1b

.global park
park:
    wfe
    b       park

// Resident EL2 vectors: `hvc #0` from EL1 = reboot request; EL1 fault = '?'
// then reset; EL2-local faults = '!' then park.
.macro HB_VEC
    .balign 0x80
    movz    x9, #0x0000
    movk    x9, #0x0003, lsl #16
    movk    x9, #0x001c, lsl #32
    mov     w11, #0x21              // '!'
81: ldr     w12, [x9, #0x18]
    tbnz    w12, #5, 81b
    strb    w11, [x9]
82: wfe
    b       82b
.endm

// Save EL1's GP regs (x9-x13) on the EL2 stack FIRST — before `mrs esr`
// clobbers x10 — so a CONTAINED fault (el1_blocked, which returns to EL1) leaves
// EL1 state intact. Reset paths (HVC/other-fault) don't return, so their
// unbalanced SP is irrelevant (the SoC resets). Nested hole-faults balance
// push/pop each time.
lower64_sync_gate:
    stp     x9,  x10, [sp, #-48]!
    stp     x11, x12, [sp, #16]
    str     x13,      [sp, #32]
    mrs     x10, esr_el2
    lsr     x11, x10, #26
    cmp     x11, #0x16              // HVC64 -> reboot (#0) or A/B confirm (#1)
    b.eq    hvc_dispatch
    cmp     x11, #0x24              // Data Abort from EL1 -> maybe isolation trap
    b.eq    el1_blocked
    movz    x9, #0x0000
    movk    x9, #0x0003, lsl #16
    movk    x9, #0x001c, lsl #32
    mov     w11, #0x3f              // '?' = other EL1 fault; fail-closed reset
91: ldr     w12, [x9, #0x18]
    tbnz    w12, #5, 91b
    strb    w11, [x9]
    b       reset_platform

// P7e: EL1 data abort. FAIL-CLOSED by default: only a fault whose FAR is inside
// the protected HBoot region [0x200000,0x800000) is a "blocked-from-EL2" event
// we contain (mark 'X', skip the faulting instruction, restore regs, return to
// EL1). ANY other EL1 data abort is a real kernel fault -> reset, as before P7e.
el1_blocked:
    mrs     x10, far_el2            // (x9-x13 already saved by lower64_sync_gate)
    movz    x13, #0x0020, lsl #16   // 0x00200000 = HOLE_LO
    cmp     x10, x13
    b.lo    el1_blk_reset           // FAR < 0x200000 -> not the EL2 region
    movz    x13, #0x0080, lsl #16   // 0x00800000 = HOLE_HI
    cmp     x10, x13
    b.hs    el1_blk_reset           // FAR >= 0x800000 -> not the EL2 region
    movz    x9, #0x0000
    movk    x9, #0x0003, lsl #16
    movk    x9, #0x001c, lsl #32
    mov     w11, #0x58              // 'X' = EL1 blocked from HBoot EL2 region
92: ldr     w12, [x9, #0x18]
    tbnz    w12, #5, 92b
    strb    w11, [x9]
    mrs     x10, elr_el2
    add     x10, x10, #4            // skip the faulting load
    msr     elr_el2, x10
    ldr     x13,      [sp, #32]     // restore EL1's registers + return
    ldp     x11, x12, [sp, #16]
    ldp     x9,  x10, [sp], #48
    eret

// FAR outside the protected region -> real EL1 fault. Restore SP + fail-closed.
el1_blk_reset:
    ldr     x13,      [sp, #32]
    ldp     x11, x12, [sp, #16]
    ldp     x9,  x10, [sp], #48
    b       el1_fault_reset

// Any EL1 data abort OUTSIDE the protected region -> fail-closed reset.
el1_fault_reset:
    movz    x9, #0x0000
    movk    x9, #0x0003, lsl #16
    movk    x9, #0x001c, lsl #32
    mov     w11, #0x3f              // '?' = EL1 fault; reset
93: ldr     w12, [x9, #0x18]
    tbnz    w12, #5, 93b
    strb    w11, [x9]
    b       reset_platform

// HVC64 from EL1. ISS (ESR_EL2[15:0], still in x10) = the hvc immediate:
//   #1 = A/B boot confirm — disarm the trial watchdog + return to EL1 (commit).
//   anything else (#0) = reboot request -> full SoC reset (unchanged).
hvc_dispatch:
    and     x12, x10, #0xffff       // ISS = hvc immediate
    cmp     x12, #1
    b.eq    hvc_confirm             // hvc #1 -> A/B boot confirm (below)
    cmp     x12, #2
    b.eq    hvc_mbox                // hvc #2 -> SEC-2 mailbox proxy (below)
    b       reset_platform          // hvc #0 (or other) -> reboot
hvc_confirm:
    // hvc #1 — disarm the PM watchdog: RSTC &= ~WRCFG, keep password.
    movz    x9, #0x0000
    movk    x9, #0x7d20, lsl #16
    movk    x9, #0x0010, lsl #32
    movz    w12, #0x5a00, lsl #16
    ldr     w10, [x9, #0x1c]
    bic     w10, w10, #0x30
    orr     w10, w10, w12
    str     w10, [x9, #0x1c]
    // Emit 'C' (A/B boot committed) on the RP1 UART @0x1C00030000.
    movz    x9, #0x0000
    movk    x9, #0x0003, lsl #16
    movk    x9, #0x001c, lsl #32
    mov     w11, #0x43              // 'C'
94: ldr     w12, [x9, #0x18]
    tbnz    w12, #5, 94b
    strb    w11, [x9]
    // Restore EL1's x9-x13 (saved at gate entry) and return past the hvc.
    ldr     x13,      [sp, #32]
    ldp     x11, x12, [sp, #16]
    ldp     x9,  x10, [sp], #48
    eret

// SEC-2 — hvc #2: the mailbox PROXY. EL1 passes its property-buffer PA in x0 and the word
// count in x1 (x0-x8 are untouched by the gate, which saved only x9-x13). Call the Rust
// whitelist+transact helper (returns the result in x0), then restore x9-x13 and return to
// EL1. `bl` clobbers x30 and x0-x18 per AAPCS — the EL1 caller's `hvc #2` asm declares those
// clobbered, so nothing EL1 relies on is lost. The EL2 stack (gate pushed 48 B) backs the call.
hvc_mbox:
    bl      hboot_hvc_mbox          // x0 = pa, x1 = nwords  ->  x0 = result (0 = ok)
    ldr     x13,      [sp, #32]
    ldp     x11, x12, [sp, #16]
    ldp     x9,  x10, [sp], #48
    eret

    .balign 0x800
.global __hboot_vectors
__hboot_vectors:
    HB_VEC                          // 0x000 sync  SP0
    HB_VEC                          // 0x080 irq   SP0
    HB_VEC                          // 0x100 fiq   SP0
    HB_VEC                          // 0x180 serr  SP0
    HB_VEC                          // 0x200 sync  SPx
    HB_VEC                          // 0x280 irq   SPx
    HB_VEC                          // 0x300 fiq   SPx
    HB_VEC                          // 0x380 serr  SPx
    .balign 0x80                    // 0x400 sync  lower64 -> the gate
    b       lower64_sync_gate
    HB_VEC                          // 0x480 irq   lower64
    HB_VEC                          // 0x500 fiq   lower64
    HB_VEC                          // 0x580 serr  lower64
    HB_VEC                          // 0x600 sync  lower32
    HB_VEC                          // 0x680 irq   lower32
    HB_VEC                          // 0x700 fiq   lower32
    HB_VEC                          // 0x780 serr  lower32
