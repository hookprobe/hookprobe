// HookProbe microkernel — aarch64 boot stub, CM5 (BCM2712) variant.
// BREADCRUMB PROBE BUILD (operator design, 2026-07-21): dump-before-touch,
// BootDebug page in RAM @ 0x3FFF0000, step counter + UART/clock/pinmux
// register snapshots at every boot stage, heartbeat re-dump loop, then a PM
// reset attempt. Read back from Linux via /dev/mem after the (warm) reboot:
//   dd if=/dev/mem bs=8 skip=$((0x3FFF0000/8)) count=64 | od -A d -t x8
//
// BootDebug layout (u64 slots at 0x3FFF0000 + 8*i):
//  [0] magic 0x4845514B44424731 "HEQKDBG1"   [1] step   [2] EL   [3] SCTLR
//  [4] HCR_EL2                                [5] VBAR
//  pre-touch dump:  [8]FR [9]IBRD [10]FBRD [11]LCR_H [12]CR [13]IMSC [14]RIS
//                   [15]DMACR [16]CLK_CTRL [17]CLK_DIV [18]CLK_SEL
//                   [19]G14_CTRL [20]G15_CTRL [21]PAD14 [22]PAD15
//  post-init dump:  [24..38] same order
//  heartbeat:       [40]counter [41]FR [42]CR [43]CLK_CTRL [44]G14_CTRL
// Steps: 1=entry 2=daif+vectors 3=pre-dump 4=clk 5=pinmux 6=pl011 7=printed
//        8=heartbeat 9=PM-reset-attempt
//
// Every crumb is followed by dc civac + dsb so it lands in DRAM whatever the
// MMU/cache state the firmware left (EL2, possibly translated).

.section .text.boot

.macro CRUMB off:req, reg:req
    str     \reg, [x19, #\off]
    add     x17, x19, #\off
    dc      civac, x17
    dsb     sy
.endm

.macro STEP n:req
    mov     x10, #\n
    CRUMB   8, x10
.endm

// ---- ARM64 Linux Image header (64 bytes), byte-mimic of kernel_2712.img ---
.global _image_header
_image_header:
    .long   0xfa405a4d          // code0: "MZ" magic (harmless ccmp)
    b       _start              // code1: real arm64 kernels branch here
    .quad   0                   // text_offset
    .quad   0x400000            // image_size
    .quad   0xc                 // flags: LE | 16K pages | anywhere
    .quad   0
    .quad   0
    .quad   0
    .long   0x644d5241          // "ARM\x64"
    .long   0

.global _start
_start:
    mrs     x0, mpidr_el1
    and     x0, x0, #0xff
    cbnz    x0, park

    // Breadcrumb base + magic + step 1 (proves firmware entered the image).
    movz    x19, #0x0000
    movk    x19, #0x3fff, lsl #16   // x19 = 0x3FFF0000
    movz    x10, #0x4731            // "HEQKDBG1" little-endian build
    movk    x10, #0x4442, lsl #16
    movk    x10, #0x514b, lsl #32
    movk    x10, #0x4845, lsl #48
    CRUMB   0, x10
    STEP    1

    // 1. Mask everything; 2. catch-all vectors before any MMIO.
    msr     daifset, #0xf
    adr     x0, __early_vectors
    mrs     x1, CurrentEL
    lsr     x1, x1, #2
    CRUMB   16, x1                  // [2] EL
    cmp     x1, #2
    b.ne    11f
    msr     vbar_el2, x0
    mrs     x10, sctlr_el2
    CRUMB   24, x10                 // [3] SCTLR_EL2
    mrs     x10, hcr_el2
    CRUMB   32, x10                 // [4] HCR_EL2
    b       12f
11: msr     vbar_el1, x0
    mrs     x10, sctlr_el1
    CRUMB   24, x10
12: isb
    CRUMB   40, x0                  // [5] VBAR value installed
    STEP    2

    // 3. PRE-TOUCH DUMP (read everything, modify nothing).
    movz    x20, #0x0000            // x20 = RP1 UART0 @ 0x1C00030000
    movk    x20, #0x0003, lsl #16
    movk    x20, #0x001c, lsl #32
    ldr     w10, [x20, #0x18]
    CRUMB   64, x10                 // [8] FR
    ldr     w10, [x20, #0x24]
    CRUMB   72, x10                 // [9] IBRD
    ldr     w10, [x20, #0x28]
    CRUMB   80, x10                 // [10] FBRD
    ldr     w10, [x20, #0x2c]
    CRUMB   88, x10                 // [11] LCR_H
    ldr     w10, [x20, #0x30]
    CRUMB   96, x10                 // [12] CR
    ldr     w10, [x20, #0x38]
    CRUMB   104, x10                // [13] IMSC
    ldr     w10, [x20, #0x3c]
    CRUMB   112, x10                // [14] RIS
    ldr     w10, [x20, #0x48]
    CRUMB   120, x10                // [15] DMACR
    movz    x8, #0x8000             // clocks block @ 0x1C00018000
    movk    x8, #0x0001, lsl #16
    movk    x8, #0x001c, lsl #32
    ldr     w10, [x8, #0x54]
    CRUMB   128, x10                // [16] CLK_UART_CTRL
    ldr     w10, [x8, #0x58]
    CRUMB   136, x10                // [17] CLK_UART_DIV_INT
    ldr     w10, [x8, #0x60]
    CRUMB   144, x10                // [18] CLK_UART_SEL
    movz    x8, #0x0074             // IO_BANK0 GPIO14_CTRL
    movk    x8, #0x000d, lsl #16
    movk    x8, #0x001c, lsl #32
    ldr     w10, [x8]
    CRUMB   152, x10                // [19] GPIO14_CTRL
    ldr     w10, [x8, #8]
    CRUMB   160, x10                // [20] GPIO15_CTRL
    movz    x8, #0x003c             // PADS_BANK0 GPIO14
    movk    x8, #0x000f, lsl #16
    movk    x8, #0x001c, lsl #32
    ldr     w10, [x8]
    CRUMB   168, x10                // [21] PAD14
    ldr     w10, [x8, #4]
    CRUMB   176, x10                // [22] PAD15
    STEP    3

    // 4. Re-arm clk_uart (xosc ÷1 = 50 MHz).
    movz    x8, #0x8000
    movk    x8, #0x0001, lsl #16
    movk    x8, #0x001c, lsl #32
    mov     w10, #1
    str     w10, [x8, #0x58]
    movz    w10, #0x0840            // ENABLE | AUXSRC=2 (xosc)
    str     w10, [x8, #0x54]
    STEP    4

    // 5. Pinmux GPIO14/15 -> uart0 + pads.
    movz    x8, #0x0074
    movk    x8, #0x000d, lsl #16
    movk    x8, #0x001c, lsl #32
    mov     w10, #4
    str     w10, [x8]
    str     w10, [x8, #8]
    movz    x8, #0x003c
    movk    x8, #0x000f, lsl #16
    movk    x8, #0x001c, lsl #32
    ldr     w10, [x8]
    bic     w10, w10, #0x80
    orr     w10, w10, #0x40
    str     w10, [x8]
    ldr     w10, [x8, #4]
    bic     w10, w10, #0x80
    orr     w10, w10, #0x40
    str     w10, [x8, #4]
    STEP    5

    // 6. PL011 init 115200 8N1 (IBRD 27 FBRD 8).
    str     wzr, [x20, #0x30]
    str     wzr, [x20, #0x2c]
    mov     w10, #0x7ff
    str     w10, [x20, #0x44]
    mov     w10, #27
    str     w10, [x20, #0x24]
    mov     w10, #8
    str     w10, [x20, #0x28]
    mov     w10, #0x70
    str     w10, [x20, #0x2c]
    mov     w10, #0x301
    str     w10, [x20, #0x30]
    STEP    6

    // POST-INIT DUMP [24..38].
    ldr     w10, [x20, #0x18]
    CRUMB   192, x10                // [24] FR
    ldr     w10, [x20, #0x24]
    CRUMB   200, x10                // [25] IBRD
    ldr     w10, [x20, #0x28]
    CRUMB   208, x10                // [26] FBRD
    ldr     w10, [x20, #0x2c]
    CRUMB   216, x10                // [27] LCR_H
    ldr     w10, [x20, #0x30]
    CRUMB   224, x10                // [28] CR
    movz    x8, #0x8000
    movk    x8, #0x0001, lsl #16
    movk    x8, #0x001c, lsl #32
    ldr     w10, [x8, #0x54]
    CRUMB   232, x10                // [29] CLK_UART_CTRL
    movz    x8, #0x0074
    movk    x8, #0x000d, lsl #16
    movk    x8, #0x001c, lsl #32
    ldr     w10, [x8]
    CRUMB   240, x10                // [30] GPIO14_CTRL

    // 7. Print "UART OK" (may be deaf; the crumbs are the real channel).
    mov     x9, x20
    mov     w11, #0x55              // 'U'
    bl      early_putc
    mov     w11, #0x4f              // 'O'
    bl      early_putc
    mov     w11, #0x4b              // 'K'
    bl      early_putc
    mov     w11, #0x0d
    bl      early_putc
    mov     w11, #0x0a
    bl      early_putc
    STEP    7

    // 8. Continue boot in the operator's order, announcing each stage:
    // stack -> 'S', EL1+vectors -> 'E', bss -> 'B', then Rust.
    STEP    8
    adrp    x0, __stack_top
    add     x0, x0, #:lo12:__stack_top
    mov     sp, x0
    mov     x9, x20
    mov     w11, #0x53              // 'S' = stack OK
    bl      early_putc

    mrs     x0, CurrentEL
    lsr     x0, x0, #2
    cmp     x0, #2
    b.eq    drop_to_el1
    b       el1_start               // already at EL1

drop_to_el1:
    mov     x0, #(1 << 31)          // HCR_EL2.RW: EL1 is AArch64
    msr     hcr_el2, x0
    mov     x0, #0x3c5              // EL1h, DAIF masked
    msr     spsr_el2, x0
    adrp    x0, __stack_top
    add     x0, x0, #:lo12:__stack_top
    msr     sp_el1, x0
    adr     x0, el1_start
    msr     elr_el2, x0
    eret

el1_start:
    adrp    x0, __vectors           // kernel's real vector table
    add     x0, x0, #:lo12:__vectors
    msr     vbar_el1, x0
    isb
    mov     x9, x20
    mov     w11, #0x45              // 'E' = EL1 + vectors OK
    bl      early_putc

    adrp    x0, __bss_start
    add     x0, x0, #:lo12:__bss_start
    adrp    x1, __bss_end
    add     x1, x1, #:lo12:__bss_end
1:  cmp     x0, x1
    b.hs    2f
    str     xzr, [x0], #8
    b       1b
2:  mov     x9, x20
    mov     w11, #0x42              // 'B' = bss zeroed
    bl      early_putc
    mov     w11, #0x0d
    bl      early_putc
    mov     w11, #0x0a
    bl      early_putc
    STEP    9
    bl      kmain                   // 'RUST OK' + banner come from kmain

// Early UART putc: BOUNDED spin (dead UART must not hang the boot).
early_putc:
    movz    w16, #0x4000
1:  ldr     w12, [x9, #0x18]
    tbz     w12, #5, 2f
    subs    w16, w16, #1
    b.ne    1b
    ret
2:  strb    w11, [x9, #0x00]
    ret

// Clean full-SoC reset via the PM block @0x107D200000 (bcm2835 layout).
.global reset_to_linux
reset_to_linux:
    movz    x9, #0x0000
    movk    x9, #0x7d20, lsl #16
    movk    x9, #0x0010, lsl #32
    movz    w12, #0x5a00, lsl #16   // PM_PASSWORD
    ldr     w10, [x9, #0x20]
    movz    w11, #0x0555
    bic     w10, w10, w11
    orr     w10, w10, w12
    str     w10, [x9, #0x20]        // PM_RSTS: boot partition 0
    movz    w10, #10
    orr     w10, w10, w12
    str     w10, [x9, #0x24]        // PM_WDOG = 10 ticks
    ldr     w10, [x9, #0x1c]
    bic     w10, w10, #0x30
    orr     w10, w10, #0x20
    orr     w10, w10, w12
    str     w10, [x9, #0x1c]        // PM_RSTC = FULL_RESET
1:  wfe
    b       1b

park:
    wfe
    b       park

// Catch-all vectors: crumb step=0xE? -> print '!' -> park. Fault visibility
// without a working console: [1]=0xEE marks "took an exception".
.macro EARLY_VEC
    .balign 0x80
    movz    x19, #0x0000
    movk    x19, #0x3fff, lsl #16
    mov     x10, #0xee
    str     x10, [x19, #8]
    add     x17, x19, #8
    dc      civac, x17
    dsb     sy
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

// Lower-EL sync at EL2 (offset 0x400): EL1's gateway back to EL2. `hvc #0`
// = intentional reboot request (kmain's end-of-run); anything else is an EL1
// fault — print '?' and reset anyway, so the bench always self-recovers.
lower64_sync_handler:
    mrs     x10, esr_el2
    lsr     x10, x10, #26
    cmp     x10, #0x16              // EC 0x16 = HVC from AArch64
    b.eq    reset_to_linux
    movz    x9, #0x0000
    movk    x9, #0x0003, lsl #16
    movk    x9, #0x001c, lsl #32
    mov     w11, #0x3f              // '?' = unexpected EL1 fault
91: ldr     w12, [x9, #0x18]
    tbnz    w12, #5, 91b
    strb    w11, [x9]
    b       reset_to_linux

    .balign 0x800
__early_vectors:
    EARLY_VEC                       // 0x000 sync  SP0
    EARLY_VEC                       // 0x080 irq   SP0
    EARLY_VEC                       // 0x100 fiq   SP0
    EARLY_VEC                       // 0x180 serr  SP0
    EARLY_VEC                       // 0x200 sync  SPx
    EARLY_VEC                       // 0x280 irq   SPx
    EARLY_VEC                       // 0x300 fiq   SPx
    EARLY_VEC                       // 0x380 serr  SPx
    .balign 0x80                    // 0x400 sync  lower64 -> HVC/fault gate
    b       lower64_sync_handler
    EARLY_VEC                       // 0x480 irq   lower64
    EARLY_VEC                       // 0x500 fiq   lower64
    EARLY_VEC                       // 0x580 serr  lower64
    EARLY_VEC                       // 0x600 sync  lower32
    EARLY_VEC                       // 0x680 irq   lower32
    EARLY_VEC                       // 0x700 fiq   lower32
    EARLY_VEC                       // 0x780 serr  lower32
