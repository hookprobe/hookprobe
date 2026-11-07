// HookProbe microkernel — aarch64 boot stub (P0).
// Firmware/QEMU hands us the CPU in AArch64 state (EL2 on `virt` with
// virtualization, else EL1). We: gate to the primary core, set the stack,
// drop EL2->EL1 if needed, install nothing here (VBAR set in Rust-adjacent
// asm below), zero .bss, and jump to Rust `kmain`.

.section .text.boot

// ---- ARM64 Linux Image header (64 bytes) --------------------------------
// Makes the Raspberry Pi firmware load HEQK exactly like a normal arm64 kernel
// (the working kernel_2712.img path) — no os_check/kernel_address hacks. The
// firmware jumps to the image start (code0 = b _start). Ignored by QEMU, which
// enters at the ELF entry `_start` directly. Because the kernel is PC-relative,
// it runs correctly at whatever address the firmware loads it.
.global _image_header
_image_header:
    b       _start              // code0: branch past the header to the entry
    .long   0                   // code1
    .quad   0x80000             // text_offset (load at RAM base + 0x80000)
    .quad   0x400000            // image_size (4 MiB: image + bss + stack)
    .quad   0                   // flags: LE, 4 KiB, load at text_offset
    .quad   0                   // res2
    .quad   0                   // res3
    .quad   0                   // res4
    .long   0x644d5241          // magic "ARM\x64" @ offset 0x38
    .long   0                   // res5

.global _start
_start:
    // Park every non-primary core.
    mrs     x0, mpidr_el1
    and     x0, x0, #0xff
    cbnz    x0, park

    // Stack (valid whether we run at EL2 or EL1).
    adrp    x0, __stack_top
    add     x0, x0, #:lo12:__stack_top
    mov     sp, x0

    // Which EL did firmware leave us in?
    mrs     x0, CurrentEL
    lsr     x0, x0, #2
    cmp     x0, #2
    b.eq    drop_to_el1
    b       el1_start            // already at EL1

drop_to_el1:
    // EL1 executes AArch64 (HCR_EL2.RW = 1).
    mov     x0, #(1 << 31)
    msr     hcr_el2, x0
    // Return state: EL1h, DAIF masked  (M[3:0]=0b0101 | DAIF=0xf<<6 => 0x3c5).
    mov     x0, #0x3c5
    msr     spsr_el2, x0
    // EL1 stack pointer.
    adrp    x0, __stack_top
    add     x0, x0, #:lo12:__stack_top
    msr     sp_el1, x0
    // Land at el1_start after ERET.
    adr     x0, el1_start
    msr     elr_el2, x0
    eret

el1_start:
    // Install the exception vector table.
    adrp    x0, __vectors
    add     x0, x0, #:lo12:__vectors
    msr     vbar_el1, x0
    isb

    // Zero .bss  [__bss_start, __bss_end)  (both 16-byte aligned).
    adrp    x0, __bss_start
    add     x0, x0, #:lo12:__bss_start
    adrp    x1, __bss_end
    add     x1, x1, #:lo12:__bss_end
1:  cmp     x0, x1
    b.hs    2f
    str     xzr, [x0], #8
    b       1b
2:
    // Into Rust. Should not return.
    bl      kmain

park:
    wfe
    b       park
