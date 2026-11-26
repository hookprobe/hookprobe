// SPDX-License-Identifier: AGPL-3.0-only
// m5probe entry: ARM64 Linux Image header (U-Boot `booti`), boot-core check, self-relocation
// (PIE, R_AARCH64_RELATIVE only), stack, .bss, exception vectors for whichever EL we were entered
// at, then Rust. x0 = FDT physical address on entry (booti contract); x1-x3 = 0.

.section .text.boot, "ax"

.global _image_header
_image_header:
    b       _start              // code0
    .long   0                   // code1
    .quad   0                   // text_offset: placed at a 2 MiB-aligned address + 0
    .quad   0x100000            // image_size: whole footprint incl. bss + stack (linker ASSERT)
    .quad   0xa                 // flags: little-endian | 4K pages | physical placement anywhere
    .quad   0
    .quad   0
    .quad   0
    .long   0x644d5241          // "ARM\x64"
    .long   0

.global _start
_start:
    mov     x19, x0             // FDT PA — keep across everything below
    mrs     x2, mpidr_el1       // only the boot core runs (compare Aff3..Aff0 with 0)
    mov     x3, #0xffffff
    movk    x3, #0xff, lsl #32
    and     x2, x2, x3
    cbnz    x2, park
    msr     daifset, #0xf

    // ---- self-relocate: base = runtime address of the image (linked at 0) ----
    adr     x20, _image_header
    adr     x4, __rela_start
    adr     x5, __rela_end
1:  cmp     x4, x5
    b.hs    2f
    ldp     x6, x7, [x4], #16   // r_offset, r_info
    ldr     x8, [x4], #8        // r_addend
    and     x7, x7, #0xffffffff
    cmp     x7, #1027           // R_AARCH64_RELATIVE
    b.ne    reloc_bad
    add     x8, x8, x20
    str     x8, [x20, x6]
    b       1b
2:
    // ---- stack + .bss ----
    adr     x0, __stack_top
    mov     sp, x0
    adr     x0, __bss_start
    adr     x1, __bss_end
3:  cmp     x0, x1
    b.hs    4f
    stp     xzr, xzr, [x0], #16
    b       3b
4:
    // ---- vectors at the current EL (EL2 expected; EL1 tolerated and reported) ----
    adr     x0, m5p_vectors
    mrs     x1, CurrentEL
    lsr     x1, x1, #2
    cmp     x1, #2
    b.ne    5f
    msr     vbar_el2, x0
    b       6f
5:  msr     vbar_el1, x0
6:  isb
    mov     x0, x19             // fdt
    mov     x1, x20             // image base
    bl      probe_main
park:
    wfe
    b       park

reloc_bad:                      // a relocation type we do not handle: nothing safe to print with yet
    wfe
    b       reloc_bad

// ---- exception vectors: every slot reports and halts (bench diagnostics) ----
.macro VSLOT n
    .balign 0x80
    mov     x0, #\n
    b       m5p_exc_common
.endm
    .balign 0x800
.global m5p_vectors
m5p_vectors:
    VSLOT 0
    VSLOT 1
    VSLOT 2
    VSLOT 3
    VSLOT 4
    VSLOT 5
    VSLOT 6
    VSLOT 7
    VSLOT 8
    VSLOT 9
    VSLOT 10
    VSLOT 11
    VSLOT 12
    VSLOT 13
    VSLOT 14
    VSLOT 15
m5p_exc_common:
    bl      m5p_exception       // never returns
    b       park
