/* SPDX-License-Identifier: AGPL-3.0-only
   m5probe: linked at 0, position-independent (PIE + self-applied RELATIVE relocs, src/entry.s).
   Everything, including .bss and the stack, fits in the 1 MiB `image_size` the Image header
   declares, so U-Boot's booti reserves the whole footprint. */
ENTRY(_image_header)

SECTIONS
{
    . = 0;
    .text : {
        KEEP(*(.text.boot))
        *(.text .text.*)
    }
    .rodata : ALIGN(16) { *(.rodata .rodata.*) }
    .data.rel.ro : ALIGN(16) { *(.data.rel.ro .data.rel.ro.*) }
    .got : ALIGN(16) { *(.got .got.*) }
    .data : ALIGN(16) { *(.data .data.*) }
    .rela.dyn : ALIGN(16) {
        __rela_start = .;
        *(.rela .rela.*)
        __rela_end = .;
    }
    .dynamic : ALIGN(16) { *(.dynamic) }
    .dynsym : ALIGN(16) { *(.dynsym) }
    .dynstr : { *(.dynstr) }
    .hash : ALIGN(16) { *(.hash) }
    .gnu.hash : ALIGN(16) { *(.gnu.hash) }
    . = ALIGN(16);
    __load_end = .;

    .bss (NOLOAD) : ALIGN(16) {
        __bss_start = .;
        *(.bss .bss.*)
        *(COMMON)
        . = ALIGN(16);
        __bss_end = .;
    }
    . = ALIGN(16);
    __stack_bottom = .;
    . += 0x10000;
    __stack_top = .;
    _end = .;

    /DISCARD/ : { *(.comment) *(.note .note.*) *(.eh_frame .eh_frame_hdr) *(.interp) }
}
ASSERT(_end <= 0x100000, "m5probe (incl. bss + stack) exceeds the 1 MiB image_size in its Image header")
