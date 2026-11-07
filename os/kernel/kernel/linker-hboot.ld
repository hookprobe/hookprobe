/* HEQK microkernel payload for HBoot. Linked at KERNEL_LOAD_PA (0x1000000);
   HBoot relocates the raw payload here and enters _start at offset 0.
   Keeps the boot stub first so _start leads the flat binary. */
ENTRY(_start)

SECTIONS
{
    . = 0x1000000;
    __text_start = .;            /* page-aligned: W^X maps [__text_start,__text_end) RO+X */

    .text : {
        KEEP(*(.text.boot))      /* _start must lead the image (entry_offset 0) */
        *(.text .text.*)
    }

    . = ALIGN(4096);
    __text_end = .;              /* everything past here is RW+PXN (no W^X violation) */

    .rodata : { *(.rodata .rodata.*) }
    .data   : { *(.data .data.*) }

    .bss (NOLOAD) : ALIGN(16) {
        __bss_start = .;
        *(.bss .bss.*)
        *(COMMON)
        . = ALIGN(16);
        __bss_end = .;
    }

    . = ALIGN(16);
    . = . + 0x80000;             /* 512 KiB boot stack */
    __stack_top = .;

    /DISCARD/ : { *(.comment) *(.note .note.*) *(.eh_frame*) }
}
