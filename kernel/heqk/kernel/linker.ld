/* HookProbe microkernel image layout for QEMU `virt` (RAM base 0x4000_0000;
   `-kernel` loads at 0x4008_0000). Keeps the boot stub first, reserves a
   512 KiB stack after .bss, and exports the symbols boot.s needs. */
ENTRY(_start)

SECTIONS
{
    . = 0x40080000;
    __text_start = .;            /* page-aligned: W^X maps [__text_start,__text_end) RO+X */

    .text : {
        KEEP(*(.text.boot))      /* _start must lead the image */
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
