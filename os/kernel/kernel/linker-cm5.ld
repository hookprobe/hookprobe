/* HEQK Core image layout for Raspberry Pi CM5 / BCM2712.
   The Pi firmware relocates arm64 kernels to 0x200000 (observed live 2026-07-21) (RAM base = 0x0) and
   enters at EL2 with x0 = DTB. Same structure as the QEMU script, different
   origin. Keeps the boot stub first; reserves a 512 KiB stack after .bss. */
ENTRY(_start)

SECTIONS
{
    . = 0x200000;
    __text_start = .;            /* page-aligned (2 MiB origin): W^X maps [__text_start,__text_end) RO+X */

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
