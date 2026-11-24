/* SPDX-License-Identifier: AGPL-3.0-only
   heqk flash stub (ADR 0070) — an HBoot payload, laid out exactly like the kernel's linker-hboot.ld:
   linked at KERNEL_LOAD_PA (0x1000000); HBoot relocates the raw payload here and enters _start at offset 0. */
ENTRY(_start)

SECTIONS
{
    . = 0x1000000;
    __text_start = .;            /* page-aligned: mmu_cm5's W^X maps [__text_start,__text_end) RO+X */

    .text : {
        KEEP(*(.text.boot))      /* _start (arch-aarch64 boot_hboot.s) must lead the image */
        *(.text .text.*)
    }

    . = ALIGN(4096);
    __text_end = .;

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
    . = . + 0x100000;            /* 1 MiB stack: the SLH-DSA verify is stack-hungry */
    __stack_top = .;

    /* Everything (image + 5 MiB slot buffer + stack) stays below the frame pool / BootInfo pages. */
    ASSERT(. <= 0x3000000, "flash stub image + bss + stack past 48 MiB")

    /DISCARD/ : { *(.comment) *(.note .note.*) *(.eh_frame*) }
}
