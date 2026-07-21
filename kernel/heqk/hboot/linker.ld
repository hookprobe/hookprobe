/* HBoot — HEQK boot manager. Loaded by the EEPROM bootloader at 0x200000.
   Must fit below the payload header at 0x200000 + 0x200000 (2 MiB). */
ENTRY(_start)

SECTIONS
{
    . = 0x200000;

    .text : {
        KEEP(*(.text.boot))
        *(.text .text.*)
    }
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
    . = . + 0x10000;             /* 64 KiB stack */
    __stack_top = .;

    ASSERT(. <= 0x400000, "HBoot exceeds the 2 MiB slot before the payload")

    /DISCARD/ : { *(.comment) *(.note .note.*) *(.eh_frame*) }
}
