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

    /* HBoot text+data+bss must stay below 0x400000: the EEPROM loads the whole
       combined image flat at 0x200000, so the payload (header+kernel) lands at
       0x200000 + HBOOT_PAYLOAD_OFFSET = 0x400000 in RAM. */
    ASSERT(. <= 0x400000, "HBoot code+bss collides with the payload image in RAM")

    /* Stack grows DOWN from 0x800000 — free RAM above the loaded combined image
       (~0x41A000 end) and below the kernel load address (0x1000000). ~4 MiB of
       headroom: ed25519 + SLH-DSA verify are stack-hungry, and with the MMU off
       there is no guard page, so a too-small stack silently corrupts memory. */
    __stack_top = 0x800000;

    /DISCARD/ : { *(.comment) *(.note .note.*) *(.eh_frame*) }
}
