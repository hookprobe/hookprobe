/* QEMU virt: RAM starts at 0x4000_0000; -kernel loads this ELF at its link address. */
ENTRY(_start)
SECTIONS {
  . = 0x40080000;
  .text   : { KEEP(*(.text.boot)) *(.text .text.*) }
  .rodata : ALIGN(16) { *(.rodata .rodata.*) }
  .data   : ALIGN(16) { *(.data .data.*) }
  .bss    : ALIGN(16) { __bss_start = .; *(.bss .bss.*) *(COMMON) __bss_end = .; }
  . = ALIGN(16);
  . += 0x40000;
  __stack_top = .;
  /DISCARD/ : { *(.eh_frame*) *(.comment) *(.note*) }
}
