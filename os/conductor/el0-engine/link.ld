/* el0-engine link map, QEMU layout, PROPOSED and UNASSIGNED base (C0 measurement only; HomePods assigns
 * the real range). Position-fixed ET_EXEC; one PT_LOAD per flag set (W^X), like os/kernel/el0-*. */
ENTRY(_start)
SECTIONS {
  . = 0xBE900000;
  .text   : ALIGN(0x1000) { *(.text .text.*) }
  . = ALIGN(0x1000);
  .rodata : ALIGN(0x1000) { *(.rodata .rodata.*) }
  . = ALIGN(0x1000);
  .data   : ALIGN(0x1000) { *(.data .data.*) }
  .bss    : ALIGN(0x1000) { *(.bss .bss.*) *(COMMON) }
  /DISCARD/ : { *(.eh_frame*) *(.eh_frame_hdr) *(.comment) *(.note*) *(.ARM.*) }
}
