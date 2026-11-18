/* el0-neuro link map, QEMU, PROPOSED base: no other el0 server uses 0xBE00_0000. HomePods assigns the final base (docs/research/neuro/12 R1).
 * Position-fixed ET_EXEC; every PT_LOAD page-aligned; one PT_LOAD per flag set (W^X), like os/kernel/el0-*. */
ENTRY(_start)
SECTIONS {
  . = 0xBE000000;
  .text   : ALIGN(0x1000) { *(.text .text.*) }
  . = ALIGN(0x1000);
  .rodata : ALIGN(0x1000) { *(.rodata .rodata.*) }
  . = ALIGN(0x1000);
  .data   : ALIGN(0x1000) { *(.data .data.*) }
  .bss    : ALIGN(0x1000) { *(.bss .bss.*) *(COMMON) }
  /DISCARD/ : { *(.eh_frame*) *(.eh_frame_hdr) *(.comment) *(.note*) *(.ARM.*) }
}
