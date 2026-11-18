/* el0-neuro link map, CM5, PROPOSED base: the free gap 0x1_4025_4000..0x1_4030_0000 between el0-lansvc and el0-hsh. HomePods assigns the final base (docs/research/neuro/12 R1).
 * Position-fixed ET_EXEC; every PT_LOAD page-aligned; one PT_LOAD per flag set (W^X), like os/kernel/el0-*. */
ENTRY(_start)
SECTIONS {
  . = 0x140260000;
  .text   : ALIGN(0x1000) { *(.text .text.*) }
  . = ALIGN(0x1000);
  .rodata : ALIGN(0x1000) { *(.rodata .rodata.*) }
  . = ALIGN(0x1000);
  .data   : ALIGN(0x1000) { *(.data .data.*) }
  .bss    : ALIGN(0x1000) { *(.bss .bss.*) *(COMMON) }
  /DISCARD/ : { *(.eh_frame*) *(.eh_frame_hdr) *(.comment) *(.note*) *(.ARM.*) }
}
