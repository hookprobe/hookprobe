/* el0-tlshost link map (link-cm5): position-FIXED ET_EXEC, every PT_LOAD page-aligned (M5.1 loader), one
 * PT_LOAD per flag set (W^X). Heap / stack / IO are mapped by the kernel at fixed offsets from this base
 * (src/main.rs + kernel/src/tlshost.rs agree on them). */
ENTRY(_start)
SECTIONS {
  . = 0x140080000;
  .text   : ALIGN(0x1000) { *(.text .text.*) }
  . = ALIGN(0x1000);
  .rodata : ALIGN(0x1000) { *(.rodata .rodata.*) }
  . = ALIGN(0x1000);
  .data   : ALIGN(0x1000) { *(.data .data.*) }
  .bss    : ALIGN(0x1000) { *(.bss .bss.*) *(COMMON) }
  /DISCARD/ : { *(.eh_frame*) *(.eh_frame_hdr) *(.comment) *(.note*) *(.ARM.*) }
}
