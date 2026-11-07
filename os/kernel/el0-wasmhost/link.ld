/* M5.3 — EL0 Wasm-host link map. A position-FIXED ET_EXEC (the M5.1 loader maps each
 * PT_LOAD at its p_vaddr; no relocations). Every PT_LOAD is 4 KiB-page-aligned in BOTH
 * vaddr and file offset so the loader's page-aligned-vaddr invariant holds and its
 * page-by-page copy lands correctly. lld auto-emits ONE PT_LOAD per distinct flag set
 * (R+X text, R rodata, RW data/bss) — so W^X holds segment-by-segment (no RWX segment).
 * The stack, heap and work page are NOT in this image — the kernel maps them at fixed
 * VAs (matching src/main.rs), exactly like the M5.1 fixture's kernel-provided stack. */
ENTRY(_start)
SECTIONS {
  . = 0x90000000;                 /* EL0 code base (== main.rs EL0_WHOST2_CODE_VA)      */
  .text   : ALIGN(0x1000) { *(.text .text.*) }
  . = ALIGN(0x1000);
  .rodata : ALIGN(0x1000) { *(.rodata .rodata.*) }
  . = ALIGN(0x1000);
  .data   : ALIGN(0x1000) { *(.data .data.*) }
  .bss    : ALIGN(0x1000) { *(.bss .bss.*) *(COMMON) }
  /DISCARD/ : { *(.eh_frame*) *(.eh_frame_hdr) *(.comment) *(.note*) *(.ARM.*) }
}
