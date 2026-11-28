/* ADR 0060 S2 — worker-engine link map. Position-fixed ET_EXEC at 0xB000_0000: a VA that exists ONLY in worker
 * cores' private tables (core 0 never maps it). It lies inside the QEMU EL0 VA window only so the kernel's
 * existing, fuzzed `elf::parse` accepts it unchanged; it is not an EL0 image and never runs at EL0.
 * The engine has NO writable state: no .data/.bss (the asserts below fail the link otherwise), so one read-only
 * copy serves every worker; all mutable state is passed in by the caller. */
ENTRY(engine_entry)
SECTIONS {
  . = 0xB0000000;
  .text   : ALIGN(0x1000) { KEEP(*(.text.engine_entry)) *(.text .text.*) }
  . = ALIGN(0x1000);
  .rodata : ALIGN(0x1000) { *(.rodata .rodata.*) }
  .data   : { *(.data .data.*) }
  .bss    : { *(.bss .bss.*) *(COMMON) }
  /DISCARD/ : { *(.eh_frame*) *(.eh_frame_hdr) *(.comment) *(.note*) *(.ARM.*) }
}
ASSERT(SIZEOF(.data) == 0, "worker-engine must not have .data (no mutable statics: S1b unmaps kernel data)");
ASSERT(SIZEOF(.bss) == 0, "worker-engine must not have .bss (no mutable statics)");
