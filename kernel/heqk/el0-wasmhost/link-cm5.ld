/* M5.5 (Track C, U5) — EL0 Wasm-host link map for the CM5 SYNCHRONOUS-EXCURSION ABI.
 * Identical structure to link.ld, but based at the GB5 EL0 user window (0x1_4000_0000 ==
 * mmu_cm5::USER_VA_BASE) so the whole image (text ~355 KiB + rodata ~26 KiB + data) lands
 * inside the single 2 MiB L3 table the CM5 single-AS mapper (map_user_code/map_user_data)
 * can reach. The kernel maps the stack, heap and work page at higher VAs in that SAME 2 MiB
 * window (see main.rs WASMI_CM5_* constants); none are in this image. lld emits ONE PT_LOAD
 * per distinct flag set (R+X text, R rodata, RW data/bss) — W^X holds segment-by-segment. */
ENTRY(_start)
SECTIONS {
  . = 0x140000000;                /* EL0 code base (== mmu_cm5::USER_VA_BASE, GB5)       */
  .text   : ALIGN(0x1000) { *(.text .text.*) }
  . = ALIGN(0x1000);
  .rodata : ALIGN(0x1000) { *(.rodata .rodata.*) }
  . = ALIGN(0x1000);
  .data   : ALIGN(0x1000) { *(.data .data.*) }
  .bss    : ALIGN(0x1000) { *(.bss .bss.*) *(COMMON) }
  /DISCARD/ : { *(.eh_frame*) *(.eh_frame_hdr) *(.comment) *(.note*) *(.ARM.*) }
}
