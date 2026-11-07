// HEQK microkernel entry when launched by HBoot (heqk-boot).
//
// Contract on entry (guaranteed by hboot_launch_el1):
//   - EL1h, DAIF masked (SPSR was 0x3c5)
//   - console already up on RP1 UART0 @0x1C00030000 (HBoot owns bring-up)
//   - HBoot's EL2 vectors resident: `hvc #0` = reboot gate
//   - x0 = BootInfo PA (0x3FFE0000), x1 = HBOOT_ENTRY_MAGIC "HBOT"
//   - payload was relocated to its link address (0x1000000); _start is at
//     offset 0 (no image header — HBoot loads a raw payload).
// So the kernel does the minimum: stack, its own EL1 vectors, bss, kmain.

.section .text.boot

.global _start
_start:
    mov     x19, x0             // stash BootInfo PA for kmain

    adrp    x0, __stack_top
    add     x0, x0, #:lo12:__stack_top
    mov     sp, x0

    adrp    x0, __vectors       // kernel's own EL1 vector table
    add     x0, x0, #:lo12:__vectors
    msr     vbar_el1, x0
    isb

    adrp    x0, __bss_start
    add     x0, x0, #:lo12:__bss_start
    adrp    x1, __bss_end
    add     x1, x1, #:lo12:__bss_end
1:  cmp     x0, x1
    b.hs    2f
    str     xzr, [x0], #8
    b       1b
2:
    mov     x0, x19             // BootInfo PA -> kmain(x0)
    bl      kmain

3:  wfe
    b       3b
