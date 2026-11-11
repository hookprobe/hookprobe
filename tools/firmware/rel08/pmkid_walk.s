    .syntax unified
    .cpu cortex-r4
    .arch armv7-r
    .eabi_attribute Tag_CPU_arch, 10
    .eabi_attribute Tag_THUMB_ISA_use, 2
    .thumb
    .section .text.walk,"ax"
    .global pmkid_walk
    .type pmkid_walk,%function
@ CYW43455 7.45.265 PMKID-cache expiry walk, corrected (replaces 0x1c823c..0x1c82b4, 120 bytes).
@ obj: [0]=ctx, [0x430]=timer, [0x434]=count u8, [0x438]=head; node: [0x18]=ticks (-1 fatal), [0x1c]=next.
pmkid_walk:
    push    {r4, r5, r6, r7, lr}
    ldr     r3, [r0]
    mov     r5, r0
    ldr.w   r4, [r0, #0x438]
    ldr.w   r1, [r5, #0x430]
    ldr     r0, [r3, #0x8]
    movs    r7, #0                  @ prev = NULL
    bl      fw_del_timer
    b       check
loop:
    ldr     r6, [r4, #0x1c]         @ next
    cbnz    r3, dec
    cbnz    r7, mid
    str.w   r6, [r5, #0x438]        @ expiring head: head = next
    b       unl
mid:
    str     r6, [r7, #0x1c]         @ expiring middle/tail: prev->next = next (the missing unlink)
unl:
    ldr     r3, [r5]
    mov     r1, r4
    ldr     r0, [r3, #0x4]
    bl      fw_free_entry
    ldrb.w  r3, [r5, #0x434]
    subs    r3, #1
    strb.w  r3, [r5, #0x434]
    b       advance                 @ prev unchanged: consecutive expiries stay correct
dec:
    subs    r3, #1
    str     r3, [r4, #0x18]
    mov     r7, r4                  @ survivor becomes prev
advance:
    mov     r4, r6
check:
    cbz     r4, tail
    ldr     r3, [r4, #0x18]
    adds    r2, r3, #1
    bne     loop
hang:
    b       hang                    @ ticks == -1: the original fatal stop, kept
tail:
    ldr     r3, [r5]
    ldr.w   r2, [r5, #0x438]
    ldr.w   r1, [r5, #0x430]
    ldr     r0, [r3, #0x8]
    cbnz    r2, rearm
    bl      fw_free_timer           @ list empty: free the timer, clear timer + count
    str.w   r4, [r5, #0x430]
    strb.w  r4, [r5, #0x434]
    pop     {r4, r5, r6, r7, pc}
rearm:
    movw    r2, #0x2710             @ 10 s
    mov     r3, r4
    pop.w   {r4, r5, r6, r7, lr}
    b.w     fw_add_timer
