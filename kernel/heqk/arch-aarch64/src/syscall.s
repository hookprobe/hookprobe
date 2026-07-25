// HookProbe microkernel — P3 EL0 entry + kernel resume (setjmp/longjmp style).
//
// enter_user(entry, user_sp): save the kernel's callee-saved context + SP + LR
// into KRESUME, then ERET into EL0 at `entry` on `user_sp`. resume_kernel():
// restore that context and RET — i.e. make enter_user() "return" to its caller.
// The syscall/fault handler calls resume_kernel() to bring control back to the
// kernel from EL0 (on the user's exit syscall or a contained fault).

.section .text

.global enter_user
enter_user:                          // x0 = entry, x1 = user_sp
    adrp    x2, KRESUME
    add     x2, x2, #:lo12:KRESUME
    stp     x19, x20, [x2, #0]
    stp     x21, x22, [x2, #16]
    stp     x23, x24, [x2, #32]
    stp     x25, x26, [x2, #48]
    stp     x27, x28, [x2, #64]
    stp     x29, x30, [x2, #80]
    mov     x3, sp
    str     x3, [x2, #96]
    msr     sp_el0, x1               // user stack
    msr     elr_el1, x0              // user entry
    mov     x3, #0x80                // SPSR = EL0t, IRQ masked
    msr     spsr_el1, x3
    // Scrub kernel register state before dropping to EL0 — otherwise EL0 starts
    // with x2=&KRESUME (a kernel pointer) and x4..x30 holding live kernel values,
    // an information leak that hands EL0 a fixed kernel anchor. Zero x0..x30.
    mov     x0, xzr
    mov     x1, xzr
    mov     x2, xzr
    mov     x3, xzr
    mov     x4, xzr
    mov     x5, xzr
    mov     x6, xzr
    mov     x7, xzr
    mov     x8, xzr
    mov     x9, xzr
    mov     x10, xzr
    mov     x11, xzr
    mov     x12, xzr
    mov     x13, xzr
    mov     x14, xzr
    mov     x15, xzr
    mov     x16, xzr
    mov     x17, xzr
    mov     x18, xzr
    mov     x19, xzr
    mov     x20, xzr
    mov     x21, xzr
    mov     x22, xzr
    mov     x23, xzr
    mov     x24, xzr
    mov     x25, xzr
    mov     x26, xzr
    mov     x27, xzr
    mov     x28, xzr
    mov     x29, xzr
    mov     x30, xzr
    eret

// -------- P3 user program: position-independent, copied into an EL0 page ------
// Does 3 syscalls (hello, getval, printval) then triggers a contained fault.
.global user_stub
.global user_stub_end
user_stub:
    mov     x8, #3                  // SYS_HELLO
    svc     #0
    mov     x8, #2                  // SYS_GETVAL -> x0
    svc     #0
    mov     x8, #4                  // SYS_PRINTVAL (a0 = x0 = returned value)
    svc     #0
    mov     x0, #3                  // CPtr 3 (a Frame in the root task's CSpace)
    mov     x8, #5                  // SYS_CAP_IDENTIFY: invoke a capability
    svc     #0
    movz    x9, #0xE000, lsl #16    // x9 = 0xE000_0000 (unmapped)
    str     x0, [x9]                // EL0 data abort -> kernel contains it
1:  b       1b
user_stub_end:

// -------- Driver-isolation demo: an EL0 driver server ------------------------
// Runs at EL0 with ONLY a granted device-MMIO window (0xE200_0000 -> the NIC's
// virtio-mmio page). Reads the NIC DeviceID register, reports it via syscall,
// and exits. It has no kernel access — a compromised driver is contained here.
.global driver_stub
.global driver_stub_end
driver_stub:
    movz    x10, #0xE200, lsl #16   // x10 = 0xE200_0000 (granted device window)
    movk    x10, #0x0e08            // x10 = 0xE200_0e08 (virtio-net DeviceID reg)
    ldr     w0, [x10]               // read the NIC register via the capability
    mov     x8, #7                  // SYS_DRIVER_REPORT (a0 = DeviceID)
    svc     #0
    mov     x8, #6                  // SYS_EXIT_USER
    svc     #0
1:  b       1b
driver_stub_end:

// -------- P7c step 4b: a CRASHING EL0 driver (fault-restart proof) -----------
// Faults immediately (writes beyond the 39-bit VA range -> translation fault).
// The kernel contains it and rebuilds a fresh frame; after a restart budget it
// kills the TCB. A driver crash is contained AND recovered, box stays up.
.global el0_fault_stub
.global el0_fault_stub_end
el0_fault_stub:
    movz x2, #0x0100, lsl #32     // x2 = 0x100_0000_0000 (1 TB, beyond the 39-bit VA)
    str  x2, [x2]                 // data/translation abort -> EL0 fault -> restart
1:  b    1b
el0_fault_stub_end:

// -------- P7c: uncooperative EL0 task (preemption proof) ---------------------
// Runs at EL0 with IRQs ENABLED and makes NO syscalls — it just spins forever
// incrementing a counter at [x0]. If the box isn't wedged (the scheduler keeps
// ticking and other threads run), the timer is preempting it => EL0 is a real
// scheduled TCB, not a cooperative side-path (closes B-6).
.global el0_loop_stub
.global el0_loop_stub_end
el0_loop_stub:                       // x0 = counter VA (EL0-mapped RW)
1:  ldr     x1, [x0]
    add     x1, x1, #1
    str     x1, [x0]
    b       1b
el0_loop_stub_end:

// -------- P7c step 3b: isolated EL0 GEM driver (register probe) --------------
// Runs at EL0 granted ONLY the GEM MMIO page (mapped at the GB5 user window
// 0x1_4000_2000). Reads GEM NCFGR (offset 0x004) through that capability and
// reports it, then exits — proving the REAL GEM is reachable from an isolated
// EL0 driver on metal. enter_user scrubs x0-x30, so it builds the VA itself.
.global gem_probe_stub
.global gem_probe_stub_end
gem_probe_stub:
    movz x1, #0x4000, lsl #16    // x1 = 0x0000_0000_4000_0000
    movk x1, #0x0001, lsl #32    // x1 = 0x0000_0001_4000_0000 (GB5 base)
    add  x1, x1, #0x2000         // UDEV_VA = 0x1_4000_2000 (granted GEM window)
    ldr  w0, [x1, #4]            // GEM NCFGR (offset 0x004) via the capability
    mov  x8, #7                  // SYS_DRIVER_REPORT (report the read value)
    svc  #0
    mov  x8, #6                  // SYS_EXIT_USER (contained return to the kernel)
    svc  #0
1:  b   1b
gem_probe_stub_end:

// -------- P7c step 3b stage 2: EL0 GEM RX driver (poll the descriptor ring) --
// The RX hot path — the part that touches attacker-controlled packet data — runs
// isolated at EL0, granted ONLY a Normal-NC window onto the descriptor ring
// (0x1_4000_3000). It scans the 8 x 24-byte descriptors for a received frame
// (word0 USED bit) and reports that descriptor's status word (word1 = EOF|SOF|
// len), then exits. The kernel did the privileged one-time bring-up.
.global gem_rx_stub
.global gem_rx_stub_end
gem_rx_stub:
    movz x1, #0x4000, lsl #16     // x1 = 0x0000_0000_4000_0000
    movk x1, #0x0001, lsl #32     // x1 = 0x0000_0001_4000_0000 (GB5 base)
    add  x1, x1, #0x3000          // URING_VA = 0x1_4000_3000 (granted NC ring)
    mov  x4, xzr                  // outer wait counter
0:  mov  x2, xzr                  // descriptor index
    mov  x5, #24                  // descriptor stride
1:  mul  x6, x2, x5
    add  x7, x1, x6               // &desc[i]
    ldr  w3, [x7]                 // desc[i].word0
    tbnz w3, #0, 2f               // USED (bit0) set -> frame received
    add  x2, x2, #1
    cmp  x2, #8                   // NRX
    b.lo 1b
    add  x4, x4, #1               // no frame this pass; bounded spin + retry
    movz x9, #0x0400, lsl #16     // 0x400_0000 bound (~a second, to catch live traffic)
    cmp  x4, x9
    b.lo 0b
    mov  x0, xzr                  // timeout -> report 0
    b    3f
2:  ldr  w0, [x7, #4]            // desc[i].word1 (status/len) -> report it
3:  mov  x8, #7                   // SYS_DRIVER_REPORT
    svc  #0
    mov  x8, #6                   // SYS_EXIT_USER
    svc  #0
9:  b    9b
gem_rx_stub_end:

// -------- P7c step 3b stage 3: EL0 GEM TX driver (launch a transmit) ---------
// The kernel pre-filled the TX buffer + set the descriptor address. This EL0
// driver, granted the TX-ring NC window (0x1_4000_4000) + the GEM register window
// (0x1_4000_2000), ARMS the descriptor (word1 = len|LAST|WRAP), kicks TSTART
// (NCR = RE|TE|MPE|TSTART = 0x21c), and polls word1 for USED (bit31 = transmitted).
.global gem_tx_stub
.global gem_tx_stub_end
gem_tx_stub:
    movz x1, #0x4000, lsl #16     // x1 = 0x1_4000_0000 (GB5 base)
    movk x1, #0x0001, lsl #32
    add  x2, x1, #0x4000          // x2 = UTXVA (TX ring desc, NC)
    add  x3, x1, #0x2000          // x3 = UDEV_VA (GEM registers)
    movz w4, #0x8040              // word1 = len(0x40) | LAST(0x8000)
    movk w4, #0x4000, lsl #16     //       | WRAP(0x40000000) = 0x40008040
    str  w4, [x2, #4]             // arm desc[0].word1 (USED=0 -> hand to HW)
    dsb  sy
    movz w5, #0x021c              // NCR = RE|TE|MPE|TSTART
    str  w5, [x3]                 // kick the TX DMA (GEM+0 = NCR)
    mov  x6, xzr                  // completion poll (bounded)
1:  ldr  w0, [x2, #4]            // desc[0].word1
    tbnz w0, #31, 2f             // USED (bit31) set -> transmit complete
    add  x6, x6, #1
    movz x7, #0x0040, lsl #16     // 0x40_0000 bound
    cmp  x6, x7
    b.lo 1b
2:  mov  x8, #7                   // SYS_DRIVER_REPORT (report final word1)
    svc  #0
    mov  x8, #6                   // SYS_EXIT_USER
    svc  #0
9:  b    9b
gem_tx_stub_end:

// -------- P7c step 3b stage 4: EL0 RX driver delivers a frame to the kernel ---
// Like gem_rx_stub, but reports (descriptor_index << 16) | frame_len so the
// kernel packet-engine can read that RX buffer and run the IDS verdict — closing
// the loop: isolated EL0 driver -> frame -> kernel detection/enforcement.
.global gem_ids_stub
.global gem_ids_stub_end
gem_ids_stub:
    movz x1, #0x4000, lsl #16
    movk x1, #0x0001, lsl #32
    add  x1, x1, #0x3000          // URING_VA (granted NC descriptor ring)
    mov  x4, xzr
0:  mov  x2, xzr                  // descriptor index
    mov  x5, #24
1:  mul  x6, x2, x5
    add  x7, x1, x6
    ldr  w3, [x7]                 // desc[i].word0
    tbnz w3, #0, 2f               // USED?
    add  x2, x2, #1
    cmp  x2, #8
    b.lo 1b
    add  x4, x4, #1
    movz x9, #0x0400, lsl #16     // ~1s spin bound
    cmp  x4, x9
    b.lo 0b
    mov  x0, xzr                  // timeout -> 0
    b    3f
2:  ldr  w0, [x7, #4]            // desc[i].word1
    and  w0, w0, #0x3fff          // frame length
    orr  w0, w0, w2, lsl #16      // (index << 16) | len
3:  mov  x8, #7                   // SYS_DRIVER_REPORT (index+len)
    svc  #0
    mov  x8, #6                   // SYS_EXIT_USER
    svc  #0
9:  b    9b
gem_ids_stub_end:

// -------- P13 Stage E: isolated EL0 I2C driver (a real DW_apb_i2c transaction) --
// Runs at EL0 granted ONLY the i2c1 4 KiB MMIO page (mapped at the GB5 user window
// 0x1_4000_2000) — no pinmux, no clocks, nothing else. The kernel already opened +
// timed the controller (EL1). This driver issues ONE single-byte READ probe of
// address 0x08 through its capability: set IC_TAR (offset 0x04), enable (IC_ENABLE
// 0x6c = 1), push IC_DATA_CMD (0x10 = 0x300 READ|STOP), then poll IC_RAW_INTR_STAT
// (0x34) for TX_ABRT (bit6 = NACK) or IC_RXFLR (0x78 != 0 = data). It reports the
// final RAW_INTR_STAT — the transaction COMPLETING (a controller answer, ACK or
// NACK) is the proof, not a device being present. All loops are bounded.
.global p13_i2c_stub
.global p13_i2c_stub_end
p13_i2c_stub:
    movz x1, #0x4000, lsl #16     // x1 = 0x0000_0000_4000_0000
    movk x1, #0x0001, lsl #32     // x1 = 0x0000_0001_4000_0000 (GB5 base)
    add  x1, x1, #0x2000          // UDEV_VA = 0x1_4000_2000 (granted i2c1 page)
    // Program target address 0x08 while disabled (kernel left it enabled=0).
    mov  w2, #0
    str  w2, [x1, #0x6c]          // IC_ENABLE = 0 (ensure disabled)
    mov  w2, #0x08
    str  w2, [x1, #0x04]          // IC_TAR = 0x08
    mov  w2, #1
    str  w2, [x1, #0x6c]          // IC_ENABLE = 1
    ldr  w2, [x1, #0x54]          // read IC_CLR_TX_ABRT (clear stale abort)
    movz w2, #0x0300              // DATA_CMD = READ | STOP
    str  w2, [x1, #0x10]          // IC_DATA_CMD (issue the 1-byte READ)
    dsb  sy
    mov  x6, xzr                  // bounded poll
1:  ldr  w3, [x1, #0x34]          // IC_RAW_INTR_STAT
    tbnz w3, #6, 2f               // TX_ABRT (bit6) -> NACK, transaction done
    ldr  w4, [x1, #0x78]          // IC_RXFLR
    cbnz w4, 2f                   // data arrived -> ACK, transaction done
    add  x6, x6, #1
    movz x7, #0x0040, lsl #16     // ~0x40_0000 bound
    cmp  x6, x7
    b.lo 1b
2:  ldr  w0, [x1, #0x34]          // report final RAW_INTR_STAT (proof of completion)
    ldr  w5, [x1, #0x54]          // clear the abort latch
    mov  x8, #7                   // SYS_DRIVER_REPORT
    svc  #0
    mov  x8, #6                   // SYS_EXIT_USER
    svc  #0
9:  b    9b
p13_i2c_stub_end:

// -------- P12: the blocking-WAIT proof (two scheduled EL0 TCBs) --------------
// WAITer: holds a read-right Notification at CPtr 0. Calls SYS_WAIT (17) and BLOCKS; the
// kernel resumes it (via a later Signal + the timer) with the received badge in x0.
// It stores that badge to its result word (mapped RW at 0x8400_2000) so the kernel
// can verify it after the scheduler run, then exits cleanly via SYS_TASK_EXIT (22)
// — NOT SYS_EXIT_USER (which for a scheduled TCB would longjmp into a stale KRESUME;
// the DSN-6 fix routes even that safely, but a scheduled TCB should use TASK_EXIT).
.global p12_wait_stub
.global p12_wait_stub_end
p12_wait_stub:
    mov  x0, #0                   // CPtr 0 = my read-right Notification
    mov  x8, #17                  // SYS_WAIT (blocks; wakes with badge in x0)
    svc  #0
    movz x1, #0x8400, lsl #16     // x1 = 0x8400_0000
    add  x1, x1, #0x2000          // x1 = 0x8400_2000 (my result word, EL0-mapped RW)
    str  x0, [x1]                 // result = received badge
    mov  x8, #22                  // SYS_TASK_EXIT (scheduler-aware clean exit)
    svc  #0
1:  b    1b
p12_wait_stub_end:

// SIGNALler: holds a write-right Notification (badge stamped in the cap) at CPtr 0.
// One SYS_SIGNAL (16) — the badge comes from the CAP, not from x0 — then exits.
.global p12_signal_stub
.global p12_signal_stub_end
p12_signal_stub:
    mov  x0, #0                   // CPtr 0 = my write-right Notification (badge in the cap)
    mov  x8, #16                  // SYS_SIGNAL (never blocks the signaller)
    svc  #0
    mov  x8, #22                  // SYS_TASK_EXIT
    svc  #0
1:  b    1b
p12_signal_stub_end:

.global resume_kernel
resume_kernel:
    adrp    x2, KRESUME
    add     x2, x2, #:lo12:KRESUME
    ldp     x19, x20, [x2, #0]
    ldp     x21, x22, [x2, #16]
    ldp     x23, x24, [x2, #32]
    ldp     x25, x26, [x2, #48]
    ldp     x27, x28, [x2, #64]
    ldp     x29, x30, [x2, #80]
    ldr     x3, [x2, #96]
    mov     sp, x3
    ret                              // returns into enter_user()'s caller
