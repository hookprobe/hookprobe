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
// NOTE: there are TWO EL0 RX scan stubs in this file (gem_rx_stub below, and
// gem_ids_stub further down which the PRODUCTION sensor loop uses). BOTH hardcode the
// ring depth and BOTH must track gem.rs `const NRX`.
//
// The RX hot path — the part that touches attacker-controlled packet data — runs
// isolated at EL0, granted ONLY a Normal-NC window onto the descriptor ring
// (0x1_4000_3000). It scans the 16 x 24-byte descriptors for a received frame
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
    cmp  x2, #128                  // NRX — MUST match gem.rs `const NRX` (see its doc comment)
    b.lo 1b
    add  x4, x4, #1               // no frame this pass; bounded spin + retry
    movz x9, #0x8000, lsl #0      // 0x8000 bound (~tens of us). METAL 2026-09-07: the old
                                  // 0x0400_0000 (~seconds) bound was CATASTROPHIC under load —
                                  // rxprof measured el0=15.6 s/frame during a burst. One frame
                                  // per excursion + a multi-second empty-scan wait means when the
                                  // ring overflows (BNA) the stub finds nothing and burns the full
                                  // bound, so the ring never drains. A short bound returns fast, the
                                  // kernel recycles + re-arms, BNA clears, the ring drains.
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
// The kernel did the privileged half (gem::tx_prep_el0): picked the controller's NEXT ring
// slot, filled that slot's buffer, set its address words, cleared latched TSR — and left a
// PLAN at the bottom of this driver's own stack page (0x1_4000_1000):
//     [+0] u32 desc_off  (byte offset of the descriptor inside the TX-ring window)
//     [+4] u32 word1     (len | LAST | WRAP-only-if-last-slot)
// This EL0 driver, granted the TX-ring NC window (0x1_4000_4000) + the GEM register window
// (0x1_4000_2000), ARMS that descriptor, kicks TSTART (NCR = RE|TE|MPE|TSTART = 0x21c), and
// polls word1 for USED (bit31). Like gem::tx_frame it RE-KICKS every 512 spins while the
// transmitter is idle (TSR.TGO clear) — this GEM silently drops TSTART writes (7c4e4a5).
.global gem_tx_stub
.global gem_tx_stub_end
gem_tx_stub:
    movz x1, #0x4000, lsl #16     // x1 = 0x1_4000_0000 (GB5 base)
    movk x1, #0x0001, lsl #32
    add  x9, x1, #0x1000          // x9 = the plan (bottom of this driver's stack page)
    ldr  w10, [x9]                // desc_off
    ldr  w4, [x9, #4]             // word1 to arm
    add  x2, x1, #0x4000          // TX-ring window
    add  x2, x2, x10              // x2 = the planned descriptor
    add  x3, x1, #0x2000          // x3 = UDEV_VA (GEM registers)
    str  w4, [x2, #4]             // arm word1 (USED=0 -> hand to HW)
    dsb  sy
    movz w5, #0x021c              // NCR = RE|TE|MPE|TSTART
    str  w5, [x3]                 // kick the TX DMA (GEM+0 = NCR)
    mov  x6, xzr                  // completion poll (bounded)
1:  ldr  w0, [x2, #4]            // word1
    tbnz w0, #31, 2f             // USED (bit31) set -> transmit complete
    add  x6, x6, #1
    tst  x6, #0x1ff               // every 512 spins ...
    b.ne 3f
    ldr  w11, [x3, #0x14]         // ... TSR
    tbnz w11, #3, 3f              // TGO set -> a frame is in flight, leave it alone
    str  w5, [x3]                 // idle -> the kick was dropped: re-issue TSTART
3:  movz x7, #0x0040, lsl #16     // 0x40_0000 bound
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
    cmp  x2, #128                  // NRX — MUST match gem.rs `const NRX`. NOTE: there are TWO
                                  // RX scan stubs (gem_rx_stub AND gem_ids_stub, the one
                                  // the PROD sensor loop uses). Updating only one silently
                                  // strands the descriptors past the stale bound: the ring
                                  // fills, they are never recycled, BNA fires and RX DIES.
    b.lo 1b
    add  x4, x4, #1
    movz x9, #0x20, lsl #0        // THERMAL (2026-09-10): short empty-wait (~a few us of ring
                                  // scan) then RETURN 0 so the kernel WFE-idles (event-stream
                                  // paced, ~19us) instead of the A76 spinning hot here. Only
                                  // the EMPTY path is bounded by this; a USED descriptor still
                                  // returns IMMEDIATELY (tbnz above), so throughput is
                                  // unchanged. gem_rx_stub keeps its own (probe-only) bound.
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

// -------- R1 (M5.0): cap-gated synchronous IPC — SERVER (Recv -> Reply) ------
// Runs at EL0 holding an Endpoint(R-right) cap at CPtr 0 in its OWN CSpace. SYS_EP_RECV (25)
// BLOCKS until a client SYS_CALLs; the kernel returns the delivered message word in x0.
// The server saves that word to its result page (0x8600_2000), then SYS_REPLY (26) with
// reply word 0x2bee in x1 to wake the caller, and SYS_TASK_EXIT (22). Proves a real EL0
// task drives the real syscall path with an ENFORCED capability (D4 #1 gate).
.global ipc_server_stub
.global ipc_server_stub_end
ipc_server_stub:
    mov  x0, #0                  // CPtr 0 = my Endpoint(R-right)
    mov  x8, #25                 // SYS_EP_RECV (blocks; delivered msg returns in x0)
    svc  #0
    movz x1, #0x8600, lsl #16    // x1 = 0x8600_0000
    add  x1, x1, #0x2000         // SRESULT_VA = 0x8600_2000 (EL0-mapped RW)
    str  x0, [x1]                // server result = the received message word
    mov  x0, #0                  // CPtr 0 = my Endpoint(R-right) (REPLY needs the R right)
    movz x1, #0x2bee             // reply word (server -> caller)
    mov  x8, #26                 // SYS_REPLY (wakes the served caller with x1; never blocks)
    svc  #0
    mov  x8, #22                 // SYS_TASK_EXIT (scheduler-aware clean exit)
    svc  #0
1:  b    1b
ipc_server_stub_end:

// -------- R1 (M5.0): cap-gated synchronous IPC — CLIENT (Call) ---------------
// Runs at EL0 holding an Endpoint(W-right) cap at CPtr 0. SYS_CALL (24) sends message 0x1c71
// (x1) and BLOCKS until the server SYS_REPLYs; the kernel returns the reply word in x0.
// The client saves that to its result page (0x8700_2000) and SYS_TASK_EXITs.
.global ipc_client_stub
.global ipc_client_stub_end
ipc_client_stub:
    mov  x0, #0                  // CPtr 0 = my Endpoint(W-right)
    movz x1, #0x1c71             // message word (client -> server)
    mov  x8, #24                 // SYS_CALL (send + block until REPLY; reply returns in x0)
    svc  #0
    movz x1, #0x8700, lsl #16    // x1 = 0x8700_0000
    add  x1, x1, #0x2000         // CRESULT_VA = 0x8700_2000 (EL0-mapped RW)
    str  x0, [x1]                // client result = the reply word
    mov  x8, #22                 // SYS_TASK_EXIT
    svc  #0
1:  b    1b
ipc_client_stub_end:

// -------- M5.1: cap-gated sync-IPC SERVER for the ELF-LOADED client ----------
// The client of THIS rendezvous is LOADED FROM AN ELF (kernel/src/elf.rs), not copied
// from a stub — this plain server stub is its counterpart. Holds an Endpoint(R-right)
// cap at CPtr 0 in its OWN CSpace. SYS_EP_RECV (25) BLOCKS until the ELF client
// SYS_CALLs; the kernel delivers the message in x0. The server then SYS_REPLY (26) with
// a DISTINCT reply word 0x5e17 in x1 (distinct from R1's 0x2bee so the M5.1 proof is
// independent of the M5.0 proof), and SYS_TASK_EXIT (22). No result page needed — the
// M5.1 proof reads the ELF CLIENT's received reply, written into its RW data segment.
.global elf_ipc_server_stub
.global elf_ipc_server_stub_end
elf_ipc_server_stub:
    mov  x0, #0                  // CPtr 0 = my Endpoint(R-right)
    mov  x8, #25                 // SYS_EP_RECV (blocks; delivered msg returns in x0)
    svc  #0
    mov  x0, #0                  // CPtr 0 for REPLY (needs the R right)
    movz x1, #0x5e17             // reply word (server -> ELF client)
    mov  x8, #26                 // SYS_REPLY (wakes the served caller with x1; never blocks)
    svc  #0
    mov  x8, #22                 // SYS_TASK_EXIT (scheduler-aware clean exit)
    svc  #0
1:  b    1b
elf_ipc_server_stub_end:

// -------- M5.2b: the bespoke 5-opcode Wasm INTERPRETER, running AT EL0 --------
// The M5.2 in-kernel interpreter's EXECUTION ENGINE (exec_expr: local.get / i32.const /
// i32.add / i32.eq / end) relocated to run ISOLATED at EL0, in its OWN ASID/TTBR0. The
// kernel (EL1) has ALREADY Ed25519-verified the module (trust root = the kernel's signing
// key, checked BEFORE any byte crosses into EL0) and located the exported classify()
// code-expression; it hands THIS host ONLY the verified expression + the port arg through
// a RW work page, plus an Endpoint(W-right) cap at CPtr 0. The host interprets classify
// HERE at EL0 and SYS_CALLs the verdict to the kernel over the ENFORCED IPC path. A
// malformed expression (e.g. an out-of-range local.get) faults at EL0 and is CONTAINED by
// the R1 fault-restart — it can NEVER panic the kernel. Position-independent (only
// PC-relative bl to internal .L labels + absolute-VALUE VA immediates, no relocations),
// so it is copied verbatim into an EL0 code page exactly like the other stubs.
//
// Work page (mapped RW at WHOST_WORK_VA = 0x8C00_2000; base rebuilt into x0 below):
//   [+0]  port (i32 local 0)   [+8] expr_len (u64)   [+16..] expr bytes
//   [+0x800..] operand-stack scratch (grows up; 32-bit values zero/sign-extended to 64)
.global wasmhost_stub
.global wasmhost_stub_end
wasmhost_stub:
    movz x0, #0x8C00, lsl #16     // x0 = WHOST_WORK_VA base (0x8C00_0000)
    add  x0, x0, #0x2, lsl #12    // x0 = 0x8C00_2000 (the RW work page)
    ldr  x20, [x0, #8]            // x20 = expr_len
    add  x21, x0, #16            // x21 = expr cursor
    add  x22, x21, x20           // x22 = expr end
    add  x23, x0, #0x800         // x23 = operand-stack ptr (grows up)
.Lwh_loop:
    cmp  x21, x22
    b.hs .Lwh_fail               // ran off the end without `end` -> fail-closed sentinel
    ldrb w9, [x21], #1           // op = *cursor++
    cmp  w9, #0x20               // local.get
    b.eq .Lwh_localget
    cmp  w9, #0x41               // i32.const
    b.eq .Lwh_const
    cmp  w9, #0x6a               // i32.add
    b.eq .Lwh_add
    cmp  w9, #0x46               // i32.eq
    b.eq .Lwh_eq
    cmp  w9, #0x0b               // end
    b.eq .Lwh_end
    b    .Lwh_fail               // unknown opcode -> fail-closed
.Lwh_localget:
    bl   .Lwh_leb_u              // idx -> x10 (advances x21)
    add  x14, x0, x10, lsl #2    // &locals[idx] (32-bit locals; port at [x0]); OOB idx ->
    ldr  w15, [x14]             //   unmapped EL0 addr -> CONTAINED EL0 fault (isolation)
    str  x15, [x23], #8          // push (zero-extended)
    b    .Lwh_loop
.Lwh_const:
    bl   .Lwh_leb_s              // signed value -> x10 (advances x21)
    str  x10, [x23], #8          // push
    b    .Lwh_loop
.Lwh_add:
    ldr  x16, [x23, #-8]!        // pop b
    ldr  x17, [x23, #-8]!        // pop a
    add  w17, w17, w16           // 32-bit add
    str  x17, [x23], #8          // push (zero-extended)
    b    .Lwh_loop
.Lwh_eq:
    ldr  x16, [x23, #-8]!        // pop b
    ldr  x17, [x23, #-8]!        // pop a
    cmp  w17, w16
    cset x18, eq                 // 1 iff equal, else 0
    str  x18, [x23], #8          // push
    b    .Lwh_loop
.Lwh_end:
    ldr  x24, [x23, #-8]         // verdict = top of operand stack
    b    .Lwh_send
.Lwh_fail:
    mov  x24, #-1                // fail-closed sentinel (kernel treats !=0/1 as error)
.Lwh_send:
    mov  x0, #0                  // CPtr 0 = my Endpoint(W-right)
    and  x1, x24, #0xffffffff    // verdict word (i32) -> the message
    mov  x8, #24                 // SYS_CALL (send verdict + block for reply)
    svc  #0
    mov  x8, #22                 // SYS_TASK_EXIT (scheduler-aware clean exit)
    svc  #0
9:  b    9b
// --- internal PC-relative LEB128 subroutines (self-contained; bl stays inside the blob) --
.Lwh_leb_u:                       // unsigned LEB128 -> x10 (advances x21); clobbers x10-x13,x30
    mov  x10, xzr                 // result
    mov  x11, xzr                 // shift
1:  ldrb w12, [x21], #1
    and  x13, x12, #0x7f
    lsl  x13, x13, x11
    orr  x10, x10, x13
    add  x11, x11, #7
    tbnz w12, #7, 1b              // continuation bit set -> keep going
    ret
.Lwh_leb_s:                       // signed LEB128 -> x10 sign-extended (advances x21); +x14
    mov  x10, xzr
    mov  x11, xzr
1:  ldrb w12, [x21], #1
    and  x13, x12, #0x7f
    lsl  x13, x13, x11
    orr  x10, x10, x13
    add  x11, x11, #7
    tbnz w12, #7, 1b
    tbz  w12, #6, 2f              // sign bit of last group clear -> no sign-extension
    cmp  x11, #64
    b.hs 2f
    mov  x14, #-1
    lsl  x14, x14, x11
    orr  x10, x10, x14           // sign-extend the high bits
2:  ret
wasmhost_stub_end:

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
