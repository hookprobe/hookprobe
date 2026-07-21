//! P6b — BPF JIT: native aarch64 codegen for the signed threat rule.
//!
//! Translates the RFC 9669 BPF threat rule (dst-port filter) into native ARM64
//! machine code, W^X-locks it (RO+executable via `map_code_page`), and returns a
//! callable function pointer — the fast path replacing the interpreter. BPF regs
//! map to aarch64 x-registers (R0->x0 = return, R1->x1 = packet ptr). A general
//! two-pass JIT for arbitrary programs is the next increment; this compiles the
//! (verified) signed first-party rule.
//!
//! Hardening notes (from BPF_THREAT_PLANE.md): W^X is enforced here; constant
//! blinding + retpolines apply once the JIT accepts third-party programs.

/// Compile the signed threat rule to native code. Returns the entry VA (as a
/// usize to be transmuted to `extern "C" fn(*const u8) -> u64`), or None.
pub fn compile_threat_rule() -> Option<usize> {
    // Pre-encoded ARM64 for: R0 = (port==4444) ? DROP(2) : PASS(1)
    //   0 mov  x1, x0          ; R1 = packet pointer (AAPCS arg0)
    //   1 ldrb w2, [x1, #0]    ; R2 = pkt[0] (high byte)
    //   2 lsl  x2, x2, #8
    //   3 ldrb w3, [x1, #1]    ; R3 = pkt[1] (low byte)
    //   4 orr  x2, x2, x3      ; R2 = dst_port (big-endian)
    //   5 movz w9, #4444
    //   6 cmp  x2, x9
    //   7 b.ne +3              ; -> PASS (index 10)
    //   8 movz x0, #2          ; DROP
    //   9 ret
    //  10 movz x0, #1          ; PASS
    //  11 ret
    const CODE: [u32; 12] = [
        0xAA0003E1, 0x39400022, 0xD378DC42, 0x39400423, 0xAA030042, 0x52822B89,
        0xEB09005F, 0x54000061, 0xD2800040, 0xD65F03C0, 0xD2800020, 0xD65F03C0,
    ];

    let frame = crate::mmu::reserve_region(4096);
    if frame == 0 {
        return None;
    }
    unsafe {
        let p = frame as *mut u32;
        for (i, &word) in CODE.iter().enumerate() {
            core::ptr::write_volatile(p.add(i), word);
        }
    }
    // Make the freshly-written code visible to the instruction fetcher.
    crate::mmu::sync_instruction_cache(frame, CODE.len() * 4);

    // W^X: map the code at a fresh VA as read-only + executable.
    const CODE_VA: usize = 0xD100_0000;
    if !crate::Mmu.map_code_page(CODE_VA, frame) {
        return None;
    }
    Some(CODE_VA)
}
