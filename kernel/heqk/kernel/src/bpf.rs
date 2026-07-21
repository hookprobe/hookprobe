//! P6 — AI Runtime: a small RFC 9669 BPF virtual machine (interpreter).
//!
//! Runs standard BPF bytecode (a *subset* of the RFC 9669 ISA — enough for a
//! packet-filter threat rule) against a packet, returning a verdict. This
//! replaces the native stand-in that P5's Packet Engine used: the ring's verdict
//! IS this VM now. v1 is a signed-first-party interpreter with a runtime memory
//! bounds check (Layer-2 software sandbox); a JIT + a full verifier are the next
//! increments (see BPF_THREAT_PLANE.md). The moat: this same bytecode runs on
//! the Linux/FreeBSD/QNX HookProbe substrates too.

use core::ptr::read_volatile;

pub const PASS: u64 = 1;
pub const DROP: u64 = 2;
pub const INVALID: u64 = 0; // OOB / unknown op / step limit — caller fails safe

// BPF instruction encoding: u8 opcode | u4 dst | u4 src | i16 off | i32 imm.
const fn insn(op: u8, dst: u8, src: u8, off: i16, imm: i32) -> u64 {
    (op as u64)
        | ((dst as u64) << 8)
        | ((src as u64) << 12)
        | (((off as u16) as u64) << 16)
        | (((imm as u32) as u64) << 32)
}

// Opcodes used (RFC 9669 encoding):
//   0x71 LDX_B (dst = *(u8*)(src+off))   0x67 LSH64_K   0x4f OR64_X
//   0xb7 MOV64_K   0x55 JNE_K   0x95 EXIT
/// The signed first-party threat rule. R1 points at the **L4 (TCP/UDP) header**
/// (the parser in `net.rs` locates it); the dst port is the big-endian field at
/// L4 offset 2..4 (src port is 0..2). DROP if dst-port == 4444, else PASS.
pub const THREAT_RULE: [u64; 9] = [
    insn(0x71, 2, 1, 2, 0),    // R2 = *(u8*)(R1+2)   dst-port high byte
    insn(0x67, 2, 0, 0, 8),    // R2 <<= 8
    insn(0x71, 3, 1, 3, 0),    // R3 = *(u8*)(R1+3)   dst-port low byte
    insn(0x4f, 2, 3, 0, 0),    // R2 |= R3            (R2 = dst_port)
    insn(0x55, 2, 0, 2, 4444), // if R2 != 4444 goto +2
    insn(0xb7, 0, 0, 0, 2),    // R0 = DROP
    insn(0x95, 0, 0, 0, 0),    // EXIT
    insn(0xb7, 0, 0, 0, 1),    // R0 = PASS
    insn(0x95, 0, 0, 0, 0),    // EXIT
];

/// Static verifier — gate a program before it runs (v1: signed first-party, so
/// this is a safety net; a full PREVAIL-style abstract-interpretation verifier
/// is for opening the plane to third-party rules). Checks: known opcodes, valid
/// registers, **no backward jumps** (termination — no loops), forward jump
/// targets in range, and a reachable EXIT. Returns true if the program is safe.
pub fn verify(prog: &[u64]) -> bool {
    if prog.is_empty() {
        return false;
    }
    let mut has_exit = false;
    for (i, &ins) in prog.iter().enumerate() {
        let op = (ins & 0xff) as u8;
        let dst = ((ins >> 8) & 0xf) as usize;
        let src = ((ins >> 12) & 0xf) as usize;
        let off = ((ins >> 16) & 0xffff) as u16 as i16;
        if dst >= 11 || src >= 11 {
            return false; // register out of range
        }
        match op {
            0x71 | 0x67 | 0x4f | 0xb7 => {} // LDX_B / LSH64 / OR64 / MOV64 — ok
            0x55 => {
                // JNE: forward-only (no loops), target within [0, len].
                if off < 0 {
                    return false;
                }
                let target = i as i64 + 1 + off as i64;
                if target < 0 || target as usize >= prog.len() {
                    return false; // must land on a real instruction
                }
            }
            0x95 => has_exit = true, // EXIT
            _ => return false,       // unknown opcode
        }
    }
    has_exit
}

/// Execute `prog` against the packet `[pkt, pkt+len)`. R1 = packet pointer.
/// Returns the verdict in R0, or INVALID on any safety violation.
pub fn run(prog: &[u64], pkt: *const u8, len: usize) -> u64 {
    let mut r = [0u64; 11];
    r[1] = pkt as u64;
    let pbase = pkt as u64;
    // Saturating: an absurd `len` must not wrap `pend` below `pbase` and defeat
    // the LDX_B bounds check. (Packet path caps len at u16 today; defensive.)
    let pend = pbase.saturating_add(len as u64);
    let mut pc: usize = 0;
    let mut steps: u32 = 0;

    while pc < prog.len() {
        steps += 1;
        if steps > 10_000 {
            return INVALID; // termination bound — no infinite loops
        }
        let ins = prog[pc];
        let op = (ins & 0xff) as u8;
        let dst = ((ins >> 8) & 0xf) as usize;
        let src = ((ins >> 12) & 0xf) as usize;
        let off = ((ins >> 16) & 0xffff) as u16 as i16;
        let imm = ((ins >> 32) & 0xffff_ffff) as u32 as i32;
        if dst >= 11 || src >= 11 {
            return INVALID; // register out of range
        }

        match op {
            0x71 => {
                // LDX_B: dst = *(u8*)(src + off), with a runtime bounds check.
                let addr = r[src].wrapping_add(off as i64 as u64);
                if addr < pbase || addr >= pend {
                    return INVALID; // out-of-bounds load — the software sandbox
                }
                r[dst] = unsafe { read_volatile(addr as *const u8) } as u64;
            }
            0x67 => r[dst] = r[dst].wrapping_shl((imm as u32) & 63), // LSH64_K
            0x4f => r[dst] |= r[src],                                // OR64_X
            0xb7 => r[dst] = imm as i64 as u64,                      // MOV64_K
            0x55 => {
                // JNE_K: branch is relative to the next instruction.
                if r[dst] != (imm as i64 as u64) {
                    pc = (pc as i64 + off as i64) as usize;
                }
            }
            0x95 => return r[0], // EXIT
            _ => return INVALID, // unknown opcode
        }
        pc = pc.wrapping_add(1);
    }
    INVALID
}
