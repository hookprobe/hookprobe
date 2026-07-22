//! P6b/P8 — BPF JIT: general native aarch64 codegen.
//!
//! `compile(prog)` is a two-pass compiler for the verified RFC 9669 ISA subset
//! the interpreter (`kernel::bpf::run`) supports: LDX_B/H/W, MOV/ADD/AND/LSH/OR
//! (K and X forms), the conditional-jump family, and EXIT. It emits native ARM64
//! into a fresh frame, W^X-locks it (RO+executable via `map_code_page`), and
//! returns a callable `extern "C" fn(*const u8) -> u64`. The datapath calls the
//! JIT'd rule on the hot path (interpreter is the fallback), so verdicts run at
//! native speed.
//!
//! **Soundness of the elided bounds checks.** The PREVAIL-style verifier
//! (`bpf::verify_prevail`) proves, statically, that for every packet of length
//! `>= min_len` *every* load is in-bounds. The JIT therefore emits raw loads with
//! NO per-load bounds branch — and the caller MUST only invoke the compiled code
//! when `len >= min_len` (the packet engine does; otherwise it uses the
//! interpreter, which bounds-checks). This is exactly how production BPF JITs
//! elide the checks the verifier has already discharged.
//!
//! Register map: BPF R0..R10 -> ARM64 x0..x10 (all caller-saved -> no prologue
//! save needed in a leaf function — our ISA subset has no BPF calls). Scratch:
//! x14, x15. R0 lives in x0, so EXIT is just `ret`. No `alloc`: the compiler
//! emits straight into the (single-page) executable frame with fixed-size
//! side tables.

// --- ARM64 instruction encoders (little-endian u32 words) -------------------
#[inline]
fn mov_reg(rd: u32, rm: u32) -> u32 {
    0xAA0003E0 | (rm << 16) | rd // ORR Xd, XZR, Xm
}
#[inline]
fn movz(rd: u32, imm16: u16, shift: u32) -> u32 {
    0xD2800000 | (shift << 21) | ((imm16 as u32) << 5) | rd
}
#[inline]
fn movk(rd: u32, imm16: u16, shift: u32) -> u32 {
    0xF2800000 | (shift << 21) | ((imm16 as u32) << 5) | rd
}
#[inline]
fn movn(rd: u32, imm16: u16, shift: u32) -> u32 {
    0x92800000 | (shift << 21) | ((imm16 as u32) << 5) | rd
}
#[inline]
fn add_reg(rd: u32, rn: u32, rm: u32) -> u32 {
    0x8B000000 | (rm << 16) | (rn << 5) | rd
}
#[inline]
fn orr_reg(rd: u32, rn: u32, rm: u32) -> u32 {
    0xAA000000 | (rm << 16) | (rn << 5) | rd
}
#[inline]
fn and_reg(rd: u32, rn: u32, rm: u32) -> u32 {
    0x8A000000 | (rm << 16) | (rn << 5) | rd
}
#[inline]
fn lsl_imm(rd: u32, rn: u32, sh: u32) -> u32 {
    // LSL Xd, Xn, #sh  == UBFM Xd, Xn, #(-sh mod 64), #(63-sh)
    let sh = sh & 63;
    let immr = (64 - sh) & 63;
    let imms = 63 - sh;
    0xD3400000 | (immr << 16) | (imms << 10) | (rn << 5) | rd
}
#[inline]
fn cmp_reg(rn: u32, rm: u32) -> u32 {
    0xEB00001F | (rm << 16) | (rn << 5) // SUBS XZR, Xn, Xm
}
#[inline]
fn tst_reg(rn: u32, rm: u32) -> u32 {
    0xEA00001F | (rm << 16) | (rn << 5) // ANDS XZR, Xn, Xm
}
#[inline]
fn ldrb(rt: u32, rn: u32) -> u32 {
    0x39400000 | (rn << 5) | rt // LDRB Wt, [Xn]
}
#[inline]
fn ldrh(rt: u32, rn: u32) -> u32 {
    0x79400000 | (rn << 5) | rt // LDRH Wt, [Xn]
}
#[inline]
fn ldr_w(rt: u32, rn: u32) -> u32 {
    0xB9400000 | (rn << 5) | rt // LDR Wt, [Xn]
}
#[inline]
fn ret() -> u32 {
    0xD65F03C0
}
#[inline]
fn bcond(cond: u32) -> u32 {
    0x54000000 | cond // B.cond with imm19 = 0 (patched later)
}
#[inline]
fn patch_bcond(word: u32, delta_insns: i32) -> u32 {
    let imm19 = (delta_insns as u32) & 0x7FFFF;
    (word & !0x00FF_FFE0) | (imm19 << 5)
}

const SCRATCH: u32 = 14; // x14
const SCRATCH2: u32 = 15; // x15
const MAX_INSNS: usize = 256; // rules are small; one 4 KiB code page
const PAGE_WORDS: usize = 1024; // 4096 / 4

/// A fixed-capacity code emitter writing straight into the executable frame.
struct Emit {
    p: *mut u32,
    pos: usize,
    overflow: bool,
}
impl Emit {
    #[inline]
    fn push(&mut self, w: u32) {
        if self.pos >= PAGE_WORDS {
            self.overflow = true;
            return;
        }
        unsafe { core::ptr::write_volatile(self.p.add(self.pos), w) };
        self.pos += 1;
    }
    #[inline]
    fn patch(&mut self, idx: usize, w: u32) {
        unsafe { core::ptr::write_volatile(self.p.add(idx), w) };
    }
    #[inline]
    fn at(&self, idx: usize) -> u32 {
        unsafe { core::ptr::read_volatile(self.p.add(idx)) }
    }
}

/// Materialize a sign-extended 32-bit immediate into x`rd` (BPF imm is i32, used
/// as `imm as i64 as u64`). Emits 1-2 words.
fn emit_imm(e: &mut Emit, rd: u32, imm: i32) {
    let v = imm as i64 as u64;
    if imm >= 0 {
        let lo = (v & 0xFFFF) as u16;
        let hi = ((v >> 16) & 0xFFFF) as u16;
        e.push(movz(rd, lo, 0));
        if hi != 0 {
            e.push(movk(rd, hi, 1));
        }
    } else {
        // MOVN sets all higher bits to 1 (correct sign extension for i32).
        let nlo = ((!v) & 0xFFFF) as u16;
        e.push(movn(rd, nlo, 0));
        let hi = ((v >> 16) & 0xFFFF) as u16;
        if hi != 0xFFFF {
            e.push(movk(rd, hi, 1));
        }
    }
}

/// Compile a **verified** BPF program to native ARM64. Returns the entry VA (to
/// be transmuted to `extern "C" fn(*const u8) -> u64`) or None on an unsupported
/// op / too-large program / allocation failure. The program MUST have passed
/// `bpf::verify_prevail` first (forward-only jumps, packet-relative loads).
pub fn compile(prog: &[u64]) -> Option<usize> {
    let n = prog.len();
    if n == 0 || n > MAX_INSNS {
        return None;
    }
    let frame = crate::mmu::reserve_region(4096);
    if frame == 0 {
        return None;
    }
    let mut e = Emit { p: frame as *mut u32, pos: 0, overflow: false };
    let mut bpf_start = [0usize; MAX_INSNS + 1];
    let mut fixups: [(usize, usize); MAX_INSNS] = [(0, 0); MAX_INSNS];
    let mut nfix = 0usize;

    // Prologue: R1 = pkt (arg x0); R0 = 0. Set R1 from x0 before zeroing R0(=x0).
    e.push(mov_reg(1, 0));
    e.push(movz(0, 0, 0));

    for pc in 0..n {
        bpf_start[pc] = e.pos;
        let ins = prog[pc];
        let op = (ins & 0xff) as u8;
        let dst = ((ins >> 8) & 0xf) as u32;
        let src = ((ins >> 12) & 0xf) as u32;
        let off = ((ins >> 16) & 0xffff) as u16 as i16;
        let imm = ((ins >> 32) & 0xffff_ffff) as u32 as i32;

        match op {
            0x71 | 0x69 | 0x61 => {
                // LDX_B/H/W dst = *(uW*)(src+off): addr = R[src]+off in scratch.
                emit_imm(&mut e, SCRATCH, off as i32);
                e.push(add_reg(SCRATCH, src, SCRATCH));
                match op {
                    0x71 => e.push(ldrb(dst, SCRATCH)),
                    0x69 => e.push(ldrh(dst, SCRATCH)),
                    _ => e.push(ldr_w(dst, SCRATCH)),
                }
            }
            0xb7 => emit_imm(&mut e, dst, imm),            // MOV64_K
            0xbf => e.push(mov_reg(dst, src)),             // MOV64_X
            0x07 => {
                emit_imm(&mut e, SCRATCH, imm); // ADD64_K
                e.push(add_reg(dst, dst, SCRATCH));
            }
            0x0f => e.push(add_reg(dst, dst, src)),        // ADD64_X
            0x57 => {
                emit_imm(&mut e, SCRATCH, imm); // AND64_K
                e.push(and_reg(dst, dst, SCRATCH));
            }
            0x67 => e.push(lsl_imm(dst, dst, (imm as u32) & 63)), // LSH64_K
            0x4f => e.push(orr_reg(dst, dst, src)),               // OR64_X
            0x15 | 0x25 | 0x35 | 0x45 | 0x55 | 0x1d | 0x2d | 0x3d | 0x4d | 0x5d => {
                // Conditional jump: compare dst vs (imm|src), branch to pc+1+off.
                let is_x = op & 0x08 != 0;
                let rhs = if is_x {
                    src
                } else {
                    emit_imm(&mut e, SCRATCH2, imm);
                    SCRATCH2
                };
                if (op & 0xf0) == 0x40 {
                    e.push(tst_reg(dst, rhs)); // JSET
                } else {
                    e.push(cmp_reg(dst, rhs));
                }
                let cond: u32 = match op & 0xf0 {
                    0x10 => 0, // JEQ -> EQ
                    0x20 => 8, // JGT -> HI
                    0x30 => 2, // JGE -> HS
                    0x40 => 1, // JSET -> NE
                    _ => 1,    // JNE -> NE
                };
                let target = (pc as i64 + 1 + off as i64) as usize;
                if nfix < MAX_INSNS {
                    fixups[nfix] = (e.pos, target);
                    nfix += 1;
                }
                e.push(bcond(cond));
            }
            0x95 => e.push(ret()), // EXIT: R0 is x0 -> return
            _ => return None,      // unsupported opcode
        }
        if e.overflow {
            return None;
        }
    }
    // Sentinel target for a fixup landing one past the end; also a terminal RET.
    bpf_start[n] = e.pos;
    e.push(ret());
    if e.overflow {
        return None;
    }

    // Resolve forward jumps: delta (in instructions) = target_native - branch.
    for i in 0..nfix {
        let (brw, target) = fixups[i];
        let tgt = bpf_start[target.min(n)];
        let delta = tgt as i32 - brw as i32;
        e.patch(brw, patch_bcond(e.at(brw), delta));
    }

    crate::mmu::sync_instruction_cache(frame, e.pos * 4);

    // Map the code at a fresh RO+exec VA (each compiled rule gets its own slot).
    let slot = JIT_SLOT.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
    let code_va: usize = 0xD100_0000 + slot * 0x10000;
    if !crate::Mmu.map_code_page(code_va, frame) {
        return None;
    }
    Some(code_va)
}

static JIT_SLOT: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);
