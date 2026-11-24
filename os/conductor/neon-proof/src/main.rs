// SPDX-License-Identifier: AGPL-3.0-only
//! Bare-metal differential test: NEON + DotProd Q4 GEMV against the scalar reference, on an emulated
//! Cortex-A76 with no operating system. PASS/FAIL on the UART; exit status through semihosting.
#![no_std]
#![no_main]

use core::arch::{asm, global_asm};
use core::fmt::Write;
use neuro_kernels::*;

global_asm!(
    r#"
    .section .text.boot
    .global _start
_start:
    ldr x0, =__stack_top
    mov sp, x0
    // Enable FP/SIMD at EL1 and EL0 (CPACR_EL1.FPEN = 0b11). This is what KR-1 grants to one server.
    mov x0, #(3 << 20)
    msr cpacr_el1, x0
    isb
    ldr x0, =__bss_start
    ldr x1, =__bss_end
1:  cmp x0, x1
    b.hs 2f
    str xzr, [x0], #8
    b 1b
2:  bl main
3:  b 3b
"#
);

struct Uart;
impl Write for Uart {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        for b in s.bytes() {
            // PL011 data register on QEMU virt.
            unsafe { core::ptr::write_volatile(0x0900_0000 as *mut u8, b) };
        }
        Ok(())
    }
}

fn exit(code: u64) -> ! {
    // Semihosting SYS_EXIT (0x18) with ADP_Stopped_ApplicationExit.
    let block: [u64; 2] = [0x20026, code];
    unsafe { asm!("hlt #0xf000", in("x0") 0x18u64, in("x1") block.as_ptr(), options(noreturn)) }
}

#[panic_handler]
fn panic(i: &core::panic::PanicInfo) -> ! {
    let _ = writeln!(Uart, "PANIC {i}");
    exit(2)
}

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
}

const MAX_COLS: usize = 1024;
static mut W: [u8; MAX_COLS * 2] = [0; MAX_COLS * 2];
static mut X: [u8; MAX_COLS] = [0; MAX_COLS];

#[no_mangle]
extern "C" fn main() -> ! {
    let mut u = Uart;
    let (isar0, midr): (u64, u64);
    unsafe {
        asm!("mrs {}, id_aa64isar0_el1", out(reg) isar0);
        asm!("mrs {}, midr_el1", out(reg) midr);
    }
    let dp = (isar0 >> 44) & 0xf;
    let _ = writeln!(u, "neon-proof: MIDR part {:#x}, ID_AA64ISAR0_EL1.DP = {}", (midr >> 4) & 0xfff, dp);
    if dp == 0 {
        let _ = writeln!(u, "FAIL: this CPU has no DotProd");
        exit(1);
    }
    // SAFETY: DotProd was just read from the ID register and _start enabled FP/SIMD.
    let simd = unsafe { Simd::neon_dot() };
    let (w, x) = unsafe { (&mut *core::ptr::addr_of_mut!(W), &mut *core::ptr::addr_of_mut!(X)) };
    let mut rng = Rng(0x9e37_79b9_7f4a_7c15);
    let (mut cases, mut macs) = (0u64, 0u64);
    for round in 0..20_000u32 {
        let cols = 32 * (1 + (rng.next() % 32) as usize);
        let wn = group_bytes(cols);
        // Edge rounds: every weight −8 or 7, every activation −128 or 127; otherwise random.
        for b in w[..wn].iter_mut() {
            *b = match round % 5 {
                0 => 0x88,
                1 => 0x77,
                _ => rng.next() as u8,
            };
        }
        for v in x[..cols].iter_mut() {
            *v = match round % 7 {
                0 => 0x80, // −128
                1 => 0x7f, // 127
                _ => rng.next() as u8,
            };
        }
        let start = [rng.next() as i32 >> 8, 0, -7, i32::MAX / 2];
        let (mut a, mut b) = (start, start);
        let ok1 = gemv_q4_group_scalar(&w[..wn], &x[..cols], &mut a);
        let ok2 = gemv_q4_group(simd, &w[..wn], &x[..cols], &mut b);
        if !ok1 || !ok2 || a != b {
            let _ = writeln!(u, "FAIL round {round} cols {cols}: scalar {a:?} neon {b:?}");
            exit(1);
        }
        cases += 1;
        macs += 4 * cols as u64;
    }
    // Length errors are refused by both paths, with nothing written.
    let mut a = [1, 2, 3, 4];
    if gemv_q4_group(simd, &w[..63], &x[..32], &mut a) || gemv_q4_group(simd, &w[..64], &x[..31], &mut a) || a != [1, 2, 3, 4] {
        let _ = writeln!(u, "FAIL: bad lengths accepted");
        exit(1);
    }
    let _ = writeln!(u, "PASS kernel: {} groups, {} MACs, {} identical to the scalar reference", cases, macs, simd.name());

    // The same through the engine: a packaged 64×256 Q4 layer, admitted once, run with both implementations.
    use neuro_engine::{kernel, pack, Model};
    const ROWS: usize = 64;
    const COLS: usize = 256;
    static mut WEIGHTS: [u8; ROWS * COLS / 2 + ROWS * 8] = [0; ROWS * COLS / 2 + ROWS * 8];
    static mut PKG: [u8; ROWS * COLS / 2 + ROWS * 8 + 256] = [0; ROWS * COLS / 2 + ROWS * 8 + 256];
    static mut ARENA: [u8; COLS + ROWS] = [0; COLS + ROWS];
    let (wb, pkg, arena) = unsafe { (&mut *core::ptr::addr_of_mut!(WEIGHTS), &mut *core::ptr::addr_of_mut!(PKG), &mut *core::ptr::addr_of_mut!(ARENA)) };
    let b_off = ROWS * COLS / 2;
    for b in wb[..b_off].iter_mut() {
        *b = rng.next() as u8;
    }
    for r in 0..ROWS {
        wb[b_off + 4 * r..b_off + 4 * r + 4].copy_from_slice(&((rng.next() as i32) >> 12).to_le_bytes());
        wb[b_off + 4 * (ROWS + r)..b_off + 4 * (ROWS + r) + 4].copy_from_slice(&(1 + (rng.next() % 2048) as i32).to_le_bytes());
    }
    let steps = [pack::StepDef { kernel: kernel::GEMV_Q4_I8, shift: 12, input: 0, output: 1, rows: ROWS as u16, cols: COLS as u16, w_off: 0, b_off: b_off as u32, mult: 0, zero: 3 }];
    let Some(n) = pack::package(pkg, &[(0, COLS as u32), (COLS as u32, ROWS as u32)], &steps, wb, (COLS + ROWS) as u32, 0, 1) else {
        let _ = writeln!(u, "FAIL: could not pack");
        exit(1)
    };
    let model = match Model::admit(&pkg[..n]) {
        Ok(m) => m,
        Err(e) => {
            let _ = writeln!(u, "FAIL: admission {e:?}");
            exit(1)
        }
    };
    let mut runs = 0u32;
    for _ in 0..2_000 {
        let mut xin = [0u8; COLS];
        for v in xin.iter_mut() {
            *v = rng.next() as u8;
        }
        let (mut o1, mut o2) = ([0u8; ROWS], [0u8; ROWS]);
        if model.run(arena, &xin, &mut o1).is_err() || model.run_with(simd, arena, &xin, &mut o2).is_err() || o1 != o2 {
            let _ = writeln!(u, "FAIL: engine outputs differ");
            exit(1);
        }
        runs += 1;
    }
    let _ = writeln!(u, "PASS engine: {}x{} Q4 layer ({} byte package, {} MACs per run), {} runs, scalar == {}", ROWS, COLS, n, model.macs(), runs, simd.name());
    lm_proof(&mut u, simd, &mut rng);
    exit(0)
}

mod tables {
    include!(concat!(env!("OUT_DIR"), "/tables.rs"));
}

/// A whole 2-layer decoder (GQA, RoPE, SwiGLU, 4-bit weights), generated in place with integer randomness,
/// run with the scalar path and with NEON from the same prompt: every logit of every step must be equal.
fn lm_proof(u: &mut Uart, simd: Simd, rng: &mut Rng) {
    use neuro_lm::{Dims, Layer, Model, Work, Q4};
    const VOCAB: usize = 100;
    const DM: usize = 64;
    const L: usize = 2;
    const NH: usize = 4;
    const NKV: usize = 2;
    const HD: usize = 16;
    const FFN: usize = 128;
    const CTX: usize = 48;
    // Bytes per matrix (rows × cols / 2) for q, k, v, o, gate, up, down; then the head.
    const SIZES: [usize; 7] = [NH * HD * DM / 2, NKV * HD * DM / 2, NKV * HD * DM / 2, DM * NH * HD / 2, FFN * DM / 2, FFN * DM / 2, DM * FFN / 2];
    const PER_LAYER: usize = SIZES[0] + SIZES[1] + SIZES[2] + SIZES[3] + SIZES[4] + SIZES[5] + SIZES[6];
    const TOTAL: usize = L * PER_LAYER + VOCAB * DM / 2;
    static mut W: [u8; TOTAL] = [0; TOTAL];
    static mut EMB: [i8; VOCAB * DM] = [0; VOCAB * DM];
    static mut GAIN: [i16; (2 * L + 1) * DM] = [0; (2 * L + 1) * DM];
    static mut M_ACT: [i32; FFN] = [0; FFN];
    static mut M_RES: [i32; DM] = [0; DM];
    static mut M_RES2: [i32; DM] = [0; DM];
    static mut M_HEAD: [i32; VOCAB] = [0; VOCAB];
    static mut KV_A: [i8; L * NKV * CTX * HD * 2] = [0; L * NKV * CTX * HD * 2];
    static mut KV_B: [i8; L * NKV * CTX * HD * 2] = [0; L * NKV * CTX * HD * 2];
    static mut WA: Work<64, 128, 48, 100> = Work::new();
    static mut WB: Work<64, 128, 48, 100> = Work::new();
    let (w, emb, gain) = unsafe { (&mut *core::ptr::addr_of_mut!(W), &mut *core::ptr::addr_of_mut!(EMB), &mut *core::ptr::addr_of_mut!(GAIN)) };
    let (ma, mr, mr2, mh) = unsafe { (&mut *core::ptr::addr_of_mut!(M_ACT), &mut *core::ptr::addr_of_mut!(M_RES), &mut *core::ptr::addr_of_mut!(M_RES2), &mut *core::ptr::addr_of_mut!(M_HEAD)) };
    for b in w.iter_mut() {
        // two random nibbles in −8..7 each (every byte value is a valid pair)
        *b = rng.next() as u8;
    }
    for e in emb.iter_mut() {
        *e = (rng.next() % 49) as i8 - 24;
    }
    for g in gain.iter_mut() {
        *g = 4096 + (rng.next() % 801) as i16 - 400;
    }
    ma.fill(tables::M_ACT_64);
    mr.fill(tables::M_RES_64);
    mr2.fill(tables::M_RES_128);
    mh.fill(tables::M_HEAD_64);
    let (w, emb, gain, ma, mr, mr2, mh): (&'static [u8], &'static [i8], &'static [i16], &'static [i32], &'static [i32], &'static [i32], &'static [i32]) = (w, emb, gain, ma, mr, mr2, mh);
    let mut off = 0usize;
    let mut take = |n: usize| {
        let s = &w[off..off + n];
        off += n;
        s
    };
    let mut layers: [Option<Layer<'static>>; L] = [None; L];
    for (li, slot) in layers.iter_mut().enumerate() {
        let q4 = |w: &'static [u8], rows: usize, cols: usize, m: &'static [i32]| Q4 { rows, cols, w, mult: &m[..rows], shift: 24 };
        *slot = Some(Layer {
            attn_norm: &gain[2 * li * DM..(2 * li + 1) * DM],
            wq: q4(take(SIZES[0]), NH * HD, DM, ma),
            wk: q4(take(SIZES[1]), NKV * HD, DM, ma),
            wv: q4(take(SIZES[2]), NKV * HD, DM, ma),
            wo: q4(take(SIZES[3]), DM, NH * HD, mr),
            ffn_norm: &gain[(2 * li + 1) * DM..(2 * li + 2) * DM],
            w_gate: q4(take(SIZES[4]), FFN, DM, ma),
            w_up: q4(take(SIZES[5]), FFN, DM, ma),
            w_down: q4(take(SIZES[6]), DM, FFN, mr2),
        });
    }
    let layers: [Layer<'static>; L] = match layers {
        [Some(a), Some(b)] => [a, b],
        _ => exit(1),
    };
    let head = Q4 { rows: VOCAB, cols: DM, w: take(VOCAB * DM / 2), mult: mh, shift: 24 };
    let model = Model {
        dims: Dims { vocab: VOCAB, d_model: DM, n_layers: L, n_heads: NH, n_kv_heads: NKV, head_dim: HD, ffn: FFN, max_ctx: CTX },
        embed: emb,
        layers: &layers,
        final_norm: &gain[2 * L * DM..],
        head,
        rope: &tables::ROPE,
        exp: &tables::EXP,
        silu: &tables::SILU,
        score_mult: tables::SCORE_MULT,
        score_shift: tables::SCORE_SHIFT,
    };
    if model.check().is_err() {
        let _ = writeln!(u, "FAIL: model shapes");
        exit(1);
    }
    let (kva, kvb, wa, wb) = unsafe { (&mut *core::ptr::addr_of_mut!(KV_A), &mut *core::ptr::addr_of_mut!(KV_B), &mut *core::ptr::addr_of_mut!(WA), &mut *core::ptr::addr_of_mut!(WB)) };
    let prompt = [7usize, 42, 3, 99, 15, 0, 64];
    let (mut tok_a, mut tok_b) = (0usize, 0usize);
    let mut generated = [0u8; CTX];
    let mut steps = 0usize;
    for pos in 0..CTX {
        let (ta, tb) = if pos < prompt.len() { (prompt[pos], prompt[pos]) } else { (tok_a, tok_b) };
        let ra = model.step(Simd::SCALAR, ta, pos, kva, wa);
        let rb = model.step(simd, tb, pos, kvb, wb);
        match (ra, rb) {
            (Ok(a), Ok(b)) if a == b && wa.logits == wb.logits => {
                tok_a = a;
                tok_b = b;
                generated[pos] = a as u8;
                steps += 1;
            }
            _ => {
                let _ = writeln!(u, "FAIL: scalar and {} decoders differ at position {pos}", simd.name());
                exit(1);
            }
        }
    }
    let _ = writeln!(u, "PASS decoder: 2 layers, 4 heads / 2 KV heads, RoPE, SwiGLU, 4-bit weights ({} weight bytes); {} positions, every logit equal, scalar == {}", TOTAL, steps, simd.name());
    let _ = writeln!(u, "  generated tokens after the prompt: {:?}", &generated[prompt.len()..prompt.len() + 12]);
}
