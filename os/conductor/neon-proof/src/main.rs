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
    // Identity map with 1 GiB blocks, as an OS would give a server: 0-1 GiB device (the UART),
    // 1-2 GiB normal write-back cacheable (RAM). Normal memory with SCTLR_EL1.A clear allows the
    // unaligned 16-byte loads of GGUF Q8_0 blocks (34 bytes each); with the MMU off every access is
    // device memory, where they fault.
    adrp x0, l1_table
    mov x1, #0x401                  // block | AF | AttrIdx 0 (device-nGnRnE)
    str x1, [x0]
    ldr x1, =0x40000705             // 0x4000_0000 | AF | inner shareable | AttrIdx 1 | block
    str x1, [x0, #8]
    ldr x1, =0xff00                 // MAIR: attr0 device-nGnRnE, attr1 normal write-back
    msr mair_el1, x1
    ldr x1, =0x200803519            // TCR: T0SZ 25 (39-bit VA, start at L1), WB walks, inner shareable, 4 KiB, EPD1, 40-bit PA
    msr tcr_el1, x1
    msr ttbr0_el1, x0
    dsb ish
    tlbi vmalle1
    dsb ish
    isb
    mrs x1, sctlr_el1
    orr x1, x1, #(1 << 0)           // M
    orr x1, x1, #(1 << 2)           // C
    orr x1, x1, #(1 << 12)          // I
    bic x1, x1, #(1 << 1)           // A clear: unaligned access to normal memory allowed
    msr sctlr_el1, x1
    isb
    ldr x0, =__bss_start
    ldr x1, =__bss_end
1:  cmp x0, x1
    b.hs 2f
    str xzr, [x0], #8
    b 1b
2:  bl main
3:  b 3b

    .section .data.pt, "aw"
    .balign 4096
l1_table:
    .space 4096
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
    q8_proof(&mut u, simd, &mut rng);
    q8_bench(&mut u, simd, &mut rng);
    qwen3_proof(&mut u, simd, &mut rng);
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

/// Q8_0 rows (GGUF block layout) × per-block quantised activations: NEON + DotProd against the scalar
/// reference, including edge values and binary16 scales across the whole finite range.
fn q8_proof(u: &mut Uart, simd: Simd, rng: &mut Rng) {
    use neuro_kernels::q8;
    const MAXC: usize = 2048;
    static mut WR: [u8; q8::row_bytes(MAXC)] = [0; q8::row_bytes(MAXC)];
    static mut XV: [i64; MAXC] = [0; MAXC];
    static mut XQ: [i8; MAXC] = [0; MAXC];
    static mut XS: [(i32, i32); MAXC / 32] = [(0, 0); MAXC / 32];
    let (wr, xv, xq, xs) = unsafe { (&mut *core::ptr::addr_of_mut!(WR), &mut *core::ptr::addr_of_mut!(XV), &mut *core::ptr::addr_of_mut!(XQ), &mut *core::ptr::addr_of_mut!(XS)) };
    let (mut rows, mut macs) = (0u64, 0u64);
    for round in 0..6_000u32 {
        let cols = 32 * (1 + (rng.next() % 64) as usize);
        let wn = q8::row_bytes(cols);
        for blk in wr[..wn].chunks_exact_mut(q8::BLOCK_BYTES) {
            // Any finite binary16 scale (exponent 0..=30), sign included.
            let e = (rng.next() % 31) as u16;
            let bits = (e << 10) | (rng.next() as u16 & 0x83ff);
            blk[..2].copy_from_slice(&bits.to_le_bytes());
            for q in blk[2..].iter_mut() {
                *q = match round % 5 {
                    0 => 0x81, // −127
                    1 => 0x7f,
                    _ => rng.next() as u8,
                };
            }
        }
        let mag = [1u32, 12, 24, 40][(round % 4) as usize];
        for v in xv[..cols].iter_mut() {
            *v = (rng.next() as i64) >> (63 - mag);
        }
        if !q8::quantize(&xv[..cols], &mut xq[..cols], &mut xs[..cols / 32]) {
            let _ = writeln!(u, "FAIL: q8 quantize refused");
            exit(1);
        }
        let act = q8::Act { q: &xq[..cols], scale: &xs[..cols / 32] };
        let (a, b) = (q8::row_scalar(&wr[..wn], &act), q8::row(simd, &wr[..wn], &act));
        if a.is_none() || a != b {
            let _ = writeln!(u, "FAIL q8 round {round} cols {cols}: scalar {a:?} neon {b:?}");
            exit(1);
        }
        rows += 1;
        macs += cols as u64;
    }
    let _ = writeln!(u, "PASS q8 kernel: {rows} Q8_0 rows, {macs} MACs, every binary16 exponent, {} identical to the scalar reference", simd.name());

    // The 4-row kernel, and whole matrices (4-row groups plus 1-3 remainder rows) through matvec.
    const C4: usize = 1024;
    static mut W7: [u8; 7 * q8::row_bytes(C4)] = [0; 7 * q8::row_bytes(C4)];
    let w7 = unsafe { &mut *core::ptr::addr_of_mut!(W7) };
    let (mut groups, mut mats) = (0u64, 0u64);
    for round in 0..3_000u32 {
        let cols = 32 * (1 + (rng.next() % 32) as usize);
        let rb = q8::row_bytes(cols);
        let nrows = 1 + (rng.next() % 7) as usize;
        for blk in w7[..nrows * rb].chunks_exact_mut(q8::BLOCK_BYTES) {
            // Mostly realistic scales (fast path), sometimes extreme ones (general path).
            let e = if round % 3 == 0 { (rng.next() % 31) as u16 } else { 5 + (rng.next() % 6) as u16 };
            let bits = (e << 10) | (rng.next() as u16 & 0x83ff);
            blk[..2].copy_from_slice(&bits.to_le_bytes());
            for q in blk[2..].iter_mut() {
                *q = if round % 7 == 0 { 0x81 } else { rng.next() as u8 };
            }
        }
        let mag = [12u32, 20, 28, 44][(round % 4) as usize];
        for v in xv[..cols].iter_mut() {
            *v = (rng.next() as i64) >> (63 - mag);
        }
        q8::quantize(&xv[..cols], &mut xq[..cols], &mut xs[..cols / 32]);
        let act = q8::Act { q: &xq[..cols], scale: &xs[..cols / 32] };
        if nrows >= 4 {
            let (mut a, mut b) = ([0i64; 4], [1i64; 4]);
            let ok = q8::rows4_scalar(&w7[..4 * rb], &act, &mut a) && q8::rows4(simd, &w7[..4 * rb], &act, &mut b);
            if !ok || a != b {
                let _ = writeln!(u, "FAIL q8 rows4 round {round} cols {cols}: scalar {a:?} neon {b:?}");
                exit(1);
            }
            groups += 1;
        }
        let (mut ms, mut mn) = ([0i64; 7], [1i64; 7]);
        let ok1 = q8::matvec(Simd::SCALAR, &w7[..nrows * rb], nrows, &act, |r, v| ms[r] = v);
        let ok2 = q8::matvec(simd, &w7[..nrows * rb], nrows, &act, |r, v| mn[r] = v);
        let mut want = [0i64; 7];
        for r in 0..nrows {
            want[r] = q8::row_scalar(&w7[r * rb..(r + 1) * rb], &act).unwrap_or(i64::MIN);
        }
        if !ok1 || !ok2 || ms[..nrows] != want[..nrows] || mn[..nrows] != want[..nrows] {
            let _ = writeln!(u, "FAIL q8 matvec round {round} rows {nrows} cols {cols}");
            exit(1);
        }
        mats += 1;
    }
    let mut o = [7i64; 4];
    if q8::rows4(simd, &w7[..4 * q8::row_bytes(64) - 1], &q8::Act { q: &xq[..64], scale: &xs[..2] }, &mut o) || o != [7; 4] {
        let _ = writeln!(u, "FAIL: rows4 accepted a short matrix");
        exit(1);
    }
    let _ = writeln!(u, "PASS q8 4-row kernel: {groups} groups and {mats} matrices (1-7 rows, fast and general scale paths), {} identical to the scalar reference", simd.name());
}

/// A whole Qwen3-shaped decoder (QK-norm, NEOX RoPE θ = 1e6, GQA, SwiGLU, tied head, Q8_0 weights in GGUF
/// layout, binary32 gains) run scalar and NEON from the same prompt: every logit of every step equal.
fn qwen3_proof(u: &mut Uart, simd: Simd, rng: &mut Rng) {
    use neuro_kernels::q8::row_bytes;
    use neuro_lm::qwen3::{Kv, Layer, Mat, Model, Work};
    use neuro_lm::Dims;
    const D: Dims = Dims { vocab: 128, d_model: 64, n_layers: 2, n_heads: 4, n_kv_heads: 2, head_dim: 32, ffn: 128, max_ctx: 32 };
    const QD: usize = 128;
    const KVD: usize = 64;
    const SIZES: [usize; 7] = [QD * 68, KVD * 68, KVD * 68, 64 * row_bytes(QD), 128 * 68, 128 * 68, 64 * row_bytes(128)];
    const PER_LAYER: usize = SIZES[0] + SIZES[1] + SIZES[2] + SIZES[3] + SIZES[4] + SIZES[5] + SIZES[6];
    const TOTAL: usize = 2 * PER_LAYER + 128 * 68;
    const NORMS: usize = 2 * (64 + 32 + 32 + 64) * 4 + 64 * 4;
    const KVN: usize = 2 * 2 * 2 * 32 * 32;
    const KVS: usize = 2 * 2 * 2 * 32;
    const A64: usize = 2 * 64 + 2 * QD + 2 * KVD + 2 * 128 + 32 + 128;
    static mut W: [u8; TOTAL] = [0; TOTAL];
    static mut G: [u8; NORMS] = [0; NORMS];
    static mut KV_A: ([i16; KVN], [u8; KVS]) = ([0; KVN], [0; KVS]);
    static mut KV_B: ([i16; KVN], [u8; KVS]) = ([0; KVN], [0; KVS]);
    static mut WA: ([i64; A64], [i8; 128], [(i32, i32); 4], [i32; 32]) = ([0; A64], [0; 128], [(0, 0); 4], [0; 32]);
    static mut WB: ([i64; A64], [i8; 128], [(i32, i32); 4], [i32; 32]) = ([0; A64], [0; 128], [(0, 0); 4], [0; 32]);
    let (w, g) = unsafe { (&mut *core::ptr::addr_of_mut!(W), &mut *core::ptr::addr_of_mut!(G)) };
    let embed_off = 2 * PER_LAYER;
    for (i, blk) in w.chunks_exact_mut(34).enumerate() {
        // Weight scale ≈ 2^-10 (binary16 exponent 5); embedding scale ≈ 2^-5 (exponent 10).
        let e: u16 = if i * 34 >= embed_off { 10 } else { 5 };
        let bits = (e << 10) | (rng.next() as u16 & 0x3ff);
        blk[..2].copy_from_slice(&bits.to_le_bytes());
        for q in blk[2..].iter_mut() {
            *q = rng.next() as u8;
        }
    }
    for c in g.chunks_exact_mut(4) {
        // binary32 gains around 1.0 (0x3f800000 ± 2^-4 relative)
        let bits = 0x3f80_0000u32 + (rng.next() as u32 % 0x10_0000) - 0x8_0000;
        c.copy_from_slice(&bits.to_le_bytes());
    }
    let (w, g): (&'static [u8], &'static [u8]) = (w, g);
    let (mut wo, mut go) = (0usize, 0usize);
    let mut mat = |rows: usize, cols: usize| {
        let n = rows * row_bytes(cols);
        let m = Mat { rows, cols, w: &w[wo..wo + n] };
        wo += n;
        m
    };
    let mut gain = |n: usize| {
        let s = &g[go..go + 4 * n];
        go += 4 * n;
        s
    };
    let mut layer = || Layer { attn_norm: gain(64), wq: mat(QD, 64), wk: mat(KVD, 64), wv: mat(KVD, 64), wo: mat(64, QD), q_norm: gain(32), k_norm: gain(32), ffn_norm: gain(64), w_gate: mat(128, 64), w_up: mat(128, 64), w_down: mat(64, 128) };
    let layers = [layer(), layer()];
    let model = Model { dims: D, embed: Mat { rows: 128, cols: 64, w: &w[embed_off..] }, layers: &layers, final_norm: &g[NORMS - 256..], head: None, rope: &tables::ROPE_NEOX, eps: tables::EPS_BITS, kq_scale: tables::KQ_SCALE_BITS };
    if model.check().is_err() {
        let _ = writeln!(u, "FAIL: qwen3 model shapes");
        exit(1);
    }
    let (kva, kvb, wa, wb) = unsafe { (&mut *core::ptr::addr_of_mut!(KV_A), &mut *core::ptr::addr_of_mut!(KV_B), &mut *core::ptr::addr_of_mut!(WA), &mut *core::ptr::addr_of_mut!(WB)) };
    let (Some(mut work_a), Some(mut work_b)) = (Work::new(&D, &mut wa.0, &mut wa.1, &mut wa.2, &mut wa.3), Work::new(&D, &mut wb.0, &mut wb.1, &mut wb.2, &mut wb.3)) else {
        let _ = writeln!(u, "FAIL: qwen3 work buffers");
        exit(1)
    };
    let (mut kv_a, mut kv_b) = (Kv { vals: &mut kva.0, shifts: &mut kva.1 }, Kv { vals: &mut kvb.0, shifts: &mut kvb.1 });
    let prompt = [3usize, 77, 12, 101, 64];
    let mut tok = 0usize;
    let mut generated = [0u8; 32];
    for pos in 0..D.max_ctx {
        let t = if pos < prompt.len() { prompt[pos] } else { tok };
        let (ra, rb) = (model.step(Simd::SCALAR, t, pos, &mut kv_a, &mut work_a), model.step(simd, t, pos, &mut kv_b, &mut work_b));
        match (ra, rb) {
            (Ok(a), Ok(b)) if a == b && work_a.logits == work_b.logits => {
                tok = a;
                generated[pos] = a as u8;
            }
            _ => {
                let _ = writeln!(u, "FAIL: qwen3 scalar and {} differ at position {pos}", simd.name());
                exit(1);
            }
        }
    }
    let _ = writeln!(u, "PASS qwen3: 2 layers, QK-norm, NEOX RoPE theta 1e6, GQA 4/2, SwiGLU, tied head, Q8_0 ({} weight bytes); {} positions, every logit equal, scalar == {}", TOTAL, D.max_ctx, simd.name());
    let _ = writeln!(u, "  generated tokens after the prompt: {:?}", &generated[prompt.len()..prompt.len() + 12]);
}

fn cntvct() -> u64 {
    let v: u64;
    unsafe { asm!("isb", "mrs {}, cntvct_el0", out(reg) v) };
    v
}

/// Executed-instruction proxy: run under `qemu -icount shift=0`, where every instruction advances the
/// virtual clock by 1 ns, so generic-timer ticks × (10^9 / CNTFRQ) = instructions executed. Deterministic,
/// but instructions, not cycles: a real A76 issues several per cycle and memory bandwidth is not modelled.
fn q8_bench(u: &mut Uart, simd: Simd, rng: &mut Rng) {
    use neuro_kernels::q8;
    const ROWS: usize = 512;
    const COLS: usize = 2048;
    static mut WM: [u8; ROWS * q8::row_bytes(COLS)] = [0; ROWS * q8::row_bytes(COLS)];
    static mut XB: [i64; COLS] = [0; COLS];
    static mut XQB: [i8; COLS] = [0; COLS];
    static mut XSB: [(i32, i32); COLS / 32] = [(0, 0); COLS / 32];
    let (wm, xb, xq, xs) = unsafe { (&mut *core::ptr::addr_of_mut!(WM), &mut *core::ptr::addr_of_mut!(XB), &mut *core::ptr::addr_of_mut!(XQB), &mut *core::ptr::addr_of_mut!(XSB)) };
    for blk in wm.chunks_exact_mut(q8::BLOCK_BYTES) {
        let bits = ((5 + (rng.next() % 6) as u16) << 10) | (rng.next() as u16 & 0x83ff); // scales ~2^-10..2^-5
        blk[..2].copy_from_slice(&bits.to_le_bytes());
        for q in blk[2..].iter_mut() {
            *q = rng.next() as u8;
        }
    }
    for v in xb.iter_mut() {
        *v = (rng.next() as i64) >> 44; // |x| up to 2^19 in Q16 (≈ 8.0)
    }
    q8::quantize(xb, xq, xs);
    let act = q8::Act { q: xq, scale: xs };
    let freq: u64;
    unsafe { asm!("mrs {}, cntfrq_el0", out(reg) freq) };
    let ns_per_tick = 1_000_000_000 / freq.max(1);
    let macs = (ROWS * COLS) as u64;
    let rb = q8::row_bytes(COLS);
    let mut check = [0i64; 3];
    let mut measure = |name: &str, which: usize, u: &mut Uart| {
        let t0 = cntvct();
        let mut sum = 0i64;
        match which {
            0 => {
                for r in 0..ROWS {
                    sum = sum.wrapping_add(q8::row_scalar(&wm[r * rb..(r + 1) * rb], &act).unwrap_or(0));
                }
            }
            1 => {
                for r in 0..ROWS {
                    sum = sum.wrapping_add(q8::row(simd, &wm[r * rb..(r + 1) * rb], &act).unwrap_or(0));
                }
            }
            _ => {
                q8::matvec(simd, wm, ROWS, &act, |_, v| sum = sum.wrapping_add(v));
            }
        }
        let ticks = cntvct() - t0;
        check[which] = sum;
        let insns = ticks * ns_per_tick;
        let _ = writeln!(u, "  {name}: {insns} instructions, {}.{:02} per MAC", insns / macs, insns * 100 / macs % 100);
    };
    let _ = writeln!(u, "BENCH q8 512x2048 matrix x vector (instruction counts valid only under -icount shift=0):");
    measure("scalar reference         ", 0, u);
    measure("NEON 1-row               ", 1, u);
    measure("NEON 4-row (matvec)      ", 2, u);
    if check[0] != check[1] || check[1] != check[2] {
        let _ = writeln!(u, "FAIL: benchmark results differ");
        exit(1);
    }
}
