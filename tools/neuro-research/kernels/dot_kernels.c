// SPDX-License-Identifier: AGPL-3.0-only
// Neuro research, Gate 2: the inner loop of LLM decode (one weight row . one activation vector)
// in four weight representations, written with Arm NEON intrinsics the way a no_std Rust runtime
// would write them with core::arch::aarch64 (same LLVM intrinsics, same instructions).
//
//   q8   : int8 weights, block of 32 with one f32 scale        (ggml Q8_0-like, 8.5 bits/weight incl. scale)
//   q4   : 4-bit weights, block of 32, offset 8, f32 scale       (ggml Q4_0-like, 4.5 bits/weight; here f32 scale)
//   t2u  : ternary {-1,0,+1}, 2 bits/weight, UNPACKED to int8 then SDOT (BitNet I2_S-like)
//   t2l  : ternary as two 1-bit planes (+ and -), consumed via a 16-entry lookup table of
//          4-activation partial sums with TBL -- no unpacking to int8 (T-MAC / TL-style)
//
// Activations: int8, per-block f32 scale (Q8_0). Accumulation int32 (SDOT) or int16 (LUT).
// Research code: correctness is checked against a scalar reference; NOT a runtime.
// Build (assembly for the CM5 core): clang -O3 -mcpu=cortex-a76 -ffreestanding -S dot_kernels.c
#include <arm_neon.h>
#include <stdint.h>

#define QK 32

typedef struct { float d; int8_t q[QK]; } blk_q8;          // 36 B / 32 weights
typedef struct { float d; uint8_t q[QK / 2]; } blk_q4;     // 20 B / 32 weights (ggml uses f16 d: 18 B)
typedef struct { float d; uint8_t q[QK / 4]; } blk_t2;     // 12 B / 32 weights; 2-bit codes 0:-1 1:0 2:+1
typedef struct { float d; uint8_t pos[QK / 8]; uint8_t neg[QK / 8]; } blk_t2p;  // 12 B / 32 weights, bit planes

// ---- q8 x q8 ----------------------------------------------------------------------------------
float dot_q8(const blk_q8 *w, const blk_q8 *x, int nb) {
    float32x4_t acc = vdupq_n_f32(0.f);
    for (int i = 0; i < nb; i++) {
        int8x16_t w0 = vld1q_s8(w[i].q), w1 = vld1q_s8(w[i].q + 16);
        int8x16_t x0 = vld1q_s8(x[i].q), x1 = vld1q_s8(x[i].q + 16);
        int32x4_t s = vdotq_s32(vdotq_s32(vdupq_n_s32(0), w0, x0), w1, x1);
        acc = vmlaq_n_f32(acc, vcvtq_f32_s32(s), w[i].d * x[i].d);
    }
    return vaddvq_f32(acc);
}

// ---- q4 x q8 : unpack nibbles (AND, USHR, SUB 8) then SDOT --------------------------------------
float dot_q4(const blk_q4 *w, const blk_q8 *x, int nb) {
    float32x4_t acc = vdupq_n_f32(0.f);
    const uint8x16_t m4 = vdupq_n_u8(0x0f);
    const int8x16_t s8 = vdupq_n_s8(8);
    for (int i = 0; i < nb; i++) {
        uint8x16_t v = vld1q_u8(w[i].q);
        int8x16_t lo = vsubq_s8(vreinterpretq_s8_u8(vandq_u8(v, m4)), s8);
        int8x16_t hi = vsubq_s8(vreinterpretq_s8_u8(vshrq_n_u8(v, 4)), s8);
        int8x16_t x0 = vld1q_s8(x[i].q), x1 = vld1q_s8(x[i].q + 16);
        int32x4_t s = vdotq_s32(vdotq_s32(vdupq_n_s32(0), lo, x0), hi, x1);
        acc = vmlaq_n_f32(acc, vcvtq_f32_s32(s), w[i].d * x[i].d);
    }
    return vaddvq_f32(acc);
}

// ---- ternary, unpack 2-bit codes to int8 {-1,0,1}, then SDOT ----------------------------------
// layout: byte j of q holds weights j, j+8, j+16, j+24 in bits 0-1, 2-3, 4-5, 6-7
float dot_t2u(const blk_t2 *w, const blk_q8 *x, int nb) {
    float32x4_t acc = vdupq_n_f32(0.f);
    const uint8x16_t m2 = vdupq_n_u8(3);
    const int8x16_t one = vdupq_n_s8(1);
    for (int i = 0; i < nb; i++) {
        uint8x8_t b = vld1_u8(w[i].q);
        uint8x16_t v = vcombine_u8(b, vshr_n_u8(b, 2));          // weights 0-7 | 8-15
        uint8x16_t u = vcombine_u8(vshr_n_u8(b, 4), vshr_n_u8(b, 6));  // 16-23 | 24-31
        int8x16_t w0 = vsubq_s8(vreinterpretq_s8_u8(vandq_u8(v, m2)), one);
        int8x16_t w1 = vsubq_s8(vreinterpretq_s8_u8(vandq_u8(u, m2)), one);
        int8x16_t x0 = vld1q_s8(x[i].q), x1 = vld1q_s8(x[i].q + 16);
        int32x4_t s = vdotq_s32(vdotq_s32(vdupq_n_s32(0), w0, x0), w1, x1);
        acc = vmlaq_n_f32(acc, vcvtq_f32_s32(s), w[i].d * x[i].d);
    }
    return vaddvq_f32(acc);
}

// ---- ternary via lookup tables, no unpacking ---------------------------------------------------
// Precompute ONCE per activation vector (amortised over every weight row of the layer):
// for each group g of 4 activations, the 16 subset sums S_g[m] = sum_{k: bit k of m} x[4g+k],
// stored as int16 split into a low-byte table and a high-byte table (TBL looks up bytes).
// A weight row stores, per group, a 4-bit mask of +1 weights and a 4-bit mask of -1 weights.
// dot = sum_g S_g[pos_g] - S_g[neg_g].  Per 32 weights: 8 groups; masks are nibbles.
// Here 16 groups (64 weights) are processed per step: tables for 16 groups = 16 x 16 entries,
// so each lane uses its own table -> a TBL per group is needed; T-MAC instead permutes so that
// one TBL serves 16 rows at once. We implement the T-MAC arrangement: 16 ROWS share a group's table.
//
// t2l_rows16: computes 16 dot products (16 weight rows) at once. For each group g:
//   idx_pos[16 rows] (uint8 nibbles), idx_neg[16 rows]
//   lo = TBL(Tlo_g, idx), hi = TBL(Thi_g, idx)  -> int16 partial sums for 16 rows
void lut_build(const int8_t *x, int n, uint8_t *tlo, uint8_t *thi) {  // n multiple of 4; 16 B each per group
    for (int g = 0; g < n / 4; g++)
        for (int m = 0; m < 16; m++) {
            int s = 0;
            for (int k = 0; k < 4; k++) if (m >> k & 1) s += x[4 * g + k];
            tlo[16 * g + m] = (uint8_t)(s & 0xff);
            thi[16 * g + m] = (uint8_t)((s >> 8) & 0xff);
        }
}

// pos/neg: [group][16 rows] one nibble-index byte each (unpacked index bytes; a packed form would hold
// two rows per byte and add one AND + one USHR per group). out: 16 int32 sums.
void dot_t2l_rows16(const uint8_t *pos, const uint8_t *neg, const uint8_t *tlo, const uint8_t *thi,
                    int ngroups, int32_t *out) {
    int16x8_t a0 = vdupq_n_s16(0), a1 = vdupq_n_s16(0);
    int32x4_t r0 = vdupq_n_s32(0), r1 = r0, r2 = r0, r3 = r0;
    for (int g = 0; g < ngroups; g++) {
        uint8x16_t tl = vld1q_u8(tlo + 16 * g), th = vld1q_u8(thi + 16 * g);
        uint8x16_t ip = vld1q_u8(pos + 16 * g), in = vld1q_u8(neg + 16 * g);
        uint8x16_t pl = vqtbl1q_u8(tl, ip), ph = vqtbl1q_u8(th, ip);
        uint8x16_t nl = vqtbl1q_u8(tl, in), nh = vqtbl1q_u8(th, in);
        int16x8_t p0 = vreinterpretq_s16_u8(vzip1q_u8(pl, ph)), p1 = vreinterpretq_s16_u8(vzip2q_u8(pl, ph));
        int16x8_t n0 = vreinterpretq_s16_u8(vzip1q_u8(nl, nh)), n1 = vreinterpretq_s16_u8(vzip2q_u8(nl, nh));
        a0 = vaddq_s16(a0, vsubq_s16(p0, n0));
        a1 = vaddq_s16(a1, vsubq_s16(p1, n1));
        if ((g & 31) == 31) {  // widen before int16 can overflow (|S| <= 508 per group, 32 groups < 32767)
            r0 = vaddw_s16(r0, vget_low_s16(a0)); r1 = vaddw_high_s16(r1, a0);
            r2 = vaddw_s16(r2, vget_low_s16(a1)); r3 = vaddw_high_s16(r3, a1);
            a0 = a1 = vdupq_n_s16(0);
        }
    }
    r0 = vaddw_s16(r0, vget_low_s16(a0)); r1 = vaddw_high_s16(r1, a0);
    r2 = vaddw_s16(r2, vget_low_s16(a1)); r3 = vaddw_high_s16(r3, a1);
    vst1q_s32(out, r0); vst1q_s32(out + 4, r1); vst1q_s32(out + 8, r2); vst1q_s32(out + 12, r3);
}

// Same, with indices PACKED: per group, 8 bytes hold the + nibbles of 16 rows (row l in byte l%8,
// low nibble for l<8, high nibble for l>=8) and 8 bytes the - nibbles => 2 bits per weight in memory.
// Extra cost per group: split each 8-byte load into 16 index lanes (AND, USHR, combine).
void dot_t2lp_rows16(const uint8_t *pos, const uint8_t *neg, const uint8_t *tlo, const uint8_t *thi,
                     int ngroups, int32_t *out) {
    int16x8_t a0 = vdupq_n_s16(0), a1 = vdupq_n_s16(0);
    int32x4_t r0 = vdupq_n_s32(0), r1 = r0, r2 = r0, r3 = r0;
    const uint8x8_t m4 = vdup_n_u8(0x0f);
    for (int g = 0; g < ngroups; g++) {
        uint8x16_t tl = vld1q_u8(tlo + 16 * g), th = vld1q_u8(thi + 16 * g);
        uint8x8_t bp = vld1_u8(pos + 8 * g), bn = vld1_u8(neg + 8 * g);
        uint8x16_t ip = vcombine_u8(vand_u8(bp, m4), vshr_n_u8(bp, 4));
        uint8x16_t in = vcombine_u8(vand_u8(bn, m4), vshr_n_u8(bn, 4));
        uint8x16_t pl = vqtbl1q_u8(tl, ip), ph = vqtbl1q_u8(th, ip);
        uint8x16_t nl = vqtbl1q_u8(tl, in), nh = vqtbl1q_u8(th, in);
        int16x8_t p0 = vreinterpretq_s16_u8(vzip1q_u8(pl, ph)), p1 = vreinterpretq_s16_u8(vzip2q_u8(pl, ph));
        int16x8_t n0 = vreinterpretq_s16_u8(vzip1q_u8(nl, nh)), n1 = vreinterpretq_s16_u8(vzip2q_u8(nl, nh));
        a0 = vaddq_s16(a0, vsubq_s16(p0, n0));
        a1 = vaddq_s16(a1, vsubq_s16(p1, n1));
        if ((g & 31) == 31) {
            r0 = vaddw_s16(r0, vget_low_s16(a0)); r1 = vaddw_high_s16(r1, a0);
            r2 = vaddw_s16(r2, vget_low_s16(a1)); r3 = vaddw_high_s16(r3, a1);
            a0 = a1 = vdupq_n_s16(0);
        }
    }
    r0 = vaddw_s16(r0, vget_low_s16(a0)); r1 = vaddw_high_s16(r1, a0);
    r2 = vaddw_s16(r2, vget_low_s16(a1)); r3 = vaddw_high_s16(r3, a1);
    vst1q_s32(out, r0); vst1q_s32(out + 4, r1); vst1q_s32(out + 8, r2); vst1q_s32(out + 12, r3);
}
