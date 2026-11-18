// SPDX-License-Identifier: AGPL-3.0-only
// Correctness + single-thread GEMV timing for dot_kernels.c. Times measured on the machine this runs on
// (a development host is NOT a Cortex-A76: label results accordingly). Weight matrices are sized well
// above the last-level cache so the measurement is a streaming (decode-like) GEMV.
// Build: clang -O3 -mcpu=native bench.c dot_kernels.c -o bench   (on a CM5: -mcpu=cortex-a76)
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <math.h>

#define QK 32
typedef struct { float d; int8_t q[QK]; } blk_q8;
typedef struct { float d; uint8_t q[QK / 2]; } blk_q4;
typedef struct { float d; uint8_t q[QK / 4]; } blk_t2;
float dot_q8(const blk_q8 *, const blk_q8 *, int);
float dot_q4(const blk_q4 *, const blk_q8 *, int);
float dot_t2u(const blk_t2 *, const blk_q8 *, int);
void lut_build(const int8_t *, int, uint8_t *, uint8_t *);
void dot_t2l_rows16(const uint8_t *, const uint8_t *, const uint8_t *, const uint8_t *, int, int32_t *);
void dot_t2lp_rows16(const uint8_t *, const uint8_t *, const uint8_t *, const uint8_t *, int, int32_t *);

static double now(void) { struct timespec t; clock_gettime(CLOCK_MONOTONIC, &t); return t.tv_sec + t.tv_nsec * 1e-9; }
static uint64_t rs = 88172645463325252ull;
static uint32_t rnd(void) { rs ^= rs << 13; rs ^= rs >> 7; rs ^= rs << 17; return (uint32_t)rs; }

int main(int argc, char **argv) {
    int K = argc > 1 ? atoi(argv[1]) : 2048;     // row length (hidden size)
    int R = argc > 2 ? atoi(argv[2]) : 32768;    // rows (sized so every matrix >> LLC)
    int reps = argc > 3 ? atoi(argv[3]) : 5;
    int nb = K / QK, ng = K / 4;
    // activations
    blk_q8 *x = malloc(sizeof(blk_q8) * nb);
    int8_t *xi = malloc(K);
    for (int b = 0; b < nb; b++) { x[b].d = 1.0f; for (int j = 0; j < QK; j++) { x[b].q[j] = (int8_t)(rnd() % 255 - 127); xi[b * QK + j] = x[b].q[j]; } }
    // weights: one ternary matrix, expressed in all formats so results are comparable
    int8_t *wt = malloc((size_t)R * K);
    for (size_t i = 0; i < (size_t)R * K; i++) wt[i] = (int8_t)(rnd() % 3) - 1;
    blk_q8 *w8 = malloc(sizeof(blk_q8) * (size_t)R * nb);
    blk_q4 *w4 = malloc(sizeof(blk_q4) * (size_t)R * nb);
    blk_t2 *w2 = malloc(sizeof(blk_t2) * (size_t)R * nb);
    for (size_t r = 0; r < (size_t)R; r++) for (int b = 0; b < nb; b++) {
        const int8_t *s = wt + r * K + b * QK;
        blk_q8 *o8 = &w8[r * nb + b]; blk_q4 *o4 = &w4[r * nb + b]; blk_t2 *o2 = &w2[r * nb + b];
        o8->d = o4->d = o2->d = 1.0f;
        memcpy(o8->q, s, QK);
        for (int j = 0; j < QK / 2; j++) o4->q[j] = (uint8_t)((s[j] + 8) | ((s[j + 16] + 8) << 4));
        memset(o2->q, 0, QK / 4);
        for (int j = 0; j < QK; j++) o2->q[j % 8] |= (uint8_t)((s[j] + 1) << (2 * (j / 8)));
    }
    // LUT layout: rows in tiles of 16; per tile, per group: 16 pos-index bytes then 16 neg-index bytes
    uint8_t *ip = malloc((size_t)R * ng), *in = malloc((size_t)R * ng);
    for (int t = 0; t < R / 16; t++) for (int g = 0; g < ng; g++) for (int l = 0; l < 16; l++) {
        const int8_t *s = wt + (size_t)(t * 16 + l) * K + 4 * g;
        uint8_t p = 0, n = 0;
        for (int k = 0; k < 4; k++) { if (s[k] == 1) p |= 1 << k; if (s[k] == -1) n |= 1 << k; }
        ip[((size_t)t * ng + g) * 16 + l] = p; in[((size_t)t * ng + g) * 16 + l] = n;
    }
    // packed: per tile, per group: 8 bytes of + nibbles, then (separate array) 8 bytes of - nibbles
    uint8_t *pp = calloc((size_t)R * ng / 2, 1), *pn = calloc((size_t)R * ng / 2, 1);
    for (int t = 0; t < R / 16; t++) for (int g = 0; g < ng; g++) for (int l = 0; l < 16; l++) {
        uint8_t p = ip[((size_t)t * ng + g) * 16 + l], n = in[((size_t)t * ng + g) * 16 + l];
        size_t o = ((size_t)t * ng + g) * 8 + (l % 8);
        pp[o] |= (uint8_t)(l < 8 ? p : p << 4); pn[o] |= (uint8_t)(l < 8 ? n : n << 4);
    }
    uint8_t *tlo = malloc(16 * ng), *thi = malloc(16 * ng);
    float *y = malloc(sizeof(float) * R); int32_t *yl = malloc(sizeof(int32_t) * R);
    // reference
    long bad = 0;
    for (int r = 0; r < R; r += 997) {
        long ref = 0; for (int k = 0; k < K; k++) ref += (long)wt[(size_t)r * K + k] * xi[k];
        float a = dot_q8(w8 + (size_t)r * nb, x, nb), b = dot_q4(w4 + (size_t)r * nb, x, nb), c = dot_t2u(w2 + (size_t)r * nb, x, nb);
        if (fabsf(a - ref) > 0.5f || fabsf(b - ref) > 0.5f || fabsf(c - ref) > 0.5f) bad++;
    }
    lut_build(xi, K, tlo, thi);
    for (int t = 0; t < R / 16; t += 61) {
        int32_t o[16];
        dot_t2l_rows16(ip + (size_t)t * ng * 16, in + (size_t)t * ng * 16, tlo, thi, ng, o);
        for (int l = 0; l < 16; l++) { long ref = 0; for (int k = 0; k < K; k++) ref += (long)wt[(size_t)(t * 16 + l) * K + k] * xi[k]; if (o[l] != ref) bad++; }
        dot_t2lp_rows16(pp + (size_t)t * ng * 8, pn + (size_t)t * ng * 8, tlo, thi, ng, o);
        for (int l = 0; l < 16; l++) { long ref = 0; for (int k = 0; k < K; k++) ref += (long)wt[(size_t)(t * 16 + l) * K + k] * xi[k]; if (o[l] != ref) bad++; }
    }
    printf("K=%d rows=%d correctness mismatches=%ld\n", K, R, bad);
    printf("%-6s %10s %12s %10s %12s\n", "kernel", "bits/w", "matrix MB", "ms/GEMV", "weight GB/s");
    // bits/w = bytes actually streamed per weight in THIS layout (f32 block scales; ggml uses f16: q8 8.5, q4 4.5)
    struct { const char *n; double bits; } f[5] = {{"q8", 36 * 8.0 / 32}, {"q4", 20 * 8.0 / 32}, {"t2u", 12 * 8.0 / 32},
                                                  {"t2l", 4.0}, {"t2lp", 2.0}};
    for (int k = 0; k < 5; k++) {
        double best = 1e9;
        for (int rep = 0; rep < reps; rep++) {
            double t0 = now();
            if (k == 0) for (int r = 0; r < R; r++) y[r] = dot_q8(w8 + (size_t)r * nb, x, nb);
            if (k == 1) for (int r = 0; r < R; r++) y[r] = dot_q4(w4 + (size_t)r * nb, x, nb);
            if (k == 2) for (int r = 0; r < R; r++) y[r] = dot_t2u(w2 + (size_t)r * nb, x, nb);
            if (k == 4) { lut_build(xi, K, tlo, thi); for (int t = 0; t < R / 16; t++) dot_t2lp_rows16(pp + (size_t)t * ng * 8, pn + (size_t)t * ng * 8, tlo, thi, ng, yl + t * 16); }
            if (k == 3) { lut_build(xi, K, tlo, thi); for (int t = 0; t < R / 16; t++) dot_t2l_rows16(ip + (size_t)t * ng * 16, in + (size_t)t * ng * 16, tlo, thi, ng, yl + t * 16); }
            double dt = now() - t0; if (dt < best) best = dt;
        }
        double mb = (double)R * K * f[k].bits / 8 / 1e6;
        printf("%-6s %10.2f %12.1f %10.2f %12.2f\n", f[k].n, f[k].bits, mb, best * 1e3, mb / 1e3 / best);
    }
    volatile float sink = y[R - 1] + yl[R - 1]; (void)sink;
    return 0;
}
