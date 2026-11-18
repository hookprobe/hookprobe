	.text
	.file	"dot_kernels.c"
	.globl	dot_q8                          // -- Begin function dot_q8
	.p2align	4
	.type	dot_q8,@function
dot_q8:                                 // @dot_q8
// %bb.0:
	cmp	w2, #1
	b.lt	.LBB0_4
// %bb.1:
	mov	w8, w2
	movi	v0.2d, #0000000000000000
	.p2align	5, , 16
.LBB0_2:                                // =>This Inner Loop Header: Depth=1
	ldur	q1, [x0, #4]
	ldur	q2, [x0, #20]
	ldur	q3, [x1, #4]
	ldur	q4, [x1, #20]
	movi	v5.2d, #0000000000000000
	sdot	v5.4s, v1.16b, v3.16b
	sdot	v5.4s, v2.16b, v4.16b
	scvtf	v1.4s, v5.4s
	ldr	s2, [x0], #36
	ldr	s3, [x1], #36
	fmul	s2, s2, s3
	fmla	v0.4s, v1.4s, v2.s[0]
	subs	x8, x8, #1
	b.ne	.LBB0_2
// %bb.3:
	faddp	v0.4s, v0.4s, v0.4s
	faddp	s0, v0.2s
	ret
.LBB0_4:
	movi	v0.2d, #0000000000000000
	faddp	v0.4s, v0.4s, v0.4s
	faddp	s0, v0.2s
	ret
.Lfunc_end0:
	.size	dot_q8, .Lfunc_end0-dot_q8
                                        // -- End function
	.globl	dot_q4                          // -- Begin function dot_q4
	.p2align	4
	.type	dot_q4,@function
dot_q4:                                 // @dot_q4
// %bb.0:
	cmp	w2, #1
	b.lt	.LBB1_4
// %bb.1:
	mov	w8, w2
	add	x9, x0, #4
	movi	v0.2d, #0000000000000000
	movi	v1.16b, #15
	movi	v2.16b, #248
	.p2align	5, , 16
.LBB1_2:                                // =>This Inner Loop Header: Depth=1
	ldr	q3, [x9]
	and	v4.16b, v3.16b, v1.16b
	add	v4.16b, v4.16b, v2.16b
	movi	v5.16b, #248
	usra	v5.16b, v3.16b, #4
	ldur	q3, [x1, #4]
	ldur	q6, [x1, #20]
	movi	v7.2d, #0000000000000000
	sdot	v7.4s, v4.16b, v3.16b
	sdot	v7.4s, v5.16b, v6.16b
	scvtf	v3.4s, v7.4s
	ldur	s4, [x9, #-4]
	ldr	s5, [x1], #36
	fmul	s4, s4, s5
	fmla	v0.4s, v3.4s, v4.s[0]
	add	x9, x9, #20
	subs	x8, x8, #1
	b.ne	.LBB1_2
// %bb.3:
	faddp	v0.4s, v0.4s, v0.4s
	faddp	s0, v0.2s
	ret
.LBB1_4:
	movi	v0.2d, #0000000000000000
	faddp	v0.4s, v0.4s, v0.4s
	faddp	s0, v0.2s
	ret
.Lfunc_end1:
	.size	dot_q4, .Lfunc_end1-dot_q4
                                        // -- End function
	.section	.rodata.cst16,"aM",@progbits,16
	.p2align	4, 0x0                          // -- Begin function dot_t2u
.LCPI2_0:
	.byte	252                             // 0xfc
	.byte	252                             // 0xfc
	.byte	252                             // 0xfc
	.byte	252                             // 0xfc
	.byte	252                             // 0xfc
	.byte	252                             // 0xfc
	.byte	252                             // 0xfc
	.byte	252                             // 0xfc
	.byte	250                             // 0xfa
	.byte	250                             // 0xfa
	.byte	250                             // 0xfa
	.byte	250                             // 0xfa
	.byte	250                             // 0xfa
	.byte	250                             // 0xfa
	.byte	250                             // 0xfa
	.byte	250                             // 0xfa
	.text
	.globl	dot_t2u
	.p2align	4
	.type	dot_t2u,@function
dot_t2u:                                // @dot_t2u
// %bb.0:
	cmp	w2, #1
	b.lt	.LBB2_4
// %bb.1:
	mov	w8, w2
	add	x9, x0, #4
	movi	v0.2d, #0000000000000000
	adrp	x10, .LCPI2_0
	ldr	q1, [x10, :lo12:.LCPI2_0]
	movi	v2.16b, #3
	movi	v3.2d, #0xffffffffffffffff
	.p2align	5, , 16
.LBB2_2:                                // =>This Inner Loop Header: Depth=1
	ldr	d4, [x9]
	ushr	v5.8b, v4.8b, #2
	mov	v6.16b, v4.16b
	mov	v6.d[1], v5.d[0]
	mov	v4.d[1], v4.d[0]
	ushl	v4.16b, v4.16b, v1.16b
	and	v5.16b, v6.16b, v2.16b
	add	v5.16b, v5.16b, v3.16b
	and	v4.16b, v4.16b, v2.16b
	add	v4.16b, v4.16b, v3.16b
	ldur	q6, [x1, #4]
	ldur	q7, [x1, #20]
	movi	v16.2d, #0000000000000000
	sdot	v16.4s, v5.16b, v6.16b
	sdot	v16.4s, v4.16b, v7.16b
	scvtf	v4.4s, v16.4s
	ldur	s5, [x9, #-4]
	ldr	s6, [x1], #36
	fmul	s5, s5, s6
	fmla	v0.4s, v4.4s, v5.s[0]
	add	x9, x9, #12
	subs	x8, x8, #1
	b.ne	.LBB2_2
// %bb.3:
	faddp	v0.4s, v0.4s, v0.4s
	faddp	s0, v0.2s
	ret
.LBB2_4:
	movi	v0.2d, #0000000000000000
	faddp	v0.4s, v0.4s, v0.4s
	faddp	s0, v0.2s
	ret
.Lfunc_end2:
	.size	dot_t2u, .Lfunc_end2-dot_t2u
                                        // -- End function
	.globl	lut_build                       // -- Begin function lut_build
	.p2align	4
	.type	lut_build,@function
lut_build:                              // @lut_build
// %bb.0:
	cmp	w1, #4
	b.lt	.LBB3_9
// %bb.1:
	mov	x8, xzr
	lsr	w9, w1, #2
	b	.LBB3_3
	.p2align	5, , 16
.LBB3_2:                                //   in Loop: Header=BB3_3 Depth=1
	add	x8, x8, #1
	add	x0, x0, #4
	cmp	x8, x9
	b.eq	.LBB3_9
.LBB3_3:                                // =>This Loop Header: Depth=1
                                        //     Child Loop BB3_5 Depth 2
                                        //       Child Loop BB3_7 Depth 3
	mov	x10, xzr
	ubfiz	x11, x8, #4, #28
	b	.LBB3_5
	.p2align	5, , 16
.LBB3_4:                                //   in Loop: Header=BB3_5 Depth=2
	add	x13, x10, x11
	strb	w12, [x2, x13]
	lsr	w12, w12, #8
	strb	w12, [x3, x13]
	add	x10, x10, #1
	cmp	x10, #16
	b.eq	.LBB3_2
.LBB3_5:                                //   Parent Loop BB3_3 Depth=1
                                        // =>  This Loop Header: Depth=2
                                        //       Child Loop BB3_7 Depth 3
	mov	x13, xzr
	mov	w12, wzr
	b	.LBB3_7
	.p2align	5, , 16
.LBB3_6:                                //   in Loop: Header=BB3_7 Depth=3
	add	x13, x13, #1
	cmp	x13, #4
	b.eq	.LBB3_4
.LBB3_7:                                //   Parent Loop BB3_3 Depth=1
                                        //     Parent Loop BB3_5 Depth=2
                                        // =>    This Inner Loop Header: Depth=3
	lsr	w14, w10, w13
	tbz	w14, #0, .LBB3_6
// %bb.8:                               //   in Loop: Header=BB3_7 Depth=3
	ldrsb	w14, [x0, x13]
	add	w12, w12, w14
	b	.LBB3_6
.LBB3_9:
	ret
.Lfunc_end3:
	.size	lut_build, .Lfunc_end3-lut_build
                                        // -- End function
	.globl	dot_t2l_rows16                  // -- Begin function dot_t2l_rows16
	.p2align	4
	.type	dot_t2l_rows16,@function
dot_t2l_rows16:                         // @dot_t2l_rows16
// %bb.0:
	cmp	w4, #1
	b.lt	.LBB4_5
// %bb.1:
	mov	x8, xzr
	mov	w9, w4
	movi	v1.2d, #0000000000000000
	movi	v5.2d, #0000000000000000
	movi	v0.2d, #0000000000000000
	movi	v4.2d, #0000000000000000
	movi	v3.2d, #0000000000000000
	movi	v2.2d, #0000000000000000
	b	.LBB4_3
	.p2align	5, , 16
.LBB4_2:                                //   in Loop: Header=BB4_3 Depth=1
	add	x8, x8, #1
	cmp	x9, x8
	b.eq	.LBB4_6
.LBB4_3:                                // =>This Inner Loop Header: Depth=1
	lsl	x10, x8, #4
	ldr	q6, [x2, x10]
	ldr	q7, [x3, x10]
	ldr	q16, [x0, x10]
	ldr	q17, [x1, x10]
	tbl	v18.16b, { v6.16b }, v16.16b
	tbl	v16.16b, { v7.16b }, v16.16b
	tbl	v6.16b, { v6.16b }, v17.16b
	tbl	v7.16b, { v7.16b }, v17.16b
	zip1	v17.16b, v18.16b, v16.16b
	zip2	v16.16b, v18.16b, v16.16b
	zip1	v18.16b, v6.16b, v7.16b
	zip2	v6.16b, v6.16b, v7.16b
	mvn	w10, w8
	sub	v7.8h, v17.8h, v18.8h
	add	v5.8h, v7.8h, v5.8h
	sub	v6.8h, v16.8h, v6.8h
	add	v0.8h, v6.8h, v0.8h
	tst	x10, #0x1f
	b.ne	.LBB4_2
// %bb.4:                               //   in Loop: Header=BB4_3 Depth=1
	saddw	v1.4s, v1.4s, v5.4h
	saddw2	v4.4s, v4.4s, v5.8h
	saddw	v3.4s, v3.4s, v0.4h
	saddw2	v2.4s, v2.4s, v0.8h
	movi	v0.2d, #0000000000000000
	movi	v5.2d, #0000000000000000
	b	.LBB4_2
.LBB4_5:
	movi	v0.2d, #0000000000000000
	movi	v2.2d, #0000000000000000
	movi	v3.2d, #0000000000000000
	movi	v4.2d, #0000000000000000
	movi	v1.2d, #0000000000000000
	movi	v5.2d, #0000000000000000
.LBB4_6:
	saddw	v1.4s, v1.4s, v5.4h
	saddw2	v4.4s, v4.4s, v5.8h
	saddw	v3.4s, v3.4s, v0.4h
	saddw2	v0.4s, v2.4s, v0.8h
	stp	q1, q4, [x5]
	stp	q3, q0, [x5, #32]
	ret
.Lfunc_end4:
	.size	dot_t2l_rows16, .Lfunc_end4-dot_t2l_rows16
                                        // -- End function
	.globl	dot_t2lp_rows16                 // -- Begin function dot_t2lp_rows16
	.p2align	4
	.type	dot_t2lp_rows16,@function
dot_t2lp_rows16:                        // @dot_t2lp_rows16
// %bb.0:
	cmp	w4, #1
	b.lt	.LBB5_5
// %bb.1:
	mov	x8, xzr
	movi	v1.2d, #0000000000000000
	mov	w9, w4
	movi	v5.2d, #0000000000000000
	movi	v6.8b, #15
	movi	v0.2d, #0000000000000000
	movi	v4.2d, #0000000000000000
	movi	v3.2d, #0000000000000000
	movi	v2.2d, #0000000000000000
	b	.LBB5_3
	.p2align	5, , 16
.LBB5_2:                                //   in Loop: Header=BB5_3 Depth=1
	add	x8, x8, #1
	cmp	x9, x8
	b.eq	.LBB5_6
.LBB5_3:                                // =>This Inner Loop Header: Depth=1
	lsl	x10, x8, #4
	ldr	q7, [x2, x10]
	ldr	q16, [x3, x10]
	ldr	d17, [x0, x8, lsl #3]
	ldr	d18, [x1, x8, lsl #3]
	and	v19.8b, v17.8b, v6.8b
	ushr	v17.8b, v17.8b, #4
	mov	v19.d[1], v17.d[0]
	and	v17.8b, v18.8b, v6.8b
	ushr	v18.8b, v18.8b, #4
	mov	v17.d[1], v18.d[0]
	tbl	v18.16b, { v7.16b }, v19.16b
	tbl	v19.16b, { v16.16b }, v19.16b
	tbl	v7.16b, { v7.16b }, v17.16b
	tbl	v16.16b, { v16.16b }, v17.16b
	zip1	v17.16b, v18.16b, v19.16b
	zip2	v18.16b, v18.16b, v19.16b
	zip1	v19.16b, v7.16b, v16.16b
	zip2	v7.16b, v7.16b, v16.16b
	mvn	w10, w8
	sub	v16.8h, v17.8h, v19.8h
	add	v5.8h, v16.8h, v5.8h
	sub	v7.8h, v18.8h, v7.8h
	add	v0.8h, v7.8h, v0.8h
	tst	x10, #0x1f
	b.ne	.LBB5_2
// %bb.4:                               //   in Loop: Header=BB5_3 Depth=1
	saddw	v1.4s, v1.4s, v5.4h
	saddw2	v4.4s, v4.4s, v5.8h
	saddw	v3.4s, v3.4s, v0.4h
	saddw2	v2.4s, v2.4s, v0.8h
	movi	v0.2d, #0000000000000000
	movi	v5.2d, #0000000000000000
	b	.LBB5_2
.LBB5_5:
	movi	v0.2d, #0000000000000000
	movi	v2.2d, #0000000000000000
	movi	v3.2d, #0000000000000000
	movi	v4.2d, #0000000000000000
	movi	v1.2d, #0000000000000000
	movi	v5.2d, #0000000000000000
.LBB5_6:
	saddw	v1.4s, v1.4s, v5.4h
	saddw2	v4.4s, v4.4s, v5.8h
	saddw	v3.4s, v3.4s, v0.4h
	saddw2	v0.4s, v2.4s, v0.8h
	stp	q1, q4, [x5]
	stp	q3, q0, [x5, #32]
	ret
.Lfunc_end5:
	.size	dot_t2lp_rows16, .Lfunc_end5-dot_t2lp_rows16
                                        // -- End function
	.ident	"Apple clang version 17.0.0 (clang-1700.6.4.2)"
	.section	".note.GNU-stack","",@progbits
	.addrsig
