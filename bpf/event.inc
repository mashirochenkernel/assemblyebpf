/* SPDX-License-Identifier: GPL-2.0 */

	.macro event_head kind
	mov %r6, %r1
	call 14
	mov %r7, %r0
	mov %r1, %r7
	rsh %r1, 32
	mov %r0, 0
	jne %r1, 0, 1f
	exit
1:
	mov %r1, %r10
	add %r1, -144
	mov %r2, 16
	call 16
	mov %r1, 0
	stxw [%r10+-184], %r1
	lddw %r1, 0
	mov %r2, %r10
	add %r2, -184
	call 1
	jeq %r0, 0, 3f
	ldxw %r1, [%r0+0]
	jeq %r1, 0, 2f
	mov %r2, %r7
	rsh %r2, 32
	jne %r1, %r2, 4f
2:
	ldxw %r1, [%r0+4]
	jeq %r1, 0, 3f
	ldxdw %r1, [%r10+-144]
	ldxdw %r2, [%r0+8]
	jne %r1, %r2, 4f
	ldxdw %r1, [%r10+-136]
	ldxdw %r2, [%r0+16]
	jne %r1, %r2, 4f
	ja 3f
4:
	mov %r0, 0
	exit
3:
	mov %r1, \kind
	stxw [%r10+-184], %r1
	lddw %r1, 1
	mov %r2, %r10
	add %r2, -184
	call 1
	jeq %r0, 0, 5f
	mov %r2, 1
	xadddw [%r0+0], %r2
5:
	mov %r1, %r7
	rsh %r1, 32
	stxw [%r10+-184], %r1
	lddw %r1, 6
	mov %r2, %r10
	add %r2, -184
	call 1
	jne %r0, 0, 7f
	mov %r1, 1
	stxdw [%r10+-192], %r1
	lddw %r1, 6
	mov %r2, %r10
	add %r2, -184
	mov %r3, %r10
	add %r3, -192
	mov %r4, 0
	call 2
	ja 9f
7:
	mov %r2, 1
	xadddw [%r0+0], %r2
9:
	mov %r1, 0
	stxdw [%r10+-176], %r1
	mov %r1, \kind
	stxw [%r10+-176], %r1
	stxdw [%r10+-168], %r7
	call 5
	stxdw [%r10+-160], %r0
	mov %r1, 0
	stxdw [%r10+-152], %r1
	.endm

	.macro event_out size
	mov %r1, %r6
	lddw %r2, 0
	mov32 %r3, 0xffffffff
	mov %r4, %r10
	add %r4, -176
	mov %r5, \size
	call 25
	mov %r0, 0
	exit
	.endm

	.macro emit_event kind
	event_head \kind
	event_out 48
	.endm

	.macro emit_aux kind, off
	event_head \kind
	ldxdw %r1, [%r6+\off]
	stxdw [%r10+-152], %r1
	event_out 48
	.endm

	.macro emit_io kind, fdoff, lenoff
	event_head \kind
	ldxdw %r1, [%r6+\fdoff]
	stxdw [%r10+-152], %r1
	mov %r1, \kind
	stxw [%r10+-184], %r1
	lddw %r1, 2
	mov %r2, %r10
	add %r2, -184
	call 1
	jeq %r0, 0, 6f
	ldxdw %r2, [%r6+\lenoff]
	xadddw [%r0+0], %r2
6:
	event_out 48
	.endm

	.macro emit_str kind, off
	event_head \kind
	ldxdw %r3, [%r6+\off]
	mov %r1, %r10
	add %r1, -128
	mov %r2, 128
	call 114
	event_out 176
	.endm

	.macro emit_exec kind, off
	event_head \kind
	mov %r1, %r7
	rsh %r1, 32
	stxw [%r10+-184], %r1
	ldxdw %r1, [%r10+-160]
	stxdw [%r10+-192], %r1
	lddw %r1, 3
	mov %r2, %r10
	add %r2, -184
	mov %r3, %r10
	add %r3, -192
	mov %r4, 0
	call 2
	ldxdw %r3, [%r6+\off]
	mov %r1, %r10
	add %r1, -128
	mov %r2, 128
	call 114
	event_out 176
	.endm

	.macro emit_exit kind
	event_head \kind
	mov %r1, %r7
	rsh %r1, 32
	stxw [%r10+-184], %r1
	lddw %r1, 3
	mov %r2, %r10
	add %r2, -184
	call 1
	jeq %r0, 0, 8f
	ldxdw %r8, [%r0+0]
	ldxdw %r1, [%r10+-160]
	sub %r1, %r8
	stxdw [%r10+-152], %r1
	lddw %r1, 3
	mov %r2, %r10
	add %r2, -184
	call 3
8:
	event_out 48
	.endm
