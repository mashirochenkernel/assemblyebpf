/* SPDX-License-Identifier: GPL-2.0 */

	.macro lat_enter
	call 14
	mov %r7, %r0
	mov %r1, %r7
	rsh %r1, 32
	jeq %r1, 0, 1f
	stxdw [%r10+-16], %r7
	call 5
	stxdw [%r10+-24], %r0
	lddw %r1, 5
	mov %r2, %r10
	add %r2, -16
	mov %r3, %r10
	add %r3, -24
	mov %r4, 0
	call 2
1:
	mov %r0, 0
	exit
	.endm

	.macro lat_exit
	call 14
	mov %r7, %r0
	stxdw [%r10+-16], %r7
	lddw %r1, 5
	mov %r2, %r10
	add %r2, -16
	call 1
	jeq %r0, 0, 9f
	ldxdw %r8, [%r0+0]
	lddw %r1, 5
	mov %r2, %r10
	add %r2, -16
	call 3
	call 5
	jlt %r0, %r8, 9f
	sub %r0, %r8
	mov %r8, %r0
	mov %r3, 0
	mov %r1, %r8
	rsh %r1, 32
	jeq %r1, 0, 1f
	add %r3, 32
	mov %r8, %r1
1:
	mov %r1, %r8
	rsh %r1, 16
	jeq %r1, 0, 2f
	add %r3, 16
	mov %r8, %r1
2:
	mov %r1, %r8
	rsh %r1, 8
	jeq %r1, 0, 3f
	add %r3, 8
	mov %r8, %r1
3:
	mov %r1, %r8
	rsh %r1, 4
	jeq %r1, 0, 4f
	add %r3, 4
	mov %r8, %r1
4:
	mov %r1, %r8
	rsh %r1, 2
	jeq %r1, 0, 5f
	add %r3, 2
	mov %r8, %r1
5:
	mov %r1, %r8
	rsh %r1, 1
	jeq %r1, 0, 6f
	add %r3, 1
6:
	stxw [%r10+-24], %r3
	lddw %r1, 4
	mov %r2, %r10
	add %r2, -24
	call 1
	jeq %r0, 0, 9f
	mov %r2, 1
	xadddw [%r0+0], %r2
9:
	mov %r0, 0
	exit
	.endm
