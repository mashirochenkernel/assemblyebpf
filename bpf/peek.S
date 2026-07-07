/* SPDX-License-Identifier: GPL-2.0 */

	.section "tracepoint/raw_syscalls/sys_enter", "ax"
	.global peek_read
peek_read:
	mov %r6, %r1
	mov %r1, 0
	stxw [%r10+-192], %r1
	lddw %r1, 0
	mov %r2, %r10
	add %r2, -192
	call 1
	jeq %r0, 0, 1f
	mov %r9, %r0
	ldxdw %r8, [%r9+112]
	jeq %r8, 0, 1f
	ldxw %r7, [%r9+120]
	jeq %r7, 0, 1f
	call 14
	mov %r1, %r0
	rsh %r1, 32
	jne %r1, %r7, 1f
	mov %r1, 36
	stxw [%r10+-184], %r1
	mov %r1, 0
	stxw [%r10+-180], %r1
	stxdw [%r10+-176], %r0
	call 5
	stxdw [%r10+-168], %r0
	stxdw [%r10+-160], %r8
	mov %r1, 0
	stxdw [%r10+-152], %r1
	mov %r1, %r10
	add %r1, -144
	mov %r2, 16
	call 16
	mov %r1, %r10
	add %r1, -128
	mov %r2, 64
	mov %r3, %r8
	call 112
	mov %r1, %r6
	lddw %r2, 0
	mov32 %r3, 0xffffffff
	mov %r4, %r10
	add %r4, -184
	mov %r5, 120
	call 25
1:
	mov %r0, 0
	exit

	.section "license", "a"
_license:
	.asciz "GPL"
