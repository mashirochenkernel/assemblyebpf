/* SPDX-License-Identifier: GPL-2.0 */

	.section "tracepoint/sched/sched_switch", "ax"
	.global off_switch
off_switch:
	mov %r6, %r1
	call 5
	mov %r7, %r0

	ldxw %r8, [%r6+56]
	stxw [%r10+-4], %r8
	lddw %r1, 10
	mov %r2, %r10
	add %r2, -4
	call 1
	jeq %r0, 0, 2f
	ldxdw %r1, [%r0+0]
	mov %r2, %r7
	sub %r2, %r1
	stxdw [%r10+-16], %r2
	stxw [%r10+-4], %r8
	lddw %r1, 11
	mov %r2, %r10
	add %r2, -4
	call 1
	jne %r0, 0, 5f
	stxw [%r10+-4], %r8
	lddw %r1, 11
	mov %r2, %r10
	add %r2, -4
	mov %r3, %r10
	add %r3, -16
	mov %r4, 0
	call 2
	ja 6f
5:
	ldxdw %r2, [%r10+-16]
	xadddw [%r0+0], %r2
6:
	stxw [%r10+-4], %r8
	lddw %r1, 10
	mov %r2, %r10
	add %r2, -4
	call 3
2:
	ldxdw %r1, [%r6+32]
	and %r1, 3
	jeq %r1, 0, 8f
	ldxw %r8, [%r6+24]
	stxw [%r10+-4], %r8
	stxdw [%r10+-16], %r7
	lddw %r1, 10
	mov %r2, %r10
	add %r2, -4
	mov %r3, %r10
	add %r3, -16
	mov %r4, 0
	call 2
8:
	mov %r0, 0
	exit

	.section "license", "a"
_license:
	.asciz "GPL"
