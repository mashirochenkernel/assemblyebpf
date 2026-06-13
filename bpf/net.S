/* SPDX-License-Identifier: GPL-2.0 */

	.section "kprobe/tcp_connect", "ax"
	.global trace_tcp_connect
trace_tcp_connect:
	mov %r6, %r1
	mov %r1, 3
	call 14
	mov %r7, %r0
	mov %r1, %r10
	add %r1, -16
	mov %r2, 16
	call 16
	mov %r1, 3
	stxw [%r10+-32], %r1
	stxdw [%r10+-24], %r7
	ldxdw %r1, [%r10+-16]
	stxdw [%r10+-16], %r1
	ldxdw %r1, [%r10+-8]
	stxdw [%r10+-8], %r1
	mov %r1, %r6
	lddw %r2, 0
	mov %r3, 0xffffffff
	mov %r4, %r10
	add %r4, -32
	mov %r5, 32
	call 25
	mov %r0, 0
	exit

	.section "license", "a"
_license:
	.asciz "GPL"
