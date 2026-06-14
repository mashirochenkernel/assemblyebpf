/* SPDX-License-Identifier: GPL-2.0 */

	.include "bpf/event.inc"

	.section "kprobe/tcp_connect", "ax"
	.global trace_tcp_connect
trace_tcp_connect:
	event_head 3
	ldxdw %r8, [%r6+112]
	mov %r1, %r10
	add %r1, -192
	mov %r2, 4
	mov %r3, %r8
	call 113
	mov %r1, %r10
	add %r1, -196
	mov %r2, 2
	mov %r3, %r8
	add %r3, 12
	call 113
	ldxw %r1, [%r10+-192]
	ldxh %r2, [%r10+-196]
	lsh %r2, 32
	or %r1, %r2
	stxdw [%r10+-152], %r1
	event_out 48

	.section "license", "a"
_license:
	.asciz "GPL"
