/* SPDX-License-Identifier: GPL-2.0 */

	.macro emit_event kind
	mov %r6, %r1
	mov %r1, 3
	call 14
	mov %r7, %r0
	mov %r1, %r10
	add %r1, -16
	mov %r2, 16
	call 16
	mov %r1, 0
	stxdw [%r10+-32], %r1
	mov %r1, \kind
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
	.endm

	.section "tracepoint/syscalls/sys_enter_read", "ax"
	.global trace_read
trace_read:
	emit_event 5

	.section "tracepoint/syscalls/sys_enter_write", "ax"
	.global trace_write
trace_write:
	emit_event 6

	.section "tracepoint/syscalls/sys_enter_close", "ax"
	.global trace_close
trace_close:
	emit_event 7

	.section "license", "a"
_license:
	.asciz "GPL"
