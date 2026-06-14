/* SPDX-License-Identifier: GPL-2.0 */

	.include "bpf/event.inc"

	.section "tracepoint/syscalls/sys_enter_connect", "ax"
	.global trace_connect
trace_connect:
	emit_aux 8, 16

	.section "tracepoint/syscalls/sys_enter_accept4", "ax"
	.global trace_accept4
trace_accept4:
	emit_aux 9, 16

	.section "tracepoint/syscalls/sys_enter_sendto", "ax"
	.global trace_sendto
trace_sendto:
	emit_aux 10, 16

	.section "tracepoint/syscalls/sys_enter_recvfrom", "ax"
	.global trace_recvfrom
trace_recvfrom:
	emit_aux 11, 16

	.section "license", "a"
_license:
	.asciz "GPL"
