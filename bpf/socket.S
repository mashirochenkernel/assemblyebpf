/* SPDX-License-Identifier: GPL-2.0 */

	.include "bpf/event.inc"

	.section "tracepoint/syscalls/sys_enter_connect", "ax"
	.global trace_connect
trace_connect:
	enter_sockaddr 8, 16, 24

	.section "tracepoint/syscalls/sys_exit_connect", "ax"
	.global trace_connect_exit
trace_connect_exit:
	emit_exit_ret

	.section "tracepoint/syscalls/sys_enter_accept4", "ax"
	.global trace_accept4
trace_accept4:
	enter_aux 9, 16

	.section "tracepoint/syscalls/sys_exit_accept4", "ax"
	.global trace_accept4_exit
trace_accept4_exit:
	emit_exit_ret

	.section "tracepoint/syscalls/sys_enter_sendto", "ax"
	.global trace_sendto
trace_sendto:
	emit_sockaddr 10, 16, 48

	.section "tracepoint/syscalls/sys_enter_recvfrom", "ax"
	.global trace_recvfrom
trace_recvfrom:
	emit_io 11, 16, 32

	.section "license", "a"
_license:
	.asciz "GPL"
