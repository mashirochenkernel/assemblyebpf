/* SPDX-License-Identifier: GPL-2.0 */

	.include "bpf/event.inc"

	.section "tracepoint/syscalls/sys_enter_connect", "ax"
	.global trace_connect
trace_connect:
	emit_event 8

	.section "tracepoint/syscalls/sys_enter_accept4", "ax"
	.global trace_accept4
trace_accept4:
	emit_event 9

	.section "tracepoint/syscalls/sys_enter_sendto", "ax"
	.global trace_sendto
trace_sendto:
	emit_event 10

	.section "tracepoint/syscalls/sys_enter_recvfrom", "ax"
	.global trace_recvfrom
trace_recvfrom:
	emit_event 11

	.section "license", "a"
_license:
	.asciz "GPL"
