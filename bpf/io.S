/* SPDX-License-Identifier: GPL-2.0 */

	.include "bpf/event.inc"

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
