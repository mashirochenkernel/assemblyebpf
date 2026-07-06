/* SPDX-License-Identifier: GPL-2.0 */

	.include "bpf/event.inc"

	.section "tracepoint/syscalls/sys_enter_read", "ax"
	.global trace_read
trace_read:
	emit_io 5, 16, 32

	.section "tracepoint/syscalls/sys_enter_write", "ax"
	.global trace_write
trace_write:
	emit_io_data 6, 16, 32, 24

	.section "tracepoint/syscalls/sys_enter_close", "ax"
	.global trace_close
trace_close:
	emit_aux 7, 16

	.section "license", "a"
_license:
	.asciz "GPL"
